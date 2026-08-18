//! ADR-5B-R1: real-Windows drain-lifecycle runtime.
//!
//! Launches the benign capture-epoch helper UNDER a real debugger session
//! (DebugActiveProcess-style via WindowsDebugger::new with post_attach=false,
//! which uses DEBUG_ONLY_THIS_PROCESS), drains debug events through
//! WindowsDebugger::drain_debug_event for a bounded window, then verifies:
//!
//! - every drained event passed through the unified lifecycle (sequence
//!   monotonic, exactly-once continue);
//! - every CreateThread registered a thread handle and every ExitThread
//!   removed a previously registered one (NO unmatched exits);
//! - every LOAD_DLL / CREATE_PROCESS hFile was closed by the drain;
//! - the thread table is consistent before/after the drain window
//!   (same registered TIDs, no leaked handles).
//!
//! This runtime is gated behind the `capture-epoch-harness` feature (same as
//! the capture-epoch harness) because it spawns real processes and opens
//! Windows handles; the DEFAULT `cargo test -p mida-core` build compiles it
//! to an empty test module (0 tests).

#![cfg(feature = "capture-epoch-harness")]

use std::time::{Duration, Instant};

use mida_core::{ContinueStatus, CreateProcessOptions, DebugEvent, DebuggerCore, WindowsDebugger};

/// Process-wide serialization: real-process tests must not run in parallel
/// (global handle counts and debug-session exclusivity).
static HARNESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Acquire the harness lock, recovering from a poisoned mutex (a previous
/// test panicked while holding it; the process state is still usable).
fn harness_lock() -> std::sync::MutexGuard<'static, ()> {
    HARNESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Real-constant binding test (audit F-001): the ContinueStatus values must
/// match the Windows NTSTATUS constants EXACTLY. 0x40010001 is
/// DBG_REPLY_LATER, NOT DBG_EXCEPTION_NOT_HANDLED (0x80010001) — a wrong
/// value silently corrupts exception disposition in the drain window.
#[test]
fn continue_status_binds_real_win32_constants() {
    use windows::Win32::Foundation::{DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED};
    assert_eq!(
        ContinueStatus::Continue as u32,
        DBG_CONTINUE.0 as u32,
        "Continue must equal DBG_CONTINUE"
    );
    assert_eq!(
        ContinueStatus::ExceptionNotHandled as u32,
        DBG_EXCEPTION_NOT_HANDLED.0 as u32,
        "ExceptionNotHandled must equal DBG_EXCEPTION_NOT_HANDLED (0x80010001), not DBG_REPLY_LATER (0x40010001)"
    );
    // Guard against the exact regression: 0x40010001 is DBG_REPLY_LATER.
    assert_ne!(
        ContinueStatus::ExceptionNotHandled as u32,
        0x4001_0001,
        "0x40010001 is DBG_REPLY_LATER, never use it for exception forwarding"
    );
}

fn helper_bin() -> &'static str {
    option_env!("CARGO_BIN_EXE_capture_epoch_helper")
        .expect("helper not built (enable feature capture-epoch-harness)")
}

/// Build CreateProcessOptions that launch the helper under a real debugger
/// with thread churn (spawn + short-lived threads).
fn helper_opts(tag: &str) -> CreateProcessOptions {
    let helper = helper_bin();
    let shm = format!("mida_drain_{tag}_{}", std::process::id());
    let pidfile = format!(
        "{}\\mida_drain_pid_{}_{}.txt",
        std::env::temp_dir().display(),
        tag,
        std::process::id()
    );
    let _ = std::fs::remove_file(&pidfile);
    CreateProcessOptions {
        executable: std::path::PathBuf::from(helper),
        command_line: Some(format!(
            "--shm {shm} --pidfile {pidfile} --workers 2 --spawn-every-ms 50 --short-lived-every-ms 30 --max-ms 8000"
        )),
        is_dll: false,
        suspended: false,
        post_attach: false,
    }
}

#[test]
fn drain_lifecycle_thread_table_consistency() {
    let _guard = harness_lock();
    let opts = helper_opts("tbl");
    let mut dbg = WindowsDebugger::new(&opts).expect("WindowsDebugger::new");

    // Phase 1: consume the initial CREATE_PROCESS event (main loop wait).
    let first = dbg.wait_event().expect("wait_event");
    assert!(matches!(first, DebugEvent::CreateProcess { .. }));
    dbg.continue_event(
        dbg.pending_event_thread_id().unwrap_or(0),
        ContinueStatus::Continue,
    )
    .expect("continue CREATE_PROCESS");

    // Record the thread table snapshot right after CREATE_PROCESS.
    let initial_main_tid = dbg.main_thread_id();

    // Phase 2: drain for a bounded window (the helper spawns threads every
    // 50ms and short-lived threads every 30ms, so the drain MUST observe
    // CreateThread/ExitThread pairs).
    let window = Duration::from_millis(1500);
    let start = Instant::now();
    let mut receipts = Vec::new();
    while Instant::now() - start < window {
        match dbg.drain_debug_event(50) {
            Ok(Some(r)) => receipts.push(r),
            Ok(None) => {}
            Err(e) => panic!("drain_debug_event failed: {e}"),
        }
    }

    // Phase 3: verify bookkeeping invariants.
    let stats = dbg.drain_stats().clone();
    // No DEFECTIVE unmatched ExitThread: every exit whose thread object is
    // still alive must have had a registered handle. Short-lived exits
    // between drain polls are legal and recorded separately (verified via
    // OpenThread + 0ms wait, not inferred).
    assert_eq!(
        stats.unmatched_exit_threads, 0,
        "drain observed unmatched ExitThread with thread still alive (bookkeeping gap): {stats:?}"
    );
    // Every LOAD_DLL / CREATE_PROCESS hFile close was ATTEMPTED; every
    // attempt must have SUCCEEDED (no leaked handles).
    let load_dll_count = receipts.iter().filter(|r| r.event_code == 6).count() as u64;
    let create_proc_count = receipts.iter().filter(|r| r.event_code == 3).count() as u64;
    assert_eq!(
        stats.hfiles_close_attempted,
        load_dll_count + create_proc_count,
        "drain did not attempt every hFile close: stats={stats:?} receipts_loaded={load_dll_count} create_proc={create_proc_count}"
    );
    assert_eq!(
        stats.hfiles_close_failed, 0,
        "some hFile CloseHandle FAILED (leaked handle): {stats:?}"
    );
    assert_eq!(
        stats.hfiles_close_succeeded, stats.hfiles_close_attempted,
        "hFile close succeeded count != attempted count: {stats:?}"
    );
    // The helper spawns threads; we should have seen at least one CreateThread.
    assert!(
        stats.create_threads_registered > 0,
        "drain saw no CreateThread in a 1.5s window (helper churn not observed): {stats:?}"
    );
    // Exit classification is EXHAUSTIVE: every ExitThread falls into exactly
    // one of removed / short-lived / unmatched, and no exit can be silently
    // dropped. (In a short drain window some spawned threads are still alive
    // at the end, so we only assert the accounting invariant: the sum of the
    // three classifications equals the number of ExitThread receipts.)
    let exit_receipts = receipts.iter().filter(|r| r.event_code == 4).count() as u64;
    let exit_classified = stats.exit_threads_removed
        + stats.exit_short_lived_with_create_observation
        + stats.unmatched_exit_threads;
    assert_eq!(
        exit_receipts, exit_classified,
        "ExitThread receipts not exhaustively classified: receipts={exit_receipts} classified={exit_classified} stats={stats:?}"
    );
    // Sequences are monotonic and non-zero.
    let mut prev = 0u64;
    for r in &receipts {
        assert!(r.sequence > prev, "sequence not monotonic: {r:?}");
        prev = r.sequence;
    }
    // After the drain window the main thread is still registered.
    assert!(
        dbg.thread_handle(initial_main_tid).is_ok(),
        "main thread handle lost after drain"
    );

    // Phase 4: Drop kills the owned process (ProcessOwnership::OwnedLaunch).
    drop(_guard);
}

#[test]
fn drain_propagates_debug_registers_to_new_threads() {
    let _guard = harness_lock();
    let opts = helper_opts("dr");
    let mut dbg = WindowsDebugger::new(&opts).expect("WindowsDebugger::new");

    let first = dbg.wait_event().expect("wait_event");
    assert!(matches!(first, DebugEvent::CreateProcess { .. }));
    dbg.continue_event(
        dbg.pending_event_thread_id().unwrap_or(0),
        ContinueStatus::Continue,
    )
    .expect("continue CREATE_PROCESS");

    // Install a benign hardware breakpoint (execute on the main thread's
    // image base + 0x10 — harmless, may never fire but occupies a slot).
    // Use a zero-ish high address to avoid any accidental execution hit:
    // DR0 on a guard-page-ish address is fine; we only assert propagation.
    let bp_addr = dbg.image_base() as usize + 0x10;
    dbg.set_hw_breakpoint(0, bp_addr, mida_core::HwbpType::Execute)
        .expect("set HW BP");

    // Drain while the helper churns threads. Every CreateThread must trigger
    // DR propagation (the drain path applies apply_event_bookkeeping which
    // calls apply_debug_registers_thread when has_any_hw_breakpoint).
    let window = Duration::from_millis(1200);
    let start = Instant::now();
    let mut created = 0u64;
    let mut created_tids = Vec::new();
    while Instant::now() - start < window {
        match dbg.drain_debug_event(50) {
            Ok(Some(r)) => {
                if r.event_code == 2 {
                    created += 1;
                    created_tids.push(r.thread_id);
                }
            }
            Ok(None) => {}
            Err(e) => panic!("drain_debug_event failed: {e}"),
        }
    }
    let stats = dbg.drain_stats();
    assert!(created > 0, "no CreateThread observed");
    assert_eq!(
        stats.dr_propagations, created,
        "every drain-created thread must receive DR propagation: stats={stats:?} created={created}"
    );
    assert_eq!(stats.create_threads_registered, created);
    // ADR-5B-R1 F-003: counter equality is NOT enough — verify the DR state
    // actually landed by reading a live thread's debug-register context.
    let mut verified = 0u64;
    for tid in created_tids {
        if let Ok(ctx) = dbg.get_thread_context_dbg(tid) {
            // The helper threads are short-lived; a thread may exit between
            // drain and probe. Any thread we CAN still query must show the
            // propagated DR0 address (bp_addr).
            if ctx.Dr0 == bp_addr as u64 {
                verified += 1;
            }
        }
    }
    assert!(
        verified > 0,
        "no live thread verified to actually hold the propagated DR0 (bp_addr={bp_addr:#x}): stats={stats:?}"
    );

    // Cleanup must NOT panic: a failed clear (Windows(5) = access denied on
    // a thread that exited mid-drain) must not poison the global harness
    // lock and cascade fake failures into the other tests (audit F-007).
    if let Err(e) = dbg.clear_hw_breakpoint(0) {
        eprintln!(
            "drain_propagates_debug_registers_to_new_threads: clear HW BP failed (non-fatal): {e}"
        );
    }
    drop(dbg);
    drop(_guard);
}

#[test]
fn drain_receipt_exception_events_are_recorded_and_continued() {
    // Use poison-recovering harness_lock (audit F-007: a previous test's
    // panic must not turn this test into a fake failure).
    let _guard = harness_lock();
    let opts = helper_opts("exc");
    let mut dbg = WindowsDebugger::new(&opts).expect("WindowsDebugger::new");

    let first = dbg.wait_event().expect("wait_event");
    assert!(matches!(first, DebugEvent::CreateProcess { .. }));
    dbg.continue_event(
        dbg.pending_event_thread_id().unwrap_or(0),
        ContinueStatus::Continue,
    )
    .expect("continue CREATE_PROCESS");

    // Drain long enough to catch the initial loader breakpoint exceptions
    // (ntdll / CRT init raises breakpoints the debugger sees as exceptions).
    let window = Duration::from_millis(800);
    let start = Instant::now();
    let mut exceptions_continued = 0u64;
    let mut exceptions_forwarded = 0u64;
    while Instant::now() - start < window {
        match dbg.drain_debug_event(50) {
            Ok(Some(r)) => {
                match r.disposition {
                    mida_core::DrainDisposition::Exception => {
                        // Debugger-owned (breakpoint/single-step): DBG_CONTINUE.
                        exceptions_continued += 1;
                        assert!(
                            r.continue_status == mida_core::ContinueStatus::Continue as u32,
                            "debugger-owned exception must use DBG_CONTINUE: {r:?}"
                        );
                    }
                    mida_core::DrainDisposition::ExceptionForwarded => {
                        // Unknown first-chance: DBG_EXCEPTION_NOT_HANDLED.
                        exceptions_forwarded += 1;
                        assert!(
                            r.continue_status
                                == mida_core::ContinueStatus::ExceptionNotHandled as u32,
                            "forwarded exception must use DBG_EXCEPTION_NOT_HANDLED: {r:?}"
                        );
                        assert_eq!(
                            r.first_chance,
                            Some(true),
                            "forwarded must be first-chance: {r:?}"
                        );
                    }
                    _ => {}
                }
                if r.disposition == mida_core::DrainDisposition::Exception
                    || r.disposition == mida_core::DrainDisposition::ExceptionForwarded
                {
                    assert!(r.exception_code.is_some(), "exception receipt missing code");
                    assert!(
                        r.first_chance.is_some(),
                        "exception receipt missing first_chance"
                    );
                }
            }
            Ok(None) => {}
            Err(e) => panic!("drain_debug_event failed: {e}"),
        }
    }
    let stats = dbg.drain_stats();
    assert_eq!(
        stats.exceptions_continued, exceptions_continued,
        "exception continued counter mismatch"
    );
    assert_eq!(
        stats.exceptions_forwarded, exceptions_forwarded,
        "exception forwarded counter mismatch"
    );
    // Second-chance / fail-closed must never fire for the benign helper.
    assert_eq!(stats.exceptions_failed_closed, 0);

    drop(_guard);
}

#[test]
fn drain_receipts_are_retained_and_takeable() {
    // ADR-5B-R1 F-005: the debugger must retain EVERY drain receipt so the
    // loader window is fully auditable, and take_drain_receipts must hand
    // them out exactly once.
    let _guard = harness_lock();
    let opts = helper_opts("rcpt");
    let mut dbg = WindowsDebugger::new(&opts).expect("WindowsDebugger::new");

    let first = dbg.wait_event().expect("wait_event");
    assert!(matches!(first, DebugEvent::CreateProcess { .. }));
    dbg.continue_event(
        dbg.pending_event_thread_id().unwrap_or(0),
        ContinueStatus::Continue,
    )
    .expect("continue CREATE_PROCESS");

    // Drain a short window and collect BOTH the returned receipts and the
    // retained copies.
    let window = Duration::from_millis(400);
    let start = Instant::now();
    let mut returned = 0u64;
    while Instant::now() - start < window {
        match dbg.drain_debug_event(30) {
            Ok(Some(_)) => returned += 1,
            Ok(None) => {}
            Err(e) => panic!("drain_debug_event failed: {e}"),
        }
    }
    assert!(returned > 0, "no events drained in window");
    let retained = dbg.retained_drain_receipt_count() as u64;
    assert_eq!(
        retained, returned,
        "retained receipts != returned receipts (audit trail incomplete): retained={retained} returned={returned}"
    );
    // take_drain_receipts hands out exactly the retained set once.
    let taken = dbg.take_drain_receipts();
    assert_eq!(taken.len() as u64, retained, "take mismatch");
    assert_eq!(
        dbg.retained_drain_receipt_count(),
        0,
        "take_drain_receipts must clear the accumulator"
    );
    // Taken receipts are the same events, in order.
    for (i, r) in taken.iter().enumerate() {
        assert!(r.sequence > 0, "receipt {i} has zero sequence");
        if i > 0 {
            assert!(
                r.sequence > taken[i - 1].sequence,
                "receipts out of order at {i}"
            );
        }
    }

    drop(_guard);
}
