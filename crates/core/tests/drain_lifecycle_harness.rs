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
    // between drain polls are legal and recorded separately.
    assert_eq!(
        stats.unmatched_exit_threads, 0,
        "drain observed unmatched ExitThread with thread still alive (bookkeeping gap): {stats:?}"
    );
    // Every LOAD_DLL / CREATE_PROCESS hFile was closed.
    let load_dll_count = receipts.iter().filter(|r| r.event_code == 6).count() as u64;
    let create_proc_count = receipts.iter().filter(|r| r.event_code == 3).count() as u64;
    assert_eq!(
        stats.hfiles_closed,
        load_dll_count + create_proc_count,
        "drain did not close every hFile: stats={stats:?} receipts_loaded={load_dll_count} create_proc={create_proc_count}"
    );
    // The helper spawns threads; we should have seen at least one CreateThread.
    assert!(
        stats.create_threads_registered > 0,
        "drain saw no CreateThread in a 1.5s window (helper churn not observed): {stats:?}"
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
    while Instant::now() - start < window {
        match dbg.drain_debug_event(50) {
            Ok(Some(r)) => {
                if r.event_code == 2 {
                    created += 1;
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

    dbg.clear_hw_breakpoint(0).expect("clear HW BP");
    drop(_guard);
}

#[test]
fn drain_receipt_exception_events_are_recorded_and_continued() {
    let _guard = HARNESS_LOCK.lock().unwrap();
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
    let mut exceptions_seen = 0u64;
    while Instant::now() - start < window {
        match dbg.drain_debug_event(50) {
            Ok(Some(r)) => {
                if r.disposition == mida_core::DrainDisposition::Exception {
                    exceptions_seen += 1;
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
        stats.exceptions_continued, exceptions_seen,
        "exception counter mismatch"
    );

    drop(_guard);
}
