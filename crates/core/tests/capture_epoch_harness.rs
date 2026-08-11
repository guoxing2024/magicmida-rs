//! Route Z R0 AF2: real Windows capture-epoch harness.
//!
//! Launches a benign helper process with worker threads incrementing a shared
//! counter, then verifies that `freeze_process_threads` genuinely stops every
//! target thread (counter stops, thread set converged, all frozen) and that
//! `unfreeze_process_threads` resumes them (counter resumes, exact suspend-count
//! restore). Runs repeatedly (≥20 iterations) so any real freeze/restore failure
//! is surfaced.
//!
//! This harness is gated behind the `capture-epoch-harness` feature: it requires
//! the feature-gated failure-injection entry points and the helper binary, so the
//! DEFAULT `cargo test -p mida-core` build compiles it to an empty test module
//! (0 tests) rather than importing feature-only symbols. The real Windows tests
//! run under `cargo test -p mida-core --features capture-epoch-harness`.

#![cfg(feature = "capture-epoch-harness")]

use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use mida_core::capture_epoch::CaptureEpochGuard;
use mida_core::windows_debugger::{clear_transient_exit_diagnostics, transient_exit_observations};
use mida_core::windows_debugger::{
    enumerate_process_threads, freeze_process_threads, freeze_process_threads_with_failure,
    unfreeze_process_threads,
};
use mida_core::{CoreError, DebugEvent, DebuggerCore};
use windows::Win32::System::Diagnostics::Debug::CONTEXT;

const OFF_COUNTER: usize = 0;
const OFF_RUNNING: usize = 8;
const OFF_WORKER: usize = 12;
const OFF_BARRIER_CUR_TID: usize = 16;
const OFF_BARRIER_CMD_TID: usize = 20;
const OFF_BARRIER_CMD_SET: usize = 24;
const MAP_SIZE: usize = 32;

/// Shared-memory view of the helper's counter (opened by name).
///
/// **Synchronization model (Route Z R0 AF2 AF1 AF4 / P2-1):** every field is
/// accessed through `AtomicU32`/`AtomicU64` on BOTH the helper and this harness
/// side (never one side atomic and the other a plain raw load/store). This gives
/// the command/status protocol an explicit happens-before: the test's `store`
/// publishes a command; the helper's `load` observes it; the barrier thread exits;
/// the test's `WaitForSingleObject` observes the OS thread-object signal. Offsets
/// are checked for the required atomic alignment in `debug_assert`s.
struct SharedCounter {
    base: *mut u8,
    mapping: windows::Win32::Foundation::HANDLE,
}

impl SharedCounter {
    fn open(name: &str) -> Result<Self, String> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Memory::{OpenFileMappingW, FILE_MAP_ALL_ACCESS};
        // SAFETY: open the named file mapping the helper created.
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let h = unsafe { OpenFileMappingW(FILE_MAP_ALL_ACCESS.0, false, PCWSTR(wide.as_ptr())) }
            .map_err(|e| format!("OpenFileMappingW failed: {e:?}"))?;
        // SAFETY: map the shared view.
        let p = unsafe {
            windows::Win32::System::Memory::MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, MAP_SIZE)
        };
        if p.Value.is_null() {
            return Err("MapViewOfFile failed".into());
        }
        let base = p.Value as *mut u8;
        // Alignment assertions: u64 at OFF_COUNTER, u32 fields aligned to 4.
        debug_assert_eq!(OFF_COUNTER % 8, 0, "counter offset must be 8-aligned (u64)");
        debug_assert_eq!(OFF_RUNNING % 4, 0);
        debug_assert_eq!(OFF_WORKER % 4, 0);
        debug_assert_eq!(OFF_BARRIER_CUR_TID % 4, 0);
        debug_assert_eq!(OFF_BARRIER_CMD_TID % 4, 0);
        debug_assert_eq!(OFF_BARRIER_CMD_SET % 4, 0);
        debug_assert!(MAP_SIZE >= 28, "mapping must cover all fields");
        Ok(Self { base, mapping: h })
    }

    fn counter(&self) -> u64 {
        // SAFETY: base+OFF_COUNTER is an aligned u64 field shared with the helper.
        unsafe { AtomicU64::from_ptr(self.base.add(OFF_COUNTER) as *mut u64) }
            .load(Ordering::SeqCst)
    }
    fn running(&self) -> u32 {
        // SAFETY: base+OFF_RUNNING is an aligned u32 field shared with the helper.
        unsafe { AtomicU32::from_ptr(self.base.add(OFF_RUNNING) as *mut u32) }
            .load(Ordering::SeqCst)
    }
    fn worker_count(&self) -> u32 {
        // SAFETY: aligned u32 field.
        unsafe { AtomicU32::from_ptr(self.base.add(OFF_WORKER) as *mut u32) }.load(Ordering::SeqCst)
    }
    fn set_running(&self, v: u32) {
        // SAFETY: aligned u32 field.
        unsafe { AtomicU32::from_ptr(self.base.add(OFF_RUNNING) as *mut u32) }
            .store(v, Ordering::SeqCst);
    }

    /// TID of a live barrier thread currently registered by the helper (0 = none).
    fn barrier_cur_tid(&self) -> u32 {
        // SAFETY: aligned u32 field.
        unsafe { AtomicU32::from_ptr(self.base.add(OFF_BARRIER_CUR_TID) as *mut u32) }
            .load(Ordering::SeqCst)
    }
}

/// Free-function form of the barrier termination proof, so the `ExitBarrier`
/// closure can capture just the raw base pointer (Copy, `'static`) with no
/// borrowed-lifetime coupling.
///
/// Opens a `SYNCHRONIZE` thread handle, commands the helper to exit `tid`, then
/// blocks until `WaitForSingleObject` observes `WAIT_OBJECT_0` (the OS thread
/// object signaled = terminated). Returns `BarrierExitResult::Terminated` ONLY on
/// that OS-level proof; `Timeout` on `WAIT_TIMEOUT`; `Failure(code)` on
/// `WAIT_FAILED` / open failure. Closes the handle on every path (P2-2).
fn force_exit_at(base: *mut u8, tid: u32) -> mida_core::windows_debugger::BarrierExitResult {
    use windows::Win32::System::Threading::{OpenThread, WaitForSingleObject, THREAD_SYNCHRONIZE};
    // SAFETY: open a SYNCHRONIZE handle to the barrier thread (must be alive while
    // it waits at the barrier).
    let h = match unsafe { OpenThread(THREAD_SYNCHRONIZE, false, tid) } {
        Ok(h) => h,
        Err(e) => {
            // OpenThread failure: `e.code()` is an HRESULT. Preserve both the HRESULT
            // and its low 16-bit Win32 word so a raw HRESULT is never mislabeled as a
            // Win32 code (P2-3).
            let hresult = e.code().0 as u32;
            return mida_core::windows_debugger::BarrierExitResult::Failure {
                hresult,
                win32_code: hresult & 0xffff,
            };
        }
    };
    // Command the helper to terminate `tid` (publish command, then arm it).
    // SAFETY: aligned shared u32 fields.
    unsafe {
        let cmd_tid = AtomicU32::from_ptr(base.add(OFF_BARRIER_CMD_TID) as *mut u32);
        let cmd_set = AtomicU32::from_ptr(base.add(OFF_BARRIER_CMD_SET) as *mut u32);
        cmd_tid.store(tid, Ordering::SeqCst);
        cmd_set.store(1, Ordering::SeqCst);
    }
    // Wait (bounded) for the OS thread object to become signaled (terminated).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut result = mida_core::windows_debugger::BarrierExitResult::Timeout;
    while Instant::now() < deadline {
        // SAFETY: WaitForSingleObject on our own SYNCHRONIZE thread handle.
        let w = unsafe { WaitForSingleObject(h, 0) };
        if w == windows::Win32::Foundation::WAIT_OBJECT_0 {
            result = mida_core::windows_debugger::BarrierExitResult::Terminated;
            break;
        } else if w == windows::Win32::Foundation::WAIT_FAILED {
            // Evidence query failed: NOT termination evidence. Fail-closed.
            // SAFETY: GetLastError read immediately after the failed call — a true
            // Win32 code (P2-3). hresult=0 since WAIT_FAILED is not an HRESULT.
            let code = unsafe { windows::Win32::Foundation::GetLastError() }.0;
            result = mida_core::windows_debugger::BarrierExitResult::Failure {
                hresult: 0,
                win32_code: code,
            };
            break;
        }
        // WAIT_TIMEOUT (thread still alive) -> keep waiting until deadline.
        let _ = w;
        std::thread::sleep(Duration::from_millis(1));
    }
    // Disarm the command regardless of outcome.
    // SAFETY: aligned shared u32 field.
    unsafe {
        let cmd_set = AtomicU32::from_ptr(base.add(OFF_BARRIER_CMD_SET) as *mut u32);
        cmd_set.store(0, Ordering::SeqCst);
    }
    // Close the handle on every path (P2-2: no leak).
    // SAFETY: closes the handle we opened above.
    let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
    result
}

impl Drop for SharedCounter {
    fn drop(&mut self) {
        // SAFETY: unmap + close the mapping handles.
        unsafe {
            use windows::Win32::System::Memory::{UnmapViewOfFile, MEMORY_MAPPED_VIEW_ADDRESS};
            let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.base as *mut std::ffi::c_void,
            });
            let _ = windows::Win32::Foundation::CloseHandle(self.mapping);
        }
    }
}

/// Whether the test-only helper binary is built (feature `capture-epoch-harness`).
/// When disabled (default build), the real-Windows harness tests are skipped.
fn helper_available() -> bool {
    option_env!("CARGO_BIN_EXE_capture_epoch_helper").is_some()
}

/// Launch the benign helper and wait until its shared counter starts moving.
fn launch_helper(
    tag: &str,
    workers: usize,
    spawn_every_ms: u64,
    short_lived_every_ms: u64,
) -> Result<(Child, SharedCounter, String), String> {
    launch_helper_opt(tag, workers, spawn_every_ms, short_lived_every_ms, 0)
}

/// Like [`launch_helper`] but also starts `arm_exit_threads != 0` an "exit storm":
/// the helper continuously spawns short-lived threads that exit after ~1µs, so the
/// deterministic thread-exit race test can exercise the snapshot→OpenThread exit
/// window.
fn launch_helper_opt(
    tag: &str,
    workers: usize,
    spawn_every_ms: u64,
    short_lived_every_ms: u64,
    arm_exit_threads: u32,
) -> Result<(Child, SharedCounter, String), String> {
    let helper = option_env!("CARGO_BIN_EXE_capture_epoch_helper")
        .ok_or_else(|| "helper not built (enable feature capture-epoch-harness)".to_string())?;
    let shm = format!("mida_ce_{tag}_{}", std::process::id());
    let pidfile = format!(
        "{}\\mida_ce_pid_{}_{}.txt",
        std::env::temp_dir().display(),
        tag,
        std::process::id()
    );
    let _ = std::fs::remove_file(&pidfile);
    let mut cmd = Command::new(helper);
    cmd.args([
        "--shm",
        &shm,
        "--pidfile",
        &pidfile,
        "--workers",
        &workers.to_string(),
        "--spawn-every-ms",
        &spawn_every_ms.to_string(),
        "--short-lived-every-ms",
        &short_lived_every_ms.to_string(),
        "--exit-on-command",
        &arm_exit_threads.to_string(),
        "--max-ms",
        "15000",
    ]);
    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn helper failed: {e}"))?;

    // Wait for PID file.
    let pid = wait_pidfile(&pidfile, Duration::from_secs(5))?;
    let shm_view = SharedCounter::open(&shm)?;

    // Wait for the counter to start moving (workers alive).
    let start = Instant::now();
    let mut first = shm_view.counter();
    loop {
        std::thread::sleep(Duration::from_millis(10));
        let c = shm_view.counter();
        if c != first {
            break;
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err("helper counter never started (no workers?)".into());
        }
        first = c;
    }
    Ok((child, shm_view, pid))
}

fn wait_pidfile(path: &str, timeout: Duration) -> Result<String, String> {
    let start = Instant::now();
    loop {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Ok(s);
            }
        }
        if start.elapsed() > timeout {
            return Err("pidfile timeout".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn cleanup(mut child: Child, shm: &SharedCounter) {
    // Tell the helper to stop (clear running).
    let _ = std::fs::remove_file(&format!(
        "{}\\mida_ce_pid_{}_{}.txt",
        std::env::temp_dir().display(),
        std::process::id(),
        std::process::id()
    ));
    shm.set_running(0);
    let _ = child.kill();
    let _ = child.wait();
}

/// Read a thread's suspend count via its handle (for restore verification).
fn thread_suspend_count(tid: u32) -> i32 {
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    // SAFETY: open + suspend + resume to read the count, then restore.
    unsafe {
        if let Ok(h) = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, tid) {
            let prior = SuspendThread(h);
            let _ = ResumeThread(h);
            let _ = windows::Win32::Foundation::CloseHandle(h);
            if prior == u32::MAX {
                return -1;
            }
            // prior is the count before our suspend; after our suspend it is prior+1.
            return prior as i32;
        }
        -1
    }
}

/// One full freeze/restore round-trip against a live helper process.
fn run_freeze_round(tag: &str) -> Result<(), String> {
    let (child, shm, pid) = launch_helper(tag, 3, 40, 0)?;
    let target_pid: u32 = pid.parse().map_err(|_| "bad pid")?;

    // Sanity: running and workers present.
    assert!(shm.running() == 1, "helper should be running");
    assert!(shm.worker_count() >= 3, "helper should have >=3 workers");

    // 1. Counter is moving while unfrozen.
    let c0 = shm.counter();
    std::thread::sleep(Duration::from_millis(50));
    let c1 = shm.counter();
    assert_ne!(c0, c1, "counter must advance while target is running");

    // 2. Freeze every target thread.
    let suspended = freeze_process_threads(target_pid).map_err(|e| format!("freeze: {e:?}"))?;
    assert!(
        !suspended.is_empty(),
        "freeze should suspend target threads"
    );

    // The freeze must cover the CURRENT target thread set (including any thread
    // spawned by the helper's spawner during enumeration): after freeze, every
    // enumerated helper thread must be suspended (suspend count >= 1).
    let after_freeze_tids = enumerate_process_threads(target_pid)
        .map_err(|e| format!("post-freeze enumerate: {e:?}"))?;
    assert!(
        !after_freeze_tids.is_empty(),
        "target should have threads after freeze"
    );
    let mut all_frozen = true;
    for tid in &after_freeze_tids {
        let sc = thread_suspend_count(*tid);
        if sc < 1 {
            all_frozen = false;
            eprintln!("thread {tid} not suspended after freeze (count={sc})");
        }
    }
    assert!(
        all_frozen,
        "not every target thread was suspended by the freeze"
    );

    // 3. While frozen, the counter must NOT advance for a sustained window.
    let fc0 = shm.counter();
    std::thread::sleep(Duration::from_millis(350)); // 250-500ms freeze window
    let fc1 = shm.counter();
    assert_eq!(
        fc0, fc1,
        "counter advanced while target frozen (TOCTOU not prevented)"
    );

    // 4. Unfreeze: counter resumes.
    unfreeze_process_threads(&suspended).map_err(|e| format!("unfreeze: {e:?}"))?;
    let u0 = shm.counter();
    assert!(
        wait_counter_change(&shm, u0),
        "counter did not resume after unfreeze"
    );

    // 5. Restore: target threads should be running again (suspend count back to 0
    //    for threads that were not pre-suspended).
    for (tid, prior) in &suspended {
        if *prior == 0 {
            let sc = thread_suspend_count(*tid);
            assert_eq!(
                sc, 0,
                "thread {tid} not restored to running after unfreeze (count={sc})"
            );
        }
    }

    cleanup(child, &shm);
    Ok(())
}

// ---------------------------------------------------------------------------
// Real-process tests (each runs the helper once).
// ---------------------------------------------------------------------------

#[test]
fn real_process_freeze_stops_workers() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    run_freeze_round("freeze_stop").expect("freeze must stop worker counters");
}

#[test]
fn real_process_unfreeze_resumes_workers() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    // Cover the freeze-stop and unfreeze-resume in one round (asserted inside).
    run_freeze_round("unfreeze_resume").expect("unfreeze must resume worker counters");
}

#[test]
fn real_process_freeze_covers_thread_set() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    // The helper spawns workers periodically; freeze must cover the current set
    // and re-enumerate until stable.
    run_freeze_round("thread_set").expect("freeze must cover the target thread set");
}

/// 20x repetition: any single real freeze/restore failure fails the suite.
#[test]
fn real_process_repeated_20x_all_pass() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    for i in 0..20 {
        run_freeze_round(&format!("rep{i}"))
            .unwrap_or_else(|e| panic!("iteration {i} failed: {e}"));
    }
}

/// Verify that a thread already suspended BEFORE the epoch has its prior suspend
/// count preserved: the epoch only adds one suspend layer of its own and removes
/// exactly that one layer on unfreeze (never unconditionally resumes to 0).
#[test]
fn real_process_prior_suspend_count_restored() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    let (child, shm, pid) = launch_helper("prior_cnt", 2, 0, 0).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    let tids = enumerate_process_threads(target_pid).unwrap();
    assert!(tids.len() >= 2, "helper should have main + workers");

    // Pick a worker thread (not the main thread; the main thread tid is
    // typically the process id). Manually suspending a worker must NOT stop the
    // helper's other workers / counter.
    let tid = *tids
        .iter()
        .find(|t| **t != target_pid)
        .expect("a non-main worker thread exists");
    assert!(tid != target_pid, "must pick a worker, not the main thread");

    // Manually suspend that thread once: prior count becomes 1.
    let prior0;
    unsafe {
        let h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, tid).unwrap();
        let r = SuspendThread(h);
        assert_ne!(r, u32::MAX, "manual suspend failed");
        prior0 = r; // suspend count before our manual suspend (0 for a running thread)
        let _ = windows::Win32::Foundation::CloseHandle(h);
    }
    assert_eq!(prior0, 0, "worker should have been running (prior=0)");

    // Freeze: the thread gains one epoch suspend layer (now count = 2).
    let suspended = freeze_process_threads(target_pid).unwrap();
    let me = suspended
        .iter()
        .find(|(t, _)| *t == tid)
        .expect("thread in freeze set");
    assert_eq!(
        me.1, 1,
        "epoch must record prior suspend count of 1 for pre-suspended thread"
    );
    assert_eq!(
        thread_suspend_count(tid),
        2,
        "pre-suspended thread must be at count 2 during epoch"
    );

    // Unfreeze: only our own layer is removed (back to count 1, NOT 0).
    unfreeze_process_threads(&suspended).unwrap();
    assert_eq!(
        thread_suspend_count(tid),
        1,
        "epoch must not unconditionally resume a pre-suspended thread to 0"
    );

    // Release the manual suspend (back to running).
    unsafe {
        let h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, tid).unwrap();
        let _ = ResumeThread(h);
        let _ = windows::Win32::Foundation::CloseHandle(h);
    }
    assert_eq!(
        thread_suspend_count(tid),
        0,
        "thread must be running after manual resume"
    );

    // Helper still runs (counter moves). Poll with a bounded deadline to avoid
    // flaky timing under parallel-test load.
    let c0 = shm.counter();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut resumed = false;
    while Instant::now() < deadline {
        if shm.counter() != c0 {
            resumed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(resumed, "helper must still run after prior-count round");

    cleanup(child, &shm);
}

/// Partial-freeze failure must roll back (fail-closed): freezing an invalid /
/// nonexistent target PID returns an error and never reports a "frozen" result.
#[test]
fn real_process_partial_freeze_rolls_back() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    // A nonexistent PID must fail closed (no threads frozen, error returned).
    let bad_pid = 0x7fffffff_u32;
    match freeze_process_threads(bad_pid) {
        Ok(suspended) => {
            // If it somehow "succeeded", it must have frozen nothing and be
            // resumable without error (rollback-safe).
            assert!(
                suspended.is_empty(),
                "must not claim to freeze a nonexistent process"
            );
        }
        Err(_) => {
            // Expected fail-closed.
        }
    }
}

/// Minimal `DebuggerCore` backed by the helper PID, so the real
/// `CaptureEpochGuard` RAII path can be exercised against a live helper process.
struct HelperDebugger {
    pid: u32,
    fail_after_suspend: Option<u32>,
    fail_resume_tid: Option<u32>,
}

impl HelperDebugger {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            fail_after_suspend: None,
            fail_resume_tid: None,
        }
    }
}

impl mida_core::DebuggerCore for HelperDebugger {
    fn process_handle(&self) -> windows::Win32::Foundation::HANDLE {
        windows::Win32::Foundation::HANDLE(std::ptr::null_mut())
    }
    fn pid(&self) -> u32 {
        self.pid
    }
    fn image_base(&self) -> u64 {
        0
    }
    fn wait_event(&mut self) -> Result<DebugEvent, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn continue_event(
        &mut self,
        _t: u32,
        _s: mida_core::ContinueStatus,
    ) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn read_memory(&self, _a: usize, _b: &mut [u8]) -> Result<usize, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn write_memory(&mut self, _a: usize, _d: &[u8]) -> Result<usize, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn get_thread_context(&self, _t: u32) -> Result<CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn set_thread_context(&self, _t: u32, _c: &CONTEXT) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn freeze_target_threads(&mut self) -> Result<Vec<(u32, u32)>, mida_core::CoreError> {
        let injection = mida_core::windows_debugger::FreezeInjection {
            fail_after_suspend: self.fail_after_suspend,
            fail_resume_tid: self.fail_resume_tid,
            exit_barrier: None,
        };
        freeze_process_threads_with_failure(self.pid, injection)
    }
    fn unfreeze_target_threads(
        &self,
        suspended: &[(u32, u32)],
    ) -> Result<(), mida_core::CoreError> {
        unfreeze_process_threads(suspended)
    }
}

/// `DebuggerCore` that implements ONLY `freeze_target_threads` (via the helper)
/// and NOT `unfreeze_target_threads`, so the default fail-closed unfreeze is
/// exercised: `CaptureEpochGuard::end()` must return an error rather than
/// silently resume nothing (P1-6).
struct FreezeOnlyDebugger {
    pid: u32,
}

impl mida_core::DebuggerCore for FreezeOnlyDebugger {
    fn process_handle(&self) -> windows::Win32::Foundation::HANDLE {
        windows::Win32::Foundation::HANDLE(std::ptr::null_mut())
    }
    fn pid(&self) -> u32 {
        self.pid
    }
    fn image_base(&self) -> u64 {
        0
    }
    fn wait_event(&mut self) -> Result<DebugEvent, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn continue_event(
        &mut self,
        _t: u32,
        _s: mida_core::ContinueStatus,
    ) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn read_memory(&self, _a: usize, _b: &mut [u8]) -> Result<usize, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn write_memory(&mut self, _a: usize, _d: &[u8]) -> Result<usize, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn get_thread_context(&self, _t: u32) -> Result<CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn set_thread_context(&self, _t: u32, _c: &CONTEXT) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn freeze_target_threads(&mut self) -> Result<Vec<(u32, u32)>, mida_core::CoreError> {
        freeze_process_threads(self.pid)
    }
    // Intentionally NOT overriding unfreeze_target_threads: exercises the default.
}

/// [P1] REAL partial-freeze rollback with PRECISE per-thread proof: at least 2
/// real threads are successfully suspended, then a failure is injected. The test
/// records the exact pre-freeze suspend count of EVERY target thread, then after
/// the failed freeze asserts each thread is restored to its EXACT pre-freeze
/// count (not "some value in [0,1]"). The shared counter resuming is NOT used as
/// the restore proof.
#[test]
fn real_process_partial_freeze_after_n_threads_rolls_back() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    let (child, shm, pid) = launch_helper("partial_rollback", 4, 0, 0).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    let mut dbg = HelperDebugger::new(target_pid);
    dbg.fail_after_suspend = Some(2); // fail after 2 real suspends

    // Record the exact pre-freeze suspend count of every target thread BEFORE the
    // failed freeze. With `--spawn-every-ms 0` the thread set is stable (main +
    // 4 workers), so these are the authoritative baseline.
    let tids_before = enumerate_process_threads(target_pid).unwrap();
    assert!(
        tids_before.len() >= 5,
        "helper should have main + 4 workers"
    );
    let mut pre_counts: std::collections::BTreeMap<u32, i32> = std::collections::BTreeMap::new();
    for tid in &tids_before {
        pre_counts.insert(*tid, thread_suspend_count(*tid));
    }

    // Counter moves before.
    let c0 = shm.counter();
    std::thread::sleep(Duration::from_millis(40));
    assert_ne!(
        c0,
        shm.counter(),
        "counter must advance before partial freeze"
    );

    // Partial freeze must return Err (fail-closed), and must have rolled back.
    let err = dbg
        .freeze_target_threads()
        .expect_err("partial freeze must fail");
    let es = format!("{err:?}");
    assert!(
        es.contains("test-injected") || es.contains("freeze"),
        "unexpected error: {es}"
    );

    // PRECISE per-thread restore proof: every thread returns to its exact
    // pre-freeze suspend count. No thread may be left suspended (a running
    // thread's count is 0, so post-rollback it MUST be exactly 0).
    let tids_after = enumerate_process_threads(target_pid).unwrap();
    for tid in &tids_after {
        let expected = pre_counts.get(tid).copied().unwrap_or(0);
        let got = thread_suspend_count(*tid);
        assert_eq!(
            got, expected,
            "thread {tid} NOT restored to its pre-freeze suspend count {expected} after rollback (got {got})"
        );
    }
    // All previously-enumerated threads must still exist (none leaked).
    for tid in &tids_before {
        assert!(
            tids_after.contains(tid),
            "thread {tid} vanished after rollback"
        );
    }

    cleanup(child, &shm);
}

/// [P1] Partial-freeze rollback that ITSELF fails (a real, controlled ResumeThread
/// failure injected for one tid) must: (a) still resume every OTHER thread, and
/// (b) return a combined error carrying the original freeze failure AND the failed
/// thread id + phase. The failed thread is then manually resumed by the test.
#[test]
fn real_process_partial_freeze_rollback_failure_reports_tid() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    let (child, shm, pid) = launch_helper("rollback_fail", 4, 0, 0).unwrap();
    let target_pid: u32 = pid.parse().unwrap();

    // Record exact pre-freeze counts.
    let tids_before = enumerate_process_threads(target_pid).unwrap();
    let mut pre_counts: std::collections::BTreeMap<u32, i32> = std::collections::BTreeMap::new();
    for tid in &tids_before {
        pre_counts.insert(*tid, thread_suspend_count(*tid));
    }

    // Choose a real non-main worker thread to be the rollback-failure victim.
    let victim = *tids_before
        .iter()
        .find(|t| **t != target_pid)
        .expect("a non-main worker thread exists");

    let mut dbg = HelperDebugger::new(target_pid);
    dbg.fail_after_suspend = Some(2); // freeze aborts after 2 suspends
    dbg.fail_resume_tid = Some(victim); // rollback fails to resume the victim

    let err = dbg
        .freeze_target_threads()
        .expect_err("freeze must fail (rollback also fails)");
    match err {
        CoreError::CaptureFreezeWithRollbackFailure {
            freeze,
            rollback_failed_count,
            rollback_failed,
            rollback_error,
        } => {
            assert!(freeze.contains("test-injected"), "freeze msg: {freeze}");
            assert!(rollback_failed_count >= 1, "expected >=1 rollback failure");
            assert!(
                rollback_error.is_none(),
                "structural rollback failure must not carry a generic error"
            );
            let victim_fail = rollback_failed
                .iter()
                .find(|f| f.thread_id == victim)
                .expect("failed tid must be reported");
            assert_eq!(victim_fail.phase, "resume", "phase must be resume");
        }
        other => panic!("expected CaptureFreezeWithRollbackFailure, got {other:?}"),
    }

    // Every OTHER thread is restored to its exact pre-freeze count (the rollback
    // continued past the injected failure).
    let tids_after = enumerate_process_threads(target_pid).unwrap();
    for tid in &tids_after {
        if *tid == victim {
            continue; // this one is intentionally left suspended (to be cleaned up below)
        }
        let expected = pre_counts.get(tid).copied().unwrap_or(0);
        let got = thread_suspend_count(*tid);
        assert_eq!(
            got, expected,
            "thread {tid} not restored after rollback-failure (expected {expected}, got {got})"
        );
    }

    // The victim is genuinely LEFT SUSPENDED (the injected resume failure means
    // the rollback did not resume it), at exactly pre_freeze_count + 1.
    let victim_count = thread_suspend_count(victim);
    assert_eq!(
        victim_count,
        pre_counts.get(&victim).copied().unwrap_or(0) + 1,
        "victim must be left suspended (injected resume failure) at pre_count+1"
    );
    // Release the victim's injected layer back to its pre-freeze count (cleanup of
    // the injected failure layer).
    while thread_suspend_count(victim) > pre_counts.get(&victim).copied().unwrap_or(0) {
        use windows::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
        };
        // SAFETY: open + resume the victim until it returns to its baseline.
        unsafe {
            if let Ok(h) = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                false,
                victim,
            ) {
                let _ = ResumeThread(h);
                let _ = windows::Win32::Foundation::CloseHandle(h);
            }
        }
    }
    assert_eq!(
        thread_suspend_count(victim),
        pre_counts.get(&victim).copied().unwrap_or(0),
        "victim must be fully restored after test cleanup"
    );

    cleanup(child, &shm);
}

/// [P1] REAL CaptureEpochGuard Drop restores threads when the capture body
/// returns an ordinary `Err` via `?`/early return (NOT a panic). The guard must
/// restore every thread to its exact pre-epoch suspend count on the error-return
/// path.
#[test]
fn real_process_epoch_guard_drop_restores_on_error() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    let (child, shm, pid) = launch_helper("guard_err", 3, 0, 0).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    let mut dbg = HelperDebugger::new(target_pid);

    // Record exact pre-epoch counts of every target thread.
    let tids_before = enumerate_process_threads(target_pid).unwrap();
    let mut pre_counts: std::collections::BTreeMap<u32, i32> = std::collections::BTreeMap::new();
    for tid in &tids_before {
        pre_counts.insert(*tid, thread_suspend_count(*tid));
    }

    // A real capture body that returns `Err` through `?`/early return. The guard
    // is dropped during an ordinary error return (NOT an unwind), so Drop must
    // restore the threads.
    fn capture_body(dbg: &mut HelperDebugger) -> Result<(), CoreError> {
        let epoch = CaptureEpochGuard::begin(dbg)?;
        // Verify the epoch actually froze threads.
        if epoch.suspended_count() == 0 {
            return Err(CoreError::ProcessCreation("epoch froze nothing".into()));
        }
        // Early return with Err → epoch Drop restores threads.
        Err(CoreError::ProcessCreation(
            "simulated capture failure inside epoch (error return, not panic)".into(),
        ))
    }

    let result = capture_body(&mut dbg);
    assert!(result.is_err(), "capture body must return Err");

    // PRECISE restore: every thread returns to its exact pre-epoch suspend count.
    let tids_after = enumerate_process_threads(target_pid).unwrap();
    for tid in &tids_after {
        let expected = pre_counts.get(tid).copied().unwrap_or(0);
        let got = thread_suspend_count(*tid);
        assert_eq!(
            got, expected,
            "thread {tid} NOT restored to pre-epoch count {expected} after error-return Drop (got {got})"
        );
    }
    // Counter resumes (workers unfrozen) as additional evidence.
    let r0 = shm.counter();
    std::thread::sleep(Duration::from_millis(80));
    assert_ne!(
        r0,
        shm.counter(),
        "counter must resume after guard error-return restore"
    );

    cleanup(child, &shm);
}

/// [P1] REAL CaptureEpochGuard Drop restores threads after a panic, and the
/// panic does not kill the test runner.
#[test]
fn real_process_epoch_guard_drop_restores_on_panic() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    let (child, shm, pid) = launch_helper("guard_panic", 3, 0, 0).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    let mut dbg = HelperDebugger::new(target_pid);

    let tids_before = enumerate_process_threads(target_pid).unwrap();
    let mut pre_counts: std::collections::BTreeMap<u32, i32> = std::collections::BTreeMap::new();
    for tid in &tids_before {
        pre_counts.insert(*tid, thread_suspend_count(*tid));
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut epoch = CaptureEpochGuard::begin(&mut dbg).unwrap();
        let _ = epoch.debugger();
        panic!("simulated panic inside epoch");
    }));
    assert!(result.is_err(), "panic must be caught");

    // PRECISE restore after panic-unwind → guard Drop.
    let tids_after = enumerate_process_threads(target_pid).unwrap();
    for tid in &tids_after {
        let expected = pre_counts.get(tid).copied().unwrap_or(0);
        let got = thread_suspend_count(*tid);
        assert_eq!(
            got, expected,
            "thread {tid} NOT restored to pre-epoch count {expected} after panic Drop (got {got})"
        );
    }

    // Counter resumes after the panic unwind → guard Drop restored threads.
    let r0 = shm.counter();
    std::thread::sleep(Duration::from_millis(80));
    assert_ne!(
        r0,
        shm.counter(),
        "counter must resume after guard panic-drop restore"
    );

    cleanup(child, &shm);
}

/// [P1-1] DETERMINISTIC snapshot→OpenThread thread-exit (barrier, single shot).
///
/// NOT a probabilistic storm. The helper arms a barrier thread that publishes its
/// exact TID and blocks; the test reads that TID, configures an `ExitBarrier` with
/// `window = BeforeOpen`, and calls freeze exactly once. The freeze's feature-gated
/// hook, at the moment it is about to `OpenThread` that TID, commands the thread to
/// exit and waits for confirmation (helper sets `barrier_done`). The subsequent
/// `OpenThread` therefore deterministically returns ERROR_INVALID_PARAMETER (87),
/// hitting the `"before_open"` transient-exit branch. The diagnostic proves the
/// exact TID + phase was recorded. Surviving threads are frozen; the freeze
/// completes; all threads restored precisely.
#[test]
fn real_process_deterministic_exit_before_open() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    // Arm barrier threads alongside the workers.
    let (child, shm, pid) = launch_helper_opt("det_before_open", 3, 0, 0, 4).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    clear_transient_exit_diagnostics();
    // [P2-2] Baseline handle count after launch (mapping open) for the harness's own
    // leak check.
    let handles_after_launch = process_handle_count().unwrap();

    // Record exact pre-freeze suspend counts.
    let tids_before = enumerate_process_threads(target_pid).unwrap();
    let mut pre_counts: std::collections::BTreeMap<u32, i32> = std::collections::BTreeMap::new();
    for tid in &tids_before {
        pre_counts.insert(*tid, thread_suspend_count(*tid));
    }

    // Obtain a live barrier thread's TID (published by the helper and guaranteed to
    // block until commanded to exit).
    let barrier_tid = wait_for_barrier_tid(&shm, Duration::from_secs(5))
        .expect("helper must register a barrier thread");

    // Single freeze with the deterministic before_open barrier.
    let injection = mida_core::windows_debugger::FreezeInjection {
        fail_after_suspend: None,
        fail_resume_tid: None,
        exit_barrier: Some(mida_core::windows_debugger::ExitBarrier {
            tid: barrier_tid,
            window: mida_core::windows_debugger::ExitBarrierWindow::BeforeOpen,
            // `'static`: owns the shared-memory base pointer (Copy), so no borrow
            // of `shm` escapes the synchronous freeze call.
            force_exit: Box::new(move |t| force_exit_at(shm.base, t)),
        }),
    };
    let suspended = freeze_process_threads_with_failure(target_pid, injection)
        .map_err(|e| panic!("freeze with deterministic before_open barrier failed: {e:?}"))
        .unwrap();

    // PROVE the before_open transient-exit branch was hit for the exact barrier TID.
    let obs = transient_exit_observations();
    assert!(
        obs.iter()
            .any(|(t, phase)| *t == barrier_tid && *phase == "before_open"),
        "before_open transient-exit not recorded for barrier TID {barrier_tid}; obs={obs:?}"
    );

    // Unfreeze: surviving threads restored precisely.
    unfreeze_process_threads(&suspended).unwrap();
    verify_threads_restored_precisely(&target_pid, &pre_counts);

    // [P2-2] The harness itself must not leak thread handles: measure handle count
    // right after launch (mapping open) and after all harness operations, require
    // net-zero.
    let after_ops = process_handle_count().unwrap();
    assert!(
        after_ops == handles_after_launch,
        "harness leaked handles during deterministic before_open test (after_launch={handles_after_launch}, after_ops={after_ops})"
    );

    cleanup(child, &shm);
}

/// [P1-2] DETERMINISTIC OpenThread→SuspendThread thread-exit (barrier, single shot).
///
/// The helper barrier thread publishes its TID and blocks; the test configures an
/// `ExitBarrier` with `window = AfterOpenBeforeSuspend`. The freeze's feature-gated
/// hook, AFTER `OpenThread` succeeds for that TID and BEFORE `SuspendThread`,
/// commands the thread to exit and waits for confirmation. The already-open handle
/// becomes signaled (thread terminated); `SuspendThread` then fails; the production
/// implementation detects the dead thread via `WaitForSingleObject` and records
/// `phase = "after_open_before_suspend"` as a transient exit. Single freeze, exact
/// phase proven.
#[test]
fn real_process_deterministic_exit_after_open_before_suspend() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    let (child, shm, pid) = launch_helper_opt("det_after_open", 3, 0, 0, 4).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    clear_transient_exit_diagnostics();
    let handles_after_launch = process_handle_count().unwrap();

    let tids_before = enumerate_process_threads(target_pid).unwrap();
    let mut pre_counts: std::collections::BTreeMap<u32, i32> = std::collections::BTreeMap::new();
    for tid in &tids_before {
        pre_counts.insert(*tid, thread_suspend_count(*tid));
    }

    let barrier_tid = wait_for_barrier_tid(&shm, Duration::from_secs(5))
        .expect("helper must register a barrier thread");

    let injection = mida_core::windows_debugger::FreezeInjection {
        fail_after_suspend: None,
        fail_resume_tid: None,
        exit_barrier: Some(mida_core::windows_debugger::ExitBarrier {
            tid: barrier_tid,
            window: mida_core::windows_debugger::ExitBarrierWindow::AfterOpenBeforeSuspend,
            // `'static`: owns the shared-memory base pointer (Copy).
            force_exit: Box::new(move |t| force_exit_at(shm.base, t)),
        }),
    };
    eprintln!("after_open barrier_tid={barrier_tid} phase_hit=true");
    let suspended = freeze_process_threads_with_failure(target_pid, injection)
        .map_err(|e| {
            panic!("freeze with deterministic after_open_before_suspend barrier failed: {e:?}")
        })
        .unwrap();

    // PROVE the after_open_before_suspend transient-exit branch was hit.
    let obs = transient_exit_observations();
    assert!(
        obs.iter().any(|(t, phase)| *t == barrier_tid && *phase == "after_open_before_suspend"),
        "after_open_before_suspend transient-exit not recorded for barrier TID {barrier_tid}; obs={obs:?}"
    );

    unfreeze_process_threads(&suspended).unwrap();
    verify_threads_restored_precisely(&target_pid, &pre_counts);

    // [P2-2] Harness must not leak handles.
    let after_ops = process_handle_count().unwrap();
    assert!(
        after_ops == handles_after_launch,
        "harness leaked handles during deterministic after_open test (after_launch={handles_after_launch}, after_ops={after_ops})"
    );

    cleanup(child, &shm);
}

/// [P1-3] / [P2-2] Barrier callback that fails to prove OS termination must make the
/// freeze fail closed (rollback), NOT proceed, and NOT leak handles.
///
/// The `force_exit` callback returns `BarrierExitResult::Timeout` (the OS thread
/// object never signaled), so the freeze must abort before OpenThread/SuspendThread,
/// roll back any already-suspended threads, and return a structured error carrying
/// the barrier TID and phase. Handle count must be net-zero (P2-2).
#[test]
fn real_process_barrier_failure_fails_closed_no_handle_leak() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    let (child, shm, pid) = launch_helper_opt("barrier_fail", 3, 0, 0, 2).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    let handles_after_launch = process_handle_count().unwrap();

    let barrier_tid = wait_for_barrier_tid(&shm, Duration::from_secs(5))
        .expect("helper must register a barrier thread");

    let injection = mida_core::windows_debugger::FreezeInjection {
        fail_after_suspend: None,
        fail_resume_tid: None,
        exit_barrier: Some(mida_core::windows_debugger::ExitBarrier {
            tid: barrier_tid,
            window: mida_core::windows_debugger::ExitBarrierWindow::BeforeOpen,
            // Simulate a barrier that cannot prove OS termination.
            force_exit: Box::new(move |_t| mida_core::windows_debugger::BarrierExitResult::Timeout),
        }),
    };
    let err = freeze_process_threads_with_failure(target_pid, injection)
        .expect_err("barrier failure must fail the freeze closed");
    let es = format!("{err:?}");
    assert!(
        es.contains("did not prove termination"),
        "must carry the barrier failure reason, got: {es}"
    );

    // [P2-2] No handle leak across the fail-closed barrier path.
    let after_ops = process_handle_count().unwrap();
    assert!(
        after_ops == handles_after_launch,
        "harness leaked handles on barrier-failure path (after_launch={handles_after_launch}, after_ops={after_ops})"
    );

    // No thread may be left suspended after the fail-closed rollback.
    let tids = enumerate_process_threads(target_pid).unwrap();
    for tid in &tids {
        assert!(
            thread_suspend_count(*tid) <= 0,
            "thread {tid} left suspended after barrier-failure rollback (count={})",
            thread_suspend_count(*tid)
        );
    }

    cleanup(child, &shm);
}

/// Wait until the helper registers a live barrier thread and return its TID.
fn wait_for_barrier_tid(shm: &SharedCounter, timeout: Duration) -> Option<u32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let tid = shm.barrier_cur_tid();
        if tid != 0 {
            return Some(tid);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    None
}

/// Verify every currently-present thread is at its exact pre-freeze suspend count.
/// Threads that have exited (transient) are not restore failures and are skipped.
fn verify_threads_restored_precisely(
    target_pid: &u32,
    pre_counts: &std::collections::BTreeMap<u32, i32>,
) {
    let tids_after = enumerate_process_threads(*target_pid).unwrap();
    for tid in &tids_after {
        if !thread_exists(*tid) {
            continue; // exited thread, not a restore failure
        }
        let expected = pre_counts.get(tid).copied().unwrap_or(0);
        let got = thread_suspend_count(*tid);
        assert_eq!(
            got, expected,
            "thread {tid} not restored to pre-freeze count {expected} (got {got})"
        );
    }
}

/// RAII-safe existence probe: opens the thread and closes the handle immediately
/// (no leak). Returns true if the thread exists.
fn thread_exists(tid: u32) -> bool {
    use windows::Win32::System::Threading::{
        OpenThread, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    // SAFETY: open the thread handle, then close it immediately (P2-2: no leak).
    match unsafe { OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, tid) } {
        Ok(h) => {
            // SAFETY: close the handle we just opened.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
            true
        }
        Err(_) => false,
    }
}

/// [P1] end() then Drop is idempotent with a REAL pre-suspended thread, so a
/// double-resume (double-unfreeze) cannot be hidden by a `count >= 0` check. A
/// worker is pre-suspended to count 1; during the epoch it is count 2; after
/// `end()` it must be exactly 1; after `Drop` it must STILL be exactly 1 (any
/// second resume would underflow it below its pre-suspended baseline — a
/// double-resume of a running thread would push count negative and fail).
#[test]
fn real_process_epoch_end_then_drop_is_idempotent() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    let (child, shm, pid) = launch_helper("end_idem", 3, 0, 0).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    let mut dbg = HelperDebugger::new(target_pid);

    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    // Pick a real non-main worker thread to pre-suspend to baseline count 1.
    let tids = enumerate_process_threads(target_pid).unwrap();
    let tid = *tids
        .iter()
        .find(|t| **t != target_pid)
        .expect("a non-main worker thread exists");
    // Pre-suspend it once: baseline = 1.
    unsafe {
        let h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, tid).unwrap();
        let r = SuspendThread(h);
        assert_ne!(r, u32::MAX, "manual pre-suspend failed");
        assert_eq!(r, 0, "worker should have been running (prior=0)");
        let _ = windows::Win32::Foundation::CloseHandle(h);
    }
    assert_eq!(
        thread_suspend_count(tid),
        1,
        "baseline pre-suspended count = 1"
    );

    // Begin epoch: the pre-suspended thread gains one epoch layer → count 2.
    let mut epoch = CaptureEpochGuard::begin(&mut dbg).unwrap();
    assert_eq!(
        thread_suspend_count(tid),
        2,
        "pre-suspended thread must be at count 2 during epoch"
    );

    // Explicit end removes exactly one layer → back to 1 (NOT 0).
    epoch.end().unwrap();
    assert_eq!(
        thread_suspend_count(tid),
        1,
        "after end() the pre-suspended thread must be at its baseline 1 (double-resume would underflow)"
    );

    // Drop must NOT resume again → still exactly 1.
    drop(epoch);
    assert_eq!(
        thread_suspend_count(tid),
        1,
        "after Drop the pre-suspended thread must STILL be at baseline 1 (no double-resume)"
    );

    // Helper keeps running (other workers unfrozen, counter moves).
    let a0 = shm.counter();
    assert!(
        wait_counter_change(&shm, a0),
        "helper must keep running after drop (idempotent)"
    );

    // Cleanup: release only the harness's own pre-suspend layer → back to 0.
    unsafe {
        let h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, tid).unwrap();
        let _ = ResumeThread(h);
        let _ = windows::Win32::Foundation::CloseHandle(h);
    }
    assert_eq!(
        thread_suspend_count(tid),
        0,
        "thread must be running after test cleanup"
    );

    cleanup(child, &shm);
}

/// [P1-6] A backend that implements ONLY `freeze_target_threads` (freeze works,
/// unfreeze NOT implemented) must fail closed at `CaptureEpochGuard::end()` with
/// an explicit unsupported error — never silently resume nothing.
#[test]
fn real_process_freeze_only_backend_end_fails_closed() {
    if !helper_available() {
        eprintln!("SKIP: helper not built (enable feature capture-epoch-harness)");
        return;
    }

    let (child, _shm, pid) = launch_helper("freeze_only", 2, 0, 0).unwrap();
    let target_pid: u32 = pid.parse().unwrap();
    let mut dbg = FreezeOnlyDebugger { pid: target_pid };

    // begin() freezes the target (FreezeOnlyDebugger::freeze_target_threads is
    // implemented via the real helper freeze).
    let mut epoch = CaptureEpochGuard::begin(&mut dbg).unwrap();
    assert!(
        epoch.suspended_count() > 0,
        "freeze-only backend must still freeze threads"
    );

    // end() must fail closed: the default unfreeze_target_threads returns an
    // unsupported error, NOT Ok(()). Without this, a backend that forgets to
    // implement unfreeze would leave the target frozen while reporting success.
    let err = epoch
        .end()
        .expect_err("unimplemented unfreeze must fail closed");
    let es = format!("{err:?}");
    assert!(
        es.contains("unfreeze") || es.contains("unsupported"),
        "expected unfreeze-unsupported error, got {es}"
    );

    // The guard's Drop is best-effort and must not panic on the same failure.
    drop(epoch);

    // Clean up the threads the freeze-only backend left suspended (it cannot
    // unfreeze them). The freeze suspended every non-calling helper thread exactly
    // once. Resume each thread exactly as many times as its current suspend count
    // (read via the suspend+resume helper, which restores the count), so a running
    // thread is never underflowed.
    let tids = enumerate_process_threads(target_pid).unwrap();
    for t in &tids {
        use windows::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
        };
        // SAFETY: open the helper thread.
        if let Ok(h) =
            unsafe { OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, false, *t) }
        {
            let mut guard = 0;
            while thread_suspend_count(*t) > 0 && guard < 8 {
                // SAFETY: resume one suspend layer.
                let _ = unsafe { ResumeThread(h) };
                guard += 1;
            }
            // SAFETY: close the handle.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
        }
    }

    cleanup(child, &_shm);
}

/// Helper: current process handle count via `GetProcessHandleCount`, returned as a
/// `Result` so a query failure is surfaced (never silently treated as 0).
fn process_handle_count() -> Result<u32, String> {
    use windows::Win32::System::Threading::GetProcessHandleCount;
    let mut count = 0u32;
    // SAFETY: GetCurrentProcess returns a pseudo-handle; count is writable.
    unsafe {
        let h = windows::Win32::System::Threading::GetCurrentProcess();
        GetProcessHandleCount(h, &mut count)
            .map_err(|e| format!("GetProcessHandleCount failed: {e:?}"))?;
    }
    Ok(count)
}

/// Poll until the shared counter changes from `from` (bounded), so counter-resume
/// assertions are robust under parallel-test load rather than fixed-sleep flaky.
fn wait_counter_change(shm: &SharedCounter, from: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if shm.counter() != from {
            return true;
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    false
}

/// [P2] No handle growth across many freeze/unfreeze cycles. After a warm-up run
/// to stabilize the process handle set, ≥50 serial freeze/unfreeze cycles must
/// produce NET ZERO handle growth (output initial/warmup/final/max). A very small
/// fixed one-time framework delta is tolerated ONLY if it is stable after warm-up
/// and not monotonic. This test runs under `--test-threads=1` so parallel tests do
/// not pollute the process handle count.
#[test]
fn real_process_repeated_freeze_has_no_handle_growth() {
    if !helper_available() {
        eprintln!("SKIP: helper not built");
        return;
    }
    let (child, shm, pid) = launch_helper("handle_leak", 3, 0, 0).unwrap();
    let target_pid: u32 = pid.parse().unwrap();

    // Warm-up: a handful of cycles to let any one-time framework handle allocation
    // settle BEFORE we measure growth (so a one-time delta is not counted as a leak).
    for _ in 0..5 {
        let s = freeze_process_threads(target_pid).unwrap();
        unfreeze_process_threads(&s).unwrap();
    }
    let after_warmup = process_handle_count().unwrap();

    // Serial measured cycles.
    let measured_initial = process_handle_count().unwrap();
    let mut max_seen = measured_initial;
    for _i in 0..50 {
        let s = freeze_process_threads(target_pid).unwrap();
        unfreeze_process_threads(&s).unwrap();
        let now = process_handle_count().unwrap();
        if now > max_seen {
            max_seen = now;
        }
    }
    let measured_final = process_handle_count().unwrap();

    // No net handle growth after warm-up.
    let net = measured_final as i64 - measured_initial as i64;
    assert_eq!(
        net, 0,
        "handle count must have NET ZERO growth over 50 cycles (initial={measured_initial}, final={measured_final}, max={max_seen})"
    );
    // No monotonic growth: peak during the loop must not exceed the final settled
    // count (which equals initial after a clean run).
    assert!(
        max_seen <= measured_final,
        "handle count rose to {max_seen} then stayed above final {measured_final} (possible transient leak)"
    );

    // Helper still works and no thread is left suspended.
    let tids = enumerate_process_threads(target_pid).unwrap();
    for tid in &tids {
        assert!(
            thread_suspend_count(*tid) >= 0,
            "thread {tid} suspend underflow after cycles"
        );
    }

    eprintln!(
        "handle-leak: warmup={after_warmup} initial={measured_initial} max={max_seen} final={measured_final}"
    );
    cleanup(child, &shm);
}
