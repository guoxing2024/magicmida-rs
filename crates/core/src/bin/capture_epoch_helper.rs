//! Route Z R0 AF2/AF3/AF4: benign helper process for real Windows capture-epoch
//! freeze/unfreeze verification.
//!
//! The helper exposes a shared (named) memory mapping containing:
//!   offset 0:  u64  `counter`          (incremented by every worker thread)
//!   offset 8:  u32  `running`          (1 = helper running, 0 = shutting down)
//!   offset 12: u32  `worker_count`     (number of active workers)
//!   offset 16: u32  `barrier_cur_tid`  (TID of a live barrier thread, or 0)
//!   offset 20: u32  `barrier_cmd_tid`  (TID the test commands to exit)
//!   offset 24: u32  `barrier_cmd_set`  (1 = a barrier command is armed)
//!
//! Worker threads increment the counter in a tight loop. A spawner thread
//! periodically creates a new worker (to exercise the thread-set race).
//!
//! `--exit-on-command N` arms N **barrier threads**: each publishes its TID to
//! `barrier_cur_tid`, then blocks until the test commands exactly that TID to exit
//! (writes `barrier_cmd_tid=X`, `barrier_cmd_set=1`). The matching barrier thread
//! then terminates. The HELPER does NOT claim termination — the harness proves the
//! OS thread object terminated via `WaitForSingleObject` on a `SYNCHRONIZE` handle
//! (Route Z R0 AF2 AF1 AF4 / P1-1), so a command acknowledgement is never conflated
//! with termination.
//!
//! The helper writes its PID to the given pidfile, then runs until `running` is
//! cleared (or a hard timeout).
//!
//! Usage:
//!   capture_epoch_helper --shm <mapping-name> --pidfile <path> --workers N [--spawn-every-ms M] [--short-lived-every-ms M] [--exit-on-command N] [--max-ms T]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

// Memory-mapped shared layout (must match the test).
const OFF_COUNTER: usize = 0;
const OFF_RUNNING: usize = 8;
const OFF_WORKER: usize = 12;
const OFF_BARRIER_CUR_TID: usize = 16;
const OFF_BARRIER_CMD_TID: usize = 20;
const OFF_BARRIER_CMD_SET: usize = 24;
const MAP_SIZE: usize = 32;

fn main() {
    let mut shm = None;
    let mut pidfile = None;
    let mut workers = 2usize;
    let mut spawn_every_ms = 250u64;
    let mut short_lived_every_ms = 0u64;
    let mut max_ms = 30000u64;
    let mut exit_on_command = 0u32;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--shm" => shm = args.next(),
            "--pidfile" => pidfile = args.next(),
            "--workers" => workers = args.next().and_then(|v| v.parse().ok()).unwrap_or(2),
            "--spawn-every-ms" => {
                spawn_every_ms = args.next().and_then(|v| v.parse().ok()).unwrap_or(250)
            }
            "--short-lived-every-ms" => {
                short_lived_every_ms = args.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            "--exit-on-command" => {
                exit_on_command = args.next().and_then(|v| v.parse().ok()).unwrap_or(0)
            }
            "--max-ms" => max_ms = args.next().and_then(|v| v.parse().ok()).unwrap_or(30000),
            _ => {}
        }
    }
    let Some(shm_name) = shm else {
        eprintln!("missing --shm");
        std::process::exit(2);
    };
    let Some(pidfile) = pidfile else {
        eprintln!("missing --pidfile");
        std::process::exit(2);
    };

    // Create a named shared memory mapping.
    // SAFETY: named file mapping, read/write, PAGE_READWRITE.
    let mapping = unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};
        let wide: Vec<u16> = shm_name.encode_utf16().chain(std::iter::once(0)).collect();
        let h = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_READWRITE,
            0,
            MAP_SIZE as u32,
            PCWSTR(wide.as_ptr()),
        )
        .unwrap_or(INVALID_HANDLE_VALUE);
        if h.is_invalid() {
            eprintln!("CreateFileMappingW failed");
            std::process::exit(3);
        }
        h
    };
    // SAFETY: map the full view read/write.
    let base = unsafe {
        use windows::Win32::System::Memory::MapViewOfFile;
        use windows::Win32::System::Memory::FILE_MAP_ALL_ACCESS;
        let p = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, MAP_SIZE as usize);
        if p.Value.is_null() {
            eprintln!("MapViewOfFile failed");
            std::process::exit(4);
        }
        p.Value as *mut u8
    };

    // Shared state (offsets in the mapping).
    let counter = unsafe { &mut *(base.add(OFF_COUNTER) as *mut u64) };
    let running = unsafe { &mut *(base.add(OFF_RUNNING) as *mut u32) };
    let worker = unsafe { &mut *(base.add(OFF_WORKER) as *mut u32) };
    let b_cur = unsafe { &mut *(base.add(OFF_BARRIER_CUR_TID) as *mut u32) };
    let b_cmd_tid = unsafe { &mut *(base.add(OFF_BARRIER_CMD_TID) as *mut u32) };
    let b_cmd_set = unsafe { &mut *(base.add(OFF_BARRIER_CMD_SET) as *mut u32) };
    *counter = 0;
    *running = 1;
    *worker = workers as u32;
    *b_cur = 0;
    *b_cmd_tid = 0;
    *b_cmd_set = 0;

    // Write PID.
    std::fs::write(&pidfile, format!("{}", std::process::id())).ok();

    // Shared atomic wrappers for the worker loops.
    let counter_atomic = unsafe { AtomicU64::from_ptr(counter) };
    let running_atomic = unsafe { AtomicU32::from_ptr(running) };
    let worker_atomic = unsafe { AtomicU32::from_ptr(worker) };
    let b_cur_atomic = unsafe { AtomicU32::from_ptr(b_cur) };
    let b_cmd_tid_atomic = unsafe { AtomicU32::from_ptr(b_cmd_tid) };
    let b_cmd_set_atomic = unsafe { AtomicU32::from_ptr(b_cmd_set) };

    // Barrier threads (deterministic transient-exit race): each publishes its TID,
    // then blocks until commanded to exit, then simply returns (terminates). The
    // HELPER does NOT claim termination — the harness proves the OS thread object
    // terminated via `WaitForSingleObject` on a `SYNCHRONIZE` handle, so a command
    // acknowledgement is never conflated with termination (Route Z R0 AF2 AF1 AF4 /
    // P1-1). A barrier thread is guaranteed alive when a ToolHelp snapshot observes
    // it, and terminates exactly when commanded.
    if exit_on_command > 0 {
        let run = Arc::new(running_atomic);
        let b_cur_a = Arc::new(b_cur_atomic);
        let b_cmd_tid_a = Arc::new(b_cmd_tid_atomic);
        let b_cmd_set_a = Arc::new(b_cmd_set_atomic);
        for _ in 0..exit_on_command {
            let run = Arc::clone(&run);
            let cur = Arc::clone(&b_cur_a);
            let cmd_tid = Arc::clone(&b_cmd_tid_a);
            let cmd_set = Arc::clone(&b_cmd_set_a);
            std::thread::spawn(move || {
                // SAFETY: GetCurrentThreadId returns this thread's id.
                let my_tid = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
                cur.store(my_tid, Ordering::SeqCst);
                // Block at the barrier until commanded to exit, or shutdown.
                while run.load(Ordering::SeqCst) == 1 {
                    if cmd_set.load(Ordering::SeqCst) == 1
                        && cmd_tid.load(Ordering::SeqCst) == my_tid
                    {
                        // Commanded: clear our published TID, then terminate. The
                        // harness confirms OS termination separately (SYNCHRONIZE
                        // handle + WaitForSingleObject).
                        cur.store(0, Ordering::SeqCst);
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_micros(50));
                }
            });
        }
    }

    // Spawn the initial workers.
    let workers_arc = Arc::new(worker_atomic);
    let run_arc = Arc::new(running_atomic);
    let cnt_arc = Arc::new(counter_atomic);
    for _ in 0..workers {
        let cnt = Arc::clone(&cnt_arc);
        let run = Arc::clone(&run_arc);
        let wc = Arc::clone(&workers_arc);
        std::thread::spawn(move || {
            let _ = &wc;
            while run.load(Ordering::SeqCst) == 1 {
                cnt.fetch_add(1, Ordering::SeqCst);
            }
        });
    }

    // Spawner thread: periodically create a new worker (thread-set race).
    if spawn_every_ms > 0 {
        let cnt = Arc::clone(&cnt_arc);
        let run = Arc::clone(&run_arc);
        let wc = Arc::clone(&workers_arc);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(spawn_every_ms));
            if run.load(Ordering::SeqCst) != 1 {
                break;
            }
            let cnt2 = Arc::clone(&cnt);
            let run2 = Arc::clone(&run);
            let wc2 = Arc::clone(&wc);
            std::thread::spawn(move || {
                let _ = &wc2;
                while run2.load(Ordering::SeqCst) == 1 {
                    cnt2.fetch_add(1, Ordering::SeqCst);
                }
            });
        });
    }

    // Short-lived thread spawner (thread-set churn, non-deterministic diagnostics
    // only): periodically create a thread that exits quickly. The DETERMINISTIC
    // transient-exit tests use the barrier threads above; this optional churn is
    // retained only for the survival/freeze-coverage test.
    if short_lived_every_ms > 0 {
        let run = Arc::clone(&run_arc);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(short_lived_every_ms));
            if run.load(Ordering::SeqCst) != 1 {
                break;
            }
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_micros(100));
            });
        });
    }

    // Run until `running` is cleared (by the test) or the hard timeout.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_ms);
    while running_atomic.load(Ordering::SeqCst) == 1 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }

    // Clean shutdown: clear running, unmap, close.
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Memory::{UnmapViewOfFile, MEMORY_MAPPED_VIEW_ADDRESS};
        let _ = UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
            Value: base as *mut std::ffi::c_void,
        });
        let _ = CloseHandle(mapping);
    }
}
