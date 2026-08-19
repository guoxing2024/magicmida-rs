// ADR7-B2 debugger-attach harness.
// Attaches to a target process (DebugActiveProcess), observes for a fixed
// window, records every exception event (code / first-chance / address /
// thread id), then detaches (DebugActiveProcessStop).
//
// Pure FFI (kernel32), same style as b1_benign_host_full.rs - compiled
// directly with rustc, no cargo deps.
//
// Usage: b2_debugger_attach <pid> [window_ms]

use std::ffi::c_void;
use std::os::raw::{c_int, c_uint, c_ulong};

#[repr(C)]
struct DebugEvent {
    debug_event_code: c_uint,
    process_id: c_ulong,
    thread_id: c_ulong,
    u: DebugEventUnion,
}

#[repr(C)]
union DebugEventUnion {
    exception: ExceptionDebugInfo,
    _pad: [u64; 24],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ExceptionDebugInfo {
    exception_record: ExceptionRecord,
    first_chance: c_uint,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ExceptionRecord {
    exception_code: c_uint,
    exception_flags: c_uint,
    exception_record_ptr: *mut ExceptionRecord,
    exception_address: *mut c_void,
    number_parameters: c_uint,
    _info: [u64; 15],
}

const EXCEPTION_DEBUG_EVENT: c_uint = 1;
const CREATE_PROCESS_DEBUG_EVENT: c_uint = 3;
const CREATE_THREAD_DEBUG_EVENT: c_uint = 2;
const EXIT_PROCESS_DEBUG_EVENT: c_uint = 5;
const LOAD_DLL_DEBUG_EVENT: c_uint = 6;
const UNLOAD_DLL_DEBUG_EVENT: c_uint = 7;
const OUTPUT_DEBUG_STRING_EVENT: c_uint = 8;
const RIP_EVENT: c_uint = 9;

const DBG_CONTINUE: c_uint = 0x00010002;
const DBG_EXCEPTION_NOT_HANDLED: c_uint = 0x80010001;

#[link(name = "kernel32")]
extern "system" {
    fn DebugActiveProcess(pid: c_ulong) -> c_int;
    fn DebugActiveProcessStop(pid: c_ulong) -> c_int;
    fn WaitForDebugEvent(lp_debug_event: *mut DebugEvent, dw_milliseconds: c_ulong) -> c_int;
    fn ContinueDebugEvent(
        dw_process_id: c_ulong,
        dw_thread_id: c_ulong,
        dw_continue_status: c_uint,
    ) -> c_int;
    fn GetTickCount64() -> u64;
    fn GetCurrentProcessId() -> c_ulong;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pid: u32 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .expect("usage: b2_debugger_attach <pid> [window_ms]");
    let window_ms: u32 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);

    println!("B2_ATTACH_START pid={} window_ms={} debugger_pid={}", pid, window_ms, unsafe { GetCurrentProcessId() });

    let rc = unsafe { DebugActiveProcess(pid as c_ulong) };
    if rc == 0 {
        println!("B2_ATTACH_FAILED pid={} err=DebugActiveProcess returned 0", pid);
        std::process::exit(1);
    }
    println!("B2_ATTACHED pid={}", pid);

    let start = unsafe { GetTickCount64() };
    let mut events: u32 = 0;
    let mut exceptions: Vec<String> = Vec::new();
    let mut dll_loads: u32 = 0;
    let mut exit_seen = false;

    loop {
        let now = unsafe { GetTickCount64() };
        if now.wrapping_sub(start) >= window_ms as u64 {
            println!("B2_WINDOW_END elapsed_ms={}", now.wrapping_sub(start));
            break;
        }
        let mut ev: DebugEvent = unsafe { std::mem::zeroed() };
        let wait = (window_ms as u64).saturating_sub(now.wrapping_sub(start)).min(500) as c_ulong;
        let wr = unsafe { WaitForDebugEvent(&mut ev, wait) };
        if wr == 0 {
            continue;
        }
        events += 1;
        match ev.debug_event_code {
            EXCEPTION_DEBUG_EVENT => {
                let code = unsafe { ev.u.exception.exception_record.exception_code };
                let first = unsafe { ev.u.exception.first_chance };
                let addr = unsafe { ev.u.exception.exception_record.exception_address } as u64;
                let tid = ev.thread_id;
                println!(
                    "B2_EXCEPTION pid={} tid={} code=0x{:08x} first_chance={} address=0x{:x}",
                    ev.process_id, tid, code, if first != 0 { 1 } else { 0 }, addr
                );
                exceptions.push(format!(
                    r#"{{"code":"0x{:08x}","first_chance":{},"address":"0x{:x}","thread_id":{}}}"#,
                    code, if first != 0 { 1 } else { 0 }, addr, tid
                ));
                unsafe {
                    ContinueDebugEvent(ev.process_id, ev.thread_id, DBG_EXCEPTION_NOT_HANDLED);
                }
            }
            CREATE_PROCESS_DEBUG_EVENT => {
                println!("B2_CREATE_PROCESS pid={} tid={}", ev.process_id, ev.thread_id);
                unsafe { ContinueDebugEvent(ev.process_id, ev.thread_id, DBG_CONTINUE) };
            }
            CREATE_THREAD_DEBUG_EVENT => {
                unsafe { ContinueDebugEvent(ev.process_id, ev.thread_id, DBG_CONTINUE) };
            }
            LOAD_DLL_DEBUG_EVENT => {
                dll_loads += 1;
                unsafe { ContinueDebugEvent(ev.process_id, ev.thread_id, DBG_CONTINUE) };
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                unsafe { ContinueDebugEvent(ev.process_id, ev.thread_id, DBG_CONTINUE) };
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                println!("B2_EXIT_PROCESS pid={} tid={}", ev.process_id, ev.thread_id);
                exit_seen = true;
                unsafe { ContinueDebugEvent(ev.process_id, ev.thread_id, DBG_CONTINUE) };
                break;
            }
            OUTPUT_DEBUG_STRING_EVENT | RIP_EVENT => {
                unsafe { ContinueDebugEvent(ev.process_id, ev.thread_id, DBG_CONTINUE) };
            }
            _ => {
                unsafe { ContinueDebugEvent(ev.process_id, ev.thread_id, DBG_CONTINUE) };
            }
        }
    }

    let drc = unsafe { DebugActiveProcessStop(pid as c_ulong) };
    let elapsed = unsafe { GetTickCount64() }.wrapping_sub(start);
    println!(
        "B2_DETACH pid={} rc={} elapsed_ms={} events={} dll_loads={} exit_seen={}",
        pid, drc, elapsed, events, dll_loads, if exit_seen { 1 } else { 0 }
    );

    let exception_0xc0000409 = exceptions.iter().any(|e| e.contains("0xc0000409"));
    let mut json = String::from(r#"{ "attached": true"#);
    json.push_str(&format!(r#", "pid": {}"#, pid));
    json.push_str(&format!(r#", "window_ms": {}"#, window_ms));
    json.push_str(&format!(r#", "elapsed_ms": {}"#, elapsed));
    json.push_str(&format!(r#", "events": {}"#, events));
    json.push_str(&format!(r#", "dll_loads": {}"#, dll_loads));
    json.push_str(&format!(r#", "exit_seen": {}"#, if exit_seen { 1 } else { 0 }));
    json.push_str(&format!(r#", "exception_0xc0000409": {}"#, if exception_0xc0000409 { 1 } else { 0 }));
    json.push_str(&format!(r#", "exceptions": [{}] }}"#, exceptions.join(",")));
    println!("B2_JSON={}", json);
    println!("B2_END");
}
