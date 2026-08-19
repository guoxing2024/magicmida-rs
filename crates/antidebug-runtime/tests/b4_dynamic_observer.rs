// ADR7-B4 dynamic-instrumentation observer harness (debugger-side recorder).
//
// Attaches to a target process (DebugActiveProcess), observes the debug
// event stream, and records:
//   - module loads (runtime DLL base for RVA mapping),
//   - hardware-breakpoint observation points (DR0-DR3) installed at the
//     ADR7-B3 static RVAs after the runtime DLL is seen,
//   - every exception (code / first-chance / address / thread id),
//   - int29 site matching against the static table,
//   - post-exception RIP/RSP (GetThreadContext),
//   - continuation decision per event.
//
// Pure FFI (kernel32), no cargo deps - compiled directly with rustc, same
// style as b2_debugger_attach.rs.
//
// The observer NEVER modifies the target image, NEVER writes into the runtime
// DLL, and forwards unknown exceptions with DBG_EXCEPTION_NOT_HANDLED
// (fail-closed: 0xc0000409 is never swallowed).
//
// Usage: b4_dynamic_observer <pid> [window_ms] [timeline_out]

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
    load_dll: LoadDllDebugInfo,
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

#[derive(Clone, Copy)]
#[repr(C)]
struct LoadDllDebugInfo {
    h_file: *mut c_void,
    base_of_dll: *mut c_void,
    debug_info_file_offset: c_uint,
    debug_info_size: c_uint,
    _name_ptr: *mut c_void,
}

#[repr(C)]
struct MemoryBasicInformation {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: c_uint,
    _partition_id: u16,
    region_size: usize,
    state: c_uint,
    protect: c_uint,
    type_: c_uint,
}

#[repr(C)]
struct Context {
    p1_home: u64,
    p2_home: u64,
    p3_home: u64,
    p4_home: u64,
    p5_home: u64,
    p6_home: u64,
    context_flags: c_uint,
    mx_csr: c_uint,
    seg_cs: u16,
    seg_ds: u16,
    seg_es: u16,
    seg_fs: u16,
    seg_gs: u16,
    seg_ss: u16,
    e_flags: c_uint,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u64,
    dr7: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rsp: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
}

const EXCEPTION_DEBUG_EVENT: c_uint = 1;
const CREATE_THREAD_DEBUG_EVENT: c_uint = 2;
const CREATE_PROCESS_DEBUG_EVENT: c_uint = 3;
const EXIT_THREAD_DEBUG_EVENT: c_uint = 4;
const EXIT_PROCESS_DEBUG_EVENT: c_uint = 5;
const LOAD_DLL_DEBUG_EVENT: c_uint = 6;
const UNLOAD_DLL_DEBUG_EVENT: c_uint = 7;
const OUTPUT_DEBUG_STRING_EVENT: c_uint = 8;
const RIP_EVENT: c_uint = 9;

const DBG_CONTINUE: c_uint = 0x00010002;
const DBG_EXCEPTION_NOT_HANDLED: c_uint = 0x80010001;
const EXCEPTION_BREAKPOINT: c_uint = 0x80000003;
const EXCEPTION_SINGLE_STEP: c_uint = 0x80000004;
const EXCEPTION_FAST_FAIL: c_uint = 0xC0000409;
#[allow(dead_code)]
const _EXCEPTION_FAST_FAIL_REF: c_uint = EXCEPTION_FAST_FAIL;

const MEM_IMAGE: c_uint = 0x1000000;
const CONTEXT_DEBUG_REGISTERS_AMD64: c_uint = 0x00000010;
const CONTEXT_CONTROL_AMD64: c_uint = 0x00000001;
const THREAD_GET_CONTEXT: c_uint = 0x0008;

// ADR7-B4-RUNTIME-BINDING-CORRECTION-1: observation points bound to the
// EXACT runtime artifact sha256 AE42901E... (mida_antidebug_runtime.dll,
// 370,688 B; see crates/core/src/b4_runtime_offset_map.json).
// Extracted via cdb (PDB symbols) + dumpbin (disassembly).
const OBS_POINTS: [(u32, &str); 4] = [
    (0x2eda0, "panic_count::increase entry"),
    (0x2edc6, "panic_count::increase+0x26 (TLS check jne)"),
    (0x2e604, "panic_with_hook entry"),
    (0x2e638, "panic_with_hook -> panic_count::increase call site"),
];

const INT29_SITES: [u32; 9] = [
    0x2bfc1, 0x2c366, 0x2c599, 0x2c759, 0x2d070, 0x2e7e8, 0x2e816, 0x3f32c, 0x3fab7,
];

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
    fn OpenProcess(
        dw_desired_access: c_uint,
        b_inherit_handle: c_int,
        dw_process_id: c_ulong,
    ) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> c_int;
    fn VirtualQueryEx(
        h_process: *mut c_void,
        lp_address: *const c_void,
        lp_buffer: *mut MemoryBasicInformation,
        dw_length: usize,
    ) -> usize;
    fn OpenThread(
        dw_desired_access: c_uint,
        b_inherit_handle: c_int,
        dw_thread_id: c_ulong,
    ) -> *mut c_void;
    fn GetThreadContext(h_thread: *mut c_void, lp_context: *mut Context) -> c_int;
    fn SetThreadContext(h_thread: *mut c_void, lp_context: *const Context) -> c_int;
}

#[link(name = "psapi")]
extern "system" {
    fn GetMappedFileNameW(
        h_process: *mut c_void,
        lpv: *const c_void,
        lp_filename: *mut u16,
        n_size: c_uint,
    ) -> c_uint;
}

fn module_name_for(proc_handle: *mut c_void, addr: u64) -> Option<String> {
    unsafe {
        let mut mbi: MemoryBasicInformation = std::mem::zeroed();
        let n = VirtualQueryEx(
            proc_handle,
            addr as *const c_void,
            &mut mbi,
            std::mem::size_of::<MemoryBasicInformation>(),
        );
        if n == 0 || mbi.type_ != MEM_IMAGE || mbi.allocation_base.is_null() {
            return None;
        }
        let mut buf = [0u16; 512];
        let r = GetMappedFileNameW(
            proc_handle,
            mbi.allocation_base,
            buf.as_mut_ptr(),
            buf.len() as c_uint,
        );
        if r == 0 {
            return None;
        }
        let name = String::from_utf16_lossy(&buf[..r as usize]);
        let base = name.rsplit('\\').next().unwrap_or(&name).to_string();
        Some(base)
    }
}

fn set_hw_breakpoints(_proc_handle: *mut c_void, tid: u32, runtime_base: u64) {
    unsafe {
        let h = OpenThread(THREAD_GET_CONTEXT, 0, tid as c_ulong);
        if h.is_null() {
            return;
        }
        let mut ctx: Context = std::mem::zeroed();
        ctx.context_flags = CONTEXT_DEBUG_REGISTERS_AMD64 | CONTEXT_CONTROL_AMD64;
        if GetThreadContext(h, &mut ctx) == 0 {
            CloseHandle(h);
            return;
        }
        for (i, (rva, _)) in OBS_POINTS.iter().enumerate() {
            let va = runtime_base + *rva as u64;
            match i {
                0 => ctx.dr0 = va,
                1 => ctx.dr1 = va,
                2 => ctx.dr2 = va,
                3 => ctx.dr3 = va,
                _ => {}
            }
        }
        // DR7: local enable (bit 0/2/4/6) + execute type (RW=00, LEN=00)
        // bits 16-17, 20-21, 24-25, 28-29.
        ctx.dr7 = 0x0000_0000_0000_0001 | (1 << 2) | (1 << 4) | (1 << 6);
        SetThreadContext(h, &ctx);
        CloseHandle(h);
    }
}

fn read_rip_rsp(_proc_handle: *mut c_void, tid: u32) -> (Option<u64>, Option<u64>) {
    unsafe {
        let h = OpenThread(THREAD_GET_CONTEXT, 0, tid as c_ulong);
        if h.is_null() {
            return (None, None);
        }
        let mut ctx: Context = std::mem::zeroed();
        ctx.context_flags = CONTEXT_CONTROL_AMD64;
        if GetThreadContext(h, &mut ctx) == 0 {
            CloseHandle(h);
            return (None, None);
        }
        let rip = ctx.rip;
        let rsp = ctx.rsp;
        CloseHandle(h);
        (Some(rip), Some(rsp))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pid: u32 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .expect("usage: b4_dynamic_observer <pid> [window_ms] [timeline_out]");
    let window_ms: u32 = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8000);
    let timeline_out = args.get(3).cloned().unwrap_or_else(|| "b4_timeline.json".to_string());

    println!(
        "B4_OBS_START pid={} window_ms={} debugger_pid={} timeline={}",
        pid,
        window_ms,
        unsafe { GetCurrentProcessId() },
        timeline_out
    );

    let proc_handle = unsafe {
        OpenProcess(0x1FFFFF, 0, pid as c_ulong) // PROCESS_ALL_ACCESS
    };
    if proc_handle.is_null() {
        println!("B4_OPEN_PROCESS_FAILED pid={}", pid);
        std::process::exit(1);
    }

    let rc = unsafe { DebugActiveProcess(pid as c_ulong) };
    if rc == 0 {
        println!("B4_ATTACH_FAILED pid={}", pid);
        unsafe { CloseHandle(proc_handle) };
        std::process::exit(1);
    }
    println!("B4_ATTACHED pid={}", pid);

    let start = unsafe { GetTickCount64() };
    let mut runtime_base: u64 = 0;
    let mut events: Vec<String> = Vec::new();
    let mut seq: u64 = 0;
    let mut dll_loads: u32 = 0;
    let mut exceptions_seen: u32 = 0;
    let mut c0000409_seen: u32 = 0;
    let mut obs_hits: u32 = 0;
    let mut int29_hits: u32 = 0;
    let mut exit_seen = false;

    loop {
        let now = unsafe { GetTickCount64() };
        if now.wrapping_sub(start) >= window_ms as u64 {
            println!("B4_WINDOW_END elapsed_ms={}", now.wrapping_sub(start));
            break;
        }
        let mut ev: DebugEvent = unsafe { std::mem::zeroed() };
        let wait = (window_ms as u64).saturating_sub(now.wrapping_sub(start)).min(500) as c_ulong;
        let wr = unsafe { WaitForDebugEvent(&mut ev, wait) };
        if wr == 0 {
            continue;
        }
        seq += 1;
        let ts = unsafe { GetTickCount64() }.wrapping_sub(start);
        let event_json: String;
        let mut continuation = DBG_CONTINUE;
        match ev.debug_event_code {
            EXCEPTION_DEBUG_EVENT => {
                let code = unsafe { ev.u.exception.exception_record.exception_code };
                let first = unsafe { ev.u.exception.first_chance != 0 };
                let addr = unsafe { ev.u.exception.exception_record.exception_address } as u64;
                let tid = ev.thread_id;
                exceptions_seen += 1;
                if code == 0xC0000409 {
                    c0000409_seen += 1;
                }
                let (rip, rsp) = read_rip_rsp(proc_handle, tid);
                // bound runtime sha256 AE42901E... image size 370,688 B
                // (~0x5a800); only addresses within the module (0x100000
                // guard) are runtime RVAs.
                let rva = if runtime_base != 0 && addr >= runtime_base && addr - runtime_base < 0x100000 {
                    Some(addr - runtime_base)
                } else {
                    None
                };
                let int29 = rva.map_or(false, |r| INT29_SITES.contains(&(r as u32)));
                if int29 {
                    int29_hits += 1;
                }
                let is_bp = code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP;
                if is_bp && runtime_base != 0 {
                    // breakpoint at observation point?
                    if let Some(r) = rva {
                        if OBS_POINTS.iter().any(|(p, _)| *p as u64 == r) {
                            obs_hits += 1;
                        }
                    }
                }
                // fail-closed: never swallow unknown first-chance; never
                // continue second-chance (let the OS kill the target).
                if !is_bp {
                    if first {
                        continuation = DBG_EXCEPTION_NOT_HANDLED;
                    } else {
                        continuation = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                println!(
                    "B4_EXCEPTION seq={} tid={} code=0x{:08x} first_chance={} address=0x{:x} rva={:?} int29={} rip=0x{:x} rsp=0x{:x} cont={}",
                    seq, tid, code, if first { 1 } else { 0 }, addr,
                    rva.map(|r| format!("0x{:x}", r)), if int29 { 1 } else { 0 },
                    rip.unwrap_or(0), rsp.unwrap_or(0), continuation
                );
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"exception","tid":{},"code":"0x{:08x}","first_chance":{},"address":"0x{:x}","rva":{},"int29":{},"rip":{},"rsp":{},"continuation":{}}}"#,
                    seq, ts, tid, code, if first { 1 } else { 0 }, addr,
                    rva.map(|r| format!("\"0x{:x}\"", r)).unwrap_or_else(|| "null".into()),
                    if int29 { 1 } else { 0 },
                    rip.map(|r| format!("\"0x{:x}\"", r)).unwrap_or_else(|| "null".into()),
                    rsp.map(|r| format!("\"0x{:x}\"", r)).unwrap_or_else(|| "null".into()),
                    continuation
                );
            }
            CREATE_PROCESS_DEBUG_EVENT => {
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"create_process","tid":{},"pid":{}}}"#,
                    seq, ts, ev.thread_id, ev.process_id
                );
            }
            CREATE_THREAD_DEBUG_EVENT => {
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"create_thread","tid":{}}}"#,
                    seq, ts, ev.thread_id
                );
            }
            EXIT_THREAD_DEBUG_EVENT => {
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"exit_thread","tid":{}}}"#,
                    seq, ts, ev.thread_id
                );
            }
            LOAD_DLL_DEBUG_EVENT => {
                dll_loads += 1;
                let base = unsafe { ev.u.load_dll.base_of_dll as u64 };
                let name = module_name_for(proc_handle, base);
                let is_runtime = name.as_deref() == Some("mida_antidebug_runtime.dll");
                if is_runtime {
                    runtime_base = base;
                    // install observation points on all threads we can
                    set_hw_breakpoints(proc_handle, ev.thread_id, base);
                    println!(
                        "B4_RUNTIME_LOADED base=0x{:x} tid={} obs_points_installed=4",
                        base, ev.thread_id
                    );
                }
                println!(
                    "B4_LOAD_DLL base=0x{:x} name={:?} is_runtime={}",
                    base, name, if is_runtime { 1 } else { 0 }
                );
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"load_dll","base":"0x{:x}","name":{},"is_runtime":{}}}"#,
                    seq, ts, base,
                    name.map(|n| format!("\"{}\"", n)).unwrap_or_else(|| "null".into()),
                    if is_runtime { 1 } else { 0 }
                );
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"unload_dll"}}"#,
                    seq, ts
                );
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                exit_seen = true;
                println!("B4_EXIT_PROCESS pid={} tid={}", ev.process_id, ev.thread_id);
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"exit_process","pid":{}}}"#,
                    seq, ts, ev.process_id
                );
            }
            OUTPUT_DEBUG_STRING_EVENT | RIP_EVENT => {
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"other"}}"#,
                    seq, ts
                );
            }
            _ => {
                event_json = format!(
                    r#"{{"seq":{},"ts_ms":{},"kind":"other"}}"#,
                    seq, ts
                );
            }
        }
        events.push(event_json);
        unsafe {
            ContinueDebugEvent(ev.process_id, ev.thread_id, continuation);
        }
        if ev.debug_event_code == EXIT_PROCESS_DEBUG_EVENT {
            break;
        }
    }

    let drc = unsafe { DebugActiveProcessStop(pid as c_ulong) };
    let elapsed = unsafe { GetTickCount64() }.wrapping_sub(start);
    println!(
        "B4_DETACH pid={} rc={} elapsed_ms={} events={} dll_loads={} exceptions={} obs_hits={} int29_hits={} exit_seen={}",
        pid, drc, elapsed, seq, dll_loads, exceptions_seen, obs_hits, int29_hits,
        if exit_seen { 1 } else { 0 }
    );

    // Write timeline JSON
    let mut json = String::from("{\n");
    json.push_str("  \"schema\": \"mida.adr7-b4-timeline/v1\",\n");
    json.push_str(&format!("  \"target_pid\": {},\n", pid));
    json.push_str(&format!("  \"runtime_base\": \"0x{:x}\",\n", runtime_base));
    json.push_str("  \"observer_points\": [");
    for (i, (rva, name)) in OBS_POINTS.iter().enumerate() {
        if i > 0 { json.push_str(", "); }
        json.push_str(&format!("\"0x{:x} {}\"", rva, name));
    }
    json.push_str("],\n");
    json.push_str("  \"int29_sites\": [");
    for (i, rva) in INT29_SITES.iter().enumerate() {
        if i > 0 { json.push_str(", "); }
        json.push_str(&format!("\"0x{:x}\"", rva));
    }
    json.push_str("],\n");
    json.push_str(&format!("  \"obs_hits\": {},\n", obs_hits));
    json.push_str(&format!("  \"int29_hits\": {},\n", int29_hits));
    json.push_str(&format!("  \"exceptions_0xc0000409\": {},\n",
        c0000409_seen));
    json.push_str("  \"records\": [\n");
    json.push_str(&events.join(",\n"));
    json.push_str("\n  ]\n}\n");
    let _ = std::fs::write(&timeline_out, &json);
    println!("B4_TIMELINE_WRITTEN path={}", timeline_out);
    println!("B4_END");
}
