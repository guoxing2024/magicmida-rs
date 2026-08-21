// Benign host harness: repeated LoadLibraryW / FreeLibrary cycles of the
// MIDA anti-debug runtime DLL with Initialize -> GetAttestation -> Shutdown
// per cycle. Verifies no resource growth (handles) and a clean lifecycle.
//
// Uses DYNAMIC loading (GetProcAddress) so FreeLibrary really unloads the
// module between rounds - a static import would keep the DLL resident and
// defeat the unload/reload semantics.
//
// No protected sample is loaded; no ScyllaHide; the DLL under test is the
// MIDA ADR-4 runtime cdylib.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(lp: *const u16) -> *mut c_void;
    fn FreeLibrary(h: *mut c_void) -> c_int;
    fn GetProcAddress(h: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetProcessHandleCount(h: *mut c_void, c: *mut u32) -> c_int;
    fn GetTickCount64() -> u64;
}

// MIDA runtime C ABI (mirrors the Rust #[repr(C)] struct exactly).
#[repr(C)]
struct MidaInitParams {
    target_pid: u32,
    module_base: u64,
    profile_id: *const c_char,
    profile_digest: *const c_char,
    expected_hooks: usize,
    expected_surfaces: *const *const c_char,
}

type InitializeFn = unsafe extern "C" fn(
    *const MidaInitParams,
    *mut u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> c_int;
type GetAttestationFn = unsafe extern "C" fn(*mut u8, usize, *mut usize) -> c_int;
type ShutdownFn = unsafe extern "C" fn() -> c_int;

const ERR_OK: c_int = 0;
const ERR_ALREADY_SHUTDOWN: c_int = 5;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn cstr(s: &str) -> Vec<c_char> {
    s.bytes()
        .map(|b| b as c_char)
        .chain(std::iter::once(0))
        .collect()
}

fn handle_count() -> u32 {
    unsafe {
        let mut n: u32 = 0;
        let r = GetProcessHandleCount(GetCurrentProcess(), &mut n);
        if r == 0 {
            panic!("GetProcessHandleCount failed");
        }
        n
    }
}

fn main() {
    // ADR7-A0-EVIDENCE-CORRECTION-1: the runtime DLL path MUST come from the
    // caller (argv[1], falling back to MIDA_RUNTIME_DLL env), never from a
    // hard-coded stale build directory. The previous hard-coded
    // "D:\tmp\magicmida-adr4c-target\..." pointed at an OLD runtime whose
    // byte identity happened to match; that made the experiment's PATH
    // provenance wrong even though the executed bytes were identical.
    let dll_path_str = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("MIDA_RUNTIME_DLL").ok())
        .expect(
            "usage: benign_host <path-to-mida_antidebug_runtime.dll> (or set MIDA_RUNTIME_DLL)",
        );
    eprintln!("BENIGN_HOST loading runtime DLL from: {dll_path_str}");
    let dll_path = wide(&dll_path_str);
    let base_handles = handle_count();
    let base_tick = unsafe { GetTickCount64() };
    println!("baseline handles={}", base_handles);

    const ROUNDS: u32 = 5;
    let mut prev_handles = base_handles;
    for round in 0..ROUNDS {
        // Dynamic load - this is the ONLY reference to the DLL.
        let h = unsafe { LoadLibraryW(dll_path.as_ptr()) };
        if h.is_null() {
            panic!("LoadLibraryW failed at round {}", round);
        }
        // Resolve exports.
        let name_init = wide("MidaAntidebugInitialize");
        let name_get = wide("MidaAntidebugGetAttestation");
        let name_shut = wide("MidaAntidebugShutdown");
        // GetProcAddress takes an ANSI name (LPCSTR), not wide.
        let init_p = unsafe { GetProcAddress(h, b"MidaAntidebugInitialize\0".as_ptr()) };
        let get_p = unsafe { GetProcAddress(h, b"MidaAntidebugGetAttestation\0".as_ptr()) };
        let shut_p = unsafe { GetProcAddress(h, b"MidaAntidebugShutdown\0".as_ptr()) };
        let _ = (name_init, name_get, name_shut);
        if init_p.is_null() || get_p.is_null() || shut_p.is_null() {
            panic!(
                "GetProcAddress failed at round {}: init={:p} get={:p} shut={:p}",
                round, init_p, get_p, shut_p
            );
        }
        let init: InitializeFn = unsafe { std::mem::transmute(init_p) };
        let get_att: GetAttestationFn = unsafe { std::mem::transmute(get_p) };
        let shut: ShutdownFn = unsafe { std::mem::transmute(shut_p) };

        // Initialize.
        let profile_id = cstr("oreans_origin_x64_v1");
        let profile_digest = cstr("deadbeef");
        let expected = [
            cstr("AD-PROC-001"),
            cstr("AD-PROC-002"),
            cstr("AD-PROC-003"),
        ];
        let mut surface_ptrs: Vec<*const c_char> = expected.iter().map(|v| v.as_ptr()).collect();
        let params = MidaInitParams {
            target_pid: std::process::id(),
            module_base: h as u64,
            profile_id: profile_id.as_ptr(),
            profile_digest: profile_digest.as_ptr(),
            expected_hooks: expected.len(),
            expected_surfaces: surface_ptrs.as_mut_ptr(),
        };
        let mut sha_buf = [0u8; 64];
        let mut att_buf = [0u8; 8192];
        let mut written: usize = 0;
        let rc = unsafe {
            init(
                &params,
                sha_buf.as_mut_ptr(),
                sha_buf.len(),
                att_buf.as_mut_ptr(),
                att_buf.len(),
                &mut written,
            )
        };
        if rc != ERR_OK {
            panic!("Initialize failed at round {}: rc={}", round, rc);
        }
        // GetAttestation: read back twice.
        let mut att2 = [0u8; 8192];
        let mut written2: usize = 0;
        let rc2 = unsafe { get_att(att2.as_mut_ptr(), att2.len(), &mut written2) };
        if rc2 != ERR_OK {
            panic!("GetAttestation failed at round {}: rc={}", round, rc2);
        }
        let mut att3 = [0u8; 8192];
        let mut written3: usize = 0;
        let rc3 = unsafe { get_att(att3.as_mut_ptr(), att3.len(), &mut written3) };
        if rc3 != ERR_OK {
            panic!(
                "second GetAttestation failed at round {}: rc={}",
                round, rc3
            );
        }
        // Shutdown.
        let rc4 = unsafe { shut() };
        if rc4 != ERR_OK {
            panic!("Shutdown failed at round {}: rc={}", round, rc4);
        }
        // Post-shutdown GetAttestation must report AlreadyShutdown.
        let mut att4 = [0u8; 8192];
        let mut written4: usize = 0;
        let rc5 = unsafe { get_att(att4.as_mut_ptr(), att4.len(), &mut written4) };
        if rc5 != ERR_ALREADY_SHUTDOWN {
            panic!(
                "post-shutdown GetAttestation expected {}, got {}",
                ERR_ALREADY_SHUTDOWN, rc5
            );
        }
        // FreeLibrary - with no static import this actually unloads.
        let fr = unsafe { FreeLibrary(h) };
        if fr == 0 {
            panic!("FreeLibrary failed at round {}", round);
        }
        let cur_handles = handle_count();
        println!(
            "round {}: handles {} (delta {})",
            round,
            cur_handles,
            cur_handles as i64 - prev_handles as i64
        );
        if cur_handles > prev_handles + 4 {
            panic!(
                "handle growth at round {}: {} -> {}",
                round, prev_handles, cur_handles
            );
        }
        prev_handles = cur_handles;
    }
    let final_handles = handle_count();
    println!("final handles={} baseline={}", final_handles, base_handles);
    if final_handles > base_handles + 8 {
        panic!(
            "sustained handle growth: baseline {} final {}",
            base_handles, final_handles
        );
    }
    println!(
        "BENIGN_HOST_OK rounds={} elapsed_ms={}",
        ROUNDS,
        unsafe { GetTickCount64() } - base_tick
    );
}
