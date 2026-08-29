//! XC-8-A probe host: load a candidate DLL, call GetAppVersion, and capture
//! the AV (access violation) via a Vectored Exception Handler. Prints RIP +
//! key registers + the faulting instruction to stderr so we can attribute
//! whether the crash is a data dependency (RIP in .text reading external
//! memory) or VM execution (RIP jumped into the removed .winlice range).

use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_CONTINUE_EXECUTION};
use windows::Win32::System::Diagnostics::Debug::{
    EXCEPTION_DEBUG_EVENT, EXCEPTION_POINTERS, EXCEPTION_RECORD,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

static MOD_BASE: OnceLock<u64> = OnceLock::new();

extern "system" fn veh_handler(ep: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        if ep.is_null() {
            return 0;
        }
        let rec = (*ep).ExceptionRecord;
        if rec.is_null() {
            return 0;
        }
        let code = (*rec).ExceptionCode;
        if code == EXCEPTION_ACCESS_VIOLATION {
            let rip = (*rec).ExceptionAddress as u64;
            let base = *MOD_BASE.get().unwrap_or(&0);
            let info0 = if (*rec).NumberParameters >= 1 {
                (*rec).ExceptionInformation[0]
            } else {
                0
            };
            let info1 = if (*rec).NumberParameters >= 2 {
                (*rec).ExceptionInformation[1]
            } else {
                0
            };
            eprintln!("[VEH] ACCESS_VIOLATION: RIP=0x{rip:X} (rva=0x{:X})", rip.wrapping_sub(base));
            eprintln!("[VEH] violation_type={info0} fault_addr=0x{info1:X}");
            // Try to read the faulting instruction bytes via context (if avail).
            let ctx = (*ep).ContextRecord;
            if !ctx.is_null() {
                // CONTEXT on x64: Rip at offset 0xF8 (248)
                let ctxb = ctx as *const u8;
                let rip2 = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0xF8), 8));
                let rsp = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0x88), 8));
                let rax = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0x98), 8));
                let rcx = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0xA0), 8));
                let rdx = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0xA8), 8));
                let rbx = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0xB0), 8));
                let rbp = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0xB8), 8));
                let rsi = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0xC0), 8));
                let rdi = u64::from_le_bytes(std::slice::from_raw_parts(ctxb.add(0xC8), 8));
                eprintln!("[VEH] ctx Rip=0x{rip2:X} Rsp=0x{rsp:X} Rax=0x{rax:X} Rcx=0x{rcx:X}");
                eprintln!("[VEH] ctx Rdx=0x{rdx:X} Rbx=0x{rbx:X} Rbp=0x{rbp:X} Rsi=0x{rsi:X} Rdi=0x{rdi:X}");
            }
            // Dump first 16 bytes at RIP
            let mut buf = [0u8; 16];
            let src = rip as *const u8;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = src.add(i).read_volatile();
            }
            eprintln!("[VEH] instr: {}", buf.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
            // Do not swallow: return 0 (continue search) so process crashes as usual.
        }
    }
    0
}

fn main() {
    let dll = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: veh_probe.exe <dll> [GetAppVersion|Run]");
        std::process::exit(2);
    });
    let func = env::args().nth(2).unwrap_or_else(|| "GetAppVersion".into());

    // Install VEH (kernel32.AddVectoredExceptionHandler).
    unsafe {
        let kernel32 = LoadLibraryW(PCWSTR(
            OsStr::new("kernel32.dll")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
        ));
        let _ = kernel32;
        let add_veh: unsafe extern "system" fn(*const (), u32) -> *const () =
            std::mem::transmute(
                GetProcAddress(
                    LoadLibraryW(PCWSTR(
                        OsStr::new("kernel32.dll")
                            .encode_wide()
                            .chain(std::iter::once(0))
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    )),
                    PCWSTR(b"AddVectoredExceptionHandler\0".as_ptr() as _),
                )
                .unwrap_or(None),
            );
        let _ = add_veh(veh_handler as *const (), 1); // first handler
    }

    // Load the target DLL.
    let dllw: Vec<u16> = OsStr::new(&dll).encode_wide().chain(std::iter::once(0)).collect();
    let hmod = unsafe { LoadLibraryW(PCWSTR(dllw.as_ptr())) };
    if hmod.is_invalid() {
        eprintln!("LoadLibraryW failed for {dll}");
        std::process::exit(1);
    }
    let base = hmod.0 as u64;
    let _ = MOD_BASE.set(base);
    eprintln!("[probe] loaded {dll} hmod=0x{base:X}");

    // Resolve and call the target function.
    let name: Vec<u8> = format!("{func}\0").into_bytes();
    let proc = unsafe { GetProcAddress(hmod, PCWSTR(name.as_ptr() as _)) };
    if proc.is_none() {
        eprintln!("[probe] {func} not found");
        std::process::exit(1);
    }
    let faddr = proc.unwrap() as u64;
    eprintln!("[probe] {func} @ 0x{faddr:X} (rva 0x{:X})", faddr.wrapping_sub(base));

    // Call it (no args, capture return).
    let f: unsafe extern "system" fn() -> u64 = std::mem::transmute(faddr);
    let ret = unsafe { f() };
    eprintln!("[probe] {func} returned 0x{ret:X} (no crash)");
}
