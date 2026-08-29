//! XC-4 host loader: minimal x64 EXE that LoadLibrary's a protected DLL and
//! then blocks, keeping the DLL's decrypted image alive for an external
//! module-aware dump.
//!
//! Contract (XC-4 ②):
//! - no shell, no CRT deps beyond standard, minimal.
//! - flow: LoadLibraryW(core.dll) -> block (bounded sleep loop; keeps the
//!   decrypted image alive for the external module-aware dump).
//! - DLL path via argv[1] (or env HOST_LOADER_DLL). No hardcoding.
//! - keeps a strong reference (HMODULE) alive; never frees.

use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use host_loader::resolve_dll_path;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::Sleep;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
    let dll = resolve_dll_path(
        &env::args().skip(1).collect::<Vec<_>>(),
        env::var("HOST_LOADER_DLL").ok(),
    )
    .unwrap_or_else(|| {
        eprintln!("usage: host_loader.exe <core.dll path>  (or set HOST_LOADER_DLL)");
        std::process::exit(2);
    });
    let dllw = wide(OsStr::new(&dll));
    // SAFETY: dllw is a valid null-terminated wide string.
    let hmod = match unsafe { LoadLibraryW(PCWSTR(dllw.as_ptr())) } {
        Ok(h) => h,
        Err(e) => {
            eprintln!("host_loader: LoadLibraryW failed for {dll}: {e}");
            std::process::exit(1);
        }
    };
    // Keep the HMODULE referenced across the blocking window.
    let _keep = hmod.0; // Light self-check: resolve Run() address (do NOT call it — XC-4 ③).
                        // GetProcAddress uses ANSI PCSTR for the proc name.
                        // SAFETY: name is a valid C string; failure is non-fatal.
    let run_name: Vec<u8> = b"Run\0".to_vec();
    let run_ptr = unsafe { GetProcAddress(hmod, PCSTR(run_name.as_ptr())) };
    let ver_name: Vec<u8> = b"GetAppVersion\0".to_vec();
    let ver_ptr = unsafe { GetProcAddress(hmod, PCSTR(ver_name.as_ptr())) };
    eprintln!(
        "host_loader: loaded {dll} hmod={:p} Run={:?} GetAppVersion={:?} — blocking",
        hmod.0, run_ptr, ver_ptr
    );
    // Block indefinitely so the decrypted DLL image stays alive for the
    // external module-aware dump. A bounded sleep loop avoids depending on
    // event-object plumbing and keeps the process trivially killable.
    loop {
        // SAFETY: Sleep takes a u32 ms value.
        unsafe { Sleep(3600_000) }; // 1 hour per tick; loop renews
    }
}
