//! Process creation and management types.
//!
//! Wraps the Windows process creation flow for both standalone executables and
//! DLLs (which need a stub host). The core entry point is
//! [`create_debug_process`].

use std::path::{Path, PathBuf};

use tracing::{debug, info};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    BOOL, GetLastError, HANDLE, NTSTATUS, STATUS_SUCCESS,
};
use windows::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory,
    IMAGE_FILE_DLL, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64,
};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
#[cfg(target_arch = "x86")]
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_I386;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Threading::{
    CreateProcessW, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
    STARTUPINFOW, STARTF_USESHOWWINDOW, CREATE_SUSPENDED,
    DEBUG_ONLY_THIS_PROCESS, CREATE_NO_WINDOW,
    CREATE_DEFAULT_ERROR_MODE, NORMAL_PRIORITY_CLASS,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
use windows::Wdk::System::Threading::{
    NtQueryInformationProcess, PROCESSINFOCLASS,
};

use crate::error::CoreError;

// ---------------------------------------------------------------------------
// Re-exported types (imported in lib.rs)
// ---------------------------------------------------------------------------

/// Options for creating a debuggee process.
#[derive(Debug, Clone)]
pub struct CreateProcessOptions {
    /// Path to the executable or DLL to debug.
    pub executable: PathBuf,
    /// Optional command-line arguments (appended after the executable path).
    pub command_line: Option<String>,
    /// `true` when the target is a DLL rather than a standalone EXE.
    pub is_dll: bool,
    /// `true` to create the process suspended (typically used so the debugger
    /// can set up breakpoints before the entry point runs).
    pub suspended: bool,
}

/// Handle to a running debuggee process and its main thread.
///
/// The debugger must close both handles (explicitly via
/// [`CloseHandle`](windows::Win32::Foundation::CloseHandle)) when the session
/// ends — this struct does **not** implement `Drop` because handle lifetimes
/// are managed explicitly during the debug loop.
#[derive(Debug)]
pub struct TargetProcess {
    /// Handle to the target process (`PROCESS_ALL_ACCESS`).
    pub handle: HANDLE,
    /// Target process ID.
    pub pid: u32,
    /// ID of the main (initial) thread.
    pub main_thread_id: u32,
    /// Handle to the main thread (`THREAD_ALL_ACCESS`).
    pub main_thread_handle: HANDLE,
    /// Preferred image base address of the target executable, read from the
    /// PEB during `CREATE_PROCESS_DEBUG_EVENT`.
    pub image_base: u64,
    /// If `is_dll` was true, the path to the generated stub EXE (must be
    /// deleted after the debug session). `None` for a regular EXE.
    pub stub_exe: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// PEB field offsets
// ---------------------------------------------------------------------------

/// Byte offset of `PEB.BeingDebugged` from the start of the PEB.
/// `Reserved1` is `[u8; 2]`, then `BeingDebugged: u8` is at offset 2.
const PEB_BEING_DEBUGGED_OFFSET: u64 = 2;

/// Byte offset of `PEB.ImageBaseAddress` from the start of the PEB.
/// Per the Pascal reference: x86 = 8, x64 = 16.
#[cfg(target_arch = "x86")]
const PEB_IMAGE_BASE_OFFSET: u64 = 8;
#[cfg(target_arch = "x86_64")]
const PEB_IMAGE_BASE_OFFSET: u64 = 16;

/// Byte offset of `PEB.pShimData` from the start of the PEB.
/// Per the Pascal reference: x86 = 0x1E8, x64 = 0x2D8.
#[cfg(target_arch = "x86")]
const PEB_SHIM_DATA_OFFSET: u64 = 0x1E8;
#[cfg(target_arch = "x86_64")]
const PEB_SHIM_DATA_OFFSET: u64 = 0x2D8;

// ---------------------------------------------------------------------------
// PE signature constant
// ---------------------------------------------------------------------------

const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

/// Suffix appended to the DLL filename to form the **loader-host** EXE path.
///
/// The loader host is a purpose-built executable that calls `LoadLibraryW` on
/// the packed DLL and then parks.  Unlike the stub EXE it does **not** touch the
/// DLL's headers: the real Windows loader maps the image, runs its TLS
/// callbacks, and calls `DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)` through
/// the normal `LdrpLoadDll` path.
const HOST_EXE_SUFFIX: &str = "MMHost.exe";

// ---------------------------------------------------------------------------
// Loader host source
// ---------------------------------------------------------------------------

/// Minimal C source for the loader host.
///
/// It takes the DLL path as `argv[1]`, loads it with `LoadLibraryW`, prints the
/// result to `<dll>.host.log`, resolves two exports as a liveness check, and
/// then sleeps so an external debugger keeps the fully-bootstrapped image
/// mapped while it dumps it.
///
/// Compiled on demand by [`ensure_loader_host`] with whatever C compiler is on
/// `PATH` (`gcc` from the bundled MinGW is the expected one).
const HOST_SOURCE: &str = r#"/* Auto-generated loader host. Do not edit; see mida-core/src/process.rs. */
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 2;

    /* argv[1] is an ANSI path; widen it so non-ASCII paths survive. */
    wchar_t wide[32768];
    if (MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wide,
                            (int)(sizeof wide / sizeof wide[0])) == 0)
        return 2;

    /* Log to %TEMP%, not next to the sample: the sample directory belongs to
       the user, and a debug run must not leave files in it. */
    char log[MAX_PATH * 2];
    snprintf(log, sizeof log, "%s\\magicmida-hosts\\host-%lu.log",
             getenv("TEMP") ? getenv("TEMP") : ".", (unsigned long)GetCurrentProcessId());
    FILE *lf = fopen(log, "w");

    HMODULE h = LoadLibraryW(wide);
    if (lf) {
        fprintf(lf, "pid=%lu base=%p ok=%d\n", (unsigned long)GetCurrentProcessId(),
                (void *)h, h != NULL);
        if (h) {
            fprintf(lf, "GetAppVersion=%p Run=%p\n",
                    (void *)GetProcAddress(h, "GetAppVersion"),
                    (void *)GetProcAddress(h, "Run"));
        }
        fflush(lf);
    }

    if (h == NULL) {
        if (lf) fclose(lf);
        return 1;
    }

    /* Keep the module mapped so the debugger can dump the bootstrapped image. */
    for (;;) Sleep(1000);
}
"#;

/// Name of the C compiler used to build the loader host.
const HOST_COMPILER: &str = "gcc";


// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a debuggee process according to `opts`.
///
/// # How it works
///
/// 1. Inspects the PE header to determine the architecture and whether the
///    file is a DLL (overriding `opts.is_dll` if it was not already set).
/// 2. If the target is a DLL, generates a loader host via
///    [`ensure_loader_host`] so the real `LoadLibraryW` runs the shell.
/// 3. Calls `CreateProcessW` with `DEBUG_ONLY_THIS_PROCESS` (and
///    `CREATE_SUSPENDED` when `opts.suspended` is set).
/// 4. Fills a [`TargetProcess`] from the resulting `PROCESS_INFORMATION`.
///
/// # Errors
///
/// Returns [`CoreError::ProcessCreation`] when the PE header is malformed,
/// the file is for the wrong architecture, `CopyFileW` fails, a memory
/// read/write fails, or `CreateProcessW` itself fails.
pub fn create_debug_process(
    opts: &CreateProcessOptions,
) -> Result<TargetProcess, CoreError> {
    // Step 1: inspect the PE file (determines DLL flag, verifies arch)
    let pe_info = pe_inspect(&opts.executable)?;

    let is_dll = opts.is_dll || pe_info.is_dll;
    let executable_path: PathBuf;
    let mut host_arguments: Option<String> = None;

    // Step 2: if DLL, build a loader host and pass the DLL as its argument.
    //
    // The previous approach rewrote the DLL into a stub EXE (clear
    // IMAGE_FILE_DLL, point the entry point at a hand-written `call DllMain`
    // shim).  That does not work for a Themida-packed DLL: the loader's
    // `DLL_PROCESS_ATTACH` sequencing never runs, and the shell dies at
    // `.winlice+0x33E22E` dereferencing a null pointer.  Handing the DLL to the
    // real loader instead lets the shell bootstrap exactly as it does when the
    // host application loads it normally.
    let stub_exe = if is_dll {
        let host_path = ensure_loader_host(&opts.executable)?;
        info!("Created DLL loader host: {}", host_path.display());
        // The DLL argument must be **absolute**.
        //
        // `CreateProcess` sets the child's working directory to the host's own
        // directory (below), which is now `%TEMP%\magicmida-hosts`, not the
        // sample's directory.  A relative input path therefore resolves against
        // the wrong place and `LoadLibraryW` fails with `ok=0` (measured: the
        // host log showed `base=0000000000000000 ok=0`, and the run then died
        // with "OEP not found" because nothing was ever loaded).
        let dll_abs = std::fs::canonicalize(&opts.executable)
            .unwrap_or_else(|_| opts.executable.clone());
        host_arguments = Some(format!("\"{}\"", dll_abs.display()));
        executable_path = host_path.clone();
        Some(host_path)
    } else {
        executable_path = opts.executable.clone();
        None
    };

    // Step 3: build command line
    let cmd_line = match (&host_arguments, &opts.command_line) {
        (Some(dll_arg), Some(extra)) => {
            format!("\"{}\" {} {}", executable_path.display(), dll_arg, extra)
        }
        (Some(dll_arg), None) => format!("\"{}\" {}", executable_path.display(), dll_arg),
        (None, Some(extra)) => format!("\"{}\" {}", executable_path.display(), extra),
        (None, None) => format!("\"{}\"", executable_path.display()),
    };
    debug!(%cmd_line, "Launching debuggee");

    // Step 4: create the process
    //
    // `CREATE_NO_WINDOW` instead of `CREATE_NEW_CONSOLE`:
    //
    // The debuggee is launched with `DEBUG_ONLY_THIS_PROCESS`, so nothing about
    // the unpack pipeline needs a console of its own — the CLI/GUI drives it
    // through the debug API and reads its output from the dump, not from a
    // terminal.  `CREATE_NEW_CONSOLE` therefore only did one thing: flashed a
    // black console window on every run, on top of the caller's window.  That is
    // pure visual noise, and it is why unpacking from the GUI popped a CMD box.
    //
    // `CREATE_NO_WINDOW` keeps the same "no inherited console" property while
    // creating no visible window.  It does not affect debugging, the child's
    // ability to create its own windows, or `WaitForDebugEvent`; the Themida
    // shell creates its GUI windows itself via `CreateWindowExW`, which is
    // unaffected by console flags.  Verified by both end-to-end gates: the EXE
    // product still reaches its `授权验证` window, and the DLL case still answers
    // `GetAppVersion() == "1.1"`.
    let mut flags = CREATE_DEFAULT_ERROR_MODE
        | CREATE_NO_WINDOW
        | NORMAL_PRIORITY_CLASS
        | DEBUG_ONLY_THIS_PROCESS;

    if opts.suspended {
        flags |= CREATE_SUSPENDED;
    }

    let mut si = STARTUPINFOW::default();
    // SAFETY: STARTUPINFOW is repr(C) and the zeroed default is valid.
    // cb must be set to the struct size per Windows API contract.
    si.cb = size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW.0 as u16;

    let mut pi = PROCESS_INFORMATION::default();

    // CreateProcessW may modify the command-line buffer, so allocate mutable
    // wide string.
    let mut cmd_line_wide: Vec<u16> = cmd_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Use the directory containing the executable as the working directory.
    let current_dir_str = executable_path
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or(".");
    let current_dir_wide: Vec<u16> = current_dir_str
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY:
    // - All pointers reference valid, initialized data that outlives the call.
    // - cmd_line_wide is null-terminated and mutable (CreateProcessW may write).
    // - STARTUPINFOW::cb is set to the correct size.
    unsafe {
        CreateProcessW(
            None,                                           // lpApplicationName
            windows::core::PWSTR::from_raw(cmd_line_wide.as_mut_ptr()), // lpCommandLine
            None,                                           // lpProcessAttributes
            None,                                           // lpThreadAttributes
            BOOL::from(false),                              // bInheritHandles
            flags,
            None,                                           // lpEnvironment
            PCWSTR::from_raw(current_dir_wide.as_ptr()),     // lpCurrentDirectory
            &si,
            &mut pi,
        )
        .map_err(|e| {
            CoreError::ProcessCreation(format!(
                "CreateProcessW failed: {e} (code {:#x})",
                e.code().0 as u32
            ))
        })?;
    }

    let target = TargetProcess {
        handle: pi.hProcess,
        pid: pi.dwProcessId,
        main_thread_id: pi.dwThreadId,
        main_thread_handle: pi.hThread,
        image_base: 0, // filled later from the CREATE_PROCESS debug event
        stub_exe,
    };

    info!(
        pid = target.pid,
        tid = target.main_thread_id,
        "Debuggee process created"
    );

    Ok(target)
}

// ---------------------------------------------------------------------------
// Optional-header field locations
// ---------------------------------------------------------------------------
// PE inspection
// ---------------------------------------------------------------------------

/// Information gathered from the PE header of the target executable.
#[derive(Debug, Clone, Copy)]
struct PeInfo {
    /// `true` if the PE header has the `IMAGE_FILE_DLL` characteristic.
    is_dll: bool,
}

/// Read the PE headers from `path` and return the basic information the
/// debugger needs.
///
/// Reference: `TDebuggerCore.PEInspect` in `DebuggerCore.pas` (lines 536–559).
fn pe_inspect(path: &Path) -> Result<PeInfo, CoreError> {
    let data = std::fs::read(path).map_err(|e| {
        CoreError::ProcessCreation(format!("Cannot read '{}': {e}", path.display()))
    })?;

    // Ensure the file is large enough to hold a minimal PE header.
    if data.len() < size_of::<IMAGE_DOS_HEADER>() {
        return Err(CoreError::ProcessCreation(
            "File is not a valid PE (too small for DOS header)".into(),
        ));
    }

    // SAFETY: data is at least IMAGE_DOS_HEADER bytes. We're reading a POD
    // struct from well-aligned bytes — IMAGE_DOS_HEADER is repr(C) and its
    // fields all have natural alignment.
    let dos = unsafe { &*(data.as_ptr() as *const IMAGE_DOS_HEADER) };

    // The Pascal reference checks: `if e_lfanew > $F00 then fail`
    if dos.e_lfanew as u32 > 0xF00 {
        return Err(CoreError::ProcessCreation(
            "Selected file is not a PE or is malformed (e_lfanew out of range)".into(),
        ));
    }

    let pe_offset = dos.e_lfanew as usize;
    if data.len() < pe_offset + size_of::<IMAGE_NT_HEADERS64>() {
        return Err(CoreError::ProcessCreation(
            "PE header extends past end of file".into(),
        ));
    }

    // Read the NT headers signature (first 4 bytes at pe_offset).
    let signature = {
        let bytes = data.get(pe_offset..pe_offset + 4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| CoreError::ProcessCreation(
                "Failed to read PE signature bytes".into()
            ))?;
        u32::from_le_bytes(bytes)
    };

    if signature != IMAGE_NT_SIGNATURE {
        return Err(CoreError::ProcessCreation(format!(
            "PE signature mismatch (expected {:#010x}, got {:#010x})",
            IMAGE_NT_SIGNATURE, signature
        )));
    }

    // Read the file header (starts at pe_offset + 4, past Signature).
    // SAFETY: we verified bounds above.
    let file_header_offset = pe_offset + 4;
    // SAFETY: bounds were verified above (data.len() >= pe_offset + size_of::<IMAGE_NT_HEADERS64>); offset is within the file.
    let fh = unsafe {
        &*(data.as_ptr().add(file_header_offset) as *const IMAGE_FILE_HEADER)
    };

    let is_dll = (fh.Characteristics.0 & IMAGE_FILE_DLL.0) != 0;

    // Architecture check (matches the Pascal reference)
    #[cfg(target_arch = "x86")]
    let expected_machine = IMAGE_FILE_MACHINE_I386;
    #[cfg(target_arch = "x86_64")]
    let expected_machine = IMAGE_FILE_MACHINE_AMD64;

    if fh.Machine != expected_machine {
        let expected_name = if cfg!(target_arch = "x86") { "32-bit" } else { "64-bit" };
        let actual_name = if cfg!(target_arch = "x86") { "64-bit" } else { "32-bit" };
        return Err(CoreError::ProcessCreation(format!(
            "File is for the wrong architecture (Machine={machine:?}): \
             expected {expected_name}, please use the {actual_name} version of Magicmida.",
            machine = fh.Machine,
        )));
    }

    Ok(PeInfo {
        is_dll,
    })
}

// ---------------------------------------------------------------------------
// Loader host generation
// ---------------------------------------------------------------------------

/// Build (or reuse) the loader host executable for `dll_path` and return its
/// path.
///
/// The host is a small native EXE that calls `LoadLibraryW` on the DLL.  This is
/// the only correct way to bootstrap a Themida-packed DLL: the packer's
/// `DllMain` depends on the loader having run `DLL_PROCESS_ATTACH` sequencing
/// (TLS callbacks, heap, CRT init).  Bypassing that — which is what clearing
/// `IMAGE_FILE_DLL` and jumping straight to `DllMain` does — sends the shell
/// dereferencing a null pointer at `.winlice+0x33E22E`.
///
/// The source is written to `<dll>.host.c` and compiled with [`HOST_COMPILER`].
/// The result is cached: if the EXE is newer than the source it is reused, so a
/// repeated unpack does not pay the compile cost.
///
/// # Why the host goes in the temp directory, not beside the sample
///
/// It used to be written next to the input (`core.dllMMHost.exe`), which put two
/// build artefacts into the user's sample folder on every run and — worse —
/// left the EXE behind whenever the debuggee outlived the CLI.  A debuggee's
/// image stays mapped while its process object is alive, so `remove_file`
/// reports `ERROR_ACCESS_DENIED`; measured, the host survived every DLL run and
/// only became deletable after the CLI process itself exited.
///
/// Writing it under `%TEMP%\magicmida-hosts\` keeps the sample directory clean
/// and makes a leftover file a temp-file problem rather than a corrupted
/// sample directory.  The path is still deterministic per DLL (a hash of the
/// canonical path), so the compile cache keeps working.
pub fn ensure_loader_host(dll_path: &Path) -> Result<PathBuf, CoreError> {
    let dll_str = dll_path
        .as_os_str()
        .to_str()
        .ok_or_else(|| CoreError::ProcessCreation("DLL path is not valid UTF-8".into()))?;

    // A stable, collision-free name for this DLL's host.  The canonical path is
    // hashed rather than sanitised: sample names contain characters (spaces,
    // CJK, dots) that would otherwise need escaping, and two different samples
    // must never share one host binary.
    let canonical = std::fs::canonicalize(dll_path)
        .unwrap_or_else(|_| dll_path.to_path_buf());
    let stem = canonical
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("target");
    let hash = {
        // FNV-1a over the canonical path — no dependency, stable across runs.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in canonical.to_string_lossy().as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    };
    let host_dir = std::env::temp_dir().join("magicmida-hosts");
    std::fs::create_dir_all(&host_dir).map_err(|e| {
        CoreError::ProcessCreation(format!(
            "Cannot create the loader-host directory '{}': {e}",
            host_dir.display()
        ))
    })?;
    sweep_stale_loader_hosts(&host_dir);

    // Keep the sample's stem in the name so a leftover file is identifiable.
    let safe_stem: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(32)
        .collect();
    let src_path = host_dir.join(format!("{safe_stem}_{hash:016x}.host.c"));
    let exe_path = host_dir.join(format!("{safe_stem}_{hash:016x}{HOST_EXE_SUFFIX}"));

    debug!(
        dll = %dll_str,
        host = %exe_path.display(),
        "Loader host location"
    );

    // Write the source every time — it is tiny, and keeping it in sync with the
    // Rust constant matters more than saving a few hundred bytes of I/O.
    std::fs::write(&src_path, HOST_SOURCE).map_err(|e| {
        CoreError::ProcessCreation(format!(
            "Cannot write loader-host source '{}': {e}",
            src_path.display()
        ))
    })?;

    // Reuse a current build.
    if let (Ok(exe_meta), Ok(src_meta)) =
        (std::fs::metadata(&exe_path), std::fs::metadata(&src_path))
    {
        if let (Ok(exe_t), Ok(src_t)) = (exe_meta.modified(), src_meta.modified()) {
            if exe_t >= src_t {
                debug!(host = %exe_path.display(), "Reusing existing loader host");
                return Ok(exe_path);
            }
        }
    }

    let output = {
        use std::os::windows::process::CommandExt;
        // `gcc` is a console program.  Without `CREATE_NO_WINDOW` the OS gives it
        // a fresh console, which shows up as a black box flashing on screen every
        // time a DLL target needs its loader host rebuilt.  We capture stdout and
        // stderr through pipes, so no console is needed at all.
        std::process::Command::new(HOST_COMPILER)
            .arg("-O2")
            .arg("-o")
            .arg(&exe_path)
            .arg(&src_path)
            .creation_flags(CREATE_NO_WINDOW.0)
            .output()
            .map_err(|e| {
                CoreError::ProcessCreation(format!(
                    "Cannot run '{HOST_COMPILER}' to build the loader host: {e}. \
                     A C compiler on PATH is required to unpack DLL targets."
                ))
            })?
    };

    if !output.status.success() {
        return Err(CoreError::ProcessCreation(format!(
            "Building the loader host failed (status {}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    info!(host = %exe_path.display(), "Built loader host");
    Ok(exe_path)
}

// ---------------------------------------------------------------------------
// PEB patching (called from the debug event loop)
// ---------------------------------------------------------------------------

/// Clear `PEB.BeingDebugged` and `PEB.pShimData` for an anti-anti-debug
/// workaround. Also reads the image base from the PEB.
///
/// Call this during the `CREATE_PROCESS_DEBUG_EVENT` handler, after the
/// process handle is available but before the target resumes execution.
///
/// Returns the image base address.
///
/// Reference: `TDebuggerCore.OnCreateProcessDebugEvent` in `DebuggerCore.pas`
/// (lines 296–349).
pub fn patch_peb_anti_debug(
    process_handle: HANDLE,
) -> Result<u64, CoreError> {
    // Step 1: query PEB address via NtQueryInformationProcess.
    let mut pbi = PROCESS_BASIC_INFORMATION::default();
    let mut return_length: u32 = 0;

    // SAFETY:
    // - process_handle is a valid process handle.
    // - pbi is an initialized PROCESS_BASIC_INFORMATION (CopyType).
    // - ProcessBasicInformation (0) requests the PEB address.
    let status: NTSTATUS;
    // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
    unsafe {
        status = NtQueryInformationProcess(
            process_handle,
            PROCESSINFOCLASS(0i32), // ProcessBasicInformation = 0
            (&mut pbi as *mut PROCESS_BASIC_INFORMATION) as *mut std::ffi::c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        );
    }

    if status != STATUS_SUCCESS {
        // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
        let err = unsafe { GetLastError() };
        return Err(CoreError::ProcessCreation(format!(
            "NtQueryInformationProcess failed: NTSTATUS {:#x}, GetLastError={}",
            status.0, err.0
        )));
    }

    let peb_addr = pbi.PebBaseAddress as u64;
    if peb_addr == 0 {
        return Err(CoreError::ProcessCreation(
            "NtQueryInformationProcess returned null PEB address".into(),
        ));
    }
    debug!(peb = %format!("{peb_addr:#x}"), "PEB address");

    // Step 2: clear PEB.BeingDebugged (offset 2).
    let being_debugged_addr = peb_addr + PEB_BEING_DEBUGGED_OFFSET;
    let mut debugged_byte: u8 = 0;

    // SAFETY: peb_addr is valid in the target; we read 1 byte at offset 2.
    unsafe {
        let _ = ReadProcessMemory(
            process_handle,
            being_debugged_addr as *const std::ffi::c_void,
            (&mut debugged_byte as *mut u8) as *mut std::ffi::c_void,
            1,
            None,
        ).map(|()| {
            if debugged_byte != 0 {
                debug!("Patching PEB.BeingDebugged (was {})", debugged_byte);
                let zero: u8 = 0;
                let _ = WriteProcessMemory(
                    process_handle,
                    being_debugged_addr as *const std::ffi::c_void,
                    (&zero as *const u8) as *const std::ffi::c_void,
                    1,
                    None,
                );
            }
        });
    }

    // Step 3: read the image base from PEB.
    let image_base_addr = peb_addr + PEB_IMAGE_BASE_OFFSET;
    let ptr_size = if cfg!(target_arch = "x86") { 4usize } else { 8usize };
    let mut image_base: u64 = 0;
    let mut bytes_read: usize = 0;

    // SAFETY: reading a pointer-sized value from the image-base field.
    unsafe {
        ReadProcessMemory(
            process_handle,
            image_base_addr as *const std::ffi::c_void,
            (&mut image_base as *mut u64) as *mut std::ffi::c_void,
            ptr_size,
            Some(&mut bytes_read),
        )
        .map_err(|_| {
            CoreError::ProcessCreation(
                "Reading process image base from PEB failed".into(),
            )
        })?;

        if bytes_read != ptr_size {
            return Err(CoreError::ProcessCreation(format!(
                "Short read on PEB image base: expected {ptr_size} bytes, got {bytes_read}"
            )));
        }
    }

    debug!(image_base = %format!("{image_base:#x}"), "Process image base");

    // Step 4: clear PEB.pShimData (anti-AppHelp).
    let shim_data_addr = peb_addr + PEB_SHIM_DATA_OFFSET;
    let mut shim_val: u64 = 0;

    // SAFETY: reading a pointer-sized value from the shim-data field.
    unsafe {
        let _ = ReadProcessMemory(
            process_handle,
            shim_data_addr as *const std::ffi::c_void,
            (&mut shim_val as *mut u64) as *mut std::ffi::c_void,
            ptr_size,
            None,
        ).map(|()| {
            if shim_val != 0 {
                let zero: u64 = 0;
                let _ = WriteProcessMemory(
                    process_handle,
                    shim_data_addr as *const std::ffi::c_void,
                    (&zero as *const u64) as *const std::ffi::c_void,
                    ptr_size,
                    None,
                );
                info!("Cleared PEB.pShimData to prevent apphelp hooks");
            }
        });
    }

    Ok(image_base)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Delete a generated host EXE, treating "still in use" as a non-event.
///
/// # Why this is not a warning
///
/// The loader host is a **cache**: `ensure_loader_host` reuses it when it is
/// newer than its source, so deleting it after every run throws away the gcc
/// compile.  Worse, the deletion cannot succeed while the process that maps it
/// is still alive, and a debuggee that terminated while being debugged keeps
/// its image mapped until the kernel tears the session down — measured: the
/// file was locked for the whole life of the CLI and became deletable only
/// after it exited.
///
/// So a failure here is the normal case, not an error: the file lives under
/// `%TEMP%\magicmida-hosts\`, it is ours, and [`sweep_stale_loader_hosts`]
/// removes entries that are no longer current.  Reporting `WARN` for it was
/// noise on every single DLL run.
pub fn cleanup_stub_exe(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => debug!("Deleted host EXE: {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!("Host EXE already gone: {}", path.display());
        }
        Err(e) => debug!(
            "Keeping host EXE '{}' (still mapped, cleaned by sweep): {e}",
            path.display()
        ),
    }
}

/// Remove loader-host files that are no longer current.
///
/// Called once when a host is about to be built.  An entry is stale when
/// nothing has touched it for a day, which is long enough that no live run can
/// still own it — a run takes seconds — and short enough that a folder does not
/// accumulate one host per sample forever.
///
/// The `.host.c` sources are removed together with their EXE: they are
/// regenerated on demand, and leaving them behind would make the folder grow
/// twice as fast.
pub fn sweep_stale_loader_hosts(host_dir: &Path) {
    const MAX_AGE_SECS: u64 = 24 * 60 * 60;
    let Ok(entries) = std::fs::read_dir(host_dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Only ever touch our own artefacts; the folder may be shared.
        if !(name.ends_with(".host.c")
            || name.ends_with(HOST_EXE_SUFFIX)
            || (name.starts_with("host-") && name.ends_with(".log")))
        {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() > MAX_AGE_SECS);
        if stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        debug!(removed, dir = %host_dir.display(), "Swept stale loader hosts");
    }
}

/// Close both process and thread handles without terminating the target.
///
/// # Safety
///
/// `handle` and `thread` must be valid handles (or
/// [`HANDLE::default()`]), and must not be used after this call.
pub fn close_process_handles(handle: HANDLE, thread: HANDLE) {
    // SAFETY: handles are valid or null. Closing a null handle is a safe
    // no-op (it returns an error, which we ignore).
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        if !handle.is_invalid() {
            let _ = CloseHandle(handle);
        }
        if !thread.is_invalid() {
            let _ = CloseHandle(thread);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `pe_inspect` on a non-existent file returns a `ProcessCreation` error.
    #[test]
    fn pe_inspect_missing_file() {
        let result = pe_inspect(Path::new("C:\\__this_file_does_not_exist__"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CoreError::ProcessCreation(_)),
            "expected ProcessCreation, got {err:?}",
        );
    }
}
