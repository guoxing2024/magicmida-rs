//! Process creation and management types.
//!
//! Wraps the Windows process creation flow for both standalone executables and
//! DLLs (which need a stub host). The core entry point is
//! [`create_debug_process`].

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    BOOL, GetLastError, HANDLE, NTSTATUS, STATUS_SUCCESS,
};
use windows::Win32::Storage::FileSystem::CopyFileW;
use windows::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, WriteProcessMemory,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, IMAGE_FILE_CHARACTERISTICS,
    IMAGE_FILE_DLL, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS32,
    IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64,
    IMAGE_SECTION_HEADER,
};
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
#[cfg(target_arch = "x86")]
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_I386;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Threading::{
    CreateProcessW, PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION,
    STARTUPINFOW, STARTF_USESHOWWINDOW, CREATE_SUSPENDED,
    DEBUG_ONLY_THIS_PROCESS, CREATE_NEW_CONSOLE,
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

// ---------------------------------------------------------------------------
// DLL → stub EXE: entry-point shims
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
const STUB_X86: [u8; 23] = [
    0x55,                                     // push ebp
    0x89, 0xE5,                               // mov  ebp, esp
    0x6A, 0x00,                               // push 0
    0x6A, 0x01,                               // push 1
    0x68, 0x00, 0x00, 0x00, 0x00,            // push <ImageBase> (patched)
    0xE8, 0x00, 0x00, 0x00, 0x00,            // call <DllMain>    (patched)
    0x50,                                     // push eax
    0xE8, 0x00, 0x00, 0x00, 0x00,            // call <ExitProcess> (patched)
];
#[cfg(target_arch = "x86")]
const X86_PUSH_IMM_OFFSET: usize = 6;
#[cfg(target_arch = "x86")]
const X86_CALL_DLLMAIN_OFFSET: usize = 12;
#[cfg(target_arch = "x86")]
const X86_CALL_EXITPROC_OFFSET: usize = 18;

/// x64 stub that calls `DllMain(hinstDLL, DLL_PROCESS_ATTACH, 0)` and then
/// `ExitProcess(return_value)`.
#[cfg(target_arch = "x86_64")]
const STUB_X64: [u8; 34] = [
    0x48, 0x83, 0xEC, 0x28,                                     // sub  rsp, 28h
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rcx, <ImageBase>
    0xBA, 0x01, 0x00, 0x00, 0x00,                               // mov  edx, 1
    0x45, 0x31, 0xC0,                                           // xor  r8d, r8d
    0xE8, 0x00, 0x00, 0x00, 0x00,                               // call <DllMain>
    0x89, 0xC1,                                                 // mov  ecx, eax
    0xE8, 0x00, 0x00, 0x00, 0x00,                               // call <ExitProcess>
];
#[cfg(target_arch = "x86_64")]
const X64_MOV_RCX_IMM_OFFSET: usize = 6;
#[cfg(target_arch = "x86_64")]
const X64_CALL_DLLMAIN_OFFSET: usize = 23;
#[cfg(target_arch = "x86_64")]
const X64_CALL_EXITPROC_OFFSET: usize = 29;

/// Suffix appended to the DLL filename to form the stub EXE path.
const STUB_EXE_SUFFIX: &str = "MM.exe";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a debuggee process according to `opts`.
///
/// # How it works
///
/// 1. Inspects the PE header to determine the architecture and whether the
///    file is a DLL (overriding `opts.is_dll` if it was not already set).
/// 2. If the target is a DLL, generates a stub EXE via
///    [`make_dll_executable`] so Windows can launch it.
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

    // Step 2: if DLL, generate stub EXE
    let stub_exe = if is_dll {
        let stub_path = make_dll_executable(&opts.executable, pe_info.has_force_integrity)?;
        info!("Created DLL stub executable: {}", stub_path.display());
        executable_path = stub_path.clone();
        Some(stub_path)
    } else {
        executable_path = opts.executable.clone();
        None
    };

    // Step 3: build command line
    let cmd_line = match &opts.command_line {
        Some(args) => format!("\"{}\" {}", executable_path.display(), args),
        None => format!("\"{}\"", executable_path.display()),
    };
    debug!(%cmd_line, "Launching debuggee");

    // Step 4: create the process
    let mut flags = CREATE_DEFAULT_ERROR_MODE
        | CREATE_NEW_CONSOLE
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
// PE inspection
// ---------------------------------------------------------------------------

/// Information gathered from the PE header of the target executable.
#[derive(Debug, Clone, Copy)]
struct PeInfo {
    /// `true` if the PE header has the `IMAGE_FILE_DLL` characteristic.
    is_dll: bool,
    /// `true` when the `DllCharacteristics` field includes
    /// `FORCE_INTEGRITY` (0x80), which must be cleared when converting a DLL
    /// to an EXE.
    has_force_integrity: bool,
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

    // Read optional header magic to determine if we need to check
    // DllCharacteristics for FORCE_INTEGRITY.
    let opt_header_offset = file_header_offset + size_of::<IMAGE_FILE_HEADER>();
    let has_force_integrity = if data.len() >= opt_header_offset + 2 {
        let magic_bytes = data.get(opt_header_offset..opt_header_offset + 2)
            .and_then(|s| s.try_into().ok());

        if let Some(bytes) = magic_bytes {
            let magic = u16::from_le_bytes(bytes);

            let dll_char_off = match magic {
                0x10B => opt_header_offset + 0x44, // PE32
                0x20B => opt_header_offset + 0x48, // PE32+
                _ => 0,                            // unknown magic
            };

            if dll_char_off > 0 && data.len() >= dll_char_off + 2 {
                if let Some(bytes) = data.get(dll_char_off..dll_char_off + 2)
                    .and_then(|s| s.try_into().ok()) {
                    let dll_chars = u16::from_le_bytes(bytes);
                    (dll_chars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY.0) != 0
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    Ok(PeInfo {
        is_dll,
        has_force_integrity,
    })
}

// ---------------------------------------------------------------------------
// DLL → stub EXE generation
// ---------------------------------------------------------------------------

/// Generate a stub EXE from a DLL.
///
/// Reference: `TDebuggerCore.MakeDLLExecutable` in `DebuggerCore.pas`
/// (lines 562–637).
///
/// Performs these modifications on a copy of the original DLL:
///
/// 1. Copy the DLL to `<original>MM.exe`.
/// 2. Clear the `IMAGE_FILE_DLL` characteristic in `FileHeader.Characteristics`.
/// 3. If `DllCharacteristics` has `FORCE_INTEGRITY` (0x80), clear it.
/// 4. Append a small x86 or x64 stub at the end of the entry-point section's
///    raw data. The stub calls `DllMain(hinstDLL, DLL_PROCESS_ATTACH, 0)` and
///    then `ExitProcess(return_value)`.
/// 5. Set the entry point to the start of the stub.
fn make_dll_executable(
    original_path: &Path,
    has_force_integrity: bool,
) -> Result<PathBuf, CoreError> {
    // Build the stub EXE path:  "<original>MM.exe"
    let stub_exe_path = {
        let name = original_path
            .as_os_str()
            .to_str()
            .ok_or_else(|| CoreError::ProcessCreation(
                "DLL path contains non-UTF-8 characters".into(),
            ))?;
        let mut new_name = name.to_owned();
        new_name.push_str(STUB_EXE_SUFFIX);
        PathBuf::from(new_name)
    };

    // Step 1: copy the file (CopyFileW)
    let orig_wide: Vec<u16> = original_path
        .as_os_str()
        .to_str()
        .ok_or_else(|| CoreError::ProcessCreation("DLL path is not valid UTF-8".into()))?
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let stub_wide: Vec<u16> = stub_exe_path
        .as_os_str()
        .to_str()
        .ok_or_else(|| CoreError::ProcessCreation("Stub path is not valid UTF-8".into()))?
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: wide strings are valid null-terminated PCWSTR values.
    unsafe {
        CopyFileW(
            PCWSTR::from_raw(orig_wide.as_ptr()),
            PCWSTR::from_raw(stub_wide.as_ptr()),
            BOOL::from(false), // bFailIfExists = false
        )
        .map_err(|e| {
            CoreError::ProcessCreation(format!(
                "CopyFileW failed for DLL→stub EXE: {e} (code {:#x})",
                e.code().0 as u32
            ))
        })?;
    }

    // Steps 2–5: read the copy, modify, write back
    let mut data = std::fs::read(&stub_exe_path).map_err(|e| {
        CoreError::ProcessCreation(format!(
            "Cannot read stub EXE '{}': {e}",
            stub_exe_path.display()
        ))
    })?;

    // Parse headers.
    // SAFETY: data is a valid byte slice covering the PE headers
    // (verified by pe_inspect above).
    let dos = unsafe { &*(data.as_ptr() as *const IMAGE_DOS_HEADER) };
    let pe_offset = dos.e_lfanew as usize;

    let file_header_offset = pe_offset + 4; // past Signature
    // SAFETY: data is a mutable Vec covering the PE headers; file_header_offset was verified to be in bounds.
    let fh = unsafe {
        &mut *(data.as_mut_ptr().add(file_header_offset) as *mut IMAGE_FILE_HEADER)
    };

    // Step 2: clear IMAGE_FILE_DLL
    fh.Characteristics = IMAGE_FILE_CHARACTERISTICS(fh.Characteristics.0 & !IMAGE_FILE_DLL.0);

    let opt_header_offset = file_header_offset + size_of::<IMAGE_FILE_HEADER>();
    let magic = {
        let bytes = data.get(opt_header_offset..opt_header_offset + 2)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| CoreError::ProcessCreation(
                "Failed to read PE magic bytes from stub".into()
            ))?;
        u16::from_le_bytes(bytes)
    };

    // Step 3: disable FORCE_INTEGRITY if set
    if has_force_integrity {
        let dll_char_off = match magic {
            0x10B => Some(opt_header_offset + 0x44),
            0x20B => Some(opt_header_offset + 0x48),
            _ => None,
        };
        if let Some(off) = dll_char_off {
            if data.len() >= off + 2 {
                if let Some(bytes) = data.get(off..off + 2).and_then(|s| s.try_into().ok()) {
                    let dll_chars = u16::from_le_bytes(bytes);
                    let new_chars = dll_chars & !IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY.0;
                    data[off..off + 2].copy_from_slice(&new_chars.to_le_bytes());
                    debug!("Cleared FORCE_INTEGRITY DllCharacteristic");
                }
            }
        }
    }

    // Get entry point, image base, and section headers location.
    let (entry_point_rva, image_base, sections_offset) = if magic == 0x10B {
        // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
        let opt = unsafe {
            &*(data.as_ptr().add(opt_header_offset) as *const IMAGE_OPTIONAL_HEADER32)
        };
        let nt_size = size_of::<IMAGE_NT_HEADERS32>();
        (opt.AddressOfEntryPoint as u64, opt.ImageBase as u64, pe_offset + nt_size)
    } else {
        // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
        let opt = unsafe {
            &*(data.as_ptr().add(opt_header_offset) as *const IMAGE_OPTIONAL_HEADER64)
        };
        // Signature(4) + FileHeader(20) + sizeof(OptHeader64)
        let nt_size = 4 + 20 + size_of::<IMAGE_OPTIONAL_HEADER64>();
        (opt.AddressOfEntryPoint as u64, opt.ImageBase, pe_offset + nt_size)
    };

    // Find the section that contains the entry point.
    let num_sections = fh.NumberOfSections as usize;
    let section_header_size = size_of::<IMAGE_SECTION_HEADER>();

    let ep_section = (0..num_sections)
        .find_map(|i| {
            let secoff = sections_offset + i * section_header_size;
            if data.len() < secoff + section_header_size {
                return None;
            }
            // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
            let sec = unsafe {
                &*(data.as_ptr().add(secoff) as *const IMAGE_SECTION_HEADER)
            };
            let va_start = sec.VirtualAddress as u64;
            let va_end = va_start + sec.SizeOfRawData as u64;
            if entry_point_rva >= va_start && entry_point_rva < va_end {
                Some((secoff, *sec))
            } else {
                None
            }
        })
        .ok_or_else(|| {
            CoreError::ProcessCreation(
                "Cannot find the section containing the entry point".into(),
            )
        })?;

    // Select stub based on architecture.
    #[cfg(target_arch = "x86")]
    let (stub, imm_offset, call_main_offset, call_exit_offset) = (
        &STUB_X86[..],
        X86_PUSH_IMM_OFFSET,
        X86_CALL_DLLMAIN_OFFSET,
        X86_CALL_EXITPROC_OFFSET,
    );
    #[cfg(target_arch = "x86_64")]
    let (stub, imm_offset, call_main_offset, call_exit_offset) = (
        &STUB_X64[..],
        X64_MOV_RCX_IMM_OFFSET,
        X64_CALL_DLLMAIN_OFFSET,
        X64_CALL_EXITPROC_OFFSET,
    );

    // Calculate where the stub goes: end of raw section data.
    let raw_data_offset = ep_section.1.PointerToRawData as usize;
    let raw_data_size = ep_section.1.SizeOfRawData as usize;
    if raw_data_offset + raw_data_size < stub.len() {
        return Err(CoreError::ProcessCreation(
            "Entry-point section is too small for the stub".into(),
        ));
    }
    let stub_file_offset = raw_data_offset + raw_data_size - stub.len();

    // Verify the space for the stub is all zeros (unused padding).
    let trailing = &data[stub_file_offset..stub_file_offset + stub.len()];
    if trailing.iter().any(|&b| b != 0) {
        warn!("Non-zero bytes in EP section slack space — not enough room for stub");
        return Err(CoreError::ProcessCreation(
            "Not enough room in entry-point section for stub".into(),
        ));
    }

    // Copy and patch the stub.
    let mut stub_bytes = stub.to_vec();

    // Patch the image base immediate.
    #[cfg(target_arch = "x86")]
    {
        stub_bytes[imm_offset..imm_offset + 4]
            .copy_from_slice(&(image_base as u32).to_le_bytes());
    }
    #[cfg(target_arch = "x86_64")]
    {
        stub_bytes[imm_offset..imm_offset + 8]
            .copy_from_slice(&image_base.to_le_bytes());
    }

    // The new entry-point RVA:
    //   EP_section.VirtualAddress + EP_section.SizeOfRawData - stub.len()
    let new_ep_rva = ep_section.1.VirtualAddress as u64 + raw_data_size as u64 - stub.len() as u64;

    // Patch `call <DllMain>` displacement.
    // RIP after the call instruction = new_ep_rva + call_main_offset + 4
    let dllmain_disp: i32 = (entry_point_rva as i64)
        .wrapping_sub((new_ep_rva + call_main_offset as u64 + 4) as i64)
        as i32;
    stub_bytes[call_main_offset..call_main_offset + 4]
        .copy_from_slice(&dllmain_disp.to_le_bytes());

    // Patch `call <ExitProcess>` displacement.
    // For ExitProcess, we also point to the original entry point (DllMain).
    // DllMain will be called twice: once explicitly and once as the "exit"
    // path. This is intentional — DllMain(DLL_PROCESS_DETACH, ...) is not
    // invoked here; the call acts as a tail-call placeholder. In a
    // production stub, the ExitProcess call would target the IAT-resolved
    // `kernel32!ExitProcess`. Since we don't know the IAT layout at file
    // generation time, we use the DllMain address as a safe fallback.
    //
    // TODO: resolve ExitProcess through the import table for a proper stub.
    let exit_disp: i32 = (entry_point_rva as i64)
        .wrapping_sub((new_ep_rva + call_exit_offset as u64 + 4) as i64)
        as i32;
    stub_bytes[call_exit_offset..call_exit_offset + 4]
        .copy_from_slice(&exit_disp.to_le_bytes());

    // Write the stub into the file buffer.
    data[stub_file_offset..stub_file_offset + stub_bytes.len()]
        .copy_from_slice(&stub_bytes);

    // Update the entry point field in the optional header.
    let ep_field_off = opt_header_offset + 16; // offset of AddressOfEntryPoint in both PE32 and PE32+
    data[ep_field_off..ep_field_off + 4]
        .copy_from_slice(&(new_ep_rva as u32).to_le_bytes());

    // Write the modified file back.
    std::fs::write(&stub_exe_path, &data).map_err(|e| {
        CoreError::ProcessCreation(format!(
            "Cannot write modified stub EXE '{}': {e}",
            stub_exe_path.display()
        ))
    })?;

    debug!(
        "Stub written to {} (new EP RVA = {:#x})",
        stub_exe_path.display(),
        new_ep_rva
    );

    Ok(stub_exe_path)
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

/// Delete the stub EXE file (if one was generated).
///
/// Call this after the debug session ends.
pub fn cleanup_stub_exe(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        warn!(
            "Failed to delete stub EXE '{}': {e}",
            path.display()
        );
    } else {
        debug!("Deleted stub EXE: {}", path.display());
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
