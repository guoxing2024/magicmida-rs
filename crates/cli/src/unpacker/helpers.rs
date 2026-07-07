//! Path, address, and API resolution helpers for the unpacker.

use std::path::{Path, PathBuf};
use anyhow::anyhow;
use tracing::{debug, info};
use windows::core::s;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use mida_core::DebuggerCore;
use mida_packers_themida::{install_code_section_guard, ThemidaState};
use super::session::{ResolvedApis, ProcessSession, ReadOnlyProcessDebugger};

// ---------------------------------------------------------------------------
// ScyllaHide paths
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const SCYLLA_INJECTOR_NAME: &str = "InjectorCLIx64.exe";
#[cfg(target_arch = "x86")]
const SCYLLA_INJECTOR_NAME: &str = "InjectorCLIx86.exe";

#[cfg(target_arch = "x86_64")]
const SCYLLA_HOOK_NAME: &str = "HookLibraryx64.dll";
#[cfg(target_arch = "x86")]
const SCYLLA_HOOK_NAME: &str = "HookLibraryx86.dll";

/// Resolve the absolute path to the ScyllaHide injector binary.
pub(super) fn scylla_injector_path() -> PathBuf {
    exe_dir().join(SCYLLA_INJECTOR_NAME)
}

/// Resolve the absolute path to the ScyllaHide hook library DLL.
pub(super) fn scylla_hook_path() -> PathBuf {
    exe_dir().join(SCYLLA_HOOK_NAME)
}

/// Directory containing the CLI executable.
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// Output path
// ---------------------------------------------------------------------------

/// Compute the output path, using the Pascal "U" suffix convention.
///
/// Example: `test.exe` → `testU.exe`, `lib.dll` → `libU.dll`.
pub(super) fn resolve_output_path(input: &Path, output: Option<&Path>) -> PathBuf {
    if let Some(out) = output {
        return out.to_path_buf();
    }

    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("exe");

    let mut name = String::with_capacity(stem.len() + 1 + ext.len() + 1);
    name.push_str(stem);
    name.push('U');
    name.push('.');
    name.push_str(ext);

    input
        .parent()
        .unwrap_or(Path::new("."))
        .join(&name)
}

// ---------------------------------------------------------------------------
// API resolution
// ---------------------------------------------------------------------------

/// Resolve kernel32 API addresses **in the debugger's own process**.
///
/// On x64, kernel32.dll is loaded at the same base address in every process
/// (ASLR randomisation happens once per boot, not per-process).
pub(super) fn resolve_api_addrs() -> Result<ResolvedApis, anyhow::Error> {
    use windows::core::PCSTR;
    // SAFETY: GetModuleHandleW with a valid constant wide string never fails
    // for kernel32.dll / ntdll.dll (always loaded in every process).
    let k32 = unsafe { GetModuleHandleW(windows::core::w!("kernel32.dll")) }
        .map_err(|e| anyhow!("GetModuleHandleW(kernel32.dll) failed: {e}"))?;
    // SAFETY: ntdll.dll is always loaded in every Windows process; w!() yields a valid null-terminated wide string.
    let ntdll = unsafe { GetModuleHandleW(windows::core::w!("ntdll.dll")) }
        .map_err(|e| anyhow!("GetModuleHandleW(ntdll.dll) failed: {e}"))?;

    let resolve = |module: windows::Win32::Foundation::HMODULE, name: PCSTR| -> Result<usize, anyhow::Error> {
        // SAFETY: module is a valid HMODULE from GetModuleHandleW; name is a valid PCSTR constant from s!().
        let addr = unsafe { GetProcAddress(module, name) };
        match addr {
            Some(ptr) => Ok(ptr as usize),
            None => {
                // SAFETY: GetLastError is always safe to call — it reads the calling thread's last-error value.
                let err = unsafe { windows::Win32::Foundation::GetLastError() };
                Err(anyhow!("GetProcAddress failed: code {}", err.0))
            }
        }
    };

    let apis = ResolvedApis {
        close_handle: resolve(k32, s!("CloseHandle"))?,
        virtual_alloc: resolve(k32, s!("VirtualAlloc"))?,
        nt_close: resolve(ntdll, s!("NtClose"))?,
        nt_allocate_virtual_memory: resolve(ntdll, s!("NtAllocateVirtualMemory"))?,
        sleep: resolve(k32, s!("Sleep"))?,
        lstrlen: resolve(k32, s!("lstrlen"))?,
    };

    debug!(
        close_handle = %format!("{:#x}", apis.close_handle),
        virtual_alloc = %format!("{:#x}", apis.virtual_alloc),
        nt_close = %format!("{:#x}", apis.nt_close),
        nt_alloc = %format!("{:#x}", apis.nt_allocate_virtual_memory),
        sleep = %format!("{:#x}", apis.sleep),
        lstrlen = %format!("{:#x}", apis.lstrlen),
        "Resolved kernel32 and ntdll API addresses",
    );

    Ok(apis)
}

/// Resolve a host-process API address from a loaded DLL.
/// Returns 0 on failure.
pub(super) fn resolve_host_api(dll: &str, func: &str) -> usize {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    let to_pcstr = |s: &str| PCSTR::from_raw(s.as_ptr());
    // SAFETY: dll string is null-terminated UTF-8; GetModuleHandleA accepts a valid PCSTR.
    let Ok(module) = (unsafe { GetModuleHandleA(to_pcstr(&format!("{dll}\0"))) }) else {
        return 0;
    };
    // SAFETY: module is a valid HMODULE; func name is a null-terminated PCSTR.
    unsafe { GetProcAddress(module, to_pcstr(&format!("{func}\0"))) }
        .map(|f| f as usize)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Data section bounds
// ---------------------------------------------------------------------------

/// Compute the data-section boundaries for the IAT guard-address fallback.
pub(super) fn compute_data_section_bounds(
    image_base: usize,
    base_of_data: usize,
    sections: &[mida_pe::PeSection],
) -> (usize, usize) {
    for section in sections {
        let section_start = section.virtual_address as usize;
        let section_end = section_start + section.virtual_size as usize;
        if base_of_data < section_end {
            let data_start = image_base + base_of_data;
            let data_size = section_end.saturating_sub(base_of_data);
            return (data_start, data_size);
        }
    }
    (0, 0)
}

// ---------------------------------------------------------------------------
// PE header helper
// ---------------------------------------------------------------------------

/// Compute the RVA of the first byte of section `idx`'s name field within the
/// PE header of a remote process.
pub(super) fn pe_section_name_remote_rva(
    h_process: HANDLE,
    image_base: usize,
    idx: usize,
) -> Option<usize> {
    use mida_core::DebuggerCore;
    let mut buf4 = [0u8; 4];
    let ro = ReadOnlyProcessDebugger { h_process, image_base: image_base as u64 };
    ro.read_memory(image_base + 0x3C, &mut buf4).ok()?;
    let e_lfanew = u32::from_le_bytes(buf4) as usize;
    let nt = image_base + e_lfanew;

    let mut buf2 = [0u8; 2];
    ro.read_memory(nt + 4 + 16, &mut buf2).ok()?;
    let opt_hdr_size = u16::from_le_bytes(buf2) as usize;

    let sections_start = nt + 24 + opt_hdr_size;
    let name_addr = sections_start + idx * 40;
    let rva = name_addr.saturating_sub(image_base);
    Some(rva)
}

// ---------------------------------------------------------------------------
// .NET dump
// ---------------------------------------------------------------------------

/// Dump a .NET + Themida binary via raw memory dump at the _CorExeMain
/// breakpoint.
pub(super) fn dotnet_dump_and_dump_output(
    dbg: &mut ProcessSession,
    image_base: usize,
    output_path: &Path,
) -> Result<(), anyhow::Error> {
    let mut header_buf = vec![0u8; 0x1000];
    let read = dbg
        .read_memory(image_base, &mut header_buf)
        .map_err(|e| anyhow!("Failed to read .NET header: {e}"))?;
    if read < 0x1000 {
        return Err(anyhow!("Short read on .NET header: got {read} bytes"));
    }

    let live_pe = mida_pe::PeHeader::from_bytes(&header_buf)?;
    let entry_point = live_pe.entry_point;

    mida_pe::dump_dotnet(dbg, image_base as u64, entry_point, output_path)
        .map_err(|e| anyhow!(".NET dump failed: {e}"))
}

// ---------------------------------------------------------------------------
// Hardware breakpoint handler
// ---------------------------------------------------------------------------

/// Handle a hardware breakpoint event (CloseHandle / VirtualAlloc / .text+0x1000).
pub(super) fn handle_hw_breakpoint(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    guard_installed: &mut bool,
    address: u64,
    _thread_id: u32,
    image_base_usize: usize,
    _image_boundary: usize,
    h_process: HANDLE,
    guard_protection: u32,
) -> Result<(), anyhow::Error> {
    let rip = address as usize;

    let text_write_bp_addr = (image_base_usize + 0x1000) as u64;
    let slot0_is_text_write = dbg
        .hw_breakpoint_addr(0) == Some(text_write_bp_addr);

    if let Some(ref apis) = dbg.apis {
        let at_close = rip == apis.close_handle || rip == apis.nt_close;
        let at_virtual_alloc = rip == apis.virtual_alloc || rip == apis.nt_allocate_virtual_memory;

        if at_close {
            info!(
                rip = %format_args!("{rip:#x}"),
                is_nt_close = rip == apis.nt_close,
                "CloseHandle/NtClose hit — switching to .text write BP",
            );
            dbg.clear_hw_breakpoint(0)?;
            dbg.set_hw_breakpoint(
                0,
                image_base_usize + 0x1000,
                mida_core::HwbpType::Write,
            )?;
        } else if at_virtual_alloc {
            info!(
                rip = %format_args!("{rip:#x}"),
                is_nt_alloc = rip == apis.nt_allocate_virtual_memory,
                "VirtualAlloc/NtAllocateVirtualMemory hit — installing code section guard",
            );
            dbg.clear_hw_breakpoint(0)?;
            install_code_section_guard(
                h_process,
                image_base_usize + state.pe_info.pe_sections[0].virtual_address as usize,
                state.pe_info.base_of_data as usize - state.pe_info.pe_sections[0].virtual_address as usize,
                guard_protection,
            )?;
            *guard_installed = true;
        } else if slot0_is_text_write {
            info!(
                rip = %format_args!("{rip:#x}"),
                "Write to .text base — switching to VirtualAlloc execute BP",
            );
            dbg.clear_hw_breakpoint(0)?;
            let va_addr = dbg.apis.as_ref().map(|a| a.virtual_alloc);
            if let Some(va) = va_addr {
                dbg.set_hw_breakpoint(0, va, mida_core::HwbpType::Execute)?;
                info!(
                    virtual_alloc = %format!("{va:#x}"),
                    "VirtualAlloc HW breakpoint set (slot 0)",
                );
            }
        } else if !*guard_installed {
            debug!(
                rip = %format_args!("{rip:#x}"),
                exception = %format!("{address:#x}"),
                "Unexpected breakpoint with no guard installed"
            );
        }
    }

    Ok(())
}
