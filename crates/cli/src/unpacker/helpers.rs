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

/// Profile file name.  One file for all packers; the profile is selected by
/// the `CurrentProfile` key inside it, not by the file name.
const SCYLLA_INI_NAME: &str = "scylla_hide.ini";

/// Resolve the absolute path to the ScyllaHide injector binary.
pub(super) fn scylla_injector_path() -> PathBuf {
    exe_dir().join(SCYLLA_INJECTOR_NAME)
}

/// Resolve the absolute path to the ScyllaHide hook library DLL.
pub(super) fn scylla_hook_path() -> PathBuf {
    exe_dir().join(SCYLLA_HOOK_NAME)
}

/// Resolve the absolute path to the ScyllaHide profile file.
///
/// The injector takes **no ini argument** (measured: `InjectorCLIx64.exe
/// pid:<pid> <HookLibraryx64.dll> nowait`), so it reads `scylla_hide.ini` from
/// the directory it lives in — which is where the profile has to be rewritten
/// for per-packer selection.
pub(super) fn scylla_ini_path() -> PathBuf {
    exe_dir().join(SCYLLA_INI_NAME)
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

/// Flatten the PE section table into `(rva, virtual_size, is_executable)`
/// triples, the shape the IAT locator consumes.
///
/// The locator needs this to tell a real data section from the unmapped-looking
/// gap between two sections: gaps are mapped and readable at run time, so
/// `read_memory` on one succeeds and returns zeroes.  Memory content cannot
/// distinguish them; the section table can.
pub(super) fn section_table(sections: &[mida_pe::PeSection]) -> Vec<(u32, u32, bool)> {
    sections
        .iter()
        .map(|s| {
            (
                s.virtual_address,
                s.virtual_size,
                s.characteristics & 0x2000_0000 != 0,
            )
        })
        .collect()
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
// Packed-DLL detection
// ---------------------------------------------------------------------------

/// Themida v3 x64 section that only exists in a packed image, never in a
/// normal host EXE.  Eight bytes, space-padded, exactly as it appears in the
/// section table.
const WINLICE_SECTION: &[u8; 8] = b".winlice";

/// Return the base address of `candidate` if it is the packed DLL.
///
/// Called for every `LOAD_DLL` event.  The debuggee is our loader host, so the
/// first thing the loader reports is the host EXE and then the system DLLs; the
/// packed DLL is identified by its `.winlice` section rather than by path,
/// because the path in `LOAD_DLL` is ANSI and may be non-ASCII.
///
/// `expected_text_rva` is the `.text` RVA parsed from the file on disk.  A
/// matching `.winlice` is enough on its own, but requiring the section table to
/// agree with the file rules out a stray `ntdll` copy that happens to contain
/// the string.
pub(super) fn detect_packed_dll(
    dbg: &ProcessSession,
    candidate: usize,
    expected_text_rva: u32,
) -> Option<usize> {
    let sections = read_remote_sections(dbg, candidate)?;

    let has_winlice = sections.iter().any(|s| &s.name == WINLICE_SECTION);
    if !has_winlice {
        return None;
    }

    // The image we care about must agree with the on-disk section 0 RVA.
    let text_rva = sections.first()?.virtual_address;
    if text_rva != expected_text_rva {
        return None;
    }

    Some(candidate)
}

/// A section header read out of a remote process.
struct RemoteSection {
    name: [u8; 8],
    virtual_address: u32,
}

/// Parse the section table of the PE mapped at `base` in the debuggee.
fn read_remote_sections(dbg: &ProcessSession, base: usize) -> Option<Vec<RemoteSection>> {
    let mut dos = [0u8; 0x40];
    dbg.read_memory(base, &mut dos).ok()?;
    if &dos[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?) as usize;
    let nt = base.checked_add(e_lfanew)?;

    let mut sig = [0u8; 4];
    dbg.read_memory(nt, &mut sig).ok()?;
    if &sig != b"PE\0\0" {
        return None;
    }

    let mut fh = [0u8; 20];
    dbg.read_memory(nt + 4, &mut fh).ok()?;
    let num_sections = u16::from_le_bytes(fh[2..4].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(fh[16..18].try_into().ok()?) as usize;
    // A sane PE has a handful of sections; bail on a corrupt header rather than
    // trying to read a million headers out of the target.
    if num_sections == 0 || num_sections > 96 {
        return None;
    }

    let sec_start = nt + 4 + 20 + opt_size;
    let mut out = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let mut sh = [0u8; 40];
        dbg.read_memory(sec_start + i * 40, &mut sh).ok()?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&sh[0..8]);
        out.push(RemoteSection {
            name,
            virtual_address: u32::from_le_bytes(sh[12..16].try_into().ok()?),
        });
    }
    Some(out)
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

// ---------------------------------------------------------------------------
// read_tls_callback_oep
// ---------------------------------------------------------------------------

/// Read a packed DLL's real entry point out of the shell's own TLS callback
/// array.
///
/// # Why this exists
///
/// An EXE target's OEP is found by arming a `PAGE_NOACCESS` guard over `.text`
/// and taking the first execute fault.  A packed DLL cannot use that mechanism:
/// at the moment the guard would be armed the shell is still inside its own
/// `DllMain`, and the guard's fault/retry cycle derails it.  Measured with an
/// identical debugger and ScyllaHide injection:
///
/// | `.text` guard | `.bss` non-zero | `hinstDLL` global |
/// |---|---|---|
/// | armed   | 0   | 0        |
/// | not armed | 177 | set    |
///
/// The guard is also unnecessary.  Themida's DLL shell publishes the real
/// `DllMain` into its TLS callback array during startup: measured on the
/// reference `core.dll` after a full boot, `[image_base + 0x170010]` holds
/// `image_base + 0x2BB10`, which is exactly the OEP the guarded path discovers.
///
/// # Returns
///
/// The first callback address that lies inside the image and is non-zero, or
/// `None` while the array is still empty (the caller retries).
pub(super) fn read_tls_callback_oep(
    dbg: &ProcessSession,
    image_base: usize,
    image_boundary: usize,
) -> Option<usize> {
    const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

    // Locate the TLS directory from the live headers rather than from the
    // in-memory `ThemidaPeInfo`, which does not carry the data directories.
    let mut headers = vec![0u8; 0x1000];
    if dbg.read_memory(image_base, &mut headers).is_err() {
        return None;
    }
    let pe = mida_pe::PeHeader::from_bytes(&headers).ok()?;
    let tls_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
    if tls_dir.virtual_address == 0 || tls_dir.size == 0 {
        return None;
    }

    // The callback array is a pointer-sized slot at the end of the TLS
    // directory: StartRawData, EndRawData, AddressOfIndex, AddressOfCallbacks.
    // The directory is itself an address, not an RVA, so read it live rather
    // than mapping it through the file.
    let ptr = std::mem::size_of::<usize>();
    let dir_addr = image_base + tls_dir.virtual_address as usize;
    let mut dir = vec![0u8; ptr * 4];
    if dbg.read_memory(dir_addr, &mut dir).is_err() {
        return None;
    }
    let read_ptr = |off: usize| -> usize {
        if ptr == 8 {
            u64::from_le_bytes(dir[off..off + 8].try_into().unwrap_or([0u8; 8])) as usize
        } else {
            u32::from_le_bytes(dir[off..off + 4].try_into().unwrap_or([0u8; 4])) as usize
        }
    };

    let callbacks = read_ptr(ptr * 3);
    if callbacks == 0 {
        return None;
    }

    // Walk the array: it is a NULL-terminated list of absolute addresses.
    for i in 0..8 {
        let mut slot = vec![0u8; ptr];
        if dbg.read_memory(callbacks + i * ptr, &mut slot).is_err() {
            return None;
        }
        let addr = if ptr == 8 {
            u64::from_le_bytes(slot[..8].try_into().unwrap_or([0u8; 8])) as usize
        } else {
            u32::from_le_bytes(slot[..4].try_into().unwrap_or([0u8; 4])) as usize
        };
        if addr == 0 {
            return None; // end of list; nothing published yet
        }
        // Only accept an address that lies inside the image: the shell also
        // publishes its own internal callbacks, which are not the entry point.
        let rva = addr.wrapping_sub(image_base);
        if rva < image_boundary.wrapping_sub(image_base) {
            return Some(addr);
        }
    }
    None
}



// ---------------------------------------------------------------------------
// live_bss_activity
// ---------------------------------------------------------------------------

/// Count non-zero bytes in the image's writable data sections.
///
/// # Why this is the right "initialisation finished" signal
///
/// A packed DLL's shell writes its state into uninitialised/writable sections
/// (`.bss`, `.data`) during `DllMain`.  Measured on the reference `core.dll`,
/// injected with ScyllaHide and running under this debugger, the shell goes from
/// 0 to 177 non-zero bytes in one step around 300 ms and then stops changing.
///
/// The TLS callback array becomes non-zero at that same moment, so "the OEP is
/// published" alone is not a safe stop condition — sampling finer than the
/// 50 ms resolution used for that measurement shows the callback landing a few
/// instructions before the rest of the state.  Waiting for the *activity* to
/// settle is sample-independent: it does not name any RVA or any particular
/// global, so it works for any packed DLL rather than just this one.
pub(super) fn live_data_nonzero(dbg: &ProcessSession, image_base: usize, pe_sections: &[mida_pe::PeSection]) -> usize {
    let mut total = 0;
    for sec in pe_sections {
        // Only writable data sections carry runtime state; skip code and
        // read-only sections, which are static from the file.
        let ch = sec.characteristics;
        let writable = ch & 0x8000_0000 != 0;
        let executable = ch & 0x2000_0000 != 0;
        if !writable || executable {
            continue;
        }
        let va = sec.virtual_address as usize;
        let size = (sec.virtual_size as usize).min(0x100_000);
        if size == 0 {
            continue;
        }
        let mut buf = vec![0u8; size];
        if dbg.read_memory(image_base + va, &mut buf).is_ok() {
            total += buf.iter().filter(|b| **b != 0).count();
        }
    }
    total
}
