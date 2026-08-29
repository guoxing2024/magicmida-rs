//! Dump the `.text` section from a running process.
//!
//! XC-3-A: module-aware — by default dumps the process main module `.text`;
//! with `--module=<name>` dumps the decrypted `.text` of any loaded module
//! whose base name contains `<name>` (enables protected-DLL dumping from a
//! real LoadLibrary host).
//!
//! Production `.unwrap()`s are invariants (WO-12 follow-up): fixed-width
//! slice `try_into()` behind explicit bound checks (no fallible path masked).
#![allow(clippy::unwrap_used)]

use super::session::ReadOnlyProcessDebugger;
use crate::log::{self, LogType};
use anyhow::anyhow;
use mida_core::DebuggerCore;
use mida_pe::PeHeader;
use std::path::Path;
use tracing::debug;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleBaseNameW, GetModuleFileNameExW, LIST_MODULES_ALL,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};

/// Pure module-name matching: does `base_name` (case-insensitive) contain
/// `needle`? Centralises the substring semantics so the module scan's match
/// decision is unit-testable without a live process (XC-3-A).
pub fn module_name_matches(base_name: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    base_name.to_lowercase().contains(&needle.to_lowercase())
}

/// Resolve the module (base address + on-disk PE path) whose base name
/// contains `needle`. If `needle` is None, returns the main module via the
/// process image path and a null HMODULE sentinel meaning "main module"
/// (base resolved from the PE's preferred image base).
pub(super) fn resolve_target_module(
    h_process: windows::Win32::Foundation::HANDLE,
    needle: Option<&str>,
) -> Result<(u64, std::path::PathBuf), anyhow::Error> {
    // Main-module path (used both as default target and to resolve image_base
    let mut path_buf: Vec<u16> = vec![0u16; 4096];
    let mut len = path_buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            h_process,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(path_buf.as_mut_ptr()),
            &mut len,
        )
    };
    let main_path: std::path::PathBuf = if ok.is_ok() && len > 0 {
        String::from_utf16_lossy(&path_buf[..len as usize]).into()
    } else {
        return Err(anyhow!(
            "Cannot determine process image path for PID — \
             the process may have exited or access is denied."
        ));
    };

    let Some(needle) = needle else {
        // Default: main module. Image base = PE preferred base (main module
        // is loaded at its preferred address unless ASLR/rebasing occurred;
        // keep the historical behaviour).
        let pe = PeHeader::from_file(&main_path)?;
        return Ok((pe.image_base, main_path));
    };

    // Enumerate loaded modules and match by base name substring.
    let mut needed: u32 = 0;
    // 1st call: size probe.
    unsafe {
        EnumProcessModulesEx(
            h_process,
            std::ptr::null_mut(),
            0,
            &mut needed,
            LIST_MODULES_ALL,
        )
        .map_err(|e| anyhow!("EnumProcessModulesEx size probe failed: {e}"))?;
    }
    if needed == 0 {
        return Err(anyhow!("EnumProcessModulesEx returned 0 modules"));
    }
    let count = (needed as usize) / std::mem::size_of::<HMODULE>();
    let mut mods: Vec<HMODULE> = vec![HMODULE::default(); count];
    let mut written: u32 = 0;
    unsafe {
        EnumProcessModulesEx(
            h_process,
            mods.as_mut_ptr(),
            (count * std::mem::size_of::<HMODULE>()) as u32,
            &mut written,
            LIST_MODULES_ALL,
        )
        .map_err(|e| anyhow!("EnumProcessModulesEx failed: {e}"))?;
    }
    let got = (written as usize) / std::mem::size_of::<HMODULE>();
    mods.truncate(got);

    // XC-XXI 最小改造 (模块级): needle 以 .dll/.exe 结尾时优先精确匹配,
    // 避免子串匹配误命中系统库 (--module=core.dll 误命中 SHCORE.dll)。
    let exact_priority = needle.ends_with(".dll") || needle.ends_with(".exe");

    // 第一遍: 精确匹配 (大小写不敏感全等)
    if exact_priority {
        for &m in &mods {
            let mut name: Vec<u16> = vec![0u16; 4096];
            let n = unsafe { GetModuleBaseNameW(h_process, m, &mut name) } as usize;
            if n == 0 {
                continue;
            }
            let base_name = String::from_utf16_lossy(&name[..n]);
            if !base_name.eq_ignore_ascii_case(needle) {
                continue;
            }
            let mut fname: Vec<u16> = vec![0u16; 4096];
            let fl = unsafe { GetModuleFileNameExW(h_process, m, &mut fname) } as usize;
            let full: std::path::PathBuf = if fl > 0 {
                String::from_utf16_lossy(&fname[..fl]).into()
            } else {
                main_path.clone()
            };
            let _pe = PeHeader::from_file(&full)
                .map_err(|e| anyhow!("Failed to parse module PE {full:?}: {e}"))?;
            let base = m.0 as u64;
            debug!(module = %base_name, path = %full.display(), base = %format!("{base:#x}"),
                "Resolved target module via EXACT match");
            return Ok((base, full));
        }
    }

    for &m in &mods {
        let mut name: Vec<u16> = vec![0u16; 4096];
        let n = unsafe { GetModuleBaseNameW(h_process, m, &mut name) } as usize;
        if n == 0 {
            continue;
        }
        let base_name = String::from_utf16_lossy(&name[..n]);
        if !module_name_matches(&base_name, needle) {
            continue;
        }
        let mut fname: Vec<u16> = vec![0u16; 4096];
        let fl = unsafe { GetModuleFileNameExW(h_process, m, &mut fname) } as usize;
        let full: std::path::PathBuf = if fl > 0 {
            String::from_utf16_lossy(&fname[..fl]).into()
        } else {
            main_path.clone()
        };
        // Parse the module's on-disk PE to confirm it is a valid image and
        // obtain sections[0] for the caller's dump range (re-parsed inside
        // dump_process_code). The module base itself comes from the module
        // handle, not the PE preferred base (ASLR may rebase).
        let _pe = PeHeader::from_file(&full)
            .map_err(|e| anyhow!("Failed to parse module PE {full:?}: {e}"))?;
        let base = m.0 as u64;
        debug!(module = %base_name, path = %full.display(), base = %format!("{base:#x}"),
            "Resolved target module via module scan");
        return Ok((base, full));
    }
    Err(anyhow!(
        "No loaded module matches --module={needle} (enumerated {got} modules)"
    ))
}
/// Pure dump-range computation for a resolved module: returns the in-memory
/// `.text` start/end for `sections[0] .. base_of_data` at `image_base`.
/// Mirrors `mida_packers_themida::dump_process_code`'s range logic so the
/// bounds can be unit-tested (XC-3-A).
#[allow(dead_code)] // kept as the unit-test mirror of dump_process_code's range logic
pub fn module_dump_range(
    image_base: u64,
    is_64bit: bool,
    sec0_virtual_address: u32,
    size_of_code: u32,
    base_of_data_opt: Option<u32>,
) -> Option<(u64, u64)> {
    let start = image_base + sec0_virtual_address as u64;
    let base_of_data = if is_64bit {
        sec0_virtual_address + size_of_code
    } else {
        base_of_data_opt?
    };
    let end = image_base + base_of_data as u64;
    if end <= start {
        return None;
    }
    Some((start, end))
}

/// Dump the de-virtualised `.text` section from a running (unpacked) process.
///
/// XC-3-A: when `module` is Some, the target is the loaded module whose base
/// name contains `module`; the module's in-memory `.text` (decrypted by the
/// shell at DllMain/export-call time) is dumped. The dump range is
/// `module_base + sections[0].virtual_address .. + base_of_data`, matching
/// the main-module logic but at the resolved module base.
pub fn dump_process_code(
    pid: u32,
    unpacked_file: &Path,
    module: Option<&str>,
) -> Result<(), anyhow::Error> {
    // SAFETY: pid is a valid OS process ID; the handle is owned by
    // ReadOnlyProcessDebugger below and closed automatically on drop.
    let h_process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| anyhow!("Cannot open process {}: {e}", pid))?;

    let (image_base, image_path) = resolve_target_module(h_process, module)?;

    let pe = PeHeader::from_file(&image_path)
        .map_err(|e| anyhow!("Failed to parse PE of target: {e}"))?;

    let is_64bit = pe.is_64bit;
    debug!(?image_path, is_64bit, base = %format!("{image_base:#x}"), "Resolved dump target");

    // h_process ownership transfers here; it is closed via Drop on any return
    // path (including the early-return below).
    let ro_dbg = ReadOnlyProcessDebugger::new(h_process, image_base);

    let written = mida_packers_themida::dump_process_code(&ro_dbg, &pe, image_base, unpacked_file)
        .map_err(|e| anyhow!("dump_process_code failed: {e}"))?;

    log::log(
        LogType::Good,
        &format!("Dumped {} bytes to {}", written, unpacked_file.display()),
    );

    Ok(())
}

/// XC-6 (XX-III grid 3/4): full-image dump of a loaded module in a running
/// process, via the `mida_pe::dump_process` pipeline (headers + all sections
/// + IAT fix + export table + data sections).
///
/// `keep_runtime_base` implements XC-6-A strategy B: the rebuilt PE's
/// ImageBase stays at the runtime ASLR base and DYNAMIC_BASE is cleared, so
/// every absolute address captured in the live image (already rebased by the
/// loader) is self-consistent without a `.reloc` directory (which the
/// protector stripped to a trivial placeholder).
pub fn dump_module_full(
    pid: u32,
    output: &Path,
    module: Option<&str>,
    keep_runtime_base: bool,
    shrink: bool,
) -> Result<(), anyhow::Error> {
    use mida_pe::{ContainerRestoreMode, DumpOptions, DumpProfile, DumpTiming};

    // SAFETY: pid is a valid OS process ID; the handle is owned by
    // ReadOnlyProcessDebugger below and closed automatically on drop.
    let h_process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| anyhow!("Cannot open process {}: {e}", pid))?;

    let (image_base, image_path) = resolve_target_module(h_process, module)?;
    let pe = PeHeader::from_file(&image_path)
        .map_err(|e| anyhow!("Failed to parse PE of target: {e}"))?;

    debug!(?image_path, base = %format!("{image_base:#x}"), "Resolved dump-module target");

    let mut ro_dbg = ReadOnlyProcessDebugger::new(h_process, image_base);

    // XC-6: Oreans/WinLicense DLLs wipe the IAT data directory (dir[12])
    // while keeping the IMPORT directory (dir[1]) intact. Derive the IAT
    // region from the import descriptors' FirstThunk chain so dump_process
    // can fix imports (second grid already proved loader-direct fill).
    let import_dir = pe.nt_headers.optional_header.data_directory[1];
    let iat_dir = pe.nt_headers.optional_header.data_directory[12];
    let iat_location: Option<(usize, usize)> = if iat_dir.virtual_address == 0 || iat_dir.size == 0
    {
        if import_dir.virtual_address != 0 && import_dir.size != 0 {
            let slot = if pe.is_64bit { 8usize } else { 4usize };
            let mut first_ft = 0u32;
            let mut last_ft_end = 0u32;
            let mut buf = [0u8; 20];
            let mut rva = import_dir.virtual_address;
            loop {
                let n = ro_dbg.read_memory(image_base as usize + rva as usize, &mut buf);
                let n = n.unwrap_or(0);
                if n < 20 {
                    break;
                }
                let name_rva = u32::from_le_bytes(buf[12..16].try_into().unwrap());
                let ft = u32::from_le_bytes(buf[16..20].try_into().unwrap());
                if name_rva == 0 && ft == 0 {
                    break;
                }
                if ft != 0 {
                    if first_ft == 0 {
                        first_ft = ft;
                    }
                    let end = ft + slot as u32;
                    if end > last_ft_end {
                        last_ft_end = end;
                    }
                }
                rva += 20;
            }
            if first_ft != 0 && last_ft_end > first_ft {
                let va = image_base as usize + first_ft as usize;
                let size = (last_ft_end - first_ft) as usize;
                log::log(
                    LogType::Info,
                    &format!(
                        "Derived IAT region from import descriptors: va={va:#x} size={size:#x}"
                    ),
                );
                Some((va, size))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let dump_opts = DumpOptions {
        image_base,
        // Preserve the on-disk entry point (DllMain semantics for DLLs; the
        // packed EP is not meaningful post-decrypt).
        entry_point: pe.entry_point,
        fix_imports: true,
        create_data_sections: true,
        shrink,
        output_path: output.to_path_buf(),
        executable_path: Some(image_path.clone()),
        iat_location,
        additional_iat_locations: Vec::new(),
        early_section_snapshots: Vec::new(),
        container_restore: ContainerRestoreMode::Off,
        profile: DumpProfile::OreansClassic,
        security_cookie_rva: None,
        security_cookie_complement_rva: None,
        pure_rebuild: false,
        dump_timing: DumpTiming::Immediate,
        section_content_reference: None,
        capture_policy: mida_pe::DumpCapturePolicy::default(),
        keep_runtime_base,
    };

    mida_pe::dump_process(&mut ro_dbg, &dump_opts)
        .map_err(|e| anyhow!("dump_process failed: {e}"))?;

    log::log(
        LogType::Good,
        &format!(
            "Full module dump written to {} (keep_runtime_base={})",
            output.display(),
            keep_runtime_base
        ),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{module_dump_range, module_name_matches};

    #[test]
    fn module_name_matches_substring_case_insensitive() {
        assert!(module_name_matches("core.dll", "core"));
        assert!(module_name_matches("CORE.DLL", "core"));
        assert!(module_name_matches("my-core-module.dll", "core"));
        assert!(module_name_matches("core.dll", "CORE"));
    }

    #[test]
    fn module_name_matches_negative() {
        assert!(!module_name_matches("other.dll", "core"));
        assert!(module_name_matches("coreless.dll", "core")); // substring semantics: "coreless" contains "core"
        assert!(!module_name_matches("core.dll", "")); // empty needle never matches
        assert!(!module_name_matches("", "core"));
        assert!(!module_name_matches("core.dll", "other.dll"));
    }

    #[test]
    fn module_dump_range_x64_uses_size_of_code() {
        // x64: base_of_data = sections[0].virtual_address + size_of_code
        let (start, end) = module_dump_range(
            0x3205C0000, // core.dll image base
            true,
            0x1000,   // sections[0].virtual_address
            0x1017C0, // size_of_code
            None,     // x64 ignores base_of_data
        )
        .expect("range");
        assert_eq!(start, 0x3205C1000);
        assert_eq!(end, 0x3205C0000 + 0x1000 + 0x1017C0);
    }

    #[test]
    fn module_dump_range_x86_uses_base_of_data() {
        let (start, end) =
            module_dump_range(0x400000, false, 0x1000, 0x2000, Some(0x7000)).expect("range");
        assert_eq!(start, 0x401000);
        assert_eq!(end, 0x407000);
    }

    #[test]
    fn module_dump_range_empty_rejected() {
        // end <= start -> None (degenerate PE)
        assert!(module_dump_range(0x1000, true, 0x2000, 0, None).is_none());
        // x86 missing base_of_data -> None
        assert!(module_dump_range(0x1000, false, 0x1000, 0x1000, None).is_none());
    }
}
