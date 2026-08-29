//! Runtime IAT observation for a protected DLL loaded in a host process.
//!
//! XC-5 (XX-III grid 2/4): observe whether a WinLicense/Oreans-protected DLL's
//! IAT slots are (a) resolved directly by the Windows loader (slots hold real
//! process addresses inside loaded modules), or (b) redirected through a VM
//! thunk (slots hold addresses inside the protected module itself or another
//! non-module region). The result decides the IAT-fix strategy for grid 3
//! (PE rebuild).
//!
//! Also snapshots the runtime `.edata` region (export table) so grid 3 can
//! rebuild the export directory from live bytes.
//!
//! Production `.unwrap()`s are invariants (WO-12 follow-up): fixed-width
//! slice `try_into()` behind explicit bound checks (no fallible path masked).
#![allow(clippy::unwrap_used)]

use std::path::Path;

use anyhow::anyhow;
use serde::Serialize;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleBaseNameW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use mida_pe::PeHeader;

use super::dump::resolve_target_module;
use crate::log::{self, LogType};

/// One resolved IAT slot.
#[derive(Debug, Clone, Serialize)]
pub struct IatSlotObservation {
    /// Imported function name (hint/name), or ordinal string.
    pub function: String,
    /// RVA of this IAT slot within the module image.
    pub iat_rva: u32,
    /// Runtime value stored in the slot (after loader resolution).
    pub value: u64,
    /// True when `value` falls inside a loaded module's image range.
    pub in_loaded_module: bool,
    /// Base name of the module containing `value` (when resolved).
    pub target_module: Option<String>,
    /// When the target is the protected module itself: a VM-thunk signature.
    pub vm_thunk: bool,
}

/// One import descriptor's observation.
#[derive(Debug, Clone, Serialize)]
pub struct ImportDescriptorObservation {
    /// DLL name from the import descriptor (e.g. "urlmon.dll").
    pub dll: String,
    /// FirstThunk (IAT RVA) of this descriptor.
    pub first_thunk_rva: u32,
    /// OriginalFirstThunk (INT RVA) — 0 when the loader uses FT as ILT.
    pub original_first_thunk_rva: u32,
    /// Resolved slots.
    pub slots: Vec<IatSlotObservation>,
}

/// Full observation report.
#[derive(Debug, Clone, Serialize)]
pub struct IatObserveReport {
    pub module: String,
    pub image_base: u64,
    pub module_size: u64,
    pub import_descriptors: Vec<ImportDescriptorObservation>,
    /// Total resolved-to-module slots vs total slots.
    pub resolved_count: usize,
    pub total_slots: usize,
    pub vm_thunk_count: usize,
    /// True when every slot resolved to a loaded module (loader-direct fill).
    pub all_loader_resolved: bool,
    /// Runtime .edata snapshot (raw bytes, hex) for export-table rebuild.
    pub edata_rva: u32,
    pub edata_size: u32,
    pub edata_hex: String,
}

/// Loaded-module ranges in the target process (base..base+size).
#[derive(Debug, Clone)]
struct ModuleRange {
    base: u64,
    size: u64,
    name: String,
}

/// Enumerate the target process's loaded modules and their image ranges.
fn enum_module_ranges(
    h_process: windows::Win32::Foundation::HANDLE,
) -> Result<Vec<ModuleRange>, anyhow::Error> {
    let mut needed: u32 = 0;
    // SAFETY: probe call — NULL buffer, size 0.
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
        return Ok(Vec::new());
    }
    let count = (needed as usize) / std::mem::size_of::<HMODULE>();
    let mut mods: Vec<HMODULE> = vec![HMODULE::default(); count];
    let mut written: u32 = 0;
    // SAFETY: mods is valid for count*sizeof(HMODULE) bytes.
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

    let mut ranges = Vec::with_capacity(got);
    for &m in &mods {
        let mut name: Vec<u16> = vec![0u16; 4096];
        let n = unsafe { GetModuleBaseNameW(h_process, m, &mut name) } as usize;
        let base_name = if n > 0 {
            String::from_utf16_lossy(&name[..n])
        } else {
            String::new()
        };
        // SAFETY: m is a valid module handle; lpmodinfo valid.
        let mut info = MODULEINFO::default();
        let ok = unsafe {
            GetModuleInformation(
                h_process,
                m,
                &mut info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        };
        if ok.is_err() {
            continue;
        }
        ranges.push(ModuleRange {
            base: info.lpBaseOfDll as u64,
            size: info.SizeOfImage as u64,
            name: base_name,
        });
    }
    Ok(ranges)
}

/// Find which loaded module (if any) contains `value`.
fn find_module_for_value(value: u64, ranges: &[ModuleRange]) -> Option<(String, bool)> {
    for r in ranges {
        if value >= r.base && value < r.base + r.size {
            return Some((r.name.clone(), false));
        }
    }
    None
}

/// Read a null-terminated C string at `rva` (within module at image_base) from
/// the process memory via `read_at`.
fn read_cstring_at(
    read_at: &dyn Fn(u64, &mut [u8]) -> Result<usize, anyhow::Error>,
    image_base: u64,
    rva: u32,
    max_len: usize,
) -> Result<String, anyhow::Error> {
    let mut buf = vec![0u8; max_len];
    let n = read_at(image_base + rva as u64, &mut buf)?;
    let s = buf[..n].split(|&b| b == 0).next().unwrap_or_default();
    Ok(String::from_utf8_lossy(s).into_owned())
}

/// Main IAT-observation entry point (XC-5, grid 2/4).
pub fn iat_observe(
    pid: u32,
    module: Option<&str>,
    out: Option<&Path>,
) -> Result<IatObserveReport, anyhow::Error> {
    // SAFETY: pid is a valid OS process id; handle closed on drop below.
    let h_process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| anyhow!("Cannot open process {pid}: {e}"))?;

    let (image_base, image_path) = resolve_target_module(h_process, module)?;
    let pe = PeHeader::from_file(&image_path)
        .map_err(|e| anyhow!("Failed to parse PE of target {image_path:?}: {e}"))?;

    // Read closure over the process handle.
    let read_at = |addr: u64, buf: &mut [u8]| -> Result<usize, anyhow::Error> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        let mut bytes_read: usize = 0;
        // SAFETY: h_process valid; buf valid; addr is a VA in the target.
        unsafe {
            ReadProcessMemory(
                h_process,
                addr as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                Some(&mut bytes_read),
            )
            .map_err(|_| anyhow!("ReadProcessMemory failed at {addr:#x}"))?;
        }
        Ok(bytes_read)
    };

    // Enumerate loaded-module ranges (for loader-direct vs VM-thunk verdict).
    let ranges = enum_module_ranges(h_process)?;
    log::log(
        LogType::Info,
        &format!(
            "iat-observe: pid={pid} module={} image_base={:#x} loaded_modules={}",
            image_path.display(),
            image_base,
            ranges.len()
        ),
    );

    let import_dir = pe.nt_headers.optional_header.data_directory[1]; // IMPORT
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return Err(anyhow!(
            "Module has no import directory (VA={:#x} size={:#x})",
            import_dir.virtual_address,
            import_dir.size
        ));
    }
    let desc_size = 20u32; // IMAGE_IMPORT_DESCRIPTOR
    let slot_size = if pe.is_64bit { 8u64 } else { 4u64 };
    let ordinal_flag: u64 = if pe.is_64bit {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };

    let mut descriptors: Vec<ImportDescriptorObservation> = Vec::new();
    let mut resolved_count = 0usize;
    let mut total_slots = 0usize;
    let mut vm_thunk_count = 0usize;

    // Iterate import descriptors at import_dir.virtual_address.
    let mut desc_rva = import_dir.virtual_address;
    loop {
        let mut desc_buf = [0u8; 20];
        let n = read_at(image_base + desc_rva as u64, &mut desc_buf)?;
        if n < 20 {
            break;
        }
        let oft = u32::from_le_bytes(desc_buf[0..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(desc_buf[12..16].try_into().unwrap());
        let ft = u32::from_le_bytes(desc_buf[16..20].try_into().unwrap());
        if name_rva == 0 && oft == 0 && ft == 0 {
            break; // terminator
        }
        let dll_name = read_cstring_at(&read_at, image_base, name_rva, 256)?;
        if dll_name.is_empty() {
            break;
        }

        // INT is the name/hint table; IAT is where the loader writes addresses.
        // Prefer OFT for names; fall back to FT when OFT==0 (loader uses FT as ILT).
        let int_rva = if oft != 0 { oft } else { ft };
        let iat_rva = ft;

        let mut slots: Vec<IatSlotObservation> = Vec::new();
        let mut slot_idx = 0u32;
        loop {
            let slot_rva = int_rva + slot_idx * slot_size as u32;
            let mut int_buf = [0u8; 8];
            let ni = read_at(image_base + slot_rva as u64, &mut int_buf)?;
            if ni < slot_size as usize {
                break;
            }
            let int_val = if pe.is_64bit {
                u64::from_le_bytes(int_buf[..8].try_into().unwrap())
            } else {
                u32::from_le_bytes(int_buf[..4].try_into().unwrap()) as u64
            };
            if int_val == 0 {
                break; // end of thunk array
            }
            // Read the IAT slot (loader-written value).
            let iat_slot_rva = iat_rva + slot_idx * slot_size as u32;
            let mut iat_buf = [0u8; 8];
            let ni2 = read_at(image_base + iat_slot_rva as u64, &mut iat_buf)?;
            if ni2 < slot_size as usize {
                break;
            }
            let iat_val = if pe.is_64bit {
                u64::from_le_bytes(iat_buf[..8].try_into().unwrap())
            } else {
                u32::from_le_bytes(iat_buf[..4].try_into().unwrap()) as u64
            };

            let function = if int_val & ordinal_flag != 0 {
                format!("#{}", int_val & 0xFFFF)
            } else {
                // hint/name RVA: read the name at int_val (the IMAGE_IMPORT_BY_NAME
                // struct starts with a hint u16 then the name).
                let mut hdr = [0u8; 2];
                let _ = read_at(image_base + int_val as u64, &mut hdr);
                let name_rva_import = int_val as u32 + 2;
                read_cstring_at(&read_at, image_base, name_rva_import, 128).unwrap_or_default()
            };

            // Classify the runtime IAT value.
            let (in_loaded_module, target_module, vm_thunk) = if iat_val == 0 {
                (false, None, false)
            } else if let Some((name, _)) = find_module_for_value(iat_val, &ranges) {
                (true, Some(name), false)
            } else if iat_val >= image_base && iat_val < image_base + pe.size_of_image() as u64 {
                // Inside the protected module itself -> VM thunk / stub dispatch.
                (false, None, true)
            } else {
                (false, None, false)
            };
            if vm_thunk {
                vm_thunk_count += 1;
            }
            if in_loaded_module {
                resolved_count += 1;
            }
            total_slots += 1;

            slots.push(IatSlotObservation {
                function,
                iat_rva: iat_slot_rva,
                value: iat_val,
                in_loaded_module,
                target_module,
                vm_thunk,
            });
            slot_idx += 1;
        }

        descriptors.push(ImportDescriptorObservation {
            dll: dll_name,
            first_thunk_rva: iat_rva,
            original_first_thunk_rva: oft,
            slots,
        });
        desc_rva += desc_size;
    }

    // Snapshot .edata (export directory) runtime bytes for grid-3 rebuild.
    let edata_dir = pe.nt_headers.optional_header.data_directory[0]; // EXPORT
    let (edata_rva, edata_size, edata_hex) =
        if edata_dir.virtual_address != 0 && edata_dir.size != 0 {
            let mut buf = vec![0u8; edata_dir.size as usize];
            let n = read_at(image_base + edata_dir.virtual_address as u64, &mut buf)?;
            buf.truncate(n);
            (edata_dir.virtual_address, edata_dir.size, hex_str(&buf))
        } else {
            (0, 0, String::new())
        };

    let all_loader_resolved = total_slots > 0 && resolved_count == total_slots;
    let report = IatObserveReport {
        module: image_path.display().to_string(),
        image_base,
        module_size: pe.size_of_image() as u64,
        import_descriptors: descriptors,
        resolved_count,
        total_slots,
        vm_thunk_count,
        all_loader_resolved,
        edata_rva,
        edata_size,
        edata_hex,
    };

    if let Some(out) = out {
        let json =
            serde_json::to_string_pretty(&report).map_err(|e| anyhow!("serialize report: {e}"))?;
        std::fs::write(out, json).map_err(|e| anyhow!("write {}: {e}", out.display()))?;
        log::log(
            LogType::Good,
            &format!(
                "iat-observe report written to {} (slots={} resolved={} vm_thunks={})",
                out.display(),
                report.total_slots,
                report.resolved_count,
                report.vm_thunk_count
            ),
        );
    }

    Ok(report)
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{find_module_for_value, hex_str, ModuleRange};

    fn ranges() -> Vec<ModuleRange> {
        vec![
            ModuleRange {
                base: 0x7ffe_0000_0000,
                size: 0x200_000,
                name: "kernel32.dll".into(),
            },
            ModuleRange {
                base: 0x7ffc_0000_0000,
                size: 0x100_000,
                name: "ntdll.dll".into(),
            },
            ModuleRange {
                base: 0x3205c_0000,
                size: 0xdb2_000,
                name: "core.dll".into(),
            },
        ]
    }

    #[test]
    fn find_inside_module() {
        let r = find_module_for_value(0x7ffe_0000_1234, &ranges());
        assert!(r.is_some());
        assert_eq!(r.unwrap().0, "kernel32.dll");
    }

    #[test]
    fn find_at_boundary() {
        // kernel32 range: 0x7ffe_0000_0000 .. 0x7ffe_0020_0000 (2 MiB)
        // base + size - 1 is inside; base + size is outside.
        let r = find_module_for_value(0x7ffe_001f_ffff, &ranges());
        assert!(r.is_some());
        assert!(find_module_for_value(0x7ffe_0020_0000, &ranges()).is_none());
        // ntdll range: 0x7ffc_0000_0000 .. 0x7ffc_0010_0000 (1 MiB)
        assert!(find_module_for_value(0x7ffc_000f_ffff, &ranges()).is_some());
        assert!(find_module_for_value(0x7ffc_0010_0000, &ranges()).is_none());
    }

    #[test]
    fn find_none_for_gap() {
        assert!(find_module_for_value(0x1000, &ranges()).is_none());
    }

    #[test]
    fn hex_empty() {
        assert_eq!(hex_str(&[]), "");
    }
}
