//! Remote module enumeration and export table reading.
//!
//! Extracted from `dumper.rs` — corresponds to `TDumper.TakeModuleSnapshot`
//! and `TDumper.GatherModuleExportsFromRemoteProcess` in `Dumper.pas`.

use tracing::{debug, warn};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::error::PeError;

use super::helpers::{read_ptr, MAX_GAP_SLOTS};
use super::types::{is_api_address, RemoteModule};
use crate::import_table::iat_slot_size;

// -----------------------------------------------------------------------
// determine_iat_size
// -----------------------------------------------------------------------

/// Determine the actual size of the IAT by scanning for valid API addresses.
///
/// Corresponds to `TDumper.DetermineIATSize` in `Dumper.pas`.
///
/// Scans up to `MAX_IAT_SLOTS` slots.  Track the last offset where a valid
/// API address was found; stop when no valid address is seen within
/// `MAX_GAP_SLOTS` slots of the last valid one.
pub(crate) fn determine_iat_size(
    process_handle: HANDLE,
    pid: u32,
    image_base: u64,
    is_64bit: bool,
    iat_data: &[u8],
) -> Result<usize, PeError> {
    let modules = take_module_snapshot(process_handle, pid, image_base, is_64bit)?;
    let ptr_size = iat_slot_size(is_64bit);
    let max_slots = iat_data.len() / ptr_size;

    let mut last_valid_offset: usize = 0;
    let mut i: usize = 0;

    while i < max_slots && (last_valid_offset == 0 || i < last_valid_offset + MAX_GAP_SLOTS) {
        let val = read_ptr(iat_data, i * ptr_size, is_64bit);

        if is_api_address(&modules, val) {
            last_valid_offset = i * ptr_size;
        }

        i += 1;
    }

    Ok(last_valid_offset + ptr_size)
}

// -----------------------------------------------------------------------
// take_module_snapshot
// -----------------------------------------------------------------------

/// Enumerate all loaded modules in the target process and parse their export
/// tables.
///
/// Corresponds to `TDumper.TakeModuleSnapshot` in `Dumper.pas`.
///
/// Uses the ToolHelp API (`CreateToolhelp32Snapshot` → `Module32FirstW` /
/// `Module32NextW`) to enumerate modules, then calls
/// [`gather_module_exports_from_remote`] for each one.
///
/// # Parameters
///
/// - `process_handle` — handle to the target process with `PROCESS_VM_READ`.
/// - `pid` — target process ID (used for the snapshot).
/// - `image_base` — base address of the main (target) module. This module is
///   skipped (it contains no import-relevant exports).
/// - `is_64bit` — `true` if the target is a 64-bit process.
///
/// # Errors
///
/// Logs a warning and skips modules whose export table cannot be read (e.g.
/// because they are paged out).  Returns an empty list only if the ToolHelp
/// snapshot itself fails.
pub fn take_module_snapshot(
    process_handle: HANDLE,
    pid: u32,
    image_base: u64,
    is_64bit: bool,
) -> Result<Vec<RemoteModule>, PeError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    };
    use windows::Win32::Foundation::CloseHandle;

    // 1. Create the module snapshot
    // SAFETY: pid is the target process ID obtained from the debugger.
    let h_snap = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE, pid)
    }
    .map_err(|e| {
        PeError::Parse(format!(
            "CreateToolhelp32Snapshot failed: {:#x}",
            e.code().0
        ))
    })?;

    let mut modules: Vec<RemoteModule> = Vec::new();

    // 2. Enumerate modules
    let mut me = MODULEENTRY32W::default();
    me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    // SAFETY: h_snap is a valid handle; me is a valid pointer to a
    // MODULEENTRY32W whose dwSize is correctly filled in.
    let first_ok = unsafe { Module32FirstW(h_snap, &mut me) };

    if first_ok.is_ok() {
        loop {
            // Skip the main module (the target EXE itself).
            if me.hModule.0 as u64 != image_base {
                let base = me.modBaseAddr as u64;
                let end = base + me.modBaseSize as u64;
                let name = String::from_utf16_lossy(&me.szModule)
                    .trim_end_matches('\0')
                    .to_lowercase();

                debug!(
                    base = format!("{base:#x}"),
                    end = format!("{end:#x}"),
                    %name,
                    "Enumerating module"
                );

                match gather_module_exports_from_remote(
                    process_handle,
                    base,
                    is_64bit,
                ) {
                    Ok((exports, forwards)) => {
                        modules.push(RemoteModule {
                            base,
                            end_off: end,
                            name,
                            exports,
                            forwards,
                        });
                    }
                    Err(e) => {
                        warn!(
                            %name,
                            error = %e,
                            "Failed to read exports for module, skipping"
                        );
                    }
                }
            }

            // SAFETY: h_snap is valid; me was populated by a previous call to
            // Module32FirstW or Module32NextW.
            let next_ok = unsafe { Module32NextW(h_snap, &mut me) };
            if next_ok.is_err() {
                break;
            }
        }
    }

    // 3. Clean up
    // SAFETY: h_snap is a valid snapshot handle.
    unsafe { let _ = CloseHandle(h_snap); }

    debug!(
        module_count = modules.len(),
        "Module snapshot complete"
    );

    Ok(modules)
}

// -----------------------------------------------------------------------
// gather_module_exports_from_remote
// -----------------------------------------------------------------------

/// Read the export table of a single module from the remote process.
///
/// Uses `ReadProcessMemory` to read the module's PE headers in the target
/// address space, finds the export directory, and builds a map:
/// `function_address → function_name` plus a list of forward exports.
///
/// Corresponds to `TDumper.GatherModuleExportsFromRemoteProcess` in
/// `Dumper.pas`.
pub(crate) fn gather_module_exports_from_remote(
    process_handle: HANDLE,
    module_base: u64,
    _is_64bit: bool,
) -> Result<
    (
        std::collections::HashMap<u64, String>,
        Vec<(String, u64)>,
    ),
    PeError,
> {
    // Helper: read memory from the target process.
    fn read_remote(handle: HANDLE, addr: u64, buf: &mut [u8]) -> Result<usize, PeError> {
        let mut bytes: usize = 0;
        // SAFETY: handle is a valid process handle; addr is a virtual address
        // within a loaded module; buf is writable for the given length.
        unsafe {
            ReadProcessMemory(
                handle,
                addr as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                Some(&mut bytes),
            )
            .map_err(|e| {
                PeError::Parse(format!(
                    "ReadProcessMemory({addr:#x}, {len}) failed: {e:?}",
                    addr = addr,
                    len = buf.len()
                ))
            })?;
        }
        Ok(bytes)
    }

    // Helper to safely extract fixed-size byte arrays
    let read_u32_le = |buf: &[u8], offset: usize| -> Result<u32, PeError> {
        buf.get(offset..offset + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(PeError::Parse(format!("Failed to read u32 at offset {}", offset)))
    };

    let read_u16_le = |buf: &[u8], offset: usize| -> Result<u16, PeError> {
        buf.get(offset..offset + 2)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or(PeError::Parse(format!("Failed to read u16 at offset {}", offset)))
    };

    // 1. Read DOS header (first 64 bytes for the e_lfanew field).
    let mut dos_buf = [0u8; 64];
    read_remote(process_handle, module_base, &mut dos_buf)?;
    let e_lfanew = read_u32_le(&dos_buf, 60)? as u64;

    // 2. Read NT signature + file header + optional header magic.
    // Maximum size we need: 4 (sig) + 20 (file hdr) + 112 (opt hdr PE32+) = 136.
    // Round up to cover the data directories.
    const MAX_NT_HEADER: usize = 512;
    let mut nt_buf = [0u8; MAX_NT_HEADER];
    let _ = read_remote(process_handle, module_base + e_lfanew, &mut nt_buf)?;

    let pe_sig = read_u32_le(&nt_buf, 0)?;
    if pe_sig != 0x00004550 {
        return Err(PeError::InvalidPeSignature);
    }

    // Optional header magic (signature(4) + file_header(20) = offset 24)
    let magic = read_u16_le(&nt_buf, 24)?;

    // Data directory offset within optional header
    let dd_off: usize = if magic == 0x20B {
        // PE32+: data directories at 4+20+112 = 136
        136
    } else if magic == 0x10B {
        // PE32: data directories at 4+20+96 = 120
        120
    } else {
        return Err(PeError::UnknownMagic(magic));
    };

    // Export directory is the first data directory (index 0).
    let exp_va = read_u32_le(&nt_buf, dd_off)?;
    let exp_size = read_u32_le(&nt_buf, dd_off + 4)?;

    if exp_va == 0 || exp_size < 40 {
        // No exports in this module
        return Ok((std::collections::HashMap::new(), Vec::new()));
    }

    // 3. Read the export directory.
    let mut exp_buf = vec![0u8; exp_size as usize];
    read_remote(
        process_handle,
        module_base + exp_va as u64,
        &mut exp_buf,
    )?;

    // IMAGE_EXPORT_DIRECTORY layout:
    //   +0  Characteristics     (u32)
    //   +4  TimeDateStamp       (u32)
    //   +8  MajorVersion        (u16)
    //   +10 MinorVersion        (u16)
    //   +12 Name                (u32)
    //   +16 Base                (u32)
    //   +20 NumberOfFunctions   (u32)
    //   +24 NumberOfNames       (u32)
    //   +28 AddressOfFunctions  (u32)
    //   +32 AddressOfNames      (u32)
    //   +36 AddressOfNameOrdinals (u32)

    // Helper for export buffer reads
    let read_exp_u32 = |offset: usize| -> Result<u32, PeError> {
        exp_buf.get(offset..offset + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(PeError::Parse(format!("Failed to read u32 from export at offset {}", offset)))
    };

    let read_exp_u16 = |offset: usize| -> Result<u16, PeError> {
        exp_buf.get(offset..offset + 2)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or(PeError::Parse(format!("Failed to read u16 from export at offset {}", offset)))
    };

    let num_functions = read_exp_u32(20)? as usize;
    let num_names = read_exp_u32(24)? as usize;
    let addr_of_functions = read_exp_u32(28)?;
    let addr_of_names = read_exp_u32(32)?;
    let addr_of_name_ordinals = read_exp_u32(36)?;
    let ordinal_base = read_exp_u32(16)?;

    // Helper: convert an RVA within the export section to a buffer offset.
    let rva_to_off = |rva: u32| -> Option<usize> {
        if rva >= exp_va && rva < exp_va + exp_size {
            Some((rva - exp_va) as usize)
        } else {
            None
        }
    };

    let mut exports: std::collections::HashMap<u64, String> =
        std::collections::HashMap::new();
    let mut forwards: Vec<(String, u64)> = Vec::new();

    // Track which function indices have names assigned.
    let mut named = vec![false; num_functions];

    // 4. Enumerate named exports.
    for i in 0..num_names {
        let name_off = match rva_to_off(addr_of_names + i as u32 * 4) {
            Some(off) if off + 4 <= exp_buf.len() => off,
            _ => break,
        };
        let ord_off = match rva_to_off(addr_of_name_ordinals + i as u32 * 2) {
            Some(off) if off + 2 <= exp_buf.len() => off,
            _ => break,
        };

        let name_rva = match read_exp_u32(name_off) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let func_index = match read_exp_u16(ord_off) {
            Ok(v) => v as usize,
            Err(_) => continue,
        };

        let fn_off = match rva_to_off(addr_of_functions + func_index as u32 * 4) {
            Some(off) if off + 4 <= exp_buf.len() => off,
            _ => continue,
        };
        let func_rva = match read_exp_u32(fn_off) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Read the name string
        if let Some(ns_off) = rva_to_off(name_rva) {
            if ns_off < exp_buf.len() {
                let end = exp_buf[ns_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(exp_buf.len() - ns_off);
                let name =
                    String::from_utf8_lossy(&exp_buf[ns_off..ns_off + end]).into_owned();

                let addr = module_base + func_rva as u64;
                exports.insert(addr, name);

                if func_index < num_functions {
                    named[func_index] = true;
                }

                // Check for forward export: the function RVA points inside the
                // export section (i.e., it's a string rather than an actual
                // code address).
                if let Some(fwd_off) = rva_to_off(func_rva) {
                    if fwd_off < exp_buf.len() {
                        let fwd_end = exp_buf[fwd_off..]
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(exp_buf.len() - fwd_off);
                        let fwd_str = String::from_utf8_lossy(
                            &exp_buf[fwd_off..fwd_off + fwd_end],
                        )
                        .into_owned();
                        // Skip private forwards containing ".#"
                        if !fwd_str.contains(".#") {
                            forwards.push((fwd_str, addr));
                        }
                    }
                }
            }
        }
    }

    // 5. Add ordinal exports for unnamed function entries.
    for i in 0..num_functions {
        if named[i] {
            continue;
        }
        let fn_off = match rva_to_off(addr_of_functions + i as u32 * 4) {
            Some(off) if off + 4 <= exp_buf.len() => off,
            _ => continue,
        };
        let func_rva = match read_exp_u32(fn_off) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ordinal = ordinal_base + i as u32;
        exports.insert(module_base + func_rva as u64, format!("#{ordinal}"));
    }

    Ok((exports, forwards))
}

// MAX_IAT_SLOTS is used in import_rebuild.rs, not here.
