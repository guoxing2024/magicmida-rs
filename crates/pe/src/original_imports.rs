//! Resolve imports from the original PE file's .idata section.
//!
//! This corresponds to `TDumper.GetOriginalImports` in `Dumper.pas`.
//! Instead of trying to read the (possibly encrypted) IAT from the live
//! process, we read the import table from the **original file on disk**,
//! extract DLL and function names, and resolve API addresses using
//! `GetProcAddress` in the debugger process (which shares ASLR base with
//! the target for well-known DLLs).

use std::path::Path;

use crate::header::PeHeader;
use tracing::{debug, info, warn};

/// Read the import table from the original PE file on disk.
///
/// Returns a list of (DLL name, Vec<function name or ordinal>).
pub fn read_original_import_table(path: &Path) -> Vec<(String, Vec<String>)> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            warn!("Cannot read original PE: {e}");
            return Vec::new();
        }
    };

    let pe = match PeHeader::from_bytes(&bytes) {
        Ok(p) => p,
        Err(e) => {
            warn!("Cannot parse original PE: {e}");
            return Vec::new();
        }
    };

    let import_dir = pe.nt_headers.optional_header.data_directory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        debug!("No import directory in original PE");
        return Vec::new();
    }

    // Find the section containing the import table
    let import_rva = import_dir.virtual_address as usize;
    let section = pe.sections.iter().find(|s| {
        let sec_start = s.virtual_address as usize;
        let sec_end = sec_start + s.virtual_size as usize;
        import_rva >= sec_start && import_rva < sec_end
    });

    let section = match section {
        Some(s) => s,
        None => {
            warn!("Import directory RVA {import_rva:#x} not found in any section");
            return Vec::new();
        }
    };

    let mut result: Vec<(String, Vec<String>)> = Vec::new();

    // The import table is in the section's raw data
    // We need to read from the file at the section's raw offset
    let sec_va = section.virtual_address as usize;
    let sec_raw_offset = section.raw_offset as usize;
    let sec_raw_size = section.raw_size as usize;

    if sec_raw_offset + sec_raw_size > bytes.len() {
        warn!("Section raw data extends past end of file");
        return Vec::new();
    }

    let section_data = &bytes[sec_raw_offset..sec_raw_offset + sec_raw_size];

    // Parse import descriptors
    let import_offset = import_rva - sec_va;
    let desc_size = 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)

    let mut desc_offset = import_offset;
    while desc_offset + desc_size <= section_data.len() {
        let desc = &section_data[desc_offset..desc_offset + desc_size];

        let original_first_thunk = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
        let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]);
        let first_thunk = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);

        if name_rva == 0 {
            break;
        }

        // Read DLL name (may be in a different section)
        let dll_name = {
            let name_sec = pe.sections.iter().find(|s| {
                let start = s.virtual_address as usize;
                let end = start + s.virtual_size as usize;
                (name_rva as usize) >= start && (name_rva as usize) < end
            });
            match name_sec {
                Some(ns) => {
                    let off =
                        (name_rva as usize) - ns.virtual_address as usize + ns.raw_offset as usize;
                    if off < bytes.len() {
                        read_cstring(&bytes, off)
                    } else {
                        String::new()
                    }
                }
                None => String::new(),
            }
        };

        if dll_name.is_empty() {
            break;
        }

        // Read thunk data to get function names.
        // Thunks may be in a different section than the import descriptors,
        // so we use RVA-to-offset conversion via the PE section table.
        let mut functions: Vec<String> = Vec::new();
        // Prefer OriginalFirstThunk: after the loader resolves imports,
        // FirstThunk contains process addresses rather than hint/name RVAs.
        // Some rebuilt files intentionally set OFT to zero, so fall back to
        // FirstThunk for those Pascal-compatible tables.
        let mut thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        } as usize;
        let thunk_size = if pe.is_64bit { 8 } else { 4 };
        let ordinal_flag = if pe.is_64bit {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000
        };
        loop {
            // Find the section containing this RVA
            let thunk_sec = pe.sections.iter().find(|s| {
                let start = s.virtual_address as usize;
                let end = start + s.virtual_size as usize;
                thunk_rva >= start && thunk_rva < end
            });
            let thunk_sec = match thunk_sec {
                Some(s) => s,
                None => break,
            };
            let thunk_off =
                thunk_rva - thunk_sec.virtual_address as usize + thunk_sec.raw_offset as usize;
            if thunk_off + thunk_size > bytes.len() {
                break;
            }

            let thunk = if pe.is_64bit {
                u64::from_le_bytes(
                    bytes[thunk_off..thunk_off + 8]
                        .try_into()
                        .unwrap_or_default(),
                )
            } else {
                u32::from_le_bytes(
                    bytes[thunk_off..thunk_off + 4]
                        .try_into()
                        .unwrap_or_default(),
                ) as u64
            };

            if thunk == 0 {
                break;
            }

            if thunk & ordinal_flag != 0 {
                let ordinal = thunk & 0xFFFF;
                functions.push(format!("#{ordinal}"));
            } else {
                // Import by name - hint/name at thunk RVA
                let hint_rva = (thunk & 0x7fff_ffff) as usize;
                let hint_sec = pe.sections.iter().find(|s| {
                    let start = s.virtual_address as usize;
                    let end = start + s.virtual_size as usize;
                    hint_rva >= start && hint_rva < end
                });
                if let Some(hs) = hint_sec {
                    let hint_off = hint_rva - hs.virtual_address as usize + hs.raw_offset as usize;
                    if hint_off + 2 < bytes.len() {
                        let func_name = read_cstring(&bytes, hint_off + 2);
                        if !func_name.is_empty() {
                            functions.push(func_name);
                        }
                    }
                }
            }

            thunk_rva += thunk_size;
        }

        if !functions.is_empty() {
            result.push((dll_name.to_lowercase(), functions));
        }

        desc_offset += desc_size;
    }

    info!(
        "Read {} import modules with {} total functions from original PE",
        result.len(),
        result.iter().map(|(_, f)| f.len()).sum::<usize>()
    );

    result
}

fn read_cstring(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    let slice = &data[offset..end];
    String::from_utf8_lossy(slice).to_string()
}

/// Resolve API addresses using GetProcAddress for well-known DLLs.
///
/// Returns a map of (DLL name, function name) -> API address.
///
/// # DLL handle lifetime
///
/// Each `LoadLibraryExA` call increments the per-process DLL reference count.
/// The loaded module handles are intentionally **not** freed here: `mida-pe`
/// is consumed by the short-lived `mida-cli` unpacker that exits immediately
/// after use, so the handles are reclaimed when the process exits. If
/// `mida-pe` is ever embedded in a long-lived host process, callers should
/// add `FreeLibrary` calls (or refactor to reuse a single module cache) to
/// avoid accumulating loaded-DLL references.
pub fn resolve_imports_via_getprocaddress(
    imports: &[(String, Vec<String>)],
) -> std::collections::HashMap<(String, String), usize> {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExA, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    let mut resolved = std::collections::HashMap::new();

    for (dll_name, functions) in imports {
        // Load the DLL from system directory
        let dll_name_cstr = format!("{dll_name}\0");
        debug!("Loading DLL: {dll_name}");
        // SAFETY: dll_name_cstr is a null-terminated UTF-8 string; LOAD_LIBRARY_SEARCH_SYSTEM32 is a valid flag.
        let h_module = unsafe {
            LoadLibraryExA(
                PCSTR::from_raw(dll_name_cstr.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };

        let h_module = match h_module {
            Ok(h) => {
                debug!("Loaded {dll_name} at {h:?}");
                h
            }
            Err(e) => {
                warn!("Cannot load {dll_name}: {e}");
                continue;
            }
        };

        for func_name in functions {
            debug!("Resolving {dll_name}:{func_name}");
            let addr = if let Some(ordinal_str) = func_name.strip_prefix('#') {
                // Import by ordinal: use MAKEINTRESOURCEA(ordinal)
                let ordinal: u16 = match ordinal_str.parse() {
                    Ok(o) => o,
                    Err(_) => {
                        warn!("Invalid ordinal format: {func_name}");
                        continue;
                    }
                };
                // MAKEINTRESOURCEA(ordinal) = (LPCSTR)(ULONG_PTR)((WORD)(ordinal))
                let ordinal_ptr = ordinal as usize as *const u8;
                // SAFETY: h_module is a valid HMODULE from LoadLibraryExA; ordinal_ptr is a valid MAKEINTRESOURCEA-style pointer.
                unsafe { GetProcAddress(h_module, PCSTR::from_raw(ordinal_ptr)) }
            } else {
                let func_name_cstr = format!("{func_name}\0");
                debug!("Looking up {dll_name}:{func_name}");
                // SAFETY: h_module is a valid HMODULE; func_name_cstr is a null-terminated UTF-8 string.
                unsafe { GetProcAddress(h_module, PCSTR::from_raw(func_name_cstr.as_ptr())) }
            };

            match addr {
                Some(addr) => {
                    resolved.insert((dll_name.clone(), func_name.clone()), addr as usize);
                    debug!("Resolved {dll_name}:{func_name} -> {:#x}", addr as usize);
                }
                None => {
                    warn!("Cannot resolve {dll_name}:{func_name}");
                }
            }
        }
    }

    info!(
        "Resolved {} of {} imports via GetProcAddress",
        resolved.len(),
        imports.iter().map(|(_, f)| f.len()).sum::<usize>()
    );

    resolved
}

/// Read import table with FirstThunk RVAs for proper IAT address assignment.
///
/// Returns: Vec<(dll_name, first_thunk_rva, functions)>
///
/// This is used by build_import_table_from_original to preserve the original
/// IAT layout when using original PE imports instead of rebuilt imports.
pub fn read_original_import_table_with_rvas(path: &Path) -> Vec<(String, u32, Vec<String>)> {
    debug!("read_original_import_table_with_rvas: START");

    let bytes = match std::fs::read(path) {
        Ok(b) => {
            debug!(
                "read_original_import_table_with_rvas: Read {} bytes",
                b.len()
            );
            b
        }
        Err(e) => {
            warn!("Cannot read original PE: {e}");
            return Vec::new();
        }
    };

    let pe = match PeHeader::from_bytes(&bytes) {
        Ok(p) => {
            debug!("read_original_import_table_with_rvas: Parsed PE header");
            p
        }
        Err(e) => {
            warn!("Cannot parse original PE: {e}");
            return Vec::new();
        }
    };

    let import_dir = pe.nt_headers.optional_header.data_directory[1];
    debug!(
        "read_original_import_table_with_rvas: Import dir RVA=0x{:X}, size={}",
        import_dir.virtual_address, import_dir.size
    );

    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        debug!("No import directory in original PE");
        return Vec::new();
    }

    let import_rva = import_dir.virtual_address as usize;
    let section = pe.sections.iter().find(|s| {
        let sec_start = s.virtual_address as usize;
        let sec_end = sec_start + s.virtual_size as usize;
        import_rva >= sec_start && import_rva < sec_end
    });

    let section = match section {
        Some(s) => {
            debug!("read_original_import_table_with_rvas: Found import section");
            s
        }
        None => {
            warn!("Import directory RVA {import_rva:#x} not found in any section");
            return Vec::new();
        }
    };

    let mut result: Vec<(String, u32, Vec<String>)> = Vec::new();

    let sec_va = section.virtual_address as usize;
    let sec_raw_offset = section.raw_offset as usize;
    let sec_raw_size = section.raw_size as usize;

    if sec_raw_offset + sec_raw_size > bytes.len() {
        warn!("Section raw data extends past end of file");
        return Vec::new();
    }

    let section_data = &bytes[sec_raw_offset..sec_raw_offset + sec_raw_size];

    let import_offset = import_rva - sec_va;
    let desc_size = 20;

    debug!("read_original_import_table_with_rvas: Starting descriptor loop");

    let mut desc_offset = import_offset;
    let mut desc_count = 0;
    while desc_offset + desc_size <= section_data.len() {
        let desc = &section_data[desc_offset..desc_offset + desc_size];

        let original_first_thunk = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
        let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]);
        let first_thunk = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);

        if name_rva == 0 {
            debug!("read_original_import_table_with_rvas: Found terminator descriptor");
            break;
        }

        desc_count += 1;
        if desc_count > 100 {
            warn!(
                "read_original_import_table_with_rvas: Too many descriptors ({}), breaking",
                desc_count
            );
            break;
        }

        debug!(
            "read_original_import_table_with_rvas: Processing descriptor #{}, name_rva=0x{:X}",
            desc_count, name_rva
        );

        let dll_name = {
            let name_sec = pe.sections.iter().find(|s| {
                let start = s.virtual_address as usize;
                let end = start + s.virtual_size as usize;
                (name_rva as usize) >= start && (name_rva as usize) < end
            });
            match name_sec {
                Some(ns) => {
                    let off =
                        (name_rva as usize) - ns.virtual_address as usize + ns.raw_offset as usize;
                    if off < bytes.len() {
                        read_cstring(&bytes, off)
                    } else {
                        String::new()
                    }
                }
                None => String::new(),
            }
        };

        if dll_name.is_empty() {
            debug!("read_original_import_table_with_rvas: Empty DLL name, breaking");
            break;
        }

        debug!(
            "read_original_import_table_with_rvas: DLL={}, reading thunks",
            dll_name
        );

        let mut functions: Vec<String> = Vec::new();
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk as usize
        } else {
            first_thunk as usize
        };

        debug!(
            "read_original_import_table_with_rvas: Thunk RVA=0x{:X}",
            thunk_rva
        );

        let thunk_size = if pe.is_64bit { 8 } else { 4 };
        let ordinal_flag = if pe.is_64bit {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000
        };

        let mut thunk_rva_cur = thunk_rva;
        let mut thunk_count = 0;
        loop {
            thunk_count += 1;
            if thunk_count > 500 {
                warn!(
                    "read_original_import_table_with_rvas: Too many thunks for {} ({}), breaking",
                    dll_name, thunk_count
                );
                break;
            }

            if thunk_count % 50 == 0 {
                debug!(
                    "read_original_import_table_with_rvas: Processing thunk #{} for {}",
                    thunk_count, dll_name
                );
            }
            let thunk_sec = pe.sections.iter().find(|s| {
                let start = s.virtual_address as usize;
                let end = start + s.virtual_size as usize;
                thunk_rva_cur >= start && thunk_rva_cur < end
            });
            let thunk_sec = match thunk_sec {
                Some(s) => s,
                None => break,
            };
            let thunk_off =
                thunk_rva_cur - thunk_sec.virtual_address as usize + thunk_sec.raw_offset as usize;
            if thunk_off + thunk_size > bytes.len() {
                break;
            }

            let thunk = if pe.is_64bit {
                u64::from_le_bytes(
                    bytes[thunk_off..thunk_off + 8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                )
            } else {
                u32::from_le_bytes(
                    bytes[thunk_off..thunk_off + 4]
                        .try_into()
                        .unwrap_or([0u8; 4]),
                ) as u64
            };

            if thunk == 0 {
                break;
            }

            if (thunk & ordinal_flag) != 0 {
                let ordinal = (thunk & 0xFFFF) as u16;
                functions.push(format!("#{ordinal}"));
            } else {
                let hint_name_rva = thunk as usize;
                let hn_sec = pe.sections.iter().find(|s| {
                    let start = s.virtual_address as usize;
                    let end = start + s.virtual_size as usize;
                    hint_name_rva >= start && hint_name_rva < end
                });
                let func_name = match hn_sec {
                    Some(hs) => {
                        let off = hint_name_rva - hs.virtual_address as usize
                            + hs.raw_offset as usize
                            + 2;
                        if off < bytes.len() {
                            read_cstring(&bytes, off)
                        } else {
                            String::new()
                        }
                    }
                    None => String::new(),
                };
                if !func_name.is_empty() {
                    functions.push(func_name);
                }
            }

            thunk_rva_cur += thunk_size;
        }

        if !functions.is_empty() {
            result.push((dll_name, first_thunk, functions));
        }

        desc_offset += desc_size;
    }

    info!(
        "Read {} import descriptors with {} total functions from original PE (with RVAs)",
        result.len(),
        result.iter().map(|(_, _, f)| f.len()).sum::<usize>()
    );

    result
}

/// One normalized import identity at a final-candidate IAT slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalImportIdentity {
    /// IAT slot RVA in the serialized candidate.
    pub slot_rva: u32,
    /// Lowercase ASCII-normalized DLL/module name.
    pub module_name: String,
    /// Exactly one of `function_name` and `ordinal` is populated.
    pub function_name: Option<String>,
    /// Exactly one of `function_name` and `ordinal` is populated.
    pub ordinal: Option<u16>,
}

/// Strictly parse every import descriptor, lookup thunk, and final IAT thunk.
///
/// The parser is deliberately independent from the legacy lossy import APIs:
/// it returns `Result`, preserves function-name case, treats ordinal imports as
/// first-class identities, and verifies that the serialized `FirstThunk` bytes
/// agree with the lookup encoding at the same slot RVA.
pub fn parse_final_import_identities(
    bytes: &[u8],
) -> Result<Vec<FinalImportIdentity>, crate::error::PeError> {
    let pe = PeHeader::from_bytes(bytes)?;
    let dir = pe.nt_headers.optional_header.data_directory[1];
    if dir.virtual_address == 0 || dir.size == 0 {
        return Err(crate::error::PeError::Parse(
            "final candidate has no import directory".into(),
        ));
    }
    let dir_start = dir.virtual_address;
    let dir_end = dir_start
        .checked_add(dir.size)
        .ok_or_else(|| crate::error::PeError::Parse("import directory RVA overflow".into()))?;
    let ptr_size = if pe.is_64bit { 8usize } else { 4usize };
    let ordinal_flag = if pe.is_64bit {
        0x8000_0000_0000_0000u64
    } else {
        0x8000_0000u64
    };

    let mut out = Vec::new();
    let mut seen_slots = std::collections::HashSet::new();
    let mut desc_rva = dir_start;
    let mut terminated = false;
    while desc_rva.checked_add(20).is_some_and(|end| end <= dir_end) {
        let desc = read_rva_exact(bytes, &pe, desc_rva, 20, "import descriptor")?;
        // IMAGE_IMPORT_DESCRIPTOR is terminated only by a full 20-byte zero
        // record.  Timestamp/forwarder fields are not ignorable here.
        if desc.iter().all(|byte| *byte == 0) {
            terminated = true;
            break;
        }
        let oft = u32::from_le_bytes(desc[0..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(desc[12..16].try_into().unwrap());
        let first_thunk = u32::from_le_bytes(desc[16..20].try_into().unwrap());
        if name_rva == 0 || first_thunk == 0 {
            return Err(crate::error::PeError::Parse(format!(
                "invalid import descriptor at RVA {desc_rva:#x}"
            )));
        }
        let module_name = normalize_module_name(read_rva_cstring(bytes, &pe, name_rva, "module")?)?;
        let lookup_rva = if oft != 0 { oft } else { first_thunk };
        let mut index = 0usize;

        loop {
            let delta = u32::try_from(
                index
                    .checked_mul(ptr_size)
                    .ok_or_else(|| crate::error::PeError::Parse("thunk index overflow".into()))?,
            )
            .map_err(|_| crate::error::PeError::Parse("thunk RVA overflow".into()))?;
            let lookup = lookup_rva
                .checked_add(delta)
                .ok_or_else(|| crate::error::PeError::Parse("lookup thunk RVA overflow".into()))?;
            let iat_rva = first_thunk
                .checked_add(delta)
                .ok_or_else(|| crate::error::PeError::Parse("IAT slot RVA overflow".into()))?;
            let lookup_value = decode_thunk(read_rva_exact(
                bytes,
                &pe,
                lookup,
                ptr_size,
                "import lookup thunk",
            )?);
            let final_value = decode_thunk(read_rva_exact(
                bytes,
                &pe,
                iat_rva,
                ptr_size,
                "final IAT thunk",
            )?);
            if lookup_value == 0 {
                if final_value != 0 {
                    return Err(crate::error::PeError::Parse(format!(
                        "final IAT terminator mismatch at slot RVA {iat_rva:#x}"
                    )));
                }
                break;
            }
            if final_value != lookup_value {
                return Err(crate::error::PeError::Parse(format!(
                    "lookup/final thunk encoding mismatch at slot RVA {iat_rva:#x}"
                )));
            }
            if !seen_slots.insert(iat_rva) {
                return Err(crate::error::PeError::Parse(format!(
                    "duplicate final import slot RVA {iat_rva:#x}"
                )));
            }
            let lookup_identity =
                decode_import_identity(bytes, &pe, lookup_value, ordinal_flag, iat_rva)?;
            let final_identity =
                decode_import_identity(bytes, &pe, final_value, ordinal_flag, iat_rva)?;
            if lookup_identity != final_identity {
                return Err(crate::error::PeError::Parse(format!(
                    "lookup/final IAT identity mismatch at slot RVA {iat_rva:#x}"
                )));
            }
            let (function_name, ordinal) = lookup_identity;
            if function_name.is_some() == ordinal.is_some() {
                return Err(crate::error::PeError::Parse(format!(
                    "import identity is not exactly-one at slot RVA {iat_rva:#x}"
                )));
            }
            out.push(FinalImportIdentity {
                slot_rva: iat_rva,
                module_name: module_name.clone(),
                function_name,
                ordinal,
            });
            index = index
                .checked_add(1)
                .ok_or_else(|| crate::error::PeError::Parse("thunk count overflow".into()))?;
            if index > 1_000_000 {
                return Err(crate::error::PeError::Parse(
                    "import thunk count exceeds safety limit".into(),
                ));
            }
        }

        desc_rva = desc_rva
            .checked_add(20)
            .ok_or_else(|| crate::error::PeError::Parse("descriptor RVA overflow".into()))?;
    }
    if !terminated {
        return Err(crate::error::PeError::Parse(
            "import descriptor array is not terminated within directory".into(),
        ));
    }
    if out.is_empty() {
        return Err(crate::error::PeError::Parse(
            "final candidate import table has no thunks".into(),
        ));
    }
    out.sort_by_key(|item| item.slot_rva);
    Ok(out)
}

fn decode_thunk(bytes: &[u8]) -> u64 {
    match bytes.len() {
        8 => u64::from_le_bytes(bytes.try_into().unwrap()),
        4 => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
        _ => unreachable!("PE thunk width is 4 or 8 bytes"),
    }
}

fn decode_import_identity(
    bytes: &[u8],
    pe: &PeHeader,
    value: u64,
    ordinal_flag: u64,
    slot_rva: u32,
) -> Result<(Option<String>, Option<u16>), crate::error::PeError> {
    if value & ordinal_flag != 0 {
        // Ordinal is the low 16 bits.  Zero is representable and therefore
        // accepted; only reserved bits outside the flag/ordinal are invalid.
        if value & !ordinal_flag & !0xffff != 0 {
            return Err(crate::error::PeError::Parse(format!(
                "invalid reserved ordinal bits at slot RVA {slot_rva:#x}"
            )));
        }
        return Ok((None, Some((value & 0xffff) as u16)));
    }
    let hint_name_rva = u32::try_from(value).map_err(|_| {
        crate::error::PeError::Parse(format!(
            "import hint/name RVA out of range at slot RVA {slot_rva:#x}"
        ))
    })?;
    let name_rva = hint_name_rva
        .checked_add(2)
        .ok_or_else(|| crate::error::PeError::Parse("hint/name RVA overflow".into()))?;
    let name = read_rva_cstring(bytes, pe, name_rva, "function")?;
    Ok((Some(validate_function_name(name)?), None))
}

fn normalize_module_name(bytes: &[u8]) -> Result<String, crate::error::PeError> {
    let text = validate_import_name(bytes, "module")?;
    Ok(text.to_ascii_lowercase())
}

fn validate_function_name(bytes: &[u8]) -> Result<String, crate::error::PeError> {
    Ok(validate_import_name(bytes, "function")?.to_string())
}

fn validate_import_name<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str, crate::error::PeError> {
    if bytes.is_empty() {
        return Err(crate::error::PeError::Parse(format!("empty {what} name")));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| crate::error::PeError::Parse(format!("{what} name is not UTF-8")))?;
    if text.as_bytes().contains(&0) || text.trim().is_empty() {
        return Err(crate::error::PeError::Parse(format!(
            "invalid empty {what} name"
        )));
    }
    Ok(text)
}

fn read_rva_exact<'a>(
    bytes: &'a [u8],
    pe: &PeHeader,
    rva: u32,
    len: usize,
    what: &str,
) -> Result<&'a [u8], crate::error::PeError> {
    let offset = pe.rva_to_offset(rva).ok_or_else(|| {
        crate::error::PeError::Parse(format!("{what} RVA {rva:#x} is outside sections"))
    })? as usize;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| crate::error::PeError::Parse(format!("{what} file offset overflow")))?;
    if end > bytes.len() {
        return Err(crate::error::PeError::Parse(format!(
            "{what} exceeds serialized candidate bounds"
        )));
    }
    let section = pe
        .sections
        .iter()
        .find(|section| {
            let start = section.virtual_address as u64;
            let end_rva = start + section.raw_size as u64;
            (rva as u64) >= start && (rva as u64) + len as u64 <= end_rva
        })
        .ok_or_else(|| {
            crate::error::PeError::Parse(format!(
                "{what} RVA {rva:#x} is outside serialized raw section data"
            ))
        })?;
    let expected = section.raw_offset as usize + (rva - section.virtual_address) as usize;
    if expected != offset {
        return Err(crate::error::PeError::Parse(format!(
            "{what} RVA mapping is inconsistent"
        )));
    }
    Ok(&bytes[offset..end])
}

fn read_rva_cstring<'a>(
    bytes: &'a [u8],
    pe: &PeHeader,
    rva: u32,
    what: &str,
) -> Result<&'a [u8], crate::error::PeError> {
    let offset = pe.rva_to_offset(rva).ok_or_else(|| {
        crate::error::PeError::Parse(format!("{what} RVA {rva:#x} is outside sections"))
    })? as usize;
    let section = pe
        .sections
        .iter()
        .find(|section| {
            (rva as u64) >= section.virtual_address as u64
                && (rva as u64) < section.virtual_address as u64 + section.raw_size as u64
        })
        .ok_or_else(|| {
            crate::error::PeError::Parse(format!("{what} is outside serialized raw section data"))
        })?;
    let section_end = (section.raw_offset as usize)
        .checked_add(section.raw_size as usize)
        .ok_or_else(|| crate::error::PeError::Parse("section bounds overflow".into()))?
        .min(bytes.len());
    if offset >= section_end || offset >= bytes.len() {
        return Err(crate::error::PeError::Parse(format!(
            "empty/out-of-range {what}"
        )));
    }
    let nul = bytes[offset..section_end]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| crate::error::PeError::Parse(format!("unterminated {what}")))?;
    let value = &bytes[offset..offset + nul];
    if value.is_empty() {
        return Err(crate::error::PeError::Parse(format!("empty {what}")));
    }
    Ok(value)
}
