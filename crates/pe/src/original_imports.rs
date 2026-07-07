//! Resolve imports from the original PE file's .idata section.
//!
//! This corresponds to `TDumper.GetOriginalImports` in `Dumper.pas`.
//! Instead of trying to read the (possibly encrypted) IAT from the live
//! process, we read the import table from the **original file on disk**,
//! extract DLL and function names, and resolve API addresses using
//! `GetProcAddress` in the debugger process (which shares ASLR base with
//! the target for well-known DLLs).

use std::path::Path;

use tracing::{debug, info, warn};
use crate::header::PeHeader;

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

        let name_rva = u32::from_le_bytes([desc[12], desc[13], desc[14], desc[15]]);
        let ft_rva = u32::from_le_bytes([desc[16], desc[17], desc[18], desc[19]]);

        if name_rva == 0 {
            break;
        }

        // Read DLL name
        let dll_name = if (name_rva as usize) >= sec_va {
            let name_offset = (name_rva as usize) - sec_va;
            read_cstring(section_data, name_offset)
        } else {
            String::new()
        };

        if dll_name.is_empty() {
            break;
        }

        // Read thunk data to get function names
        let mut functions: Vec<String> = Vec::new();
        if (ft_rva as usize) >= sec_va {
            let ft_offset = (ft_rva as usize) - sec_va;
            let mut thunk_offset = ft_offset;
            while thunk_offset + 8 <= section_data.len() {
                let thunk = usize::from_le_bytes([
                    section_data[thunk_offset],
                    section_data[thunk_offset + 1],
                    section_data[thunk_offset + 2],
                    section_data[thunk_offset + 3],
                    section_data[thunk_offset + 4],
                    section_data[thunk_offset + 5],
                    section_data[thunk_offset + 6],
                    section_data[thunk_offset + 7],
                ]);

                if thunk == 0 {
                    break;
                }

                const IMAGE_ORDINAL_FLAG64: usize = 0x8000_0000_0000_0000;
                if thunk & IMAGE_ORDINAL_FLAG64 != 0 {
                    // Import by ordinal
                    let ordinal = thunk & 0xFFFF;
                    functions.push(format!("#{ordinal}"));
                } else {
                    // Import by name - hint/name at thunk address
                    let hint_rva = (thunk & 0x7FFFFFFF) as u32;
                    if (hint_rva as usize) >= sec_va {
                        let hint_offset = (hint_rva as usize) - sec_va;
                        if hint_offset + 2 <= section_data.len() {
                            // Skip 2-byte hint, read name
                            let name_start = hint_offset + 2;
                            let func_name = read_cstring(section_data, name_start);
                            if !func_name.is_empty() {
                                functions.push(func_name);
                            }
                        }
                    }
                }

                thunk_offset += 8;
            }
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
pub fn resolve_imports_via_getprocaddress(
    imports: &[(String, Vec<String>)],
) -> std::collections::HashMap<(String, String), usize> {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExA, LOAD_LIBRARY_SEARCH_SYSTEM32};

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
                LOAD_LIBRARY_SEARCH_SYSTEM32
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
            let addr = if func_name.starts_with('#') {
                // Import by ordinal: use MAKEINTRESOURCEA(ordinal)
                let ordinal: u16 = match func_name[1..].parse() {
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
