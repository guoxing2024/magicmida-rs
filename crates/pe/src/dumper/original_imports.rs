//! Reader for the original PE import table.
//!
//! Extracted from `dumper.rs` — corresponds to `TDumper.GetOriginalImports`
//! in `Dumper.pas`.

use std::path::Path;

use crate::error::PeError;
use crate::header::PeHeader;
use crate::import_table::IMPORT_DESCRIPTOR_SIZE;

use super::helpers::IMAGE_DIRECTORY_ENTRY_IMPORT;

/// Extract the original import list from a file's import directory.
///
/// Returns a list of `"dllname.funcname"` strings.
///
/// Corresponds to `TDumper.GetOriginalImports` in `Dumper.pas`.
pub fn get_original_imports(file_path: &Path) -> Result<Vec<String>, PeError> {
    let data = std::fs::read(file_path)?;
    let pe = PeHeader::from_bytes(&data)?;

    let import_dir =
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return Ok(Vec::new());
    }

    let section = pe
        .get_section_by_rva(import_dir.virtual_address)
        .ok_or(PeError::SectionNotFound(import_dir.virtual_address))?;

    let section_data_start = section.raw_offset as usize;
    let section_data_end = section_data_start + section.raw_size as usize;

    if section_data_end > data.len() {
        return Err(PeError::OffsetOutOfRange(section_data_end as u32));
    }
    let section_data = &data[section_data_start..section_data_end];

    let dir_offset = (import_dir.virtual_address - section.virtual_address) as usize;
    let mut result = Vec::new();

    let mut desc_off = dir_offset;
    loop {
        if desc_off + IMPORT_DESCRIPTOR_SIZE > section_data.len() {
            break;
        }

        // Read Name field (offset +12 in descriptor)
        let name_rva = section_data.get(desc_off + 12..desc_off + 16)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(PeError::Parse("Failed to read import descriptor name RVA".into()))?;

        if name_rva == 0 {
            break; // End of descriptor array
        }

        // Read DLL name
        let name_section = pe
            .get_section_by_rva(name_rva)
            .ok_or(PeError::SectionNotFound(name_rva))?;
        let name_in_section = (name_rva - name_section.virtual_address) as usize;
        let name_section_start = name_section.raw_offset as usize;

        if name_section_start + name_in_section < data.len() {
            let name_end = data[name_section_start + name_in_section..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(256);
            let dll_name =
                String::from_utf8_lossy(
                    &data[name_section_start + name_in_section
                        ..name_section_start + name_in_section + name_end],
                )
                .to_lowercase();

            // Read FirstThunk to enumerate functions
            let first_thunk_rva = section_data.get(desc_off + 16..desc_off + 20)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or(PeError::Parse("Failed to read FirstThunk RVA".into()))?;

            if first_thunk_rva != 0 {
                let thunk_section = pe
                    .get_section_by_rva(first_thunk_rva)
                    .ok_or(PeError::SectionNotFound(first_thunk_rva))?;
                let _thunk_data_start = thunk_section.raw_offset as usize;
                let thunk_off = (first_thunk_rva - thunk_section.virtual_address) as usize;

                let is_64bit = pe.is_64bit;
                let ptr_size = if is_64bit { 8 } else { 4 };

                let mut t_off = thunk_off;
                loop {
                    if t_off + ptr_size > data.len() {
                        break;
                    }

                    let thunk_val = if is_64bit {
                        data.get(t_off..t_off + 8)
                            .and_then(|s| s.try_into().ok())
                            .map(u64::from_le_bytes)
                            .unwrap_or(0)
                    } else {
                        data.get(t_off..t_off + 4)
                            .and_then(|s| s.try_into().ok())
                            .map(u32::from_le_bytes)
                            .map(u64::from)
                            .unwrap_or(0)
                    };

                    if thunk_val == 0 {
                        break;
                    }

                    let func_name = if is_64bit && (thunk_val & 0x8000_0000_0000_0000) != 0 {
                        // Ordinal import
                        let ord = (thunk_val & 0xFFFF) as u16;
                        format!("#{ord}")
                    } else if !is_64bit && (thunk_val & 0x8000_0000) != 0 {
                        let ord = (thunk_val & 0xFFFF) as u16;
                        format!("#{ord}")
                    } else {
                        // Name import — read name from RVA
                        let name_rva = thunk_val as u32;
                        let ns = pe
                            .get_section_by_rva(name_rva)
                            .ok_or(PeError::SectionNotFound(name_rva))?;
                        let ns_off = (name_rva - ns.virtual_address) as usize;
                        let ns_base = ns.raw_offset as usize;
                        // skip 2-byte hint
                        let name_start = ns_base + ns_off + 2;
                        if name_start < data.len() {
                            let end = data[name_start..]
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(256);
                            String::from_utf8_lossy(&data[name_start..name_start + end])
                                .into_owned()
                        } else {
                            String::new()
                        }
                    };

                    if !func_name.is_empty() {
                        result.push(format!("{dll_name}.{func_name}"));
                    }

                    t_off += ptr_size;
                }
            }
        }

        desc_off += IMPORT_DESCRIPTOR_SIZE;
    }

    Ok(result)
}
