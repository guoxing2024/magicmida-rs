//! DLL export table parser
//!
//! Used to build ordinal -> function name mappings for ordinal import restoration.

use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

/// Read exports from a DLL file and build ordinal -> function name map.
///
/// Returns: HashMap<ordinal, function_name>
pub fn read_dll_exports(dll_path: &Path) -> HashMap<u16, String> {
    let mut result = HashMap::new();

    let bytes = match std::fs::read(dll_path) {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to read DLL {}: {}", dll_path.display(), e);
            return result;
        }
    };

    // Parse PE header
    if bytes.len() < 0x40 {
        return result;
    }

    let pe_offset =
        u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;

    if pe_offset + 0x200 > bytes.len() {
        return result;
    }

    // Check PE signature
    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return result;
    }

    // Read optional header offset
    let opt_header_offset = pe_offset + 24;

    // Read export directory RVA (offset 112 in optional header, entry 0)
    let data_dir_offset = opt_header_offset + 112;

    if data_dir_offset + 8 > bytes.len() {
        return result;
    }

    let export_rva = u32::from_le_bytes([
        bytes[data_dir_offset],
        bytes[data_dir_offset + 1],
        bytes[data_dir_offset + 2],
        bytes[data_dir_offset + 3],
    ]) as usize;

    let export_size = u32::from_le_bytes([
        bytes[data_dir_offset + 4],
        bytes[data_dir_offset + 5],
        bytes[data_dir_offset + 6],
        bytes[data_dir_offset + 7],
    ]) as usize;

    if export_rva == 0 || export_size == 0 {
        debug!("DLL {} has no exports", dll_path.display());
        return result;
    }

    // Find section containing export directory
    let num_sections_offset = pe_offset + 6;
    let num_sections =
        u16::from_le_bytes([bytes[num_sections_offset], bytes[num_sections_offset + 1]]) as usize;

    let opt_header_size_offset = pe_offset + 20;
    let opt_header_size = u16::from_le_bytes([
        bytes[opt_header_size_offset],
        bytes[opt_header_size_offset + 1],
    ]) as usize;

    let section_table_offset = opt_header_offset + opt_header_size;

    let mut export_file_offset = None;
    let mut section_rva_base = 0usize;

    for i in 0..num_sections {
        let section_offset = section_table_offset + i * 40;
        if section_offset + 40 > bytes.len() {
            break;
        }

        let virtual_address = u32::from_le_bytes([
            bytes[section_offset + 12],
            bytes[section_offset + 13],
            bytes[section_offset + 14],
            bytes[section_offset + 15],
        ]) as usize;

        let virtual_size = u32::from_le_bytes([
            bytes[section_offset + 8],
            bytes[section_offset + 9],
            bytes[section_offset + 10],
            bytes[section_offset + 11],
        ]) as usize;

        let pointer_to_raw = u32::from_le_bytes([
            bytes[section_offset + 20],
            bytes[section_offset + 21],
            bytes[section_offset + 22],
            bytes[section_offset + 23],
        ]) as usize;

        if export_rva >= virtual_address && export_rva < virtual_address + virtual_size {
            section_rva_base = virtual_address;
            export_file_offset = Some(pointer_to_raw + (export_rva - virtual_address));
            break;
        }
    }

    let Some(export_file_offset) = export_file_offset else {
        warn!("Export directory RVA not found in any section");
        return result;
    };

    if export_file_offset + 40 > bytes.len() {
        return result;
    }

    // Read export directory structure
    let num_functions_offset = export_file_offset + 20;
    let num_names_offset = export_file_offset + 24;
    let names_rva_offset = export_file_offset + 32;
    let ordinals_rva_offset = export_file_offset + 36;

    let _num_functions = u32::from_le_bytes([
        bytes[num_functions_offset],
        bytes[num_functions_offset + 1],
        bytes[num_functions_offset + 2],
        bytes[num_functions_offset + 3],
    ]);

    let num_names = u32::from_le_bytes([
        bytes[num_names_offset],
        bytes[num_names_offset + 1],
        bytes[num_names_offset + 2],
        bytes[num_names_offset + 3],
    ]) as usize;

    let names_rva = u32::from_le_bytes([
        bytes[names_rva_offset],
        bytes[names_rva_offset + 1],
        bytes[names_rva_offset + 2],
        bytes[names_rva_offset + 3],
    ]) as usize;

    let ordinals_rva = u32::from_le_bytes([
        bytes[ordinals_rva_offset],
        bytes[ordinals_rva_offset + 1],
        bytes[ordinals_rva_offset + 2],
        bytes[ordinals_rva_offset + 3],
    ]) as usize;

    // Helper to convert RVA to file offset
    let rva_to_offset = |rva: usize| -> Option<usize> {
        // Simple: assume same section as export directory
        if rva >= section_rva_base {
            Some(export_file_offset - (export_rva - section_rva_base) + (rva - section_rva_base))
        } else {
            None
        }
    };

    let Some(names_offset) = rva_to_offset(names_rva) else {
        return result;
    };

    let Some(ordinals_offset) = rva_to_offset(ordinals_rva) else {
        return result;
    };

    // Read name/ordinal pairs
    for i in 0..num_names {
        let name_ptr_offset = names_offset + i * 4;
        let ordinal_idx_offset = ordinals_offset + i * 2;

        if name_ptr_offset + 4 > bytes.len() || ordinal_idx_offset + 2 > bytes.len() {
            break;
        }

        let name_rva = u32::from_le_bytes([
            bytes[name_ptr_offset],
            bytes[name_ptr_offset + 1],
            bytes[name_ptr_offset + 2],
            bytes[name_ptr_offset + 3],
        ]) as usize;

        let ordinal =
            u16::from_le_bytes([bytes[ordinal_idx_offset], bytes[ordinal_idx_offset + 1]]);

        let Some(name_offset) = rva_to_offset(name_rva) else {
            continue;
        };

        if name_offset >= bytes.len() {
            continue;
        }

        // Read null-terminated string
        let mut name = String::new();
        for j in name_offset..bytes.len() {
            if bytes[j] == 0 {
                break;
            }
            name.push(bytes[j] as char);
        }

        if !name.is_empty() {
            result.insert(ordinal, name);
        }
    }

    debug!(
        "Loaded {} exports from {}",
        result.len(),
        dll_path.display()
    );
    result
}

/// Try to find a DLL in common Windows system directories.
pub fn find_system_dll(dll_name: &str) -> Option<std::path::PathBuf> {
    let system_dirs = [
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Windows\\System",
    ];

    for dir in &system_dirs {
        let path = std::path::Path::new(dir).join(dll_name);
        if path.exists() {
            return Some(path);
        }
    }

    None
}
