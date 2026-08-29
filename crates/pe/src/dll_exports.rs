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

/// Try to find a DLL inside the given system search directories.
///
/// Pure helper: the directory list is a caller-supplied parameter (see
/// [`system_dll_search_dirs`] for the Win32-derived candidate list) so this
/// module stays OS-free and usable in offline/parsing contexts.
pub fn find_system_dll(
    dll_name: &str,
    system_dirs: &[std::path::PathBuf],
) -> Option<std::path::PathBuf> {
    for dir in system_dirs {
        let path = dir.join(dll_name);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Candidate Windows system-directory list, derived from the OS at runtime.
///
/// A general-purpose engine must not assume the Windows directory lives on
/// `C:`, so the candidates are built from `GetWindowsDirectoryW` /
/// `GetSystemDirectoryW` (native system dir + the 32-bit/legacy sibling
/// directories that historically lived under the same Windows root):
///
/// 1. `GetSystemDirectoryW` result (e.g. `C:\Windows\System32`);
/// 2. `<windows>\SysWOW64`;
/// 3. `<windows>\System`.
///
/// On non-Windows, or when the API cannot be queried, the list is empty and
/// the caller's miss path (a `warn!` at the call site) applies — never a
/// silent fallback to a hard-coded drive.
#[cfg(windows)]
pub fn system_dll_search_dirs() -> Vec<std::path::PathBuf> {
    use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

    fn query(dir_fn: unsafe fn(Option<&mut [u16]>) -> u32) -> Option<String> {
        let mut buf = [0u16; 261]; // MAX_PATH + 1
        let len = unsafe { dir_fn(Some(&mut buf)) };
        if len == 0 || len as usize >= buf.len() {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }

    let mut dirs = Vec::with_capacity(3);
    if let Some(system32) = query(GetSystemDirectoryW) {
        dirs.push(std::path::PathBuf::from(system32));
    }
    if let Some(windows_dir) = query(GetWindowsDirectoryW) {
        let windows_dir = std::path::PathBuf::from(windows_dir);
        dirs.push(windows_dir.join("SysWOW64"));
        dirs.push(windows_dir.join("System"));
    }
    dirs
}

/// Non-Windows build: no system directory can be queried; the caller's miss
/// path applies (see [`find_system_dll`]).
#[cfg(not(windows))]
pub fn system_dll_search_dirs() -> Vec<std::path::PathBuf> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_system_dll_hits_an_existing_dir() {
        let dir = std::env::temp_dir().join(format!("mida-dll-exports-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("fake.dll"), b"x").unwrap();
        let dirs = vec![dir.clone(), std::env::temp_dir()];
        let found = find_system_dll("fake.dll", &dirs);
        assert_eq!(found, Some(dir.join("fake.dll")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_system_dll_misses_when_absent_or_dirs_empty() {
        let dir =
            std::env::temp_dir().join(format!("mida-dll-exports-miss-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(find_system_dll("absent.dll", &[dir.clone()]), None);
        assert_eq!(find_system_dll("anything.dll", &[]), None);
        std::fs::remove_dir_all(&dir).ok();
    }
}
