//! PE header validation and patching.
//!
//! Extracted from `dump_process` in `dumper.rs`.

use tracing::{debug, info};

use crate::error::PeError;
use crate::header::PeHeader;

use super::helpers::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
use super::types::DumpOptions;

/// Validate and patch PE header fields that protectors (e.g. Themida) may
/// have corrupted.
///
/// - Characteristics must have `IMAGE_FILE_EXECUTABLE_IMAGE` (0x2)
/// - Subsystem must be a recognised `IMAGE_SUBSYSTEM_*` constant
/// - When `executable_path` is present, merge valid fields from the
///   on-disk PE header (Characteristics, Subsystem, ImageBase).
pub(crate) fn validate_and_patch_pe_header(
    pe: &mut PeHeader,
    opts: &DumpOptions,
) -> Result<(), PeError> {
    const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    let valid_subsystems: [u16; 5] = [2, 3, 7, 9, 10];
    if pe.nt_headers.file_header.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        pe.nt_headers.file_header.characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
        debug!("patched FileHeader.Characteristics (missing EXECUTABLE_IMAGE)");
    }
    if !valid_subsystems.contains(&pe.nt_headers.optional_header.subsystem) {
        // Subsystem 2 (GUI) is the most common default for protected binaries.
        pe.nt_headers.optional_header.subsystem = 2;
        debug!("patched Subsystem (invalid value)");
    }
    if let Some(ref ep) = opts.executable_path {
        if let Ok(bytes) = std::fs::read(ep) {
            if let Ok(disk_pe) = PeHeader::from_bytes(&bytes) {
                // Merge disk values where they look valid.
                if disk_pe.nt_headers.file_header.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
                    pe.nt_headers.file_header.characteristics =
                        disk_pe.nt_headers.file_header.characteristics;
                }
                if valid_subsystems.contains(&disk_pe.nt_headers.optional_header.subsystem) {
                    pe.nt_headers.optional_header.subsystem =
                        disk_pe.nt_headers.optional_header.subsystem;
                }
                // ===超越 Pascal: 恢复原始 ImageBase===
                let original_image_base = disk_pe.nt_headers.optional_header.image_base;
                let runtime_image_base = pe.nt_headers.optional_header.image_base;

                if original_image_base != 0 && original_image_base != runtime_image_base {
                    pe.nt_headers.optional_header.image_base = original_image_base;
                    info!(
                        "Restored ImageBase: {:#x} -> {:#x} (will patch absolute addresses)",
                        runtime_image_base, original_image_base
                    );
                }
                // 禁用 ASLR：程序加载到固定基址，不需要重定位表
                pe.nt_headers.optional_header.dll_characteristics &=
                    !IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
                info!("validated PE header fields");
            }
        }
    }
    Ok(())
}

/// Shrink: remove Themida-specific sections and compact VAs.
///
/// Returns the saved exception directory (RVA, size) if one was captured
/// before the `.winlice` section was deleted.
pub(crate) fn shrink_sections(pe: &mut PeHeader) -> Option<(u32, u32)> {
    let mut saved_exception_rva: Option<(u32, u32)> = None;

    // Capture the exception directory before anything deletes it.
    const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
    let exc_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if exc_dir.virtual_address != 0 && exc_dir.size != 0 {
        info!(
            "Exception dir to preserve: RVA={:#x} Size={:#x}",
            exc_dir.virtual_address, exc_dir.size
        );
        saved_exception_rva = Some((exc_dir.virtual_address, exc_dir.size));
    }

    let themida_names = [".winlice", ".boot", ".themida", ".reloc"];
    let mut removed = 0usize;
    let mut removed_ranges: Vec<(u32, u32)> = Vec::new();
    let mut i = pe.sections.len();
    loop {
        if i == 0 { break; }
        i -= 1;
        let should_delete = {
            let s = &pe.sections[i];
            let lower = s.name.to_lowercase();
            themida_names.iter().any(|t| lower.contains(t))
        };
        if should_delete {
            let removed_va = pe.sections[i].virtual_address;
            let removed_vs = pe.sections[i].virtual_size;
            removed_ranges.push((removed_va, removed_va + removed_vs));

            pe.sections.remove(i);
            pe.nt_headers.file_header.number_of_sections =
                pe.nt_headers.file_header.number_of_sections.saturating_sub(1);
            removed += 1;
        }
    }
    if removed > 0 {
        compact_section_vas(pe, &removed_ranges, removed);
    }

    // Restore standard section names for unnamed sections
    pe.rename_unnamed_sections();
    info!("Restored standard section names");

    saved_exception_rva
}

/// Compact section VAs to eliminate gaps left by removed sections,
/// and clear dangling data-directory entries.
fn compact_section_vas(pe: &mut PeHeader, removed_ranges: &[(u32, u32)], removed: usize) {
    let section_align = pe.nt_headers.optional_header.section_alignment;
    let mut next_va: u32 = 0x1000; // Start after headers

    for section in &mut pe.sections {
        if section.virtual_address == 0x1000 {
            next_va = section.virtual_address + section.virtual_size;
            next_va = crate::utils::align_up(next_va, section_align);
            continue;
        }

        let old_va = section.virtual_address;
        if old_va != next_va {
            let delta = next_va as i64 - old_va as i64;
            info!(
                "Reassigning section {} VA: 0x{:x} -> 0x{:x} (delta={:#x})",
                section.name, old_va, next_va, delta
            );
            section.virtual_address = next_va;
            section.header.virtual_address = next_va;
        }
        next_va = next_va + section.virtual_size;
        next_va = crate::utils::align_up(next_va, section_align);
    }

    pe.nt_headers.optional_header.size_of_image = next_va;
    let max_end = next_va;

    // Clear data directory entries that point into removed sections.
    for dir_idx in 0..pe.nt_headers.optional_header.data_directory.len() {
        let dd = &pe.nt_headers.optional_header.data_directory[dir_idx];
        if dd.virtual_address == 0 || dd.size == 0 {
            continue;
        }
        for &(start, end) in removed_ranges {
            if dd.virtual_address >= start && dd.virtual_address < end {
                let dir_names = [
                    "Export", "Import", "Resource", "Exception", "Certificate",
                    "BaseReloc", "Debug", "Arch", "GlobalPtr", "TLS",
                    "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved",
                ];
                let dir_name = dir_names.get(dir_idx).copied().unwrap_or("Unknown");
                info!(
                    "Clearing dangling DataDirectory[{}] ({}) RVA={:#x} Size={:#x}",
                    dir_idx, dir_name, dd.virtual_address, dd.size
                );
                pe.nt_headers.optional_header.data_directory[dir_idx].virtual_address = 0;
                pe.nt_headers.optional_header.data_directory[dir_idx].size = 0;
                break;
            }
        }
    }
    info!("Shrink complete: removed {} sections, VAs compacted, SizeOfImage: {:#x}", removed, max_end);
}
