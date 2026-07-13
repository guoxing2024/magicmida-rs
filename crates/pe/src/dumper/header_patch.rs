//! PE header validation and patching.
//!
//! Extracted from `dump_process` in `dumper.rs`.

use tracing::{debug, info};

use crate::error::PeError;
use crate::utils::align_up;
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
/// Detect Themida sections with randomized non-standard names.
///
/// Unlike is_themida_section in the themida crate, this function
/// excludes standard section names (.text, .rdata, etc.) even when
/// their raw_size is zero (Themida compresses disk data).
fn is_nonstandard_themida_section(s: &crate::header::PeSection) -> bool {
    const STANDARD: &[&str] = &[
        ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc",
        ".bss", ".tls", ".CRT", ".idata", ".textbss", ".init",
        ".fini", ".plt", ".got", ".gotplt",
        ".gfids", ".giats", ".gehcont", ".00cfg",
        ".volatilemetadata", ".xtbl", "BSS", "CODE", "DATA",
        ".minicrt", ".msvcinit",
    ];
    if STANDARD.contains(&s.name.as_str()) {
        return false;
    }
    if s.name.starts_with(".debug_") || s.name.starts_with(".v") {
        return false;
    }
    // Non-standard name: check Themida-like characteristics.
    let has_execute = s.characteristics & 0x20000000 != 0;
    let has_write = s.characteristics & 0x80000000 != 0;
    let large_vsize = s.virtual_size > 0x10000;
    // Themida code sections: executable with large virtual size.
    if has_execute && large_vsize { return true; }
    // Themida IAT sections: writable, non-standard name, not .data.
    if has_write && s.name != ".data" { return true; }
    // Themida memory-only sections: zero raw size with large virtual size.
    if s.raw_size == 0 && s.virtual_size > 0x10000 { return true; }
    false
}

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
            // Always remove .reloc (rebuilt from scratch).
            // Also detect Themida sections with randomized names like
            // .,\W, .KI3, .|lT — these are non-standard names that
            // don't appear in legitimate PE binaries.
            // Standard names (.text, .rdata, etc.) are never removed,
            // even if raw_size=0 (Themida compresses disk data).
            // Blank names are also skipped — some compilers strip
            // section names and those are legitimate code/data.
            if lower.contains(".reloc") {
                true
            } else if s.name.trim().is_empty() {
                // Blank name: only hardcoded Themida names.
                themida_names.iter().any(|t| lower.contains(t))
            } else {
                // Non-empty name: hardcoded names OR non-standard
                // name with Themida-like characteristics (exec or
                // write + large virtual size with no/low raw data).
                let hardcoded = themida_names.iter().any(|t| lower.contains(t));
                if hardcoded {
                    true
                } else {
                    is_nonstandard_themida_section(s)
                }
            }
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
    let dir_names = [
        "Export", "Import", "Resource", "Exception", "Certificate",
        "BaseReloc", "Debug", "Arch", "GlobalPtr", "TLS",
        "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved",
    ];
    // Clear data directory entries that point into removed sections.
    for dir_idx in 0..pe.nt_headers.optional_header.data_directory.len() {
        let dd_va = pe.nt_headers.optional_header.data_directory[dir_idx].virtual_address;
        let dd_size = pe.nt_headers.optional_header.data_directory[dir_idx].size;
        if dd_va == 0 || dd_size == 0 {
            continue;
        }
        // First check if the directory points into a removed section.
        for &(start, end) in removed_ranges {
            if dd_va >= start && dd_va < end {
                let dir_name = dir_names.get(dir_idx).copied().unwrap_or("Unknown");
                info!(
                    "Clearing dangling DataDirectory[{}] ({}) RVA={:#x} Size={:#x}",
                    dir_idx, dir_name, dd_va, dd_size
                );
                pe.nt_headers.optional_header.data_directory[dir_idx].virtual_address = 0;
                pe.nt_headers.optional_header.data_directory[dir_idx].size = 0;
                continue;
            }
        }
    }
    // Fill VA gaps left by removed Themida sections.
    //
    // Windows x64 loader rejects PEs where section VirtualAddresses have
    // gaps (non-contiguous VA space).  Instead of moving existing sections
    // (which would break absolute address references in .text), we insert
    // filler sections with RawSize=0 to make the VA space contiguous.
    let section_align = pe.nt_headers.optional_header.section_alignment;
    let mut i = 1;
    while i < pe.sections.len() {
        let prev_end = {
            let prev = &pe.sections[i - 1];
            let end = prev.virtual_address + prev.virtual_size;
            align_up(end, section_align)
        };
        let cur_va = pe.sections[i].virtual_address;
        if cur_va > prev_end {
            let gap_size = cur_va - prev_end;
            let filler = crate::header::PeSection {
                header: crate::header::ImageSectionHeader {
                    name: *b".fill\x00\x00\x00",
                    virtual_size: gap_size,
                    virtual_address: prev_end,
                    size_of_raw_data: 0,
                    pointer_to_raw_data: 0,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    // Read + Initialized Data (BSS-like, no raw data)
                    characteristics: 0x4000_0040,
                },
                name: ".fill".to_string(),
                virtual_address: prev_end,
                virtual_size: gap_size,
                raw_offset: 0,
                raw_size: 0,
                characteristics: 0x4000_0040,
                extra_data: None,
            };
            pe.sections.insert(i, filler);
            pe.nt_headers.file_header.number_of_sections =
                pe.nt_headers.file_header.number_of_sections.saturating_add(1);
            info!("Filled VA gap: .fill VA=0x{:X} VS=0x{:X}", prev_end, gap_size);
        }
        i += 1;
    }
    info!("Shrink complete: removed {} sections (gaps filled)", removed);
}

/// Compact section VAs to eliminate gaps left by removed sections,
/// and move the corresponding data in dump_buf so that
/// dump_buf[section.virtual_address] still contains the correct data.
///
/// This must be called AFTER dump_buf is read from the target process
/// and AFTER all new sections (.pdata, .reloc, .import) are created,
/// but BEFORE sanitize() / trim_huge_sections() / write_output_file().
#[allow(dead_code)]
pub(crate) fn compact_and_shift(pe: &mut PeHeader, dump_buf: &mut [u8]) {
    let section_align = pe.nt_headers.optional_header.section_alignment;
    let mut next_va: u32 = 0x1000;
    let mut va_remaps: Vec<(u32, u32)> = Vec::new();

    for section in &mut pe.sections {
        let old_va = section.virtual_address;
        let vsize = section.virtual_size;

        if old_va != next_va {
            // Move data in dump_buf for sections without extra_data.
            // Sections with extra_data (.pdata, .reloc, .import) don't
            // read from dump_buf, so no data move needed.
            if section.extra_data.is_none() {
                let old_off = old_va as usize;
                let new_off = next_va as usize;
                let data_len = vsize as usize;
                if old_off + data_len <= dump_buf.len()
                    && new_off + data_len <= dump_buf.len()
                    && new_off < old_off
                {
                    // Backward move — safe with a temporary copy.
                    let tmp: Vec<u8> = dump_buf[old_off..old_off + data_len].to_vec();
                    dump_buf[new_off..new_off + data_len].copy_from_slice(&tmp);
                }
            }
            va_remaps.push((old_va, next_va));
            section.virtual_address = next_va;
            section.header.virtual_address = next_va;
        }
        next_va = crate::utils::align_up(next_va + vsize, section_align);
    }

    // Remap data directory RVAs that point into shifted sections.
    let dir_names = [
        "Export", "Import", "Resource", "Exception", "Certificate",
        "BaseReloc", "Debug", "Arch", "GlobalPtr", "TLS",
        "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved",
    ];
    for dir_idx in 0..pe.nt_headers.optional_header.data_directory.len() {
        let dd_va = pe.nt_headers.optional_header.data_directory[dir_idx].virtual_address;
        let dd_size = pe.nt_headers.optional_header.data_directory[dir_idx].size;
        if dd_va == 0 || dd_size == 0 {
            continue;
        }
        // Find the remap whose old_va is the largest value <= dd_va.
        if let Some(&(old_va, new_va)) = va_remaps
            .iter()
            .filter(|&&(ov, _)| dd_va >= ov)
            .max_by_key(|&&(ov, _)| ov)
        {
            let delta = new_va as i64 - old_va as i64;
            if delta != 0 {
                let new_rva = (dd_va as i64 + delta) as u32;
                let dir_name = dir_names.get(dir_idx).copied().unwrap_or("Unknown");
                info!(
                    "Remapping DataDirectory[{}] ({}) RVA: {:#x} -> {:#x} (delta={:#x})",
                    dir_idx, dir_name, dd_va, new_rva, delta
                );
                pe.nt_headers.optional_header.data_directory[dir_idx].virtual_address = new_rva;
            }
        }
    }

    // Fix up internal resource data entry RVAs.
    // Resource data entries (IMAGE_RESOURCE_DATA_ENTRY.OffsetToData) contain
    // absolute RVAs pointing into the .rsrc section.  When the section VA
    // changes, these must be updated by the same delta.
    const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
    let rsrc_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if rsrc_dir.virtual_address != 0 && rsrc_dir.size != 0 {
        // Find the remap for .rsrc.
        if let Some(&(_old_rsrc_va, _new_rsrc_va)) = va_remaps.iter().find(|&&(ov, _)| ov == rsrc_dir.virtual_address) {
            // Wait — the data directory was already remapped above, so
            // rsrc_dir.virtual_address is now the NEW va.  We need the OLD va.
            // Use the remap in reverse: find the entry whose new_va == current rsrc VA.
        }
        // Actually, let's just scan all remaps and fix resource entries for
        // any section that was moved and contains resource data.
        for &(old_va, new_va) in &va_remaps {
            let delta = new_va as i64 - old_va as i64;
            if delta == 0 { continue; }
            let old_end = old_va + rsrc_dir.size; // approximate
            // Scan dump_buf for 4-byte values in [old_va, old_end) and shift them.
            let scan_start = new_va as usize;
            let scan_end = (new_va as usize).saturating_add(rsrc_dir.size as usize);
            if scan_end <= dump_buf.len() {
                let mut fixed = 0u32;
                for off in (scan_start..scan_end - 3).step_by(4) {
                    let val = u32::from_le_bytes([
                        dump_buf[off], dump_buf[off + 1], dump_buf[off + 2], dump_buf[off + 3],
                    ]);
                    if val >= old_va && val < old_end {
                        let new_val = (val as i64 + delta) as u32;
                        dump_buf[off..off + 4].copy_from_slice(&new_val.to_le_bytes());
                        fixed += 1;
                    }
                }
                if fixed > 0 {
                    info!("Fixed {} resource data RVAs in section at {:#x}", fixed, new_va);
                }
            }
            break; // Only process the .rsrc section
        }
    }

    pe.nt_headers.optional_header.size_of_image = next_va;
    info!("Compact and shift: SizeOfImage={:#x}", next_va);
}
