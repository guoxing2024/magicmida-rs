//! Post-processing for unpacked PE images.
//!
//! Includes:
//! - Themida section shrinking (merge VSize, restore RawSize)
//! - Absolute address fixing
//! - File layout packing
//! - Relocation table building (v2)

use crate::PeHeader;
use crate::PeError;
use crate::relocation::RelocationTableBuilder;
use tracing::{info, debug, warn};

/// Apply post-processing to an unpacked PE image.
///
/// # Arguments
/// * `out_data` - Buffer containing the unpacked PE image
/// * `opts` - Post-processing options
///
/// # Returns
/// Error if post-processing fails
///
/// # Examples
///
/// ```ignore
/// use mida_pe::dumper::postprocess::postprocess_image;
///
/// let mut image = std::fs::read("dump.exe")?;
/// postprocess_image(&mut image, true)?; // Enable shrink
/// std::fs::write("output.exe", image)?;
/// ```
pub fn postprocess_image(out_data: &mut Vec<u8>, options: PostprocessOptions) -> Result<(), PeError> {
    // Parse PE to get structure
    let mut pe = PeHeader::from_bytes(out_data)?;

    // 1. Shrink: remove Themida sections, merge VSize into previous section
    if options.shrink {
        apply_shrink(&mut pe, out_data)?;
    }

    // 2. Rename unnamed sections
    if options.rename_sections {
        pe.rename_unnamed_sections();
        info!("Restored standard section names");
    }

    // 3. Fix hardcoded runtime addresses
    if options.fix_addresses {
        fix_hardcoded_addresses(out_data, None, pe.is_64bit)?;
    }

    // 4. Pack file layout (move sections to eliminate gaps)
    if options.pack_layout {
        pack_section_layout(out_data, &pe)?;
    }

    // 5. Build relocation table (for ASLR support)
    if options.build_relocations {
        build_relocation_table(out_data, None, pe.is_64bit)?;
    }

    Ok(())
}

/// Options for PE post-processing
#[derive(Debug, Clone, PartialEq)]
pub struct PostprocessOptions {
    pub shrink: bool,
    pub rename_sections: bool,
    pub fix_addresses: bool,
    pub pack_layout: bool,
    pub build_relocations: bool,
}

impl Default for PostprocessOptions {
    fn default() -> Self {
        Self {
            shrink: true,
            rename_sections: true,
            fix_addresses: true,
            pack_layout: true,
            build_relocations: false, // Disabled by default (needs fixes)
        }
    }
}

/// Shrink: remove Themida-specific sections (.winlice, .boot, .themida)
///
/// Strategy: merge the virtual size of removed sections into the previous
/// remaining section. This keeps the virtual address space contiguous so
/// data directories (e.g. Exception table in .winlice) remain valid.
///
/// After sanitize(), we restore the original RawSize for merged sections so
/// the file doesn't contain Themida junk data.
fn apply_shrink(pe: &mut PeHeader, out_data: &mut Vec<u8>) -> Result<(), PeError> {
    let themida_names = [".winlice", ".boot", ".themida"];
    let mut removed = 0usize;
    let mut merged_sections: Vec<(u32, u32)> = Vec::new(); // (section_va, original_vsize)

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
            let removed_name = pe.sections[i].name.clone();

            // Merge virtual size into previous remaining section
            if i > 0 {
                let prev_end = pe.sections[i - 1].virtual_address + pe.sections[i - 1].virtual_size;
                let new_end = removed_va + removed_vs;
                if new_end > prev_end {
                    let original_vs = pe.sections[i - 1].virtual_size;
                    let merged_vs = new_end - pe.sections[i - 1].virtual_address;
                    pe.sections[i - 1].virtual_size = merged_vs;
                    pe.sections[i - 1].header.virtual_size = merged_vs;
                    // Track by VA (not index) since indices shift on removal
                    merged_sections.push((pe.sections[i - 1].virtual_address, original_vs));
                    info!(
                        "Merged {} VSize into previous section: new VSize={:#x} (original={:#x})",
                        removed_name, merged_vs, original_vs
                    );
                }
            }

            pe.sections.remove(i);
            pe.nt_headers.file_header.number_of_sections =
                pe.nt_headers.file_header.number_of_sections.saturating_sub(1);
            removed += 1;
            info!("Removed Themida section: {}", removed_name);
        }
    }

    if removed > 0 {
        // Recalculate SizeOfImage based on remaining sections
        let mut max_end = 0u32;
        for s in &pe.sections {
            let end = s.virtual_address + s.virtual_size;
            let aligned = crate::utils::align_up(end, pe.nt_headers.optional_header.section_alignment);
            if aligned > max_end { max_end = aligned; }
        }
        pe.nt_headers.optional_header.size_of_image = max_end;
        debug!("Shrink complete: removed {} sections, SizeOfImage={:#x}", removed, max_end);

        // Restore original RawSize for merged sections
        // sanitize() set RawSize=VSize, but merged sections have large VSize
        // while the actual file data should be the original pre-merge amount
        for &(sec_va, orig_vs) in &merged_sections {
            if let Some(idx) = pe.sections.iter().position(|s| s.virtual_address == sec_va) {
                let file_align = pe.nt_headers.optional_header.file_alignment;
                let aligned_vs = crate::utils::align_up(orig_vs, file_align);
                pe.sections[idx].header.size_of_raw_data = aligned_vs;
                debug!(
                    "Restored RawSize for section {} (VA={:#x}): {:#x} (VSize stays {:#x})",
                    idx, sec_va, aligned_vs, pe.sections[idx].virtual_size
                );
            }
        }
    }

    Ok(())
}

/// Fix hardcoded runtime absolute addresses to RVAs
///
/// Scans non-executable, initialized sections and adjusts absolute
/// addresses that point to the runtime image to file-position RVAs.
pub fn fix_hardcoded_addresses(
    out_data: &mut [u8],
    runtime_image_base: Option<u64>,
    is_64bit: bool,
) -> Result<(), PeError> {
    let pe = PeHeader::from_bytes(out_data)?;
    let file_image_base = pe.nt_headers.optional_header.image_base;
    let runtime_base = runtime_image_base.unwrap_or(file_image_base);
    let delta = (file_image_base as i64).wrapping_sub(runtime_base as i64);

    info!(
        "Scanning for hardcoded addresses: runtime_base={:#x}, file_base={:#x}, delta={:#x}",
        runtime_base, file_image_base, delta
    );

    let ptr_size = if is_64bit { 8 } else { 4 };
    let mut fixed_count = 0;
    let mut scanned_bytes = 0;

    let image_size = pe.nt_headers.optional_header.size_of_image as u64;
    let runtime_start = runtime_base;
    let runtime_end = runtime_base + image_size;

    for section in &pe.sections {
        // Skip executable sections (code uses RIP-relative, not absolute pointers)
        let is_executable = (section.characteristics & 0x20000000) != 0;
        if is_executable {
            debug!("Skipping executable section {} ", section.name);
            continue;
        }

        // Skip uninitialized sections
        let is_uninitialized = (section.characteristics & 0x00000080) != 0;
        if is_uninitialized {
            continue;
        }

        let section_start = section.raw_offset as usize;
        let section_size = section.raw_size as usize;
        let section_end = section_start + section_size;

        if section_end > out_data.len() {
            warn!("Section {} extends beyond file size, skipping", section.name);
            continue;
        }

        debug!(
            "Scanning section {} (RVA: {:#x}, size: {:#x}, file offset: {:#x})",
            section.name, section.virtual_address, section_size, section_start
        );

        let mut section_fixed = 0;
        for offset in (section_start..section_end).step_by(ptr_size) {
            // Use @inline(never) to avoid inlining from caller's debug! formatting
            #[inline(never)]
            fn try_fix_address(data: &[u8], offset: usize, delta: i64, ptr_size: usize, runtime_start: u64, runtime_end: u64, is_64bit: bool) -> Option<u64> {
                let addr = u64::from_le_bytes(data[offset..offset+ptr_size].try_into().ok()?);
                
                if addr == 0 {
                    return None;
                }

                // Check if this looks like a runtime address
                let is_runtime_addr = if is_64bit {
                    addr >= runtime_start && addr < runtime_end
                } else {
                    addr >= runtime_start && addr < runtime_end
                };

                if is_runtime_addr && delta != 0 {
                    let old_val = u64::from_le_bytes(data[offset..offset+ptr_size].try_into().ok()?);
                    let new_val = (old_val as i64).wrapping_add(delta) as u64;
                    Some(new_val)
                } else {
                    None
                }
            }

            if let Some(new_addr) = try_fix_address(out_data, offset, delta, ptr_size, runtime_start, runtime_end, is_64bit) {
                if ptr_size == 8 {
                    out_data[offset..offset + 8].copy_from_slice(&new_addr.to_le_bytes());
                } else {
                    out_data[offset..offset + 4].copy_from_slice(&(new_addr as u32).to_le_bytes());
                }
                section_fixed += 1;
            }
        }

        if section_fixed > 0 {
            debug!("Fixed {} hardcoded addresses in section {}", section_fixed, section.name);
        }
        fixed_count += section_fixed;
        scanned_bytes += section_size;
    }

    info!(
        "Scanned {} bytes in writable sections, fixed {} hardcoded addresses",
        scanned_bytes, fixed_count
    );

    Ok(())
}

/// Pack section layout: move scattered sections to eliminate gaps
///
/// Only moves sections that have large (>1MB) gaps before them.
/// This preserves PE header integrity by operating in-place.
pub fn pack_section_layout(out_data: &mut Vec<u8>, pe: &PeHeader) -> Result<(), PeError> {
    let pe_offset = if out_data.len() >= 0x40 {
        u32::from_le_bytes([out_data[0x3C], out_data[0x3D], out_data[0x3E], out_data[0x3F]]) as usize
    } else {
        return Err(PeError::InvalidPeSignature);
    };

    let file_alignment = pe.nt_headers.optional_header.file_alignment as usize;
    let align = |n: usize| -> usize {
        (n + file_alignment - 1) & !(file_alignment - 1)
    };

    let section_table_offset =
        pe_offset + 24 + pe.nt_headers.file_header.size_of_optional_header as usize;

    // First pass: calculate section ends in file order
    let mut sections_info: Vec<(usize, usize, usize)> = Vec::new();
    for (i, section) in pe.sections.iter().enumerate() {
        let old_ptr = section.header.pointer_to_raw_data as usize;
        let raw_size = section.header.size_of_raw_data as usize;
        let old_end = old_ptr + raw_size;
        sections_info.push((i, old_ptr, old_end));
    }

    // Find sections to move: gap > 1MB
    let gap_threshold = 0x100000;
    let mut prev_end = 0usize;
    let mut moves: Vec<(usize, usize, usize, usize)> = Vec::new();

    for &(idx, old_ptr, old_end) in &sections_info {
        let gap = old_ptr.saturating_sub(prev_end);
        if gap > gap_threshold && old_ptr < out_data.len() {
            let data_len = old_end.min(out_data.len()) - old_ptr;
            if data_len > 0 {
                let new_ptr = align(prev_end);
                moves.push((idx, old_ptr, data_len, new_ptr));
                prev_end = new_ptr + data_len;
            } else {
                prev_end = old_end;
            }
        } else {
            prev_end = old_end.max(prev_end);
        }
    }

    // Apply moves: copy data in-place
    for &(section_idx, old_ptr, data_len, new_ptr) in &moves {
        let data_copy: Vec<u8> = out_data[old_ptr..old_ptr + data_len].to_vec();

        let needed = new_ptr + data_len;
        if needed > out_data.len() {
            out_data.resize(needed, 0);
        }
        out_data[new_ptr..new_ptr + data_len].copy_from_slice(&data_copy);

        // Update PointerToRawData
        let sec_header_offset = section_table_offset + (section_idx * 40);
        if sec_header_offset + 40 <= out_data.len() {
            let new_ptr_val = new_ptr as u32;
            out_data[sec_header_offset + 20..sec_header_offset + 24]
                .copy_from_slice(&new_ptr_val.to_le_bytes());
        }
    }

    // Truncate file
    let mut max_end = 0usize;
    for (i, section) in pe.sections.iter().enumerate() {
        let ptr = if let Some(&(_, _, _, new_ptr)) = moves.iter().find(|&&(idx, _, _, _)| idx == i) {
            new_ptr
        } else {
            section.header.pointer_to_raw_data as usize
        };
        let end = ptr + section.header.size_of_raw_data as usize;
        if end > max_end { max_end = end; }
    }

    let old_size = out_data.len();
    out_data.truncate(max_end);

    info!(
        "Packed section layout: {} bytes -> {} bytes (saved {} bytes)",
        old_size, max_end, old_size - max_end
    );

    Ok(())
}

/// Build Base Relocation Table for ASLR support
///
/// Scans non-executable, initialized sections for absolute addresses pointing
/// to the image and generates relocation entries. Must be called AFTER
/// fix_hardcoded_addresses (which patches addresses to file_image_base).
///
/// CRITICAL: Only scans non-executable sections. x64 code uses RIP-relative
/// addressing, so absolute addresses in .text are instruction operands,
/// not pointers. Relocating them corrupts instructions → 0xC0000005.
pub fn build_relocation_table(
    out_data: &mut Vec<u8>,
    _runtime_image_base: Option<u64>,
    is_64bit: bool,
) -> Result<(), PeError> {
    let pe = PeHeader::from_bytes(out_data)?;
    // Use the CURRENT image base from the file (after fix_hardcoded_addresses
    // has already patched all runtime addresses to this value)
    let image_base = pe.nt_headers.optional_header.image_base;
    let image_size = pe.nt_headers.optional_header.size_of_image;

    let mut builder = RelocationTableBuilder::new(image_base, image_size);

    info!(
        "Building relocation table: image_base={:#x}, image_size={:#x}",
        image_base, image_size
    );

    let ptr_size = if is_64bit { 8 } else { 4 };
    let image_end = image_base + image_size as u64;

    for section in &pe.sections {
        let is_executable = (section.characteristics & 0x20000000) != 0;
        if is_executable {
            debug!("Skipping executable section {} for relocations", section.name);
            continue;
        }

        let is_uninitialized = (section.characteristics & 0x00000080) != 0;
        if is_uninitialized {
            continue;
        }

        // Skip the .reloc section itself
        if section.name.trim_end_matches('\0') == ".reloc" {
            continue;
        }

        let section_start = section.raw_offset as usize;
        let section_size = section.raw_size as usize;
        let section_end = section_start + section_size;

        if section_end > out_data.len() {
            continue;
        }

        // Scan for absolute addresses pointing to our image
        // Use virtual_address as the section RVA (not raw_offset!)
        let section_rva = section.virtual_address;
        let mut section_count = 0;

        for offset in (0..section_size.saturating_sub(ptr_size - 1)).step_by(ptr_size) {
            let file_off = section_start + offset;
            let addr = if is_64bit {
                u64::from_le_bytes(out_data[file_off..file_off + 8].try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(out_data[file_off..file_off + 4].try_into().unwrap_or([0; 4])) as u64
            };

            if addr >= image_base && addr < image_end {
                let entry_rva = section_rva + offset as u32;
                let reloc_type = if is_64bit { 10 } else { 3 }; // DIR64 or HIGHLOW
                builder.add_relocation(entry_rva, reloc_type);
                section_count += 1;
            }
        }

        if section_count > 0 {
            debug!("Section {}: {} relocations", section.name, section_count);
        }
    }

    let reloc_count = builder.count();
    info!("Generated {} relocation entries", reloc_count);

    if reloc_count == 0 {
        warn!("No relocations found");
        return Ok(());
    }

    // Build the .reloc section data
    let reloc_data = builder.build();
    info!("Relocation table size: {} bytes", reloc_data.len());

    // Write reloc data: append after the last section in the file
    // This is simpler and safer than trying to fit into the existing .reloc space
    let file_align = pe.nt_headers.optional_header.file_alignment;
    let aligned_size = crate::utils::align_up(reloc_data.len() as u32, file_align);

    // Find current end of file
    let mut max_end = 0usize;
    let mut reloc_idx = None;
    let mut max_va_end = 0u32; // max virtual address end
    for (i, section) in pe.sections.iter().enumerate() {
        let end = section.raw_offset as usize + section.raw_size as usize;
        if end > max_end { max_end = end; }
        let va_end = section.virtual_address + section.virtual_size;
        if va_end > max_va_end { max_va_end = va_end; }
        if section.name.trim_end_matches('\0') == ".reloc" {
            reloc_idx = Some(i);
        }
    }

    // Append reloc data at end of file, aligned
    let new_reloc_offset = crate::utils::align_up(max_end as u32, file_align) as usize;
    let needed = new_reloc_offset + aligned_size as usize;
    if needed > out_data.len() {
        out_data.resize(needed, 0);
    }
    out_data[new_reloc_offset..new_reloc_offset + reloc_data.len()].copy_from_slice(&reloc_data);
    for b in &mut out_data[new_reloc_offset + reloc_data.len()..new_reloc_offset + aligned_size as usize] {
        *b = 0;
    }

    // Update .reloc section: move VA to after all other sections to avoid overlap
    if let Some(idx) = reloc_idx {
        let section_align = pe.nt_headers.optional_header.section_alignment;
        // New VA: after the last section's virtual end, aligned
        let new_reloc_va = crate::utils::align_up(max_va_end, section_align);

        let pe_off = u32::from_le_bytes(out_data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
        let sec_hdr_off = pe_off + 24 + pe.nt_headers.file_header.size_of_optional_header as usize + (idx * 40);

        // VirtualSize
        out_data[sec_hdr_off + 8..sec_hdr_off + 12].copy_from_slice(&(reloc_data.len() as u32).to_le_bytes());
        // RawSize (aligned)
        out_data[sec_hdr_off + 16..sec_hdr_off + 20].copy_from_slice(&aligned_size.to_le_bytes());
        // PointerToRawData
        out_data[sec_hdr_off + 20..sec_hdr_off + 24].copy_from_slice(&(new_reloc_offset as u32).to_le_bytes());
        // VirtualAddress (moved to avoid overlap!)
        out_data[sec_hdr_off + 12..sec_hdr_off + 16].copy_from_slice(&new_reloc_va.to_le_bytes());

        // Update BaseReloc data directory (index 5)
        let dd_off = pe_off + 24 + if is_64bit { 112 } else { 96 };
        let basereloc_off = dd_off + (5 * 8);
        out_data[basereloc_off..basereloc_off + 4].copy_from_slice(&new_reloc_va.to_le_bytes());
        out_data[basereloc_off + 4..basereloc_off + 8].copy_from_slice(&(reloc_data.len() as u32).to_le_bytes());

        // Update SizeOfImage
        let new_size_of_image = crate::utils::align_up(new_reloc_va + reloc_data.len() as u32, section_align);
        let img_size_off = pe_off + 24 + 56; // SizeOfImage in OptionalHeader
        out_data[img_size_off..img_size_off + 4].copy_from_slice(&new_size_of_image.to_le_bytes());

        // Enable ASLR: set DYNAMIC_BASE flag
        let dll_chars_off = pe_off + 24 + 70;
        let dll_chars = u16::from_le_bytes(out_data[dll_chars_off..dll_chars_off + 2].try_into().unwrap_or([0; 2]));
        const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
        let new_chars = dll_chars | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        out_data[dll_chars_off..dll_chars_off + 2].copy_from_slice(&new_chars.to_le_bytes());

        info!(
            "Relocation table: {} entries, {} bytes at VA={:#x} offset={:#x}, ASLR enabled, SizeOfImage={:#x}",
            reloc_count, reloc_data.len(), new_reloc_va, new_reloc_offset, new_size_of_image
        );
    } else {
        warn!("No .reloc section found");
    }

    Ok(())
}

// TODO: Implement file-level relocation rebuilding
// Not done yet due to 0xC0000005 crash in V2
fn rebuild_file_relocations(
    pe: &PeHeader,
) -> Result<Vec<u8>, PeError> {
    unimplemented!("Rebuild file-level relocations (TODO after V2 is stable)")
}
