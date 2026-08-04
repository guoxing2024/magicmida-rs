//! Post-processing for unpacked PE images.
//!
//! Includes:
//! - Themida section shrinking (merge VSize, restore RawSize)
//! - Absolute address fixing
//! - File layout packing
//! - Relocation table building (v2)

use crate::relocation::RelocationTableBuilder;
use crate::PeError;
use crate::PeHeader;
use tracing::{debug, info, warn};

const MAX_POSTPROCESS_OUTPUT_SIZE: usize = 512 * 1024 * 1024;

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
pub fn postprocess_image(
    out_data: &mut Vec<u8>,
    options: PostprocessOptions,
) -> Result<(), PeError> {
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
fn apply_shrink(pe: &mut PeHeader, _out_data: &mut Vec<u8>) -> Result<(), PeError> {
    let themida_names = [".winlice", ".boot", ".themida"];
    let mut removed = 0usize;
    let mut merged_sections: Vec<(u32, u32)> = Vec::new(); // (section_va, original_vsize)

    let mut i = pe.sections.len();
    loop {
        if i == 0 {
            break;
        }
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
                let prev_end = pe.sections[i - 1]
                    .virtual_address
                    .checked_add(pe.sections[i - 1].virtual_size)
                    .ok_or_else(|| {
                        PeError::Parse("section virtual end overflow during shrink".into())
                    })?;
                let new_end = removed_va
                    .checked_add(removed_vs)
                    .ok_or_else(|| PeError::Parse("removed section virtual end overflow".into()))?;
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
            pe.nt_headers.file_header.number_of_sections = pe
                .nt_headers
                .file_header
                .number_of_sections
                .saturating_sub(1);
            removed += 1;
            info!("Removed Themida section: {}", removed_name);
        }
    }

    if removed > 0 {
        // Recalculate SizeOfImage based on remaining sections
        let mut max_end = 0u32;
        for s in &pe.sections {
            let end = s
                .virtual_address
                .checked_add(s.virtual_size)
                .ok_or_else(|| {
                    PeError::Parse("section virtual end overflow during shrink".into())
                })?;
            let aligned = checked_align_up(
                end,
                pe.nt_headers.optional_header.section_alignment,
                "shrink SizeOfImage",
            )?;
            if aligned > max_end {
                max_end = aligned;
            }
        }
        pe.nt_headers.optional_header.size_of_image = max_end;
        debug!(
            "Shrink complete: removed {} sections, SizeOfImage={:#x}",
            removed, max_end
        );

        // Restore original RawSize for merged sections
        // sanitize() set RawSize=VSize, but merged sections have large VSize
        // while the actual file data should be the original pre-merge amount
        for &(sec_va, orig_vs) in &merged_sections {
            if let Some(idx) = pe.sections.iter().position(|s| s.virtual_address == sec_va) {
                let file_align = pe.nt_headers.optional_header.file_alignment;
                let aligned_vs = checked_align_up(orig_vs, file_align, "merged raw size")?;
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
    let file_image_base = if is_64bit {
        pe.nt_headers.optional_header.image_base
    } else {
        u64::from(
            u32::try_from(pe.nt_headers.optional_header.image_base)
                .map_err(|_| PeError::Parse("PE32 image base does not fit in 32 bits".into()))?,
        )
    };
    let runtime_base = runtime_image_base.unwrap_or(file_image_base);
    let runtime_start = if is_64bit {
        runtime_base
    } else {
        u64::from(u32::try_from(runtime_base).map_err(|_| {
            PeError::Parse("PE32 runtime image base does not fit in 32 bits".into())
        })?)
    };
    let image_size = u64::from(pe.nt_headers.optional_header.size_of_image);
    let runtime_end = runtime_start
        .checked_add(image_size)
        .ok_or_else(|| PeError::Parse("runtime image range overflow".into()))?;

    info!(
        "Scanning for hardcoded addresses: runtime_base={:#x}, file_base={:#x}, image_size={:#x}",
        runtime_start, file_image_base, image_size
    );

    let ptr_size: usize = if is_64bit { 8 } else { 4 };
    let mut fixed_count = 0usize;
    let mut scanned_bytes = 0usize;

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

        let section_start = usize::try_from(section.raw_offset)
            .map_err(|_| PeError::Parse("section raw offset does not fit usize".into()))?;
        let section_size = usize::try_from(section.raw_size)
            .map_err(|_| PeError::Parse("section raw size does not fit usize".into()))?;
        let section_end = section_start
            .checked_add(section_size)
            .ok_or_else(|| PeError::Parse("section raw range overflow".into()))?;

        if section_end > out_data.len() {
            warn!(
                "Section {} extends beyond file size, skipping",
                section.name
            );
            continue;
        }

        debug!(
            "Scanning section {} (RVA: {:#x}, size: {:#x}, file offset: {:#x})",
            section.name, section.virtual_address, section_size, section_start
        );

        let mut section_fixed = 0usize;
        for offset in (section_start..section_end).step_by(ptr_size) {
            let Some(new_addr) = try_fix_address(
                out_data,
                offset,
                ptr_size,
                runtime_start,
                runtime_end,
                file_image_base,
                is_64bit,
            )?
            else {
                continue;
            };

            if ptr_size == 8 {
                let end = offset
                    .checked_add(8)
                    .ok_or_else(|| PeError::Parse("64-bit address write overflow".into()))?;
                out_data[offset..end].copy_from_slice(&new_addr.to_le_bytes());
            } else {
                let new_addr32 = u32::try_from(new_addr)
                    .map_err(|_| PeError::Parse("PE32 fixed address exceeds 32 bits".into()))?;
                let end = offset
                    .checked_add(4)
                    .ok_or_else(|| PeError::Parse("32-bit address write overflow".into()))?;
                out_data[offset..end].copy_from_slice(&new_addr32.to_le_bytes());
            }
            section_fixed += 1;
        }

        if section_fixed > 0 {
            debug!(
                "Fixed {} hardcoded addresses in section {}",
                section_fixed, section.name
            );
        }
        fixed_count = fixed_count
            .checked_add(section_fixed)
            .ok_or_else(|| PeError::Parse("fixed address count overflow".into()))?;
        scanned_bytes = scanned_bytes
            .checked_add(section_size)
            .ok_or_else(|| PeError::Parse("scanned byte count overflow".into()))?;
    }

    info!(
        "Scanned {} bytes in writable sections, fixed {} hardcoded addresses",
        scanned_bytes, fixed_count
    );

    Ok(())
}

#[inline(never)]
fn try_fix_address(
    data: &[u8],
    offset: usize,
    ptr_size: usize,
    runtime_start: u64,
    runtime_end: u64,
    file_image_base: u64,
    is_64bit: bool,
) -> Result<Option<u64>, PeError> {
    let end = offset
        .checked_add(ptr_size)
        .ok_or_else(|| PeError::Parse("address read overflow".into()))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| PeError::Parse("address read outside section".into()))?;
    let addr = if is_64bit {
        u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| PeError::Parse("invalid 64-bit address width".into()))?,
        )
    } else {
        u64::from(u32::from_le_bytes(bytes.try_into().map_err(|_| {
            PeError::Parse("invalid 32-bit address width".into())
        })?))
    };

    if addr == 0 || !(runtime_start..runtime_end).contains(&addr) {
        return Ok(None);
    }

    let offset_from_runtime = addr
        .checked_sub(runtime_start)
        .ok_or_else(|| PeError::Parse("runtime address underflow".into()))?;
    let new_addr = file_image_base
        .checked_add(offset_from_runtime)
        .ok_or_else(|| PeError::Parse("fixed address overflow".into()))?;
    if !is_64bit && new_addr > u64::from(u32::MAX) {
        return Err(PeError::Parse(
            "fixed PE32 address exceeds 32-bit VA range".into(),
        ));
    }
    Ok(Some(new_addr))
}

fn checked_align_up(value: u32, alignment: u32, what: &str) -> Result<u32, PeError> {
    if alignment == 0 {
        return Err(PeError::Parse(format!("{what}: alignment is zero")));
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - remainder)
            .ok_or_else(|| PeError::Parse(format!("{what} alignment overflow")))
    }
}

fn checked_align_up_usize(value: usize, alignment: usize, what: &str) -> Result<usize, PeError> {
    if alignment == 0 {
        return Err(PeError::Parse(format!("{what}: alignment is zero")));
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - remainder)
            .ok_or_else(|| PeError::Parse(format!("{what} alignment overflow")))
    }
}

fn ensure_postprocess_size(size: usize) -> Result<(), PeError> {
    if size > MAX_POSTPROCESS_OUTPUT_SIZE {
        return Err(PeError::SizeLimit {
            what: "postprocess output".into(),
            size,
            max: MAX_POSTPROCESS_OUTPUT_SIZE,
        });
    }
    Ok(())
}

/// Pack section layout: move scattered sections to eliminate gaps
///
/// Only moves sections that have large (>1MB) gaps before them.
/// This preserves PE header integrity by operating in-place.
pub fn pack_section_layout(out_data: &mut Vec<u8>, pe: &PeHeader) -> Result<(), PeError> {
    let pe_offset = if out_data.len() >= 0x40 {
        u32::from_le_bytes([
            out_data[0x3C],
            out_data[0x3D],
            out_data[0x3E],
            out_data[0x3F],
        ]) as usize
    } else {
        return Err(PeError::InvalidPeSignature);
    };

    let file_alignment = usize::try_from(pe.nt_headers.optional_header.file_alignment)
        .map_err(|_| PeError::Parse("file alignment does not fit usize".into()))?;
    let section_table_offset = pe_offset
        .checked_add(24)
        .and_then(|n| {
            n.checked_add(usize::from(
                pe.nt_headers.file_header.size_of_optional_header,
            ))
        })
        .ok_or_else(|| PeError::Parse("section table offset overflow".into()))?;

    // First pass: calculate section ends in file order
    let mut sections_info: Vec<(usize, usize, usize)> = Vec::new();
    for (i, section) in pe.sections.iter().enumerate() {
        let old_ptr = section.header.pointer_to_raw_data as usize;
        let raw_size = section.header.size_of_raw_data as usize;
        let old_end = old_ptr
            .checked_add(raw_size)
            .ok_or_else(|| PeError::Parse("section raw end overflow".into()))?;
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
                let new_ptr =
                    checked_align_up_usize(prev_end, file_alignment, "packed section offset")?;
                let moved_end = new_ptr
                    .checked_add(data_len)
                    .ok_or_else(|| PeError::Parse("packed section end overflow".into()))?;
                moves.push((idx, old_ptr, data_len, new_ptr));
                prev_end = moved_end;
            } else {
                prev_end = old_end;
            }
        } else {
            prev_end = old_end.max(prev_end);
        }
    }

    // Apply moves: copy data in-place
    for &(section_idx, old_ptr, data_len, new_ptr) in &moves {
        let old_end = old_ptr
            .checked_add(data_len)
            .ok_or_else(|| PeError::Parse("source section copy overflow".into()))?;
        let data_copy: Vec<u8> = out_data[old_ptr..old_end].to_vec();

        let needed = new_ptr
            .checked_add(data_len)
            .ok_or_else(|| PeError::Parse("destination section copy overflow".into()))?;
        ensure_postprocess_size(needed)?;
        if needed > out_data.len() {
            out_data.resize(needed, 0);
        }
        let new_end = new_ptr
            .checked_add(data_len)
            .ok_or_else(|| PeError::Parse("destination section range overflow".into()))?;
        out_data[new_ptr..new_end].copy_from_slice(&data_copy);

        // Update PointerToRawData
        let sec_header_offset = section_table_offset
            .checked_add(
                section_idx
                    .checked_mul(40)
                    .ok_or_else(|| PeError::Parse("section header offset overflow".into()))?,
            )
            .ok_or_else(|| PeError::Parse("section header offset overflow".into()))?;
        let sec_header_end = sec_header_offset
            .checked_add(40)
            .ok_or_else(|| PeError::Parse("section header range overflow".into()))?;
        if sec_header_end <= out_data.len() {
            let new_ptr_val = u32::try_from(new_ptr)
                .map_err(|_| PeError::Parse("packed section offset exceeds PE32 limit".into()))?;
            out_data[sec_header_offset + 20..sec_header_offset + 24]
                .copy_from_slice(&new_ptr_val.to_le_bytes());
        }
    }

    // Truncate file
    let mut max_end = 0usize;
    for (i, section) in pe.sections.iter().enumerate() {
        let ptr = if let Some(&(_, _, _, new_ptr)) = moves.iter().find(|&&(idx, _, _, _)| idx == i)
        {
            new_ptr
        } else {
            section.header.pointer_to_raw_data as usize
        };
        let end = ptr
            .checked_add(section.header.size_of_raw_data as usize)
            .ok_or_else(|| PeError::Parse("packed section end overflow".into()))?;
        if end > max_end {
            max_end = end;
        }
    }

    let old_size = out_data.len();
    // Pure-rebuild / compact layouts can report section ends past the buffer
    // (PointerToRawData still virtualized) or leave max_end below the buffer.
    // Never panic on arithmetic. Prefer pad over leaving raw ranges past EOF
    // (loader rejects truncated images -?WinError 193 / ERROR_BAD_EXE_FORMAT).
    if max_end > 0 && max_end < old_size {
        out_data.truncate(max_end);
    } else if max_end > old_size {
        tracing::warn!(
            max_end,
            old_size,
            "pack_section_layout: max_end exceeds buffer; zero-padding to cover section raw ranges"
        );
        ensure_postprocess_size(max_end)?;
        out_data.resize(max_end, 0);
    }

    let new_size = out_data.len();
    info!(
        "Packed section layout: {} bytes -> {} bytes (saved {} bytes)",
        old_size,
        new_size,
        old_size.saturating_sub(new_size)
    );

    Ok(())
}

/// Pack the .reloc and .import sections tightly after .pdata in the file.
///
/// sanitize() sets PointerToRawData = VirtualAddress for all sections,
/// which leaves a gap between .pdata's file end and .reloc's file offset.
/// This function moves .reloc and .import data backward to eliminate that
/// gap, updates their PointerToRawData in the section headers, and
/// truncates the file.
///
/// Must be called AFTER build_relocation_table (which updates .reloc's
/// VirtualSize and SizeOfRawData in the on-disk header).
pub fn pack_tail_sections(out_data: &mut Vec<u8>, pe: &PeHeader) -> Result<(), PeError> {
    let pe_offset = if out_data.len() >= 0x40 {
        u32::from_le_bytes([
            out_data[0x3C],
            out_data[0x3D],
            out_data[0x3E],
            out_data[0x3F],
        ]) as usize
    } else {
        return Ok(());
    };

    let opt_hdr_size = usize::from(pe.nt_headers.file_header.size_of_optional_header);
    let section_table_offset = pe_offset
        .checked_add(24)
        .and_then(|n| n.checked_add(opt_hdr_size))
        .ok_or_else(|| PeError::Parse("tail section table offset overflow".into()))?;
    let file_align = usize::try_from(pe.nt_headers.optional_header.file_alignment)
        .map_err(|_| PeError::Parse("file alignment does not fit usize".into()))?;

    let num_sections = pe.nt_headers.file_header.number_of_sections as usize;

    let mut pdata_end = 0usize;
    let mut tail_indices: Vec<usize> = Vec::new();

    for i in 0..num_sections {
        let so = section_table_offset + i * 40;
        if so + 40 > out_data.len() {
            break;
        }
        let name = &out_data[so..so + 8];
        let raw_size =
            u32::from_le_bytes(out_data[so + 16..so + 20].try_into().unwrap_or([0; 4])) as usize;
        let raw_ptr =
            u32::from_le_bytes(out_data[so + 20..so + 24].try_into().unwrap_or([0; 4])) as usize;
        let end = raw_ptr
            .checked_add(raw_size)
            .ok_or_else(|| PeError::Parse("tail section raw end overflow".into()))?;

        if name.starts_with(b".pdata") && end > pdata_end {
            pdata_end = end;
        }
        if name.starts_with(b".reloc") || name.starts_with(b".import") {
            tail_indices.push(i);
        }
    }

    if tail_indices.is_empty() || pdata_end == 0 {
        return Ok(());
    }

    let mut next_ptr = checked_align_up_usize(pdata_end, file_align, "tail section offset")?;
    for &idx in &tail_indices {
        let so = section_table_offset + idx * 40;
        if so + 40 > out_data.len() {
            break;
        }

        let old_ptr =
            u32::from_le_bytes(out_data[so + 20..so + 24].try_into().unwrap_or([0; 4])) as usize;
        let raw_size =
            u32::from_le_bytes(out_data[so + 16..so + 20].try_into().unwrap_or([0; 4])) as usize;

        if old_ptr <= next_ptr {
            continue;
        }

        let data_len = raw_size.min(out_data.len().saturating_sub(old_ptr));
        if data_len == 0 {
            continue;
        }

        let old_end = old_ptr
            .checked_add(data_len)
            .ok_or_else(|| PeError::Parse("tail source range overflow".into()))?;
        let data_copy: Vec<u8> = out_data[old_ptr..old_end].to_vec();
        let needed = next_ptr
            .checked_add(data_len)
            .ok_or_else(|| PeError::Parse("tail destination range overflow".into()))?;
        ensure_postprocess_size(needed)?;
        if needed > out_data.len() {
            out_data.resize(needed, 0);
        }
        let new_end = next_ptr
            .checked_add(data_len)
            .ok_or_else(|| PeError::Parse("tail destination range overflow".into()))?;
        out_data[next_ptr..new_end].copy_from_slice(&data_copy);

        let new_ptr_val = next_ptr as u32;
        out_data[so + 20..so + 24].copy_from_slice(&new_ptr_val.to_le_bytes());

        info!(
            "pack_tail: section {} moved ptr {:#x} -> {:#x} ({} bytes)",
            idx, old_ptr, next_ptr, data_len
        );

        next_ptr = checked_align_up_usize(
            next_ptr
                .checked_add(data_len)
                .ok_or_else(|| PeError::Parse("tail next offset overflow".into()))?,
            file_align,
            "tail next offset",
        )?;
    }

    let new_end = next_ptr;
    if new_end < out_data.len() {
        info!(
            "pack_tail: truncated file {} -> {} bytes (saved {})",
            out_data.len(),
            new_end,
            out_data.len() - new_end
        );
        out_data.truncate(new_end);
    }

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
/// not pointers. Relocating them corrupts instructions ->0xC0000005.
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

    let ptr_size: usize = if is_64bit { 8 } else { 4 };
    let image_end = image_base
        .checked_add(image_size as u64)
        .ok_or_else(|| PeError::Parse("relocation image range overflow".into()))?;

    for section in &pe.sections {
        let is_executable = (section.characteristics & 0x20000000) != 0;
        if is_executable {
            debug!(
                "Skipping executable section {} for relocations",
                section.name
            );
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
        let section_end = section_start
            .checked_add(section_size)
            .ok_or_else(|| PeError::Parse("relocation section range overflow".into()))?;

        if section_end > out_data.len() {
            continue;
        }

        // Scan for absolute addresses pointing to our image
        // Use virtual_address as the section RVA (not raw_offset!)
        let section_rva = section.virtual_address;
        let mut section_count = 0;

        let scan_len = section_size
            .checked_sub(ptr_size.saturating_sub(1))
            .unwrap_or(0);
        for offset in (0..scan_len).step_by(ptr_size) {
            let file_off = section_start
                .checked_add(offset)
                .ok_or_else(|| PeError::Parse("relocation scan offset overflow".into()))?;
            let addr = if is_64bit {
                u64::from_le_bytes(
                    out_data[file_off..file_off + 8]
                        .try_into()
                        .unwrap_or([0; 8]),
                )
            } else {
                u32::from_le_bytes(
                    out_data[file_off..file_off + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as u64
            };

            if addr >= image_base && addr < image_end {
                let entry_rva = section_rva
                    .checked_add(u32::try_from(offset).map_err(|_| {
                        PeError::Parse("relocation RVA offset exceeds PE32 limit".into())
                    })?)
                    .ok_or_else(|| PeError::Parse("relocation RVA overflow".into()))?;
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

    let file_align = pe.nt_headers.optional_header.file_alignment;

    // Find .reloc section
    let mut reloc_idx = None;
    for (i, section) in pe.sections.iter().enumerate() {
        if section.name.trim_end_matches('\0') == ".reloc" {
            reloc_idx = Some(i);
            break;
        }
    }

    if let Some(idx) = reloc_idx {
        let pe_off = u32::from_le_bytes(out_data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
        let sec_hdr_off =
            pe_off + 24 + pe.nt_headers.file_header.size_of_optional_header as usize + (idx * 40);

        // Read the .reloc section's VA and RawPtr from the on-disk header.
        // We created this section in dumper.rs with a generous 0x2000 virtual
        // size, so the full relocation table fits without clamping.
        let reloc_raw_ptr = u32::from_le_bytes(
            out_data[sec_hdr_off + 20..sec_hdr_off + 24]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let reloc_va = u32::from_le_bytes(
            out_data[sec_hdr_off + 12..sec_hdr_off + 16]
                .try_into()
                .unwrap_or([0; 4]),
        );
        // Also read the section's raw size -?the builder must not write past it.
        let reloc_raw_size = u32::from_le_bytes(
            out_data[sec_hdr_off + 16..sec_hdr_off + 20]
                .try_into()
                .unwrap_or([0; 4]),
        );

        // The relocation table must NOT be truncated. Our .reloc section was
        // pre-sized to 0x2000 bytes which is large enough for the ~5992-byte
        // table. If (somehow) the generated data is larger than the section's
        // raw size, we error out instead of silently clamping -?a truncated
        // reloc table produces a corrupt binary that crashes under ASLR.
        if (reloc_data.len() as u32) > reloc_raw_size {
            return Err(PeError::Parse(format!(
                "Relocation table ({} bytes) exceeds pre-allocated .reloc raw size ({} bytes); \
                 increase RELOC_SECTION_VSIZE in dumper.rs",
                reloc_data.len(),
                reloc_raw_size
            )));
        }

        let aligned_size = crate::utils::align_up(reloc_data.len() as u32, file_align);
        // Do not shrink the declared relocation span. With sparse, high-RVA
        // layouts Windows rejects some images as ERROR_BAD_EXE_FORMAT when a
        // regenerated table makes the section shorter than its prior valid
        // extent. Keep the existing capacity and zero-fill unused bytes.
        let declared_raw_size = reloc_raw_size.max(aligned_size);

        // Ensure the output buffer is large enough.
        let reloc_start = usize::try_from(reloc_raw_ptr)
            .map_err(|_| PeError::Parse("relocation raw pointer does not fit usize".into()))?;
        let needed = reloc_start
            .checked_add(
                usize::try_from(declared_raw_size)
                    .map_err(|_| PeError::Parse("relocation raw size does not fit usize".into()))?,
            )
            .ok_or_else(|| PeError::Parse("relocation output range overflow".into()))?;
        ensure_postprocess_size(needed)?;
        if needed > out_data.len() {
            out_data.resize(needed, 0);
        }

        // Write the full relocation data at the section's RawPtr.
        let reloc_data_end = reloc_start
            .checked_add(reloc_data.len())
            .ok_or_else(|| PeError::Parse("relocation data range overflow".into()))?;
        out_data[reloc_start..reloc_data_end].copy_from_slice(&reloc_data);
        // Zero-fill the remainder of the aligned region.
        for b in &mut out_data[reloc_data_end..needed] {
            *b = 0;
        }

        // Keep the section's declared capacity; only the directory reports
        // the valid table length.
        out_data[sec_hdr_off + 16..sec_hdr_off + 20]
            .copy_from_slice(&declared_raw_size.to_le_bytes());

        // Update BaseReloc data directory (index 5) -?VA stays, size = actual.
        let dd_off = pe_off + 24 + if is_64bit { 112 } else { 96 };
        let basereloc_off = dd_off + (5 * 8);
        out_data[basereloc_off..basereloc_off + 4].copy_from_slice(&reloc_va.to_le_bytes());
        out_data[basereloc_off + 4..basereloc_off + 8]
            .copy_from_slice(&(reloc_data.len() as u32).to_le_bytes());

        // Do NOT re-enable DYNAMIC_BASE.  write_output_file already cleared
        // it, and fix_hardcoded_addresses patched all absolute addresses to
        // the file ImageBase.  Enabling ASLR would cause the loader to apply
        // relocations on top of already-correct addresses, corrupting them.
        // The relocation table is kept for correctness if the image is ever
        // loaded at a different base by a tool, but ASLR is disabled so the
        // loader uses the preferred ImageBase.

        info!(
            "Relocation table: {} entries ({} bytes, untruncated), VA={:#x}, ASLR disabled",
            reloc_count,
            reloc_data.len(),
            reloc_va
        );
    } else {
        warn!("No .reloc section found");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PeHeader;
    use crate::rebuild::{rebuild_pe_image, PlannedSection, RebuildPlan};

    fn data_image(is_64bit: bool, runtime_address: u64) -> Vec<u8> {
        let mut plan = if is_64bit {
            RebuildPlan::pe32_plus()
        } else {
            RebuildPlan::pe32()
        };
        let bytes = if is_64bit {
            runtime_address.to_le_bytes().to_vec()
        } else {
            u32::try_from(runtime_address)
                .expect("test runtime address fits PE32")
                .to_le_bytes()
                .to_vec()
        };
        plan.sections
            .push(PlannedSection::new(".data", 0xC000_0040, bytes));
        plan.entry_point_rva = 0x1000;
        rebuild_pe_image(&plan).expect("synthetic PE")
    }

    #[test]
    fn fix_hardcoded_addresses_reads_and_writes_pe32_values() {
        let runtime_base = 0x1000_0000u64;
        let runtime_address = runtime_base + 0x1234;
        let mut image = data_image(false, runtime_address);
        fix_hardcoded_addresses(&mut image, Some(runtime_base), false).expect("fix PE32");

        let pe = PeHeader::from_bytes(&image).expect("reparse PE32");
        let raw = pe.sections[0].raw_offset as usize;
        let fixed = u32::from_le_bytes(image[raw..raw + 4].try_into().unwrap());
        assert_eq!(fixed, 0x0040_1234);
    }

    #[test]
    fn fix_hardcoded_addresses_reads_and_writes_pe32_plus_values() {
        let runtime_base = 0x0000_0001_4000_0000u64;
        let runtime_address = runtime_base + 0x1234;
        let mut image = data_image(true, runtime_address);
        fix_hardcoded_addresses(&mut image, Some(runtime_base), true).expect("fix PE32+");

        let pe = PeHeader::from_bytes(&image).expect("reparse PE32+");
        let raw = pe.sections[0].raw_offset as usize;
        let fixed = u64::from_le_bytes(image[raw..raw + 8].try_into().unwrap());
        let expected = pe
            .nt_headers
            .optional_header
            .image_base
            .checked_add(0x1234)
            .expect("test image base arithmetic");
        assert_eq!(fixed, expected);
    }

    #[test]
    fn fix_hardcoded_addresses_rejects_overflowing_runtime_range() {
        let mut image = data_image(true, 0x1000);
        let err = fix_hardcoded_addresses(&mut image, Some(u64::MAX - 0x100), true)
            .expect_err("runtime range overflow must be rejected");
        assert!(matches!(err, PeError::Parse(_)));
    }
}
