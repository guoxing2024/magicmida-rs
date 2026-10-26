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

        // Uninitialized sections normally hold no bytes on disk, so there is
        // nothing to fix up.  But after a live-memory dump they DO hold bytes:
        // a packed image's `.bss` is where the shell parks its initialised
        // globals, and those globals are full of runtime pointers.  Skipping
        // them leaves absolute addresses baked at the dump-time base, which
        // then point nowhere once the product loads elsewhere.
        //
        // Only skip when the section really is empty in the output buffer.
        let is_uninitialized = (section.characteristics & 0x00000080) != 0;
        if is_uninitialized {
            let start = section.raw_offset as usize;
            let end = start.saturating_add(section.raw_size as usize);
            let has_data = end <= out_data.len()
                && out_data[start..end].iter().any(|&b| b != 0);
            if !has_data {
                continue;
            }
            debug!(
                section = %section.name,
                "Uninitialized section carries dumped data — fixing addresses anyway"
            );
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

/// Byte ranges belonging to the import table's *metadata*: descriptors, DLL
/// name strings, function name strings, and the lookup/thunk tables.
///
/// **No relocation entry may ever point inside one of these.**  The loader
/// applies relocations before it resolves imports, so an entry landing on a
/// name string adds the load delta to ASCII and the lookup then fails with
/// `STATUS_ENTRYPOINT_NOT_FOUND` (0xC0000139).
///
/// This is not hypothetical.  The x86 product emitted a HIGHLOW entry at rva
/// `0x19344`, which sits inside the name string `"GetMessageA"` at `0x1933a`
/// and straddles `"geA\0"` = `0x00416567` — a value that genuinely falls inside
/// the image range `0x400000..0x41b000`, so the range test alone cannot reject
/// it.  Measured: clearing that one entry turned 0xC0000139 into a successful
/// load, while every import name resolved under `GetProcAddress` both before and
/// after (`imp_check`: 54 named imports, 0 failed) — the disagreement between
/// the two is exactly what a clobbered name string looks like.
///
/// x86 is where this bites because an image based at `0x400000` is only 1.7 MB,
/// so four ASCII bytes of a name are likely to land in range; the x64 goldens
/// base at `0x140000000` and no name string can reach it (measured: 0 such
/// entries in both).
fn import_metadata_ranges(pe: &PeHeader, data: &[u8], is_64bit: bool) -> Vec<(u32, u32)> {
    const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
    let ptr = if is_64bit { 8usize } else { 4 };
    let dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if dir.virtual_address == 0 {
        return Vec::new();
    }

    let u32_at = |o: usize| -> u32 {
        if o + 4 <= data.len() {
            u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
        } else {
            0
        }
    };
    let str_len = |o: usize| -> Option<usize> {
        let mut n = 0usize;
        while o + n < data.len() && n < 256 {
            if data[o + n] == 0 {
                return Some(n);
            }
            n += 1;
        }
        None
    };

    let mut ranges: Vec<(u32, u32)> = Vec::new();
    let mut cursor = dir.virtual_address;
    let mut guard = 0usize;

    // Walk descriptors until the null terminator, collecting each descriptor,
    // its DLL name, and both thunk tables with every function name they cite.
    loop {
        guard += 1;
        if guard > 512 {
            break;
        }
        let Some(off) = pe.rva_to_offset(cursor) else {
            break;
        };
        let off = off as usize;
        let (oft, name_rva, ft) = (u32_at(off), u32_at(off + 12), u32_at(off + 16));
        ranges.push((cursor, 20));
        if name_rva == 0 {
            break;
        }

        if let Some(n) = pe.rva_to_offset(name_rva) {
            if let Some(len) = str_len(n as usize) {
                ranges.push((name_rva, len as u32 + 1));
            }
        }

        for table in [oft, ft] {
            if table == 0 {
                continue;
            }
            let Some(t0) = pe.rva_to_offset(table) else {
                continue;
            };
            let t0 = t0 as usize;
            let mut k = 0usize;
            loop {
                k += 1;
                if k > 4096 {
                    break;
                }
                let entry = u32_at(t0 + (k - 1) * ptr);
                if entry == 0 {
                    break;
                }
                // Only a name entry cites a string; an ordinal has the high bit set.
                if entry & 0x8000_0000 == 0 {
                    if let Some(f) = pe.rva_to_offset(entry) {
                        if let Some(len) = str_len(f as usize + 2) {
                            ranges.push((entry, len as u32 + 2 + 1));
                        }
                    }
                }
            }
            ranges.push((table, (k * ptr) as u32));
        }

        cursor += 20;
    }

    ranges
}

/// Build Base Relocation Table for ASLR support
///
/// Scans non-executable, initialized sections for absolute addresses pointing
/// to the image and generates relocation entries. Must be called AFTER
/// fix_hardcoded_addresses (which patches addresses to file_image_base).
///
/// CRITICAL: Only scans non-executable sections **on x64**.  x64 code uses
/// RIP-relative addressing, so absolute addresses in .text are instruction
/// operands, not pointers.  Relocating them corrupts instructions →
/// 0xC0000005.
///
/// On x86 the opposite is true and the section must be scanned: 32-bit code has
/// no RIP-relative addressing, so every global access is an absolute operand
/// (`cmp dword ptr [0x403010], 2`).  See [`crate::code_relocations`] for the
/// measurements — the reference x86 sample's own table has 256 of its 277
/// entries inside `.text`, and skipping them leaves the product crashing at the
/// first absolute global access after the loader picks a different base.
///
/// CRITICAL: Also refuses any entry that lands inside the import table's
/// metadata — see [`import_metadata_ranges`] for why that rule exists.
/// Everything `build_relocation_table` needs in order to know *which* dwords
/// to relocate, collected into a builder.  Split out so the `.reloc`
/// reservation can be sized from the same scan before the section exists.
fn collect_relocation_builder(
    data: &[u8],
    is_64bit: bool,
) -> Result<(PeHeader, RelocationTableBuilder), PeError> {
    let pe = PeHeader::from_bytes(data)?;
    // Use the CURRENT image base from the file (after fix_hardcoded_addresses
    // has already patched all runtime addresses to this value)
    let image_base = pe.nt_headers.optional_header.image_base;
    let image_size = pe.nt_headers.optional_header.size_of_image;

    let mut builder = RelocationTableBuilder::new(image_base, image_size);

    // Anything inside the import table's own metadata must never be relocated:
    // the loader applies relocations before resolving imports, so an entry on a
    // name string adds the load delta to ASCII and the lookup dies with
    // 0xC0000139.  See `import_metadata_ranges` for the measured x86 case.
    let metadata_ranges = import_metadata_ranges(&pe, data, is_64bit);
    let in_import_metadata = |rva: u32| -> bool {
        metadata_ranges
            .iter()
            .any(|&(start, len)| rva >= start && rva < start.saturating_add(len))
    };

    info!(
        "Building relocation table: image_base={:#x}, image_size={:#x}, \
         {} import-metadata ranges protected",
        image_base,
        image_size,
        metadata_ranges.len()
    );

    let ptr_size = if is_64bit { 8 } else { 4 };
    let image_end = image_base + image_size as u64;

    // ---- x86 only: absolute operands inside executable sections ------------
    //
    // `dump_buf` uses file offset == RVA for mapped sections, which is exactly
    // the layout `scan_code_relocations` expects.  The x64 rule is unchanged:
    // RIP-relative code has no absolute operands worth rebasing.
    if !is_64bit {
        let sections: Vec<(u32, u32, u32)> = pe
            .sections
            .iter()
            .filter(|s| s.name.trim_end_matches('\0') != ".reloc")
            .map(|s| (s.virtual_address, s.raw_size, s.characteristics))
            .collect();
        let code_hits = crate::code_relocations::scan_code_relocations(
            data,
            image_base as u32,
            image_size,
            sections,
            |rva| in_import_metadata(rva),
        );
        info!(
            "Code relocation scan (x86): {} absolute operands inside executable sections",
            code_hits.len()
        );
        for hit in &code_hits {
            builder.add_relocation(hit.rva, 3); // IMAGE_REL_BASED_HIGHLOW
            debug!(
                "  code relocation at rva {:#x} -> {:#x}",
                hit.rva, hit.target
            );
        }
    }

    for section in &pe.sections {
        let is_executable = (section.characteristics & 0x20000000) != 0;
        if is_executable {
            // x86 already covered executable sections above with an
            // instruction-aware scan; the pointer-stride walk below would
            // miss 79% of them and cannot tell an operand from a pointer.
            if is_64bit {
                debug!("Skipping executable section {} for relocations", section.name);
            }
            continue;
        }

        // Uninitialized sections normally hold no bytes on disk, so there is
        // nothing to relocate.  But after a live-memory dump they DO hold
        // bytes: a packed image's `.bss` is where the shell parks its
        // initialised globals, and those globals are full of runtime pointers.
        // Skipping them leaves absolute addresses baked at the dump-time base,
        // which then point nowhere once the product loads elsewhere.
        //
        // Only skip when the section really is empty in the output buffer.
        let is_uninitialized = (section.characteristics & 0x00000080) != 0;
        if is_uninitialized {
            let start = section.raw_offset as usize;
            let end = start.saturating_add(section.raw_size as usize);
            let has_data = end <= data.len()
                && data[start..end].iter().any(|&b| b != 0);
            if !has_data {
                continue;
            }
            debug!(
                section = %section.name,
                "Uninitialized section carries dumped data — relocating it anyway"
            );
        }

        // Skip the .reloc section itself
        if section.name.trim_end_matches('\0') == ".reloc" {
            continue;
        }

        let section_start = section.raw_offset as usize;
        let section_size = section.raw_size as usize;
        let section_end = section_start + section_size;

        if section_end > data.len() {
            continue;
        }

        // Scan for absolute addresses pointing to our image
        // Use virtual_address as the section RVA (not raw_offset!)
        let section_rva = section.virtual_address;
        let mut section_count = 0;

        for offset in (0..section_size.saturating_sub(ptr_size - 1)).step_by(ptr_size) {
            let file_off = section_start + offset;
            let addr = if is_64bit {
                u64::from_le_bytes(data[file_off..file_off + 8].try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(data[file_off..file_off + 4].try_into().unwrap_or([0; 4])) as u64
            };

            if addr >= image_base && addr < image_end {
                let entry_rva = section_rva + offset as u32;
                // Reject entries that would corrupt the import table.  The range
                // test above is not enough on its own: ASCII in a name string can
                // land inside a small image's address range.
                if in_import_metadata(entry_rva) {
                    debug!(
                        "Refusing relocation at rva {:#x}: inside import-table metadata",
                        entry_rva
                    );
                    continue;
                }
                let reloc_type = if is_64bit { 10 } else { 3 }; // DIR64 or HIGHLOW
                builder.add_relocation(entry_rva, reloc_type);
                section_count += 1;
            }
        }

        if section_count > 0 {
            debug!("Section {}: {} relocations", section.name, section_count);
        }
    }

    Ok((pe, builder))
}

/// The size a relocation table generated from `data` would occupy — the
/// lower bound for the `.reloc` section reservation.
///
/// The full generator runs later on the final file layout, where additional
/// exclusions apply (the rebuilt import metadata) and compaction may have
/// removed bytes, so this pass is an upper bound on the real table.
pub fn estimate_reloc_table_size(data: &[u8], is_64bit: bool) -> u32 {
    match collect_relocation_builder(data, is_64bit) {
        Ok((_, builder)) => builder.build().len() as u32,
        Err(_) => 0,
    }
}

pub fn build_relocation_table(
    out_data: &mut Vec<u8>,
    _runtime_image_base: Option<u64>,
    is_64bit: bool,
) -> Result<(), PeError> {
    let (pe, builder) = collect_relocation_builder(out_data, is_64bit)?;
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
        // Also read the section's raw size — the builder must not write past it.
        let reloc_raw_size = u32::from_le_bytes(
            out_data[sec_hdr_off + 16..sec_hdr_off + 20]
                .try_into()
                .unwrap_or([0; 4]),
        );

        // The relocation table must NOT be truncated. Our .reloc section was
        // pre-sized to 0x2000 bytes which is large enough for the ~5992-byte
        // table. If (somehow) the generated data is larger than the section's
        // raw size, we error out instead of silently clamping — a truncated
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

        // Ensure the output buffer is large enough.
        let needed = reloc_raw_ptr as usize + aligned_size as usize;
        if needed > out_data.len() {
            out_data.resize(needed, 0);
        }

        // Write the full relocation data at the section's RawPtr.
        out_data[reloc_raw_ptr as usize..reloc_raw_ptr as usize + reloc_data.len()]
            .copy_from_slice(&reloc_data);
        // Zero-fill the remainder of the aligned region.
        for b in &mut out_data
            [reloc_raw_ptr as usize + reloc_data.len()..reloc_raw_ptr as usize + aligned_size as usize]
        {
            *b = 0;
        }

        // Update .reloc section header: VirtualSize = actual table size,
        // SizeOfRawData = aligned size. VA stays as created.
        //
        // **Unless that opens a hole in the virtual layout.**  The placeholder
        // `.reloc` was created with a generous reserved size so the table would
        // fit, and the next section (`.import`) was placed after it.  Rewriting
        // `virtual_size` down to the real table length does not move `.import`,
        // so for an image whose table is smaller than the reservation the
        // aligned end of `.reloc` no longer reaches the next section:
        //
        //     x86 product: .reloc VA 0x17000, table 0xac -> aligned end 0x18000
        //                  .import VA 0x19000                -> HOLE 0x1000
        //     x64 golden:  .reloc VA 0x174000, table 0x1754 -> aligned end 0x176000
        //                  .import VA 0x176000              -> no hole
        //
        // The loader rejects a non-contiguous image outright: measured
        // `CreateProcess -> ERROR_BAD_EXE_FORMAT (193)` on the x86 product, and
        // injecting the same hole into a working sample reproduces the 193.
        //
        // Closing it by growing `virtual_size` up to the next section's VA costs
        // nothing and moves no other header.  The loader reads only
        // `BaseReloc.size` bytes and zero-fills the rest, exactly as it does for
        // `.bss`.  The golden x64 case has no hole, so this branch does not fire
        // there and its bytes are untouched.
        let section_align = pe.nt_headers.optional_header.section_alignment.max(1);
        let reloc_end = reloc_va + reloc_data.len() as u32;
        let aligned_end = crate::utils::align_up(reloc_end, section_align);
        let next_va = pe
            .sections
            .iter()
            .filter(|s| s.virtual_address > reloc_va)
            .map(|s| s.virtual_address)
            .min();
        let announced_vsize = match next_va {
            Some(next) if next > aligned_end => {
                warn!(
                    "Closing a {:#x}-byte hole after .reloc: virtual_size {:#x} -> {:#x} \
                     (the loader refuses non-contiguous sections)",
                    next - aligned_end,
                    reloc_data.len() as u32,
                    next - reloc_va
                );
                next - reloc_va
            }
            _ => reloc_data.len() as u32,
        };
        out_data[sec_hdr_off + 8..sec_hdr_off + 12]
            .copy_from_slice(&announced_vsize.to_le_bytes());
        out_data[sec_hdr_off + 16..sec_hdr_off + 20]
            .copy_from_slice(&aligned_size.to_le_bytes());

        // Update BaseReloc data directory (index 5) — VA stays, size = actual.
        let dd_off = pe_off + 24 + if is_64bit { 112 } else { 96 };
        let basereloc_off = dd_off + (5 * 8);
        out_data[basereloc_off..basereloc_off + 4].copy_from_slice(&reloc_va.to_le_bytes());
        out_data[basereloc_off + 4..basereloc_off + 8]
            .copy_from_slice(&(reloc_data.len() as u32).to_le_bytes());

        // Enable ASLR: set DYNAMIC_BASE flag.
        let dll_chars_off = pe_off + 24 + 70;
        let dll_chars = u16::from_le_bytes(
            out_data[dll_chars_off..dll_chars_off + 2]
                .try_into()
                .unwrap_or([0; 2]),
        );
        const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
        let new_chars = dll_chars | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        out_data[dll_chars_off..dll_chars_off + 2].copy_from_slice(&new_chars.to_le_bytes());

        info!(
            "Relocation table: {} entries ({} bytes, untruncated), VA={:#x}, ASLR enabled",
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
mod relocation_metadata_tests {
    use super::*;

    /// Build a minimal 32-bit PE with two sections:
    ///   `.data`  rva 0x1000, holds a genuine image pointer at rva 0x1000
    ///   `.import` rva 0x2000, holds one descriptor + names, and — critically —
    ///             a *function name string* whose ASCII bytes also happen to
    ///             encode a value inside the image range.
    ///
    /// The last part is the whole point: it reproduces the real x86 defect where
    /// `"geA\0"` inside `"GetMessageA"` read as `0x00416567`, which is inside
    /// `0x400000..0x41b000`.  A range test alone accepts it; the metadata
    /// exclusion must reject it.
    fn make_pe32_with_trap_name() -> Vec<u8> {
        let mut b = vec![0u8; 0x1000];
        // DOS header
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c] = 0x80;
        // PE signature
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        // Machine = i386
        b[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
        b[coff + 2..coff + 4].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
        b[coff + 16..coff + 18].copy_from_slice(&224u16.to_le_bytes()); // SizeOfOptionalHeader

        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EP
        b[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
        b[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlign
        b[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlign
        // SizeOfImage must be large enough that the trap dword 0x00416567
        // (from "geA\0") falls *inside* the image range.  The real x86 product
        // had SizeOfImage 0x1b000, i.e. range 0x400000..0x41b000, and 0x416567
        // is inside it.  A smaller SizeOfImage makes the trap harmless and the
        // test passes even with the fix disabled — verified by mutation.
        b[opt + 56..opt + 60].copy_from_slice(&0x1b000u32.to_le_bytes()); // SizeOfImage
        b[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders

        let dd = opt + 96;
        // Import directory -> rva 0x2000
        b[dd + 8..dd + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        b[dd + 12..dd + 16].copy_from_slice(&40u32.to_le_bytes());

        let sh = opt + 224;
        // .data @ rva 0x1000, raw 0x200
        b[sh..sh + 5].copy_from_slice(b".data");
        b[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh + 16..sh + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
        b[sh + 36..sh + 40].copy_from_slice(&0xC0000040u32.to_le_bytes());

        // .import @ rva 0x2000, raw 0x1200
        let sh2 = sh + 40;
        b[sh2..sh2 + 7].copy_from_slice(b".import");
        b[sh2 + 8..sh2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        b[sh2 + 16..sh2 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh2 + 20..sh2 + 24].copy_from_slice(&0x1200u32.to_le_bytes());
        b[sh2 + 36..sh2 + 40].copy_from_slice(&0x40000040u32.to_le_bytes());

        // .reloc @ rva 0x3000, raw 0x2200 — `build_relocation_table` writes here.
        let sh3 = sh2 + 40;
        b[sh3..sh3 + 6].copy_from_slice(b".reloc");
        b[sh3 + 8..sh3 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh3 + 12..sh3 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        b[sh3 + 16..sh3 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sh3 + 20..sh3 + 24].copy_from_slice(&0x2200u32.to_le_bytes());
        b[sh3 + 36..sh3 + 40].copy_from_slice(&0x42000040u32.to_le_bytes());

        b.resize(0x3200, 0);
        // genuine pointer in .data
        b[0x200..0x204].copy_from_slice(&0x400000u32.to_le_bytes());
        // descriptor at rva 0x2000 -> file 0x1200
        let d = 0x1200;
        b[d..d + 4].copy_from_slice(&0x2060u32.to_le_bytes()); // OFT
        b[d + 12..d + 16].copy_from_slice(&0x2040u32.to_le_bytes()); // Name
        b[d + 16..d + 20].copy_from_slice(&0x2060u32.to_le_bytes()); // FirstThunk
        // DLL name "user32.dll" at rva 0x2040
        b[0x1240..0x124a].copy_from_slice(b"user32.dll");
        // Lookup table at rva 0x2060: one name entry -> rva 0x2072, then terminator.
        b[0x1260..0x1264].copy_from_slice(&0x2072u32.to_le_bytes());
        // Hint/Name entry at rva 0x2072: 2-byte hint, then "GetMessageA" at rva
        // 0x2074.  Character 8 of that name is 'g', so "geA\0" lands at rva
        // 0x207c — 4-byte aligned relative to the section start, and therefore
        // actually visited by the relocation scanner.  The dword there is
        // 'g','e','A',0 = 0x00416567, inside 0x400000..0x405000, so the range
        // test alone accepts it.
        //
        // This geometry is copied from the real defect: the x86 product had its
        // Hint/Name entry at rva 0x1933a, the name at 0x1933c (4-aligned), and
        // "geA\0" at 0x19344 — the rva that got the bogus HIGHLOW entry.
        //
        // Alignment matters for the test's power.  A first attempt put the trap
        // at an unaligned rva; the scanner never looked at it, so the test
        // passed even with the fix disabled.  Verified by mutation.
        b[0x1274..0x127f].copy_from_slice(b"GetMessageA");
        b
    }

    /// The trap string must really contain an in-image dword, otherwise the test
    /// proves nothing about the real defect.
    #[test]
    fn trap_name_encodes_an_in_image_dword() {
        let b = make_pe32_with_trap_name();
        // "geA\0" begins 7 bytes into "GetMessageA"
        let mut found = None;
        for i in 0..b.len().saturating_sub(3) {
            let v = u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
            if v == 0x0041_6567 {
                found = Some(i);
            }
        }
        assert_eq!(
            found,
            Some(0x127c),
            "the name string must encode 0x00416567, which sits inside \
             0x400000..0x404000 and therefore survives a pure range test"
        );
    }

    #[test]
    fn relocation_never_lands_inside_import_metadata() {
        let mut data = make_pe32_with_trap_name();
        build_relocation_table(&mut data, None, false).expect("relocation build");

        let pe = PeHeader::from_bytes(&data).unwrap();
        let ranges = import_metadata_ranges(&pe, &data, false);
        assert!(
            ranges.iter().any(|&(s, l)| s <= 0x207c && 0x207c < s + l),
            "the name-string range must be protected: {ranges:#x?}"
        );

        // Every emitted entry must be outside those ranges.
        let rva = pe.nt_headers.optional_header.data_directory[5].virtual_address;
        let size = pe.nt_headers.optional_header.data_directory[5].size;
        let base = pe.rva_to_offset(rva).unwrap() as usize;
        let mut off = base;
        let mut entries = 0;
        while off < base + size as usize {
            let page = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            let bs = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
            if bs == 0 {
                break;
            }
            for i in 0..((bs - 8) / 2) as usize {
                let eo = off + 8 + i * 2;
                let en = u16::from_le_bytes(data[eo..eo + 2].try_into().unwrap());
                if en >> 12 == 0 {
                    continue;
                }
                let target = page + u32::from(en & 0xfff);
                entries += 1;
                for &(s, l) in &ranges {
                    assert!(
                        !(target >= s && target < s + l),
                        "relocation at rva {target:#x} lands inside import metadata \
                         {s:#x}+{l:#x} — the loader would corrupt it and then fail \
                         with 0xC0000139"
                    );
                }
            }
            off += bs as usize;
        }
        assert!(entries >= 1, "the genuine .data pointer should still be relocated");
    }

    /// The genuine pointer must survive: excluding import metadata must not
    /// degenerate into excluding everything.
    #[test]
    fn genuine_pointer_is_still_relocated() {
        let mut data = make_pe32_with_trap_name();
        build_relocation_table(&mut data, None, false).expect("relocation build");
        let pe = PeHeader::from_bytes(&data).unwrap();
        let ranges = import_metadata_ranges(&pe, &data, false);
        assert!(
            !ranges.iter().any(|&(s, l)| s <= 0x1000 && 0x1000 < s + l),
            "rva 0x1000 is a real pointer, not import metadata"
        );
    }
}
