//! Output file writing logic for the dump process.
//!
//! Extracted from `dump_process` in `dumper.rs`.

use tracing::{debug, info, warn};

use crate::error::PeError;
use crate::header::PeHeader;
use crate::import_table::ImportTableBuilder;

use super::helpers::{
    create_dos_header, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
};
use super::import_section::{fill_additional_iat_locations, write_iat_to_output};
use super::types::DumpOptions;

use super::container_snapshot::ContainerSnapshot;

/// Write the dumped PE to the output file.
///
/// This assembles:
/// - Synthetic DOS header
/// - NT headers + section table
/// - Section data (from dump buffer or extra_data)
/// - Import IAT values
pub(crate) fn write_output_file(
    pe: &mut PeHeader,
    dump_buf: &[u8],
    _import_builder: Option<&ImportTableBuilder>,
    import_thunks: &[u64],
    original_iat_rva: u32,
    is_64bit: bool,
    opts: &DumpOptions,
    output_entry_point: u32,
    _containers: &[ContainerSnapshot],
) -> Result<Vec<u8>, PeError> {
    let pe_offset = 0x80usize;
    let mut out_data = Vec::new();

    // 6a. Synthetic DOS header
    out_data.extend_from_slice(&create_dos_header());

    // 6b. Update header fields
    pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;
    pe.nt_headers.optional_header.address_of_entry_point = output_entry_point;
    pe.nt_headers.optional_header.dll_characteristics &= !IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    // NOTE: Don't convert .data to BSS - some programs need initialized data
    // Instead, we'll selectively zero problematic regions in write_section_data

    // 6c. Serialize NT headers + section table
    debug!(
        file_chars = %format!("{:#06x}", pe.nt_headers.file_header.characteristics),
        subsystem = %format!("{:#06x}", pe.nt_headers.optional_header.subsystem),
        nsec = pe.nt_headers.file_header.number_of_sections,
        iat_dir_rva = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].virtual_address),
        iat_dir_size = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].size),
        tls_dir_rva = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[9].virtual_address),
        tls_dir_size = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[9].size),
        "before serialize_headers",
    );
    let header_data = pe.serialize_headers()?;
    let header_len = header_data.len();
    let header_end = pe_offset + header_len;

    // DEBUG: Check what serialize_headers actually wrote
    debug_serialize_output(&header_data);

    let first_section_ptr = pe
        .sections
        .iter()
        .filter(|s| s.header.size_of_raw_data > 0 && s.header.pointer_to_raw_data > 0)
        .map(|s| s.header.pointer_to_raw_data as usize)
        .min()
        .unwrap_or(header_end);
    let initial_len = std::cmp::max(header_end, first_section_ptr);
    out_data.resize(initial_len, 0);
    out_data[pe_offset..header_end].copy_from_slice(&header_data);

    // 6d. Manually re-write the data directories
    rewrite_data_directories(&mut out_data, pe, pe_offset, is_64bit);

    // 6e. Write each section's data
    write_section_data(&mut out_data, pe, dump_buf);

    // HOTFIX: Initialize container pointers to zero
    // The container at RVA 0x145710 has invalid values that cause ACCESS_VIOLATION
    // Setting to zero tells the program the container is empty
    if let Some(section) = pe.sections.iter().find(|s| s.virtual_address <= 0x145710 && 0x145710 < s.virtual_address + s.virtual_size) {
        let container_rva = 0x145710u32;
        let container_offset = section.header.pointer_to_raw_data + (container_rva - section.virtual_address);

        if container_offset < out_data.len() as u32 && container_offset + 24 <= out_data.len() as u32 {
            info!("HOTFIX: Zeroing container pointer at RVA {:#x}, file offset {:#x}", container_rva, container_offset);

            // Zero out the container triple (begin, end, capacity) = 24 bytes
            for i in 0..24 {
                out_data[(container_offset + i) as usize] = 0;
            }
        }
    }

    // 6e2. Container restoration is now handled by the pre-OEP bootstrap stub.
    // The stub embedded in .boot will allocate heap memory and update the
    // encoded pointers at runtime. No static restoration needed here.

    // 6f. Write Hint/Name RVAs to the IAT location
    write_iat_to_output(&mut out_data, pe, import_thunks, original_iat_rva, is_64bit);

    // 6g. Fill additional IAT locations
    fill_additional_iat_locations(&mut out_data, pe, opts, import_thunks, is_64bit);

    // Final sanity check
    let final_chars_offset = pe_offset + 22;
    debug!(
        final_chars = %format!("{:#06x}", u16::from_le_bytes([out_data[final_chars_offset], out_data[final_chars_offset + 1]])),
        "final out_data header characteristics",
    );

    Ok(out_data)
}

/// Debug output for serialize_headers.
fn debug_serialize_output(header_data: &[u8]) {
    let sec1_offset_in_header = 0x108 + 40;
    let chars_offset_in_header = sec1_offset_in_header + 36;
    if chars_offset_in_header + 4 <= header_data.len() {
        let chars = u32::from_le_bytes([
            header_data[chars_offset_in_header],
            header_data[chars_offset_in_header + 1],
            header_data[chars_offset_in_header + 2],
            header_data[chars_offset_in_header + 3],
        ]);
        info!(
            "serialize_headers buffer: Section 1 chars at {:#x} = {:#x}",
            chars_offset_in_header, chars
        );
    }

    debug!(
        header_out_chars = %format!("{:#06x}", u16::from_le_bytes([header_data[22], header_data[23]])),
        "after serialize_headers",
    );
    debug!(
        import_va = %format!("{:#x}", u32::from_le_bytes([header_data[136], header_data[137], header_data[138], header_data[139]])),
        import_sz = %format!("{:#x}", u32::from_le_bytes([header_data[140], header_data[141], header_data[142], header_data[143]])),
        iat_va = %format!("{:#x}", u32::from_le_bytes([header_data[232], header_data[233], header_data[234], header_data[235]])),
        iat_sz = %format!("{:#x}", u32::from_le_bytes([header_data[236], header_data[237], header_data[238], header_data[239]])),
        "after serialize_headers: IMPORT/IAT data_dir",
    );
}

/// Manually re-write data directories at the correct offsets.
fn rewrite_data_directories(out_data: &mut [u8], pe: &PeHeader, pe_offset: usize, is_64bit: bool) {
    // CRITICAL FIX: Correct calculation for PE32+ Data Directory offset
    // PE Header structure:
    // - PE signature: 4 bytes
    // - COFF header: 20 bytes
    // - Optional Header starts at PE + 24
    //   - For PE32+: Data Directory starts at Optional Header + 112

    let opt_header_offset = pe_offset + 24;
    let dd_start = if is_64bit {
        opt_header_offset + 112  // PE32+: magic(2) + versions(2) + sizes(20) + addresses(24) + sizes(16) + magic(8) + subsystem(2) + dll(2) + sizes(40) = 112
    } else {
        opt_header_offset + 96   // PE32
    };

    info!(
        "CRITICAL FIX: Rewriting data directories at offset {:#x}, TLS[9] = RVA={:#x} Size={:#x}",
        dd_start,
        pe.nt_headers.optional_header.data_directory[9].virtual_address,
        pe.nt_headers.optional_header.data_directory[9].size
    );

    // Write all 16 data directories
    for (i, dd) in pe
        .nt_headers
        .optional_header
        .data_directory
        .iter()
        .enumerate()
    {
        let off = dd_start + i * 8;
        if off + 8 <= out_data.len() {
            out_data[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
            out_data[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());

            // Debug log for TLS and IMPORT
            if i == 9 && dd.virtual_address != 0 {
                info!(
                    "CRITICAL FIX: Wrote TLS Directory[9] at file offset {:#x}: RVA={:#x}, Size={:#x}",
                    off, dd.virtual_address, dd.size
                );

                // Verify the write
                let verify_rva = u32::from_le_bytes([out_data[off], out_data[off+1], out_data[off+2], out_data[off+3]]);
                let verify_size = u32::from_le_bytes([out_data[off+4], out_data[off+5], out_data[off+6], out_data[off+7]]);
                info!(
                    "CRITICAL FIX: Verified TLS in buffer: RVA={:#x}, Size={:#x}",
                    verify_rva, verify_size
                );
            }

            if i == 1 {
                info!(
                    "Writing IMPORT Directory[1] at file offset {:#x}: RVA={:#x}, Size={:#x}",
                    off, dd.virtual_address, dd.size
                );
            }
        } else {
            warn!(
                "CRITICAL FIX: Cannot write directory[{}] at offset {:#x}, buffer size={}",
                i, off, out_data.len()
            );
        }
    }

    // CRITICAL FIX: Force Data Directory[15] to 0
    let dd15_offset = dd_start + 15 * 8;
    if dd15_offset + 8 <= out_data.len() {
        out_data[dd15_offset..dd15_offset + 4].fill(0);
        out_data[dd15_offset + 4..dd15_offset + 8].fill(0);
        info!(
            "CRITICAL FIX: Cleared Data Directory[15] at offset {:#x}",
            dd15_offset
        );
    }

    debug!(
        "After manual data_directory write: IAT[12] in out_data at offset {:#x}: RVA={:#x} size={:#x}",
        dd_start + 12 * 8,
        u32::from_le_bytes([out_data[dd_start + 96], out_data[dd_start + 97], out_data[dd_start + 98], out_data[dd_start + 99]]),
        u32::from_le_bytes([out_data[dd_start + 100], out_data[dd_start + 101], out_data[dd_start + 102], out_data[dd_start + 103]])
    );
    debug!(
        "After manual data_directory write: IMPORT[1] in out_data at offset {:#x}: RVA={:#x} size={:#x}",
        dd_start + 8,
        u32::from_le_bytes([out_data[dd_start + 8], out_data[dd_start + 9], out_data[dd_start + 10], out_data[dd_start + 11]]),
        u32::from_le_bytes([out_data[dd_start + 12], out_data[dd_start + 13], out_data[dd_start + 14], out_data[dd_start + 15]])
    );
}

/// Write section data at each section's PointerToRawData offset.
fn write_section_data(out_data: &mut Vec<u8>, pe: &PeHeader, dump_buf: &[u8]) {
    let dump_size = pe.size_of_image() as usize;
    let delta = 0u32; // pe.trim_huge_sections result, not used here for simplicity

    let trimmed_total = delta as usize;
    let dump_buf_effective_len = dump_size.saturating_sub(trimmed_total);

    for section in &pe.sections {
        let raw_offset = section.header.pointer_to_raw_data as usize;
        if raw_offset == 0 || section.header.size_of_raw_data == 0 {
            continue;
        }

        let raw_size = section.header.size_of_raw_data as usize;
        let data = if let Some(ref extra) = section.extra_data {
            if raw_offset + extra.len() > out_data.len() {
                out_data.resize(raw_offset + extra.len(), 0);
            }
            out_data[raw_offset..raw_offset + extra.len()].copy_from_slice(extra);
            continue;
        } else if section.virtual_address as usize + raw_size <= dump_buf_effective_len {
            &dump_buf[section.virtual_address as usize..section.virtual_address as usize + raw_size]
        } else if raw_size <= dump_buf.len() {
            &dump_buf[section.virtual_address as usize..section.virtual_address as usize + raw_size]
        } else {
            warn!(
                section = %section.name,
                va = format_args!("{:#x}", section.virtual_address),
                raw_offset = format_args!("{raw_offset:#x}"),
                raw_size = format_args!("{raw_size:#x}"),
                "Section data falls outside captured dump; skipping"
            );
            continue;
        };

        let out_end = raw_offset + data.len();
        if out_end > out_data.len() {
            out_data.resize(out_end, 0);
        }
        out_data[raw_offset..raw_offset + data.len()].copy_from_slice(data);
        debug!(
            section = %section.name,
            raw_offset = format_args!("{raw_offset:#x}"),
            len = data.len(),
            "section written",
        );
    }
}
