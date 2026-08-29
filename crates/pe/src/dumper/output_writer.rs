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

    // Loader-valid invariant: every section raw range claimed in the section
    // table must be covered by the final file length. Callers may set
    // SizeOfRawData larger than the payload they attach (e.g. section-align
    // bootstrap stubs); without padding, CreateProcess fails with WinError 193.
    ensure_section_raw_ranges_covered(&mut out_data, pe);

    // Zero detected SecurityCookie container triples in the on-disk image.
    // Stale live-process heap pointers cause AV; the post-CRT .boot stub
    // re-allocates and re-encodes them at runtime. Generic over all detections
    // (replaces the old hard-coded 0x145710 hotfix).
    let mut zeroed = 0usize;
    for container in _containers {
        let Some(section) = pe.sections.iter().find(|s| {
            s.virtual_address <= container.rva
                && container.rva < s.virtual_address.saturating_add(s.virtual_size)
        }) else {
            continue;
        };
        if section.header.pointer_to_raw_data == 0 || section.header.size_of_raw_data == 0 {
            continue;
        }
        let file_off = section.header.pointer_to_raw_data as usize
            + (container.rva - section.virtual_address) as usize;
        if file_off + 24 > out_data.len() {
            continue;
        }
        out_data[file_off..file_off + 24].fill(0);
        zeroed += 1;
    }
    if zeroed > 0 {
        info!(
            containers = zeroed,
            "Zeroed detected container triples (runtime restore via .boot if installed)"
        );
    }

    // 6f. Write Hint/Name RVAs to the IAT location
    write_iat_to_output(&mut out_data, pe, import_thunks, original_iat_rva, is_64bit);

    // 6g. Fill additional IAT locations
    fill_additional_iat_locations(&mut out_data, pe, opts, import_thunks, is_64bit);

    // Re-assert raw-range coverage after IAT writes (they only touch existing
    // bytes, but keep the invariant explicit at the emit boundary).
    ensure_section_raw_ranges_covered(&mut out_data, pe);

    // Final sanity check
    let final_chars_offset = pe_offset + 22;
    debug!(
        final_chars = %format!("{:#06x}", u16::from_le_bytes([out_data[final_chars_offset], out_data[final_chars_offset + 1]])),
        "final out_data header characteristics",
    );

    Ok(out_data)
}

/// Ensure every section's `PointerToRawData + SizeOfRawData` is within `out_data`.
///
/// Pads the file with zeros when a section header claims a raw range past EOF.
/// This is a generic PE loader contract: Windows rejects images whose section
/// raw ranges extend past the file (ERROR_BAD_EXE_FORMAT / WinError 193).
///
/// Does **not** shrink oversized files or rewrite section headers — only
/// extends the buffer so on-disk headers remain consistent with file length.
pub(crate) fn ensure_section_raw_ranges_covered(out_data: &mut Vec<u8>, pe: &PeHeader) {
    let mut max_end = out_data.len();
    let mut short_sections = 0usize;
    for section in &pe.sections {
        let ptr = section.header.pointer_to_raw_data as usize;
        let raw = section.header.size_of_raw_data as usize;
        if ptr == 0 || raw == 0 {
            continue;
        }
        let Some(end) = ptr.checked_add(raw) else {
            warn!(
                section = %section.name,
                ptr = format_args!("{ptr:#x}"),
                raw = format_args!("{raw:#x}"),
                "section raw range overflows usize; skipping pad"
            );
            continue;
        };
        if end > out_data.len() {
            short_sections += 1;
            debug!(
                section = %section.name,
                ptr = format_args!("{ptr:#x}"),
                raw = format_args!("{raw:#x}"),
                end = format_args!("{end:#x}"),
                file_len = format_args!("{:#x}", out_data.len()),
                "section raw range past EOF; will zero-pad file"
            );
        }
        if end > max_end {
            max_end = end;
        }
    }
    if max_end > out_data.len() {
        let old = out_data.len();
        out_data.resize(max_end, 0);
        info!(
            old_len = format_args!("{old:#x}"),
            new_len = format_args!("{max_end:#x}"),
            short_sections,
            "Padded PE output so all section raw ranges are file-covered"
        );
    }
}

/// True when every non-empty raw section range fits in `file_len`.
///
/// Used by unit tests and can be reused by emit-path self-checks.
#[allow(dead_code)]
pub(crate) fn section_raw_ranges_fit(pe: &PeHeader, file_len: usize) -> bool {
    pe.sections.iter().all(|section| {
        let ptr = section.header.pointer_to_raw_data as usize;
        let raw = section.header.size_of_raw_data as usize;
        if ptr == 0 || raw == 0 {
            return true;
        }
        match ptr.checked_add(raw) {
            Some(end) => end <= file_len,
            None => false,
        }
    })
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
        opt_header_offset + 112 // PE32+: magic(2) + versions(2) + sizes(20) + addresses(24) + sizes(16) + magic(8) + subsystem(2) + dll(2) + sizes(40) = 112
    } else {
        opt_header_offset + 96 // PE32
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
                let verify_rva = u32::from_le_bytes([
                    out_data[off],
                    out_data[off + 1],
                    out_data[off + 2],
                    out_data[off + 3],
                ]);
                let verify_size = u32::from_le_bytes([
                    out_data[off + 4],
                    out_data[off + 5],
                    out_data[off + 6],
                    out_data[off + 7],
                ]);
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
                i,
                off,
                out_data.len()
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
fn write_section_data(out_data: &mut Vec<u8>, pe: &mut PeHeader, dump_buf: &[u8]) {
    let _dump_size = pe.size_of_image() as usize;
    let file_align = {
        let fa = pe.nt_headers.optional_header.file_alignment as usize;
        if fa.is_power_of_two() && fa >= 0x200 {
            fa
        } else {
            0x200
        }
    };

    let n = pe.sections.len();
    for idx in 0..n {
        // Read fields without holding a borrow (we need to mutate later).
        let raw_size = pe.sections[idx].header.size_of_raw_data as usize;
        let has_extra = pe.sections[idx].extra_data.is_some();
        let va = pe.sections[idx].virtual_address as usize;
        let vsz = pe.sections[idx].virtual_size as usize;
        let name = pe.sections[idx].name.clone();

        // 1. extra_data path (import/reloc/wfix/bootstrap stubs)
        if has_extra {
            let extra = pe.sections[idx].extra_data.clone().unwrap_or_default();
            if extra.is_empty() {
                // Still reserve claimed raw range so headers stay loader-valid.
                if raw_size > 0 {
                    let raw_offset = pe.sections[idx].header.pointer_to_raw_data as usize;
                    if raw_offset != 0 {
                        let end = raw_offset.saturating_add(raw_size);
                        if end > out_data.len() {
                            out_data.resize(end, 0);
                        }
                    }
                }
                continue;
            }
            let mut raw_offset = pe.sections[idx].header.pointer_to_raw_data as usize;
            if raw_offset == 0 {
                raw_offset = (out_data.len() + file_align - 1) & !(file_align - 1);
                pe.sections[idx].header.pointer_to_raw_data = raw_offset as u32;
                pe.sections[idx].raw_offset = raw_offset as u32;
                warn!(
                    section = %name,
                    assigned_ptr = format_args!("{raw_offset:#x}"),
                    "Section has extra_data but PointerToRawData=0; appending at file end"
                );
            }
            // Cover the *claimed* SizeOfRawData, not only extra.len(). Bootstrap
            // stubs often section-align SizeOfRawData while leaving extra_data
            // unpadded; writing only extra.len() truncates the image (WinError 193).
            let cover = raw_size.max(extra.len());
            let end = raw_offset.saturating_add(cover);
            if end > out_data.len() {
                out_data.resize(end, 0);
            }
            let copy_len = extra.len().min(cover);
            out_data[raw_offset..raw_offset + copy_len].copy_from_slice(&extra[..copy_len]);
            info!(
                section = %name,
                raw_offset = format_args!("{raw_offset:#x}"),
                len = extra.len(),
                claimed_raw = format_args!("{raw_size:#x}"),
                "section written (extra_data)"
            );
            continue;
        }

        // 2. Normal path: raw_size > 0
        if raw_size > 0 {
            let raw_offset = pe.sections[idx].header.pointer_to_raw_data as usize;
            if raw_offset == 0 {
                continue;
            }
            // Always reserve the claimed raw range first (zeros).
            let out_end = raw_offset.saturating_add(raw_size);
            if out_end > out_data.len() {
                out_data.resize(out_end, 0);
            }
            if va >= dump_buf.len() {
                warn!(
                    section = %name,
                    "Section VA outside dump; zero-filled claimed raw range"
                );
                continue;
            }
            let available = raw_size.min(dump_buf.len() - va);
            if available < raw_size {
                warn!(
                    section = %name,
                    available,
                    raw_size,
                    "Section data partially outside dump; zero-padding remainder of raw range"
                );
            }
            if available > 0 {
                out_data[raw_offset..raw_offset + available]
                    .copy_from_slice(&dump_buf[va..va + available]);
            }
            debug!(
                section = %name,
                raw_offset = format_args!("{raw_offset:#x}"),
                len = available,
                "section written"
            );
            continue;
        }

        // 3. Zero-raw path: Themida sections (.themida, .winlice, etc.) often
        // have raw_size=0 on disk (compressed). The dump_buf captured their
        // runtime-decompressed content. Materialize it so the unpacked PE can
        // run without the Themida decompressor. This matches the original
        // Magicmida behavior (keeps .themida raw = virtual_size).
        if vsz == 0 {
            continue;
        }
        let available = if va + vsz <= dump_buf.len() {
            vsz
        } else if va < dump_buf.len() {
            dump_buf.len() - va
        } else {
            continue;
        };
        if available == 0 {
            continue;
        }
        // Check the data is non-zero (avoid materializing empty/BSS sections)
        let sample = &dump_buf[va..va + available.min(64)];
        if sample.iter().all(|&b| b == 0) {
            continue;
        }

        let raw_offset = (out_data.len() + file_align - 1) & !(file_align - 1);
        let aligned_raw = (available + file_align - 1) & !(file_align - 1);
        if raw_offset + aligned_raw > out_data.len() {
            out_data.resize(raw_offset + aligned_raw, 0);
        }
        out_data[raw_offset..raw_offset + available].copy_from_slice(&dump_buf[va..va + available]);
        // Mutate the section header so the PE loader maps the data.
        pe.sections[idx].header.pointer_to_raw_data = raw_offset as u32;
        pe.sections[idx].header.size_of_raw_data = aligned_raw as u32;
        pe.sections[idx].raw_offset = raw_offset as u32;
        pe.sections[idx].raw_size = aligned_raw as u32;
        info!(
            section = %name,
            va = format_args!("{va:#x}"),
            raw_offset = format_args!("{raw_offset:#x}"),
            raw_size = format_args!("{available:#x}"),
            "Materialized zero-raw section from dump buffer (Themida runtime data)"
        );
    }

    // Final pass: any section still claiming raw past EOF gets zero-padded.
    ensure_section_raw_ranges_covered(out_data, pe);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{
        ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader,
        ImageSectionHeader, PeSection,
    };
    use crate::DumpOptions;

    fn pe_with_text_and_short_extra_boot(
        text_va: u32,
        text_raw: u32,
        boot_payload_len: usize,
        boot_claimed_raw: u32,
    ) -> PeHeader {
        assert!(
            boot_payload_len < boot_claimed_raw as usize,
            "test setup requires short payload vs claimed SizeOfRawData"
        );
        let boot_ptr = 0x200u32 + text_raw;
        let boot_va = text_va + 0x1000;
        PeHeader {
            dos_header: ImageDosHeader {
                e_magic: 0x5A4D,
                e_lfanew: 0x80,
            },
            nt_headers: ImageNtHeaders {
                signature: 0x4550,
                file_header: ImageFileHeader {
                    machine: 0x8664,
                    number_of_sections: 2,
                    time_date_stamp: 0,
                    size_of_optional_header: 0xF0,
                    characteristics: 0x22,
                },
                optional_header: ImageOptionalHeader {
                    magic: 0x20B,
                    major_linker_version: 14,
                    minor_linker_version: 0,
                    size_of_code: text_raw,
                    size_of_initialized_data: boot_claimed_raw,
                    size_of_uninitialized_data: 0,
                    address_of_entry_point: 0x1000,
                    base_of_code: text_va,
                    base_of_data: None,
                    image_base: 0x140000000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    major_operating_system_version: 6,
                    minor_operating_system_version: 0,
                    major_image_version: 0,
                    minor_image_version: 0,
                    major_subsystem_version: 6,
                    minor_subsystem_version: 0,
                    win32_version_value: 0,
                    size_of_image: boot_va + 0x1000,
                    size_of_headers: 0x200,
                    check_sum: 0,
                    subsystem: 3,
                    dll_characteristics: 0,
                    size_of_stack_reserve: 0x100000,
                    size_of_stack_commit: 0x1000,
                    size_of_heap_reserve: 0x100000,
                    size_of_heap_commit: 0x1000,
                    loader_flags: 0,
                    number_of_rva_and_sizes: 16,
                    data_directory: [ImageDataDirectory::default(); 16],
                },
            },
            sections: vec![
                PeSection {
                    header: ImageSectionHeader {
                        name: *b".text\0\0\0",
                        virtual_size: text_raw,
                        virtual_address: text_va,
                        size_of_raw_data: text_raw,
                        pointer_to_raw_data: 0x200,
                        pointer_to_relocations: 0,
                        pointer_to_linenumbers: 0,
                        number_of_relocations: 0,
                        number_of_linenumbers: 0,
                        characteristics: 0x60000020,
                    },
                    name: ".text".to_string(),
                    virtual_address: text_va,
                    virtual_size: text_raw,
                    raw_offset: 0x200,
                    raw_size: text_raw,
                    characteristics: 0x60000020,
                    extra_data: None,
                },
                PeSection {
                    header: ImageSectionHeader {
                        name: *b".boot\0\0\0",
                        virtual_size: boot_claimed_raw,
                        virtual_address: boot_va,
                        size_of_raw_data: boot_claimed_raw,
                        pointer_to_raw_data: boot_ptr,
                        pointer_to_relocations: 0,
                        pointer_to_linenumbers: 0,
                        number_of_relocations: 0,
                        number_of_linenumbers: 0,
                        characteristics: 0xE0000020,
                    },
                    name: ".boot".to_string(),
                    virtual_address: boot_va,
                    virtual_size: boot_claimed_raw,
                    raw_offset: boot_ptr,
                    raw_size: boot_claimed_raw,
                    characteristics: 0xE0000020,
                    // Short payload: reproduces SizeOfRawData > extra_data.len()
                    // (generic; not a sample-specific pad constant).
                    extra_data: Some(vec![0x90; boot_payload_len]),
                },
            ],
            image_base: 0x140000000,
            entry_point: 0x1000,
            is_64bit: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }

    fn dump_opts(image_base: u64, entry_point: u32) -> DumpOptions {
        DumpOptions {
            image_base,
            entry_point,
            fix_imports: false,
            create_data_sections: false,
            shrink: false,
            output_path: std::path::PathBuf::from("NUL"),
            iat_location: None,
            additional_iat_locations: Vec::new(),
            executable_path: None,
            early_section_snapshots: Vec::new(),
            container_restore: crate::ContainerRestoreMode::Off,
            profile: crate::DumpProfile::OreansClassic,
            security_cookie_rva: None,
            security_cookie_complement_rva: None,
            pure_rebuild: false,
            dump_timing: crate::DumpTiming::Immediate,
            section_content_reference: None,
            capture_policy: crate::DumpCapturePolicy::default(),
            keep_runtime_base: false,
        }
    }

    /// Generic regression: short extra_data vs larger claimed SizeOfRawData
    /// must still produce a file covering every section raw range.
    ///
    /// Reproduces the structural class of WinError 193 (section raw end past
    /// EOF) without hardcoding any sample-specific pad length.
    #[test]
    fn write_output_file_pads_short_extra_data_to_claimed_raw_size() {
        // Multiple shortfall sizes prove the pad is driven by headers, not a
        // single magic constant from one protected sample.
        for &(payload, claimed) in &[(0x100usize, 0x1000u32), (0xE38, 0x1000), (0x50, 0x200)] {
            let mut pe = pe_with_text_and_short_extra_boot(0x1000, 0x200, payload, claimed);
            let dump_buf = vec![0u8; pe.size_of_image() as usize];
            let entry_point = pe.entry_point;
            let opts = dump_opts(pe.image_base, entry_point);
            let out = write_output_file(
                &mut pe,
                &dump_buf,
                None,
                &[],
                0,
                true,
                &opts,
                entry_point,
                &[],
            )
            .expect("write_output_file");

            assert!(
                section_raw_ranges_fit(&pe, out.len()),
                "payload={payload:#x} claimed={claimed:#x}: raw ranges must fit file len {:#x}",
                out.len()
            );

            let boot = pe
                .sections
                .iter()
                .find(|s| s.name.starts_with(".boot"))
                .expect(".boot");
            let boot_end =
                boot.header.pointer_to_raw_data as usize + boot.header.size_of_raw_data as usize;
            assert!(
                out.len() >= boot_end,
                "file {:#x} must cover .boot raw end {:#x} (shortfall class, not sample pad)",
                out.len(),
                boot_end
            );
            // Payload bytes present at start of .boot raw.
            let ptr = boot.header.pointer_to_raw_data as usize;
            assert_eq!(&out[ptr..ptr + payload], &vec![0x90; payload][..]);
            // Remainder of claimed raw is zero-padded.
            if boot.header.size_of_raw_data as usize > payload {
                assert!(
                    out[ptr + payload..boot_end].iter().all(|&b| b == 0),
                    "claimed raw past payload must be zero-filled"
                );
            }
        }
    }

    #[test]
    fn ensure_section_raw_ranges_covered_extends_truncated_buffer() {
        let pe = pe_with_text_and_short_extra_boot(0x1000, 0x200, 0x40, 0x400);
        let boot = pe.sections.iter().find(|s| s.name == ".boot").unwrap();
        let need = boot.header.pointer_to_raw_data as usize + boot.header.size_of_raw_data as usize;
        // Simulate a truncated writer that only emitted payload length.
        let mut buf = vec![0u8; boot.header.pointer_to_raw_data as usize + 0x40];
        assert!(!section_raw_ranges_fit(&pe, buf.len()));
        ensure_section_raw_ranges_covered(&mut buf, &pe);
        assert_eq!(buf.len(), need);
        assert!(section_raw_ranges_fit(&pe, buf.len()));
    }

    #[test]
    fn section_raw_ranges_fit_rejects_past_eof() {
        let pe = pe_with_text_and_short_extra_boot(0x1000, 0x200, 0x10, 0x200);
        let boot = pe.sections.iter().find(|s| s.name == ".boot").unwrap();
        let full = boot.header.pointer_to_raw_data as usize + boot.header.size_of_raw_data as usize;
        assert!(section_raw_ranges_fit(&pe, full));
        assert!(!section_raw_ranges_fit(&pe, full.saturating_sub(1)));
    }
}
