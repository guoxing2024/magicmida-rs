//! Creation of .pdata (exception table) and .reloc sections after shrink.
//!
//! Extracted from `dump_process` in `dumper.rs`.

use tracing::{info, warn};

use crate::header::PeHeader;

/// Create a .pdata section holding the exception table bytes that were
/// previously inside the deleted .winlice section.
pub(crate) fn create_pdata_section(
    pe: &mut PeHeader,
    dump_buf: &[u8],
    exc_rva: u32,
    exc_size: u32,
) {
    let exc_off = exc_rva as usize;
    let exc_len = exc_size as usize;
    let file_align = pe.nt_headers.optional_header.file_alignment;
    let section_align = pe.nt_headers.optional_header.section_alignment;

    // Copy the exception table bytes out of the dump buffer.
    let mut exc_data: Vec<u8> = Vec::with_capacity(exc_len);
    if exc_off + exc_len <= dump_buf.len() {
        exc_data.extend_from_slice(&dump_buf[exc_off..exc_off + exc_len]);
    } else if exc_off < dump_buf.len() {
        let avail = dump_buf.len() - exc_off;
        exc_data.extend_from_slice(&dump_buf[exc_off..exc_off + avail]);
        exc_data.resize(exc_len, 0);
    } else {
        warn!(
            exc_rva = format!("{:#x}", exc_rva),
            "Exception table RVA is outside dump_buf; zero-filling .pdata"
        );
        exc_data.resize(exc_len, 0);
    }

    // SizeOfRawData must be FileAlignment-aligned.
    let raw_size = crate::utils::align_up(exc_len as u32, file_align);

    let pdata_idx = pe.create_section_index(".pdata", exc_len as u32);

    pe.sections[pdata_idx].virtual_size = exc_len as u32;
    pe.sections[pdata_idx].header.virtual_size = exc_len as u32;
    pe.sections[pdata_idx].header.size_of_raw_data = raw_size;
    pe.sections[pdata_idx].raw_size = raw_size;
    // .pdata must be READ + INITIALIZED_DATA (matches MSVC default).
    const IMAGE_SCN_MEM_READ_PD: u32 = 0x4000_0000;
    const IMAGE_SCN_CNT_INITIALIZED_DATA_PD: u32 = 0x0000_0040;
    pe.sections[pdata_idx].characteristics =
        IMAGE_SCN_MEM_READ_PD | IMAGE_SCN_CNT_INITIALIZED_DATA_PD;
    pe.sections[pdata_idx].header.characteristics =
        pe.sections[pdata_idx].characteristics;

    // Pad raw data to alignment and store as extra_data.
    let mut padded = exc_data;
    if (padded.len() as u32) < raw_size {
        padded.resize(raw_size as usize, 0);
    }
    pe.sections[pdata_idx].extra_data = Some(padded);

    // Update SizeOfImage for the new section.
    let new_end = pe.sections[pdata_idx].header.virtual_address
        + crate::utils::align_up(exc_len as u32, section_align);
    if pe.nt_headers.optional_header.size_of_image < new_end {
        pe.nt_headers.optional_header.size_of_image = new_end;
    }

    // Point DataDirectory[3] (Exception) at the new .pdata.
    const IMAGE_DIRECTORY_ENTRY_EXCEPTION_PD: usize = 3;
    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION_PD] =
        crate::header::ImageDataDirectory {
            virtual_address: pe.sections[pdata_idx].virtual_address,
            size: exc_len as u32,
        };
    info!(
        "Created .pdata section idx={} VA={:#x} size={:#x} (raw={:#x}); Exception dir restored",
        pdata_idx,
        pe.sections[pdata_idx].virtual_address,
        exc_len,
        raw_size
    );
}

/// Create a placeholder .reloc section large enough for the full relocation
/// table.  The actual bytes are written later by `build_relocation_table`.
pub(crate) fn create_reloc_section(pe: &mut PeHeader) {
    let file_align = pe.nt_headers.optional_header.file_alignment;
    let section_align = pe.nt_headers.optional_header.section_alignment;

    // 0x2000 (8 KiB) virtual size — comfortably larger than the ~5992-byte
    // table the builder produces, with headroom.
    let reloc_vsize: u32 = 0x2000;
    let reloc_raw = crate::utils::align_up(reloc_vsize, file_align);

    let reloc_idx = pe.create_section_index(".reloc", reloc_vsize);
    pe.sections[reloc_idx].virtual_size = reloc_vsize;
    pe.sections[reloc_idx].header.virtual_size = reloc_vsize;
    pe.sections[reloc_idx].header.size_of_raw_data = reloc_raw;
    pe.sections[reloc_idx].raw_size = reloc_raw;
    // .reloc: READ + INITIALIZED_DATA + MEM_DISCARDABLE (matches MSVC).
    const IMAGE_SCN_MEM_READ_R: u32 = 0x4000_0000;
    const IMAGE_SCN_CNT_INITIALIZED_DATA_R: u32 = 0x0000_0040;
    const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
    pe.sections[reloc_idx].characteristics =
        IMAGE_SCN_MEM_READ_R | IMAGE_SCN_CNT_INITIALIZED_DATA_R | IMAGE_SCN_MEM_DISCARDABLE;
    pe.sections[reloc_idx].header.characteristics =
        pe.sections[reloc_idx].characteristics;

    // Zero-filled raw data placeholder.
    pe.sections[reloc_idx].extra_data = Some(vec![0u8; reloc_raw as usize]);

    // Update SizeOfImage.
    let new_end = pe.sections[reloc_idx].header.virtual_address
        + crate::utils::align_up(reloc_vsize, section_align);
    if pe.nt_headers.optional_header.size_of_image < new_end {
        pe.nt_headers.optional_header.size_of_image = new_end;
    }

    // Set BaseReloc DataDirectory[5] to the new .reloc VA.
    const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC] =
        crate::header::ImageDataDirectory {
            virtual_address: pe.sections[reloc_idx].virtual_address,
            size: reloc_vsize, // provisional; refined later
        };
    info!(
        "Created .reloc section idx={} VA={:#x} vsize={:#x} raw={:#x}",
        reloc_idx,
        pe.sections[reloc_idx].virtual_address,
        reloc_vsize,
        reloc_raw
    );
}
