//! Internal helper functions for the postprocess module.

use mida_pe::{PeHeader, PeSection};

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Check whether a data directory entry references the given section.
pub(super) fn is_referenced_by_data_directory(pe: &PeHeader, section: &PeSection) -> bool {
    let sec_start = section.virtual_address;
    let sec_end = section.virtual_address + section.virtual_size;

    for dir in &pe.nt_headers.optional_header.data_directory {
        if dir.virtual_address == 0 {
            continue;
        }
        let dir_end = dir.virtual_address.saturating_add(dir.size);
        if dir.virtual_address >= sec_start && dir_end <= sec_end {
            return true;
        }
    }
    false
}

/// Recompute `SizeOfImage` from the last section's end.
pub(super) fn recalc_size_of_image(pe: &mut PeHeader) {
    if let Some(last) = pe.sections.last() {
        let new_size = last.virtual_address + last.virtual_size;
        pe.nt_headers.optional_header.size_of_image = new_size;
    }
}

/// Create a [`PeSection`] from raw values.
///
/// Used internally to construct the new `.rdata` and `.data` sections.
pub(super) fn make_section(
    name: &str,
    virtual_address: u32,
    virtual_size: u32,
    characteristics: u32,
) -> PeSection {
    let mut name_bytes = [0u8; 8];
    let name_slice = name.as_bytes();
    let len = name_slice.len().min(8);
    name_bytes[..len].copy_from_slice(&name_slice[..len]);

    let header = mida_pe::ImageSectionHeader {
        name: name_bytes,
        virtual_size,
        virtual_address,
        size_of_raw_data: virtual_size,
        pointer_to_raw_data: virtual_address,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics,
    };

    PeSection {
        header,
        name: name.to_string(),
        virtual_address,
        virtual_size,
        raw_offset: virtual_address,
        raw_size: virtual_size,
        characteristics,
        extra_data: None,
    }
}

/// Sync the public fields of a [`PeSection`] from its raw header after mutation.
pub(super) fn update_section_from_header(section: &mut PeSection) {
    // The PeSection::update_from_header method is crate-private (pub(crate)).
    // We inline the logic here since we're outside the `mida_pe` crate.
    section.name = mida_pe::header::decode_section_name(&section.header.name);
    section.virtual_address = section.header.virtual_address;
    section.virtual_size = section.header.virtual_size;
    section.raw_offset = section.header.pointer_to_raw_data;
    section.raw_size = section.header.size_of_raw_data;
    section.characteristics = section.header.characteristics;
}
