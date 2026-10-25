//! Shared fixtures for this crate's unit tests.
//!
//! Mirrors `mida_packers_vmprotect::test_support` (which is `pub(crate)` and
//! therefore not reachable from here): hand-written field by field, so a
//! fixture cannot quietly diverge from the real header shape.

use mida_pe::{
    ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader,
    ImageSectionHeader, PeHeader, PeSection,
};

/// A PE32+ optional header.
pub(crate) fn opt_header() -> ImageOptionalHeader {
    ImageOptionalHeader {
        magic: 0x20b,
        major_linker_version: 14,
        minor_linker_version: 44,
        size_of_code: 0,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        address_of_entry_point: 0,
        base_of_code: 0,
        base_of_data: None,
        image_base: 0x1_4000_0000,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        major_operating_system_version: 6,
        minor_operating_system_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 6,
        minor_subsystem_version: 0,
        win32_version_value: 0,
        size_of_image: 0,
        size_of_headers: 0x400,
        check_sum: 0,
        subsystem: 2,
        dll_characteristics: 0x8160,
        size_of_stack_reserve: 0,
        size_of_stack_commit: 0,
        size_of_heap_reserve: 0,
        size_of_heap_commit: 0,
        loader_flags: 0,
        number_of_rva_and_sizes: 16,
        data_directory: [ImageDataDirectory::default(); 16],
    }
}

/// A `PeHeader` carrying exactly `sections`.
pub(crate) fn pe_with_sections(sections: Vec<PeSection>) -> PeHeader {
    let n = sections.len() as u16;
    PeHeader {
        dos_header: ImageDosHeader {
            e_magic: 0x5a4d,
            e_lfanew: 0x80,
        },
        nt_headers: ImageNtHeaders {
            signature: 0x0000_4550,
            file_header: ImageFileHeader {
                machine: 0x8664,
                number_of_sections: n,
                time_date_stamp: 0,
                size_of_optional_header: 0xf0,
                characteristics: 0x22,
            },
            optional_header: opt_header(),
        },
        sections,
        image_base: 0x1_4000_0000,
        entry_point: 0,
        is_64bit: true,
        file_alignment: 0x200,
        section_alignment: 0x1000,
    }
}

/// A section header with `raw_offset == 0`.
pub(crate) fn sec(name: &str, raw_size: u32, virtual_size: u32, chars: u32) -> PeSection {
    sec_at(name, raw_size, virtual_size, chars, 0)
}

/// A section header with an explicit file offset.
pub(crate) fn sec_at(
    name: &str,
    raw_size: u32,
    virtual_size: u32,
    chars: u32,
    raw_offset: u32,
) -> PeSection {
    sec_va(name, 0, virtual_size, raw_size, raw_offset, chars)
}

/// A section header with explicit virtual address, sizes, file offset and flags.
pub(crate) fn sec_va(
    name: &str,
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_offset: u32,
    chars: u32,
) -> PeSection {
    PeSection {
        header: ImageSectionHeader {
            name: [0; 8],
            virtual_size,
            virtual_address,
            size_of_raw_data: raw_size,
            pointer_to_raw_data: raw_offset,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: chars,
        },
        name: name.to_string(),
        virtual_address,
        virtual_size,
        raw_offset,
        raw_size,
        characteristics: chars,
        extra_data: None,
    }
}
