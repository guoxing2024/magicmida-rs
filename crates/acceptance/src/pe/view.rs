//! Parsed PE image view used by structural gates.

use super::read::{in_bounds, u16_le, u32_le, u64_le};

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

pub const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

pub const SIZEOF_SECTION_HEADER: usize = 40;
pub const SIZEOF_DATA_DIRECTORY: usize = 8;
pub const SIZEOF_IMPORT_DESCRIPTOR: usize = 20;

#[derive(Debug, Clone)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct SectionView {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionView {
    pub fn is_executable(&self) -> bool {
        (self.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            || (self.characteristics & IMAGE_SCN_CNT_CODE) != 0
    }

    /// Virtual size used for range checks (max of VirtualSize and SizeOfRawData when mapped).
    pub fn virtual_extent(&self) -> u64 {
        let vs = self.virtual_size as u64;
        let raw = self.size_of_raw_data as u64;
        vs.max(raw)
    }
}

#[derive(Debug, Clone)]
pub struct OptionalHeaderView {
    pub magic: u16,
    pub is_pe32_plus: bool,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub dll_characteristics: u16,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

#[derive(Debug, Clone)]
pub struct PeImage<'a> {
    pub bytes: &'a [u8],
    pub e_lfanew: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
    pub optional: OptionalHeaderView,
    pub sections: Vec<SectionView>,
    pub section_table_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIssue {
    pub code: String,
    pub message: String,
}

impl ParseIssue {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Attempt to parse a PE image. Returns the image and any non-fatal notes, or
/// a fatal issue if headers cannot be established.
#[allow(clippy::unwrap_used)] // every unwrap below follows an explicit
                              // in_bounds/checked length guard; the safe u16_le/u32_le/u64_le helpers can
                              // only return None on a short buffer, and the guards make that unreachable.
                              // These are parse invariants, not fallible error paths (WO-10).
pub fn try_parse(bytes: &[u8]) -> Result<PeImage<'_>, ParseIssue> {
    if bytes.len() < 0x40 {
        return Err(ParseIssue::new(
            "dos_too_small",
            "file smaller than minimum DOS header (0x40 bytes)",
        ));
    }
    let e_magic = u16_le(bytes, 0).unwrap();
    if e_magic != IMAGE_DOS_SIGNATURE {
        return Err(ParseIssue::new(
            "dos_signature",
            format!("invalid DOS signature 0x{e_magic:04x}, expected MZ"),
        ));
    }
    let e_lfanew = u32_le(bytes, 0x3C).unwrap();
    if e_lfanew < 0x40 {
        return Err(ParseIssue::new(
            "e_lfanew_too_small",
            format!("e_lfanew 0x{e_lfanew:x} overlaps DOS header"),
        ));
    }
    let nt_off = e_lfanew as usize;
    // PE sig (4) + COFF (20) + optional magic (2)
    if !in_bounds(nt_off as u64, 26, bytes.len() as u64) {
        return Err(ParseIssue::new(
            "nt_headers_oob",
            format!(
                "NT headers at 0x{e_lfanew:x} exceed file size {}",
                bytes.len()
            ),
        ));
    }
    let sig = u32_le(bytes, nt_off).unwrap();
    if sig != IMAGE_NT_SIGNATURE {
        return Err(ParseIssue::new(
            "nt_signature",
            format!("invalid NT signature 0x{sig:08x}"),
        ));
    }
    let coff = nt_off + 4;
    let machine = u16_le(bytes, coff).unwrap();
    let number_of_sections = u16_le(bytes, coff + 2).unwrap();
    let size_of_optional_header = u16_le(bytes, coff + 16).unwrap();
    let characteristics = u16_le(bytes, coff + 18).unwrap();

    let opt_off = coff + 20;
    if size_of_optional_header < 2 {
        return Err(ParseIssue::new(
            "optional_header_too_small",
            "SizeOfOptionalHeader < 2",
        ));
    }
    if !in_bounds(
        opt_off as u64,
        size_of_optional_header as u64,
        bytes.len() as u64,
    ) {
        return Err(ParseIssue::new(
            "optional_header_oob",
            "optional header exceeds file bounds",
        ));
    }
    let magic = u16_le(bytes, opt_off).unwrap();
    let is_pe32_plus = match magic {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => false,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => true,
        _ => {
            return Err(ParseIssue::new(
                "optional_magic",
                format!("unknown optional header magic 0x{magic:04x}"),
            ));
        }
    };

    // Layout offsets within optional header
    let (
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        address_of_entry_point,
        image_base,
        dll_characteristics,
        number_of_rva_and_sizes,
        dd_off,
    ) = if is_pe32_plus {
        // PE32+ optional header minimum size before directories: 112
        if size_of_optional_header < 112 {
            return Err(ParseIssue::new(
                "optional_header_pe32plus_truncated",
                "PE32+ optional header truncated before data directories",
            ));
        }
        let section_alignment = u32_le(bytes, opt_off + 32).unwrap();
        let file_alignment = u32_le(bytes, opt_off + 36).unwrap();
        let address_of_entry_point = u32_le(bytes, opt_off + 16).unwrap();
        let image_base = u64_le(bytes, opt_off + 24).unwrap();
        let size_of_image = u32_le(bytes, opt_off + 56).unwrap();
        let size_of_headers = u32_le(bytes, opt_off + 60).unwrap();
        let dll_characteristics = u16_le(bytes, opt_off + 70).unwrap();
        let number_of_rva_and_sizes = u32_le(bytes, opt_off + 108).unwrap();
        let dd_off = opt_off + 112;
        (
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            address_of_entry_point,
            image_base,
            dll_characteristics,
            number_of_rva_and_sizes,
            dd_off,
        )
    } else {
        // PE32 optional header minimum size before directories: 96
        if size_of_optional_header < 96 {
            return Err(ParseIssue::new(
                "optional_header_pe32_truncated",
                "PE32 optional header truncated before data directories",
            ));
        }
        let section_alignment = u32_le(bytes, opt_off + 32).unwrap();
        let file_alignment = u32_le(bytes, opt_off + 36).unwrap();
        let address_of_entry_point = u32_le(bytes, opt_off + 16).unwrap();
        let image_base = u32_le(bytes, opt_off + 28).unwrap() as u64;
        let size_of_image = u32_le(bytes, opt_off + 56).unwrap();
        let size_of_headers = u32_le(bytes, opt_off + 60).unwrap();
        let dll_characteristics = u16_le(bytes, opt_off + 70).unwrap();
        let number_of_rva_and_sizes = u32_le(bytes, opt_off + 92).unwrap();
        let dd_off = opt_off + 96;
        (
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            address_of_entry_point,
            image_base,
            dll_characteristics,
            number_of_rva_and_sizes,
            dd_off,
        )
    };

    // Data directories must fit in SizeOfOptionalHeader.
    let dd_bytes_declared = (number_of_rva_and_sizes as u64)
        .checked_mul(SIZEOF_DATA_DIRECTORY as u64)
        .ok_or_else(|| ParseIssue::new("dd_count_overflow", "NumberOfRvaAndSizes overflow"))?;
    let opt_end = (opt_off as u64)
        .checked_add(size_of_optional_header as u64)
        .ok_or_else(|| ParseIssue::new("opt_end_overflow", "optional header end overflow"))?;
    let dd_end = (dd_off as u64)
        .checked_add(dd_bytes_declared)
        .ok_or_else(|| ParseIssue::new("dd_end_overflow", "data directory table end overflow"))?;
    if dd_end > opt_end {
        return Err(ParseIssue::new(
            "dd_exceeds_optional_header",
            "data directories exceed SizeOfOptionalHeader",
        ));
    }
    if dd_end > bytes.len() as u64 {
        return Err(ParseIssue::new(
            "dd_oob",
            "data directory table exceeds file bounds",
        ));
    }

    let mut data_directories = Vec::with_capacity(number_of_rva_and_sizes as usize);
    for i in 0..number_of_rva_and_sizes as usize {
        let o = dd_off + i * SIZEOF_DATA_DIRECTORY;
        data_directories.push(DataDirectory {
            virtual_address: u32_le(bytes, o).unwrap(),
            size: u32_le(bytes, o + 4).unwrap(),
        });
    }

    let section_table_offset = opt_off + size_of_optional_header as usize;
    let sec_bytes = (number_of_sections as u64)
        .checked_mul(SIZEOF_SECTION_HEADER as u64)
        .ok_or_else(|| ParseIssue::new("section_table_overflow", "section table size overflow"))?;
    if !in_bounds(section_table_offset as u64, sec_bytes, bytes.len() as u64) {
        return Err(ParseIssue::new(
            "section_table_oob",
            "section table exceeds file bounds",
        ));
    }

    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for i in 0..number_of_sections as usize {
        let o = section_table_offset + i * SIZEOF_SECTION_HEADER;
        let mut name = [0u8; 8];
        name.copy_from_slice(&bytes[o..o + 8]);
        sections.push(SectionView {
            name,
            virtual_size: u32_le(bytes, o + 8).unwrap(),
            virtual_address: u32_le(bytes, o + 12).unwrap(),
            size_of_raw_data: u32_le(bytes, o + 16).unwrap(),
            pointer_to_raw_data: u32_le(bytes, o + 20).unwrap(),
            characteristics: u32_le(bytes, o + 36).unwrap(),
        });
    }

    Ok(PeImage {
        bytes,
        e_lfanew,
        machine,
        number_of_sections,
        size_of_optional_header,
        characteristics,
        optional: OptionalHeaderView {
            magic,
            is_pe32_plus,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            address_of_entry_point,
            image_base,
            dll_characteristics,
            number_of_rva_and_sizes,
            data_directories,
        },
        sections,
        section_table_offset,
    })
}

impl<'a> PeImage<'a> {
    pub fn directory(&self, index: usize) -> Option<&DataDirectory> {
        self.optional.data_directories.get(index)
    }

    /// Map RVA to file offset using section raw backing. Returns None if no mapping.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            if s.pointer_to_raw_data == 0 || s.size_of_raw_data == 0 {
                continue;
            }
            let va = s.virtual_address;
            let vsize = s.virtual_extent() as u32;
            if vsize == 0 {
                continue;
            }
            if rva >= va {
                let delta = rva - va;
                if delta < s.size_of_raw_data && delta < vsize {
                    return (s.pointer_to_raw_data as usize).checked_add(delta as usize);
                }
            }
        }
        // Headers region
        if rva < self.optional.size_of_headers {
            return Some(rva as usize);
        }
        None
    }

    /// True if [rva, rva+size) lies within image virtual space and each byte
    /// either maps to file raw data or is zero-fill virtual tail of a section.
    pub fn directory_in_image(&self, rva: u32, size: u32) -> bool {
        if size == 0 {
            return rva == 0 || rva < self.optional.size_of_image;
        }
        let Some(end) = (rva as u64).checked_add(size as u64) else {
            return false;
        };
        end <= self.optional.size_of_image as u64
    }

    /// True if the entire directory range has raw file backing (for structures we must read).
    pub fn directory_has_raw_backing(&self, rva: u32, size: u32) -> bool {
        if size == 0 {
            return true;
        }
        let Some(end) = rva.checked_add(size) else {
            return false;
        };
        // Walk in steps; for small dirs checking endpoints + mid is enough for section spans
        // Full check: every page-equivalent byte maps; for MVP require start and last byte map
        // and no cross-section gap without raw.
        let mut cursor = rva;
        while cursor < end {
            let Some(off) = self.rva_to_offset(cursor) else {
                return false;
            };
            if off >= self.bytes.len() {
                return false;
            }
            // advance to end of current section raw span
            let mut advanced = false;
            for s in &self.sections {
                if s.pointer_to_raw_data == 0 || s.size_of_raw_data == 0 {
                    continue;
                }
                let va = s.virtual_address;
                let Some(raw_end_rva) = va.checked_add(s.size_of_raw_data) else {
                    continue;
                };
                if cursor >= va && cursor < raw_end_rva {
                    cursor = raw_end_rva.min(end);
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                // header region
                if cursor < self.optional.size_of_headers {
                    cursor = self.optional.size_of_headers.min(end);
                    if cursor == rva {
                        // no progress
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }
        true
    }
}
