//! PE header parsing — corresponds to `PEInfo.pas` `TPEHeader`.
//!
//! Provides [`PeHeader`] which parses a PE file (32-bit or 64-bit) and
//! exposes the DOS header, NT headers, and section table in a unified form.
//! RVA ↔ file-offset translation is provided through the section table,
//! matching the Pascal `ConvertOffsetToRVAVector` / `GetSectionByVA` logic.

use crate::error::PeError;
use crate::utils::align_up;
use std::path::Path;

// ---------------------------------------------------------------------------
// Raw PE structures — our own types (no pelite exposure in the public API)
// ---------------------------------------------------------------------------

/// IMAGE_DOS_HEADER — only the fields we actually need.
#[derive(Debug, Clone, Copy)]
pub struct ImageDosHeader {
    /// Magic number — must be `0x5A4D` ("MZ").
    pub e_magic: u16,
    /// File offset of the NT header (`PE\0\0`).
    pub e_lfanew: u32,
}

/// IMAGE_FILE_HEADER — the COFF header embedded in the NT headers.
#[derive(Debug, Clone, Copy)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// IMAGE_DATA_DIRECTORY entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// IMAGE_OPTIONAL_HEADER — unified for PE32 and PE32+.
///
/// For 32-bit PE files (`magic == 0x10B`), `image_base` is the 32-bit value
/// zero-extended to 64 bits and fields like `base_of_data` hold meaningful
/// values.
#[derive(Debug, Clone)]
pub struct ImageOptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    /// PE32 only — `None` for PE32+.
    pub base_of_data: Option<u32>,
    /// Always stored as 64-bit (zero-extended for PE32).
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

/// IMAGE_NT_HEADERS — signature + file header + optional header.
///
/// This is a unified type. For 32-bit PE files the optional header is
/// stored in its 64-bit-compatible form.
#[derive(Debug, Clone)]
pub struct ImageNtHeaders {
    /// PE signature (`0x00004550` = "PE\0\0").
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader,
}

/// IMAGE_SECTION_HEADER — raw 40-byte section header.
#[derive(Debug, Clone, Copy)]
pub struct ImageSectionHeader {
    /// 8-byte UTF-8 name (may not be null-terminated).
    pub name: [u8; 8],
    /// `Misc.VirtualSize` — size of the section when loaded in memory.
    pub virtual_size: u32,
    /// RVA of the section.
    pub virtual_address: u32,
    /// Size of raw data on disk (must be a multiple of `FileAlignment`).
    pub size_of_raw_data: u32,
    /// File offset of the section's raw data.
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

// ---------------------------------------------------------------------------
// High-level PE types
// ---------------------------------------------------------------------------

/// Parsed PE section combining the raw header with convenience accessors.
///
/// Corresponds to `TPESection` in `PEInfo.pas`.
#[derive(Debug, Clone)]
pub struct PeSection {
    /// The raw `IMAGE_SECTION_HEADER`.
    pub header: ImageSectionHeader,
    /// Decoded section name (8-byte field, trimmed).
    pub name: String,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Virtual size (`Misc.VirtualSize`).
    pub virtual_size: u32,
    /// Raw file offset (`PointerToRawData`).
    pub raw_offset: u32,
    /// Raw data size on disk (`SizeOfRawData`).
    pub raw_size: u32,
    /// Section characteristics (memory protection, etc.).
    pub characteristics: u32,
    /// Optional binary data attached at dump time (e.g. for `.import`).
    /// Not serialised in `serialize_headers`; the dumper handles it.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub extra_data: Option<Vec<u8>>,
}

// impl Default is hand-written to avoid the `#[derive(Default)]` clobber
// of custom initialisation —`.
impl Default for PeSection {
    fn default() -> Self {
        Self {
            header: ImageSectionHeader {
                name: [0u8; 8],
                virtual_size: 0,
                virtual_address: 0,
                size_of_raw_data: 0,
                pointer_to_raw_data: 0,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: 0,
            },
            name: String::new(),
            virtual_address: 0,
            virtual_size: 0,
            raw_offset: 0,
            raw_size: 0,
            characteristics: 0,
            extra_data: None,
        }
    }
}

/// Parsed PE header — the central type of this crate.
///
/// Corresponds to `TPEHeader` in `PEInfo.pas`. Supports both 32-bit and
/// 64-bit PE files. Provides RVA ↔ file-offset translation through the
/// section table and helpers for section manipulation.
#[derive(Debug, Clone)]
pub struct PeHeader {
    /// DOS header.
    pub dos_header: ImageDosHeader,
    /// NT headers (signature + COFF + optional).
    pub nt_headers: ImageNtHeaders,
    /// Parsed section table.
    pub sections: Vec<PeSection>,
    /// Preferred load address (from optional header).
    pub image_base: u64,
    /// Address of entry point (RVA).
    pub entry_point: u32,
    /// `true` for PE32+ (`magic == 0x20B`), `false` for PE32 (`0x10B`).
    pub is_64bit: bool,
    /// File alignment from the optional header.
    pub file_alignment: u32,
    /// Section alignment from the optional header.
    pub section_alignment: u32,
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// PE32 optional header magic.
const PE32_MAGIC: u16 = 0x010B;
/// PE32+ optional header magic.
const PE32_PLUS_MAGIC: u16 = 0x020B;
/// DOS magic "MZ".
const DOS_MAGIC: u16 = 0x5A4D;
/// PE signature "PE\0\0".
const PE_SIGNATURE: u32 = 0x00004550;
/// Size of `IMAGE_DOS_HEADER` in bytes.
const DOS_HEADER_SIZE: usize = 64;
/// Size of the COFF file header.
const FILE_HEADER_SIZE: usize = 20;
/// Size of the PE signature.
const SIGNATURE_SIZE: usize = 4;
/// Maximum sensible section count (sanity check).
const MAX_SECTION_COUNT: u32 = 256;

impl PeHeader {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Parse PE headers from a file on disk.
    ///
    /// Corresponds to `TPEHeader.Create` called with data read from disk.
    ///
    /// # Errors
    ///
    /// Returns [`PeError::Io`] if the file cannot be read, or
    /// [`PeError::BufferTooSmall`] / [`PeError::InvalidDosSignature`]
    /// if the content is not a valid PE.
    pub fn from_file(path: &Path) -> Result<Self, PeError> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Parse PE headers from an in-memory byte slice.
    ///
    /// The buffer only needs to be large enough to cover the headers and
    /// the section table — the section *data* is not required.
    ///
    /// Corresponds to `TPEHeader.Create(Data: PByte)`.
    ///
    /// # Errors
    ///
    /// Returns [`PeError::BufferTooSmall`] if the data is not large enough,
    /// [`PeError::InvalidDosSignature`] if the DOS magic is missing, or
    /// [`PeError::InvalidPeSignature`] if the PE signature is missing.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PeError> {
        // 1. Parse DOS header
        if data.len() < DOS_HEADER_SIZE {
            return Err(PeError::BufferTooSmall(DOS_HEADER_SIZE, data.len()));
        }
        let e_magic = u16::from_le_bytes([data[0], data[1]]);
        if e_magic != DOS_MAGIC {
            return Err(PeError::InvalidDosSignature);
        }
        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
        let dos_header = ImageDosHeader { e_magic, e_lfanew };

        // 2. Jump to NT headers
        let nt_offset = e_lfanew as usize;
        let min_nt_size = SIGNATURE_SIZE + FILE_HEADER_SIZE;
        if data.len() < nt_offset + min_nt_size {
            return Err(PeError::BufferTooSmall(nt_offset + min_nt_size, data.len()));
        }

        let nt_slice = &data[nt_offset..];

        // 3. Signature
        let sig_bytes = &nt_slice[0..4];
        let signature =
            u32::from_le_bytes([sig_bytes[0], sig_bytes[1], sig_bytes[2], sig_bytes[3]]);
        if signature != PE_SIGNATURE {
            return Err(PeError::InvalidPeSignature);
        }

        // 4. COFF file header (20 bytes starting at offset 4 from NT base)
        let fh = parse_file_header(&nt_slice[SIGNATURE_SIZE..]);

        // 5. Optional header — size comes from the file header
        let opt_size = fh.size_of_optional_header as usize;
        let oh_start = SIGNATURE_SIZE + FILE_HEADER_SIZE;
        if nt_slice.len() < oh_start + opt_size {
            return Err(PeError::BufferTooSmall(
                nt_offset + oh_start + opt_size,
                data.len(),
            ));
        }
        let oh_slice = &nt_slice[oh_start..oh_start + opt_size];
        if oh_slice.len() < 2 {
            return Err(PeError::BufferTooSmall(2, oh_slice.len()));
        }
        let magic = u16::from_le_bytes([oh_slice[0], oh_slice[1]]);

        let is_64bit = magic == PE32_PLUS_MAGIC;

        let optional_header = if is_64bit {
            parse_optional_header_64(oh_slice, magic)?
        } else if magic == PE32_MAGIC {
            parse_optional_header_32(oh_slice, magic)?
        } else {
            return Err(PeError::UnknownMagic(magic));
        };

        // Extra convenience fields
        let image_base = optional_header.image_base;
        let entry_point = optional_header.address_of_entry_point;
        let file_alignment = optional_header.file_alignment;
        let section_alignment = optional_header.section_alignment;

        // 6. Section headers — immediately after optional header
        let sh_start = oh_start + opt_size;
        let section_count = fh.number_of_sections as u32;
        if section_count > MAX_SECTION_COUNT {
            return Err(PeError::InvalidSectionCount(section_count));
        }
        let sh_total = section_count as usize * 40; // each IMAGE_SECTION_HEADER = 40 bytes
        if nt_slice.len() < sh_start + sh_total {
            return Err(PeError::BufferTooSmall(
                nt_offset + sh_start + sh_total,
                data.len(),
            ));
        }

        let mut sections = Vec::with_capacity(section_count as usize);
        for i in 0..section_count as usize {
            let sh = parse_section_header(&nt_slice[sh_start + i * 40..sh_start + (i + 1) * 40]);
            let name = decode_section_name(&sh.name);
            sections.push(PeSection {
                header: sh,
                name,
                virtual_address: sh.virtual_address,
                virtual_size: sh.virtual_size,
                raw_offset: sh.pointer_to_raw_data,
                raw_size: sh.size_of_raw_data,
                characteristics: sh.characteristics,
                extra_data: None,
            });
        }

        Ok(PeHeader {
            dos_header,
            nt_headers: ImageNtHeaders {
                signature,
                file_header: fh,
                optional_header,
            },
            sections,
            image_base,
            entry_point,
            is_64bit,
            file_alignment,
            section_alignment,
        })
    }

    // ------------------------------------------------------------------
    // Section lookup
    // ------------------------------------------------------------------

    /// Find the section that contains `rva`.
    ///
    /// Corresponds to `TPEHeader.GetSectionByVA(V: Cardinal)` in `PEInfo.pas`.
    ///
    /// Iterates sections in order and returns the first one where
    /// `VirtualAddress + VirtualSize > rva`.  Note that an RVA below the
    /// first section's `VirtualAddress` will still match the first section
    /// (matching the Pascal behavior).
    ///
    /// Returns `None` if the section table is empty or `rva` is past the
    /// last section.
    #[must_use]
    pub fn get_section_by_rva(&self, rva: u32) -> Option<&PeSection> {
        self.sections.iter().find(|s| {
            s.virtual_address
                .checked_add(s.virtual_size)
                .is_some_and(|end| end > rva)
        })
    }

    // ------------------------------------------------------------------
    // RVA ↔ File offset conversion
    // ------------------------------------------------------------------

    /// Convert a file offset to an RVA (relative virtual address).
    ///
    /// Corresponds to `TPEHeader.ConvertOffsetToRVAVector` in `PEInfo.pas`.
    ///
    /// Walks the section table and returns the RVA corresponding to `offset`
    /// by looking for a section whose raw data range contains it.
    ///
    /// Uses checked arithmetic so hostile `raw_offset + raw_size` values do not
    /// wrap and spuriously match.
    #[must_use]
    pub fn offset_to_rva(&self, offset: u32) -> Option<u32> {
        for section in &self.sections {
            let Some(raw_end) = section.raw_offset.checked_add(section.raw_size) else {
                continue;
            };
            if section.raw_offset <= offset && raw_end > offset {
                let delta = offset - section.raw_offset;
                return section.virtual_address.checked_add(delta);
            }
        }
        None
    }

    /// Convert an RVA to a file offset.
    ///
    /// This is the inverse of [`offset_to_rva`] — looks up the section that contains
    /// `rva` and computes `rva - VirtualAddress + PointerToRawData`.
    ///
    /// Uses checked arithmetic so hostile virtual ranges do not wrap.
    #[must_use]
    pub fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        for section in &self.sections {
            let Some(virt_end) = section.virtual_address.checked_add(section.virtual_size) else {
                continue;
            };
            if section.virtual_address <= rva && virt_end > rva {
                let delta = rva - section.virtual_address;
                return section.raw_offset.checked_add(delta);
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Alignment helpers
    // ------------------------------------------------------------------

    /// Align `v` upward to `FileAlignment`.  Corresponds to `TPEHeader.FileAlign`.
    #[inline]
    pub fn file_align(&self, v: &mut u32) {
        *v = align_up(*v, self.nt_headers.optional_header.file_alignment);
    }

    /// Align `v` upward to `SectionAlignment`.  Corresponds to `TPEHeader.SectionAlign`.
    #[inline]
    pub fn section_align(&self, v: &mut u32) {
        *v = align_up(*v, self.nt_headers.optional_header.section_alignment);
    }

    /// Size-of-image convenience accessor.
    #[inline]
    #[must_use]
    pub fn size_of_image(&self) -> u32 {
        self.nt_headers.optional_header.size_of_image
    }

    // ------------------------------------------------------------------
    // Serialize (pure buffer emit)
    // ------------------------------------------------------------------

    /// Serialise the NT headers and section table to a byte vector.
    ///
    /// Corresponds to `TPEHeader.SaveToStream` in `PEInfo.pas`. Output is the
    /// PE signature + COFF + optional header + section table, followed by
    /// `0x200` zero padding (legacy dump layout). Callers that rebuild a full
    /// image splice this block at `e_lfanew`.
    ///
    /// Pure: buffer math only; no Win32 / process I/O.
    pub fn serialize_headers(&self) -> Result<Vec<u8>, PeError> {
        // Calculate total size: NT headers + section table + 0x200 padding zeros
        let nt_size: usize = if self.is_64bit {
            4 + 20 + 112 + 16 * 8 // sig + file + optional64 + data_dirs
        } else {
            4 + 20 + 96 + 16 * 8 // sig + file + optional32 + data_dirs
        };
        let section_table_size = self
            .sections
            .len()
            .checked_mul(40)
            .ok_or_else(|| PeError::Parse("section table size overflow".into()))?;
        let total = nt_size
            .checked_add(section_table_size)
            .and_then(|n| n.checked_add(0x200))
            .ok_or_else(|| PeError::Parse("serialize_headers size overflow".into()))?;
        let mut out = vec![0u8; total];

        // Write NT signature
        out[0..4].copy_from_slice(&self.nt_headers.signature.to_le_bytes());

        // Write file header (section count mirrors the live table)
        let fh = &self.nt_headers.file_header;
        let section_count = u16::try_from(self.sections.len())
            .map_err(|_| PeError::InvalidSectionCount(self.sections.len() as u32))?;
        out[4..6].copy_from_slice(&fh.machine.to_le_bytes());
        out[6..8].copy_from_slice(&section_count.to_le_bytes());
        out[8..12].copy_from_slice(&fh.time_date_stamp.to_le_bytes());
        // +12: PointerToSymbolTable (u32) — 0
        // +16: NumberOfSymbols (u32) — 0
        out[20..22].copy_from_slice(&fh.size_of_optional_header.to_le_bytes());
        out[22..24].copy_from_slice(&fh.characteristics.to_le_bytes());

        // Write optional header
        let oh = &self.nt_headers.optional_header;
        out[24..26].copy_from_slice(&oh.magic.to_le_bytes());
        out[26] = oh.major_linker_version;
        out[27] = oh.minor_linker_version;
        out[28..32].copy_from_slice(&oh.size_of_code.to_le_bytes());
        out[32..36].copy_from_slice(&oh.size_of_initialized_data.to_le_bytes());
        out[36..40].copy_from_slice(&oh.size_of_uninitialized_data.to_le_bytes());
        out[40..44].copy_from_slice(&oh.address_of_entry_point.to_le_bytes());
        out[44..48].copy_from_slice(&oh.base_of_code.to_le_bytes());

        if self.is_64bit {
            out[48..56].copy_from_slice(&oh.image_base.to_le_bytes());
            out[56..60].copy_from_slice(&oh.section_alignment.to_le_bytes());
            out[60..64].copy_from_slice(&oh.file_alignment.to_le_bytes());
            out[64..66].copy_from_slice(&oh.major_operating_system_version.to_le_bytes());
            out[66..68].copy_from_slice(&oh.minor_operating_system_version.to_le_bytes());
            out[68..70].copy_from_slice(&oh.major_image_version.to_le_bytes());
            out[70..72].copy_from_slice(&oh.minor_image_version.to_le_bytes());
            out[72..74].copy_from_slice(&oh.major_subsystem_version.to_le_bytes());
            out[74..76].copy_from_slice(&oh.minor_subsystem_version.to_le_bytes());
            out[76..80].copy_from_slice(&oh.win32_version_value.to_le_bytes());
            out[80..84].copy_from_slice(&oh.size_of_image.to_le_bytes());
            out[84..88].copy_from_slice(&oh.size_of_headers.to_le_bytes());
            out[88..92].copy_from_slice(&oh.check_sum.to_le_bytes());
            out[92..94].copy_from_slice(&oh.subsystem.to_le_bytes());
            out[94..96].copy_from_slice(&oh.dll_characteristics.to_le_bytes());
            out[96..104].copy_from_slice(&oh.size_of_stack_reserve.to_le_bytes());
            out[104..112].copy_from_slice(&oh.size_of_stack_commit.to_le_bytes());
            out[112..120].copy_from_slice(&oh.size_of_heap_reserve.to_le_bytes());
            out[120..128].copy_from_slice(&oh.size_of_heap_commit.to_le_bytes());
            out[128..132].copy_from_slice(&oh.loader_flags.to_le_bytes());
            out[132..136].copy_from_slice(&oh.number_of_rva_and_sizes.to_le_bytes());

            let dd_off = 136;
            for (i, dd) in oh.data_directory.iter().enumerate() {
                let off = dd_off + i * 8;
                out[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
                out[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
            }

            let sh_off = 24 + 112 + 16 * 8; // 264
            write_section_headers(&mut out, sh_off, &self.sections);
        } else {
            out[48..52].copy_from_slice(&oh.base_of_data.unwrap_or(0).to_le_bytes());
            out[52..56].copy_from_slice(&(oh.image_base as u32).to_le_bytes());
            out[56..60].copy_from_slice(&oh.section_alignment.to_le_bytes());
            out[60..64].copy_from_slice(&oh.file_alignment.to_le_bytes());
            out[64..66].copy_from_slice(&oh.major_operating_system_version.to_le_bytes());
            out[66..68].copy_from_slice(&oh.minor_operating_system_version.to_le_bytes());
            out[68..70].copy_from_slice(&oh.major_image_version.to_le_bytes());
            out[70..72].copy_from_slice(&oh.minor_image_version.to_le_bytes());
            out[72..74].copy_from_slice(&oh.major_subsystem_version.to_le_bytes());
            out[74..76].copy_from_slice(&oh.minor_subsystem_version.to_le_bytes());
            out[76..80].copy_from_slice(&oh.win32_version_value.to_le_bytes());
            out[80..84].copy_from_slice(&oh.size_of_image.to_le_bytes());
            out[84..88].copy_from_slice(&oh.size_of_headers.to_le_bytes());
            out[88..92].copy_from_slice(&oh.check_sum.to_le_bytes());
            out[92..94].copy_from_slice(&oh.subsystem.to_le_bytes());
            out[94..96].copy_from_slice(&oh.dll_characteristics.to_le_bytes());
            out[96..100].copy_from_slice(&(oh.size_of_stack_reserve as u32).to_le_bytes());
            out[100..104].copy_from_slice(&(oh.size_of_stack_commit as u32).to_le_bytes());
            out[104..108].copy_from_slice(&(oh.size_of_heap_reserve as u32).to_le_bytes());
            out[108..112].copy_from_slice(&(oh.size_of_heap_commit as u32).to_le_bytes());
            out[112..116].copy_from_slice(&oh.loader_flags.to_le_bytes());
            out[116..120].copy_from_slice(&oh.number_of_rva_and_sizes.to_le_bytes());

            let dd_off = 120;
            for (i, dd) in oh.data_directory.iter().enumerate() {
                let off = dd_off + i * 8;
                out[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
                out[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
            }

            let sh_off = 24 + 96 + 16 * 8; // 248
            write_section_headers(&mut out, sh_off, &self.sections);
        }

        Ok(out)
    }
}

fn write_section_headers(out: &mut [u8], sh_off: usize, sections: &[PeSection]) {
    for (i, section) in sections.iter().enumerate() {
        let off = sh_off + i * 40;
        out[off..off + 8].copy_from_slice(&section.header.name);
        out[off + 8..off + 12].copy_from_slice(&section.header.virtual_size.to_le_bytes());
        out[off + 12..off + 16].copy_from_slice(&section.header.virtual_address.to_le_bytes());
        out[off + 16..off + 20].copy_from_slice(&section.header.size_of_raw_data.to_le_bytes());
        out[off + 20..off + 24].copy_from_slice(&section.header.pointer_to_raw_data.to_le_bytes());
        out[off + 24..off + 28]
            .copy_from_slice(&section.header.pointer_to_relocations.to_le_bytes());
        out[off + 28..off + 32]
            .copy_from_slice(&section.header.pointer_to_linenumbers.to_le_bytes());
        out[off + 32..off + 34]
            .copy_from_slice(&section.header.number_of_relocations.to_le_bytes());
        out[off + 34..off + 36]
            .copy_from_slice(&section.header.number_of_linenumbers.to_le_bytes());
        out[off + 36..off + 40].copy_from_slice(&section.header.characteristics.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Low-level parsing functions (private)
// ---------------------------------------------------------------------------

/// Parse the COFF file header from a 20-byte slice at its start.
fn parse_file_header(slice: &[u8]) -> ImageFileHeader {
    ImageFileHeader {
        machine: read_u16_le(slice, 0),
        number_of_sections: read_u16_le(slice, 2),
        time_date_stamp: read_u32_le(slice, 4),
        size_of_optional_header: read_u16_le(slice, 16),
        characteristics: read_u16_le(slice, 18),
    }
}

/// Parse a PE32 (`magic == 0x10B`) optional header.
fn parse_optional_header_32(data: &[u8], magic: u16) -> Result<ImageOptionalHeader, PeError> {
    if data.len() < 96 {
        return Err(PeError::BufferTooSmall(96, data.len()));
    }
    let image_base = u64::from(read_u32_le(data, 28));

    Ok(ImageOptionalHeader {
        magic,
        major_linker_version: data[2],
        minor_linker_version: data[3],
        size_of_code: read_u32_le(data, 4),
        size_of_initialized_data: read_u32_le(data, 8),
        size_of_uninitialized_data: read_u32_le(data, 12),
        address_of_entry_point: read_u32_le(data, 16),
        base_of_code: read_u32_le(data, 20),
        base_of_data: Some(read_u32_le(data, 24)),
        image_base,
        section_alignment: read_u32_le(data, 32),
        file_alignment: read_u32_le(data, 36),
        major_operating_system_version: read_u16_le(data, 40),
        minor_operating_system_version: read_u16_le(data, 42),
        major_image_version: read_u16_le(data, 44),
        minor_image_version: read_u16_le(data, 46),
        major_subsystem_version: read_u16_le(data, 48),
        minor_subsystem_version: read_u16_le(data, 50),
        win32_version_value: read_u32_le(data, 52),
        size_of_image: read_u32_le(data, 56),
        size_of_headers: read_u32_le(data, 60),
        check_sum: read_u32_le(data, 64),
        subsystem: read_u16_le(data, 68),
        dll_characteristics: read_u16_le(data, 70),
        size_of_stack_reserve: u64::from(read_u32_le(data, 72)),
        size_of_stack_commit: u64::from(read_u32_le(data, 76)),
        size_of_heap_reserve: u64::from(read_u32_le(data, 80)),
        size_of_heap_commit: u64::from(read_u32_le(data, 84)),
        loader_flags: read_u32_le(data, 88),
        number_of_rva_and_sizes: read_u32_le(data, 92),
        data_directory: parse_data_directories(data, 96),
    })
}

/// Parse a PE32+ (`magic == 0x20B`) optional header.
fn parse_optional_header_64(data: &[u8], magic: u16) -> Result<ImageOptionalHeader, PeError> {
    if data.len() < 112 {
        return Err(PeError::BufferTooSmall(112, data.len()));
    }

    Ok(ImageOptionalHeader {
        magic,
        major_linker_version: data[2],
        minor_linker_version: data[3],
        size_of_code: read_u32_le(data, 4),
        size_of_initialized_data: read_u32_le(data, 8),
        size_of_uninitialized_data: read_u32_le(data, 12),
        address_of_entry_point: read_u32_le(data, 16),
        base_of_code: read_u32_le(data, 20),
        base_of_data: None,
        image_base: read_u64_le(data, 24),
        section_alignment: read_u32_le(data, 32),
        file_alignment: read_u32_le(data, 36),
        major_operating_system_version: read_u16_le(data, 40),
        minor_operating_system_version: read_u16_le(data, 42),
        major_image_version: read_u16_le(data, 44),
        minor_image_version: read_u16_le(data, 46),
        major_subsystem_version: read_u16_le(data, 48),
        minor_subsystem_version: read_u16_le(data, 50),
        win32_version_value: read_u32_le(data, 52),
        size_of_image: read_u32_le(data, 56),
        size_of_headers: read_u32_le(data, 60),
        check_sum: read_u32_le(data, 64),
        subsystem: read_u16_le(data, 68),
        dll_characteristics: read_u16_le(data, 70),
        size_of_stack_reserve: read_u64_le(data, 72),
        size_of_stack_commit: read_u64_le(data, 80),
        size_of_heap_reserve: read_u64_le(data, 88),
        size_of_heap_commit: read_u64_le(data, 96),
        loader_flags: read_u32_le(data, 104),
        number_of_rva_and_sizes: read_u32_le(data, 108),
        data_directory: parse_data_directories(data, 112),
    })
}

/// Parse the 16 data directories (8 bytes each).
fn parse_data_directories(data: &[u8], start: usize) -> [ImageDataDirectory; 16] {
    let mut dirs = [ImageDataDirectory::default(); 16];
    for (i, entry) in dirs.iter_mut().enumerate() {
        let off = start + i * 8;
        if off + 8 > data.len() {
            break;
        }
        entry.virtual_address = read_u32_le(data, off);
        entry.size = read_u32_le(data, off + 4);
    }
    dirs
}

/// Parse a 40-byte `IMAGE_SECTION_HEADER`.
fn parse_section_header(slice: &[u8]) -> ImageSectionHeader {
    let mut name = [0u8; 8];
    name.copy_from_slice(&slice[0..8]);

    ImageSectionHeader {
        name,
        virtual_size: read_u32_le(slice, 8),
        virtual_address: read_u32_le(slice, 12),
        size_of_raw_data: read_u32_le(slice, 16),
        pointer_to_raw_data: read_u32_le(slice, 20),
        pointer_to_relocations: read_u32_le(slice, 24),
        pointer_to_linenumbers: read_u32_le(slice, 28),
        number_of_relocations: read_u16_le(slice, 32),
        number_of_linenumbers: read_u16_le(slice, 34),
        characteristics: read_u32_le(slice, 36),
    }
}

/// Decode an 8-byte section name into a Rust `String`.
///
/// Section names are 8-byte ASCII that may not be null-terminated.
/// We take bytes up to the first null, or all 8 if no null.
pub fn decode_section_name(name: &[u8; 8]) -> String {
    let len = name.iter().position(|&b| b == 0).unwrap_or(8);
    // Use a lossy conversion — non-ASCII names are uncommon but not fatal.
    String::from_utf8_lossy(&name[..len]).into_owned()
}

// ---------------------------------------------------------------------------
// Little-endian read helpers
// ---------------------------------------------------------------------------

#[inline]
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

#[inline]
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[inline]
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a minimal PE32+ header in memory for round-trip testing.
#[cfg(test)]
pub(crate) fn make_minimal_pe64() -> Vec<u8> {
    let mut buf = vec![0u8; 512];

    // DOS header
    buf[0] = 0x4D; // 'M'
    buf[1] = 0x5A; // 'Z'
                   // e_lfanew at offset 60 → point to 0x40 (64)
    buf[60] = 0x40;
    buf[61] = 0x00;
    buf[62] = 0x00;
    buf[63] = 0x00;

    let nt_base = 0x40;

    // PE signature "PE\0\0"
    buf[nt_base] = 0x50;
    buf[nt_base + 1] = 0x45;
    buf[nt_base + 2] = 0x00;
    buf[nt_base + 3] = 0x00;

    // COFF file header (20 bytes starting at nt_base + 4)
    let fh = nt_base + 4;
    // Machine = AMD64 (0x8664)
    buf[fh] = 0x64;
    buf[fh + 1] = 0x86;
    // NumberOfSections = 1
    buf[fh + 2] = 1;
    buf[fh + 3] = 0;
    // SizeOfOptionalHeader = 0xF0 (240, PE32+ standard)
    buf[fh + 16] = 0xF0;
    buf[fh + 17] = 0x00;
    // Characteristics
    buf[fh + 18] = 0x22;
    buf[fh + 19] = 0x00;

    // Optional header (PE32+, starts at nt_base + 24)
    let oh = nt_base + 24;
    // Magic = 0x20B (PE32+)
    buf[oh] = 0x0B;
    buf[oh + 1] = 0x02;
    // AddressOfEntryPoint = 0x1000
    buf[oh + 16] = 0x00;
    buf[oh + 17] = 0x10;
    // ImageBase = 0x140000000
    buf[oh + 24] = 0x00;
    buf[oh + 25] = 0x00;
    buf[oh + 26] = 0x00;
    buf[oh + 27] = 0x40;
    buf[oh + 28] = 0x01;
    // SectionAlignment = 0x1000
    buf[oh + 32] = 0x00;
    buf[oh + 33] = 0x10;
    // FileAlignment = 0x200
    buf[oh + 36] = 0x00;
    buf[oh + 37] = 0x02;
    // SizeOfImage = 0x2000
    buf[oh + 56] = 0x00;
    buf[oh + 57] = 0x20;
    // SizeOfHeaders = 0x200
    buf[oh + 60] = 0x00;
    buf[oh + 61] = 0x02;
    // DLL characteristics
    buf[oh + 70] = 0x00;
    buf[oh + 71] = 0x00;
    // NumberOfRvaAndSizes = 16
    buf[oh + 108] = 0x10;
    buf[oh + 109] = 0x00;
    buf[oh + 110] = 0x00;
    buf[oh + 111] = 0x00;

    // Section header (starts at nt_base + 24 + 240 = nt_base + 264)
    let sh = nt_base + 24 + 240;
    // Name = ".text\0\0\0"
    buf[sh] = b'.';
    buf[sh + 1] = b't';
    buf[sh + 2] = b'e';
    buf[sh + 3] = b'x';
    buf[sh + 4] = b't';
    // VirtualSize = 0x1000
    buf[sh + 8] = 0x00;
    buf[sh + 9] = 0x10;
    // VirtualAddress = 0x1000
    buf[sh + 12] = 0x00;
    buf[sh + 13] = 0x10;
    // SizeOfRawData = 0x200
    buf[sh + 16] = 0x00;
    buf[sh + 17] = 0x02;
    // PointerToRawData = 0x200
    buf[sh + 20] = 0x00;
    buf[sh + 21] = 0x02;
    // Characteristics = READ | EXECUTE | CODE
    buf[sh + 36] = 0x20;
    buf[sh + 37] = 0x00;
    buf[sh + 38] = 0x00;
    buf[sh + 39] = 0x60;

    buf.truncate(512);
    buf
}

#[cfg(test)]
mod tests;
