//! PE header serialisation helper.
//!
//! Extracted from `dumper.rs` — corresponds to `TPEHeader.SaveToStream`
//! in `PEInfo.pas`.

use tracing::debug;

use crate::error::PeError;
use crate::header::PeHeader;

impl PeHeader {
    /// Serialise the NT headers and section table to a byte vector for
    /// writing to the output file.
    ///
    /// Corresponds to `TPEHeader.SaveToStream` in `PEInfo.pas`.
    pub(crate) fn serialize_headers(&self) -> Result<Vec<u8>, PeError> {
        // Calculate total size: NT headers + section table + 0x200 padding zeros
        let nt_size = if self.is_64bit {
            4 + 20 + 112 + 16 * 8 // sig + file + optional64 + data_dirs
        } else {
            4 + 20 + 96 + 16 * 8 // sig + file + optional32 + data_dirs
        };
        let section_table_size = self.sections.len() * 40;
        let total = nt_size + section_table_size + 0x200;
        let mut out = vec![0u8; total];

        // Write NT signature
        let sig = self.nt_headers.signature.to_le_bytes();
        out[0..4].copy_from_slice(&sig);

        // Write file header
        let fh = &self.nt_headers.file_header;
        out[4..6].copy_from_slice(&fh.machine.to_le_bytes());
        out[6..8].copy_from_slice(&fh.number_of_sections.to_le_bytes());
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
            // PE32+
            debug!("Writing ImageBase for PE32+: {:#x} at buffer offset 48", oh.image_base);
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

            // Data directories (starting at offset 136 = 24 + 112)
            let dd_off = 136;
            for (i, dd) in oh.data_directory.iter().enumerate() {
                let off = dd_off + i * 8;
                out[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
                out[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
            }

            // Section headers start after the optional header
            let sh_off = 24 + 112 + 16 * 8; // 264
            for (i, section) in self.sections.iter().enumerate() {
                let off = sh_off + i * 40;

                // DEBUG: Log section header fields
                if i < 3 {
                    tracing::info!(
                        "Section {}: name={:?}, VA={:#x}, chars={:#x}",
                        i,
                        std::str::from_utf8(&section.header.name).unwrap_or("(invalid)"),
                        section.header.virtual_address,
                        section.header.characteristics
                    );
                }

                out[off..off + 8].copy_from_slice(&section.header.name);
                out[off + 8..off + 12]
                    .copy_from_slice(&section.header.virtual_size.to_le_bytes());
                out[off + 12..off + 16]
                    .copy_from_slice(&section.header.virtual_address.to_le_bytes());
                out[off + 16..off + 20]
                    .copy_from_slice(&section.header.size_of_raw_data.to_le_bytes());
                out[off + 20..off + 24]
                    .copy_from_slice(&section.header.pointer_to_raw_data.to_le_bytes());
                out[off + 24..off + 28]
                    .copy_from_slice(&section.header.pointer_to_relocations.to_le_bytes());
                out[off + 28..off + 32]
                    .copy_from_slice(&section.header.pointer_to_linenumbers.to_le_bytes());
                out[off + 32..off + 34]
                    .copy_from_slice(&section.header.number_of_relocations.to_le_bytes());
                out[off + 34..off + 36]
                    .copy_from_slice(&section.header.number_of_linenumbers.to_le_bytes());
                out[off + 36..off + 40]
                    .copy_from_slice(&section.header.characteristics.to_le_bytes());

                // DEBUG: Verify what we actually wrote
                if i == 1 {
                    let written_chars = u32::from_le_bytes([out[off + 36], out[off + 37], out[off + 38], out[off + 39]]);
                    tracing::info!("Section 1: wrote characteristics {:#x} at offset {:#x}", written_chars, off + 36);
                }
            }
        } else {
            // PE32
            out[48..52].copy_from_slice(
                &oh.base_of_data
                    .unwrap_or(0)
                    .to_le_bytes(),
            );
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

            // Data directories (starting at offset 120 = 24 + 96)
            let dd_off = 120;
            for (i, dd) in oh.data_directory.iter().enumerate() {
                let off = dd_off + i * 8;
                out[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
                out[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
            }

            // Section headers start after the optional header
            let sh_off = 24 + 96 + 16 * 8; // 248
            for (i, section) in self.sections.iter().enumerate() {
                let off = sh_off + i * 40;
                out[off..off + 8].copy_from_slice(&section.header.name);
                out[off + 8..off + 12]
                    .copy_from_slice(&section.header.virtual_size.to_le_bytes());
                out[off + 12..off + 16]
                    .copy_from_slice(&section.header.virtual_address.to_le_bytes());
                out[off + 16..off + 20]
                    .copy_from_slice(&section.header.size_of_raw_data.to_le_bytes());
                out[off + 20..off + 24]
                    .copy_from_slice(&section.header.pointer_to_raw_data.to_le_bytes());
                out[off + 24..off + 28]
                    .copy_from_slice(&section.header.pointer_to_relocations.to_le_bytes());
                out[off + 28..off + 32]
                    .copy_from_slice(&section.header.pointer_to_linenumbers.to_le_bytes());
                out[off + 32..off + 34]
                    .copy_from_slice(&section.header.number_of_relocations.to_le_bytes());
                out[off + 34..off + 36]
                    .copy_from_slice(&section.header.number_of_linenumbers.to_le_bytes());
                out[off + 36..off + 40]
                    .copy_from_slice(&section.header.characteristics.to_le_bytes());
            }
        }

        Ok(out)
    }
}
