/// Base Relocation Table builder for PE dumps.
///
/// This module scans all sections for absolute addresses pointing to the image
/// and generates a complete .reloc section so the Windows PE Loader can fix
/// them when the image loads at a different base address.

use std::collections::BTreeMap;

/// A single relocation entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationEntry {
    /// RVA of the address that needs to be relocated
    pub rva: u32,
    /// Type of relocation (IMAGE_REL_BASED_*)
    pub typ: u16,
}

/// Base relocation block for a 4KB page
#[derive(Debug)]
#[allow(dead_code)]
struct RelocationBlock {
    page_rva: u32,
    entries: Vec<RelocationEntry>,
}

/// Builder for the Base Relocation Table
pub struct RelocationTableBuilder {
    /// Relocations grouped by page (4KB blocks)
    blocks: BTreeMap<u32, Vec<RelocationEntry>>,
    /// ImageBase for validation
    image_base: u64,
    /// Size of image for validation
    image_size: u32,
}

impl RelocationTableBuilder {
    /// Create a new relocation table builder
    pub fn new(image_base: u64, image_size: u32) -> Self {
        Self {
            blocks: BTreeMap::new(),
            image_base,
            image_size,
        }
    }

    /// Add a relocation entry
    pub fn add_relocation(&mut self, rva: u32, typ: u16) {
        let page_rva = rva & !0xFFF; // Align to 4KB page
        self.blocks.entry(page_rva).or_default().push(RelocationEntry { rva, typ });
    }

    /// Scan data for absolute addresses and add relocations
    ///
    /// This scans a section for pointers that point to the image itself.
    /// Such pointers need to be relocated when the image loads at a different base.
    pub fn scan_and_add_relocations(
        &mut self,
        data: &[u8],
        section_rva: u32,
        is_64bit: bool,
    ) {
        use tracing::{debug, info};

        let ptr_size = if is_64bit { 8 } else { 4 };
        let image_start = self.image_base;
        let image_end = self.image_base + self.image_size as u64;

        let mut found_count = 0;

        for offset in (0..data.len().saturating_sub(ptr_size - 1)).step_by(ptr_size) {
            let addr = if is_64bit {
                u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4])) as u64
            };

            // Check if this looks like an absolute address pointing to our image
            if addr >= image_start && addr < image_end {
                let entry_rva = section_rva + offset as u32;

                // Debug log for the critical address
                if entry_rva == 0x1051e0 || (0x1051d0..=0x1051f0).contains(&entry_rva) {
                    info!("!!! FOUND critical address: RVA={:#x}, value={:#x}, section_rva={:#x}, offset={:#x}",
                          entry_rva, addr, section_rva, offset);
                }

                let reloc_type = if is_64bit {
                    10 // IMAGE_REL_BASED_DIR64
                } else {
                    3 // IMAGE_REL_BASED_HIGHLOW
                };
                self.add_relocation(entry_rva, reloc_type);
                found_count += 1;
            }
        }

        if found_count > 0 {
            debug!("Section at RVA {:#x}: found {} relocations", section_rva, found_count);
        }
    }

    /// Get total number of relocations
    pub fn count(&self) -> usize {
        self.blocks.values().map(|v| v.len()).sum()
    }

    /// Build the .reloc section data
    ///
    /// Format: Multiple IMAGE_BASE_RELOCATION blocks, each covering a 4KB page
    /// Each block has:
    ///   DWORD VirtualAddress (page RVA)
    ///   DWORD SizeOfBlock (size of this block including header)
    ///   WORD  TypeOffset entries (type in high 4 bits, offset in low 12 bits)
    pub fn build(&self) -> Vec<u8> {
        let mut reloc_data = Vec::new();

        for (&page_rva, entries) in &self.blocks {
            // Each block must be aligned to 4 bytes and have an even number of entries
            let mut entries = entries.clone();

            // If odd number of entries, add a padding entry (type 0 = ABSOLUTE, no-op)
            if entries.len() % 2 != 0 {
                entries.push(RelocationEntry { rva: page_rva, typ: 0 });
            }

            // Block header: VirtualAddress + SizeOfBlock
            let block_size = 8 + (entries.len() * 2); // 8-byte header + 2 bytes per entry
            reloc_data.extend_from_slice(&page_rva.to_le_bytes());
            reloc_data.extend_from_slice(&(block_size as u32).to_le_bytes());

            // Entries: type (4 bits) + offset (12 bits)
            for entry in entries {
                let offset_in_page = entry.rva - page_rva;
                let type_offset = (entry.typ << 12) | (offset_in_page as u16 & 0xFFF);
                reloc_data.extend_from_slice(&type_offset.to_le_bytes());
            }
        }

        // Align to 4 bytes
        while reloc_data.len() % 4 != 0 {
            reloc_data.push(0);
        }

        reloc_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocation_builder() {
        let mut builder = RelocationTableBuilder::new(0x140000000, 0x10000);

        // Add some relocations
        builder.add_relocation(0x1000, 10); // DIR64
        builder.add_relocation(0x1008, 10);
        builder.add_relocation(0x2000, 10); // Different page

        assert_eq!(builder.count(), 3);

        let data = builder.build();
        assert!(!data.is_empty());
        assert_eq!(data.len() % 4, 0); // Must be 4-byte aligned
    }

    #[test]
    fn test_scan_relocations() {
        let image_base = 0x140000000u64;
        let mut builder = RelocationTableBuilder::new(image_base, 0x10000);

        // Create test data with some absolute addresses
        let mut data = vec![0u8; 32];
        // Put an absolute address at offset 0
        data[0..8].copy_from_slice(&(image_base + 0x1234).to_le_bytes());
        // Put another at offset 8
        data[8..16].copy_from_slice(&(image_base + 0x5678).to_le_bytes());
        // Put a non-image address at offset 16 (should be ignored)
        data[16..24].copy_from_slice(&0x7fff00000000u64.to_le_bytes());

        builder.scan_and_add_relocations(&data, 0x1000, true);

        assert_eq!(builder.count(), 2); // Only the two image addresses
    }
}
