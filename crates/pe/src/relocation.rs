/// Base Relocation Table builder for PE dumps.
///
/// This module scans all sections for absolute addresses pointing to the image
/// and generates a complete .reloc section so the Windows PE Loader can fix
/// them when the image loads at a different base address.
use std::collections::BTreeMap;

use crate::error::PeError;

/// A single relocation entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelocationEntry {
    /// RVA of the address that needs to be relocated
    pub rva: u32,
    /// Type of relocation (IMAGE_REL_BASED_*)
    pub typ: u16,
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
        self.blocks
            .entry(page_rva)
            .or_default()
            .push(RelocationEntry { rva, typ });
    }

    /// Scan data for absolute addresses and add relocations.
    ///
    /// This compatibility wrapper preserves the historical infallible API.
    /// New code should use [`Self::scan_and_add_relocations_checked`] so RVA
    /// and image-range overflow is not silently accepted.
    pub fn scan_and_add_relocations(&mut self, data: &[u8], section_rva: u32, is_64bit: bool) {
        let _ = self.scan_and_add_relocations_checked(data, section_rva, is_64bit);
    }

    /// Checked variant of [`Self::scan_and_add_relocations`].
    pub fn scan_and_add_relocations_checked(
        &mut self,
        data: &[u8],
        section_rva: u32,
        is_64bit: bool,
    ) -> Result<(), PeError> {
        use tracing::debug;

        let ptr_size = if is_64bit { 8 } else { 4 };
        let image_end = self
            .image_base
            .checked_add(self.image_size as u64)
            .ok_or_else(|| PeError::Parse("relocation image range overflow".into()))?;
        let mut found_count = 0;

        for offset in (0..data.len().saturating_sub(ptr_size - 1)).step_by(ptr_size) {
            let addr = if is_64bit {
                u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4])) as u64
            };

            if addr >= self.image_base && addr < image_end {
                let entry_rva = section_rva
                    .checked_add(u32::try_from(offset).map_err(|_| {
                        PeError::Parse("relocation scan offset exceeds PE32".into())
                    })?)
                    .ok_or_else(|| PeError::Parse("relocation RVA overflow".into()))?;
                if entry_rva >= self.image_size {
                    return Err(PeError::Parse(format!(
                        "relocation RVA {entry_rva:#x} outside image size {:#x}",
                        self.image_size
                    )));
                }
                let reloc_type = if is_64bit { 10 } else { 3 };
                self.add_relocation(entry_rva, reloc_type);
                found_count += 1;
            }
        }

        if found_count > 0 {
            debug!(
                "Section at RVA {:#x}: found {} relocations",
                section_rva, found_count
            );
        }
        Ok(())
    }

    /// Get total number of relocations
    pub fn count(&self) -> usize {
        self.blocks.values().map(|v| v.len()).sum()
    }

    /// Validate all relocation entries before serialization.
    pub fn validate(&self) -> Result<(), PeError> {
        if self.image_size == 0 && !self.blocks.is_empty() {
            return Err(PeError::Parse("relocation image size is zero".into()));
        }
        for (&page_rva, entries) in &self.blocks {
            if page_rva & 0xFFF != 0 || page_rva >= self.image_size {
                return Err(PeError::Parse(format!(
                    "relocation page RVA {page_rva:#x} outside image"
                )));
            }
            for entry in entries {
                if entry.rva < page_rva || entry.rva - page_rva > 0xFFF {
                    return Err(PeError::Parse(format!(
                        "relocation RVA {:#x} does not belong to page {page_rva:#x}",
                        entry.rva
                    )));
                }
                if entry.rva >= self.image_size {
                    return Err(PeError::Parse(format!(
                        "relocation RVA {:#x} outside image size {:#x}",
                        entry.rva, self.image_size
                    )));
                }
                if entry.typ > 0xF {
                    return Err(PeError::Parse(format!(
                        "relocation type {} exceeds PE nibble",
                        entry.typ
                    )));
                }
            }
        }
        Ok(())
    }

    /// Build the .reloc section data, rejecting malformed ranges.
    pub fn build_checked(&self) -> Result<Vec<u8>, PeError> {
        self.validate()?;
        let mut reloc_data = Vec::new();

        for (&page_rva, entries) in &self.blocks {
            let mut entries = entries.clone();
            if entries.len() % 2 != 0 {
                entries.push(RelocationEntry {
                    rva: page_rva,
                    typ: 0,
                });
            }
            let block_size = 8usize
                .checked_add(
                    entries
                        .len()
                        .checked_mul(2)
                        .ok_or_else(|| PeError::Parse("relocation block size overflow".into()))?,
                )
                .ok_or_else(|| PeError::Parse("relocation block size overflow".into()))?;
            let block_size_u32 = u32::try_from(block_size)
                .map_err(|_| PeError::Parse("relocation block exceeds PE32 size".into()))?;
            reloc_data.extend_from_slice(&page_rva.to_le_bytes());
            reloc_data.extend_from_slice(&block_size_u32.to_le_bytes());

            for entry in entries {
                let offset_in_page = entry.rva - page_rva;
                let type_offset = (entry.typ << 12) | (offset_in_page as u16 & 0xFFF);
                reloc_data.extend_from_slice(&type_offset.to_le_bytes());
            }
        }
        while reloc_data.len() % 4 != 0 {
            reloc_data.push(0);
        }
        Ok(reloc_data)
    }

    /// Compatibility serializer for callers that already guarantee valid
    /// entries.  Invalid builders emit an empty table rather than wrapping.
    pub fn build(&self) -> Vec<u8> {
        self.build_checked().unwrap_or_default()
    }

    /// Apply this builder's relocations to an image copied at `new_base`.
    ///
    /// This is a pure ASLR correctness primitive used by synthetic tests and
    /// recovery verification; it never touches a live process.
    pub fn apply_to_image(
        &self,
        image: &mut [u8],
        new_base: u64,
        is_64bit: bool,
    ) -> Result<(), PeError> {
        self.validate()?;
        let delta = if new_base >= self.image_base {
            new_base - self.image_base
        } else {
            self.image_base - new_base
        };
        for entries in self.blocks.values() {
            for entry in entries {
                if entry.typ == 0 {
                    continue;
                }
                let width = if is_64bit { 8 } else { 4 };
                let off = entry.rva as usize;
                let end = off
                    .checked_add(width)
                    .ok_or_else(|| PeError::Parse("relocation image offset overflow".into()))?;
                if end > image.len() {
                    return Err(PeError::Parse(format!(
                        "relocation RVA {:#x} exceeds image buffer",
                        entry.rva
                    )));
                }
                if is_64bit {
                    let old = u64::from_le_bytes(image[off..end].try_into().unwrap());
                    let value = if new_base >= self.image_base {
                        old.checked_add(delta)
                    } else {
                        old.checked_sub(delta)
                    }
                    .ok_or_else(|| PeError::Parse("DIR64 relocation overflow".into()))?;
                    image[off..end].copy_from_slice(&value.to_le_bytes());
                } else {
                    let old = u32::from_le_bytes(image[off..end].try_into().unwrap());
                    let delta32 = u32::try_from(delta).map_err(|_| {
                        PeError::Parse("HIGHLOW relocation delta exceeds u32".into())
                    })?;
                    let value = if new_base >= self.image_base {
                        old.checked_add(delta32)
                    } else {
                        old.checked_sub(delta32)
                    }
                    .ok_or_else(|| PeError::Parse("HIGHLOW relocation overflow".into()))?;
                    image[off..end].copy_from_slice(&value.to_le_bytes());
                }
            }
        }
        Ok(())
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
