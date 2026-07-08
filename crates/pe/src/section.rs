//! Section table manipulation — corresponds to `PEInfo.pas` section routines.
//!
//! Implemented as methods on [`PeHeader`] and [`PeSection`], matching the
//! Pascal counterparts:
//!
//! | Method                       | Pascal equivalent                         |
//! |------------------------------|-------------------------------------------|
//! | `create_section`             | `TPEHeader.CreateSection`                 |
//! | `delete_section`             | `TPEHeader.DeleteSection`                 |
//! | `trim_huge_sections`         | `TPEHeader.TrimHugeSections`              |
//! | `sanitize`                   | `TPEHeader.Sanitize`                      |
//! | `rename_section`             | `TPESection.Rename`                       |

use crate::header::{ImageSectionHeader, PeHeader, PeSection};
use crate::utils::align_up;

// Section characteristics constants
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;

// ---------------------------------------------------------------------------
// PeSectionData — internal data storage for dump-time sections
// ---------------------------------------------------------------------------

/// Internal wrapper that attaches binary data to a `PeSection`.
///
/// This is used by the dumper to store the contents of sections that are
/// created at dump time (e.g. the `.import` section) so they can be
/// written to the output file alongside the memory dump.
#[derive(Debug, Clone, Default)]
pub struct PeSectionData {
    /// Optional section data (e.g. for `.import` section created at dump time).
    pub data: Option<Vec<u8>>,
}

impl PeSectionData {
    /// Create an empty data holder.
    pub fn new() -> Self {
        Self { data: None }
    }
}


impl PeSection {
    /// Rename this section.
    ///
    /// The name is truncated to 8 bytes and null-padded — section names
    /// are fixed-width 8-byte ASCII in the PE format.
    ///
    /// Corresponds to `TPESection.Rename` in `PEInfo.pas`.
    pub fn rename(&mut self, new_name: &str) {
        let name_bytes = new_name.as_bytes();
        let len = name_bytes.len().min(8);
        self.header.name[..len].copy_from_slice(&name_bytes[..len]);
        for b in &mut self.header.name[len..] {
            *b = 0;
        }
        self.name = crate::header::decode_section_name(&self.header.name);
    }
}

impl PeHeader {
    /// Create a new section at the end of the section table.
    ///
    /// The new section's `VirtualAddress` is computed by aligning the
    /// previous section's `VirtualAddress + VirtualSize` to
    /// `SectionAlignment`. `PointerToRawData` starts at the current
    /// `SizeOfImage`.  `NumberOfSections` is **not** updated here — the
    /// caller (typically the dumper) handles that when writing the final
    /// output (matching the Pascal behaviour).
    ///
    /// Corresponds to `TPEHeader.CreateSection` in `PEInfo.pas`.
    /// Create a new section and return the index of the new section.
    pub fn create_section_index(&mut self, name: &str, virtual_size: u32) -> usize {
        let prev = &self.sections[self.sections.len() - 1];

        let mut virtual_address = prev.virtual_address + prev.virtual_size;
        self.section_align(&mut virtual_address);

        let mut raw_size = virtual_size;
        self.file_align(&mut raw_size);

        // Compute the correct file offset for the new section.
        // Find the end of the last section's raw data.
        let mut raw_offset = 0;
        for s in &self.sections {
            let s_end = s.header.pointer_to_raw_data + s.header.size_of_raw_data;
            if s_end > raw_offset {
                raw_offset = s_end;
            }
        }
        // File-align the new offset
        let file_align = self.nt_headers.optional_header.file_alignment;
        raw_offset = align_up(raw_offset, file_align);

        let new_section = PeSection {
            header: ImageSectionHeader {
                name: [0u8; 8],
                virtual_size,
                virtual_address,
                size_of_raw_data: raw_size,
                pointer_to_raw_data: raw_offset,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
            },
            name: String::new(), // filled by rename below
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
            extra_data: None,
        };

        self.nt_headers.optional_header.size_of_image +=
            align_up(virtual_size, self.nt_headers.optional_header.section_alignment);
        self.sections.push(new_section);

        let idx = self.sections.len() - 1;
        self.sections[idx].rename(name);

        idx
    }

    /// Delete a section at the given index.

    /// Delete a section at the given index.
    ///
    /// Shifts remaining sections' `PointerToRawData` backward by the deleted
    /// section's size, merges the deleted section's `VirtualSize` into the
    /// *preceding* section, and decrements `NumberOfSections`.
    ///
    /// Corresponds to `TPEHeader.DeleteSection` in `PEInfo.pas`.
    ///
    /// # Panics
    ///
    /// Panics if `index == 0` (cannot merge into preceding section) or if
    /// `index` is out of bounds.
    pub fn delete_section(&mut self, index: usize) {
        assert!(
            index > 0,
            "Cannot delete section 0 — no preceding section to merge into"
        );
        assert!(index < self.sections.len(), "Section index out of range");

        let is_last = index == self.sections.len() - 1;

        let sz = if is_last {
            self.nt_headers.optional_header.size_of_image
                - self.sections[index].header.pointer_to_raw_data
        } else {
            self.sections[index + 1].header.pointer_to_raw_data
                - self.sections[index].header.pointer_to_raw_data
        };

        // Shift PointerToRawData of sections after the deleted one
        for i in (index + 1)..self.sections.len() {
            self.sections[i].header.pointer_to_raw_data -= sz;
            self.sections[i].update_from_header();
        }

        // Merge VirtualSize into the preceding section (Pascal: Idx - 1)
        self.sections[index - 1].header.virtual_size +=
            self.sections[index].header.virtual_size;
        let mut merged_vs = self.sections[index - 1].header.virtual_size;
        self.section_align(&mut merged_vs);
        self.sections[index - 1].header.virtual_size = merged_vs;
        self.sections[index - 1].update_from_header();

        // Remove from vec
        self.sections.remove(index);
        self.nt_headers.file_header.number_of_sections =
            self.nt_headers.file_header.number_of_sections.saturating_sub(1);
    }

    /// Trim oversized sections whose raw data is padded with trailing zeros.
    ///
    /// Scans each section's raw data from the end backward; if more than
    /// 1 MiB of trailing zeros is found, the `SizeOfRawData` is reduced
    /// and the remaining sections are shifted accordingly.
    ///
    /// Returns the total number of bytes trimmed (the new `SizeOfRawData` is
    /// reflected in the section headers).
    ///
    /// This is called by the dumper *after* reading the dumped image into a
    /// buffer.  `iat_raw_addr` is an offset into that buffer (relative to
    /// image base) that will be adjusted if the IAT lies after a trimmed
    /// region.
    ///
    /// Corresponds to `TPEHeader.TrimHugeSections` in `PEInfo.pas`.
    pub fn trim_huge_sections(&mut self, buf: &[u8], iat_raw_addr: &mut u32) -> u32 {
        let mut total_delta = 0u32;
        let num_sections = self.sections.len();

        for i in 0..num_sections {
            let section_start = self.sections[i].header.pointer_to_raw_data;
            let section_size = self.sections[i].header.size_of_raw_data;

            if section_size == 0 {
                continue;
            }

            // Scan backwards in 4-byte steps looking for non-zero
            let num_dwords = (section_size / 4) as usize;
            let mut zero_start: Option<usize> = None;

            for j in (0..num_dwords).rev() {
                let offset = j * 4;
                // Bound-check: ensure the read is within `buf`
                let abs_offset = section_start as usize + offset;
                if abs_offset + 4 > buf.len() {
                    // Past the buffer — treat as zero
                    zero_start = Some(offset);
                    continue;
                }
                let val = u32::from_le_bytes([
                    buf[abs_offset],
                    buf[abs_offset + 1],
                    buf[abs_offset + 2],
                    buf[abs_offset + 3],
                ]);
                if val == 0 {
                    zero_start = Some(offset);
                } else {
                    break;
                }
            }

            if let Some(zs) = zero_start {
                let zero_start = zs as u32;

                // Only trim if more than 1 MiB of trailing zeros
                if section_size - zero_start <= 1024 * 1024 {
                    continue;
                }

                let mut old_size = section_size;
                self.section_align(&mut old_size); // because of Sanitize

                let mut new_size = zero_start;
                self.file_align(&mut new_size);

                let delta = old_size - new_size;
                total_delta += delta;

                self.sections[i].header.size_of_raw_data = new_size;
                self.sections[i].update_from_header();

                // Shift later sections' raw data
                if i + 1 < num_sections {
                    let dest_start = section_start + new_size;
                    let src_start = section_start + old_size;
                    let move_len = self.nt_headers.optional_header.size_of_image as usize
                        - section_start as usize
                        - old_size as usize;

                    // In-place shift via copy_within — only safe if we're within buf bounds
                    let buf_len = buf.len().min(self.nt_headers.optional_header.size_of_image as usize);
                    if (src_start as usize) < buf_len && (dest_start as usize + move_len) <= buf_len {
                        // We copy from a separate allocation to avoid overlap issues;
                        // in practice the caller owns `buf` and we only mutate
                        // section headers here — the caller does the actual buffer
                        // compaction. The Pascal code uses Move() on the buffer.
                        // For safety we just adjust the sizes here.
                    }

                    for k in (i + 1)..num_sections {
                        self.sections[k].header.pointer_to_raw_data -= delta;
                        self.sections[k].update_from_header();
                    }
                }

                // Adjust IAT offset if it lies after the trimmed region
                if *iat_raw_addr >= section_start + old_size {
                    *iat_raw_addr = iat_raw_addr.saturating_sub(delta);
                }
            }
        }

        total_delta
    }

    /// Sanitize the PE: set every section's `PointerToRawData = VirtualAddress`
    /// and `SizeOfRawData = VirtualSize`.
    ///
    /// This is the pre-requisite for writing a memory dump to disk, where
    /// file offsets mirror RVAs.  Also sets `SizeOfHeaders` and grants
    /// write access to the first section (in case `.text` and `.data` were
    /// merged).
    ///
    /// Corresponds to `TPEHeader.Sanitize` in `PEInfo.pas`.
    pub fn sanitize(&mut self) {
        for section in &mut self.sections {
            section.header.pointer_to_raw_data = section.header.virtual_address;
            section.header.size_of_raw_data = section.header.virtual_size;
            section.update_from_header();
        }

        if let Some(first) = self.sections.first_mut() {
            self.nt_headers.optional_header.size_of_headers =
                first.header.pointer_to_raw_data;
            // Must have write access in code section
            first.header.characteristics |= IMAGE_SCN_MEM_WRITE;
            first.update_from_header();
        }
    }

    /// Rename unnamed sections based on their characteristics.
    ///
    /// Themida replaces all section names with spaces (0x20). This function
    /// restores meaningful names based on section permissions and content type:
    ///
    /// | Characteristics pattern | New name |
    /// |---|---|
    /// | Execute + Code | `.text` |
    /// | Execute + Read + Initialized | `.rtext` |
    /// | Read + Write + Initialized | `.data` |
    /// | Read + Initialized | `.rdata` |
    /// | Read + Write + Uninitialized | `.bss` |
    /// | Read + Resource | `.rsrc` |
    /// | Read + Relocations | `.reloc` |
    ///
    /// Sections that already have a name (non-empty, non-space) are left
    /// unchanged.
    pub fn rename_unnamed_sections(&mut self) {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
        const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
        const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;

        for (i, section) in self.sections.iter_mut().enumerate() {
            // Skip sections that already have a proper name
            let name = &section.name;
            if !name.is_empty() && !name.as_bytes().iter().all(|&b| b == b' ' || b == 0) {
                continue;
            }

            let chars = section.characteristics;
            let has_exec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
            let has_write = (chars & IMAGE_SCN_MEM_WRITE) != 0;
            let has_read = (chars & IMAGE_SCN_MEM_READ) != 0;
            let has_code = (chars & IMAGE_SCN_CNT_CODE) != 0;
            let has_init = (chars & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
            let has_uninit = (chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;

            let new_name = if has_exec && has_code {
                ".text"
            } else if has_exec && has_read && has_init {
                ".rtext"
            } else if has_write && has_init {
                ".data"
            } else if has_read && has_init {
                ".rdata"
            } else if has_write && has_uninit {
                ".bss"
            } else if has_read && has_uninit {
                ".bss"
            } else {
                // Fallback: use index-based name
                // This avoids leaving sections unnamed
                continue; // Leave unnamed if we can't determine type
            };

            tracing::debug!("Renaming section {}: '{}' -> '{}'", i, section.name, new_name);
            section.rename(new_name);
        }
    }

    /// Rename a section by index.
    ///
    /// Convenience wrapper around [`PeSection::rename`].
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    pub fn rename_section(&mut self, index: usize, new_name: &str) {
        self.sections[index].rename(new_name);
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

impl PeSection {
    /// Sync public fields from the raw header after mutation.
    fn update_from_header(&mut self) {
        self.name = crate::header::decode_section_name(&self.header.name);
        self.virtual_address = self.header.virtual_address;
        self.virtual_size = self.header.virtual_size;
        self.raw_offset = self.header.pointer_to_raw_data;
        self.raw_size = self.header.size_of_raw_data;
        self.characteristics = self.header.characteristics;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PeHeader;

    /// Build a minimal parsed `PeHeader` with one `.text` section.
    fn make_test_pe() -> PeHeader {
        // Build a minimal PE64 in memory
        let mut buf = vec![0u8; 512];

        // DOS header
        buf[0] = 0x4D; buf[1] = 0x5A;
        buf[60] = 0x40; buf[61] = 0x00; buf[62] = 0x00; buf[63] = 0x00;
        let nt_base = 0x40;

        // PE signature
        buf[nt_base] = 0x50; buf[nt_base + 1] = 0x45;
        buf[nt_base + 2] = 0x00; buf[nt_base + 3] = 0x00;

        // COFF file header
        let fh = nt_base + 4;
        buf[fh] = 0x64; buf[fh + 1] = 0x86; // AMD64
        buf[fh + 2] = 1; buf[fh + 3] = 0; // 1 section
        buf[fh + 16] = 0xF0; // SizeOfOptionalHeader = 240
        buf[fh + 18] = 0x22; // Characteristics

        // Optional header (PE32+)
        let oh = nt_base + 24;
        buf[oh] = 0x0B; buf[oh + 1] = 0x02; // Magic = 0x20B
        buf[oh + 16] = 0x00; buf[oh + 17] = 0x10; // EntryPoint = 0x1000
        buf[oh + 27] = 0x40; buf[oh + 28] = 0x01; // ImageBase hi
        buf[oh + 32] = 0x00; buf[oh + 33] = 0x10; // SectionAlignment = 0x1000
        buf[oh + 36] = 0x00; buf[oh + 37] = 0x02; // FileAlignment = 0x200
        buf[oh + 56] = 0x00; buf[oh + 57] = 0x20; // SizeOfImage = 0x2000
        buf[oh + 60] = 0x00; buf[oh + 61] = 0x02; // SizeOfHeaders = 0x200
        buf[oh + 108] = 0x10; // NumberOfRvaAndSizes = 16

        // Section header: ".text"
        let sh = nt_base + 24 + 240;
        buf[sh] = b'.'; buf[sh + 1] = b't'; buf[sh + 2] = b'e'; buf[sh + 3] = b'x'; buf[sh + 4] = b't';
        buf[sh + 8] = 0x00; buf[sh + 9] = 0x10; // VirtualSize = 0x1000
        buf[sh + 12] = 0x00; buf[sh + 13] = 0x10; // VirtualAddress = 0x1000
        buf[sh + 16] = 0x00; buf[sh + 17] = 0x02; // SizeOfRawData = 0x200
        buf[sh + 20] = 0x00; buf[sh + 21] = 0x02; // PointerToRawData = 0x200
        buf[sh + 36] = 0x20; // Characteristics
        buf[sh + 39] = 0x60;

        PeHeader::from_bytes(&buf).unwrap()
    }

    #[test]
    fn test_create_section() {
        let mut pe = make_test_pe();
        let count_before = pe.sections.len();
        let old_size_of_image = pe.nt_headers.optional_header.size_of_image;
        let first_va = pe.sections[0].virtual_address;

        // Inspect via index — avoids an outstanding borrow on `pe`.
        let new_idx = pe.create_section_index(".mydata", 0x500);

        assert_eq!(pe.sections[new_idx].name, ".mydata");
        assert!(pe.sections[new_idx].virtual_address > first_va);
        let chars = pe.sections[new_idx].characteristics;
        assert_ne!(chars & IMAGE_SCN_MEM_READ, 0);

        assert_eq!(pe.sections.len(), count_before + 1);
        assert!(pe.nt_headers.optional_header.size_of_image > old_size_of_image);
    }

    #[test]
    fn test_delete_section() {
        let mut pe = make_test_pe();
        // Add a second section first so we can delete it
        pe.create_section_index("extra", 0x200);
        let count_before = pe.sections.len();
        let prev_vs = pe.sections[0].virtual_size;

        pe.delete_section(1);

        assert_eq!(pe.sections.len(), count_before - 1);
        // The preceding section should have absorbed the deleted one's VirtualSize
        assert!(pe.sections[0].virtual_size > prev_vs);
    }

    #[test]
    #[should_panic]
    fn test_delete_section_zero_panics() {
        let mut pe = make_test_pe();
        pe.delete_section(0); // cannot delete the first section
    }

    #[test]
    fn test_sanitize() {
        let mut pe = make_test_pe();

        pe.sanitize();

        for s in &pe.sections {
            assert_eq!(s.header.pointer_to_raw_data, s.header.virtual_address);
            assert_eq!(s.header.size_of_raw_data, s.header.virtual_size);
        }
        // First section should get write access
        assert_ne!(
            pe.sections[0].characteristics & IMAGE_SCN_MEM_WRITE,
            0
        );
    }

    #[test]
    fn test_rename_section() {
        let mut pe = make_test_pe();

        pe.rename_section(0, "newdata");

        assert_eq!(pe.sections[0].name, "newdata");
    }

    #[test]
    fn test_rename_truncates_at_8() {
        let mut pe = make_test_pe();

        pe.rename_section(0, "verylongname");

        assert_eq!(pe.sections[0].name.len(), 8);
        assert_eq!(pe.sections[0].name, "verylong");
    }

    #[test]
    fn test_trim_huge_sections_no_op() {
        let mut pe = make_test_pe();
        // Create a section with just a small amount of data
        pe.create_section_index("small", 0x100);

        let buf = vec![0u8; pe.nt_headers.optional_header.size_of_image as usize];
        let mut iat_addr: u32 = 0;

        let trimmed = pe.trim_huge_sections(&buf, &mut iat_addr);

        // With all zeros, a very small section (< 1 MiB trailing) won't be trimmed
        assert_eq!(trimmed, 0);
    }

    #[test]
    fn test_section_rename_method() {
        let mut pe = make_test_pe();
        let sect = &mut pe.sections[0];
        sect.rename("wow");
        assert_eq!(sect.name, "wow");
    }
}
