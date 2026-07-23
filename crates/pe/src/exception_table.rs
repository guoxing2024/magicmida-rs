//! Pure exception directory (`.pdata`) builder for PE reconstruction.
//!
//! Emits an array of `IMAGE_RUNTIME_FUNCTION_ENTRY` (12 bytes each) for the PE
//! exception data directory (index 3). Primarily used by PE32+ / x64; PE32 may
//! still carry the directory for structural emit. Accepts only typed PE values
//! and bytes — no Win32, live process, or packer policy.
//!
//! Optional `UNWIND_INFO` payloads can be embedded after the function table so a
//! single section is self-contained. Directory size is always
//! `functions.len() * RUNTIME_FUNCTION_SIZE` (the RUNTIME_FUNCTION array only).

use crate::error::PeError;

/// Size of `IMAGE_RUNTIME_FUNCTION_ENTRY` / `RUNTIME_FUNCTION` in bytes.
pub const RUNTIME_FUNCTION_SIZE: usize = 12;

/// One runtime function range in the exception directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFunction {
    /// Inclusive start RVA of the function (or region).
    pub begin_rva: u32,
    /// Exclusive end RVA of the function (or region).
    pub end_rva: u32,
    /// RVA of `UNWIND_INFO`. When `0` and a parallel embedded blob exists, the
    /// builder assigns an in-section RVA on emit.
    pub unwind_info_rva: u32,
}

/// Builder for a pure exception / `.pdata` section.
#[derive(Debug, Clone, Default)]
pub struct ExceptionTableBuilder {
    /// Ordered RUNTIME_FUNCTION entries (must be sorted by `begin_rva` on emit).
    pub functions: Vec<RuntimeFunction>,
    /// Optional UNWIND_INFO payloads embedded after the function table.
    ///
    /// When non-empty, length must equal `functions.len()`. Entries with
    /// `unwind_info_rva == 0` receive the RVA of the corresponding blob;
    /// non-zero `unwind_info_rva` values are left unchanged (blob still stored
    /// if present, for caller-owned layout tests).
    pub unwind_info: Vec<Vec<u8>>,
}

impl ExceptionTableBuilder {
    /// Empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a runtime function with an absolute unwind-info RVA.
    pub fn add_function(
        &mut self,
        begin_rva: u32,
        end_rva: u32,
        unwind_info_rva: u32,
    ) -> &mut Self {
        self.functions.push(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_info_rva,
        });
        self
    }

    /// Append a runtime function and embed `unwind_bytes` after the table.
    ///
    /// Aligns the parallel `unwind_info` vector with prior entries (empty blobs
    /// for functions that only had absolute RVAs).
    pub fn add_function_with_unwind(
        &mut self,
        begin_rva: u32,
        end_rva: u32,
        unwind_bytes: Vec<u8>,
    ) -> &mut Self {
        // Pad unwind_info to match functions that were added without blobs.
        while self.unwind_info.len() < self.functions.len() {
            self.unwind_info.push(Vec::new());
        }
        self.functions.push(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_info_rva: 0,
        });
        self.unwind_info.push(unwind_bytes);
        self
    }

    /// Number of RUNTIME_FUNCTION entries.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Validate structural rules without emitting bytes.
    pub fn validate(&self) -> Result<(), PeError> {
        if self.functions.is_empty() {
            return Err(PeError::Parse(
                "exception table requires at least one runtime function".into(),
            ));
        }
        if !self.unwind_info.is_empty() && self.unwind_info.len() != self.functions.len() {
            return Err(PeError::Parse(
                "exception unwind_info length must match functions length".into(),
            ));
        }
        let mut prev_begin: Option<u32> = None;
        let mut prev_end: Option<u32> = None;
        for (i, f) in self.functions.iter().enumerate() {
            if f.begin_rva >= f.end_rva {
                return Err(PeError::Parse(format!(
                    "exception function[{i}]: begin_rva must be < end_rva"
                )));
            }
            if let Some(pb) = prev_begin {
                if f.begin_rva < pb {
                    return Err(PeError::Parse(
                        "exception functions must be sorted by begin_rva".into(),
                    ));
                }
                if f.begin_rva == pb {
                    return Err(PeError::Parse(
                        "exception functions must not share the same begin_rva".into(),
                    ));
                }
            }
            if let Some(pe) = prev_end {
                if f.begin_rva < pe {
                    return Err(PeError::Parse(
                        "exception functions must not overlap".into(),
                    ));
                }
            }
            prev_begin = Some(f.begin_rva);
            prev_end = Some(f.end_rva);
        }
        Ok(())
    }

    /// Build section bytes for placement at `section_va`.
    ///
    /// Layout:
    /// ```text
    /// +0x00  RUNTIME_FUNCTION[n]   (n * 12)  ← exception data directory
    /// +n*12  optional UNWIND_INFO blobs (4-byte aligned each)
    /// ```
    ///
    /// Returns `(section_data, directory_size)` where `directory_size` is the
    /// RUNTIME_FUNCTION array length only.
    pub fn build_section_data(&self, section_va: u32) -> Result<(Vec<u8>, u32), PeError> {
        self.validate()?;

        let n = self.functions.len();
        let table_bytes = n
            .checked_mul(RUNTIME_FUNCTION_SIZE)
            .ok_or_else(|| PeError::Parse("exception table size overflow".into()))?;
        if table_bytes > u32::MAX as usize {
            return Err(PeError::Parse("exception table exceeds u32".into()));
        }

        // Precompute unwind blob layout (aligned to 4 bytes each).
        let mut unwind_offsets: Vec<Option<usize>> = vec![None; n];
        let mut cursor = table_bytes;
        if !self.unwind_info.is_empty() {
            for (i, blob) in self.unwind_info.iter().enumerate() {
                if blob.is_empty() {
                    continue;
                }
                // Align each blob start to 4 bytes.
                let aligned = (cursor + 3) & !3;
                unwind_offsets[i] = Some(aligned);
                cursor = aligned
                    .checked_add(blob.len())
                    .ok_or_else(|| PeError::Parse("exception unwind blob overflow".into()))?;
            }
        }
        let total = cursor;
        if total > u32::MAX as usize {
            return Err(PeError::Parse("exception section exceeds u32".into()));
        }

        let mut data = vec![0u8; total];

        // Write UNWIND_INFO blobs first so we can assign RVAs.
        if !self.unwind_info.is_empty() {
            for (i, blob) in self.unwind_info.iter().enumerate() {
                if let Some(off) = unwind_offsets[i] {
                    data[off..off + blob.len()].copy_from_slice(blob);
                }
            }
        }

        // RUNTIME_FUNCTION array
        for (i, f) in self.functions.iter().enumerate() {
            let mut unwind_rva = f.unwind_info_rva;
            if unwind_rva == 0 {
                if let Some(off) = unwind_offsets.get(i).copied().flatten() {
                    unwind_rva = section_va
                        .checked_add(off as u32)
                        .ok_or_else(|| PeError::Parse("exception unwind RVA overflow".into()))?;
                } else if !self.unwind_info.is_empty() {
                    return Err(PeError::Parse(format!(
                        "exception function[{i}]: unwind_info_rva is 0 and no embedded blob"
                    )));
                } else {
                    return Err(PeError::Parse(format!(
                        "exception function[{i}]: unwind_info_rva must be non-zero without embedded blobs"
                    )));
                }
            }

            let off = i * RUNTIME_FUNCTION_SIZE;
            write_u32(&mut data, off, f.begin_rva);
            write_u32(&mut data, off + 4, f.end_rva);
            write_u32(&mut data, off + 8, unwind_rva);
        }

        Ok((data, table_bytes as u32))
    }
}

/// Minimal x64 `UNWIND_INFO`: version 1, no flags, empty prolog, zero codes.
///
/// Suitable for synthetic leaf functions in rebuild tests (not a general
/// unwinder substitute).
#[must_use]
pub fn minimal_x64_unwind_info() -> Vec<u8> {
    // Version(3)=1 | Flags(5)=0, SizeOfProlog=0, CountOfCodes=0, Frame=0
    vec![0x01, 0x00, 0x00, 0x00]
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exception_with_absolute_unwind_rvas() {
        let mut b = ExceptionTableBuilder::new();
        b.add_function(0x1000, 0x1010, 0x2000)
            .add_function(0x1020, 0x1040, 0x2010);
        let (data, dir_size) = b.build_section_data(0x3000).expect("build");
        assert_eq!(dir_size as usize, 2 * RUNTIME_FUNCTION_SIZE);
        assert_eq!(data.len(), 2 * RUNTIME_FUNCTION_SIZE);

        let begin0 = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let end0 = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let unwind0 = u32::from_le_bytes(data[8..12].try_into().unwrap());
        assert_eq!(begin0, 0x1000);
        assert_eq!(end0, 0x1010);
        assert_eq!(unwind0, 0x2000);

        let begin1 = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(begin1, 0x1020);
    }

    #[test]
    fn exception_embeds_unwind_and_assigns_rva() {
        let mut b = ExceptionTableBuilder::new();
        b.add_function_with_unwind(0x1000, 0x1008, minimal_x64_unwind_info());
        let section_va = 0x4000u32;
        let (data, dir_size) = b.build_section_data(section_va).expect("build");
        assert_eq!(dir_size as usize, RUNTIME_FUNCTION_SIZE);
        assert!(data.len() > RUNTIME_FUNCTION_SIZE);

        let unwind_rva = u32::from_le_bytes(data[8..12].try_into().unwrap());
        assert_eq!(unwind_rva, section_va + RUNTIME_FUNCTION_SIZE as u32);
        let off = (unwind_rva - section_va) as usize;
        assert_eq!(&data[off..off + 4], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn exception_unsorted_errors() {
        let mut b = ExceptionTableBuilder::new();
        b.add_function(0x2000, 0x2010, 0x3000)
            .add_function(0x1000, 0x1010, 0x3010);
        assert!(b.build_section_data(0x4000).is_err());
    }

    #[test]
    fn exception_overlap_errors() {
        let mut b = ExceptionTableBuilder::new();
        b.add_function(0x1000, 0x1020, 0x3000)
            .add_function(0x1010, 0x1030, 0x3010);
        assert!(b.validate().is_err());
    }

    #[test]
    fn exception_empty_errors() {
        let b = ExceptionTableBuilder::new();
        assert!(b.build_section_data(0x1000).is_err());
    }

    #[test]
    fn exception_begin_ge_end_errors() {
        let mut b = ExceptionTableBuilder::new();
        b.add_function(0x1000, 0x1000, 0x2000);
        assert!(b.validate().is_err());
    }
}
