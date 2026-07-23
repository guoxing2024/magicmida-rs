//! Pure TLS directory builder for PE reconstruction.
//!
//! Emits `IMAGE_TLS_DIRECTORY32/64` plus index slot, optional template data,
//! and a NULL-terminated callback VA array. Accepts only buffers and typed PE
//! values — no live process or Win32.

use crate::error::PeError;
use crate::import_table::iat_slot_size;

/// Size of `IMAGE_TLS_DIRECTORY32`.
pub const TLS_DIRECTORY32_SIZE: usize = 24;
/// Size of `IMAGE_TLS_DIRECTORY64`.
pub const TLS_DIRECTORY64_SIZE: usize = 40;

/// Builder for a pure `.tls` section.
#[derive(Debug, Clone)]
pub struct TlsDirectoryBuilder {
    pub is_64bit: bool,
    /// Template bytes copied into the TLS data region (`Start..End`).
    pub template_data: Vec<u8>,
    /// Extra zero-fill after template (`SizeOfZeroFill`).
    pub size_of_zero_fill: u32,
    /// Callback function RVAs (converted to VAs with `image_base` on emit).
    pub callback_rvas: Vec<u32>,
    pub characteristics: u32,
}

impl Default for TlsDirectoryBuilder {
    fn default() -> Self {
        Self {
            is_64bit: true,
            template_data: Vec::new(),
            size_of_zero_fill: 0,
            callback_rvas: Vec::new(),
            characteristics: 0,
        }
    }
}

impl TlsDirectoryBuilder {
    #[must_use]
    pub fn new(is_64bit: bool) -> Self {
        Self {
            is_64bit,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn pe32() -> Self {
        Self::new(false)
    }

    #[must_use]
    pub fn pe32_plus() -> Self {
        Self::new(true)
    }

    /// Directory structure size (not the full section).
    #[must_use]
    pub fn directory_size(&self) -> usize {
        if self.is_64bit {
            TLS_DIRECTORY64_SIZE
        } else {
            TLS_DIRECTORY32_SIZE
        }
    }

    /// Build section bytes for placement at `section_va` with given `image_base`.
    ///
    /// Layout:
    /// ```text
    /// +0x00  IMAGE_TLS_DIRECTORY32/64
    /// +dir   TLS index (u32) + pad to pointer alignment
    ///        template data (may be empty; Start==End is valid)
    ///        callback array (VAs, NULL-terminated; always at least terminator)
    /// ```
    ///
    /// Returns `(section_data, directory_size)` for the TLS data directory entry.
    pub fn build_section_data(
        &self,
        section_va: u32,
        image_base: u64,
    ) -> Result<(Vec<u8>, u32), PeError> {
        let dir_size = self.directory_size();
        let ptr_size = iat_slot_size(self.is_64bit);

        // Index immediately after directory, then align for template/callbacks.
        let index_off = dir_size;
        let index_end = index_off
            .checked_add(4)
            .ok_or_else(|| PeError::Parse("tls index overflow".into()))?;
        // Align following region to pointer size.
        let aligned_after_index = (index_end + ptr_size - 1) / ptr_size * ptr_size;

        let template_off = aligned_after_index;
        let template_len = self.template_data.len();
        let template_end = template_off
            .checked_add(template_len)
            .ok_or_else(|| PeError::Parse("tls template overflow".into()))?;

        // Callbacks after template, pointer-aligned.
        let callbacks_off = (template_end + ptr_size - 1) / ptr_size * ptr_size;
        let n_cb = self.callback_rvas.len();
        let cb_slots = n_cb
            .checked_add(1)
            .ok_or_else(|| PeError::Parse("tls callback count overflow".into()))?;
        let cb_bytes = cb_slots
            .checked_mul(ptr_size)
            .ok_or_else(|| PeError::Parse("tls callback array overflow".into()))?;
        let total = callbacks_off
            .checked_add(cb_bytes)
            .ok_or_else(|| PeError::Parse("tls section size overflow".into()))?;
        if total > u32::MAX as usize {
            return Err(PeError::Parse("tls section exceeds u32".into()));
        }

        let mut data = vec![0u8; total];

        // Template
        if template_len > 0 {
            data[template_off..template_off + template_len].copy_from_slice(&self.template_data);
        }

        // Callback VAs
        for (i, &rva) in self.callback_rvas.iter().enumerate() {
            let va = image_base
                .checked_add(rva as u64)
                .ok_or_else(|| PeError::Parse("tls callback VA overflow".into()))?;
            let off = callbacks_off + i * ptr_size;
            write_ptr(&mut data, off, va, self.is_64bit);
        }
        // NULL terminator already zeroed

        // Absolute VAs for directory fields
        let start_va = if template_len > 0 {
            image_base
                .checked_add(section_va as u64)
                .and_then(|b| b.checked_add(template_off as u64))
                .ok_or_else(|| PeError::Parse("tls start VA overflow".into()))?
        } else {
            // Empty template: Start == End; point at a stable in-section address
            // (after index) so the region is mapped.
            image_base
                .checked_add(section_va as u64)
                .and_then(|b| b.checked_add(template_off as u64))
                .ok_or_else(|| PeError::Parse("tls empty start VA overflow".into()))?
        };
        let end_va = start_va
            .checked_add(template_len as u64)
            .ok_or_else(|| PeError::Parse("tls end VA overflow".into()))?;
        let index_va = image_base
            .checked_add(section_va as u64)
            .and_then(|b| b.checked_add(index_off as u64))
            .ok_or_else(|| PeError::Parse("tls index VA overflow".into()))?;
        let callbacks_va = image_base
            .checked_add(section_va as u64)
            .and_then(|b| b.checked_add(callbacks_off as u64))
            .ok_or_else(|| PeError::Parse("tls callbacks VA overflow".into()))?;

        if self.is_64bit {
            write_u64(&mut data, 0x00, start_va);
            write_u64(&mut data, 0x08, end_va);
            write_u64(&mut data, 0x10, index_va);
            write_u64(&mut data, 0x18, callbacks_va);
            write_u32(&mut data, 0x20, self.size_of_zero_fill);
            write_u32(&mut data, 0x24, self.characteristics);
        } else {
            // PE32 TLS directory uses 32-bit VAs.
            if start_va > u32::MAX as u64
                || end_va > u32::MAX as u64
                || index_va > u32::MAX as u64
                || callbacks_va > u32::MAX as u64
            {
                return Err(PeError::Parse(
                    "tls VA exceeds 32-bit address space for PE32".into(),
                ));
            }
            write_u32(&mut data, 0x00, start_va as u32);
            write_u32(&mut data, 0x04, end_va as u32);
            write_u32(&mut data, 0x08, index_va as u32);
            write_u32(&mut data, 0x0C, callbacks_va as u32);
            write_u32(&mut data, 0x10, self.size_of_zero_fill);
            write_u32(&mut data, 0x14, self.characteristics);
        }

        Ok((data, dir_size as u32))
    }
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn write_ptr(buf: &mut [u8], off: usize, v: u64, is_64bit: bool) {
    if is_64bit {
        write_u64(buf, off, v);
    } else {
        write_u32(buf, off, v as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls64_directory_fields_and_callback() {
        let mut b = TlsDirectoryBuilder::pe32_plus();
        b.template_data = vec![0x11, 0x22];
        b.callback_rvas = vec![0x2000];
        let image_base = 0x0000_0140_0000_0000u64;
        let section_va = 0x3000u32;
        let (data, dir_size) = b.build_section_data(section_va, image_base).expect("build");
        assert_eq!(dir_size as usize, TLS_DIRECTORY64_SIZE);
        assert!(data.len() > TLS_DIRECTORY64_SIZE);

        let start = u64::from_le_bytes(data[0x00..0x08].try_into().unwrap());
        let end = u64::from_le_bytes(data[0x08..0x10].try_into().unwrap());
        let index = u64::from_le_bytes(data[0x10..0x18].try_into().unwrap());
        let cbs = u64::from_le_bytes(data[0x18..0x20].try_into().unwrap());
        assert_eq!(end - start, 2);
        assert_eq!(
            index,
            image_base + section_va as u64 + TLS_DIRECTORY64_SIZE as u64
        );

        let cb_off = (cbs - image_base - section_va as u64) as usize;
        let cb0 = u64::from_le_bytes(data[cb_off..cb_off + 8].try_into().unwrap());
        assert_eq!(cb0, image_base + 0x2000);
        let term = u64::from_le_bytes(data[cb_off + 8..cb_off + 16].try_into().unwrap());
        assert_eq!(term, 0);
    }

    #[test]
    fn tls32_minimal_empty_template() {
        let b = TlsDirectoryBuilder::pe32();
        let (data, dir_size) = b.build_section_data(0x2000, 0x0040_0000).expect("build");
        assert_eq!(dir_size as usize, TLS_DIRECTORY32_SIZE);
        let start = u32::from_le_bytes(data[0x00..0x04].try_into().unwrap());
        let end = u32::from_le_bytes(data[0x04..0x08].try_into().unwrap());
        assert_eq!(start, end);
        // Always has null-terminated callback array
        let cbs = u32::from_le_bytes(data[0x0C..0x10].try_into().unwrap());
        let cb_off = (cbs - 0x0040_0000 - 0x2000) as usize;
        let term = u32::from_le_bytes(data[cb_off..cb_off + 4].try_into().unwrap());
        assert_eq!(term, 0);
    }
}
