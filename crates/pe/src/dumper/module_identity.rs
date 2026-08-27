//! Module identity — a canonical, ASLR-stable fingerprint of the target PE.

//!
//! Production `.unwrap()`s are parse invariants (fixed-width slices whose
//! bounds were just validated) (WO-10). Test unwraps are assertions.
#![allow(clippy::unwrap_used)]//! MIDA-SERIAL-14: identity primitive for the policy gate. Bind a
//! `DumpCapturePolicy` to a `ModuleIdentity` so sample-specific RVA policies
//! can never silently apply to a different PE/module/version.
//!
//! Fields are chosen for stability across ASLR (no `image_base`) and
//! non-spoofability (section layout digest). `TimeDateStamp`/`SizeOfImage`
//! are included as primary fields; the canonical section layout digest
//! (name + VirtualAddress + VirtualSize + SizeOfRawData + PointerToRawData +
//! Characteristics, in stable sorted order) is the strongest discriminator.
//!
//! The canonical serialization is deterministic and length-prefixed; equality
//! is field-wise (and digest-equivalent). Missing/invalid sections fail closed.

use sha2::{Digest, Sha256};

use crate::header::PeHeader;

/// Errors constructing a [`ModuleIdentity`] from a PE header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleIdentityError {
    /// The PE has no section table (no stable layout evidence).
    NoSections,
    /// A section's canonical serialization could not be produced (should not
    /// happen for fixed-size fields; kept for fail-closed completeness).
    SectionSerialization(&'static str),
}

impl std::fmt::Display for ModuleIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleIdentityError::NoSections => write!(f, "no section table in PE"),
            ModuleIdentityError::SectionSerialization(why) => {
                write!(f, "section serialization failed: {why}")
            }
        }
    }
}

impl std::error::Error for ModuleIdentityError {}

/// Canonical, ASLR-stable identity of a PE module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleIdentity {
    /// COFF machine (e.g. 0x8664 for x64).
    pub machine: u16,
    /// COFF `TimeDateStamp` (link timestamp; part of the tuple, not sole identity).
    pub time_date_stamp: u32,
    /// Optional header `SizeOfImage`.
    pub size_of_image: u32,
    /// Optional header `CheckSum` (0 for unsigned/ignored linkers; part of tuple).
    pub check_sum: u32,
    /// Canonical SHA-256 (hex) over the sorted, length-prefixed section layout.
    pub section_layout_digest: String,
}

impl ModuleIdentity {
    /// Build a [`ModuleIdentity`] from the current PE header (the single
    /// construction entry point). Fails closed when the section table is empty
    /// or a section cannot be serialized.
    pub fn from_pe_header(pe: &PeHeader) -> Result<Self, ModuleIdentityError> {
        if pe.sections.is_empty() {
            return Err(ModuleIdentityError::NoSections);
        }
        let mut rows = Vec::with_capacity(pe.sections.len());
        for (i, s) in pe.sections.iter().enumerate() {
            rows.push(canonical_section_row(i, s)?);
        }
        // Stable order: sort by (VirtualAddress, name) so section order in the
        // PE table cannot change the digest. Duplicate VA is impossible for a
        // valid PE; if it somehow occurs the (name,index) tiebreak still keeps
        // the digest deterministic.
        // Stable order: sort by (VirtualAddress, name). Section table order must
        // not affect the digest (ASLR/linker reordering invariance).
        rows.sort_by(|a, b| {
            let ava = u32::from_le_bytes(a[4..8].try_into().unwrap());
            let bva = u32::from_le_bytes(b[4..8].try_into().unwrap());
            ava.cmp(&bva).then_with(|| a.cmp(b))
        });
        let mut h = Sha256::new();
        h.update(b"mida.module-identity/section-layout/v1\0");
        for r in &rows {
            h.update(&r);
        }
        let section_layout_digest = format!("{:x}", h.finalize());
        Ok(Self {
            machine: pe.nt_headers.file_header.machine,
            time_date_stamp: pe.nt_headers.file_header.time_date_stamp,
            size_of_image: pe.nt_headers.optional_header.size_of_image,
            check_sum: pe.nt_headers.optional_header.check_sum,
            section_layout_digest,
        })
    }

    /// Canonical deterministic serialization (length-prefixed, fixed field order).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.section_layout_digest.len());
        push_u16(&mut out, self.machine);
        push_u32(&mut out, self.time_date_stamp);
        push_u32(&mut out, self.size_of_image);
        push_u32(&mut out, self.check_sum);
        push_str(&mut out, &self.section_layout_digest);
        out
    }

    /// SHA-256 (hex) over [`Self::canonical_bytes`]. This is the digest used
    /// in policy binding / manifest persistence; it is not the section-layout
    /// digest (which is one component field).
    pub fn digest_hex(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"mida.module-identity/v1\0");
        h.update(self.canonical_bytes());
        format!("{:x}", h.finalize())
    }

    /// Stable JSON representation (deterministic key order) for the manifest.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"machine\":{},\"time_date_stamp\":{},\"size_of_image\":{},\"check_sum\":{},\"section_layout_digest\":\"{}\"}}",
            self.machine,
            self.time_date_stamp,
            self.size_of_image,
            self.check_sum,
            json_escape(&self.section_layout_digest)
        )
    }
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Canonical, length-prefixed row for one section (stable fields only).
fn canonical_section_row(
    _idx: usize,
    s: &crate::header::PeSection,
) -> Result<Vec<u8>, ModuleIdentityError> {
    let mut row = Vec::with_capacity(64);
    row.extend_from_slice(b"sec\0");
    push_str(&mut row, &s.name);
    push_u32(&mut row, s.virtual_address);
    push_u32(&mut row, s.virtual_size);
    push_u32(&mut row, s.raw_size);
    push_u32(&mut row, s.raw_offset);
    push_u32(&mut row, s.characteristics);
    // No index tiebreak: section ORDER in the PE table must not change the
    // digest (the caller sorts rows before hashing). Duplicate (VA, name) rows
    // still produce identical bytes, which is deterministic.
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PeHeader;

    /// Minimal synthetic PE32+ with two sections, built at exact header offsets
    /// matching `parse_optional_header_64`. Returns parsed [`PeHeader`].
    fn synthetic_pe(
        machine: u16,
        stamp: u32,
        size_image: u32,
        csum: u32,
        image_base: u64,
    ) -> PeHeader {
        PeHeader::from_bytes(&tiny_pe_bytes(machine, stamp, size_image, csum, image_base)).unwrap()
    }

    fn tiny_pe_bytes(
        machine: u16,
        stamp: u32,
        size_image: u32,
        csum: u32,
        image_base: u64,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        // DOS header (64 bytes): "MZ" + e_lfanew at 0x3c = 0x40.
        b.extend_from_slice(b"MZ");
        b.extend_from_slice(&[0u8; 58]);
        b.extend_from_slice(&0x40u32.to_le_bytes());
        // NT headers at 0x40: "PE\0\0"
        b.extend_from_slice(b"PE\0\0");
        // COFF file header (20 bytes).
        b.extend_from_slice(&machine.to_le_bytes());
        b.extend_from_slice(&2u16.to_le_bytes()); // number_of_sections
        b.extend_from_slice(&stamp.to_le_bytes()); // TimeDateStamp
        b.extend_from_slice(&0u32.to_le_bytes()); // ptr_to_symtab
        b.extend_from_slice(&0u32.to_le_bytes()); // num_symbols
        b.extend_from_slice(&0xf0u16.to_le_bytes()); // size_of_optional_header = 240
        b.extend_from_slice(&0x0102u16.to_le_bytes()); // characteristics
                                                       // Optional header PE32+ (240 bytes). Fields at exact offsets.
        b.extend_from_slice(&0x20bu16.to_le_bytes()); // [0] magic
        b.extend_from_slice(&[0u8; 2]); // [2] linker versions
        b.extend_from_slice(&0x1000u32.to_le_bytes()); // [4] size_of_code
        b.extend_from_slice(&0x2000u32.to_le_bytes()); // [8] size_of_initialized_data
        b.extend_from_slice(&0u32.to_le_bytes()); // [12] size_of_uninitialized_data
        b.extend_from_slice(&0x1000u32.to_le_bytes()); // [16] address_of_entry_point
        b.extend_from_slice(&0x1000u32.to_le_bytes()); // [20] base_of_code
        b.extend_from_slice(&image_base.to_le_bytes()); // [24] image_base u64
        b.extend_from_slice(&0x1000u32.to_le_bytes()); // [32] section_alignment
        b.extend_from_slice(&0x200u32.to_le_bytes()); // [36] file_alignment
        b.extend_from_slice(&[0u8; 16]); // [40..56) versions + win32
        b.extend_from_slice(&size_image.to_le_bytes()); // [56] size_of_image
        b.extend_from_slice(&0x400u32.to_le_bytes()); // [60] size_of_headers
        b.extend_from_slice(&csum.to_le_bytes()); // [64] check_sum
        b.extend_from_slice(&[0u8; 4]); // [68] subsystem + dll_characteristics
        b.extend_from_slice(&[0u8; 32]); // [72..104) stack/heap reserve/commit
        b.extend_from_slice(&0u32.to_le_bytes()); // [104] loader_flags
        b.extend_from_slice(&16u32.to_le_bytes()); // [108] number_of_rva_and_sizes
        b.extend_from_slice(&[0u8; 128]); // [112..240) data directories (16*8)
        assert_eq!(b.len(), 0x40 + 4 + 20 + 240);
        // Section 1: .text (40 bytes)
        b.extend_from_slice(b".text\0\0\0");
        b.extend_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
        b.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        b.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        b.extend_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        b.extend_from_slice(&[0u8; 12]); // reloc/linenum
        b.extend_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics
                                                           // Section 2: .data (40 bytes)
        b.extend_from_slice(b".data\0\0\0");
        b.extend_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        b.extend_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        b.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        b.extend_from_slice(&0x600u32.to_le_bytes()); // PointerToRawData
        b.extend_from_slice(&[0u8; 12]);
        b.extend_from_slice(&0xc0000040u32.to_le_bytes()); // Characteristics
        b
    }

    #[test]
    fn same_pe_identity_equal() {
        let a = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        let b = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.digest_hex(), b.digest_hex());
    }

    #[test]
    fn image_base_differs_but_identity_equal() {
        // ASLR invariance: image_base is deliberately excluded from identity.
        let a = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        let b = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x180000000,
        ))
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn timestamp_differs_not_equal() {
        let a = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        let b = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e101,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn size_of_image_differs_not_equal() {
        let a = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        let b = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3001,
            0,
            0x140000000,
        ))
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn section_layout_change_not_equal() {
        let mut pe = synthetic_pe(0x8664, 0x5f5e100, 0x3000, 0, 0x140000000);
        pe.sections[0].virtual_size = 0x200;
        let a = ModuleIdentity::from_pe_header(&pe).unwrap();
        let b = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn section_order_does_not_change_digest() {
        let a = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        let mut pe2 = synthetic_pe(0x8664, 0x5f5e100, 0x3000, 0, 0x140000000);
        pe2.sections.swap(0, 1);
        let b = ModuleIdentity::from_pe_header(&pe2).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn no_sections_fails_closed() {
        let mut pe = synthetic_pe(0x8664, 0x5f5e100, 0x3000, 0, 0x140000000);
        pe.sections.clear();
        let e = ModuleIdentity::from_pe_header(&pe).unwrap_err();
        assert_eq!(e, ModuleIdentityError::NoSections);
    }

    #[test]
    fn json_round_trip_stable() {
        let a = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        let j = a.to_json();
        assert!(j.contains("\"machine\":34404")); // 0x8664
        assert!(j.contains("section_layout_digest"));
        let b = ModuleIdentity::from_pe_header(&synthetic_pe(
            0x8664,
            0x5f5e100,
            0x3000,
            0,
            0x140000000,
        ))
        .unwrap();
        assert_eq!(j, b.to_json());
    }
}
