//! Tests for [`super::PeHeader`] parsing and lookups.

use super::*;

#[test]
fn parse_pe64_round_trip() {
    let data = make_minimal_pe64();
    let pe = PeHeader::from_bytes(&data).expect("should parse PE64 header");

    assert!(pe.is_64bit);
    assert_eq!(pe.dos_header.e_magic, 0x5A4D);
    assert_eq!(pe.nt_headers.signature, 0x00004550);
    assert_eq!(pe.nt_headers.optional_header.magic, 0x020B);
    assert_eq!(pe.image_base, 0x140000000);
    assert_eq!(pe.entry_point, 0x1000);
    assert_eq!(pe.file_alignment, 0x200);
    assert_eq!(pe.section_alignment, 0x1000);
    assert_eq!(pe.sections.len(), 1);
    assert_eq!(pe.sections[0].name, ".text");
    assert_eq!(pe.sections[0].virtual_address, 0x1000);
    assert_eq!(pe.sections[0].raw_offset, 0x200);
}

#[test]
fn get_section_by_rva() {
    let data = make_minimal_pe64();
    let pe = PeHeader::from_bytes(&data).unwrap();

    // The .text section covers RVA 0x1000..0x2000
    let s = pe.get_section_by_rva(0x1000).unwrap();
    assert_eq!(s.name, ".text");

    // Pascal logic: VirtualAddress + VirtualSize > V,
    // so RVAs below VirtualAddress are still matched by the first section.
    // RVA 0x2000 exactly at the boundary → None
    assert!(pe.get_section_by_rva(0x2000).is_none());
}

#[test]
fn rva_offset_conversion() {
    let data = make_minimal_pe64();
    let pe = PeHeader::from_bytes(&data).unwrap();

    // .text: RVA 0x1000 ↔ Offset 0x200
    let offset = pe.rva_to_offset(0x1000).unwrap();
    assert_eq!(offset, 0x200);

    let rva = pe.offset_to_rva(0x200).unwrap();
    assert_eq!(rva, 0x1000);
}

#[test]
fn rva_offset_not_found() {
    let data = make_minimal_pe64();
    let pe = PeHeader::from_bytes(&data).unwrap();

    assert!(pe.rva_to_offset(0).is_none());
    assert!(pe.offset_to_rva(0).is_none());
}

#[test]
fn invalid_dos_signature() {
    let buf = vec![0u8; 128];
    let err = PeHeader::from_bytes(&buf).unwrap_err();
    assert!(matches!(err, PeError::InvalidDosSignature));
}

#[test]
fn buffer_too_small() {
    let buf = vec![0x4Du8, 0x5A]; // "MZ" only
    let err = PeHeader::from_bytes(&buf).unwrap_err();
    assert!(matches!(err, PeError::BufferTooSmall(..)));
}
