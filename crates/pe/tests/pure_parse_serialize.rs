//! R1-B: pure PE parse + serialize offline tests (no Win32).
//!
//! Workspace hygiene forbids checked-in PE image binaries under fixtures
//! (`pe_image_content`). Synthetic PE buffers are built in-process so tests
//! stay offline and artifact-policy clean.

use mida_pe::{PeError, PeHeader};

const FA: u32 = 0x200;
const SA: u32 = 0x1000;

#[derive(Clone, Copy)]
enum PeKind {
    Pe32,
    Pe32Plus,
}

/// Minimal valid PE image used as an offline fixture substitute.
fn build_minimal_pe(kind: PeKind) -> Vec<u8> {
    let e_lfanew: u32 = 0x80;
    let (magic, machine, opt_size, image_base_u64, chars) = match kind {
        PeKind::Pe32 => (0x10Bu16, 0x014Cu16, 0xE0u16, 0x0040_0000u64, 0x0102u16),
        PeKind::Pe32Plus => (
            0x20Bu16,
            0x8664u16,
            0xF0u16,
            0x0000_0140_0000_0000u64,
            0x0022u16,
        ),
    };

    let nt_size = 4usize + 20 + opt_size as usize;
    let headers_end = e_lfanew as usize + nt_size + 40; // one section
    let size_of_headers = (headers_end as u32).div_ceil(FA) * FA;
    let text_raw = FA;
    let total = size_of_headers + text_raw;
    let mut buf = vec![0u8; total as usize];

    // DOS
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[60..64].copy_from_slice(&e_lfanew.to_le_bytes());

    let nt = e_lfanew as usize;
    buf[nt..nt + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());

    let fh = nt + 4;
    buf[fh..fh + 2].copy_from_slice(&machine.to_le_bytes());
    buf[fh + 2..fh + 4].copy_from_slice(&1u16.to_le_bytes()); // sections
    buf[fh + 16..fh + 18].copy_from_slice(&opt_size.to_le_bytes());
    buf[fh + 18..fh + 20].copy_from_slice(&chars.to_le_bytes());

    let oh = fh + 20;
    buf[oh..oh + 2].copy_from_slice(&magic.to_le_bytes());
    // AddressOfEntryPoint
    buf[oh + 16..oh + 20].copy_from_slice(&SA.to_le_bytes());
    // BaseOfCode
    buf[oh + 20..oh + 24].copy_from_slice(&SA.to_le_bytes());

    match kind {
        PeKind::Pe32 => {
            // BaseOfData
            buf[oh + 24..oh + 28].copy_from_slice(&0u32.to_le_bytes());
            buf[oh + 28..oh + 32].copy_from_slice(&(image_base_u64 as u32).to_le_bytes());
            buf[oh + 32..oh + 36].copy_from_slice(&SA.to_le_bytes());
            buf[oh + 36..oh + 40].copy_from_slice(&FA.to_le_bytes());
            // SizeOfImage / SizeOfHeaders
            buf[oh + 56..oh + 60].copy_from_slice(&(SA * 2).to_le_bytes());
            buf[oh + 60..oh + 64].copy_from_slice(&size_of_headers.to_le_bytes());
            // Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI
            buf[oh + 68..oh + 70].copy_from_slice(&3u16.to_le_bytes());
            // NumberOfRvaAndSizes = 16
            buf[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes());
        }
        PeKind::Pe32Plus => {
            buf[oh + 24..oh + 32].copy_from_slice(&image_base_u64.to_le_bytes());
            buf[oh + 32..oh + 36].copy_from_slice(&SA.to_le_bytes());
            buf[oh + 36..oh + 40].copy_from_slice(&FA.to_le_bytes());
            buf[oh + 56..oh + 60].copy_from_slice(&(SA * 2).to_le_bytes());
            buf[oh + 60..oh + 64].copy_from_slice(&size_of_headers.to_le_bytes());
            buf[oh + 68..oh + 70].copy_from_slice(&3u16.to_le_bytes());
            buf[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes());
        }
    }

    let sh = oh + opt_size as usize;
    // .text
    buf[sh..sh + 5].copy_from_slice(b".text");
    buf[sh + 8..sh + 12].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
    buf[sh + 12..sh + 16].copy_from_slice(&SA.to_le_bytes());
    buf[sh + 16..sh + 20].copy_from_slice(&text_raw.to_le_bytes());
    buf[sh + 20..sh + 24].copy_from_slice(&size_of_headers.to_le_bytes());
    // CODE | EXECUTE | READ
    buf[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Distinct payload marker at start of .text raw
    let raw = size_of_headers as usize;
    buf[raw] = 0x90; // nop
    buf[raw + 1] = 0xC3; // ret

    buf
}

fn assert_core_fields(pe: &PeHeader, kind: PeKind) {
    match kind {
        PeKind::Pe32 => {
            assert!(!pe.is_64bit);
            assert_eq!(pe.nt_headers.optional_header.magic, 0x10B);
            assert_eq!(pe.image_base, 0x0040_0000);
            assert_eq!(pe.nt_headers.optional_header.base_of_data, Some(0));
        }
        PeKind::Pe32Plus => {
            assert!(pe.is_64bit);
            assert_eq!(pe.nt_headers.optional_header.magic, 0x20B);
            assert_eq!(pe.image_base, 0x0000_0140_0000_0000);
            assert_eq!(pe.nt_headers.optional_header.base_of_data, None);
        }
    }
    assert_eq!(pe.dos_header.e_magic, 0x5A4D);
    assert_eq!(pe.nt_headers.signature, 0x0000_4550);
    assert_eq!(pe.entry_point, SA);
    assert_eq!(pe.file_alignment, FA);
    assert_eq!(pe.section_alignment, SA);
    assert_eq!(pe.sections.len(), 1);
    assert_eq!(pe.sections[0].name, ".text");
    assert_eq!(pe.sections[0].virtual_address, SA);
    assert_eq!(pe.sections[0].raw_size, FA);
}

#[test]
fn parse_pe32_and_pe32_plus_from_bytes() {
    for kind in [PeKind::Pe32, PeKind::Pe32Plus] {
        let data = build_minimal_pe(kind);
        let pe = PeHeader::from_bytes(&data).expect("parse synthetic PE");
        assert_core_fields(&pe, kind);
        assert_eq!(
            pe.sections[0].raw_offset,
            pe.nt_headers.optional_header.size_of_headers
        );
    }
}

#[test]
fn rva_offset_round_trip_and_bounds() {
    let data = build_minimal_pe(PeKind::Pe32Plus);
    let pe = PeHeader::from_bytes(&data).unwrap();
    let raw = pe.sections[0].raw_offset;
    let va = pe.sections[0].virtual_address;

    assert_eq!(pe.rva_to_offset(va), Some(raw));
    assert_eq!(pe.offset_to_rva(raw), Some(va));
    assert_eq!(pe.rva_to_offset(va + 0x10), Some(raw + 0x10));
    assert_eq!(pe.offset_to_rva(raw + 0x10), Some(va + 0x10));

    // End exclusive
    assert!(pe.rva_to_offset(va + pe.sections[0].virtual_size).is_none());
    assert!(pe.offset_to_rva(raw + pe.sections[0].raw_size).is_none());
    assert!(pe.rva_to_offset(0).is_none());
}

#[test]
fn overflow_hostile_section_ranges_do_not_wrap_match() {
    let data = build_minimal_pe(PeKind::Pe32Plus);
    let mut pe = PeHeader::from_bytes(&data).unwrap();
    // Hostile: virtual_address + virtual_size wraps in wrapping u32 math.
    pe.sections[0].virtual_address = 0xFFFF_F000;
    pe.sections[0].virtual_size = 0x2000;
    pe.sections[0].header.virtual_address = 0xFFFF_F000;
    pe.sections[0].header.virtual_size = 0x2000;
    pe.sections[0].raw_offset = 0xFFFF_F000;
    pe.sections[0].raw_size = 0x2000;
    pe.sections[0].header.pointer_to_raw_data = 0xFFFF_F000;
    pe.sections[0].header.size_of_raw_data = 0x2000;

    // Checked math must not match low RVAs/offsets via wrap.
    assert!(pe.rva_to_offset(0x10).is_none());
    assert!(pe.offset_to_rva(0x10).is_none());
    assert!(pe.get_section_by_rva(0x10).is_none());
}

#[test]
fn serialize_headers_round_trip_pe32_plus() {
    let data = build_minimal_pe(PeKind::Pe32Plus);
    let pe = PeHeader::from_bytes(&data).unwrap();
    let nt = pe.serialize_headers().expect("serialize");
    // splice at e_lfanew into a fresh DOS stub buffer
    let mut rebuilt = data.clone();
    let lf = pe.dos_header.e_lfanew as usize;
    assert!(lf + nt.len() <= rebuilt.len() || nt.len() >= 0x200);
    if lf + nt.len() > rebuilt.len() {
        rebuilt.resize(lf + nt.len(), 0);
    }
    rebuilt[lf..lf + nt.len()].copy_from_slice(&nt);

    let pe2 = PeHeader::from_bytes(&rebuilt).expect("reparse after serialize");
    assert_core_fields(&pe2, PeKind::Pe32Plus);
    assert_eq!(
        pe2.sections[0].virtual_address,
        pe.sections[0].virtual_address
    );
    assert_eq!(pe2.sections[0].raw_offset, pe.sections[0].raw_offset);
    assert_eq!(
        pe2.sections[0].characteristics,
        pe.sections[0].characteristics
    );
    assert_eq!(
        pe2.nt_headers.optional_header.size_of_image,
        pe.nt_headers.optional_header.size_of_image
    );
}

#[test]
fn serialize_headers_round_trip_pe32() {
    let data = build_minimal_pe(PeKind::Pe32);
    let pe = PeHeader::from_bytes(&data).unwrap();
    let nt = pe.serialize_headers().expect("serialize");
    let mut rebuilt = data.clone();
    let lf = pe.dos_header.e_lfanew as usize;
    if lf + nt.len() > rebuilt.len() {
        rebuilt.resize(lf + nt.len(), 0);
    }
    rebuilt[lf..lf + nt.len()].copy_from_slice(&nt);

    let pe2 = PeHeader::from_bytes(&rebuilt).expect("reparse after serialize");
    assert_core_fields(&pe2, PeKind::Pe32);
    assert_eq!(
        pe2.nt_headers.optional_header.base_of_data,
        pe.nt_headers.optional_header.base_of_data
    );
}

#[test]
fn serialize_headers_is_deterministic() {
    let pe = PeHeader::from_bytes(&build_minimal_pe(PeKind::Pe32Plus)).unwrap();
    let a = pe.serialize_headers().unwrap();
    let b = pe.serialize_headers().unwrap();
    assert_eq!(a, b);
}

#[test]
fn invalid_inputs_reject_cleanly() {
    assert!(matches!(
        PeHeader::from_bytes(&[0u8; 128]),
        Err(PeError::InvalidDosSignature)
    ));
    assert!(matches!(
        PeHeader::from_bytes(&[0x4D, 0x5A]),
        Err(PeError::BufferTooSmall(..))
    ));

    let mut bad = build_minimal_pe(PeKind::Pe32Plus);
    // Corrupt PE signature
    let lf = u32::from_le_bytes(bad[60..64].try_into().unwrap()) as usize;
    bad[lf] = 0;
    assert!(matches!(
        PeHeader::from_bytes(&bad),
        Err(PeError::InvalidPeSignature)
    ));
}
