//! Tests for [`super`] version detection and section heuristics.

use super::*;

/// Build a minimal PE64 with two sections and an entry point outside .text.
fn make_packed_pe64() -> PeHeader {
    let mut buf = vec![0u8; 512];

    // DOS
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[60] = 0x40;
    let nt = 0x40;

    // PE sig
    buf[nt] = 0x50;
    buf[nt + 1] = 0x45;

    // File header
    let fh = nt + 4;
    buf[fh] = 0x64; // AMD64
    buf[fh + 1] = 0x86;
    buf[fh + 2] = 2; // 2 sections
    buf[fh + 16] = 0xF0; // SizeOfOptionalHeader
    buf[fh + 18] = 0x22;

    // Optional header (PE32+)
    let oh = nt + 24;
    buf[oh] = 0x0B;
    buf[oh + 1] = 0x02; // Magic = 0x20B
    buf[oh + 16] = 0x00;
    buf[oh + 17] = 0x30; // EntryPoint = 0x3000 (outside .text!)
    buf[oh + 27] = 0x40;
    buf[oh + 28] = 0x01; // ImageBase hi
    buf[oh + 32] = 0x00;
    buf[oh + 33] = 0x10; // SectionAlignment = 0x1000
    buf[oh + 36] = 0x00;
    buf[oh + 37] = 0x02; // FileAlignment = 0x200
    buf[oh + 56] = 0x00;
    buf[oh + 57] = 0x60; // SizeOfImage
    buf[oh + 60] = 0x00;
    buf[oh + 61] = 0x02;
    buf[oh + 108] = 0x10;

    // Section 1: .text at RVA 0x1000, VS=0x1000, RS=0x200
    let s1 = nt + 24 + 240;
    buf[s1] = b'.';
    buf[s1 + 1] = b't';
    buf[s1 + 2] = b'e';
    buf[s1 + 3] = b'x';
    buf[s1 + 4] = b't';
    buf[s1 + 8] = 0x00;
    buf[s1 + 9] = 0x10; // VirtualSize = 0x1000
    buf[s1 + 12] = 0x00;
    buf[s1 + 13] = 0x10; // VirtualAddress = 0x1000
    buf[s1 + 16] = 0x00;
    buf[s1 + 17] = 0x02; // SizeOfRawData = 0x200
    buf[s1 + 20] = 0x00;
    buf[s1 + 21] = 0x02;
    buf[s1 + 36] = 0x20; // Characteristics = CODE | EXECUTE | READ
    buf[s1 + 39] = 0x60;

    // Section 2 at RVA 0x4000 (first section entry after .text)
    // VS=0x5000, RS=0x200 — looks like Themida
    let s2 = s1 + 40;
    buf[s2] = b'T';
    buf[s2 + 1] = b'h';
    buf[s2 + 2] = b'e';
    buf[s2 + 3] = b'm';
    buf[s2 + 4] = b'i';
    buf[s2 + 5] = b'd';
    buf[s2 + 6] = b'a';
    buf[s2 + 8] = 0x00;
    buf[s2 + 9] = 0x50; // VirtualSize = 0x5000
    buf[s2 + 12] = 0x00;
    buf[s2 + 13] = 0x40; // VirtualAddress = 0x4000
    buf[s2 + 16] = 0x00;
    buf[s2 + 17] = 0x02; // SizeOfRawData = 0x200
    buf[s2 + 20] = 0x00;
    buf[s2 + 21] = 0x02;
    buf[s2 + 36] = 0x20; // CODE | EXECUTE | READ | WRITE
    buf[s2 + 39] = 0xE0;

    PeHeader::from_bytes(&buf).unwrap()
}

/// Build a minimal PE32 with the "Themida " section name for Ancient detection.
fn make_ancient_pe32() -> PeHeader {
    let mut buf = vec![0u8; 512];

    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[60] = 0x40;
    let nt = 0x40;

    buf[nt] = 0x50;
    buf[nt + 1] = 0x45;

    let fh = nt + 4;
    buf[fh] = 0x4C;
    buf[fh + 1] = 0x01; // i386
    buf[fh + 2] = 2; // 2 sections
    buf[fh + 16] = 0xE0; // SizeOfOptionalHeader = 0xE0 (PE32)
    buf[fh + 18] = 0x22;

    let oh = nt + 24;
    buf[oh] = 0x0B;
    buf[oh + 1] = 0x01; // PE32 magic
    buf[oh + 16] = 0x00;
    buf[oh + 17] = 0x30; // EntryPoint = 0x3000
    buf[oh + 28] = 0x00;
    buf[oh + 29] = 0x40; // ImageBase = 0x400000
    buf[oh + 32] = 0x00;
    buf[oh + 33] = 0x10;
    buf[oh + 36] = 0x00;
    buf[oh + 37] = 0x02;
    buf[oh + 56] = 0x00;
    buf[oh + 57] = 0x60;
    buf[oh + 60] = 0x00;
    buf[oh + 61] = 0x02;
    buf[oh + 92] = 0x10; // NumberOfRvaAndSizes

    // Section 1: .text
    let s1 = nt + 24 + 224; // PE32 optional header is 224 bytes
    buf[s1] = b'.';
    buf[s1 + 1] = b't';
    buf[s1 + 2] = b'e';
    buf[s1 + 3] = b'x';
    buf[s1 + 4] = b't';
    buf[s1 + 8] = 0x00;
    buf[s1 + 9] = 0x10;
    buf[s1 + 12] = 0x00;
    buf[s1 + 13] = 0x10;
    buf[s1 + 16] = 0x00;
    buf[s1 + 17] = 0x02;
    buf[s1 + 20] = 0x00;
    buf[s1 + 21] = 0x02;
    buf[s1 + 36] = 0x20;
    buf[s1 + 39] = 0x60;

    // Section 2: "Themida " (with trailing space)
    let s2 = s1 + 40;
    buf[s2] = b'T';
    buf[s2 + 1] = b'h';
    buf[s2 + 2] = b'e';
    buf[s2 + 3] = b'm';
    buf[s2 + 4] = b'i';
    buf[s2 + 5] = b'd';
    buf[s2 + 6] = b'a';
    buf[s2 + 7] = b' '; // trailing space!
    buf[s2 + 8] = 0x00;
    buf[s2 + 9] = 0x50;
    buf[s2 + 12] = 0x00;
    buf[s2 + 13] = 0x40;
    buf[s2 + 16] = 0x00;
    buf[s2 + 17] = 0x02;
    buf[s2 + 20] = 0x00;
    buf[s2 + 21] = 0x02;
    buf[s2 + 36] = 0x20;
    buf[s2 + 39] = 0xE0;

    PeHeader::from_bytes(&buf).unwrap()
}

// -- detect_version --------------------------------------------------

#[test]
fn detect_v3_for_x64() {
    let pe = make_packed_pe64();
    assert_eq!(detect_version(&pe, true), ThemidaVersion::V3);
}

#[test]
fn detect_ancient_by_section_name() {
    let pe = make_ancient_pe32();
    assert_eq!(detect_version(&pe, false), ThemidaVersion::Ancient);
}

#[test]
fn detect_unknown_when_no_signal() {
    let pe = make_packed_pe64();
    // x86 with a normal-looking second section → Unknown
    // (second section is "Themida" without trailing space, not matching V2 pattern)
    assert_eq!(detect_version(&pe, false), ThemidaVersion::Unknown);
}

// -- check_virtualized_oep -------------------------------------------

#[test]
fn oep_not_virtualised_short_bytes() {
    let pe = make_packed_pe64();
    assert!(!check_virtualized_oep(&pe, &[0xE9]));
    assert!(!check_virtualized_oep(&pe, &[]));
}

#[test]
fn oep_not_virtualised_no_jmp() {
    let pe = make_packed_pe64();
    // "push ebp; mov ebp, esp" — normal function prologue
    assert!(!check_virtualized_oep(&pe, &[0x55, 0x8B, 0xEC, 0x6A, 0xFF]));
}

#[test]
fn oep_virtualised_jmp_to_themida_section() {
    let pe = make_packed_pe64();
    // EP = 0x3000; jmp +0x0FFB → target = 0x3000 + 5 + 0x0FFB = 0x4000
    // 0x4000 is inside the "Themida" section (RVA 0x4000, VS=0x5000)
    let bytes = [0xE9u8, 0xFB, 0x0F, 0x00, 0x00];
    assert!(check_virtualized_oep(&pe, &bytes));
}

#[test]
fn oep_not_virtualised_jmp_to_text() {
    let pe = make_packed_pe64();
    // EP = 0x3000; jmp +0xE5FB → target = 0x3000 + 5 + (-0x1A05) = ?
    // Let's compute: jmp backwards into .text (0x1000)
    // .text is at RVA 0x1000. From 0x3005, we need -0x2005 to reach 0x1000.
    // -0x2005 in little-endian i32: 0xFFFFDFFB
    let bytes = [0xE9u8, 0xFB, 0xDF, 0xFF, 0xFF];
    assert!(!check_virtualized_oep(&pe, &bytes));
}

// -- is_themida_section ----------------------------------------------

#[test]
fn themida_section_by_name_contains() {
    let pe = make_packed_pe64();
    let s = &pe.sections[1];
    assert_eq!(s.name, "Themida");
    assert!(is_themida_section(s));
}

#[test]
fn themida_section_case_insensitive() {
    let pe = make_packed_pe64();
    // Build a section with name "ThEmIdA"
    let mut s = pe.sections[1].clone();
    // The raw header name is "Themida\0" — rename to mixed case
    let name_bytes = b"ThEmIdA\0";
    s.header.name.copy_from_slice(name_bytes);
    // We need to rebuild the name string. Use the public decode function
    // which isn't pub... let's just set the string directly for the test.
    s.name = "ThEmIdA".to_string();
    assert!(is_themida_section(&s));
}

#[test]
fn themida_section_by_exec_write_empty_name() {
    // Simulate a section with empty name, exec+write
    let name = [0u8; 8];
    let decoded = String::new(); // empty name from all-null bytes
    let header = mida_pe::ImageSectionHeader {
        name,
        virtual_size: 0x1000,
        virtual_address: 0x4000,
        size_of_raw_data: 0x200,
        pointer_to_raw_data: 0x200,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | 0x20,
    };
    let section = mida_pe::PeSection {
        header,
        name: decoded,
        virtual_address: 0x4000,
        virtual_size: 0x1000,
        raw_offset: 0x200,
        raw_size: 0x200,
        characteristics: header.characteristics,
        extra_data: None,
    };
    assert!(is_themida_section(&section));
}

#[test]
fn not_themida_section_normal_text() {
    let pe = make_packed_pe64();
    // .text section — only execute, no write, named ".text"
    let s = &pe.sections[0];
    assert_eq!(s.name, ".text");
    assert!(!is_themida_section(s));
}

#[test]
fn themida_section_large_vs_ratio_with_exec_write() {
    let mut name = [0u8; 8];
    name[0] = b'.';
    name[1] = b's';
    name[2] = b't';
    name[3] = b'u';
    name[4] = b'b';
    let header = mida_pe::ImageSectionHeader {
        name,
        virtual_size: 0x10000, // 64 KiB
        virtual_address: 0x5000,
        size_of_raw_data: 0x200, // 512 bytes — 128× ratio!
        pointer_to_raw_data: 0x200,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | 0x20,
    };
    let section = mida_pe::PeSection {
        header,
        name: ".stub".to_string(),
        virtual_address: 0x5000,
        virtual_size: 0x10000,
        raw_offset: 0x200,
        raw_size: 0x200,
        characteristics: header.characteristics,
        extra_data: None,
    };
    assert!(is_themida_section(&section));
}

#[test]
fn not_themida_section_bss_like() {
    // .bss-like: large VS, zero RS, but without execute — shouldn't match
    let mut name = [0u8; 8];
    name[0] = b'.';
    name[1] = b'b';
    name[2] = b's';
    name[3] = b's';
    let header = mida_pe::ImageSectionHeader {
        name,
        virtual_size: 0x10000,
        virtual_address: 0x5000,
        size_of_raw_data: 0, // zero raw size is common for .bss
        pointer_to_raw_data: 0,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: IMAGE_SCN_MEM_WRITE | 0x40, // write, no execute
    };
    let section = mida_pe::PeSection {
        header,
        name: ".bss".to_string(),
        virtual_address: 0x5000,
        virtual_size: 0x10000,
        raw_offset: 0,
        raw_size: 0,
        characteristics: header.characteristics,
        extra_data: None,
    };
    assert!(!is_themida_section(&section));
}
