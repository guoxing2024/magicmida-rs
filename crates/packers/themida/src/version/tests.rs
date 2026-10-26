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

// -- measured import-surface fingerprints (2026-10-26 ladder) ----------------

/// Build a minimal PE32 whose import directory really contains `dlls`
/// (name → function names), so `read_import_surface` is exercised on the same
/// byte layout a packer writes.  One section (`.idata`, RVA 0x1000) holds the
/// descriptors, thunk arrays, hint/name entries and DLL names.
fn pe_with_imports(dlls: &[(&str, &[&str])]) -> (PeHeader, Vec<u8>) {
    let n = dlls.len();
    let mut buf = vec![0u8; 0x2400];

    // DOS + PE signature
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let nt = 0x40usize;
    buf[nt..nt + 4].copy_from_slice(b"PE\0\0");

    // COFF file header
    let fh = nt + 4;
    buf[fh..fh + 2].copy_from_slice(&0x14cu16.to_le_bytes()); // i386
    buf[fh + 2..fh + 4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    buf[fh + 16..fh + 18].copy_from_slice(&0xe0u16.to_le_bytes()); // opt size
    buf[fh + 18..fh + 20].copy_from_slice(&0x0102u16.to_le_bytes());

    // Optional header (PE32)
    let oh = nt + 24;
    buf[oh..oh + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    buf[oh + 16..oh + 20].copy_from_slice(&0x1500u32.to_le_bytes()); // EP
    buf[oh + 20..oh + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
    buf[oh + 24..oh + 28].copy_from_slice(&0x2000u32.to_le_bytes()); // BaseOfData
    buf[oh + 28..oh + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    buf[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlign
    buf[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlign
    buf[oh + 56..oh + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    buf[oh + 60..oh + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
    buf[oh + 68..oh + 70].copy_from_slice(&2u16.to_le_bytes()); // Subsystem
    buf[oh + 92..oh + 96].copy_from_slice(&16u32.to_le_bytes()); // NrvaAndSizes
    // DataDirectory[1] = import directory at RVA 0x1000
    let dd = oh + 96;
    buf[dd + 8..dd + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[dd + 12..dd + 16].copy_from_slice(&(20 * (n as u32 + 1)).to_le_bytes());

    // Section header: .idata, RVA 0x1000, file 0x400
    let sh = oh + 0xe0;
    buf[sh..sh + 6].copy_from_slice(b".idata");
    buf[sh + 8..sh + 12].copy_from_slice(&0x2000u32.to_le_bytes()); // VS
    buf[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
    buf[sh + 16..sh + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // RS
    buf[sh + 20..sh + 24].copy_from_slice(&0x400u32.to_le_bytes()); // PR
    buf[sh + 36..sh + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());

    // Body at RVA 0x1000 == file 0x400.
    const BASE: usize = 0x400;
    let mut cursor = BASE + 20 * (n + 1); // after descriptors + terminator
    let mut descriptors = Vec::new();
    for (dll, funcs) in dlls {
        // thunk array: one RVA per function + terminator
        let thunks_rva = 0x1000 + (cursor - BASE) as u32;
        let thunk_count = funcs.len();
        let names_start = cursor + 4 * (thunk_count + 1);
        let mut p = names_start;
        let mut thunk_values = Vec::new();
        for f in *funcs {
            thunk_values.push(0x1000u32 + (p - BASE) as u32);
            buf[p..p + 2].copy_from_slice(&0u16.to_le_bytes()); // hint
            buf[p + 2..p + 2 + f.len()].copy_from_slice(f.as_bytes());
            p += 2 + f.len() + 1;
        }
        let dll_name_at = p;
        buf[p..p + dll.len()].copy_from_slice(dll.as_bytes());
        p += dll.len() + 1;
        // write thunks
        let mut t = cursor;
        for v in &thunk_values {
            buf[t..t + 4].copy_from_slice(&v.to_le_bytes());
            t += 4;
        }
        // t..t+4 already zero (terminator)
        descriptors.push((thunks_rva, 0x1000u32 + (dll_name_at - BASE) as u32, thunks_rva));
        cursor = p;
    }
    // descriptors
    for (i, (oft, name_rva, ft)) in descriptors.iter().enumerate() {
        let d = BASE + 20 * i;
        buf[d..d + 4].copy_from_slice(&oft.to_le_bytes());
        buf[d + 12..d + 16].copy_from_slice(&name_rva.to_le_bytes());
        buf[d + 16..d + 20].copy_from_slice(&ft.to_le_bytes());
    }

    let pe = PeHeader::from_bytes(&buf).expect("fixture must parse");
    (pe, buf)
}

#[test]
fn measured_classic_surface_is_v1() {
    // Measured on Themida 1.1.1.0–1.9.1.0 and WinLicense 1.1.1.0–1.8.9.0.
    let (pe, image) = pe_with_imports(&[
        ("KERNEL32.dll", &["CreateFileA", "ExitProcess"]),
        ("COMCTL32.dll", &["InitCommonControls"]),
    ]);
    assert_eq!(detect_version_with_image(&pe, false, &image), ThemidaVersion::V1);
    // WinLicense 2.0.8.0 carries the same two-DLL shape (CreateFileA+lstrcpy).
    let (pe2, image2) = pe_with_imports(&[
        ("KERNEL32.dll", &["CreateFileA", "lstrcpy"]),
        ("COMCTL32.dll", &["InitCommonControls"]),
    ]);
    assert_eq!(detect_version_with_image(&pe2, false, &image2), ThemidaVersion::V1);
    // Without the image bytes the old behaviour is unchanged.
    assert_eq!(detect_version(&pe, false), ThemidaVersion::Unknown);
}

#[test]
fn measured_secureengine_surface_is_v2() {
    // Measured on WinLicense 2.0.1.0 (SizeofResource) and the 2.0.6.5
    // CISC/RISC examples (lstrlenW / GetProfileStringW).
    for func in ["SizeofResource", "lstrlenW", "GetProfileStringW"] {
        let (pe, image) = pe_with_imports(&[("kernel32.dll", &[func])]);
        assert_eq!(
            detect_version_with_image(&pe, false, &image),
            ThemidaVersion::V2,
            "single-kernel32 surface [{func}] must be V2"
        );
    }
}

#[test]
fn the_v3_x86_shape_is_not_claimed_as_v1_or_v2() {
    // The packed v3 x86 gate sample imports four DLLs with one function each
    // (measured on OUT/x86/x86_c.exe); it must not match either rule.
    let (pe, image) = pe_with_imports(&[
        ("kernel32.dll", &["GetModuleHandleA"]),
        ("GDI32.dll", &["GetDeviceCaps"]),
        ("msvcrt.dll", &["__p__iob"]),
        ("USER32.dll", &["CreateWindowExW"]),
    ]);
    let v = detect_version_with_image(&pe, false, &image);
    assert!(
        v != ThemidaVersion::V1 && v != ThemidaVersion::V2,
        "v3-x86 shape must not match the 1.x/2.x fingerprints, got {v:?}"
    );
}

#[test]
fn import_surface_reader_never_panics_on_garbage() {
    let (pe, _) = pe_with_imports(&[("kernel32.dll", &["Sleep"])]);
    assert!(read_import_surface(&[], &pe).is_none());
    let junk = vec![0xAAu8; 0x600];
    let _ = read_import_surface(&junk, &pe);
    // A PE whose import directory RVA is zero yields None, not a panic.
    // (Zero the RVA before parsing: the walk keys on the parsed header.)
    let (_, mut image_zero) = pe_with_imports(&[("kernel32.dll", &["Sleep"])]);
    let oh = 0x40 + 24;
    image_zero[oh + 96 + 8..oh + 96 + 12].copy_from_slice(&0u32.to_le_bytes());
    let pe_zero = PeHeader::from_bytes(&image_zero).expect("zero-dir fixture must parse");
    assert!(read_import_surface(&image_zero, &pe_zero).is_none());
}
