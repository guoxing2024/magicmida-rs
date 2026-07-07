//! Themida version detection — corresponds to the version-detection logic in
//! `Themida.pas` (`TMInit`, `SelectThemidaSection`, `TMIATFix4`) and
//! `Themida64.pas` (`TMInit`).
//!
//! Provides:
//! - [`ThemidaVersion`] — identifies which major Themida generation was used.
//! - [`detect_version`] — static version fingerprinting from PE headers alone.
//! - [`check_virtualized_oep`] — checks whether the original entry point jumps
//!   straight into the Themida VM (corresponds to `CheckVirtualizedOEP`).
//! - [`is_themida_section`] — heuristic to identify a PE section that belongs to
//!   the Themida protector.

use mida_pe::{PeHeader, PeSection};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Section characteristics mask: the section is executable.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Section characteristics mask: the section is writable.
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Section name used by ancient Themida versions (ca. late 2000s).
/// The trailing space is intentional — the name is exactly 8 bytes.
const ANCIENT_THEMIDA_NAME: &[u8; 8] = b"Themida ";

// ---------------------------------------------------------------------------
// ThemidaVersion
// ---------------------------------------------------------------------------

/// Identifies the major Themida generation used to protect a binary.
///
/// The detection logic follows the Pascal reference:
///
/// | Variant    | Criterion |
/// |------------|-----------|
/// | `Ancient`  | A section is named `"Themida "` (with trailing space). |
/// | `V2`       | The last two sections both have `VirtualSize == 0x1000` |
/// |            | *and* the very last section also has `SizeOfRawData == 0x1000`. |
/// | `V3`       | x64 is always V3; x86 requires runtime detection (see note). |
/// | `Unknown`  | Static analysis cannot distinguish V1 from V3 for an x86 binary. |
///
/// # Runtime vs. static
///
/// V3 detection for x86 relies on observing that `.text` is accessed 3 times
/// without finding the Themida section (`FThemidaV3` in `Themida.pas`). This
/// crate only performs static detection — the runtime debugger (`mida-core`)
/// will update the version later when needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemidaVersion {
    /// Ancient Themida — section name equals `"Themida "`.
    Ancient,
    /// Themida 1.x series.
    V1,
    /// Themida 2.x series — last two sections are 0x1000-sized stubs.
    V2,
    /// Themida 3.x — import addresses use xor+subtraction obfuscation and the
    /// decoding logic is virtualised. Always assumed for x64 targets.
    V3,
    /// Could not determine a specific version from static PE data.
    Unknown,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect the Themida version from static PE headers.
///
/// The `is_64bit` parameter overrides the architecture — for x64 targets this
/// always returns [`ThemidaVersion::V3`] because Themida v2 has no x64 support.
///
/// # Examples
///
/// ```
/// use mida_packers_themida::{detect_version, ThemidaVersion};
/// # use mida_pe::PeHeader;
/// # fn build_pe() -> PeHeader {
/// #     let mut buf = vec![0u8; 512];
/// #     buf[0] = 0x4D; buf[1] = 0x5A;
/// #     buf[60] = 0x40; buf[61] = 0x00; buf[62] = 0x00; buf[63] = 0x00;
/// #     let nt = 0x40;
/// #     buf[nt] = 0x50; buf[nt+1]=0x45;
/// #     let fh = nt+4;
/// #     buf[fh] = 0x64; buf[fh+1] = 0x86; buf[fh+2] = 2; buf[fh+16]=0xF0; buf[fh+18]=0x22;
/// #     let oh = nt+24;
/// #     buf[oh]=0x0B; buf[oh+1]=0x02; buf[oh+16]=0x00; buf[oh+17]=0x30;
/// #     buf[oh+27]=0x40; buf[oh+28]=0x01; buf[oh+32]=0x00; buf[oh+33]=0x10;
/// #     buf[oh+36]=0x00; buf[oh+37]=0x02; buf[oh+56]=0x00; buf[oh+57]=0x50;
/// #     buf[oh+60]=0x00; buf[oh+61]=0x02; buf[oh+108]=0x10;
/// #     // section 1: .text at RVA 0x1000
/// #     let sh1 = nt+24+240;
/// #     buf[sh1]=b'.';buf[sh1+1]=b't';buf[sh1+2]=b'e';buf[sh1+3]=b'x';buf[sh1+4]=b't';
/// #     buf[sh1+8]=0x00;buf[sh1+9]=0x10; buf[sh1+12]=0x00;buf[sh1+13]=0x10;
/// #     buf[sh1+16]=0x00;buf[sh1+17]=0x02; buf[sh1+20]=0x00;buf[sh1+21]=0x02;
/// #     buf[sh1+36]=0x20;buf[sh1+39]=0x60;
/// #     // section 2: stub at RVA 0x2000 (0x1000 sized, like V2)
/// #     let sh2 = sh1+40;
/// #     buf[sh2]=b'.';buf[sh2+1]=b's';buf[sh2+2]=b't';buf[sh2+3]=b'u';buf[sh2+4]=b'b';
/// #     buf[sh2+8]=0x00;buf[sh2+9]=0x10; buf[sh2+12]=0x00;buf[sh2+13]=0x20;
/// #     buf[sh2+16]=0x00;buf[sh2+17]=0x10; buf[sh2+20]=0x00;buf[sh2+21]=0x02;
/// #     buf[sh2+36]=0xC0;buf[sh2+39]=0xE0;
/// #     PeHeader::from_bytes(&buf).unwrap()
/// # }
/// let pe = build_pe();
/// // x64 → always V3
/// assert_eq!(detect_version(&pe, true), ThemidaVersion::V3);
/// // x86 with two 0x1000 stub sections → V2
/// assert_eq!(detect_version(&pe, false), ThemidaVersion::V2);
/// ```
#[must_use]
pub fn detect_version(pe: &PeHeader, is_64bit: bool) -> ThemidaVersion {
    // x64 targets are always V3 — Themida V2 has no x64 support.
    // (Themida64.pas constructor: `FThemidaV3 := True`)
    if is_64bit {
        return ThemidaVersion::V3;
    }

    // Ancient version: any section named exactly "Themida " (8 bytes, trailing space).
    // (Themida.pas → SelectThemidaSection)
    for section in &pe.sections {
        if &section.header.name == ANCIENT_THEMIDA_NAME {
            return ThemidaVersion::Ancient;
        }
    }

    // V2 detection: the last two sections both have VirtualSize == 0x1000,
    // and the very last section also has SizeOfRawData == 0x1000.
    // (Themida.pas → TMInit, FThemidaV2BySections)
    if pe.sections.len() >= 2 {
        let last = &pe.sections[pe.sections.len() - 1];
        let second_last = &pe.sections[pe.sections.len() - 2];
        if last.virtual_size == 0x1000
            && last.raw_size == 0x1000
            && second_last.virtual_size == 0x1000
        {
            return ThemidaVersion::V2;
        }
    }

    // Static analysis alone cannot distinguish V1 from V3 for x86 targets.
    // V3 detection requires runtime heuristics (3 .text accesses without
    // finding the Themida section — see Themida.pas OnHardwareBreakpoint).
    ThemidaVersion::Unknown
}

/// Check whether the original entry point has been virtualised.
///
/// Corresponds to `TTMCommon.CheckVirtualizedOEP` in `ThemidaCommon.pas`.
///
/// The check reads the first 5 bytes at the entry point. If they form a
/// `jmp rel32` (`0xE9`) whose target lands inside a section that looks like a
/// Themida section (per [`is_themida_section`]), the OEP is considered
/// virtualised.
///
/// `entry_point_bytes` should contain at least 5 bytes read from the entry
/// point RVA. Fewer bytes always returns `false`.
///
/// # Examples
///
/// ```
/// use mida_packers_themida::check_virtualized_oep;
/// # use mida_pe::PeHeader;
/// # fn build_pe() -> PeHeader {
/// #     // Builds a PE with .text at 0x1000 (R+X), entry at 0x3000,
/// #     // and a Themida-like section at 0x4000 (R+W+X, large virtual size).
/// #     let mut buf = vec![0u8; 512];
/// #     buf[0]=0x4D;buf[1]=0x5A;buf[60]=0x40;
/// #     let nt=0x40;buf[nt]=0x50;buf[nt+1]=0x45;
/// #     let fh=nt+4;buf[fh]=0x64;buf[fh+1]=0x86;buf[fh+2]=2;buf[fh+16]=0xF0;buf[fh+18]=0x22;
/// #     let oh=nt+24;buf[oh]=0x0B;buf[oh+1]=0x02;buf[oh+16]=0x00;buf[oh+17]=0x30;
/// #     buf[oh+27]=0x40;buf[oh+28]=0x01;buf[oh+32]=0x00;buf[oh+33]=0x10;
/// #     buf[oh+36]=0x00;buf[oh+37]=0x02;buf[oh+56]=0x00;buf[oh+57]=0x60;
/// #     buf[oh+60]=0x00;buf[oh+61]=0x02;buf[oh+108]=0x10;
/// #     // .text at 0x1000, VS=0x1000, RS=0x200
/// #     let s1=nt+24+240;buf[s1]=b'.';buf[s1+1]=b't';buf[s1+2]=b'e';buf[s1+3]=b'x';
/// #     buf[s1+8]=0x00;buf[s1+9]=0x10;buf[s1+12]=0x00;buf[s1+13]=0x10;
/// #     buf[s1+16]=0x00;buf[s1+17]=0x02;buf[s1+20]=0x00;buf[s1+21]=0x02;
/// #     buf[s1+36]=0x20;buf[s1+39]=0x60;
/// #     // Themida-like at 0x4000, VS=0x5000, RS=0x200, R+W+X
/// #     let s2=s1+40;buf[s2]=b'T';buf[s2+1]=b'h';buf[s2+2]=b'e';buf[s2+3]=b'm';
/// #     buf[s2+8]=0x00;buf[s2+9]=0x50;buf[s2+12]=0x00;buf[s2+13]=0x40;
/// #     buf[s2+16]=0x00;buf[s2+17]=0x02;buf[s2+20]=0x00;buf[s2+21]=0x02;
/// #     buf[s2+36]=0x20;buf[s2+39]=0xE0;
/// #     PeHeader::from_bytes(&buf).unwrap()
/// # }
/// let pe = build_pe();
/// // jmp to 0x4000 (inside Themida section) → virtualised
/// let mut bytes = vec![0xE9u8, 0xCF, 0x0F, 0x00, 0x00]; // jmp +0x0FCF → RVA 0x3000+5+0xFCF=0x3FD4
/// # // Actually target should be inside Themida section at 0x4000
/// # bytes = vec![0xE9u8, 0xFB, 0x0F, 0x00, 0x00]; // jmp +0xFFB → RVA 0x3000+5+0xFFB=0x4000
/// assert!(check_virtualized_oep(&pe, &bytes));
/// // Not a jmp instruction → not virtualised
/// assert!(!check_virtualized_oep(&pe, &[0x55, 0x8B, 0xEC, 0x6A, 0xFF]));
/// ```
#[must_use]
pub fn check_virtualized_oep(pe: &PeHeader, entry_point_bytes: &[u8]) -> bool {
    if entry_point_bytes.len() < 5 {
        return false;
    }

    // First instruction must be `jmp rel32` (0xE9).
    if entry_point_bytes[0] != 0xE9 {
        return false;
    }

    // Decode the 32-bit signed displacement (little-endian).
    let displacement = i32::from_le_bytes([
        entry_point_bytes[1],
        entry_point_bytes[2],
        entry_point_bytes[3],
        entry_point_bytes[4],
    ]);

    // Target RVA = entry_point + 5 (length of jmp rel32) + displacement.
    let target_rva = pe
        .entry_point
        .wrapping_add(5)
        .wrapping_add(displacement as u32);

    // If the target lies in a Themida-looking section, the OEP is virtualised.
    pe.get_section_by_rva(target_rva)
        .is_some_and(is_themida_section)
}

/// Heuristically determine whether a PE section belongs to the Themida
/// protector.
///
/// Uses the following signals (any one is sufficient):
///
/// 1. **Name** — the section name contains `"themida"` (case-insensitive).
/// 2. **Empty name + execute + write** — an unnamed section that is both
///    executable and writable is highly suspicious.
/// 3. **Large virtual-size / raw-size ratio** — when `VirtualSize` is more
///    than twice `SizeOfRawData` *and* the section is both executable and
///    writable. This covers compressed/encrypted Themida stubs that expand
///    at run time.
///
/// The heuristics are deliberately loose — it is better to flag a benign
/// section than to miss the actual Themida section during unpacking.
///
/// # Examples
///
/// ```
/// use mida_packers_themida::is_themida_section;
/// use mida_pe::PeSection;
/// use mida_pe::ImageSectionHeader;
/// # // Build a section manually
/// # let mut name = [0u8; 8];
/// # name[0] = b'T'; name[1] = b'h'; name[2] = b'e'; name[3] = b'm';
/// # name[4] = b'i'; name[5] = b'd'; name[6] = b'a';
/// # let decoded = String::from_utf8_lossy(&name[..7]).into_owned();
/// # let header = ImageSectionHeader {
/// #     name, virtual_size: 0x10000, virtual_address: 0x4000,
/// #     size_of_raw_data: 0x200, pointer_to_raw_data: 0x200,
/// #     pointer_to_relocations: 0, pointer_to_linenumbers: 0,
/// #     number_of_relocations: 0, number_of_linenumbers: 0,
/// #     characteristics: 0xE0000020,
/// # };
/// # let section = PeSection {
/// #     header, name: decoded, virtual_address: 0x4000, virtual_size: 0x10000,
/// #     raw_offset: 0x200, raw_size: 0x200, characteristics: 0xE0000020,
/// #     extra_data: None,
/// # };
/// assert!(is_themida_section(&section));
/// ```
#[must_use]
pub fn is_themida_section(section: &PeSection) -> bool {
    // Signal 1: name contains "themida" (case-insensitive).
    if section.name.to_lowercase().contains("themida") {
        return true;
    }

    // Signal 1b: known Themida section names.
    let lower = section.name.to_lowercase();
    if lower.contains(".winlice") || lower.contains(".boot") || lower.contains(".themida") {
        return true;
    }

    let has_execute = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
    let has_write = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;

    // Signal 2: unnamed/empty section with execute + write permissions.
    let is_empty_name = section.name.is_empty()
        || section.name.as_bytes().iter().all(|&b| b == 0);
    if is_empty_name && has_execute && has_write {
        return true;
    }

    // Signal 3: VirtualSize is significantly larger than SizeOfRawData
    // (indicating runtime decompression/decryption) combined with execute +
    // write permissions.
    if section.raw_size > 0
        && section.virtual_size > section.raw_size * 2
        && has_execute
        && has_write
    {
        return true;
    }

    // Signal 4: zero raw size with large virtual size and execute permission.
    // Themida stores its code in memory-only sections (e.g. .winlice).
    if section.raw_size == 0 && section.virtual_size > 0x10000 && has_execute {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
}
