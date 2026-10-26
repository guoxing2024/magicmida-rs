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
/// | `V1`       | The measured **classic stub import surface**: exactly two |
/// |            | imported DLLs (`kernel32` + `comctl32`) with at most four |
/// |            | functions in total. Measured on the version ladder |
/// |            | (Themida 1.1.1–1.9.1, WinLicense 1.1.1–1.8.9 — and |
/// |            | WinLicense 2.0.8, which shares the surface; see below). |
/// | `V2`       | The measured **SecureEngine-2.x import surface**: exactly |
/// |            | one imported DLL (`kernel32`) with at most two functions, |
/// |            | or the Pascal dual-`0x1000`-stub shape. |
/// | `V3`       | x64 is always V3; x86 requires runtime detection (see note). |
/// | `Unknown`  | None of the static signals matched. |
///
/// # Measured provenance (2026-10-26, Tuts 4 You version ladder)
///
/// 86 unpack-mes labelled by their exact packer version (Themida 1.1.1.0 →
/// 1.9.1.0, WinLicense 1.1.1.0 → 2.0.8.0) were run through this
/// classification.  Findings that shaped the rules:
///
/// * The 1.x-generation stub always imports exactly `KERNEL32.dll` +
///   `COMCTL32.dll` with three functions in total — measured identically on
///   Themida 1.1.1–1.9.1 and WinLicense 1.1.1–1.8.9.  WinLicense **2.0.8**
///   carries the same two-DLL surface (`CreateFileA, lstrcpy` +
///   `InitCommonControls`), so "classic surface" says *1.x-generation
///   pipeline*, and 2.0.8 is the one known later build that shares it.
/// * SecureEngine-2.x builds collapse the import table to a **single
///   kernel32 function** — measured `SizeofResource` (2.0.1.0), `lstrlenW`
///   (CISC example), `GetProfileStringW` (RISC example); the function name
///   is randomised per build, the one-DLL shape is not.
/// * Section names are **not** reliable below 3.x: 1.9.1 renames the section
///   to whatever the user chose (`Tuts4You` in the ladder), and 2.x
///   randomises section names per build (`vlbnmttz`-style).  The
///   `"Themida "` name rule (this file's original rule, kept first) covers
///   only 1.1.1–1.5 of the ladder.
/// * The unlicense tool's 2.x section-start byte patterns (`56 50 53 E8 01 …`)
///   do **not** occur anywhere in this ladder — measured, so they were not
///   ported.
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
    detect_version_with_image(pe, is_64bit, &[])
}

/// [`detect_version`], with the file bytes available so the measured
/// import-surface fingerprints can be read (see the type-level table).
///
/// `image` may be empty; the import rules are then skipped and the result is
/// exactly what [`detect_version`] has always returned.
#[must_use]
pub fn detect_version_with_image(pe: &PeHeader, is_64bit: bool, image: &[u8]) -> ThemidaVersion {
    // x64 targets are always V3 — Themida V2 has no x64 support.
    // (Themida64.pas constructor: `FThemidaV3 := True`)
    if is_64bit {
        return ThemidaVersion::V3;
    }

    // Ancient version: any section named exactly "Themida " (8 bytes, trailing space).
    // (Themida.pas → SelectThemidaSection; measured on ladder 1.1.1–1.8.2.)
    for section in &pe.sections {
        if &section.header.name == ANCIENT_THEMIDA_NAME {
            return ThemidaVersion::Ancient;
        }
    }

    // Measured import-surface fingerprints (2026-10-26 ladder, see type doc).
    if let Some(surface) = read_import_surface(image, pe) {
        if is_secureengine2_surface(&surface) {
            return ThemidaVersion::V2;
        }
        if is_classic_stub_surface(&surface) {
            return ThemidaVersion::V1;
        }
    }

    // V2 detection (Pascal reference; no ladder sample carries this shape,
    // kept because it is the documented Themidie-era rule): the last two
    // sections both have VirtualSize == 0x1000, and the very last section
    // also has SizeOfRawData == 0x1000.
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

    // Static analysis alone cannot distinguish V1 from V3 for x86 targets
    // beyond the signals above.  V3 detection requires runtime heuristics
    // (3 .text accesses without finding the Themida section — see
    // Themida.pas OnHardwareBreakpoint).
    ThemidaVersion::Unknown
}

// ---------------------------------------------------------------------------
// Import-surface fingerprints
// ---------------------------------------------------------------------------

/// One imported DLL and the function names in its original thunk table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedDll {
    /// DLL name as written in the import directory (original case).
    pub dll: String,
    /// Imported function names (ordinal imports appear as `#N`).
    pub functions: Vec<String>,
}

/// Read the import directory's DLL/function names out of the file image.
///
/// Returns `None` when there is no import directory or its bytes do not map
/// into the image; malformed entries stop the walk instead of panicking.
#[must_use]
pub fn read_import_surface(image: &[u8], pe: &PeHeader) -> Option<Vec<ImportedDll>> {
    const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
    let dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if dir.virtual_address == 0 || image.is_empty() {
        return None;
    }

    let rva_to_off = |rva: u32| -> Option<usize> {
        for s in &pe.sections {
            let va = s.virtual_address;
            let span = s.virtual_size.max(s.raw_size);
            if rva >= va && rva < va.saturating_add(span) {
                let delta = rva - va;
                if delta < s.raw_size {
                    return Some(s.raw_offset as usize + delta as usize);
                }
                return None; // inside the virtual tail: no file bytes
            }
        }
        None
    };
    let read_u32 = |off: usize| -> Option<u32> {
        image
            .get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_cstr = |off: usize| -> Option<String> {
        let rest = image.get(off..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    };

    let mut out = Vec::new();
    let mut cursor = rva_to_off(dir.virtual_address)?;
    // IMAGE_IMPORT_DESCRIPTOR = 20 bytes; terminated by an all-zero entry.
    // Bounded so a malformed directory cannot loop forever.
    for _ in 0..64 {
        let (oft, _ts, _fwd, name_rva, ft) = (
            read_u32(cursor)?,
            read_u32(cursor + 4)?,
            read_u32(cursor + 8)?,
            read_u32(cursor + 12)?,
            read_u32(cursor + 16)?,
        );
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let dll = read_cstr(rva_to_off(name_rva)?)?;

        let mut functions = Vec::new();
        let thunk_rva = if oft != 0 { oft } else { ft };
        if let Some(mut toff) = rva_to_off(thunk_rva) {
            for _ in 0..256 {
                let Some(value) = read_u32(toff) else { break };
                if value == 0 {
                    break;
                }
                if value & 0x8000_0000 != 0 {
                    functions.push(format!("#{}", value & 0xffff));
                } else if let Some(name) = rva_to_off(value & 0x7fff_ffff).and_then(|o| {
                    // IMAGE_IMPORT_BY_NAME: WORD hint, then the name.
                    read_cstr(o + 2)
                }) {
                    functions.push(name);
                }
                toff += 4;
            }
        }
        out.push(ImportedDll { dll, functions });
        cursor += 20;
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// The measured 1.x-generation classic stub surface: exactly two imported
/// DLLs, `kernel32` + `comctl32` (case-insensitive), at most four functions
/// in total.
///
/// Measured: Themida 1.1.1–1.9.1 and WinLicense 1.1.1–1.8.9 all carry
/// `KERNEL32.dll[CreateFileA, ExitProcess]` + `COMCTL32.dll[InitCommonControls]`;
/// WinLicense 2.0.8 carries `KERNEL32.dll[CreateFileA, lstrcpy]` +
/// `COMCTL32.dll[InitCommonControls]` — same two-DLL shape.
#[must_use]
pub fn is_classic_stub_surface(surface: &[ImportedDll]) -> bool {
    if surface.len() != 2 {
        return false;
    }
    let mut has_kernel32 = false;
    let mut has_comctl32 = false;
    let mut funcs = 0usize;
    for entry in surface {
        let name = entry.dll.to_ascii_lowercase();
        if name == "kernel32.dll" {
            has_kernel32 = true;
        } else if name == "comctl32.dll" {
            has_comctl32 = true;
        } else {
            return false;
        }
        funcs += entry.functions.len();
    }
    has_kernel32 && has_comctl32 && funcs <= 4
}

/// The measured SecureEngine-2.x import surface: exactly one imported DLL,
/// `kernel32`, with at most two functions.
///
/// Measured: WinLicense 2.0.1.0 imports only `kernel32[SizeofResource]`;
/// the 2.0.6.5 CISC/RISC examples import only `kernel32[lstrlenW]` /
/// `kernel32[GetProfileStringW]`.  The function name is randomised per
/// build, the one-DLL shape is not.
#[must_use]
pub fn is_secureengine2_surface(surface: &[ImportedDll]) -> bool {
    surface.len() == 1
        && surface[0].dll.eq_ignore_ascii_case("kernel32.dll")
        && !surface[0].functions.is_empty()
        && surface[0].functions.len() <= 2
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

    // Signal 1c: WinLicense 1.x truncates its section name to 8 bytes
    // ("WinLicen") — measured on the version ladder (WinLicense 1.1.1.0 and
    // 1.4.0.2 unpack-mes, 19 samples, every one otherwise invisible to this
    // heuristic).  Without this the packer gate would route those targets
    // away from the Themida pipeline.
    if lower.starts_with("winlicen") {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
