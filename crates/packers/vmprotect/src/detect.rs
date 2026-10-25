//! VMProtect detection and mode classification.
//!
//! ## Why the decision is structured this way
//!
//! Themida's `is_themida_section` heuristic keys on an executable section
//! with `raw_size == 0` and a large virtual size.  Measured over 87 protected
//! samples on this machine, that shape occurs in **6 genuine Themida
//! samples** and in the `Packed` VMProtect sample — so the heuristic is
//! correct for Themida and *cannot* be tightened into rejecting VMProtect.
//! The packer decision therefore has to be an explicit step that runs first,
//! which is what [`detect`] provides.
//!
//! ## The discriminator, and how it was chosen
//!
//! Measured cross-tabulation (`D:\Projects\lunlun\OUT\discriminator.py`):
//!
//! | family | n | `MEM_NOT_PAGED`+exec | `.fptable` | `.vmp*` | `.rdata0/1/2` | `.winlice` |
//! |---|---|---|---|---|---|---|
//! | `.fptable` family | 23 | 18 | 23 | 0 | 19 | 0 |
//! | 伦伦 (VMProtect, confirmed) | 1 | 1 | 1 | 1 | 0 | 0 |
//! | Themida | 3 | 0 | 0 | 0 | 0 | 0 |
//! | Themida + Oreans | 60 | 0 | 0 | 0 | 0 | 60 |
//!
//! `.fptable` and `.winlice`/`.boot` **never** co-occur (0 of 87), and
//! `MEM_NOT_PAGED` is absent from all 63 Themida samples.  The decisive
//! condition is therefore:
//!
//! ```text
//! a `.vmp0/1/2` section            (a VMProtect-only name), or
//! MEM_NOT_PAGED + executable       AND (`.fptable` present OR a runtime section)
//! ```
//!
//! which fires on both DIE-confirmed VMProtect samples with a measured
//! false-positive count of **0 / 63** against Themida.  A format that reuses
//! this section shape without being VMProtect would break the rule — that is
//! why every verdict carries its [`Evidence`] rather than a bare `true`.

use mida_packer_api::{Detection, Evidence, Family, Packer, PackerKind, VmProtectMode};
use mida_pe::{PeHeader, PeSection};

/// `IMAGE_SCN_MEM_EXECUTE`
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// `IMAGE_SCN_MEM_NOT_PAGED` — measured on both VMProtect samples'
/// runtime sections (`chars == 0x68000060`) and on **no** Themida sample.
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;

/// Smallest virtual size that counts as "worth reconstructing" when an
/// executable section has no file bytes.
pub const PACKED_MIN_VIRTUAL_SIZE: u32 = 0x1_0000;

/// Upper bound used when judging whether a `RUNTIME_FUNCTION` triple looks
/// real.  Matches the values used for the python cross-check so the pinned
/// numbers are comparable.
const TRIPLE_MAX_END: u32 = 0x0400_0000;
const TRIPLE_MAX_UNWIND: u32 = 0x0080_0000;

/// Section name with NUL padding and the 8-space placeholder that Themida
/// uses for unnamed sections stripped off.
pub fn section_name(sec: &PeSection) -> &str {
    sec.name.trim_matches(|c: char| c == '\0' || c == ' ')
}

/// `true` for the VMProtect-only section names.
pub fn is_vmp_named_section(name: &str) -> bool {
    matches!(name, ".vmp0" | ".vmp1" | ".vmp2")
}

/// `true` for the `.rdata0/1/2` names used by the `Packed` mode's builder.
pub fn is_template_named_section(name: &str) -> bool {
    matches!(name, ".rdata0" | ".rdata1" | ".rdata2")
}

/// `true` when the section is executable.
pub fn is_executable(sec: &PeSection) -> bool {
    sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
}

/// `true` when the section is marked non-pageable.
pub fn is_not_paged(sec: &PeSection) -> bool {
    sec.characteristics & IMAGE_SCN_MEM_NOT_PAGED != 0
}

/// Executable sections marked `MEM_NOT_PAGED`.  Measured 19/24 on the
/// `.fptable` family, 0/63 on Themida.
pub fn notpaged_executable_sections(pe: &PeHeader) -> Vec<&PeSection> {
    pe.sections
        .iter()
        .filter(|s| is_executable(s) && is_not_paged(s))
        .collect()
}

/// Executable sections whose bytes are absent from the file — the measured
/// signature of `VmProtectMode::Packed`.
///
/// `zz_test.exe`: `.text` (`virtual_size 0x12b05c`) and `.rdata0`
/// (`0x5a8572`), both `raw_size 0`.
pub fn packed_sections(pe: &PeHeader) -> Vec<&PeSection> {
    pe.sections
        .iter()
        .filter(|s| {
            is_executable(s) && s.raw_size == 0 && s.virtual_size >= PACKED_MIN_VIRTUAL_SIZE
        })
        .collect()
}

/// The non-standard `.fptable` section, if present.
pub fn fptable_section(pe: &PeHeader) -> Option<&PeSection> {
    pe.sections
        .iter()
        .find(|s| section_name(s) == ".fptable")
}

/// Sections that carry VMProtect's own code and metadata: executable,
/// non-pageable, and actually present in the file.
///
/// Measured `.vmp0` (`raw 0x217e00`) for `MinProtection` and `.rdata2`
/// (`raw 0x1466400`) for `Packed`.
///
/// There is deliberately **no size threshold** here.  An earlier revision
/// required `raw_size >= PACKED_MIN_VIRTUAL_SIZE`, which was not backed by
/// any measurement and had two costs: it hid a small VM section entirely,
/// and it made every small fixture invisible.  The two conditions that
/// remain are already specific — over the 87-sample corpus,
/// `MEM_NOT_PAGED` + executable occurs on 19 of the 24 `.fptable`-family
/// samples and on 0 of 63 Themida samples — and `raw_size > 0` is what
/// separates "the bytes are here" from "the bytes are reconstructed at
/// runtime".
pub fn runtime_sections<'a>(pe: &'a PeHeader, image: &[u8]) -> Vec<&'a PeSection> {
    pe.sections
        .iter()
        .filter(|s| {
            is_executable(s) && is_not_paged(s) && section_bytes(s, image).is_some()
        })
        .collect()
}

/// The section's file bytes, or `None` when the section has no file bytes or
/// the declared range leaves the file.
pub fn section_bytes<'a>(sec: &PeSection, image: &'a [u8]) -> Option<&'a [u8]> {
    let start = sec.raw_offset as usize;
    let len = sec.raw_size as usize;
    if len == 0 {
        return None;
    }
    image.get(start..start.checked_add(len)?)
}

/// Shannon entropy in bits/byte, `0.0` for empty input.
pub fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f32;
    let mut e = 0.0f32;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f32 / n;
            e -= p * p.log2();
        }
    }
    e
}

/// `(plausible, sampled)` `RUNTIME_FUNCTION` triples in `data`.
///
/// Real `.pdata` tables are near-100 % plausible; VMProtect's scrambled
/// `.pdata` measures **0/64**.  A section with no bytes samples 0.
pub fn plausible_runtime_function_triples(data: &[u8], max: usize) -> (usize, usize) {
    let n = (data.len() / 12).min(max);
    let mut ok = 0usize;
    for i in 0..n {
        let b = &data[i * 12..i * 12 + 12];
        let start = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let end = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let unwind = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        if start > 0 && start < end && end < TRIPLE_MAX_END && unwind < TRIPLE_MAX_UNWIND {
            ok += 1;
        }
    }
    (ok, n)
}

/// `MinProtection` when every executable section still has file bytes,
/// `Packed` as soon as one executable section does not.
///
/// Measured: 伦伦 has no `raw_size == 0` section → `MinProtection`;
/// `zz_test.exe` has `.text` and `.rdata0` → `Packed`.
pub fn classify_mode(pe: &PeHeader) -> VmProtectMode {
    if packed_sections(pe).is_empty() {
        VmProtectMode::MinProtection
    } else {
        VmProtectMode::Packed
    }
}

/// The `Packer` implementation for VMProtect.
#[derive(Debug, Default, Clone, Copy)]
pub struct VmProtectDetector;

impl VmProtectDetector {
    /// Construct the detector.
    pub fn new() -> Self {
        Self
    }
}

impl Packer for VmProtectDetector {
    fn name(&self) -> &'static str {
        "VMProtect"
    }

    fn family(&self) -> Family {
        Family::VmProtect
    }

    fn detect(&self, pe: &PeHeader, image: &[u8]) -> Option<Vec<Evidence>> {
        let vmp_named: Vec<&str> = pe
            .sections
            .iter()
            .map(section_name)
            .filter(|n| is_vmp_named_section(n))
            .collect();
        let notpaged = notpaged_executable_sections(pe);
        let fptable = fptable_section(pe);
        let runtime = runtime_sections(pe, image);

        // Decisive condition — see the module docs for the measured counts.
        let decisive = !vmp_named.is_empty()
            || (!notpaged.is_empty() && (fptable.is_some() || !runtime.is_empty()));
        if !decisive {
            return None;
        }

        let mut ev: Vec<Evidence> = Vec::new();
        if !vmp_named.is_empty() {
            ev.push(Evidence::new(
                "vmp-section",
                format!("sections {vmp_named:?}"),
            ));
        }
        if !notpaged.is_empty() {
            let names: Vec<&str> = notpaged.iter().map(|s| section_name(s)).collect();
            ev.push(Evidence::new(
                "notpaged-executable-section",
                format!("sections {names:?}"),
            ));
        }
        if let Some(s) = fptable {
            ev.push(Evidence::new(
                "fptable-section",
                format!("{} raw_size {:#x}", section_name(s), s.raw_size),
            ));
        }
        if !runtime.is_empty() {
            let names: Vec<&str> = runtime.iter().map(|s| section_name(s)).collect();
            ev.push(Evidence::new(
                "runtime-section",
                format!(
                    "sections {names:?} ({} B of VM code/metadata in file)",
                    runtime.iter().map(|s| s.raw_size as u64).sum::<u64>()
                ),
            ));
        }
        Some(ev)
    }
}

/// Detect VMProtect, carrying the evidence needed to justify the verdict.
///
/// Returns `None` when the image does not match, so the caller can fall
/// through to the next packer.  The `absent` list records the markers that
/// were looked for and not found, because a surprising verdict is usually
/// about a missing marker, not a present one.
pub fn detect(pe: &PeHeader, image: &[u8]) -> Option<Detection> {
    let evidence = VmProtectDetector.detect(pe, image)?;

    let mut absent: Vec<Evidence> = Vec::new();
    let has_vmp = pe
        .sections
        .iter()
        .any(|s| is_vmp_named_section(section_name(s)));
    if !has_vmp {
        absent.push(Evidence::new("vmp-section", "no .vmp0/.vmp1/.vmp2"));
    }
    if notpaged_executable_sections(pe).is_empty() {
        absent.push(Evidence::new(
            "notpaged-executable-section",
            "no executable section marked MEM_NOT_PAGED",
        ));
    }
    if fptable_section(pe).is_none() {
        absent.push(Evidence::new("fptable-section", "no .fptable"));
    }
    if runtime_sections(pe, image).is_empty() {
        absent.push(Evidence::new(
            "runtime-section",
            "no in-file non-pageable executable section",
        ));
    }
    if let Some((ok, n)) = scrambled_pdata(pe, image) {
        if n > 0 && ok == 0 {
            absent.push(Evidence::new(
                "scrambled-pdata",
                format!(".pdata holds {ok}/{n} plausible RUNTIME_FUNCTION triples"),
            ));
        }
    }

    Some(Detection {
        kind: PackerKind::VmProtect(pe_mode(pe)),
        evidence,
        absent,
    })
}

fn pe_mode(pe: &PeHeader) -> VmProtectMode {
    classify_mode(pe)
}

/// `Some((plausible, sampled))` when a `.pdata` section with file bytes
/// exists.  `0/n` is the measured signature of VMProtect scrambling the
/// table and moving the live copy into its runtime section.
pub fn scrambled_pdata(pe: &PeHeader, image: &[u8]) -> Option<(usize, usize)> {
    let sec = pe.sections.iter().find(|s| section_name(s) == ".pdata")?;
    let bytes = section_bytes(sec, image)?;
    Some(plausible_runtime_function_triples(bytes, 64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{pe_with_sections as pe_with, sec, sec_at};

    #[test]
    fn section_name_strips_nul_and_the_themida_space_placeholder() {
        // Themida writes eight spaces for unnamed sections; a naive
        // `trim_end_matches('\0')` would leave them and every name compare
        // downstream would silently miss.
        assert_eq!(section_name(&sec(".text\0\0\0", 0, 0, 0)), ".text");
        assert_eq!(section_name(&sec("        ", 0, 0, 0)), "");
        assert_eq!(section_name(&sec(".vmp0", 0, 0, 0)), ".vmp0");
    }

    #[test]
    fn measured_characteristics_classify_as_expected() {
        // Measured: both VMProtect runtime sections declare 0x68000060.
        let vmp = sec(".vmp0", 0x217e00, 0x217c44, 0x6800_0060);
        assert!(is_executable(&vmp));
        assert!(is_not_paged(&vmp));
        // Measured: Themida's `.boot` declares 0x60000060 — the same
        // R|X|CODE|IDATA, but NOT non-pageable.  This one bit is the
        // discriminator, and it is absent from all 63 Themida samples.
        let boot = sec(".boot", 0x4e8800, 0x4e8800, 0x6000_0060);
        assert!(is_executable(&boot));
        assert!(!is_not_paged(&boot));
        // Measured: Themida's `.winlice` is writable and not non-pageable.
        let winlice = sec(".winlice", 0, 0x6d6000, 0xe000_0060);
        assert!(is_executable(&winlice));
        assert!(!is_not_paged(&winlice));
    }

    #[test]
    fn packed_detection_needs_raw_size_zero_and_a_real_virtual_size() {
        let exe = 0x6000_0020;

        // 伦伦: every executable section still has file bytes -> MinProtection.
        let a = pe_with(vec![
            sec(".text", 0x72400, 0x722a4, exe),
            sec(".vmp0", 0x217e00, 0x217c44, 0x6800_0060),
        ]);
        assert!(packed_sections(&a).is_empty());
        assert_eq!(classify_mode(&a), VmProtectMode::MinProtection);

        // zz_test.exe: `.text` and `.rdata0` are absent from the file -> Packed.
        let b = pe_with(vec![
            sec(".text", 0, 0x12b05c, exe),
            sec(".rdata0", 0, 0x5a8572, exe),
            sec(".rdata2", 0x1466400, 0x1466354, 0x6800_0060),
        ]);
        assert_eq!(packed_sections(&b).len(), 2);
        assert_eq!(classify_mode(&b), VmProtectMode::Packed);

        // A tiny `raw_size == 0` section is ordinary PE padding, not packing.
        let c = pe_with(vec![sec(".text", 0x200, 0x100, exe), sec(".pad", 0, 0x80, exe)]);
        assert!(packed_sections(&c).is_empty());
        assert_eq!(classify_mode(&c), VmProtectMode::MinProtection);
    }

    #[test]
    fn runtime_sections_require_file_bytes() {
        let img = vec![0u8; 0x1000];
        // Present in the file.
        let present = pe_with(vec![sec_at(".vmp0", 0x400, 0x400, 0x6800_0060, 0x200)]);
        assert_eq!(runtime_sections(&present, &img).len(), 1);
        // Same section, but its declared range leaves the file: not a runtime
        // section, because we cannot read what VMProtect put there.
        let absent = pe_with(vec![sec_at(".vmp0", 0x400, 0x400, 0x6800_0060, 0xf00)]);
        assert!(runtime_sections(&absent, &img).is_empty());
        // Non-pageable but NOT executable is not a runtime section.
        let data = pe_with(vec![sec_at(".fptable", 0x200, 0x100, 0xc800_0040, 0x100)]);
        assert!(runtime_sections(&data, &img).is_empty());
    }

    #[test]
    fn shannon_entropy_matches_known_shapes() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0);
        // All 256 byte values, equally often -> exactly 8 bits/byte.
        let flat: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        assert!((shannon_entropy(&flat) - 8.0).abs() < 1e-4);
        // 16 distinct values, equally often -> 4 bits/byte.
        let half: Vec<u8> = (0..16u8).cycle().take(16 * 64).collect();
        assert!((shannon_entropy(&half) - 4.0).abs() < 1e-4);
    }

    #[test]
    fn triple_plausibility_separates_real_tables_from_scrambled_ones() {
        // The measured head of VMProtect's scrambled `.pdata` (伦伦, 0/64).
        let scrambled: Vec<u8> = vec![
            0xe9, 0xa9, 0x69, 0x33, 0xec, 0xb2, 0x4d, 0x3e, 0xf6, 0x31, 0x62, 0xf4,
        ];
        assert_eq!(plausible_runtime_function_triples(&scrambled, 64), (0, 1));

        // A real entry: start 0x1010, end 0x103d, unwind 0x8b430 — the first
        // triple of 伦伦's relocated exception directory.
        let real: Vec<u8> = vec![
            0x10, 0x10, 0x00, 0x00, 0x3d, 0x10, 0x00, 0x00, 0x30, 0xb4, 0x08, 0x00,
        ];
        assert_eq!(plausible_runtime_function_triples(&real, 64), (1, 1));

        // A buffer too short for one triple samples nothing, and must not be
        // reported as "implausible" — 0/0 and 0/64 mean different things.
        assert_eq!(plausible_runtime_function_triples(&[], 64), (0, 0));
        assert_eq!(plausible_runtime_function_triples(&[0u8; 11], 64), (0, 0));
    }

    #[test]
    fn section_bytes_bounds_checks_instead_of_panicking() {
        let image = vec![0u8; 0x200];
        let ok = sec(".text", 0x100, 0x100, 0);
        assert_eq!(section_bytes(&ok, &image).map(|b| b.len()), Some(0x100));
        // A section whose declared range leaves the file reads as absent.
        let past_end = sec_at(".rsrc", 0x1000, 0x1000, 0, 0x100);
        assert!(section_bytes(&past_end, &image).is_none());
        // No file bytes at all is `None`, not an empty slice.
        let bss = sec(".bss", 0, 0x1000, 0);
        assert!(section_bytes(&bss, &image).is_none());
    }

    #[test]
    fn scrambled_pdata_reports_the_measured_zero_of_sixty_four() {
        let mut img = vec![0u8; 0x600];
        // 64 triples of the measured scrambled shape (repeating 12 bytes).
        let pat = [
            0xe9u8, 0xa9, 0x69, 0x33, 0xec, 0xb2, 0x4d, 0x3e, 0xf6, 0x31, 0x62, 0xf4,
        ];
        for i in 0..64 {
            img[0x200 + i * 12..0x200 + i * 12 + 12].copy_from_slice(&pat);
        }
        let pe = pe_with(vec![sec_at(".pdata", 0x300, 0x300, 0x4000_0040, 0x200)]);
        let (ok, n) = scrambled_pdata(&pe, &img).expect(".pdata with bytes");
        assert_eq!((ok, n), (0, 64));

        // No `.pdata` at all (the `Packed` mode) reports `None` rather than
        // a fake zero count.
        let packed = pe_with(vec![sec(".text", 0, 0x1000, 0x6000_0020)]);
        assert!(scrambled_pdata(&packed, &img).is_none());
    }

    #[test]
    fn detect_fires_on_the_measured_vmprotect_shapes_and_not_on_themida_shapes() {
        let img = vec![0u8; 0x1000];
        let detector = VmProtectDetector;

        // 伦伦: `.vmp0` + `.fptable` + MEM_NOT_PAGED.
        let lunlun = pe_with(vec![
            sec_at(".text", 0x400, 0x400, 0x6000_0020, 0x0),
            sec_at(".fptable", 0x200, 0x100, 0xc000_0040, 0x0),
            sec_at(".vmp0", 0x400, 0x400, 0x6800_0060, 0x400),
        ]);
        let ev = detector
            .detect(&lunlun, &img)
            .expect("伦伦's shape must be detected");
        let codes: Vec<&str> = ev.iter().map(|e| e.code).collect();
        assert!(codes.contains(&"vmp-section"));
        assert!(codes.contains(&"notpaged-executable-section"));
        assert!(codes.contains(&"fptable-section"));
        assert!(codes.contains(&"runtime-section"));

        // zz_test.exe: no `.vmp*` name, so the structure has to carry it.
        let zz = pe_with(vec![
            sec(".text", 0, 0x12b05c, 0x6000_0020),
            sec(".fptable", 0, 0x100, 0xc000_0040),
            sec_at(".rdata2", 0x400, 0x400, 0x6800_0060, 0x0),
        ]);
        assert!(detector.detect(&zz, &img).is_some());
        assert_eq!(classify_mode(&zz), VmProtectMode::Packed);

        // Themida's measured shape: `.winlice` (raw_size 0, RWE) + `.boot`,
        // and crucially NO MEM_NOT_PAGED and NO `.fptable`.
        let themida = pe_with(vec![
            sec("        ", 0x4c600, 0xdd9a0, 0x6000_0020),
            sec(".bss", 0, 0xc80, 0xc000_0080),
            sec(".winlice", 0, 0x6d6000, 0xe000_0060),
            sec(".boot", 0x4e8800, 0x4e8800, 0x6000_0060),
        ]);
        assert!(
            detector.detect(&themida, &img).is_none(),
            "Themida must not be claimed as VMProtect — 0 of 63 measured samples fire"
        );

        // A `raw_size == 0` executable section alone is not enough: 6 genuine
        // Themida samples have exactly that shape, which is why
        // `is_themida_section` cannot be tightened into a VMProtect test.
        let raw0_only = pe_with(vec![sec(".rdata0", 0, 0x5a8572, 0x6000_0020)]);
        assert!(detector.detect(&raw0_only, &img).is_none());
    }

    #[test]
    fn detect_records_what_was_absent_so_a_verdict_is_diagnosable() {
        let img = vec![0u8; 0x400];
        let pe = pe_with(vec![
            // A code section with no file bytes is what makes this `Packed`.
            sec(".text", 0x0, 0x12b05c, 0x6000_0020),
            sec_at(".fptable", 0x200, 0x100, 0xc000_0040, 0x0),
            sec_at(".rdata2", 0x200, 0x200, 0x6800_0060, 0x200),
        ]);
        let d = detect(&pe, &img).expect("template shape is VMProtect");
        assert!(d.is_vmprotect());
        assert_eq!(d.kind, PackerKind::VmProtect(VmProtectMode::Packed));
        // The name marker is absent, and the verdict says so instead of
        // silently omitting it.
        let absent: Vec<&str> = d.absent.iter().map(|e| e.code).collect();
        assert!(absent.contains(&"vmp-section"));
        assert!(!d.absent.iter().any(|e| e.code == "fptable-section"));
        assert!(detect(&pe_with(vec![sec(".text", 0x400, 0x400, 0x6000_0020)]), &img).is_none());
    }
}
