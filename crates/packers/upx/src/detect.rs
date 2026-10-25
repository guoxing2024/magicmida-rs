//! Detection: a valid PE-format `PackHeader` **and** UPX-named sections.
//!
//! ## Why both conditions
//!
//! A bare `'UPX!'` with a valid checksum can appear in any file (a packed
//! payload inside another binary, a resource).  UPX's own PE output always
//! carries the sections `UPX0`/`UPX1` (+ optional `UPX2`, measured on the x86
//! sample) — requiring both keeps the verdict honest, and every claim still
//! names its evidence.

use mida_packer_api::{Detection, Evidence, Family, Packer, PackerKind};
use mida_pe::{PeHeader, PeSection};

use crate::header::{find_pack_header, is_pe_format};

/// The section names UPX's PE output uses (measured; case as written).
const UPX_SECTION_NAMES: &[&str] = &["UPX0", "UPX1", "UPX2"];

/// Section name with NUL padding stripped (mirrors the other packer crates,
/// which measure real files where the name field is NUL-padded).
pub fn section_name(sec: &PeSection) -> &str {
    sec.name.trim_matches(|c: char| c == '\0' || c == ' ')
}

/// `true` for the UPX-owned section names.
pub fn is_upx_section(name: &str) -> bool {
    UPX_SECTION_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// The UPX-named sections of this image.
pub fn upx_sections(pe: &PeHeader) -> Vec<&str> {
    pe.sections
        .iter()
        .map(section_name)
        .filter(|n| is_upx_section(n))
        .collect()
}

/// The `Packer` implementation for UPX.
#[derive(Debug, Default, Clone, Copy)]
pub struct UpxDetector;

impl UpxDetector {
    /// Construct the detector.
    pub fn new() -> Self {
        Self
    }
}

impl Packer for UpxDetector {
    fn name(&self) -> &'static str {
        "UPX"
    }

    fn family(&self) -> Family {
        Family::Upx
    }

    fn detect(&self, pe: &PeHeader, image: &[u8]) -> Option<Vec<Evidence>> {
        let ph = find_pack_header(image)?;
        if !is_pe_format(ph.format) {
            return None;
        }
        let sections = upx_sections(pe);
        if sections.is_empty() {
            return None;
        }
        Some(vec![
            Evidence::new(
                "upx-packheader",
                format!(
                    "offset {:#x}, version {}, format {} ({}), method {} ({}), level {}, filter {} (cto {})",
                    ph.file_offset,
                    ph.version,
                    ph.format,
                    ph.format_label(),
                    ph.method,
                    ph.method_label(),
                    ph.level,
                    ph.filter,
                    ph.filter_cto
                ),
            ),
            Evidence::new("upx-sections", format!("sections {sections:?}")),
        ])
    }
}

/// Detect UPX, carrying the evidence needed to justify the verdict.
///
/// Returns `None` when the image does not match, so the caller can fall
/// through to the next packer.  The `absent` list records the markers that
/// were looked for and not found.
pub fn detect(pe: &PeHeader, image: &[u8]) -> Option<Detection> {
    let evidence = UpxDetector::new().detect(pe, image)?;

    let mut absent: Vec<Evidence> = Vec::new();
    if !pe.sections.iter().any(|s| section_name(s) == "UPX0") {
        absent.push(Evidence::new(
            "upx0-empty-section",
            "no UPX0 section (the raw_size == 0 placeholder for the original image)",
        ));
    }
    // The loader stub lives at the end of UPX1 and the entry point points into
    // it; when the entry point is elsewhere the report will say so, but the
    // detection stands either way.

    Some(Detection {
        kind: PackerKind::Upx,
        evidence,
        absent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{pe_with_sections as fixture_pe, sec};

    /// A minimal image with a valid PackHeader: measured mida_x64_nrv values.
    fn fixture_image() -> (PeHeader, Vec<u8>) {
        use crate::header::test_support::{build_header, sample_header};
        let mut image = vec![0u8; 0x400];
        // Placed the way the GNU-built samples place it: inside UPX1's raw
        // data, preceded by UPX's version string ("5.21\0" measured).
        image[0x200..0x205].copy_from_slice(b"5.21\0");
        image[0x205..0x225].copy_from_slice(&build_header(&sample_header()));
        let pe = fixture_pe(vec![
            sec("UPX0", 0, 0x2d6000, 0xe000_0080),
            sec("UPX1", 0x14fc00, 0x150000, 0xe000_0040),
        ]);
        (pe, image)
    }

    #[test]
    fn detect_fires_on_the_upx_shape_and_names_both_markers() {
        let (pe, image) = fixture_image();
        let d = detect(&pe, &image).expect("UPX shape must be detected");
        assert!(d.is_upx());
        assert_eq!(d.kind, PackerKind::Upx);
        assert_eq!(d.summary(), "UPX");
        let codes: Vec<&str> = d.evidence.iter().map(|e| e.code).collect();
        assert!(codes.contains(&"upx-packheader"));
        assert!(codes.contains(&"upx-sections"));
        // The packheader detail names the measured header fields.
        let detail = &d.evidence[0].detail;
        assert!(detail.contains("nrv2e-le32"), "{detail}");
        assert!(detail.contains("pe32+-amd64"), "{detail}");
    }

    #[test]
    fn upx_sections_alone_or_packheader_alone_is_not_enough() {
        // Sections without a valid header: no verdict.
        let pe = fixture_pe(vec![sec("UPX0", 0, 0x1000, 0xe000_0080)]);
        assert!(detect(&pe, &vec![0u8; 0x40]).is_none());
        // A valid header without UPX sections: no verdict either (the magic
        // could belong to a payload of some other file).
        let (_, image) = fixture_image();
        let plain = fixture_pe(vec![sec(".text", 0x200, 0x200, 0x6000_0020)]);
        assert!(detect(&plain, &image).is_none());
    }

    #[test]
    fn section_names_are_matched_case_insensitively_and_trimmed() {
        assert!(is_upx_section("UPX0") && is_upx_section("upx1") && is_upx_section("UPX2"));
        assert!(!is_upx_section(".text") && !is_upx_section("UPX"));
        let mut s = sec("UPX1\0\0", 0, 0, 0);
        s.name.push_str("\0\0");
        assert_eq!(section_name(&s), "UPX1");
    }
}
