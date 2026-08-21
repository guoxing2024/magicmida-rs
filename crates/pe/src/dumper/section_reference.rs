//! Section content reference (WO-102 R1 opt-in) + entropy observation (R2).
//!
//! R1: an **opt-in** baseline for EXECUTE-characteristic section content.
//! Production paths never pass a baseline implicitly; callers that do
//! (e.g. a future PostSelfDecrypt capture) get a fail-closed
//! `DumpContentMismatch` on divergence instead of silent garbage emit.
//!
//! R2: pure observation — flag high-entropy EXECUTE sections in the dump
//! manifest (`encrypted_region_suspect=true`) without modifying any byte.

use crate::PeError;

/// Shannon entropy (bits/byte) of a byte slice, computed over a sample.
///
/// Returns `None` for an empty sample. The sample is taken as the first
/// `len.min(SAMPLE_BYTES)` bytes (4 KiB default); callers may pre-sample
/// any region they consider representative.
pub fn shannon_entropy_bits(sample: &[u8]) -> Option<f64> {
    if sample.is_empty() {
        return None;
    }
    let mut counts = [0u64; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let n = sample.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    Some(h)
}

/// Entropy threshold (bits/byte) above which a section is flagged as a
/// suspected encrypted region (R2, WO-102 design).
pub const ENCRYPTED_REGION_ENTROPY_THRESHOLD: f64 = 7.5;

/// Number of bytes sampled for the R2 entropy observation.
pub const R2_SAMPLE_BYTES: usize = 4096;

/// R2 observation result for one EXECUTE section.
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedRegionObservation {
    /// Section index in the image section table.
    pub section_index: usize,
    /// Section name (best-effort, may be empty).
    pub section_name: String,
    /// Whether the sampled content exceeded the entropy threshold.
    pub suspect: bool,
    /// Measured entropy in bits/byte (rounded to 3 decimals).
    pub entropy_bits: f64,
}

/// R1 opt-in content-consistency baseline (WO-102 design).
///
/// Carries the on-disk reference bytes for sections the caller wants
/// checked. Only EXECUTE-characteristic sections present in `sections`
/// are compared; missing references are treated as "no baseline" for
/// that section (never fail on absence).
#[derive(Debug, Clone, Default)]
pub struct SectionContentReference {
    /// Per-section reference bytes keyed by section name.
    pub sections: std::collections::HashMap<String, Vec<u8>>,
}

impl SectionContentReference {
    /// Build a reference from an on-disk PE image (path).
    ///
    /// Returns an empty reference when the file cannot be read or parsed,
    /// so callers can degrade to "no baseline" without inventing one.
    pub fn from_disk(path: &std::path::Path) -> Result<Self, PeError> {
        let bytes = std::fs::read(path).map_err(|e| {
            PeError::Io(std::io::Error::new(
                e.kind(),
                format!("read {}: {e}", path.display()),
            ))
        })?;
        let pe = crate::header::PeHeader::from_bytes(&bytes)?;
        let mut sections = std::collections::HashMap::new();
        for s in pe.sections.iter() {
            if s.header.characteristics & 0x2000_0000 != 0 {
                // EXECUTE characteristic (IMAGE_SCN_MEM_EXECUTE)
                let start = s.header.pointer_to_raw_data as usize;
                let size = s.header.size_of_raw_data as usize;
                let data = bytes
                    .get(start..start.saturating_add(size))
                    .unwrap_or(&[])
                    .to_vec();
                sections.insert(s.name.clone(), data);
            }
        }
        Ok(Self { sections })
    }

    /// Compare live section bytes against the reference.
    ///
    /// Returns `None` when the section has no baseline (absent from the
    /// reference) — absence never fails. Returns `Some((offset, len))`
    /// with the first differing byte offset and the differing run length
    /// when content diverges.
    pub fn first_diff(&self, name: &str, live: &[u8]) -> Option<(usize, usize)> {
        let Some(ref_bytes) = self.sections.get(name) else {
            return None;
        };
        let common = live.len().min(ref_bytes.len());
        let mut first = None;
        for i in 0..common {
            if live[i] != ref_bytes[i] {
                first = Some(i);
                break;
            }
        }
        let first = first?;
        // Differing run length from first diff to end of common region.
        let mut len = 0;
        for i in first..common {
            if live[i] != ref_bytes[i] {
                len += 1;
            } else {
                break;
            }
        }
        Some((first, len.max(1)))
    }
}

/// R2 observation: flag EXECUTE-characteristic sections whose sampled
/// content exceeds the entropy threshold (`encrypted_region_suspect`).
///
/// Pure observation — never modifies bytes. Sections are sampled at
/// their virtual address start (`R2_SAMPLE_BYTES` bytes); short sections
/// use their full length.
pub fn observe_encrypted_regions(
    sections: &[(String, u32, u32)], // (name, rva, virtual_size)
    image: &[u8],
) -> Vec<EncryptedRegionObservation> {
    let mut out = Vec::new();
    for (i, (name, rva, vsize)) in sections.iter().enumerate() {
        let start = *rva as usize;
        let len = (*vsize as usize).min(R2_SAMPLE_BYTES);
        let sample = image.get(start..start.saturating_add(len)).unwrap_or(&[]);
        let Some(h) = shannon_entropy_bits(sample) else {
            continue;
        };
        out.push(EncryptedRegionObservation {
            section_index: i,
            section_name: name.clone(),
            suspect: h > ENCRYPTED_REGION_ENTROPY_THRESHOLD,
            entropy_bits: (h * 1000.0).round() / 1000.0,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros_is_zero() {
        let h = shannon_entropy_bits(&[0u8; 4096]).unwrap();
        assert!(h < 0.01, "zero bytes should have ~0 entropy, got {h}");
    }

    #[test]
    fn entropy_of_random_is_high() {
        // Deterministic pseudo-random bytes (xorshift) — no rand dep.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut buf = [0u8; 4096];
        for b in buf.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = (state & 0xff) as u8;
        }
        let h = shannon_entropy_bits(&buf).unwrap();
        assert!(h > 7.5, "random bytes should exceed threshold, got {h}");
    }

    #[test]
    fn ascii_text_entropy_is_below_threshold() {
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(80);
        let h = shannon_entropy_bits(&text).unwrap();
        assert!(h < 7.5, "ASCII text entropy too high: {h}");
    }

    #[test]
    fn empty_sample_has_no_entropy() {
        assert_eq!(shannon_entropy_bits(&[]), None);
    }

    #[test]
    fn first_diff_reports_offset_and_length() {
        let mut ref_map = std::collections::HashMap::new();
        ref_map.insert(".text".to_string(), vec![1u8; 64]);
        let r = SectionContentReference { sections: ref_map };
        let mut live = vec![1u8; 64];
        live[10] = 2;
        live[11] = 3;
        let diff = r.first_diff(".text", &live);
        assert_eq!(diff, Some((10, 2)));
    }

    #[test]
    fn missing_reference_never_fails() {
        let r = SectionContentReference::default();
        assert_eq!(r.first_diff(".text", &[1u8; 16]), None);
    }

    #[test]
    fn identical_content_has_no_diff() {
        let mut ref_map = std::collections::HashMap::new();
        ref_map.insert(".text".to_string(), vec![7u8; 32]);
        let r = SectionContentReference { sections: ref_map };
        assert_eq!(r.first_diff(".text", &[7u8; 32]), None);
    }

    #[test]
    fn r1_opt_in_detects_divergent_execute_section() {
        // R1 is opt-in: with a baseline, EXECUTE section divergence fails closed.
        let mut ref_map = std::collections::HashMap::new();
        ref_map.insert(".text".to_string(), vec![1u8; 16]);
        let r1_ref = SectionContentReference { sections: ref_map };
        let mut live = vec![2u8; 16]; // runtime .text (decrypted) differs from disk
        live[3] = 9;
        let diff = r1_ref.first_diff(".text", &live);
        assert_eq!(diff, Some((0, 16))); // fail-closed on divergence
    }

    #[test]
    fn r1_opt_in_disabled_without_baseline() {
        // No baseline: R1 disabled, no failure possible (production default).
        let r1_ref = SectionContentReference::default();
        assert_eq!(r1_ref.first_diff(".text", &[0xff; 32]), None);
    }
}
