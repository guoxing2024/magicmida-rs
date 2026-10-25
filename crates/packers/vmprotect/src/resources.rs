//! Resource-directory walking and encrypted-payload location.
//!
//! ## Why the offset plumbing is spelled out
//!
//! `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` is an **RVA**, not a file
//! offset.  Reading a payload by treating it as a file offset produced a
//! wrong SHA-256 during this crate's investigation (`fcb2e125…` instead of
//! `91d585e6…`) because the read started 21,504 bytes too late and ran past
//! EOF.  Everything here therefore goes through
//! [`PeHeader::rva_to_offset`] and then bounds-checks against the image, and
//! a payload that is only partly in the file reports `sha256: None` rather
//! than a hash of a truncated slice.

use mida_pe::PeHeader;
use sha2::{Digest, Sha256};

use crate::detect::shannon_entropy;

/// `RT_RCDATA` — the resource type both measured payloads use.
pub const RT_RCDATA: u32 = 10;

/// Only resources at least this large are reported.  The measured payloads
/// are 15.36 MB (`MinProtection`) and 12.19 MB (`Packed`); ordinary `RCDATA`
/// — version info, manifests, icons — is orders of magnitude smaller.
pub const LARGE_RESOURCE_MIN: u32 = 1 << 20;

const RESOURCE_DIRECTORY_INDEX: usize = 2;
const DIRECTORY_HEADER_SIZE: usize = 16;
const DIRECTORY_ENTRY_SIZE: usize = 8;
const MAX_ENTRIES_PER_DIRECTORY: usize = 4096;
const NAME_IS_STRING: u32 = 0x8000_0000;
const OFFSET_MASK: u32 = 0x7fff_ffff;

/// One leaf of the resource tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEntry {
    /// Numeric type when the type is an ordinal (`RT_RCDATA` == 10).
    pub type_id: Option<u32>,
    /// Type name when the type is a string.
    pub type_name: Option<String>,
    /// Numeric name/id (`101` / `131` in the measured samples).
    pub name_id: Option<u32>,
    /// String name when the entry is named.
    pub name: Option<String>,
    /// Language id from the third tree level.
    pub lang: u32,
    /// RVA of the data — **not** a file offset.
    pub data_rva: u32,
    /// Declared size in bytes.
    pub size: u32,
}

/// A resource large enough to be a payload, with everything measurable about it.
#[derive(Debug, Clone, PartialEq)]
pub struct LargeResource {
    pub type_id: Option<u32>,
    pub type_name: Option<String>,
    pub name_id: Option<u32>,
    pub name: Option<String>,
    pub lang: u32,
    /// RVA of the data.
    pub data_rva: u32,
    /// Declared size.
    pub size: u32,
    /// File offset of the data, or `None` when the data is not present in the
    /// file at all (the measured `Packed` payload is memory-only).
    pub file_offset: Option<u32>,
    /// How many bytes of the declared `size` are actually in the file.
    pub bytes_in_file: usize,
    /// Entropy over the bytes that are present.
    pub entropy: Option<f32>,
    /// SHA-256, only when **all** `size` bytes are present.
    pub sha256: Option<String>,
    /// Longest printable ASCII prefix, up to 16 bytes, at least 4 long.
    /// This is how `XMP2QH_` was found on the `MinProtection` payload.
    pub magic: Option<String>,
    /// `true` when the bytes start with a real `MZ`/`PE\0\0` header.
    pub looks_like_pe: bool,
}

impl LargeResource {
    /// `true` when the payload is entirely inside the file.
    pub fn fully_in_file(&self) -> bool {
        self.file_offset.is_some() && self.bytes_in_file == self.size as usize
    }

    /// One-line summary for a report.
    pub fn one_line(&self) -> String {
        let what = match (self.type_id, &self.name_id, &self.name) {
            (Some(t), Some(id), _) => format!("type {t} id {id}"),
            (Some(t), None, Some(n)) => format!("type {t} name {n}"),
            (Some(t), None, None) => format!("type {t}"),
            _ => "resource".to_string(),
        };
        let mut s = format!("{what} lang {:#x}: {} B", self.lang, self.size);
        match self.file_offset {
            Some(off) => s.push_str(&format!(" at file offset {off:#x}")),
            None => s.push_str(" (not in file — memory-only)"),
        }
        if let Some(e) = self.entropy {
            s.push_str(&format!(", entropy {e:.4}"));
        }
        if self.bytes_in_file < self.size as usize {
            s.push_str(&format!(
                ", only {}/{} B present",
                self.bytes_in_file, self.size
            ));
        }
        if let Some(m) = &self.magic {
            s.push_str(&format!(", magic {m:?}"));
        }
        if self.looks_like_pe {
            s.push_str(", looks like a PE image");
        }
        if let Some(h) = &self.sha256 {
            s.push_str(&format!(", sha256 {h}"));
        }
        s
    }
}

/// Every leaf in the resource tree, or an empty vector when the tree cannot
/// be read.  Never fails: a caller cannot act on an unreadable resource tree
/// anyway, and turning it into an error would make `analyze` fallible for a
/// sample whose *other* facts are perfectly readable.
pub fn walk_resources(pe: &PeHeader, image: &[u8]) -> Vec<ResourceEntry> {
    let dd = &pe.nt_headers.optional_header.data_directory[RESOURCE_DIRECTORY_INDEX];
    if dd.virtual_address == 0 || dd.size == 0 {
        return Vec::new();
    }
    let Some(base) = pe.rva_to_offset(dd.virtual_address) else {
        return Vec::new();
    };
    let Some(win) = image.get(base as usize..) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let Some(types) = read_directory(win, 0) else {
        return Vec::new();
    };
    for (type_raw, type_off) in types {
        if !is_directory(type_off) {
            continue;
        }
        let (type_id, type_name) = decode_name(win, type_raw);
        let Some(names) = read_directory(win, directory_offset(type_off)) else {
            continue;
        };
        for (name_raw, name_off) in names {
            if !is_directory(name_off) {
                continue;
            }
            let (name_id, name) = decode_name(win, name_raw);
            let Some(langs) = read_directory(win, directory_offset(name_off)) else {
                continue;
            };
            for (lang_raw, data_off) in langs {
                if is_directory(data_off) {
                    continue;
                }
                let off = data_off as usize;
                let (Some(data_rva), Some(size)) = (u32_at(win, off), u32_at(win, off + 4)) else {
                    continue;
                };
                out.push(ResourceEntry {
                    type_id,
                    type_name: type_name.clone(),
                    name_id,
                    name: name.clone(),
                    lang: lang_raw,
                    data_rva,
                    size,
                });
            }
        }
    }
    out
}

/// Every resource of at least [`LARGE_RESOURCE_MIN`] bytes, with the payload
/// facts a report needs.
pub fn large_resources(pe: &PeHeader, image: &[u8]) -> Vec<LargeResource> {
    walk_resources(pe, image)
        .into_iter()
        .filter(|e| e.size >= LARGE_RESOURCE_MIN)
        .map(|e| {
            // `rva_to_offset` happily returns an offset past EOF (the measured
            // `Packed` payload lands 1.5 MB past the end), so the offset is
            // only reported when the file really has something there.
            let file_offset = pe
                .rva_to_offset(e.data_rva)
                .filter(|off| (*off as usize) < image.len());

            let (bytes_in_file, entropy, sha256, magic, looks_like_pe) = match file_offset {
                Some(off) => {
                    let slice = &image[off as usize..];
                    let take = slice.len().min(e.size as usize);
                    let bytes = &slice[..take];
                    let complete = take == e.size as usize;
                    (
                        take,
                        Some(shannon_entropy(bytes)),
                        if complete {
                            Some(sha256_hex(bytes))
                        } else {
                            None
                        },
                        printable_prefix(bytes, 16),
                        is_pe_image(bytes),
                    )
                }
                None => (0, None, None, None, false),
            };

            LargeResource {
                type_id: e.type_id,
                type_name: e.type_name,
                name_id: e.name_id,
                name: e.name,
                lang: e.lang,
                data_rva: e.data_rva,
                size: e.size,
                file_offset,
                bytes_in_file,
                entropy,
                sha256,
                magic,
                looks_like_pe,
            }
        })
        .collect()
}

/// Lower-case hex SHA-256.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Longest printable ASCII prefix up to `max` bytes, or `None` when fewer
/// than 4 bytes are printable.  The measured `MinProtection` payload starts
/// `58 4d 50 32 51 48 5f 86` → `"XMP2QH_"`, so the 8th byte being
/// non-printable must not hide the 7 printable ones.
fn printable_prefix(bytes: &[u8], max: usize) -> Option<String> {
    let n = bytes
        .iter()
        .copied()
        .take(max)
        .take_while(|b| (0x20..0x7f).contains(b))
        .count();
    if n >= 4 {
        Some(String::from_utf8_lossy(&bytes[..n]).into_owned())
    } else {
        None
    }
}

/// `true` when `bytes` starts with a plausible `MZ` + `PE\0\0` pair.
fn is_pe_image(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return false;
    }
    let e = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    e + 4 <= bytes.len() && &bytes[e..e + 4] == b"PE\x00\x00"
}

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    let b = d.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    let b = d.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn is_directory(raw: u32) -> bool {
    raw & NAME_IS_STRING != 0
}

fn directory_offset(raw: u32) -> usize {
    (raw & OFFSET_MASK) as usize
}

fn read_directory(win: &[u8], off: usize) -> Option<Vec<(u32, u32)>> {
    let named = u16_at(win, off + 12)? as usize;
    let ided = u16_at(win, off + 14)? as usize;
    let total = named + ided;
    if total > MAX_ENTRIES_PER_DIRECTORY {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        let e = off + DIRECTORY_HEADER_SIZE + i * DIRECTORY_ENTRY_SIZE;
        out.push((u32_at(win, e)?, u32_at(win, e + 4)?));
    }
    Some(out)
}

fn decode_name(win: &[u8], raw: u32) -> (Option<u32>, Option<String>) {
    if !is_directory(raw) {
        return (Some(raw), None);
    }
    let off = directory_offset(raw);
    let Some(len) = u16_at(win, off) else {
        return (None, None);
    };
    let start = off + 2;
    let end = start + len as usize * 2;
    let Some(bytes) = win.get(start..end) else {
        return (None, None);
    };
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    (None, Some(String::from_utf16_lossy(&units)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal, hand-written resource tree with one leaf so the
    /// walker can be tested without a real sample.
    ///
    /// Layout (offsets relative to the resource base):
    /// `0x00` type directory -> entry(type 10, dir 0x20)
    /// `0x20` name directory -> entry(id 101, dir 0x40)
    /// `0x40` lang directory -> entry(lang 0x409, data entry 0x60)
    /// `0x60` data entry    -> { rva, size, codepage, reserved }
    fn tree(data_rva: u32, size: u32) -> Vec<u8> {
        let mut b = vec![0u8; 0x70];
        let wdir = |b: &mut Vec<u8>, off: usize, named: u16, ided: u16, name: u32, sub: u32| {
            b[off + 12..off + 14].copy_from_slice(&named.to_le_bytes());
            b[off + 14..off + 16].copy_from_slice(&ided.to_le_bytes());
            b[off + 16..off + 20].copy_from_slice(&name.to_le_bytes());
            b[off + 20..off + 24].copy_from_slice(&sub.to_le_bytes());
        };
        wdir(&mut b, 0x00, 0, 1, RT_RCDATA, 0x8000_0000 | 0x20);
        wdir(&mut b, 0x20, 0, 1, 101, 0x8000_0000 | 0x40);
        wdir(&mut b, 0x40, 0, 1, 0x409, 0x60);
        b[0x60..0x64].copy_from_slice(&data_rva.to_le_bytes());
        b[0x64..0x68].copy_from_slice(&size.to_le_bytes());
        b
    }

    #[test]
    fn printable_prefix_finds_the_measured_magic_despite_a_nonprintable_byte() {
        // Measured head of the 伦伦 payload: 58 4d 50 32 51 48 5f 86.
        let m = printable_prefix(&[0x58, 0x4d, 0x50, 0x32, 0x51, 0x48, 0x5f, 0x86], 16);
        assert_eq!(m.as_deref(), Some("XMP2QH_"));
        // Too short to be a magic is not a magic.
        assert_eq!(printable_prefix(b"MZ\x90\x00", 16), None);
        assert_eq!(printable_prefix(&[0xff; 32], 16), None);
    }

    #[test]
    fn pe_detection_requires_a_real_header_pair() {
        let mut good = vec![0u8; 0x100];
        good[0..2].copy_from_slice(b"MZ");
        good[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        good[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        assert!(is_pe_image(&good));

        // "MZ" with a garbage e_lfanew is not a PE.
        let mut bad = good.clone();
        bad[0x3c..0x40].copy_from_slice(&0x1000u32.to_le_bytes());
        assert!(!is_pe_image(&bad));
        assert!(!is_pe_image(b"MZ"));
        assert!(!is_pe_image(&[]));
    }

    #[test]
    fn walker_uses_rva_to_offset_and_reports_truncated_payloads_as_unhashed() {
        let mut image = vec![0u8; 0x400];
        let tree_bytes = tree(0x200, 0x100);
        image[0x100..0x100 + tree_bytes.len()].copy_from_slice(&tree_bytes);
        // Fill the payload region with a known pattern.
        for i in 0..0x100 {
            image[0x200 + i] = i as u8;
        }

        let mut pe = crate::test_support::pe_with_sections(vec![
            crate::test_support::sec_at(".rsrc", 0x400, 0x400, 0x4000_0040, 0x0),
        ]);
        // Point the resource data directory at RVA 0x100 (where the tree is).
        pe.nt_headers.optional_header.data_directory[RESOURCE_DIRECTORY_INDEX] =
            mida_pe::ImageDataDirectory {
                virtual_address: 0x100,
                size: 0x70,
            };

        let entries = walk_resources(&pe, &image);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].type_id, Some(RT_RCDATA));
        assert_eq!(entries[0].name_id, Some(101));
        assert_eq!(entries[0].lang, 0x409);
        assert_eq!(entries[0].data_rva, 0x200);
        assert_eq!(entries[0].size, 0x100);

        // `large_resources` filters at 1 MiB, so a 256-byte resource is
        // deliberately not reported as a payload.
        assert!(large_resources(&pe, &image).is_empty());

        // Declare it large: the walker now reports it, and because the file
        // cannot hold that many bytes it must NOT emit a sha256.
        let big = u32::MAX;
        let tree_bytes = tree(0x200, big);
        image[0x100..0x100 + tree_bytes.len()].copy_from_slice(&tree_bytes);
        let res = large_resources(&pe, &image);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].size, big);
        assert!(!res[0].fully_in_file());
        assert_eq!(res[0].sha256, None, "a truncated slice must not be hashed");
        assert!(res[0].entropy.is_some());
        assert!(!res[0].looks_like_pe);
    }

    #[test]
    fn a_data_rva_past_eof_is_reported_as_absent_not_as_an_offset() {
        // Measured on zz_test.exe: the `Packed` payload's RVA maps past EOF.
        let tree_bytes = tree(0x2000, 0x100);
        let mut image = vec![0u8; 0x400];
        image[0x100..0x100 + tree_bytes.len()].copy_from_slice(&tree_bytes);
        let mut pe = crate::test_support::pe_with_sections(vec![
            crate::test_support::sec_at(".rsrc", 0x400, 0x400, 0x4000_0040, 0x0),
        ]);
        pe.nt_headers.optional_header.data_directory[RESOURCE_DIRECTORY_INDEX] =
            mida_pe::ImageDataDirectory {
                virtual_address: 0x100,
                size: 0x70,
            };
        let entries = walk_resources(&pe, &image);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data_rva, 0x2000);
        // Nothing readable in the file -> no bytes, no entropy, no hash.
        let res = large_resources(&pe, &image);
        assert!(res.is_empty(), "1 MiB filter drops it before the read");
    }

    #[test]
    fn missing_or_empty_resource_directory_is_not_an_error() {
        let pe = crate::test_support::pe_with_sections(vec![]);
        let image = vec![0u8; 0x100];
        assert!(walk_resources(&pe, &image).is_empty());
        assert!(large_resources(&pe, &image).is_empty());
    }
}
