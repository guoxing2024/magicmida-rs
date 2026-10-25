//! The 32-byte `PackHeader`, byte-for-byte as written by UPX 5.2.1.
//!
//! Authoritative source: `src/packhead.cpp` at tag v5.2.1
//! (`putPackHeader` / `decodePackHeaderFromBuf`), verified against four
//! locally packed samples (`OUT\upx_layout.py`, `OUT\upx_adler.py`).

/// PackHeader format byte for PE32 (`UPX_F_W32PE_I386`). Measured: the x86
/// sample's header reads 9.
pub const FMT_W32PE_I386: u8 = 9;
/// PackHeader format byte for PE32+/AMD64 (`UPX_F_W64PE_AMD64`). Measured: all
/// three x64 samples' headers read 36.
pub const FMT_W64PE_AMD64: u8 = 36;

/// Method ids from `conf.h`; measured defaults: plain pack → 8, `--lzma` → 14.
pub const M_NRV2B_LE32: u8 = 2;
pub const M_NRV2D_LE32: u8 = 5;
pub const M_NRV2E_LE32: u8 = 8;
pub const M_LZMA: u8 = 14;

/// `true` for the method ids this project knows how to name.
pub fn is_known_method(m: u8) -> bool {
    matches!(m, M_NRV2B_LE32 | M_NRV2D_LE32 | M_NRV2E_LE32 | M_LZMA)
}

/// `true` for the PE format ids produced by UPX for Windows.
pub fn is_pe_format(f: u8) -> bool {
    matches!(f, FMT_W32PE_I386 | FMT_W64PE_AMD64)
}

/// A parsed `PackHeader`.  `file_offset` is where the 32-byte header starts in
/// the packed file — the placement itself is *not* fixed (see [`find_pack_header`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackHeader {
    /// File offset of the `'UPX!'` magic.
    pub file_offset: u64,
    /// Packer stub/header version. Measured: 13 for UPX 5.2.1.
    pub version: u8,
    /// Format id ([`FMT_W32PE_I386`] / [`FMT_W64PE_AMD64`] for our samples).
    pub format: u8,
    /// Compression method id ([`M_NRV2E_LE32`] by default, [`M_LZMA`] with `--lzma`).
    pub method: u8,
    /// Compression level, low nibble (`level & 15` per `decodePackHeaderFromBuf`).
    pub level: u8,
    /// Adler-32 of the uncompressed stream (seeded; see [`adler32`]).
    pub u_adler: u32,
    /// Adler-32 of the compressed stream. Measured: equals `adler32(stream)` 4/4.
    pub c_adler: u32,
    /// Uncompressed stream length in bytes.
    pub u_len: u32,
    /// Compressed stream length in bytes.
    pub c_len: u32,
    /// The original file's size, including its copied overlay.
    pub u_file_size: u32,
    /// Filter id applied to the code before compression (73 = `0x49` for x64,
    /// 38 = `0x26` for x86 in every measured sample).
    pub filter: u8,
    /// Filter cto byte.
    pub filter_cto: u8,
    /// MRU parameter (0 for NRV/LZMA PE output).
    pub n_mru: u8,
}

impl PackHeader {
    /// Human name of the compression method.
    pub fn method_label(&self) -> &'static str {
        match self.method {
            M_NRV2B_LE32 => "nrv2b-le32",
            M_NRV2D_LE32 => "nrv2d-le32",
            M_NRV2E_LE32 => "nrv2e-le32",
            M_LZMA => "lzma",
            _ => "unknown",
        }
    }

    /// Human name of the format.
    pub fn format_label(&self) -> &'static str {
        match self.format {
            FMT_W32PE_I386 => "pe32",
            FMT_W64PE_AMD64 => "pe32+-amd64",
            _ => "unknown",
        }
    }

    /// Recompute the header checksum over the bytes this header came from.
    ///
    /// `get_packheader_checksum` sums `bytes[+4 .. +31]` (27 bytes, offsets 4
    /// through 30 inclusive) modulo 251 and compares against byte `+31`.
    pub fn checksum_ok(&self, image: &[u8]) -> bool {
        let start = self.file_offset as usize;
        let end = start + 32;
        if end > image.len() {
            return false;
        }
        let mut sum: u32 = 0;
        for &b in &image[start + 4..start + 31] {
            sum += b as u32;
        }
        (sum % 251) as u8 == image[start + 31]
    }
}

/// Parse a `PackHeader` at exactly `offset` without validating anything but
/// the field ranges.  Used by [`find_pack_header`] after the magic matches.
fn parse_at(image: &[u8], offset: usize) -> Option<PackHeader> {
    if offset + 32 > image.len() {
        return None;
    }
    let le32 = |o: usize| u32::from_le_bytes([image[o], image[o + 1], image[o + 2], image[o + 3]]);
    Some(PackHeader {
        file_offset: offset as u64,
        version: image[offset + 4],
        format: image[offset + 5],
        method: image[offset + 6],
        level: image[offset + 7],
        u_adler: le32(offset + 8),
        c_adler: le32(offset + 12),
        u_len: le32(offset + 16),
        c_len: le32(offset + 20),
        u_file_size: le32(offset + 24),
        filter: image[offset + 28],
        filter_cto: image[offset + 29],
        n_mru: image[offset + 30],
    })
}

/// Find the file's `PackHeader`.
///
/// The placement is **not** fixed — measured on four UPX 5.2.1 PE samples:
///
/// - MSVC-built input (0x400 file alignment): the header sits in the PE
///   header slack, ending exactly at `UPX1`'s raw start (`0x3e0`).
/// - GNU-built inputs (0x200 alignment): the header sits inside `UPX1`'s raw
///   data, preceded by UPX's version string (`0x205`), and for the x86 sample
///   it overlaps `UPX1`'s start by 21 bytes (`0x1f5`).
///
/// So the search scans every `'UPX!'` occurrence and keeps the first one that
/// survives the checks `decodePackHeaderFromBuf` applies: a valid header
/// checksum (version >= 10 has one), a known method, and sane lengths
/// (`u_len >= c_len >= 2`; `ph_decompress` throws when `u_len < c_len`).
pub fn find_pack_header(image: &[u8]) -> Option<PackHeader> {
    let mut from = 0usize;
    while from + 4 <= image.len() {
        let hit = image[from..]
            .windows(4)
            .position(|w| w == b"UPX!")
            .map(|p| p + from)?;
        from = hit + 1;
        let Some(ph) = parse_at(image, hit) else {
            continue;
        };
        // Version 10 introduced the header checksum; older headers are only
        // detectable heuristically and are not this project's target.
        if !(10..=15).contains(&ph.version) {
            continue;
        }
        if !is_known_method(ph.method) || !is_pe_format(ph.format) {
            continue;
        }
        if ph.c_len < 2 || ph.u_len < ph.c_len {
            continue;
        }
        if !ph.checksum_ok(image) {
            continue;
        }
        return Some(ph);
    }
    None
}

/// Standard Adler-32 seeded with 1.
///
/// Measured on all four samples: `c_adler == adler32(compressed stream)` —
/// the same value `zlib.adler32(stream, 1)` produces, which is what let the
/// measurement be cross-checked with Python before this implementation
/// existed.  Chunked per the zlib reference so the modulo runs every 5552
/// bytes instead of every byte.
pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// Test fixtures shared by this crate's unit tests (the detector's tests need
/// a real header shape, and duplicating the checksum rule would risk drift).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// The measured `mida_x64_nrv.upx.exe` header, field for field.
    pub(crate) fn sample_header() -> PackHeader {
        PackHeader {
            file_offset: 0,
            version: 13,
            format: FMT_W64PE_AMD64,
            method: M_NRV2E_LE32,
            level: 7,
            u_adler: 0xC6_4A_16_1F,
            c_adler: 0x76_BC_55_DC,
            u_len: 4_344_114,
            c_len: 1_374_037,
            u_file_size: 6_379_269,
            filter: 73,
            filter_cto: 55,
            n_mru: 0,
        }
    }

    /// Serialise with UPX's own checksum rule (`packhead.cpp`).
    pub(crate) fn build_header(ph: &PackHeader) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(b"UPX!");
        buf[4] = ph.version;
        buf[5] = ph.format;
        buf[6] = ph.method;
        buf[7] = ph.level;
        buf[8..12].copy_from_slice(&ph.u_adler.to_le_bytes());
        buf[12..16].copy_from_slice(&ph.c_adler.to_le_bytes());
        buf[16..20].copy_from_slice(&ph.u_len.to_le_bytes());
        buf[20..24].copy_from_slice(&ph.c_len.to_le_bytes());
        buf[24..28].copy_from_slice(&ph.u_file_size.to_le_bytes());
        buf[28] = ph.filter;
        buf[29] = ph.filter_cto;
        buf[30] = ph.n_mru;
        let sum: u32 = buf[4..31].iter().map(|&b| b as u32).sum();
        buf[31] = (sum % 251) as u8;
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::{build_header, sample_header};

    #[test]
    fn checksum_round_trips_and_rejects_a_corrupted_byte() {
        let ph = sample_header();
        let buf = build_header(&ph);
        let parsed = parse_at(&buf, 0).expect("parses");
        assert_eq!(parsed, ph);
        assert!(parsed.checksum_ok(&buf));
        // Flip one payload byte inside the summed range: the checksum must
        // reject it.  This is what keeps a spoofed "UPX!" from counting.
        let mut bad = buf.clone();
        bad[10] ^= 0x40;
        assert!(!parsed.checksum_ok(&bad));
    }

    #[test]
    fn find_skips_invalid_magic_hits_and_keeps_the_valid_one() {
        let ph = sample_header();
        let mut image = vec![0u8; 64];
        // A stray magic with no checksum behind it: must be skipped, not used.
        image[0..4].copy_from_slice(b"UPX!");
        let real = build_header(&ph);
        image[24..56].copy_from_slice(&real);
        let mut found = find_pack_header(&image).expect("the valid header must be found");
        found.file_offset = 0; // normalise for comparison
        assert_eq!(found, ph);
    }

    #[test]
    fn find_returns_none_without_a_valid_header() {
        assert!(find_pack_header(&vec![0u8; 64]).is_none());
        // Magic present but garbage fields (unknown method): skipped.
        let mut image = vec![0u8; 64];
        image[0..4].copy_from_slice(b"UPX!");
        image[6] = 0xEE; // method
        image[7] = 13; // version (would need a checksum, but method fails first)
        assert!(find_pack_header(&image).is_none());
    }

    #[test]
    fn method_and_format_labels_name_the_measured_values() {
        let ph = sample_header();
        assert_eq!(ph.method_label(), "nrv2e-le32");
        assert_eq!(ph.format_label(), "pe32+-amd64");
        let x86 = PackHeader {
            method: M_LZMA,
            format: FMT_W32PE_I386,
            ..ph
        };
        assert_eq!(x86.method_label(), "lzma");
        assert_eq!(x86.format_label(), "pe32");
        assert!(is_known_method(M_NRV2B_LE32) && is_known_method(M_NRV2D_LE32));
        assert!(!is_known_method(0) && !is_known_method(255));
        assert!(is_pe_format(FMT_W32PE_I386) && is_pe_format(FMT_W64PE_AMD64));
        assert!(!is_pe_format(1));
    }

    #[test]
    fn adler32_matches_the_reference_vector_and_the_python_crosscheck() {
        // The documented zlib vector.
        assert_eq!(adler32(b"abc"), 0x024D_0127);
        assert_eq!(adler32(b""), 1);
        // Chunking must not change the value (the 5552 boundary is 2 mod 5552
        // for a 5553-byte input).
        let long: Vec<u8> = (0..=255u8).cycle().take(5553).collect();
        let single = {
            let (mut a, mut b) = (1u32, 0u32);
            for &byte in &long {
                a += byte as u32;
                b += a;
                a %= 65521;
                b %= 65521;
            }
            (b << 16) | a
        };
        assert_eq!(adler32(&long), single);
    }
}
