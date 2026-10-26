//! UCL NRV2B decompressor, `le32` bit-stream variant — method id 2.
//!
//! The decoder core lives in [`crate::nrv`], shared with NRV2D and NRV2E.
//! Direct port of UCL 1.03 `src/n2b_d.c` (as vendored by UPX v5.2.1).
//! NRV2B is the odd one out of the three: its offset loop has no second
//! branch (`do { m_off = m_off*2 + b } while (!b)`), the raw-offset byte
//! feeds the offset whole (`last_m_off = ++m_off`, no LSB theft), the
//! length tree starts from two fresh bits, and the far-match threshold is
//! 0xd00, not 0x500.

use super::error::UpxUnpackError;
use super::nrv::{self, NrvVariant};

/// Decompress `src` (one NRV2B `le32` stream) into at most `dst_bound` bytes.
///
/// Returns the decoded bytes; the caller checks the length against
/// `PackHeader::u_len` and verifies `u_adler`.
pub fn decompress(src: &[u8], dst_bound: usize) -> Result<Vec<u8>, UpxUnpackError> {
    nrv::decompress(src, dst_bound, NrvVariant::N2b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built vector from `OUT\nrv2bd_encode.py` (BFS over the decoder's
    /// own bit ops, self-verified against a Python port of `n2b_d.c` before
    /// it was pinned here): six literals, one direct match through the
    /// extended length path (two fresh bits (0,0), unary 3, +2 → copy 6),
    /// one repeat-offset match through the two-fresh-bit path (copy 3), one
    /// through (0,1) (copy 2), a trailing literal, and the EOF marker.
    const STREAM: &[u8] = &[
        0x00, 0x8b, 0x99, 0xfd, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x05, 0x66, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x80, 0x04, 0xff,
    ];
    const EXPECTED: &[u8] = b"abcdefabcdefabcdef";

    #[test]
    fn decodes_the_hand_built_three_match_vector() {
        let out = decompress(STREAM, EXPECTED.len()).expect("decodes");
        assert_eq!(out, EXPECTED);
    }

    #[test]
    fn a_truncated_stream_is_an_error_not_a_panic() {
        for cut in [0usize, 1, 3, 4, 8, STREAM.len() - 1] {
            let r = decompress(&STREAM[..cut], EXPECTED.len());
            assert!(r.is_err(), "cut at {cut} must not decode");
        }
    }

    #[test]
    fn a_too_small_output_bound_is_an_error_not_a_panic() {
        let r = decompress(STREAM, EXPECTED.len() - 1);
        assert!(r.is_err(), "the bound must be enforced");
    }

    #[test]
    fn empty_input_is_an_error_not_a_panic() {
        // A stream needs at least one 32-bit word before anything can decode.
        assert!(decompress(&[], 16).is_err());
    }
}
