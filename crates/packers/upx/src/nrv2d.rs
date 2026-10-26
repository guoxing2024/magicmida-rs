//! UCL NRV2D decompressor, `le32` bit-stream variant — method id 5.
//!
//! The decoder core lives in [`crate::nrv`], shared with NRV2B and NRV2E.
//! Direct port of UCL 1.03 `src/n2d_d.c` (as vendored by UPX v5.2.1).
//! NRV2D sits between B and E: two-level offset loop and LSB theft like E,
//! but the length tree has no E's extra selector level (seed bit, then
//! `m_len = m_len*2 + b`, extended adds 2) and the far-match threshold is
//! 0x500 like E, not 0xd00 like B.

use super::error::UpxUnpackError;
use super::nrv::{self, NrvVariant};

/// Decompress `src` (one NRV2D `le32` stream) into at most `dst_bound` bytes.
///
/// Returns the decoded bytes; the caller checks the length against
/// `PackHeader::u_len` and verifies `u_adler`.
pub fn decompress(src: &[u8], dst_bound: usize) -> Result<Vec<u8>, UpxUnpackError> {
    nrv::decompress(src, dst_bound, NrvVariant::N2d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built vector from `OUT\nrv2bd_encode.py` (BFS over the decoder's
    /// own bit ops, self-verified against a Python port of `n2d_d.c` before
    /// it was pinned here): six literals, one direct match whose length seed
    /// rides the raw-offset byte's stolen LSB (seed 0, extended unary →
    /// copy 6), one repeat-offset match with seed 1 (copy 2), one with
    /// seed 0 + bit 1 (copy 3), a trailing literal, and the EOF marker.
    const STREAM: &[u8] = &[
        0x12, 0x9a, 0xb2, 0xfd, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x0b, 0x66, 0x54, 0x92, 0x24,
        0x49, 0xff,
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
