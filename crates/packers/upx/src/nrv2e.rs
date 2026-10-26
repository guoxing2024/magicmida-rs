//! UCL NRV2E decompressor, `le32` bit-stream variant — method id 8, the
//! default for UPX's PE output.
//!
//! The decoder core lives in [`crate::nrv`], shared with NRV2B and NRV2D;
//! this module keeps NRV2E's identity, its provenance, and the hand-built
//! unit vector.  Direct port of UCL 1.03 `src/n2e_d.c` (as vendored by UPX
//! v5.2.1 in `vendor/ucl`, fetched from `github.com/upx/upx-vendor-ucl`,
//! branch `upx-vendor`).
//!
//! The port was verified two ways before it existed in this file: a Python
//! prototype (`OUT\upx_unpack_proto.py`) decoded all three NRV2E corpus
//! samples with matching `u_adler`, and a hand-built bit stream
//! (`OUT\nrv2e_encode.py`, BFS over the decoder's own ops) pins the exact
//! bit semantics in the unit test below.

use super::error::UpxUnpackError;
use super::nrv::{self, NrvVariant};

/// Decompress `src` (one NRV2E `le32` stream) into at most `dst_bound` bytes.
///
/// Returns the decoded bytes; the caller checks the length against
/// `PackHeader::u_len` and verifies `u_adler`.
pub fn decompress(src: &[u8], dst_bound: usize) -> Result<Vec<u8>, UpxUnpackError> {
    nrv::decompress(src, dst_bound, NrvVariant::N2e)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built vector from `OUT\nrv2e_encode.py` (BFS over the decoder's
    /// own bit ops, so it does not depend on any compressor): two matches —
    /// "hello" through the `m_len0 == 0` length path and "he" through the
    /// `m_len0 == 1` path — plus literal runs and the EOF marker.
    const STREAM: &[u8] = &[
        0xed, 0xff, 0xfb, 0xff, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
        0x2c, 0x20, 0x19, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6e, 0x21, 0x20, 0x74, 0x34, 0x20, 0x49,
        0x92, 0x24, 0xe1, 0x65, 0x6e, 0x64, 0x00, 0x00, 0x40, 0x25, 0xff,
    ];
    const EXPECTED: &[u8] = b"hello world, hello again! the end";

    #[test]
    fn decodes_the_hand_built_two_match_vector() {
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
}
