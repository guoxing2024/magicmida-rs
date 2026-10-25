//! UCL NRV2E decompressor, `le32` bit-stream variant — method id 8, the
//! default for UPX's PE output.
//!
//! Direct port of UCL 1.03 `src/n2e_d.c` (as vendored by UPX v5.2.1 in
//! `vendor/ucl`, fetched from `github.com/upx/upx-vendor-ucl`, branch
//! `upx-vendor`) with the `getbit_le32` bit reader from `src/getbit.h`:
//! the bit channel consumes 32-bit little-endian words MSB-first, and the
//! words share one byte stream with the raw bytes (literals, the `m_off`
//! low byte) — a word is fetched whenever the bit buffer empties, a raw
//! byte is consumed between bit fetches.
//!
//! The port was verified two ways before it existed in this file: a Python
//! prototype (`OUT\upx_unpack_proto.py`) decoded all three NRV2E corpus
//! samples with matching `u_adler`, and a hand-built bit stream
//! (`OUT\nrv2e_encode.py`, BFS over the decoder's own ops) pins the exact
//! bit semantics in the unit test below.

use super::error::UpxUnpackError;

struct BitReader<'a> {
    src: &'a [u8],
    ilen: usize,
    bb: u32,
    bc: u32,
}

impl<'a> BitReader<'a> {
    /// `getbit_le32(bb, bc, src, ilen)`: on an empty buffer fetch the LE32
    /// word at `ilen` and yield its MSB; otherwise yield the next bit down.
    fn bit(&mut self) -> Result<bool, UpxUnpackError> {
        if self.bc == 0 {
            if self.ilen + 4 > self.src.len() {
                return Err(UpxUnpackError::Nrv2e("input overrun (bit word)"));
            }
            self.bb = u32::from_le_bytes([
                self.src[self.ilen],
                self.src[self.ilen + 1],
                self.src[self.ilen + 2],
                self.src[self.ilen + 3],
            ]);
            self.ilen += 4;
            self.bc = 31;
            return Ok((self.bb >> 31) & 1 == 1);
        }
        self.bc -= 1;
        Ok((self.bb >> self.bc) & 1 == 1)
    }

    fn byte(&mut self) -> Result<u8, UpxUnpackError> {
        let b = *self
            .src
            .get(self.ilen)
            .ok_or(UpxUnpackError::Nrv2e("input overrun (raw byte)"))?;
        self.ilen += 1;
        Ok(b)
    }
}

/// Decompress `src` (one NRV2E `le32` stream) into at most `dst_bound` bytes.
///
/// Returns the decoded bytes; the caller checks the length against
/// `PackHeader::u_len` and verifies `u_adler`.
pub fn decompress(src: &[u8], dst_bound: usize) -> Result<Vec<u8>, UpxUnpackError> {
    let mut r = BitReader {
        src,
        ilen: 0,
        bb: 0,
        bc: 0,
    };
    let mut dst: Vec<u8> = Vec::with_capacity(dst_bound.min(1 << 24));
    let mut last_m_off: u32 = 1;

    loop {
        // literal run
        while r.bit()? {
            if r.ilen >= src.len() {
                return Err(UpxUnpackError::Nrv2e("input overrun (literal)"));
            }
            if dst.len() >= dst_bound {
                return Err(UpxUnpackError::Nrv2e("output overrun (literal)"));
            }
            let b = r.byte()?;
            dst.push(b);
        }

        // match offset
        let mut m_off_loop: u64 = 1;
        loop {
            let b = r.bit()? as u64;
            m_off_loop = m_off_loop * 2 + b;
            // n2e_d.c: fail(m_off > UCL_UINT32_C(0xffffff) + 3) — the EOF
            // encoding tops out exactly at 0x1000002.
            if m_off_loop > 0xFF_FFFF_u64 + 3 {
                return Err(UpxUnpackError::Nrv2e("lookbehind overrun (offset)"));
            }
            if r.bit()? {
                break;
            }
            let d = r.bit()? as u64;
            m_off_loop = (m_off_loop - 1) * 2 + d;
        }

        let m_off: u32;
        let mut m_len: u32;
        if m_off_loop == 2 {
            // reuse the previous offset
            m_off = last_m_off;
            m_len = r.bit()? as u32;
        } else {
            let raw = ((m_off_loop - 3) as u32)
                .wrapping_mul(256)
                .wrapping_add(r.byte()? as u32);
            if raw == 0xFFFF_FFFF {
                break; // EOF marker
            }
            m_len = (!raw) & 1;
            m_off = (raw >> 1)
                .checked_add(1)
                .ok_or(UpxUnpackError::Nrv2e("offset overflow"))?;
            last_m_off = m_off;
        }

        // match length
        if m_len != 0 {
            m_len = 1 + r.bit()? as u32;
        } else if r.bit()? {
            m_len = 3 + r.bit()? as u32;
        } else {
            m_len += 1;
            loop {
                m_len = m_len * 2 + r.bit()? as u32;
                if m_len as usize >= dst_bound {
                    return Err(UpxUnpackError::Nrv2e("output overrun (length)"));
                }
                if r.bit()? {
                    break;
                }
            }
            m_len += 3;
        }
        if m_off > 0x500 {
            m_len += 1; // the far-match +1 of n2e_d.c
        }

        let total = m_len as usize + 1;
        if m_off as usize > dst.len() {
            return Err(UpxUnpackError::Nrv2e("lookbehind overrun (copy)"));
        }
        if dst.len() + total > dst_bound {
            return Err(UpxUnpackError::Nrv2e("output overrun (copy)"));
        }
        let pos = dst.len() - m_off as usize;
        for i in 0..total {
            let b = dst[pos + i];
            dst.push(b);
        }
    }
    Ok(dst)
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
