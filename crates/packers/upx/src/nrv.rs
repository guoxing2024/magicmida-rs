//! The shared UCL NRV2B / NRV2D / NRV2E decompressor core, `le32` bit-stream
//! variant — method ids 2, 5 and 8 in UPX's `PackHeader`.
//!
//! Direct port of UCL 1.03 `src/n2b_d.c`, `src/n2d_d.c` and `src/n2e_d.c`
//! (as vendored by UPX v5.2.1, fetched from
//! `github.com/upx/upx-vendor-ucl`, branch `upx-vendor`) with the
//! `getbit_le32` bit reader from `src/getbit.h`: the bit channel consumes
//! 32-bit little-endian words MSB-first, and the words share one byte stream
//! with the raw bytes (literals, the `m_off` low byte) — a word is fetched
//! whenever the bit buffer empties, a raw byte is consumed between bit
//! fetches.
//!
//! ## What actually differs between the three (measured, per .c file)
//!
//! All three share the literal-run loop, the EOF encoding (the raw-offset
//! path computing exactly `0xffff_ffff`), and the copy rule (m_len+1 bytes,
//! overlap allowed).  They differ in exactly four places:
//!
//! | aspect | NRV2B | NRV2D | NRV2E |
//! |---|---|---|---|
//! | offset loop | `do { m_off = m_off*2 + b } while (!b)` — no second branch | `for(;;) { m_off = m_off*2 + b; if (b) break; m_off = (m_off-1)*2 + b; }` | same as NRV2D |
//! | raw-offset byte | feeds `m_off` only | LSB is stolen as the first length bit (`m_len = !raw & 1`), then `m_off = raw>>1 + 1` | same as NRV2D |
//! | length tree after the first bit(s) | two fresh bits, extended on zero | one bit on top of the seed, extended on zero | `m_len0 ? 1+b : (b ? 3+b : extended)` — one selector level more, extended adds 3 not 2 |
//! | far-match threshold | `m_off > 0xd00` | `m_off > 0x500` | `m_off > 0x500` |
//!
//! `last_m_off = ++m_off` in all three: the stored *and* used distance is
//! the raw value plus one.

use super::error::UpxUnpackError;

/// Which of the three NRV2x algorithms a stream uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrvVariant {
    /// UCL NRV2B (`n2b_d.c`) — PackHeader method 2.
    N2b,
    /// UCL NRV2D (`n2d_d.c`) — PackHeader method 5.
    N2d,
    /// UCL NRV2E (`n2e_d.c`) — PackHeader method 8, UPX's PE default.
    N2e,
}

impl NrvVariant {
    /// Algorithm-named error, so a malformed stream always says which
    /// decoder rejected it.
    fn err(self, msg: &'static str) -> UpxUnpackError {
        match self {
            NrvVariant::N2b => UpxUnpackError::Nrv2b(msg),
            NrvVariant::N2d => UpxUnpackError::Nrv2d(msg),
            NrvVariant::N2e => UpxUnpackError::Nrv2e(msg),
        }
    }

    /// The far-match threshold: `m_len += (m_off > X)` per the .c file.
    /// NRV2B uses 0xd00; NRV2D and NRV2E use 0x500.
    fn far_threshold(self) -> u32 {
        match self {
            NrvVariant::N2b => 0xd00,
            NrvVariant::N2d | NrvVariant::N2e => 0x500,
        }
    }
}

/// `getbit_le32` reader: `bb` is the current word, `bc` the bits left in it.
struct BitReader<'a> {
    src: &'a [u8],
    ilen: usize,
    bb: u32,
    bc: u32,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            ilen: 0,
            bb: 0,
            bc: 0,
        }
    }

    /// On an empty buffer fetch the LE32 word at `ilen` and yield its MSB;
    /// otherwise yield the next bit down.
    fn bit(&mut self) -> Result<bool, UpxUnpackError> {
        if self.bc == 0 {
            if self.ilen + 4 > self.src.len() {
                return Err(UpxUnpackError::Bitstream("input overrun (bit word)"));
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
            .ok_or(UpxUnpackError::Bitstream("input overrun (raw byte)"))?;
        self.ilen += 1;
        Ok(b)
    }
}

/// Decompress `src` (one NRV2B/D/E `le32` stream) into at most `dst_bound`
/// bytes.
///
/// Returns the decoded bytes; the caller checks the length against
/// `PackHeader::u_len` and verifies `u_adler`.
pub fn decompress(
    src: &[u8],
    dst_bound: usize,
    v: NrvVariant,
) -> Result<Vec<u8>, UpxUnpackError> {
    let mut r = BitReader::new(src);
    let mut dst: Vec<u8> = Vec::with_capacity(dst_bound.min(1 << 24));
    let mut last_m_off: u32 = 1;

    loop {
        // literal run — identical in all three variants
        while r.bit()? {
            if r.ilen >= src.len() {
                return Err(v.err("input overrun (literal)"));
            }
            if dst.len() >= dst_bound {
                return Err(v.err("output overrun (literal)"));
            }
            let b = r.byte()?;
            dst.push(b);
        }

        // match offset — NRV2B's loop has no second branch.
        // The loop variable keeps the `_loop` suffix so the typed `m_off`
        // below can shadow it without an uninitialized read.
        let mut m_off_loop: u64 = 1;
        if v == NrvVariant::N2b {
            // n2b_d.c: do { m_off = m_off*2 + b; check } while (!b);
            // the EOF encoding tops out exactly at 0x1000002.
            loop {
                m_off_loop = m_off_loop * 2 + r.bit()? as u64;
                if m_off_loop > 0xFF_FFFF_u64 + 3 {
                    return Err(v.err("lookbehind overrun (offset)"));
                }
                if r.bit()? {
                    break;
                }
            }
        } else {
            // n2d_d.c / n2e_d.c: for (;;) { m_off = m_off*2 + b; check;
            // if (b) break; m_off = (m_off-1)*2 + b; }
            // The check sits after the first add only — the second add is
            // re-checked at the top of the next iteration, exactly as in C.
            loop {
                m_off_loop = m_off_loop * 2 + r.bit()? as u64;
                if m_off_loop > 0xFF_FFFF_u64 + 3 {
                    return Err(v.err("lookbehind overrun (offset)"));
                }
                if r.bit()? {
                    break;
                }
                let d = r.bit()? as u64;
                m_off_loop = (m_off_loop - 1) * 2 + d;
            }
        }

        let m_off: u32;
        let mut m_len: u32;
        if m_off_loop == 2 {
            // reuse the previous offset
            m_off = last_m_off;
            m_len = match v {
                // B reads no length bit here; D and E read one.
                NrvVariant::N2b => 0,
                NrvVariant::N2d | NrvVariant::N2e => r.bit()? as u32,
            };
        } else {
            let raw = ((m_off_loop - 3) as u32)
                .wrapping_mul(256)
                .wrapping_add(r.byte()? as u32);
            if raw == 0xFFFF_FFFF {
                break; // EOF marker
            }
            match v {
                // B: the whole raw byte feeds the offset.
                NrvVariant::N2b => {
                    m_off = raw.wrapping_add(1); // last_m_off = ++m_off
                    m_len = 0;
                    last_m_off = m_off;
                }
                // D and E: the byte's LSB is the first length bit.
                NrvVariant::N2d | NrvVariant::N2e => {
                    m_len = (!raw) & 1;
                    m_off = (raw >> 1)
                        .checked_add(1)
                        .ok_or_else(|| v.err("offset overflow"))?; // last_m_off = ++m_off
                    last_m_off = m_off;
                }
            }
        }

        // match length — three different trees
        match v {
            NrvVariant::N2b => {
                // n2b_d.c: m_len = getbit(); m_len = m_len*2 + getbit();
                // two fresh bits in BOTH branches (the seed stays 0).
                m_len = m_len * 2 + r.bit()? as u32;
                m_len = m_len * 2 + r.bit()? as u32;
                if m_len == 0 {
                    m_len = extended(&mut r, v, dst_bound)? + 2;
                }
            }
            NrvVariant::N2d => {
                // n2d_d.c: one bit on top of the seed, extended (+2) on zero.
                m_len = m_len * 2 + r.bit()? as u32;
                if m_len == 0 {
                    m_len = extended(&mut r, v, dst_bound)? + 2;
                }
            }
            NrvVariant::N2e => {
                // n2e_d.c: one selector level more; extended adds 3.
                if m_len != 0 {
                    m_len = 1 + r.bit()? as u32;
                } else if r.bit()? {
                    m_len = 3 + r.bit()? as u32;
                } else {
                    m_len = extended(&mut r, v, dst_bound)? + 3;
                }
            }
        }
        if m_off > v.far_threshold() {
            m_len += 1; // the far-match +1
        }

        let total = m_len as usize + 1;
        if m_off as usize > dst.len() {
            return Err(v.err("lookbehind overrun (copy)"));
        }
        if dst.len() + total > dst_bound {
            return Err(v.err("output overrun (copy)"));
        }
        let pos = dst.len() - m_off as usize;
        for i in 0..total {
            let b = dst[pos + i];
            dst.push(b);
        }
    }
    Ok(dst)
}

/// The unary tail `m_len = 1; do { m_len = m_len*2 + b } while (!b);` shared
/// by all three; the caller adds its own constant (B/D: +2, E: +3).
fn extended(
    r: &mut BitReader<'_>,
    v: NrvVariant,
    dst_bound: usize,
) -> Result<u32, UpxUnpackError> {
    let mut m_len: u32 = 1;
    loop {
        m_len = m_len * 2 + r.bit()? as u32;
        if m_len as usize >= dst_bound {
            return Err(v.err("output overrun (length)"));
        }
        if r.bit()? {
            break;
        }
    }
    Ok(m_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader fetches a fresh LE32 word on an empty buffer and then
    /// yields the remaining bits MSB-first.
    #[test]
    fn the_reader_consumes_le32_words_msb_first() {
        let r_src = 0xA5u32.to_le_bytes(); // 1010_0101 .. 5 data bits used
        let mut r = BitReader::new(&r_src);
        // 31 bits after the first, then the buffer is empty → next fetch
        // overruns a 4-byte source.
        let mut bits = String::new();
        for _ in 0..32 {
            bits.push(if r.bit().unwrap() { '1' } else { '0' });
        }
        assert_eq!(bits, format!("{:032b}", 0xA5));
        assert!(r.bit().is_err(), "4 bytes hold exactly 32 bits");
    }

    /// A raw byte between bit fetches advances the same stream the words
    /// come from — the interleaving the whole format rests on.
    #[test]
    fn raw_bytes_and_bit_words_share_one_stream() {
        let mut src = Vec::new();
        src.extend_from_slice(&0x8000_0000u32.to_le_bytes()); // bit 1, then 31 zeros
        src.push(0xAB);
        let mut r = BitReader::new(&src);
        assert!(r.bit().unwrap());
        assert_eq!(r.byte().unwrap(), 0xAB); // consumed right after the word
        assert!(r.byte().is_err(), "stream is exhausted");
    }

    #[test]
    fn every_variant_names_itself_in_errors() {
        for v in [NrvVariant::N2b, NrvVariant::N2d, NrvVariant::N2e] {
            let e = v.err("boom");
            let s = format!("{e}");
            let name = match v {
                NrvVariant::N2b => "nrv2b",
                NrvVariant::N2d => "nrv2d",
                NrvVariant::N2e => "nrv2e",
            };
            assert!(s.contains(name), "{s} must name {name}");
        }
        // The thresholds are measured, not chosen: B is the odd one out.
        assert_eq!(NrvVariant::N2b.far_threshold(), 0xd00);
        assert_eq!(NrvVariant::N2d.far_threshold(), 0x500);
        assert_eq!(NrvVariant::N2e.far_threshold(), 0x500);
    }
}
