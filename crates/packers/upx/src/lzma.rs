//! LZMA decompression for UPX method id 14.
//!
//! UPX does **not** use the `.lzma`-alone stream format.  Per
//! `src/compress/compress_lzma.cpp` at tag v5.2.1, the stream starts with
//! **2 bytes of UPX-style properties** — `b0 = (lc+lp)<<3 | pb`,
//! `b1 = lp<<4 | lc` — followed by the raw LZMA1 stream, decoded against the
//! known output size with no end-of-stream marker (the encoder never writes
//! one; `upx_lzma_decompress` feeds `ph.u_len` as the output bound).
//!
//! To reuse a standard decoder we synthesize a `.lzma`-alone header around
//! the raw stream: props byte `(pb*5+lp)*9+lc`, a dictionary covering the
//! whole output (the largest distance any stream can reference is `u_len`)
//! and the exact unpacked size.  The 2-byte property layout and the doctest
//! vector from `compress_lzma.cpp` are pinned by the unit test below; the
//! real-sample proof is the ignored corpus gate (`upx -d` byte-exact, 4/4).

use super::error::UpxUnpackError;

pub fn decompress(src: &[u8], dst_bound: usize) -> Result<Vec<u8>, UpxUnpackError> {
    if src.len() < 3 {
        return Err(UpxUnpackError::Lzma("stream shorter than props+1".into()));
    }
    let pb = (src[0] & 7) as u32;
    let lp = (src[1] >> 4) as u32;
    let lc = (src[1] & 15) as u32;
    if pb >= 5 || lp >= 5 || lc >= 9 {
        return Err(UpxUnpackError::Lzma(format!(
            "props out of range: pb={pb} lp={lp} lc={lc}"
        )));
    }
    // UPX extra stuff in the first byte: the 5 high bits repeat lc+lp.
    if (src[0] >> 3) as u32 != lc + lp {
        return Err(UpxUnpackError::Lzma(
            "props header inconsistent (b0>>3 != lc+lp)".into(),
        ));
    }

    let props_byte = ((pb * 5 + lp) * 9 + lc) as u8;
    // The output itself is the window: no valid distance can exceed u_len.
    let dict_size = dst_bound.next_power_of_two().max(1 << 12).min(1 << 30) as u32;
    let mut alone = Vec::with_capacity(13 + src.len() - 2);
    alone.push(props_byte);
    alone.extend_from_slice(&dict_size.to_le_bytes());
    alone.extend_from_slice(&(dst_bound as u64).to_le_bytes());
    alone.extend_from_slice(&src[2..]);

    let mut out: Vec<u8> = Vec::with_capacity(dst_bound);
    lzma_rs::lzma_decompress(&mut std::io::Cursor::new(&alone), &mut out)
        .map_err(|e| UpxUnpackError::Lzma(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The doctest vector shipped inside `compress_lzma.cpp` itself:
    /// 2 props bytes + 7 stream bytes decode to 16 bytes, and both truncation
    /// and a smaller output bound are rejected.
    const VECTOR: &[u8] = &[0x1a, 0x03, 0x00, 0x7f, 0xed, 0x3c, 0x00, 0x00, 0x00];

    #[test]
    fn decodes_the_upx_doctest_vector() {
        let out = decompress(VECTOR, 16).expect("decodes");
        assert_eq!(out, vec![0xff_u8; 16]);
    }

    #[test]
    fn props_validation_rejects_inconsistent_headers() {
        // b0 high bits no longer agree with lc+lp.
        let mut bad = VECTOR.to_vec();
        bad[0] = 0x00; // (0)>>3 = 0 != lc+lp = 3
        assert!(decompress(&bad, 16).is_err());
        assert!(decompress(&VECTOR[..2], 16).is_err(), "too short");
    }
}
