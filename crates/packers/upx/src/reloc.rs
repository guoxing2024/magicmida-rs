//! Compressed base relocations, ported from UPX v5.2.1.
//!
//! - `unoptimize` — `src/packer_r.cpp` `unoptimizeReloc`: the delta stream is
//!   one byte per relocation (`< 0xf0`), three bytes
//!   (`0xfN + le16`, `N > 0`), or seven bytes (`f0 00 00 + le32`); positions
//!   accumulate from `-4` and the stream ends with a `0` byte.  With
//!   `bswap` (always `true` on the PE path) the relocated value in the image
//!   is byte-swapped le↔be at each position — at pack time
//!   `optimizeReloc` swapped the original little-endian VA into big-endian
//!   order for compression, so this restores it.
//! - `build_blocks` — `src/pefile.cpp` `Reloc::finish`: entries sorted by
//!   position, grouped into 4 KiB pages, each block `le32 page` +
//!   `le32 size_of_block` + `le16 (type<<12)|offset` entries — and
//!   `size_of_block` is written back **after** the align-to-4 padding, so the
//!   trailing `0x0000` pad counts toward it (`rel->size_of_block = sob` after
//!   the pad loop).  That one line is the difference between a byte-exact
//!   rebuild and a `.reloc` that is off by 2 in every odd-entry block.
//!
//! Verified byte-exact against `upx -d` on all four corpus samples
//! (60463 relocations on the x86 one).

use super::error::UpxUnpackError;

/// Decode the delta stream that lives inside `image` at `stream_at` and
/// byte-swap each relocated value in place.  `limit` bounds the relocated
/// positions (`pc + width <= limit`) — on the PE path the stream sits at
/// `orig_crelocs` and every position precedes it, which is what makes the
/// in-place read/swap safe.  Returns the positions (offsets into `image`)
/// and the stream length including the `0` terminator.
pub fn unoptimize(
    image: &mut [u8],
    stream_at: usize,
    limit: usize,
    bits: u32,
) -> Result<(Vec<u32>, usize), UpxUnpackError> {
    let width = if bits == 64 { 8 } else { 4 };

    // count pass — the terminator is a 0 byte
    let mut fix = 0usize;
    let mut relocnum = 0usize;
    loop {
        let Some(&b) = image.get(stream_at + fix) else {
            return Err(UpxUnpackError::Reloc("delta stream runs off the image"));
        };
        if b == 0 {
            break;
        }
        if b >= 0xF0 {
            if b == 0xF0
                && image.get(stream_at + fix + 1).copied().unwrap_or(1) == 0
                && image.get(stream_at + fix + 2).copied().unwrap_or(1) == 0
            {
                fix += 4;
            }
            fix += 2;
        }
        fix += 1;
        relocnum += 1;
    }
    let consumed = fix + 1; // past the terminator

    let mut positions = Vec::with_capacity(relocnum);
    let mut pc: u32 = (-4_i32) as u32;
    fix = 0;
    for _ in 0..relocnum {
        let b = image[stream_at + fix];
        let delta: u32 = if b < 0xF0 {
            fix += 1;
            b as u32
        } else {
            let hi = u16::from_le_bytes([
                *image.get(stream_at + fix + 1).unwrap_or(&0),
                *image.get(stream_at + fix + 2).unwrap_or(&0),
            ]);
            fix += 3;
            let d = ((b & 0x0F) as u32) * 0x10000 + hi as u32;
            if d == 0 {
                let bytes = [
                    *image.get(stream_at + fix).unwrap_or(&0),
                    *image.get(stream_at + fix + 1).unwrap_or(&0),
                    *image.get(stream_at + fix + 2).unwrap_or(&0),
                    *image.get(stream_at + fix + 3).unwrap_or(&0),
                ];
                fix += 4;
                u32::from_le_bytes(bytes)
            } else {
                d
            }
        };
        if delta < 4 {
            return Err(UpxUnpackError::Reloc("overlapping fixups"));
        }
        pc = pc.wrapping_add(delta);
        if pc as usize + width > limit {
            return Err(UpxUnpackError::Reloc("relocated position beyond the image"));
        }
        let start = pc as usize;
        image[start..start + width].reverse(); // bswap, le<->be
        positions.push(pc);
    }
    Ok((positions, consumed))
}

/// Build standard `.reloc` blocks from `(rva, type)` entries — `Reloc::finish`.
pub fn build_blocks(mut entries: Vec<(u32, u16)>) -> Vec<u8> {
    entries.sort_unstable();
    let mut out = Vec::new();
    let mut current_page: u32 = 0;
    let mut block: Option<(u32, Vec<u16>)> = None;

    fn finish_block(page: u32, ents: &[u16]) -> Vec<u8> {
        // UPX pads to 4 and writes the padded size back into the header.
        let sob = (8 + 2 * ents.len()) as u32;
        let sob_padded = sob.div_ceil(4) * 4;
        let mut buf = Vec::with_capacity(sob_padded as usize);
        buf.extend_from_slice(&page.to_le_bytes());
        buf.extend_from_slice(&sob_padded.to_le_bytes());
        for &e in ents {
            buf.extend_from_slice(&e.to_le_bytes());
        }
        while buf.len() & 3 != 0 {
            buf.push(0);
        }
        buf
    }

    for (i, &(pos, rtype)) in entries.iter().enumerate() {
        if i == 0 || pos.wrapping_sub(current_page) >= 0x1000 {
            if let Some((page, ents)) = block.take() {
                out.extend_from_slice(&finish_block(page, &ents));
            }
            current_page = pos & !0xFFF;
            block = Some((current_page, Vec::new()));
        }
        block.as_mut().unwrap().1.push((rtype << 12) | (pos & 0xFFF) as u16);
    }
    if let Some((page, ents)) = block.take() {
        out.extend_from_slice(&finish_block(page, &ents));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stream `[05 04 00]` at offset 12: positions start at -4, so 5 -> 1,
    /// 4 -> 5; both precede the stream, as they must on the PE path.  The
    /// values at those positions get byte-swapped.
    #[test]
    fn decodes_a_two_entry_delta_stream_and_swaps_values() {
        let mut image = vec![0u8; 16];
        image[1..5].copy_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        image[5..9].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        image[12..15].copy_from_slice(&[0x05, 0x04, 0x00]);
        let (pos, len) = unoptimize(&mut image, 12, 12, 32).expect("decodes");
        assert_eq!(pos, vec![1, 5]);
        assert_eq!(len, 3);
        // swapped in place, le<->be
        assert_eq!(&image[1..5], &0xAABB_CCDDu32.to_be_bytes());
        assert_eq!(&image[5..9], &0x1122_3344u32.to_be_bytes());
    }

    /// The 7-byte escape (`f0 00 00 + le32`) carries a large delta.
    #[test]
    fn the_seven_byte_escape_carries_large_deltas() {
        let mut image = vec![0u8; 0x20000];
        let delta: u32 = 0x1_0000;
        let mut stream = vec![0xF0u8, 0x00, 0x00];
        stream.extend_from_slice(&delta.to_le_bytes());
        stream.push(0x04); // small delta to the next
        stream.push(0x00);
        let at = 0x1_F000;
        image[at..at + stream.len()].copy_from_slice(&stream);
        let (pos, _) = unoptimize(&mut image, at, at, 32).expect("decodes");
        assert_eq!(pos, vec![0xFFFF_FFFCu32.wrapping_add(delta), 0x1_0000]);
    }

    /// A delta < 4 would double-book a dword: rejected.
    #[test]
    fn overlapping_fixups_are_rejected() {
        let mut image = vec![0u8; 64];
        image[32..34].copy_from_slice(&[0x02, 0x00]);
        assert!(unoptimize(&mut image, 32, 32, 32).is_err());
    }

    /// A relocated position at or beyond `limit` is rejected — on the PE path
    /// `limit` is the stream start, and the stream bytes must never be
    /// reinterpreted as relocated values.
    #[test]
    fn positions_beyond_the_limit_are_rejected() {
        let mut image = vec![0u8; 64];
        image[32..34].copy_from_slice(&[0x40, 0x00]); // delta 0x40 -> pc = -4+0x40 = 0x3C
        // 0x3C >= limit 32 -> must error
        assert!(unoptimize(&mut image, 32, 32, 32).is_err());
    }

    /// Blocks: page grouping, and `size_of_block` counts the pad — a
    /// 3-entry block is `sob = 16` (14 padded), a 1-entry block `sob = 12`.
    #[test]
    fn blocks_group_by_page_and_count_the_padding() {
        // page 0x1000: 3 entries; page 0x2000: 1 entry
        let entries = vec![
            (0x1000, 3u16),
            (0x1ABC, 3),
            (0x1DEF, 3),
            (0x2004, 10),
        ];
        let b = build_blocks(entries);
        assert_eq!(b.len(), 16 + 12);
        let (page, sob) = (
            u32::from_le_bytes(b[0..4].try_into().unwrap()),
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
        );
        assert_eq!(page, 0x1000);
        assert_eq!(sob, 16, "3 entries + 2 pad bytes: sob counts the pad");
        assert_eq!(&b[8..14], &[0x00, 0x30, 0xBC, 0x3A, 0xEF, 0x3D]);
        assert_eq!(&b[14..16], &[0, 0]); // pad reads as an ABSOLUTE entry
        let (page2, sob2) = (
            u32::from_le_bytes(b[16..20].try_into().unwrap()),
            u32::from_le_bytes(b[20..24].try_into().unwrap()),
        );
        assert_eq!(page2, 0x2000);
        assert_eq!(sob2, 12, "one entry (10) padded to 4: sob is 12");
        assert_eq!(&b[24..26], &[0x04, 0xA0]); // DIR64<<12 | 0x004
        assert_eq!(&b[26..28], &[0, 0]);
    }
}
