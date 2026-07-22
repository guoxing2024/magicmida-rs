//! Safe little-endian reads that never panic on short buffers.

#[inline]
pub fn u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let s = buf.get(off..end)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
pub fn u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = buf.get(off..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
pub fn u64_le(buf: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let s = buf.get(off..end)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Checked end = start + len without wrapping.
#[inline]
pub fn range_end(start: u64, len: u64) -> Option<u64> {
    start.checked_add(len)
}

/// True if [start, start+len) is within [0, limit).
#[inline]
pub fn in_bounds(start: u64, len: u64, limit: u64) -> bool {
    match range_end(start, len) {
        Some(end) => end <= limit,
        None => false,
    }
}
