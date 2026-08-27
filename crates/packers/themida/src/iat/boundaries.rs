//! IAT boundary scanning: given a known IAT reference, walk backwards to find
//! the start and forwards to find the size.
//!
//! All functions in this module are `pub(super)` — they are internal to the
//! [`crate::iat`] module.

use tracing::{info, warn};

use mida_core::DebuggerCore;

use super::fix::{is_likely_api_address, is_within_image_bounds};
use super::{IatLocation, CONSECUTIVE_ZERO_THRESHOLD, MAX_IAT_SIZE, MAX_TRASH_SLOTS};
use crate::error::ThemidaError;

// ===========================================================================
// Internal — Multi-block IAT discovery
// ===========================================================================

/// A contiguous region of valid IAT slots, discovered during multi-block scanning.
#[derive(Debug, Clone, Copy)]
pub(super) struct IatBlock {
    /// Slot index (relative to the start of the read buffer) of the first slot.
    pub(super) start_slot: usize,
    /// Number of slots in this block.
    pub(super) slot_count: usize,
}

/// Find all valid IAT blocks in the scanned buffer.
///
/// Magicmida's `TraceImports` does NOT assume a single contiguous IAT — it
/// iterates through the entire IAT buffer and resolves *every* slot that
/// points into the Themida section, regardless of gaps between valid slots.
///
/// V3 binaries can have fragmented IATs where valid entries are separated by
/// large runs of zeros.  To match Magicmida, we:
///
/// 1. Read the full MAX_IAT_SIZE buffer starting from `iat_start`.
/// 2. Identify all "valid" slots — those that are either zero (padding),
///    valid API addresses (outside the image), or Themida-section pointers
///    (V3 obfuscated imports).
/// 3. Group contiguous valid slots into blocks separated by "corrupt" slots
///    (non-zero, non-API, non-Themida pointers — these are NOT IAT entries).
/// 4. Return all blocks; callers can choose to merge adjacent blocks or
///    process them individually.
///
/// The returned blocks are sorted by slot index (ascending).
#[allow(dead_code)] // legacy block discovery; superseded by boundary scan
pub(super) fn discover_iat_blocks(iat_data: &[usize]) -> Vec<IatBlock> {
    discover_iat_blocks_with_image(iat_data, 0, 0)
}

/// Like [`discover_iat_blocks`], but treats pointers in
/// `[image_base, image_boundary)` as valid (Themida stub / image-local).
pub(super) fn discover_iat_blocks_with_image(
    iat_data: &[usize],
    image_base: usize,
    image_boundary: usize,
) -> Vec<IatBlock> {
    let mut blocks: Vec<IatBlock> = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut valid_count: usize = 0;
    let mut consecutive_zeros: usize = 0;

    for (i, &val) in iat_data.iter().enumerate() {
        let is_valid = val == 0
            || is_likely_api_address(val)
            || is_within_image_bounds(val, image_base, image_boundary);

        if is_valid {
            if val == 0 {
                consecutive_zeros += 1;
                // If we've seen too many consecutive zeros, end the current
                // block here.  Large runs of zeros before the IAT should not
                // be included in the IAT span — they are padding between
                // data-section entries, not IAT slots.
                if consecutive_zeros > 16 {
                    if let Some(start) = current_start {
                        if valid_count > consecutive_zeros {
                            // Trim the trailing zeros from the block.
                            blocks.push(IatBlock {
                                start_slot: start,
                                slot_count: valid_count - consecutive_zeros,
                            });
                        }
                        current_start = None;
                        valid_count = 0;
                    }
                    consecutive_zeros = 0;
                    continue;
                }
            } else {
                consecutive_zeros = 0;
            }
            // Only start a new block on a non-zero value — leading zeros
            // are not IAT slots.
            if current_start.is_none() && val != 0 {
                current_start = Some(i);
            }
            if current_start.is_some() {
                valid_count += 1;
            }
        } else {
            // "Corrupt" slot — end the current block.
            if let Some(start) = current_start {
                if valid_count >= 1 {
                    // Trim trailing zeros from the block.
                    let trimmed = valid_count.saturating_sub(consecutive_zeros);
                    blocks.push(IatBlock {
                        start_slot: start,
                        slot_count: trimmed.max(1),
                    });
                }
                current_start = None;
                valid_count = 0;
                consecutive_zeros = 0;
            }
        }
    }

    // Don't forget the last block.
    if let Some(start) = current_start {
        if valid_count > consecutive_zeros {
            // Trim trailing zeros.
            let trimmed = valid_count - consecutive_zeros;
            if trimmed >= 1 {
                blocks.push(IatBlock {
                    start_slot: start,
                    slot_count: trimmed,
                });
            }
        }
    }

    blocks
}

/// Choose the best IAT block as the "primary" one — the block that contains
/// the reference slot `ref_index`.
///
/// If no block contains `ref_index`, returns the largest block (by slot count).
pub(super) fn select_primary_block(blocks: &[IatBlock], ref_index: usize) -> Option<usize> {
    if blocks.is_empty() {
        return None;
    }

    // Prefer the block containing the reference index.
    for (idx, block) in blocks.iter().enumerate() {
        if ref_index >= block.start_slot && ref_index < block.start_slot + block.slot_count {
            return Some(idx);
        }
    }

    // Fallback: largest block.
    blocks
        .iter()
        .enumerate()
        .max_by_key(|(_, b)| b.slot_count)
        .map(|(idx, _)| idx)
}

// ===========================================================================
// Internal — IAT boundary scanning
// ===========================================================================

/// Given a known pointer *inside* the IAT (`iat_ref`), walk backwards to
/// find the start and forwards to find the size.
///
/// The IAT is a contiguous block of pointer-sized slots.  Valid slots are
/// either:
/// - non-zero and point to an API (address outside the image, or in a
///   known DLL range), OR
/// - non-zero and point inside a Themida section (V3 obfuscated imports).
///
/// The table is preceded and followed by regions with many consecutive
/// zero slots (or non-API / non-Themida pointers).
///
/// ## Multi-block IAT support (V3 fragmented IATs)
///
/// Some Themida v3 binaries have fragmented IATs where valid entries are
/// separated by large runs of zeros (more than `CONSECUTIVE_ZERO_THRESHOLD`
/// slots).  The original Magicmida `TraceImports` handles this by iterating
/// through the *entire* IAT buffer and resolving every slot that points into
/// the Themida section, regardless of gaps.
///
/// To match Magicmida, this function:
/// 1. Reads the full `MAX_IAT_SIZE` buffer centered on `iat_ref`.
/// 2. Uses `discover_iat_blocks` to find all valid IAT regions.
/// 3. Selects the block containing `iat_ref` as the primary block.
/// 4. If additional valid blocks exist *after* the primary block (with only
///    zero/corrupt gaps between them), extends the IAT to include them.
pub(super) fn scan_iat_boundaries(
    debugger: &dyn DebuggerCore,
    iat_ref: usize,
) -> Result<IatLocation, ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();
    let image_base = debugger.image_base() as usize;
    let image_boundary = read_image_boundary(debugger, image_base).unwrap_or(0);

    // Read the IAT data centred on `iat_ref` such that iat_data[high] is
    // the pointer at iat_ref.
    // Read starting FROM iat_ref (not centered on it) so the buffer
    // covers the full IAT forward.  The backward scan is less useful
    // now that find_earliest_iat_ref already found the correct start,
    // but we keep a small backward margin (64 slots) for safety.
    let backward_margin = 64 * ptr_size;
    let read_start = iat_ref.saturating_sub(backward_margin);

    // XX-3 page-grained read: instead of one MAX_IAT_SIZE hard read (which
    // FATALs on the first unmapped page — XX-2), walk forward in 4 KiB pages
    // and truncate at the first page whose read returns fewer bytes than
    // requested.  This supports partial IAT dumps and eliminates the
    // 40960-byte one-shot failure.
    const PAGE: usize = 0x1000;
    let mut iat_data: Vec<usize> = Vec::new();
    let mut cursor = read_start;
    let mut read_total = 0usize;
    while read_total < MAX_IAT_SIZE {
        let chunk = (MAX_IAT_SIZE - read_total).min(PAGE);
        let mut buf = vec![0u8; chunk];
        let n = debugger
            .read_memory(cursor, &mut buf)
            .map_err(|e| ThemidaError::Debugger(format!("scan_iat_boundaries read: {e}")))?;
        if n == 0 {
            // Unmapped page — truncate here.
            break;
        }
        // Append whole slots only; keep a trailing partial-slot carry is not
        // needed since the IAT is 8-byte aligned and pages are 8-byte aligned.
        let slot_bytes = (n / ptr_size) * ptr_size;
        if slot_bytes == 0 {
            break;
        }
        for off in (0..slot_bytes).step_by(ptr_size) {
            let val = usize::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
                buf[off + 4],
                buf[off + 5],
                buf[off + 6],
                buf[off + 7],
            ]);
            iat_data.push(val);
        }
        read_total += n;
        cursor += n;
        if n < chunk {
            // Partial page read (page boundary / guard) — stop.
            break;
        }
    }

    let actual_slots = iat_data.len();

    if actual_slots < 2 {
        return Err(ThemidaError::IatNotFound);
    }

    // The index in iat_data that corresponds to `iat_ref`.
    let ref_index = (iat_ref.saturating_sub(read_start)) / ptr_size;
    if ref_index >= actual_slots {
        return Err(ThemidaError::IatNotFound);
    }

    let mut iat_start = 0usize; // stays 0 until we find a valid region
    let mut consecutive_zeros: usize = 0;

    // Walk backwards from `ref_index` to find the start.
    // Cap the backward scan to avoid extending into adjacent data
    // sections (e.g. Section 4 when the IAT is in Section 6).
    const MAX_IAT_SLOTS_BACKWARD: usize = 512; // 4 KiB on x64
    let mut seeker = ref_index;
    let mut slots_scanned: usize = 0;
    loop {
        let val = iat_data[seeker];

        if val == 0 {
            consecutive_zeros += 1;
            if consecutive_zeros > CONSECUTIVE_ZERO_THRESHOLD {
                // Note: CONSECUTIVE_ZERO_THRESHOLD (64) is used for the
                // forward scan's multi-block gap detection.  For the backward
                // scan, use a smaller threshold (16) to avoid extending the
                // IAT start too far back into padding zeros before .rdata.
                if consecutive_zeros > 16 {
                    iat_start = read_start
                        + (seeker + consecutive_zeros + 1).min(actual_slots - 1) * ptr_size;
                    break;
                }
            }
        } else if is_likely_api_address(val)
            || is_within_image_bounds(val, image_base, image_boundary)
        {
            iat_start = read_start + seeker * ptr_size;
            consecutive_zeros = 0;
        } else {
            info!(
                "Ending IAT start search at {:#x} because pointer is {val:#x}",
                read_start + seeker * ptr_size
            );
            iat_start = read_start + (seeker + 1) * ptr_size;
            break;
        }

        slots_scanned += 1;
        if slots_scanned > MAX_IAT_SLOTS_BACKWARD {
            break;
        }

        if seeker == 0 {
            if iat_start == 0 {
                return Err(ThemidaError::IatNotFound);
            }
            break;
        }
        seeker -= 1;
    }

    if iat_start == 0 {
        return Err(ThemidaError::IatNotFound);
    }

    // Now walk forwards from iat_start to find the size.
    // Use multi-block discovery to handle fragmented V3 IATs.
    let start_index = (iat_start.saturating_sub(read_start)) / ptr_size;

    // Discover all valid IAT blocks in the buffer (API + in-image stubs).
    let blocks = discover_iat_blocks_with_image(&iat_data, image_base, image_boundary);

    // Find the block that contains our start_index.
    let primary_idx = select_primary_block(&blocks, start_index);

    let (final_start_slot, final_slot_count) = match primary_idx {
        Some(idx) => {
            let primary = blocks[idx];
            let primary_end = primary.start_slot + primary.slot_count;

            // Check if there are additional valid blocks after the primary block.
            // If so, extend the IAT to include them (matching Magicmida's behavior
            // of iterating through the entire IAT buffer).
            let mut combined_end = primary_end;
            let mut combined_start = primary.start_slot;

            // Look for subsequent blocks that are "close enough" to be part of
            // the same logical IAT.  We use a generous gap threshold here because
            // V3 IATs can have large internal gaps.
            for block in &blocks[idx + 1..] {
                let gap = block.start_slot.saturating_sub(combined_end);
                // If the gap is small enough (less than MAX_IAT_SIZE / 8), consider
                // it part of the same IAT.  This handles fragmented V3 IATs where
                // valid entries are separated by runs of zeros.
                if gap < MAX_IAT_SIZE / (ptr_size * 8) {
                    combined_end = block.start_slot + block.slot_count;
                } else {
                    break;
                }
            }

            // Also check if there are valid blocks *before* the primary block
            // that should be included (e.g., if the IAT starts earlier than
            // our backward scan found).
            for block in blocks[..idx].iter().rev() {
                let gap = combined_start.saturating_sub(block.start_slot + block.slot_count);
                if gap < MAX_IAT_SIZE / (ptr_size * 8) {
                    combined_start = block.start_slot;
                } else {
                    break;
                }
            }

            info!(
                "IAT multi-block: primary block at slot {} ({} slots), \
                 combined span: slot {} ({} slots), total blocks: {}",
                primary.start_slot,
                primary.slot_count,
                combined_start,
                combined_end - combined_start,
                blocks.len()
            );

            (combined_start, combined_end - combined_start)
        }
        None => {
            // No valid blocks found — fall back to the original single-block
            // forward scan behavior.
            warn!("No valid IAT blocks discovered — falling back to single-block scan");
            let mut trash_counter: usize = 0;
            let mut iat_end = iat_start;

            for i in start_index..actual_slots {
                let val = iat_data[i];

                if val == 0 || !is_likely_api_address(val) {
                    trash_counter += 1;
                    if trash_counter > MAX_TRASH_SLOTS {
                        iat_end = read_start + i.saturating_sub(trash_counter) * ptr_size;
                        break;
                    }
                } else {
                    trash_counter = 0;
                    iat_end = read_start + (i + 1) * ptr_size;
                }
            }

            let size = iat_end.saturating_sub(iat_start);
            if size == 0 || size > MAX_IAT_SIZE {
                warn!("IAT size {size} is zero or exceeds MAX_IAT_SIZE");
                return Err(ThemidaError::IatNotFound);
            }

            info!(
                "IAT boundaries (single-block fallback): start={:#x}, end={:#x}, size={} ({} slots)",
                iat_start,
                iat_end,
                size,
                size / ptr_size,
            );

            return Ok(IatLocation {
                address: iat_start,
                size,
                requires_writable_section: false, // TODO: detect from PE header
            });
        }
    };

    let iat_start_final = read_start + final_start_slot * ptr_size;
    // The multi-block scan can extend the IAT start backwards into adjacent
    // data sections because `is_likely_api_address`/`is_within_image` are
    // permissive heuristics (Pascal's `IsAPIAddress` checks module export
    // tables, which naturally rejects data-section pointers).
    //
    // For Themida V3 where the IAT is a small region in a data section, we
    // clamp the start to `iat_ref` itself when the scan tries to extend too
    // far back.  This matches the observation that Pascal's IAT start
    // (`0x1369b0`) is within a few hundred bytes of its IAT ref.
    let iat_start_final = if iat_start_final < iat_ref.saturating_sub(0x2000) {
        info!(
            "Clamping IAT start from {:#x} to iat_ref {:#x} (scan extended too far back)",
            iat_start_final, iat_ref
        );
        iat_ref
    } else {
        iat_start_final
    };
    // Add a small forward margin (8 slots) to catch trailing unresolved
    // slots that the V3 trace will resolve. The multi-block scan trims
    // trailing zeros, but Themida V3 may leave the last few IAT slots
    // as zero (unresolved) at dump time — the V3 trace resolves them
    // by single-stepping the Themida wrapper. Without this margin, we
    // miss the last import (e.g. InternetSetOptionW from wininet.dll).
    const IAT_FORWARD_MARGIN_SLOTS: usize = 8;
    let size = (final_slot_count + IAT_FORWARD_MARGIN_SLOTS) * ptr_size;

    if size == 0 || size > MAX_IAT_SIZE {
        warn!("IAT size {size} is zero or exceeds MAX_IAT_SIZE");
        return Err(ThemidaError::IatNotFound);
    }

    let iat_end_final = iat_start_final + size;

    info!(
        "IAT boundaries: start={:#x}, end={:#x}, size={} ({} slots), blocks={}",
        iat_start_final,
        iat_end_final,
        size,
        size / ptr_size,
        blocks.len(),
    );

    Ok(IatLocation {
        address: iat_start_final,
        size,
        requires_writable_section: false, // TODO: detect from PE header
    })
}

/// Read `ImageBase + SizeOfImage` from the live process PE headers.
///
/// Returns `None` if headers cannot be read; callers then treat image-local
/// stubs as non-valid (API-only scan).
fn read_image_boundary(debugger: &dyn DebuggerCore, image_base: usize) -> Option<usize> {
    if image_base == 0 {
        return None;
    }
    let mut dos = [0u8; 0x40];
    debugger.read_memory(image_base, &mut dos).ok()?;
    if dos[0] != b'M' || dos[1] != b'Z' {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3c..0x40].try_into().ok()?) as usize;
    let mut nt = [0u8; 0x58]; // enough for OptionalHeader.SizeOfImage at +56
    debugger
        .read_memory(image_base.checked_add(e_lfanew)?, &mut nt)
        .ok()?;
    if &nt[0..4] != b"PE\0\0" {
        return None;
    }
    // OptionalHeader starts at NT+24; SizeOfImage at optional+56 for PE32/PE32+.
    let size_of_image = u32::from_le_bytes(nt[24 + 56..24 + 60].try_into().ok()?) as usize;
    if size_of_image == 0 {
        return None;
    }
    Some(image_base.saturating_add(size_of_image))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_core::{ContinueStatus, CoreError, DebugEvent, DebuggerCore};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Diagnostics::Debug::CONTEXT;

    /// Page-backed debugger memory: only pages explicitly `put` are readable;
    /// everything else returns 0 bytes (unmapped).
    struct PageMem {
        base: u64,
        pages: std::collections::BTreeMap<usize, Vec<u8>>,
    }

    impl PageMem {
        fn new(base: u64) -> Self {
            PageMem {
                base,
                pages: std::collections::BTreeMap::new(),
            }
        }
        fn put_page(&mut self, page: usize, bytes: &[u8]) {
            self.pages.insert(page, bytes.to_vec());
        }
    }

    impl DebuggerCore for PageMem {
        fn process_handle(&self) -> HANDLE {
            HANDLE::default()
        }
        fn pid(&self) -> u32 {
            1
        }
        fn image_base(&self) -> u64 {
            self.base
        }
        fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
            Err(CoreError::DebugState("no events".into()))
        }
        fn continue_event(&mut self, _t: u32, _s: ContinueStatus) -> Result<(), CoreError> {
            Ok(())
        }
        fn read_memory(&self, addr: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
            let page = addr & !0xFFF;
            let off = addr - page;
            match self.pages.get(&page) {
                Some(data) => {
                    if off >= data.len() {
                        return Ok(0);
                    }
                    let n = (data.len() - off).min(buf.len());
                    buf[..n].copy_from_slice(&data[off..off + n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }
        fn write_memory(&mut self, _a: usize, _d: &[u8]) -> Result<usize, CoreError> {
            Ok(0)
        }
        fn get_thread_context(&self, _t: u32) -> Result<CONTEXT, CoreError> {
            Err(CoreError::DebugState("no ctx".into()))
        }
        fn set_thread_context(&self, _t: u32, _c: &CONTEXT) -> Result<(), CoreError> {
            Ok(())
        }
    }

    /// Two consecutive pages of resolved-API IAT slots; page 3 is unmapped.
    /// The page-grained scan must truncate at the unmapped page and return a
    /// partial IAT instead of FATAL-ing on a hard read.
    #[test]
    fn scan_iat_boundaries_truncates_at_unmapped_page() {
        let image_base = 0x140000000usize;
        // Put the ref 0x400 into its page so the 64-slot backward margin
        // (512 bytes) still lands inside the same mapped page.
        let iat_ref = 0x140010400usize;
        let page_base = iat_ref & !0xFFF;
        let mut dbg = PageMem::new(image_base as u64);

        // Page 0 (ref page): resolved API addresses.
        let mut page0 = vec![0u8; 0x1000];
        for (i, chunk) in page0.chunks_mut(8).enumerate() {
            let val = 0x7ff0_0000_0000usize + i * 8;
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        dbg.put_page(page_base, &page0);

        // Page 1: another full page.
        let mut page1 = vec![0u8; 0x1000];
        for (i, chunk) in page1.chunks_mut(8).enumerate() {
            let val = 0x7ff0_0000_1000usize + i * 8;
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        dbg.put_page(page_base + 0x1000, &page1);

        // Page 2 (unmapped) is intentionally absent.

        let result = scan_iat_boundaries(&dbg, iat_ref);
        // Must not FATAL; must return a partial IAT spanning at most 2 pages.
        let iat = result.expect("page-grained scan must succeed on partial IAT");
        assert!(iat.address > 0);
        assert!(iat.size > 0);
        assert!(iat.size <= 2 * 0x1000);
    }

    /// A single readable page around the ref must still produce a valid IAT.
    #[test]
    fn scan_iat_boundaries_single_page_ok() {
        let image_base = 0x140000000usize;
        let iat_ref = 0x140010400usize;
        let page_base = iat_ref & !0xFFF;
        let mut dbg = PageMem::new(image_base as u64);
        let mut page0 = vec![0u8; 0x1000];
        for (i, chunk) in page0.chunks_mut(8).enumerate() {
            let val = 0x7ff0_0000_0000usize + i * 8;
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        dbg.put_page(page_base, &page0);

        let iat = scan_iat_boundaries(&dbg, iat_ref).expect("single-page IAT");
        assert!(iat.address > 0);
        assert!(iat.size > 0);
        assert!(iat.size <= 0x1000 + 64 * 8); // one page + backward margin
    }
}
