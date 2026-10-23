//! IAT boundary scanning: given a known IAT reference, walk backwards to find
//! the start and forwards to find the size.
//!
//! All functions in this module are `pub(super)` — they are internal to the
//! [`crate::iat`] module.

use tracing::{info, warn};

use mida_core::DebuggerCore;

use crate::error::ThemidaError;
use super::fix::{is_likely_api_address, is_within_image};
use super::{
    IatLocation, CONSECUTIVE_ZERO_THRESHOLD, MAX_EARLIER_REF_GAP,
    MAX_IAT_SIZE, MAX_TRASH_SLOTS,
};

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
pub(super) fn discover_iat_blocks(iat_data: &[usize]) -> Vec<IatBlock> {
    let mut blocks: Vec<IatBlock> = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut valid_count: usize = 0;

    for (i, &val) in iat_data.iter().enumerate() {
        let is_valid = val == 0
            || is_likely_api_address(val)
            || is_within_image(val, 0, iat_data.len());

        if is_valid {
            if current_start.is_none() {
                current_start = Some(i);
            }
            valid_count += 1;
        } else {
            // "Corrupt" slot — end the current block.
            if let Some(start) = current_start {
                if valid_count >= 1 {
                    blocks.push(IatBlock {
                        start_slot: start,
                        slot_count: valid_count,
                    });
                }
                current_start = None;
                valid_count = 0;
            }
        }
    }

    // Don't forget the last block.
    if let Some(start) = current_start {
        if valid_count >= 1 {
            blocks.push(IatBlock {
                start_slot: start,
                slot_count: valid_count,
            });
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
    image_base: usize,
    image_boundary: usize,
) -> Result<IatLocation, ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();
    let in_image = |v: usize| -> bool { v >= image_base && v < image_boundary };

    // Allocate a buffer large enough to hold the maximum IAT.
    let max_slots = MAX_IAT_SIZE / ptr_size;
    let mut iat_data = vec![0usize; max_slots];

    // Read the IAT data with `iat_ref` a quarter of the way into the buffer.
    //
    // The one-sided form (`iat_ref - MAX_IAT_SIZE + ptr_size`) puts the
    // reference in the buffer's *last* slot, so there is no room at all ahead
    // of it and the table can only ever be measured from its start up to the
    // reference.  Measured on the reference DLL that yielded 268 slots when the
    // table is 3283, and on the EXE it silently capped the span too.
    //
    // A quarter of the buffer behind the reference leaves 3840 slots ahead,
    // which is more than either sample needs past its reference (DLL 3018,
    // EXE 1062), while still giving the backward walk 1280 slots of room — well
    // beyond the 512-slot cap it applies.
    let lead_slots = (MAX_IAT_SIZE / ptr_size) / 4;
    let read_start = iat_ref.saturating_sub(lead_slots * ptr_size);
    let bytes_read = debugger
        // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
        .read_memory(read_start, unsafe {
            std::slice::from_raw_parts_mut(
                iat_data.as_mut_ptr() as *mut u8,
                iat_data.len() * ptr_size,
            )
        })
        .map_err(|e| ThemidaError::Debugger(format!("scan_iat_boundaries read: {e}")))?;

    let actual_slots = bytes_read / ptr_size;
    iat_data.truncate(actual_slots);

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
    //
    // Two things stop the walk, and they mean different things:
    //
    // * A run of more than `CONSECUTIVE_ZERO_THRESHOLD` zero slots is *table
    //   padding*, so the start is the first slot after it.
    // * A non-zero value that is neither a plausible API nor a pointer inside
    //   the image is not an IAT entry.  Measured on the reference DLL that is
    //   a bare RVA (`0x14365a` and friends, the same class the trace engine
    //   classifies as `not-an-import`), so the start is the slot after it.
    //
    // Both samples' true starts are found by the second rule: the DLL's head
    // is preceded by a run of bare RVAs, the EXE's by one too.  A bare RVA must
    // therefore terminate the walk rather than be skipped — treating it as
    // "unknown, keep going" is what previously dragged the start a further
    // 0x5A0 backwards into unrelated `.rdata`.
    //
    // Cap the walk so a table that runs off into adjacent data cannot be
    // followed indefinitely.
    const MAX_IAT_SLOTS_BACKWARD: usize = 512;
    let mut seeker = ref_index;
    let mut slots_scanned: usize = 0;
    loop {
        let val = iat_data[seeker];

        if val == 0 {
            consecutive_zeros += 1;
            if consecutive_zeros > CONSECUTIVE_ZERO_THRESHOLD {
                iat_start = read_start
                    + (seeker + consecutive_zeros + 1).min(actual_slots - 1) * ptr_size;
                break;
            }
        } else if is_likely_api_address(val) || is_within_image(val, read_start, actual_slots) {
            iat_start = read_start + seeker * ptr_size;
            consecutive_zeros = 0;
        } else {
            info!("Ending IAT start search at {:#x} because pointer is {val:#x}", read_start + seeker * ptr_size);
            iat_start = read_start + (seeker + 1) * ptr_size;
            break;
        }

        slots_scanned += 1;
        if slots_scanned > MAX_IAT_SLOTS_BACKWARD { break; }

        if seeker == 0 {
            if iat_start == 0 { return Err(ThemidaError::IatNotFound); }
            break;
        }
        seeker -= 1;
    }

    if iat_start == 0 {
        return Err(ThemidaError::IatNotFound);
    }

    // Trim leading padding and out-of-table prefix slots.
    //
    // The walk stops *at* the last slot that is not an IAT entry, so `iat_start`
    // begins with whatever padding followed it.  Two kinds of slot can sit
    // there and neither belongs to the table:
    //
    // * zeros — the separator itself;
    // * a fully resolved address *outside* the image — an already-imported API
    //   that happens to precede the table.  Measured on the reference DLL:
    //   slot rva `0x141a78` holds `0x7ff8c1054390` (a system DLL), and counting
    //   it yields 290 resolved instead of the golden 289.
    //
    // The table's first real entry is the first slot that still needs work:
    // a pointer *inside* the image (a Themida trampoline) or a bare RVA.
    //
    // "Inside the image" is decided by `is_within_image`'s rule inverted: a
    // resolved import points into a *system* module, which on x64 is the
    // 0x7FFx range, while a Themida trampoline points inside the protected
    // image.  The image's own base is not available here, so the test is the
    // one that separates the two kinds of pointer: a value that is a plausible
    // API *and* not within the image's own address span is out of table.
    let mut trim = (iat_start.saturating_sub(read_start)) / ptr_size;
    while trim < actual_slots {
        let v = iat_data[trim];
        let is_padding = v == 0;
        let is_outside_api = is_likely_api_address(v) && !in_image(v);
        if !is_padding && !is_outside_api {
            break;
        }
        trim += 1;
    }
    if trim < actual_slots {
        iat_start = read_start + trim * ptr_size;
    }

    // Now walk forwards from iat_start to find the size.
    // Use multi-block discovery to handle fragmented V3 IATs.
    let start_index = (iat_start.saturating_sub(read_start)) / ptr_size;

    // Discover all valid IAT blocks in the buffer.
    let blocks = discover_iat_blocks(&iat_data);

    // Anchor on the backward walk's own answer.
    //
    // `select_primary_block` looks for the block *containing* `start_index`,
    // and falls back to the largest block when the walk's answer sits in a gap
    // between blocks — which is exactly what happens on the reference DLL: the
    // walk stops at rva `0x141a68`, two slots before the first valid block, so
    // the lookup misses and the largest block (a 1289-slot `.rdata` region) is
    // chosen instead.  The head of the table is then lost.
    //
    // The walk is the authority: it is the only pass that knows where the
    // reference sits.  So pick the first block at or after it, and never a
    // block that starts before it.
    let primary_idx = blocks
        .iter()
        .position(|b| b.start_slot + b.slot_count > start_index)
        .or_else(|| select_primary_block(&blocks, start_index));

    let (final_start_slot, final_slot_count) = match primary_idx {
        Some(idx) => {
            let primary = blocks[idx];
            let primary_end = primary.start_slot + primary.slot_count;

            // Check if there are additional valid blocks after the primary block.
            // If so, extend the IAT to include them (matching Magicmida's behavior
            // of iterating through the entire IAT buffer).
            let mut combined_end = primary_end;
            // Start from the trimmed head, not the block's raw start: the block
            // may begin with the padding and out-of-table prefix the trim just
            // removed, and taking the block start would put them straight back.
            let mut combined_start = primary.start_slot.max(start_index);

            // Merge subsequent blocks across short gaps, and across the zero
            // region that separates the table from whatever follows it.
            //
            // The reported span covers the trailing zero region, not just the
            // entries: measured on both reference samples the golden sizes
            // (DLL 3283, EXE 1063) extend past the last entry into padding, and
            // the trailing `not-an-import` slots sit out there too (DLL 3,
            // EXE 8).  Stopping at the last entry instead drops those to zero
            // and shrinks the span to a fraction of the record.
            //
            // A gap bound alone cannot express that, because the zero region is
            // hundreds of slots wide.  So: merge a *zero-only* gap of any
            // length, and merge a gap containing real data only when it is
            // short (48 slots covers the largest internal gap measured in either
            // sample: 46 in the DLL, 39 in the EXE).
            const MAX_FORWARD_GAP_SLOTS: usize = 48;
            for block in &blocks[idx + 1..] {
                let gap = block.start_slot.saturating_sub(combined_end);
                let gap_is_all_zeros = iat_data[combined_end..block.start_slot]
                    .iter()
                    .all(|&v| v == 0);
                if gap <= MAX_FORWARD_GAP_SLOTS || gap_is_all_zeros {
                    combined_end = block.start_slot + block.slot_count;
                } else {
                    break;
                }
            }

            // Merge *backwards* into earlier blocks only when the backward walk
            // stopped well short of the reference — i.e. the table head was not
            // reached and the earlier blocks really do hold it.
            //
            // The discriminator is the distance the walk covered, not the gap
            // width and not the block layout:
            //
            // | sample | walk covered before iat_ref | needs a backward merge? |
            // |--------|-----------------------------|-------------------------|
            // | EXE    | 0x328 (one block)           | yes — its head lives in earlier blocks; without the merge only 2 slots survive |
            // | DLL    | 0x860 (the whole head)      | no — the walk already reached the head; merging drags the start into unrelated `.rdata` |
            //
            // Any gap-width threshold loose enough for the EXE also swallows the
            // DLL's neighbours, which is why this kept regressing.  The walk's
            // own reach separates them cleanly.
            let walk_reach = iat_ref.saturating_sub(iat_start);
            let walk_stopped_early = walk_reach <= MAX_EARLIER_REF_GAP;
            let ref_offset_in_block = start_index.saturating_sub(primary.start_slot);
            let _ = ref_offset_in_block;
            if walk_stopped_early {
                // Take only the *nearest* earlier block, and only if it ends
                // within a short gap AND the walk really did stop at a barrier
                // rather than at the head.
                //
                // The EXE's reference sits 0x328 before its head with a bare-RVA
                // run in between, so `walk_stopped_early` is true there and the
                // merge is what recovers its 1063-slot table.  The DLL's walk
                // covered 0x860, so it never enters this branch.
                const MAX_BACKWARD_GAP_SLOTS: usize = 64;
                if let Some(prev) = blocks[..idx].last() {
                    let gap = combined_start.saturating_sub(prev.start_slot + prev.slot_count);
                    if gap <= MAX_BACKWARD_GAP_SLOTS {
                        // Do not go further back than the trimmed head allows:
                        // the merged block may itself begin with out-of-table
                        // slots, so re-run the same trim predicate on its start.
                        let prev_start = prev.start_slot;
                        let mut s = prev_start;
                        while s < combined_start {
                            let v = iat_data[s];
                            if v != 0 && !(is_likely_api_address(v) && !in_image(v)) {
                                break;
                            }
                            s += 1;
                        }
                        // Never move the head earlier than the walk's own answer
                        // when that answer is itself already a real entry.
                        combined_start = s.max(start_index.min(combined_start));
                    }
                }
            } else {
                info!(
                    walk_reach,
                    "Not merging backwards: the backward walk already covered this far, \
                     so the table head is behind the reference, not before it"
                );
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
                        iat_end = read_start
                            + i.saturating_sub(trash_counter) * ptr_size;
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
                requires_writable_section: false,  // TODO: detect from PE header
            });
        }
    };

    let iat_start_final = read_start + final_start_slot * ptr_size;
    // Safety clamp: the multi-block merge can extend the start backwards into
    // adjacent data because `is_likely_api_address` / `is_within_image` are
    // permissive heuristics.  The backward walk above has its own stopping
    // rules and is the authority on the start, so this only guards against a
    // merge that ran away — it must not fire on a legitimate head.
    //
    // Measured on the reference DLL: the walk correctly stops at rva
    // `0x141a68`, which is 0x860 before `iat_ref`.  The previous 0x2000
    // threshold left that alone, but a run that dragged the start to buffer
    // slot 0 (rva `0x13fac8`, 0x2800 before the reference) did trip it — and
    // tripping it snaps the start all the way to `iat_ref`, discarding the
    // whole table head.  Half a page is enough to catch a runaway merge while
    // still admitting a head that is genuinely one page back.
    const MAX_BACKWARD_HEAD: usize = 0x1000;
    let iat_start_final = if iat_start_final < iat_ref.saturating_sub(MAX_BACKWARD_HEAD) {
        info!(
            "Clamping IAT start from {:#x} to iat_ref {:#x} (scan extended too far back)",
            iat_start_final, iat_ref
        );
        iat_ref
    } else {
        iat_start_final
    };
    let size = final_slot_count * ptr_size;

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
        requires_writable_section: false,  // TODO: detect from PE header
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two reference samples need opposite treatment, and the discriminator
    /// is how far the backward walk reached — not any gap width.
    ///
    /// Both numbers are measured: the EXE's reference sits 0x328 before its
    /// table head, the DLL's 0x860.  The boundary sits between them.
    #[test]
    fn walk_reach_separates_the_two_samples() {
        let exe_reach = 0x328usize;
        let dll_reach = 0x860usize;
        assert!(
            exe_reach <= MAX_EARLIER_REF_GAP,
            "the EXE's walk must count as 'stopped early' so its head gets merged"
        );
        assert!(
            dll_reach > MAX_EARLIER_REF_GAP,
            "the DLL's walk must not, or the merge drags its head into .rdata"
        );
    }

    /// A short zero run separates import groups inside the table; a long one is
    /// the region past it.  Both are "valid" for block discovery, which is why
    /// the span can extend into padding — this test pins that the threshold used
    /// for the backward walk is smaller than the trailing region measured in
    /// both samples.
    #[test]
    fn consecutive_zero_threshold_is_below_the_trailing_region() {
        // Measured trailing zero runs: DLL 594 slots, EXE 426.
        assert!(CONSECUTIVE_ZERO_THRESHOLD < 426);
        assert!(CONSECUTIVE_ZERO_THRESHOLD < 594);
    }

    /// The forward gap bound has to admit every genuine internal gap in both
    /// samples and stop before the next region.
    ///
    /// Measured internal gaps: DLL largest 46 slots, EXE largest 39.  The EXE's
    /// next region starts 54 slots past its table end.
    #[test]
    fn forward_gap_bound_admits_internal_gaps_only() {
        const MAX_FORWARD_GAP_SLOTS: usize = 48;
        assert!(46 <= MAX_FORWARD_GAP_SLOTS, "DLL internal gap must merge");
        assert!(39 <= MAX_FORWARD_GAP_SLOTS, "EXE internal gap must merge");
        assert!(
            54 > MAX_FORWARD_GAP_SLOTS,
            "the EXE's next region must not merge"
        );
    }
}
