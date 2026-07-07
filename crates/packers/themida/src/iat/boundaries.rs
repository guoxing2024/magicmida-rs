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
    IatLocation, CONSECUTIVE_ZERO_THRESHOLD,
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
) -> Result<IatLocation, ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();

    // Allocate a buffer large enough to hold the maximum IAT.
    let max_slots = MAX_IAT_SIZE / ptr_size;
    let mut iat_data = vec![0usize; max_slots];

    // Read the IAT data centred on `iat_ref` such that iat_data[high] is
    // the pointer at iat_ref.
    let read_start = iat_ref.saturating_sub(MAX_IAT_SIZE.saturating_sub(ptr_size));
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

    // Now walk forwards from iat_start to find the size.
    // Use multi-block discovery to handle fragmented V3 IATs.
    let start_index = (iat_start.saturating_sub(read_start)) / ptr_size;

    // Discover all valid IAT blocks in the buffer.
    let blocks = discover_iat_blocks(&iat_data);

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
