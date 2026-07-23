//! Early post-attach section snapshots (zero-raw `.data` CRT baseline).
//!
//! Extracted from `mod.rs` (P1 host thin split). Capture/refresh rules keep a
//! clean BSS baseline and only merge image-relative late globals — behavior
//! unchanged from the inline helpers.

use anyhow::anyhow;
use tracing::debug;

use crate::log::{self, LogType};
use mida_core::DebuggerCore;
use mida_pe::{EarlySectionSnapshot, PeHeader};

use super::session::ProcessSession;

/// Capture zero-raw selected sections while the main thread is still suspended.
pub(super) fn capture_early_section_snapshots(
    dbg: &ProcessSession,
    pe: &PeHeader,
    selected_names: &[&str],
) -> Result<Vec<EarlySectionSnapshot>, anyhow::Error> {
    let image_base = dbg.image_base() as usize;
    let mut snapshots = Vec::new();

    for section in &pe.sections {
        if section.raw_size != 0 || !selected_names.contains(&section.name.as_str()) {
            continue;
        }

        let size = section.virtual_size as usize;
        if size == 0 {
            continue;
        }
        // Cap VirtualSize-driven allocations (H-1: hostile PE DoS).
        const MAX_EARLY_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
        if size > MAX_EARLY_SNAPSHOT_BYTES {
            return Err(anyhow!(
                "early snapshot for {} rejected: VirtualSize {:#x} exceeds cap {:#x}",
                section.name,
                size,
                MAX_EARLY_SNAPSHOT_BYTES
            ));
        }
        let address = image_base
            .checked_add(section.virtual_address as usize)
            .ok_or_else(|| anyhow!("early snapshot address overflow for {}", section.name))?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| {
            anyhow!(
                "early snapshot for {}: failed to reserve {size} bytes",
                section.name
            )
        })?;
        bytes.resize(size, 0);
        let read = dbg
            .read_memory(address, &mut bytes)
            .map_err(|e| anyhow!("failed to capture early {} snapshot: {e}", section.name))?;
        if read != size {
            return Err(anyhow!(
                "short early {} snapshot read: got {read} bytes, expected {size}",
                section.name
            ));
        }

        let non_zero = bytes.iter().filter(|&&byte| byte != 0).count();
        let hash = fnv1a64(&bytes);
        log::log(
            LogType::Info,
            &format!(
                "early snapshot: {} RVA {:#x}, size {:#x}, non-zero {}, fnv1a64 {:#018x} (main thread suspended)",
                section.name, section.virtual_address, size, non_zero, hash
            ),
        );
        snapshots.push(EarlySectionSnapshot {
            section_name: section.name.clone(),
            rva: section.virtual_address,
            bytes,
        });
    }

    Ok(snapshots)
}

/// No-op: first capture is the only safe CRT baseline for zero-raw `.data`.
pub(super) fn update_pre_text_snapshots(
    dbg: &ProcessSession,
    snapshots: &mut [EarlySectionSnapshot],
    rip: usize,
) -> Result<(), anyhow::Error> {
    // For zero-raw `.data`, the FIRST capture (main thread still suspended,
    // post-loader) is the only safe CRT baseline: all zeros / pure BSS.
    //
    // During free-run observation the CRT and app fill `.data` with process-
    // local heap handles (`_pioinfo`, GetProcessHeap cache, stdio tables).
    // Absorbing that state into the dump makes the independent PE re-enter
    // CRT with half-initialized globals and AV at `_pioinfo[i]->_ptr`.
    //
    // Keep the initial clean snapshot; image-relative late values are merged
    // later by `merge_reinitializable_data_state`.
    let _ = (dbg, snapshots, rip);
    Ok(())
}

/// Refresh only still-all-zero snapshots after loader; skip CRT-polluted live state.
pub(super) fn refresh_early_snapshots_after_loader(
    dbg: &ProcessSession,
    snapshots: &mut [EarlySectionSnapshot],
) -> Result<(), anyhow::Error> {
    // Only refresh snapshots that are STILL all-zero. A non-zero early capture
    // (e.g. packer-written constants before main-thread resume) is already a
    // valid baseline. Never replace a clean BSS baseline with live CRT state.
    let image_base = dbg.image_base() as usize;
    for snapshot in snapshots {
        if snapshot.bytes.iter().any(|&byte| byte != 0) {
            continue;
        }

        let address = image_base
            .checked_add(snapshot.rva as usize)
            .ok_or_else(|| {
                anyhow!(
                    "loader snapshot address overflow for {}",
                    snapshot.section_name
                )
            })?;
        let mut candidate = vec![0u8; snapshot.bytes.len()];
        let read = dbg.read_memory(address, &mut candidate).map_err(|e| {
            anyhow!(
                "failed to refresh {} loader snapshot: {e}",
                snapshot.section_name
            )
        })?;
        if read != candidate.len() {
            return Err(anyhow!(
                "short {} loader snapshot read: got {read} bytes, expected {}",
                snapshot.section_name,
                snapshot.bytes.len()
            ));
        }

        // If the live section now contains process-local absolute pointers
        // (low 4GB, 8-byte aligned), the CRT has already run and this is no
        // longer a safe BSS baseline — keep zeros.
        let polluted = candidate.chunks_exact(8).any(|chunk| {
            let v = u64::from_le_bytes(chunk.try_into().unwrap_or_default());
            v >= 0x1_0000 && v <= 0xffff_ffff && (v & 7) == 0
        });
        if polluted {
            log::log(
                LogType::Info,
                &format!(
                    "loader snapshot refresh skipped for {} (live CRT pollution detected; keeping clean BSS zeros)",
                    snapshot.section_name
                ),
            );
            continue;
        }

        snapshot.bytes = candidate;
        let non_zero = snapshot.bytes.iter().filter(|&&byte| byte != 0).count();
        let hash = fnv1a64(&snapshot.bytes);
        log::log(
            LogType::Info,
            &format!(
                "loader snapshot refresh: {} RVA {:#x}, size {:#x}, non-zero {}, fnv1a64 {:#018x} (main thread frozen at first .text execution)",
                snapshot.section_name,
                snapshot.rva,
                snapshot.bytes.len(),
                non_zero,
                hash
            ),
        );
    }
    Ok(())
}

/// Merge late image-relative qwords into early zero slots (reinitializable globals).
pub(super) fn merge_reinitializable_data_state(
    dbg: &ProcessSession,
    snapshots: &mut [EarlySectionSnapshot],
    image_size: usize,
) -> Result<(), anyhow::Error> {
    let image_base = dbg.image_base() as usize;
    let image_end = image_base.saturating_add(image_size);
    for snapshot in snapshots {
        let address = image_base
            .checked_add(snapshot.rva as usize)
            .ok_or_else(|| {
                anyhow!(
                    "late data snapshot address overflow for {}",
                    snapshot.section_name
                )
            })?;
        let mut late = vec![0u8; snapshot.bytes.len()];
        let read = dbg.read_memory(address, &mut late).map_err(|e| {
            anyhow!(
                "failed to read late {} snapshot: {e}",
                snapshot.section_name
            )
        })?;
        if read != late.len() {
            return Err(anyhow!(
                "short late {} snapshot read: got {read} bytes, expected {}",
                snapshot.section_name,
                late.len()
            ));
        }

        let mut merged = 0usize;
        for (early_chunk, late_chunk) in
            snapshot.bytes.chunks_exact_mut(8).zip(late.chunks_exact(8))
        {
            let early = u64::from_le_bytes(early_chunk.try_into().unwrap_or_default());
            let late = u64::from_le_bytes(late_chunk.try_into().unwrap_or_default());
            let late_address = late as usize;
            if early == 0 && (image_base..image_end).contains(&late_address) {
                early_chunk.copy_from_slice(late_chunk);
                merged += 1;
            }
        }
        debug!(
            section = %snapshot.section_name,
            merged,
            "merged reinitializable image-relative data globals"
        );
    }
    Ok(())
}

pub(super) fn log_snapshot_summary(snapshots: &[EarlySectionSnapshot], stage: &str) {
    for snapshot in snapshots {
        let non_zero = snapshot.bytes.iter().filter(|&&byte| byte != 0).count();
        log::log(
            LogType::Info,
            &format!(
                "{stage}: {} RVA {:#x}, size {:#x}, non-zero {}, fnv1a64 {:#018x}",
                snapshot.section_name,
                snapshot.rva,
                snapshot.bytes.len(),
                non_zero,
                fnv1a64(&snapshot.bytes)
            ),
        );
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::fnv1a64;

    #[test]
    fn fnv1a64_stable_empty() {
        assert_eq!(fnv1a64(&[]), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn fnv1a64_changes_with_byte() {
        assert_ne!(fnv1a64(b"a"), fnv1a64(b"b"));
    }
}
