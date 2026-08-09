//! Raw-slab capture coherence + transformed-child overlay (R0-C.1).
//!
//! P1 root cause: the production dump order transformed the heap child payloads
//! (scrub/repair/sort/sanitize) *before* capturing the heap slab. The slab holds
//! the **raw live bytes** while the children hold **post-transform bytes**, so
//! R0-C normalization's byte-equality check saw a false "capture collision".
//!
//! Correct data-version model:
//!   1. capture raw containers / raw heap globals / raw heap slab from the
//!      debuggee (same live state);
//!   2. preserve the raw child bytes;
//!   3. run the existing scrub/repair transforms (offline, candidate-payload
//!      only — never writes debuggee memory);
//!   4. prove raw coherence (raw child == raw slab slice at the child offset);
//!   5. overlay the **transformed** child bytes onto a patched backing slab;
//!   6. R0-C normalization then compares the transformed child against the
//!      patched slab (identical by construction).
//!
//! No raw coherence evidence => fail closed. The transformed child is never
//! compared against the un-patched raw slab.

use sha2::{Digest, Sha256};

use super::container_snapshot::ContainerSnapshot;
use super::heap_global_snapshot::{HeapGlobalSnapshot, HeapSlab, RegionProvenance};

/// Kind of a captured child region (for overlay provenance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawChildKind {
    HeapGlobal,
    Container,
}

impl RawChildKind {
    pub fn label(self) -> &'static str {
        match self {
            RawChildKind::HeapGlobal => "heap_global",
            RawChildKind::Container => "container",
        }
    }
}

/// A raw (pre-transform) child snapshot, preserved before any offline repair.
#[derive(Debug, Clone)]
pub struct RawChild {
    /// Old (live) allocation base.
    pub old_base: u64,
    /// Raw captured size in bytes.
    pub size: usize,
    /// Raw bytes exactly as read from the debuggee (pre-transform).
    pub raw_bytes: Vec<u8>,
    /// Kind (HeapGlobal or Container).
    pub kind: RawChildKind,
}

/// A coherent raw capture bundle: the raw slab plus the raw children it may
/// contain. Captured from the debuggee before any offline transform.
#[derive(Debug, Clone)]
pub struct RawSlabCapture {
    /// Raw heap slab bytes (pre-transform).
    pub slab: HeapSlab,
    /// Raw children (heap globals + containers) with their raw bytes.
    pub children: Vec<RawChild>,
}

/// A structured overlay ledger entry recording one transformed child overlaid
/// onto the patched backing slab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformedRegionOverlay {
    /// Kind of the overlaid child.
    pub child_kind: RawChildKind,
    /// Old base of the child.
    pub child_old_base: u64,
    /// Size of the child in bytes.
    pub child_size: usize,
    /// Offset of the child within the backing slab.
    pub slab_offset: usize,
    /// sha256 of the raw child bytes (coherence proof).
    pub raw_child_digest: String,
    /// sha256 of the raw slab slice `[offset, offset+size)` (coherence proof).
    pub raw_slab_slice_digest: String,
    /// sha256 of the transformed child bytes (post-transform).
    pub transformed_child_digest: String,
    /// Provenance of the transform (from the actual executed transform ledger).
    pub transform_ids: Vec<String>,
    /// Whether the overlay was applied.
    pub overlay_applied: bool,
    /// R0-E Path A: when this child is a contained subview of a backing object
    /// (force-admit interior child inside its containing object's range), the
    /// old base of the backing object it was overlaid onto. `None` for a
    /// standalone overlay or a synthetic region.
    pub contained_in_old_base: Option<u64>,
}

/// Errors from raw-coherence verification / transformed overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayError {
    /// The raw child range does not lie entirely within the raw slab.
    RawChildOutsideSlab {
        child_kind: RawChildKind,
        child_old_base: u64,
        child_size: usize,
        slab_old_base: u64,
        slab_size: usize,
    },
    /// offset + size overflowed.
    RawChildRangeOverflow {
        child_old_base: u64,
        child_size: usize,
        slab_old_base: u64,
        slab_offset: usize,
    },
    /// The raw slab slice at the child offset differs from the raw child bytes.
    RawCaptureDrift {
        child_kind: RawChildKind,
        child_old_base: u64,
        child_size: usize,
        slab_old_base: u64,
        slab_size: usize,
        slab_offset: usize,
        first_mismatch_offset: usize,
        raw_child_digest: String,
        raw_slab_slice_digest: String,
    },
    /// Two overlays conflict (partial overlap or same range different bytes).
    /// GTO R0-F: now carries the ACTUAL applied peer (not the current child
    /// duplicated) so the diagnostic names both real children.
    ///
    /// Retained for range-relationship reporting and API stability; the
    /// write-set overlay emits [`OverlayError::TransformWriteConflict`] for
    /// genuine same-byte-different-value conflicts, so this variant is not
    /// constructed on the current path.
    #[allow(dead_code)]
    OverlayConflict {
        a_child_old_base: u64,
        a_size: usize,
        b_child_old_base: u64,
        b_size: usize,
        slab_offset: usize,
    },
    /// Two transforms write the SAME slab byte to DIFFERENT final values.
    /// Genuine transformed write conflict (fail-closed). See GTO R0-F.
    TransformWriteConflict {
        /// old base of the first (earlier-applied) child.
        a_child_old_base: u64,
        /// size of the first child.
        a_size: usize,
        /// old base of the second (current) child.
        b_child_old_base: u64,
        /// size of the second child.
        b_size: usize,
        /// slab offset of the first conflicting byte.
        first_mismatch_slab_offset: usize,
        /// the raw (before) byte value at that slab offset.
        before_byte: u8,
        /// the value the first child's transform wrote.
        a_after_byte: u8,
        /// the value the second child's transform writes.
        b_after_byte: u8,
        /// transform ids of the first child.
        a_transform_ids: Vec<String>,
        /// transform ids of the second child.
        b_transform_ids: Vec<String>,
    },
    /// No raw counterpart found for a transformed child.
    RawChildMissing {
        child_old_base: u64,
        child_kind: RawChildKind,
    },
}

/// A single resolved write at one slab byte (for deterministic write-set merge).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedWrite {
    /// The final byte value written to the slab.
    value: u8,
    /// old base of the child that owns this write.
    child_old_base: u64,
    /// transform ids that produced this write.
    transform_ids: Vec<String>,
}

impl std::fmt::Display for OverlayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverlayError::RawChildOutsideSlab {
                child_kind,
                child_old_base,
                child_size,
                slab_old_base,
                slab_size,
            } => write!(
                f,
                "raw child outside slab: kind={} old_base={:#x} size={:#x} slab=[{:#x},+{:#x})",
                child_kind.label(),
                child_old_base,
                child_size,
                slab_old_base,
                slab_size
            ),
            OverlayError::RawChildRangeOverflow {
                child_old_base,
                child_size,
                slab_old_base,
                slab_offset,
            } => write!(
                f,
                "raw child range overflow: child {:#x} size {:#x} slab {:#x} offset {:#x}",
                child_old_base, child_size, slab_old_base, slab_offset
            ),
            OverlayError::RawCaptureDrift {
                child_kind,
                child_old_base,
                child_size,
                slab_old_base,
                slab_size,
                slab_offset,
                first_mismatch_offset,
                raw_child_digest,
                raw_slab_slice_digest,
            } => write!(
                f,
                "raw capture drift: kind={} child {:#x} size {:#x} slab [{:#x},+{:#x}) offset {:#x} \
                 first_mismatch={:#x} raw_child_sha={} raw_slab_slice_sha={}",
                child_kind.label(),
                child_old_base,
                child_size,
                slab_old_base,
                slab_size,
                slab_offset,
                first_mismatch_offset,
                raw_child_digest,
                raw_slab_slice_digest
            ),
            OverlayError::OverlayConflict {
                a_child_old_base,
                a_size,
                b_child_old_base,
                b_size,
                slab_offset,
            } => write!(
                f,
                "overlay conflict: [{:#x},+{:#x}) vs [{:#x},+{:#x}) overlap at slab offset {:#x}",
                a_child_old_base, a_size, b_child_old_base, b_size, slab_offset
            ),
            OverlayError::TransformWriteConflict {
                a_child_old_base,
                a_size,
                b_child_old_base,
                b_size,
                first_mismatch_slab_offset,
                before_byte,
                a_after_byte,
                b_after_byte,
                a_transform_ids,
                b_transform_ids,
            } => write!(
                f,
                "transformed write conflict: [{:#x},+{:#x}) vs [{:#x},+{:#x}) \
                 first_mismatch_slab_offset={:#x} before={:#04x} a_after={:#04x} b_after={:#04x} \
                 a_transform={:?} b_transform={:?}",
                a_child_old_base,
                a_size,
                b_child_old_base,
                b_size,
                first_mismatch_slab_offset,
                before_byte,
                a_after_byte,
                b_after_byte,
                a_transform_ids,
                b_transform_ids
            ),
            OverlayError::RawChildMissing {
                child_old_base,
                child_kind,
            } => write!(
                f,
                "no raw child for transformed child: kind={} old_base={:#x}",
                child_kind.label(),
                child_old_base
            ),
        }
    }
}

impl std::error::Error for OverlayError {}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Snapshot the raw children (pre-transform) into a form usable for coherence
/// verification after transforms. Container raw bytes come from
/// `heap_content`; heap-global raw bytes from `content`.
pub fn raw_children_from_capture(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
) -> Vec<RawChild> {
    let mut out = Vec::new();
    for c in containers {
        let size = c
            .decoded_end
            .checked_sub(c.decoded_begin)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        if size == 0 {
            continue;
        }
        let mut raw = c.heap_content.clone();
        raw.truncate(size);
        out.push(RawChild {
            old_base: c.decoded_begin,
            size,
            raw_bytes: raw,
            kind: RawChildKind::Container,
        });
    }
    for g in heap_globals {
        if g.is_heap_handle || g.is_image_inline || g.content.is_empty() {
            continue;
        }
        out.push(RawChild {
            old_base: g.live_ptr,
            size: g.content.len(),
            raw_bytes: g.content.clone(),
            kind: RawChildKind::HeapGlobal,
        });
    }
    // Deterministic order by (old_base, kind).
    out.sort_by_key(|c| (c.old_base, c.kind as u8));
    out
}

/// Verify raw coherence and overlay the transformed child bytes onto a patched
/// backing slab.
///
/// For each transformed child (by old_base), find its raw counterpart, compute
/// the slab offset, verify `raw_slab[offset..offset+size] == raw_child`, then
/// write `transformed_bytes` into the patched slab at `offset`. Returns the
/// patched slab and the overlay ledger.
///
/// Fail-closed on any raw-coherence drift, range overflow, child outside slab,
/// or conflicting overlays. Never modifies debuggee memory (offline candidate
/// construction only).
pub fn build_patched_backing_slab(
    raw_capture: &RawSlabCapture,
    transformed_globals: &[HeapGlobalSnapshot],
    transformed_containers: &[ContainerSnapshot],
    transform_ids: &[&'static str],
) -> Result<(HeapSlab, Vec<TransformedRegionOverlay>), OverlayError> {
    let slab = &raw_capture.slab;
    let mut backing = slab.content.clone();

    // Index raw children by old_base.
    let raw_by_base: std::collections::BTreeMap<u64, &RawChild> = raw_capture
        .children
        .iter()
        .map(|c| (c.old_base, c))
        .collect();

    // Collect transformed children (heap-global + container) with provenance.
    // SyntheticDerived children (created by an offline transform, no raw
    // source) are carried but excluded from raw-coherence; UnknownSynthetic
    // fails closed. See GTO Core Recovery R0-D.
    let mut transformed: Vec<(u64, usize, Vec<u8>, RawChildKind, RegionProvenance)> = Vec::new();
    for g in transformed_globals {
        if g.is_heap_handle || g.is_image_inline || g.content.is_empty() {
            continue;
        }
        transformed.push((
            g.live_ptr,
            g.content.len(),
            g.content.clone(),
            RawChildKind::HeapGlobal,
            g.provenance.clone(),
        ));
    }
    for c in transformed_containers {
        let size = c
            .decoded_end
            .checked_sub(c.decoded_begin)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        if size == 0 {
            continue;
        }
        let mut content = c.heap_content.clone();
        content.truncate(size);
        transformed.push((
            c.decoded_begin,
            size,
            content,
            RawChildKind::Container,
            RegionProvenance::RawCaptured {
                raw_digest: String::new(),
            },
        ));
    }
    // Deterministic order by (old_base, kind).
    transformed.sort_by_key(|(base, _, _, kind, _)| (*base, *kind as u8));

    let mut overlays: Vec<TransformedRegionOverlay> = Vec::new();
    // GTO R0-F: track resolved writes at slab-byte granularity for conflict
    // detection. Only differing transformed bytes are writes.
    let mut resolved_writes: std::collections::BTreeMap<usize, ResolvedWrite> =
        std::collections::BTreeMap::new();

    for (child_base, child_size, transformed_bytes, kind, provenance) in &transformed {
        let child_base = *child_base;
        let child_size = *child_size;
        let kind = *kind;
        let transformed_bytes = transformed_bytes.clone();
        // R0-D: UnknownSynthetic always fails closed.
        if let RegionProvenance::UnknownSynthetic = &provenance {
            return Err(OverlayError::RawChildMissing {
                child_old_base: child_base,
                child_kind: kind,
            });
        }
        // R0-D: SyntheticDerived children have no raw source by design; they
        // are recorded as synthetic ledger entries (not overlaid into the
        // slab) and materialized as independent runtime regions.
        if let RegionProvenance::SyntheticDerived {
            transform_id,
            source_anchor,
            construction_digest,
        } = &provenance
        {
            let t_digest = sha256_hex(&transformed_bytes);
            debug_assert_eq!(t_digest, *construction_digest);
            overlays.push(TransformedRegionOverlay {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_offset: 0,
                raw_child_digest: String::new(),
                raw_slab_slice_digest: String::new(),
                transformed_child_digest: t_digest,
                transform_ids: vec![transform_id.clone()],
                overlay_applied: false,
                contained_in_old_base: None,
            });
            let _ = source_anchor;
            continue;
        }
        let Some(raw) = raw_by_base.get(&child_base).copied() else {
            return Err(OverlayError::RawChildMissing {
                child_old_base: child_base,
                child_kind: kind,
            });
        };
        // Slab offset = child_base - slab.old_base (checked).
        let Some(slab_offset) = child_base.checked_sub(slab.old_base) else {
            return Err(OverlayError::RawChildOutsideSlab {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base: slab.old_base,
                slab_size: slab.content.len(),
            });
        };
        let slab_offset_us =
            usize::try_from(slab_offset).map_err(|_| OverlayError::RawChildOutsideSlab {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base: slab.old_base,
                slab_size: slab.content.len(),
            })?;
        let Some(child_end) = slab_offset_us.checked_add(child_size) else {
            return Err(OverlayError::RawChildRangeOverflow {
                child_old_base: child_base,
                child_size,
                slab_old_base: slab.old_base,
                slab_offset: slab_offset_us,
            });
        };
        if child_end > slab.content.len() {
            return Err(OverlayError::RawChildOutsideSlab {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base: slab.old_base,
                slab_size: slab.content.len(),
            });
        }
        // In-place transforms keep the child size; a size-changing transform is
        // not supported (fail closed).
        let raw_child_bytes = &raw.raw_bytes[..raw.size.min(raw.raw_bytes.len())];
        if raw_child_bytes.len() != child_size {
            return Err(OverlayError::RawCaptureDrift {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base: slab.old_base,
                slab_size: slab.content.len(),
                slab_offset: slab_offset_us,
                first_mismatch_offset: raw_child_bytes.len().min(child_size),
                raw_child_digest: sha256_hex(raw_child_bytes),
                raw_slab_slice_digest: sha256_hex(&slab.content[slab_offset_us..child_end]),
            });
        }
        // Raw coherence: raw slab slice == raw child bytes (same length now).
        let raw_slab_slice = &slab.content[slab_offset_us..child_end];
        if raw_slab_slice != raw_child_bytes {
            let mut first_mismatch = usize::MAX;
            for (k, (a, b)) in raw_slab_slice
                .iter()
                .zip(raw_child_bytes.iter())
                .enumerate()
            {
                if a != b {
                    first_mismatch = k;
                    break;
                }
            }
            return Err(OverlayError::RawCaptureDrift {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base: slab.old_base,
                slab_size: slab.content.len(),
                slab_offset: slab_offset_us,
                first_mismatch_offset: first_mismatch,
                raw_child_digest: sha256_hex(raw_child_bytes),
                raw_slab_slice_digest: sha256_hex(raw_slab_slice),
            });
        }
        // GTO R0-F: conflict resolution is based on the transformed WRITE-SET
        // (the byte runs where this child's bytes differ from its raw capture),
        // not on the whole child range. Overlapping capture/probe windows with
        // disjoint (or identical) writes do NOT conflict; only a transform that
        // writes the SAME slab byte to a DIFFERENT final value than an
        // already-resolved write fails closed. Unmodified raw bytes are not
        // writes and never trigger a conflict by themselves.
        let t_digest = sha256_hex(&transformed_bytes);
        let raw_len = raw_child_bytes.len().min(child_size);
        // Compute this child's write-set (slab byte offsets that changed).
        let mut write_runs: Vec<(usize, usize, Vec<u8>)> = Vec::new(); // (slab_off, len, bytes)
        {
            let mut run_start: Option<(usize, Vec<u8>)> = None;
            for i in 0..raw_len {
                let so = slab_offset_us + i;
                if transformed_bytes[i] != raw_child_bytes[i] {
                    match run_start.as_mut() {
                        Some((_, acc)) => acc.push(transformed_bytes[i]),
                        None => run_start = Some((so, vec![transformed_bytes[i]])),
                    }
                } else if let Some((s, acc)) = run_start.take() {
                    write_runs.push((s, acc.len(), acc));
                }
            }
            if let Some((s, acc)) = run_start.take() {
                write_runs.push((s, acc.len(), acc));
            }
        }
        let my_transform_ids: Vec<String> = transform_ids.iter().map(|s| s.to_string()).collect();
        // Resolve each write byte against already-applied writes.
        let mut contributed_new_write = false;
        let mut all_shared_with_same_base = true;
        let mut any_shared_write = false;
        for &(so, _, ref bytes) in &write_runs {
            for (k, &val) in bytes.iter().enumerate() {
                let abs = so + k;
                match resolved_writes.get(&abs) {
                    None => {
                        resolved_writes.insert(
                            abs,
                            ResolvedWrite {
                                value: val,
                                child_old_base: child_base,
                                transform_ids: my_transform_ids.clone(),
                            },
                        );
                        contributed_new_write = true;
                    }
                    Some(existing) if existing.value == val => {
                        // SharedWriteSameValue: same final byte from two
                        // transforms. Record for ledger; only a true duplicate
                        // (same base, all writes shared) is deduped.
                        any_shared_write = true;
                        if existing.child_old_base != child_base {
                            all_shared_with_same_base = false;
                        }
                    }
                    Some(existing) => {
                        return Err(OverlayError::TransformWriteConflict {
                            a_child_old_base: existing.child_old_base,
                            a_size: child_size,
                            b_child_old_base: child_base,
                            b_size: child_size,
                            first_mismatch_slab_offset: abs,
                            before_byte: raw_child_bytes[k],
                            a_after_byte: existing.value,
                            b_after_byte: val,
                            a_transform_ids: existing.transform_ids.clone(),
                            b_transform_ids: my_transform_ids.clone(),
                        });
                    }
                }
            }
        }
        // Apply the write-set to the patched backing slab.
        for &(so, len, ref bytes) in &write_runs {
            backing[so..so + len].copy_from_slice(bytes);
        }
        // GTO R0-F: a child whose ENTIRE write-set was already resolved with the
        // SAME values from the SAME base is a true duplicate (same object
        // captured twice) and is deduped. An overlapping view (different base)
        // that happens to share some writes is still recorded (SharedWriteSameValue),
        // so both real views appear in the ledger.
        let is_true_duplicate = !write_runs.is_empty()
            && !contributed_new_write
            && any_shared_write
            && all_shared_with_same_base;
        if is_true_duplicate {
            continue;
        }
        // Compute containment relationship for the ledger (R0-E Path A): does
        // this child sit inside another transformed child's range?
        let contained_in = transformed
            .iter()
            .find(|(ob, osz, _, ok, _)| {
                // exclude this child itself
                !(*ok == kind && *ob == child_base)
                    && *ob <= child_base
                    && child_base + child_size as u64 <= ob.saturating_add(*osz as u64)
            })
            .map(|(ob, _, _, _, _)| *ob);
        overlays.push(TransformedRegionOverlay {
            child_kind: kind,
            child_old_base: child_base,
            child_size,
            slab_offset: slab_offset_us,
            raw_child_digest: sha256_hex(raw_child_bytes),
            raw_slab_slice_digest: sha256_hex(raw_slab_slice),
            transformed_child_digest: t_digest,
            transform_ids: my_transform_ids,
            overlay_applied: true,
            contained_in_old_base: contained_in,
        });
    }

    // Deterministic overlay sort.
    overlays.sort_by_key(|o| (o.child_old_base, o.slab_offset, o.child_size));
    Ok((
        HeapSlab {
            old_base: slab.old_base,
            content: backing,
        },
        overlays,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::heap_global_snapshot::CaptureExtentKind;
    use super::*;
    use crate::dumper::container_snapshot::ContainerSnapshot;
    use crate::dumper::heap_global_snapshot::{HeapGlobalSnapshot, HeapSlab};

    fn global(live_ptr: u64, content: Vec<u8>, inline: bool) -> HeapGlobalSnapshot {
        HeapGlobalSnapshot {
            rva: if inline { 0x40 } else { 0 },
            live_ptr,
            content,
            is_heap_handle: false,
            is_image_inline: inline,
            provenance: RegionProvenance::default(),
            extent_kind: CaptureExtentKind::default(),
        }
    }

    fn handle(live_ptr: u64) -> HeapGlobalSnapshot {
        HeapGlobalSnapshot {
            rva: 0x10,
            live_ptr,
            content: Vec::new(),
            is_heap_handle: true,
            is_image_inline: false,
            provenance: RegionProvenance::default(),
            extent_kind: CaptureExtentKind::default(),
        }
    }

    /// Produce same-length "transformed" bytes (each byte +1) so raw and
    /// transformed child lengths always match (in-place transform model).
    fn repaint(v: &[u8]) -> Vec<u8> {
        v.iter().map(|b| b.wrapping_add(1)).collect()
    }

    fn container(begin: u64, end: u64, content: Vec<u8>) -> ContainerSnapshot {
        ContainerSnapshot {
            rva: 0x20,
            decoded_begin: begin,
            decoded_end: end,
            decoded_capacity: end + 0x10,
            cookie: 0x1234,
            heap_content: content,
        }
    }

    fn slab(base: u64, content: Vec<u8>) -> HeapSlab {
        HeapSlab {
            old_base: base,
            content,
        }
    }

    fn slab_with_child(
        slab_base: u64,
        slab_sz: usize,
        child_base: u64,
        raw_child: Vec<u8>,
    ) -> HeapSlab {
        let mut content = vec![0u8; slab_sz];
        let off = (child_base - slab_base) as usize;
        content[off..off + raw_child.len()].copy_from_slice(&raw_child);
        slab(slab_base, content)
    }

    const ROUTEK_SLAB_BASE: u64 = 0x1ff000;
    const ROUTEK_SLAB_SZ: usize = 0x35a1118;
    const ROUTEK_CHILD_BASE: u64 = 0x200000;

    #[test]
    fn r0c1_capture_slab_before_transforms() {
        let g = global(ROUTEK_CHILD_BASE, b"raw-child-bytes".to_vec(), false);
        let children = raw_children_from_capture(&[], &[g.clone()]);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].raw_bytes, b"raw-child-bytes".to_vec());
        assert_eq!(children[0].kind, RawChildKind::HeapGlobal);
    }

    #[test]
    fn r0c1_raw_equal_transform_unchanged() {
        let raw = b"child-unchanged".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let transformed = global(ROUTEK_CHILD_BASE, raw.clone(), false);
        let (patched, overlays) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        assert_eq!(overlays.len(), 1);
        let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        assert_eq!(&patched.content[off..off + raw.len()], &raw[..]);
    }

    #[test]
    fn r0c1_raw_equal_transform_changed_overlay() {
        let raw = b"original-raw-child".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let transformed_bytes = b"REPAIRED-child-xxx".to_vec();
        let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
        let (patched, _) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        assert_eq!(
            &patched.content[off..off + transformed_bytes.len()],
            &transformed_bytes[..]
        );
    }

    #[test]
    fn r0c1_raw_drift_rejected() {
        let raw = b"child-A-content".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            b"child-B-content".to_vec(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let transformed = global(ROUTEK_CHILD_BASE, raw.clone(), false);
        let err =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    #[test]
    fn r0c1_overlay_slab_slice_equals_transformed() {
        let raw = b"raw-AAAAAAAAAAAA".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let transformed_bytes = repaint(&raw);
        let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
        let (patched, _) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        assert_eq!(
            &patched.content[off..off + transformed_bytes.len()],
            &transformed_bytes[..]
        );
    }

    #[test]
    fn r0c1_routek_exact_offset() {
        let raw = vec![0x41u8; 0x1a];
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: 0x1a,
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let transformed_bytes = vec![0x42u8; 0x1a];
        let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
        let (patched, overlays) = build_patched_backing_slab(
            &raw_capture,
            &[transformed],
            &[],
            &["repair_gscript_window_strings"],
        )
        .unwrap();
        assert_eq!(overlays[0].slab_offset, 0x1000);
        assert_eq!(overlays[0].child_size, 0x1a);
        assert_eq!(&patched.content[0x1000..0x101a], &transformed_bytes[..]);
        assert_eq!(
            overlays[0].transform_ids,
            vec!["repair_gscript_window_strings".to_string()]
        );
    }

    #[test]
    fn r0c1_repaired_window_string_overlay() {
        let raw = b"ZhuChuangKou".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let repaired = b"NewClassName".to_vec();
        let transformed = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
        let (patched, o) = build_patched_backing_slab(
            &raw_capture,
            &[transformed],
            &[],
            &["repair_gscript_window_strings"],
        )
        .unwrap();
        assert_eq!(o[0].transform_ids[0], "repair_gscript_window_strings");
        let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        assert_eq!(&patched.content[off..off + repaired.len()], &repaired[..]);
    }

    #[test]
    fn r0c1_scrubbed_pointer_overlay() {
        let raw = vec![0xAAu8; 16];
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: 16,
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let scrubbed = vec![0u8; 16];
        let transformed = global(ROUTEK_CHILD_BASE, scrubbed.clone(), false);
        let (patched, o) = build_patched_backing_slab(
            &raw_capture,
            &[transformed],
            &[],
            &["scrub_uncaptured_heap_pointers"],
        )
        .unwrap();
        assert_eq!(o[0].transform_ids[0], "scrub_uncaptured_heap_pointers");
        let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        assert_eq!(&patched.content[off..off + 16], &[0u8; 16][..]);
    }

    #[test]
    fn r0c1_container_scrub_overlay() {
        let raw = vec![0xAAu8; 24];
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: 24,
                raw_bytes: raw.clone(),
                kind: RawChildKind::Container,
            }],
        };
        let scrubbed = vec![0u8; 24];
        let transformed = container(ROUTEK_CHILD_BASE, ROUTEK_CHILD_BASE + 24, scrubbed.clone());
        let (patched, o) =
            build_patched_backing_slab(&raw_capture, &[], &[transformed], &["scrub"]).unwrap();
        assert_eq!(o[0].child_kind, RawChildKind::Container);
        let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        assert_eq!(&patched.content[off..off + 24], &[0u8; 24][..]);
    }

    #[test]
    fn r0c1_two_disjoint_children() {
        let raw_a = b"child-A-bytes".to_vec();
        let raw_b = b"child-B-bytes".to_vec();
        let mut content = vec![0u8; ROUTEK_SLAB_SZ];
        let off_a = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        content[off_a..off_a + raw_a.len()].copy_from_slice(&raw_a);
        content[0x3000..0x3000 + raw_b.len()].copy_from_slice(&raw_b);
        let raw_capture = RawSlabCapture {
            slab: slab(ROUTEK_SLAB_BASE, content),
            children: vec![
                RawChild {
                    old_base: ROUTEK_CHILD_BASE,
                    size: raw_a.len(),
                    raw_bytes: raw_a.clone(),
                    kind: RawChildKind::HeapGlobal,
                },
                RawChild {
                    old_base: ROUTEK_SLAB_BASE + 0x3000,
                    size: raw_b.len(),
                    raw_bytes: raw_b.clone(),
                    kind: RawChildKind::HeapGlobal,
                },
            ],
        };
        let ga = global(ROUTEK_CHILD_BASE, repaint(&raw_a), false);
        let gb = global(ROUTEK_SLAB_BASE + 0x3000, repaint(&raw_b), false);
        let (_, overlays) =
            build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
        assert_eq!(overlays.len(), 2);
    }

    #[test]
    fn r0c1_duplicate_overlay_dedup() {
        let raw = b"child-dup-xxx".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let repaired = repaint(&raw);
        let ga = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
        let gb = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
        let (_, overlays) =
            build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
        assert_eq!(overlays.len(), 1);
    }

    #[test]
    fn r0c1_duplicate_conflict_rejected() {
        let raw = b"child-confx".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let ga = global(ROUTEK_CHILD_BASE, repaint(&raw), false);
        let gb = global(ROUTEK_CHILD_BASE, repaint(&repaint(&raw)), false);
        let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    }

    #[test]
    fn r0c1_partial_overlap_rejected() {
        // Two children at 0x200000 and 0x200010 (offset +16), both 32 bytes.
        // Their raw bytes AGREE in the overlap so raw coherence passes; the
        // transformed overlays then partially overlap -> overlay conflict.
        let raw_a = vec![0xAAu8; 32];
        let raw_b = vec![0xAAu8; 32]; // same bytes (agree in overlap)
        let mut content = vec![0u8; ROUTEK_SLAB_SZ];
        let off_a = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        content[off_a..off_a + 32].copy_from_slice(&raw_a);
        let off_b = off_a + 16;
        content[off_b..off_b + 32].copy_from_slice(&raw_b);
        let raw_capture = RawSlabCapture {
            slab: slab(ROUTEK_SLAB_BASE, content),
            children: vec![
                RawChild {
                    old_base: ROUTEK_CHILD_BASE,
                    size: 32,
                    raw_bytes: raw_a,
                    kind: RawChildKind::HeapGlobal,
                },
                RawChild {
                    old_base: ROUTEK_CHILD_BASE + 16,
                    size: 32,
                    raw_bytes: raw_b,
                    kind: RawChildKind::HeapGlobal,
                },
            ],
        };
        // transformed overlays differ and partially overlap -> conflict.
        let ga = global(ROUTEK_CHILD_BASE, vec![0u8; 32], false);
        let gb = global(ROUTEK_CHILD_BASE + 16, vec![0x01u8; 32], false);
        let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    }

    #[test]
    fn r0c1_overlay_out_of_slab() {
        let raw_capture = RawSlabCapture {
            slab: slab(ROUTEK_SLAB_BASE, vec![0u8; 0x1000]),
            children: vec![],
        };
        let transformed = global(ROUTEK_SLAB_BASE + 0x1000, vec![0u8; 0x10], false);
        let err =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
        assert!(
            matches!(err, OverlayError::RawChildMissing { .. })
                || matches!(err, OverlayError::RawChildOutsideSlab { .. })
        );
    }

    #[test]
    fn r0c1_child_outside_slab() {
        let raw_capture = RawSlabCapture {
            slab: slab(0x1000, vec![0u8; 0x100]),
            children: vec![RawChild {
                old_base: 0x2000,
                size: 8,
                raw_bytes: vec![0u8; 8],
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let transformed = global(0x2000, vec![0u8; 8], false);
        let err =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::RawChildOutsideSlab { .. }));
    }

    #[test]
    fn r0c1_image_inline_not_overlaid() {
        let raw_capture = RawSlabCapture {
            slab: slab(0x1000, vec![0u8; 0x100]),
            children: vec![],
        };
        let inline = global(0x140000000, b"img-inline".to_vec(), true);
        // image-inline globals are skipped by overlay (they live in the image);
        // no overlay is produced.
        let (_, overlays) =
            build_patched_backing_slab(&raw_capture, &[inline], &[], &["t"]).unwrap();
        assert!(overlays.is_empty());
    }

    #[test]
    fn r0c1_heap_handle_not_overlaid() {
        let raw_capture = RawSlabCapture {
            slab: slab(0x1000, vec![0u8; 0x100]),
            children: vec![],
        };
        let h = handle(0x8f0000);
        let (_, overlays) = build_patched_backing_slab(&raw_capture, &[h], &[], &["t"]).unwrap();
        assert!(overlays.is_empty());
    }

    #[test]
    fn r0c1_nobypass_off_path_unchanged() {
        let raw_capture = RawSlabCapture {
            slab: slab(0x1000, vec![0u8; 0x100]),
            children: vec![],
        };
        let (_, overlays) = build_patched_backing_slab(&raw_capture, &[], &[], &["t"]).unwrap();
        assert!(overlays.is_empty());
    }

    #[test]
    fn r0c1_ledger_deterministic_sort() {
        let raw_a = b"AAA".to_vec();
        let raw_b = b"BBB".to_vec();
        let mut content = vec![0u8; ROUTEK_SLAB_SZ];
        content[0x1000..0x1003].copy_from_slice(&raw_a);
        content[0x2000..0x2003].copy_from_slice(&raw_b);
        let raw_capture = RawSlabCapture {
            slab: slab(ROUTEK_SLAB_BASE, content),
            children: vec![
                RawChild {
                    old_base: ROUTEK_SLAB_BASE + 0x2000,
                    size: 3,
                    raw_bytes: raw_b,
                    kind: RawChildKind::HeapGlobal,
                },
                RawChild {
                    old_base: ROUTEK_SLAB_BASE + 0x1000,
                    size: 3,
                    raw_bytes: raw_a,
                    kind: RawChildKind::HeapGlobal,
                },
            ],
        };
        let ga = global(ROUTEK_SLAB_BASE + 0x1000, b"XXX".to_vec(), false);
        let gb = global(ROUTEK_SLAB_BASE + 0x2000, b"YYY".to_vec(), false);
        let (_, o1) =
            build_patched_backing_slab(&raw_capture, &[gb.clone(), ga.clone()], &[], &["t"])
                .unwrap();
        let (_, o2) = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
        assert_eq!(o1, o2);
        assert!(o1[0].child_old_base < o1[1].child_old_base);
    }

    #[test]
    fn r0c1_metadata_patched_slab() {
        let raw = b"raw-child-xyz".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let transformed_bytes = repaint(&raw);
        let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
        let (patched, _) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
        assert_eq!(
            &patched.content[off..off + transformed_bytes.len()],
            &transformed_bytes[..]
        );
    }

    #[test]
    fn r0c1_raw_mismatch_no_candidate() {
        let raw = b"raw-A".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            b"raw-B".to_vec(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw,
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let transformed = global(ROUTEK_CHILD_BASE, b"REPAIRED".to_vec(), false);
        let err =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    #[test]
    fn r0c1_overlay_conflict_no_candidate() {
        let raw = b"child-conflict".to_vec();
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            raw.clone(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: ROUTEK_CHILD_BASE,
                size: raw.len(),
                raw_bytes: raw.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        let ga = global(ROUTEK_CHILD_BASE, repaint(&raw), false);
        let gb = global(ROUTEK_CHILD_BASE, repaint(&repaint(&raw)), false);
        let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    }

    fn synthetic(live_ptr: u64, bytes: Vec<u8>, tid: &str) -> HeapGlobalSnapshot {
        let mut g = global(live_ptr, bytes, false);
        g.provenance = RegionProvenance::SyntheticDerived {
            transform_id: tid.to_string(),
            source_anchor: "gscript+0xbd8 (test)".to_string(),
            construction_digest: sha256_hex(&g.content),
        };
        g
    }

    // GTO Core Recovery R0-D: the live Route L R1 geometry had a synthetic
    // window-string child at 0x200000 OUTSIDE the captured slab
    // [0x9e0000, 0x3977090). R0-D must not fail-closed on a SyntheticDerived
    // child (no raw source by design) — it is recorded as a synthetic ledger
    // entry and materialized as an independent runtime region.
    #[test]
    fn r0d_synthetic_child_outside_slab_not_rejected() {
        let slab_base: u64 = 0x9e0000;
        let slab_sz = 0x2a97090usize;
        let synthetic_base: u64 = 0x200000;
        // Raw slab contains a normal captured child inside it.
        let real_child_bytes = b"real-captured-child".to_vec();
        let s = slab_with_child(
            slab_base,
            slab_sz,
            slab_base + 0x3000,
            real_child_bytes.clone(),
        );
        let raw_slab_content = s.content.clone();
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![RawChild {
                old_base: slab_base + 0x3000,
                size: real_child_bytes.len(),
                raw_bytes: real_child_bytes.clone(),
                kind: RawChildKind::HeapGlobal,
            }],
        };
        // Transformed: one in-slab raw child (unchanged) + one synthetic child
        // at 0x200000 (outside the slab, SyntheticDerived provenance).
        let real = global(slab_base + 0x3000, real_child_bytes.clone(), false);
        let synth = synthetic(
            synthetic_base,
            b"NewClassName".to_vec(),
            "repair_gscript_window_strings",
        );
        let (patched, overlays) = build_patched_backing_slab(
            &raw_capture,
            &[real, synth],
            &[],
            &["repair_gscript_window_strings"],
        )
        .unwrap();
        // Synthetic child did NOT get written into the slab (it has no slab
        // offset) and is recorded with overlay_applied=false.
        let synth_overlays: Vec<_> = overlays
            .iter()
            .filter(|o| o.child_old_base == synthetic_base)
            .collect();
        assert_eq!(synth_overlays.len(), 1);
        assert!(!synth_overlays[0].overlay_applied);
        assert_eq!(synth_overlays[0].slab_offset, 0);
        assert_eq!(
            synth_overlays[0].transform_ids,
            vec!["repair_gscript_window_strings".to_string()]
        );
        // The in-slab child overlay still applied.
        let real_overlays: Vec<_> = overlays
            .iter()
            .filter(|o| o.child_old_base == slab_base + 0x3000)
            .collect();
        assert_eq!(real_overlays.len(), 1);
        assert!(real_overlays[0].overlay_applied);
        // The patched slab is unchanged at the (non-existent) synthetic offset.
        assert_eq!(patched.content, raw_slab_content);
    }

    // R0-D: an UnknownSynthetic child must fail closed (never a fallback
    // candidate, never silently dropped).
    #[test]
    fn r0d_unknown_synthetic_fails_closed() {
        let slab_base: u64 = 0x9e0000;
        let slab_sz = 0x2000usize;
        let s = slab(slab_base, vec![0u8; slab_sz]);
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![],
        };
        let mut g = global(slab_base + 0x1000, vec![0x41u8; 16], false);
        g.provenance = RegionProvenance::UnknownSynthetic;
        let err = build_patched_backing_slab(&raw_capture, &[g], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::RawChildMissing { .. }));
    }

    // R0-D: a SyntheticDerived child must NOT be silently treated as a raw
    // child (it must carry SyntheticDerived provenance, not RawCaptured).
    #[test]
    fn r0d_synthetic_provenance_is_derived_not_raw() {
        let synth = synthetic(
            0x200000,
            b"NewClassName".to_vec(),
            "repair_gscript_window_strings",
        );
        match &synth.provenance {
            RegionProvenance::SyntheticDerived {
                transform_id,
                construction_digest,
                ..
            } => {
                assert_eq!(transform_id, "repair_gscript_window_strings");
                assert_eq!(*construction_digest, sha256_hex(&synth.content));
            }
            other => panic!("expected SyntheticDerived, got {other:?}"),
        }
    }

    // GTO Core Recovery R0-E Path A: a force-admit interior child contained
    // within its backing object's range is reconciled as a subview (overlaid at
    // its contained offset) rather than rejected as an OverlayConflict. This is
    // the Route M R1 blocker geometry: slab [0x89f000,...), backing 0x8d8580,
    // subview child 0x8d8d60 (inside 0x8d8580), both raw-coherent with the slab.
    #[test]
    fn r0e_contained_subview_reconciled_not_conflict() {
        let slab_base: u64 = 0x89f000;
        let backing_base: u64 = 0x8d8580;
        let subview_base: u64 = 0x8d8d60;
        let backing_sz: usize = 6688; // 0x1a20
        let subview_sz: usize = 0x400;
        // Raw slab content: backing occupies [0x8d8580, 0x8d8580+6688);
        // subview bytes at its offset are [0xEE; 0x400], and the backing raw
        // content matches at that offset (same physical memory).
        let backing_off = (backing_base - slab_base) as usize; // 0x39580
        let subview_off = (subview_base - slab_base) as usize; // 0x39d60
        let subview_in_backing = (subview_base - backing_base) as usize; // 0x7e0
        let mut slab_content = vec![0u8; backing_off + backing_sz];
        // Backing raw content at subview offset = [0xEE; 0x400].
        for i in 0..subview_sz {
            slab_content[backing_off + subview_in_backing + i] = 0xEE;
        }
        let raw_capture = RawSlabCapture {
            slab: slab(slab_base, slab_content.clone()),
            children: vec![
                RawChild {
                    old_base: backing_base,
                    size: backing_sz,
                    raw_bytes: {
                        // raw backing: zeros with [0xEE;0x400] at subview offset
                        let mut b = vec![0u8; backing_sz];
                        b[subview_in_backing..subview_in_backing + subview_sz].fill(0xEE);
                        b
                    },
                    kind: RawChildKind::HeapGlobal,
                },
                RawChild {
                    old_base: subview_base,
                    size: subview_sz,
                    raw_bytes: vec![0xEEu8; subview_sz],
                    kind: RawChildKind::HeapGlobal,
                },
            ],
        };
        // Transformed: backing unchanged; subview transformed (bytes differ from
        // raw to exercise the subview overlay). Both raw-coherent with the slab.
        let backing = global(
            backing_base,
            {
                let mut b = vec![0u8; backing_sz];
                b[subview_in_backing..subview_in_backing + subview_sz].fill(0xEE);
                b
            },
            false,
        );
        let subview_transformed = vec![0xDDu8; subview_sz];
        let subview = global(subview_base, subview_transformed.clone(), false);
        let (patched, overlays) = build_patched_backing_slab(
            &raw_capture,
            &[backing, subview],
            &[],
            &["repair_gscript_window_strings"],
        )
        .unwrap();
        // The subview's transformed bytes must be overlaid at its offset.
        let subview_overlays: Vec<_> = overlays
            .iter()
            .filter(|o| o.child_old_base == subview_base)
            .collect();
        assert_eq!(subview_overlays.len(), 1);
        assert!(subview_overlays[0].overlay_applied);
        assert_eq!(
            subview_overlays[0].contained_in_old_base,
            Some(backing_base)
        );
        // Patched slab at subview offset == transformed subview bytes.
        assert_eq!(
            &patched.content[subview_off..subview_off + subview_sz],
            &subview_transformed[..]
        );
    }

    // GTO Core Recovery R0-E: a genuinely partial overlap (neither child
    // contained in the other) still fails closed — the containment
    // reconciliation does NOT weaken the conflict guarantee for unrelated
    // overlapping regions. In a single shared slab the partial overlap is
    // detected either as raw drift (the two children can't both be coherent
    // over the shared region) or as an OverlayConflict; either is fail-closed.
    #[test]
    fn r0e_partial_overlap_still_conflict() {
        let slab_base: u64 = 0x89f000;
        let a_base: u64 = 0x89f000 + 0x1000;
        let b_base: u64 = 0x89f000 + 0x1080;
        let sz = 0x100usize;
        let mut slab_content = vec![0u8; 0x2000];
        // a=[0x1000,0x1100), b=[0x1080,0x1180) share [0x1080,0x1100).
        slab_content[0x1000..0x1100].copy_from_slice(&vec![0xAA; 0x100]);
        slab_content[0x1080..0x1180].copy_from_slice(&vec![0xBB; 0x100]);
        let raw_capture = RawSlabCapture {
            slab: slab(slab_base, slab_content),
            children: vec![
                RawChild {
                    old_base: a_base,
                    size: sz,
                    raw_bytes: vec![0xAA; sz],
                    kind: RawChildKind::HeapGlobal,
                },
                RawChild {
                    old_base: b_base,
                    size: sz,
                    raw_bytes: vec![0xBB; sz],
                    kind: RawChildKind::HeapGlobal,
                },
            ],
        };
        let ga = global(a_base, vec![0xAA; sz], false);
        let gb = global(b_base, vec![0xBB; sz], false);
        let result = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]);
        // Fail-closed: either raw drift (shared slab region cannot satisfy both
        // raw-coherence checks) or an overlay conflict. Never a successful plan.
        assert!(result.is_err());
    }

    // ---------- GTO Core Recovery R0-F tests ----------

    // Route N geometry constants: overlapping first-hop probe windows.
    const ROUTEN_SLAB_BASE: u64 = 0x14f000;
    const ROUTEN_A_BASE: u64 = 0x96bb80;
    const ROUTEN_B_BASE: u64 = 0x96bbd0;
    const ROUTEN_VIEW_SZ: usize = 0x400;

    // Build a raw capture where the two Route N views both read from a slab
    // whose bytes at [A_BASE .. B_BASE+0x400) are all `fill`.
    fn route_n_raw_capture(fill: u8) -> RawSlabCapture {
        let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
        let end_off = (ROUTEN_B_BASE + ROUTEN_VIEW_SZ as u64 - ROUTEN_SLAB_BASE) as usize;
        let mut content = vec![0u8; end_off];
        content[a_off..end_off].fill(fill);
        RawSlabCapture {
            slab: slab(ROUTEN_SLAB_BASE, content),
            children: vec![
                RawChild {
                    old_base: ROUTEN_A_BASE,
                    size: ROUTEN_VIEW_SZ,
                    raw_bytes: vec![fill; ROUTEN_VIEW_SZ],
                    kind: RawChildKind::HeapGlobal,
                },
                RawChild {
                    old_base: ROUTEN_B_BASE,
                    size: ROUTEN_VIEW_SZ,
                    raw_bytes: vec![fill; ROUTEN_VIEW_SZ],
                    kind: RawChildKind::HeapGlobal,
                },
            ],
        }
    }

    // Two overlapping probe windows with DISJOINT transformed writes must NOT
    // conflict (the core R0-F fix for Route N R1).
    #[test]
    fn r0f_overlapping_views_with_disjoint_writes_merge() {
        let raw_capture = route_n_raw_capture(0xAA);
        // A writes its first 0x50 bytes to 0xBB; B writes its last 0x20 bytes
        // to 0xCC. The write-sets are disjoint -> merge, no conflict.
        let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
        a[..0x50].fill(0xBB);
        let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
        b[0x3e0..].fill(0xCC);
        let (patched, overlays) = build_patched_backing_slab(
            &raw_capture,
            &[
                global(ROUTEN_A_BASE, a, false),
                global(ROUTEN_B_BASE, b, false),
            ],
            &[],
            &["t1", "t2"],
        )
        .unwrap();
        let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
        let b_off = (ROUTEN_B_BASE - ROUTEN_SLAB_BASE) as usize;
        // A's first 0x50 bytes written to 0xBB.
        assert_eq!(
            &patched.content[a_off..a_off + 0x50],
            &vec![0xBBu8; 0x50][..]
        );
        // B's last 0x20 bytes written to 0xCC.
        assert_eq!(
            &patched.content[b_off + 0x3e0..b_off + 0x400],
            &vec![0xCCu8; 0x20][..]
        );
        // Both overlays present.
        assert_eq!(overlays.len(), 2);
    }

    // Two overlapping views with NO transformed writes (unchanged) -> no
    // conflict, patched slab == raw slab.
    #[test]
    fn r0f_overlapping_views_with_no_transforms_need_no_overlay() {
        let raw_capture = route_n_raw_capture(0xAA);
        let raw_slab = raw_capture.slab.content.clone();
        let a = global(ROUTEN_A_BASE, vec![0xAAu8; ROUTEN_VIEW_SZ], false);
        let b = global(ROUTEN_B_BASE, vec![0xAAu8; ROUTEN_VIEW_SZ], false);
        let (patched, _) = build_patched_backing_slab(&raw_capture, &[a, b], &[], &["t"]).unwrap();
        assert_eq!(patched.content, raw_slab);
    }

    // Same byte written by two transforms to the SAME final value merges
    // deterministically (SharedWriteSameValue).
    #[test]
    fn r0f_same_delta_value_merges_deterministically() {
        let raw_capture = route_n_raw_capture(0xAA);
        // Both A and B write byte 0x50 (the overlap) to 0xBB (same value).
        let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
        a[0x50] = 0xBB;
        let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
        b[0x00] = 0xBB; // B's offset 0 = slab A_off+0x50
        let (patched, overlays) = build_patched_backing_slab(
            &raw_capture,
            &[
                global(ROUTEN_A_BASE, a, false),
                global(ROUTEN_B_BASE, b, false),
            ],
            &[],
            &["t1", "t2"],
        )
        .unwrap();
        let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
        assert_eq!(patched.content[a_off + 0x50], 0xBB);
        assert_eq!(overlays.len(), 2);
    }

    // Same byte written to DIFFERENT final values -> TransformWriteConflict,
    // with both real peer bases reported.
    #[test]
    fn r0f_different_delta_value_fails_closed() {
        let raw_capture = route_n_raw_capture(0xAA);
        // Both write the overlap byte at slab a_off+0x50 (A's offset 0x50,
        // B's offset 0x00) to different values.
        let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
        a[0x50] = 0xBB;
        let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
        b[0x00] = 0xCC;
        let err = build_patched_backing_slab(
            &raw_capture,
            &[
                global(ROUTEN_A_BASE, a, false),
                global(ROUTEN_B_BASE, b, false),
            ],
            &[],
            &["t1", "t2"],
        )
        .unwrap_err();
        match err {
            OverlayError::TransformWriteConflict {
                a_child_old_base,
                b_child_old_base,
                a_after_byte,
                b_after_byte,
                ..
            } => {
                // The two REAL children are reported (not the current child twice).
                assert_eq!(a_child_old_base, ROUTEN_A_BASE);
                assert_eq!(b_child_old_base, ROUTEN_B_BASE);
                assert_eq!(a_after_byte, 0xBB);
                assert_eq!(b_after_byte, 0xCC);
            }
            other => panic!("expected TransformWriteConflict, got {other:?}"),
        }
    }

    // Input order independence: reversing child order gives the same result.
    #[test]
    fn r0f_input_order_does_not_change_overlay_result() {
        let raw_capture = route_n_raw_capture(0xAA);
        let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
        a[..0x50].fill(0xBB);
        let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
        b[0x3e0..].fill(0xCC);
        let g_a = global(ROUTEN_A_BASE, a.clone(), false);
        let g_b = global(ROUTEN_B_BASE, b.clone(), false);
        let (p1, _) =
            build_patched_backing_slab(&raw_capture, &[g_a.clone(), g_b.clone()], &[], &["t"])
                .unwrap();
        let (p2, _) = build_patched_backing_slab(&raw_capture, &[g_b, g_a], &[], &["t"]).unwrap();
        assert_eq!(p1.content, p2.content);
    }

    // The Route N geometry (two 0x400 views, base delta 0x50, overlap 0x3b0)
    // with NO transforms produces NO conflict.
    #[test]
    fn r0f_route_n_overlapping_probe_windows_no_conflict() {
        assert_eq!(ROUTEN_B_BASE - ROUTEN_A_BASE, 0x50);
        assert_eq!(0x400 - (ROUTEN_B_BASE - ROUTEN_A_BASE) as usize, 0x3b0);
        let raw_capture = route_n_raw_capture(0xAA);
        let a = global(ROUTEN_A_BASE, vec![0xAAu8; 0x400], false);
        let b = global(ROUTEN_B_BASE, vec![0xAAu8; 0x400], false);
        // Raw coherence passes (both match slab), and no writes -> no conflict.
        assert!(build_patched_backing_slab(&raw_capture, &[a, b], &[], &["t"]).is_ok());
    }

    // GTO R0-F: a TransformWriteConflict reports the exact slab offset of the
    // first mismatching byte (not just the range start).
    #[test]
    fn r0f_conflict_reports_first_mismatching_slab_byte() {
        let raw_capture = route_n_raw_capture(0xAA);
        let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
        // A writes at A_off+0x50; B writes at the same slab byte differently.
        let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
        a[0x50] = 0xBB;
        let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
        b[0x00] = 0xCC;
        let err = build_patched_backing_slab(
            &raw_capture,
            &[
                global(ROUTEN_A_BASE, a, false),
                global(ROUTEN_B_BASE, b, false),
            ],
            &[],
            &["t1", "t2"],
        )
        .unwrap_err();
        match err {
            OverlayError::TransformWriteConflict {
                first_mismatch_slab_offset,
                before_byte,
                ..
            } => {
                assert_eq!(first_mismatch_slab_offset, a_off + 0x50);
                assert_eq!(before_byte, 0xAA);
            }
            other => panic!("expected TransformWriteConflict, got {other:?}"),
        }
    }

    // GTO R0-F: a probe-window capture (first-hop estimate without a proven
    // boundary) must be classified as ProbeWindow, not ObservedAllocation.
    #[test]
    fn r0f_probe_window_is_not_claimed_as_allocation_extent() {
        let mut g = global(ROUTEN_A_BASE, vec![0xAAu8; ROUTEN_VIEW_SZ], false);
        // The default for a generic helper is ProbeWindow (the conservative
        // reading). A first-hop probe that only proves readability, not a
        // boundary, must stay ProbeWindow.
        assert_eq!(g.extent_kind, CaptureExtentKind::ProbeWindow);
        // Explicitly mark an observed allocation when a boundary is proven.
        g.extent_kind = CaptureExtentKind::ObservedAllocation;
        assert_eq!(g.extent_kind, CaptureExtentKind::ObservedAllocation);
    }
}
