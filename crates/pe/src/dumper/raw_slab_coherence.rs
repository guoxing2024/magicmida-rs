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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
///
/// GTO R0-G: carries the capture provenance from [`HeapGlobalSnapshot.extent_evidence`]
/// so the overlay can decide strict vs write-set-scoped coherence by extent, and
/// so the capture-drift ledger can bind each drift run to its capture path.
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

    // ---- GTO R0-G capture provenance (copied from HeapGlobalSnapshot) ----
    /// Deterministic capture id (from `extent_evidence.capture_id`).
    pub capture_id: String,
    /// Capture path (GscriptChildLink, GscriptFirstHop, MainSlot, ...).
    pub capture_path: super::heap_global_snapshot::CapturePath,
    /// Extent classification (ProbeWindow / InteriorSubview / ObservedAllocation / ...).
    pub extent_kind: super::heap_global_snapshot::CaptureExtentKind,
    /// Old base of the source parent whose slot led to this capture (if any).
    pub source_parent_old_base: Option<u64>,
    /// Byte offset of the source slot within the parent (if any).
    pub source_slot_offset: Option<usize>,
    /// The probe size requested for this capture.
    pub requested_probe_size: usize,
    /// Whether this pointer was interior to an already-captured object.
    pub was_interior: bool,
    /// Old base of the containing parent object, if any.
    pub containing_parent_old_base: Option<u64>,
    /// Size of the containing parent, if any.
    pub containing_parent_size: Option<usize>,
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

/// The byte source used as the input preimage for offline transforms (Route Q R0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformPreimageBasis {
    /// Strict extent: the raw child capture is accepted only after proving C == S.
    ChildCapture,
    /// Probe/interior extent: the authoritative slab slice seeds the transform input.
    AuthoritativeSlabSlice,
}

/// Auditable binding between a captured child and the bytes supplied to transforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformPreimageBinding {
    pub child_kind: RawChildKind,
    pub capture_id: String,
    pub child_old_base: u64,
    pub child_size: usize,
    pub extent_kind: super::heap_global_snapshot::CaptureExtentKind,
    pub slab_old_base: u64,
    pub slab_offset: usize,
    pub basis: TransformPreimageBasis,
    pub raw_child_digest: String,
    pub raw_slab_slice_digest: String,
    pub transform_input_digest: String,
    pub seeded_from_slab: bool,
}

/// A single contiguous write-run produced by one transform on one child (Route Q R0 Q0-B).
///
/// This is byte/run-level provenance, in contrast to the child-level
/// [`TransformedRegionOverlay.transform_ids`] / `HeapGlobalSnapshot.transform_ids`
/// which only record that a transform touched the child somewhere. A write-run
/// pins the exact child-relative byte span a transform changed, plus a digest
/// pair so a manifest can independently prove which bytes the transform wrote
/// (before = the transform's input preimage, after = the transform's output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformWriteRun {
    /// Deterministic capture id of the child (from `RawChild.capture_id` /
    /// `extent_evidence.capture_id`). Empty when the child has no capture id.
    pub child_capture_id: String,
    /// Old (live) base of the child.
    pub child_old_base: u64,
    /// Total child size in bytes (the preimage length the transform saw).
    pub child_size: usize,
    /// Child-relative byte offset of this contiguous run.
    pub child_offset: usize,
    /// Length of the contiguous run.
    pub length: usize,
    /// Transform that produced this run.
    pub transform_id: String,
    /// sha256 of the run's before bytes (the transform's input preimage for this span).
    pub before_digest: String,
    /// sha256 of the run's after bytes (the transform's output for this span).
    pub after_digest: String,
    /// First byte of the run before the transform.
    pub first_before_byte: u8,
    /// First byte of the run after the transform.
    pub first_after_byte: u8,
    /// Full before bytes of the run (size-controlled; authoritative evidence).
    pub before_bytes: Vec<u8>,
    /// Full after bytes of the run (size-controlled; authoritative evidence).
    pub after_bytes: Vec<u8>,
}

/// A byte/run-level transform provenance ledger (Route Q R0 Q0-B).
///
/// Deterministically ordered by `(child_old_base, child_offset, transform_id)`.
/// This replaces the ambiguous "every transform that touched a child is blamed
/// for every conflicting byte" model: each run is bound to exactly one transform
/// and one contiguous child byte span.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransformRunLedger {
    pub runs: Vec<TransformWriteRun>,
}

impl TransformRunLedger {
    /// Deterministic sort: by child base, then child offset, then transform id.
    pub fn sort_runs(&mut self) {
        self.runs.sort_by(|a, b| {
            (
                a.child_old_base,
                a.child_offset,
                a.length,
                a.transform_id.as_str(),
            )
                .cmp(&(
                    b.child_old_base,
                    b.child_offset,
                    b.length,
                    b.transform_id.as_str(),
                ))
        });
    }
}

/// Diff one transform's before/after child snapshots into byte/run-level write runs.
///
/// This is the byte-level counterpart of `record_transform_applied`: instead of
/// pushing a child-level transform id, it computes the exact contiguous runs of
/// bytes that changed and emits a [`TransformWriteRun`] for each. Because each
/// transform is diffed in isolation, a transform that only writes `+0x23`
/// (`mark_labels_non_nested`) is never attributed to `+0x28` — the run offset
/// is derived from the actual byte diff, not from the transform id.
///
/// Determinism: runs are emitted in ascending child-offset order for a stable
/// child. The caller is responsible for collapsing across transforms (a later
/// transform overwrites a byte an earlier transform wrote); that collapse is
/// left to Q0-C overlay integration, which uses the final authoritative preimage.
pub fn diff_transform_write_runs(
    before: &[HeapGlobalSnapshot],
    after: &[HeapGlobalSnapshot],
    transform_id: &str,
) -> Vec<TransformWriteRun> {
    let mut runs = Vec::new();
    for (b, a) in before.iter().zip(after.iter()) {
        if b.live_ptr != a.live_ptr || b.content == a.content {
            continue;
        }
        let child_size = a.content.len().max(b.content.len());
        let shared_len = b.content.len().min(a.content.len());
        // Build maximal contiguous runs of differing bytes.
        let mut changed: Vec<(usize, usize)> = Vec::new();
        let mut i = 0usize;
        while i < shared_len {
            if b.content[i] != a.content[i] {
                let run_start = i;
                while i < shared_len && b.content[i] != a.content[i] {
                    i += 1;
                }
                changed.push((run_start, i - run_start));
            } else {
                i += 1;
            }
        }
        for (off, len) in changed {
            let before_bytes = b.content[off..off + len].to_vec();
            let after_bytes = a.content[off..off + len].to_vec();
            let before_digest = sha256_hex(&before_bytes);
            let after_digest = sha256_hex(&after_bytes);
            runs.push(TransformWriteRun {
                child_capture_id: a.extent_evidence.capture_id.clone(),
                child_old_base: a.live_ptr,
                child_size,
                child_offset: off,
                length: len,
                transform_id: transform_id.to_string(),
                before_digest,
                after_digest,
                first_before_byte: before_bytes[0],
                first_after_byte: after_bytes[0],
                before_bytes,
                after_bytes,
            });
        }
    }
    runs
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
    /// Genuine transformed write conflict (fail-closed). See GTO R0-F / R0-F.1.
    TransformWriteConflict {
        /// old base of the first (earlier-applied) child.
        a_child_old_base: u64,
        /// size of the first child (the ACTUAL existing peer).
        a_size: usize,
        /// byte offset of the conflict within the first child.
        a_child_byte_offset: usize,
        /// old base of the second (current) child.
        b_child_old_base: u64,
        /// size of the second child.
        b_size: usize,
        /// byte offset of the conflict within the second child.
        b_child_byte_offset: usize,
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
    /// GTO R0-G: a transform wrote a byte whose preimage drifted between the
    /// child capture (t1) and the slab read (t2). The transform was derived from
    /// the old byte `C[i]`, so it cannot safely overwrite the new slab byte
    /// `S[i]`. Fail-closed.
    TransformPreimageDrift {
        /// old base of the child.
        child_old_base: u64,
        /// size of the child.
        child_size: usize,
        /// slab offset of the first drifted preimage byte.
        slab_offset: usize,
        /// child-relative byte offset of the drifted preimage.
        child_byte_offset: usize,
        /// the raw child byte (preimage the transform saw).
        c_byte: u8,
        /// the authoritative raw slab byte at the same position.
        s_byte: u8,
        /// the transformed byte the transform would have written.
        t_byte: u8,
        /// transform ids of the child.
        transform_ids: Vec<String>,
    },
}

/// How a capture-drift run (non-atomic child vs slab read) was resolved (GTO R0-G).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureDriftResolution {
    /// The child is a probe/interior view; the non-write drift is accepted and
    /// the authoritative raw slab byte wins (`B[i]=S[i]`).
    NonWriteSlabAuthoritative,
    /// A transform wrote a byte whose preimage drifted; fail-closed.
    TransformPreimageDrift,
    /// A strict extent (ObservedAllocation/BackingObject/Container) had full-range
    /// drift; fail-closed.
    StrictExtentRejected,
    /// Route Q R0 Q0-C: a probe/interior transform wrote a byte whose write-set
    /// was derived from the authoritative slab preimage (`P == S`, proven by the
    /// transform-input binding digest). The write is applied because it was
    /// replayed on the authoritative preimage, not on a stale child capture.
    /// Only allowed when the binding's `transform_input_digest == sha256(S)`.
    TransformReplayedOnAuthoritativePreimage,
}

/// A structured capture-drift run: one contiguous run of bytes where the raw
/// child capture (t1) differs from the authoritative raw slab slice (t2) (GTO R0-G).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureDriftRun {
    /// Capture id of the child (from RawChild.capture_id).
    pub child_capture_id: String,
    /// Old base of the child.
    pub child_old_base: u64,
    /// Child-relative byte offset of this drift run.
    pub child_offset: usize,
    /// Absolute slab offset of this drift run.
    pub slab_offset: usize,
    /// Length of the drift run.
    pub length: usize,
    /// sha256 of the raw child drift run bytes.
    pub child_digest: String,
    /// sha256 of the raw slab drift run bytes.
    pub slab_digest: String,
    /// Whether this drift run intersects any transformed write byte.
    pub intersects_transform_write: bool,
    /// How this drift run was resolved.
    pub resolution: CaptureDriftResolution,
}

/// A single resolved write at one slab byte (for deterministic write-set merge).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedWrite {
    /// The final byte value written to the slab.
    value: u8,
    /// old base of the child that owns this write.
    child_old_base: u64,
    /// size of the owning child (the ACTUAL existing peer, not the current).
    child_size: usize,
    /// byte offset of this write within the owning child.
    child_byte_offset: usize,
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
                a_child_byte_offset,
                b_child_old_base,
                b_size,
                b_child_byte_offset,
                first_mismatch_slab_offset,
                before_byte,
                a_after_byte,
                b_after_byte,
                a_transform_ids,
                b_transform_ids,
            } => write!(
                f,
                "transformed write conflict: [{:#x},+{:#x})@+{:#x} vs [{:#x},+{:#x})@+{:#x} \
                 first_mismatch_slab_offset={:#x} before={:#04x} a_after={:#04x} b_after={:#04x} \
                 a_transform={:?} b_transform={:?}",
                a_child_old_base,
                a_size,
                a_child_byte_offset,
                b_child_old_base,
                b_size,
                b_child_byte_offset,
                first_mismatch_slab_offset,
                before_byte,
                a_after_byte,
                b_after_byte,
                a_transform_ids,
                b_transform_ids
            ),
            OverlayError::TransformPreimageDrift {
                child_old_base,
                child_size,
                slab_offset,
                child_byte_offset,
                c_byte,
                s_byte,
                t_byte,
                transform_ids,
            } => write!(
                f,
                "transform preimage drift: child {child_old_base:#x} (size {child_size:#x})                  slab_offset={slab_offset:#x} child_byte_offset={child_byte_offset:#x}                  C={c_byte:#04x} S={s_byte:#04x} T={t_byte:#04x} transform={:?}                  (transform derived from drifted preimage; cannot safely overwrite slab)",
                transform_ids
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
            capture_id: String::new(),
            capture_path: super::heap_global_snapshot::CapturePath::MainSlot,
            extent_kind: super::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
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
            capture_id: g.extent_evidence.capture_id.clone(),
            capture_path: g.extent_evidence.capture_path,
            extent_kind: g.extent_kind,
            source_parent_old_base: g.extent_evidence.containing_parent_old_base,
            source_slot_offset: g.extent_evidence.source_slot_offset,
            requested_probe_size: g.extent_evidence.probe_requested_size,
            was_interior: g.extent_evidence.was_interior,
            containing_parent_old_base: g.extent_evidence.containing_parent_old_base,
            containing_parent_size: g.extent_evidence.containing_parent_size,
        });
    }
    // Deterministic order by (old_base, kind).
    out.sort_by_key(|c| (c.old_base, c.kind as u8));
    out
}

/// Seed transform inputs from authoritative slab bytes for probe/interior views.
///
/// This is the first Route Q R0 stage: raw child bytes remain available in
/// `RawSlabCapture` as C, while the mutable transform snapshots for
/// `ProbeWindow` / `InteriorSubview` are replaced with the exact slab slice S.
/// Strict extents are not reseeded; they must prove C == S and continue using C.
/// The returned bindings are the audit evidence that makes the transform basis
/// explicit rather than relying on call order or extent-kind inference alone.
pub fn seed_transform_inputs_from_authoritative_slab(
    raw_capture: &RawSlabCapture,
    containers: &mut [ContainerSnapshot],
    heap_globals: &mut [HeapGlobalSnapshot],
) -> Result<Vec<TransformPreimageBinding>, OverlayError> {
    use super::heap_global_snapshot::CaptureExtentKind as CEK;

    let mut bindings = Vec::new();

    for container in containers.iter() {
        let child_size = container
            .decoded_end
            .checked_sub(container.decoded_begin)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        if child_size == 0 {
            continue;
        }
        let current = &container.heap_content[..child_size.min(container.heap_content.len())];
        let raw = find_raw_child(
            raw_capture,
            container.decoded_begin,
            child_size,
            RawChildKind::Container,
            "",
            current,
        )?;
        let (slab_offset, slab_slice) = slab_slice_for_child(raw_capture, raw)?;
        if slab_slice != current {
            return Err(raw_capture_drift_error(
                RawChildKind::Container,
                raw.old_base,
                child_size,
                raw_capture.slab.old_base,
                raw_capture.slab.content.len(),
                slab_offset,
                slab_slice,
                current,
            ));
        }
        bindings.push(TransformPreimageBinding {
            child_kind: RawChildKind::Container,
            capture_id: raw.capture_id.clone(),
            child_old_base: raw.old_base,
            child_size,
            extent_kind: CEK::ObservedAllocation,
            slab_old_base: raw_capture.slab.old_base,
            slab_offset,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(current),
            raw_slab_slice_digest: sha256_hex(slab_slice),
            transform_input_digest: sha256_hex(current),
            seeded_from_slab: false,
        });
    }

    for global in heap_globals.iter_mut() {
        if global.is_heap_handle || global.is_image_inline || global.content.is_empty() {
            continue;
        }
        let child_size = global.content.len();
        let raw = find_raw_child(
            raw_capture,
            global.live_ptr,
            child_size,
            RawChildKind::HeapGlobal,
            &global.extent_evidence.capture_id,
            &global.content,
        )?;
        let (slab_offset, slab_slice) = slab_slice_for_child(raw_capture, raw)?;
        let basis = match global.extent_kind {
            CEK::ProbeWindow | CEK::InteriorSubview => {
                global.content.copy_from_slice(slab_slice);
                TransformPreimageBasis::AuthoritativeSlabSlice
            }
            CEK::ObservedAllocation | CEK::BackingObject => {
                if slab_slice != global.content.as_slice() {
                    return Err(raw_capture_drift_error(
                        RawChildKind::HeapGlobal,
                        raw.old_base,
                        child_size,
                        raw_capture.slab.old_base,
                        raw_capture.slab.content.len(),
                        slab_offset,
                        slab_slice,
                        &global.content,
                    ));
                }
                TransformPreimageBasis::ChildCapture
            }
            CEK::SyntheticDerived => continue,
        };
        bindings.push(TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: raw.capture_id.clone(),
            child_old_base: raw.old_base,
            child_size,
            extent_kind: global.extent_kind,
            slab_old_base: raw_capture.slab.old_base,
            slab_offset,
            basis,
            raw_child_digest: sha256_hex(&raw.raw_bytes),
            raw_slab_slice_digest: sha256_hex(slab_slice),
            transform_input_digest: sha256_hex(&global.content),
            seeded_from_slab: matches!(basis, TransformPreimageBasis::AuthoritativeSlabSlice),
        });
    }

    bindings.sort_by_key(|b| (b.child_old_base, b.child_kind, b.slab_offset));
    Ok(bindings)
}

fn find_raw_child<'a>(
    raw_capture: &'a RawSlabCapture,
    child_old_base: u64,
    child_size: usize,
    child_kind: RawChildKind,
    capture_id: &str,
    current: &[u8],
) -> Result<&'a RawChild, OverlayError> {
    let mut candidates: Vec<&RawChild> = raw_capture
        .children
        .iter()
        .filter(|child| {
            child.old_base == child_old_base
                && child.kind == child_kind
                && child.size == child_size
                && (capture_id.is_empty() || child.capture_id == capture_id)
                && child.raw_bytes.as_slice() == current
        })
        .collect();
    candidates.sort_by_key(|child| child.capture_id.as_str());
    candidates
        .into_iter()
        .next()
        .ok_or(OverlayError::RawChildMissing {
            child_old_base,
            child_kind,
        })
}

fn slab_slice_for_child<'a>(
    raw_capture: &'a RawSlabCapture,
    child: &RawChild,
) -> Result<(usize, &'a [u8]), OverlayError> {
    let slab_offset = child
        .old_base
        .checked_sub(raw_capture.slab.old_base)
        .and_then(|v| usize::try_from(v).ok())
        .ok_or(OverlayError::RawChildOutsideSlab {
            child_kind: child.kind,
            child_old_base: child.old_base,
            child_size: child.size,
            slab_old_base: raw_capture.slab.old_base,
            slab_size: raw_capture.slab.content.len(),
        })?;
    let child_end =
        slab_offset
            .checked_add(child.size)
            .ok_or(OverlayError::RawChildRangeOverflow {
                child_old_base: child.old_base,
                child_size: child.size,
                slab_old_base: raw_capture.slab.old_base,
                slab_offset,
            })?;
    let slab_slice = raw_capture.slab.content.get(slab_offset..child_end).ok_or(
        OverlayError::RawChildOutsideSlab {
            child_kind: child.kind,
            child_old_base: child.old_base,
            child_size: child.size,
            slab_old_base: raw_capture.slab.old_base,
            slab_size: raw_capture.slab.content.len(),
        },
    )?;
    Ok((slab_offset, slab_slice))
}

fn raw_capture_drift_error(
    child_kind: RawChildKind,
    child_old_base: u64,
    child_size: usize,
    slab_old_base: u64,
    slab_size: usize,
    slab_offset: usize,
    slab_slice: &[u8],
    raw_child: &[u8],
) -> OverlayError {
    let first_mismatch_offset = slab_slice
        .iter()
        .zip(raw_child.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| slab_slice.len().min(raw_child.len()));
    OverlayError::RawCaptureDrift {
        child_kind,
        child_old_base,
        child_size,
        slab_old_base,
        slab_size,
        slab_offset,
        first_mismatch_offset,
        raw_child_digest: sha256_hex(raw_child),
        raw_slab_slice_digest: sha256_hex(slab_slice),
    }
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
    // The global round transform list. NOT attributed to individual children:
    // per-child provenance comes from `HeapGlobalSnapshot.transform_ids`
    // (populated by diffing content across each transform). Retained for API
    // compatibility / round documentation.
    _transform_ids: &[&'static str],
) -> Result<
    (
        HeapSlab,
        Vec<TransformedRegionOverlay>,
        Vec<CaptureDriftRun>,
    ),
    OverlayError,
> {
    let slab = &raw_capture.slab;
    let mut backing = slab.content.clone();

    // GTO R0-F.1: index raw children by (old_base, kind) preserving ALL entries.
    // A silent BTreeMap collect would drop duplicates (last-write-wins). The
    // lookup below reconciles duplicates: identical entries dedup deterministically,
    // distinct entries with a provable slab-coherent authority use that one, and
    // otherwise fail closed (no silent overwrite).
    let mut raw_by_key: std::collections::BTreeMap<(u64, RawChildKind), Vec<&RawChild>> =
        std::collections::BTreeMap::new();
    for c in &raw_capture.children {
        raw_by_key.entry((c.old_base, c.kind)).or_default().push(c);
    }

    // Collect transformed children (heap-global + container) with provenance.
    // SyntheticDerived children (created by an offline transform, no raw
    // source) are carried but excluded from raw-coherence; UnknownSynthetic
    // fails closed. See GTO Core Recovery R0-D.
    let mut transformed: Vec<(
        u64,
        usize,
        Vec<u8>,
        RawChildKind,
        RegionProvenance,
        Vec<String>,
        super::heap_global_snapshot::CaptureExtentKind,
        String,
    )> = Vec::new();
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
            g.transform_ids.clone(),
            g.extent_kind,
            g.extent_evidence.capture_id.clone(),
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
            Vec::new(),
            super::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            String::new(),
        ));
    }
    // Deterministic order by (old_base, kind).
    transformed.sort_by_key(|(base, _, _, kind, _, _, _, _)| (*base, *kind as u8));

    let mut overlays: Vec<TransformedRegionOverlay> = Vec::new();
    // GTO R0-G: capture-drift runs ledger (probe/interior non-write drift resolved
    // to slab authority; strict extents rejected).
    let mut drift_runs: Vec<CaptureDriftRun> = Vec::new();
    // GTO R0-F: track resolved writes at slab-byte granularity for conflict
    // detection. Only differing transformed bytes are writes.
    let mut resolved_writes: std::collections::BTreeMap<usize, ResolvedWrite> =
        std::collections::BTreeMap::new();

    for (
        child_base,
        child_size,
        transformed_bytes,
        kind,
        provenance,
        child_transform_ids,
        extent_kind,
        capture_id,
    ) in &transformed
    {
        let child_base = *child_base;
        let child_size = *child_size;
        let kind = *kind;
        let transformed_bytes = transformed_bytes.clone();
        let child_transform_ids = child_transform_ids.clone();
        let extent_kind = *extent_kind;
        let capture_id = capture_id.clone();
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
        let Some(raws) = raw_by_key.get(&(child_base, kind)) else {
            return Err(OverlayError::RawChildMissing {
                child_old_base: child_base,
                child_kind: kind,
            });
        };
        // GTO R0-F.1: reconcile multiple raw children at the same (base, kind).
        // Identical entries dedup deterministically; if more than one distinct
        // raw snapshot remains, prefer the one coherent with the raw slab slice,
        // else fail closed (ambiguous raw duplicate, never silently overwritten).
        let raw = if raws.len() == 1 {
            raws[0]
        } else {
            // Slab offset for coherence check.
            let so = child_base
                .checked_sub(slab.old_base)
                .and_then(|v| usize::try_from(v).ok());
            let distinct: Vec<&&RawChild> = raws
                .iter()
                .filter(|r| {
                    so.and_then(|s| {
                        slab.content
                            .get(s..s + r.raw_bytes.len())
                            .map(|slice| slice == r.raw_bytes.as_slice())
                    })
                    .unwrap_or(false)
                })
                .collect();
            if distinct.len() == 1 {
                distinct[0]
            } else if distinct.len() > 1 {
                // Multiple distinct raw children both coherent with the slab:
                // ambiguous — the raw slab cannot distinguish them.
                return Err(OverlayError::RawChildMissing {
                    child_old_base: child_base,
                    child_kind: kind,
                });
            } else {
                // None coherent; dedup identical bytes only.
                let first = raws[0];
                if raws.iter().all(|r| r.raw_bytes == first.raw_bytes) {
                    first
                } else {
                    return Err(OverlayError::RawChildMissing {
                        child_old_base: child_base,
                        child_kind: kind,
                    });
                }
            }
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
        // GTO R0-G three-way reconciliation: C = raw child capture (t1), S = raw
        // slab slice (t2, authoritative), T = transformed child.
        //   - strict extents (ObservedAllocation / BackingObject / Container):
        //     full-range raw equality required (C == S); any drift fails closed.
        //   - probe/interior views (ProbeWindow / InteriorSubview): write-set-scoped
        //     preimage coherence. Only transformed write bytes need C[i]==S[i];
        //     non-write drift is accepted (B[i]=S[i], slab authority) and recorded.
        let raw_slab_slice = &slab.content[slab_offset_us..child_end];
        use super::heap_global_snapshot::CaptureExtentKind as CEK;
        let is_strict_extent = matches!(extent_kind, CEK::ObservedAllocation | CEK::BackingObject)
            || kind == RawChildKind::Container;
        if is_strict_extent {
            // Strict: full-range coherence still required.
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
        // GTO R0-G: for probe/interior views, verify transform-write preimages
        // are clean (C[i]==S[i]) and accept non-write drift (slab authority).
        if !is_strict_extent {
            // A transform write whose preimage drifted cannot safely overwrite S.
            for &(so, _, ref bytes) in &write_runs {
                for (k, _) in bytes.iter().enumerate() {
                    let abs = so + k;
                    let child_byte_offset = abs - slab_offset_us;
                    let c_byte = raw_child_bytes[child_byte_offset];
                    let s_byte = slab.content[abs];
                    if c_byte != s_byte {
                        return Err(OverlayError::TransformPreimageDrift {
                            child_old_base: child_base,
                            child_size,
                            slab_offset: abs,
                            child_byte_offset,
                            c_byte,
                            s_byte,
                            t_byte: transformed_bytes[child_byte_offset],
                            transform_ids: child_transform_ids.clone(),
                        });
                    }
                }
            }
            // Non-write drift runs (C[i]!=S[i] where T[i]==C[i]) are accepted:
            // the authoritative slab byte wins (B[i]=S[i]); record a drift run.
            let mut run_start: Option<usize> = None;
            let mut flush = |start: usize, end: usize, drift_runs: &mut Vec<CaptureDriftRun>| {
                let child_off = start - slab_offset_us;
                let len = end - start;
                drift_runs.push(CaptureDriftRun {
                    child_capture_id: capture_id.clone(),
                    child_old_base: child_base,
                    child_offset: child_off,
                    slab_offset: start,
                    length: len,
                    child_digest: sha256_hex(&raw_child_bytes[child_off..child_off + len]),
                    slab_digest: sha256_hex(&slab.content[start..end]),
                    intersects_transform_write: false,
                    resolution: CaptureDriftResolution::NonWriteSlabAuthoritative,
                });
            };
            for i in 0..raw_len {
                let so = slab_offset_us + i;
                let drifted = raw_child_bytes[i] != slab.content[so]
                    && transformed_bytes[i] == raw_child_bytes[i];
                if drifted {
                    if run_start.is_none() {
                        run_start = Some(so);
                    }
                } else if let Some(start) = run_start.take() {
                    flush(start, so, &mut drift_runs);
                }
            }
            if let Some(start) = run_start.take() {
                flush(start, slab_offset_us + raw_len, &mut drift_runs);
            }
        }
        // GTO R0-F.1: use per-child transform provenance (which transforms
        // actually modified this child), not the global round list. The global
        // `transform_ids` is no longer attributed to every child.
        // Resolve each write byte against already-applied writes.
        let mut contributed_new_write = false;
        let mut all_shared_with_same_base = true;
        let mut any_shared_write = false;
        for &(so, _, ref bytes) in &write_runs {
            for (k, &val) in bytes.iter().enumerate() {
                let abs = so + k;
                let child_byte_offset = abs - slab_offset_us; // this child's byte offset
                match resolved_writes.get(&abs) {
                    None => {
                        resolved_writes.insert(
                            abs,
                            ResolvedWrite {
                                value: val,
                                child_old_base: child_base,
                                child_size,
                                child_byte_offset,
                                transform_ids: child_transform_ids.clone(),
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
                        // GTO R0-F.1: report the ACTUAL existing peer size (not
                        // the current child's) and the authoritative raw slab
                        // byte at the ABSOLUTE slab offset (not a run-relative
                        // index into the current child).
                        let a_slab_off = (existing.child_old_base - slab.old_base) as usize;
                        let a_child_byte_offset = abs.saturating_sub(a_slab_off);
                        return Err(OverlayError::TransformWriteConflict {
                            a_child_old_base: existing.child_old_base,
                            a_size: existing.child_size,
                            a_child_byte_offset,
                            b_child_old_base: child_base,
                            b_size: child_size,
                            b_child_byte_offset: child_byte_offset,
                            first_mismatch_slab_offset: abs,
                            before_byte: slab.content[abs],
                            a_after_byte: existing.value,
                            b_after_byte: val,
                            a_transform_ids: existing.transform_ids.clone(),
                            b_transform_ids: child_transform_ids.clone(),
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
            .find(|(ob, osz, _, ok, _, _, _, _)| {
                // exclude this child itself
                !(*ok == kind && *ob == child_base)
                    && *ob <= child_base
                    && child_base + child_size as u64 <= ob.saturating_add(*osz as u64)
            })
            .map(|(ob, _, _, _, _, _, _, _)| *ob);
        overlays.push(TransformedRegionOverlay {
            child_kind: kind,
            child_old_base: child_base,
            child_size,
            slab_offset: slab_offset_us,
            raw_child_digest: sha256_hex(raw_child_bytes),
            raw_slab_slice_digest: sha256_hex(raw_slab_slice),
            transformed_child_digest: t_digest,
            transform_ids: child_transform_ids,
            overlay_applied: true,
            contained_in_old_base: contained_in,
        });
    }

    // Deterministic sort of the drift ledger.
    drift_runs.sort_by_key(|d| (d.child_old_base, d.slab_offset, d.child_offset));
    // Deterministic overlay sort.
    overlays.sort_by_key(|o| (o.child_old_base, o.slab_offset, o.child_size));
    Ok((
        HeapSlab {
            old_base: slab.old_base,
            content: backing,
        },
        overlays,
        drift_runs,
    ))
}

/// Route Q R0 Q0-C: three-way overlay over the authoritative transform preimage.
///
/// This is the Q0-C overlay state machine described by the work order §5. Unlike
/// [`build_patched_backing_slab`] (which computes the probe/interior write-set
/// against the child capture `C`), this entry point derives the write-set from
/// the **actual transform input preimage** `P`, which Q0-A bound to each child:
///
/// ```text
/// Strict (ChildCapture binding):   P = C, require C == S (else RawCaptureDrift)
///                                  write-set = { i | T[i] != P[i] }
/// Probe/Interior (SlabSlice):      P = S, verify transform_input_digest == sha256(S)
///                                  capture drift = { i | C[i] != S[i] }
///                                  write-set = { i | T[i] != P[i] } = { i | T[i] != S[i] }
///                                  backing starts from S
/// ```
///
/// A probe/interior write is only applied when the binding proves the transform
/// input was the authoritative slab slice (transform_input_digest == sha256(S)),
/// recorded as [`CaptureDriftResolution::TransformReplayedOnAuthoritativePreimage`].
/// If a probe/interior child has a write that cannot be proven to derive from
/// `S`, it fails closed with [`OverlayError::TransformPreimageDrift`].
pub fn build_patched_backing_slab_q0c(
    raw_capture: &RawSlabCapture,
    transformed_globals: &[HeapGlobalSnapshot],
    transformed_containers: &[ContainerSnapshot],
    bindings: &[TransformPreimageBinding],
) -> Result<
    (
        HeapSlab,
        Vec<TransformedRegionOverlay>,
        Vec<CaptureDriftRun>,
    ),
    OverlayError,
> {
    use super::heap_global_snapshot::CaptureExtentKind as CEK;
    let slab = &raw_capture.slab;
    let mut backing = slab.content.clone();

    // Index raw children by (old_base, kind) preserving all entries (dedup later).
    let mut raw_by_key: std::collections::BTreeMap<(u64, RawChildKind), Vec<&RawChild>> =
        std::collections::BTreeMap::new();
    for c in &raw_capture.children {
        raw_by_key.entry((c.old_base, c.kind)).or_default().push(c);
    }

    // Collect transformed children (heap-global + container) with provenance.
    let mut transformed: Vec<(
        u64,
        usize,
        Vec<u8>,
        RawChildKind,
        RegionProvenance,
        Vec<String>,
        super::heap_global_snapshot::CaptureExtentKind,
        String,
    )> = Vec::new();
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
            g.transform_ids.clone(),
            g.extent_kind,
            g.extent_evidence.capture_id.clone(),
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
            Vec::new(),
            super::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            String::new(),
        ));
    }
    // Deterministic order by (old_base, kind).
    transformed.sort_by_key(|(base, _, _, kind, _, _, _, _)| (*base, *kind as u8));

    let mut overlays: Vec<TransformedRegionOverlay> = Vec::new();
    let mut drift_runs: Vec<CaptureDriftRun> = Vec::new();
    let mut resolved_writes: std::collections::BTreeMap<usize, ResolvedWrite> =
        std::collections::BTreeMap::new();

    for (
        child_base,
        child_size,
        transformed_bytes,
        kind,
        provenance,
        child_transform_ids,
        extent_kind,
        capture_id,
    ) in &transformed
    {
        let child_base = *child_base;
        let child_size = *child_size;
        let kind = *kind;
        let transformed_bytes = transformed_bytes.clone();
        let child_transform_ids = child_transform_ids.clone();
        let extent_kind = *extent_kind;
        let capture_id = capture_id.clone();

        if let RegionProvenance::UnknownSynthetic = &provenance {
            return Err(OverlayError::RawChildMissing {
                child_old_base: child_base,
                child_kind: kind,
            });
        }
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

        let Some(raws) = raw_by_key.get(&(child_base, kind)) else {
            return Err(OverlayError::RawChildMissing {
                child_old_base: child_base,
                child_kind: kind,
            });
        };
        // Reconcile duplicate raw children (same policy as build_patched_backing_slab).
        let raw = if raws.len() == 1 {
            raws[0]
        } else {
            let so = child_base
                .checked_sub(slab.old_base)
                .and_then(|v| usize::try_from(v).ok());
            let distinct: Vec<&&RawChild> = raws
                .iter()
                .filter(|r| {
                    so.and_then(|s| {
                        slab.content
                            .get(s..s + r.raw_bytes.len())
                            .map(|slice| slice == r.raw_bytes.as_slice())
                    })
                    .unwrap_or(false)
                })
                .collect();
            if distinct.len() == 1 {
                distinct[0]
            } else if distinct.len() > 1 {
                return Err(OverlayError::RawChildMissing {
                    child_old_base: child_base,
                    child_kind: kind,
                });
            } else {
                let first = raws[0];
                if raws.iter().all(|r| r.raw_bytes == first.raw_bytes) {
                    first
                } else {
                    return Err(OverlayError::RawChildMissing {
                        child_old_base: child_base,
                        child_kind: kind,
                    });
                }
            }
        };
        // Slab offset (checked).
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
        let raw_slab_slice = &slab.content[slab_offset_us..child_end];

        // ---- Route Q R0 Q0-C: determine the transform input preimage P from the
        // authoritative binding. ----
        // Find the binding for this child (by old_base, kind, capture_id).
        let binding = bindings.iter().find(|b| {
            b.child_old_base == child_base
                && b.child_kind == kind
                && (b.capture_id.is_empty() || b.capture_id == capture_id)
        });

        // Determine P and whether this is a strict (ChildCapture) or slab-seeded
        // (AuthoritativeSlabSlice) transform basis.
        let (p_bytes, basis) = match binding {
            Some(b) if b.basis == TransformPreimageBasis::AuthoritativeSlabSlice => {
                // Probe/interior: transform input must equal the authoritative
                // slab slice (ledger proof via digest). Verify before trusting T.
                let s_digest = sha256_hex(raw_slab_slice);
                if b.transform_input_digest != s_digest {
                    // Transform claims slab basis but digest disagrees: fail closed.
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: 0,
                        c_byte: raw_child_bytes[0],
                        s_byte: raw_slab_slice[0],
                        t_byte: transformed_bytes[0],
                        transform_ids: child_transform_ids.clone(),
                    });
                }
                (
                    raw_slab_slice.to_vec(),
                    TransformPreimageBasis::AuthoritativeSlabSlice,
                )
            }
            Some(b) if b.basis == TransformPreimageBasis::ChildCapture => {
                // Strict: require full-range C == S.
                if raw_slab_slice != raw_child_bytes {
                    let first_mismatch = raw_slab_slice
                        .iter()
                        .zip(raw_child_bytes.iter())
                        .position(|(a, c)| a != c)
                        .unwrap_or_else(|| raw_slab_slice.len().min(raw_child_bytes.len()));
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
                (
                    raw_child_bytes.to_vec(),
                    TransformPreimageBasis::ChildCapture,
                )
            }
            // No binding: a child has no authoritative preimage evidence. For
            // strict extents fall back to the legacy coherence (require C==S);
            // for probe/interior this is a Q0-C failure (must prove P==S).
            None => {
                let _ = child_base;
                if matches!(extent_kind, CEK::ObservedAllocation | CEK::BackingObject)
                    || kind == RawChildKind::Container
                {
                    if raw_slab_slice != raw_child_bytes {
                        let first_mismatch = raw_slab_slice
                            .iter()
                            .zip(raw_child_bytes.iter())
                            .position(|(a, c)| a != c)
                            .unwrap_or_else(|| raw_slab_slice.len().min(raw_child_bytes.len()));
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
                    (
                        raw_child_bytes.to_vec(),
                        TransformPreimageBasis::ChildCapture,
                    )
                } else {
                    // Probe/interior without a binding: cannot prove P==S.
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: 0,
                        c_byte: raw_child_bytes[0],
                        s_byte: raw_slab_slice[0],
                        t_byte: transformed_bytes[0],
                        transform_ids: child_transform_ids.clone(),
                    });
                }
            }
            // Unreachable in practice: TransformPreimageBasis has exactly two
            // variants. Fail closed if a future variant slips through without a
            // policy.
            Some(_) => {
                return Err(OverlayError::TransformPreimageDrift {
                    child_old_base: child_base,
                    child_size,
                    slab_offset: slab_offset_us,
                    child_byte_offset: 0,
                    c_byte: raw_child_bytes[0],
                    s_byte: raw_slab_slice[0],
                    t_byte: transformed_bytes[0],
                    transform_ids: child_transform_ids.clone(),
                });
            }
        };
        let is_slab_seeded = basis == TransformPreimageBasis::AuthoritativeSlabSlice;

        // ---- Compute the write-set against P (the transform input preimage).
        let t_digest = sha256_hex(&transformed_bytes);
        let p_digest = sha256_hex(&p_bytes);
        let p_len = p_bytes.len().min(child_size);
        let mut write_runs: Vec<(usize, usize, Vec<u8>)> = Vec::new(); // (slab_off, len, bytes)
        {
            let mut run_start: Option<(usize, Vec<u8>)> = None;
            for i in 0..p_len {
                let so = slab_offset_us + i;
                if transformed_bytes[i] != p_bytes[i] {
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

        // ---- Route Q R0 Q0-C: probe/interior non-write capture drift + the
        // TransformReplayedOnAuthoritativePreimage resolution for applied writes.
        if is_slab_seeded {
            // Capture drift: C[i] != S[i] where T[i] == S[i] (transform did not
            // change that byte). Recorded as NonWriteSlabAuthoritative; the slab
            // byte wins and is the backing seed.
            let mut run_start: Option<usize> = None;
            let mut flush = |start: usize, end: usize, drift_runs: &mut Vec<CaptureDriftRun>| {
                let child_off = start - slab_offset_us;
                let len = end - start;
                drift_runs.push(CaptureDriftRun {
                    child_capture_id: capture_id.clone(),
                    child_old_base: child_base,
                    child_offset: child_off,
                    slab_offset: start,
                    length: len,
                    child_digest: sha256_hex(&raw_child_bytes[child_off..child_off + len]),
                    slab_digest: sha256_hex(&slab.content[start..end]),
                    intersects_transform_write: false,
                    resolution: CaptureDriftResolution::NonWriteSlabAuthoritative,
                });
            };
            for i in 0..p_len {
                let so = slab_offset_us + i;
                let drifted = raw_child_bytes[i] != slab.content[so]
                    && transformed_bytes[i] == slab.content[so];
                if drifted {
                    if run_start.is_none() {
                        run_start = Some(so);
                    }
                } else if let Some(start) = run_start.take() {
                    flush(start, so, &mut drift_runs);
                }
            }
            if let Some(start) = run_start.take() {
                flush(start, slab_offset_us + p_len, &mut drift_runs);
            }
            // The applied writes (T != S) are proven to derive from the slab
            // slice (binding.transform_input_digest == sha256(S)). Record each
            // as TransformReplayedOnAuthoritativePreimage. Any write here is
            // legitimate because P == S by the binding digest proof.
            let mut replay_runs: Vec<CaptureDriftRun> = Vec::new();
            for &(so, len, ref bytes) in &write_runs {
                let child_off = so - slab_offset_us;
                let dr = CaptureDriftRun {
                    child_capture_id: capture_id.clone(),
                    child_old_base: child_base,
                    child_offset: child_off,
                    slab_offset: so,
                    length: len,
                    child_digest: sha256_hex(&raw_child_bytes[child_off..child_off + len]),
                    slab_digest: sha256_hex(&slab.content[so..so + len]),
                    intersects_transform_write: true,
                    resolution: CaptureDriftResolution::TransformReplayedOnAuthoritativePreimage,
                };
                let _ = bytes;
                replay_runs.push(dr);
            }
            drift_runs.extend(replay_runs);
        }

        // ---- Resolve write-set against already-applied writes (conflict detection).
        let mut contributed_new_write = false;
        let mut all_shared_with_same_base = true;
        let mut any_shared_write = false;
        for &(so, _, ref bytes) in &write_runs {
            for (k, &val) in bytes.iter().enumerate() {
                let abs = so + k;
                let child_byte_offset = abs - slab_offset_us;
                match resolved_writes.get(&abs) {
                    None => {
                        resolved_writes.insert(
                            abs,
                            ResolvedWrite {
                                value: val,
                                child_old_base: child_base,
                                child_size,
                                child_byte_offset,
                                transform_ids: child_transform_ids.clone(),
                            },
                        );
                        contributed_new_write = true;
                    }
                    Some(existing) if existing.value == val => {
                        any_shared_write = true;
                        if existing.child_old_base != child_base {
                            all_shared_with_same_base = false;
                        }
                    }
                    Some(existing) => {
                        let a_slab_off = (existing.child_old_base - slab.old_base) as usize;
                        let a_child_byte_offset = abs.saturating_sub(a_slab_off);
                        return Err(OverlayError::TransformWriteConflict {
                            a_child_old_base: existing.child_old_base,
                            a_size: existing.child_size,
                            a_child_byte_offset,
                            b_child_old_base: child_base,
                            b_size: child_size,
                            b_child_byte_offset: child_byte_offset,
                            first_mismatch_slab_offset: abs,
                            before_byte: slab.content[abs],
                            a_after_byte: existing.value,
                            b_after_byte: val,
                            a_transform_ids: existing.transform_ids.clone(),
                            b_transform_ids: child_transform_ids.clone(),
                        });
                    }
                }
            }
        }
        // Apply the write-set to the patched backing slab.
        for &(so, len, ref bytes) in &write_runs {
            backing[so..so + len].copy_from_slice(bytes);
        }
        // Dedup true duplicates (same object captured twice).
        let is_true_duplicate = !write_runs.is_empty()
            && !contributed_new_write
            && any_shared_write
            && all_shared_with_same_base;
        if is_true_duplicate {
            continue;
        }
        // Containment for the ledger.
        let contained_in = transformed
            .iter()
            .find(|(ob, osz, _, ok, _, _, _, _)| {
                !(*ok == kind && *ob == child_base)
                    && *ob <= child_base
                    && child_base + child_size as u64 <= ob.saturating_add(*osz as u64)
            })
            .map(|(ob, _, _, _, _, _, _, _)| *ob);
        let _ = p_digest;
        overlays.push(TransformedRegionOverlay {
            child_kind: kind,
            child_old_base: child_base,
            child_size,
            slab_offset: slab_offset_us,
            raw_child_digest: sha256_hex(raw_child_bytes),
            raw_slab_slice_digest: sha256_hex(raw_slab_slice),
            transformed_child_digest: t_digest,
            transform_ids: child_transform_ids,
            overlay_applied: true,
            contained_in_old_base: contained_in,
        });
    }

    // Deterministic sort of the drift ledger.
    drift_runs.sort_by_key(|d| (d.child_old_base, d.slab_offset, d.child_offset));
    // Deterministic overlay sort.
    overlays.sort_by_key(|o| (o.child_old_base, o.slab_offset, o.child_size));
    Ok((
        HeapSlab {
            old_base: slab.old_base,
            content: backing,
        },
        overlays,
        drift_runs,
    ))
}

#[cfg(test)]
mod tests {
    use super::super::heap_global_snapshot::{CaptureExtentEvidence, CaptureExtentKind};
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
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
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
            extent_evidence: CaptureExtentEvidence::default(),
            transform_ids: Vec::new(),
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

    /// Test helper: a RawChild with default (probe-window, no-parent) provenance.
    fn raw_child(old_base: u64, size: usize, raw_bytes: Vec<u8>, kind: RawChildKind) -> RawChild {
        RawChild {
            old_base,
            size,
            raw_bytes,
            kind,
            capture_id: String::new(),
            capture_path: super::super::heap_global_snapshot::CapturePath::MainSlot,
            extent_kind: super::super::heap_global_snapshot::CaptureExtentKind::ProbeWindow,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let transformed = global(ROUTEK_CHILD_BASE, raw.clone(), false);
        let (patched, overlays, _) =
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let transformed_bytes = b"REPAIRED-child-xxx".to_vec();
        let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
        let (patched, _, _) =
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let mut transformed = global(ROUTEK_CHILD_BASE, raw.clone(), false);
        // Strict ObservedAllocation extent: full-range drift must be rejected.
        transformed.extent_kind =
            super::super::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let transformed_bytes = repaint(&raw);
        let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
        let (patched, _, _) =
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                0x1a,
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let transformed_bytes = vec![0x42u8; 0x1a];
        let mut transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
        transformed.transform_ids = vec!["repair_gscript_window_strings".to_string()];
        let (patched, overlays, _) = build_patched_backing_slab(
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let repaired = b"NewClassName".to_vec();
        let mut transformed = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
        transformed.transform_ids = vec!["repair_gscript_window_strings".to_string()];
        let (patched, o, _) = build_patched_backing_slab(
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                16,
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let scrubbed = vec![0u8; 16];
        let mut transformed = global(ROUTEK_CHILD_BASE, scrubbed.clone(), false);
        transformed.transform_ids = vec!["scrub_uncaptured_heap_pointers".to_string()];
        let (patched, o, _) = build_patched_backing_slab(
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                24,
                raw.clone(),
                RawChildKind::Container,
            )],
        };
        let scrubbed = vec![0u8; 24];
        let transformed = container(ROUTEK_CHILD_BASE, ROUTEK_CHILD_BASE + 24, scrubbed.clone());
        let (patched, o, _) =
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
                raw_child(
                    ROUTEK_CHILD_BASE,
                    raw_a.len(),
                    raw_a.clone(),
                    RawChildKind::HeapGlobal,
                ),
                raw_child(
                    ROUTEK_SLAB_BASE + 0x3000,
                    raw_b.len(),
                    raw_b.clone(),
                    RawChildKind::HeapGlobal,
                ),
            ],
        };
        let ga = global(ROUTEK_CHILD_BASE, repaint(&raw_a), false);
        let gb = global(ROUTEK_SLAB_BASE + 0x3000, repaint(&raw_b), false);
        let (_, overlays, _) =
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let repaired = repaint(&raw);
        let ga = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
        let gb = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
        let (_, overlays, _) =
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
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
                raw_child(ROUTEK_CHILD_BASE, 32, raw_a, RawChildKind::HeapGlobal),
                raw_child(ROUTEK_CHILD_BASE + 16, 32, raw_b, RawChildKind::HeapGlobal),
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
            children: vec![raw_child(0x2000, 8, vec![0u8; 8], RawChildKind::HeapGlobal)],
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
        let (_, overlays, _) =
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
        let (_, overlays, _) = build_patched_backing_slab(&raw_capture, &[h], &[], &["t"]).unwrap();
        assert!(overlays.is_empty());
    }

    #[test]
    fn r0c1_nobypass_off_path_unchanged() {
        let raw_capture = RawSlabCapture {
            slab: slab(0x1000, vec![0u8; 0x100]),
            children: vec![],
        };
        let (_, overlays, _) = build_patched_backing_slab(&raw_capture, &[], &[], &["t"]).unwrap();
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
                raw_child(
                    ROUTEK_SLAB_BASE + 0x2000,
                    3,
                    raw_b,
                    RawChildKind::HeapGlobal,
                ),
                raw_child(
                    ROUTEK_SLAB_BASE + 0x1000,
                    3,
                    raw_a,
                    RawChildKind::HeapGlobal,
                ),
            ],
        };
        let ga = global(ROUTEK_SLAB_BASE + 0x1000, b"XXX".to_vec(), false);
        let gb = global(ROUTEK_SLAB_BASE + 0x2000, b"YYY".to_vec(), false);
        let (_, o1, _) =
            build_patched_backing_slab(&raw_capture, &[gb.clone(), ga.clone()], &[], &["t"])
                .unwrap();
        let (_, o2, _) = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        let transformed_bytes = repaint(&raw);
        let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
        let (patched, _, _) =
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw,
                RawChildKind::HeapGlobal,
            )],
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
            children: vec![raw_child(
                ROUTEK_CHILD_BASE,
                raw.len(),
                raw.clone(),
                RawChildKind::HeapGlobal,
            )],
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
            children: vec![raw_child(
                slab_base + 0x3000,
                real_child_bytes.len(),
                real_child_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        // Transformed: one in-slab raw child (unchanged) + one synthetic child
        // at 0x200000 (outside the slab, SyntheticDerived provenance).
        let real = global(slab_base + 0x3000, real_child_bytes.clone(), false);
        let synth = synthetic(
            synthetic_base,
            b"NewClassName".to_vec(),
            "repair_gscript_window_strings",
        );
        let (patched, overlays, _) = build_patched_backing_slab(
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
                raw_child(
                    backing_base,
                    backing_sz,
                    {
                        // raw backing: zeros with [0xEE;0x400] at subview offset
                        let mut b = vec![0u8; backing_sz];
                        b[subview_in_backing..subview_in_backing + subview_sz].fill(0xEE);
                        b
                    },
                    RawChildKind::HeapGlobal,
                ),
                raw_child(
                    subview_base,
                    subview_sz,
                    vec![0xEEu8; subview_sz],
                    RawChildKind::HeapGlobal,
                ),
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
        let (patched, overlays, _) = build_patched_backing_slab(
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
                raw_child(a_base, sz, vec![0xAA; sz], RawChildKind::HeapGlobal),
                raw_child(b_base, sz, vec![0xBB; sz], RawChildKind::HeapGlobal),
            ],
        };
        let mut ga = global(a_base, vec![0xAA; sz], false);
        let mut gb = global(b_base, vec![0xBB; sz], false);
        // Strict ObservedAllocation extents: an unrelated partial overlap with
        // conflicting bytes must still fail closed (the two children cannot both
        // be full-range coherent over the shared slab region).
        ga.extent_kind = super::super::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
        gb.extent_kind = super::super::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
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
                raw_child(
                    ROUTEN_A_BASE,
                    ROUTEN_VIEW_SZ,
                    vec![fill; ROUTEN_VIEW_SZ],
                    RawChildKind::HeapGlobal,
                ),
                raw_child(
                    ROUTEN_B_BASE,
                    ROUTEN_VIEW_SZ,
                    vec![fill; ROUTEN_VIEW_SZ],
                    RawChildKind::HeapGlobal,
                ),
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
        let (patched, overlays, _) = build_patched_backing_slab(
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
        let (patched, _, _) =
            build_patched_backing_slab(&raw_capture, &[a, b], &[], &["t"]).unwrap();
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
        let (patched, overlays, _) = build_patched_backing_slab(
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
        let (p1, _, _) =
            build_patched_backing_slab(&raw_capture, &[g_a.clone(), g_b.clone()], &[], &["t"])
                .unwrap();
        let (p2, _, _) =
            build_patched_backing_slab(&raw_capture, &[g_b, g_a], &[], &["t"]).unwrap();
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

    // GTO R0-F.1: TransformWriteConflict reports the ACTUAL existing peer size
    // (not the current child's size) and the authoritative absolute slab byte.
    #[test]
    fn r0f1_conflict_reports_existing_peer_size_and_absolute_slab_byte() {
        let raw_capture = route_n_raw_capture(0xAA);
        let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
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
                a_size,
                b_size,
                before_byte,
                a_child_byte_offset,
                b_child_byte_offset,
                ..
            } => {
                // a is the earlier-applied peer (0x96bb80), size 0x400.
                assert_eq!(a_size, ROUTEN_VIEW_SZ);
                assert_eq!(b_size, ROUTEN_VIEW_SZ);
                // before_byte is the absolute slab byte (0xAA), not a run index.
                assert_eq!(before_byte, 0xAA);
                // a's child-relative offset of the conflict = 0x50.
                assert_eq!(a_child_byte_offset, 0x50);
                // b's child-relative offset = 0x00.
                assert_eq!(b_child_byte_offset, 0x00);
                let _ = a_off;
            }
            other => panic!("expected TransformWriteConflict, got {other:?}"),
        }
    }

    // GTO R0-F.1: per-child transform provenance — a child modified by a
    // transform carries that transform id, and an unchanged child carries none.
    #[test]
    fn r0f1_per_child_transform_ids_not_global_and_unchanged_has_none() {
        // A modified child: its transform_ids = ["t1"] (not the global list).
        let raw_capture = route_n_raw_capture(0xAA);
        let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
        a[0x10] = 0xBB;
        let mut ga = global(ROUTEN_A_BASE, a, false);
        ga.transform_ids = vec!["t1".to_string()];
        // An unchanged child: content == raw, no transform_ids.
        let gb = global(ROUTEN_B_BASE, vec![0xAAu8; ROUTEN_VIEW_SZ], false);
        let (_, overlays, _) =
            build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t1", "t2", "t3"]).unwrap();
        let overlay_a = overlays
            .iter()
            .find(|o| o.child_old_base == ROUTEN_A_BASE)
            .unwrap();
        // The modified child's overlay carries only "t1", not the global 3.
        assert_eq!(overlay_a.transform_ids, vec!["t1".to_string()]);
        let overlay_b = overlays
            .iter()
            .find(|o| o.child_old_base == ROUTEN_B_BASE)
            .unwrap();
        // The unchanged child carries no transform writer (empty list).
        assert!(overlay_b.transform_ids.is_empty());
    }

    // ---------- GTO Core Recovery R0-G tests ----------

    use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
    use super::super::heap_global_snapshot::CapturePath;

    /// Route O R1 exact drift geometry (recorded live): child 0x9f93e8 captured
    /// at 0x70 bytes inside slab [0x9bf000,+0x2db3750), first mismatch at 0x28.
    const R0G_SLAB_BASE: u64 = 0x9bf000;
    const R0G_CHILD_BASE: u64 = 0x9f93e8;
    const R0G_CHILD_SIZE: usize = 0x70;
    const R0G_CHILD_OFF: usize = 0x3a3e8;
    const R0G_FIRST_MISMATCH: usize = 0x28;

    /// A raw child in Route O geometry with the given stable prefix length.
    fn r0g_raw_child_at(base: u64, prefix_match: usize, extent: CEK, capture_id: &str) -> RawChild {
        let mut bytes = vec![0xAAu8; R0G_CHILD_SIZE];
        // bytes[0..prefix_match] match the slab; bytes[prefix_match..] drift.
        for i in prefix_match..R0G_CHILD_SIZE {
            bytes[i] = 0xBB; // drifted (child != slab)
        }
        let mut c = raw_child(base, R0G_CHILD_SIZE, bytes, RawChildKind::HeapGlobal);
        c.extent_kind = extent;
        c.capture_id = capture_id.to_string();
        c
    }

    /// A raw child at the Route O child base.
    fn r0g_raw_child(prefix_match: usize, extent: CEK, capture_id: &str) -> RawChild {
        r0g_raw_child_at(R0G_CHILD_BASE, prefix_match, extent, capture_id)
    }

    /// A slab whose content at the child offset is all 0xAA (so only bytes past
    /// `prefix_match` drift in the child).
    fn r0g_slab() -> HeapSlab {
        let mut content = vec![0u8; R0G_CHILD_OFF + R0G_CHILD_SIZE];
        for i in 0..R0G_CHILD_SIZE {
            content[R0G_CHILD_OFF + i] = 0xAA;
        }
        HeapSlab {
            old_base: R0G_SLAB_BASE,
            content,
        }
    }

    /// A transformed child in Route O geometry; if `write_off < prefix_match` the
    /// transform writes into the stable prefix (clean preimage), else into the
    /// drifted region.
    fn r0g_transformed(
        prefix_match: usize,
        write_off: usize,
        write_val: u8,
        extent: CEK,
    ) -> HeapGlobalSnapshot {
        let mut content = vec![0xAAu8; R0G_CHILD_SIZE];
        for i in prefix_match..R0G_CHILD_SIZE {
            content[i] = 0xBB; // raw-child drift baseline
        }
        // Apply the transform write (over the raw-child value at that offset).
        content[write_off] = write_val;
        let mut g = global(R0G_CHILD_BASE, content, false);
        g.extent_kind = extent;
        g
    }

    #[test]
    fn route_q_r0_probe_transform_input_is_seeded_from_authoritative_slab() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::InteriorSubview,
                "route-q-probe",
            )],
        };
        let mut global = r0g_transformed(
            R0G_FIRST_MISMATCH,
            R0G_FIRST_MISMATCH,
            0xBB,
            CEK::InteriorSubview,
        );
        global.extent_evidence.capture_id = "route-q-probe".into();
        let mut globals = vec![global];
        let mut containers = Vec::new();

        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();

        assert_eq!(
            globals[0].content,
            vec![0xAA; R0G_CHILD_SIZE],
            "probe/interior transform input must be the authoritative slab slice"
        );
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].basis,
            TransformPreimageBasis::AuthoritativeSlabSlice
        );
        assert!(bindings[0].seeded_from_slab);
        assert_ne!(
            bindings[0].raw_child_digest,
            bindings[0].raw_slab_slice_digest
        );
        assert_eq!(
            bindings[0].transform_input_digest,
            bindings[0].raw_slab_slice_digest
        );
    }

    #[test]
    fn route_q_r0_strict_extent_drift_is_rejected_before_transforms() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ObservedAllocation,
                "route-q-strict-drift",
            )],
        };
        let mut global = r0g_transformed(
            R0G_FIRST_MISMATCH,
            R0G_FIRST_MISMATCH,
            0xBB,
            CEK::ObservedAllocation,
        );
        global.extent_evidence.capture_id = "route-q-strict-drift".into();
        let mut globals = vec![global];
        let mut containers = Vec::new();

        let err = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::RawCaptureDrift {
                first_mismatch_offset: R0G_FIRST_MISMATCH,
                ..
            }
        ));
    }

    #[test]
    fn route_q_r0_clean_strict_extent_keeps_child_capture_basis() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_CHILD_SIZE,
                CEK::BackingObject,
                "route-q-strict-clean",
            )],
        };
        let mut global = global(R0G_CHILD_BASE, vec![0xAA; R0G_CHILD_SIZE], false);
        global.extent_kind = CEK::BackingObject;
        global.extent_evidence.capture_id = "route-q-strict-clean".into();
        let mut globals = vec![global];
        let mut containers = Vec::new();

        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();

        assert_eq!(globals[0].content, vec![0xAA; R0G_CHILD_SIZE]);
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].basis, TransformPreimageBasis::ChildCapture);
        assert!(!bindings[0].seeded_from_slab);
        assert_eq!(
            bindings[0].transform_input_digest,
            bindings[0].raw_child_digest
        );
    }

    // ---- Route Q R0 Q0-B: byte/run-level transform provenance ----

    // The Route P geometry writer: a transform that writes the mName qword at
    // +0x28 (repair_label_names_after_scrub) must be attributed to exactly that
    // contiguous 8-byte run, with the authoritative preimage in `before_bytes`.
    #[test]
    fn route_q_r0b_repair_label_name_writer_isolated_to_0x28_run() {
        let mut before = global(0x8aa5f8, vec![0u8; 0x70], false);
        before.extent_evidence.capture_id = "gscript_child_link:0x8bc550:0x0:0x8aa5f8:true".into();
        // The authoritative slab preimage S at +0x28 already holds a different
        // non-null pointer (e.g. first byte 0xf0). Repair overwrites it with the
        // inline pointer label_live+0x30 = 0x8aa5f8+0x30 = 0x8aa628.
        let s_preimage = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
        before.content[0x28..0x30].copy_from_slice(&s_preimage);
        let mut after = before.clone();
        let ptr = 0x8aa628u64.to_le_bytes();
        after.content[0x28..0x30].copy_from_slice(&ptr);

        let runs = diff_transform_write_runs(
            &[before.clone()],
            &[after],
            "repair_label_names_after_scrub",
        );

        assert_eq!(runs.len(), 1, "one contiguous 8-byte run expected");
        let run = &runs[0];
        assert_eq!(run.transform_id, "repair_label_names_after_scrub");
        assert_eq!(run.child_old_base, 0x8aa5f8);
        assert_eq!(run.child_offset, 0x28);
        assert_eq!(run.length, 8);
        assert_eq!(run.first_before_byte, s_preimage[0]);
        assert_eq!(run.first_after_byte, ptr[0]);
        assert_eq!(run.before_bytes, s_preimage.to_vec());
        assert_eq!(run.after_bytes, ptr.to_vec());
        assert_eq!(run.before_digest, sha256_hex(&s_preimage));
        assert_eq!(run.after_digest, sha256_hex(&ptr));
        assert!(run.child_capture_id.contains("gscript_child_link"));
    }

    // mark_labels_non_nested writes Label+0x23, NOT +0x28. The byte/run diff
    // must never attribute a +0x28 write to it.
    #[test]
    fn route_q_r0b_mark_non_nested_writer_only_attributed_to_0x23() {
        let mut before = global(0x8aa5f8, vec![0u8; 0x70], false);
        before.extent_evidence.capture_id = "gscript_child_link:0x8bc550:0x0:0x8aa5f8:true".into();
        let mut after = before.clone();
        // mark_labels_non_nested flips byte +0x23 (nested flag).
        after.content[0x23] = 0x01;

        let runs = diff_transform_write_runs(&[before], &[after], "mark_labels_non_nested");

        assert_eq!(runs.len(), 1, "only the +0x23 write is present");
        assert_eq!(runs[0].transform_id, "mark_labels_non_nested");
        assert_eq!(runs[0].child_offset, 0x23);
        assert_eq!(runs[0].length, 1);
        // Critical: never a +0x28 run for this transform.
        assert_ne!(runs[0].child_offset, 0x28);
        assert_eq!(runs[0].first_before_byte, 0x00);
        assert_eq!(runs[0].first_after_byte, 0x01);
    }

    // scrub_uncaptured_heap_pointers zeroes dangling pointers (S -> 0). The run
    // records the authoritative preimage byte (before) and the zeroed output.
    #[test]
    fn route_q_r0b_scrub_zeroing_records_clean_preimage() {
        let mut before = global(0x8aa5f8, vec![0u8; 0x70], false);
        before.extent_evidence.capture_id = "gscript_child_link:0x8bc550:0x0:0x8aa5f8:true".into();
        // The authoritative slab preimage S at +0x28 is a full non-null pointer
        // (drift byte 0xf0, remaining qword bytes non-zero). Scrub zeroes the
        // dangling pointer (it pointed at an uncaptured range).
        let s_preimage = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
        before.content[0x28..0x30].copy_from_slice(&s_preimage);
        let mut after = before.clone();
        after.content[0x28..0x30].fill(0);

        let runs = diff_transform_write_runs(&[before], &[after], "scrub_uncaptured_heap_pointers");

        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].transform_id, "scrub_uncaptured_heap_pointers");
        assert_eq!(runs[0].child_offset, 0x28);
        assert_eq!(runs[0].length, 8);
        // before digest = the authoritative S preimage bytes; after = zeroed.
        assert_eq!(runs[0].before_bytes, s_preimage.to_vec());
        assert_eq!(runs[0].after_bytes, vec![0u8; 8]);
        assert_eq!(runs[0].first_before_byte, s_preimage[0]);
        assert_eq!(runs[0].first_after_byte, 0x00);
    }

    // Two disjoint write runs in one child become two separate runs, each with
    // its own offset/length/digest, and the ledger sorts deterministically.
    #[test]
    fn route_q_r0b_disjoint_runs_are_separate_and_sorted() {
        let mut before = global(0x8aa5f8, vec![0u8; 0x70], false);
        before.extent_evidence.capture_id = "route-q-disjoint".into();
        let mut after = before.clone();
        after.content[0x23] = 0x01;
        // A full non-zero qword write (all 8 bytes differ from the zero preimage).
        let ptr = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
        after.content[0x28..0x30].copy_from_slice(&ptr);

        let mut runs = diff_transform_write_runs(
            &[before],
            &[after],
            "mark_labels_non_nested", // combined for determinism demo
        );
        runs.sort_by(|a, b| a.child_offset.cmp(&b.child_offset));
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].child_offset, 0x23);
        assert_eq!(runs[0].length, 1);
        assert_eq!(runs[1].child_offset, 0x28);
        assert_eq!(runs[1].length, 8);
    }

    // A child whose content is unchanged by the transform produces no runs.
    #[test]
    fn route_q_r0b_unchanged_child_produces_no_runs() {
        let before = global(0x8aa5f8, vec![0xAA; 0x70], false);
        let after = before.clone();
        let runs = diff_transform_write_runs(&[before], &[after], "repair_label_names_after_scrub");
        assert!(runs.is_empty());
    }

    // The run ledger sorts deterministically by (base, offset, length, id).
    #[test]
    fn route_q_r0b_run_ledger_deterministic_sort() {
        let mut l1 = TransformRunLedger::default();
        let mut l2 = TransformRunLedger::default();
        let base = TransformWriteRun {
            child_capture_id: "x".into(),
            child_old_base: 0x8aa5f8,
            child_size: 0x70,
            child_offset: 0x28,
            length: 8,
            transform_id: "repair_label_names_after_scrub".into(),
            before_digest: "b".into(),
            after_digest: "a".into(),
            first_before_byte: 0,
            first_after_byte: 0x28,
            before_bytes: vec![0; 8],
            after_bytes: vec![0x28; 8],
        };
        // Insert out of order in l1 and in order in l2; both sort identically.
        let mut low = base.clone();
        low.child_offset = 0x23;
        low.length = 1;
        l1.runs.push(base.clone());
        l1.runs.push(low.clone());
        l2.runs.push(low);
        l2.runs.push(base);
        l1.sort_runs();
        l2.sort_runs();
        assert_eq!(l1, l2);
        assert_eq!(l1.runs[0].child_offset, 0x23);
        assert_eq!(l1.runs[1].child_offset, 0x28);
    }

    // ---- Route Q R0 Q0-C: three-way overlay over authoritative preimage ----

    // Route P exact geometry: an InteriorSubview child (size 0x70, drift at
    // +0x28) whose transform runs on the authoritative slab slice (P=S) and
    // writes byte +0x28. Under Q0-C this must be APPLIED as
    // TransformReplayedOnAuthoritativePreimage (NOT fail-closed), because the
    // binding proves transform_input_digest == sha256(S).
    #[test]
    fn route_q_r0c_interior_transform_replayed_on_authoritative_preimage() {
        // Slab where the child range is all 0xAA except +0x28 = 0xf0 (authoritative S).
        let child_base: u64 = 0x8aa5f8;
        let child_size = 0x70usize;
        let slab_base: u64 = 0x874000;
        let child_off = (child_base - slab_base) as usize;
        let mut slab_content = vec![0u8; child_off + child_size];
        for i in 0..child_size {
            slab_content[child_off + i] = 0xAA;
        }
        slab_content[child_off + 0x28] = 0xf0; // S byte at +0x28
        let slab = HeapSlab {
            old_base: slab_base,
            content: slab_content,
        };
        // Raw child capture C: drifts from S (C[0x28]=0x00 != S[0x28]=0xf0).
        let mut raw_bytes = vec![0xAAu8; child_size];
        raw_bytes[0x28] = 0x00;
        let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
        child.extent_kind = CEK::InteriorSubview;
        child.capture_id = "route-p-geometry".into();
        let raw_capture = RawSlabCapture {
            slab,
            children: vec![child],
        };

        // Q0-A seeding: replace the probe/interior transform input with S.
        // The child's pre-seed content must equal the raw child capture C.
        let mut seeded = global(child_base, vec![0xAAu8; child_size], false);
        seeded.content[0x28] = 0x00; // C value at +0x28
        seeded.extent_kind = CEK::InteriorSubview;
        seeded.extent_evidence.capture_id = "route-p-geometry".into();
        let mut globals = vec![seeded];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].basis,
            TransformPreimageBasis::AuthoritativeSlabSlice
        );
        // Seeded input now == S (0xAA everywhere, +0x28 = 0xf0).
        assert_eq!(globals[0].content[0x28], 0xf0);

        // Transform writes +0x28 to a repaired pointer (0x8aa628 first byte 0x28).
        globals[0].content[0x28] = 0x28;
        globals[0].transform_ids = vec!["repair_label_names_after_scrub".to_string()];

        let (patched, overlays, drift) =
            build_patched_backing_slab_q0c(&raw_capture, &[globals[0].clone()], &[], &bindings)
                .unwrap();
        // The +0x28 write was applied (T != S).
        assert_eq!(patched.content[child_off + 0x28], 0x28);
        // A TransformReplayedOnAuthoritativePreimage run was recorded.
        assert!(drift.iter().any(|d| {
            d.resolution == CaptureDriftResolution::TransformReplayedOnAuthoritativePreimage
                && d.child_offset == 0x28
        }));
        assert_eq!(overlays.len(), 1);
        assert_eq!(overlays[0].overlay_applied, true);
    }

    // Probe/interior non-write drift under Q0-C still resolves to slab authority.
    #[test]
    fn route_q_r0c_interior_nonwrite_drift_uses_slab_authority() {
        let child_base: u64 = 0x8aa5f8;
        let child_size = 0x70usize;
        let slab_base: u64 = 0x874000;
        let child_off = (child_base - slab_base) as usize;
        let mut slab_content = vec![0u8; child_off + child_size];
        for i in 0..child_size {
            slab_content[child_off + i] = 0xAA;
        }
        slab_content[child_off + 0x28] = 0xf0;
        let slab = HeapSlab {
            old_base: slab_base,
            content: slab_content,
        };
        // C drifts at +0x28 (0x00 vs S 0xf0) but the transform writes nothing.
        let mut raw_bytes = vec![0xAAu8; child_size];
        raw_bytes[0x28] = 0x00;
        let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
        child.extent_kind = CEK::InteriorSubview;
        child.capture_id = "route-p-nonwrite".into();
        let raw_capture = RawSlabCapture {
            slab,
            children: vec![child],
        };
        // Seed: transform input becomes S. Pre-seed content must equal C.
        let mut seeded = global(child_base, vec![0xAAu8; child_size], false);
        seeded.content[0x28] = 0x00; // C value at +0x28
        seeded.extent_kind = CEK::InteriorSubview;
        seeded.extent_evidence.capture_id = "route-p-nonwrite".into();
        let mut globals = vec![seeded];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        // No transform write: T == S. Backing starts from S.
        let (patched, _, drift) =
            build_patched_backing_slab_q0c(&raw_capture, &[globals[0].clone()], &[], &bindings)
                .unwrap();
        // Slab authority wins at +0x28.
        assert_eq!(patched.content[child_off + 0x28], 0xf0);
        // NonWriteSlabAuthoritative drift run recorded.
        assert!(drift.iter().any(|d| {
            d.resolution == CaptureDriftResolution::NonWriteSlabAuthoritative
                && d.child_offset == 0x28
        }));
    }

    // Q0-C: a binding claiming slab basis but whose transform_input_digest does
    // NOT equal the authoritative slab slice digest fails closed.
    #[test]
    fn route_q_r0c_mismatched_transform_input_digest_fails_closed() {
        let child_base: u64 = 0x8aa5f8;
        let child_size = 0x70usize;
        let slab_base: u64 = 0x874000;
        let child_off = (child_base - slab_base) as usize;
        let mut slab_content = vec![0u8; child_off + child_size];
        for i in 0..child_size {
            slab_content[child_off + i] = 0xAA;
        }
        slab_content[child_off + 0x28] = 0xf0;
        let slab = HeapSlab {
            old_base: slab_base,
            content: slab_content,
        };
        let mut raw_bytes = vec![0xAAu8; child_size];
        raw_bytes[0x28] = 0x00;
        let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
        child.extent_kind = CEK::InteriorSubview;
        child.capture_id = "route-p-baddigest".into();
        let raw_capture = RawSlabCapture {
            slab,
            children: vec![child],
        };
        // A forged binding: claims AuthoritativeSlabSlice but digest is wrong.
        let bad_binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "route-p-baddigest".into(),
            child_old_base: child_base,
            child_size,
            extent_kind: CEK::InteriorSubview,
            slab_old_base: slab_base,
            slab_offset: child_off,
            basis: TransformPreimageBasis::AuthoritativeSlabSlice,
            raw_child_digest: "c".into(),
            raw_slab_slice_digest: "s".into(),
            transform_input_digest: "WRONG".into(), // != sha256(S)
            seeded_from_slab: true,
        };
        let mut transformed = global(child_base, vec![0xAAu8; child_size], false);
        transformed.extent_kind = CEK::InteriorSubview;
        transformed.extent_evidence.capture_id = "route-p-baddigest".into();
        transformed.content[0x28] = 0x28;
        let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[bad_binding])
            .unwrap_err();
        assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
    }

    // Q0-C: strict extent with a ChildCapture binding and full C==S coherence
    // produces a write-set overlay; any C!=S drift is rejected.
    #[test]
    fn route_q_r0c_strict_extent_write_applies_and_drift_rejected() {
        let child_base: u64 = 0x8aa5f8;
        let child_size = 0x70usize;
        let slab_base: u64 = 0x874000;
        let child_off = (child_base - slab_base) as usize;
        let mut slab_content = vec![0u8; child_off + child_size];
        for i in 0..child_size {
            slab_content[child_off + i] = 0xAA;
        }
        let slab = HeapSlab {
            old_base: slab_base,
            content: slab_content,
        };
        // C == S (all 0xAA), strict ObservedAllocation.
        let raw_bytes = vec![0xAAu8; child_size];
        let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
        child.extent_kind = CEK::ObservedAllocation;
        child.capture_id = "route-q-strict-ok".into();
        let raw_capture = RawSlabCapture {
            slab,
            children: vec![child],
        };
        // ChildCapture binding (strict), C==S.
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "route-q-strict-ok".into(),
            child_old_base: child_base,
            child_size,
            extent_kind: CEK::ObservedAllocation,
            slab_old_base: slab_base,
            slab_offset: child_off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&vec![0xAAu8; child_size]),
            raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; child_size]),
            transform_input_digest: sha256_hex(&vec![0xAAu8; child_size]),
            seeded_from_slab: false,
        };
        // Transform writes byte 0x10 to 0xEE.
        let mut transformed = global(child_base, vec![0xAAu8; child_size], false);
        transformed.extent_kind = CEK::ObservedAllocation;
        transformed.extent_evidence.capture_id = "route-q-strict-ok".into();
        transformed.content[0x10] = 0xEE;
        transformed.transform_ids = vec!["t1".to_string()];
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding]).unwrap();
        assert_eq!(patched.content[child_off + 0x10], 0xEE);
        assert_eq!(overlays.len(), 1);
        // Non-written bytes stay 0xAA (unchanged).
        assert_eq!(patched.content[child_off + 0x20], 0xAA);

        // Now a strict child with C!=S must fail closed.
        let mut drifting_raw = vec![0xAAu8; child_size];
        drifting_raw[0x28] = 0x00; // C[0x28] != S[0x28] (0xAA)
        let mut child2 = raw_child(
            child_base,
            child_size,
            drifting_raw,
            RawChildKind::HeapGlobal,
        );
        child2.extent_kind = CEK::ObservedAllocation;
        child2.capture_id = "route-q-strict-drift".into();
        let raw_capture2 = RawSlabCapture {
            slab: HeapSlab {
                old_base: slab_base,
                content: vec![0xAAu8; child_off + child_size],
            },
            children: vec![child2],
        };
        let binding2 = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "route-q-strict-drift".into(),
            child_old_base: child_base,
            child_size,
            extent_kind: CEK::ObservedAllocation,
            slab_old_base: slab_base,
            slab_offset: child_off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: "c".into(),
            raw_slab_slice_digest: "s".into(),
            transform_input_digest: "p".into(),
            seeded_from_slab: false,
        };
        let mut transformed2 = global(child_base, vec![0xAAu8; child_size], false);
        transformed2.extent_kind = CEK::ObservedAllocation;
        transformed2.content[0x28] = 0x00;
        let err = build_patched_backing_slab_q0c(&raw_capture2, &[transformed2], &[], &[binding2])
            .unwrap_err();
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    // 1. Probe-window non-write drift uses the authoritative slab (B[i]=S[i]).
    #[test]
    fn r0g_nonwrite_probe_drift_uses_slab_authority() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ProbeWindow,
                "probe1",
            )],
        };
        // No transform: T == C.
        let mut transformed = global(
            R0G_CHILD_BASE,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        transformed.extent_kind = CEK::ProbeWindow;
        let (patched, _, drift) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        // The authoritative slab byte wins: patched at child offset is the slab
        // value (0xAA everywhere, since the slab is all 0xAA).
        assert_eq!(
            &patched.content[R0G_CHILD_OFF..R0G_CHILD_OFF + R0G_CHILD_SIZE],
            &vec![0xAAu8; R0G_CHILD_SIZE][..]
        );
        // A NonWriteSlabAuthoritative drift run was recorded covering the tail.
        assert!(!drift.is_empty());
        assert!(drift
            .iter()
            .any(|d| d.resolution == CaptureDriftResolution::NonWriteSlabAuthoritative));
        assert!(drift
            .iter()
            .all(|d| d.resolution == CaptureDriftResolution::NonWriteSlabAuthoritative));
    }

    // 2. Interior-subview non-write drift uses the authoritative slab.
    #[test]
    fn r0g_nonwrite_interior_drift_uses_slab_authority() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::InteriorSubview,
                "interior1",
            )],
        };
        let mut transformed = global(
            R0G_CHILD_BASE,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        transformed.extent_kind = CEK::InteriorSubview;
        let (patched, _, drift) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        assert_eq!(
            &patched.content[R0G_CHILD_OFF..R0G_CHILD_OFF + R0G_CHILD_SIZE],
            &vec![0xAAu8; R0G_CHILD_SIZE][..]
        );
        assert!(drift
            .iter()
            .all(|d| d.resolution == CaptureDriftResolution::NonWriteSlabAuthoritative));
    }

    // 3. No-transform drift does not modify the slab (patched == raw slab).
    #[test]
    fn r0g_no_transform_drift_does_not_modify_slab() {
        let slab = r0g_slab();
        let raw_slab = slab.content.clone();
        let raw_capture = RawSlabCapture {
            slab,
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ProbeWindow,
                "probe2",
            )],
        };
        // T == C (no transform writes).
        let mut transformed = global(
            R0G_CHILD_BASE,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        transformed.extent_kind = CEK::ProbeWindow;
        let (patched, _, _) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        assert_eq!(patched.content, raw_slab);
    }

    // 4. A transform writing a stable preimage (write < first mismatch) applies.
    #[test]
    fn r0g_stable_preimage_transform_write_applies() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ProbeWindow,
                "probe3",
            )],
        };
        // Transform writes byte 0x10 (within stable prefix) to 0xEE.
        let transformed = r0g_transformed(R0G_FIRST_MISMATCH, 0x10, 0xEE, CEK::ProbeWindow);
        let (patched, _, _) = build_patched_backing_slab(
            &raw_capture,
            &[transformed],
            &[],
            &["repair_gscript_window_strings"],
        )
        .unwrap();
        // The write was applied at slab offset.
        assert_eq!(patched.content[R0G_CHILD_OFF + 0x10], 0xEE);
        // The drifted tail stays at slab authority (0xAA).
        assert_eq!(patched.content[R0G_CHILD_OFF + R0G_FIRST_MISMATCH], 0xAA);
    }

    // 5. A transform writing a drifted preimage fails closed (TransformPreimageDrift).
    #[test]
    fn r0g_transform_preimage_drift_fails_closed() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ProbeWindow,
                "probe4",
            )],
        };
        // Transform writes byte 0x30 (>= first mismatch 0x28), which drifted.
        let transformed = r0g_transformed(R0G_FIRST_MISMATCH, 0x30, 0xEE, CEK::ProbeWindow);
        let err =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
    }

    // 6. Strict ObservedAllocation full-range drift still fails closed.
    #[test]
    fn r0g_strict_observed_allocation_drift_fails_closed() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ObservedAllocation,
                "obs1",
            )],
        };
        // Even with no transform, a strict allocation with full-range drift fails.
        let mut transformed = global(
            R0G_CHILD_BASE,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        transformed.extent_kind = CEK::ObservedAllocation;
        let err =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    // 7. BackingObject full-range drift still fails closed.
    #[test]
    fn r0g_backing_object_drift_fails_closed() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::BackingObject,
                "back1",
            )],
        };
        let mut transformed = global(
            R0G_CHILD_BASE,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        transformed.extent_kind = CEK::BackingObject;
        let err =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    // 8. Synthetic children still skip raw coherence entirely.
    #[test]
    fn r0g_synthetic_still_skips_raw_coherence() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![],
        };
        // A synthetic child (SyntheticDerived provenance) with no raw source.
        let mut synth = global(0x10000, b"NewClassName\0".to_vec(), false);
        synth.provenance = RegionProvenance::SyntheticDerived {
            transform_id: "repair_gscript_window_strings".to_string(),
            source_anchor: "gscript+0xbd8".to_string(),
            construction_digest: sha256_hex(&synth.content),
        };
        synth.extent_kind = CEK::SyntheticDerived;
        // Should not fail on raw coherence (no raw child); recorded as synthetic ledger.
        let (_, overlays, _) =
            build_patched_backing_slab(&raw_capture, &[synth], &[], &["t"]).unwrap();
        assert!(!overlays.is_empty());
        assert!(!overlays[0].overlay_applied);
    }

    // 9. Drift runs are deterministically sorted.
    #[test]
    fn r0g_drift_runs_are_deterministically_sorted() {
        // Two probe children with drift -> drift runs sorted by (base, slab_offset).
        let a = R0G_CHILD_BASE;
        let b = R0G_CHILD_BASE + 0x100;
        let mut content = vec![0u8; (b - R0G_SLAB_BASE) as usize + R0G_CHILD_SIZE];
        for off in 0..R0G_CHILD_SIZE {
            content[(a - R0G_SLAB_BASE) as usize + off] = 0xAA;
            content[(b - R0G_SLAB_BASE) as usize + off] = 0xAA;
        }
        let raw_capture = RawSlabCapture {
            slab: HeapSlab {
                old_base: R0G_SLAB_BASE,
                content,
            },
            children: vec![
                r0g_raw_child_at(a, R0G_FIRST_MISMATCH, CEK::ProbeWindow, "pa"),
                r0g_raw_child_at(b, R0G_FIRST_MISMATCH, CEK::ProbeWindow, "pb"),
            ],
        };
        let mk = |live: u64, id: &str| {
            let mut g = global(
                live,
                {
                    let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                    for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                        b[i] = 0xBB;
                    }
                    b
                },
                false,
            );
            g.extent_kind = CEK::ProbeWindow;
            g.extent_evidence.capture_id = id.to_string();
            g
        };
        let ga = mk(a, "pa");
        let gb = mk(b, "pb");
        let (_, _, d1) =
            build_patched_backing_slab(&raw_capture, &[gb.clone(), ga.clone()], &[], &["t"])
                .unwrap();
        let (_, _, d2) = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
        assert_eq!(d1, d2);
        for w in d1.windows(2) {
            assert!(w[0].child_old_base <= w[1].child_old_base);
        }
    }

    // 10. Drift ledger binds the child capture id.
    #[test]
    fn r0g_drift_ledger_binds_capture_id() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ProbeWindow,
                "gscript_child_link:0x1:0x0:0x9f93e8:0x400",
            )],
        };
        let mut transformed = global(
            R0G_CHILD_BASE,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        transformed.extent_kind = CEK::ProbeWindow;
        transformed.extent_evidence.capture_id =
            "gscript_child_link:0x1:0x0:0x9f93e8:0x400".to_string();
        let (_, _, drift) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        assert!(!drift.is_empty());
        for d in &drift {
            assert_eq!(
                d.child_capture_id,
                "gscript_child_link:0x1:0x0:0x9f93e8:0x400"
            );
        }
    }

    // 11. first_mismatch is never used as the allocation size.
    #[test]
    fn r0g_first_mismatch_is_not_used_as_size() {
        // The drift at 0x28 must NOT truncate the child to 0x28. The child keeps
        // its full captured size (0x70) and the slab stays authoritative.
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ProbeWindow,
                "probe5",
            )],
        };
        let mut transformed = global(
            R0G_CHILD_BASE,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        transformed.extent_kind = CEK::ProbeWindow;
        let (patched, _, _) =
            build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
        // The slab content at the full child range (0x70 bytes) is retained.
        assert_eq!(
            &patched.content[R0G_CHILD_OFF..R0G_CHILD_OFF + R0G_CHILD_SIZE],
            &vec![0xAAu8; R0G_CHILD_SIZE][..]
        );
    }

    // 12. Input order does not change drift resolution.
    #[test]
    fn r0g_input_order_does_not_change_drift_resolution() {
        let raw_capture = RawSlabCapture {
            slab: r0g_slab(),
            children: vec![r0g_raw_child(
                R0G_FIRST_MISMATCH,
                CEK::ProbeWindow,
                "probe6",
            )],
        };
        // T == C (child with the same drift tail as the raw child).
        let mk = || {
            let mut g = global(
                R0G_CHILD_BASE,
                {
                    let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                    for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                        b[i] = 0xBB;
                    }
                    b
                },
                false,
            );
            g.extent_kind = CEK::ProbeWindow;
            g
        };
        let t1 = mk();
        let t2 = mk();
        let (p1, _, d1) = build_patched_backing_slab(&raw_capture, &[t1], &[], &["t"]).unwrap();
        let (p2, _, d2) = build_patched_backing_slab(&raw_capture, &[t2], &[], &["t"]).unwrap();
        assert_eq!(p1.content, p2.content);
        assert_eq!(d1, d2);
    }

    // 13. Existing transform-write conflict (same byte, different value) still fails.
    #[test]
    fn r0g_existing_transform_write_conflict_still_fails() {
        let raw_capture = route_n_raw_capture(0xAA);
        let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
        a[0x50] = 0xBB;
        let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
        b[0x00] = 0xCC;
        // Both children are strict ObservedAllocation (R0-F semantics preserved).
        let mut ga = global(ROUTEN_A_BASE, a, false);
        ga.extent_kind = CEK::ObservedAllocation;
        let mut gb = global(ROUTEN_B_BASE, b, false);
        gb.extent_kind = CEK::ObservedAllocation;
        let err =
            build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t1", "t2"]).unwrap_err();
        assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    }

    // 14. Existing raw-duplicate ambiguity still fails closed.
    #[test]
    fn r0g_existing_raw_duplicate_ambiguity_still_fails() {
        // Two distinct raw children at the same base with different bytes, NEITHER
        // slab-coherent (slab holds a third distinct byte pattern) -> ambiguous,
        // fails closed (no silent overwrite).
        let s = slab_with_child(
            ROUTEK_SLAB_BASE,
            ROUTEK_SLAB_SZ,
            ROUTEK_CHILD_BASE,
            b"slab-bytes-xxx".to_vec(),
        );
        let raw_capture = RawSlabCapture {
            slab: s,
            children: vec![
                raw_child(
                    ROUTEK_CHILD_BASE,
                    14,
                    b"child-A-bytes".to_vec(),
                    RawChildKind::HeapGlobal,
                ),
                raw_child(
                    ROUTEK_CHILD_BASE,
                    14,
                    b"child-B-bytes".to_vec(),
                    RawChildKind::HeapGlobal,
                ),
            ],
        };
        let ga = global(ROUTEK_CHILD_BASE, b"child-A-bytes".to_vec(), false);
        let gb = global(ROUTEK_CHILD_BASE, b"child-B-bytes".to_vec(), false);
        // Neither raw child matches the slab ("slab-bytes-xxx"); the two raw
        // children differ from each other -> ambiguous duplicate -> fail closed.
        let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap_err();
        assert!(matches!(err, OverlayError::RawChildMissing { .. }));
    }

    // 15. Route O exact geometry constant sanity.
    #[test]
    fn r0g_route_o_geometry_is_exact() {
        assert_eq!(R0G_CHILD_BASE - R0G_SLAB_BASE, R0G_CHILD_OFF as u64);
        assert_eq!(R0G_CHILD_OFF as u64, 0x3a3e8);
        assert_eq!(R0G_CHILD_SIZE, 0x70);
        assert_eq!(R0G_FIRST_MISMATCH, 0x28);
        // The child is inside the Route O slab.
        assert!(R0G_CHILD_BASE >= R0G_SLAB_BASE);
        assert!(R0G_CHILD_BASE + R0G_CHILD_SIZE as u64 <= R0G_SLAB_BASE + 0x2db3750);
    }
}
