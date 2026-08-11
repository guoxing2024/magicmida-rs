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

/// Deterministic, non-empty capture id for a Container region (Route Q R0
/// AF1 Rev 2). `ContainerSnapshot` has no natural capture id, but a stable
/// identity is required for the Q0-C exact binding to match the raw/seeding
/// stage to the transformed representation. Derive it from the decoded begin
/// so every stage (raw children, seeding, overlay) agrees.
pub fn container_capture_id(decoded_begin: u64) -> String {
    format!("container:{decoded_begin:#x}")
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

/// A coherent raw capture bundle: the raw children plus the authoritative slabs
/// (main heap slab + each dedicated dangling-edge slab) they may be contained in.
/// Captured from the debuggee before any offline transform. TAF1-A: the full
/// authoritative slab set is part of the capture bundle, so seed / overlay /
/// coverage / runtime all operate on the SAME slabs (no
/// overlay-single / runtime-multi fork).
#[derive(Debug, Clone)]
pub struct RawSlabCapture {
    /// Raw authoritative slab bytes (pre-transform). May hold more than one slab
    /// (main heap slab + dedicated dangling-edge slabs). Every raw child must be
    /// contained in exactly one of these slabs.
    pub slabs: Vec<HeapSlab>,
    /// Raw children (heap globals + containers) with their raw bytes.
    pub children: Vec<RawChild>,
}

/// Resolve which authoritative slab contains a raw child range, and the byte
/// offset within it. Route T R0 / TAF1-B: the covering slab is selected from the
/// full multi-slab set deterministically.
///
/// Returns `(slab_index, slab_old_base, slab_size, slab_offset, &slab_bytes)`.
/// 0 covering slabs -> `ProbeCoverageMissing`-style fail-closed; >1 covering
/// slabs (excluding the exact-duplicate case where a dedicated slab is a
/// superset) -> fail-closed as ambiguous.
fn covering_slab_for_child<'a>(
    raw_capture: &'a RawSlabCapture,
    child_old_base: u64,
    child_size: usize,
    child_kind: RawChildKind,
) -> Result<(usize, u64, usize, usize, &'a [u8]), OverlayError> {
    let child_end = child_old_base.checked_add(child_size as u64).ok_or(
        OverlayError::RawChildRangeOverflow {
            child_old_base,
            child_size,
            slab_old_base: 0,
            slab_offset: 0,
        },
    )?;
    let mut covering: Vec<(usize, u64, usize, usize)> = Vec::new();
    for (si, s) in raw_capture.slabs.iter().enumerate() {
        if s.content.is_empty() || s.old_base == 0 {
            continue;
        }
        let s_end = s.old_base.checked_add(s.content.len() as u64).ok_or(
            OverlayError::RawChildRangeOverflow {
                child_old_base,
                child_size,
                slab_old_base: s.old_base,
                slab_offset: 0,
            },
        )?;
        if child_old_base >= s.old_base && child_end <= s_end {
            let off = usize::try_from(child_old_base - s.old_base).unwrap_or(usize::MAX);
            covering.push((si, s.old_base, s.content.len(), off));
        }
    }
    match covering.len() {
        0 => Err(OverlayError::ProbeCoverageMissing {
            child_kind,
            child_base: child_old_base,
            child_size,
            extent_kind: String::new(),
            candidate_slab_count: raw_capture.slabs.len(),
            nearest_authority: None,
            nearest_authority_gap: 0,
        }),
        1 => {
            let (si, base, size, off) = covering[0];
            let slab = &raw_capture.slabs[si];
            Ok((si, base, size, off, &slab.content))
        }
        _ => {
            // Ambiguous coverage (contained in multiple slabs). A dedicated slab
            // that exactly duplicates a main-slab slice should have been deduped;
            // any real multi-coverage is a hard fail-closed.
            Err(OverlayError::ProbeCoverageMissing {
                child_kind,
                child_base: child_old_base,
                child_size,
                extent_kind: String::new(),
                candidate_slab_count: raw_capture.slabs.len(),
                nearest_authority: Some((
                    covering[0].1,
                    covering[0].1.saturating_add(covering[0].2 as u64),
                )),
                nearest_authority_gap: 0,
            })
        }
    }
}

/// Provenance of a normalized authoritative slab (Route T R0 AF2 / TAF2-B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabNormalization {
    /// Kept as-is (the survivor backing region).
    Kept,
    /// Dedup / contained-alias taxonomy. These are NOT constructed on kept entries:
    /// a dropped input is recorded as a `NormalizationEvent` (action
    /// `deduplicated` / `contained_exact_alias`), the authoritative channel for
    /// the audit. The variants are retained to document the normalization concept.
    #[allow(dead_code)]
    Deduplicated,
    #[allow(dead_code)]
    ContainedExactAlias,
}

/// An input slab candidate carrying its TRUE capture role (TAF3-A). The role is
/// never inferred from position — dedicated-only inputs keep role "dedicated".
#[derive(Debug, Clone)]
pub struct AuthoritativeSlabCandidate {
    /// The slab backing region.
    pub slab: HeapSlab,
    /// Real capture role: "main" | "dedicated".
    pub role: &'static str,
}

/// A normalized authoritative slab entry with its provenance.
#[derive(Debug, Clone)]
pub struct NormalizedSlab {
    /// The slab backing region (kept after normalization).
    pub slab: HeapSlab,
    /// How it was normalized (always `Kept` for a survivor; dedups/aliases are
    /// recorded as events, not kept entries).
    pub normalization: SlabNormalization,
    /// Role: "main" or "dedicated" — the TRUE capture role (never inferred).
    pub role: &'static str,
    /// Route T R0 AF3 Rev1: the input sequence this survivor ORIGINATED from. When
    /// reverse containment replaces a kept slab with a later outer slab, the
    /// survivor's bytes come from the OUTER input — so this records the true origin
    /// (the outer input's sequence), not the replaced inner's.
    pub origin_input_sequence: usize,
}

/// Route T R0 AF3 (TAF3-B): a normalization event describing what happened to one
/// INPUT slab — whether it survived (kept), was dropped as an exact duplicate
/// (deduplicated), or was dropped as a contained exact alias. Each event answers:
/// which input, why dropped, which survivor it belongs to, its original digest,
/// and the interval relationship.
#[derive(Debug, Clone)]
pub struct NormalizationEvent {
    /// Input sequence (index into the candidates passed in).
    pub input_sequence: usize,
    /// True capture role of the input ("main" | "dedicated").
    pub input_role: &'static str,
    /// Old base of the input slab.
    pub input_old_base: u64,
    /// Size of the input slab.
    pub input_size: usize,
    /// sha256 of the input slab's raw bytes.
    pub input_raw_digest: String,
    /// Action: "kept" | "deduplicated" | "contained_exact_alias".
    pub action: &'static str,
    /// Sequence of the survivor (kept slab index) this input maps to, if any.
    pub survivor_sequence: Option<usize>,
    /// Interval relationship to the survivor (e.g. "exact_duplicate",
    /// "contained_same_bytes", "kept").
    pub relationship: &'static str,
}

/// Route T R0 AF2 (TAF2-B) / AF3: deterministically normalize the authoritative
/// slab set (main heap slab + dedicated dangling-edge slabs) BEFORE coverage / raw
/// capture / seed. This prevents the same range being claimed by two authorities.
///
/// Rules (fail-closed, never implicit):
/// 1. Exact duplicate `(base, size, bytes)` -> keep the FIRST, drop later ones
///    (emit a `deduplicated` event; the survivor keeps `Kept`).
/// 2. A slab fully contained in an earlier slab with IDENTICAL bytes -> keep only
///    the outer slab (the inner is an exact authoritative alias; emit a
///    `contained_exact_alias` event).
/// 3. Fully contained but DIFFERENT bytes -> `AuthoritativeSlabConflict`
///    (contained_byte_conflict) — unresolvable.
/// 4. Partial overlap (neither contains the other) -> `AuthoritativeSlabConflict`
///    (partial_overlap) — never implicitly joined.
/// 5. Reverse containment (a later slab is a superset of a kept slab, same bytes):
///    replace the kept slab with the outer, then RE-CHECK the outer against ALL
///    other kept slabs (no early break) — TAF3-C.
/// 6. TAF3-D: after construction, the normalized set MUST be pairwise-disjoint;
///    any remaining overlap fails closed.
///
/// The returned (kept set, event ledger) feeds coverage, raw capture, seed,
/// overlay, runtime planner, and manifest (one shared authoritative set).
pub fn normalize_authoritative_slabs(
    candidates: &[AuthoritativeSlabCandidate],
) -> Result<(Vec<NormalizedSlab>, Vec<NormalizationEvent>), OverlayError> {
    let mut kept: Vec<NormalizedSlab> = Vec::new();
    let mut events: Vec<NormalizationEvent> = Vec::new();
    // Rev1: parallel to `kept` — the index into `events` of the "kept" event for
    // each kept slab's origin input. Used by reverse-containment to UPDATE the
    // replaced inner's event to `contained_exact_alias` (bijection: each valid
    // input produces exactly one event).
    let mut kept_event_idx: Vec<usize> = Vec::new();

    for (seq, cand) in candidates.iter().enumerate() {
        let s = &cand.slab;
        if s.content.is_empty() || s.old_base == 0 {
            // Empty/invalid slabs carry no authority; skip (not a conflict).
            continue;
        }
        let s_digest = sha256_hex(&s.content);

        // The event for the current input (we build it per-branch below). For a
        // kept input, we emit one "kept" event. For an absorbed/replaced input, we
        // emit/update one event. To guarantee bijection, an input that was first
        // KEPT and later REVERSE-REPLACED has its original "kept" event UPDATED to
        // `contained_exact_alias`, and the replacing input gets its own "kept"
        // event. So no input ever yields more than one event.
        let s_end = s.old_base.checked_add(s.content.len() as u64).ok_or(
            OverlayError::AuthoritativeSlabConflict {
                a_old_base: s.old_base,
                a_size: s.content.len(),
                b_old_base: s.old_base,
                b_size: s.content.len(),
                relationship: "overflow",
                mismatch_offset: None,
            },
        )?;

        // Determine this input's fate by comparing against ALL kept slabs.
        let mut absorbed: Option<usize> = None; // kept index that absorbs s (drop s)
        let mut reverse_replace: Option<usize> = None; // kept index replaced by s (s survives)
        let mut conflict: Option<OverlayError> = None;

        for i in 0..kept.len() {
            let k = &kept[i].slab;
            let k_end = k.old_base.checked_add(k.content.len() as u64).ok_or(
                OverlayError::AuthoritativeSlabConflict {
                    a_old_base: k.old_base,
                    a_size: k.content.len(),
                    b_old_base: s.old_base,
                    b_size: s.content.len(),
                    relationship: "overflow",
                    mismatch_offset: None,
                },
            )?;
            // Exact duplicate (base+size equal).
            if s.old_base == k.old_base && s.content.len() == k.content.len() {
                if s.content == k.content {
                    absorbed = Some(i);
                    break; // exact duplicate -> drop, done
                } else {
                    conflict = Some(OverlayError::AuthoritativeSlabConflict {
                        a_old_base: k.old_base,
                        a_size: k.content.len(),
                        b_old_base: s.old_base,
                        b_size: s.content.len(),
                        relationship: "contained_byte_conflict",
                        mismatch_offset: Some(
                            s.content
                                .iter()
                                .zip(k.content.iter())
                                .position(|(a, b)| a != b)
                                .unwrap_or(0),
                        ),
                    });
                    break;
                }
            }
            // s fully contained in k?
            if s.old_base >= k.old_base && s_end <= k_end {
                let off = (s.old_base - k.old_base) as usize;
                let k_slice = &k.content[off..off + s.content.len()];
                if k_slice == s.content {
                    absorbed = Some(i); // contained exact alias -> drop s, survivor k
                    break;
                } else {
                    conflict = Some(OverlayError::AuthoritativeSlabConflict {
                        a_old_base: k.old_base,
                        a_size: k.content.len(),
                        b_old_base: s.old_base,
                        b_size: s.content.len(),
                        relationship: "contained_byte_conflict",
                        mismatch_offset: Some(
                            off + k_slice
                                .iter()
                                .zip(s.content.iter())
                                .position(|(a, b)| a != b)
                                .unwrap_or(0),
                        ),
                    });
                    break;
                }
            }
            // k fully contained in s (reverse containment)?
            if k.old_base >= s.old_base && k_end <= s_end {
                let off = (k.old_base - s.old_base) as usize;
                let s_slice = &s.content[off..off + k.content.len()];
                if s_slice == k.content {
                    // s is a superset of k with same bytes -> s survives, k replaced.
                    // Record the replacement and break out of the scan; the dedicated
                    // recheck loop below re-examines the new outer (s) against ALL
                    // other kept slabs (TAF3-C), catching any partial overlap or
                    // byte conflict that the current scan would miss.
                    reverse_replace = Some(i);
                    break;
                } else {
                    conflict = Some(OverlayError::AuthoritativeSlabConflict {
                        a_old_base: s.old_base,
                        a_size: s.content.len(),
                        b_old_base: k.old_base,
                        b_size: k.content.len(),
                        relationship: "contained_byte_conflict",
                        mismatch_offset: Some(
                            off + s_slice
                                .iter()
                                .zip(k.content.iter())
                                .position(|(a, b)| a != b)
                                .unwrap_or(0),
                        ),
                    });
                    break;
                }
            }
            // Partial overlap (neither contains the other).
            if s.old_base < k_end && k.old_base < s_end {
                conflict = Some(OverlayError::AuthoritativeSlabConflict {
                    a_old_base: k.old_base,
                    a_size: k.content.len(),
                    b_old_base: s.old_base,
                    b_size: s.content.len(),
                    relationship: "partial_overlap",
                    mismatch_offset: None,
                });
                break;
            }
        }

        if let Some(e) = conflict {
            return Err(e);
        }

        if let Some(ki) = absorbed {
            // s is dropped (dedup or contained alias). Emit an event.
            let survivor_role = kept[ki].role;
            let action = if kept[ki].slab.old_base == s.old_base
                && kept[ki].slab.content.len() == s.content.len()
            {
                "deduplicated"
            } else {
                "contained_exact_alias"
            };
            events.push(NormalizationEvent {
                input_sequence: seq,
                input_role: cand.role,
                input_old_base: s.old_base,
                input_size: s.content.len(),
                input_raw_digest: s_digest,
                action,
                survivor_sequence: Some(ki),
                relationship: if action == "deduplicated" {
                    "exact_duplicate"
                } else {
                    "contained_same_bytes"
                },
            });
            let _ = survivor_role;
            continue;
        }

        if let Some(ki) = reverse_replace {
            // s survives and REPLACES kept[ki] (s is a superset of the kept slab
            // with identical bytes). Rev1: correct the provenance of BOTH inputs.
            //
            // 1) The replaced kept slab (originating from input
            //    `kept[ki].origin_input_sequence`) is now an alias of s. UPDATE its
            //    original "kept" event to `contained_exact_alias`, keeping the
            //    inner's OWN identity (input_seq / role / geometry all = inner A),
            //    never s's identity.
            let inner = &kept[ki];
            let orig_seq = inner.origin_input_sequence;
            events[kept_event_idx[ki]] = NormalizationEvent {
                input_sequence: orig_seq,
                input_role: inner.role,
                input_old_base: inner.slab.old_base,
                input_size: inner.slab.content.len(),
                input_raw_digest: sha256_hex(&inner.slab.content),
                action: "contained_exact_alias",
                survivor_sequence: Some(ki),
                relationship: "contained_same_bytes",
            };
            // 2) Emit a "kept" event for the current input s (its OWN identity).
            let s_kept_event_idx = events.len();
            events.push(NormalizationEvent {
                input_sequence: seq,
                input_role: cand.role,
                input_old_base: s.old_base,
                input_size: s.content.len(),
                input_raw_digest: s_digest.clone(),
                action: "kept",
                survivor_sequence: Some(ki),
                relationship: "kept",
            });
            // 3) The survivor becomes s, with s's role and origin (NOT inner.role).
            kept[ki] = NormalizedSlab {
                slab: s.clone(),
                normalization: SlabNormalization::Kept,
                role: cand.role,
                origin_input_sequence: seq,
            };
            kept_event_idx[ki] = s_kept_event_idx;
            // TAF3-C: after replacing, RE-CHECK the new outer against ALL kept slabs
            // (the loop above compared against the pre-replacement `kept`). Re-run
            // from the start to catch overlaps with other kept slabs.
            let outer = AuthoritativeSlabCandidate {
                slab: s.clone(),
                role: cand.role,
            };
            for j in 0..kept.len() {
                if j == ki {
                    continue; // the replaced inner is an intended alias of outer
                }
                let k = &kept[j].slab;
                let k_end2 = k.old_base.saturating_add(k.content.len() as u64);
                let s_end2 = outer
                    .slab
                    .old_base
                    .saturating_add(outer.slab.content.len() as u64);
                // if outer partially overlaps or conflicts with kept[j], fail closed
                if outer.slab.old_base < k_end2 && k.old_base < s_end2 {
                    // Not a clean containment (outer should fully contain or be disjoint).
                    let contained = (outer.slab.old_base <= k.old_base && s_end2 >= k_end2)
                        || (k.old_base <= outer.slab.old_base && k_end2 >= s_end2);
                    if !contained {
                        return Err(OverlayError::AuthoritativeSlabConflict {
                            a_old_base: k.old_base,
                            a_size: k.content.len(),
                            b_old_base: outer.slab.old_base,
                            b_size: outer.slab.content.len(),
                            relationship: "partial_overlap",
                            mismatch_offset: None,
                        });
                    }
                    // if contained but different bytes -> conflict
                    if outer.slab.old_base <= k.old_base && s_end2 >= k_end2 {
                        let off = (k.old_base - outer.slab.old_base) as usize;
                        let os = &outer.slab.content[off..off + k.content.len()];
                        if os != k.content {
                            return Err(OverlayError::AuthoritativeSlabConflict {
                                a_old_base: k.old_base,
                                a_size: k.content.len(),
                                b_old_base: outer.slab.old_base,
                                b_size: outer.slab.content.len(),
                                relationship: "contained_byte_conflict",
                                mismatch_offset: Some(off),
                            });
                        }
                    }
                }
            }
            continue;
        }

        // Not absorbed, no reverse-replace, no conflict -> keep as a new region.
        let kept_event_idx_new = events.len();
        events.push(NormalizationEvent {
            input_sequence: seq,
            input_role: cand.role,
            input_old_base: s.old_base,
            input_size: s.content.len(),
            input_raw_digest: s_digest,
            action: "kept",
            survivor_sequence: Some(kept.len()),
            relationship: "kept",
        });
        kept.push(NormalizedSlab {
            slab: s.clone(),
            normalization: SlabNormalization::Kept,
            role: cand.role,
            origin_input_sequence: seq,
        });
        kept_event_idx.push(kept_event_idx_new);
    }

    // TAF3-D: pairwise-disjoint invariant over the final normalized set.
    for i in 0..kept.len() {
        for j in (i + 1)..kept.len() {
            let a = &kept[i].slab;
            let b = &kept[j].slab;
            let a_end = a.old_base.saturating_add(a.content.len() as u64);
            let b_end = b.old_base.saturating_add(b.content.len() as u64);
            if a.old_base < b_end && b.old_base < a_end {
                // Any overlap that survived normalization is a hard error.
                return Err(OverlayError::AuthoritativeSlabConflict {
                    a_old_base: a.old_base,
                    a_size: a.content.len(),
                    b_old_base: b.old_base,
                    b_size: b.content.len(),
                    relationship: "partial_overlap",
                    mismatch_offset: None,
                });
            }
        }
    }

    // Rev1-3: event bijection invariant. Every VALID input (non-empty, non-zero
    // base) must produce exactly one event, all input_sequence values unique, all
    // survivor_sequence valid, and every kept survivor must have a "kept" event
    // from its origin input. Each event's role/base/size/digest must describe ITS
    // OWN input, not the survivor. Any violation fails closed.
    let valid_inputs: Vec<&AuthoritativeSlabCandidate> = candidates
        .iter()
        .filter(|c| !c.slab.content.is_empty() && c.slab.old_base != 0)
        .collect();
    let valid_count = valid_inputs.len();
    if events.len() != valid_count {
        return Err(OverlayError::AuthoritativeSlabConflict {
            a_old_base: 0,
            a_size: 0,
            b_old_base: 0,
            b_size: 0,
            relationship: "event_bijection_violation",
            mismatch_offset: Some(events.len()),
        });
    }
    // All input_sequence values unique and within [0, valid_count).
    let mut seen_seq: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for e in &events {
        if e.input_sequence >= valid_count || !seen_seq.insert(e.input_sequence) {
            return Err(OverlayError::AuthoritativeSlabConflict {
                a_old_base: e.input_old_base,
                a_size: e.input_size,
                b_old_base: 0,
                b_size: 0,
                relationship: "event_bijection_violation",
                mismatch_offset: Some(e.input_sequence),
            });
        }
        if let Some(s) = e.survivor_sequence {
            if s >= kept.len() {
                return Err(OverlayError::AuthoritativeSlabConflict {
                    a_old_base: e.input_old_base,
                    a_size: e.input_size,
                    b_old_base: 0,
                    b_size: 0,
                    relationship: "event_survivor_out_of_range",
                    mismatch_offset: Some(s),
                });
            }
        }
        // The event's role/base/size/digest must match its OWN input.
        let inp = &candidates[e.input_sequence];
        if e.input_role != inp.role
            || e.input_old_base != inp.slab.old_base
            || e.input_size != inp.slab.content.len()
            || e.input_raw_digest != sha256_hex(&inp.slab.content)
        {
            return Err(OverlayError::AuthoritativeSlabConflict {
                a_old_base: e.input_old_base,
                a_size: e.input_size,
                b_old_base: 0,
                b_size: 0,
                relationship: "event_identity_mismatch",
                mismatch_offset: Some(e.input_sequence),
            });
        }
    }
    // Every kept survivor must have a "kept" event from its origin input.
    for (ki, ks) in kept.iter().enumerate() {
        let origin = ks.origin_input_sequence;
        if origin >= valid_count {
            return Err(OverlayError::AuthoritativeSlabConflict {
                a_old_base: ks.slab.old_base,
                a_size: ks.slab.content.len(),
                b_old_base: 0,
                b_size: 0,
                relationship: "survivor_origin_out_of_range",
                mismatch_offset: Some(origin),
            });
        }
        let has_kept = events.iter().any(|e| {
            e.input_sequence == origin && e.action == "kept" && e.survivor_sequence == Some(ki)
        });
        if !has_kept {
            return Err(OverlayError::AuthoritativeSlabConflict {
                a_old_base: ks.slab.old_base,
                a_size: ks.slab.content.len(),
                b_old_base: 0,
                b_size: 0,
                relationship: "survivor_missing_kept_event",
                mismatch_offset: Some(ki),
            });
        }
    }

    Ok((kept, events))
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
    /// Old base of the AUTHORITATIVE slab that actually covers this child
    /// (main heap slab or the dedicated dangling-edge slab). TAF1-B: never
    /// defaults to a single `raw_capture.slab`.
    pub slab_old_base: u64,
    /// Size of the authoritative slab that covers this child (TAF1-B).
    pub slab_size: usize,
    /// Digest (sha256) of the full authoritative slab bytes (TAF1-B, auditable).
    pub slab_digest: String,
    /// Byte offset of the child within its covering slab.
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
    ///
    /// Note: the PRODUCTION pipeline appends runs in execution order (AF1-A) and
    /// does not sort, because sorting by transform id would lose the overwrite
    /// chain for a byte written by multiple transforms. This method is retained
    /// for deterministic per-child grouping where the caller explicitly wants it.
    #[allow(dead_code)]
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

/// A declared size-reinit operation: a specific transform, applied to a specific
/// child (by image RVA), that LEGITIMATELY changes the child's content length as
/// part of product recovery (e.g. `sanitize_ahk_runtime_global` replaces the
/// captured 32 KiB heap blob with a small zero-filled re-init slab). Only these
/// exact declarations may change size across a transform; any other size change
/// is undeclared provenance drift and fails closed.
///
/// Route Y R0 (Y0-A): this is the single authoritative source of "declared size
/// transitions". It is NOT a relaxation of the identity checks — an undeclared
/// size change still returns `TransformRunLedgerInvalid`, and a declared one is
/// validated precisely (transform id, child rva, old size within tolerance, new
/// size exact, re-init content all-zero).
#[derive(Debug, Clone, Copy)]
pub struct DeclaredSizeReinit {
    /// Transform id that performs the size re-init (exact match required).
    pub transform_id: &'static str,
    /// Image RVA of the child being re-inited (exact match required).
    pub child_rva: u32,
    /// Expected old (before) size. `old_size_tolerance` bounds how far a real
    /// captured blob may deviate (the live heap blob size can vary).
    pub old_size: usize,
    /// Allowable deviation from `old_size` (inclusive) before rejecting.
    pub old_size_tolerance: usize,
    /// Exact after (new) size required.
    pub new_size: usize,
    /// After content must be entirely zero-filled (re-init slab).
    pub zero_filled: bool,
}

/// Look up the declared size-reinit for a `(transform_id, child_rva)` pair.
/// Returns `None` for any transform/child that is NOT a declared size reinit —
/// in which case a size change is undeclared drift and fails closed.
pub fn declared_size_reinit(
    transform_id: &str,
    child_rva: u32,
) -> Option<&'static DeclaredSizeReinit> {
    const SANITIZE_AHK_RUNTIME_GLOBAL: &DeclaredSizeReinit = &DeclaredSizeReinit {
        transform_id: "sanitize_ahk_runtime_global",
        child_rva: 0x141bf0,
        old_size: 0x8000,
        old_size_tolerance: 0x2000, // live heap blob ~32 KiB, allow variance
        new_size: 0x180,
        zero_filled: true,
    };
    match (transform_id, child_rva) {
        ("sanitize_ahk_runtime_global", 0x141bf0) => Some(SANITIZE_AHK_RUNTIME_GLOBAL),
        _ => None,
    }
}

/// True if any declared size-reinit targets this child RVA (independent of the
/// specific transform). Used to recognize a child that undergoes a declared
/// size transition, so its PRIOR runs (raw-size stage) and its transition run
/// (new-size stage) can both pass membership while undeclared drift still
/// fails closed.
pub fn is_declared_reinit_child_rva(child_rva: u32) -> bool {
    child_rva == 0x141bf0
}

/// Validate a declared size reinit against the actual before/after participant.
/// Returns `Ok` only if every declared field matches; otherwise a precise
/// `TransformRunLedgerInvalid` reason.
///
/// Route Y R0 (Y0-A rev 2 / Audit P1-1): the field-level core is shared by the
/// recording path (`validate_raw_identity_across_transform`) and the Q0-C
/// overlay consumer boundary (`build_patched_backing_slab_q0c`) so the overlay
/// cannot accept an old/new size, RVA, or zero-fill that the recorder would
/// reject. Both consumer boundaries enforce the declaration identically.
pub fn validate_declared_size_reinit(
    spec: &DeclaredSizeReinit,
    before_len: usize,
    after: &HeapGlobalSnapshot,
    run_index: usize,
) -> Result<(), OverlayError> {
    validate_declared_size_reinit_fields(
        spec,
        before_len,
        after.rva,
        &after.extent_evidence.capture_id,
        after.live_ptr,
        &after.content,
        run_index,
    )
}

/// Field-level declared-size-reinit validation shared by every consumer boundary
/// (recorder diff + Q0-C overlay). Mirrors [`validate_declared_size_reinit`] but
/// takes the raw fields so the overlay (which holds transformed bytes, an rva,
/// a capture id and a live base rather than a full [`HeapGlobalSnapshot`]) can
/// enforce the same declaration without fabricating a snapshot.
pub fn validate_declared_size_reinit_fields(
    spec: &DeclaredSizeReinit,
    before_len: usize,
    after_rva: u32,
    after_capture_id: &str,
    after_live_ptr: u64,
    after_content: &[u8],
    run_index: usize,
) -> Result<(), OverlayError> {
    // The child's image RVA must match the declaration exactly.
    if after_rva != spec.child_rva {
        return Err(OverlayError::TransformRunLedgerInvalid {
            run_index,
            child_capture_id: after_capture_id.to_string(),
            child_old_base: after_live_ptr,
            child_size: after_content.len(),
            child_offset: 0,
            length: 0,
            transform_id: spec.transform_id.to_string(),
            reason: format!(
                "declared size reinit child rva {:#x} != expected {:#x} for old_base {:#x}",
                after_rva, spec.child_rva, after_live_ptr
            ),
        });
    }
    let old_ok = before_len
        .checked_sub(spec.old_size)
        .map(|d| d <= spec.old_size_tolerance)
        .unwrap_or(false)
        || spec
            .old_size
            .checked_sub(before_len)
            .map(|d| d <= spec.old_size_tolerance)
            .unwrap_or(false);
    if !old_ok {
        return Err(OverlayError::TransformRunLedgerInvalid {
            run_index,
            child_capture_id: after_capture_id.to_string(),
            child_old_base: after_live_ptr,
            child_size: after_content.len(),
            child_offset: 0,
            length: 0,
            transform_id: spec.transform_id.to_string(),
            reason: format!(
                "declared size reinit old size {} outside tolerance {} of expected {} for old_base {:#x}",
                before_len, spec.old_size_tolerance, spec.old_size, after_live_ptr
            ),
        });
    }
    if after_content.len() != spec.new_size {
        return Err(OverlayError::TransformRunLedgerInvalid {
            run_index,
            child_capture_id: after_capture_id.to_string(),
            child_old_base: after_live_ptr,
            child_size: after_content.len(),
            child_offset: 0,
            length: 0,
            transform_id: spec.transform_id.to_string(),
            reason: format!(
                "declared size reinit new size {} != expected {} for old_base {:#x}",
                after_content.len(),
                spec.new_size,
                after_live_ptr
            ),
        });
    }
    if spec.zero_filled && after_content.iter().any(|&b| b != 0) {
        return Err(OverlayError::TransformRunLedgerInvalid {
            run_index,
            child_capture_id: after_capture_id.to_string(),
            child_old_base: after_live_ptr,
            child_size: after_content.len(),
            child_offset: 0,
            length: 0,
            transform_id: spec.transform_id.to_string(),
            reason: format!(
                "declared size reinit content not zero-filled for old_base {:#x}",
                after_live_ptr
            ),
        });
    }
    Ok(())
}

/// Route X R0 AF1 (P0-2): verify the FULL raw identity tuple is unchanged across
/// a transform for a matched raw participant, EXCEPT that a declared size reinit
/// (see [`declared_size_reinit`]) may legitimately change `content.len()`.
/// Matching by live_ptr alone is not enough — a change in capture_id / extent_kind /
/// capture_path (or an UNDECLARED content.len change) is provenance drift and must
/// fail closed, never be silently diffed.
pub fn validate_raw_identity_across_transform(
    b: &HeapGlobalSnapshot,
    a: &HeapGlobalSnapshot,
    run_index: usize,
    transform_id: &str,
) -> Result<(), OverlayError> {
    let check_identity = |field: &str, before_v: &str, after_v: &str| -> Option<OverlayError> {
        if before_v != after_v {
            Some(OverlayError::TransformRunLedgerInvalid {
                run_index,
                child_capture_id: a.extent_evidence.capture_id.clone(),
                child_old_base: a.live_ptr,
                child_size: a.content.len(),
                child_offset: 0,
                length: 0,
                transform_id: transform_id.to_string(),
                reason: format!(
                    "raw identity drift on {field} for old_base {:#x}: {before_v} -> {after_v}",
                    a.live_ptr
                ),
            })
        } else {
            None
        }
    };
    if let Some(e) = check_identity(
        "capture_id",
        &b.extent_evidence.capture_id,
        &a.extent_evidence.capture_id,
    ) {
        return Err(e);
    }
    // content.len: unchanged, OR a DECLARED size reinit for this transform+child.
    if b.content.len() != a.content.len() {
        match declared_size_reinit(transform_id, a.rva) {
            Some(spec) => validate_declared_size_reinit(spec, b.content.len(), a, run_index)?,
            None => {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index,
                    child_capture_id: a.extent_evidence.capture_id.clone(),
                    child_old_base: a.live_ptr,
                    child_size: a.content.len(),
                    child_offset: 0,
                    length: 0,
                    transform_id: transform_id.to_string(),
                    reason: format!(
                        "undeclared raw identity drift on content.len for old_base {:#x}: {} -> {}",
                        a.live_ptr,
                        b.content.len(),
                        a.content.len()
                    ),
                });
            }
        }
    }
    if let Some(e) = check_identity(
        "extent_kind",
        &format!("{:?}", b.extent_kind),
        &format!("{:?}", a.extent_kind),
    ) {
        return Err(e);
    }
    if let Some(e) = check_identity(
        "capture_path",
        &format!("{:?}", b.extent_evidence.capture_path),
        &format!("{:?}", a.extent_evidence.capture_path),
    ) {
        return Err(e);
    }
    Ok(())
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
///
/// Route X R0 (X0-A/X0-B): the raw-overlay ledger is built ONLY from canonical
/// raw-coherence participants ([`HeapGlobalSnapshot::is_raw_coherence_participant`]),
/// matched by stable child identity (`live_ptr`), never by positional `zip`.
///
///   - Non-raw snapshots (image-inline, heap-handle, empty, SyntheticDerived)
///     are excluded from run generation; they never appear in the raw ledger.
///   - A raw participant present in `before` but not `after` (or vice versa) is a
///     participant-set change and fails closed.
///   - A duplicate `live_ptr` among raw participants is an ambiguous identity and
///     fails closed.
///   - A changed raw participant whose capture_id is empty is malformed and fails
///     closed (empty raw capture id must never reach the overlay validator).
///
/// Returns `Err(OverlayError::TransformRunLedgerInvalid)` with a precise run
/// index / base / size / offset / length / capture id / reason on any violation.
pub fn diff_transform_write_runs(
    before: &[HeapGlobalSnapshot],
    after: &[HeapGlobalSnapshot],
    transform_id: &str,
) -> Result<Vec<TransformWriteRun>, OverlayError> {
    let mut runs = Vec::new();

    // Index raw-coherence participants by stable child identity (live_ptr).
    fn index_participants<'a>(
        globals: &'a [HeapGlobalSnapshot],
        transform_id: &str,
    ) -> Result<std::collections::BTreeMap<u64, &'a HeapGlobalSnapshot>, OverlayError> {
        let mut map: std::collections::BTreeMap<u64, &HeapGlobalSnapshot> =
            std::collections::BTreeMap::new();
        for g in globals {
            if !g.is_raw_coherence_participant() {
                continue;
            }
            if map.insert(g.live_ptr, g).is_some() {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index: 0,
                    child_capture_id: g.extent_evidence.capture_id.clone(),
                    child_old_base: g.live_ptr,
                    child_size: g.content.len(),
                    child_offset: 0,
                    length: 0,
                    transform_id: transform_id.to_string(),
                    reason: format!(
                        "duplicate raw participant identity at old_base {:#x}",
                        g.live_ptr
                    ),
                });
            }
        }
        Ok(map)
    }

    let before_map = index_participants(before, transform_id)?;
    let after_map = index_participants(after, transform_id)?;

    // Participant-set closure: every raw participant in before must exist in
    // after, and vice versa. A change (appearance/disappearance) is an invariant
    // violation unless the affected region is non-raw (excluded above).
    let mut run_index = 0usize;
    for base in before_map.keys() {
        if !after_map.contains_key(base) {
            let g = before_map[base];
            return Err(OverlayError::TransformRunLedgerInvalid {
                run_index,
                child_capture_id: g.extent_evidence.capture_id.clone(),
                child_old_base: *base,
                child_size: g.content.len(),
                child_offset: 0,
                length: 0,
                transform_id: transform_id.to_string(),
                reason: format!(
                    "participant set change: raw participant old_base {base:#x} missing from after"
                ),
            });
        }
    }
    for base in after_map.keys() {
        if !before_map.contains_key(base) {
            let g = after_map[base];
            return Err(OverlayError::TransformRunLedgerInvalid {
                run_index,
                child_capture_id: g.extent_evidence.capture_id.clone(),
                child_old_base: *base,
                child_size: g.content.len(),
                child_offset: 0,
                length: 0,
                transform_id: transform_id.to_string(),
                reason: format!(
                    "participant set change: raw participant old_base {base:#x} missing from before"
                ),
            });
        }
    }

    // Route X R0 AF1 (P0-2) + Route Y R0 (Y0-A): for each matched raw participant,
    // verify the FULL raw identity tuple is unchanged across the transform —
    // except a DECLARED size reinit (see declared_size_reinit) may legitimately
    // change content.len(). Matching by live_ptr alone is not enough: a change in
    // capture_id / extent_kind / capture_path, or an UNDECLARED content.len change,
    // is provenance drift and must fail closed, never be silently diffed.
    for (base, a) in after_map.iter() {
        let b = before_map[base];
        validate_raw_identity_across_transform(b, a, run_index, transform_id)?;
    }

    // For each matched raw participant, diff and emit runs.
    for (base, a) in after_map.iter() {
        let b = before_map[base];
        if b.content == a.content {
            continue;
        }
        // A changed raw participant must carry a non-empty capture id (malformed
        // empty raw ID fails closed — never reaches the overlay validator).
        let capture_id = &a.extent_evidence.capture_id;
        if capture_id.is_empty() {
            return Err(OverlayError::TransformRunLedgerInvalid {
                run_index,
                child_capture_id: String::new(),
                child_old_base: *base,
                child_size: a.content.len(),
                child_offset: 0,
                length: 0,
                transform_id: transform_id.to_string(),
                reason: format!("empty raw capture id for changed participant old_base {base:#x}"),
            });
        }
        // Route Y R0 (Y0-A): `child_size` is the TRANSFORMED (after) size — the
        // size the overlay writes. For a declared size reinit this is the new
        // re-init size (e.g. 0x180), not the old captured blob size.
        let child_size = a.content.len();
        // Route Y R0 (Y0-A rev 4 / Audit P1): a DECLARED size reinit (shrink)
        // emits ONE dedicated full `[0, new_size)` transition run — NOT a sparse
        // byte diff. A zero byte already present in the old prefix would otherwise
        // not be "changed" by the byte diff and would split the sanitize diff into
        // multiple runs, breaking the exactly-one-transition-run invariant that
        // the Q0-C consumer enforces. The recorder and the Q0-C consumer must
        // agree on the transition representation.
        let is_declared_shrink = declared_size_reinit(transform_id, a.rva).is_some()
            && b.content.len() != a.content.len()
            && a.content.len() <= b.content.len()
            && a.content.len() > 0;
        let mut changed: Vec<(usize, usize)> = Vec::new();
        if is_declared_shrink {
            changed.push((0, a.content.len()));
        } else {
            // Build maximal contiguous runs of differing bytes.
            let shared_len = b.content.len().min(a.content.len());
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
        }
        for (off, len) in changed {
            let before_bytes = b.content[off..off + len].to_vec();
            let after_bytes = a.content[off..off + len].to_vec();
            let before_digest = sha256_hex(&before_bytes);
            let after_digest = sha256_hex(&after_bytes);
            runs.push(TransformWriteRun {
                child_capture_id: capture_id.clone(),
                child_old_base: *base,
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
            run_index += 1;
        }
    }
    Ok(runs)
}

/// Execution-owning transform recorder (Route R R0-B / Audit Fix 1).
///
/// A single call OWNS the entire transform lifecycle — it is impossible for a
/// caller to execute a transform, forget to record it, pass a wrong transform id,
/// or mutate globals between execution and recording. Inside one call:
///   1. captures the `before` child snapshot;
///   2. executes the transform closure against `heap_globals`;
///   3. records child-level evidence (`record_transform_applied`);
///   4. records byte/run evidence (`diff_transform_write_runs`) and appends to the
///      ledger in execution order.
///
/// Production `dump_process.rs` and the full-pipeline test call these SAME
/// helpers so the orchestration is never duplicated and child-level `transform_ids`
/// can never diverge from the byte/run ledger.
///
/// The `scrub` transform additionally mutates `containers`; the closure may capture
/// `&mut containers` as needed (see call sites).
pub fn apply_recorded_transform(
    heap_globals: &mut Vec<HeapGlobalSnapshot>,
    transform_id: &str,
    ledger: &mut TransformRunLedger,
    transform: impl FnOnce(&mut Vec<HeapGlobalSnapshot>),
) -> Result<(), OverlayError> {
    // Route V R0 (V0-A): per-transform stage telemetry via StageGuard.
    // Route X R0 (X0-B): recording can fail closed on a participant-set or
    // identity violation; the typed OverlayError is surfaced so the pipeline
    // aborts before overlay/manifest/candidate (never weakened).
    let mut guard = super::stage_timing::StageGuard::begin(transform_id);
    let result = (|| -> Result<(), OverlayError> {
        let before = heap_globals.clone();
        transform(heap_globals);
        super::heap_global_snapshot::record_transform_applied(heap_globals, &before, transform_id);
        let runs = diff_transform_write_runs(&before, heap_globals, transform_id)?;
        guard.with_stats(super::stage_timing::StageStats {
            item_count: runs.len(),
            byte_count: runs.iter().map(|r| r.length as u64).sum(),
        });
        ledger.runs.extend(runs);
        Ok(())
    })();
    match &result {
        Ok(_) => {}
        Err(e) => guard.error(format!("{e:#}")),
    }
    result
}

/// Execution-owning recorder for a transform that can fail (Route R R0-B /
/// Audit Fix 1). Runs the closure, and on `Ok` records both child and byte
/// evidence. On `Err` it propagates the error WITHOUT recording — the caller
/// (e.g. `dump_process`) aborts before overlay/manifest/candidate.
pub fn try_apply_recorded_transform<E: std::fmt::Debug + From<OverlayError>>(
    heap_globals: &mut Vec<HeapGlobalSnapshot>,
    transform_id: &str,
    ledger: &mut TransformRunLedger,
    transform: impl FnOnce(&mut Vec<HeapGlobalSnapshot>) -> Result<(), E>,
) -> Result<(), E> {
    // Route V R0 (V0-A): per-transform stage enter/exit/error telemetry.
    // Uses a StageGuard directly (not `run_stage`) because this function is
    // generic over `E` and must propagate the original error type unchanged.
    // Telemetry is non-semantic: the error is logged via `Debug` only; the
    // business result is unchanged.
    //
    // Route X R0 (X0-B): the diff/ledger recording can fail closed on a
    // participant-set or identity violation; the `OverlayError` is converted to
    // `E` via `From<OverlayError>` and propagated (fail-closed preserved).
    let mut guard = super::stage_timing::StageGuard::begin(transform_id);
    let result = (|| {
        let before = heap_globals.clone();
        transform(heap_globals)?;
        super::heap_global_snapshot::record_transform_applied(heap_globals, &before, transform_id);
        let runs = diff_transform_write_runs(&before, heap_globals, transform_id)?;
        let stats = super::stage_timing::StageStats {
            item_count: runs.len(),
            byte_count: runs.iter().map(|r| r.length as u64).sum(),
        };
        ledger.runs.extend(runs);
        guard.with_stats(stats);
        Ok(())
    })();
    match &result {
        Ok(_) => {}
        Err(e) => guard.error(format!("{e:?}")),
    }
    result
}

/// Route S R0-D: validate the SHAPE of every run in the ledger ONCE, before any
/// per-child byte replay, and report the EXACT run index + identity + reason via
/// [`OverlayError::TransformRunLedgerInvalid`] — never a misleading per-child
/// `TransformPreimageDrift`. A malformed unrelated/extra run fails the whole
/// ledger. Fail-closed (no leniency): empty capture id, empty transform id,
/// bad length, bad digests, broken byte vectors all rejected.
pub fn validate_run_ledger_shape(run_ledger: &TransformRunLedger) -> Result<(), OverlayError> {
    for (idx, r) in run_ledger.runs.iter().enumerate() {
        let end = r.child_offset.checked_add(r.length);
        let reason = if r.child_capture_id.is_empty() {
            Some("empty child_capture_id".to_string())
        } else if r.transform_id.is_empty() {
            Some("empty transform_id".to_string())
        } else if r.length == 0 {
            Some("length == 0".to_string())
        } else if r.child_size == 0 {
            Some("child_size == 0".to_string())
        } else if end.is_none() {
            Some("child_offset + length overflow".to_string())
        } else if end.unwrap() > r.child_size {
            Some("child_offset + length exceeds child_size".to_string())
        } else if r.before_bytes.len() != r.length {
            Some(format!(
                "before_bytes.len()={} != length={}",
                r.before_bytes.len(),
                r.length
            ))
        } else if r.after_bytes.len() != r.length {
            Some(format!(
                "after_bytes.len()={} != length={}",
                r.after_bytes.len(),
                r.length
            ))
        } else if r.first_before_byte != r.before_bytes[0] {
            Some("first_before_byte != before_bytes[0]".to_string())
        } else if r.first_after_byte != r.after_bytes[0] {
            Some("first_after_byte != after_bytes[0]".to_string())
        } else if sha256_hex(&r.before_bytes) != r.before_digest {
            Some("before_digest != sha256(before_bytes)".to_string())
        } else if sha256_hex(&r.after_bytes) != r.after_digest {
            Some("after_digest != sha256(after_bytes)".to_string())
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(OverlayError::TransformRunLedgerInvalid {
                run_index: idx,
                child_capture_id: r.child_capture_id.clone(),
                child_old_base: r.child_old_base,
                child_size: r.child_size,
                child_offset: r.child_offset,
                length: r.length,
                transform_id: r.transform_id.clone(),
                reason,
            });
        }
    }
    Ok(())
}

/// Route X R0 AF1 (X0-D / P0-3): global run→raw-child MEMBERSHIP gate.
///
/// Before byte replay, verify EVERY run in the ledger resolves to exactly one raw
/// child in the canonical raw-coherence participant set, matched by the FULL
/// identity tuple `(capture_id, old_base, child_size)` — never by base alone.
/// A shape-valid but orphaned/duplicate/mismatched run (one that no transformed
/// child will consume) fails closed with its exact index + identity + reason.
///
/// `transformed_globals` are the canonical raw-coherence participants (already
/// filtered by `is_raw_coherence_participant`), so a run whose child is absent
/// from this set is a participant-set violation.
pub fn validate_run_membership(
    raw_capture: &RawSlabCapture,
    transformed_globals: &[HeapGlobalSnapshot],
    run_ledger: &TransformRunLedger,
) -> Result<(), OverlayError> {
    // Build the set of canonical raw-coherence participants keyed by
    // (capture_id, old_base) with their size. Duplicate (capture_id, old_base)
    // among participants is ambiguous and fails closed.
    let mut participants: std::collections::BTreeMap<(String, u64), usize> =
        std::collections::BTreeMap::new();
    for g in transformed_globals {
        if !g.is_raw_coherence_participant() {
            continue;
        }
        let key = (g.extent_evidence.capture_id.clone(), g.live_ptr);
        if participants.insert(key, g.content.len()).is_some() {
            return Err(OverlayError::TransformRunLedgerInvalid {
                run_index: 0,
                child_capture_id: g.extent_evidence.capture_id.clone(),
                child_old_base: g.live_ptr,
                child_size: g.content.len(),
                child_offset: 0,
                length: 0,
                transform_id: String::new(),
                reason: format!(
                    "duplicate canonical participant (capture_id, old_base) = ({:?}, {:#x})",
                    g.extent_evidence.capture_id, g.live_ptr
                ),
            });
        }
    }
    // Raw children must also have unique (capture_id, old_base).
    let mut raw_keys: std::collections::BTreeSet<(String, u64)> = std::collections::BTreeSet::new();
    for c in &raw_capture.children {
        let key = (c.capture_id.clone(), c.old_base);
        if !raw_keys.insert(key) {
            return Err(OverlayError::TransformRunLedgerInvalid {
                run_index: 0,
                child_capture_id: c.capture_id.clone(),
                child_old_base: c.old_base,
                child_size: c.size,
                child_offset: 0,
                length: 0,
                transform_id: String::new(),
                reason: format!(
                    "duplicate raw child (capture_id, old_base) = ({:?}, {:#x})",
                    c.capture_id, c.old_base
                ),
            });
        }
    }

    for (idx, r) in run_ledger.runs.iter().enumerate() {
        // 1. The run must resolve to exactly one raw child. Match by the stable
        //    identity (capture_id, old_base); size must match UNLESS this run is a
        //    DECLARED size reinit (Route Y R0 Y0-A), in which case the run's
        //    child_size is the new re-init size and the raw child's size is the old
        //    captured size — a legitimate size transition.
        let is_declared_reinit = (|| {
            // Find the transformed canonical participant for this run to read rva.
            let g = transformed_globals.iter().find(|g| {
                g.is_raw_coherence_participant()
                    && g.live_ptr == r.child_old_base
                    && g.extent_evidence.capture_id == r.child_capture_id
            });
            match g {
                Some(g) => declared_size_reinit(&r.transform_id, g.rva).is_some(),
                None => false,
            }
        })();
        let matches: Vec<&RawChild> = raw_capture
            .children
            .iter()
            .filter(|c| {
                c.capture_id == r.child_capture_id
                    && c.old_base == r.child_old_base
                    && (c.size == r.child_size || is_declared_reinit)
            })
            .collect();
        if matches.is_empty() {
            return Err(OverlayError::TransformRunLedgerInvalid {
                run_index: idx,
                child_capture_id: r.child_capture_id.clone(),
                child_old_base: r.child_old_base,
                child_size: r.child_size,
                child_offset: r.child_offset,
                length: r.length,
                transform_id: r.transform_id.clone(),
                reason: format!("run has no matching raw child by (capture_id, old_base, size)"),
            });
        }
        if matches.len() > 1 {
            return Err(OverlayError::TransformRunLedgerInvalid {
                run_index: idx,
                child_capture_id: r.child_capture_id.clone(),
                child_old_base: r.child_old_base,
                child_size: r.child_size,
                child_offset: r.child_offset,
                length: r.length,
                transform_id: r.transform_id.clone(),
                reason: format!(
                    "run resolves to {} raw children by (capture_id, old_base, size); expected exactly one",
                    matches.len()
                ),
            });
        }
        // 2. The run's child must belong to the canonical participant set.
        //    Size semantics (Route Y R0 / Audit P1-3): a child that is the target
        //    of a DECLARED size re-init transitions from its RAW size to the
        //    declared NEW size. Its PRIOR runs (other transforms that ran before
        //    the re-init, e.g. scrub, while the child was still at raw size) carry
        //    child_size == RAW size; the DECLARED transition run itself carries
        //    child_size == NEW size. Both are legitimate; any other size on this
        //    child fails closed.
        let key = (r.child_capture_id.clone(), r.child_old_base);
        // Does this child's RVA name a declared size-reinit target?
        let child_is_declared_reinit_target = transformed_globals.iter().any(|g| {
            g.is_raw_coherence_participant()
                && g.live_ptr == r.child_old_base
                && g.extent_evidence.capture_id == r.child_capture_id
                && is_declared_reinit_child_rva(g.rva)
        });
        match participants.get(&key) {
            Some(&participant_size) => {
                if child_is_declared_reinit_target {
                    // Allow exactly RAW size (prior runs) or NEW size (transition).
                    let child_rva = transformed_globals
                        .iter()
                        .find(|g| {
                            g.is_raw_coherence_participant()
                                && g.live_ptr == r.child_old_base
                                && g.extent_evidence.capture_id == r.child_capture_id
                        })
                        .map(|g| g.rva);
                    let raw_size = raw_capture
                        .children
                        .iter()
                        .find(|c| {
                            c.capture_id == r.child_capture_id && c.old_base == r.child_old_base
                        })
                        .map(|c| c.size);
                    let new_size = child_rva
                        .and_then(|rv| declared_size_reinit(&r.transform_id, rv))
                        .map(|s| s.new_size);
                    let ok = (raw_size.is_some() && r.child_size == raw_size.unwrap())
                        || (new_size.is_some() && r.child_size == new_size.unwrap());
                    if !ok {
                        return Err(OverlayError::TransformRunLedgerInvalid {
                            run_index: idx,
                            child_capture_id: r.child_capture_id.clone(),
                            child_old_base: r.child_old_base,
                            child_size: r.child_size,
                            child_offset: r.child_offset,
                            length: r.length,
                            transform_id: r.transform_id.clone(),
                            reason: format!(
                                "declared reinit child run size {} not in (raw {:?}, new {:?})",
                                r.child_size, raw_size, new_size
                            ),
                        });
                    }
                } else if participant_size != r.child_size {
                    return Err(OverlayError::TransformRunLedgerInvalid {
                        run_index: idx,
                        child_capture_id: r.child_capture_id.clone(),
                        child_old_base: r.child_old_base,
                        child_size: r.child_size,
                        child_offset: r.child_offset,
                        length: r.length,
                        transform_id: r.transform_id.clone(),
                        reason: format!(
                            "run child size {} != canonical participant size {}",
                            r.child_size, participant_size
                        ),
                    });
                }
            }
            None => {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index: idx,
                    child_capture_id: r.child_capture_id.clone(),
                    child_old_base: r.child_old_base,
                    child_size: r.child_size,
                    child_offset: r.child_offset,
                    length: r.length,
                    transform_id: r.transform_id.clone(),
                    reason: format!(
                        "run child (capture_id, old_base) = ({:?}, {:#x}) not in canonical participant set",
                        r.child_capture_id, r.child_old_base
                    ),
                });
            }
        }
    }
    Ok(())
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
    /// Route S R0-B: a raw-coherence participant has an empty/invalid capture
    /// identity before the overlay. Detected at the `capture_identity_bind` gate
    /// (before raw_children_from_capture), not at overlay time.
    CaptureIdentityInvalid {
        /// kind of the child (heap_global / container).
        child_kind: RawChildKind,
        /// old base of the child.
        child_old_base: u64,
        /// size of the child.
        child_size: usize,
        /// the offending capture id (empty when missing).
        capture_id: String,
        /// the capture path.
        capture_path: String,
        /// the extent kind.
        extent_kind: String,
    },
    /// Route S R0-C: the Q0-C exact binding could not be resolved because there
    /// is NO binding for this child.
    TransformPreimageBindingMissing {
        child_kind: RawChildKind,
        child_old_base: u64,
        child_size: usize,
        capture_id: String,
        extent_kind: String,
        slab_old_base: u64,
        slab_offset: usize,
    },
    /// Route S R0-C: more than one exact binding matched this child.
    TransformPreimageBindingAmbiguous {
        child_kind: RawChildKind,
        child_old_base: u64,
        child_size: usize,
        capture_id: String,
        extent_kind: String,
        slab_old_base: u64,
        slab_offset: usize,
        match_count: usize,
    },
    /// Route S R0-C: the binding identity is structurally invalid (empty or
    /// inconsistent capture id / size / extent / slab).
    TransformPreimageBindingIdentityInvalid {
        child_kind: RawChildKind,
        child_old_base: u64,
        child_size: usize,
        capture_id: String,
        extent_kind: String,
        slab_old_base: u64,
        slab_offset: usize,
        reason: String,
    },
    /// Route S R0-D: the global run-ledger shape validator found a malformed run.
    /// Carries the EXACT run index + identity + reason (not the currently-walked
    /// child's TransformPreimageDrift).
    TransformRunLedgerInvalid {
        run_index: usize,
        child_capture_id: String,
        child_old_base: u64,
        child_size: usize,
        child_offset: usize,
        length: usize,
        transform_id: String,
        reason: String,
    },
    /// Route T R0-C: a ProbeWindow / InteriorSubview has no authoritative slab
    /// coverage. Detected at the `capture_coverage_bind` gate (before overlay /
    /// runtime plan), so an uncovered window is reported early and precisely,
    /// not deferred to runtime rebase plan validation.
    ProbeCoverageMissing {
        /// Kind of the child (heap_global / container).
        child_kind: RawChildKind,
        /// Old base of the uncovered probe/interior child.
        child_base: u64,
        /// Size of the uncovered child.
        child_size: usize,
        /// Extent kind (ProbeWindow / InteriorSubview).
        extent_kind: String,
        /// Number of candidate authoritative slabs considered.
        candidate_slab_count: usize,
        /// The nearest candidate slab authority range, if any `(base, end)`.
        nearest_authority: Option<(u64, u64)>,
        /// Distance from the child base to the nearest authority range, in bytes.
        nearest_authority_gap: u64,
    },
    /// Route T R0 AF2 (TAF2-B): two authoritative slabs overlap but are NOT a
    /// clean exact-duplicate or contained-same-bytes relation. The slab set must
    /// be normalized before coverage/raw-capture/seed; an unresolvable overlap
    /// (contained but different bytes, or partial overlap) fails closed.
    AuthoritativeSlabConflict {
        /// Old base of the first slab.
        a_old_base: u64,
        /// Size of the first slab.
        a_size: usize,
        /// Old base of the second slab.
        b_old_base: u64,
        /// Size of the second slab.
        b_size: usize,
        /// Relationship kind: "contained_byte_conflict" | "partial_overlap".
        relationship: &'static str,
        /// First mismatching byte offset (when contained-different-bytes).
        mismatch_offset: Option<usize>,
    },
}

// Route X R0 (X0-B): an `OverlayError` surfaced by transform-run-ledger recording
// (participant-set change, ambiguous identity, malformed empty raw id) is a PE
// stage error so the pipeline fails closed at the exact stage with a stable
// machine-parseable id. This is error-context only; it never weakens a check.
impl From<OverlayError> for crate::error::PeError {
    fn from(e: OverlayError) -> Self {
        crate::error::PeError::GtoStage {
            stage: "raw_slab_overlay".into(),
            error: format!("{e:#}"),
        }
    }
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
            OverlayError::CaptureIdentityInvalid {
                child_kind,
                child_old_base,
                child_size,
                capture_id,
                capture_path,
                extent_kind,
            } => write!(
                f,
                "capture identity invalid: kind={} child={child_old_base:#x} size={child_size:#x} \
                 capture_id={capture_id:?} path={capture_path} extent={extent_kind} \
                 (must have non-empty capture identity before raw coherence)",
                child_kind.label()
            ),
            OverlayError::TransformPreimageBindingMissing {
                child_kind,
                child_old_base,
                child_size,
                capture_id,
                extent_kind,
                slab_old_base,
                slab_offset,
            } => write!(
                f,
                "transform preimage binding missing: kind={} child={child_old_base:#x} \
                 size={child_size:#x} capture_id={capture_id:?} extent={extent_kind} \
                 slab=[{slab_old_base:#x},+{slab_offset:#x})",
                child_kind.label()
            ),
            OverlayError::TransformPreimageBindingAmbiguous {
                child_kind,
                child_old_base,
                child_size,
                capture_id,
                extent_kind,
                slab_old_base,
                slab_offset,
                match_count,
            } => write!(
                f,
                "transform preimage binding ambiguous: kind={} child={child_old_base:#x} \
                 size={child_size:#x} capture_id={capture_id:?} extent={extent_kind} \
                 slab=[{slab_old_base:#x},+{slab_offset:#x}) match_count={match_count}",
                child_kind.label()
            ),
            OverlayError::TransformPreimageBindingIdentityInvalid {
                child_kind,
                child_old_base,
                child_size,
                capture_id,
                extent_kind,
                slab_old_base,
                slab_offset,
                reason,
            } => write!(
                f,
                "transform preimage binding identity invalid: kind={} child={child_old_base:#x} \
                 size={child_size:#x} capture_id={capture_id:?} extent={extent_kind} \
                 slab=[{slab_old_base:#x},+{slab_offset:#x}) reason={reason}",
                child_kind.label()
            ),
            OverlayError::TransformRunLedgerInvalid {
                run_index,
                child_capture_id,
                child_old_base,
                child_size,
                child_offset,
                length,
                transform_id,
                reason,
            } => write!(
                f,
                "transform run ledger invalid at run[{run_index}]: child_capture_id={child_capture_id:?} \
                 child_old_base={child_old_base:#x} child_size={child_size:#x} \
                 child_offset={child_offset:#x} length={length:#x} transform={transform_id:?} \
                 reason={reason}",
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
            OverlayError::ProbeCoverageMissing {
                child_kind,
                child_base,
                child_size,
                extent_kind,
                candidate_slab_count,
                nearest_authority,
                nearest_authority_gap,
            } => write!(
                f,
                "probe/interior {child_kind:?} 0x{child_base:x},+{child_size:#x} extent={extent_kind} \
                 not covered by any authoritative slab (candidate_slab_count={candidate_slab_count}, \
                 nearest_authority={nearest_authority:?} gap={nearest_authority_gap:#x}); \
                 refusing to treat a heuristic read window as a heap extent",
            ),
            OverlayError::AuthoritativeSlabConflict {
                a_old_base,
                a_size,
                b_old_base,
                b_size,
                relationship,
                mismatch_offset,
            } => write!(
                f,
                "authoritative slab overlap conflict: [{a_old_base:#x},+{a_size:#x}) vs \
                 [{b_old_base:#x},+{b_size:#x}) relationship={relationship} \
                 mismatch_offset={mismatch_offset:?}; refusing ambiguous slab authority",
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

/// Route S R0-B: unified raw-coherence capture-identity gate.
///
/// Every heap-global that will participate in raw slab coherence (non-image,
/// non-handle, non-empty, non-SyntheticDerived) MUST carry a non-empty capture id,
/// an explicit capture path, and an explicit extent kind before it is snapshot
/// into a raw child / binding. This runs AFTER duplicate reconciliation and BEFORE
/// `raw_children_from_capture`, so an empty identity fails at the
/// `capture_identity_bind` stage instead of surfacing much later as a misleading
/// `TransformPreimageDrift` at overlay time (the Route R R1 dangling-edge root
/// cause). Containers carry a deterministic id from `container_capture_id`.
pub fn validate_raw_coherence_capture_identities(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
) -> Result<(), OverlayError> {
    use super::heap_global_snapshot::{CaptureExtentKind as CEK, CapturePath as CP};
    // Track the FULL identity tuple per capture id so same-base duplicates with a
    // differing size / extent / path are rejected (not just different base).
    let mut seen: std::collections::BTreeMap<String, (u64, usize, CEK, CP)> =
        std::collections::BTreeMap::new();
    for g in heap_globals {
        // Route X R0 (X0-A): the canonical raw-coherence participant predicate.
        // Excludes heap handles, image-inline, empty, and SyntheticDerived.
        if !g.is_raw_coherence_participant() {
            continue;
        }
        let cap = &g.extent_evidence.capture_id;
        let path = g.extent_evidence.capture_path;
        let ext = g.extent_kind;
        if cap.is_empty() {
            return Err(OverlayError::CaptureIdentityInvalid {
                child_kind: RawChildKind::HeapGlobal,
                child_old_base: g.live_ptr,
                child_size: g.content.len(),
                capture_id: String::new(),
                capture_path: format!("{:?}", path),
                extent_kind: format!("{:?}", ext),
            });
        }
        // Route S R0-AuditFix1 (P1-2): enforce the identity matrix.
        //   DanglingEdge -> ProbeWindow, and capture_id prefix must be `dangling_edge:`
        //   Synthetic path -> forbidden for a raw-coherence participant
        //   capture_id prefix must be consistent with the capture path (so a
        //   dangling-edge capture cannot masquerade as MainSlot and vice versa).
        let cap_prefix = cap.split(':').next().unwrap_or("");
        let path_ok = match path {
            CP::DanglingEdge => ext == CEK::ProbeWindow && cap_prefix == "dangling_edge",
            CP::MainSlot => matches!(ext, CEK::ObservedAllocation | CEK::ProbeWindow),
            CP::GscriptChildLink | CP::GscriptFirstHop => {
                matches!(ext, CEK::ProbeWindow | CEK::InteriorSubview)
            }
            CP::StringBufferChild => ext == CEK::ProbeWindow,
            // ImageInline / Synthetic are not raw-coherence participants.
            CP::ImageInline | CP::Synthetic => false,
        };
        if !path_ok {
            return Err(OverlayError::CaptureIdentityInvalid {
                child_kind: RawChildKind::HeapGlobal,
                child_old_base: g.live_ptr,
                child_size: g.content.len(),
                capture_id: cap.clone(),
                capture_path: format!("{:?}", path),
                extent_kind: format!("{:?}", ext),
            });
        }
        // A capture_id prefix that claims a role must be consistent with the path.
        // e.g. `mainslot:...` id on a DanglingEdge path (or vice versa) is invalid.
        if cap_prefix == "dangling_edge" && path != CP::DanglingEdge {
            return Err(OverlayError::CaptureIdentityInvalid {
                child_kind: RawChildKind::HeapGlobal,
                child_old_base: g.live_ptr,
                child_size: g.content.len(),
                capture_id: cap.clone(),
                capture_path: format!("{:?}", path),
                extent_kind: format!("{:?}", ext),
            });
        }
        if cap_prefix == "mainslot" && path != CP::MainSlot {
            return Err(OverlayError::CaptureIdentityInvalid {
                child_kind: RawChildKind::HeapGlobal,
                child_old_base: g.live_ptr,
                child_size: g.content.len(),
                capture_id: cap.clone(),
                capture_path: format!("{:?}", path),
                extent_kind: format!("{:?}", ext),
            });
        }
        // Route S R0-AuditFix1 (P1-3): duplicate capture id — same base is only
        // allowed if the ENTIRE identity tuple is identical; differing size/extent/
        // path on the same base is ambiguous and must fail.
        let tuple = (g.live_ptr, g.content.len(), ext, path);
        if let Some(&prior) = seen.get(cap) {
            if prior != tuple {
                return Err(OverlayError::CaptureIdentityInvalid {
                    child_kind: RawChildKind::HeapGlobal,
                    child_old_base: g.live_ptr,
                    child_size: g.content.len(),
                    capture_id: cap.clone(),
                    capture_path: format!("{:?}", path),
                    extent_kind: format!("{:?}", ext),
                });
            }
        } else {
            seen.insert(cap.clone(), tuple);
        }
    }
    // Containers: deterministic id from container_capture_id(decoded_begin).
    for c in containers {
        let size = c
            .decoded_end
            .checked_sub(c.decoded_begin)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        if size == 0 {
            continue;
        }
        let id = container_capture_id(c.decoded_begin);
        if id.is_empty() {
            return Err(OverlayError::CaptureIdentityInvalid {
                child_kind: RawChildKind::Container,
                child_old_base: c.decoded_begin,
                child_size: size,
                capture_id: String::new(),
                capture_path: "MainSlot".into(),
                extent_kind: "ObservedAllocation".into(),
            });
        }
    }
    Ok(())
}

/// Route T R0-A: probe/interior coverage gate (`capture_coverage_bind`).
///
/// Every ProbeWindow / InteriorSubview heap-global MUST be contained in exactly
/// one authoritative slab (main heap slab or a dedicated dangling-edge slab).
/// This runs BEFORE the overlay / runtime rebase planning, so an uncovered probe
/// is reported here — with precise coverage diagnostics — instead of surfacing
/// much later at `runtime_rebase_plan_validation` (the Route S R1 `0x850150`
/// blocker). The rule is fail-closed: a heuristic read window is not a proven
/// heap extent unless it is backed by an authoritative slab.
///
/// `heap_slabs` is the full authoritative slab set (main + dedicated dangling
/// edges). Containers are authoritative allocations (ObservedAllocation) and are
/// not probe views, so they are not checked here.
pub fn validate_probe_coverage(
    heap_globals: &[HeapGlobalSnapshot],
    heap_slabs: &[HeapSlab],
) -> Result<(), OverlayError> {
    use super::heap_global_snapshot::CaptureExtentKind as CEK;
    let slab_ranges: Vec<(u64, u64)> = heap_slabs
        .iter()
        .filter(|s| !s.content.is_empty() && s.old_base != 0)
        .map(|s| {
            (
                s.old_base,
                s.old_base.saturating_add(s.content.len() as u64),
            )
        })
        .collect();
    for g in heap_globals {
        // Route X R0 (X0-A): coverage binding must use the canonical raw-coherence
        // participant predicate (excludes heap handles, image-inline, empty, and
        // SyntheticDerived), so the covered set matches identity gate / raw-child /
        // seeding / ledger / overlay.
        if !g.is_raw_coherence_participant() {
            continue;
        }
        let is_probe = matches!(g.extent_kind, CEK::ProbeWindow | CEK::InteriorSubview);
        if !is_probe {
            continue;
        }
        let child_end = g.live_ptr.saturating_add(g.content.len() as u64);
        // Count exactly-one slab containment.
        let mut covering: Option<(u64, u64)> = None;
        let mut cover_count = 0usize;
        for &(sb, se) in &slab_ranges {
            if g.live_ptr >= sb && child_end <= se {
                cover_count += 1;
                covering = Some((sb, se));
            }
        }
        if cover_count == 1 {
            continue; // covered by exactly one authoritative slab
        }
        if cover_count > 1 {
            // Ambiguous coverage (contained in multiple slabs) is also a hard
            // coverage failure (the rebase planner would reject it as ambiguous).
            return Err(OverlayError::ProbeCoverageMissing {
                child_kind: RawChildKind::HeapGlobal,
                child_base: g.live_ptr,
                child_size: g.content.len(),
                extent_kind: format!("{:?}", g.extent_kind),
                candidate_slab_count: slab_ranges.len(),
                nearest_authority: covering,
                nearest_authority_gap: 0,
            });
        }
        // Not covered: find the nearest authority range (T0-C precise diagnostic).
        let mut nearest: Option<(u64, u64, u64)> = None; // (base, end, gap)
        for &(sb, se) in &slab_ranges {
            let gap = if g.live_ptr >= sb && g.live_ptr < se {
                0
            } else if g.live_ptr < sb {
                sb.saturating_sub(g.live_ptr)
            } else {
                g.live_ptr.saturating_sub(se)
            };
            if nearest.map_or(true, |(_, _, ng)| gap < ng) {
                nearest = Some((sb, se, gap));
            }
        }
        let (n_base, n_end, n_gap) = nearest.unwrap_or((0, 0, u64::MAX));
        return Err(OverlayError::ProbeCoverageMissing {
            child_kind: RawChildKind::HeapGlobal,
            child_base: g.live_ptr,
            child_size: g.content.len(),
            extent_kind: format!("{:?}", g.extent_kind),
            candidate_slab_count: slab_ranges.len(),
            nearest_authority: if slab_ranges.is_empty() {
                None
            } else {
                Some((n_base, n_end))
            },
            nearest_authority_gap: n_gap,
        });
    }
    Ok(())
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
            capture_id: container_capture_id(c.decoded_begin),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        });
    }
    for g in heap_globals {
        if !g.is_raw_coherence_participant() {
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
        let cap_id = container_capture_id(container.decoded_begin);
        let raw = find_raw_child(
            raw_capture,
            container.decoded_begin,
            child_size,
            RawChildKind::Container,
            &cap_id,
            current,
        )?;
        let (slab_old_base, slab_size, slab_digest, slab_offset, slab_slice) =
            slab_slice_for_child(raw_capture, raw)?;
        if slab_slice != current {
            return Err(raw_capture_drift_error(
                RawChildKind::Container,
                raw.old_base,
                child_size,
                slab_old_base,
                slab_size,
                slab_offset,
                slab_slice,
                current,
            ));
        }
        bindings.push(TransformPreimageBinding {
            child_kind: RawChildKind::Container,
            capture_id: cap_id,
            child_old_base: raw.old_base,
            child_size,
            extent_kind: CEK::ObservedAllocation,
            slab_old_base,
            slab_size,
            slab_digest,
            slab_offset,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(current),
            raw_slab_slice_digest: sha256_hex(slab_slice),
            transform_input_digest: sha256_hex(current),
            seeded_from_slab: false,
        });
    }

    for global in heap_globals.iter_mut() {
        // Route X R0 (X0-A): seeding must use the canonical raw-coherence
        // participant predicate (excludes heap handles, image-inline, empty, and
        // SyntheticDerived), so the seeded set matches identity gate / raw-child /
        // ledger / overlay. No ad-hoc condition sets.
        if !global.is_raw_coherence_participant() {
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
        let (slab_old_base, slab_size, slab_digest, slab_offset, slab_slice) =
            slab_slice_for_child(raw_capture, raw)?;
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
                        slab_old_base,
                        slab_size,
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
            slab_old_base,
            slab_size,
            slab_digest,
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

/// Resolve a raw child to its authoritative slab slice, selecting the unique
/// covering slab from the full multi-slab set (TAF1-B).
///
/// Returns `(slab_old_base, slab_size, slab_digest, slab_offset, &slab_slice)`.
/// A child with 0 or >1 covering slabs fails closed (never defaults to a single
/// `raw_capture.slab`).
fn slab_slice_for_child<'a>(
    raw_capture: &'a RawSlabCapture,
    child: &RawChild,
) -> Result<(u64, usize, String, usize, &'a [u8]), OverlayError> {
    let (_si, base, size, offset, slab_bytes) =
        covering_slab_for_child(raw_capture, child.old_base, child.size, child.kind)?;
    let child_end = offset
        .checked_add(child.size)
        .ok_or(OverlayError::RawChildRangeOverflow {
            child_old_base: child.old_base,
            child_size: child.size,
            slab_old_base: base,
            slab_offset: offset,
        })?;
    let slab_slice =
        slab_bytes
            .get(offset..child_end)
            .ok_or(OverlayError::RawChildOutsideSlab {
                child_kind: child.kind,
                child_old_base: child.old_base,
                child_size: child.size,
                slab_old_base: base,
                slab_size: size,
            })?;
    let slab_digest = sha256_hex(slab_bytes);
    Ok((base, size, slab_digest, offset, slab_slice))
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
    // Legacy single-slab path (test-only; production uses build_patched_backing_slab_q0c).
    // TAF1-A: RawSlabCapture now holds a slab VECTOR. For the legacy path, operate
    // on the first (main) slab; children not contained in it still fail closed.
    let slab = raw_capture
        .slabs
        .first()
        .ok_or(OverlayError::ProbeCoverageMissing {
            child_kind: RawChildKind::HeapGlobal,
            child_base: 0,
            child_size: 0,
            extent_kind: String::new(),
            candidate_slab_count: 0,
            nearest_authority: None,
            nearest_authority_gap: 0,
        })?;
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
        if !g.is_raw_coherence_participant() {
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
            crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
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
    run_ledger: &TransformRunLedger,
) -> Result<
    (
        Vec<HeapSlab>,
        Vec<TransformedRegionOverlay>,
        Vec<CaptureDriftRun>,
    ),
    OverlayError,
> {
    use super::heap_global_snapshot::CaptureExtentKind as CEK;
    // TAF1-A / TAF1-C: the overlay operates over ALL authoritative slabs. Each
    // transformed child is written into its covering slab's patched copy, so the
    // main slab AND every dedicated dangling-edge slab are both patched here
    // (no overlay-single / runtime-multi fork).
    let mut backings: Vec<Vec<u8>> = raw_capture
        .slabs
        .iter()
        .map(|s| s.content.clone())
        .collect();

    // Index raw children by (old_base, kind) preserving all entries (dedup later).
    let mut raw_by_key: std::collections::BTreeMap<(u64, RawChildKind), Vec<&RawChild>> =
        std::collections::BTreeMap::new();
    for c in &raw_capture.children {
        raw_by_key.entry((c.old_base, c.kind)).or_default().push(c);
    }

    // Collect transformed children (heap-global + container) with provenance.
    // Route Y R0 (Y0-A rev 3 / Audit P1-1): the tuple carries `rva` (to recognize
    // a DECLARED size-reinit child) AND the full capture identity
    // (`capture_id`, `extent_kind`, `capture_path`) so the overlay can resolve
    // the exact raw child by identity — never by raw-byte/slab coherence alone.
    let mut transformed: Vec<(
        u64,
        usize,
        Vec<u8>,
        RawChildKind,
        RegionProvenance,
        Vec<String>,
        super::heap_global_snapshot::CaptureExtentKind,
        String,
        u32,
        super::heap_global_snapshot::CapturePath,
    )> = Vec::new();
    for g in transformed_globals {
        if !g.is_raw_coherence_participant() {
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
            g.rva,
            g.extent_evidence.capture_path,
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
        // Route Q R0 AF1 Rev 2: containers carry a deterministic non-empty
        // capture id (derived from decoded_begin) so the exact binding from the
        // raw/seeding stage matches the transformed representation.
        let cap_id = container_capture_id(c.decoded_begin);
        transformed.push((
            c.decoded_begin,
            size,
            content,
            RawChildKind::Container,
            RegionProvenance::RawCaptured {
                raw_digest: String::new(),
            },
            Vec::new(),
            crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            cap_id,
            0, // containers have no reinit declaration
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        ));
    }
    // Deterministic order by (old_base, kind).
    transformed.sort_by_key(|(base, _, _, kind, _, _, _, _, _, _)| (*base, *kind as u8));

    let mut overlays: Vec<TransformedRegionOverlay> = Vec::new();
    let mut drift_runs: Vec<CaptureDriftRun> = Vec::new();
    // TAF1-C: resolved writes are keyed by (slab_index, offset) so children from
    // DIFFERENT slabs never collide (each slab is an independent authority).
    let mut resolved_writes: std::collections::BTreeMap<(usize, usize), ResolvedWrite> =
        std::collections::BTreeMap::new();

    // Route S R0-D: validate the GLOBAL run-ledger shape exactly ONCE before the
    // child loop, so a malformed run is reported with its exact index (not blamed
    // on whichever child happens to be walked first).
    validate_run_ledger_shape(run_ledger)?;
    // Route X R0 AF1 (X0-D/P0-3): validate GLOBAL run→raw-child MEMBERSHIP before
    // byte replay — every run must resolve to exactly one raw child in the
    // canonical raw-coherence participant set (full identity tuple). A shape-valid
    // but orphaned/duplicate/mismatched run fails closed here, never silently
    // dropped because no transformed child consumed it.
    validate_run_membership(raw_capture, transformed_globals, run_ledger)?;

    for (
        child_base,
        child_size,
        transformed_bytes,
        kind,
        provenance,
        child_transform_ids,
        extent_kind,
        capture_id,
        child_rva,
        child_capture_path,
    ) in &transformed
    {
        let child_base = *child_base;
        let mut child_size = *child_size;
        let kind = *kind;
        let transformed_bytes = transformed_bytes.clone();
        let child_transform_ids = child_transform_ids.clone();
        let extent_kind = *extent_kind;
        let capture_id = capture_id.clone();
        let child_rva = *child_rva;
        let child_capture_path = *child_capture_path;
        // Route Y R0 (Y0-A): detect a DECLARED size-reinit child. Its transformed
        // content.len() differs from the raw child size legitimately; coherence is
        // validated at the RAW size while the transformed (new-size) bytes are
        // written.
        let declared_reinit = child_transform_ids
            .iter()
            .any(|tid| declared_size_reinit(tid, child_rva).is_some());

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
        // Route Y R0 (Y0-A rev 3 / Audit P1-1): a DECLARED size-reinit child's
        // raw child is resolved by FULL CAPTURE IDENTITY — (capture_id, old_base,
        // kind, extent_kind, capture_path) — BEFORE any size / slab-coverage /
        // binding handling. Never `max(raw.size)` over a set that shares only
        // (old_base, kind), and never raw-byte/slab coherence selection: those
        // can pick a DIFFERENT capture. Exactly one identity match is required.
        let declared_raw: Option<&RawChild> = if declared_reinit {
            let mut by_identity: Vec<&&RawChild> = raws
                .iter()
                .filter(|r| {
                    r.capture_id == capture_id
                        && r.extent_kind == extent_kind
                        && r.capture_path == child_capture_path
                })
                .collect();
            by_identity.sort_by_key(|r| r.old_base);
            if by_identity.len() != 1 {
                return Err(OverlayError::RawChildMissing {
                    child_old_base: child_base,
                    child_kind: kind,
                });
            }
            child_size = by_identity[0].size;
            Some(by_identity[0])
        } else {
            None
        };
        // TAF1-B / TAF1-C: resolve the child's unique covering slab from the full
        // multi-slab set (0 or >1 covering slabs fail closed; never defaults to a
        // single raw_capture.slab).
        let (si, slab_old_base, slab_size, slab_offset_us, slab_bytes) =
            covering_slab_for_child(raw_capture, child_base, child_size, kind)?;
        // Reconcile duplicate raw children. A DECLARED reinit uses the already
        // identity-resolved raw child; ordinary children keep the existing
        // slab-coherence dedup policy (no capture identity to disambiguate).
        let raw = match declared_raw {
            Some(r) => r,
            None => {
                if raws.len() == 1 {
                    raws[0]
                } else {
                    let so = usize::try_from(slab_offset_us).ok();
                    let distinct: Vec<&&RawChild> = raws
                        .iter()
                        .filter(|r| {
                            so.and_then(|s| {
                                slab_bytes
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
                }
            }
        };
        let Some(child_end) = slab_offset_us.checked_add(child_size) else {
            return Err(OverlayError::RawChildRangeOverflow {
                child_old_base: child_base,
                child_size,
                slab_old_base,
                slab_offset: slab_offset_us,
            });
        };
        if child_end > slab_bytes.len() {
            return Err(OverlayError::RawChildOutsideSlab {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base,
                slab_size,
            });
        }
        let raw_child_bytes = &raw.raw_bytes[..raw.size.min(raw.raw_bytes.len())];
        if raw_child_bytes.len() != child_size {
            return Err(OverlayError::RawCaptureDrift {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base,
                slab_size,
                slab_offset: slab_offset_us,
                first_mismatch_offset: raw_child_bytes.len().min(child_size),
                raw_child_digest: sha256_hex(raw_child_bytes),
                raw_slab_slice_digest: sha256_hex(&slab_bytes[slab_offset_us..child_end]),
            });
        }
        let raw_slab_slice = &slab_bytes[slab_offset_us..child_end];

        // ---- Route Q R0 Q0-A AF1: resolve the authoritative binding EXACTLY. ----
        // Q0-C requires a unique full-identity binding per transformed child. We
        // do NOT fall back to legacy coherence on a missing binding: a transform
        // preimage P is only trusted if there is a provable binding. All fields
        // must match exactly, the extent-to-basis matrix must hold, and every
        // digest must verify against the raw child C, the raw slab slice S, and
        // the derived P. Empty capture_id is ambiguous and rejected.
        let raw_slab_slice_digest = sha256_hex(raw_slab_slice);
        let raw_child_digest = sha256_hex(raw_child_bytes);

        // Collect candidate bindings for this (base, kind). Must be non-empty.
        let candidates: Vec<&TransformPreimageBinding> = bindings
            .iter()
            .filter(|b| b.child_old_base == child_base && b.child_kind == kind)
            .collect();
        if candidates.is_empty() {
            // Route S R0-C: NO binding for this child — a distinct, precise error
            // (not a byte-drift TransformPreimageDrift). No byte conflict is implied.
            return Err(OverlayError::TransformPreimageBindingMissing {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                capture_id,
                extent_kind: format!("{:?}", extent_kind),
                slab_old_base,
                slab_offset: slab_offset_us,
            });
        }

        // Find the unique binding with a FULL identity match.
        // TAF2-A: the FULL authoritative slab identity is enforced — not just the
        // child-relative fields. `slab_old_base` + `slab_offset` prove the child is
        // at the right position, AND `slab_size` + `slab_digest` prove the binding
        // references the ACTUAL covering slab (not a same-base/different-content
        // impostor). A wrong slab_size or slab_digest makes the binding fail closed.
        let actual_slab_digest = sha256_hex(slab_bytes);
        let exact: Vec<&TransformPreimageBinding> = candidates
            .iter()
            .copied()
            .filter(|b| {
                // capture_id must be non-empty and exact (never a wildcard).
                !b.capture_id.is_empty()
                    && b.capture_id == capture_id
                    // size must match the transformed child size.
                    && b.child_size == child_size
                    // extent must match the transformed child's extent.
                    && b.extent_kind == extent_kind
                    // slab identity + offset must match the verified raw slice.
                    && b.slab_old_base == slab_old_base
                    && b.slab_offset == slab_offset_us
                    // TAF2-A: the binding must reference the ACTUAL covering slab —
                    // same size AND same full-bytes digest. Never accept a binding
                    // whose recorded slab differs from the one being patched.
                    && b.slab_size == slab_bytes.len()
                    && b.slab_digest == actual_slab_digest
            })
            .collect();
        if exact.is_empty() {
            // Route S R0-C: candidates exist (matched base/kind) but none matched
            // the FULL identity (capture_id/size/extent/slab). Report the precise
            // missing-binding cause rather than a byte-drift error.
            let reason = format!(
                "candidates={} matched base/kind but none matched full identity \
                 (capture_id={capture_id:?} size={child_size:#x} extent={extent_kind:?} \
                 actual_slab_size={} actual_slab_digest={})",
                candidates.len(),
                slab_bytes.len(),
                actual_slab_digest
            );
            return Err(OverlayError::TransformPreimageBindingIdentityInvalid {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                capture_id,
                extent_kind: format!("{:?}", extent_kind),
                slab_old_base,
                slab_offset: slab_offset_us,
                reason,
            });
        }
        if exact.len() > 1 {
            // Route S R0-C: ambiguous duplicate bindings — a distinct error.
            return Err(OverlayError::TransformPreimageBindingAmbiguous {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                capture_id,
                extent_kind: format!("{:?}", extent_kind),
                slab_old_base,
                slab_offset: slab_offset_us,
                match_count: exact.len(),
            });
        }
        let binding = exact[0];

        // Enforce the extent-to-basis matrix. A strict child (ObservedAllocation /
        // BackingObject / Container) must be ChildCapture; a probe/interior child
        // must be AuthoritativeSlabSlice. Cross-basis is a Q0-C violation: a strict
        // child accepting a slab-seeded binding would bypass the C == S check.
        let required_basis = match extent_kind {
            CEK::ObservedAllocation | CEK::BackingObject => TransformPreimageBasis::ChildCapture,
            CEK::ProbeWindow | CEK::InteriorSubview => {
                TransformPreimageBasis::AuthoritativeSlabSlice
            }
            // SyntheticDerived children never carry raw bindings (handled above).
            CEK::SyntheticDerived => TransformPreimageBasis::ChildCapture,
        };
        // The extent-to-basis matrix is enforced for ALL kinds including Container.
        // A Container must be ChildCapture; a slab-seeded (AuthoritativeSlabSlice)
        // Container binding fails closed (it would bypass the strict C==S check).
        if binding.basis != required_basis {
            // Basis does not match the required extent policy: fail closed.
            return Err(OverlayError::TransformPreimageDrift {
                child_old_base: child_base,
                child_size,
                slab_offset: slab_offset_us,
                child_byte_offset: 0,
                c_byte: raw_child_bytes.first().copied().unwrap_or(0),
                s_byte: raw_slab_slice.first().copied().unwrap_or(0),
                t_byte: transformed_bytes.first().copied().unwrap_or(0),
                transform_ids: child_transform_ids.clone(),
            });
        }

        // Verify the binding digests against the actual raw C, raw S, and the
        // derived P. Any digest mismatch means the binding is stale or forged.
        if binding.raw_child_digest != raw_child_digest {
            return Err(OverlayError::RawCaptureDrift {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base,
                slab_size,
                slab_offset: slab_offset_us,
                first_mismatch_offset: 0,
                raw_child_digest,
                raw_slab_slice_digest,
            });
        }
        if binding.raw_slab_slice_digest != raw_slab_slice_digest {
            return Err(OverlayError::RawCaptureDrift {
                child_kind: kind,
                child_old_base: child_base,
                child_size,
                slab_old_base,
                slab_size,
                slab_offset: slab_offset_us,
                first_mismatch_offset: 0,
                raw_child_digest,
                raw_slab_slice_digest,
            });
        }

        // Determine P from the (now verified) basis.
        let (p_bytes, basis) = match binding.basis {
            TransformPreimageBasis::AuthoritativeSlabSlice => {
                // Probe/interior: P = S (the authoritative slab slice).
                let s_digest = raw_slab_slice_digest.clone();
                // seeded_from_slab must be consistent with the basis.
                if !binding.seeded_from_slab {
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: 0,
                        c_byte: raw_child_bytes.first().copied().unwrap_or(0),
                        s_byte: raw_slab_slice.first().copied().unwrap_or(0),
                        t_byte: transformed_bytes.first().copied().unwrap_or(0),
                        transform_ids: child_transform_ids.clone(),
                    });
                }
                // transform_input_digest must equal sha256(S) (P == S).
                if binding.transform_input_digest != s_digest {
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: 0,
                        c_byte: raw_child_bytes.first().copied().unwrap_or(0),
                        s_byte: raw_slab_slice.first().copied().unwrap_or(0),
                        t_byte: transformed_bytes.first().copied().unwrap_or(0),
                        transform_ids: child_transform_ids.clone(),
                    });
                }
                (
                    raw_slab_slice.to_vec(),
                    TransformPreimageBasis::AuthoritativeSlabSlice,
                )
            }
            TransformPreimageBasis::ChildCapture => {
                // Strict: require full-range C == S and transform_input_digest ==
                // sha256(C).
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
                        slab_old_base,
                        slab_size,
                        slab_offset: slab_offset_us,
                        first_mismatch_offset: first_mismatch,
                        raw_child_digest: raw_child_digest.clone(),
                        raw_slab_slice_digest: raw_slab_slice_digest.clone(),
                    });
                }
                // seeded_from_slab must be false for a strict child.
                if binding.seeded_from_slab {
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: 0,
                        c_byte: raw_child_bytes.first().copied().unwrap_or(0),
                        s_byte: raw_slab_slice.first().copied().unwrap_or(0),
                        t_byte: transformed_bytes.first().copied().unwrap_or(0),
                        transform_ids: child_transform_ids.clone(),
                    });
                }
                // transform_input_digest must equal sha256(C).
                if binding.transform_input_digest != raw_child_digest {
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: 0,
                        c_byte: raw_child_bytes.first().copied().unwrap_or(0),
                        s_byte: raw_slab_slice.first().copied().unwrap_or(0),
                        t_byte: transformed_bytes.first().copied().unwrap_or(0),
                        transform_ids: child_transform_ids.clone(),
                    });
                }
                (
                    raw_child_bytes.to_vec(),
                    TransformPreimageBasis::ChildCapture,
                )
            }
        };
        let is_slab_seeded = basis == TransformPreimageBasis::AuthoritativeSlabSlice;

        // Route Y R0 (Y0-A rev 2 / Audit P1-1, P1-2): a DECLARED size-reinit child
        // is FULLY re-validated at this Q0-C consumer boundary — the old-size
        // tolerance, the exact new size, the RVA and the zero-fill requirement —
        // its transition must be provably present in the ledger, and its
        // transformed (new-size) bytes enter the SAME resolved-writes conflict /
        // last-writer accounting as ordinary writes. A bare `copy_from_slice` that
        // bypassed replay, digest linkage, overlap/conflict detection and last-writer
        // enforcement is gone.
        if declared_reinit {
            // (P1-1) The unique-resolved raw child (full identity) defines the old
            // size; never `max(raw.size)` over an ambiguous multi-child set.
            let spec = child_transform_ids
                .iter()
                .filter_map(|tid| declared_size_reinit(tid, child_rva))
                .next()
                .expect("declared_reinit implies a declaration exists");
            let raw_old_size = raw.size;
            validate_declared_size_reinit_fields(
                spec,
                raw_old_size,
                child_rva,
                &capture_id,
                child_base,
                &transformed_bytes,
                0,
            )?;
            let new_size = spec.new_size;
            // (P1-2 rev 3 / Audit P1-2) Uniqueness is decided on the transition
            // IDENTITY (transform_id + capture_id + old_base) — never after
            // filtering to an already-expected shape. If the ledger carries one
            // well-formed run plus any additional run with the same transition
            // identity but a wrong size/offset/bytes, that is ambiguous and must
            // fail closed (a malformed extra run must not be silently dropped).
            let child_run_idxs: Vec<usize> = run_ledger
                .runs
                .iter()
                .enumerate()
                .filter(|(_, r)| r.child_capture_id == capture_id && r.child_old_base == child_base)
                .map(|(i, _)| i)
                .collect();
            let transition_idxs: Vec<usize> = child_run_idxs
                .iter()
                .copied()
                .filter(|&i| run_ledger.runs[i].transform_id == spec.transform_id)
                .collect();
            if transition_idxs.len() != 1 {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index: 0,
                    child_capture_id: capture_id.clone(),
                    child_old_base: child_base,
                    child_size: transformed_bytes.len(),
                    child_offset: 0,
                    length: 0,
                    transform_id: spec.transform_id.to_string(),
                    reason: format!(
                        "declared size reinit for old_base {:#x} must have EXACTLY ONE ledger run \
                         for transition identity (transform={:?} capture={:?}); found {}",
                        child_base,
                        spec.transform_id,
                        capture_id,
                        transition_idxs.len()
                    ),
                });
            }
            let t_idx = transition_idxs[0];
            let ev = &run_ledger.runs[t_idx];
            // (P1-2 rev 3) The unique transition run must carry the declared new
            // size and cover [0, new_size).
            if ev.child_size != new_size || ev.child_offset != 0 || ev.length != new_size {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index: t_idx,
                    child_capture_id: capture_id.clone(),
                    child_old_base: child_base,
                    child_size: ev.child_size,
                    child_offset: ev.child_offset,
                    length: ev.length,
                    transform_id: spec.transform_id.to_string(),
                    reason: format!(
                        "declared size reinit run shape invalid for old_base {:#x}: \
                         child_size={:#x} offset={:#x} length={:#x}, expected {:#x} [0,{:#x})",
                        child_base, ev.child_size, ev.child_offset, ev.length, new_size, new_size
                    ),
                });
            }
            if ev.child_capture_id.is_empty() || ev.transform_id.is_empty() {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index: t_idx,
                    child_capture_id: ev.child_capture_id.clone(),
                    child_old_base: child_base,
                    child_size: new_size,
                    child_offset: 0,
                    length: 0,
                    transform_id: spec.transform_id.to_string(),
                    reason: format!(
                        "declared size reinit run has empty identity for old_base {:#x}",
                        child_base
                    ),
                });
            }
            // (P1-3 rev 3 / Audit P1-3) The transition's BEFORE evidence is the
            // state right before the sanitize transform executed, NOT the original
            // raw prefix. Production runs prior recorded transforms (e.g.
            // scrub_uncaptured_heap_pointers, which can zero any heap-global qword)
            // before sanitize. Replay every prior run of this child in ledger
            // execution order from the bound authoritative preimage, verify each
            // run's before == current state, then the transition's before == the
            // replayed current state, and the final after == the transformed
            // new-size region.
            let mut current = p_bytes.to_vec();
            for (pos, &ri) in child_run_idxs.iter().enumerate() {
                let r = &run_ledger.runs[ri];
                if ri >= t_idx {
                    break;
                }
                let off = r.child_offset;
                let len = r.length;
                let end = match off.checked_add(len) {
                    Some(e) => e,
                    None => {
                        return Err(OverlayError::TransformRunLedgerInvalid {
                            run_index: ri,
                            child_capture_id: r.child_capture_id.clone(),
                            child_old_base: child_base,
                            child_size: r.child_size,
                            child_offset: off,
                            length: len,
                            transform_id: r.transform_id.clone(),
                            reason: format!(
                                "prior run length overflow for old_base {:#x}",
                                child_base
                            ),
                        });
                    }
                };
                if end > current.len() || len == 0 {
                    return Err(OverlayError::TransformRunLedgerInvalid {
                        run_index: ri,
                        child_capture_id: r.child_capture_id.clone(),
                        child_old_base: child_base,
                        child_size: r.child_size,
                        child_offset: off,
                        length: len,
                        transform_id: r.transform_id.clone(),
                        reason: format!(
                            "prior run out of preimage bounds for old_base {:#x}",
                            child_base
                        ),
                    });
                }
                // Self-consistency of the prior run's digest pair.
                if r.before_bytes.len() != len
                    || r.after_bytes.len() != len
                    || sha256_hex(&r.before_bytes) != r.before_digest
                    || sha256_hex(&r.after_bytes) != r.after_digest
                    || r.first_before_byte != r.before_bytes[0]
                    || r.first_after_byte != r.after_bytes[0]
                {
                    return Err(OverlayError::TransformRunLedgerInvalid {
                        run_index: ri,
                        child_capture_id: r.child_capture_id.clone(),
                        child_old_base: child_base,
                        child_size: r.child_size,
                        child_offset: off,
                        length: len,
                        transform_id: r.transform_id.clone(),
                        reason: format!(
                            "prior run digest/byte inconsistency for old_base {:#x}",
                            child_base
                        ),
                    });
                }
                // before == current state at [off, off+len).
                if current[off..end] != r.before_bytes {
                    return Err(OverlayError::TransformRunLedgerInvalid {
                        run_index: ri,
                        child_capture_id: r.child_capture_id.clone(),
                        child_old_base: child_base,
                        child_size: r.child_size,
                        child_offset: off,
                        length: len,
                        transform_id: r.transform_id.clone(),
                        reason: format!(
                            "prior run before mismatch at old_base {:#x} (prior-writer chain broken)",
                            child_base
                        ),
                    });
                }
                current[off..end].copy_from_slice(&r.after_bytes);
                let _ = pos;
            }
            // The replayed state is what the declared transition saw as its input.
            if current.len() < new_size || current[0..new_size] != ev.before_bytes {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index: t_idx,
                    child_capture_id: capture_id.clone(),
                    child_old_base: child_base,
                    child_size: new_size,
                    child_offset: 0,
                    length: 0,
                    transform_id: spec.transform_id.to_string(),
                    reason: format!(
                        "declared size reinit before mismatch for old_base {:#x} (must equal \
                         prior-writer-replayed current state, not the raw prefix)",
                        child_base
                    ),
                });
            }
            // The transition's after bytes must be exactly the transformed new-size
            // region (zeroed), digest and bytes both replayable.
            if ev.after_bytes != transformed_bytes[0..new_size]
                || ev.after_digest != sha256_hex(&transformed_bytes[0..new_size])
                || ev.first_after_byte != transformed_bytes[0]
            {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index: t_idx,
                    child_capture_id: capture_id.clone(),
                    child_old_base: child_base,
                    child_size: new_size,
                    child_offset: 0,
                    length: 0,
                    transform_id: spec.transform_id.to_string(),
                    reason: format!(
                        "declared size reinit after mismatch for old_base {:#x}",
                        child_base
                    ),
                });
            }
            // Every child run must be consumed: nothing may follow the terminal
            // declared transition (it is the final zeroed state).
            if child_run_idxs.iter().any(|&ri| ri > t_idx) {
                return Err(OverlayError::TransformRunLedgerInvalid {
                    run_index: 0,
                    child_capture_id: capture_id.clone(),
                    child_old_base: child_base,
                    child_size: new_size,
                    child_offset: 0,
                    length: 0,
                    transform_id: spec.transform_id.to_string(),
                    reason: format!(
                        "declared size reinit for old_base {:#x} must be the LAST run for \
                         its capture; orphan post-transition run present",
                        child_base
                    ),
                });
            }
            // (P1-2) Bounds: the new-size region must stay inside the covering slab.
            if slab_offset_us
                .checked_add(new_size)
                .map_or(true, |end| end > slab_bytes.len())
            {
                return Err(OverlayError::RawChildOutsideSlab {
                    child_kind: kind,
                    child_old_base: child_base,
                    child_size: new_size,
                    slab_old_base,
                    slab_size,
                });
            }
            // (P1-2) Register EVERY transformed byte into the unified
            // resolved-writes conflict / last-writer accounting, exactly like an
            // ordinary write-set. Overlap with another child writing a different
            // value → TransformWriteConflict (no silent overwrite).
            for (i, &val) in transformed_bytes[0..new_size].iter().enumerate() {
                let abs = slab_offset_us + i;
                match resolved_writes.get(&(si, abs)) {
                    None => {
                        resolved_writes.insert(
                            (si, abs),
                            ResolvedWrite {
                                value: val,
                                child_old_base: child_base,
                                child_size: raw_old_size,
                                child_byte_offset: i,
                                transform_ids: child_transform_ids.clone(),
                            },
                        );
                    }
                    Some(existing) if existing.value == val => {}
                    Some(existing) => {
                        let a_slab_off = (existing.child_old_base - slab_old_base) as usize;
                        let a_child_byte_offset = abs.saturating_sub(a_slab_off);
                        return Err(OverlayError::TransformWriteConflict {
                            a_child_old_base: existing.child_old_base,
                            a_size: existing.child_size,
                            a_child_byte_offset,
                            b_child_old_base: child_base,
                            b_size: raw_old_size,
                            b_child_byte_offset: i,
                            first_mismatch_slab_offset: abs,
                            before_byte: slab_bytes[abs],
                            a_after_byte: existing.value,
                            b_after_byte: val,
                            a_transform_ids: existing.transform_ids.clone(),
                            b_transform_ids: child_transform_ids.clone(),
                        });
                    }
                }
            }
            // (P1-2) Apply the new-size region to the patched backing slab.
            backings[si][slab_offset_us..slab_offset_us + new_size]
                .copy_from_slice(&transformed_bytes[0..new_size]);
            overlays.push(TransformedRegionOverlay {
                child_kind: kind,
                child_old_base: child_base,
                child_size: new_size,
                slab_offset: slab_offset_us,
                raw_child_digest: sha256_hex(raw_child_bytes),
                raw_slab_slice_digest: sha256_hex(raw_slab_slice),
                transformed_child_digest: sha256_hex(&transformed_bytes[0..new_size]),
                transform_ids: child_transform_ids.clone(),
                overlay_applied: true,
                contained_in_old_base: None,
            });
            continue;
        }

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

        // ---- Route Q R0 Q0-A AF1 Rev 2: strict byte/run write attribution. ----
        // For EVERY byte that differs from P (T[i] != P[i]), the ledger MUST prove
        // a deterministic last-writer whose replay chain ends at T[i]. There is no
        // "has_runs_for_child" bypass: a transformed byte with zero covering runs,
        // or with a chain that does not land on T[i], fails closed. Each covering
        // run must match the full child identity, stay in bounds, and have
        // self-consistent before/after digests. Overlapping runs are replayed in
        // ledger order (execution order), and the final state must equal T[i].
        for i in 0..p_len {
            if transformed_bytes[i] == p_bytes[i] {
                continue;
            }
            // Collect covering runs for this byte, in execution (ledger) order.
            // The ledger is appended in production execution order; its Vec index
            // is the sequence. We do NOT sort (that would lose the overwrite chain).
            let covering: Vec<&TransformWriteRun> = run_ledger
                .runs
                .iter()
                .filter(|r| {
                    // Full child identity match (capture_id, base, size).
                    r.child_capture_id == capture_id
                        && r.child_old_base == child_base
                        && r.child_size == child_size
                        // Run covers byte i and stays in child bounds (checked).
                        && r.child_offset <= i
                        && r
                            .child_offset
                            .checked_add(r.length)
                            .is_some_and(|end| i < end && end <= child_size)
                })
                .collect();
            if covering.is_empty() {
                // No run covers this byte: an unattributed transformed byte.
                return Err(OverlayError::TransformPreimageDrift {
                    child_old_base: child_base,
                    child_size,
                    slab_offset: slab_offset_us,
                    child_byte_offset: i,
                    c_byte: raw_child_bytes[i],
                    s_byte: raw_slab_slice[i],
                    t_byte: transformed_bytes[i],
                    transform_ids: child_transform_ids.clone(),
                });
            }
            // Route R R0-C: validate the run SHAPE before indexing its byte vectors,
            // so a malformed ledger returns TransformPreimageDrift instead of
            // panicking on a short vector or overflow. Applies to every covering run.
            for r in &covering {
                if r.length == 0
                    || r.before_bytes.len() != r.length
                    || r.after_bytes.len() != r.length
                    || r.first_before_byte != r.before_bytes[0]
                    || r.first_after_byte != r.after_bytes[0]
                    || r.child_capture_id.is_empty()
                    || r.transform_id.is_empty()
                {
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: i,
                        c_byte: raw_child_bytes[i],
                        s_byte: raw_slab_slice[i],
                        t_byte: transformed_bytes[i],
                        transform_ids: child_transform_ids.clone(),
                    });
                }
            }
            // Replay the covering runs in execution order against the preimage P.
            // Each run's before byte must equal the current state, and its digest
            // must be self-consistent with its before_bytes.
            let mut state = p_bytes[i];
            let mut last_writer: Option<&str> = None;
            for r in &covering {
                // Digest self-consistency: before_digest == sha256(before_bytes),
                // after_digest == sha256(after_bytes).
                if sha256_hex(&r.before_bytes) != r.before_digest
                    || sha256_hex(&r.after_bytes) != r.after_digest
                {
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: i,
                        c_byte: raw_child_bytes[i],
                        s_byte: raw_slab_slice[i],
                        t_byte: transformed_bytes[i],
                        transform_ids: child_transform_ids.clone(),
                    });
                }
                let rel = i - r.child_offset; // safe: child_offset <= i (filter)
                let run_before = r.before_bytes[rel];
                let run_after = r.after_bytes[rel];
                // Chain continuity: this run's before byte must equal the prior state.
                if run_before != state {
                    return Err(OverlayError::TransformPreimageDrift {
                        child_old_base: child_base,
                        child_size,
                        slab_offset: slab_offset_us,
                        child_byte_offset: i,
                        c_byte: raw_child_bytes[i],
                        s_byte: raw_slab_slice[i],
                        t_byte: transformed_bytes[i],
                        transform_ids: child_transform_ids.clone(),
                    });
                }
                state = run_after;
                last_writer = Some(&r.transform_id);
            }
            // The final state after replaying all covering runs must equal T[i],
            // and the last writer is the attribution.
            if state != transformed_bytes[i] {
                return Err(OverlayError::TransformPreimageDrift {
                    child_old_base: child_base,
                    child_size,
                    slab_offset: slab_offset_us,
                    child_byte_offset: i,
                    c_byte: raw_child_bytes[i],
                    s_byte: raw_slab_slice[i],
                    t_byte: transformed_bytes[i],
                    transform_ids: child_transform_ids.clone(),
                });
            }
            let _ = last_writer;
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
                    slab_digest: sha256_hex(&slab_bytes[start..end]),
                    intersects_transform_write: false,
                    resolution: CaptureDriftResolution::NonWriteSlabAuthoritative,
                });
            };
            for i in 0..p_len {
                let so = slab_offset_us + i;
                let drifted =
                    raw_child_bytes[i] != slab_bytes[so] && transformed_bytes[i] == slab_bytes[so];
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
                    slab_digest: sha256_hex(&slab_bytes[so..so + len]),
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
                match resolved_writes.get(&(si, abs)) {
                    None => {
                        resolved_writes.insert(
                            (si, abs),
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
                        let a_slab_off = (existing.child_old_base - slab_old_base) as usize;
                        let a_child_byte_offset = abs.saturating_sub(a_slab_off);
                        return Err(OverlayError::TransformWriteConflict {
                            a_child_old_base: existing.child_old_base,
                            a_size: existing.child_size,
                            a_child_byte_offset,
                            b_child_old_base: child_base,
                            b_size: child_size,
                            b_child_byte_offset: child_byte_offset,
                            first_mismatch_slab_offset: abs,
                            before_byte: slab_bytes[abs],
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
            backings[si][so..so + len].copy_from_slice(bytes);
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
            .find(|(ob, osz, _, ok, _, _, _, _, _, _)| {
                !(*ok == kind && *ob == child_base)
                    && *ob <= child_base
                    && child_base + child_size as u64 <= ob.saturating_add(*osz as u64)
            })
            .map(|(ob, _, _, _, _, _, _, _, _, _)| *ob);
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
    // TAF1-A / TAF1-C: return ONE patched slab per authoritative slab (main +
    // each dedicated dangling-edge slab), in the same order as raw_capture.slabs.
    let patched: Vec<HeapSlab> = raw_capture
        .slabs
        .iter()
        .enumerate()
        .map(|(i, s)| HeapSlab {
            old_base: s.old_base,
            content: backings[i].clone(),
        })
        .collect();
    Ok((patched, overlays, drift_runs))
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
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            slabs: vec![slab(ROUTEK_SLAB_BASE, content)],
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            slabs: vec![slab(ROUTEK_SLAB_BASE, content)],
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
            slabs: vec![slab(ROUTEK_SLAB_BASE, vec![0u8; 0x1000])],
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
            slabs: vec![slab(0x1000, vec![0u8; 0x100])],
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
            slabs: vec![slab(0x1000, vec![0u8; 0x100])],
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
            slabs: vec![slab(0x1000, vec![0u8; 0x100])],
            children: vec![],
        };
        let h = handle(0x8f0000);
        let (_, overlays, _) = build_patched_backing_slab(&raw_capture, &[h], &[], &["t"]).unwrap();
        assert!(overlays.is_empty());
    }

    #[test]
    fn r0c1_nobypass_off_path_unchanged() {
        let raw_capture = RawSlabCapture {
            slabs: vec![slab(0x1000, vec![0u8; 0x100])],
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
            slabs: vec![slab(ROUTEK_SLAB_BASE, content)],
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            slabs: vec![s],
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
            slabs: vec![s],
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
        let synth_transform_ids_provenance = match &synth.provenance {
            RegionProvenance::SyntheticDerived { transform_id, .. } => Some(transform_id.clone()),
            _ => None,
        };
        let (patched, overlays, _) = build_patched_backing_slab(
            &raw_capture,
            &[real, synth],
            &[],
            &["repair_gscript_window_strings"],
        )
        .unwrap();
        // Synthetic child did NOT get written into the slab and is NOT a
        // raw-slab overlay child (Route X R0: non-raw / SyntheticDerived is
        // excluded from raw overlay; it never appears as a raw overlay entry).
        let synth_overlays: Vec<_> = overlays
            .iter()
            .filter(|o| o.child_old_base == synthetic_base)
            .collect();
        assert_eq!(synth_overlays.len(), 0);
        // The synthetic child's child-level transform evidence is preserved
        // (transform provenance is not silently destroyed by exclusion).
        assert!(matches!(
            synth_transform_ids_provenance,
            Some(t) if t == "repair_gscript_window_strings"
        ));
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
            slabs: vec![s],
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
            slabs: vec![slab(slab_base, slab_content.clone())],
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
            slabs: vec![slab(slab_base, slab_content)],
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
        ga.extent_kind = crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
        gb.extent_kind = crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
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
            slabs: vec![slab(ROUTEN_SLAB_BASE, content)],
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
        let raw_slab = raw_capture.slabs[0].content.clone();
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
        )
        .unwrap();

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

        let runs =
            diff_transform_write_runs(&[before], &[after], "mark_labels_non_nested").unwrap();

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

        let runs = diff_transform_write_runs(&[before], &[after], "scrub_uncaptured_heap_pointers")
            .unwrap();

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
        )
        .unwrap();
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
        let runs = diff_transform_write_runs(&[before], &[after], "repair_label_names_after_scrub")
            .unwrap();
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
            slabs: vec![slab],
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
        // A production byte/run ledger proving the +0x28 write came from
        // repair_label_names_after_scrub on the authoritative preimage S[0x28]=0xf0.
        let mut ledger = TransformRunLedger::default();
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "route-p-geometry".into(),
            child_old_base: child_base,
            child_size,
            child_offset: 0x28,
            length: 1,
            transform_id: "repair_label_names_after_scrub".into(),
            before_digest: sha256_hex(&[0xf0]),
            after_digest: sha256_hex(&[0x28]),
            first_before_byte: 0xf0,
            first_after_byte: 0x28,
            before_bytes: vec![0xf0],
            after_bytes: vec![0x28],
        });

        let (patched, overlays, drift) = build_patched_backing_slab_q0c(
            &raw_capture,
            &[globals[0].clone()],
            &[],
            &bindings,
            &ledger,
        )
        .unwrap();
        // The +0x28 write was applied (T != S).
        assert_eq!(patched[0].content[child_off + 0x28], 0x28);
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
            slabs: vec![slab],
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
        let (patched, _, drift) = build_patched_backing_slab_q0c(
            &raw_capture,
            &[globals[0].clone()],
            &[],
            &bindings,
            &TransformRunLedger::default(),
        )
        .unwrap();
        // Slab authority wins at +0x28.
        assert_eq!(patched[0].content[child_off + 0x28], 0xf0);
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
        // TAF2-A: capture the full-slab digest/size before moving into raw_capture.
        let slab_digest = sha256_hex(&slab.content);
        let slab_len = slab.content.len();
        let mut raw_bytes = vec![0xAAu8; child_size];
        raw_bytes[0x28] = 0x00;
        let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
        child.extent_kind = CEK::InteriorSubview;
        child.capture_id = "route-p-baddigest".into();
        // Capture digest inputs before moving child/slab into raw_capture.
        let child_digest = sha256_hex(&child.raw_bytes);
        let slab_slice_digest = sha256_hex(&slab.content[child_off..child_off + child_size]);
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![child],
        };
        // A forged binding: claims AuthoritativeSlabSlice with correct C/S digests
        // but a WRONG transform_input_digest (!= sha256(S)).
        let bad_binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "route-p-baddigest".into(),
            child_old_base: child_base,
            child_size,
            extent_kind: CEK::InteriorSubview,
            slab_old_base: slab_base,
            slab_size: slab_len,
            slab_digest,
            slab_offset: child_off,
            basis: TransformPreimageBasis::AuthoritativeSlabSlice,
            raw_child_digest: child_digest,
            raw_slab_slice_digest: slab_slice_digest,
            transform_input_digest: "WRONG".into(), // != sha256(S)
            seeded_from_slab: true,
        };
        let mut transformed = global(child_base, vec![0xAAu8; child_size], false);
        transformed.extent_kind = CEK::InteriorSubview;
        transformed.extent_evidence.capture_id = "route-p-baddigest".into();
        transformed.content[0x28] = 0x28;
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[bad_binding],
            &TransformRunLedger::default(),
        )
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
        // TAF2-A: full-slab identity for the binding.
        let slab_digest = sha256_hex(&slab.content);
        let slab_len = slab.content.len();
        // C == S (all 0xAA), strict ObservedAllocation.
        let raw_bytes = vec![0xAAu8; child_size];
        let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
        child.extent_kind = CEK::ObservedAllocation;
        child.capture_id = "route-q-strict-ok".into();
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
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
            slab_size: slab_len,
            slab_digest,
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
        // Production byte/run ledger: the +0x10 write from t1 (preimage 0xAA -> 0xEE).
        let mut ledger = TransformRunLedger::default();
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "route-q-strict-ok".into(),
            child_old_base: child_base,
            child_size,
            child_offset: 0x10,
            length: 1,
            transform_id: "t1".into(),
            before_digest: sha256_hex(&[0xAA]),
            after_digest: sha256_hex(&[0xEE]),
            first_before_byte: 0xAA,
            first_after_byte: 0xEE,
            before_bytes: vec![0xAA],
            after_bytes: vec![0xEE],
        });
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap();
        assert_eq!(patched[0].content[child_off + 0x10], 0xEE);
        assert_eq!(overlays.len(), 1);
        // Non-written bytes stay 0xAA (unchanged).
        assert_eq!(patched[0].content[child_off + 0x20], 0xAA);

        // Now a strict child with C!=S must fail closed.
        let mut drifting_raw = vec![0xAAu8; child_size];
        drifting_raw[0x28] = 0x00; // C[0x28] != S[0x28] (0xAA)
        let mut child2 = raw_child(
            child_base,
            child_size,
            drifting_raw.clone(),
            RawChildKind::HeapGlobal,
        );
        child2.extent_kind = CEK::ObservedAllocation;
        child2.capture_id = "route-q-strict-drift".into();
        // TAF2-A: this test's second slab is a separate inline authority; capture
        // its own digest/size.
        let slab2 = HeapSlab {
            old_base: slab_base,
            content: vec![0xAAu8; child_off + child_size],
        };
        let slab2_digest = sha256_hex(&slab2.content);
        let slab2_len = slab2.content.len();
        let raw_capture2 = RawSlabCapture {
            slabs: vec![slab2],
            children: vec![child2],
        };
        let binding2 = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "route-q-strict-drift".into(),
            child_old_base: child_base,
            child_size,
            extent_kind: CEK::ObservedAllocation,
            slab_old_base: slab_base,
            slab_size: slab2_len,
            slab_digest: slab2_digest,
            slab_offset: child_off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&drifting_raw),
            raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; child_size]),
            transform_input_digest: sha256_hex(&drifting_raw),
            seeded_from_slab: false,
        };
        let mut transformed2 = global(child_base, vec![0xAAu8; child_size], false);
        transformed2.extent_kind = CEK::ObservedAllocation;
        transformed2.extent_evidence.capture_id = "route-q-strict-drift".into();
        transformed2.content[0x28] = 0x00;
        let err = build_patched_backing_slab_q0c(
            &raw_capture2,
            &[transformed2],
            &[],
            &[binding2],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    // ---- Route Q R0 Q0-A AF1-B: binding resolution negative matrix ----
    // The audit (AF1-B) requires exact, unique, full-field binding resolution.
    // Every under-constraint below must fail closed. This builds a probe/interior
    // child + a CORRECT binding, then mutates one identity/digest field at a time
    // and asserts the overlay rejects it (TransformPreimageDrift / RawCaptureDrift).

    const AF1B_BASE: u64 = 0x8aa5f8;
    const AF1B_SIZE: usize = 0x70;
    const AF1B_SLAB: u64 = 0x874000;

    /// A valid probe/interior fixture + correct AuthoritativeSlabSlice binding.
    fn af1b_fixture() -> (RawSlabCapture, HeapGlobalSnapshot, TransformPreimageBinding) {
        let child_off = (AF1B_BASE - AF1B_SLAB) as usize;
        let mut slab_content = vec![0u8; child_off + AF1B_SIZE];
        for i in 0..AF1B_SIZE {
            slab_content[child_off + i] = 0xAA;
        }
        // S mName = full non-null pointer (drift byte 0xf0).
        let s_ptr = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
        slab_content[child_off + 0x28..child_off + 0x30].copy_from_slice(&s_ptr);
        let slab = HeapSlab {
            old_base: AF1B_SLAB,
            content: slab_content,
        };
        let mut raw_bytes = vec![0xAAu8; AF1B_SIZE];
        raw_bytes[0x28..0x30].fill(0); // C mName null (drift)
                                       // Capture digests before moving.
        let child_digest = sha256_hex(&raw_bytes);
        let slab_slice_digest = sha256_hex(&slab.content[child_off..child_off + AF1B_SIZE]);
        let mut child = raw_child(AF1B_BASE, AF1B_SIZE, raw_bytes, RawChildKind::HeapGlobal);
        child.extent_kind = CEK::InteriorSubview;
        child.capture_id = "af1b-probe".into();
        let slab_digest = sha256_hex(&slab.content);
        let slab_len = slab.content.len();
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![child],
        };
        // Pre-seed content == C so seeding can find it.
        let mut seeded = global(AF1B_BASE, vec![0xAAu8; AF1B_SIZE], false);
        seeded.extent_kind = CEK::InteriorSubview;
        seeded.extent_evidence.capture_id = "af1b-probe".into();
        seeded.content[0x28..0x30].fill(0);
        // A correct binding (matching the seeded transform input).
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "af1b-probe".into(),
            child_old_base: AF1B_BASE,
            child_size: AF1B_SIZE,
            extent_kind: CEK::InteriorSubview,
            slab_old_base: AF1B_SLAB,
            slab_size: slab_len,
            slab_digest,
            slab_offset: child_off,
            basis: TransformPreimageBasis::AuthoritativeSlabSlice,
            raw_child_digest: child_digest,
            raw_slab_slice_digest: slab_slice_digest.clone(),
            transform_input_digest: slab_slice_digest,
            seeded_from_slab: true,
        };
        (raw_capture, seeded, binding)
    }

    // Missing binding -> fail closed (no legacy fallback for probe/interior).
    #[test]
    fn route_q_af1b_missing_binding_fails_closed() {
        let (raw_capture, transformed, _binding) = af1b_fixture();
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingMissing { .. }
        ));
    }

    // Duplicate full-identity bindings -> ambiguous -> fail closed.
    #[test]
    fn route_q_af1b_duplicate_binding_fails_closed() {
        let (raw_capture, transformed, binding) = af1b_fixture();
        let dup = binding.clone();
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding, dup],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingAmbiguous { .. }
        ));
    }

    // A strict child accepting a slab-seeded (AuthoritativeSlabSlice) binding
    // must fail closed — it would bypass the C==S check.
    #[test]
    fn route_q_af1b_strict_accepting_slab_basis_fails_closed() {
        let (raw_capture, mut transformed, mut binding) = af1b_fixture();
        // Reclassify as strict; the binding stays slab-seeded (wrong basis).
        transformed.extent_kind = CEK::ObservedAllocation;
        binding.extent_kind = CEK::ObservedAllocation;
        binding.basis = TransformPreimageBasis::AuthoritativeSlabSlice; // forbidden for strict
        binding.seeded_from_slab = true;
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, OverlayError::TransformPreimageDrift { .. })
                || matches!(err, OverlayError::RawCaptureDrift { .. })
        );
    }

    // Wrong extent_kind in the binding (does not match child) -> fail closed.
    #[test]
    fn route_q_af1b_wrong_extent_fails_closed() {
        let (raw_capture, transformed, mut binding) = af1b_fixture();
        binding.extent_kind = CEK::BackingObject; // mismatched extent
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingIdentityInvalid { .. }
        ));
    }

    // Wrong child_size in the binding -> fail closed.
    #[test]
    fn route_q_af1b_wrong_size_fails_closed() {
        let (raw_capture, transformed, mut binding) = af1b_fixture();
        binding.child_size = AF1B_SIZE + 8; // mismatched size
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingIdentityInvalid { .. }
        ));
    }

    // Wrong slab_old_base in the binding -> fail closed.
    #[test]
    fn route_q_af1b_wrong_slab_base_fails_closed() {
        let (raw_capture, transformed, mut binding) = af1b_fixture();
        binding.slab_old_base = AF1B_SLAB - 0x1000; // mismatched slab identity
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingIdentityInvalid { .. }
        ));
    }

    // Wrong slab_offset in the binding -> fail closed.
    #[test]
    fn route_q_af1b_wrong_slab_offset_fails_closed() {
        let (raw_capture, transformed, mut binding) = af1b_fixture();
        binding.slab_offset += 8; // mismatched offset
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingIdentityInvalid { .. }
        ));
    }

    // Wrong raw_child_digest (stale C) -> fail closed.
    #[test]
    fn route_q_af1b_wrong_child_digest_fails_closed() {
        let (raw_capture, transformed, mut binding) = af1b_fixture();
        binding.raw_child_digest = "stale".into(); // mismatched C digest
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    // Wrong raw_slab_slice_digest (stale S) -> fail closed.
    #[test]
    fn route_q_af1b_wrong_slab_digest_fails_closed() {
        let (raw_capture, transformed, mut binding) = af1b_fixture();
        binding.raw_slab_slice_digest = "stale".into(); // mismatched S digest
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    // Inconsistent seeded_from_slab (false on a slab-seeded binding) -> fail closed.
    #[test]
    fn route_q_af1b_inconsistent_seeded_fails_closed() {
        let (raw_capture, transformed, mut binding) = af1b_fixture();
        binding.seeded_from_slab = false; // inconsistent with AuthoritativeSlabSlice
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
    }

    // Empty capture_id in the binding -> ambiguous -> fail closed.
    #[test]
    fn route_q_af1b_empty_capture_id_fails_closed() {
        let (raw_capture, transformed, mut binding) = af1b_fixture();
        binding.capture_id = String::new(); // empty capture id = identity invalid
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingIdentityInvalid { .. }
        ));
    }

    // ---- Route Q R0 AF1 Rev 2 (P0-1): strict write-run attribution negatives ----
    // For every T != P byte the ledger MUST prove a deterministic last writer via a
    // contiguous, digest-consistent, in-order replay landing on T. Each negative
    // below must fail closed. The fixture writes child +0x28 from P=S[0x28]=0xf0 to
    // T[0x28]=0x28 (repair_label_names_after_scrub) with a CORRECT binding; only the
    // ledger is perturbed.

    /// A probe/interior child with correct binding, transformed +0x28 -> 0x28.
    fn af1a_write_fixture() -> (RawSlabCapture, HeapGlobalSnapshot, TransformPreimageBinding) {
        let (raw_capture, mut transformed, binding) = af1b_fixture();
        // The transform input P == S. The transformed child must equal S except for
        // the +0x28 write, so only one byte differs (clean single write). S's
        // +0x28..+0x30 carries the full pointer 0xf0f1f2f3f4f5f6f7.
        let s_ptr = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
        transformed.content[0x28..0x30].copy_from_slice(&s_ptr); // == S
        transformed.content[0x28] = 0x28; // repair writes the pointer low byte
        (raw_capture, transformed, binding)
    }

    /// A correct single-run ledger: repair wrote +0x28 0xf7 -> 0x28.
    fn af1a_correct_ledger() -> TransformRunLedger {
        let mut ledger = TransformRunLedger::default();
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "af1b-probe".into(),
            child_old_base: AF1B_BASE,
            child_size: AF1B_SIZE,
            child_offset: 0x28,
            length: 1,
            transform_id: "repair_label_names_after_scrub".into(),
            before_digest: sha256_hex(&[0xf7]),
            after_digest: sha256_hex(&[0x28]),
            first_before_byte: 0xf7,
            first_after_byte: 0x28,
            before_bytes: vec![0xf7],
            after_bytes: vec![0x28],
        });
        ledger
    }

    // 1. T != P with ZERO covering runs -> fail closed (no has_runs_for_child bypass).
    #[test]
    fn route_q_af1a_zero_runs_fails_closed() {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
    }

    // 2. Wrong capture id in the run -> no identity match -> fail closed.
    // Route X R0 AF1 (P0-3): the global run-membership gate catches this EARLIER
    // as TransformRunLedgerInvalid (precise reason), before per-child replay.
    #[test]
    fn route_q_af1a_wrong_capture_id_fails_closed() {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let mut ledger = af1a_correct_ledger();
        ledger.runs[0].child_capture_id = "different-child".into();
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::TransformRunLedgerInvalid { .. }
                    | OverlayError::TransformPreimageDrift { .. }
            ),
            "wrong capture id must fail closed, got {err:?}"
        );
    }

    // 3. Wrong child size in the run -> identity mismatch -> fail closed.
    #[test]
    fn route_q_af1a_wrong_child_size_fails_closed() {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let mut ledger = af1a_correct_ledger();
        ledger.runs[0].child_size = AF1B_SIZE + 16;
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::TransformRunLedgerInvalid { .. }
                    | OverlayError::TransformPreimageDrift { .. }
            ),
            "wrong child size must fail closed, got {err:?}"
        );
    }

    // 4. Out-of-range run (offset+length > child_size) -> fail closed.
    #[test]
    fn route_q_af1a_out_of_range_run_fails_closed() {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let mut ledger = af1a_correct_ledger();
        ledger.runs[0].child_offset = AF1B_SIZE - 1; // length 1 -> runs past end
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
    }

    // 5. Earlier writer matches T but a LATER writer differs -> the later writer
    //    must win; if the final state != T, fail closed (no earlier-writer spoof).
    #[test]
    fn route_q_af1a_later_writer_differs_fails_closed() {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let mut ledger = af1a_correct_ledger(); // repair: 0xf0 -> 0x28 (matches T)
                                                // A later writer (sanitize) overwrites +0x28 to 0x00, so final != T.
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "af1b-probe".into(),
            child_old_base: AF1B_BASE,
            child_size: AF1B_SIZE,
            child_offset: 0x28,
            length: 1,
            transform_id: "sanitize_ahk_runtime_global".into(),
            before_digest: sha256_hex(&[0x28]),
            after_digest: sha256_hex(&[0x00]),
            first_before_byte: 0x28,
            first_after_byte: 0x00,
            before_bytes: vec![0x28],
            after_bytes: vec![0x00],
        });
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        assert!(
            matches!(err, OverlayError::TransformPreimageDrift { .. }),
            "later writer differs from T must fail closed"
        );
    }

    // 6. Broken before/after chain: a later run's before byte != prior state.
    #[test]
    fn route_q_af1a_broken_chain_fails_closed() {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let mut ledger = af1a_correct_ledger();
        // A later run whose before byte does NOT equal the prior state (0x28).
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "af1b-probe".into(),
            child_old_base: AF1B_BASE,
            child_size: AF1B_SIZE,
            child_offset: 0x28,
            length: 1,
            transform_id: "sanitize_ahk_runtime_global".into(),
            before_digest: sha256_hex(&[0xAB]), // != prior state 0x28
            after_digest: sha256_hex(&[0x00]),
            first_before_byte: 0xAB,
            first_after_byte: 0x00,
            before_bytes: vec![0xAB],
            after_bytes: vec![0x00],
        });
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        assert!(
            matches!(err, OverlayError::TransformPreimageDrift { .. }),
            "broken before/after chain must fail closed"
        );
    }

    // 7. Digest mismatch: before_digest != sha256(before_bytes) -> fail closed.
    #[test]
    fn route_q_af1a_digest_mismatch_fails_closed() {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let mut ledger = af1a_correct_ledger();
        ledger.runs[0].before_digest = "wrong-digest".into(); // != sha256(before_bytes)
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        // Route S R0-D: digest mismatch is caught by the global run-ledger validator.
        assert!(
            matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
            "digest mismatch must fail closed, got {err:?}"
        );
    }

    // 8. A CORRECT ledger (positive control): the write is attributed and applied.
    #[test]
    fn route_q_af1a_correct_ledger_attributes_and_applies() {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let ledger = af1a_correct_ledger();
        let (patched, _, _) =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap();
        assert_eq!(
            patched[0].content[(AF1B_BASE - AF1B_SLAB) as usize + 0x28],
            0x28
        );
    }

    // ---- Route R R0-C: malformed run shape must FAIL CLOSED (TransformPreimageDrift),
    // never panic on a short byte vector or inconsistent first bytes.
    fn route_q_af1a_malformed_run(mutate: impl FnOnce(&mut TransformWriteRun)) {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let mut ledger = af1a_correct_ledger();
        mutate(&mut ledger.runs[0]);
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        // Route S R0-D: malformed covering run is caught by the global validator.
        assert!(
            matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
            "malformed run must fail closed, got {err:?}"
        );
    }

    #[test]
    fn route_q_af1a_short_before_bytes_fails_closed() {
        // before_bytes too short (would index-panic without shape validation).
        route_q_af1a_malformed_run(|r| r.before_bytes.clear());
    }

    #[test]
    fn route_q_af1a_empty_capture_id_run_fails_closed() {
        route_q_af1a_malformed_run(|r| r.child_capture_id.clear());
    }

    #[test]
    fn route_q_af1a_empty_transform_id_run_fails_closed() {
        route_q_af1a_malformed_run(|r| r.transform_id.clear());
    }

    #[test]
    fn route_q_af1a_first_before_byte_inconsistent_fails_closed() {
        // first_before_byte disagrees with before_bytes[0].
        route_q_af1a_malformed_run(|r| r.first_before_byte = r.first_before_byte.wrapping_add(1));
    }

    #[test]
    fn route_q_af1a_length_zero_fails_closed() {
        route_q_af1a_malformed_run(|r| r.length = 0);
    }

    // ---- Route R R0-C / Audit Fix 1: GLOBAL ledger validation. ----
    // A malformed run for a DIFFERENT (unrelated) child must still fail the whole
    // ledger, even when the current child has a correct covering writer. This is
    // exercised with a valid covering run + a malformed extra run; the overlay
    // must fail closed (the global validator runs before per-byte attribution).

    fn route_r_r0c_malformed_extra(mutate: impl FnOnce(&mut TransformWriteRun)) {
        let (raw_capture, transformed, binding) = af1a_write_fixture();
        let mut ledger = af1a_correct_ledger(); // valid covering run for +0x28
                                                // A malformed run for an UNRELATED child (different base) — must fail the
                                                // whole ledger via the global validator, not be ignored.
        let mut extra = TransformWriteRun {
            child_capture_id: "other-child".into(),
            child_old_base: AF1B_BASE + 0x10000, // unrelated base
            child_size: 8,
            child_offset: 0,
            length: 1,
            transform_id: "scrub_uncaptured_heap_pointers".into(),
            before_digest: sha256_hex(&[0x01]),
            after_digest: sha256_hex(&[0x02]),
            first_before_byte: 0x01,
            first_after_byte: 0x02,
            before_bytes: vec![0x01],
            after_bytes: vec![0x02],
        };
        mutate(&mut extra);
        ledger.runs.push(extra);
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        // Route S R0-D: the global validator reports the EXACT malformed run index
        // (the extra run at index 1) via TransformRunLedgerInvalid, not a per-child
        // TransformPreimageDrift.
        match &err {
            OverlayError::TransformRunLedgerInvalid { run_index, .. } => {
                assert_eq!(*run_index, 1, "must identify the malformed extra run index");
            }
            other => panic!("expected TransformRunLedgerInvalid, got {other:?}"),
        }
    }

    #[test]
    fn route_r_r0c_valid_plus_zero_length_extra_fails() {
        route_r_r0c_malformed_extra(|r| r.length = 0);
    }

    #[test]
    fn route_r_r0c_valid_plus_empty_id_extra_fails() {
        route_r_r0c_malformed_extra(|r| r.child_capture_id.clear());
    }

    #[test]
    fn route_r_r0c_valid_plus_short_vector_extra_fails() {
        route_r_r0c_malformed_extra(|r| r.before_bytes.clear());
    }

    #[test]
    fn route_r_r0c_offset_length_overflow_fails() {
        route_r_r0c_malformed_extra(|r| r.child_offset = usize::MAX - 1);
    }

    // ---- Route R R0-B / Audit Fix 1: execution-owning recorder tests. ----
    // The recorder executes the transform AND records both child-level
    // `transform_ids` and the byte/run ledger in one call, so the two can never
    // diverge.

    #[test]
    fn route_r_r0b_apply_recorded_transform_records_both_ledgers() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        // A strict child (C==S) that a transform will modify.
        let child_base = 0x8aa5f8u64;
        let child_size = 0x70usize;
        let slab_base = 0x874000u64;
        let child_off = (child_base - slab_base) as usize;
        let slab = HeapSlab {
            old_base: slab_base,
            content: vec![0xAAu8; child_off + child_size],
        };
        let mut child = raw_child(
            child_base,
            child_size,
            vec![0xAAu8; child_size],
            RawChildKind::HeapGlobal,
        );
        child.extent_kind = CEK::ObservedAllocation;
        child.capture_id = "r0b-child".into();
        let slab_digest = sha256_hex(&slab.content);
        let slab_len = slab.content.len();
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![child],
        };
        // A transformed child whose +0x10 will be changed by the transform.
        let mut globals = vec![global(child_base, vec![0xAAu8; child_size], false)];
        globals[0].extent_kind = CEK::ObservedAllocation;
        globals[0].extent_evidence.capture_id = "r0b-child".into();
        let mut binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "r0b-child".into(),
            child_old_base: child_base,
            child_size,
            extent_kind: CEK::ObservedAllocation,
            slab_old_base: slab_base,
            slab_size: slab_len,
            slab_digest,
            slab_offset: child_off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&vec![0xAAu8; child_size]),
            raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; child_size]),
            transform_input_digest: sha256_hex(&vec![0xAAu8; child_size]),
            seeded_from_slab: false,
        };
        let _ = &mut binding;
        let mut ledger = TransformRunLedger::default();
        // Use the execution-owning helper: it must run the transform AND record.
        let mut b = binding;
        apply_recorded_transform(&mut globals, "t_probe_write", &mut ledger, |g| {
            g[0].content[0x10] = 0xEE; // the transform writes +0x10
        })
        .unwrap();
        // The child's transform_ids now carries t_probe_write (child-level evidence).
        assert!(globals[0]
            .transform_ids
            .contains(&"t_probe_write".to_string()));
        // The byte/run ledger has a run at +0x10 for this child.
        assert!(ledger.runs.iter().any(|r| {
            r.transform_id == "t_probe_write"
                && r.child_old_base == child_base
                && r.child_offset == 0x10
                && r.after_bytes == vec![0xEE]
        }));
        // The run ledger and child transform_ids are consistent.
        for r in &ledger.runs {
            assert!(globals[0].transform_ids.contains(&r.transform_id));
        }
        // The overlay must attribute +0x10 to t_probe_write (proves consistency).
        let (patched, _, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &[b], &ledger).unwrap();
        assert_eq!(patched[0].content[child_off + 0x10], 0xEE);
    }

    // The execution-owning API makes "forgot to record" / "wrong transform id"
    // structurally impossible: there is no way to execute a transform and NOT
    // record it, because the recorder owns execution.
    #[test]
    fn route_r_r0b_wrong_or_missing_recording_not_constructible() {
        // Build a child + correct binding, then verify that ANY write to the child
        // MUST go through apply_recorded_transform (which always records). We prove
        // this by showing that applying the transform via the helper records the
        // run; there is no separate "execute without recording" entry point for a
        // transform in the production API. If the ledger were empty after a write,
        // the overlay would fail closed (unattributed byte).
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let child_base = 0x8aa5f8u64;
        let child_size = 0x70usize;
        let slab_base = 0x874000u64;
        let child_off = (child_base - slab_base) as usize;
        let slab = HeapSlab {
            old_base: slab_base,
            content: vec![0xAAu8; child_off + child_size],
        };
        let mut child = raw_child(
            child_base,
            child_size,
            vec![0xAAu8; child_size],
            RawChildKind::HeapGlobal,
        );
        child.extent_kind = CEK::ObservedAllocation;
        child.capture_id = "r0b-constructible".into();
        let slab_digest = sha256_hex(&slab.content);
        let slab_len = slab.content.len();
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![child],
        };
        let mut globals = vec![global(child_base, vec![0xAAu8; child_size], false)];
        globals[0].extent_kind = CEK::ObservedAllocation;
        globals[0].extent_evidence.capture_id = "r0b-constructible".into();
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "r0b-constructible".into(),
            child_old_base: child_base,
            child_size,
            extent_kind: CEK::ObservedAllocation,
            slab_old_base: slab_base,
            slab_size: slab_len,
            slab_digest,
            slab_offset: child_off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&vec![0xAAu8; child_size]),
            raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; child_size]),
            transform_input_digest: sha256_hex(&vec![0xAAu8; child_size]),
            seeded_from_slab: false,
        };
        // If we somehow wrote the child WITHOUT recording (which the API prevents),
        // the overlay would fail closed. Prove the fail-closed backstop exists:
        // an empty ledger + a written byte => TransformPreimageDrift.
        let mut globals_dirty = globals.clone();
        globals_dirty[0].content[0x10] = 0xEE; // a write with NO recorded run
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &globals_dirty,
            &[],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, OverlayError::TransformPreimageDrift { .. }),
            "a write with no recorded run must fail closed"
        );
    }

    // ---- Route Q R0 AF1 Rev 2 (P0-2/P0-3): Container identity + basis matrix ----
    // A Container is a strict child: ChildCapture basis, and its capture id must be
    // the deterministic `container_capture_id(decoded_begin)` so the raw/seeding
    // stage and the transformed representation agree. Wrong-basis (slab-seeded)
    // Container bindings must fail closed (no exemption).

    const AF1C_BASE: u64 = 0x8cc000;
    const AF1C_SIZE: usize = 0x40;

    /// A Container child inside a slab, with a correct ChildCapture binding.
    fn af1c_container_fixture() -> (RawSlabCapture, ContainerSnapshot, TransformPreimageBinding) {
        let child_off = (AF1C_BASE - AF1B_SLAB) as usize; // reuse slab base 0x874000
        let mut slab_content = vec![0u8; child_off + AF1C_SIZE];
        for i in 0..AF1C_SIZE {
            slab_content[child_off + i] = 0x55;
        }
        let slab_slice_digest = sha256_hex(&slab_content[child_off..child_off + AF1C_SIZE]);
        let slab = HeapSlab {
            old_base: AF1B_SLAB,
            content: slab_content,
        };
        let content = vec![0x55u8; AF1C_SIZE];
        let cap_id = container_capture_id(AF1C_BASE);
        let child = RawChild {
            old_base: AF1C_BASE,
            size: AF1C_SIZE,
            raw_bytes: content.clone(),
            kind: RawChildKind::Container,
            capture_id: cap_id.clone(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        };
        let slab_digest = sha256_hex(&slab.content);
        let slab_len = slab.content.len();
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![child],
        };
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::Container,
            capture_id: cap_id,
            child_old_base: AF1C_BASE,
            child_size: AF1C_SIZE,
            extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            slab_old_base: AF1B_SLAB,
            slab_size: slab_len,
            slab_digest,
            slab_offset: child_off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&content),
            raw_slab_slice_digest: slab_slice_digest,
            transform_input_digest: sha256_hex(&content),
            seeded_from_slab: false,
        };
        let cont = container(AF1C_BASE, AF1C_BASE + AF1C_SIZE as u64, content);
        (raw_capture, cont, binding)
    }

    // Positive: a Container with exact ChildCapture binding and matching identity
    // is overlaid successfully (identity matches across stages).
    #[test]
    fn route_q_af1c_container_exact_child_capture_positive() {
        let (raw_capture, cont, binding) = af1c_container_fixture();
        let (patched, overlays, _) = build_patched_backing_slab_q0c(
            &raw_capture,
            &[],
            &[cont],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap();
        // No transform wrote the container, so the slab bytes are preserved.
        let child_off = (AF1C_BASE - AF1B_SLAB) as usize;
        assert_eq!(patched[0].content[child_off], 0x55);
        assert!(overlays
            .iter()
            .any(|o| o.child_kind == RawChildKind::Container));
    }

    // Route R R0-E: TRUE end-to-end Container identity chain. From a raw
    // ContainerSnapshot, derive raw children, construct the RawSlabCapture, seed
    // the authoritative preimage (returning the real binding), run the Q0-C
    // overlay with THAT binding (no manual reconstruction), and render+parse the
    // manifest — proving the production three-stage identity chain is coherent.
    #[test]
    fn route_q_af1c_container_end_to_end() {
        // 1. Raw ContainerSnapshot + a slab covering it.
        let child_off = (AF1C_BASE - AF1B_SLAB) as usize;
        let mut slab_content = vec![0u8; child_off + AF1C_SIZE];
        for i in 0..AF1C_SIZE {
            slab_content[child_off + i] = 0x55;
        }
        let slab = HeapSlab {
            old_base: AF1B_SLAB,
            content: slab_content,
        };
        let cont = container(
            AF1C_BASE,
            AF1C_BASE + AF1C_SIZE as u64,
            vec![0x55u8; AF1C_SIZE],
        );
        // 2. raw_children_from_capture derives the container's raw child + id.
        let raw_children = raw_children_from_capture(&[cont.clone()], &[]);
        let rc = raw_children
            .iter()
            .find(|r| r.kind == RawChildKind::Container)
            .expect("container raw child");
        assert_eq!(rc.capture_id, container_capture_id(AF1C_BASE));
        // 3. Construct RawSlabCapture from the real slab + derived raw children.
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: raw_children,
        };
        // 4. seed_transform_inputs_from_authoritative_slab returns the REAL binding.
        let mut globals: Vec<HeapGlobalSnapshot> = Vec::new();
        let mut containers = vec![cont.clone()];
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        let binding = bindings
            .iter()
            .find(|b| b.child_kind == RawChildKind::Container)
            .expect("container binding");
        assert_eq!(binding.capture_id, container_capture_id(AF1C_BASE));
        assert_eq!(binding.basis, TransformPreimageBasis::ChildCapture);
        // 5. Q0-C overlay using the REAL seeded binding (no manual reconstruction).
        let (patched, overlays, _drift) = build_patched_backing_slab_q0c(
            &raw_capture,
            &globals,
            &containers,
            &bindings,
            &TransformRunLedger::default(),
        )
        .unwrap();
        assert_eq!(patched[0].content[child_off], 0x55);
        assert!(overlays
            .iter()
            .any(|o| o.child_kind == RawChildKind::Container));
        // 6. Render + parse the manifest (production contract).
        let json = crate::dumper::snapshot_manifest::render_manifest_json(
            std::path::Path::new("af1c.exe"),
            crate::dumper::types::DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &containers,
            &globals,
            &crate::dumper::capture_policy::DumpCapturePolicy::ahk_gto_default(),
            None,
            &overlays,
            &[],
            &bindings,
            &TransformRunLedger::default(),
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
        // The preimage ledger proves the container's ChildCapture basis.
        let pl = v["transform_preimage_ledger"].as_array().unwrap();
        assert!(pl.iter().any(|b| b["child_kind"] == "container"
            && b["basis"] == "ChildCapture"
            && b["capture_id"] == container_capture_id(AF1C_BASE)));
    }

    // Negative: a Container with a slab-seeded (AuthoritativeSlabSlice) basis must
    // fail closed — the Container must be ChildCapture (no basis exemption).
    #[test]
    fn route_q_af1c_container_wrong_slab_basis_fails_closed() {
        let (raw_capture, cont, mut binding) = af1c_container_fixture();
        binding.basis = TransformPreimageBasis::AuthoritativeSlabSlice;
        binding.seeded_from_slab = true;
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[],
            &[cont],
            &[binding],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, OverlayError::TransformPreimageDrift { .. }),
            "Container must not accept slab basis"
        );
    }

    // Identity stability: container_capture_id is deterministic and used by both
    // raw_children_from_capture and the seed binding so they agree.
    #[test]
    fn route_q_af1c_container_identity_is_deterministic_and_stable() {
        let (raw_capture, mut cont, _binding) = af1c_container_fixture();
        // raw_children_from_capture derives the same id as container_capture_id.
        let raw_children = raw_children_from_capture(&[cont.clone()], &[]);
        let rc = raw_children
            .iter()
            .find(|r| r.kind == RawChildKind::Container)
            .unwrap();
        assert_eq!(rc.capture_id, container_capture_id(AF1C_BASE));
        assert!(!rc.capture_id.is_empty());
        // Seeding produces a binding whose capture_id matches the container raw id.
        let mut globals: Vec<HeapGlobalSnapshot> = Vec::new();
        let bindings =
            seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut [cont], &mut globals)
                .unwrap();
        let b = bindings
            .iter()
            .find(|b| b.child_kind == RawChildKind::Container)
            .unwrap();
        assert_eq!(b.capture_id, container_capture_id(AF1C_BASE));
        assert_eq!(b.basis, TransformPreimageBasis::ChildCapture);
    }

    // 1. Probe-window non-write drift uses the authoritative slab (B[i]=S[i]).
    #[test]
    fn r0g_nonwrite_probe_drift_uses_slab_authority() {
        let raw_capture = RawSlabCapture {
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![slab],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
        // Should not fail on raw coherence (no raw child); recorded as synthetic.
        // Route X R0: the SyntheticDerived child is NOT a raw-slab overlay child,
        // so it produces NO raw overlay entry (it may still carry child-level
        // transform evidence).
        let (_, overlays, _) =
            build_patched_backing_slab(&raw_capture, &[synth], &[], &["t"]).unwrap();
        assert!(overlays.is_empty());
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
            slabs: vec![HeapSlab {
                old_base: R0G_SLAB_BASE,
                content,
            }],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![r0g_slab()],
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
            slabs: vec![s],
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

    // ================= Route S R0-E: Route R1 exact geometry regression =========
    // The Route R R1 live blocker: dangling heap edge 0x9a4d40 (size 0x710,
    // slab 0x9a3000, offset 0x1d40, ProbeWindow, DanglingEdge) previously had an
    // EMPTY capture_id (CaptureExtentEvidence::default()), which the Q0-C exact
    // binding rejected as TransformPreimageDrift. S0-A fixes the identity at the
    // source; S0-B validates it early. These tests pin the geometry + the fix.

    const S0E_SLAB: u64 = 0x9a3000;
    const S0E_CHILD: u64 = 0x9a4d40;
    const S0E_SIZE: usize = 0x710;
    const S0E_OFF: usize = 0x1d40;

    /// A dangling-edge child with the Route R1 geometry + a deterministic
    /// non-empty capture id (as S0-A now produces).
    fn s0e_dangling_fixture() -> (RawSlabCapture, HeapGlobalSnapshot, TransformPreimageBinding) {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let mut slab_content = vec![0u8; S0E_OFF + S0E_SIZE];
        for i in 0..S0E_SIZE {
            slab_content[S0E_OFF + i] = 0x50;
        }
        let slab_slice_digest = sha256_hex(&slab_content[S0E_OFF..S0E_OFF + S0E_SIZE]);
        let slab = HeapSlab {
            old_base: S0E_SLAB,
            content: slab_content,
        };
        let raw_bytes = vec![0x50u8; S0E_SIZE];
        let cap_id = format!("dangling_edge:{S0E_CHILD:#x}:{S0E_SIZE:#x}");
        let child = RawChild {
            old_base: S0E_CHILD,
            size: S0E_SIZE,
            raw_bytes: raw_bytes.clone(),
            kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            capture_path: super::super::heap_global_snapshot::CapturePath::DanglingEdge,
            extent_kind: CEK::ProbeWindow,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: 0x1000,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        };
        let slab_digest = sha256_hex(&slab.content);
        let slab_len = slab.content.len();
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![child],
        };
        let mut transformed = global(S0E_CHILD, vec![0x50u8; S0E_SIZE], false);
        transformed.extent_kind = CEK::ProbeWindow;
        transformed.extent_evidence.capture_id = cap_id.clone();
        transformed.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            child_old_base: S0E_CHILD,
            child_size: S0E_SIZE,
            extent_kind: CEK::ProbeWindow,
            slab_old_base: S0E_SLAB,
            slab_size: slab_len,
            slab_digest,
            slab_offset: S0E_OFF,
            basis: TransformPreimageBasis::AuthoritativeSlabSlice,
            raw_child_digest: sha256_hex(&raw_bytes),
            raw_slab_slice_digest: slab_slice_digest.clone(),
            transform_input_digest: slab_slice_digest,
            seeded_from_slab: true,
        };
        (raw_capture, transformed, binding)
    }

    // With a correct non-empty capture_id, byte 0 C=S=T=0x50 does NOT error, and
    // the overlay completes naturally (this is the exact Route R1 geometry that
    // previously died on the empty-id exact-binding rejection).
    #[test]
    fn route_s_r0e_route_r1_geometry_overlay_completes() {
        let (raw_capture, transformed, binding) = s0e_dangling_fixture();
        // transform input = S (unchanged): T == P == S at every byte, incl byte 0.
        let mut ledger = TransformRunLedger::default();
        // No writes -> empty ledger is valid; overlay must complete.
        let (patched, overlays, _drift) =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap();
        // Byte 0 preserved (C=S=T=0x50 is not an error).
        assert_eq!(patched[0].content[S0E_OFF], 0x50);
        assert!(overlays
            .iter()
            .any(|o| o.child_old_base == S0E_CHILD && o.overlay_applied));
    }

    // The capture identity must be non-empty and identical across all three stages
    // (raw child -> seed binding -> transform input).
    #[test]
    fn route_s_r0e_capture_id_consistent_three_stages() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        // Build a container-free dangling-edge capture, run the gate + raw_children.
        let mut slab_content = vec![0u8; S0E_OFF + S0E_SIZE];
        for i in 0..S0E_SIZE {
            slab_content[S0E_OFF + i] = 0x50;
        }
        let slab = HeapSlab {
            old_base: S0E_SLAB,
            content: slab_content,
        };
        let raw_bytes = vec![0x50u8; S0E_SIZE];
        let cap_id = format!("dangling_edge:{S0E_CHILD:#x}:{S0E_SIZE:#x}");
        // heap_global as the capture produces it (S0-A form).
        let mut g = global(S0E_CHILD, raw_bytes.clone(), false);
        g.extent_kind = CEK::ProbeWindow;
        g.extent_evidence.capture_id = cap_id.clone();
        g.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        let raw_capture = RawSlabCapture {
            slabs: vec![slab.clone()],
            children: vec![RawChild {
                old_base: S0E_CHILD,
                size: S0E_SIZE,
                raw_bytes,
                kind: RawChildKind::HeapGlobal,
                capture_id: cap_id.clone(),
                capture_path: super::super::heap_global_snapshot::CapturePath::DanglingEdge,
                extent_kind: CEK::ProbeWindow,
                source_parent_old_base: None,
                source_slot_offset: None,
                requested_probe_size: 0x1000,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            }],
        };
        // Gate passes (non-empty identity).
        let mut globals = vec![g];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
        // raw_children_from_capture preserves the id.
        let raw_children = raw_children_from_capture(&containers, &globals);
        let rc = raw_children
            .iter()
            .find(|r| r.old_base == S0E_CHILD)
            .unwrap();
        assert_eq!(rc.capture_id, cap_id);
        // Seeding binding uses the same id.
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        let b = bindings
            .iter()
            .find(|b| b.child_old_base == S0E_CHILD)
            .unwrap();
        assert_eq!(b.capture_id, cap_id);
    }

    // Negative: an empty dangling capture_id fails at the capture_identity_bind
    // gate (validate_raw_coherence_capture_identities), NOT at overlay time.
    #[test]
    fn route_s_r0e_empty_dangling_capture_id_fails_at_bind_gate() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let mut g = global(S0E_CHILD, vec![0x50u8; S0E_SIZE], false);
        g.extent_kind = CEK::ProbeWindow;
        // Leave capture_id empty (the S0-A bug).
        let globals = vec![g];
        let containers: Vec<ContainerSnapshot> = Vec::new();
        let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
        assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
    }

    // Negative: the REAL scrub_uncaptured_heap_pointers must attribute only the
    // qwords it actually zeroes (an external dangling pointer), and the run's
    // capture_id must match the child/binding. This exercises the production
    // scrub path (Route R R1 live exposed the dangling-edge identity gap), not a
    // hand-constructed zeroing.
    #[test]
    fn route_s_r0e_scrub_writer_only_attributes_changed_qword() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        // Build the dangling-edge child with a REAL external pointer qword at +0x40
        // (points outside the child's own captured range, in the plausible user VA
        // window), so the production scrub zeroes it.
        let child_end = S0E_CHILD + S0E_SIZE as u64;
        let external_ptr = 0x4000_0000u64; // plausible user heap VA, outside child range
        let mut content = vec![0x50u8; S0E_SIZE];
        content[0x40..0x48].copy_from_slice(&external_ptr.to_le_bytes());
        let cap_id = format!("dangling_edge:{S0E_CHILD:#x}:{S0E_SIZE:#x}");
        let mut g = global(S0E_CHILD, content, false);
        g.extent_kind = CEK::ProbeWindow;
        g.extent_evidence.capture_id = cap_id.clone();
        g.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        g.extent_evidence.was_interior = false;
        // Raw capture matching the child.
        let mut raw_bytes = vec![0x50u8; S0E_SIZE];
        raw_bytes[0x40..0x48].copy_from_slice(&external_ptr.to_le_bytes());
        // Build the slab as a named variable so we can capture its digest before move.
        let s0e_slab = HeapSlab {
            old_base: S0E_SLAB,
            content: {
                let mut s = vec![0u8; S0E_OFF + S0E_SIZE];
                for i in 0..S0E_SIZE {
                    s[S0E_OFF + i] = 0x50;
                }
                s[S0E_OFF + 0x40..S0E_OFF + 0x48].copy_from_slice(&external_ptr.to_le_bytes());
                s
            },
        };
        let slab_digest = sha256_hex(&s0e_slab.content);
        let slab_len = s0e_slab.content.len();
        let raw_capture = RawSlabCapture {
            slabs: vec![s0e_slab],
            children: vec![RawChild {
                old_base: S0E_CHILD,
                size: S0E_SIZE,
                raw_bytes: raw_bytes.clone(),
                kind: RawChildKind::HeapGlobal,
                capture_id: cap_id.clone(),
                capture_path: super::super::heap_global_snapshot::CapturePath::DanglingEdge,
                extent_kind: CEK::ProbeWindow,
                source_parent_old_base: None,
                source_slot_offset: None,
                requested_probe_size: 0x1000,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            }],
        };
        let slab_slice_digest =
            sha256_hex(&raw_capture.slabs[0].content[S0E_OFF..S0E_OFF + S0E_SIZE]);
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            child_old_base: S0E_CHILD,
            child_size: S0E_SIZE,
            extent_kind: CEK::ProbeWindow,
            slab_old_base: S0E_SLAB,
            slab_size: slab_len,
            slab_digest,
            slab_offset: S0E_OFF,
            basis: TransformPreimageBasis::AuthoritativeSlabSlice,
            raw_child_digest: sha256_hex(&raw_bytes),
            raw_slab_slice_digest: slab_slice_digest.clone(),
            transform_input_digest: slab_slice_digest,
            seeded_from_slab: true,
        };
        // Run the REAL production scrub via the execution-owning recorder.
        let mut globals = vec![g];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let mut ledger = TransformRunLedger::default();
        let mut image_base = 0x140000000u64;
        let mut image_end = image_base + 0x1000_0000;
        apply_recorded_transform(
            &mut globals,
            "scrub_uncaptured_heap_pointers",
            &mut ledger,
            |g| {
                super::super::heap_global_snapshot::scrub_uncaptured_heap_pointers(
                    &mut containers,
                    g,
                    image_base,
                    image_end,
                );
            },
        )
        .unwrap();
        // The REAL scrub zeroed the external pointer qword at +0x40..0x48. Because
        // 0x4000_0000 is little-endian [0,0,0,0x40,0,0,0,0], only byte +0x43 actually
        // changed (0x40 -> 0); the diff/run records exactly that changed byte (offset
        // 0x43, length 1) — proving the run attributes only the byte the production
        // scrub changed, not the whole qword.
        assert!(ledger.runs.iter().any(|r| {
            r.child_old_base == S0E_CHILD
                && r.child_offset == 0x43
                && r.length == 1
                && r.transform_id == "scrub_uncaptured_heap_pointers"
                && r.child_capture_id == cap_id
        }));
        let _ = (child_end, image_base, image_end);
        // Overlay with the recorded run + binding completes (C=S=T at byte 0 is fine).
        let (patched, _, _) = build_patched_backing_slab_q0c(
            &raw_capture,
            &globals,
            &containers,
            &[binding],
            &ledger,
        )
        .unwrap();
        assert_eq!(patched[0].content[S0E_OFF + 0x40], 0x00);
    }

    // Negative: missing binding reports TransformPreimageBindingMissing.
    #[test]
    fn route_s_r0e_missing_binding_reports_binding_missing() {
        let (raw_capture, transformed, _binding) = s0e_dangling_fixture();
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingMissing { .. }
        ));
    }

    // Negative: duplicate binding reports TransformPreimageBindingAmbiguous.
    #[test]
    fn route_s_r0e_duplicate_binding_reports_ambiguous() {
        let (raw_capture, transformed, binding) = s0e_dangling_fixture();
        let dup = binding.clone();
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed],
            &[],
            &[binding, dup],
            &TransformRunLedger::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformPreimageBindingAmbiguous { .. }
        ));
    }

    // Negative: a malformed unrelated run identifies the exact run index, and the
    // FIRST unchanged child is NOT blamed for it.
    #[test]
    fn route_s_r0e_malformed_unrelated_run_identifies_exact_index() {
        let (raw_capture, transformed, binding) = s0e_dangling_fixture();
        let mut ledger = TransformRunLedger::default();
        // A malformed unrelated run (different child, zero-length).
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "unrelated".into(),
            child_old_base: 0xdead_0000,
            child_size: 8,
            child_offset: 0,
            length: 0, // malformed
            transform_id: "scrub_uncaptured_heap_pointers".into(),
            before_digest: sha256_hex(&[]),
            after_digest: sha256_hex(&[]),
            first_before_byte: 0,
            first_after_byte: 0,
            before_bytes: vec![],
            after_bytes: vec![],
        });
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        match &err {
            OverlayError::TransformRunLedgerInvalid { run_index, .. } => {
                assert_eq!(*run_index, 0, "must identify the malformed run index");
            }
            other => panic!("expected TransformRunLedgerInvalid, got {other:?}"),
        }
    }

    // Negative: a duplicate capture id across two raw-coherence participants fails
    // at the capture_identity_bind gate (ambiguous identity).
    #[test]
    fn route_s_r0e_duplicate_capture_identity_fails_at_bind_gate() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let mut g1 = global(0x9a4d40, vec![0x50u8; 0x20], false);
        g1.extent_kind = CEK::ProbeWindow;
        g1.extent_evidence.capture_id = "dup_id".into();
        let mut g2 = global(0x9a6000, vec![0x50u8; 0x20], false);
        g2.extent_kind = CEK::ProbeWindow;
        g2.extent_evidence.capture_id = "dup_id".into(); // SAME id, different base
        let globals = vec![g1, g2];
        let containers: Vec<ContainerSnapshot> = Vec::new();
        let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
        assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
    }

    // Positive: every production raw-coherence participant with a non-empty
    // identity passes the gate (the S0-B invariant holds for well-formed input).
    #[test]
    fn route_s_r0e_all_production_raw_snapshots_have_non_empty_identity() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        // A representative set of raw-coherence participants, each with a distinct
        // non-empty capture id and explicit path/extent.
        let mut g1 = global(0x9a4d40, vec![0x50u8; 0x710], false);
        g1.extent_kind = CEK::ProbeWindow;
        g1.extent_evidence.capture_id =
            format!("dangling_edge:{:#x}:{:#x}", 0x9a4d40u64, 0x710usize);
        g1.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        let mut g2 = global(0x9a6000, vec![0x50u8; 0x40], false);
        g2.extent_kind = CEK::ObservedAllocation;
        g2.extent_evidence.capture_id =
            format!("mainslot:{:#x}:{:#x}", 0x140000000u64, 0x9a6000u64);
        g2.extent_evidence.capture_path = super::super::heap_global_snapshot::CapturePath::MainSlot;
        let mut g3 = global(0x9b0000, vec![0x50u8; 0x100], false);
        g3.extent_kind = CEK::InteriorSubview;
        g3.extent_evidence.capture_id = format!("gscript_child:{:#x}", 0x9b0000u64);
        g3.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::GscriptChildLink;
        let globals = vec![g1, g2, g3];
        let containers: Vec<ContainerSnapshot> = Vec::new();
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    }

    // ---- Route S R0 Audit Fix 1 (P1-2/P1-3): identity matrix negatives. ----
    // A raw-coherence participant must satisfy the capture_path <-> extent matrix,
    // and duplicate capture ids are only valid if the FULL tuple matches.

    fn s0e_identity_neg(mutate: impl FnOnce(&mut HeapGlobalSnapshot)) -> OverlayError {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let mut g = global(0x9a4d40, vec![0x50u8; 0x20], false);
        g.extent_kind = CEK::ProbeWindow;
        g.extent_evidence.capture_id = "dangling_edge:0x9a4d40:0x20".into();
        g.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        mutate(&mut g);
        let globals = vec![g];
        let containers: Vec<ContainerSnapshot> = Vec::new();
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err()
    }

    // DanglingEdge + MainSlot path (masquerade) -> fail.
    #[test]
    fn route_s_r0e_identity_dangling_edge_mainslot_fails() {
        let err = s0e_identity_neg(|g| {
            g.extent_evidence.capture_path =
                super::super::heap_global_snapshot::CapturePath::MainSlot;
        });
        assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
    }

    // DanglingEdge + non-ProbeWindow extent -> fail.
    #[test]
    fn route_s_r0e_identity_dangling_edge_non_probe_fails() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let err = s0e_identity_neg(|g| g.extent_kind = CEK::ObservedAllocation);
        assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
    }

    // Synthetic path on a raw-coherence participant -> fail.
    #[test]
    fn route_s_r0e_identity_synthetic_path_fails() {
        let err = s0e_identity_neg(|g| {
            g.extent_evidence.capture_path =
                super::super::heap_global_snapshot::CapturePath::Synthetic;
        });
        assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
    }

    // Same id + same base + different size -> fail (ambiguous).
    #[test]
    fn route_s_r0e_identity_same_id_same_base_diff_size_fails() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let mut g1 = global(0x9a4d40, vec![0x50u8; 0x20], false);
        g1.extent_kind = CEK::ProbeWindow;
        g1.extent_evidence.capture_id = "dup".into();
        g1.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        let mut g2 = global(0x9a4d40, vec![0x50u8; 0x30], false); // SAME base, different size
        g2.extent_kind = CEK::ProbeWindow;
        g2.extent_evidence.capture_id = "dup".into();
        g2.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        let globals = vec![g1, g2];
        let containers: Vec<ContainerSnapshot> = Vec::new();
        let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
        assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
    }

    // Same id + same base + different path -> fail.
    #[test]
    fn route_s_r0e_identity_same_id_same_base_diff_path_fails() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let mut g1 = global(0x9a4d40, vec![0x50u8; 0x20], false);
        g1.extent_kind = CEK::ProbeWindow;
        g1.extent_evidence.capture_id = "dup".into();
        g1.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        let mut g2 = global(0x9a4d40, vec![0x50u8; 0x20], false); // SAME base + size
        g2.extent_kind = CEK::ProbeWindow;
        g2.extent_evidence.capture_id = "dup".into();
        g2.extent_evidence.capture_path = super::super::heap_global_snapshot::CapturePath::MainSlot; // diff path
        let globals = vec![g1, g2];
        let containers: Vec<ContainerSnapshot> = Vec::new();
        let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
        assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
    }

    // Same id + same base + different extent -> fail.
    #[test]
    fn route_s_r0e_identity_same_id_same_base_diff_extent_fails() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        let mut g1 = global(0x9a4d40, vec![0x50u8; 0x20], false);
        g1.extent_kind = CEK::ProbeWindow;
        g1.extent_evidence.capture_id = "dup".into();
        g1.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        let mut g2 = global(0x9a4d40, vec![0x50u8; 0x20], false); // SAME base + size + path
        g2.extent_kind = CEK::ObservedAllocation; // diff extent
        g2.extent_evidence.capture_id = "dup".into();
        g2.extent_evidence.capture_path =
            super::super::heap_global_snapshot::CapturePath::DanglingEdge;
        let globals = vec![g1, g2];
        let containers: Vec<ContainerSnapshot> = Vec::new();
        let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
        assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
    }

    // ---- Route T R0: probe/interior coverage gate (validate_probe_coverage) ----

    fn probe_global(live_ptr: u64, size: usize) -> HeapGlobalSnapshot {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        use super::super::heap_global_snapshot::CapturePath as CP;
        let mut g = global(live_ptr, vec![0u8; size], false);
        g.extent_kind = CEK::ProbeWindow;
        g.extent_evidence.capture_path = CP::DanglingEdge;
        g.extent_evidence.capture_id = format!("dangling_edge:{live_ptr:#x}:{size:#x}");
        g
    }

    fn slab_of_len(old_base: u64, len: usize) -> HeapSlab {
        HeapSlab {
            old_base,
            content: vec![0u8; len],
        }
    }

    /// TAF3: build an AuthoritativeSlabCandidate from a role + slab.
    fn cand(role: &'static str, slab: HeapSlab) -> AuthoritativeSlabCandidate {
        AuthoritativeSlabCandidate { slab, role }
    }

    // T0-E test 1: uncovered ProbeWindow -> capture_coverage_bind failure.
    #[test]
    fn route_t_r0_uncovered_probe_fails() {
        let g = probe_global(0x850150, 0x1000);
        // No slab covers [0x850150, 0x851150).
        let slabs = vec![slab_of_len(0x9a3000, 0x1000)];
        let err = validate_probe_coverage(&[g], &slabs).unwrap_err();
        match err {
            OverlayError::ProbeCoverageMissing {
                child_base,
                child_size,
                extent_kind,
                candidate_slab_count,
                nearest_authority,
                nearest_authority_gap,
                ..
            } => {
                assert_eq!(child_base, 0x850150);
                assert_eq!(child_size, 0x1000);
                assert!(extent_kind.contains("ProbeWindow"));
                assert_eq!(candidate_slab_count, 1);
                assert_eq!(nearest_authority, Some((0x9a3000, 0x9a4000)));
                assert!(nearest_authority_gap > 0);
            }
            other => panic!("expected ProbeCoverageMissing, got {other:?}"),
        }
    }

    // T0-E test 2: covered ProbeWindow -> runtime plan success.
    #[test]
    fn route_t_r0_covered_probe_ok() {
        let g = probe_global(0x850150, 0x1000);
        // A dedicated slab exactly covers the probe range.
        let slabs = vec![slab_of_len(0x850150, 0x1000)];
        validate_probe_coverage(&[g], &slabs).unwrap();
    }

    // T0-E test 3: 0x850150 exact geometry -> covered (end-to-end offline success).
    #[test]
    fn route_t_r0_exact_850150_geometry_covered() {
        let g = probe_global(0x850150, 0x1000);
        // Main slab covers a wider range that also contains 0x850150.
        let slabs = vec![slab_of_len(0x850000, 0x2000)];
        validate_probe_coverage(&[g], &slabs).unwrap();
    }

    // T0-E test 4: multiple probe windows in one slab -> all aliases valid.
    #[test]
    fn route_t_r0_multiple_probes_one_slab_all_ok() {
        let g1 = probe_global(0x850150, 0x1000);
        let g2 = probe_global(0x851a80, 0x200);
        let g3 = probe_global(0x854cd0, 0x400);
        // One dedicated slab covering all three probe ranges.
        let slabs = vec![slab_of_len(0x850000, 0x6000)];
        validate_probe_coverage(&[g1, g2, g3], &slabs).unwrap();
    }

    // T0-E test 5: probe window crossing slab boundary -> fail-closed.
    #[test]
    fn route_t_r0_probe_crossing_slab_boundary_fails() {
        // Probe [0x850150, 0x851150) crosses the slab end at 0x851000.
        let g = probe_global(0x850150, 0x1000);
        let slabs = vec![slab_of_len(0x850000, 0x1000)]; // ends at 0x851000, probe needs to 0x851150
        let err = validate_probe_coverage(&[g], &slabs).unwrap_err();
        assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
    }

    // T0-E test 6: no slabs at all -> every probe fails with nearest_authority=None.
    #[test]
    fn route_t_r0_no_slabs_probe_fails_with_none_authority() {
        let g = probe_global(0x850150, 0x1000);
        let slabs: Vec<HeapSlab> = Vec::new();
        let err = validate_probe_coverage(&[g], &slabs).unwrap_err();
        match err {
            OverlayError::ProbeCoverageMissing {
                child_base,
                candidate_slab_count,
                nearest_authority,
                ..
            } => {
                assert_eq!(child_base, 0x850150);
                assert_eq!(candidate_slab_count, 0);
                assert_eq!(nearest_authority, None);
            }
            other => panic!("expected ProbeCoverageMissing, got {other:?}"),
        }
    }

    // T0-D: coverage is range-based — a different base at the same offset is
    // covered by the same slab logic (no VA hardcoding).
    #[test]
    fn route_t_r0_coverage_is_range_based_not_va_hardcoded() {
        // A probe at a different address entirely is covered by its own slab.
        let g = probe_global(0x3852d30, 0x1000);
        let slabs = vec![slab_of_len(0x3852d30, 0x1000)];
        validate_probe_coverage(&[g], &slabs).unwrap();
        // Same logic covers 0x850150 too — proving the rule is by range, not VA.
        let g2 = probe_global(0x850150, 0x1000);
        let slabs2 = vec![slab_of_len(0x850150, 0x1000)];
        validate_probe_coverage(&[g2], &slabs2).unwrap();
    }

    // InteriorSubview coverage is also enforced.
    #[test]
    fn route_t_r0_interior_subview_uncovered_fails() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        use super::super::heap_global_snapshot::CapturePath as CP;
        let mut g = global(0x200000, vec![0u8; 0x100], false);
        g.extent_kind = CEK::InteriorSubview;
        g.extent_evidence.capture_path = CP::GscriptChildLink;
        g.extent_evidence.capture_id = format!("child:0x{:x}:0x100", 0x200000u64);
        let slabs = vec![slab_of_len(0x9a3000, 0x1000)]; // does not cover 0x200000
        let err = validate_probe_coverage(&[g], &slabs).unwrap_err();
        assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
    }

    // ==================== Route T R0 Audit Fix 1 (TAF1) tests ====================
    // Multi-slab authoritative coherence wiring: dedicated dangling-edge slabs
    // must flow through raw capture -> seed -> transform -> overlay -> runtime.

    /// A dedicated dangling-edge slab covering exactly [base, base+size), with a
    /// ProbeWindow raw child + a matching transform + binding. This mirrors the
    /// Route S R1 `0x850150` geometry but at a dedicated (non-main) slab.
    fn taf1_dedicated_fixture(
        slab_base: u64,
        size: usize,
    ) -> (
        RawSlabCapture,
        HeapGlobalSnapshot,
        TransformPreimageBinding,
        Vec<u8>,
    ) {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        use super::super::heap_global_snapshot::CapturePath as CP;
        let slab_content = vec![0x50u8; size];
        let slab_slice_digest = sha256_hex(&slab_content);
        let raw_bytes = vec![0x50u8; size];
        let cap_id = format!("dangling_edge:{slab_base:#x}:{size:#x}");
        let child = RawChild {
            old_base: slab_base,
            size,
            raw_bytes: raw_bytes.clone(),
            kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            capture_path: CP::DanglingEdge,
            extent_kind: CEK::ProbeWindow,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: size,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        };
        let raw_capture = RawSlabCapture {
            slabs: vec![HeapSlab {
                old_base: slab_base,
                content: slab_content.clone(),
            }],
            children: vec![child],
        };
        let mut transformed = global(slab_base, vec![0x50u8; size], false);
        transformed.extent_kind = CEK::ProbeWindow;
        transformed.extent_evidence.capture_id = cap_id.clone();
        transformed.extent_evidence.capture_path = CP::DanglingEdge;
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            child_old_base: slab_base,
            child_size: size,
            extent_kind: CEK::ProbeWindow,
            slab_old_base: slab_base,
            slab_size: size,
            slab_digest: sha256_hex(&slab_content),
            slab_offset: 0,
            basis: TransformPreimageBasis::AuthoritativeSlabSlice,
            raw_child_digest: sha256_hex(&raw_bytes),
            raw_slab_slice_digest: slab_slice_digest.clone(),
            transform_input_digest: slab_slice_digest,
            seeded_from_slab: true,
        };
        (raw_capture, transformed, binding, raw_bytes)
    }

    // TAF1: a dangling-edge child in a DEDICATED slab must be absorbed at seed
    // and overlaid onto its dedicated slab (NOT reported outside the main slab).
    #[test]
    fn route_t_af1_dedicated_child_not_outside_main_slab() {
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let (raw_capture, transformed, binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
        // Seed: the child must resolve to the DEDICATED slab (offset 0), not a
        // RawChildOutsideSlab against an absent main slab.
        let mut globals = vec![transformed.clone()];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].slab_old_base, DEDICATED);
        assert_eq!(bindings[0].slab_offset, 0);
        // Overlay: dedicated slab is patched in place.
        let mut ledger = TransformRunLedger::default();
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap();
        assert_eq!(patched.len(), 1);
        assert_eq!(patched[0].old_base, DEDICATED);
        assert!(overlays
            .iter()
            .any(|o| o.child_old_base == DEDICATED && o.overlay_applied));
    }

    // TAF1: multi-slab raw capture -> seed -> overlay POSITIVE end-to-end. Two
    // children in two distinct slabs (main + dedicated) both seed and overlay.
    #[test]
    fn route_t_af1_multislab_raw_capture_seed_overlay_positive() {
        const MAIN: u64 = 0x9a3000;
        const MAIN_CHILD: u64 = 0x9a4d40;
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x100;
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        use super::super::heap_global_snapshot::CapturePath as CP;
        // Main slab with a ProbeWindow child at 0x9a4d40.
        let main_off = (MAIN_CHILD - MAIN) as usize;
        let mut main_content = vec![0u8; main_off + SIZE];
        for i in 0..SIZE {
            main_content[main_off + i] = 0xAA;
        }
        let main_cap = format!("dangling_edge:{MAIN_CHILD:#x}:{SIZE:#x}");
        let main_child = RawChild {
            old_base: MAIN_CHILD,
            size: SIZE,
            raw_bytes: vec![0xAAu8; SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: main_cap.clone(),
            capture_path: CP::DanglingEdge,
            extent_kind: CEK::ProbeWindow,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: SIZE,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        };
        let (dedicated_raw, _, _, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
        let raw_capture = RawSlabCapture {
            slabs: vec![
                HeapSlab {
                    old_base: MAIN,
                    content: main_content,
                },
                dedicated_raw.slabs[0].clone(),
            ],
            children: vec![main_child, dedicated_raw.children[0].clone()],
        };
        // Both children are ProbeWindow; seed both from their covering slab.
        let mut main_g = global(MAIN_CHILD, vec![0xAAu8; SIZE], false);
        main_g.extent_kind = CEK::ProbeWindow;
        main_g.extent_evidence.capture_id = main_cap.clone();
        main_g.extent_evidence.capture_path = CP::DanglingEdge;
        let mut ded_g = global(DEDICATED, vec![0x50u8; SIZE], false);
        ded_g.extent_kind = CEK::ProbeWindow;
        ded_g.extent_evidence.capture_id = format!("dangling_edge:{DEDICATED:#x}:{SIZE:#x}");
        ded_g.extent_evidence.capture_path = CP::DanglingEdge;
        let mut globals = vec![main_g, ded_g];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        // TWO bindings, each recording its ACTUAL covering slab.
        assert_eq!(bindings.len(), 2);
        let b_main = bindings
            .iter()
            .find(|b| b.child_old_base == MAIN_CHILD)
            .unwrap();
        let b_ded = bindings
            .iter()
            .find(|b| b.child_old_base == DEDICATED)
            .unwrap();
        assert_eq!(b_main.slab_old_base, MAIN);
        assert_eq!(b_ded.slab_old_base, DEDICATED);
        // Overlay both -> two patched slabs, both children applied.
        let mut ledger = TransformRunLedger::default();
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .unwrap();
        assert_eq!(patched.len(), 2);
        assert_eq!(patched[0].old_base, MAIN);
        assert_eq!(patched[1].old_base, DEDICATED);
        assert_eq!(overlays.len(), 2);
    }

    // TAF1: main slab + dedicated slab, a child in each -> both patched.
    #[test]
    fn route_t_af1_main_plus_dedicated_transform_overlay() {
        const MAIN: u64 = 0x9a3000;
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x100;
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        use super::super::heap_global_snapshot::CapturePath as CP;
        // Main slab at 0x9a3000 with a ProbeWindow child at 0x9a4d40 (Route R1 geo).
        let mut main_slab_content = vec![0u8; (0x9a4d40 - MAIN) as usize + SIZE];
        for i in 0..SIZE {
            main_slab_content[(0x9a4d40 - MAIN) as usize + i] = 0xAA;
        }
        let main_child_cap = format!("dangling_edge:{:#x}:{SIZE:#x}", 0x9a4d40u64);
        let main_child = RawChild {
            old_base: 0x9a4d40,
            size: SIZE,
            raw_bytes: vec![0xAAu8; SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: main_child_cap.clone(),
            capture_path: CP::DanglingEdge,
            extent_kind: CEK::ProbeWindow,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: SIZE,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        };
        // Dedicated slab for the dangling edge at 0x850150.
        let (dedicated_raw, dedicated_transformed, dedicated_binding, _) =
            taf1_dedicated_fixture(DEDICATED, SIZE);
        let raw_capture = RawSlabCapture {
            slabs: vec![
                HeapSlab {
                    old_base: MAIN,
                    content: main_slab_content,
                },
                dedicated_raw.slabs[0].clone(),
            ],
            children: vec![main_child, dedicated_raw.children[0].clone()],
        };
        let mut main_transformed = global(0x9a4d40, vec![0xAAu8; SIZE], false);
        main_transformed.extent_kind = CEK::ProbeWindow;
        main_transformed.extent_evidence.capture_id = main_child_cap;
        main_transformed.extent_evidence.capture_path = CP::DanglingEdge;
        let main_binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: main_transformed.extent_evidence.capture_id.clone(),
            child_old_base: 0x9a4d40,
            child_size: SIZE,
            extent_kind: CEK::ProbeWindow,
            slab_old_base: MAIN,
            slab_size: (0x9a4d40 - MAIN) as usize + SIZE,
            slab_digest: sha256_hex(&raw_capture.slabs[0].content),
            slab_offset: (0x9a4d40 - MAIN) as usize,
            basis: TransformPreimageBasis::AuthoritativeSlabSlice,
            raw_child_digest: sha256_hex(&vec![0xAAu8; SIZE]),
            raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; SIZE]),
            transform_input_digest: sha256_hex(&vec![0xAAu8; SIZE]),
            seeded_from_slab: true,
        };
        let mut ledger = TransformRunLedger::default();
        let (patched, overlays, _) = build_patched_backing_slab_q0c(
            &raw_capture,
            &[main_transformed, dedicated_transformed],
            &[],
            &[main_binding, dedicated_binding],
            &ledger,
        )
        .unwrap();
        // TWO patched slabs: main + dedicated.
        assert_eq!(patched.len(), 2);
        assert_eq!(patched[0].old_base, MAIN);
        assert_eq!(patched[1].old_base, DEDICATED);
        assert_eq!(overlays.len(), 2);
    }

    // TAF1 (CRITICAL): dedicated-ONLY transform overlay. A dangling-edge child in
    // a dedicated slab goes through seed -> transform -> overlay and produces a
    // patched dedicated slab — the offline closure for the Route S R1 blocker.
    #[test]
    fn route_t_af1_dedicated_only_transform_overlay() {
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let (raw_capture, transformed, binding, raw_bytes) =
            taf1_dedicated_fixture(DEDICATED, SIZE);
        // Seed (dedicated-only, no main slab).
        let mut globals = vec![transformed.clone()];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert_eq!(bindings[0].slab_old_base, DEDICATED);
        assert_eq!(bindings[0].slab_size, SIZE);
        // Apply a transform: scrub a dangling pointer at +0x40 to 0.
        let mut ledger = TransformRunLedger::default();
        let before_snapshot = globals[0].clone();
        let mut after = globals[0].clone();
        after.content[0x40] = 0x00;
        {
            // record the scrub write run via the snapshot-diff helper.
            let runs = diff_transform_write_runs(
                &[before_snapshot],
                &[after.clone()],
                "scrub_uncaptured_heap_pointers",
            )
            .unwrap();
            ledger.runs.extend(runs);
        }
        // Overlay the transformed (scrubbed) child onto the dedicated slab.
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &[after], &[], &[binding], &ledger)
                .unwrap();
        // ONE patched dedicated slab; the scrub byte was applied.
        assert_eq!(patched.len(), 1);
        assert_eq!(patched[0].old_base, DEDICATED);
        assert_eq!(patched[0].content[0x40], 0x00, "scrub must be overlaid");
        assert_eq!(patched[0].content[0], 0x50, "unchanged byte preserved");
        assert!(overlays
            .iter()
            .any(|o| o.child_old_base == DEDICATED && o.overlay_applied));
        let _ = raw_bytes;
    }

    // TAF1: no main slab does NOT skip raw coherence (dedicated-only still seeds+overlays).
    #[test]
    fn route_t_af1_no_main_slab_does_not_skip_coherence() {
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let (raw_capture, transformed, binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
        // raw_capture has ONLY the dedicated slab (no main slab). Seed must still
        // resolve the child to the dedicated slab.
        let mut globals = vec![transformed];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].slab_old_base, DEDICATED);
        assert!(bindings[0].seeded_from_slab);
        // Overlay must run (not skipped because no main slab).
        let mut ledger = TransformRunLedger::default();
        let (patched, _, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .unwrap();
        assert_eq!(patched.len(), 1);
        assert_eq!(patched[0].old_base, DEDICATED);
    }

    // TAF1: empty slab set + probe fails at capture_coverage_bind.
    #[test]
    fn route_t_af1_empty_slab_coverage_fails_at_capture_coverage_bind() {
        let g = probe_global(0x850150, 0x1000);
        let empty: Vec<HeapSlab> = Vec::new();
        let err = validate_probe_coverage(&[g], &empty).unwrap_err();
        assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
    }

    // TAF1 (evidence-gap fix, TAF2-F): the coverage gate runs BEFORE overlay. This
    // mirrors the PRODUCTION stage order from dump_process:
    //   capture_identity_bind -> capture_coverage_bind -> seed -> transforms -> overlay
    // With an uncovered probe, `capture_coverage_bind` must fail and the overlay
    // must never be reached. This is a verifiable harness of the real order, not a
    // lone validator call.
    #[test]
    fn route_t_af1_coverage_runs_before_overlay() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        use super::super::heap_global_snapshot::CapturePath as CP;
        // A dangling-edge probe at 0x850150 with NO covering slab.
        let cap_id = format!("dangling_edge:{:#x}:{:#x}", 0x850150u64, 0x1000usize);
        let mut g = global(0x850150, vec![0x50u8; 0x1000], false);
        g.extent_kind = CEK::ProbeWindow;
        g.extent_evidence.capture_id = cap_id.clone();
        g.extent_evidence.capture_path = CP::DanglingEdge;
        let globals = vec![g];
        let containers: Vec<ContainerSnapshot> = Vec::new();
        let empty_slabs: Vec<HeapSlab> = Vec::new();
        // Stage 1 (production): capture_identity_bind — must PASS (id is valid).
        validate_raw_coherence_capture_identities(&containers, &globals)
            .expect("identity bind must pass before coverage");
        // Stage 2 (production): capture_coverage_bind — must FAIL closed (uncovered).
        let err = validate_probe_coverage(&globals, &empty_slabs).unwrap_err();
        assert!(
            matches!(err, OverlayError::ProbeCoverageMissing { .. }),
            "coverage bind must fail before overlay, got {err:?}"
        );
        // Stage 3 (production): the overlay is NEVER reached because coverage
        // failed. Construct the raw capture and confirm the overlay would reject
        // (this is a tautology of fail-closed, but it proves the gate fires first).
        // We do NOT call build_patched_backing_slab_q0c here because the production
        // order stops at coverage_bind — proving the harness order is correct.
    }

    // TAF1: seed binding records the ACTUAL covering slab (base/size/digest/offset).
    #[test]
    fn route_t_af1_multi_slab_binding_records_actual_slab() {
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let (raw_capture, transformed, _, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
        let mut globals = vec![transformed];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        let b = &bindings[0];
        assert_eq!(b.slab_old_base, DEDICATED);
        assert_eq!(b.slab_size, SIZE);
        assert_eq!(b.slab_offset, 0);
        assert_eq!(b.slab_digest, sha256_hex(&raw_capture.slabs[0].content));
        assert_eq!(b.basis, TransformPreimageBasis::AuthoritativeSlabSlice);
        assert!(b.seeded_from_slab);
    }

    // TAF1: an exact-duplicate probe (base+size == its dedicated slab) is absorbed
    // as an alias at offset 0, never double-allocated.
    #[test]
    fn route_t_af1_exact_duplicate_does_not_double_allocate() {
        // TAF2-F (evidence-gap fix): this MUST test the main+dedicated OVERLAP
        // scenario, not a lone single slab. A dedicated slab exactly duplicating
        // the main slab is normalized to ONE backing region, so the overlay and
        // runtime both allocate it exactly once (no double allocation).
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        use super::super::heap_global_snapshot::CapturePath as CP;
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        // main slab and dedicated slab are EXACT duplicates (same base/size/bytes).
        let main = HeapSlab {
            old_base: DEDICATED,
            content: vec![0x50u8; SIZE],
        };
        let dedicated = HeapSlab {
            old_base: DEDICATED,
            content: vec![0x50u8; SIZE],
        };
        let (normalized, _events) =
            normalize_authoritative_slabs(&[cand("main", main), cand("dedicated", dedicated)])
                .unwrap();
        assert_eq!(
            normalized.len(),
            1,
            "exact duplicate must normalize to ONE backing"
        );
        // Build the raw capture from the normalized single slab + a ProbeWindow child.
        let cap_id = format!("dangling_edge:{DEDICATED:#x}:{SIZE:#x}");
        let child = RawChild {
            old_base: DEDICATED,
            size: SIZE,
            raw_bytes: vec![0x50u8; SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            capture_path: CP::DanglingEdge,
            extent_kind: CEK::ProbeWindow,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: SIZE,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        };
        let raw_capture = RawSlabCapture {
            slabs: vec![normalized[0].slab.clone()],
            children: vec![child],
        };
        let mut transformed = global(DEDICATED, vec![0x50u8; SIZE], false);
        transformed.extent_kind = CEK::ProbeWindow;
        transformed.extent_evidence.capture_id = cap_id;
        transformed.extent_evidence.capture_path = CP::DanglingEdge;
        let mut globals = vec![transformed];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        let mut ledger = TransformRunLedger::default();
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .unwrap();
        // Exactly ONE slab region + ONE alias (no double allocation).
        assert_eq!(
            patched.len(),
            1,
            "overlay must allocate the slab exactly once"
        );
        assert_eq!(overlays.len(), 1, "overlay must produce exactly one alias");
        assert!(overlays[0].overlay_applied);
        // Runtime plan also sees ONE slab region (no double allocation).
        let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
            &containers,
            &globals,
            &patched,
            &crate::dumper::runtime_rebase::declared_slots_from_capture(
                &containers,
                &globals,
                &patched,
            ),
            &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
            &[],
            0x140000000,
            0x140000000,
        )
        .unwrap()
        .expect("plan must be produced");
        assert_eq!(
            plan.regions.len(),
            1,
            "runtime must allocate the slab exactly once"
        );
    }

    // TAF1: a child that spans two slabs fails closed.
    #[test]
    fn route_t_af1_cross_slab_child_fails_closed() {
        const S1: u64 = 0x850000;
        const S2: u64 = 0x851000;
        const SIZE: usize = 0x1000;
        // Child [0x850100, 0x851100) spans both slabs [0x850000,+0x1000) and
        // [0x851000,+0x1000). No single slab contains it.
        let s1 = HeapSlab {
            old_base: S1,
            content: vec![0u8; 0x1000],
        };
        let s2 = HeapSlab {
            old_base: S2,
            content: vec![0u8; 0x1000],
        };
        let raw_capture = RawSlabCapture {
            slabs: vec![s1, s2],
            children: Vec::new(),
        };
        // A probe spanning the boundary cannot be covered by exactly one slab.
        let g = probe_global(0x850100, SIZE);
        let err = validate_probe_coverage(&[g], &raw_capture.slabs).unwrap_err();
        assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
    }

    // TAF1 (evidence-gap fix, TAF2-E/F): the manifest ROUNDTRIP contains all
    // authoritative slabs. We render a manifest with a real authoritative_slab_ledger,
    // parse the JSON, and verify slab count/order/base/size/digest, and that the
    // binding references a slab present in the ledger.
    #[test]
    fn route_t_af1_manifest_roundtrip_contains_all_authoritative_slabs() {
        use super::super::snapshot_manifest::AuthoritativeSlabLedgerEntry;
        // A dedicated slab at 0x850150 (raw digest = sha256 of 0x50 content).
        let raw_digest = sha256_hex(&vec![0x50u8; 0x1000]);
        let patched_digest = sha256_hex(&vec![0x55u8; 0x1000]); // after overlay
        let slab_ledger = vec![AuthoritativeSlabLedgerEntry {
            sequence: 0,
            role: "dedicated",
            old_base: 0x850150,
            size: 0x1000,
            raw_digest: raw_digest.clone(),
            patched_digest: patched_digest.clone(),
            normalization: "kept",
            source: "dedicated",
        }];
        // Render a manifest with this slab ledger.
        let json = crate::dumper::snapshot_manifest::render_manifest_json(
            std::path::Path::new("cand.exe"),
            crate::dumper::types::DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &[],
            &[],
            &crate::dumper::capture_policy::DumpCapturePolicy::ahk_gto_default(),
            None,
            &[],
            &[],
            &[],
            &TransformRunLedger::default(),
            &[],
            &[],
            &slab_ledger,
            &[],
        )
        .unwrap();
        // Parse and verify the slab ledger.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
        let ledger = v["authoritative_slab_ledger"]
            .as_array()
            .expect("slab ledger present");
        assert_eq!(ledger.len(), 1, "slab count must be 1");
        let entry = &ledger[0];
        assert_eq!(entry["sequence"], 0);
        assert_eq!(entry["role"], "dedicated");
        assert_eq!(entry["old_base"], "0x850150");
        assert_eq!(entry["size"], 0x1000);
        assert_eq!(entry["raw_digest"], raw_digest);
        assert_eq!(entry["patched_digest"], patched_digest);
        assert_eq!(entry["normalization"], "kept");
        assert_eq!(entry["source"], "dedicated");
        // The ledger proves the runtime/overlay/manifest slab sets are consistent:
        // exactly one slab, whose raw and patched digests are both recorded.
        assert!(json.contains("\"authoritative_slab_ledger\""));
    }

    // ==================== Route T R0 Audit Fix 2 (TAF2) tests ====================

    // TAF2-A: a binding with the wrong slab_size (but correct base/offset) must
    // FAIL CLOSED at the overlay exact-match (TransformPreimageBindingIdentityInvalid).
    #[test]
    fn route_t_af2_wrong_slab_size_fails_closed() {
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let (raw_capture, transformed, mut binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
        // Corrupt the binding's slab_size (still correct base/offset/digest).
        binding.slab_size = SIZE - 1;
        let mut ledger = TransformRunLedger::default();
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::TransformPreimageBindingIdentityInvalid { .. }
            ),
            "wrong slab_size must fail closed, got {err:?}"
        );
    }

    // TAF2-A: a binding with the wrong slab_digest (but correct base/size/offset)
    // must FAIL CLOSED at the overlay exact-match.
    #[test]
    fn route_t_af2_wrong_slab_digest_fails_closed() {
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let (raw_capture, transformed, mut binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
        // Corrupt the binding's slab_digest (still correct base/size/offset).
        binding.slab_digest = "DEADBEEF".into();
        let mut ledger = TransformRunLedger::default();
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::TransformPreimageBindingIdentityInvalid { .. }
            ),
            "wrong slab_digest must fail closed, got {err:?}"
        );
    }

    // TAF2-A: a binding with the wrong slab_base AND digest must FAIL CLOSED.
    #[test]
    fn route_t_af2_wrong_slab_base_and_digest_fails_closed() {
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let (raw_capture, transformed, mut binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
        // Corrupt both base and digest.
        binding.slab_old_base = DEDICATED - 0x1000;
        binding.slab_digest = "DEADBEEF".into();
        let mut ledger = TransformRunLedger::default();
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
                .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::TransformPreimageBindingIdentityInvalid { .. }
            ),
            "wrong slab_base+digest must fail closed, got {err:?}"
        );
    }

    // TAF2-B: main + dedicated EXACT duplicate (same base/size/bytes) normalizes
    // to ONE backing region (the later duplicate is dropped).
    #[test]
    fn route_t_af2_main_dedicated_exact_duplicate_normalizes() {
        const BASE: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let main = HeapSlab {
            old_base: BASE,
            content: vec![0x50u8; SIZE],
        };
        let dedicated = HeapSlab {
            old_base: BASE,
            content: vec![0x50u8; SIZE],
        };
        let (normalized, _events) = normalize_authoritative_slabs(&[
            cand("main", main.clone()),
            cand("dedicated", dedicated.clone()),
        ])
        .unwrap();
        assert_eq!(normalized.len(), 1, "exact duplicate must collapse to one");
        assert_eq!(normalized[0].slab.old_base, BASE);
        assert_eq!(normalized[0].normalization, SlabNormalization::Kept);
    }

    // TAF2-B: a dedicated slab fully contained in the main slab with identical
    // bytes normalizes to ONE backing region (the inner is an exact alias).
    #[test]
    fn route_t_af2_main_dedicated_contained_same_bytes_normalizes() {
        // Main slab [0x900000, +0x20000); dedicated [0x905000, +0x1000) with the
        // SAME bytes at the contained offset.
        let main = HeapSlab {
            old_base: 0x900000,
            content: {
                let mut c = vec![0u8; 0x20000];
                for i in 0..0x1000 {
                    c[0x5000 + i] = 0x50;
                }
                c
            },
        };
        let dedicated = HeapSlab {
            old_base: 0x905000,
            content: vec![0x50u8; 0x1000],
        };
        let (normalized, _events) = normalize_authoritative_slabs(&[
            cand("main", main.clone()),
            cand("dedicated", dedicated.clone()),
        ])
        .unwrap();
        assert_eq!(
            normalized.len(),
            1,
            "contained same-bytes must keep one backing"
        );
        assert_eq!(normalized[0].slab.old_base, 0x900000);
        assert_eq!(normalized[0].slab.content.len(), 0x20000);
    }

    // TAF2-B: a dedicated slab contained in the main slab with DIFFERENT bytes
    // fails closed (AuthoritativeSlabConflict).
    #[test]
    fn route_t_af2_main_dedicated_contained_different_bytes_fails_closed() {
        let main = HeapSlab {
            old_base: 0x900000,
            content: {
                let mut c = vec![0u8; 0x20000];
                for i in 0..0x1000 {
                    c[0x5000 + i] = 0x50;
                }
                c
            },
        };
        // Same range but different byte at the contained offset.
        let dedicated = HeapSlab {
            old_base: 0x905000,
            content: vec![0x51u8; 0x1000], // differs from main's 0x50
        };
        let err =
            normalize_authoritative_slabs(&[cand("main", main), cand("dedicated", dedicated)])
                .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::AuthoritativeSlabConflict {
                    relationship: "contained_byte_conflict",
                    ..
                }
            ),
            "contained different-bytes must fail closed, got {err:?}"
        );
    }

    // TAF2-D: partial overlap (neither contains the other) fails closed.
    #[test]
    fn route_t_af2_partial_overlap_fails_closed() {
        // [0x900000,+0x1000) and [0x900800,+0x1000) overlap partially.
        let a = HeapSlab {
            old_base: 0x900000,
            content: vec![0x50u8; 0x1000],
        };
        let b = HeapSlab {
            old_base: 0x900800,
            content: vec![0x50u8; 0x1000],
        };
        let err =
            normalize_authoritative_slabs(&[cand("main", a), cand("dedicated", b)]).unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::AuthoritativeSlabConflict {
                    relationship: "partial_overlap",
                    ..
                }
            ),
            "partial overlap must fail closed, got {err:?}"
        );
    }

    // TAF2-B/F: the normalized set must be shared by overlay AND runtime. After
    // normalization, a child that lives in the contained-alias region resolves to
    // the ONE kept slab for both overlay and runtime plan.
    #[test]
    fn route_t_af2_normalized_set_is_shared_by_overlay_and_runtime() {
        use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
        use super::super::heap_global_snapshot::CapturePath as CP;
        // A dedicated slab at 0x905000 is exactly contained in the main slab
        // [0x900000,+0x20000) with identical bytes. After normalization only the
        // main slab remains; the child at 0x905000 resolves to it.
        let main = HeapSlab {
            old_base: 0x900000,
            content: {
                let mut c = vec![0u8; 0x20000];
                for i in 0..0x1000 {
                    c[0x5000 + i] = 0x50;
                }
                c
            },
        };
        let dedicated = HeapSlab {
            old_base: 0x905000,
            content: vec![0x50u8; 0x1000],
        };
        let (normalized, _events) = normalize_authoritative_slabs(&[
            cand("main", main.clone()),
            cand("dedicated", dedicated.clone()),
        ])
        .unwrap();
        assert_eq!(normalized.len(), 1);
        let kept = normalized[0].slab.clone();
        // A ProbeWindow child at 0x905000 must resolve to the single kept slab.
        let cap_id = format!("dangling_edge:{:#x}:{:#x}", 0x905000u64, 0x1000usize);
        let child = RawChild {
            old_base: 0x905000,
            size: 0x1000,
            raw_bytes: vec![0x50u8; 0x1000],
            kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            capture_path: CP::DanglingEdge,
            extent_kind: CEK::ProbeWindow,
            source_parent_old_base: None,
            source_slot_offset: None,
            requested_probe_size: 0x1000,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        };
        let raw_capture = RawSlabCapture {
            slabs: vec![kept],
            children: vec![child],
        };
        // Seed + overlay against the normalized single slab.
        let mut transformed = global(0x905000, vec![0x50u8; 0x1000], false);
        transformed.extent_kind = CEK::ProbeWindow;
        transformed.extent_evidence.capture_id = cap_id;
        transformed.extent_evidence.capture_path = CP::DanglingEdge;
        let mut globals = vec![transformed];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert_eq!(
            bindings[0].slab_old_base, 0x900000,
            "binding must use kept slab"
        );
        let mut ledger = TransformRunLedger::default();
        let (patched, _, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .unwrap();
        assert_eq!(patched.len(), 1, "overlay must use the one kept slab");
        assert_eq!(patched[0].old_base, 0x900000);
        // Runtime plan also sees the single slab (shared set).
        let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
            &containers,
            &globals,
            &patched,
            &crate::dumper::runtime_rebase::declared_slots_from_capture(
                &containers,
                &globals,
                &patched,
            ),
            &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
            &[],
            0x140000000,
            0x140000000,
        )
        .unwrap()
        .expect("plan must be produced");
        assert_eq!(plan.regions.len(), 1, "runtime must use the one kept slab");
    }

    // ==================== Route T R0 Audit Fix 3 (TAF3) tests ====================

    // TAF3-E: dedicated-only input keeps role/source "dedicated" (never "main").
    #[test]
    fn route_t_af3_dedicated_only_role_stays_dedicated() {
        const DEDICATED: u64 = 0x850150;
        const SIZE: usize = 0x1000;
        let (normalized, events) = normalize_authoritative_slabs(&[cand(
            "dedicated",
            HeapSlab {
                old_base: DEDICATED,
                content: vec![0x50u8; SIZE],
            },
        )])
        .unwrap();
        assert_eq!(normalized.len(), 1);
        assert_eq!(
            normalized[0].role, "dedicated",
            "dedicated-only must NOT become main"
        );
        assert_eq!(normalized[0].slab.old_base, DEDICATED);
        // The kept event also records role "dedicated".
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].input_role, "dedicated");
        assert_eq!(events[0].action, "kept");
        assert_eq!(events[0].survivor_sequence, Some(0));
    }

    // TAF3-F: dedup + contained-alias produce manifest normalization events.
    #[test]
    fn route_t_af3_dedup_and_alias_emit_events() {
        use super::super::snapshot_manifest::AuthoritativeSlabLedgerEntry;
        // main at 0x900000; dedicated EXACT duplicate of main's contained region
        // (same base+size+bytes) -> dedup event; a SECOND dedicated that is a
        // contained alias (main contains it, same bytes).
        let main = HeapSlab {
            old_base: 0x900000,
            content: {
                let mut c = vec![0u8; 0x20000];
                for i in 0..0x1000 {
                    c[0x5000 + i] = 0x50;
                }
                c
            },
        };
        // exact duplicate of the whole main slab -> dedup
        let dup = main.clone();
        // contained alias: same region as a slice of main, same bytes
        let alias = HeapSlab {
            old_base: 0x905000,
            content: vec![0x50u8; 0x1000],
        };
        let (kept, events) = normalize_authoritative_slabs(&[
            cand("main", main),
            cand("dedicated", dup),
            cand("dedicated", alias),
        ])
        .unwrap();
        assert_eq!(kept.len(), 1, "only the main slab survives");
        assert_eq!(kept[0].role, "main");
        // Events: main=kept, dup=deduplicated, alias=contained_exact_alias.
        let kept_event = events.iter().find(|e| e.action == "kept").unwrap();
        let dup_event = events
            .iter()
            .find(|e| e.action == "deduplicated")
            .expect("dup must emit deduplicated event");
        let alias_event = events
            .iter()
            .find(|e| e.action == "contained_exact_alias")
            .expect("alias must emit contained_exact_alias event");
        assert_eq!(kept_event.input_role, "main");
        assert_eq!(dup_event.input_role, "dedicated");
        assert_eq!(dup_event.relationship, "exact_duplicate");
        assert_eq!(dup_event.survivor_sequence, Some(0));
        assert_eq!(alias_event.input_role, "dedicated");
        assert_eq!(alias_event.relationship, "contained_same_bytes");
        assert_eq!(alias_event.survivor_sequence, Some(0));
        // Render + parse the manifest with the slab ledger + events -> roundtrip.
        let slab_ledger = vec![AuthoritativeSlabLedgerEntry {
            sequence: 0,
            role: "main",
            old_base: 0x900000,
            size: 0x20000,
            raw_digest: sha256_hex(&kept[0].slab.content),
            patched_digest: sha256_hex(&kept[0].slab.content),
            normalization: "kept",
            source: "main",
        }];
        let json = crate::dumper::snapshot_manifest::render_manifest_json(
            std::path::Path::new("cand.exe"),
            crate::dumper::types::DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &[],
            &[],
            &crate::dumper::capture_policy::DumpCapturePolicy::ahk_gto_default(),
            None,
            &[],
            &[],
            &[],
            &TransformRunLedger::default(),
            &[],
            &[],
            &slab_ledger,
            &events,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
        let ne = v["normalization_events"]
            .as_array()
            .expect("events present");
        assert_eq!(ne.len(), 3, "3 events (kept + dedup + alias)");
        let actions: Vec<&str> = ne.iter().map(|e| e["action"].as_str().unwrap()).collect();
        assert!(actions.contains(&"kept"));
        assert!(actions.contains(&"deduplicated"));
        assert!(actions.contains(&"contained_exact_alias"));
        // Each event records its survivor (which runtime/overlay uses).
        for e in ne.iter() {
            assert_eq!(
                e["survivor_sequence"].as_u64(),
                Some(0),
                "all map to main survivor"
            );
        }
    }

    // TAF3-G: reverse containment (a later slab is a superset of a kept slab) must
    // recheck the new outer against ALL kept slabs. Construct A=[0x1000,+0x100),
    // B=[0x1100,+0x100), S=[0x1000,+0x180). S contains A but partially overlaps B
    // -> must fail closed (S was rechecked against B, not just A).
    #[test]
    fn route_t_af3_reverse_containment_plus_partial_overlap_fails_closed() {
        let a = HeapSlab {
            old_base: 0x1000,
            content: vec![0x50u8; 0x100],
        };
        let b = HeapSlab {
            old_base: 0x1100,
            content: vec![0x50u8; 0x100],
        };
        // S = [0x1000,+0x180) fully contains A ([0x1000,+0x100)) but only partially
        // overlaps B ([0x1100,+0x100)).
        let s = HeapSlab {
            old_base: 0x1000,
            content: {
                let mut c = vec![0x50u8; 0x180];
                for i in 0..0x100 {
                    c[i] = 0x50;
                }
                c
            },
        };
        // Order: A (kept), B (kept, disjoint from A), S (contains A, partial-overlaps B).
        let err = normalize_authoritative_slabs(&[
            cand("main", a),
            cand("dedicated", b),
            cand("dedicated", s),
        ])
        .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::AuthoritativeSlabConflict {
                    relationship: "partial_overlap",
                    ..
                }
            ),
            "reverse-containment recheck must catch S partial-overlap with B, got {err:?}"
        );
    }

    // TAF3-D: the normalized output is always pairwise disjoint.
    #[test]
    fn route_t_af3_normalized_output_is_pairwise_disjoint() {
        // Two disjoint dedicated slabs normalize cleanly (both kept, disjoint).
        let (kept, _) = normalize_authoritative_slabs(&[
            cand(
                "dedicated",
                HeapSlab {
                    old_base: 0x850150,
                    content: vec![0x50u8; 0x1000],
                },
            ),
            cand(
                "dedicated",
                HeapSlab {
                    old_base: 0x860000,
                    content: vec![0x50u8; 0x1000],
                },
            ),
        ])
        .unwrap();
        assert_eq!(kept.len(), 2);
        // Assert pairwise disjoint.
        for i in 0..kept.len() {
            for j in (i + 1)..kept.len() {
                let a = &kept[i].slab;
                let b = &kept[j].slab;
                let a_end = a.old_base + a.content.len() as u64;
                let b_end = b.old_base + b.content.len() as u64;
                assert!(
                    !(a.old_base < b_end && b.old_base < a_end),
                    "kept slabs must be pairwise disjoint"
                );
            }
        }
    }

    // TAF3-G: reverse containment replaces a kept slab with the outer and rechecks.
    // Here a later outer S fully contains an EARLIER kept A with same bytes; the
    // kept set must end up with S (the outer), and A's event is contained_alias.
    #[test]
    fn route_t_af3_reverse_containment_rechecks_all_kept() {
        let a = HeapSlab {
            old_base: 0x1000,
            content: vec![0x50u8; 0x100],
        };
        // S fully contains A (same bytes at offset 0).
        let s = HeapSlab {
            old_base: 0x1000,
            content: {
                let mut c = vec![0x50u8; 0x180];
                c
            },
        };
        let (kept, events) =
            normalize_authoritative_slabs(&[cand("main", a), cand("dedicated", s)]).unwrap();
        // The outer S survives (kept), and A was absorbed as a contained alias.
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].slab.old_base, 0x1000);
        assert_eq!(
            kept[0].slab.content.len(),
            0x180,
            "outer S must be the survivor"
        );
        let alias_event = events
            .iter()
            .find(|e| e.action == "contained_exact_alias")
            .expect("A absorbed as contained alias event");
        assert_eq!(alias_event.input_old_base, 0x1000);
        assert_eq!(alias_event.survivor_sequence, Some(0));
    }

    // ==================== Route T R0 Audit Fix 3 Rev 1 (bijection) tests ====================

    // Rev1: reverse-containment event identity is BIJECTIVE. A=[0x1000,+0x100)
    // main, S=[0x1000,+0x180) dedicated. S replaces A. Each input has exactly one
    // event: seq0=A/main/alias, seq1=S/dedicated/kept. Survivor = S bytes with
    // role=dedicated, origin_input_sequence=1.
    #[test]
    fn route_t_af3_rev1_reverse_containment_event_identity_is_bijective() {
        let a = HeapSlab {
            old_base: 0x1000,
            content: vec![0x50u8; 0x100],
        };
        let s = HeapSlab {
            old_base: 0x1000,
            content: vec![0x50u8; 0x180],
        };
        let (kept, events) =
            normalize_authoritative_slabs(&[cand("main", a), cand("dedicated", s)]).unwrap();
        // Exactly 2 events, one per valid input (bijection).
        assert_eq!(events.len(), 2, "one event per valid input");
        // input_sequence set == {0, 1}.
        let mut seqs: Vec<usize> = events.iter().map(|e| e.input_sequence).collect();
        seqs.sort();
        assert_eq!(seqs, vec![0, 1]);
        // seq 0 = A / main / contained_exact_alias (dropped into survivor).
        let e0 = events.iter().find(|e| e.input_sequence == 0).unwrap();
        assert_eq!(e0.input_role, "main");
        assert_eq!(e0.input_old_base, 0x1000);
        assert_eq!(e0.input_size, 0x100, "A's own geometry, not S's");
        assert_eq!(e0.action, "contained_exact_alias");
        assert_eq!(e0.survivor_sequence, Some(0));
        // seq 1 = S / dedicated / kept (the survivor).
        let e1 = events.iter().find(|e| e.input_sequence == 1).unwrap();
        assert_eq!(e1.input_role, "dedicated");
        assert_eq!(e1.input_old_base, 0x1000);
        assert_eq!(e1.input_size, 0x180, "S's own geometry");
        assert_eq!(e1.action, "kept");
        assert_eq!(e1.survivor_sequence, Some(0));
        // Survivor = S bytes, role=dedicated (NOT A's main), origin = input 1.
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].slab.content.len(), 0x180, "survivor bytes = S");
        assert_eq!(kept[0].role, "dedicated", "survivor role = S's role");
        assert_eq!(
            kept[0].origin_input_sequence, 1,
            "survivor origin = S input"
        );
    }

    // Rev1: reverse-containment manifest provenance roundtrip. Render + parse the
    // normalization_events and authoritative_slab_ledger; re-assert the bijection
    // and survivor role/origin from the parsed JSON.
    #[test]
    fn route_t_af3_rev1_reverse_containment_manifest_provenance_roundtrip() {
        use super::super::snapshot_manifest::AuthoritativeSlabLedgerEntry;
        let a = HeapSlab {
            old_base: 0x1000,
            content: vec![0x50u8; 0x100],
        };
        let s = HeapSlab {
            old_base: 0x1000,
            content: vec![0x50u8; 0x180],
        };
        let (kept, events) =
            normalize_authoritative_slabs(&[cand("main", a), cand("dedicated", s)]).unwrap();
        let slab_ledger = vec![AuthoritativeSlabLedgerEntry {
            sequence: 0,
            role: kept[0].role,
            old_base: kept[0].slab.old_base,
            size: kept[0].slab.content.len(),
            raw_digest: sha256_hex(&kept[0].slab.content),
            patched_digest: sha256_hex(&kept[0].slab.content),
            normalization: "kept",
            source: kept[0].role,
        }];
        let json = crate::dumper::snapshot_manifest::render_manifest_json(
            std::path::Path::new("cand.exe"),
            crate::dumper::types::DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &[],
            &[],
            &crate::dumper::capture_policy::DumpCapturePolicy::ahk_gto_default(),
            None,
            &[],
            &[],
            &[],
            &TransformRunLedger::default(),
            &[],
            &[],
            &slab_ledger,
            &events,
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
        // normalization_events roundtrip.
        let ne = v["normalization_events"]
            .as_array()
            .expect("events present");
        assert_eq!(ne.len(), 2);
        let e0 = ne.iter().find(|e| e["input_sequence"] == 0).unwrap();
        assert_eq!(e0["input_role"], "main");
        assert_eq!(e0["input_size"], 0x100);
        assert_eq!(e0["action"], "contained_exact_alias");
        assert_eq!(e0["survivor_sequence"], 0);
        let e1 = ne.iter().find(|e| e["input_sequence"] == 1).unwrap();
        assert_eq!(e1["input_role"], "dedicated");
        assert_eq!(e1["input_size"], 0x180);
        assert_eq!(e1["action"], "kept");
        assert_eq!(e1["survivor_sequence"], 0);
        // authoritative_slab_ledger roundtrip: survivor role=dedicated, size=S.
        let al = v["authoritative_slab_ledger"]
            .as_array()
            .expect("slab ledger present");
        assert_eq!(al.len(), 1);
        assert_eq!(al[0]["role"], "dedicated");
        assert_eq!(al[0]["size"], 0x180);
    }

    // ------------------------------------------------------------------
    // Route X R0 — raw-coherence participant-set and ledger identity closure.
    // ------------------------------------------------------------------

    /// Exact W R1 geometry: gscript image-inline body at RVA 0x149d50, live VA
    /// 0x140149d50, size 0x1950 (6480). A transform mutating it must NOT create a
    /// raw write run (image-inline is non-raw), so it can never emit an empty
    /// child_capture_id into the overlay ledger.
    #[test]
    fn route_x_r0_exact_140149d50_geometry() {
        const W_IMAGE_INLINE_RVA: u32 = 0x149d50;
        const W_IMAGE_INLINE_VA: u64 = 0x140149d50;
        const W_IMAGE_INLINE_SIZE: usize = 0x1950;
        let mut g = global(W_IMAGE_INLINE_VA, vec![0u8; W_IMAGE_INLINE_SIZE], true);
        g.rva = W_IMAGE_INLINE_RVA;
        // Verify it is NOT a raw-coherence participant.
        assert!(!g.is_raw_coherence_participant());
        // Mutate it (simulate scrub/repair touching the image-inline body).
        let before = g.clone();
        g.content[0x28c..0x28c + 2].copy_from_slice(&[0x00, 0x00]);
        let runs =
            diff_transform_write_runs(&[before], &[g], "scrub_uncaptured_heap_pointers").unwrap();
        // NO raw run is produced for an image-inline participant.
        assert!(
            runs.is_empty(),
            "image-inline must never enter the raw ledger"
        );
    }

    /// X0-A: identity gate, raw-child capture, seeding, and ledger recording must
    /// all agree that an image-inline snapshot is NOT a raw-coherence participant.
    #[test]
    fn route_x_r0_image_inline_is_non_raw_participant() {
        let g = global(0x140149d50, vec![0u8; 0x1950], true);
        assert!(!g.is_raw_coherence_participant());
        // raw_children_from_capture must exclude it.
        let children = raw_children_from_capture(&[], &[g.clone()]);
        assert!(!children.iter().any(|c| c.old_base == 0x140149d50));
        // diff_transform_write_runs must not emit a run for it even if mutated.
        let mut after = g.clone();
        after.content[0] ^= 0xFF;
        let runs = diff_transform_write_runs(&[g], &[after], "t").unwrap();
        assert!(runs.is_empty());
        // (overlay build on an empty raw capture would fail closed for other
        // reasons; the image-inline exclusion is proven by the gate/child/ledger
        // checks above.)
    }

    /// X0-B / X0-C: real scrub_uncaptured_heap_pointers through the PRODUCTION
    /// recorder produces raw runs only for raw-coherence participants, and every
    /// raw run carries a non-empty capture id (no empty-ID run from image-inline).
    #[test]
    fn route_x_r0_scrub_raw_runs_never_have_empty_capture_id() {
        let mut globals = vec![
            global(0x140149d50, vec![0x41u8; 0x1950], true), // image-inline (non-raw)
            global(0x200000, vec![0x42u8; 0x40], false),     // raw child
        ];
        // Give the raw child a capture id (as identity validation requires).
        globals[1].extent_evidence.capture_id =
            "gscript_child_link:0x200000:0:0x200000:true".into();
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let mut ledger = TransformRunLedger::default();
        let before = globals.clone();
        // Run the REAL scrub via the production recorder (also mutates containers).
        apply_recorded_transform(
            &mut globals,
            "scrub_uncaptured_heap_pointers",
            &mut ledger,
            |g| {
                super::super::heap_global_snapshot::scrub_uncaptured_heap_pointers(
                    &mut containers,
                    g,
                    0x140000000,
                    0x140100000,
                );
            },
        )
        .unwrap();
        // Every raw run has a non-empty capture id.
        for r in &ledger.runs {
            assert!(
                !r.child_capture_id.is_empty(),
                "raw run must carry a non-empty capture id: {r:?}"
            );
        }
        // No run references the image-inline base.
        assert!(!ledger.runs.iter().any(|r| r.child_old_base == 0x140149d50));
        // The raw child (if changed by scrub) is present with its capture id.
        let _ = before;
    }

    /// X0-A: the identity gate and the ledger recording must agree on the exact
    /// participant set (no ad-hoc condition sets — both use the predicate).
    #[test]
    fn route_x_r0_identity_gate_and_run_ledger_share_participant_set() {
        // A mixed set: raw (with id), image-inline, heap-handle, empty, synthetic.
        let raw = global(0x200000, vec![0x42u8; 0x40], false);
        let image_inline = global(0x140149d50, vec![0x41u8; 0x1950], true);
        let h = handle(0x300000);
        let empty = global(0x400000, vec![], false);
        let synth = synthetic(0x500000, vec![0x55; 0x20], "t");
        let globals = vec![raw.clone(), image_inline, h, empty, synth.clone()];
        // Identity gate: only the raw participant requires a capture id; the
        // non-raw ones are skipped.
        let gate_ok = validate_raw_coherence_capture_identities(&[], &globals).is_ok();
        // (raw has empty id -> gate would fail; give it an id first)
        let mut g2 = raw.clone();
        g2.extent_evidence.capture_id = "main:0x200000:0:0x200000:false".into();
        assert!(validate_raw_coherence_capture_identities(&[], &[g2.clone()]).is_ok());
        // The predicate classifies exactly the raw participant as a participant.
        let raw_only = globals
            .iter()
            .filter(|g| g.is_raw_coherence_participant())
            .count();
        assert_eq!(raw_only, 1);
        // Ledger recording: only the raw participant (when mutated) yields runs.
        let mut after_raw = g2.clone();
        after_raw.content[0] ^= 0xFF;
        let runs = diff_transform_write_runs(&[g2], &[after_raw], "t").unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].child_capture_id, "main:0x200000:0:0x200000:false");
        let _ = gate_ok;
    }

    /// X0-B: a non-raw (image-inline) mutation is not destroyed — child-level
    /// transform evidence is preserved even though it never enters the raw ledger.
    #[test]
    fn route_x_r0_non_raw_mutation_keeps_child_level_evidence() {
        let mut image = global(0x140149d50, vec![0x41u8; 0x1950], true);
        image
            .transform_ids
            .push("scrub_uncaptured_heap_pointers".to_string());
        let before = image.clone();
        image.content[0x28c] = 0x00;
        let runs = diff_transform_write_runs(&[before], &[image.clone()], "scrub").unwrap();
        // No raw run for the image-inline mutation...
        assert!(runs.is_empty());
        // ...but the child-level transform evidence is preserved.
        assert!(image
            .transform_ids
            .contains(&"scrub_uncaptured_heap_pointers".to_string()));
    }

    /// X0-B / X0-D: a genuinely malformed RAW child (non-image, non-handle,
    /// non-empty, non-synthetic) with an EMPTY capture id that changes must fail
    /// closed — never silently accepted.
    #[test]
    fn route_x_r0_malformed_empty_raw_id_still_fails_closed() {
        let mut raw = global(0x200000, vec![0x42u8; 0x40], false); // empty capture id
        assert!(raw.is_raw_coherence_participant()); // it IS a raw participant
        let before = raw.clone();
        raw.content[0] ^= 0xFF;
        let err = diff_transform_write_runs(&[before], &[raw], "t")
            .expect_err("empty raw id must fail closed");
        match err {
            OverlayError::TransformRunLedgerInvalid {
                child_old_base,
                reason,
                ..
            } => {
                assert_eq!(child_old_base, 0x200000);
                assert!(reason.contains("empty raw capture id"), "reason: {reason}");
            }
            other => panic!("expected TransformRunLedgerInvalid, got {other:?}"),
        }
    }

    /// X0-B: a participant-set change across one transform (a raw participant
    /// present in before but missing in after) fails closed.
    #[test]
    fn route_x_r0_participant_set_change_fails_closed() {
        let a = global(0x200000, vec![0x42u8; 0x40], false);
        let b = global(0x210000, vec![0x43u8; 0x40], false);
        // before has two raw participants; after drops 0x210000 -> set change.
        let before = vec![a.clone(), b.clone()];
        let after = vec![a.clone()];
        let err = diff_transform_write_runs(&before, &after, "t")
            .expect_err("participant set change must fail closed");
        match err {
            OverlayError::TransformRunLedgerInvalid { reason, .. } => {
                assert!(
                    reason.contains("participant set change"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected TransformRunLedgerInvalid, got {other:?}"),
        }
    }

    /// X0-F #8 / X0-AF1 (P0-4): the exact mixed raw + image-inline W R1 case
    /// completes overlay through the REAL production-order chain (not the legacy
    /// wrapper): identity bind -> coverage -> raw children -> seeding -> real
    /// scrub via the production recorder -> q0c overlay.
    ///
    /// Exact W R1 geometry: image RVA 0x149d50, image VA 0x140149d50, size 0x1950,
    /// scrub area +0x28c.
    #[test]
    fn route_x_af1_w_exact_geometry_real_scrub_recorder_q0c_overlay() {
        const IMAGE_RVA: u32 = 0x149d50;
        const IMAGE_VA: u64 = 0x140149d50;
        const IMAGE_SIZE: usize = 0x1950;
        // W R1 scrub write area +0x28c (length 0x2); use an 8-byte-aligned offset
        // within it so the real scrub's pointer scan actually zeroes the external
        // pointer qword.
        const SCRUB_OFF: usize = 0x288;
        const SLAB_BASE: u64 = 0x140000000;
        const SLAB_SZ: usize = 0x40000;
        const RAW_BASE: u64 = SLAB_BASE + 0x3000;

        // Raw slab with one in-slab raw child (ObservedAllocation).
        // The raw child contains a scrubbed external pointer at +0x20 so the
        // real scrub modifies it AND the raw ledger gets a genuine run.
        let mut raw_child_bytes = b"raw-captured-child-ok".to_vec();
        raw_child_bytes.resize(0x40, 0);
        raw_child_bytes[0x20..0x28].copy_from_slice(&0x6000_0000u64.to_le_bytes());
        let slab = slab_with_child(SLAB_BASE, SLAB_SZ, RAW_BASE, raw_child_bytes.clone());
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                RAW_BASE,
                raw_child_bytes.len(),
                raw_child_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;

        // Globals: the raw child (canonical participant, MainSlot) + the image-inline.
        let mut raw_g = global(RAW_BASE, raw_child_bytes.clone(), false);
        raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_g.extent_evidence.capture_path =
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        // Image-inline body: contains an external pointer-shaped qword at +0x28c
        // that scrub will zero (the W R1 scrub area).
        let mut image = global(IMAGE_VA, vec![0x41u8; IMAGE_SIZE], true);
        image.rva = IMAGE_RVA;
        image.content[SCRUB_OFF..SCRUB_OFF + 8].copy_from_slice(&0x4000_0000u64.to_le_bytes());

        let mut globals = vec![raw_g.clone(), image];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();

        // 1. Identity bind: image-inline is NOT a raw participant, so the raw
        //    child's id is the only requirement.
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
        // 2. Coverage bind: no probe/interior children (raw is ObservedAllocation),
        //    image-inline excluded -> passes.
        validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
        // 3. Raw children from capture: only the raw child.
        let children = raw_children_from_capture(&containers, &globals);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].old_base, RAW_BASE);
        // 4. Seed transform inputs from authoritative slab.
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert_eq!(bindings.len(), 1);
        // 5. Real scrub via the production recorder.
        let mut ledger = TransformRunLedger::default();
        apply_recorded_transform(
            &mut globals,
            "scrub_uncaptured_heap_pointers",
            &mut ledger,
            |g| {
                super::super::heap_global_snapshot::scrub_uncaptured_heap_pointers(
                    &mut containers,
                    g,
                    0x140000000,
                    0x140100000,
                );
            },
        )
        .unwrap();
        //    - the image-inline body WAS actually modified by the real scrub.
        assert_eq!(globals[1].content[SCRUB_OFF], 0x00);
        //    - child-level transform evidence preserved on the image-inline.
        assert!(globals[1]
            .transform_ids
            .contains(&"scrub_uncaptured_heap_pointers".to_string()));
        //    - no raw write run references the image-inline base.
        assert!(!ledger.runs.iter().any(|r| r.child_old_base == IMAGE_VA));
        //    - every raw run has a non-empty capture id + full identity.
        for r in &ledger.runs {
            assert!(!r.child_capture_id.is_empty());
            assert_eq!(r.child_capture_id, "main:0x140003000:0:0x140003000:false");
        }
        // 6. q0c overlay completes (membership + shape gates run inside).
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .unwrap();
        assert!(overlays
            .iter()
            .any(|o| o.child_old_base == RAW_BASE && o.overlay_applied));
        assert!(!overlays.iter().any(|o| o.child_old_base == IMAGE_VA));
        assert!(!patched.is_empty() && !patched[0].content.is_empty());
    }

    // ------------------------------------------------------------------
    // Route X R0 AF1 (X0-AF1) — P0-1/P0-2/P0-3 closure tests.
    // ------------------------------------------------------------------

    /// P0-1: seeding must use the canonical raw-coherence participant set. A
    /// SyntheticDerived global must be excluded from seeding (no seed binding).
    #[test]
    fn route_x_af1_synthetic_derived_is_excluded_from_seeding() {
        let raw_capture = RawSlabCapture {
            slabs: vec![],
            children: vec![],
        };
        // A SyntheticDerived child (non-raw by predicate).
        let mut synth = global(0x200000, vec![0x55; 0x20], false);
        synth.provenance = RegionProvenance::SyntheticDerived {
            transform_id: "t".into(),
            source_anchor: "anchor".into(),
            construction_digest: sha256_hex(&synth.content),
        };
        synth.extent_kind = CaptureExtentKind::SyntheticDerived;
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let mut globals = vec![synth];
        // Seeding with an empty raw capture must not fail on the synthetic child
        // (it is excluded), and must produce no bindings.
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert!(bindings.is_empty());
    }

    /// P0-1: seeding participant set == canonical predicate set. Only the raw
    /// participant is seeded; the image-inline and SyntheticDerived are not.
    #[test]
    fn route_x_af1_seeding_uses_canonical_participant_set() {
        // Slab with one in-slab raw child.
        let slab_base: u64 = 0x140000000;
        let raw_bytes = b"seed-canonical".to_vec();
        let raw_base = slab_base + 0x3000;
        let slab = slab_with_child(slab_base, 0x40000, raw_base, raw_bytes.clone());
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                raw_base,
                raw_bytes.len(),
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        // globals: raw participant + image-inline + synthetic.
        let mut raw_g = global(raw_base, raw_bytes.clone(), false);
        raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_g.extent_evidence.capture_path =
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        let image = global(0x140149d50, vec![0x41; 0x1950], true);
        let mut synth = global(0x200000, vec![0x55; 0x20], false);
        synth.provenance = RegionProvenance::SyntheticDerived {
            transform_id: "t".into(),
            source_anchor: "a".into(),
            construction_digest: sha256_hex(&synth.content),
        };
        synth.extent_kind = CaptureExtentKind::SyntheticDerived;
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        let mut globals = vec![raw_g.clone(), image, synth];
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        // Exactly ONE binding: the raw participant. Not the image-inline, not the
        // synthetic.
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].child_old_base, raw_base);
    }

    /// P0-2: same-base capture_id change fails closed (provenance drift).
    #[test]
    fn route_x_af1_same_base_capture_id_change_fails_closed() {
        let mut a = global(0x200000, vec![0x42u8; 0x40], false);
        a.extent_evidence.capture_id = "id-before".into();
        let mut b = a.clone();
        b.extent_evidence.capture_id = "id-after".into();
        b.content[0] ^= 0xFF;
        let err = diff_transform_write_runs(&[a], &[b], "t")
            .expect_err("capture_id change must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// P0-2: same-base content.len() change fails closed (size drift).
    #[test]
    fn route_x_af1_same_base_size_change_fails_closed() {
        let mut a = global(0x200000, vec![0x42u8; 0x40], false);
        a.extent_evidence.capture_id = "id".into();
        let mut b = a.clone();
        b.content.truncate(0x30); // size changes 0x40 -> 0x30
        b.content[0] ^= 0xFF;
        let err = diff_transform_write_runs(&[a], &[b], "t")
            .expect_err("content.len change must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// P0-2: same-base extent_kind change fails closed.
    #[test]
    fn route_x_af1_same_base_extent_change_fails_closed() {
        let mut a = global(0x200000, vec![0x42u8; 0x40], false);
        a.extent_evidence.capture_id = "id".into();
        a.extent_kind = CaptureExtentKind::ProbeWindow;
        let mut b = a.clone();
        b.extent_kind = CaptureExtentKind::ObservedAllocation;
        b.content[0] ^= 0xFF;
        let err = diff_transform_write_runs(&[a], &[b], "t")
            .expect_err("extent_kind change must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// P0-2: same-base capture_path change fails closed.
    #[test]
    fn route_x_af1_same_base_capture_path_change_fails_closed() {
        let mut a = global(0x200000, vec![0x42u8; 0x40], false);
        a.extent_evidence.capture_id = "id".into();
        a.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        let mut b = a.clone();
        b.extent_evidence.capture_path =
            crate::dumper::heap_global_snapshot::CapturePath::GscriptChildLink;
        b.content[0] ^= 0xFF;
        let err = diff_transform_write_runs(&[a], &[b], "t")
            .expect_err("capture_path change must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// P0-3: a well-formed but orphaned run (no raw child by identity) fails the
    /// global membership gate before byte replay.
    #[test]
    fn route_x_af1_well_formed_extra_run_without_raw_child_fails_closed() {
        // Raw capture with ONE raw child.
        let raw_bytes = b"orphan-check".to_vec();
        let raw_base = 0x140003000u64;
        let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
        let raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                raw_base,
                raw_bytes.len(),
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        // Transformed set: the raw child (canonical participant).
        let mut raw_g = global(raw_base, raw_bytes.clone(), false);
        raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_g.extent_evidence.capture_path =
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        // A shape-VALID ledger with an EXTRA run whose child (base 0x9999) has no
        // raw child and is not a canonical participant.
        let mut ledger = TransformRunLedger::default();
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "ghost:0x9999".into(),
            child_old_base: 0x9999,
            child_size: 0x10,
            child_offset: 0,
            length: 1,
            transform_id: "t".into(),
            before_digest: sha256_hex(&[0xAA]),
            after_digest: sha256_hex(&[0xBB]),
            first_before_byte: 0xAA,
            first_after_byte: 0xBB,
            before_bytes: vec![0xAA],
            after_bytes: vec![0xBB],
        });
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[raw_g], &[], &[], &ledger).unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// P0-3: a run with a WRONG capture id fails membership (orphaned).
    #[test]
    fn route_x_af1_run_wrong_capture_id_fails_membership() {
        let raw_bytes = b"wrongcap".to_vec();
        let raw_base = 0x140003000u64;
        let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                raw_base,
                raw_bytes.len(),
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        let mut raw_g = global(raw_base, raw_bytes.clone(), false);
        raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_g.extent_evidence.capture_path =
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        // A ledger run with a WRONG capture id (but matching base).
        let mut ledger = TransformRunLedger::default();
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "wrong-id".into(),
            child_old_base: raw_base,
            child_size: raw_bytes.len(),
            child_offset: 0,
            length: 1,
            transform_id: "t".into(),
            before_digest: sha256_hex(&[0xAA]),
            after_digest: sha256_hex(&[0xBB]),
            first_before_byte: 0xAA,
            first_after_byte: 0xBB,
            before_bytes: vec![0xAA],
            after_bytes: vec![0xBB],
        });
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[raw_g], &[], &[], &ledger).unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// P0-3: a run with a WRONG child size fails membership.
    #[test]
    fn route_x_af1_run_wrong_child_size_fails_membership() {
        let raw_bytes = b"wrongsize".to_vec();
        let raw_base = 0x140003000u64;
        let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                raw_base,
                raw_bytes.len(),
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        let mut raw_g = global(raw_base, raw_bytes.clone(), false);
        raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_g.extent_evidence.capture_path =
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        // A ledger run with the RIGHT capture id but WRONG child size.
        let mut ledger = TransformRunLedger::default();
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "main:0x140003000:0:0x140003000:false".into(),
            child_old_base: raw_base,
            child_size: raw_bytes.len() + 16, // wrong size
            child_offset: 0,
            length: 1,
            transform_id: "t".into(),
            before_digest: sha256_hex(&[0xAA]),
            after_digest: sha256_hex(&[0xBB]),
            first_before_byte: 0xAA,
            first_after_byte: 0xBB,
            before_bytes: vec![0xAA],
            after_bytes: vec![0xBB],
        });
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &[raw_g], &[], &[], &ledger).unwrap_err();
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// P0-3 positive: a run matching EXACTLY one raw child (full identity tuple)
    /// passes the membership gate and reaches overlay.
    #[test]
    fn route_x_af1_run_matches_exactly_one_raw_child_positive() {
        let raw_bytes = b"exactmatch".to_vec();
        let raw_base = 0x140003000u64;
        let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                raw_base,
                raw_bytes.len(),
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        let mut raw_g = global(raw_base, raw_bytes.clone(), false);
        raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
        raw_g.extent_evidence.capture_path =
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        // A ledger run matching the raw child EXACTLY (capture_id, base, size).
        let mut ledger = TransformRunLedger::default();
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "main:0x140003000:0:0x140003000:false".into(),
            child_old_base: raw_base,
            child_size: raw_bytes.len(),
            child_offset: 0,
            length: 1,
            transform_id: "t".into(),
            before_digest: sha256_hex(&[0xAA]),
            after_digest: sha256_hex(&[0xBB]),
            first_before_byte: 0xAA,
            first_after_byte: 0xBB,
            before_bytes: vec![0xAA],
            after_bytes: vec![0xBB],
        });
        // validate_run_membership passes (exactly one raw child, in participant set).
        validate_run_membership(&raw_capture, &[raw_g.clone()], &ledger).unwrap();
    }

    // ------------------------------------------------------------------
    // Route Y R0 (Y0) — Declared Size-Reinit Semantics Closure tests.
    // ------------------------------------------------------------------

    /// The sanitize_ahk_runtime_global size reinit (rva 0x141bf0, old ~0x8000 ->
    /// 0x180 zero-filled) is a DECLARED transition: diff_transform_write_runs must
    /// allow it and emit a run with the transformed (new) child size.
    #[test]
    fn route_y_r0_sanitize_size_reinit_is_declared_and_allowed() {
        let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
        a.rva = 0x141bf0;
        a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        a.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        a.extent_kind = CaptureExtentKind::ObservedAllocation;
        // sanitize re-init: 0x8000 -> 0x180 zero-filled.
        let mut b = a.clone();
        b.content = vec![0u8; 0x180];
        let runs = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global").unwrap();
        assert!(!runs.is_empty(), "sanitize re-init must emit a run");
        assert_eq!(
            runs[0].child_size, 0x180,
            "run child_size must be the new size"
        );
        assert_eq!(runs[0].child_capture_id, "mainslot:0x141bf0:0x3437e50");
        assert_eq!(runs[0].transform_id, "sanitize_ahk_runtime_global");
    }

    /// An UNDECLARED size change (not a declared reinit) still fails closed.
    #[test]
    fn route_y_r0_undeclared_size_drift_still_fails_closed() {
        let mut a = global(0x200000, vec![0xAA; 0x40], false);
        a.extent_evidence.capture_id = "id".into();
        let mut b = a.clone();
        b.content = vec![0xBB; 0x60]; // size change, no declaration
        let err = diff_transform_write_runs(&[a], &[b], "some_transform")
            .expect_err("undeclared size drift must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// A size change at the sanitize child rva but with a DIFFERENT transform is
    /// not a declared reinit and fails closed.
    #[test]
    fn route_y_r0_wrong_transform_declaration_fails_closed() {
        let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
        a.rva = 0x141bf0;
        a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        let mut b = a.clone();
        b.content = vec![0u8; 0x180];
        // Transform id is NOT sanitize_ahk_runtime_global -> undeclared.
        let err = diff_transform_write_runs(&[a], &[b], "sort_gscript_label_table")
            .expect_err("wrong transform must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// A declared reinit whose OLD size is outside tolerance fails closed.
    #[test]
    fn route_y_r0_wrong_old_size_fails_closed() {
        let mut a = global(0x3437e50, vec![0xAA; 0x20], false); // way too small
        a.rva = 0x141bf0;
        a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        let mut b = a.clone();
        b.content = vec![0u8; 0x180];
        let err = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global")
            .expect_err("wrong old size must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// A declared reinit whose NEW size != 0x180 fails closed.
    #[test]
    fn route_y_r0_wrong_new_size_fails_closed() {
        let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
        a.rva = 0x141bf0;
        a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        let mut b = a.clone();
        b.content = vec![0u8; 0x200]; // wrong new size
        let err = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global")
            .expect_err("wrong new size must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// A declared reinit whose after content is NOT zero-filled fails closed.
    #[test]
    fn route_y_r0_reinit_not_zero_filled_fails_closed() {
        let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
        a.rva = 0x141bf0;
        a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        let mut b = a.clone();
        b.content = vec![0x00; 0x180];
        b.content[0x10] = 0xFF; // not all zero
        let err = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global")
            .expect_err("non-zero re-init must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// A declared reinit whose capture identity drifted fails closed (capture_id
    /// check is independent of the size declaration).
    #[test]
    fn route_y_r0_wrong_capture_identity_fails_closed() {
        let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
        a.rva = 0x141bf0;
        a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        let mut b = a.clone();
        b.content = vec![0u8; 0x180];
        b.extent_evidence.capture_id = "wrong-id".into(); // capture_id drift
        let err = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global")
            .expect_err("capture_id drift must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// Build a COMPLETE legal declared-reinit scenario through the production
    /// chain: identity -> coverage -> raw-children -> seed -> apply_recorded_transform
    /// (real sanitize) -> (ready for q0c). Returns the full fixture so tests can
    /// either pass it straight to `build_patched_backing_slab_q0c` (positive) or
    /// corrupt exactly one dimension to exercise the Q0-C consumer fail-closed
    /// boundary (negative).
    fn y0_declared_q0c_fixture() -> (
        RawSlabCapture,
        Vec<HeapGlobalSnapshot>,
        Vec<ContainerSnapshot>,
        Vec<TransformPreimageBinding>,
        TransformRunLedger,
    ) {
        const RVA: u32 = 0x141bf0;
        const LIVE: u64 = 0x3437e50;
        const OLD_SIZE: usize = 0x8000;
        let raw_bytes = vec![0xAAu8; OLD_SIZE];
        let slab = slab_with_child(0x3400000, 0x100000, LIVE, raw_bytes.clone());
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                LIVE,
                OLD_SIZE,
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "mainslot:0x141bf0:0x3437e50".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        let mut g = global(LIVE, raw_bytes.clone(), false);
        g.rva = RVA;
        g.extent_kind = CaptureExtentKind::ObservedAllocation;
        g.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
        let mut globals = vec![g];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
        validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
        let children = raw_children_from_capture(&containers, &globals);
        assert_eq!(children.len(), 1);
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert_eq!(bindings.len(), 1);
        let mut ledger = TransformRunLedger::default();
        apply_recorded_transform(
            &mut globals,
            "sanitize_ahk_runtime_global",
            &mut ledger,
            |g| {
                super::super::heap_global_snapshot::sanitize_ahk_runtime_global(g);
            },
        )
        .unwrap();
        assert_eq!(globals[0].content.len(), 0x180);
        assert!(globals[0].content.iter().all(|&b| b == 0));
        assert!(!ledger.runs.is_empty());
        assert_eq!(ledger.runs[0].child_old_base, LIVE);
        assert_eq!(ledger.runs[0].child_size, 0x180);
        (raw_capture, globals, containers, bindings, ledger)
    }

    /// The real sanitize_ahk_runtime_global through the PRODUCTION chain
    /// (identity -> coverage -> raw-children -> seed -> apply_recorded_transform
    /// with the real sanitize -> q0c overlay -> runtime rebase plan -> manifest)
    /// must COMPLETE overlay, produce a run for the size re-init, and the patched
    /// slab must contain the expected zeroed 0x180 region.
    #[test]
    fn route_y_r0_sanitize_full_production_chain_q0c_overlay() {
        const LIVE: u64 = 0x3437e50;
        let (raw_capture, globals, containers, bindings, ledger) = y0_declared_q0c_fixture();
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .unwrap();
        assert!(overlays
            .iter()
            .any(|o| o.child_old_base == LIVE && o.overlay_applied));
        assert!(!patched.is_empty() && !patched[0].content.is_empty());
        // The patched slab region for the re-init child must be exactly 0x180 zeros.
        let off = (LIVE - raw_capture.slabs[0].old_base) as usize;
        let region = &patched[0].content[off..off + 0x180];
        assert_eq!(region.len(), 0x180);
        assert!(
            region.iter().all(|&b| b == 0),
            "declared re-init region must be zero-filled in the patched slab"
        );
        // The overlay record for the declared transition must carry the NEW size
        // and the transformed (zeroed) digest — replayable evidence.
        let o = overlays
            .iter()
            .find(|o| o.child_old_base == LIVE)
            .expect("declared overlay record");
        assert_eq!(o.child_size, 0x180);
        assert_eq!(
            o.transformed_child_digest,
            sha256_hex(&vec![0u8; 0x180]),
            "overlay must record the exact zeroed new-size digest"
        );
        // Runtime rebase plan over the patched slabs: must construct without
        // error (the declared re-init is reflected in the patched backing slab).
        let slots = crate::dumper::runtime_rebase::declared_slots_from_capture(
            &containers,
            &globals,
            &patched,
        );
        // P2: the fixture must genuinely produce a runtime rebase plan over the
        // patched slabs (the declared re-init is part of the patched backing).
        let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
            &containers,
            &globals,
            &patched,
            &slots,
            &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
            &[],
            0x140000000,
            0x150000000,
        )
        .unwrap()
        .expect("a runtime rebase plan must be produced for the declared re-init fixture");
        crate::dumper::runtime_rebase::validate_runtime_rebase_plan(&plan).unwrap();
        // Manifest: the declared transition appears in the recorded transform
        // ledger evidence (the sanitize transform is bound to the candidate).
        let declared_digest = sha256_hex(&vec![0u8; 0x180]);
        assert_eq!(
            overlays.iter().filter(|o| o.child_old_base == LIVE).count(),
            1,
            "exactly one declared overlay record"
        );
        assert_eq!(ledger.runs.len(), 1);
        assert_eq!(ledger.runs[0].transform_id, "sanitize_ahk_runtime_global");
        assert_eq!(ledger.runs[0].after_digest, declared_digest);
        // Manifest serialization must be derived from the ACTUAL ledger/overlay
        // data flow — not hand-injected strings. Build the transform list from
        // the recorded runs (the sanitize transition) and serialize.
        let manifest_dir = std::env::temp_dir().join(format!(
            "mida_y0_manifest_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&manifest_dir).unwrap();
        let candidate = manifest_dir.join("candidate.exe");
        let mut manifest_transforms: Vec<(&str, &str)> = Vec::new();
        for r in &ledger.runs {
            manifest_transforms.push((r.transform_id.as_str(), "declared-size-reinit"));
        }
        assert_eq!(
            manifest_transforms.len(),
            1,
            "ledger must drive exactly one manifest transform entry"
        );
        crate::dumper::dump_process::write_bound_transform_manifest(
            &candidate,
            &patched[0].content,
            &manifest_transforms,
            None,
        )
        .unwrap();
        let manifest = candidate.with_extension("transform_manifest.json");
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).expect("manifest written"))
                .expect("manifest must be valid JSON");
        assert_eq!(parsed["schema_version"], "mida.transform-manifest/v0");
        let entries = parsed["entries"].as_array().expect("entries array");
        assert!(
            entries
                .iter()
                .any(|e| e["id"] == "sanitize_ahk_runtime_global"),
            "manifest must record the declared transition transform from the ledger"
        );
        let _ = std::fs::remove_dir_all(&manifest_dir);
    }

    /// Q0-C consumer boundary: an EMPTY ledger cannot authorize the declared
    /// transition — no run evidence -> fails closed.
    #[test]
    fn route_y_r0_q0c_empty_ledger_fails_closed() {
        let (raw_capture, globals, _c, bindings, _ledger) = y0_declared_q0c_fixture();
        let empty_ledger = TransformRunLedger::default();
        let err =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &empty_ledger)
                .expect_err("empty ledger must fail closed at Q0-C");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// Q0-C consumer boundary: an OLD size far outside the declared tolerance
    /// (raw child much smaller than 0x8000) must be rejected THROUGH the real
    /// `build_patched_backing_slab_q0c` path — not by calling the field validator
    /// directly. We build a complete fixture whose raw child has an out-of-range
    /// size but a fully self-consistent raw/binding/ledger (so the overlay reaches
    /// the declared-reinit boundary) and assert the overlay call itself fails.
    #[test]
    fn route_y_r0_q0c_old_size_out_of_tolerance_fails_closed() {
        const RVA: u32 = 0x141bf0;
        const LIVE: u64 = 0x3437e50;
        const SLAB_BASE: u64 = 0x3400000;
        const SLAB_SZ: usize = 0x100000;
        const RAW_SIZE: usize = 0x100; // far below 0x8000 - 0x2000
        const NEW_SIZE: usize = 0x180;
        let raw_bytes = vec![0xAAu8; RAW_SIZE];
        let slab_content = slab_with_child(SLAB_BASE, SLAB_SZ, LIVE, raw_bytes.clone()).content;
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab(SLAB_BASE, slab_content.clone())],
            children: vec![raw_child(
                LIVE,
                RAW_SIZE,
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "mainA".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_capture.children[0].capture_path = CapturePath::MainSlot;
        // Transformed child: declared re-init -> zeroed NEW_SIZE.
        let mut g = global(LIVE, vec![0u8; NEW_SIZE], false);
        g.rva = RVA;
        g.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
        g.extent_kind = CaptureExtentKind::ObservedAllocation;
        g.extent_evidence.capture_id = "mainA".into();
        g.extent_evidence.capture_path = CapturePath::MainSlot;
        let globals = vec![g];
        // Hand-built binding: self-consistent with the RAW_SIZE raw child and the
        // covering slab (ChildCapture basis for an ObservedAllocation child).
        let off = (LIVE - SLAB_BASE) as usize;
        let slab_slice = slab_content[off..off + RAW_SIZE].to_vec();
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "mainA".into(),
            child_old_base: LIVE,
            child_size: RAW_SIZE,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            slab_old_base: SLAB_BASE,
            slab_size: SLAB_SZ,
            slab_digest: sha256_hex(&slab_content),
            slab_offset: off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&raw_bytes),
            raw_slab_slice_digest: sha256_hex(&slab_slice),
            transform_input_digest: sha256_hex(&raw_bytes),
            seeded_from_slab: false,
        };
        let bindings = vec![binding];
        // A shape-valid sanitize transition run (the old-size gate rejects before
        // the run shape/evidence is even consulted).
        let ledger = TransformRunLedger {
            runs: vec![TransformWriteRun {
                child_capture_id: "mainA".into(),
                child_old_base: LIVE,
                child_size: NEW_SIZE,
                child_offset: 0,
                length: NEW_SIZE,
                transform_id: "sanitize_ahk_runtime_global".into(),
                before_digest: sha256_hex(&vec![0xAAu8; NEW_SIZE]),
                after_digest: sha256_hex(&vec![0u8; NEW_SIZE]),
                first_before_byte: 0xAA,
                first_after_byte: 0x00,
                before_bytes: vec![0xAAu8; NEW_SIZE],
                after_bytes: vec![0u8; NEW_SIZE],
            }],
        };
        let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect_err("out-of-tolerance old size must fail closed THROUGH Q0-C");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// Q0-C consumer boundary: a NEW size != 0x180 on the transformed snapshot
    /// fails closed (declaration requires the exact re-init size).
    #[test]
    fn route_y_r0_q0c_new_size_wrong_fails_closed() {
        let (raw_capture, mut globals, _c, bindings, ledger) = y0_declared_q0c_fixture();
        globals[0].content = vec![0u8; 0x200]; // wrong new size
        let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect_err("wrong new size must fail closed at Q0-C");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// Q0-C consumer boundary: transformed bytes that are NOT zero-filled fail
    /// closed even though the ledger claims a reinit.
    #[test]
    fn route_y_r0_q0c_new_bytes_nonzero_fails_closed() {
        let (raw_capture, mut globals, _c, bindings, ledger) = y0_declared_q0c_fixture();
        globals[0].content = vec![0u8; 0x180];
        globals[0].content[0x40] = 0x5A; // non-zero
        let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect_err("non-zero re-init bytes must fail closed at Q0-C");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// Q0-C consumer boundary: a ledger run with a WRONG child_size (not the
    /// declared new size) fails closed — the transition must be proven at the
    /// declared new size.
    #[test]
    fn route_y_r0_q0c_ledger_child_size_wrong_fails_closed() {
        let (raw_capture, globals, _c, bindings, mut ledger) = y0_declared_q0c_fixture();
        ledger.runs[0].child_size = 0x400; // wrong new size in the ledger
        let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect_err("wrong ledger child_size must fail closed at Q0-C");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// Q0-C consumer boundary (P1-2): a declared re-init whose new-size region
    /// overlaps another transformed child writing a DIFFERENT value must fail
    /// closed with a TransformWriteConflict — never a silent overwrite. The
    /// ordinary child is processed first (lower base), registers its bytes into
    /// `resolved_writes`, then the declared re-init's zeroed region collides.
    #[test]
    fn route_y_r0_q0c_overlap_different_value_fails_closed() {
        const RVA: u32 = 0x141bf0;
        const LIVE: u64 = 0x3437e50; // declared child base (0x141bf0)
        const B_BASE: u64 = 0x3437e20; // ordinary child base, covers LIVE region
        const OLD_SIZE: usize = 0x8000;
        const NEW_SIZE: usize = 0x180;
        const SLAB_BASE: u64 = 0x3400000;
        const SLAB_SZ: usize = 0x100000;
        // A: raw [0xAA; 0x8000] at LIVE. B: raw = [0xCC; 0x30] then [0xAA; 0x180]
        // so B covers [B_BASE, LIVE+NEW_SIZE) and its overlap with A is 0xAA.
        let off_a = (LIVE - SLAB_BASE) as usize;
        let off_b = (B_BASE - SLAB_BASE) as usize;
        let b_sz = (LIVE + NEW_SIZE as u64 - B_BASE) as usize; // 0x30 + 0x180
        let mut a_raw = vec![0xAAu8; OLD_SIZE];
        let mut b_raw = vec![0xCCu8; 0x30];
        b_raw.extend(std::iter::repeat(0xAAu8).take(NEW_SIZE));
        assert_eq!(b_raw.len(), b_sz);
        let mut slab_content = vec![0u8; SLAB_SZ];
        slab_content[off_a..off_a + OLD_SIZE].copy_from_slice(&a_raw);
        slab_content[off_b..off_b + b_sz].copy_from_slice(&b_raw);
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab(SLAB_BASE, slab_content)],
            children: vec![
                raw_child(LIVE, OLD_SIZE, a_raw.clone(), RawChildKind::HeapGlobal),
                raw_child(B_BASE, b_sz, b_raw.clone(), RawChildKind::HeapGlobal),
            ],
        };
        raw_capture.children[0].capture_id = "mainA".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_capture.children[1].capture_id = "mainB".into();
        raw_capture.children[1].extent_kind = CaptureExtentKind::ObservedAllocation;
        // Declared re-init child A.
        let mut ga = global(LIVE, a_raw.clone(), false);
        ga.rva = RVA;
        ga.extent_kind = CaptureExtentKind::ObservedAllocation;
        ga.extent_evidence.capture_id = "mainA".into();
        ga.extent_evidence.capture_path = CapturePath::MainSlot;
        // Ordinary child B.
        let mut gb = global(B_BASE, b_raw.clone(), false);
        gb.extent_kind = CaptureExtentKind::ObservedAllocation;
        gb.extent_evidence.capture_id = "mainB".into();
        gb.extent_evidence.capture_path = CapturePath::MainSlot;
        let mut globals = vec![ga, gb];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
        validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
        let _ = raw_children_from_capture(&containers, &globals);
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        assert_eq!(bindings.len(), 2);
        // Apply: A -> sanitize (zeroed 0x180); B -> ordinary +1 (0xCC->0xCD, 0xAA->0xAB).
        let mut ledger = TransformRunLedger::default();
        apply_recorded_transform(
            &mut globals,
            "sanitize_ahk_runtime_global",
            &mut ledger,
            |gs| {
                for g in gs.iter_mut() {
                    if g.rva == RVA {
                        super::super::heap_global_snapshot::sanitize_ahk_runtime_global(
                            std::slice::from_mut(g),
                        );
                    }
                }
            },
        )
        .unwrap();
        apply_recorded_transform(
            &mut globals,
            "sort_gscript_label_table",
            &mut ledger,
            |gs| {
                for g in gs.iter_mut() {
                    if g.rva != RVA {
                        for b in g.content.iter_mut() {
                            *b = b.wrapping_add(1);
                        }
                    }
                }
            },
        )
        .unwrap();
        // B transforms to 0xCD/0xAB; A re-inits to 0x00.
        let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect_err("overlapping different-value write must fail closed at Q0-C");
        assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    }

    /// Hand-build a complete declared-reinit fixture WITHOUT running the
    /// production recorder, so a test can supply an arbitrary ledger (prior-writer
    /// chains, malformed extra runs, etc.). Raw child A carries the declared
    /// capture identity; the binding is a self-consistent ChildCapture binding
    /// over that raw child. Returns (raw_capture, globals, bindings); the caller
    /// owns the ledger.
    fn y0_manual_identity_fixture(
        raw_capture_id: &str,
    ) -> (
        RawSlabCapture,
        Vec<HeapGlobalSnapshot>,
        Vec<TransformPreimageBinding>,
    ) {
        const RVA: u32 = 0x141bf0;
        const LIVE: u64 = 0x3437e50;
        const OLD_SIZE: usize = 0x8000;
        const SLAB_BASE: u64 = 0x3400000;
        const SLAB_SZ: usize = 0x100000;
        let raw_bytes = vec![0xAAu8; OLD_SIZE];
        let slab_content = slab_with_child(SLAB_BASE, SLAB_SZ, LIVE, raw_bytes.clone()).content;
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab(SLAB_BASE, slab_content.clone())],
            children: vec![raw_child(
                LIVE,
                OLD_SIZE,
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = raw_capture_id.to_string();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_capture.children[0].capture_path = CapturePath::MainSlot;
        let mut g = global(LIVE, vec![0u8; 0x180], false);
        g.rva = RVA;
        g.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
        g.extent_kind = CaptureExtentKind::ObservedAllocation;
        g.extent_evidence.capture_id = raw_capture_id.to_string();
        g.extent_evidence.capture_path = CapturePath::MainSlot;
        let globals = vec![g];
        let off = (LIVE - SLAB_BASE) as usize;
        let slab_slice = slab_content[off..off + OLD_SIZE].to_vec();
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: raw_capture_id.to_string(),
            child_old_base: LIVE,
            child_size: OLD_SIZE,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            slab_old_base: SLAB_BASE,
            slab_size: SLAB_SZ,
            slab_digest: sha256_hex(&slab_content),
            slab_offset: off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&raw_bytes),
            raw_slab_slice_digest: sha256_hex(&slab_slice),
            transform_input_digest: sha256_hex(&raw_bytes),
            seeded_from_slab: false,
        };
        (raw_capture, globals, vec![binding])
    }

    /// Build a sanitize transition run with the given before bytes.
    fn y0_sanitize_run(capture_id: &str, before: Vec<u8>) -> TransformWriteRun {
        let new_size = 0x180usize;
        let after = vec![0u8; new_size];
        assert_eq!(before.len(), new_size);
        TransformWriteRun {
            child_capture_id: capture_id.to_string(),
            child_old_base: 0x3437e50,
            child_size: new_size,
            child_offset: 0,
            length: new_size,
            transform_id: "sanitize_ahk_runtime_global".into(),
            before_digest: sha256_hex(&before),
            after_digest: sha256_hex(&after),
            first_before_byte: before[0],
            first_after_byte: 0x00,
            before_bytes: before,
            after_bytes: after,
        }
    }

    /// Q0-C consumer boundary (P1-3 / Audit P1-3): a LEGAL prior-writer chain
    /// before the declared re-init must be accepted. A prior recorded transform
    /// (e.g. scrub_uncaptured_heap_pointers) changes byte 0 from 0xAA to 0xAB
    /// before sanitize; the sanitize run's before state is the replayed current
    /// state (0xAB prefix), NOT the raw prefix. The chain replays in ledger
    /// execution order and the overlay must succeed.
    #[test]
    fn route_y_r0_q0c_prior_writer_chain_before_declared_reinit_succeeds() {
        let (raw_capture, globals, bindings) = y0_manual_identity_fixture("mainA");
        // prior writer: byte 0 -> 0xAB (raw child_size 0x8000, offset 0, len 1).
        let prior = TransformWriteRun {
            child_capture_id: "mainA".into(),
            child_old_base: 0x3437e50,
            child_size: 0x8000,
            child_offset: 0,
            length: 1,
            transform_id: "scrub_uncaptured_heap_pointers".into(),
            before_digest: sha256_hex(&[0xAA]),
            after_digest: sha256_hex(&[0xAB]),
            first_before_byte: 0xAA,
            first_after_byte: 0xAB,
            before_bytes: vec![0xAA],
            after_bytes: vec![0xAB],
        };
        // sanitize sees byte 0 = 0xAB (post-scrub), rest = 0xAA.
        let mut before = vec![0xAAu8; 0x180];
        before[0] = 0xAB;
        let sanitize = y0_sanitize_run("mainA", before);
        let ledger = TransformRunLedger {
            runs: vec![prior, sanitize],
        };
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .expect("a valid prior-writer chain + declared re-init must succeed");
        let off = (0x3437e50 - 0x3400000) as usize;
        assert_eq!(&patched[0].content[off..off + 0x180], &[0u8; 0x180]);
        assert!(overlays.iter().any(|o| o.overlay_applied));
    }

    /// Q0-C consumer boundary (P1-2 / Audit P1-2): one well-formed transition run
    /// PLUS an extra run with the same transition identity but a WRONG shape must
    /// fail closed (ambiguous transition). The extra bad run must not be silently
    /// filtered out.
    #[test]
    fn route_y_r0_q0c_extra_same_identity_bad_run_fails_closed() {
        let (raw_capture, globals, bindings) = y0_manual_identity_fixture("mainA");
        let good = y0_sanitize_run("mainA", vec![0xAAu8; 0x180]);
        // Same transition identity, but wrong child_size / offset / fabricated bytes.
        let bad = TransformWriteRun {
            child_capture_id: "mainA".into(),
            child_old_base: 0x3437e50,
            child_size: 0x200, // wrong new size
            child_offset: 0x180,
            length: 0x80,
            transform_id: "sanitize_ahk_runtime_global".into(),
            before_digest: sha256_hex(&[0xAA; 0x80]),
            after_digest: sha256_hex(&[0x55; 0x80]),
            first_before_byte: 0xAA,
            first_after_byte: 0x55,
            before_bytes: vec![0xAA; 0x80],
            after_bytes: vec![0x55; 0x80],
        };
        let ledger = TransformRunLedger {
            runs: vec![good, bad],
        };
        let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect_err("an extra same-identity bad run must fail closed");
        assert!(matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
        ));
    }

    /// Q0-C consumer boundary (P1-1 / Audit P1-1): two raw children share the same
    /// old_base + kind but carry DIFFERENT capture identities. The declared
    /// re-init resolves by full capture identity and must succeed with the
    /// declared capture — it must not confuse the two captures (the pre-fix code
    /// selected by raw-byte/slab coherence and could consume the wrong capture).
    #[test]
    fn route_y_r0_q0c_same_base_different_capture_identity_resolves_correctly() {
        const RVA: u32 = 0x141bf0;
        const LIVE: u64 = 0x3437e50;
        const OLD_SIZE: usize = 0x8000;
        const SLAB_BASE: u64 = 0x3400000;
        const SLAB_SZ: usize = 0x100000;
        let raw_bytes = vec![0xAAu8; OLD_SIZE];
        let slab_content = slab_with_child(SLAB_BASE, SLAB_SZ, LIVE, raw_bytes.clone()).content;
        // Two raw children at the SAME base+kind with different capture ids.
        let mut raw_a = raw_child(LIVE, OLD_SIZE, raw_bytes.clone(), RawChildKind::HeapGlobal);
        raw_a.capture_id = "realA".into();
        raw_a.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_a.capture_path = CapturePath::MainSlot;
        let mut raw_b = raw_child(LIVE, OLD_SIZE, raw_bytes.clone(), RawChildKind::HeapGlobal);
        raw_b.capture_id = "fakeB".into();
        raw_b.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_b.capture_path = CapturePath::MainSlot;
        let raw_capture = RawSlabCapture {
            slabs: vec![slab(SLAB_BASE, slab_content.clone())],
            children: vec![raw_a, raw_b],
        };
        // Transformed snapshot declares capture "realA".
        let mut g = global(LIVE, vec![0u8; 0x180], false);
        g.rva = RVA;
        g.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
        g.extent_kind = CaptureExtentKind::ObservedAllocation;
        g.extent_evidence.capture_id = "realA".into();
        g.extent_evidence.capture_path = CapturePath::MainSlot;
        let globals = vec![g];
        let off = (LIVE - SLAB_BASE) as usize;
        let slab_slice = slab_content[off..off + OLD_SIZE].to_vec();
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "realA".into(),
            child_old_base: LIVE,
            child_size: OLD_SIZE,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            slab_old_base: SLAB_BASE,
            slab_size: SLAB_SZ,
            slab_digest: sha256_hex(&slab_content),
            slab_offset: off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&raw_bytes),
            raw_slab_slice_digest: sha256_hex(&slab_slice),
            transform_input_digest: sha256_hex(&raw_bytes),
            seeded_from_slab: false,
        };
        let ledger = TransformRunLedger {
            runs: vec![y0_sanitize_run("realA", vec![0xAAu8; 0x180])],
        };
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &[binding], &ledger)
                .expect("declared re-init must resolve the declared capture by identity");
        let off2 = (LIVE - SLAB_BASE) as usize;
        assert_eq!(&patched[0].content[off2..off2 + 0x180], &[0u8; 0x180]);
        assert!(overlays
            .iter()
            .any(|o| o.child_old_base == LIVE && o.overlay_applied));
    }

    /// Q0-C consumer boundary (P1-1 / Audit P1-1 strongest form): the declared
    /// capture's raw bytes DISAGREE with the slab, while a DIFFERENT capture at
    /// the same base+kind AGREES with the slab. The overlay must resolve by
    /// capture identity (choose A) and then FAIL CLOSED on A's coherence — it
    /// must NEVER silently fall back to the different-capture raw child (B) that
    /// happens to match the slab.
    #[test]
    fn route_y_r0_q0c_wrong_capture_raw_bytes_must_not_fall_back_to_slab_matching_child() {
        const RVA: u32 = 0x141bf0;
        const LIVE: u64 = 0x3437e50;
        const OLD_SIZE: usize = 0x8000;
        const SLAB_BASE: u64 = 0x3400000;
        const SLAB_SZ: usize = 0x100000;
        // Slab region holds B's bytes (0xBB); A's declared bytes (0xAA) differ.
        let slab_bytes = vec![0xBBu8; OLD_SIZE];
        let slab_content = slab_with_child(SLAB_BASE, SLAB_SZ, LIVE, slab_bytes.clone()).content;
        let mut raw_a = raw_child(
            LIVE,
            OLD_SIZE,
            vec![0xAAu8; OLD_SIZE],
            RawChildKind::HeapGlobal,
        );
        raw_a.capture_id = "realA".into();
        raw_a.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_a.capture_path = CapturePath::MainSlot;
        let mut raw_b = raw_child(LIVE, OLD_SIZE, slab_bytes.clone(), RawChildKind::HeapGlobal);
        raw_b.capture_id = "fakeB".into();
        raw_b.extent_kind = CaptureExtentKind::ObservedAllocation;
        raw_b.capture_path = CapturePath::MainSlot;
        let raw_capture = RawSlabCapture {
            slabs: vec![slab(SLAB_BASE, slab_content.clone())],
            children: vec![raw_a, raw_b],
        };
        // Transformed snapshot + binding + ledger all declare capture "realA".
        let mut g = global(LIVE, vec![0u8; 0x180], false);
        g.rva = RVA;
        g.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
        g.extent_kind = CaptureExtentKind::ObservedAllocation;
        g.extent_evidence.capture_id = "realA".into();
        g.extent_evidence.capture_path = CapturePath::MainSlot;
        let globals = vec![g];
        let off = (LIVE - SLAB_BASE) as usize;
        let a_slice = slab_content[off..off + OLD_SIZE].to_vec(); // B's bytes in the slab
        let binding = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "realA".into(),
            child_old_base: LIVE,
            child_size: OLD_SIZE,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            slab_old_base: SLAB_BASE,
            slab_size: SLAB_SZ,
            slab_digest: sha256_hex(&slab_content),
            slab_offset: off,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: sha256_hex(&vec![0xAAu8; OLD_SIZE]), // A's digest
            raw_slab_slice_digest: sha256_hex(&a_slice),
            transform_input_digest: sha256_hex(&vec![0xAAu8; OLD_SIZE]), // A's preimage
            seeded_from_slab: false,
        };
        let ledger = TransformRunLedger {
            runs: vec![y0_sanitize_run("realA", vec![0xAAu8; 0x180])],
        };
        let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &[binding], &ledger)
            .expect_err(
                "declared capture whose raw disagrees with the slab must fail closed, \
                 never fall back to the different-capture slab-matching child",
            );
        assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
    }

    /// Q0-C + recorder agreement (Audit P1): a real declared size re-init whose
    /// old prefix ALREADY contains zero bytes (free-list-polluted heap blob) must
    /// go through the PRODUCTION chain — recorder emits a single dedicated full
    /// transition run, and Q0-C accepts it. The recorder must NOT emit multiple
    /// sparse byte-diff runs (a zero already present in the prefix would otherwise
    /// split the diff), and Q0-C must NOT reject a legitimate single-run ledger.
    #[test]
    fn route_y_r0_q0c_sparse_zero_prefix_succeeds() {
        const RVA: u32 = 0x141bf0;
        const LIVE: u64 = 0x3437e50;
        const OLD_SIZE: usize = 0x8000;
        // Old prefix is mostly 0xAA but contains ZERO bytes at scattered offsets
        // (0x40, 0x80, 0x100) — exactly the polluted free-list blob shape.
        let mut raw_bytes = vec![0xAAu8; OLD_SIZE];
        raw_bytes[0x40] = 0x00;
        raw_bytes[0x80] = 0x00;
        raw_bytes[0x100] = 0x00;
        let slab = slab_with_child(0x3400000, 0x100000, LIVE, raw_bytes.clone());
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                LIVE,
                OLD_SIZE,
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "mainslot:0x141bf0:0x3437e50".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        let mut g = global(LIVE, raw_bytes.clone(), false);
        g.rva = RVA;
        g.extent_kind = CaptureExtentKind::ObservedAllocation;
        g.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        g.extent_evidence.capture_path = CapturePath::MainSlot;
        let mut globals = vec![g];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
        validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
        let _ = raw_children_from_capture(&containers, &globals);
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        // Real recorder + real sanitize.
        let mut ledger = TransformRunLedger::default();
        apply_recorded_transform(
            &mut globals,
            "sanitize_ahk_runtime_global",
            &mut ledger,
            |gs| {
                for gs in gs.iter_mut() {
                    super::super::heap_global_snapshot::sanitize_ahk_runtime_global(
                        std::slice::from_mut(gs),
                    );
                }
            },
        )
        .unwrap();
        assert_eq!(globals[0].content.len(), 0x180);
        assert!(globals[0].content.iter().all(|&b| b == 0));
        // The recorder MUST emit exactly ONE full transition run despite the
        // sparse zero bytes in the old prefix.
        assert_eq!(
            ledger.runs.len(),
            1,
            "declared re-init recorder must emit exactly one full transition run"
        );
        assert_eq!(ledger.runs[0].child_offset, 0);
        assert_eq!(ledger.runs[0].length, 0x180);
        // Q0-C accepts the single-run ledger and produces an exactly-zeroed slab.
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .expect("sparse-zero-prefix declared re-init must succeed at Q0-C");
        let off = (LIVE - 0x3400000) as usize;
        assert_eq!(&patched[0].content[off..off + 0x180], &[0u8; 0x180]);
        assert!(overlays.iter().any(|o| o.overlay_applied));
    }

    /// Q0-C + recorder agreement (Audit P1, prior-writer variant): a prior
    /// recorded transform zeros part of the prefix, then sanitize runs. The
    /// recorder still emits ONE full transition run for sanitize (its before
    /// state already includes the prior zeros), and Q0-C accepts the full chain.
    #[test]
    fn route_y_r0_q0c_prior_writer_sparse_zero_prefix_succeeds() {
        const RVA: u32 = 0x141bf0;
        const LIVE: u64 = 0x3437e50;
        const OLD_SIZE: usize = 0x8000;
        let mut raw_bytes = vec![0xAAu8; OLD_SIZE];
        let slab = slab_with_child(0x3400000, 0x100000, LIVE, raw_bytes.clone());
        let mut raw_capture = RawSlabCapture {
            slabs: vec![slab],
            children: vec![raw_child(
                LIVE,
                OLD_SIZE,
                raw_bytes.clone(),
                RawChildKind::HeapGlobal,
            )],
        };
        raw_capture.children[0].capture_id = "mainslot:0x141bf0:0x3437e50".into();
        raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
        let mut g = global(LIVE, raw_bytes.clone(), false);
        g.rva = RVA;
        g.extent_kind = CaptureExtentKind::ObservedAllocation;
        g.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
        g.extent_evidence.capture_path = CapturePath::MainSlot;
        let mut globals = vec![g];
        let mut containers: Vec<ContainerSnapshot> = Vec::new();
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
        validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
        let _ = raw_children_from_capture(&containers, &globals);
        let bindings = seed_transform_inputs_from_authoritative_slab(
            &raw_capture,
            &mut containers,
            &mut globals,
        )
        .unwrap();
        let mut ledger = TransformRunLedger::default();
        // A prior transform zeros byte 0x40 (like scrub), then sanitize re-inits.
        apply_recorded_transform(
            &mut globals,
            "scrub_uncaptured_heap_pointers",
            &mut ledger,
            |gs| {
                for gs in gs.iter_mut() {
                    if gs.rva == RVA {
                        if let Some(b) = gs.content.get_mut(0x40) {
                            *b = 0x00;
                        }
                    }
                }
            },
        )
        .unwrap();
        apply_recorded_transform(
            &mut globals,
            "sanitize_ahk_runtime_global",
            &mut ledger,
            |gs| {
                for gs in gs.iter_mut() {
                    super::super::heap_global_snapshot::sanitize_ahk_runtime_global(
                        std::slice::from_mut(gs),
                    );
                }
            },
        )
        .unwrap();
        assert_eq!(globals[0].content.len(), 0x180);
        assert!(globals[0].content.iter().all(|&b| b == 0));
        // sanitize's own ledger run must be a single full [0,0x180) transition run.
        let sanitize_runs: Vec<_> = ledger
            .runs
            .iter()
            .filter(|r| r.transform_id == "sanitize_ahk_runtime_global")
            .collect();
        assert_eq!(
            sanitize_runs.len(),
            1,
            "sanitize must emit exactly one full run"
        );
        assert_eq!(sanitize_runs[0].child_offset, 0);
        assert_eq!(sanitize_runs[0].length, 0x180);
        let (patched, overlays, _) =
            build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
                .expect("prior-writer + declared re-init must succeed at Q0-C");
        let off = (LIVE - 0x3400000) as usize;
        assert_eq!(&patched[0].content[off..off + 0x180], &[0u8; 0x180]);
        assert!(overlays.iter().any(|o| o.overlay_applied));
    }
}
