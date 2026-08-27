//! Raw-slab capture coherence + transformed-child overlay (R0-C.1).
//!
//! Production `.expect()`s are invariants (WO-12): each site follows a guard
//! that makes the expected value unreachable-None/Err (len-matched slices,
//! `if has_x` + `plan.x` co-check, `match`-bound states, caller-validated
//! member names, re-serialization of an already-parsed Value, FFI
//! kernel32/Sleep existence, or caller pre-checked Option). Production
//! `.unwrap()`s are the same class of invariants (WO-10 carryover missed in
//! that pass, surfaced by the WO-14 --tests audit): matching_ids[0] under a
//! count==1 guard, end.unwrap() under an is_none else branch, raw_size/
//! new_size unwraps under is_some guards. No production fallible path is
//! masked. Test-block unwraps/expects are ordinary assertions (WO-14).
#![allow(clippy::unwrap_used, clippy::expect_used)]
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

use super::capture_policy::DumpCapturePolicy;
use super::container_snapshot::ContainerSnapshot;
use super::heap_global_snapshot::{
    HeapGlobalSnapshot, HeapSlab, PreTruncParentAuthorityEvidence, PreTruncParentAuthorityKey,
    PreTruncParentAuthorityStore, RegionProvenance,
};
use super::module_identity::ModuleIdentity;

/// MIDA-SERIAL-14: reserved gate interface for sample-specific transforms.
/// MIDA-SERIAL-15 wires this into `sanitize_ahk_runtime_global`,
/// `normalize_cmd_table_capture`, `multi_fixup`, CS re-init and cookie mirror
/// call sites. This module provides the decision primitive only; the internal
/// semantics of those transforms are NOT changed here.
///
/// Rules enforced by the underlying policy gate:
///   * no module binding        -> deny;
///   * binding mismatch         -> deny;
///   * policy digest mismatch   -> deny;
///   * policy revision unset    -> deny;
///   * matching identity + valid policy -> allow.
/// The action name is advisory (e.g. "sanitize_ahk_runtime_global"); the RVA
/// alone is never sufficient.
/// Retained as the reserved decision primitive for MIDA-SERIAL-14/15 call-site
/// wiring; no in-tree caller yet, kept for the documented contract.
#[allow(dead_code)]
pub fn sample_transform_allowed(
    policy: &DumpCapturePolicy,
    module: &ModuleIdentity,
    action: &str,
) -> bool {
    policy.allows_sample_transform(module, action)
}

/// Convenience for MIDA-SERIAL-15: strip a policy to generic-only when the
/// gate denies (no binding / mismatch / digest / revision failure).
/// Reserved pairing of `sample_transform_allowed`; no in-tree caller yet.
#[allow(dead_code)]
pub fn policy_for_generic_path(policy: &DumpCapturePolicy) -> DumpCapturePolicy {
    policy.strip_sample_specific()
}

/// Kind of a captured child region (for overlay provenance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RawChildKind {
    HeapGlobal,
    Container,
}

/// Route Y R1 A6 AF3 AF2 (P1-1): the SINGLE, structurally-compared capture
/// identity that is frozen across the ENTIRE raw → binding → recorder → Q0-C
/// chain. Every field participates; equality is structural (no string
/// formatting concatenation).
///
/// This unifies the identity that was previously split across `RawChild`
/// (partial), `CaptureIdentity` (child/parent, partial), and the transformed
/// tuple (3 fields). Deriving the SAME struct from a raw child, a transformed
/// snapshot, and the binding lets every stage agree on one complete identity and
/// fail closed on any field drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullCaptureIdentity {
    pub kind: RawChildKind,
    pub capture_id: String,
    pub old_base: u64,
    pub size: usize,
    pub extent_kind: super::heap_global_snapshot::CaptureExtentKind,
    pub capture_path: super::heap_global_snapshot::CapturePath,
    pub source_root_rva: Option<u32>,
    pub source_slot_offset: Option<usize>,
    pub probe_requested_size: usize,
    pub was_interior: bool,
    pub containing_parent_old_base: Option<u64>,
    pub containing_parent_size: Option<usize>,
}

impl FullCaptureIdentity {
    /// Build from a raw child (the frozen pre-transform evidence).
    pub fn from_raw_child(c: &RawChild) -> Self {
        Self {
            kind: c.kind,
            capture_id: c.capture_id.clone(),
            old_base: c.old_base,
            size: c.size,
            extent_kind: c.extent_kind,
            capture_path: c.capture_path,
            source_root_rva: c.source_root_rva,
            source_slot_offset: c.source_slot_offset,
            probe_requested_size: c.requested_probe_size,
            was_interior: c.was_interior,
            containing_parent_old_base: c.containing_parent_old_base,
            containing_parent_size: c.containing_parent_size,
        }
    }

    /// Build from a transformed heap-global snapshot (post-transform).
    pub fn from_heap_global(g: &HeapGlobalSnapshot) -> Self {
        Self {
            kind: RawChildKind::HeapGlobal,
            capture_id: g.extent_evidence.capture_id.clone(),
            old_base: g.live_ptr,
            size: g.content.len(),
            extent_kind: g.extent_kind,
            capture_path: g.extent_evidence.capture_path,
            source_root_rva: g.extent_evidence.source_root_rva,
            source_slot_offset: g.extent_evidence.source_slot_offset,
            probe_requested_size: g.extent_evidence.probe_requested_size,
            was_interior: g.extent_evidence.was_interior,
            containing_parent_old_base: g.extent_evidence.containing_parent_old_base,
            containing_parent_size: g.extent_evidence.containing_parent_size,
        }
    }

    /// Build from a container (fixed deterministic identity).
    pub fn from_container(c: &ContainerSnapshot) -> Self {
        let size = c
            .decoded_end
            .checked_sub(c.decoded_begin)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        Self {
            kind: RawChildKind::Container,
            capture_id: container_capture_id(c.decoded_begin),
            old_base: c.decoded_begin,
            size,
            extent_kind: super::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            capture_path: super::heap_global_snapshot::CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }
    }

    /// Route Y R1 A6 AF3 AF2 (P1-5): build a full identity from classic binding
    /// fields with NO source evidence except the given capture path and probe.
    /// Used by test fixtures whose raw child / transformed snapshot carry no
    /// source root/slot/interior evidence; production seeding uses
    /// [`Self::from_raw_child`] so real source evidence is frozen.
    #[cfg(test)]
    pub fn from_plain_parts(
        kind: RawChildKind,
        capture_id: String,
        old_base: u64,
        size: usize,
        extent_kind: super::heap_global_snapshot::CaptureExtentKind,
        capture_path: super::heap_global_snapshot::CapturePath,
        probe_requested_size: usize,
    ) -> Self {
        Self {
            kind,
            capture_id,
            old_base,
            size,
            extent_kind,
            capture_path,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }
    }
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
    /// Byte offset of the source slot within the parent (if any).
    pub source_slot_offset: Option<usize>,
    /// The probe size requested for this capture.
    pub requested_probe_size: usize,
    /// Route Y R1 A6 AF3 AF2 (P1-2): the source root RVA of the gscript object
    /// that led to this capture. Frozen at raw capture time and never re-derived
    /// from a transformed snapshot.
    pub source_root_rva: Option<u32>,
    /// Whether this pointer was interior to an already-captured object.
    pub was_interior: bool,
    /// Old base of the containing parent object, if any.
    pub containing_parent_old_base: Option<u64>,
    /// Size of the containing parent, if any.
    pub containing_parent_size: Option<usize>,
}

/// Route Y R1 A6 AF3 AF2 (P1-5): full-identity equality EXCEPT `size`, which is
/// legitimately allowed to change for a DECLARED size reinit. Every other field
/// (kind, capture_id, old_base, extent, path, source root, source slot, probe,
/// was_interior, containing parent) must match exactly.
fn identity_matches_ignore_size(a: &FullCaptureIdentity, b: &FullCaptureIdentity) -> bool {
    a.kind == b.kind
        && a.capture_id == b.capture_id
        && a.old_base == b.old_base
        && a.extent_kind == b.extent_kind
        && a.capture_path == b.capture_path
        && a.source_root_rva == b.source_root_rva
        && a.source_slot_offset == b.source_slot_offset
        && a.probe_requested_size == b.probe_requested_size
        && a.was_interior == b.was_interior
        && a.containing_parent_old_base == b.containing_parent_old_base
        && a.containing_parent_size == b.containing_parent_size
}

/// Route Y R1 A6 AF3 AF2 (P1-5): compare a transformed identity against a
/// binding identity. Exact equality, OR (for a declared size reinit) equality
/// ignoring size.
fn identity_matches_binding(
    transformed: &FullCaptureIdentity,
    binding: &FullCaptureIdentity,
    declared_reinit: bool,
) -> bool {
    if declared_reinit {
        identity_matches_ignore_size(transformed, binding)
    } else {
        transformed == binding
    }
}

/// Route Y R1 A6 AF3 AF2 (P1-5): compare a binding identity against the resolved
/// raw child. Exact equality, OR (for a declared size reinit) equality ignoring
/// size.
fn identity_matches_raw_child(
    binding: &FullCaptureIdentity,
    raw: &RawChild,
    declared_reinit: bool,
) -> bool {
    let raw_identity = FullCaptureIdentity::from_raw_child(raw);
    if declared_reinit {
        identity_matches_ignore_size(binding, &raw_identity)
    } else {
        *binding == raw_identity
    }
}

/// Route Y R1 A6 AF3 AF2 AF1 AF1 (P1-2): the SINGLE shared identity resolver
/// predicate used by BOTH seeding and Q0-C pre-resolution, so the two never drift.
///
/// For a DECLARED size reinit, `size` is ignored (the raw child's old size is the
/// preimage the transform shrank from) but EVERY other identity field must match
/// exactly. For a normal child the raw identity must be fully structurally equal.
fn raw_identity_matches_transformed(
    raw: &RawChild,
    transformed: &FullCaptureIdentity,
    declared_reinit: bool,
) -> bool {
    let ri = FullCaptureIdentity::from_raw_child(raw);
    if declared_reinit {
        identity_matches_ignore_size(transformed, &ri)
    } else {
        transformed == &ri
    }
}

/// Route Y R1 A6 AF3 AF2 AF1 AF1 (P1-1): the resolution mode recorded in the
/// identity plan — the DECLARED size-reinit spec is the one already qualified in
/// the pre-resolution phase, so later phases never re-select it by transform-id
/// first-match.
enum ResolvedQ0cMode {
    Ordinary,
    DeclaredSizeReinit { spec: &'static DeclaredSizeReinit },
}

/// Route Y R1 A6 AF3 AF2 AF1 AF1 (P1-1): the typed result of the Q0-C identity
/// pre-resolution phase — one entry per non-SyntheticDerived transformed child.
/// The unique raw child is resolved by FULL identity ONCE, before any
/// ledger / binding / slab / byte / overlay decision. Later phases consume this
/// plan; they must NOT re-resolve a raw child by partial identity.
struct ResolvedQ0cChild {
    /// Index into `transformed` (the Vec<TransformedChild>).
    transformed_index: usize,
    /// Index into `raw_capture.children` — the unique full-identity match.
    raw_index: usize,
    /// The verified resolution mode (ordinary vs declared reinit with its spec).
    mode: ResolvedQ0cMode,
}

/// A transformed child (heap-global or container) collected inside
/// `build_patched_backing_slab_q0c`, carrying the FULL capture identity plus the
/// byte/provenance fields needed to write the overlay.
///
/// Route Y R1 A6 AF3 AF2 (P1-4): the identity is the complete
/// [`FullCaptureIdentity`] — NOT just (base, kind, capture_id, extent, path) —
/// so the raw-child resolution can never conflate two objects that share those
/// fields but differ in source evidence (source_root_rva / source_slot_offset /
/// probe / was_interior / containing parent).
struct TransformedChild {
    identity: FullCaptureIdentity,
    bytes: Vec<u8>,
    provenance: RegionProvenance,
    transform_ids: Vec<String>,
    rva: u32,
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
            child_capture_id: String::new(),
            child_capture_path: String::new(),
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
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
                child_capture_id: String::new(),
                child_capture_path: String::new(),
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: 0,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
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
/// never inferred from position — dedicated-only inputs keep role "dedicated",
/// and pre-trunc parent-closure inputs keep role "parent_closure".
#[derive(Debug, Clone)]
pub struct AuthoritativeSlabCandidate {
    /// The slab backing region.
    pub slab: HeapSlab,
    /// Real capture role: "main" | "dedicated" | "parent_closure" (the
    /// closure-slab role produced by `build_authority_closure_candidates`).
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
    /// Role: "main" | "dedicated" | "parent_closure" — the TRUE capture role
    /// (never inferred).
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
    /// True capture role of the input ("main" | "dedicated" | "parent_closure").
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
    /// Route Y R1 A6 AF3 AF2 (P1-5): the COMPLETE capture identity of the bound
    /// child (raw child == transform input == transformed snapshot). Q0-C
    /// verifies binding.identity == raw_child.identity == transformed.identity on
    /// every field; any drift fails closed. Never a partial (capture_id/base/size/
    /// extent) tuple.
    pub identity: FullCaptureIdentity,
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

impl TransformPreimageBinding {
    /// Route Y R1 A6 AF3 AF2 AF1 (P2): the SINGLE identity owner constructor.
    /// The legacy field tuple (`child_kind` / `capture_id` / `child_old_base` /
    /// `child_size` / `extent_kind`) is derived FROM `identity`, so a binding
    /// cannot be constructed with two self-contradictory identity sources. The
    /// slab / digest / basis evidence is passed separately.
    pub fn new(
        identity: FullCaptureIdentity,
        slab_old_base: u64,
        slab_size: usize,
        slab_digest: String,
        slab_offset: usize,
        basis: TransformPreimageBasis,
        raw_child_digest: String,
        raw_slab_slice_digest: String,
        transform_input_digest: String,
        seeded_from_slab: bool,
    ) -> Self {
        Self {
            child_kind: identity.kind,
            capture_id: identity.capture_id.clone(),
            child_old_base: identity.old_base,
            child_size: identity.size,
            extent_kind: identity.extent_kind,
            identity,
            slab_old_base,
            slab_size,
            slab_digest,
            slab_offset,
            basis,
            raw_child_digest,
            raw_slab_slice_digest,
            transform_input_digest,
            seeded_from_slab,
        }
    }

    /// Route Y R1 A6 AF3 AF2 AF1 (P2): verify that every overlapping legacy field
    /// agrees with `self.identity`. A contradictory binding (constructed through a
    /// struct literal or mutated after construction) is a single source of
    /// ambiguity and fails closed before any binding resolution.
    pub fn validate_identity_consistency(&self) -> Result<(), OverlayError> {
        let id = &self.identity;
        let mismatch = |field: &str, legacy: String, identity: String| {
            OverlayError::BindingIdentityInconsistent {
                child_old_base: self.child_old_base,
                child_kind: self.child_kind,
                field: field.to_string(),
                legacy,
                identity,
            }
        };
        if self.child_kind != id.kind {
            return Err(mismatch(
                "child_kind",
                format!("{:?}", self.child_kind),
                format!("{:?}", id.kind),
            ));
        }
        if self.capture_id != id.capture_id {
            return Err(mismatch(
                "capture_id",
                self.capture_id.clone(),
                id.capture_id.clone(),
            ));
        }
        if self.child_old_base != id.old_base {
            return Err(mismatch(
                "child_old_base",
                format!("{:#x}", self.child_old_base),
                format!("{:#x}", id.old_base),
            ));
        }
        if self.child_size != id.size {
            return Err(mismatch(
                "child_size",
                format!("{:#x}", self.child_size),
                format!("{:#x}", id.size),
            ));
        }
        if self.extent_kind != id.extent_kind {
            return Err(mismatch(
                "extent_kind",
                format!("{:?}", self.extent_kind),
                format!("{:?}", id.extent_kind),
            ));
        }
        Ok(())
    }
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
        // Route Y R1 GTO R1 (no-bypass resume): the live heap blob for this
        // slot is genuinely variable across runs (observed 0x4640 = 17984 and
        // 0x7E00 = 32256 on fresh no-bypass captures of the protected input).
        // The sanitize transform is a size re-init by design (any old content
        // is replaced by the fixed 0x180 zeroed slab), so the old-size window
        // must admit the observed variance while still rejecting degenerate
        // fragments (e.g. 0x20 in the fail-closed test). Window: [0x4000,0xC000].
        old_size: 0x8000,
        old_size_tolerance: 0x4000, // live heap blob 16-48 KiB observed variance
        new_size: 0x180,
        zero_filled: true,
    };
    match (transform_id, child_rva) {
        ("sanitize_ahk_runtime_global", 0x141bf0) => Some(SANITIZE_AHK_RUNTIME_GLOBAL),
        _ => None,
    }
}

/// Route Y R1 A6 AF3 AF2 AF1 AF1 AF1 AF1 (Task 1/P1): resolve the UNIQUE declared
/// size-reinit for a transformed child from its full `transform_ids` list and RVA.
///
/// This is the fail-closed replacement for the previous `filter_map(...).next()`
/// first-match selection. It counts EVERY declaration hit — including duplicate
/// transform IDs that hit the same declaration — and:
///
///   * 0 hits            -> `Ok(None)` (ordinary child, exact-identity lookup);
///   * exactly 1 hit     -> `Ok(Some(spec))` (unique declared reinit);
///   * more than 1 hit   -> `Err(OverlayError::TransformRunLedgerInvalid)` with a
///                          machine-parseable reason naming the child RVA, every
///                          matching transform id, the exact match count, and the
///                          `ambiguous declared size reinit` marker.
///
/// It MUST run BEFORE raw full-identity resolution: a declaration ambiguity is a
/// declaration-evidence error and is reported ahead of any raw-identity decision.
/// It never sorts-and-first-matches and never deduplicates to hide duplicate
/// evidence. The identity context (`child_capture_id` / `child_old_base` /
/// `child_size`) is carried only so the typed [`OverlayError::TransformRunLedgerInvalid`]
/// is fully populated; the ambiguity decision itself depends solely on
/// `transform_ids` + `child_rva` (see [`collect_declared_reinit_hits`]).
pub fn resolve_declared_size_reinit_spec(
    transform_ids: &[String],
    child_rva: u32,
    child_capture_id: &str,
    child_old_base: u64,
    child_size: usize,
) -> Result<Option<&'static DeclaredSizeReinit>, OverlayError> {
    let (count, matching_ids) = collect_declared_reinit_hits(transform_ids, child_rva);
    match count {
        0 => Ok(None),
        1 => Ok(Some(declared_size_reinit(&matching_ids[0], child_rva).unwrap())),
        n => Err(OverlayError::TransformRunLedgerInvalid {
            run_index: 0,
            child_capture_id: child_capture_id.to_string(),
            child_old_base,
            child_size,
            child_offset: 0,
            length: 0,
            transform_id: matching_ids.join(","),
            reason: format!(
                "ambiguous declared size reinit: child rva {child_rva:#x} matched {n} transform id(s) [{}]",
                matching_ids.join(", ")
            ),
        }),
    }
}

/// Count and collect the transform IDs in `transform_ids` that hit a declared
/// size-reinit for `child_rva`. Every hit is recorded — duplicate transform IDs
/// that hit the same declaration are each counted as distinct evidence, so a
/// duplicated ID cannot silently pass as "one unique declaration".
fn collect_declared_reinit_hits(transform_ids: &[String], child_rva: u32) -> (usize, Vec<String>) {
    let mut hits: Vec<String> = transform_ids
        .iter()
        .filter(|tid| declared_size_reinit(tid, child_rva).is_some())
        .map(|tid| tid.clone())
        .collect();
    hits.sort();
    let count = hits.len();
    (count, hits)
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
    let err = |reason: String| OverlayError::TransformRunLedgerInvalid {
        run_index,
        child_capture_id: a.extent_evidence.capture_id.clone(),
        child_old_base: a.live_ptr,
        child_size: a.content.len(),
        child_offset: 0,
        length: 0,
        transform_id: transform_id.to_string(),
        reason,
    };
    // Route Y R1 A6 AF3 AF2 (P1-3): the FULL capture identity (including every
    // source-evidence field) must be structurally identical across a transform,
    // EXCEPT a DECLARED size reinit which may legitimately change content.len.
    // Any provenance field drift is a TransformRunLedgerInvalid — a transform can
    // never reclassify or re-anchor a child.
    let before = FullCaptureIdentity::from_heap_global(b);
    let after = FullCaptureIdentity::from_heap_global(a);

    if before.capture_id != after.capture_id {
        return Err(err(format!(
            "raw identity drift on capture_id for old_base {:#x}: {} -> {}",
            a.live_ptr, before.capture_id, after.capture_id
        )));
    }
    if before.extent_kind != after.extent_kind {
        return Err(err(format!(
            "raw identity drift on extent_kind for old_base {:#x}: {:?} -> {:?}",
            a.live_ptr, before.extent_kind, after.extent_kind
        )));
    }
    if before.capture_path != after.capture_path {
        return Err(err(format!(
            "raw identity drift on capture_path for old_base {:#x}: {:?} -> {:?}",
            a.live_ptr, before.capture_path, after.capture_path
        )));
    }
    if before.source_root_rva != after.source_root_rva {
        return Err(err(format!(
            "raw identity drift on source_root_rva for old_base {:#x}: {:?} -> {:?}",
            a.live_ptr, before.source_root_rva, after.source_root_rva
        )));
    }
    if before.source_slot_offset != after.source_slot_offset {
        return Err(err(format!(
            "raw identity drift on source_slot_offset for old_base {:#x}: {:?} -> {:?}",
            a.live_ptr, before.source_slot_offset, after.source_slot_offset
        )));
    }
    if before.probe_requested_size != after.probe_requested_size {
        return Err(err(format!(
            "raw identity drift on probe_requested_size for old_base {:#x}: {} -> {}",
            a.live_ptr, before.probe_requested_size, after.probe_requested_size
        )));
    }
    if before.was_interior != after.was_interior {
        return Err(err(format!(
            "raw identity drift on was_interior for old_base {:#x}: {} -> {}",
            a.live_ptr, before.was_interior, after.was_interior
        )));
    }
    if before.containing_parent_old_base != after.containing_parent_old_base {
        return Err(err(format!(
            "raw identity drift on containing_parent_old_base for old_base {:#x}: {:?} -> {:?}",
            a.live_ptr, before.containing_parent_old_base, after.containing_parent_old_base
        )));
    }
    if before.containing_parent_size != after.containing_parent_size {
        return Err(err(format!(
            "raw identity drift on containing_parent_size for old_base {:#x}: {:?} -> {:?}",
            a.live_ptr, before.containing_parent_size, after.containing_parent_size
        )));
    }
    if before.old_base != after.old_base {
        return Err(err(format!(
            "raw identity drift on old_base for {:#x}: {:#x} -> {:#x}",
            before.old_base, before.old_base, after.old_base
        )));
    }
    if before.kind != after.kind {
        return Err(err(format!(
            "raw identity drift on kind for old_base {:#x}: {:?} -> {:?}",
            a.live_ptr, before.kind, after.kind
        )));
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
        /// Route Z R0 AF1: bounded hex excerpt of the raw child bytes around the
        /// first mismatch (diagnostic; never the whole heap object).
        raw_child_excerpt: String,
        /// Route Z R0 AF1: bounded hex excerpt of the slab slice bytes around the
        /// first mismatch (diagnostic; never the whole slab).
        raw_slab_slice_excerpt: String,
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
        /// Deterministic capture id of the uncovered child.
        child_capture_id: String,
        /// Capture path that produced the uncovered child.
        child_capture_path: String,
        /// Root image RVA that led to the child capture, if known.
        source_root_rva: Option<u32>,
        /// Byte offset of the source slot within the root, if known.
        source_slot_offset: Option<usize>,
        /// The probe size requested for this child capture.
        probe_requested_size: usize,
        /// Whether the child was interior to an already-captured object.
        was_interior: bool,
        /// Old base of the containing parent object, if any.
        containing_parent_old_base: Option<u64>,
        /// Size of the containing parent, if any.
        containing_parent_size: Option<usize>,
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
    /// Route Y R1 A6 AF3 AF2 AF1 (P2): a `TransformPreimageBinding` carries two
    /// identity sources (the legacy field tuple AND `identity: FullCaptureIdentity`).
    /// Any overlapping legacy field that disagrees with `identity` is a
    /// self-contradictory binding and fails closed before it can resolve anything.
    BindingIdentityInconsistent {
        child_old_base: u64,
        child_kind: RawChildKind,
        field: String,
        legacy: String,
        identity: String,
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
    /// Never constructed by the current pipeline (drift always fails closed via
    /// `RawCaptureDrift` error); kept as part of the capture-drift schema
    /// contract serialized by `snapshot_manifest`.
    #[allow(dead_code)]
    TransformPreimageDrift,
    /// A strict extent (ObservedAllocation/BackingObject/Container) had full-range
    /// drift; fail-closed.
    /// Never constructed by the current pipeline; kept for the same schema
    /// contract (diagnostic resolution labels).
    #[allow(dead_code)]
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
                raw_child_excerpt,
                raw_slab_slice_excerpt,
            } => write!(
                f,
                "raw capture drift: kind={} child {:#x} size {:#x} slab [{:#x},+{:#x}) offset {:#x} \
                 first_mismatch={:#x} raw_child_sha={} raw_slab_slice_sha={} \
                 raw_child_excerpt=[{}] raw_slab_slice_excerpt=[{}]",
                child_kind.label(),
                child_old_base,
                child_size,
                slab_old_base,
                slab_size,
                slab_offset,
                first_mismatch_offset,
                raw_child_digest,
                raw_slab_slice_digest,
                raw_child_excerpt,
                raw_slab_slice_excerpt
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
            OverlayError::BindingIdentityInconsistent {
                child_old_base,
                child_kind,
                field,
                legacy,
                identity,
            } => write!(
                f,
                "binding identity inconsistent: kind={} child={child_old_base:#x} \
                 field={field} legacy={legacy} identity={identity}",
                child_kind.label()
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
                child_capture_id,
                child_capture_path,
                source_root_rva,
                source_slot_offset,
                probe_requested_size,
                was_interior,
                containing_parent_old_base,
                containing_parent_size,
            } => {
                let root_rva = source_root_rva.map(|v| format!("{v:#x}"));
                let slot_off = source_slot_offset.map(|v| format!("{v:#x}"));
                let parent_base = containing_parent_old_base.map(|v| format!("{v:#x}"));
                let parent_size = containing_parent_size.map(|v| format!("{v:#x}"));
                write!(
                    f,
                    "probe/interior {child_kind:?} 0x{child_base:x},+{child_size:#x} extent={extent_kind} \
                     not covered by any authoritative slab (candidate_slab_count={candidate_slab_count}, \
                     nearest_authority={nearest_authority:?} gap={nearest_authority_gap:#x}); \
                     producer provenance: capture_id={child_capture_id:?} capture_path={child_capture_path:?} \
                     source_root_rva={root_rva:?} source_slot_offset={slot_off:?} \
                     probe_requested_size={probe_requested_size:#x} was_interior={was_interior} \
                     containing_parent_old_base={parent_base:?} \
                     containing_parent_size={parent_size:?}; \
                     refusing to treat a heuristic read window as a heap extent",
                )
            }
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
            // Route Y R1 A6 AF3: GscriptLabelTableEntry is the truthful label-table
            // source path admitted by the exhaust emitter (was MainSlot). Extents:
            // InteriorSubview when the label was captured interior to a parent;
            // ProbeWindow when no parent evidence (never protected).
            CP::GscriptLabelTableEntry => {
                matches!(ext, CEK::ProbeWindow | CEK::InteriorSubview)
            }
            CP::GscriptChildLink | CP::GscriptFirstHop => {
                matches!(ext, CEK::ProbeWindow | CEK::InteriorSubview)
            }
            CP::StringBufferChild => ext == CEK::ProbeWindow,
            CP::SplitSibling => ext == CEK::ProbeWindow && cap_prefix == "split_sibling",
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

/// MIDA-SERIAL-34/35: build parent-closure authoritative-slab candidates from
/// STRICT parent evidence before normalization.
///
/// MIDA-SERIAL-35 (P1-1): consumes the production `pre_trunc_authority` evidence
/// (FULL pre-trunc parent bytes recorded by split_swallowed_siblings before
/// truncation) so a split child whose strict parent was truncated can still
/// produce a closure authority built from the REAL pre-trunc bytes — never from
/// the truncated parent in the final heap_globals, never re-read, never guessed.
///
/// Replaces MIDA-SERIAL-33's `build_authority_closure` (which pushed finished
/// slabs directly into `authoritative_slabs` AFTER normalization). Every closure
/// candidate produced here is returned with the static role
/// `"parent_closure"` and enters the SAME `normalize_authoritative_slabs`
/// pipeline as main/dedicated candidates — normalization then decides keep /
/// dedup / contained-exact-alias / conflict, and the authoritative set is never
/// mutated after normalization.
///
/// Evidence rules (fail-closed — each rule violation just skips the child, the
/// coverage gate stays authoritative):
/// 1. child extent is ProbeWindow or InteriorSubview;
/// 2. child range uses checked_add and is fully valid;
/// 3. containing_parent_old_base/size both exist (from the split producer's
///    pre-trunc evidence or the label-table emitter);
/// 4. parent range uses checked_add;
/// 5. parent fully contains child;
/// 6. exactly one parent identity matches;
/// 7. parent extent is ObservedAllocation or BackingObject;
/// 8. parent provenance is not SyntheticDerived;
/// 9. parent slice at child offset is byte-identical to child bytes;
/// 10. parent boundary comes from producer-recorded evidence (the fields are
///     the evidence — never guessed from read_memory, density, nearest slab).
///
/// Dedup / conflict rules for multiple children referencing the same parent:
/// - same (base,size,bytes,parent-identity): ONE logical closure candidate
///   (deduplicated here by key before returning);
/// - different bytes / boundary / identity on the same parent: returned as a
///   conflict (or left for normalization to fail-closed).
///
/// The empty-set rule: closure candidates are derived from heap_globals ALONE;
/// `existing_slabs` is consulted only to skip candidates already covered (never
/// to gate the whole derivation on non-emptiness).
pub fn build_authority_closure_candidates(
    heap_globals: &[HeapGlobalSnapshot],
    existing_slabs: &[HeapSlab],
    pre_trunc_authority: &PreTruncParentAuthorityStore,
) -> Result<Vec<AuthoritativeSlabCandidate>, OverlayError> {
    use super::heap_global_snapshot::CaptureExtentKind as CEK;
    use super::heap_global_snapshot::CapturePath as CP;

    // MIDA-SERIAL-35: covered_by_existing uses checked_add for the existing
    // slab end — an overflowing slab can never be treated as covering a parent.
    let covered_by_existing = |base: u64, size: usize| -> bool {
        let Some(end) = base.checked_add(size as u64) else {
            return false;
        };
        existing_slabs.iter().any(|s| {
            if s.content.is_empty() || s.old_base == 0 {
                return false;
            }
            let Some(s_end) = s.old_base.checked_add(s.content.len() as u64) else {
                return false; // overflowing existing slab cannot cover anything
            };
            base >= s.old_base && end <= s_end
        })
    };

    // key: (parent_base, parent_size, parent_capture_id) -> candidate
    // Multiple children proving the SAME parent collapse into ONE candidate.
    let mut by_parent: std::collections::BTreeMap<
        (u64, usize, String),
        AuthoritativeSlabCandidate,
    > = std::collections::BTreeMap::new();
    // Track candidate slab DIGESTS per key so same key + different bytes is a
    // conflict (never silent last-write-wins). A digest map holds no full byte
    // copies — the candidate's HeapSlab owns the only Vec<u8> per unique key.
    let mut bytes_by_key: std::collections::BTreeMap<(u64, usize, String), [u8; 32]> =
        std::collections::BTreeMap::new();

    // MIDA-SERIAL-35 (P1-1): helper to register ONE closure candidate from a
    // parent (base, size, full bytes, identity). Multiple children proving the
    // same parent collapse; same key + different bytes is a conflict.
    //
    // MIDA-SERIAL-38/39: takes the Arc<[u8]> (shared byte storage). The
    // candidate HeapSlab materializes the Arc into a Vec<u8> exactly once per
    // unique key. Conflict detection is STRICT byte equality: the digest map is
    // only a fast prefilter — a same-digest hit still compares the full bytes
    // of the existing candidate.slab.content against the incoming Arc (never
    // relying on hash equality to prove byte equality).
    fn register_candidate(
        by_parent: &mut std::collections::BTreeMap<
            (u64, usize, String),
            AuthoritativeSlabCandidate,
        >,
        bytes_by_key: &mut std::collections::BTreeMap<(u64, usize, String), [u8; 32]>,
        p_base: u64,
        p_size: usize,
        p_arc: std::sync::Arc<[u8]>,
        p_capture_id: &str,
    ) -> Result<(), OverlayError> {
        use sha2::Digest as _;
        let key = (p_base, p_size, p_capture_id.to_string());
        let digest = {
            let mut h = sha2::Sha256::new();
            h.update(p_arc.as_ref());
            h.finalize().into()
        };
        match bytes_by_key.get(&key) {
            Some(existing_digest) if *existing_digest == digest => {
                // Digest matches — now STRICT byte equality against the
                // existing candidate (no second full Vec; compare in place).
                if let Some(existing) = by_parent.get(&key) {
                    if existing.slab.content.as_slice() != p_arc.as_ref() {
                        return Err(OverlayError::AuthoritativeSlabConflict {
                            a_old_base: p_base,
                            a_size: p_size,
                            b_old_base: p_base,
                            b_size: p_size,
                            relationship: "parent_closure_byte_conflict",
                            mismatch_offset: None,
                        });
                    }
                }
                // Already produced with identical bytes; skip.
            }
            Some(_) => {
                // Digest differs -> bytes necessarily differ -> conflict.
                return Err(OverlayError::AuthoritativeSlabConflict {
                    a_old_base: p_base,
                    a_size: p_size,
                    b_old_base: p_base,
                    b_size: p_size,
                    relationship: "parent_closure_byte_conflict",
                    mismatch_offset: None,
                });
            }
            None => {
                bytes_by_key.insert(key.clone(), digest);
                by_parent.insert(
                    key,
                    AuthoritativeSlabCandidate {
                        slab: HeapSlab {
                            old_base: p_base,
                            content: p_arc.to_vec(),
                        },
                        role: "parent_closure",
                    },
                );
            }
        }
        Ok(())
    }

    // ---- Path A (MIDA-SERIAL-35/37/38): PRE-TRUNC parent authority evidence ----
    // Consumed FIRST so the real pre-trunc bytes flow into the closure even
    // when the parent has since been truncated in heap_globals. This is the
    // ONLY path that can build an authority for a split child whose strict
    // parent was truncated by split_swallowed_siblings.
    //
    // MIDA-SERIAL-38: bindings are aggregated by parent_key FIRST. Each unique
    // parent key resolves and builds its closure candidate exactly ONCE (the
    // shared Arc<[u8]> is cloned, not the bytes). Multiple children of the same
    // parent never trigger per-binding Vec<u8> copies.
    let mut bindings_by_key: std::collections::BTreeMap<
        &PreTruncParentAuthorityKey,
        Vec<&PreTruncParentAuthorityEvidence>,
    > = std::collections::BTreeMap::new();
    for ev in pre_trunc_authority.bindings() {
        bindings_by_key.entry(&ev.parent_key).or_default().push(ev);
    }
    for (parent_key, evs) in bindings_by_key.iter() {
        // Parent metadata from the store row (extent/provenance/path) — all
        // bindings of the same key share the same row by construction.
        let Some((parent_extent, parent_provenance, parent_capture_path)) =
            pre_trunc_authority.parent_meta(parent_key)
        else {
            continue; // key never recorded -> fail-closed
        };
        // Parent must be a proven allocation (never heuristic/synthetic).
        if !matches!(parent_extent, CEK::ObservedAllocation | CEK::BackingObject) {
            continue;
        }
        if matches!(parent_provenance, RegionProvenance::SyntheticDerived { .. }) {
            continue;
        }
        if parent_capture_path == CP::DanglingEdge {
            continue;
        }
        // MIDA-SERIAL-38: resolve the shared bytes ONCE per key (Arc clone, no
        // byte copy). A key whose parent was never recorded is fail-closed.
        let Some(parent_arc) = pre_trunc_authority.lookup_arc(parent_key) else {
            continue;
        };
        let parent_full_bytes = parent_arc.as_ref();
        let parent_old_base = parent_key.parent_old_base;
        let parent_pre_trunc_size = parent_key.parent_pre_trunc_size;
        let parent_capture_id = &parent_key.parent_capture_id;
        // MIDA-SERIAL-36: the declared pre-trunc size MUST equal the stored
        // full bytes length (size equality enforced).
        if parent_pre_trunc_size == 0
            || parent_full_bytes.is_empty()
            || parent_pre_trunc_size != parent_full_bytes.len()
        {
            continue;
        }
        // Parent range must be fully valid (checked_add; no saturating).
        let Some(parent_end) = parent_old_base.checked_add(parent_pre_trunc_size as u64) else {
            continue;
        };
        // Every binding of this key must fully validate (child containment,
        // byte-match, size equality, coverage skip); if ANY fails, the whole
        // key contributes no candidate (fail-closed, order-independent).
        let mut key_ok = true;
        for ev in evs.iter() {
            // Parent must fully contain the child (checked arithmetic).
            let Some(child_end) = ev.child_base.checked_add(ev.child_size as u64) else {
                key_ok = false;
                break;
            };
            if ev.child_base < parent_old_base || child_end > parent_end {
                key_ok = false;
                break;
            }
            // The child snapshot in the final set must exist AND its content
            // length must equal the recorded child_size.
            let Some(child) = heap_globals
                .iter()
                .find(|g| g.is_raw_coherence_participant() && g.live_ptr == ev.child_base)
            else {
                key_ok = false;
                break;
            };
            if child.content.len() != ev.child_size {
                key_ok = false;
                break;
            }
            // Pre-trunc parent slice at the child offset must byte-match the
            // child (checked slice; overflow/range failure -> fail-closed).
            let child_bytes = child.content.as_slice();
            let off = (ev.child_base - parent_old_base) as usize;
            let Some(slice_end) = off.checked_add(ev.child_size) else {
                key_ok = false;
                break;
            };
            let Some(parent_slice) = parent_full_bytes.get(off..slice_end) else {
                key_ok = false;
                break;
            };
            if parent_slice != child_bytes {
                key_ok = false;
                break;
            }
        }
        if !key_ok {
            continue; // any child of this parent failed -> no candidate
        }
        if covered_by_existing(parent_old_base, parent_pre_trunc_size) {
            continue; // parent already has authority; do not duplicate
        }
        // Build ONCE per key: the Arc is cloned (no byte copy) into the
        // candidate slab content.
        register_candidate(
            &mut by_parent,
            &mut bytes_by_key,
            parent_old_base,
            parent_pre_trunc_size,
            parent_arc,
            parent_capture_id,
        )?;
    }

    // ---- Path B: heap_globals containing-parent evidence ----
    // For children whose parent was NOT truncated (label-table / first-hop
    // interior children), the existing lookup against the FINAL heap_globals is
    // correct because the parent is still present at its full size.
    for child in heap_globals {
        if !child.is_raw_coherence_participant() {
            continue;
        }
        let is_probe = matches!(child.extent_kind, CEK::ProbeWindow | CEK::InteriorSubview);
        if !is_probe {
            // ObservedAllocation / BackingObject children already carry their own
            // authoritative boundary (or a dedicated slab). Do not synthesize a
            // duplicate authority here.
            continue;
        }

        // Rule 2: child range must be fully valid (checked_add).
        let Some(child_end) = child.live_ptr.checked_add(child.content.len() as u64) else {
            continue;
        };
        if child.content.is_empty() {
            continue;
        }

        // Rule 3: parent evidence present (non-split producer paths).
        let (Some(p_base), Some(p_size)) = (
            child.extent_evidence.containing_parent_old_base,
            child.extent_evidence.containing_parent_size,
        ) else {
            continue;
        };

        // Rule 4: parent range must be fully valid.
        let Some(parent_end) = p_base.checked_add(p_size as u64) else {
            continue;
        };
        if p_size == 0 {
            continue;
        }

        // Rule 5: parent fully contains child.
        if child.live_ptr < p_base || child_end > parent_end {
            continue;
        }

        // Rule 6: exactly one parent identity matches at (p_base, p_size).
        let matches: Vec<&HeapGlobalSnapshot> = heap_globals
            .iter()
            .filter(|p| {
                p.is_raw_coherence_participant()
                    && p.live_ptr == p_base
                    && p.content.len() == p_size
            })
            .collect();
        if matches.len() != 1 {
            continue; // ambiguous / no parent -> fail-closed downstream
        }
        let parent = matches[0];

        // Rules 7-8: parent extent is a PROVEN allocation, provenance not
        // synthetic, and the parent is not a dangling-edge (which gets its own
        // dedicated slab — a closure candidate would duplicate it).
        if !matches!(
            parent.extent_kind,
            CEK::ObservedAllocation | CEK::BackingObject
        ) {
            continue;
        }
        if matches!(parent.provenance, RegionProvenance::SyntheticDerived { .. }) {
            continue;
        }
        if parent.extent_evidence.capture_path == CP::DanglingEdge {
            continue;
        }

        // Rule 9: parent slice at child offset must be byte-identical to child
        // bytes (checked bounds — never a panicking slice).
        let off = (child.live_ptr - p_base) as usize;
        let child_bytes = &child.content;
        let Some(parent_slice) = parent.content.get(off..off + child_bytes.len()) else {
            continue; // child escapes the parent bytes (cannot be byte-proven)
        };
        if parent_slice != child_bytes.as_slice() {
            // Different bytes on the same parent -> conflict evidence. This is
            // not a silent skip: the child is a probe whose parent content
            // differs from its own bytes; the coverage gate fails closed.
            continue;
        }

        // Rule 10: the parent boundary is producer-recorded evidence (the
        // containing_parent fields themselves), never guessed.
        // Already satisfied by construction.

        if covered_by_existing(p_base, p_size) {
            continue; // parent already has authority; do not duplicate
        }
        register_candidate(
            &mut by_parent,
            &mut bytes_by_key,
            p_base,
            p_size,
            std::sync::Arc::from(parent.content.as_slice()),
            &parent.extent_evidence.capture_id,
        )?;
    }

    let mut out: Vec<AuthoritativeSlabCandidate> = by_parent.into_values().collect();
    // Deterministic order by (base, size, capture id).
    out.sort_by(|a, b| {
        (a.slab.old_base, a.slab.content.len()).cmp(&(b.slab.old_base, b.slab.content.len()))
    });
    Ok(out)
}

/// MIDA-SERIAL-35 (P1-3): verify the authoritative/patched/manifest bijection.
///
/// Returns an error describing the FIRST drift found:
/// - cardinality mismatch between the normalization ledger, the raw
///   authoritative slab set, and the patched (overlaid) slab set;
/// - base mismatch at the same index;
/// - size mismatch at the same index.
///
/// When a raw capture was NOT established, the caller must pass an empty
/// authoritative/patched/ledger triple (the no-raw/no-overlay manifest
/// behavior) — this function then trivially succeeds.
pub(crate) fn validate_slab_bijection(
    ledger: &[(u64, &'static str, SlabNormalization)],
    raw_slabs: &[HeapSlab],
    patched_slabs: &[HeapSlab],
) -> Result<(), String> {
    if raw_slabs.len() != ledger.len() || patched_slabs.len() != raw_slabs.len() {
        return Err(format!(
            "manifest bijection drift: ledger={} raw={} patched={}",
            ledger.len(),
            raw_slabs.len(),
            patched_slabs.len()
        ));
    }
    for (i, (((base, _role, _norm), raw_s), patched_s)) in ledger
        .iter()
        .zip(raw_slabs.iter())
        .zip(patched_slabs.iter())
        .enumerate()
    {
        if *base != raw_s.old_base || *base != patched_s.old_base {
            return Err(format!(
                "manifest bijection base mismatch at index {i}: ledger={base:#x} raw={:#x} patched={:#x}",
                raw_s.old_base, patched_s.old_base
            ));
        }
        if raw_s.content.len() != patched_s.content.len() {
            return Err(format!(
                "manifest bijection size mismatch at index {i}: raw={} patched={}",
                raw_s.content.len(),
                patched_s.content.len()
            ));
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
    // MIDA-SERIAL-35: an overflowing slab end (checked_add fails) is NOT a
    // covering authority — it is excluded from the range set so a wrapping slab
    // can never satisfy coverage.
    let slab_ranges: Vec<(u64, u64)> = heap_slabs
        .iter()
        .filter(|s| !s.content.is_empty() && s.old_base != 0)
        .filter_map(|s| {
            s.old_base
                .checked_add(s.content.len() as u64)
                .map(|end| (s.old_base, end))
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
                child_capture_id: g.extent_evidence.capture_id.clone(),
                child_capture_path: format!("{:?}", g.extent_evidence.capture_path),
                source_root_rva: g.extent_evidence.source_root_rva,
                source_slot_offset: g.extent_evidence.source_slot_offset,
                probe_requested_size: g.extent_evidence.probe_requested_size,
                was_interior: g.extent_evidence.was_interior,
                containing_parent_old_base: g.extent_evidence.containing_parent_old_base,
                containing_parent_size: g.extent_evidence.containing_parent_size,
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
            child_capture_id: g.extent_evidence.capture_id.clone(),
            child_capture_path: format!("{:?}", g.extent_evidence.capture_path),
            source_root_rva: g.extent_evidence.source_root_rva,
            source_slot_offset: g.extent_evidence.source_slot_offset,
            probe_requested_size: g.extent_evidence.probe_requested_size,
            was_interior: g.extent_evidence.was_interior,
            containing_parent_old_base: g.extent_evidence.containing_parent_old_base,
            containing_parent_size: g.extent_evidence.containing_parent_size,
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
            source_slot_offset: None,
            requested_probe_size: 0,
            source_root_rva: None,
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
            source_slot_offset: g.extent_evidence.source_slot_offset,
            requested_probe_size: g.extent_evidence.probe_requested_size,
            source_root_rva: g.extent_evidence.source_root_rva,
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
        let raw = find_raw_child(raw_capture, &FullCaptureIdentity::from_container(container))?;
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
        bindings.push(TransformPreimageBinding::new(
            FullCaptureIdentity::from_raw_child(raw),
            slab_old_base,
            slab_size,
            slab_digest,
            slab_offset,
            TransformPreimageBasis::ChildCapture,
            sha256_hex(current),
            sha256_hex(slab_slice),
            sha256_hex(current),
            false,
        ));
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
        // Route Y R1 A6 AF3 AF2 AF1 (P1-2): seeding resolves the raw child by the
        // transformed snapshot's COMPLETE identity (never partial / first-match),
        // before any byte or slab comparison.
        let raw = find_raw_child(raw_capture, &FullCaptureIdentity::from_heap_global(global))?;
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
        bindings.push(TransformPreimageBinding::new(
            FullCaptureIdentity::from_raw_child(raw),
            slab_old_base,
            slab_size,
            slab_digest,
            slab_offset,
            basis,
            sha256_hex(&raw.raw_bytes),
            sha256_hex(slab_slice),
            sha256_hex(&global.content),
            matches!(basis, TransformPreimageBasis::AuthoritativeSlabSlice),
        ));
    }

    bindings.sort_by_key(|b| (b.child_old_base, b.child_kind, b.slab_offset));
    Ok(bindings)
}

/// Resolve the raw child for a transformed snapshot by its COMPLETE
/// `FullCaptureIdentity` — never by a partial tuple, never by raw bytes, never by
/// first-match.
///
/// Route Y R1 A6 AF3 AF2 AF1 (P1-2): the resolution requires EXACTLY ONE raw
/// child whose full identity equals the transformed identity. 0 or >1 matches
/// fail closed (`RawChildMissing` / ambiguous). An empty `capture_id` is NOT a
/// wildcard — it is compared structurally like every other field. Identity is
/// resolved BEFORE any byte/digest comparison; the caller performs the raw-byte
/// vs current-byte check only after the unique identity is chosen.
fn find_raw_child<'a>(
    raw_capture: &'a RawSlabCapture,
    identity: &FullCaptureIdentity,
) -> Result<&'a RawChild, OverlayError> {
    let matches: Vec<&RawChild> = raw_capture
        .children
        .iter()
        .filter(|child| raw_identity_matches_transformed(child, identity, false))
        .collect();
    match matches.as_slice() {
        [single] => Ok(*single),
        [] => Err(OverlayError::RawChildMissing {
            child_old_base: identity.old_base,
            child_kind: identity.kind,
        }),
        _ => Err(OverlayError::RawChildMissing {
            child_old_base: identity.old_base,
            child_kind: identity.kind,
        }),
    }
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

/// Route Z R0 AF1: build a bounded hex excerpt around the first mismatch so a
/// live raw-capture drift is diagnosable offline (distinguishing in-place
/// rewrite / free-reuse / wrong read) without dumping the whole heap object.
///
/// Window: up to `PREFIX` bytes before the mismatch offset, then up to `SPAN`
/// bytes starting at the mismatch. Never exceeds the given byte slice.
pub fn drift_excerpt(
    slice: &[u8],
    mismatch_offset: usize,
    max_prefix: usize,
    max_span: usize,
) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let prefix_start = mismatch_offset.saturating_sub(max_prefix);
    let span_end = mismatch_offset.saturating_add(max_span).min(slice.len());
    let mut out = String::with_capacity(2 * (span_end - prefix_start) + 1);
    let mut first = true;
    for &b in &slice[prefix_start..span_end] {
        if !first {
            out.push(' ');
        }
        first = false;
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
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
    // Route Z R0 AF1: bounded diagnostic excerpt (≤16 bytes before, ≤64 after).
    let raw_child_excerpt = drift_excerpt(raw_child, first_mismatch_offset, 16, 64);
    let raw_slab_slice_excerpt = drift_excerpt(slab_slice, first_mismatch_offset, 16, 64);
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
        raw_child_excerpt,
        raw_slab_slice_excerpt,
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
/// Legacy single-slab path superseded by `build_patched_backing_slab_q0c`;
/// retained for API compatibility / round documentation.
#[allow(dead_code)]
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
            child_capture_id: String::new(),
            child_capture_path: String::new(),
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
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
                raw_child_excerpt: drift_excerpt(
                    raw_child_bytes,
                    raw_child_bytes.len().min(child_size),
                    16,
                    64,
                ),
                raw_slab_slice_excerpt: drift_excerpt(
                    &slab.content[slab_offset_us..child_end],
                    raw_child_bytes.len().min(child_size),
                    16,
                    64,
                ),
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
                    raw_child_excerpt: drift_excerpt(raw_child_bytes, first_mismatch, 16, 64),
                    raw_slab_slice_excerpt: drift_excerpt(raw_slab_slice, first_mismatch, 16, 64),
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
            let flush = |start: usize, end: usize, drift_runs: &mut Vec<CaptureDriftRun>| {
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
    // Route Y R1 A6 AF3 AF2 (P1-4): each entry carries the FULL capture identity
    // (`FullCaptureIdentity`) so the overlay resolves the exact raw child by the
    // complete identity — never by raw-byte/slab coherence or a partial 3-field
    // tuple.
    let mut transformed: Vec<TransformedChild> = Vec::new();
    for g in transformed_globals {
        if !g.is_raw_coherence_participant() {
            continue;
        }
        transformed.push(TransformedChild {
            identity: FullCaptureIdentity::from_heap_global(g),
            bytes: g.content.clone(),
            provenance: g.provenance.clone(),
            transform_ids: g.transform_ids.clone(),
            rva: g.rva,
        });
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
        transformed.push(TransformedChild {
            identity: FullCaptureIdentity::from_container(c),
            bytes: content,
            provenance: RegionProvenance::RawCaptured {
                raw_digest: String::new(),
            },
            transform_ids: Vec::new(),
            rva: 0,
        });
    }
    // Deterministic order by (old_base, kind).
    transformed.sort_by_key(|t| (t.identity.old_base, t.identity.kind as u8));

    // ---- Route Y R1 A6 AF3 AF2 AF1 AF1 AF1 AF1 (Task 1/2): IDENTITY PRE-RESOLUTION
    // ---- phase (three-stage: unique declaration candidate, raw identity,
    // ---- then declared-reinit qualification). Resolve the unique raw child for
    // ---- every transformed child BEFORE any ledger-shape / run-membership /
    // ---- binding / slab / byte / overlay decision.
    //
    //   - SyntheticDerived: a LEGAL provenance with no raw preimage — skipped here
    //     (handled by the synthetic overlay path); never resolved to a raw child.
    //   - UnknownSynthetic: FAILS CLOSED HERE as RawChildMissing — before any
    //     ledger/binding/slab decision. It must never be silently skipped nor
    //     converted to SyntheticDerived nor given a raw fallback.
    //   - Ordinary / declared: resolve by full identity. For a DECLARED size
    //     reinit only `size` is ignored to find the candidate, then the
    //     declaration itself is qualified (old-size tolerance, new-size exact,
    //     zero-fill, rva, capture id) BEFORE any later gate.
    //
    // Error precedence (locked, per task 2):
    //   0. declaration candidate AMBIGUITY (0/1 rule violated) -> TransformRunLedgerInvalid
    //      with an `ambiguous declared size reinit` reason — a declaration-evidence
    //      error reported BEFORE any raw-identity decision; never coerced to ordinary.
    //   1. unique declaration then no unique raw identity (0 or >1) -> RawChildMissing
    //   2. unique declaration + unique identity but invalid declaration  -> TransformRunLedgerInvalid
    //   3. identity + declaration valid then any ledger/binding/slab error.
    let mut identity_plan: Vec<ResolvedQ0cChild> = Vec::new();
    for (ti, tc) in transformed.iter().enumerate() {
        if matches!(tc.provenance, RegionProvenance::SyntheticDerived { .. }) {
            // Legal bypass: no raw preimage; handled by the synthetic overlay path.
            continue;
        }
        if matches!(tc.provenance, RegionProvenance::UnknownSynthetic) {
            // UnknownSynthetic must fail closed IMMEDIATELY at pre-resolution,
            // before ledger-shape / membership / binding consistency.
            return Err(OverlayError::RawChildMissing {
                child_old_base: tc.identity.old_base,
                child_kind: tc.identity.kind,
            });
        }
        // Phase A — candidate declaration identification. The UNIQUE declared
        // size-reinit resolver (AF3 AF2 AF1 AF1 AF1 AF1 Task 1) counts every
        // transform-id hit; 0 hits -> ordinary (exact-identity lookup), exactly 1
        // -> declared reinit (identity-ignore-size lookup), more than 1 ->
        // fail-closed TransformRunLedgerInvalid with an `ambiguous declared size
        // reinit` reason. This MUST run BEFORE raw full-identity resolution, so a
        // declaration ambiguity is reported ahead of any raw-identity decision and
        // is never silently coerced into an ordinary child.
        let spec = resolve_declared_size_reinit_spec(
            &tc.transform_ids,
            tc.rva,
            &tc.identity.capture_id,
            tc.identity.old_base,
            tc.bytes.len(),
        )?;
        let declared_reinit = spec.is_some();
        let raw_match: Vec<(usize, &RawChild)> = raw_capture
            .children
            .iter()
            .enumerate()
            .filter(|(_, c)| raw_identity_matches_transformed(c, &tc.identity, declared_reinit))
            .collect();
        let (ri, raw) = match raw_match.as_slice() {
            [(ri, raw)] => (*ri, *raw),
            _ => {
                return Err(OverlayError::RawChildMissing {
                    child_old_base: tc.identity.old_base,
                    child_kind: tc.identity.kind,
                });
            }
        };
        // Phase B — declared-reinit qualification: before any later gate, prove the
        // actual transition satisfies the declaration (raw old size within
        // tolerance, transformed new size exact, zero-filled, rva, capture id).
        let mode = match spec {
            Some(spec) => {
                validate_declared_size_reinit_fields(
                    spec,
                    raw.size,
                    tc.rva,
                    &tc.identity.capture_id,
                    tc.identity.old_base,
                    &tc.bytes,
                    0,
                )?;
                ResolvedQ0cMode::DeclaredSizeReinit { spec }
            }
            None => ResolvedQ0cMode::Ordinary,
        };
        identity_plan.push(ResolvedQ0cChild {
            transformed_index: ti,
            raw_index: ri,
            mode,
        });
    }

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
    // Route Y R1 A6 AF3 AF2 AF1 (P2): every binding must be self-consistent
    // (legacy field tuple == identity) BEFORE any binding is used to resolve or
    // overlay anything. A contradictory binding fails closed here.
    for b in bindings {
        b.validate_identity_consistency()?;
    }

    for (tc_idx, tc) in transformed.iter().enumerate() {
        let child_base = tc.identity.old_base;
        let mut child_size = tc.identity.size;
        let kind = tc.identity.kind;
        let transformed_bytes = tc.bytes.clone();
        let child_transform_ids = tc.transform_ids.clone();
        let extent_kind = tc.identity.extent_kind;
        let capture_id = tc.identity.capture_id.clone();
        let child_rva = tc.rva;
        let child_identity = &tc.identity;

        if let RegionProvenance::UnknownSynthetic = &tc.provenance {
            return Err(OverlayError::RawChildMissing {
                child_old_base: child_base,
                child_kind: kind,
            });
        }
        if let RegionProvenance::SyntheticDerived {
            transform_id,
            source_anchor,
            construction_digest,
        } = &tc.provenance
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

        // Route Y R1 A6 AF3 AF2 AF1 AF1 (P1-1/P1-4): the raw child was already
        // resolved in the IDENTITY PRE-RESOLUTION phase (by the complete full
        // identity, before any ledger/binding/slab/byte decision). Consume the
        // typed plan here — NEVER re-lookup by partial identity, and use the
        // plan's already-qualified declaration spec (never re-select via
        // transform-id first-match).
        let plan_entry = identity_plan
            .iter()
            .find(|r| r.transformed_index == tc_idx)
            .expect("every non-synthetic transformed child has an identity-plan entry");
        let raw = &raw_capture.children[plan_entry.raw_index];
        let (declared_reinit, plan_spec) = match &plan_entry.mode {
            ResolvedQ0cMode::Ordinary => (false, None),
            ResolvedQ0cMode::DeclaredSizeReinit { spec } => (true, Some(*spec)),
        };
        if declared_reinit {
            // The declared reinit's raw old size is the preimage the transform
            // shrank from; the transformed (new) bytes are written after.
            child_size = raw.size;
        }
        // TAF1-B / TAF1-C: resolve the child's unique covering slab from the full
        // multi-slab set (0 or >1 covering slabs fail closed; never defaults to a
        // single raw_capture.slab). Runs only AFTER the unique full-identity raw
        // child is resolved.
        let (si, slab_old_base, slab_size, slab_offset_us, slab_bytes) =
            covering_slab_for_child(raw_capture, child_base, child_size, kind)?;
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
                raw_child_excerpt: drift_excerpt(
                    raw_child_bytes,
                    raw_child_bytes.len().min(child_size),
                    16,
                    64,
                ),
                raw_slab_slice_excerpt: drift_excerpt(
                    &slab_bytes[slab_offset_us..child_end],
                    raw_child_bytes.len().min(child_size),
                    16,
                    64,
                ),
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
                    // size must match the transformed child size (for a DECLARED
                    // size reinit, size changes legitimately, so it is excluded).
                    && (declared_reinit || b.child_size == child_size)
                    // extent must match the transformed child's extent.
                    && b.extent_kind == extent_kind
                    // Route Y R1 A6 AF3 AF2 (P1-5): the binding must carry the
                    // COMPLETE capture identity equal to the transformed identity
                    // AND the resolved raw child identity (size excluded ONLY for
                    // a declared size reinit). A binding that shares
                    // capture_id/base/size/extent but differs on any source-evidence
                    // field (source root / slot / probe / was_interior / containing
                    // parent) fails closed — it cannot bind a different object.
                    && identity_matches_binding(child_identity, &b.identity, declared_reinit)
                    && identity_matches_raw_child(&b.identity, raw, declared_reinit)
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
                raw_child_excerpt: drift_excerpt(raw_child_bytes, 0, 16, 64),
                raw_slab_slice_excerpt: drift_excerpt(raw_slab_slice, 0, 16, 64),
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
                raw_child_excerpt: drift_excerpt(raw_child_bytes, 0, 16, 64),
                raw_slab_slice_excerpt: drift_excerpt(raw_slab_slice, 0, 16, 64),
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
                        raw_child_excerpt: drift_excerpt(raw_child_bytes, first_mismatch, 16, 64),
                        raw_slab_slice_excerpt: drift_excerpt(
                            raw_slab_slice,
                            first_mismatch,
                            16,
                            64,
                        ),
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
            // size; never `max(raw.size)` over an ambiguous multi-child set. The
            // spec is the ONE already qualified in the identity pre-resolution
            // phase (plan.mode) — never re-selected here by transform-id
            // first-match.
            let spec = plan_spec.expect("declared_reinit implies a plan-qualified declaration");
            let raw_old_size = raw.size;
            // Defensive re-validation at the consumption boundary uses the SAME
            // plan spec (identical declaration), so the overlay cannot accept an
            // old/new size, RVA, or zero-fill the pre-resolution rejected.
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
                let Some(end) = off.checked_add(len) else {
                    return Err(OverlayError::TransformRunLedgerInvalid {
                        run_index: ri,
                        child_capture_id: r.child_capture_id.clone(),
                        child_old_base: child_base,
                        child_size: r.child_size,
                        child_offset: off,
                        length: len,
                        transform_id: r.transform_id.clone(),
                        reason: format!("prior run length overflow for old_base {:#x}", child_base),
                    });
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
            let flush = |start: usize, end: usize, drift_runs: &mut Vec<CaptureDriftRun>| {
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
            .find(|otc| {
                let ob = otc.identity.old_base;
                let osz = otc.identity.size;
                let ok = otc.identity.kind;
                !(ok == kind && ob == child_base)
                    && ob <= child_base
                    && child_base + child_size as u64 <= ob.saturating_add(osz as u64)
            })
            .map(|otc| otc.identity.old_base);
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
#[path = "raw_slab_coherence_tests.rs"]
mod raw_slab_coherence_tests;
