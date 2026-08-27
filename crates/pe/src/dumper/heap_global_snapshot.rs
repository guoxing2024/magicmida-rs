//! Snapshot process-local heap objects referenced from zero-raw writable image

//!
//! Production `.unwrap()`s are invariants: `min()` runs only after a
//! `parents.is_empty()` early return (WO-10). Test unwraps are assertions.
#![allow(clippy::unwrap_used)]
//! slots (typically `.fill` gaps left by removed Themida sections).
//!
//! These slots are not SecurityCookie-encoded triples: they hold plain heap
//! pointers. Early overlay / pointer scrub zeros them, and zero-raw sections
//! never reach the on-disk PE, so the dumped process restarts with NULL and
//! AVs on the first dereference (e.g. `mov rax,[0x18a898]; mov rcx,[rax+58h]`).
//!
//! Detection is primarily **code-xref driven**: RIP-relative targets of
//! loads/stores in executable sections. A secondary scan of preferred
//! zero-raw / `.fill` ranges picks up hot slots the linear disasm miss.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::header::PeHeader;

use super::capture_policy::DumpCapturePolicy;
use super::helpers::{alloc_capped, MAX_HEAP_CONTAINER_BYTES};

const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const MIN_USER_POINTER: u64 = 0x1_0000;
/// Full canonical user-mode ceiling (x64 Windows). Do NOT cap at 4 GiB —
/// modern heaps routinely live above `0x1_0000_0000`.
const MAX_USER_POINTER: u64 = 0x0000_7fff_ffff_ffff;
/// Hard ceiling per object (explicit size field or very hot xref only).
/// R-GTO-UI: gscript root is readable ≥128 KiB while login UI is up; allow
/// one large root so cold restart keeps more script body (still budget-capped
/// by MAX_HEAP_GLOBAL_TOTAL_BYTES / slot cap).
const MAX_HEAP_GLOBAL_BYTES: usize = 64 * 1024;
/// Default probe ceiling — committed heap regions are multi-page; reading until
/// RPM fails captures neighbour chunks and burns the aggregate budget.
const DEFAULT_SIZE_PROBE_CAP: usize = 0x2000;
/// Hot image roots (many code xrefs) may be large AHK tables.
const HOT_XREF_SIZE_PROBE_CAP: usize = 0x8000;
const HOT_XREF_THRESHOLD: u32 = 50;
/// Graph children are edges, not roots — keep them modest (AHK string/table
/// shells often sit in the 0x100–0x1000 band; larger still via hot roots).
const GRAPH_CHILD_SIZE_PROBE_CAP: usize = 0x2000;
/// Aggregate payload for roots + graph children.
/// Raised so AHK script object graphs (login GUI title + controls) fit.
const MAX_HEAP_GLOBAL_TOTAL_BYTES: usize = 3072 * 1024;
/// Stop admitting new image-root slots past this so expand still has budget.
const MAX_HEAP_GLOBAL_ROOT_BYTES: usize = 1024 * 1024;
/// Total snapshots (image roots + graph children + split siblings).
/// p20c still AVs at +0xdafa4 [rax=0x28] after plant — need denser gscript
/// multi-hop before scrub (~13k edges remaining).
const MAX_HEAP_GLOBAL_SLOTS: usize = 320;
/// Slots reserved for the final dangling-edge pass (hot pre-scrub edges).
/// Expand/split must not fill these or scrub still nulls gscript edges (p19 AV).
const HEAP_DANGLING_SLOT_RESERVE: usize = 80;
/// Image-rooted slots only — leave headroom for freeable nested buffers.
const MAX_HEAP_GLOBAL_ROOT_SLOTS: usize = 40;
const SIZE_PROBES: [usize; 7] = [0x40, 0x100, 0x400, 0x1000, 0x2000, 0x4000, 0x8000];
/// Secondary fill scan: max non-zero pointer slots to enqueue (entire preferred
/// surface). Kept high enough to cover multi-MB `.fill` gaps; capture still
/// hard-capped by `MAX_HEAP_GLOBAL_SLOTS` / total bytes.
const MAX_FILL_SCAN_CANDIDATES: usize = 512;
/// BFS rounds walking interior pointers of already-captured blobs to pull in
/// sibling heap objects the image roots do not name directly.
/// More rounds after free-safe split so remapped leaves grow the useful graph
/// (login title strings live several hops from gscript roots).
const MAX_GRAPH_EXPAND_ROUNDS: usize = 6;
/// Max new nodes admitted per expand round (keeps dump time bounded).
const MAX_EXPAND_PER_ROUND: usize = 32;
/// Only expand from the first N image-rooted captures (highest xref).
/// Cover the full slot cap so moderate-xref roots (e.g. path-string
/// wrappers) still get nested freeable buffers as separate allocs.
const MAX_EXPAND_ROOTS: usize = MAX_HEAP_GLOBAL_SLOTS;
/// Reject "heap" pointers that are really low-VA PE structures / noise.
/// Keep above the first MB so segment heads / PEB-adjacent junk is excluded.
const MIN_HEAP_POINTER: u64 = 0x10_0000;
/// Graph expand / split only: skip low-VA LFH neighbourhood junk that used to
/// burn the entire slot budget (0x121xxx/0x122xxx series in p18b). Real AHK
/// script objects for this sample live well above a few MiB.
const MIN_GRAPH_CHILD_POINTER: u64 = 0x40_0000;
// Hot RVAs / gscript knobs: see [`DumpCapturePolicy`] (built-in AHK/GTO defaults
// via `DumpCapturePolicy::ahk_gto_default`). Do not re-introduce sample-private
// const tables here — pass policy from DumpOptions instead.
/// System DLL / wow64 region on x64 Windows (kernel32 etc. live at `0x7ff…`).
/// Private heaps and user allocations sit well below this.
const MIN_MODULE_REGION: u64 = 0x0000_7ff0_0000_0000;
/// Fill-scan-only candidates (xref=0) are dropped unless at least this large.
/// In practice AHK critical slots always have code xrefs; fill-scan alone
/// previously captured low-VA junk (0x2ae30/0x62d80…) that polluted the
/// inter-block pointer graph and caused RtlpFindEntry AVs after restore.
/// Set above MAX_HEAP_GLOBAL_BYTES so only code-xref'd slots are restored.
const MIN_FILL_ONLY_CAPTURE_BYTES: usize = MAX_HEAP_GLOBAL_BYTES + 1;
const GSCRIPT_LABEL_COUNT_END: usize = 0x14;

/// One plain heap-pointer slot in a zero-raw writable section.
///
/// Graph-expansion children (no image slot) use `rva == 0`. The bootstrap must
/// not plant `*image_base = new_ptr` for those entries — only alloc/memcpy and
/// multi-range fixup apply.
///
/// When `is_heap_handle` is set, `live_ptr` is a process heap *handle*
/// (`GetProcessHeap` / `HeapCreate` result), not an opaque data object. The
/// bootstrap must plant `GetProcessHeap()` into the slot — never memcpy the
/// HEAP structure (that yields RtlpWaitOnCriticalSection AVs on the next
/// `HeapAlloc`).
///
/// When `is_image_inline` is set, `rva` is the **object body** in the image
/// (e.g. AHK `g_script` at `0x149d50`, used as `lea rcx,[g_script]`), not an
/// 8-byte pointer slot. Capture reads live image bytes at `image_base+rva`;
/// bootstrap memcpys into that image address and records fixup
/// Provenance taxonomy for a heap-global region (GTO Core Recovery R0-D).
///
/// Distinguishes how a region's bytes and live address were obtained, which
/// governs whether it may participate in raw-coherence overlay and how it is
/// materialized at runtime. A synthetic region must never be reported as
/// raw-captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionProvenance {
    /// Bytes + live address read directly from the debuggee (pre-transform).
    /// May participate in raw coherence and be overlaid after a transform.
    RawCaptured {
        /// sha256 (hex) of the raw bytes as read from the debuggee.
        raw_digest: String,
    },
    /// A raw-captured region that was modified by one or more offline
    /// transforms. Bound to its raw source region and the transform ledger.
    TransformedRawCaptured {
        /// sha256 (hex) of the pre-transform raw bytes.
        raw_digest: String,
        /// transform ids applied to this region (deterministic order).
        transform_ids: Vec<String>,
    },
    /// No raw source: bytes were synthesized by an offline transform for
    /// product recovery. Must bind a transform id, a source anchor or
    /// deterministic construction rule, and a construction digest. Never
    /// claimed as raw-observed. Materialized via independent runtime
    /// allocation (HeapAlloc) — not an in-image region.
    SyntheticDerived {
        /// transform id that created this region.
        transform_id: String,
        /// source anchor: the slot/region that references it, or the
        /// deterministic construction rule that produced the bytes.
        source_anchor: String,
        /// sha256 (hex) of the constructed bytes (deterministic).
        construction_digest: String,
    },
    /// Object body lives in the image at `rva`; proven image ownership
    /// required (not merely "address looks like an image"). Never routed
    /// through the heap allocation path.
    ImageInline,
    /// Resolved at cold-start through the resolver / IAT semantics; a
    /// dump-time API VA is never written into the candidate.
    ExternalResolved,
    /// Provenance could not be established. Always fail-closed; never
    /// reaches a Complete plan and never writes a candidate.
    UnknownSynthetic,
}

impl Default for RegionProvenance {
    fn default() -> Self {
        RegionProvenance::RawCaptured {
            raw_digest: String::new(),
        }
    }
}

/// Classification of a heap capture's byte extent (GTO Core Recovery R0-F).
///
/// Distinguishes a proven allocation extent from a heuristic read window.
/// A probe window must never be claimed as an independent heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaptureExtentKind {
    /// The capture is a read/heuristic window (e.g. `estimate_object_size`
    /// returned a `SIZE_PROBES` value); the true allocation boundary is not
    /// proven. Must not be treated as an independent allocation extent.
    #[default]
    ProbeWindow,
    /// The bytes were read at a proven allocation base with a boundary
    /// established from capture evidence (e.g. an exact slot size field).
    ObservedAllocation,
    /// A large contiguous blob backing one or more interior subviews.
    BackingObject,
    /// An interior pointer admitted as an exact-base snapshot inside a parent.
    InteriorSubview,
    /// Bytes synthesized by an offline transform (no raw source).
    SyntheticDerived,
}

/// How a heap-global snapshot was captured (GTO Core Recovery R0-F.1).
/// Binds the source path so probe windows are distinguished from observed
/// allocations, and runtime ownership can be derived deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapturePath {
    /// Read directly from an image slot / root (main detection).
    #[default]
    MainSlot,
    /// Force-admitted gscript first-hop edge.
    GscriptFirstHop,
    /// Force-admitted gscript child link field.
    GscriptChildLink,
    /// Admitted via the gscript label pointer table (+0 of gscript object).
    /// Route Y R1 A6 AF3: this is the truthful source for a label-table entry
    /// admitted by `exhaust_gscript_label_table_entries` — NOT MainSlot, which
    /// semantically means an image/root slot read.
    GscriptLabelTableEntry,
    /// Captured string-buffer child (refcounted shell).
    StringBufferChild,
    /// Captured dangling edge (final walk).
    DanglingEdge,
    /// MIDA-SERIAL-34: heap sibling promoted out of a swallowing parent by
    /// `split_swallowed_siblings` (free-safe split). NOT MainSlot — MainSlot
    /// semantically means an image/root slot read, and a split child is an
    /// interior-discovered heap object with its own captured bytes.
    SplitSibling,
    /// Image-inline object body (not a heap extent).
    ImageInline,
    /// Synthesized by an offline transform.
    Synthetic,
}

/// Capture evidence bound to a first-hop / interior snapshot (GTO R0-F.1).
/// Records enough to derive runtime ownership and alias relationships without
/// re-reading the debuggee.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaptureExtentEvidence {
    /// Deterministic capture id for ledger/reference.
    pub capture_id: String,
    /// Which capture path produced this snapshot.
    pub capture_path: CapturePath,
    /// Root image RVA that led to this capture (e.g. gscript root).
    pub source_root_rva: Option<u32>,
    /// Byte offset of the source slot within the root, if known.
    pub source_slot_offset: Option<usize>,
    /// The probe size requested (e.g. first-hop probe cap).
    pub probe_requested_size: usize,
    /// Whether this pointer was interior to an already-captured object.
    pub was_interior: bool,
    /// Old base of the containing parent object, if any.
    pub containing_parent_old_base: Option<u64>,
    /// Size of the containing parent, if any.
    pub containing_parent_size: Option<usize>,
}

/// MIDA-SERIAL-34: deterministic pre-trunc parent evidence captured by
/// split_swallowed_siblings BEFORE the swallowing parent is truncated. This is
/// the ONLY producer of containing_parent_old_base/size for split children.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SplitSiblingParentEvidence {
    /// Pre-trunc old base of the swallowing parent (live allocation base).
    pub pre_trunc_parent_old_base: Option<u64>,
    /// Pre-trunc full size of the swallowing parent (before truncation).
    pub pre_trunc_parent_size: Option<usize>,
    /// Pre-trunc extent kind of the parent (must be ObservedAllocation /
    /// BackingObject for a closure candidate; ProbeWindow / InteriorSubview /
    /// SyntheticDerived never qualify).
    pub pre_trunc_parent_extent: Option<CaptureExtentKind>,
    /// Pre-trunc provenance of the parent (must not be SyntheticDerived).
    pub pre_trunc_parent_provenance: Option<RegionProvenance>,
    /// Parent capture identity (id + path) at pre-trunc time.
    pub pre_trunc_parent_capture_id: Option<String>,
    pub pre_trunc_parent_capture_path: Option<CapturePath>,
}

/// MIDA-SERIAL-34: the deterministic candidate-evidence record produced by
/// split_swallowed_siblings for ONE split child. Replaces the lossy
/// BTreeSet<u64> candidate set: every field needed to prove (or fail-closed)
/// the split child's coverage is preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitSiblingCandidateEvidence {
    /// The child value (heap address being split out).
    pub child_value: u64,
    /// Byte offset of the qword slot within the SOURCE snapshot that held
    /// child_value (real slot offset — never a fixed constant).
    pub source_slot_offset: Option<usize>,
    /// Capture identity of the source snapshot that referenced the child.
    pub source_capture_id: Option<String>,
    /// Capture path of the source snapshot.
    pub source_capture_path: Option<CapturePath>,
    /// Source root RVA (when the source snapshot was image-rooted).
    pub source_root_rva: Option<u32>,
    /// MIDA-SERIAL-36: the set of DISTINCT source capture identities that
    /// referenced this child (dedup by identity, never by occurrence).
    pub source_identities: std::collections::BTreeSet<String>,
    /// Number of distinct source snapshots whose qword slot referenced the
    /// child (== source_identities.len()).
    pub source_hit_count: usize,
    /// Number of distinct parent snapshots (pre-trunc) that contained the child.
    pub parent_hit_count: usize,
    /// Pre-trunc parent evidence (present only when the parent is unique, strict
    /// and its pre-trunc extent/provenance qualify).
    pub parent: Option<SplitSiblingParentEvidence>,
    /// Whether the child was interior to an already-captured object.
    pub was_interior: bool,
    /// The probe size requested for the child capture.
    pub probe_requested_size: usize,
}

/// MIDA-SERIAL-35: a strict pre-trunc parent authority evidence record emitted
/// by split_swallowed_siblings BEFORE the swallowing parent is truncated. This
/// is the ONLY producer of full pre-trunc parent authority bytes. It flows out
/// of the production capture (via detect_heap_globals) into
/// build_authority_closure_candidates so a closure authority can be built from
/// the REAL pre-trunc bytes — never from the truncated parent in the final
/// heap_globals, never re-read, never guessed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreTruncParentAuthorityKey {
    /// Pre-trunc old base of the strict parent (live allocation base).
    pub parent_old_base: u64,
    /// Pre-trunc full size of the strict parent.
    pub parent_pre_trunc_size: usize,
    /// Pre-trunc parent capture identity.
    pub parent_capture_id: String,
}

/// MIDA-SERIAL-38: a producer-lifetime frozen identity of an eligible strict
/// parent, captured ONCE before any split-round truncation. All children of the
/// same original parent bind the SAME frozen key/bytes regardless of round or
/// child processing order — the split producer never re-derives "pre-trunc"
/// from an already-truncated snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenSplitParentIdentity {
    /// Parent identity key (base + ORIGINAL pre-trunc size + capture id).
    pub key: PreTruncParentAuthorityKey,
    /// Original full pre-trunc bytes (immutable; frozen before any truncation).
    /// MIDA-SERIAL-39: Arc-shared — ONE backing allocation; children clone the
    /// Arc handle, never a full Vec.
    pub full_bytes: std::sync::Arc<[u8]>,
    /// Pre-trunc extent kind (must be ObservedAllocation / BackingObject).
    pub extent: CaptureExtentKind,
    /// Pre-trunc provenance (must not be SyntheticDerived).
    pub provenance: RegionProvenance,
    /// Pre-trunc capture path.
    pub capture_path: CapturePath,
    /// Whether the snapshot remains full (untruncated) at the current out view.
    /// Starts true; cleared when a child splits it.
    pub is_full: bool,
}

/// Resolve a snapshot as an eligible frozen parent using the FULL qualifying
/// identity predicate (base, original size, capture_id, capture_path, extent,
/// provenance) — never a loose find(base,size) that could select a
/// ProbeWindow/SyntheticDerived twin with the same capture id.
fn frozen_parent_from_snapshot(o: &HeapGlobalSnapshot) -> Option<FrozenSplitParentIdentity> {
    if o.is_heap_handle || o.content.is_empty() {
        return None;
    }
    if !matches!(
        o.extent_kind,
        CaptureExtentKind::ObservedAllocation | CaptureExtentKind::BackingObject
    ) {
        return None;
    }
    if matches!(o.provenance, RegionProvenance::SyntheticDerived { .. }) {
        return None;
    }
    Some(FrozenSplitParentIdentity {
        key: PreTruncParentAuthorityKey {
            parent_old_base: o.live_ptr,
            parent_pre_trunc_size: o.content.len(),
            parent_capture_id: o.extent_evidence.capture_id.clone(),
        },
        // MIDA-SERIAL-39: ONE backing allocation from the snapshot content;
        // all children share this Arc.
        full_bytes: std::sync::Arc::from(o.content.as_slice()),
        extent: o.extent_kind,
        provenance: o.provenance.clone(),
        capture_path: o.extent_evidence.capture_path,
        is_full: true,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreTruncParentAuthorityEvidence {
    /// Parent identity key into the authority store (resolves the shared bytes).
    pub parent_key: PreTruncParentAuthorityKey,
    /// Pre-trunc extent kind (must be ObservedAllocation / BackingObject).
    pub parent_extent: CaptureExtentKind,
    /// Pre-trunc provenance (must not be SyntheticDerived).
    pub parent_provenance: RegionProvenance,
    pub parent_capture_path: CapturePath,
    /// The split child this parent authority binds to.
    pub child_base: u64,
    pub child_size: usize,
    /// Producer/source binding: the source snapshot whose slot referenced the
    /// child and the REAL slot byte offset.
    pub source_capture_id: String,
    pub source_slot_offset: Option<usize>,
}

/// MIDA-SERIAL-36: deduplicating store for pre-trunc parent authority bytes.
///
/// The same strict parent may back multiple split children. This store keeps
/// ONE immutable copy of the parent's full pre-trunc bytes per distinct parent
/// identity key (old_base, pre_trunc_size, capture_id), and produces one
/// PreTruncParentAuthorityEvidence binding per child.
///
/// Rules:
/// - same key + identical bytes -> reuse the stored bytes (dedup);
/// - same key + DIFFERENT bytes -> fail-closed (never overwrite the first);
/// - different capture identity at the same old_base -> SEPARATE entry
///   (never merged by base alone).
#[derive(Debug, Clone, Default)]
pub struct PreTruncParentAuthorityStore {
    /// key -> (bytes, extent, provenance, path). ONE byte copy per parent
    /// identity (Arc-shared) — bindings and Path A hold no second Vec<u8>.
    parents: std::collections::BTreeMap<
        PreTruncParentAuthorityKey,
        (
            std::sync::Arc<[u8]>,
            CaptureExtentKind,
            RegionProvenance,
            CapturePath,
        ),
    >,
    /// Emitted child bindings (insertion order). Each holds only the key.
    bindings: Vec<PreTruncParentAuthorityEvidence>,
}

/// MIDA-SERIAL-37: fail-closed conflict result of a bind/commit. A conflict is
/// a HARD error: the split candidate must be REJECTED (child not admitted,
/// parent not truncated, no evidence, no counters/seen residue) — never
/// silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PreTruncAuthorityError {
    /// Same parent identity key recorded with DIFFERENT bytes/extent/provenance/path.
    #[error(
        "pre-trunc authority identity conflict: parent {parent_old_base:#x} size {parent_pre_trunc_size}          capture_id '{parent_capture_id}' bound with different bytes/extent/provenance/path"
    )]
    IdentityConflict {
        parent_old_base: u64,
        parent_pre_trunc_size: usize,
        parent_capture_id: String,
    },
    /// Child binding recorded twice for the SAME (child_base, child_size).
    #[error(
        "pre-trunc authority child binding conflict: child {child_base:#x} size {child_size}          already bound (duplicate split child)"
    )]
    DuplicateChildBinding { child_base: u64, child_size: usize },
}

impl PreTruncParentAuthorityStore {
    /// MIDA-SERIAL-37: prepare the parent identity (conflict check) BEFORE any
    /// irreversible commit. Returns the key on success.
    pub fn prepare_parent(
        &self,
        parent_old_base: u64,
        parent_pre_trunc_size: usize,
        parent_full_bytes: &[u8],
        parent_extent: CaptureExtentKind,
        parent_provenance: &RegionProvenance,
        parent_capture_id: &str,
        parent_capture_path: CapturePath,
    ) -> Result<PreTruncParentAuthorityKey, PreTruncAuthorityError> {
        let key = PreTruncParentAuthorityKey {
            parent_old_base,
            parent_pre_trunc_size,
            parent_capture_id: parent_capture_id.to_string(),
        };
        if let Some((existing_bytes, eext, eprov, epath)) = self.parents.get(&key) {
            if &existing_bytes[..] != parent_full_bytes
                || *eext != parent_extent
                || eprov != parent_provenance
                || *epath != parent_capture_path
            {
                return Err(PreTruncAuthorityError::IdentityConflict {
                    parent_old_base,
                    parent_pre_trunc_size,
                    parent_capture_id: parent_capture_id.to_string(),
                });
            }
        }
        Ok(key)
    }

    /// MIDA-SERIAL-37: prepare the CHILD binding (duplicate check).
    pub fn prepare_child(
        &self,
        child_base: u64,
        child_size: usize,
    ) -> Result<(), PreTruncAuthorityError> {
        if self
            .bindings
            .iter()
            .any(|b| b.child_base == child_base && b.child_size == child_size)
        {
            return Err(PreTruncAuthorityError::DuplicateChildBinding {
                child_base,
                child_size,
            });
        }
        Ok(())
    }

    /// MIDA-SERIAL-37: record ONE binding (parent must already be prepared).
    pub fn record_binding(
        &mut self,
        key: PreTruncParentAuthorityKey,
        parent_extent: CaptureExtentKind,
        parent_provenance: RegionProvenance,
        parent_capture_path: CapturePath,
        child_base: u64,
        child_size: usize,
        source_capture_id: String,
        source_slot_offset: Option<usize>,
    ) -> PreTruncParentAuthorityEvidence {
        let binding = PreTruncParentAuthorityEvidence {
            parent_key: key,
            parent_extent,
            parent_provenance,
            parent_capture_path,
            child_base,
            child_size,
            source_capture_id,
            source_slot_offset,
        };
        self.bindings.push(binding.clone());
        binding
    }

    /// Record the parent's full bytes once (no-op when already recorded), from
    /// an Arc — NO byte copy: the Arc is stored directly.
    pub fn record_parent_arc(
        &mut self,
        key: &PreTruncParentAuthorityKey,
        parent_full_bytes: std::sync::Arc<[u8]>,
        parent_extent: CaptureExtentKind,
        parent_provenance: RegionProvenance,
        parent_capture_path: CapturePath,
    ) {
        self.parents.entry(key.clone()).or_insert_with(|| {
            (
                parent_full_bytes,
                parent_extent,
                parent_provenance,
                parent_capture_path,
            )
        });
    }

    /// Resolve the shared Arc<[u8]> for a key — consumers can clone the Arc
    /// without copying the bytes (Path A per-key single build).
    pub fn lookup_arc(&self, key: &PreTruncParentAuthorityKey) -> Option<std::sync::Arc<[u8]>> {
        self.parents.get(key).map(|(bytes, _, _, _)| bytes.clone())
    }

    /// Full metadata row for a key (extent, provenance, path).
    pub fn parent_meta(
        &self,
        key: &PreTruncParentAuthorityKey,
    ) -> Option<(CaptureExtentKind, RegionProvenance, CapturePath)> {
        self.parents
            .get(key)
            .map(|(_, ext, prov, path)| (*ext, prov.clone(), *path))
    }

    /// Emitted child bindings, in insertion order.
    pub fn bindings(&self) -> &[PreTruncParentAuthorityEvidence] {
        &self.bindings
    }
}

/// Test-only convenience accessors for [`PreTruncParentAuthorityStore`].
/// Production paths use the Arc-based / prepare+record API; these helpers
/// exist solely to make test assertions readable and are compiled out of
/// non-test builds (no dead production surface).
#[cfg(test)]
impl PreTruncParentAuthorityStore {
    /// Record the parent's full bytes once (no-op when already recorded). The
    /// bytes are stored as ONE Arc<[u8]>; every later consumer shares it.
    pub fn record_parent(
        &mut self,
        key: &PreTruncParentAuthorityKey,
        parent_full_bytes: &[u8],
        parent_extent: CaptureExtentKind,
        parent_provenance: RegionProvenance,
        parent_capture_path: CapturePath,
    ) {
        self.parents.entry(key.clone()).or_insert_with(|| {
            (
                std::sync::Arc::from(parent_full_bytes),
                parent_extent,
                parent_provenance,
                parent_capture_path,
            )
        });
    }

    /// Resolve the FULL shared parent bytes for a key (Path A lookup).
    pub fn lookup(&self, key: &PreTruncParentAuthorityKey) -> Option<&[u8]> {
        self.parents.get(key).map(|(bytes, _, _, _)| bytes.as_ref())
    }

    /// Number of distinct parent identities (bytes stored once each).
    pub fn parent_count(&self) -> usize {
        self.parents.len()
    }

    /// Number of child bindings emitted.
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// MIDA-SERIAL-37: ONE-call prepare + record. Err on conflict — the
    /// caller MUST reject the candidate (fail-closed; never silently drop).
    pub fn bind_child(
        &mut self,
        parent_old_base: u64,
        parent_pre_trunc_size: usize,
        parent_full_bytes: &[u8],
        parent_extent: CaptureExtentKind,
        parent_provenance: &RegionProvenance,
        parent_capture_id: &str,
        parent_capture_path: CapturePath,
        child_base: u64,
        child_size: usize,
        source_capture_id: String,
        source_slot_offset: Option<usize>,
    ) -> Result<PreTruncParentAuthorityEvidence, PreTruncAuthorityError> {
        let key = self.prepare_parent(
            parent_old_base,
            parent_pre_trunc_size,
            parent_full_bytes,
            parent_extent,
            parent_provenance,
            parent_capture_id,
            parent_capture_path,
        )?;
        self.prepare_child(child_base, child_size)?;
        Ok(self.record_binding(
            key,
            parent_extent,
            parent_provenance.clone(),
            parent_capture_path,
            child_base,
            child_size,
            source_capture_id,
            source_slot_offset,
        ))
    }
}

/// `old=live_ptr(=image_base+rva) → new=image_base+rva` so child edges that
/// still hold the live image base remap correctly. Planting a heap clone at
/// `*[rva]` is wrong for this class (R-GTO-UI script-heap-resume).
#[derive(Debug, Clone, Default)]
pub struct HeapGlobalSnapshot {
    /// Image RVA of the 8-byte slot that holds the heap pointer (`0` = no plant).
    /// For `is_image_inline`, RVA of the in-image object body.
    pub rva: u32,
    /// Live heap address (for fixup math at runtime).
    /// For `is_image_inline`, live image VA of the object (`image_base+rva`).
    pub live_ptr: u64,
    /// Bytes captured from the live heap object (empty when `is_heap_handle`).
    pub content: Vec<u8>,
    /// Slot holds a heap handle, not a data blob.
    pub is_heap_handle: bool,
    /// Object body lives in the image at `rva` (not a pointer slot).
    pub is_image_inline: bool,
    /// Provenance of this region (default `RawCaptured`).
    pub provenance: RegionProvenance,
    /// Extent classification (GTO R0-F). Default `ProbeWindow`.
    pub extent_kind: CaptureExtentKind,
    /// Capture evidence (GTO R0-F.1). Bound to first-hop / interior snapshots
    /// so runtime ownership can be derived deterministically.
    pub extent_evidence: CaptureExtentEvidence,
    /// Transform ids that actually modified this child (GTO R0-F.1). Populated
    /// by the dump pipeline by diffing content across each transform. An
    /// unchanged child has an empty list (it is never claimed as a writer).
    pub transform_ids: Vec<String>,
}

impl HeapGlobalSnapshot {
    /// Route X R0 (X0-A): THE canonical raw-coherence participant predicate.
    ///
    /// A snapshot is a raw-coherence participant if and only if it participates
    /// in raw capture, authoritative seeding, raw-overlay transform provenance,
    /// and overlay reconciliation. It must be:
    ///   - NOT a heap handle (a handle is a pointer, not a data blob);
    ///   - NOT an image-inline body (image-backed, non-raw; never routed through
    ///     heap allocation / raw slab overlay);
    ///   - NOT empty (no bytes to capture or overlay);
    ///   - NOT SyntheticDerived (no raw source; constructed by an offline transform).
    ///
    /// Every production path that decides "does this heap global participate in
    /// raw slab coherence?" MUST use this predicate — identity validation,
    /// raw-child construction, transform-input seeding/binding, transform
    /// write-run recording, and pre-overlay membership validation. No copied
    /// ad-hoc condition sets are accepted (that was the W R1 participant-set
    /// invariant violation: an image-inline snapshot entered the raw-overlay
    /// transform write-run ledger with an empty capture_id).
    #[must_use]
    pub fn is_raw_coherence_participant(&self) -> bool {
        use RegionProvenance as RP;
        if self.is_heap_handle || self.is_image_inline || self.content.is_empty() {
            return false;
        }
        if matches!(self.provenance, RP::SyntheticDerived { .. }) {
            return false;
        }
        true
    }
}

/// A captured heap slab: one contiguous blob covering the span of all
/// non-handle heap-global live_ptrs **plus a prefix pad** before the first
/// object. At runtime the stub reserves/copies this blob and rebases every
/// interior pointer `old_base < V < old_base+len` by `delta = new_base -
/// old_base`.
///
/// Route F / r27: exact-base multi_fixup misses **pre-object gaps**. Example:
/// computed ptr `0x846898` (= heap_handle `0x830000` + `0x16898`) sits in a
/// `0x318`-byte hole **before** the nearest captured object `0x846bb0`. A
/// slab that starts at min(object live_ptrs) leaves that hole outside the
/// rebase window. Prefix pad pulls `old_base` down so the hole is interior.
///
/// Strict-interior rule: `old_base < V < old_base+len` (excludes `V ==
/// old_base` so heap-handle references are not rebased to the slab).
#[derive(Debug, Clone, Default)]
pub struct HeapSlab {
    /// Original heap base (min live_ptr of non-handle globals, minus prefix).
    pub old_base: u64,
    /// Captured blob (best-effort RPM; gaps zero-filled).
    pub content: Vec<u8>,
}

/// Bytes reserved **before** each captured object live_ptr when forming the
/// slab span. Covers the r27 `0x318` pre-object hole class with page headroom.
pub const HEAP_SLAB_PREFIX_PAD: u64 = 0x1000;

/// Hard ceiling for one slab capture (64 MiB).
const MAX_HEAP_SLAB_BYTES: usize = 64 * 1024 * 1024;

/// Compute `[old_base, end)` for a heap slab from non-handle data globals.
///
/// Returns `None` when fewer than two data objects exist or the span is empty
/// / over budget. `old_base` is page-aligned down after applying
/// [`HEAP_SLAB_PREFIX_PAD`] before the minimum object live_ptr.
#[must_use]
pub fn compute_heap_slab_span(heap_globals: &[HeapGlobalSnapshot]) -> Option<(u64, u64)> {
    let mut min_obj: u64 = u64::MAX;
    let mut max_end: u64 = 0;
    let mut count = 0usize;
    for g in heap_globals {
        if !g.is_raw_coherence_participant() {
            continue;
        }
        if g.live_ptr < MIN_USER_POINTER || g.live_ptr > MAX_USER_POINTER {
            continue;
        }
        // Route T R0-B: dangling-edge allocations are surfaced as their OWN
        // dedicated authoritative slabs (see capture_dangling_edges). Exclude
        // them here so dispersed dangling edges do not inflate the single main
        // slab span past MAX_HEAP_SLAB_BYTES (which previously made
        // capture_heap_slab return None and left EVERY probe uncovered).
        if g.extent_evidence.capture_path == CapturePath::DanglingEdge {
            continue;
        }
        count += 1;
        if g.live_ptr < min_obj {
            min_obj = g.live_ptr;
        }
        let end = g.live_ptr.saturating_add(g.content.len() as u64);
        if end > max_end {
            max_end = end;
        }
    }
    if count < 2 || min_obj == u64::MAX || min_obj >= max_end {
        return None;
    }
    // Pull base down to cover pre-object holes (r27 0x846898 class), page-align.
    let padded = min_obj.saturating_sub(HEAP_SLAB_PREFIX_PAD);
    let old_base = padded & !0xfffu64;
    if old_base >= max_end {
        return None;
    }
    let span = max_end.saturating_sub(old_base);
    if span == 0 || span as usize > MAX_HEAP_SLAB_BYTES {
        return None;
    }
    Some((old_base, max_end))
}

/// True if `va` is a strict-interior address of slab `[old_base, old_base+len)`.
#[must_use]
#[allow(dead_code)] // legacy heap-slab analysis; retained for diagnostics
pub fn heap_slab_covers_interior(old_base: u64, len: u64, va: u64) -> bool {
    va > old_base && va < old_base.saturating_add(len)
}

/// Capture the heap span covered by all non-handle, non-inline heap globals
/// as one contiguous blob (with [`HEAP_SLAB_PREFIX_PAD`]). Best-effort RPM:
/// pages that cannot be read are zero-filled so the span stays contiguous.
/// Returns `None` when there are fewer than 2 data globals or the span
/// exceeds 64 MiB.
///
/// The slab lets the runtime stub rebase **interior** heap pointers
/// (`old_base < V < old_base+len`) that exact-base multi_fixup misses
/// (r27 root cause: `0x846898` in a 0x318-byte gap before `0x846bb0`).
pub fn capture_heap_slab(
    heap_globals: &[HeapGlobalSnapshot],
    debugger: &mut dyn mida_core::DebuggerCore,
) -> Option<HeapSlab> {
    let (min_ptr, max_end) = compute_heap_slab_span(heap_globals)?;
    let span = max_end.saturating_sub(min_ptr);
    let data_globals = heap_globals
        .iter()
        .filter(|g| g.is_raw_coherence_participant())
        .count();
    let mut blob = vec![0u8; span as usize];
    // Best-effort RPM in page-sized chunks; zero-fill unreadable gaps.
    const CHUNK: usize = 0x1000;
    let mut offset = 0usize;
    while offset < span as usize {
        let remaining = (span as usize) - offset;
        let take = remaining.min(CHUNK);
        let addr = (min_ptr as usize).saturating_add(offset);
        let mut buf = vec![0u8; take];
        if debugger.read_memory(addr, &mut buf).is_ok() {
            blob[offset..offset + take].copy_from_slice(&buf);
        }
        offset += take;
    }
    info!(
        old_base = format_args!("{min_ptr:#x}"),
        span = format_args!("{span:#x}"),
        prefix_pad = format_args!("{HEAP_SLAB_PREFIX_PAD:#x}"),
        globals = data_globals,
        "Captured heap slab for interior-pointer rebase (Route F prefix pad)"
    );
    Some(HeapSlab {
        old_base: min_ptr,
        content: blob,
    })
}

/// GTO-COLD-START-HEAP-REBASE-1 H2: close the first-hop coverage gap on AHK's
/// multi-heap layout (process heap + private heaps + CRT heap).
///
/// `exhaust_gscript_first_hop` / `expand_hot_root_children` / `expand_heap_graph`
/// all admit ProbeWindow children that can sit OUTSIDE the single main-slab
/// span computed by [`compute_heap_slab_span`]. The `capture_coverage_bind`
/// gate (`validate_probe_coverage`) then fails closed with
/// `ProbeCoverageMissing` even though every admitted child was a valid live
/// read — the capture MODEL was incomplete, not the gate.
///
/// Mirror the Route T R0-B dangling-edge pattern: a NON-interior
/// ProbeWindow/InteriorSubview child (already an authoritative read from the
/// debuggee at capture time) that is not covered by any existing authoritative
/// slab (main or dedicated) is surfaced as its own DEDICATED authoritative
/// slab covering exactly `[live_ptr, live_ptr+content.len())`. The coverage
/// gate stays unchanged: such a child then has exactly one covering slab.
///
/// Fail-closed semantics preserved:
/// - children already covered by a slab are NOT duplicated (would otherwise
///   flip coverage to ambiguous);
/// - interior children (containing_parent recorded) are NOT re-surfaced —
///   their containing parent's slab provides coverage;
/// - children outside `[MIN_USER_POINTER, MAX_USER_POINTER]` or with empty
///   content stay uncovered and still fail closed at the gate.
///
/// Pure offline: no debugger reads, no target writes. Returns the number of
/// dedicated slabs added (for stage telemetry / audit).
#[must_use]
pub fn supplement_uncovered_probe_slabs(
    heap_globals: &[HeapGlobalSnapshot],
    existing_slabs: &[HeapSlab],
    dedicated_slabs: &mut Vec<HeapSlab>,
) -> usize {
    use CaptureExtentKind as CEK;
    // Existing covering ranges (main + dedicated + any prior supplement).
    let mut ranges: Vec<(u64, u64)> = existing_slabs
        .iter()
        .chain(dedicated_slabs.iter())
        .filter(|s| !s.content.is_empty() && s.old_base != 0)
        .filter_map(|s| {
            s.old_base
                .checked_add(s.content.len() as u64)
                .map(|end| (s.old_base, end))
        })
        .collect();
    let mut added = 0usize;
    for g in heap_globals {
        if !g.is_raw_coherence_participant() {
            continue;
        }
        let is_probe = matches!(g.extent_kind, CEK::ProbeWindow | CEK::InteriorSubview);
        // GTO-COLD-START-HEAP-REBASE-1 H2 (attempt_018 wall): an image-root /
        // main-slot captured region (RawCaptured provenance, ObservedAllocation
        // extent) can also sit outside every authoritative slab when the run
        // has NO main slab (AHK multi-heap: process heap + private heaps +
        // CRT heap; capture_heap_slab produced nothing, H2 supplemented 239
        // probe dedicated slabs, but this MainSlot region 0x9f6f00 stayed
        // uncovered). Unlike a ProbeWindow (heuristic read), an
        // ObservedAllocation has a proven boundary from capture evidence, so
        // surfacing it as its own dedicated slab is sound. All fail-closed
        // guards below (conflicts, bad pointers, interior-with-parent) still
        // apply unchanged.
        if !is_probe
            && !matches!(
                (&g.provenance, g.extent_kind),
                (
                    RegionProvenance::RawCaptured { .. },
                    CEK::ObservedAllocation
                )
            )
        {
            continue;
        }
        // Interior children are covered by their containing parent's slab —
        // re-surfacing them would create ambiguous multi-coverage. Exception
        // (GTO-COLD-START-HEAP-REBASE-1 H2): a split-sibling interior child
        // whose parent authority was LOST (containing_parent_old_base=None —
        // heuristic/ambiguous parent per MIDA-SERIAL-34/39) has no slab to
        // depend on; it must be supplemented itself or the coverage gate fails
        // closed even though every byte was a valid live read.
        if g.extent_evidence.was_interior && g.extent_evidence.containing_parent_old_base.is_some()
        {
            continue;
        }
        if g.live_ptr < MIN_USER_POINTER || g.live_ptr > MAX_USER_POINTER {
            continue;
        }
        if g.content.is_empty() {
            continue;
        }
        let Some(child_end) = g.live_ptr.checked_add(g.content.len() as u64) else {
            continue;
        };
        // Count existing covering ranges (before adding ours).
        let covered = ranges
            .iter()
            .any(|&(sb, se)| g.live_ptr >= sb && child_end <= se);
        if covered {
            continue;
        }
        // Any existing range that PARTIALLY overlaps this child would make the
        // child ambiguous if we add a dedicated slab — fail closed by skipping
        // (the gate still rejects the child as uncovered; we never fabricate a
        // boundary over a conflicting authority).
        let conflicts = ranges.iter().any(|&(sb, se)| {
            (g.live_ptr < se && child_end > sb) // ranges intersect
                && !(g.live_ptr >= sb && child_end <= se) // but not contained
        });
        if conflicts {
            continue;
        }
        dedicated_slabs.push(HeapSlab {
            old_base: g.live_ptr,
            content: g.content.clone(),
        });
        ranges.push((g.live_ptr, child_end));
        added += 1;
    }
    if added > 0 {
        info!(
            added,
            total_dedicated = dedicated_slabs.len(),
            "Supplemented dedicated slabs for uncovered first-hop probe children (H2)"
        );
    }
    added
}

pub fn ensure_plant_target_sections_writable(
    pe: &mut PeHeader,
    heap_globals: &[HeapGlobalSnapshot],
) -> usize {
    let mut marked = 0usize;
    for g in heap_globals {
        if g.rva == 0 {
            continue;
        }
        let rva = g.rva;
        let Some(section) = pe.sections.iter_mut().find(|s| {
            rva >= s.virtual_address
                && rva < s.virtual_address.saturating_add(s.virtual_size.max(1))
        }) else {
            continue;
        };
        if section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            continue;
        }
        section.characteristics |= IMAGE_SCN_MEM_WRITE;
        section.header.characteristics = section.characteristics;
        marked = marked.saturating_add(1);
        info!(
            rva = format_args!("{rva:#x}"),
            section = %section.name,
            chars = format_args!("{:#x}", section.characteristics),
            "Marked heap-global plant target section MEM_WRITE"
        );
    }
    marked
}

/// Detect plain heap-pointer slots referenced by code into zero-raw writable
/// sections **and** code-xref'd `.data` slots, then copy the referenced heap
/// bytes from the live process.
///
/// `.data` matters for AHK/MSVC samples: early overlay + pointer scrub zero
/// live heap roots (e.g. `mov r13,[0x141bf0]`), so post-CRT restore must
/// re-materialize those objects even though the slots are not in `.fill`.
pub fn detect_heap_globals(
    pe: &PeHeader,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) -> (
    Vec<HeapGlobalSnapshot>,
    Vec<HeapSlab>,
    PreTruncParentAuthorityStore,
) {
    if !pe.is_64bit {
        return (
            Vec::new(),
            Vec::new(),
            PreTruncParentAuthorityStore::default(),
        );
    }

    // MIDA-SERIAL-15: identity-bound gate for sample-specific paths inside
    // detect_heap_globals (normalize cmd table / exhaust 0x147868 / drop AHK
    // string-arena control slots). These paths have hard-coded sample RVAs
    // independent of the policy; they may run ONLY when the policy carries a
    // matching module binding (plus valid revision/digest). Otherwise they are
    // skipped and the generic path proceeds.
    let sample_active = super::module_identity::ModuleIdentity::from_pe_header(pe)
        .ok()
        .map_or(false, |m| policy.sample_specific_activation(&m));
    if !sample_active && policy.has_sample_specific() {
        info!("MIDA-SERIAL-15: heap-global sample paths denied by policy gate (no matching module binding)");
    }

    let image_base = pe.nt_headers.optional_header.image_base;
    let image_end = image_base.saturating_add(pe.size_of_image() as u64);

    // Data-like image ranges: non-executable sections. At dump time Themida
    // may still list huge virtual sections without MEM_WRITE; do not require
    // WRITE. Exclude pure code so we never treat .text constants as slots.
    // kind: 0=other, 1=preferred fill/zero-raw, 2=.data (xref-only capture)
    let data_ranges: Vec<(u32, u32, u8)> = pe
        .sections
        .iter()
        .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE == 0)
        .filter(|s| s.name != ".rdata") // never treat rdata constants as heap slots
        .map(|s| {
            let kind = if is_zero_raw_writable(s) || s.name.starts_with(".fill") {
                1u8
            } else if s.name == ".data" {
                2u8
            } else {
                0u8
            };
            (
                s.virtual_address,
                s.virtual_address.saturating_add(s.virtual_size),
                kind,
            )
        })
        .collect();
    if data_ranges.is_empty() {
        return (
            Vec::new(),
            Vec::new(),
            PreTruncParentAuthorityStore::default(),
        );
    }

    let all_data: Vec<(u32, u32)> = data_ranges.iter().map(|&(lo, hi, _)| (lo, hi)).collect();
    let preferred: Vec<(u32, u32)> = data_ranges
        .iter()
        .filter(|&&(_, _, kind)| kind == 1)
        .map(|&(lo, hi, _)| (lo, hi))
        .collect();
    let data_sec: Vec<(u32, u32)> = data_ranges
        .iter()
        .filter(|&&(_, _, kind)| kind == 2)
        .map(|&(lo, hi, _)| (lo, hi))
        .collect();
    // Capture candidates = preferred fill + .data (not other writable junk).
    let capture_ranges: Vec<(u32, u32)> = preferred
        .iter()
        .copied()
        .chain(data_sec.iter().copied())
        .collect();

    // Cookie / complement neighborhood — never treat as plain heap slots.
    let cookie_blocklist = security_cookie_blocklist(pe, dump_buf);

    // xref_count: how many code sites reference each slot (hotness).
    let xref_hits = collect_code_xrefs_to_ranges(pe, dump_buf, &all_data);
    // Full-image RIP scan for preferred + .data (patched sites may lack EXECUTE).
    let capture_xrefs = collect_rip_xrefs_in_buffer(dump_buf, &capture_ranges);
    let mut candidate_scores: BTreeMap<u32, u32> = BTreeMap::new();
    for (rva, count) in &xref_hits {
        if capture_ranges
            .iter()
            .any(|&(lo, hi)| *rva >= lo && *rva < hi)
        {
            *candidate_scores.entry(*rva).or_insert(0) += *count;
        }
    }
    for (rva, count) in &capture_xrefs {
        *candidate_scores.entry(*rva).or_insert(0) += *count;
    }
    let xref_total: u32 = candidate_scores.values().sum();
    info!(
        xref_sites = xref_total,
        unique_slots = candidate_scores.len(),
        preferred_ranges = preferred.len(),
        data_ranges = data_sec.len(),
        full_image_capture_xrefs = capture_xrefs.len(),
        "Code xrefs into fill/.data heap-global candidate ranges"
    );

    // Secondary: scan preferred zero-raw / .fill via dump_buf only (no per-slot
    // RPM — multi-MB gaps). Capture stage re-reads live for truth.
    let mut fill_added = 0usize;
    for &(lo, hi) in &preferred {
        let start = lo as usize;
        let end = (hi as usize).min(dump_buf.len());
        if end.saturating_sub(start) < 8 {
            continue;
        }
        let mut rva = (start as u32 + 7) & !7;
        while (rva as usize) + 8 <= end {
            if fill_added >= MAX_FILL_SCAN_CANDIDATES {
                break;
            }
            if !candidate_scores.contains_key(&rva) {
                let offset = rva as usize;
                let value =
                    u64::from_le_bytes(dump_buf[offset..offset + 8].try_into().unwrap_or_default());
                if is_heap_pointer(value, image_base, image_end) {
                    candidate_scores.insert(rva, 0); // score 0 = fill-scan only
                    fill_added += 1;
                }
            }
            rva = rva.saturating_add(8);
        }
    }
    if fill_added > 0 {
        info!(
            fill_scan_added = fill_added,
            total_candidates = candidate_scores.len(),
            "Added preferred-range fill-scan candidates"
        );
    }

    // Force-seed known critical AHK slots. RIP scan can miss a site for one
    // dump (p20: 0x148cb8 present live, captured in p19c, absent as candidate)
    // while a sibling gate (0x148cc0) still captures — half-planted pair AVs.
    //
    // R-GTO-UI (2026-07-24): policy hot roots are authoritative even when the
    // slot sits outside fill/.data. GTO title path `0x18a898` lives in a
    // Themida exec-named section (`.,\\W`, RX) — the old capture_ranges gate
    // dropped it, cold restart left the plant NULL, login GUI never appeared.
    let mut forced = 0usize;
    let mut forced_outside_fill_data = 0usize;
    for &rva in &policy.hot_root_rvas {
        let in_capture = capture_ranges.iter().any(|&(lo, hi)| rva >= lo && rva < hi);
        if !in_capture {
            forced_outside_fill_data = forced_outside_fill_data.saturating_add(1);
        }
        let entry = candidate_scores.entry(rva).or_insert(0);
        if *entry < 64 {
            *entry = 64; // at least moderate hotness so they order near front
            forced += 1;
        }
    }
    if forced > 0 {
        info!(
            forced_hot_slots = forced,
            forced_outside_fill_data,
            total_candidates = candidate_scores.len(),
            "Force-seeded known AHK hot-root RVAs into heap-global candidates"
        );
    }

    if candidate_scores.is_empty() {
        return (
            Vec::new(),
            Vec::new(),
            PreTruncParentAuthorityStore::default(),
        );
    }

    // Order by code-xref hotness first (critical .data roots like 0x141bf0),
    // then prefer fill slots over cold data, then lower RVA.
    let mut ordered: Vec<u32> = candidate_scores.keys().copied().collect();
    ordered.sort_by_key(|rva| {
        let preferred_hit = preferred.iter().any(|&(lo, hi)| *rva >= lo && *rva < hi);
        let data_hit = data_sec.iter().any(|&(lo, hi)| *rva >= lo && *rva < hi);
        let score = candidate_scores.get(rva).copied().unwrap_or(0);
        (
            std::cmp::Reverse(score),
            if preferred_hit {
                0u8
            } else if data_hit {
                1u8
            } else {
                2u8
            },
            *rva,
        )
    });

    let mut out: Vec<HeapGlobalSnapshot> = Vec::new();
    // Route T R0-B: dedicated authoritative slabs for admitted dangling-edge
    // allocations. Each dangling edge is its own real heap allocation (read
    // directly from the debuggee), surfaced as its own slab so its ProbeWindow
    // can be absorbed at runtime-rebase time.
    let mut dedicated_slabs: Vec<HeapSlab> = Vec::new();
    let mut total_bytes = 0usize;
    let mut rejected_not_heap = 0usize;
    let mut rejected_data = 0usize;
    let mut rejected_size = 0usize;
    let mut rejected_read = 0usize;
    let mut rejected_dup_heap = 0usize;
    let mut rejected_fill_only = 0usize;
    let mut rejected_cookie = 0usize;
    let mut heap_handle_slots = 0usize;
    let mut seen_heaps: BTreeSet<u64> = BTreeSet::new();
    let mut sample_rejected: Vec<(u32, u64)> = Vec::new();
    // Process-heap handles: plant GetProcessHeap at runtime, never snapshot HEAP.
    let mut process_heaps = enumerate_process_heap_handles(debugger);
    if process_heaps.is_empty() {
        debug!("PEB heap enumeration empty — falling back to HEAP signature probes");
    }

    for rva in ordered {
        // Roots only here; children/split use the remaining slot budget later.
        let root_count = out.iter().filter(|g| g.rva != 0).count();
        if root_count >= MAX_HEAP_GLOBAL_ROOT_SLOTS || out.len() >= MAX_HEAP_GLOBAL_SLOTS {
            warn!(
                max_roots = MAX_HEAP_GLOBAL_ROOT_SLOTS,
                max_total = MAX_HEAP_GLOBAL_SLOTS,
                "Heap-global root cap reached — further roots skipped (children reserved)"
            );
            break;
        }

        let in_preferred = preferred.iter().any(|&(lo, hi)| rva >= lo && rva < hi);
        let in_data = data_sec.iter().any(|&(lo, hi)| rva >= lo && rva < hi);
        let is_policy_hot = policy.is_hot_root(rva);
        // Fill/zero-raw always eligible (subject to xref/size filters).
        // .data only via code xref — early overlay zeros heap roots there.
        // Policy hot roots may sit in Themida code-named RX pages (R-GTO-UI).
        if !in_preferred && !in_data && !is_policy_hot {
            rejected_data += 1;
            continue;
        }

        if cookie_blocklist
            .iter()
            .any(|&(lo, hi)| rva >= lo && rva < hi)
        {
            rejected_cookie += 1;
            continue;
        }

        let xref = candidate_scores.get(&rva).copied().unwrap_or(0);
        // .data: require at least one code xref (no linear fill-scan of BSS).
        // Policy hot roots are force-scored above; skip the xref gate for them.
        if in_data && !in_preferred && xref == 0 && !is_policy_hot {
            rejected_data += 1;
            continue;
        }

        let value = read_slot_value(image_base, rva, dump_buf, debugger);
        if !is_heap_pointer(value, image_base, image_end) {
            rejected_not_heap += 1;
            if sample_rejected.len() < 8 {
                sample_rejected.push((rva, value));
            }
            continue;
        }

        if !seen_heaps.insert(value) {
            rejected_dup_heap += 1;
            continue;
        }

        // Interior of an already-captured block — multi_fixup covers it; a
        // second range with a different new_begin corrupts the graph.
        if range_contains(&out, value) {
            rejected_dup_heap += 1;
            seen_heaps.remove(&value);
            continue;
        }

        // Heap *handles* (GetProcessHeap / HeapCreate): the slot is used as
        // HeapAlloc's first argument. Snapshotting the HEAP struct and planting
        // a memcpy'd fake handle corrupts RtlEnterCriticalSection.
        if process_heaps.contains(&value) || looks_like_heap_handle(debugger, value) {
            process_heaps.insert(value);
            if rva == 0 {
                seen_heaps.remove(&value);
                continue;
            }
            info!(
                rva = format_args!("{rva:#x}"),
                heap = format_args!("{value:#x}"),
                xref,
                "Captured heap-handle slot (runtime GetProcessHeap plant)"
            );
            heap_handle_slots += 1;
            out.push(HeapGlobalSnapshot {
                rva,
                live_ptr: value,
                content: Vec::new(),
                is_heap_handle: true,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
            continue;
        }

        let probe_cap = if policy.gscript_root() == Some(rva) {
            // Match content cap so R-GTO-UI larger gscript snapshots are reachable.
            policy
                .gscript_content_cap()
                .max(HOT_XREF_SIZE_PROBE_CAP)
                .min(MAX_HEAP_GLOBAL_BYTES)
        } else if policy.is_large_table(rva)
            || (xref >= HOT_XREF_THRESHOLD && !policy.is_hot_root(rva))
        {
            HOT_XREF_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        } else if policy.is_hot_root(rva) {
            // Compact string / path objects — never 32 KiB free-list swallow.
            DEFAULT_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        } else if xref >= HOT_XREF_THRESHOLD {
            HOT_XREF_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        } else {
            DEFAULT_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        };
        let mut size = estimate_object_size(dump_buf, rva as usize, value, debugger, probe_cap);
        if size == 0 {
            rejected_size += 1;
            seen_heaps.remove(&value);
            if sample_rejected.len() < 12 {
                sample_rejected.push((rva, value));
            }
            continue;
        }

        // Prefer code-xref'd slots. Fill-scan-only small objects are noise that
        // reintroduce stale cross-block pointers after restore (RtlpFindEntry).
        if xref == 0 && size < MIN_FILL_ONLY_CAPTURE_BYTES {
            rejected_fill_only += 1;
            seen_heaps.remove(&value);
            continue;
        }

        // Shrink so we do not claim a range that overlaps another capture
        // (overlapping multi_fixup entries → heap corruption c0000374).
        size = shrink_to_avoid_overlap(&out, value, size);
        if size < 8 {
            rejected_dup_heap += 1;
            seen_heaps.remove(&value);
            continue;
        }

        // Reserve aggregate headroom for graph expansion children.
        if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_ROOT_BYTES {
            warn!(
                rva = format_args!("{rva:#x}"),
                size,
                total = total_bytes,
                root_cap = MAX_HEAP_GLOBAL_ROOT_BYTES,
                "Heap-global root size budget exhausted — remaining slots deferred to expand"
            );
            seen_heaps.remove(&value);
            break;
        }

        let mut content = match alloc_capped(
            size,
            MAX_HEAP_GLOBAL_BYTES.min(MAX_HEAP_CONTAINER_BYTES),
            "heap global",
        ) {
            Ok(buf) => buf,
            Err(e) => {
                warn!(
                    rva = format_args!("{rva:#x}"),
                    size,
                    error = %e,
                    "Skipped heap global: size rejected"
                );
                seen_heaps.remove(&value);
                continue;
            }
        };

        match debugger.read_memory(value as usize, &mut content) {
            Ok(n) if n >= 8 => {
                if n < content.len() {
                    content.truncate(n);
                }
            }
            Ok(_) | Err(_) => {
                rejected_read += 1;
                seen_heaps.remove(&value);
                continue;
            }
        }
        content = trim_trailing_zero_pages(content);
        content = truncate_to_avoid_overlap(&out, value, content);
        // p21: gscript must stay compact. HOT_LARGE_TABLE used to allow 32 KiB
        // and free-list neighbours polluted first-hop expand + scrub.
        if policy.gscript_root() == Some(rva) && content.len() > policy.gscript_content_cap() {
            content.truncate(policy.gscript_content_cap());
            info!(
                rva = format_args!("{rva:#x}"),
                cap = policy.gscript_content_cap(),
                "Capped gscript root snapshot to avoid free-list swallow"
            );
        }
        if content.len() < 8 {
            rejected_dup_heap += 1;
            seen_heaps.remove(&value);
            continue;
        }
        // Admit string buffer first so multi_fixup can remap shell→buf.
        // Only null the shell if the buffer could not be snapshotted.
        let root_slot_cap = MAX_HEAP_GLOBAL_SLOTS;
        handle_string_shell_on_capture(
            &mut content,
            &mut out,
            &mut total_bytes,
            &mut seen_heaps,
            image_base,
            image_end,
            dump_buf,
            debugger,
            root_slot_cap,
        );

        info!(
            rva = format_args!("{rva:#x}"),
            heap = format_args!("{value:#x}"),
            size = content.len(),
            xref,
            in_data,
            "Captured heap-global slot"
        );

        total_bytes = total_bytes.saturating_add(content.len());
        // Route S R0-B: main heap-global slot must carry a non-empty deterministic
        // capture identity (ObservedAllocation / MainSlot). Previously default()
        // produced empty capture_id which broke the Q0-C exact binding.
        out.push(HeapGlobalSnapshot {
            rva,
            live_ptr: value,
            content,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("mainslot:{rva:#x}:{value:#x}"),
                capture_path: CapturePath::MainSlot,
                source_root_rva: Some(rva),
                source_slot_offset: None,
                probe_requested_size: 0,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        });
    }

    // Guarantee known AHK pairs are planted even if the main loop skipped a
    // slot (live null on first pass, score/order race, or transient reject).
    // p20/p20b: 0x148cc0 captured, 0x148cb8 not → plant half pair → AV.
    ensure_hot_root_slots(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        &preferred,
        &data_sec,
        &cookie_blocklist,
        policy,
    );

    // R-GTO-UI r15: image-inline gscript MUST precede first-hop/expand.
    // Otherwise first-hop walks the mistaken heap clone (32KiB free-list),
    // then image-inline replaces the root with a different pointer layout;
    // WinMain `0x48fb0` label lookup on image gscript returns null (r14b).
    capture_image_inline_gscript(
        &mut out,
        &mut total_bytes,
        image_base,
        dump_buf,
        debugger,
        policy,
    );

    // p21: force-admit *every* heap pointer in gscript's first-hop span before
    // ranked expand. Ranked multi-hop was filling 160 slots with free-list
    // noise while scrub zeroed +0x10..+0xf8 (packed has 32 live edges).
    exhaust_gscript_first_hop(
        &mut out,
        &mut dedicated_slabs,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        policy,
    );

    // R-GTO-UI r16: gscript+0 object +0x18 next-link was interior of a 32KiB
    // free-list parent (0x148c00). exact-base multi_fixup left stale VA →
    // WinMain post-MB string walk hits process freelist (0x03500350 pattern)
    // at 0x57d01. Force-admit exact bases for AHK link fields on first-hop kids.
    exhaust_gscript_child_link_fields(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        policy,
    );

    // R-GTO-UI r17: synthesize label count *before* sanitize. sanitize used to
    // walk the gscript+0 pointer table as "object links" and null interior
    // label entries → count saw leading zeros and no-op'd (r16b).
    synthesize_gscript_label_count(&mut out);

    // Also force-admit every entry in the label pointer table so multi_fixup
    // can exact-base remap and sanitize will not null them as interiors.
    exhaust_gscript_label_table_entries(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        policy,
    );

    // After link force-admit: null remaining uncaptured link targets that are
    // only interiors of oversized free-list parents (cannot exact-remap).
    // Skips dense pointer tables (label/cmd arrays).
    sanitize_dangling_object_links(&mut out, image_base, image_end);

    // R-GTO-UI r17b: re-synthesize AFTER sanitize. Live image body may hold a
    // heap pointer whose low dword looks like count (e.g. 334) at +0x10; sanitize
    // then zeros the whole qword → PE payload count=0 (r17). Force count from
    // the exact-captured label table after all nulling.
    synthesize_gscript_label_count(&mut out);

    // R-GTO-UI r14: main loop often RPM-probes 0x147868 to 32KiB (free-list
    // swallow). Resize to live count@0x147888 * 8 *before* first-hop so we do
    // not admit garbage edges past the real table → post-MB c0000374.
    if sample_active {
        normalize_cmd_table_capture(&mut out, &mut total_bytes, dump_buf, debugger);
    }

    // MIDA-SERIAL-25: the inline first-hop calls are centralized as
    // explicit identity-bound sample roles ([`declared_first_hop_roles`]:
    // 0x147868 count-scaled table + 0x141bf0 bounded field window).
    // Activation remains identity-gated (sample_active) and
    // capture-corroborated: density / size / section placement / user-heap
    // pointer are filters only; hot-root / large-table policy nominations
    // never self-activate. This does NOT eliminate sample-specific RVA
    // coupling — the roles carry sample-bound RVAs and layout facts.
    // Unbound/mismatch/revision-0/digest-mismatch policies never run
    // first-hop (fail-closed). Missing or ambiguous evidence also fails
    // closed (no fabricated children, no slot/region expansion).
    if sample_active {
        match derive_first_hop_candidates(&pe, &out, policy, image_base, image_end, dump_buf) {
            FirstHopCandidateResolution::Resolved(cands) => {
                exhaust_first_hop_candidates(
                    &mut out,
                    &mut total_bytes,
                    &mut seen_heaps,
                    image_base,
                    image_end,
                    dump_buf,
                    debugger,
                    &cands,
                );
            }
            FirstHopCandidateResolution::Missing => {
                info!(
                    "MIDA-SERIAL-25: first-hop skipped — no identity-bound role with capture corroboration"
                );
            }
            FirstHopCandidateResolution::Ambiguous => {
                warn!("MIDA-SERIAL-25: first-hop skipped — ambiguous candidates (same live table body or conflicting extents)");
            }
        }
    }

    // Then: multi-hop from hot gscript roots (bounded) so title / string-table
    // edges beyond first hop are not starved by cold high-VA free-list noise.
    expand_hot_root_children(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        policy,
    );

    // Pull in sibling objects referenced from captured blobs so multi-range
    // fixup can remap them instead of scrubbing to NULL (stale dump AVs).
    expand_heap_graph(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        policy,
    );

    // Oversized RPM probes often swallow neighbouring heap chunks. multi_fixup
    // then remaps freeable leaf pointers to *interior* addresses → HeapFree
    // c0000374 (e.g. path-string buffer inside a 2 KiB false parent).
    // MIDA-SERIAL-35: the split producer also emits PRE-TRUNC parent authority
    // evidence (full bytes) so the closure helper can build a closure authority
    // from the real pre-trunc bytes after the parent is truncated.
    // MIDA-SERIAL-37: the authority STORE owns the full pre-trunc bytes
    // (one copy per parent identity); bindings carry only the key.
    let mut pre_trunc_authority = PreTruncParentAuthorityStore::default();
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        &mut pre_trunc_authority,
        image_base,
        image_end,
        dump_buf,
        debugger,
    );

    // After free-safe splits, parents are shorter and many leaf bases are exact
    // snapshots. A second expand reaches AHK title/control objects that were
    // previously scrubbed (p18b: scrubbed_qwords≈5540, login title missing).
    expand_heap_graph(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        policy,
    );

    // Last-chance: any still-external heap edge that is readable live is
    // captured instead of scrubbed. p19 showed plant OK then AV at +0xdafa4
    // writing [rax=0x28] — classic null-object field after scrub zeroed a
    // gscript edge that AHK still walks during auto-exec.
    capture_dangling_edges(
        &mut out,
        &mut dedicated_slabs,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        policy,
    );

    // R-GTO-UI r19: drop AHK SimpleHeap bump-allocator control slots so cold
    // start re-inits a fresh 64KiB arena (0xb94a0) instead of replaying an
    // exhausted dump-time block (WinMain 0xb9360 alloc fail → AV).
    if sample_active {
        drop_ahk_string_arena_slots(&mut out, &mut total_bytes);
    }

    // multi_fixup first-match: prefer smaller/exact ranges over large parents.
    out.sort_by(|a, b| {
        a.content
            .len()
            .cmp(&b.content.len())
            .then_with(|| a.live_ptr.cmp(&b.live_ptr))
    });

    if out.is_empty() {
        info!(
            rejected_not_heap,
            rejected_data,
            rejected_size,
            rejected_read,
            rejected_dup_heap,
            rejected_fill_only,
            rejected_cookie,
            "No heap-global slots captured after filtering"
        );
        for (rva, val) in sample_rejected.iter().take(8) {
            debug!(
                rva = format_args!("{rva:#x}"),
                value = format_args!("{val:#x}"),
                "heap-global reject sample"
            );
        }
    } else {
        let graph_children = out.iter().filter(|g| g.rva == 0).count();
        info!(
            count = out.len(),
            graph_children,
            heap_handle_slots,
            total_bytes = out.iter().map(|g| g.content.len()).sum::<usize>(),
            rejected_fill_only,
            rejected_cookie,
            "Detected heap-global slots requiring post-CRT restore"
        );
    }
    // R0-E note: duplicate live_ptr reconciliation runs in dump_process AFTER
    // the raw slab is captured, so raw-slab coherence can be used as the
    // authoritative tiebreaker (the slab is the physical-memory ground truth).
    // MIDA-SERIAL-35: the pre-trunc authority evidence (full parent bytes)
    // flows out of the production capture into build_authority_closure_candidates.
    (out, dedicated_slabs, pre_trunc_authority)
}

/// Reconcile duplicate raw snapshots of the same physical heap allocation.
///
/// R0-E: the same `live_ptr` can be admitted by several capture paths (main
/// slot scan, gscript first-hop, child-link force-admit, string-buffer
/// admission, dangling edges). All snapshots of one address describe the SAME
/// physical heap object (a heap address is unique). Keeping two entries with
/// the same old_base but differing bytes trips the overlay `OverlayConflict`.
///
/// Reconciliation rule (deterministic, not last-write-wins / first-pick):
/// 1. Identical bytes → exact duplicate, keep one.
/// 2. Differing bytes → the authoritative snapshot is the one whose RAW bytes
///    match the raw slab slice at `[live_ptr - slab.old_base, ...)`, i.e. the
///    capture coherent with the physical memory read. The raw slab is the
///    ground truth captured from the debuggee.
/// 3. If no duplicate matches the raw slab slice (both drifted), keep the
///    larger snapshot (most complete read); on an exact size tie with differing
///    bytes and neither raw-coherent, this is unresolvable capture drift and
///    the duplicate is retained so the overlay fail-closes with provenance.
///
/// Must run on RAW snapshots (before transforms) so raw-coherence with the slab
/// is meaningful.
///
/// Record which children a transform actually modified (GTO R0-F.1 per-child
/// transform provenance). Compares each child's content before/after the
/// transform and appends `transform_id` to the `transform_ids` of every child
/// whose bytes changed. Unchanged children are never claimed as writers.
pub fn record_transform_applied(
    heap_globals: &mut [HeapGlobalSnapshot],
    before: &[HeapGlobalSnapshot],
    transform_id: &str,
) {
    for (g, b) in heap_globals.iter_mut().zip(before.iter()) {
        if g.live_ptr == b.live_ptr && g.content != b.content {
            g.transform_ids.push(transform_id.to_string());
        }
    }
}

/// Read the gscript label-table count without ever indexing a short image
/// inline body. The field occupies `[0x10..0x14)`; a shorter body is
/// incomplete input and must fail closed.
fn gscript_label_count(content: &[u8]) -> Option<usize> {
    let bytes = content.get(0x10..GSCRIPT_LABEL_COUNT_END)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?) as usize)
}

pub fn reconcile_duplicate_heap_globals(
    out: &mut Vec<HeapGlobalSnapshot>,
    raw_slab: Option<&HeapSlab>,
) {
    let mut by_base: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
    let mut keep = Vec::with_capacity(out.len());
    let mut dropped = 0usize;
    let mut drift_retained = 0usize;
    for g in out.iter() {
        if g.is_heap_handle || g.content.is_empty() {
            // Handle slots and empty placeholders are not coalesced by address.
            keep.push(g.clone());
            continue;
        }
        match by_base.get(&g.live_ptr) {
            Some(&existing_idx) => {
                let existing = keep[existing_idx].clone();
                // Identical bytes → true redundant capture; keep one.
                if existing.content == g.content
                    && existing.is_heap_handle == g.is_heap_handle
                    && existing.is_image_inline == g.is_image_inline
                {
                    dropped += 1;
                    continue;
                }
                // Differing bytes: resolve by raw-slab coherence when available.
                let existing_coh = raw_slab.and_then(|s| {
                    let off = g.live_ptr.checked_sub(s.old_base)?;
                    let off = usize::try_from(off).ok()?;
                    let slice = s.content.get(off..off + existing.content.len())?;
                    (slice == existing.content.as_slice()).then_some(true)
                });
                let g_coh = raw_slab.and_then(|s| {
                    let off = g.live_ptr.checked_sub(s.old_base)?;
                    let off = usize::try_from(off).ok()?;
                    let slice = s.content.get(off..off + g.content.len())?;
                    (slice == g.content.as_slice()).then_some(true)
                });
                match (existing_coh, g_coh) {
                    (Some(true), _) => {
                        // Existing entry is coherent with the slab → keep it.
                        dropped += 1;
                    }
                    (_, Some(true)) => {
                        // New entry is coherent with the slab → replace.
                        keep[existing_idx] = g.clone();
                        dropped += 1;
                    }
                    _ => {
                        // Neither is provably coherent. Prefer the larger read;
                        // on an exact tie keep the existing (deterministic) but
                        // retain both if bytes differ and neither matches —
                        // the overlay fail-closes with provenance rather than
                        // silently choosing a conflicting snapshot.
                        if g.content.len() > existing.content.len() {
                            keep[existing_idx] = g.clone();
                            dropped += 1;
                        } else if g.content.len() == existing.content.len() {
                            drift_retained += 1;
                            // keep both so the overlay reports the conflict
                            // with full provenance instead of silently picking.
                            by_base.insert(g.live_ptr, keep.len());
                            keep.push(g.clone());
                        } else {
                            dropped += 1;
                        }
                    }
                }
            }
            None => {
                by_base.insert(g.live_ptr, keep.len());
                keep.push(g.clone());
            }
        }
    }
    if dropped > 0 || drift_retained > 0 {
        info!(
            before = out.len(),
            after = keep.len(),
            dropped,
            drift_retained,
            "R0-E: reconciled duplicate raw heap-global captures at the same live_ptr"
        );
    }
    *out = keep;
}

/// Route Y R1 GTO R1 (no-bypass resume): retroactively trim overlapping
/// heap-global capture windows so adjacent objects never both claim the same
/// slab bytes.
///
/// Why this is needed: `cap_size_before_next_base` only bounds a NEW capture
/// by the higher bases already in `out` at admission time. Two admission paths
/// (gscript child-link force-admit and label-table entry exhaust) can admit
/// adjacent heap objects in an order where the earlier, lower capture's window
/// already extends past the later neighbor's base. Example (fresh no-bypass
/// capture of the protected input): label at `0x882ad0` admitted via
/// child-link force-admit with a 0x400 window [0x882ad0,0x882ed0), then label at
/// `0x882e18` admitted via label-table exhaust with window [0x882e18,0x883218).
/// The windows overlap [0x882e18,0x882ed0); the raw-slab overlay fail-closes
/// with a transformed write conflict (scrub_uncaptured_heap_pointers and
/// mark_labels_non_nested both write the shared byte at absolute 0x882e3b).
///
/// The fix is a general capture normalization, not a sample-specific patch:
/// for every pair of non-handle heap globals whose windows overlap, the
/// lower-address capture is trimmed to end at the higher-address capture's
/// base (the higher capture is the later-discovered, canonical object start).
/// Deterministic: process by ascending live_ptr; only shrink, never grow, never
/// reject. A capture trimmed below 8 bytes (or below the size the transform
/// needs) is dropped by the caller's existing filters downstream.
///
/// The raw-window exception is metadata-driven: a main-slot capture that records
/// an observed allocation with the full hot probe window is the declared-size
/// reinitialization class. No sample RVA or absolute image address is involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapGlobalWindowTrimPolicy {
    /// Keep declared-size reinitialization windows intact while trimming their
    /// neighbors. Disable only for callers that intentionally discard that raw
    /// preimage before the reinit transform runs.
    pub preserve_declared_size_windows: bool,
}

impl Default for HeapGlobalWindowTrimPolicy {
    fn default() -> Self {
        Self {
            preserve_declared_size_windows: true,
        }
    }
}

fn is_declared_size_window(g: &HeapGlobalSnapshot) -> bool {
    g.extent_kind == CaptureExtentKind::ObservedAllocation
        && g.extent_evidence.capture_path == CapturePath::MainSlot
        && g.extent_evidence.source_root_rva == Some(g.rva)
        && g.content.len() == HOT_XREF_SIZE_PROBE_CAP
}

pub fn trim_overlapping_heap_global_windows(out: &mut Vec<HeapGlobalSnapshot>) -> usize {
    trim_overlapping_heap_global_windows_with_policy(out, &HeapGlobalWindowTrimPolicy::default())
}
/// Trim overlapping heap-global windows under explicit capture policy.
pub fn trim_overlapping_heap_global_windows_with_policy(
    out: &mut Vec<HeapGlobalSnapshot>,
    policy: &HeapGlobalWindowTrimPolicy,
) -> usize {
    if out.len() < 2 {
        return 0;
    }
    let mut trimmed = 0usize;
    // Deterministic ascending base order; stable for equal bases (handles /
    // image-inline are skipped below anyway).
    let mut order: Vec<usize> = (0..out.len()).collect();
    order.sort_by_key(|&i| out[i].live_ptr);
    for pos in 0..order.len() {
        let i = order[pos];
        if out[i].is_heap_handle || out[i].is_image_inline || out[i].content.is_empty() {
            continue;
        }
        // A declared-size reinit consumes the raw preimage before replacing the
        // body. Preserve that semantic window; its neighbors remain trimmable.
        if policy.preserve_declared_size_windows && is_declared_size_window(&out[i]) {
            continue;
        }
        let a_start = out[i].live_ptr;
        let Some(a_end) = a_start.checked_add(out[i].content.len() as u64) else {
            // An overflowing range cannot be normalized safely. Fail closed.
            continue;
        };
        // Look at every later (higher or equal) capture for an interior base.
        for &j in &order[pos + 1..] {
            if out[j].is_heap_handle || out[j].is_image_inline || out[i].content.is_empty() {
                continue;
            }
            // Any later object base inside A is a legitimate canonical boundary;
            // only the explicitly protected raw window itself is exempt above.
            let b_start = out[j].live_ptr;
            if b_start <= a_start {
                continue;
            }
            if b_start < a_end {
                // B's base is interior to A's window: trim A to end at B.
                let new_len = usize::try_from(b_start - a_start).unwrap_or(out[i].content.len());
                if new_len < out[i].content.len() {
                    out[i].content.truncate(new_len);
                    trimmed += 1;
                }
                break; // A now ends at the nearest higher base; done with A.
            }
        }
    }
    if trimmed > 0 {
        info!(
            trimmed,
            "R1: trimmed overlapping heap-global capture windows (retroactive next-base cap)"
        );
    }
    trimmed
}

/// Capture AHK `g_script` as an in-image object body.
///
/// Live dump often has a heap pointer in the first qword of `.data@gscript`,
/// so the main loop classifies it as a pointer slot and plants a heap clone.
/// Product code uses `lea rcx,[gscript]` and reads fields at `+0xbd8` etc.
/// from the **image** object — the heap clone never receives those stores.
fn capture_image_inline_gscript(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    image_base: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) {
    let Some(gscript_rva) = policy.gscript_root() else {
        return;
    };
    if gscript_rva == 0 {
        return;
    }

    // Drop the mistaken pointer-slot capture of the same RVA (if any).
    if let Some(idx) = out
        .iter()
        .position(|g| g.rva == gscript_rva && !g.is_image_inline)
    {
        let removed = out.remove(idx);
        *total_bytes = total_bytes.saturating_sub(removed.content.len());
        info!(
            rva = format_args!("{gscript_rva:#x}"),
            old_live = format_args!("{:#x}", removed.live_ptr),
            old_size = removed.content.len(),
            "Replacing gscript pointer-slot capture with image-inline body"
        );
    } else if out
        .iter()
        .any(|g| g.rva == gscript_rva && g.is_image_inline)
    {
        return;
    }

    let live_va = image_base.saturating_add(gscript_rva as u64);
    // Need at least through the title/class field used by RegisterClass path
    // (`[g_script+0xbd8]`). Cap by policy + remaining image dump bytes.
    // Hard-cap to the host section's virtual size so image-inline memcpy never
    // walks past `.data` (r11 AV: 0x149d50+0x8000 > .data end 0x14ca74).
    let section_remain = {
        let mut rem = 0usize;
        // walk dump_buf PE sections via simple PE parse of dump_buf itself
        if dump_buf.len() > 0x40 {
            let e_lfanew =
                u32::from_le_bytes(dump_buf[0x3c..0x40].try_into().unwrap_or_default()) as usize;
            if e_lfanew + 24 < dump_buf.len() {
                let nsec = u16::from_le_bytes(
                    dump_buf[e_lfanew + 6..e_lfanew + 8]
                        .try_into()
                        .unwrap_or_default(),
                ) as usize;
                let so = u16::from_le_bytes(
                    dump_buf[e_lfanew + 20..e_lfanew + 22]
                        .try_into()
                        .unwrap_or_default(),
                ) as usize;
                let sec0 = e_lfanew + 24 + so;
                for i in 0..nsec {
                    let o = sec0 + i * 40;
                    if o + 40 > dump_buf.len() {
                        break;
                    }
                    let va =
                        u32::from_le_bytes(dump_buf[o + 12..o + 16].try_into().unwrap_or_default());
                    let vsz =
                        u32::from_le_bytes(dump_buf[o + 8..o + 12].try_into().unwrap_or_default());
                    if gscript_rva >= va && gscript_rva < va.saturating_add(vsz.max(1)) {
                        rem = va.saturating_add(vsz).saturating_sub(gscript_rva) as usize;
                        break;
                    }
                }
            }
        }
        rem
    };
    let min_need = 0xC00usize;
    let mut cap = policy
        .gscript_content_cap()
        .max(min_need)
        .min(MAX_HEAP_GLOBAL_BYTES);
    if section_remain > 0 {
        cap = cap.min(section_remain);
    }
    let mut size = 0usize;
    for &probe in &SIZE_PROBES {
        if probe > cap {
            break;
        }
        if can_read(debugger, live_va, probe, cap) {
            size = probe;
        } else {
            break;
        }
    }
    if size < min_need {
        // Fall back to dump_buf image bytes if live RPM is short.
        let off = gscript_rva as usize;
        if off < dump_buf.len() {
            let avail = dump_buf.len().saturating_sub(off).min(cap);
            if avail >= min_need {
                size = avail;
            }
        }
    }
    if size < min_need {
        warn!(
            rva = format_args!("{gscript_rva:#x}"),
            size, "gscript image-inline capture too small; leaving without inline body"
        );
        return;
    }

    let Ok(mut content) = alloc_capped(size, cap, "gscript image-inline") else {
        return;
    };
    let mut got = 0usize;
    match debugger.read_memory(live_va as usize, &mut content) {
        Ok(n) => got = n,
        Err(e) => {
            warn!(
                rva = format_args!("{gscript_rva:#x}"),
                err = %e,
                "gscript image-inline live read failed; trying dump_buf"
            );
        }
    }
    if got < min_need {
        let off = gscript_rva as usize;
        if off + min_need <= dump_buf.len() {
            let n = size.min(dump_buf.len() - off);
            content[..n].copy_from_slice(&dump_buf[off..off + n]);
            got = n;
        }
    }
    if got < min_need {
        warn!(
            rva = format_args!("{gscript_rva:#x}"),
            got, "gscript image-inline capture failed"
        );
        return;
    }
    content.truncate(got);
    // Drop only trailing zero runs beyond min_need (object has sparse fields).
    while content.len() > min_need {
        let new_len = content.len() - 16;
        if content[new_len..].iter().all(|&b| b == 0) {
            content.truncate(new_len);
        } else {
            break;
        }
    }

    *total_bytes = total_bytes.saturating_add(content.len());
    info!(
        rva = format_args!("{gscript_rva:#x}"),
        live = format_args!("{live_va:#x}"),
        size = content.len(),
        "Captured gscript image-inline object body"
    );
    out.push(HeapGlobalSnapshot {
        rva: gscript_rva,
        live_ptr: live_va,
        content,
        is_heap_handle: false,
        is_image_inline: true,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    });
}

/// Second-chance capture for policy hot roots missing after the main pass.
fn ensure_hot_root_slots(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    preferred: &[(u32, u32)],
    data_sec: &[(u32, u32)],
    cookie_blocklist: &[(u32, u32)],
    policy: &DumpCapturePolicy,
) {
    for &rva in policy.hot_root_rvas.iter() {
        if out.iter().any(|g| g.rva == rva) {
            continue;
        }
        let in_preferred = preferred.iter().any(|&(lo, hi)| rva >= lo && rva < hi);
        let in_data = data_sec.iter().any(|&(lo, hi)| rva >= lo && rva < hi);
        // R-GTO-UI: do not skip policy hot roots that live outside fill/.data.
        // Example: GTO title object at 0x18a898 in Themida section `.,\\W` (RX).
        // Capture + plant still work; section WRITE is applied separately.
        if !in_preferred && !in_data {
            info!(
                rva = format_args!("{rva:#x}"),
                "Hot-root ensure: RVA outside fill/.data — capturing by policy"
            );
        }
        if cookie_blocklist
            .iter()
            .any(|&(lo, hi)| rva >= lo && rva < hi)
        {
            continue;
        }

        let value = read_slot_value(image_base, rva, dump_buf, debugger);
        if !is_heap_pointer(value, image_base, image_end) {
            warn!(
                rva = format_args!("{rva:#x}"),
                value = format_args!("{value:#x}"),
                "Hot-root ensure failed: live slot not a heap pointer"
            );
            continue;
        }
        if seen_heaps.contains(&value) || range_contains(out, value) {
            // Same heap already snapshotted under another slot — still plant
            // this RVA so AHK string-table pair is not half-null.
            if process_heaps_or_handle(debugger, value) {
                warn!(
                    rva = format_args!("{rva:#x}"),
                    heap = format_args!("{value:#x}"),
                    "Hot-root ensure: value is heap handle — planting GetProcessHeap"
                );
                out.push(HeapGlobalSnapshot {
                    rva,
                    live_ptr: value,
                    content: Vec::new(),
                    is_heap_handle: true,
                    is_image_inline: false,
                    extent_kind: CaptureExtentKind::default(),
                    extent_evidence: CaptureExtentEvidence::default(),
                    transform_ids: Vec::new(),
                    provenance: RegionProvenance::default(),
                });
                continue;
            }
            // Share the existing content range: plant-only entry with empty
            // content is wrong (multi_fixup needs bytes). Re-read a modest
            // probe exclusive of the overlapping parent by shrinking.
            info!(
                rva = format_args!("{rva:#x}"),
                heap = format_args!("{value:#x}"),
                "Hot-root ensure: heap already snapshotted — plant-only alias via re-read"
            );
        }
        if looks_like_heap_handle(debugger, value) {
            info!(
                rva = format_args!("{rva:#x}"),
                heap = format_args!("{value:#x}"),
                "Hot-root ensure: heap-handle plant"
            );
            out.push(HeapGlobalSnapshot {
                rva,
                live_ptr: value,
                content: Vec::new(),
                is_heap_handle: true,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
            continue;
        }

        let ensure_probe = if policy.is_large_table(rva) {
            HOT_XREF_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        } else {
            DEFAULT_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        };
        let mut size = estimate_object_size(dump_buf, rva as usize, value, debugger, ensure_probe);
        // R-GTO-UI r13: AHK cmd table has live count dword at slot+0x20
        // (0x147888). Prefer count*8 over RPM ladder (ladder swallows
        // free-list → unreadable first qword after plant / AV @0x5747a).
        let cmd_role = CountScaledPointerRole::cmd_table();
        if cmd_role.is_slot(rva) {
            if let CountScaledExtent::Established {
                extent: want,
                count,
            } = cmd_role.derive_extent(dump_buf)
            {
                if can_read(debugger, value, want, HOT_XREF_SIZE_PROBE_CAP) {
                    info!(
                        rva = format_args!("{rva:#x}"),
                        count,
                        size = want,
                        "Hot-root ensure: cmd table sized from live count"
                    );
                    size = want;
                }
            }
        }
        if size < 8 {
            // Fall back to a small fixed probe — string capacity objects are
            // often 0x20–0x40; size field heuristics can miss them.
            size = if can_read(debugger, value, 0x40, 0x1000) {
                0x40
            } else if can_read(debugger, value, 0x20, 0x1000) {
                0x20
            } else {
                warn!(
                    rva = format_args!("{rva:#x}"),
                    heap = format_args!("{value:#x}"),
                    "Hot-root ensure failed: unreadable object"
                );
                continue;
            };
        }
        size = shrink_to_avoid_overlap(out, value, size);
        if size < 8 {
            // R-GTO-UI r13: interior of an oversized parent (e.g. cmd table
            // 0x147868 @ 0x92ecb0 inside gscript heap 32KiB). multi_fixup is
            // exact-base only, so plant-only 8B leaves the table unrebased and
            // WinMain AVs. Carve the parent to end at this base, then capture
            // the full exclusive object below.
            if carve_parent_at_hot_base(out, value) {
                size = estimate_object_size(dump_buf, rva as usize, value, debugger, ensure_probe);
                if cmd_role.is_slot(rva) {
                    if let CountScaledExtent::Established { extent: want, .. } =
                        cmd_role.derive_extent(dump_buf)
                    {
                        if can_read(debugger, value, want, HOT_XREF_SIZE_PROBE_CAP) {
                            size = want;
                        }
                    }
                }
                if size < 8 {
                    size = if can_read(debugger, value, 0x1000, HOT_XREF_SIZE_PROBE_CAP) {
                        0x1000
                    } else if can_read(debugger, value, 0x100, 0x1000) {
                        0x100
                    } else if can_read(debugger, value, 0x40, 0x1000) {
                        0x40
                    } else {
                        0
                    };
                }
                size = shrink_to_avoid_overlap(out, value, size);
                info!(
                    rva = format_args!("{rva:#x}"),
                    heap = format_args!("{value:#x}"),
                    size,
                    "Hot-root ensure: carved parent — exclusive capture"
                );
            }
        }
        if size < 8 {
            // Still overlapping (exact-base sibling): plant-only 8B last resort.
            let mut tiny = vec![0u8; 8];
            if debugger
                .read_memory(value as usize, &mut tiny)
                .ok()
                .filter(|&n| n >= 8)
                .is_none()
            {
                warn!(
                    rva = format_args!("{rva:#x}"),
                    heap = format_args!("{value:#x}"),
                    "Hot-root ensure failed: overlap and 8-byte re-read failed"
                );
                continue;
            }
            seen_heaps.insert(value);
            info!(
                rva = format_args!("{rva:#x}"),
                heap = format_args!("{value:#x}"),
                "Hot-root ensure: plant alias (overlap, 8-byte body)"
            );
            out.push(HeapGlobalSnapshot {
                rva,
                live_ptr: value,
                content: tiny,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence {
                    capture_id: format!("plant_alias:{value:#x}"),
                    capture_path: CapturePath::MainSlot,
                    source_root_rva: None,
                    source_slot_offset: None,
                    probe_requested_size: 0,
                    was_interior: false,
                    containing_parent_old_base: None,
                    containing_parent_size: None,
                },
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
            continue;
        }
        if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
            warn!(
                rva = format_args!("{rva:#x}"),
                size, "Hot-root ensure failed: total byte cap"
            );
            continue;
        }
        let Ok(mut content) = alloc_capped(
            size,
            MAX_HEAP_GLOBAL_BYTES.min(MAX_HEAP_CONTAINER_BYTES),
            "hot root ensure",
        ) else {
            continue;
        };
        match debugger.read_memory(value as usize, &mut content) {
            Ok(n) if n >= 8 => {
                if n < content.len() {
                    content.truncate(n);
                }
            }
            _ => {
                warn!(
                    rva = format_args!("{rva:#x}"),
                    heap = format_args!("{value:#x}"),
                    "Hot-root ensure failed: RPM"
                );
                continue;
            }
        }
        // Cmd/dispatch table is a dense pointer array sized by count*8; trailing
        // zero slots are valid empty entries, not free-list padding to trim.
        if !cmd_role.is_slot(rva) {
            content = trim_trailing_zero_pages(content);
        }
        content = truncate_to_avoid_overlap(out, value, content);
        if policy.gscript_root() == Some(rva) && content.len() > policy.gscript_content_cap() {
            content.truncate(policy.gscript_content_cap());
        }
        if content.len() < 8 {
            continue;
        }
        if !cmd_role.is_slot(rva) {
            handle_string_shell_on_capture(
                &mut content,
                out,
                total_bytes,
                seen_heaps,
                image_base,
                image_end,
                dump_buf,
                debugger,
                MAX_HEAP_GLOBAL_SLOTS,
            );
        }
        seen_heaps.insert(value);
        *total_bytes = total_bytes.saturating_add(content.len());
        info!(
            rva = format_args!("{rva:#x}"),
            heap = format_args!("{value:#x}"),
            size = content.len(),
            "Hot-root ensure captured missing critical slot"
        );
        out.push(HeapGlobalSnapshot {
            rva,
            live_ptr: value,
            content,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("hotroot_ensure:{value:#x}"),
                capture_path: CapturePath::MainSlot,
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: 0,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        });
    }
}

fn process_heaps_or_handle(debugger: &mut dyn mida_core::DebuggerCore, value: u64) -> bool {
    looks_like_heap_handle(debugger, value)
}

/// Force-admit every heap pointer in the first `policy.first_hop_span()` of the
/// gscript root blob, in offset order (no rank-by-VA). p20f scored
/// `heap_ptrs=2` at runtime on `0x149d50` vs packed `32` — ranked expand
/// burned the slot budget on free-list neighbours while scrub zeroed the
/// real first-hop edges that AHK walks during auto-exec / login GUI.
///
/// p21: also **split interiors**. Large table roots (32 KiB probes) often
/// swallow gscript first-hop children; skipping those as `range_contains`
/// left multi_fixup remapping edges to *unrelated* parent interiors → AHK
/// frees gscript and leaves `0x149d50=0` (p21 runtime).
fn exhaust_gscript_first_hop(
    out: &mut Vec<HeapGlobalSnapshot>,
    dedicated_slabs: &mut Vec<HeapSlab>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) {
    // Reserve room for later expand/dangling; still admit up to ~64 first-hops.
    let slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE / 2);
    let Some(gscript_rva) = policy.gscript_root() else {
        return;
    };
    let Some(gscript_idx) = out
        .iter()
        .position(|g| g.rva == gscript_rva && !g.is_heap_handle && g.content.len() >= 8)
    else {
        warn!(
            rva = format_args!("{gscript_rva:#x}"),
            "gscript first-hop exhaust skipped: root not captured"
        );
        return;
    };

    // Collect first-hop targets (including interiors of other captures).
    // R-GTO-UI r15: image-inline g_script body needs a wider hop than the
    // heap-clone default (0x200). Label/var tables sit past +0x200; short span
    // → WinMain 0x48fb0 lookup returns null after MessageBox.
    let default_span = policy.first_hop_span();
    let span = if out[gscript_idx].is_image_inline {
        out[gscript_idx].content.len().min(0x1800.max(default_span))
    } else {
        default_span.min(out[gscript_idx].content.len())
    };
    let mut targets: Vec<(usize, u64)> = Vec::new();
    let content = &out[gscript_idx].content[..span];
    let mut off = 0usize;
    while off + 8 <= content.len() {
        let v = u64::from_le_bytes(content[off..off + 8].try_into().unwrap_or_default());
        off += 8;
        // First-hop edges can sit slightly below MIN_GRAPH_CHILD (script
        // objects in the low MiB). Use MIN_HEAP_POINTER for this pass only.
        if !is_heap_pointer(v, image_base, image_end) || v < MIN_HEAP_POINTER {
            continue;
        }
        if v >= 0x1_0000_0000 {
            continue;
        }
        // Already an exact freeable snapshot — multi_fixup will remap correctly.
        if is_exact_live_ptr(out, v) {
            continue;
        }
        targets.push((off - 8, v));
    }
    if targets.is_empty() {
        info!(
            span,
            "gscript first-hop exhaust: no external heap edges in span"
        );
        return;
    }

    let mut added = 0usize;
    let mut interior = 0usize;
    let mut skipped = 0usize;
    for (edge_off, value) in targets {
        if out.len() >= slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            skipped += 1;
            continue;
        }
        if is_exact_live_ptr(out, value) {
            skipped += 1;
            continue;
        }
        if looks_like_heap_handle(debugger, value) {
            skipped += 1;
            continue;
        }
        let was_interior = range_contains(out, value);
        // Interior of a large parent is OK: we still snapshot at the exact base.
        // multi_fixup is exact-base-only (p21h), so parent interiors never steal
        // remaps from exact children. Do NOT truncate parents (p21b cut large
        // tables → thr=4 and no GUI).
        seen_heaps.insert(value);
        let mut size = estimate_object_size(
            dump_buf,
            usize::MAX,
            value,
            debugger,
            policy.first_hop_probe().min(MAX_HEAP_GLOBAL_BYTES),
        );
        if size < 8 {
            seen_heaps.remove(&value);
            skipped += 1;
            continue;
        }
        // Cap so we do not extend into a later exact base; allow interior bases
        // (unlike shrink_to_avoid_overlap which returns 0 for interiors).
        size = cap_size_before_next_base(out, value, size);
        if size < 8 {
            seen_heaps.remove(&value);
            skipped += 1;
            continue;
        }
        if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
            seen_heaps.remove(&value);
            skipped += 1;
            break;
        }
        let Ok(mut child) = alloc_capped(
            size,
            policy.first_hop_probe().min(MAX_HEAP_CONTAINER_BYTES),
            "gscript first-hop child",
        ) else {
            seen_heaps.remove(&value);
            skipped += 1;
            continue;
        };
        match debugger.read_memory(value as usize, &mut child) {
            Ok(n) if n >= 8 => {
                if n < child.len() {
                    child.truncate(n);
                }
            }
            _ => {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            }
        }
        child = trim_trailing_zero_pages(child);
        // Only trim trailing overlap with a later base — never reject interiors.
        let cap = cap_size_before_next_base(out, value, child.len());
        if cap < child.len() {
            child.truncate(cap);
        }
        if child.len() < 8 {
            seen_heaps.remove(&value);
            skipped += 1;
            continue;
        }
        handle_string_shell_on_capture(
            &mut child,
            out,
            total_bytes,
            seen_heaps,
            image_base,
            image_end,
            dump_buf,
            debugger,
            slot_cap,
        );
        if was_interior {
            interior += 1;
        }
        info!(
            heap = format_args!("{value:#x}"),
            size = child.len(),
            gscript_off = format_args!("{edge_off:#x}"),
            interior = was_interior,
            "Captured gscript first-hop edge (force-admit)"
        );
        *total_bytes = total_bytes.saturating_add(child.len());
        // GTO R0-F.1: classify this first-hop capture. If it landed inside an
        // already-captured object it is an InteriorSubview; otherwise it is a
        // ProbeWindow (estimate_object_size returned a probe, no boundary proof).
        // Neither may become an independent heap allocation (normalize_containment
        // absorbs them into the slab or fails closed).
        let containing_parent = if was_interior {
            out.iter()
                .find(|o| {
                    !o.is_heap_handle
                        && !o.content.is_empty()
                        && o.live_ptr <= value
                        && value < o.live_ptr.saturating_add(o.content.len() as u64)
                })
                .map(|o| (o.live_ptr, o.content.len()))
        } else {
            None
        };
        let extent_kind = if was_interior {
            CaptureExtentKind::InteriorSubview
        } else {
            CaptureExtentKind::ProbeWindow
        };
        // GTO-COLD-START-HEAP-REBASE-1 H2: first-hop children on AHK's
        // multi-heap layout (process heap + private heaps + CRT heap) often sit
        // OUTSIDE the single main-slab span, so the capture_coverage_bind gate
        // failed closed (ProbeCoverageMissing) even though every child was a
        // valid live read. Mirror the Route T R0-B dangling-edge pattern: a
        // non-interior first-hop child is itself an authoritative read from the
        // debuggee, so surface it as its own DEDICATED authoritative slab
        // covering exactly [value, value+len). The coverage gate stays
        // unchanged — the child is then contained in exactly one slab.
        // Interior children are NOT re-surfaced here: their containing parent
        // capture already provides coverage (adding a duplicate slab would
        // trigger the ambiguous multi-coverage failure).
        let slab_for_child: Option<HeapSlab> = if was_interior || child.is_empty() {
            None
        } else {
            Some(HeapSlab {
                old_base: value,
                content: child.clone(),
            })
        };
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: value,
            content: child,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind,
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("gscript_first_hop:{edge_off:#x}"),
                capture_path: CapturePath::GscriptFirstHop,
                source_root_rva: Some(gscript_rva),
                source_slot_offset: Some(edge_off),
                probe_requested_size: policy.first_hop_probe().min(MAX_HEAP_GLOBAL_BYTES),
                was_interior,
                containing_parent_old_base: containing_parent.map(|(b, _)| b),
                containing_parent_size: containing_parent.map(|(_, s)| s),
            },
            provenance: RegionProvenance::default(),
            transform_ids: Vec::new(),
        });
        if let Some(slab) = slab_for_child {
            dedicated_slabs.push(slab);
        }
        added += 1;
    }

    info!(
        added,
        skipped,
        interior,
        span,
        total = out.len(),
        "gscript first-hop exhaust complete"
    );
}

/// Force-admit AHK object link fields on already-captured gscript first-hop kids.
///
/// Live dump (r15b): `[gscript+0] + 0x18` pointed at `0x971948`, an *interior*
/// of oversized root `0x148c00` (`live=0x970640`, size 32KiB free-list). Exact-
/// base multi_fixup never remapped that link → WinMain string walk crashed on
/// freelist poison after MessageBox. Capture exact bases for common link
/// offsets so remap lands on freeable snapshots.
/// Route Y R1 A6 AF3 AF1 (P1-1): exposed `pub(crate)` so the AF3 AF1
/// emitter-driven pre-existing child-link tests can drive the REAL production
/// child-link emitter with a mock DebuggerCore.
pub(crate) fn exhaust_gscript_child_link_fields(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) {
    // AHK object common link/pointer fields (next, prev, parent, first-child…).
    const LINK_OFFS: &[usize] = &[0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38];
    let slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE / 4);
    // Snapshot indices of current graph children (rva==0) before we mutate.
    let seeds: Vec<usize> = out
        .iter()
        .enumerate()
        .filter(|(_, g)| g.rva == 0 && !g.is_heap_handle && g.content.len() >= 0x20)
        .map(|(i, _)| i)
        .collect();
    if seeds.is_empty() {
        return;
    }

    let mut added = 0usize;
    let mut skipped = 0usize;
    let mut interiors = 0usize;
    let seed_count = seeds.len();
    for seed_i in seeds {
        // Re-read content each time — previous admits may not change this seed.
        let content = out[seed_i].content.clone();
        let parent_live = out[seed_i].live_ptr;
        for &loff in LINK_OFFS {
            if loff + 8 > content.len() {
                continue;
            }
            if out.len() >= slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
                skipped += 1;
                continue;
            }
            let value = u64::from_le_bytes(content[loff..loff + 8].try_into().unwrap_or_default());
            if !is_heap_pointer(value, image_base, image_end) || value < MIN_HEAP_POINTER {
                continue;
            }
            if value >= 0x1_0000_0000 {
                continue;
            }
            // Skip self / already exact.
            if value == parent_live || is_exact_live_ptr(out, value) || seen_heaps.contains(&value)
            {
                skipped += 1;
                continue;
            }
            if looks_like_heap_handle(debugger, value) {
                skipped += 1;
                continue;
            }
            let was_interior = range_contains(out, value);
            seen_heaps.insert(value);
            let mut size = estimate_object_size(
                dump_buf,
                usize::MAX,
                value,
                debugger,
                policy.first_hop_probe().min(MAX_HEAP_GLOBAL_BYTES),
            );
            if size < 8 {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            }
            size = cap_size_before_next_base(out, value, size);
            if size < 8 {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            }
            if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
                seen_heaps.remove(&value);
                skipped += 1;
                break;
            }
            let Ok(mut child) = alloc_capped(
                size,
                policy.first_hop_probe().min(MAX_HEAP_CONTAINER_BYTES),
                "gscript child link",
            ) else {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            };
            match debugger.read_memory(value as usize, &mut child) {
                Ok(n) if n >= 8 => {
                    if n < child.len() {
                        child.truncate(n);
                    }
                }
                _ => {
                    seen_heaps.remove(&value);
                    skipped += 1;
                    continue;
                }
            }
            child = trim_trailing_zero_pages(child);
            let cap = cap_size_before_next_base(out, value, child.len());
            if cap < child.len() {
                child.truncate(cap);
            }
            if child.len() < 8 {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            }
            // Reject freelist-looking blobs (repeating 0x0350 / 0x28 patterns)
            // so we do not plant free-list as "object".
            if looks_like_heap_freelist(&child) {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            }
            handle_string_shell_on_capture(
                &mut child,
                out,
                total_bytes,
                seen_heaps,
                image_base,
                image_end,
                dump_buf,
                debugger,
                slot_cap,
            );
            if was_interior {
                interiors += 1;
            }
            info!(
                heap = format_args!("{value:#x}"),
                size = child.len(),
                parent = format_args!("{parent_live:#x}"),
                link_off = format_args!("{loff:#x}"),
                interior = was_interior,
                "Captured gscript child link field (force-admit)"
            );
            *total_bytes = total_bytes.saturating_add(child.len());
            // GTO R0-G: bind explicit capture evidence so the overlay can apply
            // write-set-scoped coherence for interior/probe views, and so the
            // drift ledger / normalization can resolve the authoritative parent.
            let containing_parent = if was_interior {
                find_containing_snapshot(out, value)
            } else {
                None
            };
            let extent_kind = if was_interior {
                CaptureExtentKind::InteriorSubview
            } else {
                CaptureExtentKind::ProbeWindow
            };
            // Deterministic capture id: binds capture_path + source parent + link
            // offset + target base + requested probe size.
            let capture_id = format!(
                "gscript_child_link:{parent_live:#x}:{loff:#x}:{value:#x}:{}",
                policy.first_hop_probe().min(MAX_HEAP_GLOBAL_BYTES)
            );
            let probe = policy.first_hop_probe().min(MAX_HEAP_GLOBAL_BYTES);
            out.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: value,
                content: child,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind,
                extent_evidence: CaptureExtentEvidence {
                    capture_id,
                    capture_path: CapturePath::GscriptChildLink,
                    source_root_rva: None,
                    source_slot_offset: Some(loff),
                    probe_requested_size: probe,
                    was_interior,
                    containing_parent_old_base: containing_parent.map(|(b, _)| b),
                    containing_parent_size: containing_parent.map(|(_, s)| s),
                },
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
            added += 1;
        }
    }

    info!(
        added,
        skipped,
        interiors,
        seeds = seed_count,
        total = out.len(),
        "gscript child-link exhaust complete"
    );
}

/// If image-inline gscript has a label pointer table at +0 but count@+0x10==0,
/// set count to the number of leading non-null qwords in the captured table.
///
/// `0x48fb0` fallback (`mov edi,[gscript+0x10]; mov r14,[gscript]`) skips the
/// entire binary search when count is 0 → WinMain never reaches RegisterClass.
/// AHK SimpleHeap control RVAs used by `0xb9410` bump allocator.
///
/// Must stay NULL/uninitialized on cold start so `0xb94a0` creates a fresh
/// 64KiB arena. Replaying dump-time exhausted arenas makes path-string copy
/// in WinMain (`0xb9360`) fail and fall into the error reporter AV path.
const AHK_STRING_ARENA_CONTROL_RVAS: &[u32] = &[0x148cb0, 0x148cb8, 0x148cc0];

fn drop_ahk_string_arena_slots(out: &mut Vec<HeapGlobalSnapshot>, total_bytes: &mut usize) {
    let before = out.len();
    out.retain(|g| {
        if g.is_heap_handle || g.is_image_inline {
            return true;
        }
        if AHK_STRING_ARENA_CONTROL_RVAS.contains(&g.rva) {
            return false;
        }
        true
    });
    // Recompute total_bytes from survivors (retain doesn't know sizes).
    *total_bytes = out.iter().map(|g| g.content.len()).sum();
    let dropped = before.saturating_sub(out.len());
    if dropped > 0 {
        info!(
            dropped,
            remaining = out.len(),
            "Dropped AHK SimpleHeap arena control slots (cold-init required)"
        );
    }
}

/// Public so dump_process can re-apply after scrub_uncaptured zeros fields.
pub fn resynthesize_gscript_label_count(heap_globals: &mut [HeapGlobalSnapshot]) {
    synthesize_gscript_label_count(heap_globals);
}

/// Normalize AHK runtime global object @0x141bf0 for WinMain cold re-init.
///
/// After Label bind (`0xc13d0`), WinMain does `mov rcx,[0x141bf0]` and writes a
/// full defaults block through ~+0x148 (r21). Dump often captures a 12–32KiB
/// free-list-polluted blob; leaving that body in place causes later obfuscated
/// walks to AV (r21 `@0x6110a0`). Replace with a zeroed slab large enough for
/// the re-init stores — WinMain fills the fields itself.
pub fn sanitize_ahk_runtime_global(heap_globals: &mut [HeapGlobalSnapshot]) {
    const RVA: u32 = 0x141bf0;
    // WinMain writes through +0x148; keep a little headroom.
    const NEED: usize = 0x180;
    let Some(g) = heap_globals
        .iter_mut()
        .find(|g| g.rva == RVA && !g.is_heap_handle)
    else {
        return;
    };
    let old = g.content.len();
    if old == NEED && g.content.iter().all(|&b| b == 0) {
        return;
    }
    g.content = vec![0u8; NEED];
    // Preserve live_ptr so multi_fixup / plant still targets the slot.
    info!(
        rva = format_args!("{RVA:#x}"),
        old_size = old,
        new_size = NEED,
        "Sanitized AHK runtime global 0x141bf0 to zeroed re-init slab"
    );
}

/// Ensure Label objects used by WinMain are not treated as nested redirects.
///
/// `0xc13d0`: if `[label+0x23]==0` then `rbx = [label+0x10]` (nested line).
/// Dump-time labels often have +0x23=0 and +0x10=NULL → AV at `cmp [rbx+0x23],1`
/// (r20b). Force +0x23=1 so the non-nested success path is taken. Does not
/// invent nested line objects; only flips the redirect flag.

/// Produce synthetic region requests for gscript window class/title strings.
///
/// R-GTO-UI r22b: after skip-LoadFile, WinMain reaches `0x34db0` but
/// `gscript+0xbd8` held a dump **path** string (not `NewClassName`) →
/// RegisterClass path returned 0 and WinMain exited without a product window.
///
/// GTO R0-F.2: this transform does NOT pick a hardcoded logical address or push
/// a fixed-VA snapshot. It returns two [`SyntheticRegionRequest`]s (window
/// class / title) whose anchor slots (`gscript+0xbd8` / `gscript+0xbd0`) will be
/// rewritten to the allocator-assigned collision-free base after assignment.
/// Returns an empty vec when no eligible image-inline gscript exists, or when
/// the synthetic regions are already present.
pub fn make_gscript_window_string_requests(
    heap_globals: &[HeapGlobalSnapshot],
) -> Vec<SyntheticRegionRequest> {
    const CLASS_NAME: &str = "NewClassName";
    const TITLE_NAME: &str = "ZhuChuangKou";
    const OFF_TITLE: usize = 0xbd0;
    const OFF_CLASS: usize = 0xbd8;
    const TRANSFORM_ID: &str = "repair_gscript_window_strings";

    let Some(gscript) = heap_globals
        .iter()
        .find(|g| g.is_image_inline && g.content.len() > OFF_CLASS + 8)
    else {
        return Vec::new();
    };
    // Anchor region old base = the image-inline gscript object's live base.
    let anchor_region_base = gscript.live_ptr;

    let mut requests = Vec::new();
    for (synthetic_id, text, off) in [
        ("gto.window_class", CLASS_NAME, OFF_CLASS),
        ("gto.window_title", TITLE_NAME, OFF_TITLE),
    ] {
        let mut body = Vec::with_capacity(text.len() * 2 + 2);
        for ch in text.encode_utf16() {
            body.extend_from_slice(&ch.to_le_bytes());
        }
        body.extend_from_slice(&[0, 0]);
        // Deterministic construction digest = sha256 of the constructed wide
        // string bytes (transform id carried separately on the provenance).
        let construction_digest = {
            let mut h = Sha256::new();
            h.update(body.as_slice());
            format!("{:x}", h.finalize())
        };
        let anchor = if off == OFF_CLASS {
            "gscript+0xbd8 (RegisterClass lpszClassName)"
        } else {
            "gscript+0xbd0 (CreateWindow title)"
        };
        requests.push(SyntheticRegionRequest {
            synthetic_id: synthetic_id.to_string(),
            transform_id: TRANSFORM_ID.to_string(),
            source_anchor: anchor.to_string(),
            payload: body,
            construction_digest,
            alignment: 0x10,
            pointer_slots: vec![SyntheticPointerAnchor {
                region_old_base: anchor_region_base,
                slot_offset: off,
            }],
        });
    }
    requests
}

/// A request to synthesize a runtime region with no raw source (GTO R0-F.2).
///
/// Offline transforms that need a fresh heap allocation (e.g. window class /
/// title strings for RegisterClass / CreateWindow) must NOT pick a hardcoded
/// logical address. Instead they emit a [`SyntheticRegionRequest`]; a
/// deterministic, checked free-range allocator later assigns a collision-free
/// logical old base from the authoritative ranges, and the anchor pointer slots
/// are rewritten to point at the assigned base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticRegionRequest {
    /// Stable identity for the ledger (e.g. `"gto.window_class"`).
    pub synthetic_id: String,
    /// Transform id that created this request.
    pub transform_id: String,
    /// Source anchor: the slot/region that references this synthetic region.
    pub source_anchor: String,
    /// Constructed payload bytes (deterministic).
    pub payload: Vec<u8>,
    /// sha256 (hex) of the constructed payload.
    pub construction_digest: String,
    /// Required allocation alignment (must be a power of two).
    pub alignment: usize,
    /// Pointer slots (inside already-captured regions) that must be rewritten
    /// to point at the assigned logical old base.
    pub pointer_slots: Vec<SyntheticPointerAnchor>,
}

/// An anchor pointer slot referencing a synthetic region: a slot at
/// `region_old_base + slot_offset` inside an already-captured region whose
/// 8-byte value must be rewritten to the assigned logical base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticPointerAnchor {
    /// Old base of the region whose payload holds the slot (e.g. gscript's
    /// image-inline live base).
    pub region_old_base: u64,
    /// Byte offset of the 8-byte slot within that region's payload.
    pub slot_offset: usize,
}

/// A deterministic, collision-free assignment of a synthetic logical base.
///
/// GTO R0-F.2.1: carries the `request_digest` (canonical identity of the bound
/// request) and the real rewrite/materialization evidence, so a downstream
/// consumer can verify a full identity-closed loop without re-pairing by
/// position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticAssignment {
    /// Stable identity (matches the request's `synthetic_id`).
    pub synthetic_id: String,
    /// Canonical identity digest of the bound request (see
    /// [`synthetic_request_digest`]). Binds synthetic_id, transform_id,
    /// source_anchor, payload/construction digest, alignment, and anchors.
    pub request_digest: String,
    /// The assigned logical old base (from the allocator, not a hardcode).
    pub assigned_logical_old_base: u64,
    /// Alignment the base honours.
    pub assignment_alignment: usize,
    /// Number of anchor pointer slots actually rewritten + read-back verified.
    pub rewritten_anchor_count: usize,
    /// Whether the region was materialized into a `HeapGlobalSnapshot`.
    pub materialized: bool,
}

/// A request and its assignment, bound by identity (GTO R0-F.2.1).
///
/// The allocator returns these already-bound objects so a caller never has to
/// re-pair `request` and `assignment` by position or by re-searching — which was
/// the root cause of the class/title swap in the R0-F.2 production zip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundSyntheticAssignment {
    /// The source request (its `synthetic_id` matches `assignment.synthetic_id`).
    pub request: SyntheticRegionRequest,
    /// The assignment bound to this request.
    pub assignment: SyntheticAssignment,
}

impl BoundSyntheticAssignment {
    /// Convenience accessor: the bound synthetic id.
    /// Currently unused by in-tree callers; retained as part of the bound-
    /// assignment API surface used by synthetic-region consumers/tests.
    #[allow(dead_code)]
    pub fn id(&self) -> &str {
        &self.assignment.synthetic_id
    }
    /// Convenience accessor: the assigned logical old base.
    /// Currently unused by in-tree callers; retained for symmetric access.
    #[allow(dead_code)]
    pub fn old_base(&self) -> u64 {
        self.assignment.assigned_logical_old_base
    }
}

/// Errors from deterministic synthetic logical-address assignment (GTO R0-F.2).
#[derive(Debug)]
pub enum SyntheticAssignError {
    /// A request is structurally invalid.
    InvalidRequest(String),
    /// No collision-free logical range could be found for a request.
    NoAvailableRange { synthetic_id: String },
    /// A request has a zero-length or empty payload.
    EmptyPayload { synthetic_id: String },
    /// An anchor slot is out of bounds of its region's payload.
    AnchorOutOfBounds {
        region_old_base: u64,
        slot_offset: usize,
        region_size: usize,
    },
    /// An anchor slot is not 8-byte aligned (pointer slots are x64 qwords).
    AnchorNotAligned {
        region_old_base: u64,
        slot_offset: usize,
    },
    /// The construction digest recorded on the request does not match the
    /// actual payload digest.
    ConstructionDigestMismatch {
        synthetic_id: String,
        expected: String,
        actual: String,
    },
    /// The assigned range would collide with an authority range.
    AuthorityCollision {
        synthetic_id: String,
        assigned_base: u64,
        assigned_size: usize,
    },
    /// The request <-> assignment identity mapping is inconsistent (GTO R0-F.2.1).
    SyntheticAssignmentIdentityMismatch(String),
    /// Materialization failed / would return a partial set (GTO R0-F.2.1).
    MaterializationFailed(String),
    /// The assigned base does not satisfy the requested alignment (checked
    /// alignment overflow or mis-alignment).
    AlignmentOverflow { synthetic_id: String },
}

impl std::fmt::Display for SyntheticAssignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyntheticAssignError::InvalidRequest(m) => write!(f, "synthetic request invalid: {m}"),
            SyntheticAssignError::NoAvailableRange { synthetic_id } => {
                write!(f, "no collision-free range for synthetic '{synthetic_id}'")
            }
            SyntheticAssignError::EmptyPayload { synthetic_id } => {
                write!(f, "synthetic '{synthetic_id}' has empty payload")
            }
            SyntheticAssignError::AnchorOutOfBounds {
                region_old_base,
                slot_offset,
                region_size,
            } => write!(
                f,
                "synthetic anchor slot {region_old_base:#x}@{slot_offset:#x} out of bounds \
                 (region size {region_size:#x})"
            ),
            SyntheticAssignError::AnchorNotAligned {
                region_old_base,
                slot_offset,
            } => write!(
                f,
                "synthetic anchor slot {region_old_base:#x}@{slot_offset:#x} is not 8-byte aligned"
            ),
            SyntheticAssignError::ConstructionDigestMismatch {
                synthetic_id,
                expected,
                actual,
            } => write!(
                f,
                "synthetic '{synthetic_id}' construction digest mismatch (expected {expected}, got {actual})"
            ),
            SyntheticAssignError::AuthorityCollision {
                synthetic_id,
                assigned_base,
                assigned_size,
            } => write!(
                f,
                "synthetic '{synthetic_id}' assigned [{assigned_base:#x},+{assigned_size:#x}) \
                 collides with an authority range"
            ),
            SyntheticAssignError::SyntheticAssignmentIdentityMismatch(m) => {
                write!(f, "synthetic assignment identity mismatch: {m}")
            }
            SyntheticAssignError::MaterializationFailed(m) => {
                write!(f, "synthetic materialization failed: {m}")
            }
            SyntheticAssignError::AlignmentOverflow { synthetic_id } => {
                write!(
                    f,
                    "synthetic '{synthetic_id}' assigned base alignment overflowed (near u64::MAX)"
                )
            }
        }
    }
}

impl std::error::Error for SyntheticAssignError {}

/// A label mName repair could not be resolved to a safe, provable pointer
/// (Route R R0-A / Audit Fix 1).
///
/// The transform must NOT silently fall back to reusing an old external/dangling
/// VA (which runtime rebase cannot handle and may be uncaptured). A genuinely
/// external label name is not yet wired into the collision-free synthetic
/// allocator, so the ONLY safe action is to fail closed (return this error) and
/// let `dump_process` abort the candidate before overlay/manifest. See
/// [`repair_label_names_after_scrub`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelNameRepairError {
    /// The mName points at a genuinely external address that is not a captured
    /// alias (interior/exact) and not the label's own inline storage. It cannot
    /// be safely synthesized without the allocator, so the transform fails.
    ExternalNameUnassigned {
        /// The label whose mName could not be resolved.
        label_live: u64,
        /// The external/dangling address originally in the mName field.
        external_va: u64,
    },
}

impl std::fmt::Display for LabelNameRepairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LabelNameRepairError::ExternalNameUnassigned {
                label_live,
                external_va,
            } => write!(
                f,
                "label {label_live:#x} mName points at external/dangling VA {external_va:#x}; \
                 cannot safely synthesize without the collision-free allocator — fail closed"
            ),
        }
    }
}

impl std::error::Error for LabelNameRepairError {}

/// Floor for deterministic synthetic logical placement: above the small-tag
/// range so an assigned base is never misread as a tag (runtime planner treats
/// `val < SMALL_TAG_CEILING` as a small integer, never a pointer).
const SYNTHETIC_FLOOR: u64 = 0x1_0000;

/// sha256 hex of a byte slice (used for construction digests and digest checks).
fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Public sha256 hex helper (exposed for tests building synthetic requests).
/// Test-only: every in-tree caller lives in `#[cfg(test)]` modules, so this
/// helper is compiled only when tests are built (`cargo check --tests`/`test`).
#[cfg(test)]
pub fn sha256_hex_pub(data: &[u8]) -> String {
    sha256_hex(data)
}

/// Canonical, domain-separated, length-prefixed identity digest of a synthetic
/// region request (GTO R0-F.2.1).
///
/// Binds `synthetic_id`, `transform_id`, `source_anchor`, the payload bytes,
/// the construction digest, the alignment, and the pointer anchors (in a
/// deterministic order). Any change to any identity-bearing field changes the
/// digest, so an assignment's `request_digest` is a trustworthy binding to its
/// exact request.
pub fn synthetic_request_digest(req: &SyntheticRegionRequest) -> String {
    let mut enc: Vec<u8> = Vec::new();
    // Domain separation: a fixed marker distinguishes this encoding from any
    // other digest input.
    enc.extend_from_slice(b"mida.synthetic-request/v1\0");
    let put_str = |s: &str, enc: &mut Vec<u8>| {
        enc.extend_from_slice(&(s.len() as u64).to_le_bytes());
        enc.extend_from_slice(s.as_bytes());
    };
    put_str(&req.synthetic_id, &mut enc);
    put_str(&req.transform_id, &mut enc);
    put_str(&req.source_anchor, &mut enc);
    enc.extend_from_slice(&(req.payload.len() as u64).to_le_bytes());
    enc.extend_from_slice(&req.payload);
    put_str(&req.construction_digest, &mut enc);
    enc.extend_from_slice(&(req.alignment as u64).to_le_bytes());
    // Pointer anchors in deterministic (region_old_base, slot_offset) order.
    let mut anchors = req.pointer_slots.clone();
    anchors.sort_by_key(|a| (a.region_old_base, a.slot_offset));
    enc.extend_from_slice(&(anchors.len() as u64).to_le_bytes());
    for a in &anchors {
        enc.extend_from_slice(&a.region_old_base.to_le_bytes());
        enc.extend_from_slice(&(a.slot_offset as u64).to_le_bytes());
    }
    sha256_hex(&enc)
}

/// Checked alignment-up that returns `None` when `v + (alignment-1)` overflows.
fn checked_align_up_u64(v: u64, alignment: u64) -> Option<u64> {
    let mask = alignment.checked_sub(1)?;
    let bumped = v.checked_add(mask)?;
    Some(bumped & !mask)
}

/// Deterministically assign collision-free synthetic logical addresses to a
/// set of synthetic region requests, avoiding every authority range.
///
/// # Authority ranges to avoid (all must be provided by the caller)
///
/// `avoid_ranges` is a set of half-open `[start, end)` ranges that the assigned
/// logical bases must not intersect. It must include at least: the raw heap
/// slab span, all observed heap-global ranges, all container ranges, all
/// image-inline ranges, the source image span, external module map ranges, and
/// the NULL / small-tag range. The caller collects these from the live capture
/// + module map.
///
/// # Determinism
///
/// Requests are assigned in a stable sort order by
/// `(transform_id, source_anchor, construction_digest, synthetic_id)`, and the
/// allocator scans addresses upward from a fixed floor. Identical input yields
/// identical assignments regardless of request order. The returned
/// [`BoundSyntheticAssignment`]s are **bound by identity** (`synthetic_id`), so
/// the caller never re-pairs request and assignment by position.
///
/// # Fail-closed
///
/// Any invalid request, empty payload, bad alignment, out-of-bounds /
/// mis-aligned anchor slot, construction-digest mismatch, duplicate request or
/// assignment id, missing/extra binding, authority collision, range-end
/// overflow, checked-alignment overflow near `u64::MAX`, or exhausted logical
/// space returns an error. There is no fallback to a hardcoded address.
pub fn assign_synthetic_logical_addresses(
    requests: &[SyntheticRegionRequest],
    avoid_ranges: &[(u64, u64)],
) -> Result<Vec<BoundSyntheticAssignment>, SyntheticAssignError> {
    // GTO R0-F.2.1: request ids must be unique (identity mapping is 1:1).
    let mut req_ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for r in requests {
        if !req_ids.insert(&r.synthetic_id) {
            return Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(
                format!("duplicate request synthetic_id '{}'", r.synthetic_id),
            ));
        }
    }

    // Merge + sort authority ranges into a disjoint, sorted list.
    let mut ranges: Vec<(u64, u64)> = avoid_ranges
        .iter()
        .map(|&(s, e)| {
            // Normalize to [start, end) with checked arithmetic; skip empty.
            if e <= s {
                (s, s)
            } else {
                (s, e)
            }
        })
        .filter(|&(s, e)| e > s)
        .collect();
    ranges.sort_by_key(|&(s, _)| s);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for &(s, e) in &ranges {
        match merged.last_mut() {
            Some(last) if s <= last.1 => {
                if e > last.1 {
                    last.1 = e;
                }
            }
            _ => merged.push((s, e)),
        }
    }

    // Deterministic request order.
    let mut ordered: Vec<&SyntheticRegionRequest> = requests.iter().collect();
    ordered.sort_by_key(|r| {
        (
            r.transform_id.clone(),
            r.source_anchor.clone(),
            r.construction_digest.clone(),
            r.synthetic_id.clone(),
        )
    });

    let mut assignments: Vec<BoundSyntheticAssignment> = Vec::new();
    // Already-assigned synthetic ranges (start, end) so two synthetics never overlap.
    let mut synthetic_ranges: Vec<(u64, u64)> = Vec::new();

    for req in &ordered {
        let alignment = req.alignment;
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(SyntheticAssignError::InvalidRequest(format!(
                "alignment {alignment:#x} is not a power of two"
            )));
        }
        if req.payload.is_empty() {
            return Err(SyntheticAssignError::EmptyPayload {
                synthetic_id: req.synthetic_id.clone(),
            });
        }
        // Construction digest must match the actual payload.
        if sha256_hex(&req.payload) != req.construction_digest {
            return Err(SyntheticAssignError::ConstructionDigestMismatch {
                synthetic_id: req.synthetic_id.clone(),
                expected: req.construction_digest.clone(),
                actual: sha256_hex(&req.payload),
            });
        }
        let padded_size = req
            .payload
            .len()
            .checked_add(alignment - 1)
            .map(|v| v & !(alignment - 1))
            .ok_or_else(|| {
                SyntheticAssignError::InvalidRequest(format!(
                    "payload size overflow for '{}'",
                    req.synthetic_id
                ))
            })?;
        if padded_size == 0 {
            return Err(SyntheticAssignError::EmptyPayload {
                synthetic_id: req.synthetic_id.clone(),
            });
        }

        // Find the first aligned base >= floor whose [base, base+padded_size)
        // intersects no authority range and no previously-assigned synthetic.
        // The scan JUMPS past each collision (to the aligned end of the
        // colliding range) so it terminates in O(number of ranges), never by
        // stepping through the whole address space. All alignment uses the
        // CHECKED variant so a near-u64::MAX authority range fails closed rather
        // than panicking/wrapping.
        let floor = SYNTHETIC_FLOOR;
        let mut candidate = checked_align_up_u64(floor.max(alignment as u64), alignment as u64)
            .ok_or_else(|| SyntheticAssignError::AlignmentOverflow {
                synthetic_id: req.synthetic_id.clone(),
            })?;
        let base = loop {
            let Some(end) = candidate.checked_add(padded_size as u64) else {
                return Err(SyntheticAssignError::NoAvailableRange {
                    synthetic_id: req.synthetic_id.clone(),
                });
            };
            let collide_end = merged
                .iter()
                .find(|&&(as_, ae)| candidate < ae && as_ < end)
                .map(|&(_, ae)| ae)
                .or_else(|| {
                    synthetic_ranges
                        .iter()
                        .find(|&&(ss, se)| candidate < se && ss < end)
                        .map(|&(_, se)| se)
                });
            match collide_end {
                Some(ce) => {
                    // Jump to just past the colliding range, aligned up (checked).
                    let next = checked_align_up_u64(ce, alignment as u64).ok_or_else(|| {
                        SyntheticAssignError::AlignmentOverflow {
                            synthetic_id: req.synthetic_id.clone(),
                        }
                    })?;
                    candidate = next;
                }
                None => break candidate,
            }
        };
        let assigned_end = base.checked_add(padded_size as u64).ok_or_else(|| {
            SyntheticAssignError::NoAvailableRange {
                synthetic_id: req.synthetic_id.clone(),
            }
        })?;
        synthetic_ranges.push((base, assigned_end));
        assignments.push(BoundSyntheticAssignment {
            request: (*req).clone(),
            assignment: SyntheticAssignment {
                synthetic_id: req.synthetic_id.clone(),
                request_digest: synthetic_request_digest(req),
                assigned_logical_old_base: base,
                assignment_alignment: alignment,
                rewritten_anchor_count: 0,
                materialized: false,
            },
        });
    }

    // GTO R0-F.2.1: the returned bound set must be exactly 1:1 (every request
    // bound, every assignment bound, ids unique, digests consistent). This is
    // guaranteed by construction, but the explicit check makes a future
    // refactor fail closed rather than silently pair-by-position.
    validate_bound_assignments(&assignments)?;

    // Final defense-in-depth: re-verify every assigned range is collision-free
    // against the authority ranges and pairwise-disjoint against every other
    // assigned range. The forward scan already guarantees this; the explicit
    // check makes a future refactor fail closed rather than silently overlap.
    for (i, b) in assignments.iter().enumerate() {
        let a = &b.assignment;
        let size = b.request.payload.len();
        let padded = (size + (a.assignment_alignment - 1)) & !(a.assignment_alignment - 1);
        let end = a
            .assigned_logical_old_base
            .checked_add(padded as u64)
            .ok_or_else(|| SyntheticAssignError::NoAvailableRange {
                synthetic_id: a.synthetic_id.clone(),
            })?;
        for &(as_, ae) in &merged {
            if a.assigned_logical_old_base < ae && as_ < end {
                return Err(SyntheticAssignError::AuthorityCollision {
                    synthetic_id: a.synthetic_id.clone(),
                    assigned_base: a.assigned_logical_old_base,
                    assigned_size: padded,
                });
            }
        }
        for (j, bb) in assignments.iter().enumerate() {
            if i == j {
                continue;
            }
            let b_size = bb.request.payload.len();
            let b_padded = (b_size + (bb.assignment.assignment_alignment - 1))
                & !(bb.assignment.assignment_alignment - 1);
            let b_end = bb
                .assignment
                .assigned_logical_old_base
                .checked_add(b_padded as u64)
                .unwrap_or(u64::MAX);
            if a.assigned_logical_old_base < b_end && bb.assignment.assigned_logical_old_base < end
            {
                return Err(SyntheticAssignError::AuthorityCollision {
                    synthetic_id: a.synthetic_id.clone(),
                    assigned_base: a.assigned_logical_old_base,
                    assigned_size: padded,
                });
            }
        }
    }

    // Return in deterministic sort order (already stable by the request sort).
    Ok(assignments)
}

/// Verify that a bound-assignment set is exactly 1:1 by identity (GTO R0-F.2.1).
///
/// Enforces: assignment ids all unique; each assignment's `request_digest`
/// matches its bound request's canonical digest; each request's transform_id /
/// source_anchor / construction_digest are consistent with its assignment. Fails
/// closed with [`SyntheticAssignError::SyntheticAssignmentIdentityMismatch`] on
/// any inconsistency. Duplicate ids, missing/extra bindings, and digest
/// mismatches are all rejected — never first/last match, never silent ignore,
/// never position-based binding.
pub fn validate_bound_assignments(
    bound: &[BoundSyntheticAssignment],
) -> Result<(), SyntheticAssignError> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for b in bound {
        if b.request.synthetic_id != b.assignment.synthetic_id {
            return Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(
                format!(
                    "request id '{}' != assignment id '{}'",
                    b.request.synthetic_id, b.assignment.synthetic_id
                ),
            ));
        }
        if !seen.insert(&b.request.synthetic_id) {
            return Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(
                format!("duplicate bound synthetic_id '{}'", b.request.synthetic_id),
            ));
        }
        let expect_digest = synthetic_request_digest(&b.request);
        if b.assignment.request_digest != expect_digest {
            return Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(
                format!(
                    "assignment '{}' request_digest mismatch (expected {expect_digest}, got {})",
                    b.request.synthetic_id, b.assignment.request_digest
                ),
            ));
        }
    }
    Ok(())
}

/// Rewrite anchor pointer slots to point at `assigned_base`, then read each
/// slot back and verify it equals the assigned base. Returns the number of
/// slots rewritten AND read-back verified (GTO R0-F.2.1).
///
/// `regions` is `&mut [(old_base, &mut Vec<u8>)]` so the anchor's owning region
/// payload can be patched in place. Fails closed on out-of-bounds, non-8-aligned
/// slots, or a read-back mismatch (never returns `Ok` without proof the slot was
/// actually written).
pub fn rewrite_synthetic_anchor_slots(
    regions: &mut [(u64, &mut Vec<u8>)],
    anchors: &[SyntheticPointerAnchor],
    assigned_base: u64,
) -> Result<usize, SyntheticAssignError> {
    let mut rewritten = 0usize;
    for anchor in anchors {
        if anchor.slot_offset % 8 != 0 {
            return Err(SyntheticAssignError::AnchorNotAligned {
                region_old_base: anchor.region_old_base,
                slot_offset: anchor.slot_offset,
            });
        }
        let Some((_, payload)) = regions
            .iter_mut()
            .find(|(ob, _)| *ob == anchor.region_old_base)
        else {
            // Anchor region not present in the provided set: caller responsibility
            // to pass every region that hosts an anchor.
            return Err(SyntheticAssignError::InvalidRequest(format!(
                "anchor region {:#x} not found for slot @{:#x}",
                anchor.region_old_base, anchor.slot_offset
            )));
        };
        let end = anchor.slot_offset.checked_add(8).ok_or_else(|| {
            SyntheticAssignError::AnchorOutOfBounds {
                region_old_base: anchor.region_old_base,
                slot_offset: anchor.slot_offset,
                region_size: payload.len(),
            }
        })?;
        if end > payload.len() {
            return Err(SyntheticAssignError::AnchorOutOfBounds {
                region_old_base: anchor.region_old_base,
                slot_offset: anchor.slot_offset,
                region_size: payload.len(),
            });
        }
        payload[anchor.slot_offset..end].copy_from_slice(&assigned_base.to_le_bytes());
        // Read-back verification: the slot must now hold the assigned base.
        let read = u64::from_le_bytes(
            payload[anchor.slot_offset..end]
                .try_into()
                .unwrap_or([0; 8]),
        );
        if read != assigned_base {
            return Err(SyntheticAssignError::SyntheticAssignmentIdentityMismatch(
                format!(
                    "anchor {:#x}@{:#x} read-back {read:#x} != assigned base {assigned_base:#x}",
                    anchor.region_old_base, anchor.slot_offset
                ),
            ));
        }
        rewritten += 1;
    }
    Ok(rewritten)
}

/// Materialize bound synthetic regions into `HeapGlobalSnapshot`s carrying full
/// SyntheticDerived provenance + SyntheticDerived extent classification, so the
/// production planner routes them as independent synthetic allocations (never
/// absorbed into the raw slab). GTO R0-F.2.
///
/// GTO R0-F.2.1: takes `&[BoundSyntheticAssignment]` (already identity-bound by
/// the allocator) and returns a `Result`. It NEVER silently skips a missing
/// binding: any mismatch, duplicate id, request-digest inconsistency,
/// construction-digest inconsistency, or inconsistency between the assigned
/// base and the materialized snapshot's `live_ptr` / provenance / extent fails
/// closed. No partial materialization is ever returned.
pub fn materialize_synthetic_regions(
    bound: &[BoundSyntheticAssignment],
) -> Result<Vec<HeapGlobalSnapshot>, SyntheticAssignError> {
    // Enforce exactly 1:1 identity binding (duplicate ids, digest mismatch, etc.).
    validate_bound_assignments(bound)?;

    let mut out: Vec<HeapGlobalSnapshot> = Vec::with_capacity(bound.len());
    for b in bound {
        let req = &b.request;
        let assignment = &b.assignment;
        // Construction digest of the payload must match the request's record.
        if sha256_hex(&req.payload) != req.construction_digest {
            return Err(SyntheticAssignError::ConstructionDigestMismatch {
                synthetic_id: req.synthetic_id.clone(),
                expected: req.construction_digest.clone(),
                actual: sha256_hex(&req.payload),
            });
        }
        let snap = HeapGlobalSnapshot {
            rva: 0,
            live_ptr: assignment.assigned_logical_old_base,
            content: req.payload.clone(),
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::SyntheticDerived,
            extent_evidence: CaptureExtentEvidence {
                capture_id: req.synthetic_id.clone(),
                capture_path: CapturePath::Synthetic,
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: req.payload.len(),
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: vec![req.transform_id.clone()],
            provenance: RegionProvenance::SyntheticDerived {
                transform_id: req.transform_id.clone(),
                source_anchor: req.source_anchor.clone(),
                construction_digest: req.construction_digest.clone(),
            },
        };
        // The materialized snapshot's live_ptr must equal the assigned base, and
        // its extent must be SyntheticDerived (the production plan derives
        // ownership=SyntheticAllocation from this). Any inconsistency fails.
        if snap.live_ptr != assignment.assigned_logical_old_base {
            return Err(SyntheticAssignError::MaterializationFailed(format!(
                "synthetic '{}' snapshot live_ptr {:#x} != assigned base {:#x}",
                req.synthetic_id, snap.live_ptr, assignment.assigned_logical_old_base
            )));
        }
        if snap.extent_kind != CaptureExtentKind::SyntheticDerived {
            return Err(SyntheticAssignError::MaterializationFailed(format!(
                "synthetic '{}' materialized extent {:?} != SyntheticDerived",
                req.synthetic_id, snap.extent_kind
            )));
        }
        out.push(snap);
    }
    if out.len() != bound.len() {
        return Err(SyntheticAssignError::MaterializationFailed(format!(
            "materialized {} != bound {} (partial materialization not returned)",
            out.len(),
            bound.len()
        )));
    }
    Ok(out)
}

pub fn mark_labels_non_nested(heap_globals: &mut [HeapGlobalSnapshot]) {
    let Some(gscript) = heap_globals
        .iter()
        .find(|g| g.is_image_inline && g.content.len() >= 8)
    else {
        return;
    };
    let table_ptr = u64::from_le_bytes(gscript.content[0..8].try_into().unwrap_or_default());
    if table_ptr == 0 {
        return;
    }
    let Some(count) = gscript_label_count(&gscript.content) else {
        return;
    };
    let Some(table) = heap_globals
        .iter()
        .find(|g| g.live_ptr == table_ptr && g.content.len() >= 8)
    else {
        return;
    };
    let n = count.min(table.content.len() / 8);
    let entries: Vec<u64> = (0..n)
        .map(|i| {
            u64::from_le_bytes(
                table.content[i * 8..i * 8 + 8]
                    .try_into()
                    .unwrap_or_default(),
            )
        })
        .filter(|&p| p != 0)
        .collect();
    // Snapshot exact lives before mut borrow.
    let exact: BTreeSet<u64> = heap_globals
        .iter()
        .filter(|g| !g.is_heap_handle && g.content.len() >= 8)
        .map(|g| g.live_ptr)
        .collect();
    let mut marked = 0usize;
    let mut skipped = 0usize;
    for live in entries {
        let Some(g) = heap_globals
            .iter_mut()
            .find(|g| g.live_ptr == live && g.content.len() > 0x23)
        else {
            skipped += 1;
            continue;
        };
        // Already non-nested.
        if g.content[0x23] != 0 {
            continue;
        }
        // Only flip when nested ptr is null/missing — if +0x10 is a real
        // exact-captured object, leave redirect semantics alone.
        let nested = if g.content.len() >= 0x18 {
            u64::from_le_bytes(g.content[0x10..0x18].try_into().unwrap_or_default())
        } else {
            0
        };
        if nested != 0 && exact.contains(&nested) {
            skipped += 1;
            continue;
        }
        g.content[0x23] = 1;
        marked += 1;
    }
    if marked > 0 || skipped > 0 {
        info!(
            marked,
            skipped,
            total = n,
            "Marked Label+0x23 non-nested for cold-start 0xc13d0 path"
        );
    }
}

/// Sort gscript label pointer table by mName so `0x48fb0` binary search works.
///
/// Live dumps often capture the table in insertion/hash order (r19b: `A_Args`
/// then Chinese labels). WinMain looks up `"0"` / `"A_Args"` via binary
/// search; unsorted tables always miss → rax=0 → product window path dead.
pub fn sort_gscript_label_table(heap_globals: &mut [HeapGlobalSnapshot]) {
    let Some(gscript_idx) = heap_globals
        .iter()
        .position(|g| g.is_image_inline && g.content.len() >= 0x18)
    else {
        return;
    };
    let table_ptr = u64::from_le_bytes(
        heap_globals[gscript_idx].content[0..8]
            .try_into()
            .unwrap_or_default(),
    );
    if table_ptr == 0 {
        return;
    }
    let count = u32::from_le_bytes(
        heap_globals[gscript_idx].content[0x10..0x14]
            .try_into()
            .unwrap_or_default(),
    ) as usize;
    if count < 2 {
        return;
    }
    let Some(table_idx) = heap_globals
        .iter()
        .position(|g| g.live_ptr == table_ptr && g.content.len() >= 16)
    else {
        return;
    };
    let n = count.min(heap_globals[table_idx].content.len() / 8);
    if n < 2 {
        return;
    }

    // Resolve each entry's sort key from exact mName snapshot or inline +0x30.
    // R-GTO-UI r20b: empty-key entries must NOT sort first — binary search would
    // hit null mName and wcscmp → call-obfusc AV (r20 regression).
    let mut named: Vec<(u64, String)> = Vec::with_capacity(n);
    let mut unnamed: Vec<u64> = Vec::new();
    for i in 0..n {
        let off = i * 8;
        let live = u64::from_le_bytes(
            heap_globals[table_idx].content[off..off + 8]
                .try_into()
                .unwrap_or_default(),
        );
        if live == 0 {
            break;
        }
        match resolve_label_sort_key(heap_globals, live) {
            Some(key) if !key.is_empty() => named.push((live, key)),
            _ => unnamed.push(live),
        }
    }
    if named.len() < 2 {
        info!(
            named = named.len(),
            unnamed = unnamed.len(),
            "gscript label sort skipped: too few named entries"
        );
        return;
    }
    let before_named: Vec<u64> = named.iter().map(|(p, _)| *p).collect();
    named.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let after_named: Vec<u64> = named.iter().map(|(p, _)| *p).collect();
    // Searchable prefix = named only (sorted). Unnamed trail after count.
    let mut out_ptrs: Vec<u64> = after_named.clone();
    out_ptrs.extend(unnamed.iter().copied());
    let new_count = named.len() as u32;
    let changed = before_named != after_named || (count as u32) != new_count;
    if !changed {
        info!(
            count = new_count,
            "gscript label table already sorted by mName"
        );
        return;
    }
    for (i, live) in out_ptrs.iter().enumerate() {
        let off = i * 8;
        if off + 8 > heap_globals[table_idx].content.len() {
            break;
        }
        heap_globals[table_idx].content[off..off + 8].copy_from_slice(&live.to_le_bytes());
    }
    heap_globals[gscript_idx].content[0x10..0x14].copy_from_slice(&new_count.to_le_bytes());
    if heap_globals[gscript_idx].content.len() >= 0x18 {
        heap_globals[gscript_idx].content[0x14..0x18].fill(0);
    }
    info!(
        count = new_count,
        unnamed = unnamed.len(),
        first = %named.first().map(|e| e.1.as_str()).unwrap_or(""),
        last = %named.last().map(|e| e.1.as_str()).unwrap_or(""),
        "Sorted gscript label table by mName (named-only prefix)"
    );
}

fn resolve_label_sort_key(heap_globals: &[HeapGlobalSnapshot], label_live: u64) -> Option<String> {
    let label = heap_globals
        .iter()
        .find(|g| g.live_ptr == label_live && g.content.len() >= LABEL_INLINE_NAME_OFF + 2)?;
    let name_ptr = u64::from_le_bytes(
        label.content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8]
            .try_into()
            .ok()?,
    );
    if name_ptr != 0 {
        if let Some(s) = heap_globals.iter().find(|g| g.live_ptr == name_ptr) {
            if let Some(k) = wide_bytes_to_sort_key(&s.content) {
                return Some(k);
            }
        }
    }
    // Inline residual at +0x30.
    if label.content.len() >= LABEL_INLINE_NAME_OFF + 4 {
        if let Some(b) = extract_inline_wide_name(&label.content) {
            return wide_bytes_to_sort_key(&b);
        }
    }
    None
}

fn wide_bytes_to_sort_key(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let mut u16s = Vec::new();
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let ch = u16::from_le_bytes(bytes[i..i + 2].try_into().ok()?);
        i += 2;
        if ch == 0 {
            break;
        }
        u16s.push(ch);
    }
    if u16s.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&u16s))
}

/// After scrub, repair Label.mName from inline UTF-16 at +0x30 when +0x28 is null.
///
/// Slot-cap during capture often skips name externalization; scrub then leaves
/// mName=0 → WinMain `0x48fb0` calls wcscmp(NULL) → call-obfusc AV (r17b/r18).
/// Pure offline repair: no live process needed.
///
/// Returns `Err(LabelNameRepairError::ExternalNameUnassigned)` when a label mName
/// points at a genuinely external/dangling address that is neither a captured
/// alias (interior/exact) nor the label's own inline storage. The transform must
/// NOT reuse an old external VA or silently clear the field to produce a
/// candidate; the caller (`dump_process`) aborts before overlay/manifest so the
/// candidate is never generated. This is the Route R R0-A / Audit Fix 1
/// fail-closed contract for external label names (full synthetic-allocator
/// wiring is a separate capability work order).
pub fn repair_label_names_after_scrub(
    heap_globals: &mut Vec<HeapGlobalSnapshot>,
) -> Result<(), LabelNameRepairError> {
    let Some(gscript) = heap_globals
        .iter()
        .find(|g| g.is_image_inline && g.content.len() >= 8)
    else {
        return Ok(());
    };
    let table_ptr = u64::from_le_bytes(gscript.content[0..8].try_into().unwrap_or_default());
    if table_ptr == 0 {
        return Ok(());
    }
    let Some(table) = heap_globals
        .iter()
        .find(|g| g.live_ptr == table_ptr && g.content.len() >= 8)
    else {
        return Ok(());
    };
    let count = {
        let Some(c) = gscript_label_count(&gscript.content) else {
            return Ok(());
        };
        if c > 0 {
            c as usize
        } else {
            table.content.len() / 8
        }
    };
    let table_content = table.content.clone();
    let mut repaired = 0usize;
    let names_added = 0usize; // synthetic snapshots are no longer created (R0-A)
    for i in 0..count.min(table_content.len() / 8).min(512) {
        let label_live = u64::from_le_bytes(
            table_content[i * 8..i * 8 + 8]
                .try_into()
                .unwrap_or_default(),
        );
        if label_live == 0 {
            break;
        }
        let Some(idx) = heap_globals
            .iter()
            .position(|g| g.live_ptr == label_live && g.content.len() >= LABEL_INLINE_NAME_OFF + 4)
        else {
            continue;
        };
        let name_ptr = u64::from_le_bytes(
            heap_globals[idx].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8]
                .try_into()
                .unwrap_or_default(),
        );
        // Keep only if mName already points at an exact freeable snapshot.
        if name_ptr != 0 && heap_globals.iter().any(|g| g.live_ptr == name_ptr) {
            continue;
        }

        // Route R R0-A: resolve `str_live` (the target of label.mName) to a
        // provable pointer. It must be one of:
        //   (a) label-self interior (inline +0x30)  -> keep label interior alias
        //   (b) interior to ANY other captured parent -> keep parent interior alias
        //   (c) equal to a captured exact base       -> keep exact pointer
        //   (d) genuinely EXTERNAL/dangling          -> FAIL CLOSED (no allocator yet)
        //   (e) unrecoverable (name_ptr==0, no inline) -> null mName
        // We never synthesize a snapshot in a captured range and never reuse an old
        // external VA. If mName already points at an exact freeable snapshot, it was
        // kept earlier (line 3290 `continue`).
        let mut str_live = 0u64;
        let label_end = label_live.saturating_add(heap_globals[idx].content.len() as u64);
        if name_ptr != 0 {
            let in_label = name_ptr > label_live && name_ptr < label_end;
            let parent = find_containing_snapshot(&heap_globals, name_ptr);
            let in_other_parent =
                parent.is_some_and(|(base, _)| base != name_ptr && base != label_live);
            let is_exact = is_exact_live_ptr(&heap_globals, name_ptr);
            if in_label || in_other_parent || is_exact {
                // (a)/(b)/(c): captured alias — keep the interior/exact pointer.
                str_live = name_ptr;
            } else if let Some(_b) = extract_inline_wide_name(&heap_globals[idx].content) {
                // external name_ptr but inline +0x30 is recoverable -> the label's
                // own inline storage is the alias (label-self interior).
                str_live = label_live.saturating_add(LABEL_INLINE_NAME_OFF as u64);
            } else {
                // (d) genuinely external/dangling name_ptr with no inline fallback:
                // cannot safely synthesize without the allocator — fail closed.
                return Err(LabelNameRepairError::ExternalNameUnassigned {
                    label_live,
                    external_va: name_ptr,
                });
            }
        } else if let Some(_b) = extract_inline_wide_name(&heap_globals[idx].content) {
            // name_ptr == 0 but inline +0x30 recoverable -> label-self interior alias.
            str_live = label_live.saturating_add(LABEL_INLINE_NAME_OFF as u64);
        }
        if str_live == 0 {
            // (e) fully unrecoverable: null mName (fail-closed, no forged pointer).
            heap_globals[idx].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8].fill(0);
            continue;
        }
        // str_live is a captured alias (label-self interior / other-parent interior /
        // exact captured base): keep the interior/exact pointer; NO synthetic snapshot.
        // The runtime rebase handles the interior pointer via the containing region.
        heap_globals[idx].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8]
            .copy_from_slice(&str_live.to_le_bytes());
        repaired += 1;
    }
    if repaired > 0 || names_added > 0 {
        info!(
            repaired,
            names_added,
            total = heap_globals.len(),
            "Repaired label mName after scrub (inline SSO → exact string)"
        );
    }
    Ok(())
}

fn synthesize_gscript_label_count(out: &mut [HeapGlobalSnapshot]) {
    let Some(gscript_idx) = out
        .iter()
        .position(|g| g.is_image_inline && g.content.len() >= 0x18)
    else {
        info!("gscript label-count synth skipped: no image-inline gscript");
        return;
    };
    let table_ptr = u64::from_le_bytes(
        out[gscript_idx].content[0..8]
            .try_into()
            .unwrap_or_default(),
    );
    if table_ptr == 0 {
        info!("gscript label-count synth skipped: table ptr null");
        return;
    }
    let Some(table_idx) = out
        .iter()
        .position(|g| g.live_ptr == table_ptr && g.content.len() >= 8)
    else {
        info!(
            table = format_args!("{table_ptr:#x}"),
            "gscript label-count synth skipped: table not exact-captured"
        );
        return;
    };
    let n = count_leading_heap_ptrs(&out[table_idx].content);
    if n == 0 {
        info!(
            table = format_args!("{table_ptr:#x}"),
            size = out[table_idx].content.len(),
            "gscript label-count synth skipped: zero leading entries"
        );
        return;
    }
    let count_now = u32::from_le_bytes(
        out[gscript_idx].content[0x10..0x14]
            .try_into()
            .unwrap_or_default(),
    );
    // Always write table-derived count. Live image body often has a stale
    // non-zero dword at +0x10 (pointer low half / partial init) that is not a
    // real label count; trusting it left PE with 0 after scrub (r17).
    out[gscript_idx].content[0x10..0x14].copy_from_slice(&n.to_le_bytes());
    // Clear high dword of the count qword so multi_fixup never sees a fake ptr.
    if out[gscript_idx].content.len() >= 0x18 {
        out[gscript_idx].content[0x14..0x18].fill(0);
    }
    info!(
        table = format_args!("{table_ptr:#x}"),
        count = n,
        previous = count_now,
        "Synthesized gscript label-table count at +0x10"
    );
}

fn count_leading_heap_ptrs(content: &[u8]) -> u32 {
    let mut n = 0u32;
    let mut off = 0usize;
    while off + 8 <= content.len() {
        let v = u64::from_le_bytes(content[off..off + 8].try_into().unwrap_or_default());
        if v == 0 {
            break;
        }
        if v == 0x0350_0350_0350_0350 || v == 0x2828_2828_2828_2828 {
            break;
        }
        // Use the same x64 user-heap predicate as capture admission. This
        // intentionally accepts aligned heap pointers at and above 4 GiB.
        if !is_heap_pointer(v, 0, 0) {
            break;
        }
        n = n.saturating_add(1);
        off += 8;
        if n >= 4096 {
            break;
        }
    }
    n
}

/// Force-admit every non-null entry in gscript's label pointer table (+0).
/// `pub(crate)` so the AF3 emitter-driven tests can drive the REAL production
/// emitter with a mock DebuggerCore (Route Y R1 A6 AF3 task 3/4).
pub(crate) fn exhaust_gscript_label_table_entries(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) {
    let Some(gscript) = out
        .iter()
        .find(|g| g.is_image_inline && g.content.len() >= 8)
    else {
        return;
    };
    // AF3 AF1 (P1-5): the label-table source root RVA is deterministic and fixed
    // here (before the loop mutates `out`), so the emitter can record it on every
    // admitted label-table entry without a borrow conflict.
    let source_root_rva = if gscript.rva != 0 {
        Some(gscript.rva)
    } else {
        None
    };
    let table_ptr = u64::from_le_bytes(gscript.content[0..8].try_into().unwrap_or_default());
    if table_ptr == 0 {
        return;
    }
    let Some(table_idx) = out
        .iter()
        .position(|g| g.live_ptr == table_ptr && g.content.len() >= 8)
    else {
        return;
    };
    // Bound by synthesized count if present, else full table content.
    let count = {
        let Some(g) = out.iter().find(|g| g.is_image_inline) else {
            return;
        };
        let Some(c) = gscript_label_count(&g.content) else {
            return;
        };
        if c > 0 {
            c as usize
        } else {
            out[table_idx].content.len() / 8
        }
    };
    let slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE / 4);
    let table_content = out[table_idx].content.clone();
    let mut added = 0usize;
    let mut skipped = 0usize;
    for i in 0..count.min(table_content.len() / 8).min(512) {
        let off = i * 8;
        let value = u64::from_le_bytes(table_content[off..off + 8].try_into().unwrap_or_default());
        if value == 0 {
            break;
        }
        if out.len() >= slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            skipped += 1;
            break;
        }
        if !is_heap_pointer(value, image_base, image_end) || value < MIN_HEAP_POINTER {
            skipped += 1;
            continue;
        }
        if is_exact_live_ptr(out, value) || seen_heaps.contains(&value) {
            skipped += 1;
            continue;
        }
        if looks_like_heap_handle(debugger, value) {
            skipped += 1;
            continue;
        }
        seen_heaps.insert(value);
        let mut size = estimate_object_size(
            dump_buf,
            usize::MAX,
            value,
            debugger,
            policy.first_hop_probe().min(MAX_HEAP_GLOBAL_BYTES),
        );
        if size < 8 {
            seen_heaps.remove(&value);
            skipped += 1;
            continue;
        }
        size = cap_size_before_next_base(out, value, size);
        if size < 8 {
            seen_heaps.remove(&value);
            skipped += 1;
            continue;
        }
        if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
            seen_heaps.remove(&value);
            skipped += 1;
            break;
        }
        let Ok(mut child) = alloc_capped(
            size,
            policy.first_hop_probe().min(MAX_HEAP_CONTAINER_BYTES),
            "gscript label entry",
        ) else {
            seen_heaps.remove(&value);
            skipped += 1;
            continue;
        };
        match debugger.read_memory(value as usize, &mut child) {
            Ok(n) if n >= 8 => {
                if n < child.len() {
                    child.truncate(n);
                }
            }
            _ => {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            }
        }
        child = trim_trailing_zero_pages(child);
        let cap = cap_size_before_next_base(out, value, child.len());
        if cap < child.len() {
            child.truncate(cap);
        }
        if child.len() < 8 || looks_like_heap_freelist(&child) {
            seen_heaps.remove(&value);
            skipped += 1;
            continue;
        }
        handle_string_shell_on_capture(
            &mut child,
            out,
            total_bytes,
            seen_heaps,
            image_base,
            image_end,
            dump_buf,
            debugger,
            slot_cap,
        );
        // R-GTO-UI r18: Label::mName at +0x28. Short names often live as
        // self-interior UTF-16 at +0x30; sanitize used to null that link and
        // 0x48fb0 → wcscmp(NULL) → call-obfusc AV @0xfb8f0.
        externalize_label_name_field(
            &mut child,
            value,
            out,
            total_bytes,
            seen_heaps,
            image_base,
            image_end,
            debugger,
            slot_cap,
        );
        info!(
            heap = format_args!("{value:#x}"),
            size = child.len(),
            table_off = format_args!("{off:#x}"),
            name_ptr = format_args!(
                "{:#x}",
                u64::from_le_bytes(
                    child
                        .get(0x28..0x30)
                        .and_then(|b| b.try_into().ok())
                        .unwrap_or([0; 8])
                )
            ),
            "Captured gscript label-table entry"
        );
        *total_bytes = total_bytes.saturating_add(child.len());
        // Route Y R1 A6 AF3: a label-table entry is a REAL gscript Label only
        // when it carries the canonical `gscript_label:{base}` identity. The
        // emitter is also the single point where the label's interior/parent
        // evidence is fixed — BEFORE raw capture freeze — so the Q0-C +0x23
        // scrub protection is production-reachable (live A6: B was admitted by
        // this exact emitter). When the label sits inside an already-captured
        // snapshot, classify it as InteriorSubview with a uniquely-resolved
        // containing parent; otherwise it stays a ProbeWindow with NO parent
        // evidence (never protected — no parent to bind). capture_id remains the
        // canonical base-bound `gscript_label:{value:#x}`; capture_path is the
        // truthful label-table source (not MainSlot).
        //
        // Route Y R1 A6 AF3 AF1 (P1-5): record the deterministic label-table
        // source evidence — the table-entry byte offset (`off`) and the gscript
        // root RVA (when present). probe_requested_size is 0 for this family:
        // the label-table entry size is bounded by `cap_size_before_next_base`,
        // not by a first-hop probe, so the canonical rule REQUIRES it to be 0
        // (a non-zero probe evidence would be inconsistent with this family).
        let (interior_parent, extent_kind) =
            label_table_entry_interior_classification(out, value, child.len());
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: value,
            content: child,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind,
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("gscript_label:{value:#x}"),
                capture_path: CapturePath::GscriptLabelTableEntry,
                source_root_rva,
                source_slot_offset: Some(off),
                probe_requested_size: 0,
                was_interior: interior_parent.is_some(),
                containing_parent_old_base: interior_parent.map(|(b, _)| b),
                containing_parent_size: interior_parent.map(|(_, s)| s),
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        });
        added += 1;
    }
    // Second pass: labels already exact-captured before this exhaust still need
    // mName externalized (first-hop / expand may have admitted them earlier).
    externalize_all_label_names_from_table(
        out,
        total_bytes,
        seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        policy,
    );
    info!(
        added,
        skipped,
        count,
        table = format_args!("{table_ptr:#x}"),
        total = out.len(),
        "gscript label-table entry exhaust complete"
    );
}

const LABEL_NAME_OFF: usize = 0x28;
const LABEL_INLINE_NAME_OFF: usize = 0x30;

/// Ensure Label.mName (+0x28) is an exact freeable wide-string snapshot.
fn externalize_label_name_field(
    label: &mut Vec<u8>,
    label_live: u64,
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    debugger: &mut dyn mida_core::DebuggerCore,
    slot_cap: usize,
) {
    if label.len() < LABEL_INLINE_NAME_OFF + 4 {
        return;
    }
    let name_ptr = u64::from_le_bytes(
        label[LABEL_NAME_OFF..LABEL_NAME_OFF + 8]
            .try_into()
            .unwrap_or_default(),
    );
    let label_end = label_live.saturating_add(label.len() as u64);
    let self_interior = name_ptr > label_live && name_ptr < label_end;

    // Already an exact freeable string snapshot — keep pointer for multi_fixup.
    if name_ptr != 0 && is_exact_live_ptr(out, name_ptr) && !self_interior {
        return;
    }

    // Resolve wide string bytes: prefer live name_ptr, else inline +0x30.
    let (str_live, bytes) = if name_ptr != 0
        && !self_interior
        && is_heap_pointer(name_ptr, image_base, image_end)
        && name_ptr >= MIN_HEAP_POINTER
    {
        if let Some(b) = read_wide_string_bytes(debugger, name_ptr, 0x200) {
            (name_ptr, b)
        } else if let Some(b) = extract_inline_wide_name(label) {
            // Fall back to inline copy with a stable synthetic live key.
            (label_live.saturating_add(LABEL_INLINE_NAME_OFF as u64), b)
        } else {
            return;
        }
    } else if let Some(b) = extract_inline_wide_name(label) {
        let live = if self_interior {
            name_ptr
        } else {
            label_live.saturating_add(LABEL_INLINE_NAME_OFF as u64)
        };
        (live, b)
    } else if self_interior {
        if let Some(b) = read_wide_string_bytes(debugger, name_ptr, 0x200) {
            (name_ptr, b)
        } else {
            return;
        }
    } else {
        return;
    };

    if bytes.len() < 4 {
        return;
    }

    // Capture exact string base if missing.
    if !is_exact_live_ptr(out, str_live) && !seen_heaps.contains(&str_live) {
        if out.len() >= slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            return;
        }
        // Avoid colliding with the label object base.
        if str_live == label_live {
            return;
        }
        seen_heaps.insert(str_live);
        let mut body = bytes;
        // Ensure NUL terminator for wcscmp.
        if body.len() < 2 || body[body.len() - 2..body.len()] != [0, 0] {
            body.extend_from_slice(&[0, 0]);
        }
        if total_bytes.saturating_add(body.len()) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
            seen_heaps.remove(&str_live);
            return;
        }
        info!(
            heap = format_args!("{str_live:#x}"),
            size = body.len(),
            label = format_args!("{label_live:#x}"),
            "Externalized label mName wide string"
        );
        *total_bytes = total_bytes.saturating_add(body.len());
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: str_live,
            content: body,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("external_string:{str_live:#x}"),
                capture_path: CapturePath::MainSlot,
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: 0,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        });
    }

    // Point mName at the exact string base so multi_fixup remaps it.
    label[LABEL_NAME_OFF..LABEL_NAME_OFF + 8].copy_from_slice(&str_live.to_le_bytes());
}

// Retained for the future synthetic-allocator work order (Route R R0-A external
// label wiring); currently unused because external label names fail closed.
#[allow(dead_code)]
fn extract_wide_string_from_bytes(slice: &[u8]) -> Option<Vec<u8>> {
    if slice.len() < 4 {
        return None;
    }
    let c0 = u16::from_le_bytes(slice[0..2].try_into().ok()?);
    if c0 == 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= slice.len() && i < 0x400 {
        let ch = u16::from_le_bytes(slice[i..i + 2].try_into().ok()?);
        out.extend_from_slice(&ch.to_le_bytes());
        i += 2;
        if ch == 0 {
            return if out.len() >= 4 { Some(out) } else { None };
        }
    }
    if out.len() >= 2 {
        out.extend_from_slice(&[0, 0]);
        Some(out)
    } else {
        None
    }
}

fn extract_inline_wide_name(label: &[u8]) -> Option<Vec<u8>> {
    if label.len() < LABEL_INLINE_NAME_OFF + 4 {
        return None;
    }
    let slice = &label[LABEL_INLINE_NAME_OFF..];
    let c0 = u16::from_le_bytes(slice[0..2].try_into().ok()?);
    if c0 == 0 {
        return None;
    }
    // Prefer identifier-like first char (AHK labels / hotkeys).
    let ok_first = c0 == b'_' as u16
        || c0 == b'$' as u16
        || c0 == b'@' as u16
        || (b'A' as u16..=b'Z' as u16).contains(&c0)
        || (b'a' as u16..=b'z' as u16).contains(&c0)
        || (b'0' as u16..=b'9' as u16).contains(&c0)
        || c0 > 0x7f; // non-ASCII wide labels
    if !ok_first {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= slice.len() && i < 0x100 {
        let ch = u16::from_le_bytes(slice[i..i + 2].try_into().ok()?);
        out.extend_from_slice(&ch.to_le_bytes());
        i += 2;
        if ch == 0 {
            return if out.len() >= 4 { Some(out) } else { None };
        }
    }
    if out.len() >= 2 {
        out.extend_from_slice(&[0, 0]);
        Some(out)
    } else {
        None
    }
}

fn read_wide_string_bytes(
    debugger: &mut dyn mida_core::DebuggerCore,
    ptr: u64,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let max_bytes = max_bytes.max(4).min(0x400);
    let mut buf = alloc_capped(max_bytes, max_bytes, "label name").ok()?;
    let n = debugger.read_memory(ptr as usize, &mut buf).ok()?;
    if n < 4 {
        return None;
    }
    buf.truncate(n);
    // Truncate at first UTF-16 NUL.
    let mut end = 0usize;
    while end + 2 <= buf.len() {
        let ch = u16::from_le_bytes(buf[end..end + 2].try_into().ok()?);
        end += 2;
        if ch == 0 {
            buf.truncate(end);
            return Some(buf);
        }
    }
    if buf.len() >= 2 {
        buf.extend_from_slice(&[0, 0]);
        Some(buf)
    } else {
        None
    }
}

fn externalize_all_label_names_from_table(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) {
    let Some(gscript) = out
        .iter()
        .find(|g| g.is_image_inline && g.content.len() >= 8)
    else {
        return;
    };
    let table_ptr = u64::from_le_bytes(gscript.content[0..8].try_into().unwrap_or_default());
    if table_ptr == 0 {
        return;
    }
    let Some(table) = out
        .iter()
        .find(|g| g.live_ptr == table_ptr && g.content.len() >= 8)
    else {
        return;
    };
    let count = {
        let Some(g) = out.iter().find(|g| g.is_image_inline) else {
            return;
        };
        let Some(c) = gscript_label_count(&g.content) else {
            return;
        };
        if c > 0 {
            c as usize
        } else {
            table.content.len() / 8
        }
    };
    let table_content = table.content.clone();
    let slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE / 8);
    let mut fixed = 0usize;
    for i in 0..count.min(table_content.len() / 8).min(512) {
        let value = u64::from_le_bytes(
            table_content[i * 8..i * 8 + 8]
                .try_into()
                .unwrap_or_default(),
        );
        if value == 0 {
            break;
        }
        let Some(idx) = out
            .iter()
            .position(|g| g.live_ptr == value && g.content.len() >= 0x30)
        else {
            continue;
        };
        // Move content out to satisfy borrow checker.
        let mut content = std::mem::take(&mut out[idx].content);
        let live = out[idx].live_ptr;
        externalize_label_name_field(
            &mut content,
            live,
            out,
            total_bytes,
            seen_heaps,
            image_base,
            image_end,
            debugger,
            slot_cap,
        );
        // Re-find idx — out may have grown.
        if let Some(idx2) = out.iter().position(|g| g.live_ptr == live) {
            let old_len = out[idx2].content.len();
            *total_bytes = total_bytes
                .saturating_sub(old_len)
                .saturating_add(content.len());
            out[idx2].content = content;
            fixed += 1;
        } else {
            // Should not happen; drop content bytes accounting.
            *total_bytes = total_bytes.saturating_add(content.len());
            out.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: live,
                content,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence {
                    capture_id: format!("external_string:{live:#x}"),
                    capture_path: CapturePath::MainSlot,
                    source_root_rva: None,
                    source_slot_offset: None,
                    probe_requested_size: 0,
                    was_interior: false,
                    containing_parent_old_base: None,
                    containing_parent_size: None,
                },
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
            fixed += 1;
        }
        let _ = (dump_buf, policy); // silence if unused in some builds
    }
    if fixed > 0 {
        info!(fixed, "Externalized mName on existing label-table objects");
    }
}

/// Null object link fields that still point at uncaptured heap interiors.
///
/// exact-base multi_fixup cannot rewrite interior VAs; leaving them plants
/// dump-time freelist addresses into cold start (r15b AV @0x57d01).
fn sanitize_dangling_object_links(out: &mut [HeapGlobalSnapshot], image_base: u64, image_end: u64) {
    const LINK_OFFS: &[usize] = &[0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38];
    let exact: BTreeSet<u64> = out
        .iter()
        .filter(|g| !g.is_heap_handle && g.content.len() >= 8)
        .map(|g| g.live_ptr)
        .collect();
    // (base, end) ranges for interior tests — clone before mut borrow.
    let ranges: Vec<(u64, u64)> = out
        .iter()
        .filter(|g| !g.is_heap_handle && g.content.len() >= 8)
        .map(|g| {
            (
                g.live_ptr,
                g.live_ptr.saturating_add(g.content.len() as u64),
            )
        })
        .collect();
    let mut nulled = 0usize;
    for g in out.iter_mut() {
        if g.is_heap_handle || g.content.len() < 0x20 {
            continue;
        }
        // Prefer graph children + image-inline gscript body (link fields live there).
        if g.rva != 0 && !g.is_image_inline {
            continue;
        }
        // Dense pointer tables (label arrays, cmd tables) are not object-link
        // chains — nulling entries as "dangling interiors" kills lookup.
        if looks_like_dense_pointer_table(&g.content) {
            continue;
        }
        for &loff in LINK_OFFS {
            if loff + 8 > g.content.len() {
                continue;
            }
            // Image-inline g_script: +0x10 / +0x18 are label/func *counts*
            // (dwords). Never treat them as object-link pointers — zeroing the
            // full qword wipes a real count that multi_fixup cannot restore.
            if g.is_image_inline && (loff == 0x10 || loff == 0x18) {
                continue;
            }
            let value =
                u64::from_le_bytes(g.content[loff..loff + 8].try_into().unwrap_or_default());
            if value == 0 || exact.contains(&value) {
                continue;
            }
            if !is_heap_pointer(value, image_base, image_end) || value < MIN_HEAP_POINTER {
                continue;
            }
            // Only null when the target is an *interior* of some *other* capture.
            // Self-interior (e.g. Label SSO name at this+0x30) is handled by
            // externalize_label_name_field — do not wipe it here.
            let self_lo = g.live_ptr;
            let self_hi = g.live_ptr.saturating_add(g.content.len() as u64);
            if value > self_lo && value < self_hi {
                continue;
            }
            let interior = ranges.iter().any(|&(b, e)| value > b && value < e);
            if !interior {
                continue;
            }
            g.content[loff..loff + 8].fill(0);
            nulled += 1;
        }
    }
    if nulled > 0 {
        info!(
            nulled,
            "Nulled dangling object-link interiors (exact-base safe)"
        );
    }
}

/// True when the first ~64 bytes look like a dense heap-pointer array.
fn looks_like_dense_pointer_table(content: &[u8]) -> bool {
    let n = (content.len() / 8).min(8);
    if n < 4 {
        return false;
    }
    let mut ptrs = 0u32;
    for i in 0..n {
        let v = u64::from_le_bytes(content[i * 8..i * 8 + 8].try_into().unwrap_or_default());
        if is_heap_pointer(v, 0, 0) {
            ptrs += 1;
        }
    }
    // ≥ half of first slots are user-heap shaped → treat as table, not object.
    ptrs * 2 >= n as u32
}

/// Heuristic: MSVC heap freelist / lookaside fills (repeating low patterns).
fn looks_like_heap_freelist(content: &[u8]) -> bool {
    if content.len() < 0x20 {
        return false;
    }
    // Count how many of the first 8 qwords share the same high 32 bits or
    // match freelist fill patterns seen live (0x03500350, 0x28282828…).
    let mut same_hi = 0u32;
    let mut fillish = 0u32;
    let mut prev_hi: Option<u32> = None;
    let n = (content.len() / 8).min(8);
    for i in 0..n {
        let v = u64::from_le_bytes(content[i * 8..i * 8 + 8].try_into().unwrap_or_default());
        let hi = (v >> 32) as u32;
        let lo = v as u32;
        if let Some(p) = prev_hi {
            if p == hi && hi != 0 {
                same_hi += 1;
            }
        }
        prev_hi = Some(hi);
        // byte-fill or low freelist tag patterns
        let b0 = (lo & 0xff) as u8;
        if (lo == 0x03500350 || lo == 0x28282828 || lo == 0x27272727)
            || (b0 != 0 && lo == u32::from_le_bytes([b0, b0, b0, b0]))
        {
            fillish += 1;
        }
        if hi == lo && hi != 0 && (hi == 0x03500350 || (hi & 0xff) * 0x01010101 == hi) {
            fillish += 1;
        }
    }
    fillish >= 2 || same_hi >= 4
}

/// Resize AHK cmd table root @0x147868 to live `count@0x147888 * 8`.
///
/// Main-loop large probe often admits 32KiB free-list tail; first-hop then
/// walks garbage pointers and plants freeable junk → HeapFree c0000374 after
/// MessageBox. Prefer the live count dword (preserved through overlay).
fn normalize_cmd_table_capture(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
) {
    let role = CountScaledPointerRole::cmd_table();
    let Some(idx) = out
        .iter()
        .position(|g| g.rva == role.slot_rva && !g.is_heap_handle && g.content.len() >= 8)
    else {
        return;
    };
    let (want, n) = match role.derive_extent(dump_buf) {
        CountScaledExtent::Established { extent, count } => (extent, count),
        CountScaledExtent::Unavailable => return,
    };
    let g = &mut out[idx];
    let old = g.content.len();
    if old == want {
        return;
    }
    if old > want {
        g.content.truncate(want);
        *total_bytes = total_bytes.saturating_sub(old - want);
        info!(
            rva = format_args!("{:#x}", role.slot_rva),
            count = n,
            old_size = old,
            new_size = want,
            "Normalized cmd table capture to live count*8 (truncated)"
        );
        return;
    }
    // old < want: re-read exclusive range from live heap
    let live = g.live_ptr;
    if !can_read(debugger, live, want, HOT_XREF_SIZE_PROBE_CAP) {
        return;
    }
    let Ok(mut buf) = alloc_capped(want, HOT_XREF_SIZE_PROBE_CAP, "cmd table normalize") else {
        return;
    };
    match debugger.read_memory(live as usize, &mut buf) {
        Ok(got) if got >= 8 => {
            if got < buf.len() {
                buf.truncate(got);
            }
        }
        _ => return,
    }
    *total_bytes = total_bytes.saturating_sub(old).saturating_add(buf.len());
    g.content = buf;
    info!(
        rva = format_args!("{:#x}", role.slot_rva),
        count = n,
        old_size = old,
        new_size = g.content.len(),
        "Normalized cmd table capture to live count*8 (re-read)"
    );
}

/// MIDA-SERIAL-27: identity-bound count-scaled pointer-table role.
///
/// This is the SINGLE production fact source for the AHK cmd/dispatch
/// table's identity-bound structural layout. It is explicitly sample-bound:
/// `slot_rva`, `count_offset` and `element_size` encode the bound sample's
/// object model; it is NOT a generic pointer-table discovery rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CountScaledPointerRole {
    /// Image RVA of the slot that holds the object/table pointer.
    slot_rva: u32,
    /// Slot-relative byte offset of the element-count dword.
    count_offset: usize,
    /// Element size in bytes (pointer stride).
    element_size: usize,
    /// Inclusive lower bound for the live element-count dword.
    min_count: u32,
    /// Inclusive upper bound for the live element-count dword.
    max_count: u32,
    /// Minimum valid derived extent in bytes.
    min_extent: usize,
}

/// Shared result of deriving a count-scaled extent from a dump buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CountScaledExtent {
    /// The count dword was readable and structurally valid; carries the
    /// checked count * element_size extent in bytes and the validated count.
    Established { extent: usize, count: u32 },
    /// The boundary could not be established (unreadable / truncated /
    /// invalid count / checked arithmetic failed / extent below minimum).
    Unavailable,
}

impl CountScaledPointerRole {
    /// The single production instance: AHK cmd/dispatch table @0x147868,
    /// count dword @ +0x20 (0x147888), 8-byte elements.
    const fn cmd_table() -> Self {
        Self {
            slot_rva: 0x147868,
            count_offset: 0x20,
            element_size: 8,
            min_count: 1,
            max_count: 0xffff,
            min_extent: 8,
        }
    }

    /// Identity-bound role predicate.
    fn is_slot(&self, rva: u32) -> bool {
        self.slot_rva == rva
    }

    /// Derive the count dword's RVA as `slot_rva + count_offset` (checked).
    fn count_rva(&self) -> Option<usize> {
        (self.slot_rva as usize).checked_add(self.count_offset)
    }

    /// Shared checked extent derivation.
    ///
    /// All consumers use this helper for the identity-bound count-scaled
    /// role. A count that is readable and valid but whose derived extent does
    /// not match a captured content length is NOT decided here; callers keep
    /// their layer-specific conflict handling (e.g. first-hop Ambiguous).
    fn derive_extent(&self, dump_buf: &[u8]) -> CountScaledExtent {
        let Some(count_rva) = self.count_rva() else {
            return CountScaledExtent::Unavailable;
        };
        let Some(end) = count_rva.checked_add(4) else {
            return CountScaledExtent::Unavailable;
        };
        if end > dump_buf.len() {
            return CountScaledExtent::Unavailable;
        }
        let Ok(four) = <[u8; 4]>::try_from(&dump_buf[count_rva..count_rva + 4]) else {
            return CountScaledExtent::Unavailable;
        };
        let n = u32::from_le_bytes(four);
        if !(self.min_count..=self.max_count).contains(&n) {
            return CountScaledExtent::Unavailable;
        }
        let Some(want) = (n as usize).checked_mul(self.element_size) else {
            return CountScaledExtent::Unavailable;
        };
        if want < self.min_extent {
            return CountScaledExtent::Unavailable;
        }
        CountScaledExtent::Established {
            extent: want,
            count: n,
        }
    }
}

/// MIDA-SERIAL-25: identity-bound declared first-hop role.
///
/// This is a SAMPLE-BOUND / identity-bound declaration, NOT a generic
/// structural discovery: the role, its layout facts (count dword
/// placement, element size, bounded field window) and its RVAs encode the
/// bound sample's object model. Activation additionally requires the
/// current capture to corroborate the declared semantics (verified
/// count-scaled boundary for the table role; bounded field window +
/// capture filters for the global-object role). The declaration alone —
/// like density, size, section placement or a hot-root / large-table
/// policy nomination — never activates a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeclaredFirstHopRole {
    /// Image RVA of the slot that holds the object/table pointer.
    slot_rva: u32,
    /// Identity-bound role kind with its structural layout facts.
    kind: FirstHopRoleKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstHopRoleKind {
    /// Pointer table whose extent is `count * element_size`, where the
    /// count dword lives at `slot_rva + count_offset` in the dump buffer.
    /// All arithmetic is checked; the captured extent must EXACTLY equal
    /// the count-scaled boundary (i.e. the normalized table capture).
    PointerTableCountScaled {
        /// Slot-relative byte offset of the element-count dword.
        count_offset: usize,
        /// Element size in bytes (pointer stride).
        element_size: usize,
    },
    /// Bounded field window inside a captured global object: walk only
    /// `min(content.len(), max_span)` bytes from the object base. This is
    /// the AHK global-object bounded first-hop (cover +0xd8 interior
    /// child pointer, avoid stale VA after multi-fixup). Never a
    /// count-scaled pointer table; never widened by density or content
    /// size beyond `max_span`.
    BoundedPointerWindow {
        /// Maximum scan window in bytes (8 <= span <= max_span).
        max_span: usize,
    },
}

/// MIDA-SERIAL-25: the identity-bound declared first-hop roles.
///
/// Exactly two sample-bound roles reproduce the HEAD first-hop action set:
///
///   Role 1 — AHK cmd/dispatch pointer table @0x147868 with live element
///   count dword @0x147888 (slot +0x20). Mirrors the count x 8 boundary
///   already used by `normalize_cmd_table_capture` and the hot-root
///   ensure path, expressed as a declared identity-bound role.
///
///   Role 2 — AHK global object @0x141bf0 bounded field window: scan only
///   the first 0x200 bytes (cover the +0xd8 interior child pointer). This
///   reproduces the HEAD `exhaust_pointer_table_first_hop_span(0x141bf0,
///   0x200, ...)` bounded first-hop as an explicit identity-bound role.
///
/// Everything else — every other hot root, every other large-table
/// nomination, every dense or pointer-rich object — fails closed (Missing).
fn declared_first_hop_roles() -> &'static [DeclaredFirstHopRole] {
    const CMD: CountScaledPointerRole = CountScaledPointerRole::cmd_table();
    &[
        DeclaredFirstHopRole {
            slot_rva: CMD.slot_rva,
            kind: FirstHopRoleKind::PointerTableCountScaled {
                count_offset: CMD.count_offset,
                element_size: CMD.element_size,
            },
        },
        DeclaredFirstHopRole {
            slot_rva: 0x141bf0,
            kind: FirstHopRoleKind::BoundedPointerWindow {
                max_span: 0x200, // cover +0xd8 and nearby fields only
            },
        },
    ]
}

/// Outcome of verifying a declared count x element-size boundary against the
/// current capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CountExtentOutcome {
    /// The declared boundary is established AND exactly matches the captured
    /// extent. Carries the verified extent in bytes.
    Verified(usize),
    /// The boundary cannot be established from the current capture (count
    /// dword unreadable / out of bounds / checked arithmetic failed /
    /// count invalid / extent below 8). Fail-closed as Missing.
    Unverifiable,
    /// The boundary IS established (count dword readable and valid) but
    /// CONFLICTS with the captured extent (count-scaled size != content).
    /// A single slot carrying conflicting structural extents is ambiguous;
    /// fail-closed as Ambiguous.
    Conflict,
}

/// Verify the declared first-hop role boundary against the current capture.
/// See [`CountExtentOutcome`] for the three-way result.
///
/// For [`FirstHopRoleKind::PointerTableCountScaled`] (checks must ALL hold
/// for [`CountExtentOutcome::Verified`]):
///   * count dword readable at slot_rva + count_offset in dump_buf;
///   * count in [1, 0x10000);
///   * count.checked_mul(element_size) succeeds;
///   * verified extent >= 8;
///   * verified extent EXACTLY equals g.content.len() — the captured
///     extent must be the normalized count-scaled boundary, not a larger
///     probe window or free-list tail. A readable-but-mismatching count
///     is a Conflict -> Ambiguous.
///
/// For [`FirstHopRoleKind::BoundedPointerWindow`]:
///   * span = min(content.len(), max_span);
///   * span in [8, max_span] (content too short -> Unverifiable);
///   * never widened by density, content size or pointer count;
///   * never reads or enumerates beyond max_span.
fn verify_first_hop_role(
    g: &HeapGlobalSnapshot,
    role: &DeclaredFirstHopRole,
    dump_buf: &[u8],
) -> CountExtentOutcome {
    match role.kind {
        FirstHopRoleKind::PointerTableCountScaled {
            count_offset,
            element_size,
        } => {
            // The only count-scaled identity role in production is the cmd
            // table; verification must consume that exact single fact source.
            // A declared role that drifts from the source fails closed rather
            // than introducing a second structural definition.
            let cmd = CountScaledPointerRole::cmd_table();
            if cmd.slot_rva != role.slot_rva
                || cmd.count_offset != count_offset
                || cmd.element_size != element_size
            {
                return CountExtentOutcome::Unverifiable;
            }
            let want = match cmd.derive_extent(dump_buf) {
                CountScaledExtent::Established { extent, .. } => extent,
                CountScaledExtent::Unavailable => return CountExtentOutcome::Unverifiable,
            };
            if want != g.content.len() {
                // Boundary established but conflicting with the captured extent.
                return CountExtentOutcome::Conflict;
            }
            CountExtentOutcome::Verified(want)
        }
        FirstHopRoleKind::BoundedPointerWindow { max_span } => {
            let span = g.content.len().min(max_span);
            if span < 8 {
                return CountExtentOutcome::Unverifiable;
            }
            CountExtentOutcome::Verified(span)
        }
    }
}
/// MIDA-SERIAL-25: identity-bound first-hop candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FirstHopCandidate {
    table_rva: u32,
    live_ptr: u64,
    section_index: usize,
    section_name: String,
    slot_offset_in_section: usize,
    span: usize,
    probe: usize,
    evidence: FirstHopCandidateEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstHopCandidateEvidence {
    /// The declared count x element-size boundary was verified against the
    /// current capture (identity-bound table role).
    VerifiedCountScaledExtent,
    /// The declared bounded field window (identity-bound global-object
    /// role); span is min(content.len(), max_span), never density-widened.
    IdentityBoundedPointerWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FirstHopCandidateResolution {
    /// Every candidate has an independent verified identity-bound role.
    Resolved(Vec<FirstHopCandidate>),
    /// No candidate passed the role + capture evidence gate -> no first-hop.
    Missing,
    /// Conflicting structural claims (same live body by distinct slots,
    /// or conflicting extents) -> no first-hop.
    Ambiguous,
}

/// MIDA-SERIAL-25: derive first-hop candidates from the CURRENT capture.
///
/// The inline first-hop calls are centralized as explicit identity-bound
/// sample roles ([`declared_first_hop_roles`]). Activation remains
/// identity-gated (the caller wraps this in `if sample_active`) and
/// capture-corroborated. This does NOT eliminate sample-specific RVA
/// coupling: the roles carry sample-bound RVAs and layout facts.
///
/// Density / size / section placement / user-heap pointer are FILTERS
/// only — none of them, alone or combined, can admit a candidate.
/// Deterministic: sorted by (section index, slot offset, rva, live_ptr)
/// and deduped by that key.
fn derive_first_hop_candidates(
    pe: &PeHeader,
    out: &[HeapGlobalSnapshot],
    policy: &DumpCapturePolicy,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
) -> FirstHopCandidateResolution {
    let roles = declared_first_hop_roles();
    let mut cands: BTreeMap<(usize, usize, u32, u64), FirstHopCandidate> = BTreeMap::new();

    for g in out {
        // Filters (never activators): slot present in the capture.
        if g.rva == 0 || g.is_heap_handle || g.content.len() < 8 {
            continue;
        }
        if policy.gscript_root() == Some(g.rva) {
            continue;
        }
        // Filters: non-executable data section placement.
        let Some((sec_idx, sec)) = pe.sections.iter().enumerate().find(|(_, s)| {
            let lo = s.virtual_address;
            let hi = lo.saturating_add(s.virtual_size.max(1));
            g.rva >= lo && g.rva < hi
        }) else {
            continue;
        };
        if sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            continue;
        }
        // Filters: object/table body must be a user-heap pointer.
        if !is_heap_pointer(g.live_ptr, image_base, image_end) {
            continue;
        }
        // Activator: identity-bound declared role for this slot.
        let Some(role) = roles.iter().find(|r| r.slot_rva == g.rva) else {
            continue;
        };
        // Activator: role-specific structural verification against the
        // current capture (count-scaled boundary or bounded field window).
        let (verified, evidence) = match verify_first_hop_role(g, role, dump_buf) {
            CountExtentOutcome::Verified(v) => match role.kind {
                FirstHopRoleKind::PointerTableCountScaled { .. } => {
                    (v, FirstHopCandidateEvidence::VerifiedCountScaledExtent)
                }
                FirstHopRoleKind::BoundedPointerWindow { .. } => {
                    (v, FirstHopCandidateEvidence::IdentityBoundedPointerWindow)
                }
            },
            CountExtentOutcome::Unverifiable => continue,
            CountExtentOutcome::Conflict => {
                // A single slot with a conflicting structural extent is
                // ambiguous — fail closed, run zero first-hop actions.
                return FirstHopCandidateResolution::Ambiguous;
            }
        };
        let offset_in_sec = g.rva.saturating_sub(sec.virtual_address) as usize;
        let key = (sec_idx, offset_in_sec, g.rva, g.live_ptr);
        cands.insert(
            key,
            FirstHopCandidate {
                table_rva: g.rva,
                live_ptr: g.live_ptr,
                section_index: sec_idx,
                section_name: sec.name.clone(),
                slot_offset_in_section: offset_in_sec,
                span: verified,
                probe: policy.first_hop_probe(),
                evidence,
            },
        );
    }

    if cands.is_empty() {
        return FirstHopCandidateResolution::Missing;
    }
    // Conflict detection: distinct slots claiming the SAME live table body
    // cannot be uniquely decided -> Ambiguous (fail-closed, no heuristic pick).
    let mut by_live: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
    for (_, c) in &cands {
        by_live.entry(c.live_ptr).or_default().push(c.table_rva);
    }
    if by_live.values().any(|v| v.len() > 1) {
        return FirstHopCandidateResolution::Ambiguous;
    }
    FirstHopCandidateResolution::Resolved(cands.into_values().collect())
}

/// MIDA-SERIAL-25: run first-hop exhaust for every resolved identity-bound
/// candidate using its role-derived span (count-scaled extent for the
/// table role; bounded field window for the global-object role). The
/// candidate source is the explicit identity-bound role declaration —
/// this does NOT eliminate sample-specific RVA coupling.
fn exhaust_first_hop_candidates(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    candidates: &[FirstHopCandidate],
) {
    for c in candidates {
        exhaust_pointer_table_first_hop_span(
            out,
            total_bytes,
            seen_heaps,
            image_base,
            image_end,
            dump_buf,
            debugger,
            c.table_rva,
            c.span,
            c.probe,
        );
        let (kind_label, semantics) = match c.evidence {
            FirstHopCandidateEvidence::VerifiedCountScaledExtent => {
                ("pointer_table_count_scaled", "full count-scaled extent")
            }
            FirstHopCandidateEvidence::IdentityBoundedPointerWindow => {
                ("bounded_pointer_window", "bounded field window")
            }
        };
        info!(
            table_rva = format_args!("{:#x}", c.table_rva),
            live = format_args!("{:#x}", c.live_ptr),
            section = %c.section_name,
            span = c.span,
            role_kind = kind_label,
            span_semantics = semantics,
            evidence = ?c.evidence,
            "MIDA-SERIAL-25 first-hop candidate exhaust"
        );
    }
}

fn exhaust_pointer_table_first_hop_span(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    table_rva: u32,
    max_span: usize,
    probe: usize,
) {
    let slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE / 2);
    let Some(table_idx) = out
        .iter()
        .position(|g| g.rva == table_rva && !g.is_heap_handle && g.content.len() >= 8)
    else {
        return;
    };

    let full = out[table_idx].content.clone();
    let span = full.len().min(max_span);
    let content = full[..span].to_vec();
    let mut targets: Vec<(usize, u64)> = Vec::new();
    let mut off = 0usize;
    while off + 8 <= content.len() {
        let v = u64::from_le_bytes(content[off..off + 8].try_into().unwrap_or_default());
        off += 8;
        if v == 0 {
            continue;
        }
        if !is_heap_pointer(v, image_base, image_end) || v < MIN_HEAP_POINTER {
            continue;
        }
        if v >= 0x1_0000_0000 {
            continue;
        }
        if is_exact_live_ptr(out, v) {
            continue;
        }
        targets.push((off - 8, v));
    }
    if targets.is_empty() {
        info!(
            rva = format_args!("{table_rva:#x}"),
            slots = content.len() / 8,
            "pointer-table first-hop: no external heap edges"
        );
        return;
    }

    let mut added = 0usize;
    let mut skipped = 0usize;
    let edge_count = targets.len();
    let probe = probe.min(MAX_HEAP_GLOBAL_BYTES).max(0x40);
    for (edge_off, value) in targets {
        if out.len() >= slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            skipped += 1;
            continue;
        }
        if is_exact_live_ptr(out, value) || seen_heaps.contains(&value) {
            skipped += 1;
            continue;
        }
        if looks_like_heap_handle(debugger, value) {
            skipped += 1;
            continue;
        }
        seen_heaps.insert(value);
        let mut size = estimate_object_size(dump_buf, usize::MAX, value, debugger, probe);
        if size < 8 {
            size = if can_read(debugger, value, 0x40, probe) {
                0x40
            } else if can_read(debugger, value, 0x20, probe) {
                0x20
            } else {
                skipped += 1;
                continue;
            };
        }
        size = cap_size_before_next_base(out, value, size);
        if size < 8 {
            skipped += 1;
            continue;
        }
        let Ok(mut child) = alloc_capped(
            size,
            probe.min(MAX_HEAP_CONTAINER_BYTES),
            "pointer-table first-hop child",
        ) else {
            skipped += 1;
            continue;
        };
        match debugger.read_memory(value as usize, &mut child) {
            Ok(n) if n >= 8 => {
                if n < child.len() {
                    child.truncate(n);
                }
            }
            _ => {
                skipped += 1;
                continue;
            }
        }
        child = trim_trailing_zero_pages(child);
        if child.len() < 8 {
            skipped += 1;
            continue;
        }
        handle_string_shell_on_capture(
            &mut child,
            out,
            total_bytes,
            seen_heaps,
            image_base,
            image_end,
            dump_buf,
            debugger,
            slot_cap,
        );
        if child.len() < 8 {
            skipped += 1;
            continue;
        }
        info!(
            table_rva = format_args!("{table_rva:#x}"),
            heap = format_args!("{value:#x}"),
            size = child.len(),
            table_off = format_args!("{edge_off:#x}"),
            "Captured pointer-table first-hop edge"
        );
        *total_bytes = total_bytes.saturating_add(child.len());
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: value,
            content: child,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("gscript_child:{value:#x}"),
                capture_path: CapturePath::GscriptChildLink,
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: 0,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        });
        added += 1;
    }

    info!(
        table_rva = format_args!("{table_rva:#x}"),
        added,
        skipped,
        edges = edge_count,
        total = out.len(),
        "pointer-table first-hop exhaust complete"
    );
}

/// Cap `size` so `[base, base+size)` stops before the next exact live_ptr base.
/// Unlike `shrink_to_avoid_overlap`, does **not** reject bases that sit inside
/// an existing capture (needed for gscript first-hop exact children).
fn cap_size_before_next_base(out: &[HeapGlobalSnapshot], base: u64, size: usize) -> usize {
    let mut end = base.saturating_add(size as u64);
    for o in out {
        if o.is_heap_handle || o.content.is_empty() {
            continue;
        }
        if o.live_ptr > base && o.live_ptr < end {
            end = o.live_ptr;
        }
    }
    end.saturating_sub(base) as usize
}

/// Multi-hop BFS seeded only from known hot image roots (and their admitted
/// children). p20 single-hop still left gscript edges scrubbed → dafa4 AV.
fn expand_hot_root_children(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) {
    const MAX_HOT_TOTAL: usize = 200;
    const MAX_HOT_ROUNDS: usize = 5;
    const MAX_PER_ROUND: usize = 48;
    // Compact children for string shells; large tables already captured as roots.
    const HOT_CHILD_PROBE: usize = 0x1000;
    let slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE);
    if out.is_empty() || out.len() >= slot_cap {
        return;
    }

    // Seed ONLY the critical script/title roots. Expanding every hot table
    // (0x148c00/0x148c98…) floods the budget with free-list neighbours
    // while gscript keeps ~2 live heap_ptrs at runtime (packed has ~32).
    // p21: gscript first-hop already exhaust-admitted; also seed multi-hop from
    // those exact children (matched by live_ptr in gscript first-hop span).
    let mut frontier: Vec<usize> = out
        .iter()
        .enumerate()
        .filter(|(_, g)| {
            policy.hot_expand_seed_rvas.contains(&g.rva)
                && !g.is_heap_handle
                && g.content.len() >= 8
        })
        .map(|(i, _)| i)
        .collect();
    // Collect first-hop heap targets from gscript blob, then map to admitted
    // child indices so hop-2 BFS walks real AHK objects not free-list noise.
    if let Some(gscript_rva) = policy.gscript_root() {
        if let Some(g_idx) = out
            .iter()
            .position(|g| g.rva == gscript_rva && !g.is_heap_handle)
        {
            let span = policy.first_hop_span().min(out[g_idx].content.len());
            let mut first_hop_ptrs: BTreeSet<u64> = BTreeSet::new();
            let mut off = 0usize;
            while off + 8 <= span {
                let v = u64::from_le_bytes(
                    out[g_idx].content[off..off + 8]
                        .try_into()
                        .unwrap_or_default(),
                );
                off += 8;
                if is_heap_pointer(v, image_base, image_end) && v >= MIN_GRAPH_CHILD_POINTER {
                    first_hop_ptrs.insert(v);
                }
            }
            for (i, g) in out.iter().enumerate() {
                if g.rva == 0 && !g.is_heap_handle && first_hop_ptrs.contains(&g.live_ptr) {
                    if !frontier.contains(&i) {
                        frontier.push(i);
                    }
                }
            }
        }
    }
    if frontier.is_empty() {
        return;
    }

    let mut total_added = 0usize;
    for round in 0..MAX_HOT_ROUNDS {
        if total_added >= MAX_HOT_TOTAL || out.len() >= slot_cap {
            break;
        }
        let mut candidates: BTreeMap<u64, u32> = BTreeMap::new();
        for &idx in &frontier {
            let content = &out[idx].content;
            // For the gscript root itself, only walk first-hop span (rest is
            // free-list noise after oversize probes / dense tables).
            let walk_len = if policy.gscript_root() == Some(out[idx].rva) {
                policy.first_hop_span().min(content.len())
            } else {
                content.len()
            };
            let mut off = 0usize;
            while off + 8 <= walk_len {
                let v = u64::from_le_bytes(content[off..off + 8].try_into().unwrap_or_default());
                off += 8;
                if !is_heap_pointer(v, image_base, image_end) || v < MIN_GRAPH_CHILD_POINTER {
                    continue;
                }
                // Prefer gscript mid-heap; skip ultra-high free-list arenas.
                if v >= 0x1_0000_0000 {
                    continue;
                }
                if seen_heaps.contains(&v) || range_contains(out, v) {
                    continue;
                }
                *candidates.entry(v).or_insert(0) += 1;
            }
        }
        if candidates.is_empty() {
            break;
        }
        let mut ranked: Vec<(u64, u32)> = candidates.into_iter().collect();
        ranked.sort_by(|a, b| {
            let ra = expand_candidate_rank(1000 + a.1, a.0);
            let rb = expand_candidate_rank(1000 + b.1, b.0);
            rb.cmp(&ra)
        });

        let len_before = out.len();
        let mut added = 0usize;
        for (value, refs) in ranked {
            if added >= MAX_PER_ROUND || total_added >= MAX_HOT_TOTAL || out.len() >= slot_cap {
                break;
            }
            if *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
                break;
            }
            if !seen_heaps.insert(value) || range_contains(out, value) {
                seen_heaps.remove(&value);
                continue;
            }
            if looks_like_heap_handle(debugger, value) {
                seen_heaps.remove(&value);
                continue;
            }
            let mut size = estimate_object_size(
                dump_buf,
                usize::MAX,
                value,
                debugger,
                HOT_CHILD_PROBE.min(MAX_HEAP_GLOBAL_BYTES),
            );
            if size < 8 {
                seen_heaps.remove(&value);
                continue;
            }
            size = shrink_to_avoid_overlap(out, value, size);
            if size < 8 {
                seen_heaps.remove(&value);
                continue;
            }
            if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
                seen_heaps.remove(&value);
                break;
            }
            let Ok(mut content) = alloc_capped(
                size,
                HOT_CHILD_PROBE.min(MAX_HEAP_CONTAINER_BYTES),
                "heap hot-root child",
            ) else {
                seen_heaps.remove(&value);
                continue;
            };
            match debugger.read_memory(value as usize, &mut content) {
                Ok(n) if n >= 8 => {
                    if n < content.len() {
                        content.truncate(n);
                    }
                }
                _ => {
                    seen_heaps.remove(&value);
                    continue;
                }
            }
            content = trim_trailing_zero_pages(content);
            content = truncate_to_avoid_overlap(out, value, content);
            if content.len() < 8 {
                seen_heaps.remove(&value);
                continue;
            }
            // Capture string buffers + shrink shell to freeable 0x28.
            handle_string_shell_on_capture(
                &mut content,
                out,
                total_bytes,
                seen_heaps,
                image_base,
                image_end,
                dump_buf,
                debugger,
                slot_cap,
            );
            info!(
                heap = format_args!("{value:#x}"),
                size = content.len(),
                refs,
                round = round + 1,
                "Captured hot-root graph child (gscript seed)"
            );
            *total_bytes = total_bytes.saturating_add(content.len());
            out.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: value,
                content,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence {
                    capture_id: format!("gscript_seed_child:{value:#x}"),
                    capture_path: CapturePath::GscriptFirstHop,
                    source_root_rva: None,
                    source_slot_offset: None,
                    probe_requested_size: 0,
                    was_interior: false,
                    containing_parent_old_base: None,
                    containing_parent_size: None,
                },
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
            added += 1;
            total_added += 1;
        }
        if added == 0 {
            break;
        }
        // Next round walks only newly admitted hot children.
        frontier = (len_before..out.len()).collect();
    }
    if total_added > 0 {
        info!(
            added = total_added,
            total = out.len(),
            "Hot-root multi-hop expand pass complete"
        );
    }
}

/// Priority of a capture as an expand *source*. Hot gscript image roots must
/// win over cold large tables that point into high-VA free-list arenas.
fn expand_source_priority(g: &HeapGlobalSnapshot, policy: &DumpCapturePolicy) -> u32 {
    if g.is_heap_handle || g.content.len() < 8 {
        return 0;
    }
    if policy.is_hot_root(g.rva) {
        return 1000;
    }
    if g.rva != 0 {
        // Image roots are already ordered by xref at capture; keep them above
        // anonymous children so round-0 seed BFS stays useful.
        return 100;
    }
    // Graph children: modest priority so multi-hop still works after seeds.
    10
}

/// Rank an edge for admission. p19c pure high-VA sort filled 144 slots with
/// 0x82xxxxxx free-list noise while gscript (0xa0ff30) children were scrubbed.
fn expand_candidate_rank(parent_priority: u32, value: u64) -> (u32, u8, u64) {
    // Prefer mid user heap (script objects) over ultra-high private arenas.
    // 0x1_0000_0000+ is often large private mappings / free lists on this sample.
    let band = if value < 0x0100_0000 {
        2u8 // low mid — ok
    } else if value < 0x1000_0000 {
        3u8 // best: typical AHK object band for this dump
    } else if value < 0x1_0000_0000 {
        1u8 // high private — often free-list noise
    } else {
        0u8 // very high — last resort
    };
    // Within a band, prefer higher VA (AHK tables cluster high inside the band).
    (parent_priority, band, value)
}

/// BFS: any heap pointer inside captured content that is not already covered by
/// a captured range becomes a new snapshot (`rva=0`). multi_fixup then remaps
/// those edges instead of leaving dump-time absolutes or scrubbing to NULL.
fn expand_heap_graph(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) {
    if out.is_empty() {
        return;
    }

    // Round 0 walks every currently-captured blob (roots + prior children +
    // free-safe splits). Later rounds walk only nodes admitted this expand
    // call. Low-VA filter keeps heap-manager junk out.
    let _ = MAX_EXPAND_ROOTS; // kept for documentation / future hot-root bias
    let mut scan_from = 0usize;
    let mut scan_to = out.len();
    let expand_slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE);
    // Inherit parent priority into newly admitted nodes so multi-hop stays
    // biased toward gscript even after the first hop leaves image RVAs.
    let mut node_priority: Vec<u32> = out
        .iter()
        .map(|g| expand_source_priority(g, policy))
        .collect();
    for round in 0..MAX_GRAPH_EXPAND_ROUNDS {
        if out.len() >= expand_slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            break;
        }
        // Keep priority vector aligned (split may have grown `out` between calls).
        while node_priority.len() < out.len() {
            let idx = node_priority.len();
            node_priority.push(expand_source_priority(&out[idx], policy));
        }

        // (value, best_parent_priority)
        let mut candidates: BTreeMap<u64, u32> = BTreeMap::new();
        let end = scan_to.min(out.len());
        for (idx, g) in out.iter().enumerate().take(end).skip(scan_from) {
            let parent_pri = node_priority.get(idx).copied().unwrap_or(0);
            if parent_pri == 0 {
                continue;
            }
            let mut off = 0usize;
            while off + 8 <= g.content.len() {
                let v = u64::from_le_bytes(g.content[off..off + 8].try_into().unwrap_or_default());
                off += 8;
                if !is_heap_pointer(v, image_base, image_end) {
                    continue;
                }
                // Prefer mid/high heap: low-VA LFH neighbourhoods burn slots.
                if v < MIN_GRAPH_CHILD_POINTER {
                    continue;
                }
                if seen_heaps.contains(&v) || range_contains(out, v) {
                    continue;
                }
                let entry = candidates.entry(v).or_insert(0);
                if parent_pri > *entry {
                    *entry = parent_pri;
                }
            }
        }

        if candidates.is_empty() {
            break;
        }

        // Seed-first, then mid-heap band (gscript), not pure high-VA free lists.
        let mut ranked: Vec<(u64, u32)> = candidates.into_iter().collect();
        ranked.sort_by(|a, b| {
            let ra = expand_candidate_rank(a.1, a.0);
            let rb = expand_candidate_rank(b.1, b.0);
            rb.cmp(&ra)
        });

        let len_before = out.len();
        let mut added = 0usize;
        for (value, parent_pri) in ranked {
            if added >= MAX_EXPAND_PER_ROUND {
                break;
            }
            if out.len() >= expand_slot_cap {
                break;
            }
            if !seen_heaps.insert(value) || range_contains(out, value) {
                seen_heaps.remove(&value);
                continue;
            }
            // Never expand a process-heap handle as a data child.
            if looks_like_heap_handle(debugger, value) {
                seen_heaps.remove(&value);
                continue;
            }

            let mut size = estimate_object_size(
                dump_buf,
                usize::MAX,
                value,
                debugger,
                GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES),
            );
            if size == 0 {
                seen_heaps.remove(&value);
                continue;
            }
            size = shrink_to_avoid_overlap(out, value, size);
            if size < 8 {
                seen_heaps.remove(&value);
                continue;
            }
            if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
                seen_heaps.remove(&value);
                warn!(
                    heap = format_args!("{value:#x}"),
                    size,
                    total = *total_bytes,
                    "Heap-global expand hit total size cap"
                );
                break;
            }

            let Ok(mut content) = alloc_capped(
                size,
                GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_CONTAINER_BYTES),
                "heap graph",
            ) else {
                seen_heaps.remove(&value);
                continue;
            };
            match debugger.read_memory(value as usize, &mut content) {
                Ok(n) if n >= 8 => {
                    if n < content.len() {
                        content.truncate(n);
                    }
                }
                _ => {
                    seen_heaps.remove(&value);
                    continue;
                }
            }
            content = trim_trailing_zero_pages(content);
            content = truncate_to_avoid_overlap(out, value, content);
            if content.len() < 8 {
                seen_heaps.remove(&value);
                continue;
            }
            handle_string_shell_on_capture(
                &mut content,
                out,
                total_bytes,
                seen_heaps,
                image_base,
                image_end,
                dump_buf,
                debugger,
                expand_slot_cap,
            );

            info!(
                heap = format_args!("{value:#x}"),
                size = content.len(),
                round = round + 1,
                parent_pri,
                "Captured heap-graph child (no image slot)"
            );
            *total_bytes = total_bytes.saturating_add(content.len());
            // Children of hot seeds stay hot so multi-hop title/control objects
            // keep winning over free-list noise from cold tables.
            let child_pri = parent_pri.saturating_sub(1).max(10);
            out.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: value,
                content,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence {
                    capture_id: format!("graph_child:{value:#x}"),
                    capture_path: CapturePath::GscriptFirstHop,
                    source_root_rva: None,
                    source_slot_offset: None,
                    probe_requested_size: 0,
                    was_interior: false,
                    containing_parent_old_base: None,
                    containing_parent_size: None,
                },
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
            node_priority.push(child_pri);
            added += 1;
        }

        if added == 0 {
            break;
        }
        // Walk only nodes admitted this round on the next pass (must set after
        // pushes — previously scan_to stayed at pre-push len so rounds 2+ were
        // empty and multi-hop AHK graphs never expanded).
        scan_from = len_before;
        scan_to = out.len();
        info!(
            round = round + 1,
            added,
            total = out.len(),
            "Heap-graph expansion round complete"
        );
    }
}

fn range_contains(out: &[HeapGlobalSnapshot], addr: u64) -> bool {
    out.iter().any(|o| {
        let end = o.live_ptr.saturating_add(o.content.len() as u64);
        addr >= o.live_ptr && addr < end
    })
}

/// Find the smallest (innermost) authoritative containing snapshot of `target`,
/// i.e. the non-handle, non-empty snapshot whose range `[live_ptr, live_ptr+len)`
/// contains `target`. GTO R0-G.
///
/// When multiple snapshots contain `target`, the smallest (by size) is chosen —
/// the most specific authoritative parent. This is a deterministic rule (not
/// iteration order) so a child-link / first-hop interior view always records the
/// same containing parent regardless of snapshot order.
fn find_containing_snapshot(out: &[HeapGlobalSnapshot], target: u64) -> Option<(u64, usize)> {
    let mut best: Option<(u64, usize)> = None; // (old_base, size)
    for o in out {
        if o.is_heap_handle || o.content.is_empty() {
            continue;
        }
        let end = o.live_ptr.saturating_add(o.content.len() as u64);
        if o.live_ptr <= target && target < end {
            match best {
                None => best = Some((o.live_ptr, o.content.len())),
                Some((_, bs)) if o.content.len() < bs => best = Some((o.live_ptr, o.content.len())),
                _ => {}
            }
        }
    }
    best
}

/// Route Y R1 A6 AF3: classify a freshly-admitted label-table entry's interior
/// status deterministically at EMITTER time (before raw capture freeze). Returns
/// `(Some(parent_base, parent_size), InteriorSubview)` only when the label lies
/// inside a UNIQUELY-resolved containing snapshot; otherwise `(None, ProbeWindow)`.
///
/// The containing parent is the innermost non-empty, non-handle snapshot that
/// contains the label address. If two DIFFERENT snapshots share the same innermost
/// (base, size) — i.e. the parent is ambiguous — it fails closed to ProbeWindow
/// (no parent evidence → the entry is never claimed as InteriorSubview nor
/// protected). This is the production counterpart of the AF2/AF2R1 fixture's
/// InteriorSubview + parent classification, now reachable from the real emitter.
/// Route Y R1 A6 AF3 AF1 (P1-4): resolve the unique containing parent for a
/// label-table entry admitted by the exhaust emitter, using the **full child
/// range** (base AND actual size) so a label that starts inside a parent but
/// extends beyond it is NOT misclassified as InteriorSubview.
///
/// Fail-closed rules (each returns `(None, ProbeWindow)` — never a protection):
/// - 0 parents fully containing the child range;
/// - child range overflow (`checked_add` fails) — a wrapping span can never be
///   proven contained;
/// - >1 parents tied for the **same minimal span** (base/size) — the smallest
///   containing span must be unique at the identity level;
/// - the minimal span has >1 distinct capture identities (equal-size different
///   base, or same base/size different identity) — ambiguity must refuse;
/// - child starts inside a parent but its end overflows/escapes that parent.
///
/// The parent selection is **order-independent**: every candidate is collected
/// first, then the minimal span is chosen, then uniqueness is enforced. Iteration
/// order never selects "the first" overlapping parent.
fn label_table_entry_interior_classification(
    out: &[HeapGlobalSnapshot],
    child_base: u64,
    child_size: usize,
) -> (Option<(u64, usize)>, CaptureExtentKind) {
    // checked_add: a wrapping child span can never be proven contained.
    let Some(child_end) = child_base.checked_add(child_size as u64) else {
        return (None, CaptureExtentKind::ProbeWindow);
    };
    if child_size == 0 {
        return (None, CaptureExtentKind::ProbeWindow);
    }
    // Collect every snapshot that FULLY contains the child range. Only the whole
    // range matters — a parent that covers only the label's start byte is not a
    // valid containing parent (P1-4).
    let mut parents: Vec<(u64, usize)> = Vec::new();
    for o in out {
        if o.is_heap_handle || o.content.is_empty() {
            continue;
        }
        // checked_add on the parent span; an overflowing parent span is not a
        // proven container.
        let Some(parent_end) = o.live_ptr.checked_add(o.content.len() as u64) else {
            continue;
        };
        if o.live_ptr <= child_base && child_end <= parent_end {
            parents.push((o.live_ptr, o.content.len()));
        }
    }
    if parents.is_empty() {
        return (None, CaptureExtentKind::ProbeWindow);
    }
    // Minimal containing span = smallest parent_size. Iteration order must not
    // decide: collect ALL minima first, then require uniqueness at (base,size).
    let min_size = parents.iter().map(|&(_, s)| s).min().unwrap();
    let minima: Vec<(u64, usize)> = parents
        .iter()
        .copied()
        .filter(|&(_, s)| s == min_size)
        .collect();
    if minima.len() != 1 {
        // >1 distinct (base,size) at the same minimal span, or the same span
        // reached twice → ambiguous → refuse.
        return (None, CaptureExtentKind::ProbeWindow);
    }
    let (parent_base, parent_size) = minima[0];
    // Unique at the identity level: exactly one distinct snapshot at that
    // base/size. Equal base/size with a DIFFERENT capture identity is ambiguous
    // (the parent identity is part of the protection binding).
    let mut same_span = 0usize;
    let mut distinct_identity_at_span = 0usize;
    let mut seen_ids: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for o in out {
        if o.is_heap_handle || o.content.is_empty() {
            continue;
        }
        if o.live_ptr == parent_base && o.content.len() == parent_size {
            same_span += 1;
            if seen_ids.insert(o.extent_evidence.capture_id.clone()) {
                distinct_identity_at_span += 1;
            }
        }
    }
    if same_span != 1 || distinct_identity_at_span != 1 {
        return (None, CaptureExtentKind::ProbeWindow);
    }
    (
        Some((parent_base, parent_size)),
        CaptureExtentKind::InteriorSubview,
    )
}

fn is_exact_live_ptr(out: &[HeapGlobalSnapshot], addr: u64) -> bool {
    out.iter()
        .any(|o| !o.is_heap_handle && o.live_ptr == addr && !o.content.is_empty())
}

/// AHK / custom refcounted wide-string object: `{buf, buf, len, cap, refcount}` at 0x28.
///
/// Returns `(buf_ptr, buf_bytes)` when the shell is recognized so the caller can
/// snapshot the buffer as its own freeable range **before** nulling. p20d multi-
/// hop still AVed at +0xdafa4 [rax=0x28] because sanitize zeroed title buffers
/// before expand could walk them — login title never remapped.
fn parse_refcounted_string_shell(content: &[u8]) -> Option<(u64, usize)> {
    if content.len() < 0x28 {
        return None;
    }
    let p0 = u64::from_le_bytes(content[0..8].try_into().unwrap_or_default());
    let p1 = u64::from_le_bytes(content[8..16].try_into().unwrap_or_default());
    let len = u64::from_le_bytes(content[16..24].try_into().unwrap_or_default());
    let cap = u64::from_le_bytes(content[24..32].try_into().unwrap_or_default());
    let refs = u32::from_le_bytes(content[0x20..0x24].try_into().unwrap_or_default());
    if p0 == 0 || p0 != p1 {
        return None;
    }
    if len > cap || cap > 0x10_0000 {
        return None;
    }
    if refs == 0 || refs > 0x10_000 {
        return None;
    }
    // Wide string payload. Prefer (len+1)*2; fall back to modest cap-based
    // size. Never request multi-page free-list neighbours via huge cap.
    let from_len = ((len.saturating_add(1)).saturating_mul(2) as usize).max(0x10);
    let from_cap = ((cap.saturating_add(1)).saturating_mul(2) as usize).min(0x2000);
    let bytes = from_len
        .max(0x10)
        .min(from_cap)
        .min(GRAPH_CHILD_SIZE_PROBE_CAP);
    Some((p0, bytes))
}

/// Null buffer pointers and keep only the freeable 0x28 shell after the buffer
/// has been admitted as a separate snapshot (or when free-safety requires it).
#[allow(dead_code)] // legacy refcounted-string shell sanitizer
fn sanitize_refcounted_string_shell(content: &mut Vec<u8>) -> bool {
    let Some(_) = parse_refcounted_string_shell(content) else {
        return false;
    };
    let refs = u32::from_le_bytes(content[0x20..0x24].try_into().unwrap_or_default());
    content[0..16].fill(0);
    content.truncate(0x28);
    if refs > 1 {
        content[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    }
    true
}

/// MIDA-SERIAL-37: pure string-shell resolution. No shared-state mutation.
struct StringShellResolution {
    /// The content was recognized as a refcounted string shell.
    is_shell: bool,
    /// Buffer is already covered (exact live snapshot / seen heap): keep the
    /// shell pointers, no new snapshot.
    keep_pointers: bool,
    /// Buffer bytes to admit as a new snapshot at commit (None when not
    /// capturable / already covered).
    buffer_child: Option<(u64, Vec<u8>)>, // (buf, body)
}

/// Admit the string buffer when possible. Always shrink the shell to the
/// freeable 0x28 header so oversized probes do not swallow neighbours
/// (HeapFree c0000374). Keep `buf` pointers when the buffer was snapshotted
/// so multi_fixup remaps title/path wide strings; only null when the buffer
/// cannot be captured.
///
/// MIDA-SERIAL-37: thin wrapper for the NON-transactional call sites (roots /
/// first-hop / label entries / expand / dangling edges): resolve then apply
/// immediately. The split path uses resolve + deferred apply so the admission
/// stays atomic.
fn handle_string_shell_on_capture(
    content: &mut Vec<u8>,
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    slot_cap: usize,
) {
    let res = resolve_string_shell(
        content,
        out,
        seen_heaps,
        *total_bytes,
        &[],
        image_base,
        image_end,
        dump_buf,
        debugger,
        slot_cap,
    );
    apply_string_shell_resolution(content, &res, out, total_bytes, seen_heaps);
}

/// Lightweight post-truncation geometry view over `out`: (live_ptr, len,
/// exact_base_candidate). `truncations` override the length of parents that
/// will be truncated at commit, so a buffer that lands at a swallowed
/// parent's TAIL is judged against the POST-truncation geometry (it becomes
/// exact-base / independently capturable) instead of being wrongly nulled.
fn string_shell_geometry_view(
    out: &[HeapGlobalSnapshot],
    truncations: &[(u64, usize)],
) -> Vec<(u64, usize, bool)> {
    out.iter()
        .map(|o| {
            let len = truncations
                .iter()
                .find(|(b, _)| *b == o.live_ptr)
                .map(|&(_, nl)| nl)
                .unwrap_or(o.content.len());
            (o.live_ptr, len, !o.is_heap_handle && !o.content.is_empty())
        })
        .collect()
}

/// is_exact_live_ptr over the geometry view.
fn shell_view_exact_base(view: &[(u64, usize, bool)], addr: u64) -> bool {
    view.iter().any(|(b, _, exact)| *exact && *b == addr)
}

/// Cap `size` so [base, base+size) does not overlap any view extent.
/// checked arithmetic — a wrapping span is never a valid window.
fn shrink_to_avoid_overlap_view(view: &[(u64, usize, bool)], base: u64, size: usize) -> usize {
    let Some(mut end) = base.checked_add(size as u64) else {
        return 0;
    };
    for &(live, len, _) in view {
        if len == 0 {
            continue;
        }
        let Some(o_end) = live.checked_add(len as u64) else {
            continue;
        };
        if live > base && live < end {
            end = live;
        }
        if base >= live && base < o_end {
            return 0; // interior of an existing extent
        }
    }
    match end.checked_sub(base) {
        Some(d) => d as usize,
        None => 0,
    }
}

fn truncate_to_avoid_overlap_view(
    view: &[(u64, usize, bool)],
    base: u64,
    mut content: Vec<u8>,
) -> Vec<u8> {
    let new_len = shrink_to_avoid_overlap_view(view, base, content.len());
    if new_len < content.len() {
        content.truncate(new_len);
    }
    content
}

/// MIDA-SERIAL-37: pure string-shell resolver (no shared-state mutation).
fn resolve_string_shell(
    content: &[u8],
    out: &[HeapGlobalSnapshot],
    seen_heaps: &BTreeSet<u64>,
    total_bytes: usize,
    truncations: &[(u64, usize)],
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    slot_cap: usize,
) -> StringShellResolution {
    let Some((buf, want)) = parse_refcounted_string_shell(content) else {
        return StringShellResolution {
            is_shell: false,
            keep_pointers: false,
            buffer_child: None,
        };
    };
    let view = string_shell_geometry_view(out, truncations);
    // R-GTO-UI r12: only an *exact* live_ptr match means the buffer is a
    // freeable standalone snapshot. `range_contains` is wrong here — a large
    // parent (e.g. 0x144358 @ 32KiB) can swallow path/title buffers as
    // interior addresses; multi_fixup is exact-base only.
    let covered = shell_view_exact_base(&view, buf) || seen_heaps.contains(&buf);
    if covered {
        return StringShellResolution {
            is_shell: true,
            keep_pointers: true,
            buffer_child: None,
        };
    }
    if !is_heap_pointer(buf, image_base, image_end) || buf < MIN_GRAPH_CHILD_POINTER {
        return StringShellResolution {
            is_shell: true,
            keep_pointers: false,
            buffer_child: None,
        };
    }
    if out.len() >= slot_cap || total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
        return StringShellResolution {
            is_shell: true,
            keep_pointers: false,
            buffer_child: None,
        };
    }
    if looks_like_heap_handle(debugger, buf) {
        return StringShellResolution {
            is_shell: true,
            keep_pointers: false,
            buffer_child: None,
        };
    }
    let mut size = estimate_object_size(
        dump_buf,
        usize::MAX,
        buf,
        debugger,
        want.min(GRAPH_CHILD_SIZE_PROBE_CAP)
            .min(MAX_HEAP_GLOBAL_BYTES),
    );
    if size < 8 {
        size = want.min(0x1000);
        if !can_read(debugger, buf, size.min(0x40), 0x2000) {
            return StringShellResolution {
                is_shell: true,
                keep_pointers: false,
                buffer_child: None,
            };
        }
    }
    size = shrink_to_avoid_overlap_view(&view, buf, size);
    if size < 8 {
        return StringShellResolution {
            is_shell: true,
            keep_pointers: false,
            buffer_child: None,
        };
    }
    if total_bytes
        .checked_add(size)
        .map_or(true, |v| v > MAX_HEAP_GLOBAL_TOTAL_BYTES)
    {
        return StringShellResolution {
            is_shell: true,
            keep_pointers: false,
            buffer_child: None,
        };
    }
    let Ok(mut body) = alloc_capped(
        size,
        GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_CONTAINER_BYTES),
        "string buffer child",
    ) else {
        return StringShellResolution {
            is_shell: true,
            keep_pointers: false,
            buffer_child: None,
        };
    };
    match debugger.read_memory(buf as usize, &mut body) {
        Ok(n) if n >= 2 => {
            if n < body.len() {
                body.truncate(n);
            }
        }
        _ => {
            return StringShellResolution {
                is_shell: true,
                keep_pointers: false,
                buffer_child: None,
            };
        }
    }
    body = trim_trailing_zero_pages(body);
    body = truncate_to_avoid_overlap_view(&view, buf, body);
    if body.len() < 2 {
        return StringShellResolution {
            is_shell: true,
            keep_pointers: false,
            buffer_child: None,
        };
    }
    StringShellResolution {
        is_shell: true,
        keep_pointers: false,
        buffer_child: Some((buf, body)),
    }
}

/// MIDA-SERIAL-37: infallible commit of a resolved string shell.
fn apply_string_shell_resolution(
    content: &mut Vec<u8>,
    res: &StringShellResolution,
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
) {
    if !res.is_shell {
        return;
    }
    if let Some((buf, body)) = &res.buffer_child {
        if seen_heaps.insert(*buf) {
            info!(
                heap = format_args!("{buf:#x}"),
                size = body.len(),
                "Captured string-buffer child (keep shell ptrs for multi_fixup)"
            );
            // MIDA-SERIAL-40: the buffer byte add was PRE-VALIDATED by the
            // caller's commit plan (total_bytes + buffer body cannot overflow).
            // Infallible by construction — no failure branch after mutation.
            debug_assert!(total_bytes.checked_add(body.len()).is_some());
            *total_bytes += body.len();
            out.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: *buf,
                content: body.clone(),
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence {
                    capture_id: format!("string_buf:{buf:#x}"),
                    capture_path: CapturePath::MainSlot,
                    source_root_rva: None,
                    source_slot_offset: None,
                    probe_requested_size: 0,
                    was_interior: false,
                    containing_parent_old_base: None,
                    containing_parent_size: None,
                },
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
        }
    }
    // Exact freeable shell size — never leave multi-KiB false parent.
    if content.len() > 0x28 {
        content.truncate(0x28);
    }
    if res.keep_pointers || res.buffer_child.is_some() {
        // Keep buf pointers; multi_fixup remaps them to the buffer snapshot.
        return;
    }
    // Buffer unreachable — null so AHK dtor does not free a stale absolute.
    content[0..16].fill(0);
}

/// Promote heap pointers that land *strictly inside* an existing capture to
/// their own snapshot entries, and shrink the swallowing parent so multi_fixup
/// remaps freeable leaves to exact HeapAlloc bases (not interiors).
///
/// MIDA-SERIAL-34: every split child now carries REAL producer provenance:
/// - capture_path = CapturePath::SplitSibling (never MainSlot);
/// - capture_id = split_sibling:{value}:{source_snapshot_id}:{slot_off}
///   (deterministic bind to producer + child base + source identity/slot);
/// - source_slot_offset = the REAL qword-slot byte offset inside the source
///   snapshot that referenced the child;
/// - was_interior = true;
/// - probe_requested_size = the actual probe cap requested for the child;
/// - containing_parent_* = pre-trunc parent evidence ONLY when the parent is
///   unique, strict (ObservedAllocation/BackingObject, non-SyntheticDerived)
///   and its pre-trunc boundary is recorded before truncation. When the parent
///   is ambiguous/heuristic/unprovable, the fields stay None (never fabricated
///   to make a closure succeed).
fn split_swallowed_siblings(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    pre_trunc_authority: &mut PreTruncParentAuthorityStore,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
) -> Vec<SplitSiblingCandidateEvidence> {
    // MIDA-SERIAL-37: returns the REAL admitted candidate evidence (including
    // source_hit_count / parent_hit_count) so production-path tests can assert
    // the producer's distinct-source / distinct-parent counts directly.
    let mut admitted_evidence: Vec<SplitSiblingCandidateEvidence> = Vec::new();
    const MAX_SPLIT_ROUNDS: usize = 4;
    const MAX_SPLIT_PER_ROUND: usize = 24;

    let split_slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE);

    // MIDA-SERIAL-38: producer-lifetime ORIGINAL parent registry. Eligible
    // strict parents (ObservedAllocation/BackingObject, non-SyntheticDerived,
    // non-empty, non-handle) are FROZEN ONCE here, BEFORE any round truncates
    // them. Every child of the same original parent binds the SAME frozen
    // key/bytes regardless of round or child order. The producer NEVER
    // re-derives "pre-trunc" from an already-truncated snapshot.
    let frozen_parents: Vec<FrozenSplitParentIdentity> =
        out.iter().filter_map(frozen_parent_from_snapshot).collect();
    info!(
        frozen = frozen_parents.len(),
        total = out.len(),
        "Frozen original split-parent registry (pre-truncation)"
    );

    for round in 0..MAX_SPLIT_ROUNDS {
        if out.len() >= split_slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            break;
        }

        // Candidate evidence keyed by child value. Replaces the lossy
        // BTreeSet<u64>: preserves source snapshot, source slot offset,
        // pre-trunc parent boundary, parent extent, parent identity, ambiguity.
        let mut candidates: std::collections::BTreeMap<u64, SplitSiblingCandidateEvidence> =
            std::collections::BTreeMap::new();
        for g in out.iter() {
            if g.is_heap_handle || g.content.len() < 16 {
                continue;
            }
            let mut off = 0usize;
            while off + 8 <= g.content.len() {
                let v = u64::from_le_bytes(g.content[off..off + 8].try_into().unwrap_or_default());
                off += 8;
                if !is_heap_pointer(v, image_base, image_end) {
                    continue;
                }
                // Same low-VA filter as expand: free-safe splits still needed
                // for mid-heap path strings, but not for LFH band noise.
                if v < MIN_GRAPH_CHILD_POINTER {
                    continue;
                }
                if is_exact_live_ptr(out, v) {
                    continue;
                }
                // Strict interior of some capture range (not the base).
                // MIDA-SERIAL-35: checked_add — an overflowing parent range
                // cannot be a proven container.
                let swallowed = out.iter().any(|o| {
                    if o.is_heap_handle || o.content.is_empty() {
                        return false;
                    }
                    let Some(end) = o.live_ptr.checked_add(o.content.len() as u64) else {
                        return false;
                    };
                    v > o.live_ptr && v < end
                });
                if !swallowed {
                    continue;
                }
                // MIDA-SERIAL-34: record the REAL source slot offset (the byte
                // offset of this qword within the source snapshot) and the source
                // snapshot identity, plus how many distinct sources reference the
                // child. source_slot_offset is never a fixed constant.
                // MIDA-SERIAL-35 (P2): source_hit_count counts DISTINCT source
                // capture identities (dedup by source identity), matching the
                // field/comment semantics — never raw qword occurrences.
                let slot_off = off - 8; // off was already advanced past this qword
                let entry = candidates
                    .entry(v)
                    .or_insert_with(|| SplitSiblingCandidateEvidence {
                        child_value: v,
                        source_slot_offset: None,
                        source_capture_id: None,
                        source_capture_path: None,
                        source_root_rva: None,
                        source_identities: std::collections::BTreeSet::new(),
                        source_hit_count: 0,
                        parent_hit_count: 0,
                        parent: None,
                        was_interior: true,
                        probe_requested_size: 0,
                    });
                // MIDA-SERIAL-36: distinct-source dedup — insert the source
                // identity into the SET; source_hit_count is the set cardinality.
                // Deterministic first-source-wins for slot/identity fields.
                if entry
                    .source_identities
                    .insert(g.extent_evidence.capture_id.clone())
                {
                    if entry.source_capture_id.is_none() {
                        entry.source_slot_offset = Some(slot_off);
                        entry.source_capture_id = Some(g.extent_evidence.capture_id.clone());
                        entry.source_capture_path = Some(g.extent_evidence.capture_path);
                        entry.source_root_rva = g.extent_evidence.source_root_rva;
                    }
                    entry.source_hit_count = entry.source_identities.len();
                }
            }
        }

        if candidates.is_empty() {
            break;
        }

        // Prefer higher VAs so useful mid-heap leaves win over residual junk.
        let interiors_ordered: Vec<u64> = {
            let mut v: Vec<u64> = candidates.keys().copied().collect();
            v.sort_by(|a, b| b.cmp(a));
            v
        };

        let mut added = 0usize;
        for value in interiors_ordered {
            if added >= MAX_SPLIT_PER_ROUND {
                break;
            }
            if out.len() >= split_slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
                break;
            }
            if is_exact_live_ptr(out, value) {
                continue;
            }
            if looks_like_heap_handle(debugger, value) {
                continue;
            }

            // ============ PREPARE PHASE (no out/total_bytes/seen_heaps mutation) ============
            //
            // MIDA-SERIAL-38: resolve the ORIGINAL parent authority from the
            // FROZEN registry (frozen before any truncation). A frozen parent
            // qualifies when it strictly contains the child by its ORIGINAL
            // span; the FULL qualifying identity (base, original size,
            // capture_id, path, extent, provenance) comes from the frozen row
            // — never a loose find(base,size) over the (possibly truncated)
            // current out.
            let frozen_matches: Vec<&FrozenSplitParentIdentity> = frozen_parents
                .iter()
                .filter(|f| {
                    let Some(end) = f
                        .key
                        .parent_old_base
                        .checked_add(f.key.parent_pre_trunc_size as u64)
                    else {
                        return false;
                    };
                    value > f.key.parent_old_base && value < end
                })
                .collect();
            // MIDA-SERIAL-38/39: fail-closed on ambiguity — if two DIFFERENT
            // frozen identities strictly contain the child, no authority is
            // claimed (the child keeps parent=None and coverage decides).
            //
            // MIDA-SERIAL-39: same KEY is not enough. Two eligible frozen rows
            // sharing base/size/capture_id but differing in full_bytes OR
            // extent OR provenance OR capture_path are a CONFLICT (never
            // first-wins). All rows with the same key must be byte/meta
            // identical to be resolvable.
            let unique_frozen: Option<&FrozenSplitParentIdentity> = {
                if frozen_matches.is_empty() {
                    None
                } else {
                    let first = frozen_matches[0];
                    let all_identical = frozen_matches.iter().all(|f| {
                        f.key == first.key
                            && f.full_bytes.as_ref() == first.full_bytes.as_ref()
                            && f.extent == first.extent
                            && f.provenance == first.provenance
                            && f.capture_path == first.capture_path
                    });
                    if all_identical {
                        Some(first)
                    } else {
                        None
                    }
                }
            };
            // parent_hit_count = DISTINCT frozen parent identities containing
            // the child (original registry cardinality — never per-round
            // occurrence, never truncated-prefix identities).
            let parent_hit_count = {
                let ids: std::collections::BTreeSet<PreTruncParentAuthorityKey> =
                    frozen_matches.iter().map(|f| f.key.clone()).collect();
                ids.len()
            };
            // The frozen authority row (bytes + full identity) for the unique
            // parent, if any.
            let pre_trunc_parent_full: Option<(
                u64,
                usize,
                std::sync::Arc<[u8]>,
                CaptureExtentKind,
                RegionProvenance,
                String,
                CapturePath,
            )> = unique_frozen.map(|f| {
                (
                    f.key.parent_old_base,
                    f.key.parent_pre_trunc_size,
                    f.full_bytes.clone(), // Arc handle clone — no byte copy
                    f.extent,
                    f.provenance.clone(),
                    f.key.parent_capture_id.clone(),
                    f.capture_path,
                )
            });
            // MIDA-SERIAL-37/38: PREPARE the authority binding BEFORE any
            // irreversible commit. An identity conflict or duplicate child
            // binding REJECTS the candidate here — zero mutation.
            let prepared_binding: Option<
                Result<PreTruncParentAuthorityKey, PreTruncAuthorityError>,
            > = pre_trunc_parent_full.as_ref().map(
                |(pb, ps, full_bytes, ext, prov, cid, cpath)| {
                    pre_trunc_authority.prepare_parent(
                        *pb,
                        *ps,
                        full_bytes.as_ref(),
                        *ext,
                        prov,
                        cid,
                        *cpath,
                    )
                },
            );
            let parent_evidence: Option<SplitSiblingParentEvidence> = pre_trunc_parent_full
                .as_ref()
                .map(
                    |(pb, ps, _b, ext, prov, cid, cpath)| SplitSiblingParentEvidence {
                        pre_trunc_parent_old_base: Some(*pb),
                        pre_trunc_parent_size: Some(*ps),
                        pre_trunc_parent_extent: Some(*ext),
                        pre_trunc_parent_provenance: Some(prov.clone()),
                        pre_trunc_parent_capture_id: Some(cid.clone()),
                        pre_trunc_parent_capture_path: Some(*cpath),
                    },
                );
            if let Some(entry) = candidates.get_mut(&value) {
                entry.parent = parent_evidence.clone();
                entry.parent_hit_count = parent_hit_count;
            }

            // Child size estimate / budget (no mutation on failure).
            // MIDA-SERIAL-36: the overlap shrink runs against the POST-TRUNCATION
            // view — the swallowing parents (which will be truncated at commit)
            // are excluded, so an interior split child is not rejected by its own
            // parent before commit.
            let mut size = estimate_object_size(
                dump_buf,
                usize::MAX,
                value,
                debugger,
                GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES),
            );
            let probe_requested_size = GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES);
            if size < 8 {
                continue;
            }
            size = shrink_split_child_avoid_overlap(out, value, size);
            if size < 8 {
                continue;
            }
            if total_bytes
                .checked_add(size)
                .map_or(true, |v| v > MAX_HEAP_GLOBAL_TOTAL_BYTES)
            {
                break;
            }

            let Ok(mut content) = alloc_capped(
                size,
                GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_CONTAINER_BYTES),
                "heap split sibling",
            ) else {
                continue;
            };
            match debugger.read_memory(value as usize, &mut content) {
                Ok(n) if n >= 8 => {
                    if n < content.len() {
                        content.truncate(n);
                    }
                }
                _ => continue, // read failure: NOTHING was mutated
            }
            content = trim_trailing_zero_pages(content);
            content = truncate_split_child_avoid_overlap(out, value, content);
            if content.len() < 8 {
                continue; // post-trim failure: NOTHING was mutated
            }

            // ============ COMMIT PHASE (atomic) ============
            //
            // MIDA-SERIAL-37: every conflict is detected in the PREPARE phase
            // (identity conflict / duplicate child binding). The commit below is
            // a single ordered sequence with NO failure branch between mutation
            // steps: string-shell resolution was already computed; parent
            // truncation, authority recording, counters, child push and seen
            // insert happen together. Any rejected candidate left the shared
            // state untouched.
            let binding = match prepared_binding {
                Some(Ok(key)) => Some(key),
                Some(Err(e)) => {
                    // Fail-closed: identity/bytes conflict REJECTS the split
                    // candidate — parent untouched, child not admitted, no
                    // evidence, no counters/seen residue.
                    warn!(
                        heap = format_args!("{value:#x}"),
                        error = %e,
                        "Split-sibling authority conflict: candidate rejected"
                    );
                    continue;
                }
                None => None,
            };

            // MIDA-SERIAL-39: resolve the string shell against the
            // POST-TRUNCATION geometry (swallowing parents truncated at commit)
            // so a buffer at a parent tail becomes exact-base / independently
            // capturable. Pure — no shared-state mutation.
            let truncations: Vec<(u64, usize)> = {
                let mut t = Vec::new();
                for g in out.iter() {
                    if g.is_heap_handle || g.content.is_empty() {
                        continue;
                    }
                    let Some(end) = g.live_ptr.checked_add(g.content.len() as u64) else {
                        continue;
                    };
                    if value > g.live_ptr && value < end {
                        let new_len = (value - g.live_ptr) as usize;
                        if new_len >= 8 && new_len < g.content.len() {
                            t.push((g.live_ptr, new_len));
                        }
                    }
                }
                t
            };
            let shell_res = resolve_string_shell(
                &content,
                out,
                seen_heaps,
                *total_bytes,
                &truncations,
                image_base,
                image_end,
                dump_buf,
                debugger,
                split_slot_cap,
            );
            debug_assert!(
                !shell_res.is_shell || content.len() >= 0x28,
                "string shell keeps >= 0x28 by construction"
            );

            // ================================================================
            // PHASE 1 — PREPARE: compute the FINAL child form and resolve the
            // parent authority. No shared-state mutation.
            // ================================================================
            // Final child content length: a string shell's final form is the
            // freeable 0x28 header; non-shell keeps its trimmed length. This
            // value drives the duplicate gate, the budget AND the recorded
            // binding — ONE formula.
            let final_child_size: usize = if shell_res.is_shell {
                content.len().min(0x28)
            } else {
                content.len()
            };

            // MIDA-SERIAL-40: same-key frozen registry ambiguity (two eligible
            // rows with the same key but different bytes/meta) REJECTS the
            // whole candidate at the producer — fail-closed, zero mutation.
            // (unique_frozen == None when the registry is ambiguous.)
            if unique_frozen.is_none() && !frozen_matches.is_empty() {
                warn!(
                    heap = format_args!("{value:#x}"),
                    matches = frozen_matches.len(),
                    "Split-sibling ambiguous frozen parent registry: candidate rejected"
                );
                continue;
            }

            // Duplicate-child production gate uses the FINAL child size.
            if let Err(e) = pre_trunc_authority.prepare_child(value, final_child_size) {
                warn!(
                    heap = format_args!("{value:#x}"),
                    error = %e,
                    "Split-sibling duplicate child binding: candidate rejected"
                );
                continue;
            }

            // ================================================================
            // PHASE 2 — IMMUTABLE COMMIT PLAN: ALL checked arithmetic, ALL
            // validation, computed BEFORE any mutation. The commit below
            // consumes ONLY this plan; it has no failure branches.
            // ================================================================
            // planned_slots = current + split child + optional buffer child.
            // planned_bytes = current_total + final_child_bytes + optional
            // buffer_bytes - parent truncation drops.
            //
            // Production invariant: total_bytes == sum(out content lengths).
            // A truncation drop can therefore NEVER exceed the counted bytes;
            // if the accounting is inconsistent, this is a HARD fail (never
            // clamped into a "valid" budget).
            let mut planned_slots: usize = out.len();
            let mut trunc_drop: usize = 0;
            // truncations has ONE entry per swallowing snapshot ROW; each row's
            // drop is counted exactly once (no single-parent double-count).
            for (pb, new_len) in truncations.iter() {
                for g in out.iter() {
                    if !g.is_heap_handle && !g.content.is_empty() && g.live_ptr == *pb {
                        if *new_len < g.content.len() {
                            match trunc_drop.checked_add(g.content.len() - *new_len) {
                                Some(v) => trunc_drop = v,
                                None => {
                                    warn!(
                                        heap = format_args!("{value:#x}"),
                                        "Split-sibling truncation drop overflow: rejected"
                                    );
                                    continue;
                                }
                            }
                        }
                        break;
                    }
                }
            }
            // HARD fail: an inconsistent drop (more removed than counted) is
            // never clamped into a valid budget.
            if trunc_drop > *total_bytes {
                warn!(
                    heap = format_args!("{value:#x}"),
                    trunc_drop,
                    total = *total_bytes,
                    "Split-sibling truncation drop exceeds counted bytes: rejected"
                );
                continue;
            }
            let eff_drop = trunc_drop;
            // planned slots (checked).
            planned_slots = match planned_slots.checked_add(1) {
                Some(v) => v, // split child
                None => {
                    warn!(heap = format_args!("{value:#x}"), "split slot overflow");
                    continue;
                }
            };
            let buffer_adds_slot = shell_res.buffer_child.is_some();
            if buffer_adds_slot {
                planned_slots = match planned_slots.checked_add(1) {
                    Some(v) => v,
                    None => {
                        warn!(heap = format_args!("{value:#x}"), "split slot overflow");
                        continue;
                    }
                };
            }
            // planned bytes (all checked).
            let mut add_bytes: usize = final_child_size;
            if let Some((_, body)) = &shell_res.buffer_child {
                match add_bytes.checked_add(body.len()) {
                    Some(v) => add_bytes = v,
                    None => {
                        warn!(
                            heap = format_args!("{value:#x}"),
                            "Split-sibling buffer byte overflow: rejected"
                        );
                        continue;
                    }
                }
            }
            let planned_bytes_checked = total_bytes
                .checked_add(add_bytes)
                .and_then(|b| b.checked_sub(eff_drop));
            if planned_slots > split_slot_cap
                || planned_bytes_checked.is_none()
                || planned_bytes_checked.unwrap_or(usize::MAX) > MAX_HEAP_GLOBAL_TOTAL_BYTES
            {
                warn!(
                    heap = format_args!("{value:#x}"),
                    planned_slots,
                    planned_bytes = planned_bytes_checked.unwrap_or(usize::MAX),
                    cap_slots = split_slot_cap,
                    cap_bytes = MAX_HEAP_GLOBAL_TOTAL_BYTES,
                    "Split-sibling combined budget exceeded: candidate rejected"
                );
                continue;
            }
            // A string buffer whose base equals the split child base would
            // produce two snapshots with the same live_ptr — reject.
            if let Some((buf, _)) = &shell_res.buffer_child {
                if *buf == value {
                    warn!(
                        heap = format_args!("{value:#x}"),
                        "String buffer base equals split child base: rejected"
                    );
                    continue;
                }
            }
            // The authority identity conflict was already checked in prepare
            // (prepared_binding). The final child content length >= 8 is
            // guaranteed by construction (shell >= 0x28; non-shell >= 8).
            // The immutable plan is now COMPLETE. From here on, commit is
            // infallible — no further checks, no failure branches.

            // ================================================================
            // PHASE 3 — INFALLIBLE COMMIT. Consumes only the validated plan.
            // ================================================================
            // 3a. Truncate swallowing parents: every drop is <= total_bytes
            // (validated above); plain subtraction cannot underflow.
            // Each truncations entry corresponds to ONE swallowing row. A
            // duplicate row at the SAME base is a distinct snapshot that must
            // also be truncated; do NOT break after the first match (the
            // truncation is idempotent — a row already at new_len is skipped).
            for (pb, new_len) in truncations.iter() {
                for g in out.iter_mut() {
                    if g.is_heap_handle || g.content.is_empty() {
                        continue;
                    }
                    if g.live_ptr == *pb && *new_len < g.content.len() {
                        let dropped = g.content.len() - *new_len;
                        g.content.truncate(*new_len);
                        debug_assert!(*total_bytes >= dropped);
                        *total_bytes -= dropped;
                    }
                }
            }
            // 3b. Materialize the final child content form.
            if shell_res.is_shell && content.len() > 0x28 {
                content.truncate(0x28);
            }
            debug_assert!(content.len() >= 8, "string-shell truncation keeps >= 8");

            let evidence =
                candidates
                    .get(&value)
                    .cloned()
                    .unwrap_or_else(|| SplitSiblingCandidateEvidence {
                        child_value: value,
                        source_slot_offset: None,
                        source_capture_id: None,
                        source_capture_path: None,
                        source_root_rva: None,
                        source_identities: std::collections::BTreeSet::new(),
                        source_hit_count: 0,
                        parent_hit_count,
                        parent: parent_evidence.clone(),
                        was_interior: true,
                        probe_requested_size,
                    });
            let src_id = evidence
                .source_capture_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            let slot_off = evidence.source_slot_offset.unwrap_or(usize::MAX);
            let capture_id = format!("split_sibling:{value:#x}:{src_id}:{slot_off:#x}");
            let parent_base = evidence
                .parent
                .as_ref()
                .and_then(|p| p.pre_trunc_parent_old_base);
            let parent_size = evidence
                .parent
                .as_ref()
                .and_then(|p| p.pre_trunc_parent_size);
            // 3c. Record the authority (Arc-shared bytes once) + one binding.
            if let Some(key) = binding.as_ref() {
                if let Some((_pb, _ps, full_bytes, ext, prov, _cid, cpath)) =
                    pre_trunc_parent_full.as_ref()
                {
                    pre_trunc_authority.record_parent_arc(
                        key,
                        full_bytes.clone(), // Arc handle clone — no byte copy
                        *ext,
                        prov.clone(),
                        *cpath,
                    );
                    pre_trunc_authority.record_binding(
                        key.clone(),
                        *ext,
                        prov.clone(),
                        *cpath,
                        value,
                        final_child_size,
                        evidence.source_capture_id.clone().unwrap_or_default(),
                        evidence.source_slot_offset,
                    );
                }
            }
            // 3d. String-shell buffer commit (pre-validated; infallible).
            apply_string_shell_resolution(&mut content, &shell_res, out, total_bytes, seen_heaps);
            // 3e. total_bytes add — pre-validated (checked_add in the plan);
            // plain add cannot overflow.
            debug_assert!(total_bytes.checked_add(final_child_size).is_some());
            *total_bytes += final_child_size;
            // 3f. Push the split child + seen_heaps + evidence.
            out.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: value,
                content,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::ProbeWindow,
                extent_evidence: CaptureExtentEvidence {
                    capture_id,
                    capture_path: CapturePath::SplitSibling,
                    source_root_rva: evidence.source_root_rva,
                    source_slot_offset: evidence.source_slot_offset,
                    probe_requested_size,
                    was_interior: true,
                    containing_parent_old_base: parent_base,
                    containing_parent_size: parent_size,
                },
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            });
            seen_heaps.insert(value);
            admitted_evidence.push(evidence.clone());
            info!(
                heap = format_args!("{value:#x}"),
                size = final_child_size,
                round = round + 1,
                source_slot_offset = slot_off,
                source_hit_count = evidence.source_hit_count,
                parent_hit_count,
                has_strict_parent = parent_base.is_some(),
                "Split swallowed heap sibling into own snapshot (free-safe base)"
            );
            added += 1;
        }

        if added == 0 {
            break;
        }
        info!(
            round = round + 1,
            added,
            total = out.len(),
            "Swallowed-sibling split round complete"
        );
    }
    admitted_evidence
}

/// Final pass: walk every captured blob and admit still-external heap pointers
/// that are readable in the live process. Prefer hot / high-VA targets; stop at
/// slot/byte caps. Remaining uncaptured edges are scrubbed later.
fn capture_dangling_edges(
    out: &mut Vec<HeapGlobalSnapshot>,
    dedicated_slabs: &mut Vec<HeapSlab>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    policy: &DumpCapturePolicy,
) {
    const MAX_DANGLING_ADMIT: usize = 96;
    const DANGLING_PROBE_CAP: usize = 0x1000;

    if out.is_empty() || out.len() >= MAX_HEAP_GLOBAL_SLOTS {
        return;
    }

    // Weighted refs: edges from hot gscript roots count more so dangling
    // reserve is not spent on free-list arenas that many cold tables share.
    let mut ref_counts: BTreeMap<u64, u32> = BTreeMap::new();
    for g in out.iter() {
        if g.is_heap_handle || g.content.len() < 8 {
            continue;
        }
        let weight: u32 = if policy.is_hot_root(g.rva) {
            64
        } else if g.rva != 0 {
            8
        } else {
            1
        };
        let mut off = 0usize;
        while off + 8 <= g.content.len() {
            let v = u64::from_le_bytes(g.content[off..off + 8].try_into().unwrap_or_default());
            off += 8;
            if !is_heap_pointer(v, image_base, image_end) || v < MIN_GRAPH_CHILD_POINTER {
                continue;
            }
            if seen_heaps.contains(&v) || range_contains(out, v) {
                continue;
            }
            *ref_counts.entry(v).or_insert(0) += weight;
        }
    }

    if ref_counts.is_empty() {
        return;
    }

    let mut ranked: Vec<(u64, u32)> = ref_counts.into_iter().collect();
    // Weighted-hot edges first, then mid-heap band, then higher VA.
    ranked.sort_by(|a, b| {
        let ra = expand_candidate_rank(a.1, a.0);
        let rb = expand_candidate_rank(b.1, b.0);
        rb.cmp(&ra)
    });

    let mut added = 0usize;
    for (value, refs) in ranked {
        if added >= MAX_DANGLING_ADMIT || out.len() >= MAX_HEAP_GLOBAL_SLOTS {
            break;
        }
        if *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            break;
        }
        if !seen_heaps.insert(value) || range_contains(out, value) {
            seen_heaps.remove(&value);
            continue;
        }
        if looks_like_heap_handle(debugger, value) {
            seen_heaps.remove(&value);
            continue;
        }

        let mut size = estimate_object_size(
            dump_buf,
            usize::MAX,
            value,
            debugger,
            DANGLING_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES),
        );
        if size < 8 {
            seen_heaps.remove(&value);
            continue;
        }
        size = shrink_to_avoid_overlap(out, value, size);
        if size < 8 {
            seen_heaps.remove(&value);
            continue;
        }
        if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
            seen_heaps.remove(&value);
            break;
        }

        let Ok(mut content) = alloc_capped(
            size,
            DANGLING_PROBE_CAP.min(MAX_HEAP_CONTAINER_BYTES),
            "heap dangling edge",
        ) else {
            seen_heaps.remove(&value);
            continue;
        };
        match debugger.read_memory(value as usize, &mut content) {
            Ok(n) if n >= 8 => {
                if n < content.len() {
                    content.truncate(n);
                }
            }
            _ => {
                seen_heaps.remove(&value);
                continue;
            }
        }
        content = trim_trailing_zero_pages(content);
        content = truncate_to_avoid_overlap(out, value, content);
        if content.len() < 8 {
            seen_heaps.remove(&value);
            continue;
        }
        handle_string_shell_on_capture(
            &mut content,
            out,
            total_bytes,
            seen_heaps,
            image_base,
            image_end,
            dump_buf,
            debugger,
            MAX_HEAP_GLOBAL_SLOTS,
        );

        info!(
            heap = format_args!("{value:#x}"),
            size = content.len(),
            refs,
            "Captured dangling heap edge (pre-scrub)"
        );
        *total_bytes = total_bytes.saturating_add(content.len());
        // Route S R0-A: dangling-edge snapshots MUST carry a deterministic
        // non-empty capture identity (previously CaptureExtentEvidence::default()
        // produced an empty capture_id / MainSlot path, which broke the Q0-C exact
        // binding). Explicitly bind: capture_path=DanglingEdge, extent=ProbeWindow,
        // probe_requested_size=actual cap, was_interior=false, no containing parent.
        let capture_id = format!("dangling_edge:{value:#x}:{:#x}", content.len());
        // Route T R0-B: a dangling-edge allocation is an authoritative capture of
        // its own (read directly from the debuggee), so it must ALSO be surfaced
        // as a dedicated authoritative slab covering exactly [value, value+len).
        // The ProbeWindow heap global below is then absorbed into this slab as an
        // alias at runtime-rebase time (R0-F.1), instead of being rejected as an
        // uncovered probe. This is the coverage closure for the Route S R1
        // `0x850150` blocker: dispersed dangling edges previously inflated the
        // single main-slab span past MAX_HEAP_SLAB_BYTES, so capture_heap_slab
        // returned None and NO probe had authoritative coverage.
        dedicated_slabs.push(HeapSlab {
            old_base: value,
            content: content.clone(),
        });
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: value,
            content,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::ProbeWindow,
            extent_evidence: CaptureExtentEvidence {
                capture_id,
                capture_path: CapturePath::DanglingEdge,
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: DANGLING_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES),
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        });
        added += 1;
    }

    if added > 0 {
        info!(
            added,
            total = out.len(),
            "Dangling-edge capture pass complete"
        );
    }
}

/// Truncate any existing capture whose range strictly contains `base` so that
/// the parent ends at `base`. Returns true if at least one parent was carved.
///
/// Used by hot-root ensure when a critical table (cmd dispatch @0x147868) sits
/// *inside* an oversized gscript/heap probe. Without carving, ensure falls back
/// to plant-only 8B and multi_fixup never remaps the real table body.
fn carve_parent_at_hot_base(out: &mut [HeapGlobalSnapshot], base: u64) -> bool {
    let mut carved = false;
    for o in out.iter_mut() {
        if o.is_heap_handle || o.content.is_empty() {
            continue;
        }
        let o_end = o.live_ptr.saturating_add(o.content.len() as u64);
        // Strict interior: parent starts before base and ends after base.
        if base > o.live_ptr && base < o_end {
            let new_len = (base - o.live_ptr) as usize;
            if new_len >= 8 && new_len < o.content.len() {
                info!(
                    parent_live = format_args!("{:#x}", o.live_ptr),
                    parent_rva = format_args!("{:#x}", o.rva),
                    old_size = o.content.len(),
                    new_size = new_len,
                    hot_base = format_args!("{base:#x}"),
                    "Carved oversized parent to free exclusive hot-root range"
                );
                o.content.truncate(new_len);
                carved = true;
            }
        }
    }
    carved
}

/// Cap `size` so `[base, base+size)` does not overlap any existing capture.
/// MIDA-SERIAL-36: shrink a SPLIT CHILD's proposed window against the
/// POST-TRUNCATION view. The swallowing parents (strictly containing `base`)
/// are excluded — they will be truncated to end at `base` at commit, so the
/// child owns [base, ...) after commit. All OTHER snapshots still bound the
/// child window (a later object base inside the proposed range cuts it; an
/// earlier object whose range overlaps base non-swallowingly rejects it).
fn shrink_split_child_avoid_overlap(out: &[HeapGlobalSnapshot], base: u64, size: usize) -> usize {
    let Some(mut end) = base.checked_add(size as u64) else {
        return 0;
    };
    for o in out {
        if o.is_heap_handle || o.content.is_empty() {
            continue;
        }
        let Some(o_end) = o.live_ptr.checked_add(o.content.len() as u64) else {
            continue;
        };
        if o.live_ptr < base && o_end > base {
            continue;
        }
        if o.live_ptr > base && o.live_ptr < end {
            end = o.live_ptr;
        }
        if base >= o.live_ptr && base < o_end {
            return 0;
        }
    }
    match end.checked_sub(base) {
        Some(d) => d as usize,
        None => 0,
    }
}

fn shrink_to_avoid_overlap(out: &[HeapGlobalSnapshot], base: u64, size: usize) -> usize {
    let mut end = base.saturating_add(size as u64);
    for o in out {
        let o_end = o.live_ptr.saturating_add(o.content.len() as u64);
        // Existing block starts inside our proposed range → cut before it.
        if o.live_ptr > base && o.live_ptr < end {
            end = o.live_ptr;
        }
        // We start inside an existing block — caller should have rejected.
        if base >= o.live_ptr && base < o_end {
            return 0;
        }
        // Existing block ends inside us and starts before us → cut to o_end?
        // If o starts before base and o_end > base, we are interior (handled above).
        let _ = o_end;
    }
    end.saturating_sub(base) as usize
}

/// MIDA-SERIAL-36: truncate a SPLIT CHILD's captured content against the
/// POST-TRUNCATION view (swallowing parents excluded — see
/// shrink_split_child_avoid_overlap).
fn truncate_split_child_avoid_overlap(
    out: &[HeapGlobalSnapshot],
    base: u64,
    mut content: Vec<u8>,
) -> Vec<u8> {
    let new_len = shrink_split_child_avoid_overlap(out, base, content.len());
    if new_len < content.len() {
        content.truncate(new_len);
    }
    content
}

fn truncate_to_avoid_overlap(
    out: &[HeapGlobalSnapshot],
    base: u64,
    mut content: Vec<u8>,
) -> Vec<u8> {
    let new_len = shrink_to_avoid_overlap(out, base, content.len());
    if new_len < content.len() {
        content.truncate(new_len);
    }
    content
}

/// Drop trailing all-zero pages so oversize probes do not burn the aggregate cap.
fn trim_trailing_zero_pages(mut content: Vec<u8>) -> Vec<u8> {
    const PAGE: usize = 0x1000;
    const MIN_KEEP: usize = 0x40;
    while content.len() > MIN_KEEP + PAGE {
        let start = content.len() - PAGE;
        if content[start..].iter().all(|&b| b == 0) {
            content.truncate(start);
        } else {
            break;
        }
    }
    // Keep a small zero tail for structure padding; align to 16.
    let mut last_nz = 0usize;
    for (i, &b) in content.iter().enumerate().rev() {
        if b != 0 {
            last_nz = i + 1;
            break;
        }
    }
    if last_nz == 0 {
        content.truncate(MIN_KEEP.min(content.len()));
        return content;
    }
    let keep = ((last_nz + 0x3f) & !0x3f).max(MIN_KEEP).min(content.len());
    content.truncate(keep);
    content
}

/// RVAs near MSVC SecurityCookie / complement that must not be treated as
/// plain heap-pointer slots (works on late dump cookies, not only the default).
fn security_cookie_blocklist(pe: &PeHeader, dump_buf: &[u8]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let Some(data) = pe.sections.iter().find(|s| s.name == ".data") else {
        return out;
    };
    let start = data.virtual_address as usize;
    let end = start
        .saturating_add(data.virtual_size as usize)
        .min(dump_buf.len());
    if end.saturating_sub(start) < 16 {
        return out;
    }
    let slice = &dump_buf[start..end];
    for off in (0..=slice.len().saturating_sub(16)).step_by(8) {
        let first = u64::from_le_bytes(slice[off..off + 8].try_into().unwrap_or_default());
        let second = u64::from_le_bytes(slice[off + 8..off + 16].try_into().unwrap_or_default());
        let cookie_off = if first != 0 && first != u64::MAX && second == !first {
            Some(off)
        } else if second != 0 && second != u64::MAX && first == !second {
            Some(off + 8)
        } else {
            None
        };
        if let Some(cookie_off) = cookie_off {
            let rva = data.virtual_address.saturating_add(cookie_off as u32);
            let lo = rva.saturating_sub(0x40);
            let hi = rva.saturating_add(0x50);
            out.push((lo, hi));
            break; // one cookie pair is enough
        }
    }
    out
}

/// Zero user-mode pointers inside captured heap blobs that do not land in any
/// captured heap range or the PE image.
///
/// Uncaptured sibling objects leave dangling addresses; after remap those still
/// point at dump-time heap and ntdll free/lookup paths (RtlpFindEntry) AV.
pub fn scrub_uncaptured_heap_pointers(
    containers: &mut [super::container_snapshot::ContainerSnapshot],
    heap_globals: &mut [HeapGlobalSnapshot],
    image_base: u64,
    image_end: u64,
) {
    let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(containers.len() + heap_globals.len());
    for c in containers.iter() {
        let begin = c.decoded_begin;
        let end = begin.saturating_add(c.heap_content.len() as u64);
        if end > begin {
            ranges.push((begin, end));
        }
    }
    for g in heap_globals.iter() {
        let begin = g.live_ptr;
        let end = begin.saturating_add(g.content.len() as u64);
        if end > begin {
            ranges.push((begin, end));
        }
    }

    // Route Y R1 A6 AF2 (Q0-C narrow mitigation): protect the gscript Label
    // +0x23 non-nested redirect flag byte from being clobbered by its
    // CONTAINING PARENT's scrub. Authorization is full-identity: the scrubbing
    // buffer's CurrentScrubIdentity must equal the protection's parent identity
    // on every field (capture_id, extent_kind, capture_path, old_base, size,
    // kind). Address/base/size alone is never sufficient. Containers have no
    // reliable capture identity and therefore never receive Label-flag
    // protection. The Label's own buffer is still scrubbed so
    // `mark_labels_non_nested` can set the flag to 1. This is NOT a general
    // contained-overlap permission and does NOT weaken Q0-C resolved_writes.
    let label_protections = gscript_label_flag_protections(heap_globals);

    let mut scrubbed = 0usize;
    for c in containers.iter_mut() {
        // Containers have no capture_id/extent/path — no Label-flag protection.
        let current = CurrentScrubIdentity::container(c.decoded_begin, c.heap_content.len());
        scrubbed += scrub_buffer_external_ptrs(
            &mut c.heap_content,
            &current,
            &ranges,
            image_base,
            image_end,
            &label_protections,
        );
    }
    for g in heap_globals.iter_mut() {
        let current = CurrentScrubIdentity::heap_global(g);
        scrubbed += scrub_buffer_external_ptrs(
            &mut g.content,
            &current,
            &ranges,
            image_base,
            image_end,
            &label_protections,
        );
    }
    if scrubbed > 0 {
        info!(
            scrubbed_qwords = scrubbed,
            ranges = ranges.len(),
            "Scrubbed uncaptured external heap pointers in snapshots"
        );
    }
}

/// Object kind of the buffer currently being scrubbed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScrubObjectKind {
    HeapGlobal,
    Container,
}

/// Full identity of the buffer currently being scrubbed.
///
/// Every authorization field is compared against `LabelFlagProtection.parent`.
/// Containers carry no reliable capture identity and therefore never equal a
/// parent identity (which always comes from a heap-global snapshot).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CurrentScrubIdentity {
    pub(crate) kind: ScrubObjectKind,
    pub(crate) capture_id: String,
    pub(crate) extent_kind: CaptureExtentKind,
    pub(crate) capture_path: CapturePath,
    pub(crate) old_base: u64,
    pub(crate) size: usize,
    /// Route Y R1 A6 AF3 AF2 AF1 (P1-1, option A): the CURRENT scrub parent must
    /// carry and compare the FULL parent source evidence, so a protection's
    /// recorded parent can never authorize a scrub whose live snapshot drifted on
    /// any source-evidence / containing-parent field.
    pub(crate) source_root_rva: Option<u32>,
    pub(crate) source_slot_offset: Option<usize>,
    pub(crate) probe_requested_size: usize,
    pub(crate) was_interior: bool,
    pub(crate) containing_parent_old_base: Option<u64>,
    pub(crate) containing_parent_size: Option<usize>,
}

impl CurrentScrubIdentity {
    fn heap_global(g: &HeapGlobalSnapshot) -> Self {
        Self {
            kind: ScrubObjectKind::HeapGlobal,
            capture_id: g.extent_evidence.capture_id.clone(),
            extent_kind: g.extent_kind,
            capture_path: g.extent_evidence.capture_path,
            old_base: g.live_ptr,
            size: g.content.len(),
            source_root_rva: g.extent_evidence.source_root_rva,
            source_slot_offset: g.extent_evidence.source_slot_offset,
            probe_requested_size: g.extent_evidence.probe_requested_size,
            was_interior: g.extent_evidence.was_interior,
            containing_parent_old_base: g.extent_evidence.containing_parent_old_base,
            containing_parent_size: g.extent_evidence.containing_parent_size,
        }
    }

    fn container(old_base: u64, size: usize) -> Self {
        Self {
            kind: ScrubObjectKind::Container,
            capture_id: String::new(),
            extent_kind: CaptureExtentKind::default(),
            capture_path: CapturePath::default(),
            old_base,
            size,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }
    }

    /// True iff this scrub identity is exactly the protection's parent. Every
    /// parent field — including the full source evidence and containing-parent —
    /// must match; a single field difference denies authorization.
    fn matches_parent(&self, parent: &CaptureIdentity) -> bool {
        self.kind == ScrubObjectKind::HeapGlobal
            && self.capture_id == parent.capture_id
            && self.extent_kind == parent.extent_kind
            && self.capture_path == parent.capture_path
            && self.old_base == parent.old_base
            && self.size == parent.size
            && self.source_root_rva == parent.source_root_rva
            && self.source_slot_offset == parent.source_slot_offset
            && self.probe_requested_size == parent.probe_requested_size
            && self.was_interior == parent.was_interior
            && self.containing_parent_old_base == parent.containing_parent_old_base
            && self.containing_parent_size == parent.containing_parent_size
    }
}

/// Full capture identity for a child Label or its containing parent.
/// Every field participates in generation gates and/or scrub authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CaptureIdentity {
    pub(crate) capture_id: String,
    pub(crate) extent_kind: CaptureExtentKind,
    pub(crate) capture_path: CapturePath,
    pub(crate) old_base: u64,
    pub(crate) size: usize,
    /// Route Y R1 A6 AF3: source link offset / probe size for the real
    /// `gscript_child_link:` family — consumed during family-aware canonical
    /// re-validation at consume time. None/0 for families that do not encode
    /// them (e.g. `gscript_label:`).
    pub(crate) source_slot_offset: Option<usize>,
    pub(crate) probe_requested_size: usize,
    /// Route Y R1 A6 AF3 AF1 (P1-6): the source root RVA of the gscript object
    /// that led to this capture (`gscript_first_hop:` / `gscript_label:` emit the
    /// gscript root RVA; `gscript_child_link:` has none). Consumed by the
    /// family-aware canonical parser when the family encodes it.
    pub(crate) source_root_rva: Option<u32>,
    /// Route Y R1 A6 AF3 AF1 (P1-6): whether the capture was interior to an
    /// already-captured object at emit time. Consumed by the consume-time
    /// predicate (a protection is only reachable for an interior label).
    pub(crate) was_interior: bool,
    /// Route Y R1 A6 AF3 AF2 AF1 (P1-1): the containing-parent anchor of the
    /// snapshot this identity came from. The live scrub parent must match the
    /// recorded parent on these too — a parent may itself be interior to another
    /// object, and that containment is part of the identity.
    pub(crate) containing_parent_old_base: Option<u64>,
    pub(crate) containing_parent_size: Option<usize>,
}

impl CaptureIdentity {
    fn from_heap_global(g: &HeapGlobalSnapshot) -> Self {
        Self {
            capture_id: g.extent_evidence.capture_id.clone(),
            extent_kind: g.extent_kind,
            capture_path: g.extent_evidence.capture_path,
            old_base: g.live_ptr,
            size: g.content.len(),
            source_slot_offset: g.extent_evidence.source_slot_offset,
            probe_requested_size: g.extent_evidence.probe_requested_size,
            source_root_rva: g.extent_evidence.source_root_rva,
            was_interior: g.extent_evidence.was_interior,
            containing_parent_old_base: g.extent_evidence.containing_parent_old_base,
            containing_parent_size: g.extent_evidence.containing_parent_size,
        }
    }
}

/// Strict, full-identity protection entry for a gscript Label's `+0x23`
/// non-nested redirect flag byte.
///
/// ALL carried fields participate in generation and/or scrub authorization.
/// No field is stored "for documentation only".
#[derive(Clone, Debug)]
pub(crate) struct LabelFlagProtection {
    pub(crate) child: CaptureIdentity,
    pub(crate) parent: CaptureIdentity,
    /// Always 0x23 for the non-nested redirect flag.
    pub(crate) flag_offset: usize,
    /// Absolute address of the protected flag byte (= child.old_base + 0x23).
    pub(crate) flag_addr: u64,
    /// Inclusive-exclusive absolute range of the qword that holds the flag.
    pub(crate) flag_qword_lo: u64,
    pub(crate) flag_qword_hi: u64,
}

/// Canonical gscript Label capture_id form produced by production capture:
/// `gscript_label:{live_ptr:#x}` (e.g. `gscript_label:0x8e9da8`).
///
/// Accepts ONLY that exact form: prefix + `0x` + lowercase hex equal to
/// `expected_base`. Rejects empty, prefix-only, wrong encoded address,
/// trailing garbage, uppercase, missing `0x`, and malformed digits.
pub(crate) fn parse_canonical_gscript_label_capture_id(
    capture_id: &str,
    expected_base: u64,
) -> bool {
    const PREFIX: &str = "gscript_label:";
    let Some(rest) = capture_id.strip_prefix(PREFIX) else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    // Production emitter: format!("gscript_label:{value:#x}") → "0x" + lowercase hex.
    let Some(hex) = rest.strip_prefix("0x") else {
        return false;
    };
    if hex.is_empty() {
        return false;
    }
    // Every remaining char must be a lowercase hex digit — no trailing junk.
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    let Ok(encoded) = u64::from_str_radix(hex, 16) else {
        return false;
    };
    // Encoded address must equal the Label's live_ptr, AND the string must be
    // exactly the canonical rendering (rejects leading zeros / alternate forms
    // that parse to the same integer but are not the production form).
    encoded == expected_base && capture_id == format!("gscript_label:{expected_base:#x}")
}

/// Route Y R1 A6 AF3: strict parser for the REAL production `gscript_child_link:`
/// capture-id family emitted by `exhaust_gscript_child_link_fields`
/// (heap_global_snapshot.rs):
/// `gscript_child_link:{parent_live:#x}:{loff:#x}:{value:#x}:{probe}` where
/// `probe` is the raw decimal probe size.
///
/// Validates EVERY encoded field against the snapshot's recorded identity:
/// parent == containing_parent_old_base, loff == source_slot_offset,
/// value == live_ptr, probe == probe_requested_size. Rejects any mismatch,
/// arbitrary prefixes, uppercase / trailing junk / missing fields. The
/// containing parent MUST be present (a child_link id with no parent evidence is
/// not a valid interior label identity).
fn parse_canonical_gscript_child_link_capture_id(
    capture_id: &str,
    expected_parent: Option<u64>,
    expected_loff: Option<usize>,
    expected_base: u64,
    expected_probe: usize,
) -> bool {
    const PREFIX: &str = "gscript_child_link:";
    let Some(rest) = capture_id.strip_prefix(PREFIX) else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 4 {
        return false;
    }
    let parse_hex = |s: &str| -> Option<u64> {
        let h = s.strip_prefix("0x")?;
        if h.is_empty() {
            return None;
        }
        if !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        u64::from_str_radix(h, 16).ok()
    };
    let Some(parent) = parse_hex(parts[0]) else {
        return false;
    };
    let Some(loff) = parse_hex(parts[1]) else {
        return false;
    };
    let Some(base) = parse_hex(parts[2]) else {
        return false;
    };
    let probe: usize = match parts[3].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    // Canonical round-trip (no leading zeros / alternate spellings).
    if capture_id
        != format!(
            "gscript_child_link:{parent:#x}:{loff:#x}:{base:#x}:{}",
            probe
        )
    {
        return false;
    }
    let parent_ok = match expected_parent {
        Some(p) => p == parent,
        None => false, // child_link id REQUIRES a recorded containing parent
    };
    let loff_ok = match expected_loff {
        Some(l) => (l as u64) == loff,
        None => false, // child_link id REQUIRES a recorded link offset
    };
    parent_ok && loff_ok && base == expected_base && probe == expected_probe
}

/// Route Y R1 A6 AF3 AF1 (P1-2): the `gscript_first_hop:` family is NOT
/// authorized for Label-flag protection. Its capture-id encodes only `edge_off`,
/// which cannot strictly bind child base / parent / probe / was_interior, so
/// keeping it authorized would be "code allows, test does not prove". A
/// first-hop-captured table-reachable label therefore stays fail-closed
/// (never protected). The real emitter `exhaust_gscript_first_hop` still emits
/// this id for capture/multi_fixup purposes, but `gscript_label_flag_protections`
/// refuses to authorize it (path gate + family parser both return false).

/// Route Y R1 A6 AF3: family-aware canonical capture-id validation for a
/// table-reachable gscript Label. Dispatches on the label's ACTUAL production
/// `capture_path` and validates the id against the snapshot's own recorded
/// evidence fields. This is the production reachability fix: the A6 chain
/// captures B via `exhaust_gscript_label_table_entries`, which (after the AF3
/// emitter fix) emits `GscriptLabelTableEntry` + `gscript_label:{base}` +
/// InteriorSubview + a unique containing parent; a PRE-EXISTING label first
/// captured via the real child-link emitter keeps its real
/// `gscript_child_link:` id and is accepted only with a strict family parser.
///
/// Rejects: MainSlot path, ProbeWindow-without-parent, arbitrary `gscript_*`
/// prefixes (including `gscript_first_hop:`), hand-built `gscript_label:` +
/// GscriptChildLink tuples, and any id that does not round-trip against the
/// recorded evidence.
fn parse_canonical_label_capture_id_for(label: &HeapGlobalSnapshot) -> bool {
    let ev = &label.extent_evidence;
    match ev.capture_path {
        CapturePath::GscriptLabelTableEntry => {
            parse_canonical_gscript_label_capture_id(&ev.capture_id, label.live_ptr)
                && parse_canonical_label_table_source_evidence(label)
        }
        CapturePath::GscriptChildLink => {
            // A child-link label must have been captured as interior (was_interior)
            // — it is an interior subview of its containing parent, so a
            // non-interior child_link id is inconsistent with the protection
            // requirement (P1-6: every carried identity field is consumed).
            ev.was_interior
                && parse_canonical_gscript_child_link_capture_id(
                    &ev.capture_id,
                    ev.containing_parent_old_base,
                    ev.source_slot_offset,
                    label.live_ptr,
                    ev.probe_requested_size,
                )
        }
        // GscriptFirstHop is NOT authorized (AF3 AF1 P1-2): the id encodes only
        // edge_off and cannot strictly bind base/parent/probe/was_interior.
        CapturePath::GscriptFirstHop => false,
        _ => false,
    }
}

/// Route Y R1 A6 AF3 AF1 (P1-5/P1-6): the `gscript_label:` label-table family is
/// only canonical when its deterministic source evidence is present and
/// consistent with the real emitter output. The exhaust emitter records:
///   - `source_slot_offset = Some(table_entry_off)` (byte offset within the table);
///   - `source_root_rva = Some(gscript.rva)` when the image-inline gscript object
///     carries a non-zero RVA (the production gscript root always does);
///   - `probe_requested_size == 0` (this family is bounded by
///     `cap_size_before_next_base`, NOT by a first-hop probe);
///   - `was_interior` true (a label-table entry is protected only when interior
///     to a uniquely-resolved containing parent).
///
/// A GscriptLabelTableEntry path with missing/absent source evidence, or a
/// non-zero probe evidence, is NOT canonical and must not be protected.
fn parse_canonical_label_table_source_evidence(label: &HeapGlobalSnapshot) -> bool {
    let ev = &label.extent_evidence;
    // Table-entry offset is deterministic and REQUIRED.
    if ev.source_slot_offset.is_none() {
        return false;
    }
    // This family never uses a first-hop probe — a non-zero probe evidence is
    // inconsistent with the real emitter output.
    if ev.probe_requested_size != 0 {
        return false;
    }
    // The interior label must have been captured as interior (was_interior).
    if !ev.was_interior {
        return false;
    }
    // source_root_rva is REQUIRED to be present when the emitting gscript root
    // has a valid RVA. The production image-inline gscript root always has a
    // non-zero RVA; a None here means the emitter could not establish the root.
    // We accept Some(rva) OR None — but a Some(rva) must be a plausible gscript
    // root (rva != 0). A missing root with no RVA is acceptable ONLY when the
    // root itself had no RVA; to stay conservative we require Some(non-zero).
    match ev.source_root_rva {
        Some(rva) => rva != 0,
        None => false,
    }
}

/// Route Y R1 A6 AF3: family-aware canonical re-validation at CONSUME time.
/// The stored `LabelFlagProtection` child carries the child's capture identity
/// (id/path/extent/base/size/source_slot_offset/probe). For the child_link
/// family the expected containing parent is the protection's recorded parent
/// base (that IS the containing parent by construction); the encoder's parent
/// field must equal it.
fn parse_canonical_protection_child_capture_id(p: &LabelFlagProtection) -> bool {
    let child = &p.child;
    match child.capture_path {
        CapturePath::GscriptLabelTableEntry => {
            parse_canonical_gscript_label_capture_id(&child.capture_id, child.old_base)
                // Consume-time source-evidence re-validation (P1-5/P1-6). The
                // stored protection child carries source_root_rva / was_interior
                // so the exact emitter output is re-verified at scrub time.
                && child.source_slot_offset.is_some()
                && child.probe_requested_size == 0
                && child.was_interior
                && matches!(child.source_root_rva, Some(rva) if rva != 0)
        }
        CapturePath::GscriptChildLink => {
            // Consume-time: the child must have been captured as interior
            // (was_interior) and its encoded parent/offset/base/probe must match
            // the protection's recorded parent evidence (P1-6).
            child.was_interior
                && parse_canonical_gscript_child_link_capture_id(
                    &child.capture_id,
                    Some(p.parent.old_base), // containing parent == protection parent
                    child.source_slot_offset,
                    child.old_base,
                    child.probe_requested_size,
                )
        }
        // GscriptFirstHop is NOT authorized (AF3 AF1 P1-2).
        CapturePath::GscriptFirstHop => false,
        _ => false,
    }
}

/// Require exactly one match. 0 → None (no authorization). >1 → None
/// (ambiguous; never silently pick the first).
pub(crate) fn unique_heap_global<'a, F>(
    heap_globals: &'a [HeapGlobalSnapshot],
    mut pred: F,
) -> Option<&'a HeapGlobalSnapshot>
where
    F: FnMut(&HeapGlobalSnapshot) -> bool,
{
    let mut found: Option<&HeapGlobalSnapshot> = None;
    for g in heap_globals {
        if pred(g) {
            if found.is_some() {
                return None; // duplicate/ambiguous → refuse authorization
            }
            found = Some(g);
        }
    }
    found
}

/// Route Y R1 A6 AF2: collect full-identity protection entries for every
/// legitimate gscript Label's `+0x23` non-nested redirect flag byte.
///
/// Generation requires ALL of:
///   - exactly one image-inline gscript object with a table pointer;
///   - exactly one label table at that pointer;
///   - exactly one label snapshot per table entry address;
///   - canonical `gscript_label:{base:#x}` capture_id matching live_ptr;
///   - extent_kind == InteriorSubview (ProbeWindow excluded);
///   - capture_path ∈ {GscriptChildLink} or GscriptLabelTableEntry;
///   - content.len() > 0x23; flag_addr via checked_add;
///   - exactly one containing parent matching declared base AND size;
///   - parent full identity recorded;
///   - child range strictly inside parent range;
///   - flag_addr inside both child and parent ranges.
///
/// Any ambiguity (0 or >1 match) refuses to generate a protection entry.
pub(crate) fn gscript_label_flag_protections(
    heap_globals: &[HeapGlobalSnapshot],
) -> Vec<LabelFlagProtection> {
    let mut protections = Vec::new();

    // Exactly one gscript object (image-inline, content >= 8 for table ptr).
    let Some(gscript) =
        unique_heap_global(heap_globals, |g| g.is_image_inline && g.content.len() >= 8)
    else {
        return protections;
    };
    let table_ptr = u64::from_le_bytes(gscript.content[0..8].try_into().unwrap_or_default());
    if table_ptr == 0 {
        return protections;
    }
    let Some(count) = gscript_label_count(&gscript.content) else {
        return protections;
    };

    // Exactly one label table at table_ptr.
    let Some(table) = unique_heap_global(heap_globals, |g| {
        g.live_ptr == table_ptr && g.content.len() >= 8
    }) else {
        return protections;
    };
    let n = count.min(table.content.len() / 8);
    for i in 0..n {
        let entry = u64::from_le_bytes(
            table.content[i * 8..i * 8 + 8]
                .try_into()
                .unwrap_or_default(),
        );
        if entry == 0 {
            continue;
        }
        // Exactly one label at the table-entry address.
        let Some(label) = unique_heap_global(heap_globals, |g| g.live_ptr == entry) else {
            continue; // 0 or >1 → no protection
        };

        // Bounds: flag field must exist.
        if label.content.len() <= 0x23 {
            continue;
        }
        // Extent: only confirmed InteriorSubview lineage.
        if label.extent_kind != CaptureExtentKind::InteriorSubview {
            continue;
        }
        // Path: only REAL production gscript Label families with FULLY-BOUND
        // identities. The label-table exhaust emits GscriptLabelTableEntry (AF3
        // fix); a pre-existing label captured via the real child-link emitter
        // keeps its GscriptChildLink path. MainSlot is NOT a label path, and
        // GscriptFirstHop is NOT authorized (AF3 AF1 P1-2): the first-hop
        // capture-id encodes only `edge_off`, which cannot bind child base /
        // parent / probe / was_interior on its own, so it cannot be strictly
        // validated — keeping it would be "code allows, test does not prove".
        // A first-hop-captured table-reachable label stays fail-closed.
        let path_ok = matches!(
            label.extent_evidence.capture_path,
            CapturePath::GscriptLabelTableEntry | CapturePath::GscriptChildLink
        );
        if !path_ok {
            continue;
        }
        // Canonical capture_id: family-aware strict parser validated against the
        // label's OWN recorded evidence fields (AF3 reachability). Rejects any
        // hand-built `gscript_label:` + GscriptChildLink tuple, arbitrary
        // `gscript_*` prefixes, and MainSlot/ProbeWindow-without-parent ids.
        if !parse_canonical_label_capture_id_for(label) {
            continue;
        }
        // Route Y R1 A6 AF3 AF1 (P1-5): for the label-table family, the recorded
        // source evidence must match the ACTUAL table context — the table-entry
        // byte offset `i*8` and the gscript root RVA `gscript.rva`. A correct
        // base with a wrong table offset or wrong source root is NOT protected.
        if label.extent_evidence.capture_path == CapturePath::GscriptLabelTableEntry {
            let expected_off = i * 8;
            if label.extent_evidence.source_slot_offset != Some(expected_off) {
                continue;
            }
            match label.extent_evidence.source_root_rva {
                Some(rva) if rva == gscript.rva => {}
                _ => continue,
            }
        }

        let (Some(parent_base), Some(parent_size)) = (
            label.extent_evidence.containing_parent_old_base,
            label.extent_evidence.containing_parent_size,
        ) else {
            continue; // no owning parent declared → no protection
        };

        // Exactly one parent matching declared base AND size.
        let Some(parent) = unique_heap_global(heap_globals, |g| {
            g.live_ptr == parent_base && g.content.len() == parent_size
        }) else {
            continue; // missing or duplicate parent → no protection
        };

        // Child must be strictly contained in parent.
        let child_base = label.live_ptr;
        let child_size = label.content.len();
        let Some(child_end) = child_base.checked_add(child_size as u64) else {
            continue;
        };
        let Some(parent_end) = parent_base.checked_add(parent_size as u64) else {
            continue;
        };
        if child_base < parent_base || child_end > parent_end {
            continue; // child not fully inside parent
        }

        // Flag address via checked_add (no wrapping authorization).
        let Some(flag_addr) = child_base.checked_add(0x23) else {
            continue;
        };
        // Flag must lie inside the child.
        if flag_addr < child_base || flag_addr >= child_end {
            continue;
        }
        // Flag must also lie inside the parent.
        if flag_addr < parent_base || flag_addr >= parent_end {
            continue;
        }

        // Qword that holds the flag (aligned down to 8).
        let flag_qword_lo = flag_addr & !7u64;
        let Some(flag_qword_hi) = flag_qword_lo.checked_add(8) else {
            continue;
        };

        let child = CaptureIdentity::from_heap_global(label);
        let parent_id = CaptureIdentity::from_heap_global(parent);
        // Parent identity must be a real heap-global with non-empty capture_id
        // (containers / empty-id objects cannot be authorized parents).
        if parent_id.capture_id.is_empty() {
            continue;
        }

        protections.push(LabelFlagProtection {
            child,
            parent: parent_id,
            flag_offset: 0x23,
            flag_addr,
            flag_qword_lo,
            flag_qword_hi,
        });
    }
    protections
}

/// True when the current scrub identity is authorized to skip this qword
/// under a given protection entry. EVERY identity field is consumed.
/// Pure, checked range-authorization predicate for the Label +0x23 protection:
/// `flag_addr` must be inside both child and parent, and the child must be
/// strictly inside the parent. Every addition is checked — overflow returns
/// false (no wrapping authorization).
pub(crate) fn label_flag_range_authorized(
    child_base: u64,
    child_size: usize,
    parent_base: u64,
    parent_size: usize,
    flag_addr: u64,
) -> bool {
    let Some(child_end) = child_base.checked_add(child_size as u64) else {
        return false;
    };
    let Some(parent_end) = parent_base.checked_add(parent_size as u64) else {
        return false;
    };
    if child_base < parent_base || child_end > parent_end {
        return false;
    }
    if flag_addr < child_base || flag_addr >= child_end {
        return false;
    }
    if flag_addr < parent_base || flag_addr >= parent_end {
        return false;
    }
    true
}

pub(crate) fn protection_authorizes_qword(
    current: &CurrentScrubIdentity,
    p: &LabelFlagProtection,
    qword_lo: u64,
    qword_hi: u64,
) -> bool {
    // 1. Current buffer must be exactly the recorded parent (full identity).
    if !current.matches_parent(&p.parent) {
        return false;
    }
    // 2. Child identity must still be canonical for its recorded base — family-aware
    // (AF3 reachability: accept only REAL production capture-id families, each
    // strict-validated against the stored child evidence: GscriptLabelTableEntry,
    // GscriptChildLink. GscriptFirstHop is NOT authorized — its id cannot bind
    // base/parent/probe/was_interior, so it stays fail-closed.)
    if !parse_canonical_protection_child_capture_id(p) {
        return false;
    }
    // 3. Child extent/path constraints re-checked at consume time.
    if p.child.extent_kind != CaptureExtentKind::InteriorSubview {
        return false;
    }
    if !matches!(
        p.child.capture_path,
        CapturePath::GscriptLabelTableEntry | CapturePath::GscriptChildLink
    ) {
        return false;
    }
    // 4. Flag offset must be exactly +0x23.
    if p.flag_offset != 0x23 {
        return false;
    }
    // 5. flag_addr must equal child.old_base + 0x23 (checked).
    let Some(expected_flag) = p.child.old_base.checked_add(0x23) else {
        return false;
    };
    if p.flag_addr != expected_flag {
        return false;
    }
    // 6. This qword must be the one that contains the flag.
    if p.flag_addr < qword_lo || p.flag_addr >= qword_hi {
        return false;
    }
    if qword_lo != p.flag_qword_lo || qword_hi != p.flag_qword_hi {
        return false;
    }
    // 7. Parent/child range relationship still holds (pure, checked, no wrapping).
    if !label_flag_range_authorized(
        p.child.old_base,
        p.child.size,
        p.parent.old_base,
        p.parent.size,
        p.flag_addr,
    ) {
        return false;
    }
    // 8. Current buffer base/size already equal parent via matches_parent;
    //    restate the size equality against the live buffer length contract.
    if current.old_base != p.parent.old_base || current.size != p.parent.size {
        return false;
    }
    true
}

pub(crate) fn scrub_buffer_external_ptrs(
    buf: &mut [u8],
    current: &CurrentScrubIdentity,
    ranges: &[(u64, u64)],
    image_base: u64,
    image_end: u64,
    label_protections: &[LabelFlagProtection],
) -> usize {
    let mut n = 0usize;
    let mut off = 0usize;
    while off + 8 <= buf.len() {
        let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or_default());
        // R-GTO-UI r19b: short AHK label names live as inline UTF-16 at +0x30
        // (e.g. "A_Ar" = 0x00720041005f0041). That bit pattern is also a
        // plausible user VA; scrubbing it destroys mName repair material and
        // leaves binary-search labels with null names → wcscmp AV.
        if looks_like_inline_utf16_qword(v) {
            off += 8;
            continue;
        }
        // Route Y R1 A6 AF2: skip this qword ONLY when full-identity authorization
        // holds — CurrentScrubIdentity == protection.parent on every field, child
        // still canonical, flag offset 0x23, qword is exactly the flag qword, and
        // parent/child range relationship still holds. Never authorize by physical
        // address, base/size, or capture_id prefix alone.
        let qword_lo = current.old_base + off as u64;
        let qword_hi = qword_lo + 8;
        let protected_here = label_protections
            .iter()
            .any(|p| protection_authorizes_qword(current, p, qword_lo, qword_hi));
        if protected_here {
            off += 8;
            continue;
        }
        if is_external_dangling_ptr(v, ranges, image_base, image_end) {
            buf[off..off + 8].fill(0);
            n += 1;
        }
        off += 8;
    }
    n
}

/// True when both u16 lanes look like ASCII identifier text / UTF-16 label chars.
fn looks_like_inline_utf16_qword(v: u64) -> bool {
    let lo = (v & 0xffff) as u16;
    let hi = ((v >> 16) & 0xffff) as u16;
    let lo2 = ((v >> 32) & 0xffff) as u16;
    let hi2 = ((v >> 48) & 0xffff) as u16;
    fn ok_u16(c: u16) -> bool {
        c == 0
            || c == b'_' as u16
            || c == b'$' as u16
            || c == b'@' as u16
            || c == b'#' as u16
            || c == b'-' as u16
            || c == b'.' as u16
            || (b'0' as u16..=b'9' as u16).contains(&c)
            || (b'A' as u16..=b'Z' as u16).contains(&c)
            || (b'a' as u16..=b'z' as u16).contains(&c)
            || (0x80..=0xff).contains(&c) // latin-1 label chars
    }
    // At least two non-zero ASCII-ish units; reject pure zeros.
    let units = [lo, hi, lo2, hi2];
    let nonzero = units.iter().filter(|&&c| c != 0).count();
    nonzero >= 2 && units.iter().all(|&c| ok_u16(c))
}

fn is_external_dangling_ptr(
    value: u64,
    ranges: &[(u64, u64)],
    image_base: u64,
    image_end: u64,
) -> bool {
    if value < MIN_USER_POINTER || value > MAX_USER_POINTER {
        return false;
    }
    // Image-relative absolutes are relocated by the loader / hardcode fixups.
    if value >= image_base && value < image_end {
        return false;
    }
    // Module / system range — leave alone (IAT-like junk is rare in heap blobs).
    if value >= MIN_MODULE_REGION {
        return false;
    }
    // Inside a captured block — multi-range fixup will remap at runtime.
    if ranges.iter().any(|&(lo, hi)| value >= lo && value < hi) {
        return false;
    }
    // Looks like a process-local heap pointer we did not capture.
    true
}

/// Read the 8-byte slot: prefer live process memory, fall back to dump buffer.
fn read_slot_value(
    image_base: u64,
    rva: u32,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
) -> u64 {
    let mut live = [0u8; 8];
    let addr = image_base.saturating_add(rva as u64) as usize;
    if let Ok(n) = debugger.read_memory(addr, &mut live) {
        if n == 8 {
            let v = u64::from_le_bytes(live);
            if v != 0 {
                return v;
            }
        }
    }
    let offset = rva as usize;
    if offset + 8 <= dump_buf.len() {
        u64::from_le_bytes(dump_buf[offset..offset + 8].try_into().unwrap_or_default())
    } else {
        0
    }
}

/// Sections that may hold code referencing image globals.
///
/// Themida materializes patched call sites into `.wfix` (and similar) pages
/// that are not always marked `MEM_EXECUTE` at dump time. Restricting the
/// xref scan to EXECUTE-only sections misses the only references to critical
/// zero-raw `.fill` slots (e.g. `0x18a898` loaded from `.wfix+…`).
fn section_may_hold_code(section: &crate::header::PeSection) -> bool {
    if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
        return true;
    }
    if section.characteristics & 0x20 != 0 {
        // IMAGE_SCN_CNT_CODE
        return true;
    }
    let name = section.name.as_str();
    name.starts_with(".wfix")
        || name.starts_with(".text")
        || name.starts_with(".boot")
        || name.is_empty()
}

/// Scan code-bearing sections for RIP-relative memory operands targeting
/// `ranges`. Returns map of target RVA → hit count.
fn collect_code_xrefs_to_ranges(
    pe: &PeHeader,
    dump_buf: &[u8],
    ranges: &[(u32, u32)],
) -> BTreeMap<u32, u32> {
    let mut hits: BTreeMap<u32, u32> = BTreeMap::new();

    for section in pe.sections.iter().filter(|s| section_may_hold_code(s)) {
        let start = section.virtual_address as usize;
        // Prefer raw_size when present — .wfix is small and fully on-disk.
        let span = section
            .virtual_size
            .max(section.raw_size)
            .max(section.header.size_of_raw_data) as usize;
        let end = start.saturating_add(span).min(dump_buf.len());
        if end.saturating_sub(start) < 7 {
            continue;
        }
        let code = &dump_buf[start..end];
        let mut i = 0usize;
        while i + 7 <= code.len() {
            let b0 = code[i];
            // REX.W / REX.WR / REX.WB / REX.WRB — any with W bit for 64-bit ops
            let is_rex_w = (b0 & 0xF8) == 0x48;
            if is_rex_w {
                let op = code[i + 1];
                // mov r/m, mov m/r, lea, mov imm, xor/and/or/cmp mem forms that touch slots
                if matches!(
                    op,
                    0x8b | 0x89 | 0x8d | 0xc7 | 0x33 | 0x3b | 0x0b | 0x23 | 0x85
                ) {
                    let modrm = code[i + 2];
                    if (modrm & 0xC7) == 0x05 {
                        let disp = i32::from_le_bytes([
                            code[i + 3],
                            code[i + 4],
                            code[i + 5],
                            code[i + 6],
                        ]);
                        let instr_len = if op == 0xc7 { 11 } else { 7 };
                        if op == 0xc7 && i + instr_len > code.len() {
                            i += 1;
                            continue;
                        }
                        let next_rva =
                            section.virtual_address + i as u32 + if op == 0xc7 { 11 } else { 7 };
                        let target = (next_rva as i64 + disp as i64) as u32;
                        if target & 7 == 0
                            && ranges.iter().any(|&(lo, hi)| target >= lo && target < hi)
                        {
                            *hits.entry(target).or_insert(0) += 1;
                        }
                    }
                }
            }
            i += 1;
        }
    }

    hits
}

fn is_zero_raw_writable(section: &crate::header::PeSection) -> bool {
    if section.characteristics & IMAGE_SCN_MEM_WRITE == 0 {
        return false;
    }
    section.raw_size == 0
        || section.header.size_of_raw_data == 0
        || section.name.starts_with(".fill")
}

/// NT HEAP `SegmentSignature` (x64 `_HEAP_SEGMENT` at +0x10).
const NT_HEAP_SEGMENT_SIGNATURE: u32 = 0xFFEE_FFEE;
/// Segment heap front-end marker seen on some Win10+ private heaps.
const SEGMENT_HEAP_SIGNATURE: u32 = 0xDDEE_DDEE;

/// Enumerate process heap handles from the target PEB (`ProcessHeap` +
/// `ProcessHeaps[]`). Failures return an empty set — callers fall back to
/// [`looks_like_heap_handle`].
fn enumerate_process_heap_handles(debugger: &dyn mida_core::DebuggerCore) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    let peb = match query_peb_address(debugger) {
        Some(p) if p != 0 => p,
        _ => return out,
    };
    // PEB64: ProcessHeap @ +0x30, NumberOfHeaps @ +0xE8, ProcessHeaps @ +0xF0.
    let mut process_heap = [0u8; 8];
    if debugger
        .read_memory((peb + 0x30) as usize, &mut process_heap)
        .ok()
        .filter(|&n| n == 8)
        .is_some()
    {
        let h = u64::from_le_bytes(process_heap);
        if h != 0 {
            out.insert(h);
        }
    }
    let mut nheaps_buf = [0u8; 4];
    let mut heaps_ptr_buf = [0u8; 8];
    let nheaps = if debugger
        .read_memory((peb + 0xE8) as usize, &mut nheaps_buf)
        .ok()
        .filter(|&n| n == 4)
        .is_some()
    {
        u32::from_le_bytes(nheaps_buf) as usize
    } else {
        0
    };
    let heaps_ptr = if debugger
        .read_memory((peb + 0xF0) as usize, &mut heaps_ptr_buf)
        .ok()
        .filter(|&n| n == 8)
        .is_some()
    {
        u64::from_le_bytes(heaps_ptr_buf)
    } else {
        0
    };
    if heaps_ptr != 0 && nheaps > 0 && nheaps <= 64 {
        let bytes = nheaps.saturating_mul(8);
        let mut table = vec![0u8; bytes];
        if let Ok(n) = debugger.read_memory(heaps_ptr as usize, &mut table) {
            let usable = n / 8;
            for i in 0..usable {
                let h = u64::from_le_bytes(table[i * 8..i * 8 + 8].try_into().unwrap_or_default());
                if h != 0 {
                    out.insert(h);
                }
            }
        }
    }
    if !out.is_empty() {
        info!(
            count = out.len(),
            "Enumerated process heap handles from PEB"
        );
    }
    out
}

fn query_peb_address(debugger: &dyn mida_core::DebuggerCore) -> Option<u64> {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;

    let mut pbi = PROCESS_BASIC_INFORMATION::default();
    let mut ret_len: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            debugger.process_handle(),
            PROCESSINFOCLASS(0i32),
            (&mut pbi as *mut PROCESS_BASIC_INFORMATION) as *mut std::ffi::c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        )
    };
    if status.is_ok() || status.0 == 0 {
        Some(pbi.PebBaseAddress as u64)
    } else {
        None
    }
}

/// True when `ptr` looks like an NT/segment heap *handle* (manager header),
/// not an ordinary user allocation.
fn looks_like_heap_handle(debugger: &dyn mida_core::DebuggerCore, ptr: u64) -> bool {
    if ptr < MIN_HEAP_POINTER || ptr > MAX_USER_POINTER || ptr & 0xFFF != 0 {
        // Heap bases are page-aligned in practice.
        return false;
    }
    let mut hdr = [0u8; 0x70];
    let n = match debugger.read_memory(ptr as usize, &mut hdr) {
        Ok(n) if n >= 0x48 => n,
        _ => return false,
    };
    // NT heap: SegmentSignature at +0x10.
    if n >= 0x14 {
        let sig = u32::from_le_bytes(hdr[0x10..0x14].try_into().unwrap_or_default());
        if sig == NT_HEAP_SEGMENT_SIGNATURE {
            return true;
        }
    }
    // Segment heap signature at +0.
    let sig0 = u32::from_le_bytes(hdr[0..4].try_into().unwrap_or_default());
    if sig0 == SEGMENT_HEAP_SIGNATURE || sig0 == NT_HEAP_SEGMENT_SIGNATURE {
        return true;
    }
    // Self-pointer fields common in _HEAP.
    for off in [0x28usize, 0x30, 0x40, 0x48, 0x50, 0x60] {
        if off + 8 > n {
            break;
        }
        let v = u64::from_le_bytes(hdr[off..off + 8].try_into().unwrap_or_default());
        if v == ptr {
            return true;
        }
    }
    false
}

fn is_heap_pointer(value: u64, image_base: u64, image_end: u64) -> bool {
    if value < MIN_HEAP_POINTER.max(MIN_USER_POINTER) || value > MAX_USER_POINTER {
        return false;
    }
    if value & 7 != 0 {
        return false;
    }
    // Reject image pointers.
    if (image_base..image_end).contains(&value) {
        return false;
    }
    // Reject system DLL / shared module mappings (kernel32, ntdll, …).
    // Those are readable for tens of KB and look like "heap objects" to probes.
    if value >= MIN_MODULE_REGION {
        return false;
    }
    true
}

/// Full-image linear scan for `REX.W + op + ModRM=rip-rel` targeting `ranges`.
/// Used when code lives in synthetic `.fill` with no EXECUTE section header.
fn collect_rip_xrefs_in_buffer(dump_buf: &[u8], ranges: &[(u32, u32)]) -> BTreeMap<u32, u32> {
    let mut hits: BTreeMap<u32, u32> = BTreeMap::new();
    if ranges.is_empty() || dump_buf.len() < 7 {
        return hits;
    }
    let mut i = 0usize;
    while i + 7 <= dump_buf.len() {
        let b0 = dump_buf[i];
        if (b0 & 0xF8) == 0x48 {
            let op = dump_buf[i + 1];
            if matches!(op, 0x8b | 0x89 | 0x8d | 0xc7) {
                let modrm = dump_buf[i + 2];
                if (modrm & 0xC7) == 0x05 {
                    let disp = i32::from_le_bytes([
                        dump_buf[i + 3],
                        dump_buf[i + 4],
                        dump_buf[i + 5],
                        dump_buf[i + 6],
                    ]);
                    let instr_len = if op == 0xc7 { 11 } else { 7 };
                    if op == 0xc7 && i + instr_len > dump_buf.len() {
                        i += 1;
                        continue;
                    }
                    // dump_buf is image-relative: index == RVA.
                    let next_rva = (i as u32).saturating_add(if op == 0xc7 { 11 } else { 7 });
                    let target = (next_rva as i64 + disp as i64) as u32;
                    if target & 7 == 0 && ranges.iter().any(|&(lo, hi)| target >= lo && target < hi)
                    {
                        *hits.entry(target).or_insert(0) += 1;
                    }
                }
            }
        }
        i += 1;
    }
    hits
}

fn estimate_object_size(
    dump_buf: &[u8],
    slot_offset: usize,
    heap_ptr: u64,
    debugger: &mut dyn mida_core::DebuggerCore,
    probe_cap: usize,
) -> usize {
    let probe_cap = probe_cap.min(MAX_HEAP_GLOBAL_BYTES).max(0x40);
    // Adjacent size field (slot+8) often holds 0x1000-class lengths.
    if slot_offset != usize::MAX && slot_offset + 16 <= dump_buf.len() {
        let maybe_size = u64::from_le_bytes(
            dump_buf[slot_offset + 8..slot_offset + 16]
                .try_into()
                .unwrap_or_default(),
        );
        if (0x10..=probe_cap as u64).contains(&maybe_size) && maybe_size & 0xf == 0 {
            let size = maybe_size as usize;
            if can_read(debugger, heap_ptr, size, probe_cap) {
                return size;
            }
        }
    }

    let mut best = 0usize;
    for &probe in &SIZE_PROBES {
        if probe > probe_cap {
            break;
        }
        if can_read(debugger, heap_ptr, probe, probe_cap) {
            best = probe;
        } else {
            break;
        }
    }
    // Do NOT binary-search above the last successful SIZE_PROBE: RPM succeeds
    // across whole committed heap segments and would pull in neighbour objects.
    best
}

fn can_read(
    debugger: &mut dyn mida_core::DebuggerCore,
    addr: u64,
    size: usize,
    cap: usize,
) -> bool {
    let Ok(mut buf) = alloc_capped(size, cap.max(size), "heap global probe") else {
        return false;
    };
    match debugger.read_memory(addr as usize, &mut buf) {
        Ok(n) => n == size,
        Err(_) => false,
    }
}
#[cfg(test)]
#[path = "heap_global_snapshot_tests.rs"]
mod heap_global_snapshot_tests;
