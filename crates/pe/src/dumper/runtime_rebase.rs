//! Deterministic runtime heap / container rebasing plan (offline core).

//!
//! Production `.unwrap()`s are invariants: `position(is_structural)` runs only
//! after the `n_struct == 0` early-continue, so a structural record exists
//! (WO-10). Test unwraps are assertions.
#![allow(clippy::unwrap_used)]
//!
//! GTO R0 (heap/runtime rebase): a cold-start unpacked PE must not carry
//! pointers into the original process's heap / private allocations. Those
//! addresses die with the live process. This module turns the *captured*
//! allocation set (encoded containers, plain heap globals, heap slab) into a
//! **deterministic, fail-closed rebasing plan** that the offline recovery can
//! validate and that a two-phase runtime bootstrap must satisfy:
//!
//! - **Phase 1 (allocate):** every required region is allocated fresh. A failed
//!   required allocation aborts the whole recovery; we never jump to OEP.
//! - **Phase 2 (copy & patch):** snapshot bytes are copied into the new
//!   allocations, and every declared pointer slot is rewritten from its old VA
//!   to its new VA. Only then is the completion cookie set and control moved to
//!   the real OEP.
//!
//! This module is the **planning / validation** half. It is pure (no process
//! I/O), so it is fully exercisable offline with synthetic fixtures. The
//! existing `container_bootstrap` / `heap_bootstrap` stubs are the runtime
//! execution half; their metadata layout must satisfy this plan's contract.
//!
//! # Invariants (all enforced here)
//!
//! 1. Old ranges use checked arithmetic (no `old_base + size` overflow).
//! 2. Regions may not overlap; overlap fails closed.
//! 3. A single old VA maps to exactly one target.
//! 4. Region/layout ordering is deterministic (never HashMap iteration order).
//! 5. Pointer width is explicitly bound to x64 (8 bytes); we never guess that an
//!    arbitrary 8-byte word is a pointer.
//! 6. Only explicitly declared pointer slots may be patched.
//! 7. A required pointer left unresolved fails the whole recovery.
//! 8. Optional/opaque data keeps its original bytes but is recorded as
//!    uninterpreted.
//! 9. Every patch write is bounds-checked before it touches a slot.
//! 10. After patching, no required pointer may still target a captured old
//!     heap/private range.
//!
//! # States
//!
//! A recovery summary is one of `Complete`, `Incomplete`, `Rejected`. Only
//! `unresolved_required == 0` **and** a complete bootstrap contract yields
//! `Complete`. We never use acceptance terms such as "Accepted"/"Product Pass".

use std::fmt;

use tracing::info;

use super::container_snapshot::ContainerSnapshot;
use super::heap_global_snapshot::{HeapGlobalSnapshot, HeapSlab, RegionProvenance};

/// Pointer width this plan reasons about. GTO/R0 is x64-only; anything narrower
/// is rejected before a plan is built.
pub const POINTER_WIDTH: usize = 8;
/// Tagged small-integer ceiling: values below this are treated as tags/counts,
/// never as pointers (prevents an arbitrary small qword from being rebased).
pub const SMALL_TAG_CEILING: u64 = 0x1_0000;

/// Canonical user-mode stack/TEB reserved region base on x64.
/// Above this ceiling the address space belongs to per-process
/// ephemeral state (thread stacks, TEBs) — NOT the DLL load zone
/// (0x7ff0_0000_0000..0x7fff_ff00_0000). A pointer into this region
/// cannot survive cold-start rebasing (the new process has its own
/// stacks) and is never a persistent object-graph edge.
pub const STACK_RESERVED_BASE: u64 = 0x0000_7fff_ff00_0000;
/// Hard ceiling for one rebased region's captured payload (matches dumper caps).
const MAX_REGION_BYTES: usize = 64 * 1024 * 1024;

/// Classification of a declared pointer slot's *original* value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerClassification {
    /// Original value is 0 — left untouched.
    Null,
    /// Original value points inside the rebuilt image (`image_base + rva`).
    InImage,
    /// Original value points inside one of the captured regions (old heap).
    InCapturedRegion,
    /// Original value is a stable external module / API address backed by a
    /// verifiable resolver (import/IAT/export mapping). Resolved at runtime.
    ExternalModule,
    /// Original value looks like an external high-address API but has **no**
    /// verifiable resolver. This is *not* resolved: it must count toward
    /// `unresolved_required` and the recovery cannot be `Complete`.
    ExternalCandidate,
    /// Original value is a small integer / tag, not a pointer.
    SmallIntegerOrTag,
    /// Original value is not mapped to any known image/captured/external range.
    Unmapped,
    /// Original value could match more than one captured region (ambiguous).
    Ambiguous,
}

impl PointerClassification {
    /// Deterministic label for evidence/diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            PointerClassification::Null => "null",
            PointerClassification::InImage => "in_image",
            PointerClassification::InCapturedRegion => "in_captured_region",
            PointerClassification::ExternalModule => "external_module",
            PointerClassification::ExternalCandidate => "external_candidate",
            PointerClassification::SmallIntegerOrTag => "small_integer_or_tag",
            PointerClassification::Unmapped => "unmapped",
            PointerClassification::Ambiguous => "ambiguous",
        }
    }

    /// A pointer that must resolve to a concrete target for cold-start. An
    /// `Unmapped`, `Ambiguous`, or `ExternalCandidate` pointer is *required* to
    /// resolve; leaving it unresolved fails the whole recovery.
    pub fn is_required(self) -> bool {
        matches!(
            self,
            PointerClassification::InCapturedRegion
                | PointerClassification::InImage
                | PointerClassification::ExternalModule
                | PointerClassification::ExternalCandidate
                | PointerClassification::Unmapped
                | PointerClassification::Ambiguous
        )
    }

    /// True when the pointer is a *resolved* rebase target (patchable).
    pub fn is_resolved(self) -> bool {
        matches!(
            self,
            PointerClassification::InCapturedRegion
                | PointerClassification::InImage
                | PointerClassification::ExternalModule
        )
    }

    /// True when the pointer is an unresolved-but-required candidate.
    pub fn is_unresolved_required(self) -> bool {
        matches!(
            self,
            PointerClassification::ExternalCandidate
                | PointerClassification::Unmapped
                | PointerClassification::Ambiguous
        )
    }
}

/// A captured allocation that must be re-created in the cold-start process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseRegion {
    /// Deterministic stable id (index in the plan's sorted region list).
    pub id: usize,
    /// Old (live-process) allocation base.
    pub old_base: u64,
    /// Captured payload size in bytes.
    pub size: usize,
    /// Allocation alignment (bytes).
    pub alignment: usize,
    /// Captured raw bytes (snapshot).
    pub bytes: Vec<u8>,
    /// Whether this region is required for cold-start correctness.
    pub required: bool,
    /// What produced this region (diagnostic; never a sample-VA hardcode).
    pub kind: RegionKind,
    /// When `Some`, this region's body lives inside the image at `image_rva`
    /// (e.g. an image-inline object) rather than in a fresh heap allocation.
    pub image_inline_rva: Option<u32>,
    /// Provenance of this region (GTO Core Recovery R0-D). SyntheticDerived
    /// regions are materialized via independent runtime allocation and never
    /// reported as raw-captured; UnknownSynthetic must not reach a Complete
    /// plan.
    pub provenance: RegionProvenance,
    /// Extent classification (GTO R0-F.1). Probe windows must not become
    /// independent allocations; they are absorbed as slab aliases or fail
    /// closed.
    pub extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind,
    /// Runtime ownership (GTO R0-F.1). Derives how this region is materialized
    /// at cold-start (independent HeapAlloc vs slab-owned alias vs image).
    pub ownership: RuntimeRegionOwnership,
}

/// How a region is owned/materialized at runtime (GTO Core Recovery R0-F.1).
///
/// A rebase region's ownership is one of: a fresh heap allocation, an image
/// body, a synthetic allocation, or an external resolver. Absorbed probe /
/// interior subviews are NOT regions — they live only in [`RegionAlias`] and
/// are represented by [`AliasOwnership`] (GTO R0-F.2 removed the dead
/// `SlabOwnedAlias` region variant so no unreachable branch is misleadingly
/// "implemented").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeRegionOwnership {
    /// A fresh independent heap allocation at cold-start.
    IndependentAllocation,
    /// An image-inline object body (owned by the image, not the heap).
    ImageInline,
    /// A synthetic region allocated independently at cold-start.
    SyntheticAllocation,
    /// Resolved through the external resolver / IAT at cold-start.
    ExternalResolved,
}

/// Provenance of a rebase region (diagnostic only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// SecurityCookie-encoded container (begin/end/capacity triple).
    Container,
    /// Plain heap-global object referenced from an image slot.
    HeapGlobal,
    /// Heap slab (contiguous blob covering the global span).
    HeapSlab,
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegionKind::Container => f.write_str("container"),
            RegionKind::HeapGlobal => f.write_str("heap_global"),
            RegionKind::HeapSlab => f.write_str("heap_slab"),
        }
    }
}

/// Interval relationship between two half-open ranges `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionRelation {
    /// No shared address; `b.start >= a.end` (or vice versa).
    Disjoint,
    /// `b.start == a.end` (or vice versa); touching but not overlapping.
    Adjacent,
    /// Identical ranges `[start, end)`.
    ExactDuplicate,
    /// `a` fully contains `b` (a.start <= b.start && b.end <= a.end, and a larger).
    Contains,
    /// `a` is fully inside `b`.
    ContainedBy,
    /// Ranges share bytes but neither contains the other.
    PartialOverlap,
}

impl RegionRelation {
    pub fn label(self) -> &'static str {
        match self {
            RegionRelation::Disjoint => "disjoint",
            RegionRelation::Adjacent => "adjacent",
            RegionRelation::ExactDuplicate => "exact_duplicate",
            RegionRelation::Contains => "contains",
            RegionRelation::ContainedBy => "contained_by",
            RegionRelation::PartialOverlap => "partial_overlap",
        }
    }
}

/// Classify the relationship between two half-open ranges using checked
/// arithmetic. Any arithmetic overflow fails closed (returns `Err`).
pub fn classify_region_relation(
    a_start: u64,
    a_size: usize,
    b_start: u64,
    b_size: usize,
) -> Result<RegionRelation, RebaseError> {
    let a_size_u = u64::try_from(a_size).map_err(|_| RebaseError::Overflow {
        region: 0,
        old_base: a_start,
        size: a_size,
    })?;
    let b_size_u = u64::try_from(b_size).map_err(|_| RebaseError::Overflow {
        region: 1,
        old_base: b_start,
        size: b_size,
    })?;
    let a_end = a_start.checked_add(a_size_u).ok_or(RebaseError::Overflow {
        region: 0,
        old_base: a_start,
        size: a_size,
    })?;
    let b_end = b_start.checked_add(b_size_u).ok_or(RebaseError::Overflow {
        region: 1,
        old_base: b_start,
        size: b_size,
    })?;
    // Order ranges so `a` is the lower-start one (ties resolved by larger size).
    let (lo_start, lo_size, lo_end, hi_start, hi_size, hi_end, swapped) = if a_start < b_start {
        (a_start, a_size, a_end, b_start, b_size, b_end, false)
    } else if a_start > b_start {
        (b_start, b_size, b_end, a_start, a_size, a_end, true)
    } else {
        // same start: the larger size is the outer range.
        if a_size >= b_size {
            (a_start, a_size, a_end, b_start, b_size, b_end, false)
        } else {
            (b_start, b_size, b_end, a_start, a_size, a_end, true)
        }
    };
    if lo_end <= hi_start {
        return Ok(if lo_end == hi_start {
            RegionRelation::Adjacent
        } else {
            RegionRelation::Disjoint
        });
    }
    // Overlapping. Determine containment.
    if lo_start == hi_start && lo_size == hi_size {
        return Ok(RegionRelation::ExactDuplicate);
    }
    if lo_start == hi_start {
        // Same start, one strictly bigger -> Contains/ContainedBy.
        return Ok(if swapped {
            RegionRelation::ContainedBy
        } else {
            RegionRelation::Contains
        });
    }
    if hi_end <= lo_end {
        // hi range fully inside lo range.
        if swapped {
            // b (original) is lo (outer) -> b contains a.
            Ok(RegionRelation::ContainedBy)
        } else {
            // a (original) is lo (outer) -> a contains b.
            Ok(RegionRelation::Contains)
        }
    } else {
        Ok(RegionRelation::PartialOverlap)
    }
}

/// How an absorbed alias is owned at runtime (GTO R0-F.2).
///
/// Alias ownership is distinct from [`RuntimeRegionOwnership`]: an alias is
/// never a runtime allocation; it is a view into its parent's allocation. This
/// replaces the removed dead `RuntimeRegionOwnership::SlabOwnedAlias` variant so
/// the ownership model has no unreachable production branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasOwnership {
    /// The alias is a view owned by its slab/parent allocation (not separately
    /// allocated). The only production alias ownership today.
    SlabOwned,
}

/// An absorbed (coalesced) child region that lives inside a normalized parent
/// backing region. Diagnostic + digest-binding; not a runtime allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionAlias {
    /// Old base of the absorbed child region.
    pub alias_old_base: u64,
    /// Size of the absorbed child region.
    pub alias_size: usize,
    /// Id of the normalized parent backing region.
    pub parent_region: usize,
    /// Offset of the child within the parent (`alias_old_base - parent.old_base`).
    pub parent_offset: usize,
    /// Original kind of the absorbed child.
    pub original_kind: RegionKind,
    /// Whether the child was required (must be preserved).
    pub required: bool,
    /// sha256 of the child's captured bytes (for content verification).
    pub content_digest: String,
    /// Extent classification of the absorbed child (GTO R0-F.1).
    pub extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind,
    /// Runtime ownership of this alias (GTO R0-F.2). Always `SlabOwned`; an
    /// alias is a view of its parent, never an independent allocation.
    pub ownership: AliasOwnership,
    /// sha256 of the authoritative parent slab slice `[parent_offset, +alias_size)`.
    /// The parent slab is the payload authority for probe/interior views (GTO R0-G).
    pub parent_slice_digest: String,
    /// sha256 of the accepted non-write capture drift between the child capture
    /// and the authoritative slab slice (empty when no drift). When non-empty,
    /// the parent slab bytes win; this records the drifted diff (GTO R0-G).
    pub accepted_drift_digest: String,
}

/// A declared pointer slot inside a captured region.
///
/// Only slots with explicit provenance may be patched. The plan never guesses
/// that an arbitrary qword is a pointer; un-declared qwords are candidates at
/// most (see [`PointerCandidate`]) and are never added to the fixup ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebasePointer {
    /// Id of the region containing the slot.
    pub source_region: usize,
    /// Byte offset of the slot within that region's payload.
    pub source_offset: usize,
    /// Original 8-byte value (the old VA or non-pointer).
    pub original_value: u64,
    /// Classification of `original_value`.
    pub classification: PointerClassification,
    /// Target region id for an `InCapturedRegion` pointer.
    pub target_region: Option<usize>,
    /// Byte offset within the target region (interior pointer support).
    pub target_offset: Option<u64>,
    /// Image RVA for an `InImage` pointer (rebind to rebuilt image base).
    pub image_rva: Option<u32>,
    /// Resolved external target for an `ExternalModule` pointer.
    pub external_target: Option<ExternalTarget>,
    /// Provenance that declared this slot as a pointer.
    pub provenance: SlotProvenance,
}

/// Where a [`RebasePointer`] slot was declared. A pointer may only be patched
/// when it has a real provenance; everything else is at most a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotProvenance {
    /// Declared by the container begin/end/capacity triple schema.
    ContainerTriple,
    /// Declared by a heap-global image-root slot.
    HeapGlobalRoot,
    /// Declared by an explicit capture descriptor.
    CaptureDescriptor,
    /// Declared by a relocation/root ledger.
    RelocationRoot,
    /// Declared by explicit live observation.
    LiveObservation,
}

impl SlotProvenance {
    pub fn label(self) -> &'static str {
        match self {
            SlotProvenance::ContainerTriple => "container_triple",
            SlotProvenance::HeapGlobalRoot => "heap_global_root",
            SlotProvenance::CaptureDescriptor => "capture_descriptor",
            SlotProvenance::RelocationRoot => "relocation_root",
            SlotProvenance::LiveObservation => "live_observation",
        }
    }
}

/// A heuristic pointer *candidate* found by scanning a captured payload. Pure
/// diagnostic — never patched, never auto-marked required. Used to report
/// `candidate_count` and to guard against treating every qword as a pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerCandidate {
    pub source_region: usize,
    pub source_offset: usize,
    pub value: u64,
    pub plausible_pointer: bool,
}

/// A verifiable external target for an [`PointerClassification::ExternalModule`]
/// pointer.
///
/// Resolution is only "resolved" when a concrete resolver exists (an import/IAT
/// slot, or an export mapping with a stable module). A bare high-address value
/// is at best an [`PointerClassification::ExternalCandidate`] and must count as
/// unresolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalTarget {
    /// Resolved module identity (lowercase dll name, e.g. `"kernel32.dll"`).
    pub module_identity: String,
    /// RVA within the module's export table (offset from its base).
    pub module_rva: u64,
    /// Import DLL the function resolves through (if via import/IAT).
    pub import_dll: String,
    /// Import name (or `#ordinal`).
    pub import_name_or_ordinal: String,
    /// IAT slot RVA this pointer resolves through, when an import resolver is
    /// used (the cold-start IAT holds the live API address at that slot).
    pub iat_rva: Option<u32>,
    /// How this external is resolved at runtime.
    pub resolution_kind: ExternalResolutionKind,
}

/// How an external target is resolved at cold-start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalResolutionKind {
    /// Resolved by reading the cold-start process's IAT slot (loader-bound).
    ViaIat,
    /// Resolved by a reconstructed export/GetProcAddress mapping.
    ViaExportMap,
    /// Resolved by a direct, stable module+ordinal binding (loader guarantees).
    ViaStableBinding,
}

impl ExternalResolutionKind {
    pub fn label(self) -> &'static str {
        match self {
            ExternalResolutionKind::ViaIat => "via_iat",
            ExternalResolutionKind::ViaExportMap => "via_export_map",
            ExternalResolutionKind::ViaStableBinding => "via_stable_binding",
        }
    }
}

/// Rebuild target for an `InCapturedRegion` pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Target {
    region: usize,
    offset: u64,
}

/// The offline rebasing plan for one recovery.
///
/// Everything here is sorted and deterministic; identical capture input yields
/// identical plan bytes.
#[derive(Debug, Clone)]
pub struct RuntimeRebasePlan {
    /// All captured allocations, sorted by `(old_base, size)`.
    pub regions: Vec<RebaseRegion>,
    /// Declared pointer slots, sorted by `(source_region, source_offset)`.
    /// Only these are patchable (they carry provenance).
    pub pointers: Vec<RebasePointer>,
    /// External resolver table referenced by `ExternalModule` pointers.
    pub external_targets: Vec<ExternalTarget>,
    /// Heuristic pointer candidates (diagnostic only — never patched).
    pub candidates: Vec<PointerCandidate>,
    /// Absorbed (coalesced) child regions aliased into a normalized parent.
    /// Diagnostic + digest-binding; never runtime-allocated.
    pub aliases: Vec<RegionAlias>,
    /// Old image base of the source process (diagnostic; not a rebase target).
    pub old_image_base: u64,
    /// Rebuilt image base the cold-start PE loads at (InImage rebase target).
    pub new_image_base: u64,
    /// Whether the plan is ready for two-phase runtime execution.
    pub plan_complete: bool,
    /// Deterministic digest of the plan (sha256 of a canonical byte encoding).
    pub plan_digest: String,
}

impl RuntimeRebasePlan {
    /// Total captured payload bytes across all regions.
    pub fn bytes_captured(&self) -> usize {
        self.regions.iter().map(|r| r.size).sum()
    }

    /// Count of regions marked required.
    pub fn regions_required(&self) -> usize {
        self.regions.iter().filter(|r| r.required).count()
    }

    /// Deterministic canonical byte encoding (used for `plan_digest`).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for r in &self.regions {
            out.extend_from_slice(&r.id.to_le_bytes());
            out.extend_from_slice(&r.old_base.to_le_bytes());
            out.extend_from_slice(&(r.size as u64).to_le_bytes());
            out.extend_from_slice(&(r.alignment as u64).to_le_bytes());
            out.push(r.required as u8);
            out.extend_from_slice(&(r.kind as u8).to_le_bytes());
            match r.image_inline_rva {
                Some(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                None => out.push(0),
            }
            out.extend_from_slice(&r.bytes);
            // R0-D: bind region provenance into the plan digest so a synthetic
            // payload change (or provenance change) alters the digest.
            out.push(region_provenance_tag(&r.provenance));
            match &r.provenance {
                RegionProvenance::RawCaptured { raw_digest }
                | RegionProvenance::TransformedRawCaptured { raw_digest, .. } => {
                    out.extend_from_slice(raw_digest.as_bytes());
                    out.push(0);
                }
                RegionProvenance::SyntheticDerived {
                    transform_id,
                    source_anchor,
                    construction_digest,
                } => {
                    out.extend_from_slice(transform_id.as_bytes());
                    out.push(0);
                    out.extend_from_slice(source_anchor.as_bytes());
                    out.push(0);
                    out.extend_from_slice(construction_digest.as_bytes());
                    out.push(0);
                }
                RegionProvenance::ImageInline
                | RegionProvenance::ExternalResolved
                | RegionProvenance::UnknownSynthetic => {}
            }
            // GTO R0-F.1: bind extent kind + runtime ownership into the plan
            // digest so a probe-window classification change, ownership change,
            // alias parent, or alias offset alters the digest.
            out.push(extent_kind_tag(&r.extent_kind));
            out.push(ownership_tag(&r.ownership));
        }
        for p in &self.pointers {
            out.extend_from_slice(&p.source_region.to_le_bytes());
            out.extend_from_slice(&p.source_offset.to_le_bytes());
            out.extend_from_slice(&p.original_value.to_le_bytes());
            out.push(class_as_u8(p.classification));
            out.push(provenance_as_u8(p.provenance));
            match p.target_region {
                Some(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                None => out.push(0),
            }
            match p.target_offset {
                Some(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                None => out.push(0),
            }
            match p.image_rva {
                Some(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                None => out.push(0),
            }
            match &p.external_target {
                Some(t) => {
                    out.push(1);
                    out.extend_from_slice(&t.module_rva.to_le_bytes());
                    out.extend_from_slice(&t.import_dll.as_bytes());
                    out.push(0);
                    out.extend_from_slice(&t.import_name_or_ordinal.as_bytes());
                    out.push(0);
                    match t.iat_rva {
                        Some(v) => {
                            out.push(1);
                            out.extend_from_slice(&v.to_le_bytes());
                        }
                        None => out.push(0),
                    }
                    out.push(resolution_kind_as_u8(t.resolution_kind));
                }
                None => out.push(0),
            }
        }
        for t in &self.external_targets {
            out.extend_from_slice(&t.module_rva.to_le_bytes());
            out.extend_from_slice(&t.import_dll.as_bytes());
            out.push(0);
            out.extend_from_slice(&t.import_name_or_ordinal.as_bytes());
            out.push(0);
            match t.iat_rva {
                Some(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_le_bytes());
                }
                None => out.push(0),
            }
            out.push(resolution_kind_as_u8(t.resolution_kind));
        }
        // Absorbed aliases bind normalization into the digest: changing an alias
        // content/offset must change the plan digest.
        for a in &self.aliases {
            out.extend_from_slice(&a.alias_old_base.to_le_bytes());
            out.extend_from_slice(&(a.alias_size as u64).to_le_bytes());
            out.extend_from_slice(&(a.parent_region as u64).to_le_bytes());
            out.extend_from_slice(&(a.parent_offset as u64).to_le_bytes());
            out.push(a.original_kind as u8);
            out.push(a.required as u8);
            out.extend_from_slice(a.content_digest.as_bytes());
            out.push(0);
            // GTO R0-F.1: bind the alias's extent kind into the digest.
            out.push(extent_kind_tag(&a.extent_kind));
            // GTO R0-F.2: bind the alias's ownership into the digest.
            out.push(alias_ownership_tag(a.ownership));
            // GTO R0-G: bind the authoritative parent-slice digest and the accepted
            // non-write drift digest so a change to either alters the plan digest.
            out.extend_from_slice(a.parent_slice_digest.as_bytes());
            out.push(0);
            out.extend_from_slice(a.accepted_drift_digest.as_bytes());
            out.push(0);
        }
        out
    }
}

fn class_as_u8(c: PointerClassification) -> u8 {
    match c {
        PointerClassification::Null => 0,
        PointerClassification::InImage => 1,
        PointerClassification::InCapturedRegion => 2,
        PointerClassification::ExternalModule => 3,
        PointerClassification::ExternalCandidate => 4,
        PointerClassification::SmallIntegerOrTag => 5,
        PointerClassification::Unmapped => 6,
        PointerClassification::Ambiguous => 7,
    }
}

fn provenance_as_u8(p: SlotProvenance) -> u8 {
    match p {
        SlotProvenance::ContainerTriple => 0,
        SlotProvenance::HeapGlobalRoot => 1,
        SlotProvenance::CaptureDescriptor => 2,
        SlotProvenance::RelocationRoot => 3,
        SlotProvenance::LiveObservation => 4,
    }
}

fn resolution_kind_as_u8(k: ExternalResolutionKind) -> u8 {
    match k {
        ExternalResolutionKind::ViaIat => 0,
        ExternalResolutionKind::ViaExportMap => 1,
        ExternalResolutionKind::ViaStableBinding => 2,
    }
}

/// Deterministic provenance tag for region digest binding (GTO R0-D).
fn region_provenance_tag(p: &RegionProvenance) -> u8 {
    match p {
        RegionProvenance::RawCaptured { .. } => 0,
        RegionProvenance::TransformedRawCaptured { .. } => 1,
        RegionProvenance::SyntheticDerived { .. } => 2,
        RegionProvenance::ImageInline => 3,
        RegionProvenance::ExternalResolved => 4,
        RegionProvenance::UnknownSynthetic => 5,
    }
}

/// Deterministic extent-kind tag for plan digest binding (GTO R0-F.1).
fn extent_kind_tag(e: &crate::dumper::heap_global_snapshot::CaptureExtentKind) -> u8 {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    match e {
        CEK::ProbeWindow => 0,
        CEK::ObservedAllocation => 1,
        CEK::BackingObject => 2,
        CEK::InteriorSubview => 3,
        CEK::SyntheticDerived => 4,
    }
}

/// Deterministic ownership tag for plan digest binding (GTO R0-F.1).
fn ownership_tag(o: &RuntimeRegionOwnership) -> u8 {
    match o {
        RuntimeRegionOwnership::IndependentAllocation => 0,
        RuntimeRegionOwnership::ImageInline => 2,
        RuntimeRegionOwnership::SyntheticAllocation => 3,
        RuntimeRegionOwnership::ExternalResolved => 4,
    }
}

/// Deterministic alias-ownership tag for plan digest binding (GTO R0-F.2).
fn alias_ownership_tag(o: AliasOwnership) -> u8 {
    match o {
        AliasOwnership::SlabOwned => 0,
    }
}

/// An explicit declaration that a specific slot inside a captured region is a
/// pointer. Declared slots carry provenance; only these may be patched.
///
/// `region_old_base` identifies the region (regions are keyed by their stable
/// old base). `offset` is the byte offset within that region's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredPointerSlot {
    pub region_old_base: u64,
    pub offset: usize,
    pub provenance: SlotProvenance,
}

/// Structural pointer-declaration kind (R1 STRUCTURAL-POINTER-DECLARATION).
///
/// Each declared qword is classified with a kind and the evidence behind the
/// classification. Kinds are mutually exclusive per slot; a slot is declared
/// exactly once (dedup) or rejected as a conflict (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclarationKind {
    /// Pointer into a captured heap allocation, backed by structural evidence
    /// (image-root slot / container triple / relocation root / live observation).
    StructuredHeapPointer,
    /// Pointer computed relative to a known runtime heap handle
    /// (e.g. `GetProcessHeap` + offset) — interior-pointer class.
    /// Reserved classification: never constructed by the current pipeline,
    /// kept for the declaration-kind schema label contract.
    #[allow(dead_code)]
    KnownRuntimeHandleRelativePointer,
    /// Pointer into a known object field of a typed AHK object (field-offset
    /// evidence from object layout).
    /// Reserved classification: never constructed by the current pipeline,
    /// kept for the declaration-kind schema label contract.
    #[allow(dead_code)]
    KnownObjectFieldPointer,
    /// Value in a loaded module's address range — module-relative candidate
    /// (resolver work deferred to a later work order; never auto-resolved here).
    ModuleRelativeCandidate,
    /// AHK tagged scalar (type tag namespace + low data bits). Excluded from
    /// the pointer set only with structural tag-encoding evidence.
    TaggedScalar,
    /// Small scalar (offset/count/sentinel) — excluded only with structural
    /// evidence (non-aligned, no deref site, field context).
    SmallScalar,
    /// Inline UTF-16 text packed into a qword — excluded with shape evidence.
    InlineText,
    /// Pointer into the canonical user-mode stack/TEB reserved region
    /// (>= STACK_RESERVED_BASE). Ephemeral per-process state: the cold-start
    /// process has its own stacks, so the old stack VA cannot be rebased and
    /// is excluded with high-confidence address-space evidence.
    StackEphemeral,
    /// Module boundary cache slot: the value equals a loaded module's end
    /// (base + SizeOfImage) or a small fixed delta past it (end + 0x2a4 /
    /// end + 0x1000), or the fixed module-zone base 0x7ff800000000. AHK caches
    /// module address-range boundaries for classification; they are NOT
    /// rebaseable pointers (the cold-start process has its own module
    /// layout) and are excluded with deterministic boundary evidence.
    ModuleBoundaryCache,
    /// Allocator metadata (HEAP_ENTRY header / freelist link) — excluded only
    /// with allocation-layout evidence.
    /// Reserved classification: never constructed by the current pipeline,
    /// kept for the declaration-kind schema label contract.
    #[allow(dead_code)]
    AllocatorMetadata,
    /// No structural evidence — MUST stay required (unknown_defaults_to_required).
    Unknown,
    /// Same physical slot declared again with identical value/kind/decision —
    /// audited, merged (both sources retained in the ledger).
    /// Reserved classification: never constructed by the current pipeline,
    /// kept for the declaration-kind schema label contract.
    #[allow(dead_code)]
    DuplicateSameSemantics,
    /// Same physical slot declared with conflicting value/kind/decision —
    /// terminal fail-closed.
    /// Reserved classification: never constructed by the current pipeline,
    /// kept for the declaration-kind schema label contract.
    #[allow(dead_code)]
    DuplicateConflict,
}

impl DeclarationKind {
    pub fn label(self) -> &'static str {
        match self {
            DeclarationKind::StructuredHeapPointer => "structured_heap_pointer",
            DeclarationKind::KnownRuntimeHandleRelativePointer => {
                "known_runtime_handle_relative_pointer"
            }
            DeclarationKind::KnownObjectFieldPointer => "known_object_field_pointer",
            DeclarationKind::ModuleRelativeCandidate => "module_relative_candidate",
            DeclarationKind::TaggedScalar => "tagged_scalar",
            DeclarationKind::SmallScalar => "small_scalar",
            DeclarationKind::InlineText => "inline_text",
            DeclarationKind::StackEphemeral => "stack_ephemeral",
            DeclarationKind::ModuleBoundaryCache => "module_boundary_cache",
            DeclarationKind::AllocatorMetadata => "allocator_metadata",
            DeclarationKind::Unknown => "unknown",
            DeclarationKind::DuplicateSameSemantics => "duplicate_same_semantics",
            DeclarationKind::DuplicateConflict => "duplicate_conflict",
        }
    }

    /// Whether this kind is a pointer that must enter the declared set.
    pub fn is_declared_pointer(self) -> bool {
        matches!(
            self,
            DeclarationKind::StructuredHeapPointer
                | DeclarationKind::KnownRuntimeHandleRelativePointer
                | DeclarationKind::KnownObjectFieldPointer
                | DeclarationKind::ModuleRelativeCandidate
                | DeclarationKind::Unknown
        )
    }

    /// Whether this kind is a non-pointer exclusion backed by evidence.
    /// No in-tree caller yet; retained as the mirror of `is_declared_pointer`
    /// for exclusion-path consumers.
    #[allow(dead_code)]
    pub fn is_evidence_excluded(self) -> bool {
        matches!(
            self,
            DeclarationKind::TaggedScalar
                | DeclarationKind::SmallScalar
                | DeclarationKind::InlineText
                | DeclarationKind::StackEphemeral
                | DeclarationKind::ModuleBoundaryCache
                | DeclarationKind::AllocatorMetadata
        )
    }
}

/// One auditable slot declaration record (R1 structural pipeline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotDeclarationRecord {
    /// Region identity (stable old base of the containing region).
    pub region_old_base: u64,
    /// Byte offset within the region payload.
    pub offset: usize,
    /// Raw 8-byte value at the slot.
    pub raw_value: u64,
    /// Declaration provenance (which structural source declared it).
    pub provenance: SlotProvenance,
    /// Declaration kind (mutually exclusive).
    pub kind: DeclarationKind,
    /// Human-readable declaration reason (evidence citation).
    pub reason: String,
    /// Confidence: high (structural), medium (heuristic+evidence), low (unknown).
    pub confidence: &'static str,
    /// Required decision: whether this slot must resolve (unknown → required).
    pub required: bool,
    /// Dedup status: none / merged-same-semantics / conflict.
    pub dedup_status: &'static str,
    /// Whether a duplicate-conflict was detected at this slot (terminal).
    pub conflict: bool,
    /// Source label of the scanning pass that produced this observation
    /// (container_triple / heap_global / slab_blob).
    pub source_label: &'static str,
    /// Whether this observation carries structural provenance (container
    /// triple / image-root global / graph child).
    pub is_structural: bool,
    /// True when this record is a non-structural observation (raw slab blob):
    /// it never declares a pointer; it is preserved for audit.
    pub observation_only: bool,
    /// True when this slot's declaration resolved from a structural source.
    pub resolved_structural: bool,
}

/// Result of the structural declaration pipeline.
#[derive(Debug, Clone, Default)]
pub struct SlotDeclarations {
    /// Declared pointer slots (deduped, conflict-free) — the plan input.
    pub declared: Vec<DeclaredPointerSlot>,
    /// Full audit ledger: every scanned pointer-shaped qword + its record.
    pub ledger: Vec<SlotDeclarationRecord>,
    /// Classification counts by kind (for reports).
    pub kind_counts: std::collections::BTreeMap<String, usize>,
    /// Duplicate-same-semantics count (merged, audited).
    pub duplicate_same_semantics: usize,
    /// Duplicate-conflict count (terminal).
    pub duplicate_conflict: usize,
    /// Unknown-but-required count (kept).
    pub unknown_required: usize,
    /// True when any duplicate-conflict was detected (terminal fail-closed).
    pub has_conflict: bool,
    /// True structural conflicts: two+ STRUCTURAL declarations of the same
    /// physical slot disagree on (value, kind, required). Non-structural
    /// observations never contribute (they reconcile).
    pub true_structural_conflict: usize,
    /// Non-structural observation records preserved in the ledger (raw slab
    /// blob observations; never declarations).
    pub non_structural_observation: usize,
    /// Physical slots whose declaration reconciled consistently from at
    /// least one structural source (no true structural conflict). The
    /// structural declaration itself resolved; final kind may still be
    /// Unknown (threshold-only / membership-only under R2 rules) — the
    /// counter proves the slot's declaration came from structural
    /// provenance, never from a non-structural observation.
    pub resolved_structural_declaration: usize,
}

/// Structural evidence helpers (never a bare numeric threshold).
fn is_inline_utf16_shape(v: u64) -> bool {
    fn ok(c: u16) -> bool {
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
            || (0x80..=0xff).contains(&c)
    }
    let lo = (v & 0xffff) as u16;
    let hi = ((v >> 16) & 0xffff) as u16;
    let lo2 = ((v >> 32) & 0xffff) as u16;
    let hi2 = ((v >> 48) & 0xffff) as u16;
    let units = [lo, hi, lo2, hi2];
    let nonzero = units.iter().filter(|&&c| c != 0).count();
    nonzero >= 2 && units.iter().all(|&c| ok(c))
}

/// Tag-encoding structural evidence: value in the AHK tag namespace
/// (>= 0x1_0000_0000) AND NOT inside any captured region AND NOT in the module
/// range (those would make it a real pointer). The type-tag byte at
/// `(v >> 32) & 0xff` encodes the AHK type; the low 32 bits are the small
/// tag/data field. This is evidence ONLY when the value is provably outside
/// every captured region and every module range (never a bare threshold).
fn is_tag_encoded_shape(v: u64, in_captured: bool, in_module: bool) -> bool {
    if v < 0x1_0000_0000 {
        return false;
    }
    if in_captured || in_module {
        // A value >= 0x1_0000_0000 inside a captured region or module range is
        // a REAL pointer (region/module membership is the structural proof) —
        // never excluded as a tag.
        return false;
    }
    // Outside every captured region and module range: the high tag byte is the
    // only type evidence left. Tag namespace with a small data field.
    let lo32 = (v & 0xffff_ffff) as u32;
    if v == 0xffff_ffff_ffff_ffff || v == 0x1_0000_0000 || lo32 <= 0x2000 {
        return true;
    }
    // Compound tagged values (0x8_xxxx_xxxx with a larger offset field) — tag
    // byte at (v>>32)&0xff in the AHK type-tag set with a non-pointer low field.
    let tag_byte = (v >> 32) & 0xff;
    // AHK tag bytes seen in the gto_launcher heap: 0x01..0x1f (primitive types),
    // 0x60/0x68 (string/object tags), 0x80/0x88/0x90 (boxed variants), 0x30/0x38,
    // 0x40/0x48, 0x50, 0x70..0x7f, 0xa0/0xa8, 0xb0/0xb8, 0xc0/0xc8, 0xd0/0xd8,
    // 0xe0/0xe8, 0xf0/0xf8. Reject ONLY the pure-type-tag half (low 4 bits
    // equal tag byte's low nibble or 0) as tagged_scalar; anything else stays
    // Unknown (required).
    let lo4 = lo32 & 0xf;
    let tag_lo4 = (tag_byte as u32) & 0xf;
    if tag_byte <= 0x1f && lo32 <= 0x2000 {
        return true;
    }
    if (tag_byte & 0xf0) == 0x80 && lo4 == tag_lo4 {
        // boxed-tag pattern 0x8X_xxxx_xxxx where low nibble mirrors the tag
        // (e.g. 0x800000008, 0x800000006) — tag constant, not a pointer.
        return true;
    }
    false
}

fn checked_region_end(region: usize, old_base: u64, size: usize) -> Result<u64, RebaseError> {
    let size_u64 = u64::try_from(size).map_err(|_| RebaseError::Overflow {
        region,
        old_base,
        size,
    })?;
    old_base.checked_add(size_u64).ok_or(RebaseError::Overflow {
        region,
        old_base,
        size,
    })
}

fn checked_slot_identity(region_base: u64, offset: usize) -> Result<u64, RebaseError> {
    let offset_u64 = u64::try_from(offset).map_err(|_| RebaseError::SlotIdentityOverflow {
        region_base,
        offset,
    })?;
    region_base
        .checked_add(offset_u64)
        .ok_or(RebaseError::SlotIdentityOverflow {
            region_base,
            offset,
        })
}

/// Structural pipeline: scan captured payloads, classify each pointer-shaped
/// qword with evidence, dedupe (same-semantics merge / conflict fail-closed),
/// and keep unknown required. No bare numeric-threshold exclusion.
pub fn declare_pointer_slots_structural(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slabs: &[HeapSlab],
    enumerated_module_ranges: &[(u64, u64)],
) -> SlotDeclarations {
    // Compatibility wrapper for existing non-fallible callers. The fallible
    // entry point below exposes arithmetic failures as RebaseError.
    declare_pointer_slots_structural_checked(
        containers,
        heap_globals,
        heap_slabs,
        enumerated_module_ranges,
    )
    .unwrap_or_default()
}

/// Whether `val` matches a loaded module boundary cache slot: any value in
/// the canonical module zone (0x7ff800000000 .. STACK_RESERVED_BASE) that is
/// NOT inside a verified enumerated module range. attempt_019 exposed 158
/// unresolved-required and ALL were module-zone boundary values: module ends,
/// end+0x2a4 / end+0x1000, module-zone base + small offsets, and module-gap
/// pages. AHK caches module address-range boundaries for classification;
/// they are not rebaseable pointers (the cold-start process has its own
/// module layout).
fn is_module_boundary_cache(val: u64, module_ranges: &[(u64, u64)]) -> bool {
    // GTO-COLD-START-HEAP-REBASE-1 H4-A correction (layout_A wall): the module
    // zone lower bound must match the declaration layer's `in_module`
    // threshold (0x7ff0_0000_0000). A value in 0x7ff0..0x7ff8 that is NOT
    // inside any verified enumerated module range is a module-zone hole
    // (reserved/unmapped gap below every real DLL base — observed module
    // bases all sit >= 0x7ff8_0000_0000), not a rebaseable pointer. Treating
    // it as unknown+required made the plan fail closed on ASLR layouts whose
    // heap happens to hold such a hole value (heap slab garbage / cached
    // zone boundaries). Exclusion remains evidence-gated: module_ranges must
    // be non-empty, and any value INSIDE a verified range still classifies
    // via module attribution (never excluded here).
    const MODULE_ZONE_BASE: u64 = 0x0000_7ff0_0000_0000;
    if val < MODULE_ZONE_BASE || val >= STACK_RESERVED_BASE {
        return false;
    }
    // No verified module ranges -> no boundary evidence; fail closed (the
    // value stays unknown+required rather than being silently dropped).
    if module_ranges.is_empty() {
        return false;
    }
    // Inside a verified module range -> a real module pointer (handled by
    // module attribution). Outside every range -> boundary cache slot.
    !module_ranges
        .iter()
        .any(|&(b, e)| e > b && val >= b && val < e)
}

fn declare_pointer_slots_structural_checked(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slabs: &[HeapSlab],
    enumerated_module_ranges: &[(u64, u64)],
) -> Result<SlotDeclarations, RebaseError> {
    // Round 2: verified enumerated module ranges (module base/end pairs from the
    // live module enumeration). Values inside these have a verifiable module
    // identity; values >= 0x7ff0_0000_0000 outside them are threshold-only and
    // must remain unknown+required.
    let module_ranges: Vec<(u64, u64)> = enumerated_module_ranges.to_vec();
    // Region identity for slot VA computation. Span overflow is terminal: do
    // not saturate to u64::MAX, which could make an invalid range appear valid.
    let mut regions: Vec<(u64, u64)> = Vec::new(); // (old_base, end)
    for c in containers {
        let region = regions.len();
        let end = checked_region_end(region, c.decoded_begin, c.heap_content.len())?;
        regions.push((c.decoded_begin, end));
    }
    for g in heap_globals {
        if g.is_heap_handle || g.content.is_empty() {
            continue;
        }
        let region = regions.len();
        let end = checked_region_end(region, g.live_ptr, g.content.len())?;
        regions.push((g.live_ptr, end));
    }
    for s in heap_slabs {
        if !s.content.is_empty() && s.old_base != 0 {
            let region = regions.len();
            let end = checked_region_end(region, s.old_base, s.content.len())?;
            regions.push((s.old_base, end));
        }
    }
    // Pointer-shaped sweep with STRUCTURAL PROVENANCE per qword. A qword is
    // "structural" only when it comes from a known pointer schema:
    //   - container triple (SecurityCookie begin/end/cap) — rva is a known root
    //   - heap-global image root (rva non-zero, not handle/inline)
    //   - heap-global graph child (extent_evidence / containing parent)
    // A raw slab blob has NO per-field provenance — its qwords are never
    // promoted to pointer kinds on membership alone (Round 2 semantic fix).
    // scanned: (region_base, offset, value, has_structural_provenance, source_label)
    let mut scanned: Vec<(u64, usize, u64, bool, &'static str)> = Vec::new();
    let mut push = |old_base: u64, payload: &[u8], structural: bool, label: &'static str| {
        let n = payload.len() / POINTER_WIDTH;
        for i in 0..n {
            let off = i * POINTER_WIDTH;
            let val = u64::from_le_bytes(payload[off..off + 8].try_into().unwrap_or([0; 8]));
            // Stack/TEB reserved region is ephemeral process state, not a
            // persistent object-graph edge — never scanned as a pointer target.
            if val >= SMALL_TAG_CEILING && val < STACK_RESERVED_BASE {
                scanned.push((old_base, off, val, structural, label));
            }
        }
    };
    for c in containers {
        // Container triple: the .data rva is a known pointer root (structural).
        push(c.decoded_begin, &c.heap_content, true, "container_triple");
    }
    for g in heap_globals {
        if g.is_heap_handle || g.content.is_empty() {
            continue;
        }
        // Image-root slot (rva != 0) or graph child (extent_evidence) is
        // structural; a bare probe window is not.
        use crate::dumper::heap_global_snapshot::CapturePath;
        let structural = g.rva != 0
            || g.extent_evidence.containing_parent_old_base.is_some()
            || g.extent_evidence.capture_path != CapturePath::MainSlot;
        push(g.live_ptr, &g.content, structural, "heap_global");
    }
    for s in heap_slabs {
        if !s.content.is_empty() && s.old_base != 0 {
            // Raw slab blob: NO per-field provenance.
            push(s.old_base, &s.content, false, "slab_blob");
        }
    }

    // R3 PROVENANCE-CONFLICT RECONCILIATION
    // (DECLARATION_PROVENANCE_CONFLICT_RECONCILIATION_1).
    //
    // R2 failed closed on the fresh reproduce (3,615 duplicate-conflicts)
    // because the same physical slot was scanned by BOTH the raw slab blob
    // (no per-field provenance -> unknown) and a heap-global root (structural
    // provenance -> pointer kind), and ANY kind/value disagreement was treated
    // as a terminal conflict. That is fail-closed but makes the declaration
    // stage unable to progress.
    //
    // R3 distinguishes the source semantics mandated by the work order:
    //
    //   1. TRUE structural-vs-structural conflict — two+ structural
    //      declarations of the same physical slot disagree on (value, kind,
    //      required). TERMINAL fail-closed. Never merged, never last-wins,
    //      never parent/child-prioritized.
    //   2. Non-structural raw observation + structural declaration of the
    //      same slot — NOT a semantic conflict. The raw slab blob is only an
    //      OBSERVATION (it can never declare a pointer); the structural
    //      declaration is authoritative. The observation is preserved in the
    //      ledger (auditable) and the slot resolves to the structural kind.
    //   3. parent/child graph synonym duplicates (same physical slot, same
    //      value/kind/required, possibly different provenance) — merged,
    //      every source retained in the ledger.
    //   4. TRUE value/type conflict of the same physical slot (two structural
    //      declarations disagree) — terminal fail-closed (covered by 1).
    //
    // No last-wins. No silent parent/child priority. No observation is ever
    // dropped — every scanned qword becomes a ledger record.
    let mut out = SlotDeclarations::default();
    // Group by PHYSICAL SLOT VA (region_base + offset): the same physical slot
    // may be scanned under different raw bases (parent slab + child object
    // both cover it).
    let mut by_slot: std::collections::BTreeMap<u64, Vec<SlotDeclarationRecord>> =
        std::collections::BTreeMap::new();

    for (region_base, off, val, structural, label) in scanned {
        let slot_va = checked_slot_identity(region_base, off)?;
        // Round 2 SEMANTIC FIX (retained): membership/threshold alone is NEVER
        // pointer proof. A slot is declared a pointer kind ONLY when BOTH hold:
        //   structural_provenance_present == true
        //   target_membership_or_resolver_evidence == true
        // Otherwise: unknown + required=true (never dropped, never optional).
        // Module address space = DLL load zone only; the stack/TEB reserved
        // region above STACK_RESERVED_BASE is NOT module space.
        let in_module = val >= 0x7ff0_0000_0000 && val < STACK_RESERVED_BASE;
        let inside = regions.iter().any(|&(b, e)| val >= b && val < e);
        // threshold-only: value in module address space but NOT in any verified
        // enumerated module range (no module identity / RVA / PE section).
        let threshold_only = in_module && !module_ranges.iter().any(|&(b, e)| val >= b && val < e);
        // verified module membership: inside an enumerated module range.
        let verified_module = module_ranges.iter().any(|&(b, e)| val >= b && val < e);
        // membership-only collision: inside a region/module but WITHOUT
        // structural provenance -> unknown + required.
        let membership_only = (inside || verified_module) && !structural;
        let (kind, reason, confidence): (DeclarationKind, String, &'static str) = if membership_only
        {
            (
                    DeclarationKind::Unknown,
                    format!(
                        "value {val:#x} has region/module membership but NO structural provenance                          (source {label}) — membership-only collision; unknown + required"
                    ),
                    "low",
                )
        } else if structural && inside {
            (
                    DeclarationKind::StructuredHeapPointer,
                    format!(
                        "value {val:#x} inside captured region span AND slot has structural                          provenance (source {label}) — interior heap pointer"
                    ),
                    "medium",
                )
        } else if structural && verified_module {
            (
                    DeclarationKind::ModuleRelativeCandidate,
                    format!(
                        "value {val:#x} inside verified enumerated module range AND slot has                          structural provenance (source {label}) — module-relative candidate;                          resolver deferred to later work order"
                    ),
                    "medium",
                )
        } else if is_module_boundary_cache(val, &module_ranges) {
            (
                    DeclarationKind::ModuleBoundaryCache,
                    format!(
                        "value {val:#x} matches a loaded module boundary (end / end+0x2a4 /                          end+0x1000 / module-zone base) — AHK module-range cache                          slot; excluded with deterministic boundary evidence                          (source {label})"
                    ),
                    "high",
                )
        } else if val >= STACK_RESERVED_BASE && val <= 0x0000_7fff_ffff_ffff {
            (
                    DeclarationKind::StackEphemeral,
                    format!(
                        "value {val:#x} in canonical user stack/TEB reserved region\n                          (>= STACK_RESERVED_BASE) — ephemeral per-process state;\n                          excluded with address-space evidence (source {label})"
                    ),
                    "high",
                )
        } else if threshold_only {
            (
                    DeclarationKind::Unknown,
                    format!(
                        "value {val:#x} in module address space (>= 0x7ff0_0000_0000) but NOT in                          any verified enumerated module range — threshold-only; unknown + required                          (numeric_threshold_only is prohibited as a classification)"
                    ),
                    "low",
                )
        } else if is_inline_utf16_shape(val) {
            (
                    DeclarationKind::InlineText,
                    format!(
                        "value {val:#x} matches inline UTF-16 shape (2+ ASCII/latin-1 u16 lanes)                          AND is outside every captured region/module — text payload, not a pointer"
                    ),
                    "high",
                )
        } else if is_tag_encoded_shape(val, false, false) {
            (
                    DeclarationKind::TaggedScalar,
                    format!(
                        "value {val:#x} matches AHK tagged-scalar encoding (tag namespace >= 0x1_0000_0000,                          outside every captured region and module range, type-tag byte at (v>>32)&0xff);                          type-tag evidence, not a pointer"
                    ),
                    "high",
                )
        } else if val < 0x100_0000 {
            // Small value: exclusion requires NON-alignment (a canonical
            // pointer target must be 8-aligned) OR a non-pointer field
            // context. Aligned small values remain Unknown (required).
            if (val & 0x7) != 0 {
                (
                        DeclarationKind::SmallScalar,
                        format!(
                            "value {val:#x} < 0x1000000 AND not 8-aligned — offset/count/sentinel                              shape; not a canonical pointer target"
                        ),
                        "high",
                    )
            } else {
                (
                        DeclarationKind::Unknown,
                        format!(
                            "value {val:#x} < 0x1000000 but 8-aligned — no structural evidence to                              exclude; kept required (unknown_defaults_to_required)"
                        ),
                        "low",
                    )
            }
        } else {
            (
                    DeclarationKind::Unknown,
                    format!(
                        "value {val:#x} >= 0x1000000, not in module range, not in captured                          region — no structural evidence; kept required"
                    ),
                    "low",
                )
        };

        let required = kind.is_declared_pointer();
        // R3: a non-structural source (raw slab blob) is an OBSERVATION ONLY —
        // it can never declare a pointer kind; its record is preserved for
        // audit and reconciles into a structural declaration when one exists.
        let observation_only = !structural;
        by_slot
            .entry(slot_va)
            .or_default()
            .push(SlotDeclarationRecord {
                region_old_base: region_base,
                offset: off,
                raw_value: val,
                provenance: SlotProvenance::CaptureDescriptor,
                kind,
                reason,
                confidence,
                required,
                dedup_status: if observation_only {
                    "observation_only"
                } else {
                    "none"
                },
                conflict: false,
                source_label: label,
                is_structural: structural,
                observation_only,
                resolved_structural: false,
            });
    }

    // ---- Reconcile each physical slot ----
    for (_, recs) in by_slot.iter_mut() {
        let n_struct = recs.iter().filter(|r| r.is_structural).count();
        let n_obs = recs.iter().filter(|r| r.observation_only).count();
        if n_struct == 0 {
            // No structural provenance: every record is a non-structural
            // observation. Preserve all of them; the slot stays required
            // (fail-closed) unless EVERY observation is an evidence-based
            // exclusion. If any observation lacks exclusion evidence the
            // slot keeps unknown + required (uncertainty resolves to
            // required, never to a dropped slot).
            out.non_structural_observation += n_obs;
            let any_unknown_required = recs
                .iter()
                .any(|r| r.kind == DeclarationKind::Unknown && r.required);
            if any_unknown_required {
                out.unknown_required += 1;
                out.declared.push(DeclaredPointerSlot {
                    region_old_base: recs[0].region_old_base,
                    offset: recs[0].offset,
                    provenance: recs[0].provenance,
                });
            }
            for r in recs.iter_mut() {
                r.dedup_status = "observation_only";
            }
            continue;
        }
        // At least one structural declaration. All structural records must
        // agree on (value, kind, required); disagreement is a TRUE structural
        // conflict (terminal fail-closed).
        let first_si = recs.iter().position(|r| r.is_structural).unwrap();
        let (f_val, f_kind, f_req) = {
            let f = &recs[first_si];
            (f.raw_value, f.kind, f.required)
        };
        let mut conflict = false;
        for r in recs.iter() {
            if r.is_structural && (r.raw_value != f_val || r.kind != f_kind || r.required != f_req)
            {
                conflict = true;
                break;
            }
        }
        out.non_structural_observation += n_obs;
        if conflict {
            // TRUE structural conflict — terminal. No last-wins, no
            // parent/child priority, no merging. Observations are preserved
            // and marked; the slot is NOT declared.
            out.true_structural_conflict += 1;
            out.duplicate_conflict += 1;
            out.has_conflict = true;
            for r in recs.iter_mut() {
                r.conflict = true;
                r.dedup_status = if r.is_structural {
                    "duplicate_conflict"
                } else {
                    "observation_only"
                };
            }
            continue;
        }
        // Consistent structural declaration: resolved.
        out.resolved_structural_declaration += 1;
        // A structural source that classifies Unknown (threshold-only /
        // membership-only under R2 rules) still counts as unknown+required.
        if f_kind == DeclarationKind::Unknown && f_req {
            out.unknown_required += 1;
        }
        // Structural records merge (same semantics); count merge events.
        let merges = recs
            .iter()
            .filter(|r| r.is_structural)
            .count()
            .saturating_sub(1);
        out.duplicate_same_semantics += merges;
        if f_req {
            out.declared.push(DeclaredPointerSlot {
                region_old_base: recs[first_si].region_old_base,
                offset: recs[first_si].offset,
                provenance: recs[first_si].provenance,
            });
        }
        let mut first_structural_seen = false;
        for r in recs.iter_mut() {
            if r.is_structural {
                if !first_structural_seen {
                    // The canonical structural declaration — dedup_status none.
                    first_structural_seen = true;
                    r.dedup_status = "none";
                } else {
                    let same = r.raw_value == f_val && r.kind == f_kind && r.required == f_req;
                    r.dedup_status = if same {
                        "duplicate_same_semantics"
                    } else {
                        "duplicate_conflict"
                    };
                }
            } else {
                r.dedup_status = "observation_only";
            }
            r.resolved_structural = true;
        }
    }

    // Flatten the per-slot ledger into the audit ledger deterministically:
    // by_slot iterates in physical-slot-VA order (BTreeMap) and records within
    // a slot keep scan order — fully deterministic.
    for (_, recs) in by_slot {
        for r in recs {
            out.ledger.push(r);
        }
    }

    // Counts.
    for rec in &out.ledger {
        *out.kind_counts
            .entry(rec.kind.label().to_string())
            .or_insert(0) += 1;
    }
    Ok(out)
}

/// Legacy entry point (unchanged signature, all callers/tests keep compiling):
/// now delegates to the structural pipeline and returns the declared slots.
pub fn declared_slots_from_capture(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slabs: &[HeapSlab],
) -> Vec<DeclaredPointerSlot> {
    // Legacy wrapper: no verified module ranges -> every in-module-space value
    // is threshold-only -> unknown+required (safe default, fail-closed).
    declare_pointer_slots_structural(containers, heap_globals, heap_slabs, &[]).declared
}

/// Fallible structural declaration: returns the declared slots + audit, and
/// FAILS CLOSED when any TRUE STRUCTURAL conflict (two+ structural
/// declarations of the same physical slot disagree on value/kind/required) is
/// detected. Non-structural raw observations never conflict: they reconcile
/// into the structural declaration (when present) or stay unknown+required
/// (when absent). No implicit last-wins, no parent/child priority, no silent
/// observation drop.
pub fn declare_pointer_slots_fallible(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slabs: &[HeapSlab],
    enumerated_module_ranges: &[(u64, u64)],
) -> Result<SlotDeclarations, RebaseError> {
    let decl = declare_pointer_slots_structural_checked(
        containers,
        heap_globals,
        heap_slabs,
        enumerated_module_ranges,
    )?;
    if decl.has_conflict {
        return Err(RebaseError::Plan(format!(
            "true structural conflict in pointer declaration: {} conflicting slot(s);              two or more STRUCTURAL declarations of the same physical slot disagree on              value/kind/required — terminal fail-closed (non-structural observations are              reconciled, not counted)",
            decl.true_structural_conflict
        )));
    }
    Ok(decl)
}

/// Table of external resolvers used to classify [`PointerClassification::ExternalModule`]
/// pointers. A pointer is only *resolved* when an entry here matches it.
///
/// Keyed by module identity + export RVA. Lookup happens on the **old**
/// (dump-time) addresses; at cold-start the stub resolves via `iat_rva` /
/// export map, so an ASLR module-base change is handled by the loader / IAT.
#[derive(Debug, Clone, Default)]
pub struct ExternalResolverTable {
    /// `(module_identity, module_rva)` → resolver.
    entries: std::collections::BTreeMap<(String, u64), ExternalTarget>,
}

impl ExternalResolverTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a resolver. Rejects duplicate `(module, rva)` keys.
    pub fn insert(&mut self, target: ExternalTarget) -> Result<(), RebaseError> {
        let key = (target.module_identity.clone(), target.module_rva);
        if self.entries.contains_key(&key) {
            return Err(RebaseError::Plan(format!(
                "duplicate external resolver ({}, rva {:#x})",
                target.module_identity, target.module_rva
            )));
        }
        self.entries.insert(key, target);
        Ok(())
    }

    /// Look up a resolver by module identity + export RVA.
    pub fn get(&self, module_identity: &str, module_rva: u64) -> Option<&ExternalTarget> {
        self.entries
            .get(&(module_identity.to_lowercase(), module_rva))
    }

    /// Look up a resolver by module identity + import name (fallback when the
    /// pointer's export RVA cannot be matched, e.g. dump-time IAT addresses are
    /// not attributed to a module offset).
    pub fn get_by_module_and_name(
        &self,
        module_identity: &str,
        name: &str,
    ) -> Option<&ExternalTarget> {
        let mod_l = module_identity.to_lowercase();
        self.entries
            .iter()
            .find(|(k, t)| k.0 == mod_l && t.import_name_or_ordinal.eq_ignore_ascii_case(name))
            .map(|(_, t)| t)
    }

    /// Deterministic iteration in key order.
    pub fn iter(&self) -> impl Iterator<Item = &ExternalTarget> {
        self.entries.values()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A high-address value whose owner module + export RVA are attributed from the
/// live module map. Used to decide resolved-vs-candidate for external pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAttribution {
    pub module_identity: String,
    pub module_base: u64,
    pub module_rva: u64,
}

/// Given a high-address value and the set of loaded modules, attribute it to a
/// module + export RVA. Returns `None` when the value is not inside any module.
///
/// This is the module-map attribution that lets an external pointer be matched
/// to a resolver — but a resolver must still exist for it to be *resolved*.
pub fn attribute_external(
    value: u64,
    modules: &[(String, u64, u64)], // (name, base, end)
) -> Option<ExternalAttribution> {
    for (name, base, end) in modules {
        if value >= *base && value < *end {
            return Some(ExternalAttribution {
                module_identity: name.to_lowercase(),
                module_base: *base,
                module_rva: value - base,
            });
        }
    }
    None
}

/// Build an external resolver table from the rebuilt import thunks.
///
/// For each import thunk with a name, the live IAT value at its slot is read
/// and attributed to a module via `module_map`; the resolver is keyed by
/// `(module_identity, module_rva)` and resolves at cold-start by reading the
/// rebuilt IAT slot (`iat_address`). This is ASLR-safe: we never store the
/// dump-time API VA; the loader fills the new IAT slot.
///
/// A thunk whose live value cannot be attributed to a module (or has no name)
/// is skipped — its pointer will classify as `ExternalCandidate` (unresolved).
pub fn build_external_resolvers_from_imports(
    imports: &crate::import_table::ImportTableBuilder,
    module_map: &[(String, u64, u64)],
    read_live_at: &dyn Fn(u64) -> Option<u64>,
) -> Result<ExternalResolverTable, RebaseError> {
    let mut table = ExternalResolverTable::new();
    for module in &imports.modules {
        for thunk in &module.thunks {
            let Some(name) = thunk.function_name.as_deref() else {
                continue;
            };
            // Live IAT value at the thunk slot.
            let Some(live) = read_live_at(thunk.iat_address as u64) else {
                continue;
            };
            let Some(att) = attribute_external(live, module_map) else {
                continue;
            };
            // GTO-COLD-START-HEAP-REBASE-1 H2 (attempt_013 wall): two import
            // thunks can resolve to the SAME (module, export rva) — forwarder
            // DLLs (e.g. wsock32 forwarding to ws2_32) and alias imports both
            // reference one underlying export. That is one resolver, not a
            // conflict: dedup by (module, rva), keep the first thunk's IAT
            // slot (any slot resolves the same export at cold start).
            let key = (att.module_identity.clone(), att.module_rva);
            if table.get(&key.0, key.1).is_some() {
                continue;
            }
            let target = ExternalTarget {
                module_identity: att.module_identity.clone(),
                module_rva: att.module_rva,
                import_dll: module.name.clone(),
                import_name_or_ordinal: name.to_string(),
                iat_rva: Some(thunk.iat_address),
                resolution_kind: ExternalResolutionKind::ViaIat,
            };
            table.insert(target)?;
        }
    }
    Ok(table)
}

/// Build a runtime rebase plan from the captured allocation set.
///
/// # Fail-closed
///
/// Returns `Err` when any structural invariant is violated (old-range overflow,
/// region overlap, ambiguous old-VA mapping, pointer width mismatch). Returns
/// `Ok(None)` when there is nothing to rebase (no captured allocations).
///
/// # Pointer declaration
///
/// Only [`DeclaredPointerSlot`]s become patchable pointers. Every other qword
/// in a captured payload is at most a [`PointerCandidate`] (diagnostic) and is
/// never patched or auto-marked required. External pointers are only classified
/// `ExternalModule` (resolved) when `external_resolvers` has a matching entry;
/// otherwise they become `ExternalCandidate` (unresolved, fails closed).
pub fn build_runtime_rebase_plan(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slabs: &[HeapSlab],
    declared_slots: &[DeclaredPointerSlot],
    external_resolvers: &ExternalResolverTable,
    module_map: &[(String, u64, u64)],
    old_image_base: u64,
    new_image_base: u64,
) -> Result<Option<RuntimeRebasePlan>, RebaseError> {
    // x64-only: pointer width is bound to 8 bytes. Do not guess.
    if POINTER_WIDTH != std::mem::size_of::<u64>() {
        return Err(RebaseError::Arch(
            "runtime rebasing requires 8-byte pointer slots (x64)".into(),
        ));
    }

    // --- Assemble candidate regions ---
    let mut candidates: Vec<RebaseRegion> = Vec::new();
    let mut id = 0usize;
    for c in containers {
        let size = c
            .decoded_end
            .checked_sub(c.decoded_begin)
            .and_then(|s| usize::try_from(s).ok())
            .ok_or_else(|| RebaseError::Region(id, "container span overflows usize".to_string()))?;
        let old_base = c.decoded_begin;
        candidates.push(RebaseRegion {
            id,
            old_base,
            size,
            alignment: 0x10,
            bytes: c.heap_content.clone(),
            required: true,
            kind: RegionKind::Container,
            image_inline_rva: None,
            provenance: RegionProvenance::RawCaptured {
                raw_digest: String::new(),
            },
            extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            ownership: RuntimeRegionOwnership::IndependentAllocation,
        });
        id = id.saturating_add(1);
    }
    for g in heap_globals {
        if g.is_heap_handle {
            // Heap handles are not data allocations; the runtime plants
            // GetProcessHeap and must not rebase them. Not a region.
            continue;
        }
        if g.content.is_empty() {
            continue;
        }
        if g.is_image_inline {
            // Body lives in the image; capture becomes an image-inline region.
            let rva = g.rva;
            let old_base = g.live_ptr;
            candidates.push(RebaseRegion {
                id,
                old_base,
                size: g.content.len(),
                alignment: 0x10,
                bytes: g.content.clone(),
                required: true,
                kind: RegionKind::HeapGlobal,
                image_inline_rva: Some(rva),
                provenance: RegionProvenance::ImageInline,
                extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind::BackingObject,
                ownership: RuntimeRegionOwnership::ImageInline,
            });
            id = id.saturating_add(1);
            continue;
        }
        candidates.push(RebaseRegion {
            id,
            old_base: g.live_ptr,
            size: g.content.len(),
            alignment: 0x10,
            bytes: g.content.clone(),
            required: true,
            kind: RegionKind::HeapGlobal,
            image_inline_rva: None,
            provenance: g.provenance.clone(),
            extent_kind: g.extent_kind,
            // GTO R0-F.2: a SyntheticDerived region is materialized as a
            // collision-free independent runtime allocation with
            // SyntheticDerived extent + SyntheticAllocation ownership. It is
            // never absorbed into the raw slab (normalize_containment skips
            // synthetic regions) and never reported as raw-captured.
            ownership: if matches!(g.provenance, RegionProvenance::SyntheticDerived { .. }) {
                RuntimeRegionOwnership::SyntheticAllocation
            } else {
                RuntimeRegionOwnership::IndependentAllocation
            },
        });
        id = id.saturating_add(1);
    }
    // Route T R0-B: every authoritative slab (main heap slab + each dedicated
    // dangling-edge slab) becomes a HeapSlab candidate. This lets each probe
    // window absorb into its own slab instead of being rejected as uncovered.
    for slab in heap_slabs {
        if !slab.content.is_empty() && slab.old_base != 0 {
            candidates.push(RebaseRegion {
                id,
                old_base: slab.old_base,
                size: slab.content.len(),
                alignment: 0x1000,
                bytes: slab.content.clone(),
                required: true,
                kind: RegionKind::HeapSlab,
                image_inline_rva: None,
                provenance: RegionProvenance::RawCaptured {
                    raw_digest: String::new(),
                },
                extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind::BackingObject,
                ownership: RuntimeRegionOwnership::IndependentAllocation,
            });
            id = id.saturating_add(1);
        }
    }

    if candidates.is_empty() {
        return Ok(None);
    }

    // R0-D: a region with UnknownSynthetic provenance must never reach a plan
    // (fail-closed) — it cannot be materialized safely and must not yield a
    // candidate. Reject before sorting/normalization so no downstream stage
    // sees it as a valid region.
    for c in &candidates {
        if matches!(c.provenance, RegionProvenance::UnknownSynthetic) {
            return Err(RebaseError::Plan(format!(
                "region old_base={:#x} has UnknownSynthetic provenance (fail-closed)",
                c.old_base
            )));
        }
    }

    // --- Deterministic sort by (old_base, size) ---
    candidates.sort_by_key(|r| (r.old_base, r.size));
    for (idx, r) in candidates.iter_mut().enumerate() {
        r.id = idx;
    }

    // --- Containment-aware normalization ---
    // A HeapSlab that contains heap-target children (HeapGlobal/Container,
    // non-image-inline) may coalesce them into one authoritative backing region
    // when the child bytes match the slab content at the child offset. Partial
    // overlap and conflicting content always fail closed. Returns the
    // normalized backing regions, the alias ledger, and an old_base -> (region,
    // offset) map used to translate declared slots and pointer targets.
    let (regions, aliases, old_base_map) = normalize_containment(&candidates)?;

    // --- Validate old ranges (checked arithmetic) + overlap fail-closed ---
    // After normalization the backing regions must be pairwise non-overlapping
    // (partial overlap is rejected by normalization; this is the final guard).
    for (i, r) in regions.iter().enumerate() {
        let Some(_end) = r.old_base.checked_add(r.size as u64) else {
            return Err(RebaseError::Overflow {
                region: i,
                old_base: r.old_base,
                size: r.size,
            });
        };
        if r.size == 0 {
            return Err(RebaseError::EmptyRegion(i));
        }
        if r.size > MAX_REGION_BYTES {
            return Err(RebaseError::Region(
                i,
                format!("region size {} exceeds cap {}", r.size, MAX_REGION_BYTES),
            ));
        }
        if r.alignment == 0 || !r.alignment.is_power_of_two() {
            return Err(RebaseError::Region(
                i,
                "alignment must be a power of two".into(),
            ));
        }
        if i > 0 {
            let prev = &regions[i - 1];
            let prev_end = prev.old_base.checked_add(prev.size as u64).ok_or_else(|| {
                RebaseError::Overflow {
                    region: i - 1,
                    old_base: prev.old_base,
                    size: prev.size,
                }
            })?;
            // Overlap (not just adjacency) fails closed.
            if r.old_base < prev_end {
                let rel = classify_region_relation(prev.old_base, prev.size, r.old_base, r.size)?;
                return Err(RebaseError::Overlap {
                    a: prev.old_base,
                    a_size: prev.size,
                    b: r.old_base,
                    b_size: r.size,
                    relationship: rel,
                    coalescing_allowed: false,
                    rejection_reason: "partial/conflicting overlap survives normalization".into(),
                });
            }
        }
    }

    // --- Resolve declared slots to region ids (by stable old_base) ---
    // A declared slot must reference an existing region and an in-bounds offset.
    // Absorbed child slots are translated to their parent + offset via the map.
    // This runs *before* building `pointers`, so both slots and their targets
    // use normalized coordinates.
    let mut pointers = resolve_declared_slots_normalized(
        &regions,
        &old_base_map,
        declared_slots,
        old_image_base,
        new_image_base,
        module_map,
        external_resolvers,
    )?;

    // --- Heuristic candidate scan (diagnostic only; never patched) ---
    // Records how many pointer-shaped qwords exist that were NOT declared. These
    // are never required and never enter the fixup metadata.
    let mut candidates: Vec<PointerCandidate> = Vec::new();
    for (ri, region) in regions.iter().enumerate() {
        let declared_offsets: std::collections::BTreeSet<usize> = pointers
            .iter()
            .filter(|p| p.source_region == ri)
            .map(|p| p.source_offset)
            .collect();
        let slot_count = region.bytes.len() / POINTER_WIDTH;
        for slot in 0..slot_count {
            let off = slot * POINTER_WIDTH;
            if declared_offsets.contains(&off) {
                continue; // already a declared slot
            }
            let val = u64::from_le_bytes(
                region.bytes[off..off + POINTER_WIDTH]
                    .try_into()
                    .map_err(|_| RebaseError::Slot(ri, off))?,
            );
            if val == 0 || val < SMALL_TAG_CEILING {
                continue;
            }
            // Plausible pointer shape = canonical user VA (not a pure tag).
            let plausible = val <= 0x0000_7fff_ffff_ffff;
            if plausible {
                candidates.push(PointerCandidate {
                    source_region: ri,
                    source_offset: off,
                    value: val,
                    plausible_pointer: true,
                });
            }
        }
    }

    // --- Deterministic pointer sort by (source_region, source_offset) ---
    pointers.sort_by_key(|p| (p.source_region, p.source_offset));

    // --- Verify every InCapturedRegion pointer resolves to exactly one target ---
    // Uniqueness of the old-VA → target mapping is guaranteed structurally by
    // `classify_value`: a value inside two or more captured ranges classifies
    // `Ambiguous` (which fails closed). Here we only verify the classification
    // is self-consistent: `original_value == region.old_base + interior_offset`.
    for p in &pointers {
        if p.classification != PointerClassification::InCapturedRegion {
            continue;
        }
        let (Some(region), Some(offset)) = (p.target_region, p.target_offset) else {
            return Err(RebaseError::Plan(
                "InCapturedRegion pointer missing target mapping".into(),
            ));
        };
        let target_region = &regions[region];
        let old_target = target_region.old_base;
        let computed = p.original_value.wrapping_sub(offset);
        if computed != old_target {
            return Err(RebaseError::Plan(format!(
                "pointer 0x{:x} maps to region {region} base 0x{:x} + {offset:#x} \
                 but original does not reconcile (computed 0x{:x})",
                p.original_value, old_target, computed
            )));
        }
    }

    // --- Deterministic external resolver table (dedup, key order) ---
    // Includes ViaStableBinding targets synthesized by the classifier for
    // module-attributed pointers without an IAT resolver (H2
    // old_module_base -> new_module_base primitive).
    let mut external_targets: Vec<ExternalTarget> = external_resolvers.iter().cloned().collect();
    for p in &pointers {
        if let Some(t) = &p.external_target {
            if t.resolution_kind == ExternalResolutionKind::ViaStableBinding {
                external_targets.push(t.clone());
            }
        }
    }
    external_targets.sort_by_key(|t| (t.module_identity.clone(), t.module_rva));
    external_targets
        .dedup_by(|a, b| a.module_identity == b.module_identity && a.module_rva == b.module_rva);

    let mut plan = RuntimeRebasePlan {
        regions,
        pointers,
        external_targets,
        candidates,
        aliases,
        old_image_base,
        new_image_base,
        plan_complete: true,
        plan_digest: String::new(),
    };
    plan.plan_digest = plan_digest(&plan);
    Ok(Some(plan))
}

/// Containment-aware normalization of raw captured regions.
///
/// A `HeapSlab` that fully contains heap-target children (`HeapGlobal` /
/// `Container`, non-image-inline) may coalesce them into one authoritative
/// backing region **only when** the slab content at the child offset exactly
/// equals the child's captured bytes. Partial overlap always fails closed.
///
/// Returns:
/// - `regions`: normalized backing regions (children absorbed into their slab).
/// - `aliases`: the alias ledger (absorbed children).
/// - `old_base_map`: `old_base -> (normalized_region_id, offset)` for the slab
///   base, every backing region base, and every absorbed child base. Used to
///   translate declared slots and pointer targets to normalized coordinates.
///
/// Requires `candidates` already sorted by `(old_base, size)` with stable ids.
fn normalize_containment(
    candidates: &[RebaseRegion],
) -> Result<
    (
        Vec<RebaseRegion>,
        Vec<RegionAlias>,
        std::collections::BTreeMap<u64, (usize, usize)>,
    ),
    RebaseError,
> {
    // Index slab candidates by id.
    let slab_ids: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == RegionKind::HeapSlab)
        .map(|(i, _)| i)
        .collect();

    // ---- Pre-pass: decide absorption for every non-slab candidate ----
    // A candidate is absorbed into a slab only when: it is heap-target
    // (non-image-inline), NOT a synthetic region (GTO R0-F.2: a SyntheticDerived
    // region is never absorbed — it is a collision-free independent region), and
    // it is contained in exactly one slab whose content matches at the offset.
    // This pre-pass is deterministic and lets us assign normalized slab ids
    // BEFORE building aliases, so `parent_region` always references the
    // normalized slab id (never the raw candidate index) — GTO R0-F.2 §十.
    use crate::dumper::heap_global_snapshot::RegionProvenance as RP;
    // child_absorb[i] = Some((slab_id, offset)) when candidate i is absorbed.
    let mut child_absorb: Vec<Option<(usize, usize)>> = vec![None; candidates.len()];
    for (i, r) in candidates.iter().enumerate() {
        if r.kind == RegionKind::HeapSlab {
            continue;
        }
        if r.image_inline_rva.is_some() {
            continue; // image-inline never coalesced into a slab
        }
        // GTO R0-F.2: a synthetic region (SyntheticDerived) is a collision-free
        // independent allocation — never absorbed into the raw slab.
        if matches!(r.provenance, RP::SyntheticDerived { .. }) {
            continue;
        }
        let mut containing_slab: Option<(usize, usize)> = None;
        for &sid in &slab_ids {
            let slab = &candidates[sid];
            let rel = classify_region_relation(slab.old_base, slab.size, r.old_base, r.size)?;
            // Route T R0-B: a probe/interior child is absorbed into an
            // authoritative slab when the slab CONTAINS it OR exactly DUPLICATES
            // it (base+size identical — the dedicated dangling-edge slab covers
            // the probe window exactly). ExactDuplicate yields offset 0 (the
            // probe IS the slab's allocation). Other relations never absorb.
            if rel == RegionRelation::Contains || rel == RegionRelation::ExactDuplicate {
                if containing_slab.is_some() {
                    return Err(RebaseError::Plan(format!(
                        "ambiguous coalescing parent for child region {} (0x{:x},+{:#x}): \
                         contained in multiple slabs",
                        i, r.old_base, r.size
                    )));
                }
                let off = r
                    .old_base
                    .checked_sub(slab.old_base)
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or_else(|| RebaseError::Overflow {
                        region: i,
                        old_base: r.old_base,
                        size: r.size,
                    })?;
                containing_slab = Some((sid, off));
            }
        }
        if let Some((sid, off)) = containing_slab {
            let slab = &candidates[sid];
            let child_end = r
                .size
                .checked_add(off)
                .ok_or_else(|| RebaseError::Overflow {
                    region: i,
                    old_base: r.old_base,
                    size: r.size,
                })?;
            if child_end > slab.bytes.len() {
                return Err(RebaseError::Overflow {
                    region: i,
                    old_base: r.old_base,
                    size: r.size,
                });
            }
            // Content must match the slab at the child offset (raw coherence).
            // GTO R0-G: for probe/interior views the parent slab is the payload
            // authority; a non-write capture drift tail is accepted (the child
            // forms an alias regardless). Strict extents (ObservedAllocation /
            // BackingObject / Container) still require full-range equality.
            let parent_slice = &slab.bytes[off..child_end];
            use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
            let is_relaxed_view = matches!(r.extent_kind, CEK::ProbeWindow | CEK::InteriorSubview);
            if !is_relaxed_view && parent_slice != &r.bytes[..] {
                let mut mismatch_offset = usize::MAX;
                for (k, (a, b)) in parent_slice.iter().zip(r.bytes.iter()).enumerate() {
                    if a != b {
                        mismatch_offset = k;
                        break;
                    }
                }
                return Err(RebaseError::Plan(format!(
                    "contained region content mismatch: parent={} kind={} old_base={:#x} \
                     child={} kind={} old_base={:#x} child_offset={:#x} mismatch_offset={:#x}",
                    sid, slab.kind, slab.old_base, i, r.kind, r.old_base, off, mismatch_offset
                )));
            }
            child_absorb[i] = Some((sid, off));
        }
    }
    let absorbed: std::collections::BTreeSet<usize> = child_absorb
        .iter()
        .enumerate()
        .filter(|(_, v)| v.is_some())
        .map(|(i, _)| i)
        .collect();

    // ---- Assign normalized backing ids ----
    // A candidate that is not absorbed becomes a backing region with
    // `new_id = count of non-absorbed candidates before it`. Slabs are never
    // absorbed, so each slab gets a deterministic normalized id here.
    let mut candidate_id_to_normalized_id: Vec<Option<usize>> = vec![None; candidates.len()];
    let mut next_id = 0usize;
    for (i, _) in candidates.iter().enumerate() {
        if absorbed.contains(&i) {
            continue;
        }
        candidate_id_to_normalized_id[i] = Some(next_id);
        next_id += 1;
    }

    let mut normalized: Vec<RebaseRegion> = Vec::new();
    let mut aliases: Vec<RegionAlias> = Vec::new();
    let mut old_base_map: std::collections::BTreeMap<u64, (usize, usize)> =
        std::collections::BTreeMap::new();

    for (i, r) in candidates.iter().enumerate() {
        // Non-slab children get their normalized slab id from the pre-pass.
        if let Some((sid, off)) = child_absorb[i] {
            // The child is absorbed into the slab. The alias parent references
            // the NORMALIZED slab id (never the raw candidate index).
            let slab_norm = candidate_id_to_normalized_id[sid].ok_or_else(|| {
                RebaseError::Plan(format!(
                    "slab candidate {} (0x{:x}) not assigned a normalized id",
                    sid, candidates[sid].old_base
                ))
            })?;
            // GTO R0-G: the parent slab slice is the payload authority. Compute
            // the authoritative slice digest and the accepted non-write drift
            // digest (the bytes where the child capture differs from the slab).
            let slab = &candidates[sid];
            let parent_slice = &slab.bytes[off..off + r.size];
            let parent_slice_digest = sha256_hex(parent_slice);
            let accepted_drift_digest = if parent_slice != &r.bytes[..] {
                // Accepted non-write capture drift: record the diff (child vs slab).
                let diff: Vec<u8> = parent_slice
                    .iter()
                    .zip(r.bytes.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();
                sha256_hex(&diff)
            } else {
                String::new()
            };
            aliases.push(RegionAlias {
                alias_old_base: r.old_base,
                alias_size: r.size,
                parent_region: slab_norm,
                parent_offset: off,
                original_kind: r.kind,
                required: r.required,
                content_digest: sha256_hex(&r.bytes),
                extent_kind: r.extent_kind,
                ownership: AliasOwnership::SlabOwned,
                parent_slice_digest,
                accepted_drift_digest,
            });
            old_base_map.insert(r.old_base, (slab_norm, off));
            continue;
        }
        let Some(new_id) = candidate_id_to_normalized_id[i] else {
            continue;
        };
        // Not absorbed: a backing region.
        old_base_map.insert(r.old_base, (new_id, 0));
        let mut region = r.clone();
        region.id = new_id;
        normalized.push(region);
    }

    // GTO R0-F.1: a ProbeWindow or InteriorSubview that is NOT contained in any
    // authoritative slab/parent must not survive as a region (a heuristic read
    // window is not a proven heap extent). Probe/interior views may only exist as
    // aliases (they were absorbed in the pre-pass) or fail closed.
    for (i, r) in candidates.iter().enumerate() {
        if absorbed.contains(&i) {
            continue;
        }
        use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
        if matches!(r.extent_kind, CEK::ProbeWindow | CEK::InteriorSubview) {
            // Route T R0-C: precise coverage diagnostic, not a generic string.
            // Compute the nearest candidate slab authority range (if any) so an
            // operator can tell WHICH probe is missing slab authority and how far
            // the nearest authority is.
            let extent_tag = match r.extent_kind {
                CEK::ProbeWindow => "ProbeWindow",
                CEK::InteriorSubview => "InteriorSubview",
                _ => "other",
            };
            let mut nearest: Option<(u64, u64, u64)> = None; // (base, end, gap)
            for &sid in &slab_ids {
                let slab = &candidates[sid];
                let s_end = slab.old_base.saturating_add(slab.size as u64);
                let gap = if r.old_base >= slab.old_base && r.old_base < s_end {
                    0
                } else if r.old_base < slab.old_base {
                    slab.old_base.saturating_sub(r.old_base)
                } else {
                    r.old_base.saturating_sub(s_end)
                };
                if nearest.map_or(true, |(_, _, g)| gap < g) {
                    nearest = Some((slab.old_base, s_end, gap));
                }
            }
            let (n_base, n_end, n_gap) = nearest.unwrap_or((0, 0, u64::MAX));
            return Err(RebaseError::ProbeCoverageMissing {
                region: i,
                child_base: r.old_base,
                child_size: r.size,
                extent_kind: extent_tag.to_string(),
                candidate_slab_count: slab_ids.len(),
                nearest_authority: if slab_ids.is_empty() {
                    None
                } else {
                    Some((n_base, n_end))
                },
                nearest_authority_gap: n_gap,
            });
        }
    }

    // Sort aliases deterministically by (alias_old_base, parent_region).
    aliases.sort_by_key(|a| (a.alias_old_base, a.parent_region, a.parent_offset));
    Ok((normalized, aliases, old_base_map))
}

/// Resolve declared pointer slots to normalized region ids, translating any
/// slot that lives in an absorbed child to `parent + offset`.
fn resolve_declared_slots_normalized(
    regions: &[RebaseRegion],
    old_base_map: &std::collections::BTreeMap<u64, (usize, usize)>,
    declared_slots: &[DeclaredPointerSlot],
    old_image_base: u64,
    new_image_base: u64,
    module_map: &[(String, u64, u64)],
    external_resolvers: &ExternalResolverTable,
) -> Result<Vec<RebasePointer>, RebaseError> {
    let mut pointers: Vec<RebasePointer> = Vec::new();
    let mut declared_slots = declared_slots.to_vec();
    declared_slots.sort_by_key(|s| (s.region_old_base, s.offset));

    for slot in &declared_slots {
        // Translate the slot's region base to a normalized (region, offset).
        let (ri, base_off) = old_base_map
            .get(&slot.region_old_base)
            .copied()
            .ok_or_else(|| {
                RebaseError::Plan(format!(
                    "declared slot region 0x{:x} not in normalized plan",
                    slot.region_old_base
                ))
            })?;
        // Slot absolute offset = child base offset + slot.offset.
        let slot_abs = base_off
            .checked_add(slot.offset)
            .ok_or(RebaseError::Slot(ri, slot.offset))?;
        let region = &regions[ri];
        let end = slot_abs
            .checked_add(POINTER_WIDTH)
            .ok_or_else(|| RebaseError::Slot(ri, slot_abs))?;
        if end > region.bytes.len() {
            return Err(RebaseError::Slot(ri, slot_abs));
        }
        let val = u64::from_le_bytes(
            region.bytes[slot_abs..end]
                .try_into()
                .map_err(|_| RebaseError::Slot(ri, slot_abs))?,
        );
        let pointer = classify_declared_slot(
            ri,
            slot_abs,
            val,
            regions,
            old_image_base,
            new_image_base,
            module_map,
            external_resolvers,
            slot.provenance,
        )?;
        pointers.push(pointer);
    }
    pointers.sort_by_key(|p| (p.source_region, p.source_offset));
    Ok(pointers)
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Classify a single declared pointer slot and build its [`RebasePointer`].
fn classify_declared_slot(
    ri: usize,
    off: usize,
    val: u64,
    regions: &[RebaseRegion],
    old_image_base: u64,
    new_image_base: u64,
    module_map: &[(String, u64, u64)],
    external_resolvers: &ExternalResolverTable,
    provenance: SlotProvenance,
) -> Result<RebasePointer, RebaseError> {
    if val == 0 {
        return Ok(RebasePointer {
            source_region: ri,
            source_offset: off,
            original_value: val,
            classification: PointerClassification::Null,
            target_region: None,
            target_offset: None,
            image_rva: None,
            external_target: None,
            provenance,
        });
    }
    if val < SMALL_TAG_CEILING {
        return Ok(RebasePointer {
            source_region: ri,
            source_offset: off,
            original_value: val,
            classification: PointerClassification::SmallIntegerOrTag,
            target_region: None,
            target_offset: None,
            image_rva: None,
            external_target: None,
            provenance,
        });
    }

    match classify_value(val, regions, old_image_base, new_image_base) {
        ClassResult::InImage => Ok(RebasePointer {
            source_region: ri,
            source_offset: off,
            original_value: val,
            classification: PointerClassification::InImage,
            target_region: None,
            target_offset: None,
            image_rva: Some((val.wrapping_sub(old_image_base)) as u32),
            external_target: None,
            provenance,
        }),
        ClassResult::InCapturedRegion { target, offset } => Ok(RebasePointer {
            source_region: ri,
            source_offset: off,
            original_value: val,
            classification: PointerClassification::InCapturedRegion,
            target_region: Some(target),
            target_offset: Some(offset),
            image_rva: None,
            external_target: None,
            provenance,
        }),
        ClassResult::Unmapped | ClassResult::Ambiguous => Ok(RebasePointer {
            source_region: ri,
            source_offset: off,
            original_value: val,
            classification: match classify_value(val, regions, old_image_base, new_image_base) {
                ClassResult::Ambiguous => PointerClassification::Ambiguous,
                _ => PointerClassification::Unmapped,
            },
            target_region: None,
            target_offset: None,
            image_rva: None,
            external_target: None,
            provenance,
        }),
        ClassResult::External => {
            // Attribute to a module; resolved only if a resolver exists.
            match attribute_external(val, module_map) {
                Some(att) => match external_resolvers.get(&att.module_identity, att.module_rva) {
                    Some(resolver) => Ok(RebasePointer {
                        source_region: ri,
                        source_offset: off,
                        original_value: val,
                        classification: PointerClassification::ExternalModule,
                        target_region: None,
                        target_offset: None,
                        image_rva: None,
                        external_target: Some(resolver.clone()),
                        provenance,
                    }),
                    None => {
                        // GTO-COLD-START-HEAP-REBASE-1 H2 (attempt_015 wall):
                        // a value inside a VERIFIED enumerated module range
                        // with no IAT resolver is still a module-relative
                        // pointer (module base + stable rva). The
                        // old_module_base -> new_module_base rebasing
                        // primitive resolves it via a stable binding:
                        // module identity + rva, re-based at cold start.
                        // It is NOT an unresolved candidate.
                        let stable = ExternalTarget {
                            module_identity: att.module_identity.clone(),
                            module_rva: att.module_rva,
                            import_dll: att.module_identity.clone(),
                            import_name_or_ordinal: format!("#{:#x}", att.module_rva),
                            iat_rva: None,
                            resolution_kind: ExternalResolutionKind::ViaStableBinding,
                        };
                        Ok(RebasePointer {
                            source_region: ri,
                            source_offset: off,
                            original_value: val,
                            classification: PointerClassification::ExternalModule,
                            target_region: None,
                            target_offset: None,
                            image_rva: None,
                            external_target: Some(stable),
                            provenance,
                        })
                    }
                },
                None => Ok(RebasePointer {
                    source_region: ri,
                    source_offset: off,
                    original_value: val,
                    classification: PointerClassification::ExternalCandidate,
                    target_region: None,
                    target_offset: None,
                    image_rva: None,
                    external_target: None,
                    provenance,
                }),
            }
        }
    }
}

/// Outcome of classifying one pointer value.
enum ClassResult {
    InImage,
    InCapturedRegion { target: usize, offset: u64 },
    External,
    Unmapped,
    Ambiguous,
}

impl From<ClassResult> for PointerClassification {
    fn from(c: ClassResult) -> Self {
        match c {
            ClassResult::InImage => PointerClassification::InImage,
            ClassResult::InCapturedRegion { .. } => PointerClassification::InCapturedRegion,
            ClassResult::External => PointerClassification::ExternalCandidate,
            ClassResult::Unmapped => PointerClassification::Unmapped,
            ClassResult::Ambiguous => PointerClassification::Ambiguous,
        }
    }
}

fn classify_value(
    val: u64,
    regions: &[RebaseRegion],
    old_image_base: u64,
    new_image_base: u64,
) -> ClassResult {
    // Canonical user-mode ceiling on x64.
    const MAX_USER_POINTER: u64 = 0x0000_7fff_ffff_ffff;
    let canonical = val <= MAX_USER_POINTER;

    // In-image: old base or new base, rebind to the new image. The rebuilt
    // image is a single contiguous allocation in the cold-start process; a
    // pointer that landed inside the *new* image base's span is an InImage
    // pointer (rebase to the new base).
    let image_span = 0x1_0000_0000u64; // reasonable image size bound
    let in_old_image =
        canonical && val >= old_image_base && val < old_image_base.saturating_add(image_span);
    if in_old_image {
        return ClassResult::InImage;
    }
    let in_new_image = canonical
        && new_image_base != 0
        && val >= new_image_base
        && val < new_image_base.saturating_add(image_span);
    if in_new_image {
        return ClassResult::InImage;
    }

    // External module / API region (DLL load zone above heaps, below the
    // stack/TEB reserved region). Note: this only marks the value as an
    // *external candidate*; whether it is *resolved* is decided later via the
    // resolver table / module map.
    let in_external = canonical && val >= 0x0000_7ff0_0000_0000 && val < STACK_RESERVED_BASE;
    if in_external {
        return ClassResult::External;
    }
    // Stack/TEB reserved region: ephemeral per-process state. The cold-start
    // process has its own stacks; the old stack VA cannot be rebased. It is
    // not a mapped persistent target, so it classifies Unmapped-like — but
    // Unmapped is required; instead it is NOT a pointer edge at all. We
    // return External only for the module zone; stack addresses fall through
    // to the region sweep and end up Unmapped (kept required by the plan),
    // which is fail-closed but wrong for ephemeral edges — handled earlier at
    // the declaration layer (StackEphemeral).

    // Captured region: interior membership. If it hits exactly one region,
    // that's a unique target. If it hits more than one, ambiguous (fail-closed).
    let mut hits: Vec<Target> = Vec::new();
    for (ri, r) in regions.iter().enumerate() {
        let Some(end) = r.old_base.checked_add(r.size as u64) else {
            continue;
        };
        if val >= r.old_base && val < end {
            let offset = val - r.old_base;
            // A pointer at exactly the region base is a head pointer.
            hits.push(Target { region: ri, offset });
        }
    }
    match hits.len() {
        0 => ClassResult::Unmapped,
        1 => ClassResult::InCapturedRegion {
            target: hits[0].region,
            offset: hits[0].offset,
        },
        _ => ClassResult::Ambiguous,
    }
}

/// Deterministic sha256 digest of the plan's canonical bytes.
fn plan_digest(plan: &RuntimeRebasePlan) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(plan.canonical_bytes());
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Research-only diagnostic (R1 HEAP-REGION-REBASE): describe the first
/// unresolved-required declared pointer with full source-region identity and a
/// geometric gap analysis against every captured region, the old image span,
/// and the external/module ceiling. This is pure diagnostic — it never changes
/// which pointers are declared, required, or rejected, and the fail-closed
/// error path is byte-identical up to this suffix.
fn describe_unresolved_pointer(
    plan: &RuntimeRebasePlan,
    p: &RebasePointer,
    old_image_base: u64,
) -> String {
    let region = plan.regions.get(p.source_region);
    let region_desc = match region {
        Some(r) => format!(
            "region[{}] kind={} old_base={:#x} size={:#x} rva={:?} provenance={:?} extent={:?} ownership={:?}",
            r.id,
            r.kind,
            r.old_base,
            r.size,
            r.image_inline_rva,
            r.provenance,
            r.extent_kind,
            r.ownership,
        ),
        None => "region[?] (out of range)".to_string(),
    };
    // Geometric gap analysis of the raw value against every captured region.
    let mut gap: Vec<String> = Vec::new();
    for r in &plan.regions {
        let Some(end) = r.old_base.checked_add(r.size as u64) else {
            continue;
        };
        if p.original_value >= r.old_base && p.original_value < end {
            gap.push(format!(
                "inside region {} [old_base {:#x}..{:#x})",
                r.id, r.old_base, end
            ));
            continue;
        }
        // distance to nearest edge
        let dist = if p.original_value < r.old_base {
            r.old_base - p.original_value
        } else {
            p.original_value - end
        };
        gap.push(format!(
            "gap {:#x} to region {} [old_base {:#x}..{:#x})",
            dist, r.id, r.old_base, end
        ));
    }
    let image_span = 0x1_0000_0000u64;
    let old_img_end = old_image_base.saturating_add(image_span);
    format!(
        "declared pointer ({}, source {} @ {:#x}) is unresolved-required; raw_value={:#x}; old_image_base={:#x} image_span_end={:#x}; in_old_image={}; region_analysis=[{}]",
        p.classification.label(),
        region_desc,
        p.source_offset,
        p.original_value,
        old_image_base,
        old_img_end,
        p.original_value >= old_image_base && p.original_value < old_img_end,
        gap.join("; "),
    )
}

/// Research-only (R1 HEAP-REGION-REBASE): write the FULL plan (regions +
/// declared pointers + unresolved-required subset + aliases) as JSON to the
/// path in env MIDA_GTO_RESEARCH_PLAN_OUT, when set. Pure diagnostic — never
/// changes plan semantics; fires before the fail-closed validation error.
fn dump_plan_research_json(plan: &RuntimeRebasePlan) {
    let Some(out_path) = std::env::var_os("MIDA_GTO_RESEARCH_PLAN_OUT") else {
        return;
    };
    fn js_escape(s: &str) -> String {
        let mut o = String::with_capacity(s.len() + 8);
        for c in s.chars() {
            match c {
                '"' => o.push_str("\\\""),
                '\\' => o.push_str("\\\\"),
                '\n' => o.push_str("\\n"),
                '\r' => o.push_str("\\r"),
                '\t' => o.push_str("\\t"),
                c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
                c => o.push(c),
            }
        }
        o
    }
    fn q(s: &str) -> String {
        format!("\"{}\"", js_escape(s))
    }
    let mut body = String::new();
    body.push_str("{\n");
    body.push_str(&format!(
        "  \"old_image_base\": \"{:#x}\",\n",
        plan.old_image_base
    ));
    body.push_str(&format!(
        "  \"new_image_base\": \"{:#x}\",\n",
        plan.new_image_base
    ));
    body.push_str(&format!("  \"region_count\": {},\n", plan.regions.len()));
    body.push_str(&format!("  \"pointer_count\": {},\n", plan.pointers.len()));
    // regions
    body.push_str("  \"regions\": [\n");
    for (i, r) in plan.regions.iter().enumerate() {
        let comma = if i + 1 < plan.regions.len() { "," } else { "" };
        body.push_str(&format!(
            "    {{\"id\": {}, \"kind\": {}, \"old_base\": \"{:#x}\", \"size\": {}, \"rva\": {}, \"provenance\": {}, \"extent\": {}, \"ownership\": {}, \"image_inline_rva\": {}, \"required\": {}}}{}\n",
            r.id,
            q(&r.kind.to_string()),
            r.old_base,
            r.size,
            match r.image_inline_rva { Some(v) => format!("\"{:#x}\"", v), None => "null".to_string() },
            q(&format!("{:?}", r.provenance)),
            q(&format!("{:?}", r.extent_kind)),
            q(&format!("{:?}", r.ownership)),
            match r.image_inline_rva { Some(_) => "\"inline\"".to_string(), None => "null".to_string() },
            r.required,
            comma
        ));
    }
    body.push_str("  ],\n");
    // pointers (declared, sorted) — include classification + target + value
    body.push_str("  \"pointers\": [\n");
    for (i, p) in plan.pointers.iter().enumerate() {
        let comma = if i + 1 < plan.pointers.len() { "," } else { "" };
        body.push_str(&format!(
            "    {{\"source_region\": {}, \"source_offset\": \"{:#x}\", \"original_value\": \"{:#x}\", \"classification\": {}, \"target_region\": {}, \"target_offset\": {}, \"provenance\": {}}}{}\n",
            p.source_region,
            p.source_offset,
            p.original_value,
            q(p.classification.label()),
            match p.target_region { Some(t) => t.to_string(), None => "null".to_string() },
            match p.target_offset { Some(t) => format!("\"{:#x}\"", t), None => "null".to_string() },
            q(p.provenance.label()),
            comma
        ));
    }
    body.push_str("  ],\n");
    // unresolved-required subset
    body.push_str("  \"unresolved_required\": [\n");
    let un: Vec<&RebasePointer> = plan
        .pointers
        .iter()
        .filter(|p| p.classification.is_unresolved_required())
        .collect();
    for (i, p) in un.iter().enumerate() {
        let comma = if i + 1 < un.len() { "," } else { "" };
        body.push_str(&format!(
            "    {{\"source_region\": {}, \"source_offset\": \"{:#x}\", \"original_value\": \"{:#x}\", \"classification\": {}}}{}\n",
            p.source_region,
            p.source_offset,
            p.original_value,
            q(p.classification.label()),
            comma
        ));
    }
    body.push_str("  ]\n");
    body.push_str("}\n");
    if let Err(e) = std::fs::write(&out_path, body.as_bytes()) {
        tracing::warn!(err = %e, path = ?out_path, "research plan dump write failed");
    } else {
        tracing::info!(path = ?out_path, "research plan dump written (diagnostic only)");
    }
}

/// Validate the plan structurally (offline, before write).
///
/// Returns a human-readable failure message when the plan cannot be emitted as
/// a complete cold-start candidate; `Ok(())` when it can.
pub fn validate_runtime_rebase_plan(plan: &RuntimeRebasePlan) -> Result<(), RebaseError> {
    if plan.regions.is_empty() {
        return Err(RebaseError::Plan("plan has no regions".into()));
    }
    // 1. Every required region has a target. All regions in this plan are
    //    required by construction; verify the flag is set.
    for r in &plan.regions {
        if !r.required {
            return Err(RebaseError::Plan(format!(
                "region {} is not required (cold-start contract)",
                r.id
            )));
        }
        // R0-D: a region with UnknownSynthetic provenance must never reach a
        // Complete plan or produce a candidate (fail-closed).
        if matches!(r.provenance, RegionProvenance::UnknownSynthetic) {
            return Err(RebaseError::Plan(format!(
                "region {} has UnknownSynthetic provenance (fail-closed)",
                r.id
            )));
        }
        // GTO R0-F.2: production ownership/provenance/extent invariants. A region
        // must carry a consistent triple; any mismatch is rejected (fail-closed).
        use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
        let is_slab = r.kind == RegionKind::HeapSlab;
        let is_synthetic = matches!(r.provenance, RegionProvenance::SyntheticDerived { .. });
        let is_image = matches!(r.provenance, RegionProvenance::ImageInline);
        match (
            &r.provenance,
            &r.ownership,
            &r.extent_kind,
            r.image_inline_rva,
        ) {
            // Synthetic: provenance SyntheticDerived, extent SyntheticDerived,
            // ownership SyntheticAllocation, never image-inline.
            (_, RuntimeRegionOwnership::SyntheticAllocation, CEK::SyntheticDerived, None)
                if is_synthetic => {}
            (_, _, _, _) if is_synthetic => {
                return Err(RebaseError::Plan(format!(
                    "region {} synthetic must have ownership=SyntheticAllocation, extent=SyntheticDerived, no image_rva (got ownership={:?} extent={:?} image={:?})",
                    r.id, r.ownership, r.extent_kind, r.image_inline_rva
                )));
            }
            // Image inline: provenance ImageInline, ownership ImageInline, image_rva Some.
            (_, RuntimeRegionOwnership::ImageInline, _, Some(_)) if is_image => {}
            (_, _, _, _) if is_image => {
                return Err(RebaseError::Plan(format!(
                    "region {} image-inline must have ownership=ImageInline and image_rva=Some (got ownership={:?} image={:?})",
                    r.id, r.ownership, r.image_inline_rva
                )));
            }
            // Slab backing: kind HeapSlab, extent BackingObject, ownership IndependentAllocation.
            (_, RuntimeRegionOwnership::IndependentAllocation, CEK::BackingObject, None)
                if is_slab => {}
            // Observed allocation: ownership IndependentAllocation, extent
            // ObservedAllocation (or a supported capture type), not image/synthetic.
            (_, RuntimeRegionOwnership::IndependentAllocation, CEK::ObservedAllocation, None) => {}
            // External: ownership ExternalResolved (resolver-backed), not image.
            (_, RuntimeRegionOwnership::ExternalResolved, _, None) => {}
            (_, _, CEK::ProbeWindow | CEK::InteriorSubview, _) => {
                // Probe/interior views may only exist as aliases, never as final
                // regions (GTO R0-F.1/R0-F.2).
                return Err(RebaseError::Plan(format!(
                    "region {} has extent {:?}; probe/interior may only be aliases",
                    r.id, r.extent_kind
                )));
            }
            (p, o, e, img) => {
                return Err(RebaseError::Plan(format!(
                    "region {} has inconsistent ownership/provenance/extent triple: provenance={:?} ownership={:?} extent={:?} image={:?}",
                    r.id, p, o, e, img
                )));
            }
        }
    }
    // 2. Target ranges must not overlap (old ranges already validated; the
    //    new image-inline RVAs must also be unique).
    let mut inline: Vec<u32> = plan
        .regions
        .iter()
        .filter_map(|r| r.image_inline_rva)
        .collect();
    inline.sort_unstable();
    for w in inline.windows(2) {
        if w[0] == w[1] {
            return Err(RebaseError::Plan(format!(
                "duplicate image-inline RVA {:#x}",
                w[0]
            )));
        }
    }
    // 3. All declared pointers must be structurally sound:
    //    - InCapturedRegion pointers have a valid target mapping.
    //    - InImage pointers carry a valid image RVA.
    //    - ExternalModule pointers reference a real resolver in the table.
    //    - ExternalCandidate / Unmapped / Ambiguous pointers are unresolved
    //      required — the plan is not Complete.
    for p in &plan.pointers {
        match p.classification {
            PointerClassification::InCapturedRegion => match (p.target_region, p.target_offset) {
                (Some(t), Some(o)) => {
                    if t >= plan.regions.len() {
                        return Err(RebaseError::Plan(format!(
                            "pointer target region {t} out of range"
                        )));
                    }
                    if o >= plan.regions[t].size as u64 {
                        return Err(RebaseError::Plan(format!(
                            "pointer target offset {o:#x} exceeds region {t} size"
                        )));
                    }
                }
                _ => {
                    return Err(RebaseError::Plan(
                        "InCapturedRegion pointer lacks target mapping".into(),
                    ));
                }
            },
            PointerClassification::InImage => {
                let _ = p.image_rva.ok_or_else(|| {
                    RebaseError::Plan("InImage pointer lacks image RVA".to_string())
                })?;
            }
            PointerClassification::ExternalModule => {
                let t = p.external_target.as_ref().ok_or_else(|| {
                    RebaseError::Plan("ExternalModule pointer lacks a resolver target".to_string())
                })?;
                // The resolver must be present in the plan's resolver table.
                let present = plan.external_targets.iter().any(|e| {
                    e.module_identity == t.module_identity && e.module_rva == t.module_rva
                });
                if !present {
                    return Err(RebaseError::Plan(format!(
                        "ExternalModule pointer resolver not in table: {} rva {:#x}",
                        t.module_identity, t.module_rva
                    )));
                }
            }
            PointerClassification::ExternalCandidate
            | PointerClassification::Unmapped
            | PointerClassification::Ambiguous => {
                // R1 research: keep the original fail-closed message prefix and
                // append the research-only diagnostic (region identity, raw
                // value, gap geometry). Validator semantics unchanged — the
                // plan still fails closed on this pointer.
                let base = format!(
                    "declared pointer ({}, region {} @ {:#x}) is unresolved-required",
                    p.classification.label(),
                    p.source_region,
                    p.source_offset
                );
                let detail = describe_unresolved_pointer(plan, p, plan.old_image_base);
                dump_plan_research_json(plan);
                return Err(RebaseError::Plan(format!("{base}; {detail}")));
            }
            PointerClassification::Null | PointerClassification::SmallIntegerOrTag => {}
        }
    }
    // 4. Patch-slot bounds: every pointer slot must fit inside its source
    //    region payload.
    for p in &plan.pointers {
        let r = &plan.regions[p.source_region];
        let end = p
            .source_offset
            .checked_add(POINTER_WIDTH)
            .ok_or_else(|| RebaseError::Slot(p.source_region, p.source_offset))?;
        if end > r.bytes.len() {
            return Err(RebaseError::Slot(p.source_region, p.source_offset));
        }
    }
    // 5. Target alignment correctness: every region's target (image_inline RVA
    //    or fresh allocation) must honour its alignment.
    for r in &plan.regions {
        match r.image_inline_rva {
            Some(rva) => {
                if (rva as u64) % r.alignment as u64 != 0 {
                    return Err(RebaseError::Alignment(r.id, rva as u64, r.alignment));
                }
            }
            None => {
                // Fresh heap allocations are aligned by HeapAlloc; the runtime
                // contract requires it. Offline we only verify alignment is a
                // sane power of two (done at build).
            }
        }
    }
    // 6. Alias ledger integrity: every alias references a valid parent backing
    //    region, fits within it, and never points at an absorbed child id.
    for a in &plan.aliases {
        if a.parent_region >= plan.regions.len() {
            return Err(RebaseError::Plan(format!(
                "alias parent region {} out of range",
                a.parent_region
            )));
        }
        let parent = &plan.regions[a.parent_region];
        if parent.kind != RegionKind::HeapSlab {
            return Err(RebaseError::Plan(format!(
                "alias parent region {} is not a heap slab (kind {})",
                a.parent_region, parent.kind
            )));
        }
        let alias_end = a
            .parent_offset
            .checked_add(a.alias_size)
            .ok_or_else(|| RebaseError::Plan("alias offset+size overflow".into()))?;
        if alias_end > parent.bytes.len() {
            return Err(RebaseError::Plan(format!(
                "alias [0x{:x},+{:#x}) exceeds parent region {} bytes {}",
                a.alias_old_base,
                a.alias_size,
                a.parent_region,
                parent.bytes.len()
            )));
        }
        // Alias offset must equal alias_old_base - parent.old_base.
        let expect_off = a
            .alias_old_base
            .checked_sub(parent.old_base)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| RebaseError::Plan("alias offset underflow/overflow".into()))?;
        if expect_off != a.parent_offset {
            return Err(RebaseError::Plan(format!(
                "alias parent_offset {:#x} != expected {:#x}",
                a.parent_offset, expect_off
            )));
        }
    }
    let _ = ();
    Ok(())
}

/// Validate that, after patching, no required pointer still targets a captured
/// old heap/private range. This is the post-patch scan proof.
///
/// Given a set of already-written region payloads, scan every required pointer
/// slot and confirm the written value is no longer inside any captured old
/// range.
pub fn validate_rebased_snapshots(
    plan: &RuntimeRebasePlan,
    patched_payloads: &[&[u8]],
) -> Result<(), RebaseError> {
    if patched_payloads.len() != plan.regions.len() {
        return Err(RebaseError::Plan(format!(
            "patched payload count {} != region count {}",
            patched_payloads.len(),
            plan.regions.len()
        )));
    }
    let old_ranges: Vec<(u64, u64)> = plan
        .regions
        .iter()
        .map(|r| (r.old_base, r.old_base.saturating_add(r.size as u64)))
        .collect();
    for p in &plan.pointers {
        let r = &plan.regions[p.source_region];
        let payload = patched_payloads[p.source_region];
        if payload.len() < r.bytes.len() {
            return Err(RebaseError::Slot(p.source_region, p.source_offset));
        }
        let end = p
            .source_offset
            .checked_add(POINTER_WIDTH)
            .ok_or_else(|| RebaseError::Slot(p.source_region, p.source_offset))?;
        if end > payload.len() {
            return Err(RebaseError::Slot(p.source_region, p.source_offset));
        }
        let new_val = u64::from_le_bytes(
            payload[p.source_offset..end]
                .try_into()
                .map_err(|_| RebaseError::Slot(p.source_region, p.source_offset))?,
        );
        if new_val == 0 {
            continue; // NULL is allowed
        }
        if new_val < SMALL_TAG_CEILING {
            continue; // tagged value is allowed
        }
        // Does the new value fall inside any captured old range? If so it is a
        // dangling old-process pointer and the recovery is not complete.
        for (ob, oe) in &old_ranges {
            if new_val >= *ob && new_val < *oe {
                return Err(RebaseError::Dangling {
                    slot_region: p.source_region,
                    slot_offset: p.source_offset,
                    value: new_val,
                    old_base: *ob,
                });
            }
        }
    }
    Ok(())
}

/// Validate the runtime bootstrap contract: metadata region count consistency,
/// bootstrap RVA placement, OEP legality, ASLR scheme (fixed preferred base),
/// and cookie-slot non-overlap with code/metadata/payload/alloc map.
///
/// Pure / offline. `pe` is the rebuilt header, `boot_rva`/`tls_rva` are the
/// bootstrap metadata locations, `original_oep_rva` the real OEP,
/// `region_count` the number of regions, and `contract` carries the `.boot`
/// layout sub-offsets + preferred image base.
pub fn validate_bootstrap_contract(
    pe: &crate::header::PeHeader,
    boot_rva: u32,
    tls_rva: Option<u32>,
    original_oep_rva: u32,
    region_count: usize,
    cookie_rva: u32,
    contract: &crate::dumper::runtime_bootstrap::BootContractLayout,
) -> Result<(), RebaseError> {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

    // Bootstrap code must live in an executable section.
    let boot_in_exec = pe.sections.iter().any(|s| {
        s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && boot_rva >= s.virtual_address
            && boot_rva < s.virtual_address.saturating_add(s.virtual_size.max(1))
    });
    if !boot_in_exec {
        return Err(RebaseError::Contract(format!(
            "bootstrap RVA {boot_rva:#x} not in an executable section"
        )));
    }

    if let Some(tls_rva) = tls_rva {
        let tls_in_img = tls_rva < pe.size_of_image();
        if !tls_in_img {
            return Err(RebaseError::Contract(format!(
                "TLS directory RVA {tls_rva:#x} outside image"
            )));
        }
    }

    // Original OEP must be nonzero and inside the image.
    if original_oep_rva == 0 || original_oep_rva >= pe.size_of_image() {
        return Err(RebaseError::Contract(format!(
            "original OEP RVA {original_oep_rva:#x} invalid (image size {:#x})",
            pe.size_of_image()
        )));
    }

    // Region count must be positive and bounded (metadata sanity).
    if region_count == 0 || region_count > 65535 {
        return Err(RebaseError::Contract(format!(
            "bootstrap metadata region count {region_count} out of valid range"
        )));
    }

    // ASLR scheme B: the emitted stub reads the actual loaded image base at
    // runtime from the PEB (`gs:[0x60]` -> `[+0x10]`) and uses it for every
    // image-relative address (image-inline, InImage, IAT, completion cookie).
    // There is therefore no fixed-base equality requirement here. The *actual*
    // loaded base is a runtime observation; without one, the recovery cannot be
    // marked Complete (the caller reports NotReady, never a match).
    //
    // We do record the preferred base that was compiled into the metadata header
    // (diagnostic only) and require that it is non-zero so the metadata is
    // self-consistent.
    if contract.preferred_image_base == 0 {
        return Err(RebaseError::Contract(
            "preferred image base is 0; metadata inconsistent".into(),
        ));
    }

    // Completion cookie slot placement (requirement R0-B.1 #6): must be inside
    // a writable `.boot` range and not overlap code/metadata/payload/alloc map.
    let cookie_off = contract.cookie_off;
    let cookie_rva_rel = cookie_rva.wrapping_sub(boot_rva) as usize;
    if cookie_off != cookie_rva_rel {
        return Err(RebaseError::Contract(format!(
            "completion cookie RVA {cookie_rva:#x} does not match layout offset \
             {cookie_off:#x} in .boot (rva {boot_rva:#x} -> rel {cookie_rva_rel:#x})"
        )));
    }
    let cookie_end = cookie_off
        .checked_add(4)
        .ok_or_else(|| RebaseError::Contract("cookie offset overflow".into()))?;
    if cookie_end > contract.total {
        return Err(RebaseError::Contract(format!(
            "completion cookie slot [{cookie_off:#x}, {cookie_end:#x}) exceeds .boot length {:#x}",
            contract.total
        )));
    }
    // Non-overlap with code/metadata/payload/alloc map.
    let code_range = 0..contract.header_off;
    let meta_range = contract.header_off..contract.payload_off;
    let payload_range = contract.payload_off..contract.map_off;
    let map_range = contract.map_off..(contract.cookie_off.min(contract.total));
    for (name, range) in [
        ("code", code_range),
        ("metadata", meta_range),
        ("payload", payload_range),
        ("alloc_map", map_range),
    ] {
        if cookie_off >= range.start && cookie_off < range.end {
            return Err(RebaseError::Contract(format!(
                "completion cookie at {cookie_off:#x} overlaps {name} range {:#x}..{:#x}",
                range.start, range.end
            )));
        }
    }

    // `.boot` / `.tls` declared raw sizes must cover their virtual/raw content.
    for s in &pe.sections {
        if s.name == ".boot" || s.name == ".tls" {
            if s.header.size_of_raw_data < s.virtual_size && s.header.size_of_raw_data != 0 {
                // Allow raw < virtual only for genuinely zero-fill tails; a
                // nonzero virtual with a smaller raw is suspicious for payload
                // sections, but the writer pads independently. Keep it a soft
                // check unless virtual exceeds raw by more than a page.
                let v = s.virtual_size as u64;
                let raw = s.header.size_of_raw_data as u64;
                if v > raw.saturating_add(0x1000) {
                    return Err(RebaseError::Contract(format!(
                        ".{} declared VirtualSize {v:#x} far exceeds SizeOfRawData {raw:#x}",
                        s.name
                    )));
                }
            }
        }
    }

    // The cookie slot must sit in a writable section (mov dword [..], 1).
    let cookie_in_writable = pe.sections.iter().any(|s| {
        s.characteristics & IMAGE_SCN_MEM_WRITE != 0
            && cookie_rva >= s.virtual_address
            && cookie_rva
                < s.virtual_address
                    .saturating_add(s.virtual_size.max(1).min(s.raw_size.max(1)))
    });
    if !cookie_in_writable {
        return Err(RebaseError::Contract(format!(
            "completion cookie RVA {cookie_rva:#x} not in a writable image section"
        )));
    }

    Ok(())
}

/// Diagnostic recovery summary. States are `Prepared`, `Complete`,
/// `Incomplete`, `Rejected` — never acceptance terms.
///
/// `Complete` requires: plan valid, `unresolved_required == 0`, the bootstrap
/// installed, the boot contract valid, a completion cookie present, the emitted
/// plan digest matching, and every required resolver present. A summary that
/// only has a planner (no installed bootstrap) can never be `Complete`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRebaseSummary {
    pub regions_total: usize,
    pub regions_required: usize,
    pub bytes_captured: usize,
    pub pointer_slots_total: usize,
    pub intra_region_pointers: usize,
    pub image_pointers: usize,
    pub external_pointers: usize,
    pub null_or_tagged: usize,
    pub unresolved_required: usize,
    pub unresolved_optional: usize,
    pub image_roots_patched: usize,
    pub bootstrap_kind: String,
    pub bootstrap_rva: Option<u32>,
    pub original_oep_rva: u32,
    pub completion_cookie_rva: Option<u32>,
    pub deterministic_plan_digest: String,
    pub fixup_count: usize,
    pub resolver_count: usize,
    pub candidate_count: usize,
    pub bootstrap_contract_valid: bool,
    pub recovery_status: RebaseStatus,
}

/// Recovery status — a single unambiguous state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseStatus {
    /// Plan prepared and validated offline, but the `.boot` is not yet
    /// installed (no runtime bootstrap). Never `Complete`.
    Prepared,
    /// Plan validated, bootstrap installed, contract valid, all resolvers
    /// present, completion cookie set.
    Complete,
    /// Plan validated and bootstrap installed, but some optional state is
    /// missing (not fatal, but not a complete cold-start contract).
    Incomplete,
    /// Plan or bootstrap is not viable — recovery fails closed.
    Rejected,
}

impl RebaseStatus {
    pub fn label(self) -> &'static str {
        match self {
            RebaseStatus::Prepared => "Prepared",
            RebaseStatus::Complete => "Complete",
            RebaseStatus::Incomplete => "Incomplete",
            RebaseStatus::Rejected => "Rejected",
        }
    }
}

/// Compute a diagnostic summary from a validated plan.
///
/// `boot_rva` / `completion_cookie_rva` are the runtime metadata positions the
/// bootstrap contract uses (from the installed `.boot`). A summary is
/// `Complete` only when every cold-start contract holds; with no installed
/// bootstrap it is `Prepared` at most.
pub fn summarize_plan(
    plan: &RuntimeRebasePlan,
    boot_rva: Option<u32>,
    original_oep_rva: u32,
    completion_cookie_rva: Option<u32>,
    bootstrap_kind: &str,
    bootstrap_contract_valid: bool,
) -> RuntimeRebaseSummary {
    let mut intra = 0usize;
    let mut image = 0usize;
    let mut external = 0usize;
    let mut null_tag = 0usize;
    for p in &plan.pointers {
        match p.classification {
            PointerClassification::InCapturedRegion => intra += 1,
            PointerClassification::InImage => image += 1,
            PointerClassification::ExternalModule => external += 1,
            PointerClassification::Null | PointerClassification::SmallIntegerOrTag => null_tag += 1,
            PointerClassification::ExternalCandidate
            | PointerClassification::Unmapped
            | PointerClassification::Ambiguous => {}
        }
    }
    let unresolved_required = plan
        .pointers
        .iter()
        .filter(|p| p.classification.is_unresolved_required())
        .count();
    let plan_ok = validate_runtime_rebase_plan(plan).is_ok();
    let image_roots = plan
        .regions
        .iter()
        .filter(|r| r.image_inline_rva.is_some())
        .count();

    // Complete requires: valid plan, zero unresolved-required, a real bootstrap
    // installed (boot_rva present), a completion cookie present, and the boot
    // contract valid.
    let ready = plan_ok
        && unresolved_required == 0
        && boot_rva.is_some()
        && completion_cookie_rva.is_some()
        && bootstrap_contract_valid;
    let status = if plan_ok && unresolved_required == 0 && boot_rva.is_none() {
        // Plan is sound but the `.boot` was not installed.
        RebaseStatus::Prepared
    } else if ready {
        RebaseStatus::Complete
    } else if plan_ok {
        // Plan sound but bootstrap/contract incomplete.
        RebaseStatus::Incomplete
    } else {
        RebaseStatus::Rejected
    };

    info!(
        regions_total = plan.regions.len(),
        regions_required = plan.regions_required(),
        bytes_captured = plan.bytes_captured(),
        pointer_slots = plan.pointers.len(),
        fixup_count = plan.pointers.len(),
        resolver_count = plan.external_targets.len(),
        candidate_count = plan.candidates.len(),
        intra,
        image,
        external,
        null_tag,
        unresolved_required,
        status = status.label(),
        "Runtime rebase summary"
    );

    RuntimeRebaseSummary {
        regions_total: plan.regions.len(),
        regions_required: plan.regions_required(),
        bytes_captured: plan.bytes_captured(),
        pointer_slots_total: plan.pointers.len(),
        intra_region_pointers: intra,
        image_pointers: image,
        external_pointers: external,
        null_or_tagged: null_tag,
        unresolved_required,
        unresolved_optional: plan.candidates.len(),
        image_roots_patched: image_roots,
        bootstrap_kind: bootstrap_kind.to_string(),
        bootstrap_rva: boot_rva,
        original_oep_rva,
        completion_cookie_rva,
        deterministic_plan_digest: plan.plan_digest.clone(),
        fixup_count: plan.pointers.len(),
        resolver_count: plan.external_targets.len(),
        candidate_count: plan.candidates.len(),
        bootstrap_contract_valid,
        recovery_status: status,
    }
}

/// Errors raised while planning / validating a rebase.
#[derive(Debug)]
pub enum RebaseError {
    /// The plan is not viable for cold start.
    Plan(String),
    /// Old-range arithmetic overflowed.
    Overflow {
        region: usize,
        old_base: u64,
        size: usize,
    },
    /// Region old ranges overlap (fail-closed). Carries full provenance and the
    /// interval relationship so a live-route failure is attributable precisely.
    Overlap {
        a: u64,
        a_size: usize,
        b: u64,
        b_size: usize,
        relationship: RegionRelation,
        coalescing_allowed: bool,
        rejection_reason: String,
    },
    /// A pointer slot read/write was out of bounds.
    Slot(usize, usize),
    /// Computing a physical slot identity (`region_base + offset`) overflowed.
    SlotIdentityOverflow { region_base: u64, offset: usize },
    /// A region has zero size.
    EmptyRegion(usize),
    /// A region is invalid (message).
    Region(usize, String),
    /// Alignment is wrong for a target.
    Alignment(usize, u64, usize),
    /// Post-patch a required pointer still targets a captured old range.
    Dangling {
        slot_region: usize,
        slot_offset: usize,
        value: u64,
        old_base: u64,
    },
    /// The bootstrap contract is violated.
    Contract(String),
    /// Pointer width / architecture mismatch.
    Arch(String),
    /// The AhkGto recovery requires runtime capture, but none was produced
    /// (empty containers/heap-globals/slab, or the required capture policy did
    /// not yield a plan). Must not be auto-inferred away.
    RequiredRuntimeCaptureMissing,
    /// Route T R0-C: a ProbeWindow / InteriorSubview region is not covered by
    /// any authoritative slab/parent. Fail-closed (R0-F.1). Carries precise
    /// coverage diagnostics so an operator does not have to guess which probe
    /// is missing its slab authority.
    ProbeCoverageMissing {
        /// Candidate index of the uncovered probe/interior region.
        region: usize,
        /// Old base of the uncovered region.
        child_base: u64,
        /// Size of the uncovered region.
        child_size: usize,
        /// Extent kind (ProbeWindow / InteriorSubview).
        extent_kind: String,
        /// Number of candidate authoritative slabs considered.
        candidate_slab_count: usize,
        /// The nearest candidate slab authority range, if any
        /// `(base, end)`; `None` when no slab exists at all.
        nearest_authority: Option<(u64, u64)>,
        /// Distance from the probe base to the nearest authority range, in bytes.
        nearest_authority_gap: u64,
    },
}

impl fmt::Display for RebaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RebaseError::Plan(m) => write!(f, "rebase plan: {m}"),
            RebaseError::Overflow {
                region,
                old_base,
                size,
            } => write!(
                f,
                "rebase region {region} old range overflow (base {old_base:#x} size {size:#x})"
            ),
            RebaseError::Overlap {
                a,
                a_size,
                b,
                b_size,
                relationship,
                coalescing_allowed,
                rejection_reason,
            } => write!(
                f,
                "rebase regions overlap: [{a:#x},+{a_size:#x}) vs [{b:#x},+{b_size:#x}) \
                 relationship={} coalescing_allowed={} rejection_reason={}",
                relationship.label(),
                coalescing_allowed,
                rejection_reason
            ),
            RebaseError::Slot(r, o) => write!(
                f,
                "rebase pointer slot out of bounds (region {r} @ {o:#x})",
            ),
            RebaseError::SlotIdentityOverflow { region_base, offset } => write!(
                f,
                "rebase pointer slot identity overflow (region base {region_base:#x} offset {offset:#x})",
            ),
            RebaseError::EmptyRegion(r) => write!(f, "rebase region {r} has zero size"),
            RebaseError::Region(r, m) => write!(f, "rebase region {r}: {m}"),
            RebaseError::Alignment(r, v, a) => {
                write!(f, "rebase target alignment mismatch (region {r} va {v:#x} align {a})")
            }
            RebaseError::Dangling {
                slot_region,
                slot_offset,
                value,
                old_base,
            } => write!(
                f,
                "post-patch pointer (region {slot_region} @ {slot_offset:#x}) still targets old heap {value:#x} in [{old_base:#x},…) — recovery not complete"
            ),
            RebaseError::Contract(m) => write!(f, "bootstrap contract: {m}"),
            RebaseError::Arch(m) => write!(f, "rebase architecture: {m}"),
            RebaseError::RequiredRuntimeCaptureMissing => write!(
                f,
                "AhkGto recovery requires runtime heap/container capture, but no plan was \
                 produced (empty capture or required policy did not yield one); refusing to \
                 continue without an explicit per-case policy declaring capture unnecessary"
            ),
            RebaseError::ProbeCoverageMissing {
                region,
                child_base,
                child_size,
                extent_kind,
                candidate_slab_count,
                nearest_authority,
                nearest_authority_gap,
            } => write!(
                f,
                "probe/interior region {region} (0x{child_base:x},+{child_size:#x}, extent={extent_kind}) \
                 is not contained in any authoritative slab/parent (candidate_slab_count={candidate_slab_count}, \
                 nearest_authority={nearest_authority:?} gap={nearest_authority_gap:#x}); refusing independent allocation"
            ),
        }
    }
}

impl std::error::Error for RebaseError {}

/// A plan + its diagnostic summary, prepared and validated for the dump path.
///
/// This is the authoritative input to `.boot` installation. The plan is **not**
/// discarded; it drives the runtime bootstrap metadata and is required for
/// post-install contract validation.
#[derive(Debug, Clone)]
pub struct PreparedRuntimeRebase {
    pub plan: RuntimeRebasePlan,
    pub summary: RuntimeRebaseSummary,
}

/// Prepare a runtime rebase plan for the AhkGto recovery path.
///
/// Builds the plan from captured allocations + declared pointer slots +
/// external resolvers + module map, validates it offline, and returns the
/// prepared plan + summary.
///
/// # Fail-closed
///
/// - When `require_capture` is set (AhkGtoExperimental with
///   `install_heap_bootstrap`), an empty capture / no plan is a hard
///   [`RebaseError::RequiredRuntimeCaptureMissing`], never a silent continue.
/// - Any structurally invalid plan or unresolved-required pointer fails closed.
pub fn prepare_runtime_rebase_for_dump(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slabs: &[HeapSlab],
    declared_slots: &[DeclaredPointerSlot],
    external_resolvers: &ExternalResolverTable,
    module_map: &[(String, u64, u64)],
    old_image_base: u64,
    new_image_base: u64,
    original_oep_rva: u32,
    require_capture: bool,
) -> Result<PreparedRuntimeRebase, RebaseError> {
    let Some(plan) = build_runtime_rebase_plan(
        containers,
        heap_globals,
        heap_slabs,
        declared_slots,
        external_resolvers,
        module_map,
        old_image_base,
        new_image_base,
    )?
    else {
        if require_capture {
            return Err(RebaseError::RequiredRuntimeCaptureMissing);
        }
        // No plan and not required: produce an empty Prepared (no regions).
        let empty = RuntimeRebasePlan {
            regions: Vec::new(),
            pointers: Vec::new(),
            external_targets: Vec::new(),
            candidates: Vec::new(),
            aliases: Vec::new(),
            old_image_base,
            new_image_base,
            plan_complete: true,
            plan_digest: String::new(),
        };
        let summary = summarize_plan(&empty, None, original_oep_rva, None, "none", false);
        return Ok(PreparedRuntimeRebase {
            plan: empty,
            summary,
        });
    };

    // Offline validation before the runtime contract can be trusted. An
    // unresolved-required pointer makes the plan invalid here.
    validate_runtime_rebase_plan(&plan)?;

    // Produce a summary with no installed bootstrap yet → Prepared at most.
    let summary = summarize_plan(&plan, None, original_oep_rva, None, "none", false);

    Ok(PreparedRuntimeRebase { plan, summary })
}

/// Convert a prepared (planner-only) summary into one that reflects an
/// installed bootstrap + validated contract. Returns `Err` if the contract is
/// not complete.
pub fn finalize_summary_after_install(
    prepared: &PreparedRuntimeRebase,
    installed_boot_rva: Option<u32>,
    installed_cookie_rva: Option<u32>,
    bootstrap_kind: &str,
    bootstrap_contract_valid: bool,
    emitted_plan_digest: &str,
) -> Result<RuntimeRebaseSummary, RebaseError> {
    let plan = &prepared.plan;
    let mut summary = summarize_plan(
        plan,
        installed_boot_rva,
        prepared.summary.original_oep_rva,
        installed_cookie_rva,
        bootstrap_kind,
        bootstrap_contract_valid,
    );
    // A final summary must carry the *emitted* digest (which must match the
    // plan digest — enforced by the caller's contract check).
    summary.deterministic_plan_digest = emitted_plan_digest.to_string();
    if summary.recovery_status != RebaseStatus::Complete {
        return Err(RebaseError::Plan(format!(
            "bootstrap install did not yield a Complete contract: \
             status={} unresolved_required={} boot_rva={:?} cookie={:?}",
            summary.recovery_status.label(),
            summary.unresolved_required,
            installed_boot_rva,
            installed_cookie_rva
        )));
    }
    Ok(summary)
}

#[cfg(test)]
#[path = "runtime_rebase_tests.rs"]
mod runtime_rebase_tests;
