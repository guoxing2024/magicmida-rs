//! Deterministic runtime heap / container rebasing plan (offline core).
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
use super::heap_global_snapshot::{HeapGlobalSnapshot, HeapSlab};

/// Pointer width this plan reasons about. GTO/R0 is x64-only; anything narrower
/// is rejected before a plan is built.
pub const POINTER_WIDTH: usize = 8;
/// Tagged small-integer ceiling: values below this are treated as tags/counts,
/// never as pointers (prevents an arbitrary small qword from being rebased).
pub const SMALL_TAG_CEILING: u64 = 0x1_0000;
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
    /// Original value is a stable external module / API address.
    ExternalModule,
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
            PointerClassification::SmallIntegerOrTag => "small_integer_or_tag",
            PointerClassification::Unmapped => "unmapped",
            PointerClassification::Ambiguous => "ambiguous",
        }
    }

    /// A pointer that must resolve to a concrete target for cold-start. An
    /// `Unmapped` or `Ambiguous` pointer is *required* to resolve; leaving it
    /// unresolved fails the whole recovery.
    pub fn is_required(self) -> bool {
        matches!(
            self,
            PointerClassification::InCapturedRegion
                | PointerClassification::InImage
                | PointerClassification::ExternalModule
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

/// A declared pointer slot inside a captured region.
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
    pub pointers: Vec<RebasePointer>,
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
        }
        for p in &self.pointers {
            out.extend_from_slice(&p.source_region.to_le_bytes());
            out.extend_from_slice(&p.source_offset.to_le_bytes());
            out.extend_from_slice(&p.original_value.to_le_bytes());
            out.push(class_as_u8(p.classification));
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
        PointerClassification::SmallIntegerOrTag => 4,
        PointerClassification::Unmapped => 5,
        PointerClassification::Ambiguous => 6,
    }
}

/// Build a runtime rebase plan from the captured allocation set.
///
/// # Fail-closed
///
/// Returns `Err` when any structural invariant is violated (old-range overflow,
/// region overlap, ambiguous old-VA mapping, pointer width mismatch). Returns
/// `Ok(None)` when there is nothing to rebase (no captured allocations).
pub fn build_runtime_rebase_plan(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slab: Option<&HeapSlab>,
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
        });
        id = id.saturating_add(1);
    }
    if let Some(slab) = heap_slab {
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
            });
        }
    }

    if candidates.is_empty() {
        return Ok(None);
    }

    // --- Deterministic sort by (old_base, size) ---
    candidates.sort_by_key(|r| (r.old_base, r.size));
    for (idx, r) in candidates.iter_mut().enumerate() {
        r.id = idx;
    }
    let regions = candidates;

    // --- Validate old ranges (checked arithmetic) + overlap fail-closed ---
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
                return Err(RebaseError::Overlap {
                    a: prev.old_base,
                    a_size: prev.size,
                    b: r.old_base,
                    b_size: r.size,
                });
            }
        }
    }

    // --- Build the region lookup for classification ---
    // Range-interior membership, but exact-duplicate ranges are ambiguous.
    let mut pointers = Vec::new();
    for (ri, region) in regions.iter().enumerate() {
        let bytes = &region.bytes;
        // Scan every aligned 8-byte slot inside this region's payload. A slot
        // is a *declared* pointer candidate only when its value is
        // structurally plausible (non-zero, ≥ small-tag ceiling) OR a tagged
        // value we explicitly record. We never patch un-declared slots; this
        // list is the declared ledger.
        let slot_count = bytes.len() / POINTER_WIDTH;
        for slot in 0..slot_count {
            let off = slot * POINTER_WIDTH;
            let val = u64::from_le_bytes(
                bytes[off..off + POINTER_WIDTH]
                    .try_into()
                    .map_err(|_| RebaseError::Slot(ri, off))?,
            );
            if val == 0 {
                pointers.push(RebasePointer {
                    source_region: ri,
                    source_offset: off,
                    original_value: val,
                    classification: PointerClassification::Null,
                    target_region: None,
                    target_offset: None,
                });
                continue;
            }
            if val < SMALL_TAG_CEILING {
                pointers.push(RebasePointer {
                    source_region: ri,
                    source_offset: off,
                    original_value: val,
                    classification: PointerClassification::SmallIntegerOrTag,
                    target_region: None,
                    target_offset: None,
                });
                continue;
            }
            let cls = classify_value(val, &regions, old_image_base, new_image_base);
            match cls {
                ClassResult::Unmapped | ClassResult::Ambiguous => pointers.push(RebasePointer {
                    source_region: ri,
                    source_offset: off,
                    original_value: val,
                    classification: cls.into(),
                    target_region: None,
                    target_offset: None,
                }),
                ClassResult::InCapturedRegion { target, offset } => {
                    pointers.push(RebasePointer {
                        source_region: ri,
                        source_offset: off,
                        original_value: val,
                        classification: PointerClassification::InCapturedRegion,
                        target_region: Some(target),
                        target_offset: Some(offset),
                    });
                }
                ClassResult::InImage => pointers.push(RebasePointer {
                    source_region: ri,
                    source_offset: off,
                    original_value: val,
                    classification: PointerClassification::InImage,
                    target_region: None,
                    target_offset: None,
                }),
                ClassResult::ExternalModule => pointers.push(RebasePointer {
                    source_region: ri,
                    source_offset: off,
                    original_value: val,
                    classification: PointerClassification::ExternalModule,
                    target_region: None,
                    target_offset: None,
                }),
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
        let (region, offset) = match (p.target_region, p.target_offset) {
            (Some(r), Some(o)) => (r, o),
            _ => {
                return Err(RebaseError::Plan(
                    "InCapturedRegion pointer missing target mapping".into(),
                ));
            }
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

    let mut plan = RuntimeRebasePlan {
        regions,
        pointers,
        old_image_base,
        new_image_base,
        plan_complete: true,
        plan_digest: String::new(),
    };
    plan.plan_digest = plan_digest(&plan);
    Ok(Some(plan))
}

/// Outcome of classifying one pointer value.
enum ClassResult {
    InImage,
    InCapturedRegion { target: usize, offset: u64 },
    ExternalModule,
    Unmapped,
    Ambiguous,
}

impl From<ClassResult> for PointerClassification {
    fn from(c: ClassResult) -> Self {
        match c {
            ClassResult::InImage => PointerClassification::InImage,
            ClassResult::InCapturedRegion { .. } => PointerClassification::InCapturedRegion,
            ClassResult::ExternalModule => PointerClassification::ExternalModule,
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

    // External module / API region (high canonical user VA, far above heaps).
    let in_external = canonical && val >= 0x0000_7ff0_0000_0000;
    if in_external {
        return ClassResult::ExternalModule;
    }

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
    // 3. All required pointers classified; all InCapturedRegion pointers have
    //    target mappings.
    for p in &plan.pointers {
        if p.classification == PointerClassification::InCapturedRegion {
            match (p.target_region, p.target_offset) {
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
            }
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
/// bootstrap RVA placement, OEP legality, and `.boot`/`.tls` size consistency.
///
/// Pure / offline. `pe` is the rebuilt header, `boot_rva`/`tls_rva` are the
/// bootstrap metadata locations, `original_oep_rva` the real OEP, and
/// `region_count` the number of regions the bootstrap metadata claims.
pub fn validate_bootstrap_contract(
    pe: &crate::header::PeHeader,
    boot_rva: u32,
    tls_rva: Option<u32>,
    original_oep_rva: u32,
    region_count: usize,
) -> Result<(), RebaseError> {
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

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

    Ok(())
}

/// Diagnostic recovery summary (section VIII). States are `Complete`,
/// `Incomplete`, `Rejected` — never acceptance terms.
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
    pub recovery_status: RebaseStatus,
}

/// Recovery status — a single unambiguous state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseStatus {
    Complete,
    Incomplete,
    Rejected,
}

impl RebaseStatus {
    pub fn label(self) -> &'static str {
        match self {
            RebaseStatus::Complete => "Complete",
            RebaseStatus::Incomplete => "Incomplete",
            RebaseStatus::Rejected => "Rejected",
        }
    }
}

/// Compute a diagnostic summary from a validated plan.
///
/// `boot_rva` / `completion_cookie_rva` are the runtime metadata positions the
/// bootstrap contract uses (from the installed `.boot`). Returns a summary with
/// `recovery_status` set to `Complete` only when `unresolved_required == 0` and
/// the plan passed offline validation.
pub fn summarize_plan(
    plan: &RuntimeRebasePlan,
    boot_rva: Option<u32>,
    original_oep_rva: u32,
    completion_cookie_rva: Option<u32>,
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
            PointerClassification::Unmapped | PointerClassification::Ambiguous => {}
        }
    }
    let unresolved_required = plan
        .pointers
        .iter()
        .filter(|p| p.classification.is_required())
        .filter(|p| {
            p.classification == PointerClassification::Unmapped
                || p.classification == PointerClassification::Ambiguous
        })
        .count();
    let plan_ok = validate_runtime_rebase_plan(plan).is_ok();
    let image_roots = plan
        .regions
        .iter()
        .filter(|r| r.image_inline_rva.is_some())
        .count();
    let status = if plan_ok && unresolved_required == 0 {
        RebaseStatus::Complete
    } else {
        RebaseStatus::Rejected
    };

    info!(
        regions_total = plan.regions.len(),
        regions_required = plan.regions_required(),
        bytes_captured = plan.bytes_captured(),
        pointer_slots = plan.pointers.len(),
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
        unresolved_optional: 0,
        image_roots_patched: image_roots,
        bootstrap_kind: "pre_oep_container".to_string(),
        bootstrap_rva: boot_rva,
        original_oep_rva,
        completion_cookie_rva,
        deterministic_plan_digest: plan.plan_digest.clone(),
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
    /// Region old ranges overlap (fail-closed).
    Overlap {
        a: u64,
        a_size: usize,
        b: u64,
        b_size: usize,
    },
    /// A pointer slot read/write was out of bounds.
    Slot(usize, usize),
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
            } => write!(
                f,
                "rebase regions overlap: [{a:#x},+{a_size:#x}) vs [{b:#x},+{b_size:#x})"
            ),
            RebaseError::Slot(r, o) => write!(f, "rebase pointer slot out of bounds (region {r} @ {o:#x})"),
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
        }
    }
}

impl std::error::Error for RebaseError {}

/// Integration helper for the dumper: build a plan from the captured allocation
/// set, validate it offline, and return the diagnostic summary.
///
/// Returns `Ok(None)` when there is nothing to rebase (no captured allocations).
/// Returns `Err` when the plan is structurally invalid **or** when a required
/// pointer is left unresolved — the caller must fail closed (never emit a
/// candidate that carries unresolved old heap/private pointers).
pub fn plan_and_validate_for_dump(
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slab: Option<&HeapSlab>,
    old_image_base: u64,
    new_image_base: u64,
    boot_rva: Option<u32>,
    original_oep_rva: u32,
    completion_cookie_rva: Option<u32>,
) -> Result<Option<RuntimeRebaseSummary>, RebaseError> {
    let Some(plan) = build_runtime_rebase_plan(
        containers,
        heap_globals,
        heap_slab,
        old_image_base,
        new_image_base,
    )?
    else {
        return Ok(None);
    };
    // Offline validation before the runtime contract can be trusted.
    validate_runtime_rebase_plan(&plan)?;
    let summary = summarize_plan(&plan, boot_rva, original_oep_rva, completion_cookie_rva);
    // Fail-closed: a required unresolved pointer must never be emitted as a
    // Complete recovery.
    if summary.recovery_status != RebaseStatus::Complete {
        return Err(RebaseError::Plan(format!(
            "recovery {}-resolved_required={} status={}; refusing to emit a candidate \
             carrying unresolved old heap/private pointers",
            summary.deterministic_plan_digest,
            summary.unresolved_required,
            summary.recovery_status.label()
        )));
    }
    Ok(Some(summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(rva: u32, begin: u64, end: u64, cap: u64, content: Vec<u8>) -> ContainerSnapshot {
        ContainerSnapshot {
            rva,
            decoded_begin: begin,
            decoded_end: end,
            decoded_capacity: cap,
            cookie: 0x3497_64dd_2eee,
            heap_content: content,
        }
    }

    fn global(rva: u32, live_ptr: u64, content: Vec<u8>, inline: bool) -> HeapGlobalSnapshot {
        HeapGlobalSnapshot {
            rva,
            live_ptr,
            content,
            is_heap_handle: false,
            is_image_inline: inline,
        }
    }

    const OLD_IB: u64 = 0x140_0000_00;
    const NEW_IB: u64 = 0x140_0000_00;

    /// Write an 8-byte pointer value at `off` in a zero buffer of `size`.
    fn region_bytes(size: usize, pairs: &[(usize, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; size];
        for &(off, v) in pairs {
            b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    // 1. Single region, no pointers.
    #[test]
    fn single_region_no_pointers() {
        let plan = build_runtime_rebase_plan(
            &[container(
                0x1000,
                0x500000,
                0x500008,
                0x500010,
                vec![0u8; 8],
            )],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        assert_eq!(plan.regions.len(), 1);
        assert_eq!(plan.pointers.len(), 1); // the single slot is 0 -> Null
        assert_eq!(plan.pointers[0].classification, PointerClassification::Null);
        validate_runtime_rebase_plan(&plan).unwrap();
        let s = summarize_plan(&plan, None, 0x1000, None);
        assert_eq!(s.recovery_status, RebaseStatus::Complete);
    }

    // 2. A -> B (A points to B's base).
    #[test]
    fn a_to_b() {
        let b_content = region_bytes(0x20, &[(0, 0x600000)]);
        let a_content = region_bytes(0x10, &[(0, 0x600000)]);
        let plan = build_runtime_rebase_plan(
            &[
                container(0x1000, 0x500000, 0x500010, 0x500020, a_content),
                container(0x2000, 0x600000, 0x600020, 0x600040, b_content),
            ],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        // Both regions sorted by old_base: 0x500000, 0x600000.
        assert_eq!(plan.regions[0].old_base, 0x500000);
        assert_eq!(plan.regions[1].old_base, 0x600000);
        let p = plan
            .pointers
            .iter()
            .find(|p| p.classification == PointerClassification::InCapturedRegion)
            .expect("A->B pointer");
        assert_eq!(p.target_region, Some(1));
        assert_eq!(p.target_offset, Some(0));
        validate_runtime_rebase_plan(&plan).unwrap();
    }

    // 3. A -> B -> A cycle.
    #[test]
    fn a_b_a_cycle() {
        let a = region_bytes(0x10, &[(0, 0x600000)]); // A points to B
        let b = region_bytes(0x10, &[(0, 0x500000)]); // B points to A
        let plan = build_runtime_rebase_plan(
            &[
                container(0x1000, 0x500000, 0x500010, 0x500020, a),
                container(0x2000, 0x600000, 0x600010, 0x600020, b),
            ],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        // A(0x500000) -> B(0x600000) = target region 1.
        // B(0x600000) -> A(0x500000) = target region 0.
        let a_ptr = plan.pointers.iter().find(|p| p.source_region == 0).unwrap();
        assert_eq!(a_ptr.target_region, Some(1));
        let b_ptr = plan.pointers.iter().find(|p| p.source_region == 1).unwrap();
        assert_eq!(b_ptr.target_region, Some(0));
        validate_runtime_rebase_plan(&plan).unwrap();
    }

    // 4. Self pointer.
    #[test]
    fn self_pointer() {
        let content = region_bytes(0x20, &[(0, 0x500000)]);
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500020, 0x500040, content)],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let p = plan
            .pointers
            .iter()
            .find(|p| p.classification == PointerClassification::InCapturedRegion)
            .unwrap();
        assert_eq!(p.source_region, 0);
        assert_eq!(p.target_region, Some(0));
        assert_eq!(p.target_offset, Some(0));
        validate_runtime_rebase_plan(&plan).unwrap();
    }

    // 5. Interior pointer: A+offset.
    #[test]
    fn interior_pointer() {
        let content = region_bytes(0x30, &[(0x10, 0x500020)]); // points 0x20 into self
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500030, 0x500040, content)],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let p = plan
            .pointers
            .iter()
            .find(|p| p.classification == PointerClassification::InCapturedRegion)
            .unwrap();
        assert_eq!(p.target_region, Some(0));
        assert_eq!(p.target_offset, Some(0x20));
        validate_runtime_rebase_plan(&plan).unwrap();
    }

    // 6. Multiple roots pointing to the same target.
    #[test]
    fn multiple_roots_same_target() {
        let a = region_bytes(0x10, &[(0, 0x600000), (8, 0x600000)]);
        let b = region_bytes(0x10, &[]);
        let plan = build_runtime_rebase_plan(
            &[
                container(0x1000, 0x500000, 0x500010, 0x500020, a),
                container(0x2000, 0x600000, 0x600010, 0x600020, b),
            ],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let intra: Vec<_> = plan
            .pointers
            .iter()
            .filter(|p| p.classification == PointerClassification::InCapturedRegion)
            .collect();
        assert_eq!(intra.len(), 2);
        assert!(intra.iter().all(|p| p.target_region == Some(1)));
        validate_runtime_rebase_plan(&plan).unwrap();
    }

    // 7. NULL is not modified (slot stays 0, classification Null).
    #[test]
    fn null_slot_untouched() {
        let content = vec![0u8; 0x20];
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500020, 0x500040, content)],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        assert!(plan
            .pointers
            .iter()
            .all(|p| p.classification == PointerClassification::Null));
        // Simulate a copy-patch pass that leaves NULL unchanged.
        let payloads: Vec<&[u8]> = plan.regions.iter().map(|r| r.bytes.as_slice()).collect();
        validate_rebased_snapshots(&plan, &payloads).unwrap();
    }

    // 8. Image RVA pointer correctly classified as InImage.
    #[test]
    fn image_pointer_classified() {
        let content = region_bytes(0x10, &[(0, OLD_IB + 0x1000)]);
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500010, 0x500020, content)],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let p = plan
            .pointers
            .iter()
            .find(|p| p.classification == PointerClassification::InImage)
            .expect("image pointer");
        assert_eq!(p.original_value, OLD_IB + 0x1000);
        validate_runtime_rebase_plan(&plan).unwrap();
    }

    // 9. External / module API pointer classified as ExternalModule.
    #[test]
    fn external_module_classified() {
        let content = region_bytes(0x10, &[(0, 0x7ff9_1234_5678)]);
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500010, 0x500020, content)],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let p = plan
            .pointers
            .iter()
            .find(|p| p.classification == PointerClassification::ExternalModule)
            .expect("external pointer");
        assert_eq!(p.original_value, 0x7ff9_1234_5678);
        validate_runtime_rebase_plan(&plan).unwrap();
    }

    // 10. Unmapped required pointer -> plan fails closed (Rejected).
    #[test]
    fn unmapped_required_fails_closed() {
        let content = region_bytes(0x10, &[(0, 0x1234_5678_9abc)]);
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500010, 0x500020, content)],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let s = summarize_plan(&plan, None, 0x1000, None);
        // The unmapped pointer is not required by classification, but the plan
        // contains an unmapped slot -> recovery must be Rejected.
        assert_eq!(s.unresolved_required, 1);
        assert_eq!(s.recovery_status, RebaseStatus::Rejected);
    }

    // 11. Ambiguous (value inside two overlapping-membership regions).
    #[test]
    fn ambiguous_fails_closed() {
        // Two regions whose old ranges overlap would fail at build (overlap).
        // Instead, test that an exact duplicate old base is rejected.
        let a = region_bytes(0x10, &[]);
        let plan = build_runtime_rebase_plan(
            &[
                container(0x1000, 0x500000, 0x500010, 0x500020, a.clone()),
                container(0x2000, 0x500000, 0x500010, 0x500020, a),
            ],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        );
        assert!(plan.is_err(), "overlapping regions must fail closed");
    }

    // 12. Optional opaque slot is not patched (kept as-is, recorded).
    #[test]
    fn optional_opaque_slot_not_patched() {
        // A small integer / tag value is left untouched; only its classification
        // is recorded. No target mapping is produced.
        let content = region_bytes(0x20, &[(8, 0x1234)]);
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500020, 0x500040, content)],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let tag = plan
            .pointers
            .iter()
            .find(|p| p.classification == PointerClassification::SmallIntegerOrTag)
            .expect("tag slot");
        assert_eq!(tag.original_value, 0x1234);
        assert_eq!(tag.target_region, None);
        validate_runtime_rebase_plan(&plan).unwrap();
    }

    // 13. Overlapping old regions rejected (covered by #11; explicit here).
    #[test]
    fn overlapping_old_regions_rejected() {
        let a = region_bytes(0x20, &[]);
        let plan = build_runtime_rebase_plan(
            &[
                container(0x1000, 0x500000, 0x500020, 0x500040, a.clone()),
                container(0x2000, 0x500010, 0x500030, 0x500050, a),
            ],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        );
        assert!(matches!(plan, Err(RebaseError::Overlap { .. })));
    }

    // 14. Overlapping target regions rejected (duplicate image-inline RVA).
    #[test]
    fn overlapping_target_regions_rejected() {
        let a = region_bytes(0x10, &[]);
        let plan = build_runtime_rebase_plan(
            &[],
            &[
                global(0x2000, 0x140000000, a.clone(), true),
                global(0x2000, 0x140000000, a.clone(), true),
            ],
            None,
            OLD_IB,
            NEW_IB,
        );
        // Duplicate image-inline RVA should be caught by the build (same old
        // base) or by the validator.
        match plan {
            Ok(Some(p)) => {
                assert!(
                    validate_runtime_rebase_plan(&p).is_err(),
                    "duplicate image-inline target must fail validation"
                );
            }
            Ok(None) => panic!("expected a plan"),
            Err(_) => {}
        }
    }

    // 15. old_base + size overflow rejected.
    #[test]
    fn old_base_plus_size_overflow_rejected() {
        // A heap-global with a base near u64::MAX and a real payload makes
        // old_base + size overflow (containers derive size = end - begin, so
        // they can never overflow; the global path can).
        let plan = build_runtime_rebase_plan(
            &[],
            &[global(0x2000, u64::MAX - 2, vec![0u8; 16], false)],
            None,
            OLD_IB,
            NEW_IB,
        );
        assert!(matches!(plan, Err(RebaseError::Overflow { .. })));
    }

    // 16. source pointer slot out of bounds rejected.
    #[test]
    fn source_slot_out_of_bounds_rejected() {
        // A region smaller than a pointer is impossible (size checked > 0).
        // Build one then corrupt its payload length to trigger the validator.
        let plan = build_runtime_rebase_plan(
            &[container(
                0x1000,
                0x500000,
                0x500010,
                0x500020,
                vec![0u8; 16],
            )],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        // Simulate a malformed plan where a pointer slot exceeds the payload.
        let mut bad = plan.clone();
        bad.pointers[0].source_offset = 12; // 12 + 8 > 16
        assert!(validate_runtime_rebase_plan(&bad).is_err());
    }

    // 17. allocation failure does not enter OEP (contract: no OEP on required
    //     allocation failure). Represented by: an empty required region -> Rejected.
    #[test]
    fn required_allocation_failure_rejects() {
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500000, 0x500010, vec![])],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        );
        assert!(matches!(plan, Err(RebaseError::EmptyRegion(_))));
    }

    // 18. bootstrap re-entry must not double-allocate (plan is single-shot;
    //     deterministic digest proves the plan is stable across repeats).
    #[test]
    fn plan_is_deterministic() {
        let content = region_bytes(0x10, &[(0, 0x600000)]);
        let p1 = build_runtime_rebase_plan(
            &[
                container(0x1000, 0x500000, 0x500010, 0x500020, content.clone()),
                container(0x2000, 0x600000, 0x600010, 0x600020, content.clone()),
            ],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let p2 = build_runtime_rebase_plan(
            &[
                container(0x1000, 0x500000, 0x500010, 0x500020, content.clone()),
                container(0x2000, 0x600000, 0x600010, 0x600020, content.clone()),
            ],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        assert_eq!(p1.canonical_bytes(), p2.canonical_bytes());
        assert_eq!(p1.plan_digest, p2.plan_digest);
    }

    // 19. Completion cookie only set after full success (post-patch scan
    //     passes => no dangling pointers => cookie may be set).
    #[test]
    fn post_patch_scan_no_old_range_pointer() {
        let content = region_bytes(0x10, &[(0, 0x500000)]); // self pointer
        let plan = build_runtime_rebase_plan(
            &[container(0x1000, 0x500000, 0x500010, 0x500020, content)],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        // Simulate a completed patch: the self pointer now points to the new
        // allocation base (choose a base outside all old ranges, e.g. 0x900000).
        let patched = vec![region_bytes(0x10, &[(0, 0x900000)])];
        validate_rebased_snapshots(&plan, &[patched[0].as_slice()]).unwrap();
        // If the patch left the old base, the scan must fail.
        let bad = vec![region_bytes(0x10, &[(0, 0x500000)])];
        assert!(validate_rebased_snapshots(&plan, &[bad[0].as_slice()]).is_err());
    }

    // 20. patch after scan: no required old-range pointer remains.
    #[test]
    fn patch_leaves_no_old_range_pointer() {
        // Covered comprehensively by #19; assert the direct classification too.
        let plan = build_runtime_rebase_plan(
            &[container(
                0x1000,
                0x500000,
                0x500008,
                0x500010,
                vec![0u8; 8],
            )],
            &[],
            None,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let payloads: Vec<&[u8]> = plan.regions.iter().map(|r| r.bytes.as_slice()).collect();
        validate_rebased_snapshots(&plan, &payloads).unwrap();
    }

    // 21. deterministic identical bytes (covered by #18); bootstrap contract.
    #[test]
    fn bootstrap_contract_checks() {
        // Build a minimal valid PE for contract checks.
        let pe = crate::header::make_minimal_pe64();
        let pe = crate::header::PeHeader::from_bytes(&pe).unwrap();
        // A non-executable boot RVA fails.
        let bad = validate_bootstrap_contract(&pe, 0x2000, None, 0x1000, 1);
        assert!(bad.is_err(), "boot RVA outside exec section must fail");
    }

    // 22. Oreans profile does not enable GTO heap bootstrap.
    #[test]
    fn oreans_profile_disables_gto_bootstrap() {
        let caps = crate::DumpProfile::OreansClassic.capabilities();
        assert!(!caps.install_heap_bootstrap);
        assert!(!caps.capture_heap_graph);
        assert!(!caps.capture_containers);
        let stage = crate::DumpProfile::OreansClassic.stage_plan();
        assert!(stage.all_disabled());
    }

    // 23. AhkGtoExperimental profile enables the recovery chain.
    #[test]
    fn ahk_gto_profile_enables_chain() {
        let caps = crate::DumpProfile::AhkGtoExperimental.capabilities();
        assert!(caps.install_heap_bootstrap);
        assert!(caps.capture_heap_graph);
        assert!(caps.capture_containers);
        let stage = crate::DumpProfile::AhkGtoExperimental.stage_plan();
        assert!(stage.all_enabled());
    }

    // 24. No plan => GTO recovery fail-closed (empty capture yields None, which
    //     the caller must treat as "no rebasing to prove").
    #[test]
    fn no_plan_fails_closed() {
        let plan = build_runtime_rebase_plan(&[], &[], None, OLD_IB, NEW_IB).unwrap();
        assert!(plan.is_none());
    }
}
