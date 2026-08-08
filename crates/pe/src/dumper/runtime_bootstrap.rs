//! Plan-driven runtime bootstrap for GTO cold-start.
//!
//! This module turns a validated [`RuntimeRebasePlan`] into the actual `.boot`
//! section: an authoritative metadata table (regions + pointer fixups +
//! external resolvers) plus a two-phase x64 stub that consumes it at cold
//! start. It is the **only** pointer-fixup source for the AhkGto recovery path
//! — nothing here re-guesses a mapping that the plan already decided.
//!
//! ## Execution (two phase)
//!
//! - **Phase 1 (allocate):** every heap-target region is allocated fresh via
//!   `HeapAlloc`, `region_id → new_base` is recorded in a runtime alloc map,
//!   and the captured payload is copied in. A required allocation failure jumps
//!   to a fail path that never reaches OEP.
//! - **Phase 2 (patch):** the pointer-fixup table is walked; each declared slot
//!   is rewritten:
//!   - `InCapturedRegion`: `target_new_base + target_offset`
//!   - `InImage`: `loaded_image_base + image_rva`
//!   - `ExternalModule`: read the cold-start IAT slot (`loaded_image_base +
//!     iat_rva`), never a dump-time API VA
//!   - `Null` / `SmallIntegerOrTag`: unchanged
//!   - `ExternalCandidate` / `Unmapped` / `Ambiguous`: metadata is never
//!     emitted for these (the plan fails closed before we get here).
//!
//! Finally: patch image root/global slots, set the completion cookie, clear
//! volatile registers, and jump to the real OEP.
//!
//! The offline [`simulate_runtime_rebase`] executes the **emitted metadata**
//! against provided allocation bases so the round-trip is proven without a
//! live sample.

use crate::header::PeHeader;
use crate::import_table::ImportTableBuilder;

use super::runtime_rebase::{
    ExternalResolutionKind, PointerClassification, PreparedRuntimeRebase, RebaseError,
    RuntimeRebasePlan,
};

/// .boot metadata magic.
const META_MAGIC: u32 = 0x3142_5052; // "RBP1"

// ---- Metadata layout constants (must match decoder) ----
const PLAN_HEADER_SIZE: usize = 0x40;
const REGION_META_SIZE: usize = 0x30; // 48
const FIXUP_META_SIZE: usize = 0x30; // 48
const RESOLVER_META_SIZE: usize = 0x20; // 32

// Region flags.
const REGION_FLAG_HEAP_TARGET: u32 = 0x01;
const REGION_FLAG_IMAGE_INLINE: u32 = 0x02;

/// Result of installing a plan-driven runtime bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledHeapBootstrap {
    /// PE entry point RVA to write (CRT wrapper unchanged for PostCrt).
    pub entry_point_rva: u32,
    /// RVA of the `.boot` section.
    pub boot_rva: u32,
    /// RVA of the plan metadata header within `.boot`.
    pub metadata_rva: u32,
    /// Total metadata (header + regions + fixups + resolvers + payloads) size.
    pub metadata_size: u32,
    /// RVA of the completion cookie slot.
    pub completion_cookie_rva: u32,
    /// Original OEP RVA (the final `jmp` target).
    pub original_oep_rva: u32,
    /// Number of regions encoded in the metadata.
    pub region_count: usize,
    /// Number of pointer fixups encoded in the metadata.
    pub pointer_fixup_count: usize,
    /// Number of external resolvers encoded in the metadata.
    pub resolver_count: usize,
    /// The plan digest the emitted metadata was built from.
    pub emitted_plan_digest: String,
    /// Bootstrap kind (e.g. "post_crt_two_phase").
    pub bootstrap_kind: String,
}

impl InstalledHeapBootstrap {
    /// `.boot` section contains the code (starts at boot_rva); metadata starts
    /// after the code. For the purposes of this offline module we return
    /// metadata_rva = boot_rva + code_len (set at install).
    pub fn metadata_size(&self) -> u32 {
        self.metadata_size
    }
}

/// Errors from installing a plan-driven runtime bootstrap.
///
/// Under `AhkGtoExperimental` every one of these is a hard dump error that must
/// occur before the candidate is written.
#[derive(Debug)]
pub enum HeapBootstrapError {
    /// Required import is missing from the rebuilt import table.
    MissingImport(&'static str),
    /// The plan / metadata is structurally invalid.
    Plan(RebaseError),
    /// Stub code generation failed (e.g. a relative displacement overflow).
    Codegen(String),
    /// The capture set is empty but the profile requires a runtime bootstrap.
    RequiredCaptureMissing,
    /// A required pointer could not be resolved to a patchable target.
    UnresolvedRequired(String),
    /// Not an x64 image (pointer width mismatch).
    NotX64,
}

impl std::fmt::Display for HeapBootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeapBootstrapError::MissingImport(name) => {
                write!(f, "heap bootstrap missing required import: {name}")
            }
            HeapBootstrapError::Plan(e) => write!(f, "heap bootstrap plan error: {e}"),
            HeapBootstrapError::Codegen(m) => write!(f, "heap bootstrap stub codegen: {m}"),
            HeapBootstrapError::RequiredCaptureMissing => write!(
                f,
                "heap bootstrap requires runtime capture but none was produced"
            ),
            HeapBootstrapError::UnresolvedRequired(m) => {
                write!(f, "heap bootstrap unresolved required pointer: {m}")
            }
            HeapBootstrapError::NotX64 => write!(f, "heap bootstrap requires an x64 image"),
        }
    }
}

impl std::error::Error for HeapBootstrapError {}

impl From<RebaseError> for HeapBootstrapError {
    fn from(e: RebaseError) -> Self {
        HeapBootstrapError::Plan(e)
    }
}

/// Encoded `.boot` metadata: header + region table + fixup table + resolver
/// table + payloads. Produced by [`encode_plan_metadata`], consumed by the
/// emitted stub and by [`decode_plan_metadata`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootMetadata {
    pub regions: Vec<BootRegion>,
    pub fixups: Vec<BootFixup>,
    pub resolvers: Vec<BootResolver>,
    pub payload: Vec<u8>,
    pub image_base: u64,
    pub original_oep_rva: u32,
    pub completion_cookie_rva: u32,
}

/// Encoded region descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootRegion {
    pub old_base: u64,
    pub size: usize,
    pub data_offset: u32,
    pub heap_target: bool,
    pub image_inline: bool,
    pub image_rva: u32,
    pub alignment: usize,
}

/// Encoded pointer fixup descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootFixup {
    pub source_region: usize,
    pub source_offset: usize,
    pub classification: u8,
    pub target_region: u32,
    pub target_offset: u64,
    pub image_rva: u32,
    pub external_index: u32,
    pub original_value: u64,
}

/// Encoded external resolver descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootResolver {
    pub module_rva: u64,
    pub iat_rva: u32,
    pub resolution_kind: u32,
}

// ---------------------------------------------------------------------------
// Metadata encoder / decoder
// ---------------------------------------------------------------------------

fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap_or([0; 4]))
}
fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap_or([0; 8]))
}

fn classify_u8(c: PointerClassification) -> u8 {
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

fn classify_from_u8(v: u8) -> PointerClassification {
    match v {
        0 => PointerClassification::Null,
        1 => PointerClassification::InImage,
        2 => PointerClassification::InCapturedRegion,
        3 => PointerClassification::ExternalModule,
        4 => PointerClassification::ExternalCandidate,
        5 => PointerClassification::SmallIntegerOrTag,
        6 => PointerClassification::Unmapped,
        _ => PointerClassification::Ambiguous,
    }
}

fn resolver_kind_u8(k: ExternalResolutionKind) -> u32 {
    match k {
        ExternalResolutionKind::ViaIat => 0,
        ExternalResolutionKind::ViaExportMap => 1,
        ExternalResolutionKind::ViaStableBinding => 2,
    }
}

/// Encode a validated plan into `.boot` metadata bytes (the authoritative
/// pointer-fixup source).
///
/// # Fail-closed
///
/// Returns `Err` if any declared pointer is unresolved-required
/// (`ExternalCandidate` / `Unmapped` / `Ambiguous`), or if an `ExternalModule`
/// pointer references a resolver absent from the plan's resolver table.
pub fn encode_plan_metadata(plan: &RuntimeRebasePlan) -> Result<BootMetadata, HeapBootstrapError> {
    // Resolve external indexes first.
    let mut fixups: Vec<BootFixup> = Vec::new();
    for p in &plan.pointers {
        match p.classification {
            PointerClassification::Null | PointerClassification::SmallIntegerOrTag => {
                fixups.push(BootFixup {
                    source_region: p.source_region,
                    source_offset: p.source_offset,
                    classification: classify_u8(p.classification),
                    target_region: 0,
                    target_offset: 0,
                    image_rva: 0,
                    external_index: u32::MAX,
                    original_value: p.original_value,
                });
            }
            PointerClassification::InImage => {
                let image_rva = p.image_rva.ok_or_else(|| {
                    HeapBootstrapError::UnresolvedRequired(format!(
                        "InImage pointer (region {} @ {:#x}) lacks image RVA",
                        p.source_region, p.source_offset
                    ))
                })?;
                fixups.push(BootFixup {
                    source_region: p.source_region,
                    source_offset: p.source_offset,
                    classification: classify_u8(p.classification),
                    target_region: 0,
                    target_offset: 0,
                    image_rva,
                    external_index: u32::MAX,
                    original_value: p.original_value,
                });
            }
            PointerClassification::InCapturedRegion => {
                let (t, o) = match (p.target_region, p.target_offset) {
                    (Some(t), Some(o)) => (t as u32, o),
                    _ => {
                        return Err(HeapBootstrapError::UnresolvedRequired(format!(
                            "InCapturedRegion pointer (region {} @ {:#x}) lacks target",
                            p.source_region, p.source_offset
                        )));
                    }
                };
                fixups.push(BootFixup {
                    source_region: p.source_region,
                    source_offset: p.source_offset,
                    classification: classify_u8(p.classification),
                    target_region: t,
                    target_offset: o,
                    image_rva: 0,
                    external_index: u32::MAX,
                    original_value: p.original_value,
                });
            }
            PointerClassification::ExternalModule => {
                let ext = p.external_target.as_ref().ok_or_else(|| {
                    HeapBootstrapError::UnresolvedRequired(format!(
                        "ExternalModule pointer (region {} @ {:#x}) lacks resolver",
                        p.source_region, p.source_offset
                    ))
                })?;
                let index = plan
                    .external_targets
                    .iter()
                    .position(|e| {
                        e.module_identity == ext.module_identity && e.module_rva == ext.module_rva
                    })
                    .ok_or_else(|| {
                        HeapBootstrapError::UnresolvedRequired(format!(
                            "ExternalModule pointer resolver not in table: {} rva {:#x}",
                            ext.module_identity, ext.module_rva
                        ))
                    })? as u32;
                fixups.push(BootFixup {
                    source_region: p.source_region,
                    source_offset: p.source_offset,
                    classification: classify_u8(p.classification),
                    target_region: 0,
                    target_offset: 0,
                    image_rva: 0,
                    external_index: index,
                    original_value: p.original_value,
                });
            }
            PointerClassification::ExternalCandidate
            | PointerClassification::Unmapped
            | PointerClassification::Ambiguous => {
                return Err(HeapBootstrapError::UnresolvedRequired(format!(
                    "metadata must not emit unresolved-required pointer ({}, region {} @ {:#x})",
                    p.classification.label(),
                    p.source_region,
                    p.source_offset
                )));
            }
        }
    }

    // Deterministic region order (plan regions already sorted).
    let regions: Vec<BootRegion> = plan
        .regions
        .iter()
        .map(|r| BootRegion {
            old_base: r.old_base,
            size: r.size,
            data_offset: 0, // filled below during layout
            heap_target: r.image_inline_rva.is_none(),
            image_inline: r.image_inline_rva.is_some(),
            image_rva: r.image_inline_rva.unwrap_or(0),
            alignment: r.alignment,
        })
        .collect();

    let resolvers: Vec<BootResolver> = plan
        .external_targets
        .iter()
        .map(|t| BootResolver {
            module_rva: t.module_rva,
            iat_rva: t.iat_rva.unwrap_or(0),
            resolution_kind: resolver_kind_u8(t.resolution_kind),
        })
        .collect();

    // Build the payload region (all region bytes, 8-aligned each, in region
    // order) and compute data offsets.
    let mut payload = Vec::new();
    let mut regions_out = regions;
    for (i, r) in plan.regions.iter().enumerate() {
        let off = align8(payload.len());
        if off > payload.len() {
            payload.resize(off, 0);
        }
        regions_out[i].data_offset = off as u32;
        payload.extend_from_slice(&r.bytes);
    }

    Ok(BootMetadata {
        regions: regions_out,
        fixups,
        resolvers,
        payload,
        image_base: plan.new_image_base,
        original_oep_rva: 0,      // set at install
        completion_cookie_rva: 0, // set at install
    })
}

fn align8(v: usize) -> usize {
    (v + 7) & !7
}

/// Decode a `.boot` metadata blob back into structured form. Must round-trip
/// with [`encode_plan_metadata`]. `code_len` is the offset where the plan
/// header begins (after the stub code).
pub fn decode_plan_metadata(
    blob: &[u8],
    meta_offset: usize,
) -> Result<BootMetadata, HeapBootstrapError> {
    if blob.len() < meta_offset + PLAN_HEADER_SIZE {
        return Err(HeapBootstrapError::Codegen(
            "metadata truncated (header)".into(),
        ));
    }
    let h = &blob[meta_offset..meta_offset + PLAN_HEADER_SIZE];
    if get_u32(h, 0) != META_MAGIC {
        return Err(HeapBootstrapError::Codegen("bad metadata magic".into()));
    }
    let region_count = get_u32(h, 4) as usize;
    let fixup_count = get_u32(h, 8) as usize;
    let resolver_count = get_u32(h, 12) as usize;
    let image_base = get_u64(h, 0x20);
    let original_oep_rva = get_u32(h, 0x28);
    let completion_cookie_rva = get_u32(h, 0x30);

    let region_off = get_u32(h, 0x10) as usize;
    let fixup_off = get_u32(h, 0x14) as usize;
    let resolver_off = get_u32(h, 0x18) as usize;
    let payload_off = get_u32(h, 0x1c) as usize;

    // Region table.
    let need_regions = region_off
        .checked_add(
            region_count
                .checked_mul(REGION_META_SIZE)
                .ok_or_else(|| HeapBootstrapError::Codegen("region table size overflow".into()))?,
        )
        .ok_or_else(|| HeapBootstrapError::Codegen("region table offset overflow".into()))?;
    if blob.len() < need_regions {
        return Err(HeapBootstrapError::Codegen("region table truncated".into()));
    }
    let mut regions = Vec::with_capacity(region_count);
    for i in 0..region_count {
        let b = &blob[region_off + i * REGION_META_SIZE..region_off + (i + 1) * REGION_META_SIZE];
        let flags = get_u32(b, 0x10);
        regions.push(BootRegion {
            old_base: get_u64(b, 0x00),
            size: get_u32(b, 0x08) as usize,
            data_offset: get_u32(b, 0x0c),
            heap_target: flags & REGION_FLAG_HEAP_TARGET != 0,
            image_inline: flags & REGION_FLAG_IMAGE_INLINE != 0,
            image_rva: get_u32(b, 0x18),
            alignment: get_u32(b, 0x14) as usize,
        });
    }

    // Fixup table.
    let need_fixups = fixup_off
        .checked_add(
            fixup_count
                .checked_mul(FIXUP_META_SIZE)
                .ok_or_else(|| HeapBootstrapError::Codegen("fixup table size overflow".into()))?,
        )
        .ok_or_else(|| HeapBootstrapError::Codegen("fixup table offset overflow".into()))?;
    if blob.len() < need_fixups {
        return Err(HeapBootstrapError::Codegen("fixup table truncated".into()));
    }
    let mut fixups = Vec::with_capacity(fixup_count);
    for i in 0..fixup_count {
        let b = &blob[fixup_off + i * FIXUP_META_SIZE..fixup_off + (i + 1) * FIXUP_META_SIZE];
        fixups.push(BootFixup {
            source_region: get_u32(b, 0x00) as usize,
            source_offset: get_u32(b, 0x04) as usize,
            classification: b[0x08],
            target_region: get_u32(b, 0x0c),
            target_offset: get_u64(b, 0x10),
            image_rva: get_u32(b, 0x18),
            external_index: get_u32(b, 0x1c),
            original_value: get_u64(b, 0x20),
        });
    }

    // Resolver table.
    let need_resolvers = resolver_off
        .checked_add(
            resolver_count
                .checked_mul(RESOLVER_META_SIZE)
                .ok_or_else(|| {
                    HeapBootstrapError::Codegen("resolver table size overflow".into())
                })?,
        )
        .ok_or_else(|| HeapBootstrapError::Codegen("resolver table offset overflow".into()))?;
    if blob.len() < need_resolvers {
        return Err(HeapBootstrapError::Codegen(
            "resolver table truncated".into(),
        ));
    }
    let mut resolvers = Vec::with_capacity(resolver_count);
    for i in 0..resolver_count {
        let b = &blob
            [resolver_off + i * RESOLVER_META_SIZE..resolver_off + (i + 1) * RESOLVER_META_SIZE];
        resolvers.push(BootResolver {
            module_rva: get_u64(b, 0x00),
            iat_rva: get_u32(b, 0x08),
            resolution_kind: get_u32(b, 0x0c),
        });
    }

    let payload = if payload_off <= blob.len() {
        blob[payload_off..].to_vec()
    } else {
        Vec::new()
    };

    Ok(BootMetadata {
        regions,
        fixups,
        resolvers,
        payload,
        image_base,
        original_oep_rva,
        completion_cookie_rva,
    })
}

/// Compute the byte layout of the full `.boot` (code + metadata) given the
/// metadata. Returns `(metadata_offset, total_size)`.
fn metadata_layout(meta: &BootMetadata, code_len: usize) -> (usize, usize) {
    let header_off = align8(code_len);
    let region_off = header_off + PLAN_HEADER_SIZE;
    let fixup_off = region_off + meta.regions.len() * REGION_META_SIZE;
    let resolver_off = fixup_off + meta.fixups.len() * FIXUP_META_SIZE;
    let payload_off = resolver_off + meta.resolvers.len() * RESOLVER_META_SIZE;
    let total = payload_off + meta.payload.len();
    (header_off, total)
}

/// Serialize metadata into the `.boot` byte blob starting at `meta_offset`.
fn serialize_metadata_into(
    blob: &mut [u8],
    meta: &BootMetadata,
    meta_offset: usize,
    original_oep_rva: u32,
    completion_cookie_rva: u32,
) -> Result<(), HeapBootstrapError> {
    let h = &mut blob[meta_offset..meta_offset + PLAN_HEADER_SIZE];
    put_u32(h, 0, META_MAGIC);
    put_u32(h, 4, meta.regions.len() as u32);
    put_u32(h, 8, meta.fixups.len() as u32);
    put_u32(h, 12, meta.resolvers.len() as u32);
    put_u32(h, 0x10, (meta_offset + PLAN_HEADER_SIZE) as u32);
    put_u32(
        h,
        0x14,
        (meta_offset + PLAN_HEADER_SIZE + meta.regions.len() * REGION_META_SIZE) as u32,
    );
    put_u32(
        h,
        0x18,
        (meta_offset
            + PLAN_HEADER_SIZE
            + meta.regions.len() * REGION_META_SIZE
            + meta.fixups.len() * FIXUP_META_SIZE) as u32,
    );
    put_u32(
        h,
        0x1c,
        (meta_offset
            + PLAN_HEADER_SIZE
            + meta.regions.len() * REGION_META_SIZE
            + meta.fixups.len() * FIXUP_META_SIZE
            + meta.resolvers.len() * RESOLVER_META_SIZE) as u32,
    );
    put_u64(h, 0x20, meta.image_base);
    put_u32(h, 0x28, original_oep_rva);
    put_u32(h, 0x30, completion_cookie_rva);

    // Region table.
    for (i, r) in meta.regions.iter().enumerate() {
        let base = meta_offset + PLAN_HEADER_SIZE + i * REGION_META_SIZE;
        let b = &mut blob[base..base + REGION_META_SIZE];
        put_u64(b, 0x00, r.old_base);
        put_u32(b, 0x08, r.size as u32);
        put_u32(b, 0x0c, r.data_offset);
        let mut flags = 0u32;
        if r.heap_target {
            flags |= REGION_FLAG_HEAP_TARGET;
        }
        if r.image_inline {
            flags |= REGION_FLAG_IMAGE_INLINE;
        }
        put_u32(b, 0x10, flags);
        put_u32(b, 0x14, r.alignment as u32);
        put_u32(b, 0x18, r.image_rva);
    }

    // Fixup table.
    for (i, f) in meta.fixups.iter().enumerate() {
        let base = meta_offset
            + PLAN_HEADER_SIZE
            + meta.regions.len() * REGION_META_SIZE
            + i * FIXUP_META_SIZE;
        let b = &mut blob[base..base + FIXUP_META_SIZE];
        put_u32(b, 0x00, f.source_region as u32);
        put_u32(b, 0x04, f.source_offset as u32);
        b[0x08] = f.classification;
        put_u32(b, 0x0c, f.target_region);
        put_u64(b, 0x10, f.target_offset);
        put_u32(b, 0x18, f.image_rva);
        put_u32(b, 0x1c, f.external_index);
        put_u64(b, 0x20, f.original_value);
    }

    // Resolver table.
    for (i, r) in meta.resolvers.iter().enumerate() {
        let base = meta_offset
            + PLAN_HEADER_SIZE
            + meta.regions.len() * REGION_META_SIZE
            + meta.fixups.len() * FIXUP_META_SIZE
            + i * RESOLVER_META_SIZE;
        let b = &mut blob[base..base + RESOLVER_META_SIZE];
        put_u64(b, 0x00, r.module_rva);
        put_u32(b, 0x08, r.iat_rva);
        put_u32(b, 0x0c, r.resolution_kind);
    }

    // Payload.
    let payload_off = meta_offset
        + PLAN_HEADER_SIZE
        + meta.regions.len() * REGION_META_SIZE
        + meta.fixups.len() * FIXUP_META_SIZE
        + meta.resolvers.len() * RESOLVER_META_SIZE;
    if payload_off + meta.payload.len() > blob.len() {
        return Err(HeapBootstrapError::Codegen("payload exceeds .boot".into()));
    }
    blob[payload_off..payload_off + meta.payload.len()].copy_from_slice(&meta.payload);
    Ok(())
}

// ---------------------------------------------------------------------------
// Stub code generation (two-phase)
// ---------------------------------------------------------------------------

fn rel32(next_rva: u32, target_rva: u32) -> Result<[u8; 4], HeapBootstrapError> {
    let d = i64::from(target_rva) - i64::from(next_rva);
    i32::try_from(d)
        .map(i32::to_le_bytes)
        .map_err(|_| HeapBootstrapError::Codegen("relative displacement out of range".into()))
}

/// Emit the two-phase stub code + metadata into a `.boot` section.
///
/// Returns the byte blob and the metadata offset within it.
pub fn build_runtime_bootstrap(
    pe: &mut PeHeader,
    imports: &ImportTableBuilder,
    prepared: &PreparedRuntimeRebase,
    original_entry_point: u32,
    completion_cookie_rva: u32,
) -> Result<(Vec<u8>, usize), HeapBootstrapError> {
    if !pe.is_64bit {
        return Err(HeapBootstrapError::NotX64);
    }
    let gph = imports
        .find_function_iat("GetProcessHeap")
        .ok_or(HeapBootstrapError::MissingImport("GetProcessHeap"))?;
    let ha = imports
        .find_function_iat("HeapAlloc")
        .ok_or(HeapBootstrapError::MissingImport("HeapAlloc"))?;

    let meta = encode_plan_metadata(&prepared.plan)?;
    let image_base = pe.nt_headers.optional_header.image_base;
    let boot_rva = pe
        .sections
        .last()
        .map(|s| s.virtual_address)
        .unwrap_or(0x200000);

    let (code, pts) = emit_two_phase_code(
        boot_rva,
        &meta,
        gph,
        ha,
        original_entry_point,
        completion_cookie_rva,
        image_base,
    )?;

    // Layout: [code][metadata][alloc map (8 bytes/region)]
    let (meta_offset, meta_total) = metadata_layout(&meta, code.len());
    let map_offset = align8(meta_offset + meta_total);
    let total = map_offset + meta.regions.len() * 8;

    let mut blob = vec![0u8; total];
    blob[..code.len()].copy_from_slice(&code);
    serialize_metadata_into(
        &mut blob,
        &meta,
        meta_offset,
        original_entry_point,
        completion_cookie_rva,
    )?;

    // Patch the two lea displacements in the code.
    let meta_lea = pts.meta_leia_pos;
    let map_lea = pts.map_lea_pos;
    let meta_lea_next = boot_rva + meta_lea as u32 + 7;
    let meta_target = boot_rva + meta_offset as u32;
    let md = rel32(meta_lea_next, meta_target)?;
    blob[meta_lea + 3..meta_lea + 7].copy_from_slice(&md);

    let map_lea_next = boot_rva + map_lea as u32 + 7;
    let map_target = boot_rva + map_offset as u32;
    let mp = rel32(map_lea_next, map_target)?;
    blob[map_lea + 3..map_lea + 7].copy_from_slice(&mp);

    Ok((blob, meta_offset))
}

/// Emit the x64 two-phase stub. `boot_rva` is the `.boot` section VA.
///
/// Phase 1 allocates every heap-target region (recording `new_base` in the
/// alloc map) and copies payloads; a required allocation failure loops forever
/// (never reaches OEP). Phase 2 walks the fixup table and rewrites each
/// declared slot. Then it sets the completion cookie, clears volatile
/// registers, and jumps to the real OEP.
#[allow(clippy::too_many_arguments)]
/// Emit the x64 two-phase stub. `boot_rva` is the `.boot` section VA.
///
/// Phase 1 allocates every heap-target region (recording `new_base` in the
/// alloc map) and copies payloads; a required allocation failure loops forever
/// (never reaches OEP). Phase 2 walks the fixup table and rewrites each
/// declared slot. Then it sets the completion cookie, clears volatile
/// registers, and jumps to the real OEP.
///
/// All branches use rel32 (near) jumps so the stub is robust regardless of
/// loop/table size.
#[allow(clippy::too_many_arguments)]
fn emit_two_phase_code(
    boot_rva: u32,
    _meta: &BootMetadata,
    gph_iat: u32,
    ha_iat: u32,
    original_oep_rva: u32,
    completion_cookie_rva: u32,
    image_base: u64,
) -> Result<(Vec<u8>, CodePatchPoints), HeapBootstrapError> {
    let mut s: Vec<u8> = Vec::new();

    // Prologue: push rbx,rsi,rdi,r12,r13,r14,r15 ; sub rsp,0x28
    s.extend_from_slice(&[
        0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x28,
    ]);

    // GetProcessHeap -> r14
    s.extend_from_slice(&[0xff, 0x15]);
    let gph_next = boot_rva + s.len() as u32 + 4;
    s.extend_from_slice(&rel32(gph_next, gph_iat)?);
    s.extend_from_slice(&[0x49, 0x89, 0xc6]); // mov r14, rax

    // lea r15, [rip+disp] (meta base) - patched by caller
    let meta_leia = s.len();
    s.extend_from_slice(&[0x4c, 0x8d, 0x3d, 0, 0, 0, 0]);

    // lea rbx, [rip+disp] (alloc map base) - patched by caller
    let map_lea = s.len();
    s.extend_from_slice(&[0x48, 0x8d, 0x1d, 0, 0, 0, 0]);

    // ============ Phase 1 ============
    s.extend_from_slice(&[0x45, 0x8b, 0x6f, 0x04]); // mov r13d, [r15+4]
    s.extend_from_slice(&[0x4d, 0x8b, 0x67, 0x10]); // mov r12, [r15+0x10]
    s.extend_from_slice(&[0x4d, 0x01, 0xfc]); // add r12, r15
    s.extend_from_slice(&[0x45, 0x31, 0xdb]); // xor r11d, r11d

    let p1_loop = s.len();
    s.extend_from_slice(&[0x4d, 0x85, 0xed]); // test r13d, r13d
    s.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz rel32 p1_done
    let p1_jz_done = s.len() - 4;

    s.extend_from_slice(&[0x8b, 0x4c, 0x24, 0x10]); // mov ecx, [r12+0x10]
    s.extend_from_slice(&[0x83, 0xe1, 0x01]); // and ecx, 1
    s.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz rel32 .inline
    let p1_jz_inline = s.len() - 4;

    // HeapAlloc(r14, 0, [r12+8])
    s.extend_from_slice(&[0x4c, 0x89, 0xf1]); // mov rcx, r14
    s.extend_from_slice(&[0x33, 0xd2]); // xor edx, edx
    s.extend_from_slice(&[0x45, 0x8b, 0x44, 0x24, 0x08]); // mov r8d, [r12+8]
    s.extend_from_slice(&[0xff, 0x15]);
    let ha_next = boot_rva + s.len() as u32 + 4;
    s.extend_from_slice(&rel32(ha_next, ha_iat)?);
    s.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax,rax
    s.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz rel32 p1_fail
    let p1_jz_fail = s.len() - 4;

    s.extend_from_slice(&[0x4a, 0x89, 0x04, 0xdb]); // mov [rbx+r11*8], rax
                                                    // memcpy(rax, r15+[r12+0xc], [r12+8])
    s.extend_from_slice(&[0x48, 0x89, 0xc1]); // mov rcx, rax
    s.extend_from_slice(&[0x4c, 0x89, 0xfa]); // mov rdx, r15
    s.extend_from_slice(&[0x44, 0x8b, 0x44, 0x24, 0x0c]); // mov r8d, [r12+0xc]
    s.extend_from_slice(&[0x4c, 0x01, 0xc2]); // add rdx, r8
    s.extend_from_slice(&[0x45, 0x8b, 0x44, 0x24, 0x08]); // mov r8d, [r12+8]
    s.extend_from_slice(&[0xe8, 0, 0, 0, 0]); // call memcpy
    let p1_call_memcpy = s.len() - 4;
    s.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp rel32 p1_next
    let p1_jmp_next = s.len() - 4;

    // .inline: dest = image_base + [r12+0x18]; map[index]=dest; memcpy
    let p1_inline = s.len();
    patch_rel32(&mut s, p1_jz_inline, p1_inline)?;
    s.extend_from_slice(&[0x49, 0xba]);
    s.extend_from_slice(&image_base.to_le_bytes());
    s.extend_from_slice(&[0x4d, 0x03, 0x54, 0x24, 0x18]); // add r10, [r12+0x18]
    s.extend_from_slice(&[0x4a, 0x89, 0x14, 0xdb]); // mov [rbx+r11*8], r10
    s.extend_from_slice(&[0x4c, 0x89, 0xd1]); // mov rcx, r10
    s.extend_from_slice(&[0x4c, 0x89, 0xfa]); // mov rdx, r15
    s.extend_from_slice(&[0x44, 0x8b, 0x44, 0x24, 0x0c]); // mov r8d, [r12+0xc]
    s.extend_from_slice(&[0x4c, 0x01, 0xc2]); // add rdx, r8
    s.extend_from_slice(&[0x45, 0x8b, 0x44, 0x24, 0x08]); // mov r8d, [r12+8]
    s.extend_from_slice(&[0xe8, 0, 0, 0, 0]); // call memcpy
    let p1_call_memcpy_inline = s.len() - 4;

    // .p1_next
    let p1_next = s.len();
    patch_rel32(&mut s, p1_jmp_next, p1_next)?;
    s.extend_from_slice(&[0x41, 0xff, 0xc3]); // inc r11d
    s.extend_from_slice(&[0x49, 0x83, 0xc4, 0x30]); // add r12, 0x30
    s.extend_from_slice(&[0x41, 0xff, 0xcd]); // dec r13d
    s.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jnz rel32 p1_loop
    let p1_jnz_back = s.len() - 4;
    patch_rel32(&mut s, p1_jnz_back, p1_loop)?;
    let p1_done = s.len();
    patch_rel32(&mut s, p1_jz_done, p1_done)?;

    // .p1_fail: never reach OEP. Loop forever.
    let p1_fail = s.len();
    patch_rel32(&mut s, p1_jz_fail, p1_fail)?;
    s.extend_from_slice(&[0xeb, 0xfe]); // jmp $ (infinite loop)

    // ============ Phase 2 ============
    s.extend_from_slice(&[0x45, 0x8b, 0x6f, 0x08]); // mov r13d, [r15+8]
    s.extend_from_slice(&[0x4d, 0x8b, 0x67, 0x14]); // mov r12, [r15+0x14]
    s.extend_from_slice(&[0x4d, 0x01, 0xfc]); // add r12, r15
    s.extend_from_slice(&[0x45, 0x31, 0xdb]); // xor r11d, r11d

    let p2_loop = s.len();
    s.extend_from_slice(&[0x4d, 0x85, 0xed]); // test r13d, r13d
    s.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz rel32 p2_done
    let p2_jz_done = s.len() - 4;

    s.extend_from_slice(&[0x44, 0x0f, 0xb6, 0x44, 0x24, 0x08]); // movzx r8d, byte [r12+8]
    s.extend_from_slice(&[0x41, 0x80, 0xf8, 0x00]); // cmp r8b, 0
    s.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz rel32 p2_next
    let p2_jz_null = s.len() - 4;
    s.extend_from_slice(&[0x41, 0x80, 0xf8, 0x05]); // cmp r8b, 5
    s.extend_from_slice(&[0x0f, 0x84, 0, 0, 0, 0]); // jz rel32 p2_next
    let p2_jz_tag = s.len() - 4;

    // src = alloc_map[src_region] + src_offset
    s.extend_from_slice(&[0x44, 0x8b, 0x0c, 0x24]); // mov r9d, [r12]
    s.extend_from_slice(&[0x4a, 0x8b, 0x04, 0xcb]); // mov rax, [rbx+r9*8]
    s.extend_from_slice(&[0x44, 0x8b, 0x54, 0x24, 0x04]); // mov r10d, [r12+4]
    s.extend_from_slice(&[0x4c, 0x01, 0xd0]); // add rax, r10
    s.extend_from_slice(&[0x33, 0xd2]); // xor edx, edx

    // InCapturedRegion (cls==2)
    s.extend_from_slice(&[0x41, 0x80, 0xf8, 0x02]);
    s.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jne rel32 not_intra
    let p2_jne_intra = s.len() - 4;
    s.extend_from_slice(&[0x44, 0x8b, 0x4c, 0x24, 0x0c]); // mov r9d, [r12+0xc]
    s.extend_from_slice(&[0x4a, 0x8b, 0x0c, 0xcb]); // mov rcx, [rbx+r9*8]
    s.extend_from_slice(&[0x48, 0x8b, 0x54, 0x24, 0x10]); // mov rdx, [r12+0x10]
    s.extend_from_slice(&[0x48, 0x01, 0xca]); // add rdx, rcx
    s.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp rel32 p2_write
    let p2_jmp_write = s.len() - 4;

    // InImage (cls==1)
    let p2_not_intra = s.len();
    patch_rel32(&mut s, p2_jne_intra, p2_not_intra)?;
    s.extend_from_slice(&[0x41, 0x80, 0xf8, 0x01]);
    s.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jne rel32 not_image
    let p2_jne_image = s.len() - 4;
    s.extend_from_slice(&[0x49, 0xba]);
    s.extend_from_slice(&image_base.to_le_bytes());
    s.extend_from_slice(&[0x4d, 0x03, 0x54, 0x24, 0x18]); // add r10, [r12+0x18]
    s.extend_from_slice(&[0x4c, 0x89, 0xd2]); // mov rdx, r10
    s.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp rel32 p2_write
    let p2_jmp_write2 = s.len() - 4;

    // ExternalModule (cls==3)
    let p2_not_image = s.len();
    patch_rel32(&mut s, p2_jne_image, p2_not_image)?;
    s.extend_from_slice(&[0x41, 0x80, 0xf8, 0x03]);
    s.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jne rel32 p2_unresolved
    let p2_jne_ext = s.len() - 4;
    s.extend_from_slice(&[0x4d, 0x8b, 0x4f, 0x18]); // mov r9, [r15+0x18]
    s.extend_from_slice(&[0x4d, 0x01, 0xf9]); // add r9, r15
    s.extend_from_slice(&[0x8b, 0x4c, 0x24, 0x1c]); // mov ecx, [r12+0x1c]
    s.extend_from_slice(&[0x48, 0x69, 0xc9, 0x20, 0x00, 0x00, 0x00]); // imul rcx, rcx, 0x20
    s.extend_from_slice(&[0x4c, 0x01, 0xc9]); // add rcx, r9
    s.extend_from_slice(&[0x44, 0x8b, 0x41, 0x08]); // mov r8d, [rcx+8] (iat_rva)
    s.extend_from_slice(&[0x49, 0xba]);
    s.extend_from_slice(&image_base.to_le_bytes());
    s.extend_from_slice(&[0x4c, 0x01, 0xc2]); // add rdx, r8
    s.extend_from_slice(&[0x49, 0x01, 0xd2]); // add r10, rdx
    s.extend_from_slice(&[0x4c, 0x8b, 0x12]); // mov r10, [r10]
    s.extend_from_slice(&[0x4c, 0x89, 0xd2]); // mov rdx, r10
    s.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp rel32 p2_write
    let p2_jmp_write3 = s.len() - 4;

    // .p2_write
    let p2_write = s.len();
    patch_rel32(&mut s, p2_jmp_write, p2_write)?;
    patch_rel32(&mut s, p2_jmp_write2, p2_write)?;
    patch_rel32(&mut s, p2_jmp_write3, p2_write)?;
    s.extend_from_slice(&[0x48, 0x89, 0x10]); // mov [rax], rdx

    // .p2_next
    let p2_next = s.len();
    patch_rel32(&mut s, p2_jz_null, p2_next)?;
    patch_rel32(&mut s, p2_jz_tag, p2_next)?;
    let p2_unresolved = s.len();
    patch_rel32(&mut s, p2_jne_ext, p2_unresolved)?;
    s.extend_from_slice(&[0x41, 0xff, 0xc3]); // inc r11d
    s.extend_from_slice(&[0x49, 0x83, 0xc4, 0x30]); // add r12, 0x30
    s.extend_from_slice(&[0x41, 0xff, 0xcd]); // dec r13d
    s.extend_from_slice(&[0x0f, 0x85, 0, 0, 0, 0]); // jnz rel32 p2_loop
    let p2_jnz_back = s.len() - 4;
    patch_rel32(&mut s, p2_jnz_back, p2_loop)?;
    let p2_done = s.len();
    patch_rel32(&mut s, p2_jz_done, p2_done)?;

    // ============ Completion cookie ============
    s.extend_from_slice(&[0x49, 0xba]);
    s.extend_from_slice(&image_base.to_le_bytes());
    s.extend_from_slice(&[0x49, 0x81, 0xc2]);
    s.extend_from_slice(&completion_cookie_rva.to_le_bytes());
    s.extend_from_slice(&[0xc7, 0x02, 0x01, 0x00, 0x00, 0x00]); // mov dword [r10], 1

    // ============ Clear volatile regs ============
    s.extend_from_slice(&[
        0x33, 0xc0, 0x33, 0xc9, 0x33, 0xd2, 0x4d, 0x33, 0xc0, 0x4d, 0x33, 0xc9, 0x4d, 0x33, 0xd2,
        0x4d, 0x33, 0xdb,
    ]);

    // ============ Epilogue + jmp OEP ============
    s.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
    s.extend_from_slice(&[
        0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5f, 0x5e, 0x5b,
    ]);
    s.extend_from_slice(&[0xe9, 0, 0, 0, 0]); // jmp rel32 OEP
    let jmp_oep_at = s.len() - 4;
    let jmp_oep_next = boot_rva + s.len() as u32 + 4;
    let oep_rel = i32::try_from(i64::from(original_oep_rva) - i64::from(jmp_oep_next))
        .map_err(|_| HeapBootstrapError::Codegen("OEP jump out of range".into()))?;
    s[jmp_oep_at..jmp_oep_at + 4].copy_from_slice(&oep_rel.to_le_bytes());

    // ============ inline_memcpy helper ============
    let memcpy_start = s.len();
    patch_call_rel(&mut s, p1_call_memcpy, memcpy_start)?;
    patch_call_rel(&mut s, p1_call_memcpy_inline, memcpy_start)?;
    s.extend_from_slice(&[0x57, 0x56]);
    s.extend_from_slice(&[0x48, 0x89, 0xcf, 0x48, 0x89, 0xd6, 0x4c, 0x89, 0xc1]);
    s.extend_from_slice(&[0xf3, 0xa4]); // rep movsb
    s.extend_from_slice(&[0x5e, 0x5f]);
    s.extend_from_slice(&[0xc3]); // ret

    Ok((
        s,
        CodePatchPoints {
            meta_leia_pos: meta_leia,
            map_lea_pos: map_lea,
        },
    ))
}

/// Patch points within the emitted code (byte offsets).
struct CodePatchPoints {
    meta_leia_pos: usize,
    map_lea_pos: usize,
}

/// Patch a rel32 displacement at `at` (the 4-byte operand of a 0f 84/0f 85/e9)
/// to branch to `target` (absolute byte offset within the code buffer).
fn patch_rel32(s: &mut [u8], at: usize, target: usize) -> Result<(), HeapBootstrapError> {
    // The displacement is relative to the byte after the 6-byte (jz/jnz) or
    // 5-byte (jmp) instruction. We always reserve 6 bytes for jz/jnz and 5 for
    // jmp; `at` points at the 4-byte operand which starts 2 bytes after the
    // opcode. next_ip = at + 4.
    let next_ip = at + 4;
    let disp = target as i64 - next_ip as i64;
    let d = i32::try_from(disp)
        .map_err(|_| HeapBootstrapError::Codegen("rel32 jump out of range".into()))?;
    s[at..at + 4].copy_from_slice(&d.to_le_bytes());
    Ok(())
}

fn patch_call_rel(s: &mut [u8], at: usize, target: usize) -> Result<(), HeapBootstrapError> {
    let disp = target as i64 - (at as i64 + 4);
    let d =
        i32::try_from(disp).map_err(|_| HeapBootstrapError::Codegen("call out of range".into()))?;
    s[at..at + 4].copy_from_slice(&d.to_le_bytes());
    Ok(())
}

// ---------------------------------------------------------------------------

/// Execute the emitted metadata against a set of runtime allocation bases,
/// producing the patched region payloads exactly as the stub would.
///
/// `allocation_bases[region]` = new base for heap-target region (image-inline
/// regions use their image RVA and are not in this map). Returns one payload
/// per region in plan region order.
///
/// This is the offline model execution that proves the round-trip without a
/// live sample. It consumes the **decoded metadata**, not the ideal plan patch
/// functions.
pub fn simulate_runtime_rebase(
    meta: &BootMetadata,
    allocation_bases: &[u64],
    loaded_image_base: u64,
) -> Result<Vec<Vec<u8>>, HeapBootstrapError> {
    if meta.regions.len() != allocation_bases.len() {
        return Err(HeapBootstrapError::Codegen(format!(
            "allocation_bases len {} != region count {}",
            allocation_bases.len(),
            meta.regions.len()
        )));
    }
    // Region payloads from the encoded payload area.
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(meta.regions.len());
    for (i, r) in meta.regions.iter().enumerate() {
        let off = r.data_offset as usize;
        let end = off
            .checked_add(r.size)
            .ok_or_else(|| HeapBootstrapError::Codegen("payload offset overflow".into()))?;
        if end > meta.payload.len() {
            return Err(HeapBootstrapError::Codegen(format!(
                "region {} payload out of bounds",
                i
            )));
        }
        payloads.push(meta.payload[off..end].to_vec());
    }

    // Apply fixups.
    for f in &meta.fixups {
        let src = &mut payloads[f.source_region];
        let end = f
            .source_offset
            .checked_add(8)
            .ok_or_else(|| HeapBootstrapError::Codegen("fixup offset overflow".into()))?;
        if end > src.len() {
            return Err(HeapBootstrapError::Codegen(format!(
                "fixup (region {} @ {:#x}) out of bounds",
                f.source_region, f.source_offset
            )));
        }
        let cls = classify_from_u8(f.classification);
        let new_val = match cls {
            PointerClassification::Null | PointerClassification::SmallIntegerOrTag => {
                f.original_value
            }
            PointerClassification::InCapturedRegion => {
                let t = f.target_region as usize;
                if t >= allocation_bases.len() {
                    return Err(HeapBootstrapError::UnresolvedRequired(format!(
                        "InCapturedRegion target region {t} out of range"
                    )));
                }
                allocation_bases[t].wrapping_add(f.target_offset)
            }
            PointerClassification::InImage => loaded_image_base.wrapping_add(f.image_rva as u64),
            PointerClassification::ExternalModule => {
                let idx = f.external_index as usize;
                if idx >= meta.resolvers.len() {
                    return Err(HeapBootstrapError::UnresolvedRequired(format!(
                        "external index {idx} out of range"
                    )));
                }
                let resolver = &meta.resolvers[idx];
                if resolver.iat_rva == 0 {
                    return Err(HeapBootstrapError::UnresolvedRequired(format!(
                        "external resolver {idx} has no IAT slot"
                    )));
                }
                // Resolve via cold-start IAT: read [loaded_image_base + iat_rva].
                loaded_image_base.wrapping_add(resolver.iat_rva as u64)
            }
            PointerClassification::ExternalCandidate
            | PointerClassification::Unmapped
            | PointerClassification::Ambiguous => {
                return Err(HeapBootstrapError::UnresolvedRequired(format!(
                    "unresolved-required pointer in metadata (class {})",
                    cls.label()
                )));
            }
        };
        src[f.source_offset..f.source_offset + 8].copy_from_slice(&new_val.to_le_bytes());
    }

    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dumper::container_snapshot::ContainerSnapshot;
    use crate::dumper::runtime_rebase::{
        build_runtime_rebase_plan, declared_slots_from_capture, validate_rebased_snapshots,
        DeclaredPointerSlot, ExternalTarget, RuntimeRebasePlan, SlotProvenance,
    };

    const OLD_IB: u64 = 0x140_0000_00;
    const NEW_IB: u64 = 0x140_0000_00;

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

    fn region_bytes(size: usize, pairs: &[(usize, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; size];
        for &(off, v) in pairs {
            b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    fn plan_from(containers: &[ContainerSnapshot]) -> RuntimeRebasePlan {
        let slots = declared_slots_from_capture(containers, &[], None);
        build_runtime_rebase_plan(
            containers,
            &[],
            None,
            &slots,
            &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
            &[],
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap()
    }

    fn meta_of(plan: &RuntimeRebasePlan) -> BootMetadata {
        encode_plan_metadata(plan).expect("encode")
    }

    #[test]
    fn metadata_round_trip() {
        let a = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x600000)]),
        );
        let b = container(
            0x2000,
            0x600000,
            0x600020,
            0x600040,
            region_bytes(0x20, &[]),
        );
        let plan = plan_from(&[a, b]);
        let meta = meta_of(&plan);
        let (meta_off, total) = metadata_layout(&meta, 0x100);
        let mut blob = vec![0u8; total];
        serialize_metadata_into(&mut blob, &meta, meta_off, 0x5a10, 0x2f00).unwrap();
        let decoded = decode_plan_metadata(&blob, meta_off).unwrap();
        assert_eq!(decoded.regions, meta.regions);
        assert_eq!(decoded.fixups, meta.fixups);
        assert_eq!(decoded.resolvers, meta.resolvers);
        assert_eq!(decoded.payload, meta.payload);
        assert_eq!(decoded.original_oep_rva, 0x5a10);
        assert_eq!(decoded.completion_cookie_rva, 0x2f00);
    }

    #[test]
    fn simulate_a_to_b() {
        let a = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x600000)]),
        );
        let b = container(
            0x2000,
            0x600000,
            0x600020,
            0x600040,
            region_bytes(0x20, &[]),
        );
        let plan = plan_from(&[a, b]);
        let meta = meta_of(&plan);
        let bases = [0x900000u64, 0xa00000];
        let patched = simulate_runtime_rebase(&meta, &bases, NEW_IB).unwrap();
        let a_slot = u64::from_le_bytes(patched[0][0..8].try_into().unwrap());
        assert_eq!(a_slot, 0xa00000);
        validate_rebased_snapshots(
            &plan,
            &patched.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
        )
        .unwrap();
    }

    #[test]
    fn simulate_interior_pointer() {
        let content = region_bytes(0x30, &[(0x10, 0x500020)]);
        let c = container(0x1000, 0x500000, 0x500030, 0x500040, content);
        let plan = plan_from(&[c]);
        let meta = meta_of(&plan);
        let bases = [0x900000u64];
        let patched = simulate_runtime_rebase(&meta, &bases, NEW_IB).unwrap();
        let slot = u64::from_le_bytes(patched[0][0x10..0x18].try_into().unwrap());
        assert_eq!(slot, 0x900000 + 0x20);
    }

    #[test]
    fn simulate_self_pointer() {
        let c = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        );
        let plan = plan_from(&[c]);
        let meta = meta_of(&plan);
        let patched = simulate_runtime_rebase(&meta, &[0x900000], NEW_IB).unwrap();
        let slot = u64::from_le_bytes(patched[0][0..8].try_into().unwrap());
        assert_eq!(slot, 0x900000);
    }

    #[test]
    fn simulate_cycle() {
        let a = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x600000)]),
        );
        let b = container(
            0x2000,
            0x600000,
            0x600010,
            0x600020,
            region_bytes(0x10, &[(0, 0x500000)]),
        );
        let plan = plan_from(&[a, b]);
        let meta = meta_of(&plan);
        let bases = [0x900000u64, 0xa00000];
        let patched = simulate_runtime_rebase(&meta, &bases, NEW_IB).unwrap();
        assert_eq!(
            u64::from_le_bytes(patched[0][0..8].try_into().unwrap()),
            0xa00000
        );
        assert_eq!(
            u64::from_le_bytes(patched[1][0..8].try_into().unwrap()),
            0x900000
        );
    }

    #[test]
    fn simulate_image_rva() {
        let content = region_bytes(0x10, &[(0, OLD_IB + 0x1234)]);
        let c = container(0x1000, 0x500000, 0x500010, 0x500020, content);
        let plan = plan_from(&[c]);
        let meta = meta_of(&plan);
        let loaded_base = 0x140_0000_00u64;
        let patched = simulate_runtime_rebase(&meta, &[0x900000], loaded_base).unwrap();
        assert_eq!(
            u64::from_le_bytes(patched[0][0..8].try_into().unwrap()),
            loaded_base + 0x1234
        );
    }

    #[test]
    fn encode_rejects_unresolved_required() {
        let c = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x1234_5678_9abc)]),
        );
        let slots = vec![DeclaredPointerSlot {
            region_old_base: 0x500000,
            offset: 0,
            provenance: SlotProvenance::CaptureDescriptor,
        }];
        let plan = build_runtime_rebase_plan(
            &[c],
            &[],
            None,
            &slots,
            &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
            &[],
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        assert!(encode_plan_metadata(&plan).is_err());
    }

    #[test]
    fn external_iat_resolution_roundtrip() {
        let api_va = 0x7ff9_1000_2000u64;
        let modules = vec![(
            "kernel32.dll".to_string(),
            0x7ff9_1000_0000u64,
            0x7ff9_1000_4000u64,
        )];
        let mut resolvers = crate::dumper::runtime_rebase::ExternalResolverTable::new();
        resolvers
            .insert(ExternalTarget {
                module_identity: "kernel32.dll".to_string(),
                module_rva: api_va - 0x7ff9_1000_0000,
                import_dll: "kernel32.dll".to_string(),
                import_name_or_ordinal: "HeapAlloc".to_string(),
                iat_rva: Some(0xf0100),
                resolution_kind: ExternalResolutionKind::ViaIat,
            })
            .unwrap();
        let c = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, api_va)]),
        );
        let slots = declared_slots_from_capture(&[c.clone()], &[], None);
        let plan = build_runtime_rebase_plan(
            &[c],
            &[],
            None,
            &slots,
            &resolvers,
            &modules,
            OLD_IB,
            NEW_IB,
        )
        .unwrap()
        .unwrap();
        let meta = meta_of(&plan);
        let ext_fixup = meta
            .fixups
            .iter()
            .find(|f| f.classification == 3)
            .expect("external fixup");
        assert_eq!(ext_fixup.external_index, 0);
        let loaded_base = 0x140_0000_00u64;
        let iat_slot = loaded_base + 0xf0100;
        let patched = simulate_runtime_rebase(&meta, &[0x900000], loaded_base).unwrap();
        let slot = u64::from_le_bytes(patched[0][0..8].try_into().unwrap());
        assert_eq!(slot, iat_slot);
    }

    #[test]
    fn all_bases_change_no_old_pointer() {
        let a = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x600000)]),
        );
        let b = container(
            0x2000,
            0x600000,
            0x600020,
            0x600040,
            region_bytes(0x20, &[]),
        );
        let plan = plan_from(&[a, b]);
        let meta = meta_of(&plan);
        let bases = [0x900000u64, 0xa00000];
        let patched = simulate_runtime_rebase(&meta, &bases, NEW_IB).unwrap();
        let payloads: Vec<&[u8]> = patched.iter().map(|v| v.as_slice()).collect();
        validate_rebased_snapshots(&plan, &payloads).unwrap();
    }

    #[test]
    fn stub_emits_two_phase_and_oep_jump() {
        let c = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        );
        let plan = plan_from(&[c]);
        let meta = meta_of(&plan);
        let code = emit_two_phase_code(0x2000, &meta, 0x2100, 0x2108, 0x5a10, 0x2f00, NEW_IB)
            .expect("codegen")
            .0;
        assert!(
            code.windows(2).any(|w| w == [0xff, 0x15]),
            "GetProcessHeap/HeapAlloc call"
        );
        assert!(
            code.windows(6)
                .any(|w| w == [0xc7, 0x02, 0x01, 0x00, 0x00, 0x00]),
            "completion cookie store"
        );
        assert!(code.iter().any(|&b| b == 0xe9), "OEP near jump");
        assert!(
            code.windows(2).any(|w| w == [0x41, 0x57]),
            "push r15 prologue"
        );
    }
}
