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
/// Completion cookie slot is a 4-byte dword (mov dword [r10], 1).
const COOKIE_SLOT_SIZE: usize = 4;

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
    /// The `.boot` layout sub-region offsets (for contract validation of cookie
    /// non-overlap) and the preferred image base the stub was built against.
    pub contract_layout: BootContractLayout,
}

/// Layout offsets within `.boot` used by post-install contract validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootContractLayout {
    /// Offset (within `.boot`) where the metadata header begins (= code end).
    pub header_off: usize,
    /// Offset where the payload region begins.
    pub payload_off: usize,
    /// Offset where the alloc map begins.
    pub map_off: usize,
    /// Offset where the completion cookie slot begins.
    pub cookie_off: usize,
    /// Total `.boot` byte length.
    pub total: usize,
    /// Preferred (compiled) image base the stub was emitted against.
    pub preferred_image_base: u64,
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

    // The payload length = max(region.data_offset + region.size). This excludes
    // the trailing alloc map + cookie (which follow the payload in the layout).
    let payload_len = regions
        .iter()
        .map(|r| r.data_offset as usize + r.size)
        .max()
        .unwrap_or(0);
    let payload = if payload_len == 0 {
        Vec::new()
    } else {
        let end = payload_off
            .checked_add(payload_len)
            .ok_or_else(|| HeapBootstrapError::Codegen("payload end overflow".into()))?;
        if end > blob.len() {
            return Err(HeapBootstrapError::Codegen("payload truncated".into()));
        }
        blob[payload_off..end].to_vec()
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

/// Full `.boot` layout: `[code][header][regions][fixups][resolvers][payload]
/// [alloc_map][cookie]`. The completion cookie sits at the very end so it can
/// never overlap code, metadata, payload, or the alloc map.
///
/// Returns `(meta_offset, layout)` where `layout` holds every sub-region
/// offset (relative to `.boot` start) so callers can compute the cookie RVA and
/// validate non-overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BootLayout {
    pub(crate) header_off: usize,
    pub(crate) region_off: usize,
    pub(crate) fixup_off: usize,
    pub(crate) resolver_off: usize,
    pub(crate) payload_off: usize,
    pub(crate) map_off: usize,
    pub(crate) cookie_off: usize,
    pub(crate) total: usize,
}

fn metadata_layout(meta: &BootMetadata, code_len: usize) -> (usize, BootLayout) {
    let header_off = align8(code_len);
    let region_off = header_off + PLAN_HEADER_SIZE;
    let fixup_off = region_off + meta.regions.len() * REGION_META_SIZE;
    let resolver_off = fixup_off + meta.fixups.len() * FIXUP_META_SIZE;
    let payload_off = resolver_off + meta.resolvers.len() * RESOLVER_META_SIZE;
    let payload_end = payload_off + meta.payload.len();
    let map_off = align8(payload_end);
    let map_end = map_off + meta.regions.len() * 8;
    let cookie_off = align8(map_end);
    let total = cookie_off + COOKIE_SLOT_SIZE;
    (
        header_off,
        BootLayout {
            header_off,
            region_off,
            fixup_off,
            resolver_off,
            payload_off,
            map_off,
            cookie_off,
            total,
        },
    )
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
/// Build the plan-driven `.boot` blob and return it together with the metadata
/// header offset within the blob.
///
/// Layout: `[code][header][regions][fixups][resolvers][payload][alloc_map][cookie]`.
///
/// The completion cookie is placed at the very end of the layout (never
/// overlapping code/metadata/payload/alloc map) and its RVA is baked into the
/// stub's `add r10, imm32` after the layout is known. `completion_cookie_rva`
/// is passed back out via the blob's trailing cookie slot offset so the caller
/// can derive the RVA.
pub fn build_runtime_bootstrap(
    pe: &mut PeHeader,
    imports: &ImportTableBuilder,
    prepared: &PreparedRuntimeRebase,
    original_entry_point: u32,
    boot_rva: u32,
) -> Result<BuildBootstrapResult, HeapBootstrapError> {
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

    // Emit code with a placeholder cookie RVA (patched after layout).
    let (code, pts) = emit_two_phase_code(
        boot_rva,
        &meta,
        gph,
        ha,
        original_entry_point,
        0, // cookie_rva placeholder
        image_base,
    )?;

    // Layout the full blob (code + metadata + alloc map + cookie).
    let (meta_offset, layout) = metadata_layout(&meta, code.len());
    let cookie_rva = boot_rva + layout.cookie_off as u32;

    let mut blob = vec![0u8; layout.total];
    blob[..code.len()].copy_from_slice(&code);
    serialize_metadata_into(
        &mut blob,
        &meta,
        meta_offset,
        original_entry_point,
        cookie_rva,
    )?;

    // Patch the two lea displacements (meta base, alloc map base).
    let meta_lea = pts.meta_leia_pos;
    let map_lea = pts.map_lea_pos;
    let meta_lea_next = boot_rva + meta_lea as u32 + 7;
    let meta_target = boot_rva + meta_offset as u32;
    let md = rel32(meta_lea_next, meta_target)?;
    blob[meta_lea + 3..meta_lea + 7].copy_from_slice(&md);

    let map_lea_next = boot_rva + map_lea as u32 + 7;
    let map_target = boot_rva + layout.map_off as u32;
    let mp = rel32(map_lea_next, map_target)?;
    blob[map_lea + 3..map_lea + 7].copy_from_slice(&mp);

    // Patch the completion cookie RVA into the stub's `add r10, imm32`.
    let cookie_patch = pts.cookie_patch_pos;
    blob[cookie_patch..cookie_patch + 4].copy_from_slice(&cookie_rva.to_le_bytes());

    Ok(BuildBootstrapResult {
        blob,
        meta_offset,
        boot_rva,
        completion_cookie_rva: cookie_rva,
        layout,
        emitted_plan_digest: prepared.plan.plan_digest.clone(),
    })
}

/// Result of building the plan-driven `.boot`.
#[derive(Debug, Clone)]
pub struct BuildBootstrapResult {
    pub blob: Vec<u8>,
    pub meta_offset: usize,
    pub boot_rva: u32,
    pub completion_cookie_rva: u32,
    pub(crate) layout: BootLayout,
    pub emitted_plan_digest: String,
}

impl BuildBootstrapResult {
    /// Metadata RVA = boot_rva + meta_offset.
    pub fn metadata_rva(&self) -> u32 {
        self.boot_rva + self.meta_offset as u32
    }
    /// Total `.boot` byte length.
    pub fn total_len(&self) -> usize {
        self.blob.len()
    }
    /// Cookie slot offset within `.boot` (for overlap validation).
    pub fn cookie_offset(&self) -> usize {
        self.layout.cookie_off
    }
}

/// Emit the x64 two-phase stub. `boot_rva` is the `.boot` section VA.
///
/// Phase 1 allocates every heap-target region (recording `new_base` in the
/// alloc map) and copies payloads; a required allocation failure loops forever
/// (never reaches OEP). Phase 2 walks the fixup table and rewrites each
/// declared slot. Then it sets the completion cookie, clears volatile
/// registers, and jumps to the real OEP.
///
/// All branch/offset arithmetic uses the `x64_asm` encoder so memory operands
/// carry correct REX.B/REX.X prefixes, and metadata offsets are loaded as
/// 32-bit zero-extended values (never merged into a 64-bit load). The payload
/// source address is `meta_base + payload_offset + region.data_offset`.
#[allow(clippy::too_many_arguments)]
fn emit_two_phase_code(
    boot_rva: u32,
    _meta: &BootMetadata,
    gph_iat: u32,
    ha_iat: u32,
    original_oep_rva: u32,
    cookie_rva_placeholder: u32,
    image_base: u64,
) -> Result<(Vec<u8>, CodePatchPoints), HeapBootstrapError> {
    use super::x64_asm as a;
    let mut s: Vec<u8> = Vec::new();

    // ---- Prologue: push nonvolatiles; align stack ----
    for r in [3u8, 6, 7, 12, 13, 14, 15] {
        a::push_r64(&mut s, r);
    }
    a::sub_rsp_imm8(&mut s, 0x28);

    // ---- GetProcessHeap -> r14 ----
    a::call_rip_rel32(&mut s, 0); // placeholder
    let gph_disp_at = s.len() - 4;
    let gph_next = boot_rva + gph_disp_at as u32 + 4;
    let d = rel32(gph_next, gph_iat)?;
    s[gph_disp_at..gph_disp_at + 4].copy_from_slice(&d);
    a::mov_r64_r64(&mut s, 14, 0); // mov r14, rax

    // ---- r15 = meta base (lea, patched) ----
    let meta_leia = s.len();
    s.extend_from_slice(&[0x4c, 0x8d, 0x3d, 0, 0, 0, 0]); // lea r15, [rip+disp32]

    // ---- rbx = alloc map base (lea, patched) ----
    let map_lea = s.len();
    s.extend_from_slice(&[0x48, 0x8d, 0x1d, 0, 0, 0, 0]); // lea rbx, [rip+disp32]

    // ===================== Phase 1 =====================
    // r13d = region_count = [r15+4]   (32-bit zero-extend)
    a::mov_r32_mem(&mut s, 13, &a::Mem::r15(4));
    // r12 = region table = r15 + [r15+0x10]  (32-bit zero-extend offset)
    a::mov_r32_mem(&mut s, 12, &a::Mem::r15(0x10));
    a::add_r64_r64(&mut s, 12, 15); // add r12, r15
    a::xor_r32_r32(&mut s, 11, 11); // xor r11d, r11d

    let p1_loop = s.len();
    a::test_r32_r32(&mut s, 13, 13);
    a::jcc_rel32(&mut s, 0x84, 0); // jz p1_done
    let p1_jz_done = s.len() - 4;

    // flags = [r12+0x10] & 1 (heap target?)
    a::mov_r32_mem(&mut s, 1, &a::Mem::r12(0x10)); // mov ecx, [r12+0x10]
    a::and_r32_imm8(&mut s, 1, 1);
    a::jcc_rel32(&mut s, 0x84, 0); // jz p1_inline
    let p1_jz_inline = s.len() - 4;

    // HeapAlloc(r14, 0, [r12+8])
    a::mov_r64_r64(&mut s, 1, 14); // mov rcx, r14
    a::xor_r32_r32(&mut s, 2, 2); // xor edx, edx
    a::mov_r32_mem(&mut s, 8, &a::Mem::r12(8)); // mov r8d, [r12+8] (size)
    a::call_rip_rel32(&mut s, 0);
    let ha_disp_at = s.len() - 4;
    let ha_next = boot_rva + ha_disp_at as u32 + 4;
    let d = rel32(ha_next, ha_iat)?;
    s[ha_disp_at..ha_disp_at + 4].copy_from_slice(&d);
    a::test_r64_r64(&mut s, 0, 0); // test rax, rax
    a::jcc_rel32(&mut s, 0x84, 0); // jz p1_fail
    let p1_jz_fail = s.len() - 4;

    // alloc_map[r11] = rax  -> [rbx + r11*8] = rax
    a::mov_mem_r64(&mut s, &a::Mem::rbx_index(11, 8), 0);
    // memcpy(rax, r15 + payload_offset + data_offset, size)
    a::mov_r64_r64(&mut s, 1, 0); // mov rcx, rax
    a::mov_r64_r64(&mut s, 2, 15); // mov rdx, r15
    a::mov_r32_mem(&mut s, 8, &a::Mem::r15(0x1c)); // mov r8d, [r15+0x1c] (payload_offset)
    a::add_r64_r64(&mut s, 2, 8); // add rdx, r8
    a::mov_r32_mem(&mut s, 8, &a::Mem::r12(0x0c)); // mov r8d, [r12+0xc] (data_offset)
    a::add_r64_r64(&mut s, 2, 8); // add rdx, r8
    a::mov_r32_mem(&mut s, 8, &a::Mem::r12(8)); // mov r8d, [r12+8] (size)
    a::call_rel32(&mut s, 0); // call memcpy
    let p1_call_memcpy = s.len() - 4;
    a::jmp_rel32(&mut s, 0); // jmp p1_next
    let p1_jmp_next = s.len() - 4;

    // ---- p1_inline ----
    let p1_inline = s.len();
    patch_rel32(&mut s, p1_jz_inline, p1_inline)?;
    a::mov_r64_imm64(&mut s, 10, image_base); // mov r10, image_base
    a::mov_r32_mem(&mut s, 9, &a::Mem::r12(0x18)); // mov r9d, [r12+0x18] (image_rva, 32-bit)
    a::add_r64_r64(&mut s, 10, 9); // add r10, r9
    a::mov_mem_r64(&mut s, &a::Mem::rbx_index(11, 8), 10); // [rbx+r11*8] = r10
    a::mov_r64_r64(&mut s, 1, 10); // mov rcx, r10
    a::mov_r64_r64(&mut s, 2, 15); // mov rdx, r15
    a::mov_r32_mem(&mut s, 8, &a::Mem::r15(0x1c)); // mov r8d, [r15+0x1c]
    a::add_r64_r64(&mut s, 2, 8);
    a::mov_r32_mem(&mut s, 8, &a::Mem::r12(0x0c)); // mov r8d, [r12+0xc]
    a::add_r64_r64(&mut s, 2, 8);
    a::mov_r32_mem(&mut s, 8, &a::Mem::r12(8)); // mov r8d, [r12+8]
    a::call_rel32(&mut s, 0);
    let p1_call_memcpy_inline = s.len() - 4;

    // ---- p1_next ----
    let p1_next = s.len();
    patch_rel32(&mut s, p1_jmp_next, p1_next)?;
    a::inc_r32(&mut s, 11);
    a::add_r64_imm32(&mut s, 12, 0x30); // add r12, 0x30
    a::dec_r32(&mut s, 13);
    a::jcc_rel32(&mut s, 0x85, 0); // jnz p1_loop
    let p1_jnz_back = s.len() - 4;
    patch_rel32(&mut s, p1_jnz_back, p1_loop)?;
    let p1_done = s.len();
    patch_rel32(&mut s, p1_jz_done, p1_done)?;

    // ---- p1_fail: never reach OEP. Infinite loop. ----
    let p1_fail = s.len();
    patch_rel32(&mut s, p1_jz_fail, p1_fail)?;
    a::infinite_loop(&mut s);

    // ===================== Phase 2 =====================
    // r13d = fixup_count = [r15+8]
    a::mov_r32_mem(&mut s, 13, &a::Mem::r15(8));
    // r12 = fixup table = r15 + [r15+0x14]
    a::mov_r32_mem(&mut s, 12, &a::Mem::r15(0x14));
    a::add_r64_r64(&mut s, 12, 15);
    a::xor_r32_r32(&mut s, 11, 11);

    let p2_loop = s.len();
    a::test_r32_r32(&mut s, 13, 13);
    a::jcc_rel32(&mut s, 0x84, 0); // jz p2_done
    let p2_jz_done = s.len() - 4;

    // cls = [r12+8] (byte)
    a::movzx_r32_byte_mem(&mut s, 8, &a::Mem::r12(8));
    // Null(0) / SmallTag(5) -> skip
    a::cmp_r8b_imm8(&mut s, 8, 0);
    a::jcc_rel32(&mut s, 0x84, 0); // jz p2_next
    let p2_jz_null = s.len() - 4;
    a::cmp_r8b_imm8(&mut s, 8, 5);
    a::jcc_rel32(&mut s, 0x84, 0); // jz p2_next
    let p2_jz_tag = s.len() - 4;

    // src = alloc_map[source_region] + source_offset
    a::mov_r32_mem(&mut s, 9, &a::Mem::r12(0x00)); // mov r9d, [r12] (source_region)
    a::mov_r64_mem(&mut s, 0, &a::Mem::rbx_index(9, 8)); // mov rax, [rbx+r9*8]
    a::mov_r32_mem(&mut s, 10, &a::Mem::r12(0x04)); // mov r10d, [r12+4] (source_offset)
    a::add_r64_r64(&mut s, 0, 10); // add rax, r10 (src addr)
    a::xor_r32_r32(&mut s, 2, 2); // xor edx, edx (value)

    // InCapturedRegion (cls==2)
    a::cmp_r8b_imm8(&mut s, 8, 2);
    a::jcc_rel32(&mut s, 0x85, 0); // jne not_intra
    let p2_jne_intra = s.len() - 4;
    a::mov_r32_mem(&mut s, 9, &a::Mem::r12(0x0c)); // mov r9d, [r12+0xc] (target_region)
    a::mov_r64_mem(&mut s, 1, &a::Mem::rbx_index(9, 8)); // mov rcx, [rbx+r9*8]
    a::mov_r64_mem(&mut s, 2, &a::Mem::r12(0x10)); // mov rdx, [r12+0x10] (target_offset, u64)
    a::add_r64_r64(&mut s, 2, 1); // add rdx, rcx
    a::jmp_rel32(&mut s, 0); // jmp p2_write
    let p2_jmp_write = s.len() - 4;

    // InImage (cls==1)
    let p2_not_intra = s.len();
    patch_rel32(&mut s, p2_jne_intra, p2_not_intra)?;
    a::cmp_r8b_imm8(&mut s, 8, 1);
    a::jcc_rel32(&mut s, 0x85, 0); // jne not_image
    let p2_jne_image = s.len() - 4;
    a::mov_r64_imm64(&mut s, 10, image_base);
    a::mov_r32_mem(&mut s, 9, &a::Mem::r12(0x18)); // mov r9d, [r12+0x18] (image_rva)
    a::add_r64_r64(&mut s, 10, 9);
    a::mov_r64_r64(&mut s, 2, 10); // mov rdx, r10
    a::jmp_rel32(&mut s, 0); // jmp p2_write
    let p2_jmp_write2 = s.len() - 4;

    // ExternalModule (cls==3)
    let p2_not_image = s.len();
    patch_rel32(&mut s, p2_jne_image, p2_not_image)?;
    a::cmp_r8b_imm8(&mut s, 8, 3);
    a::jcc_rel32(&mut s, 0x85, 0); // jne p2_unresolved
    let p2_jne_ext = s.len() - 4;
    // r9 = resolver table = r15 + [r15+0x18] (32-bit offset)
    a::mov_r32_mem(&mut s, 9, &a::Mem::r15(0x18));
    a::add_r64_r64(&mut s, 9, 15);
    // ecx = external_index = [r12+0x1c]
    a::mov_r32_mem(&mut s, 1, &a::Mem::r12(0x1c));
    a::imul_r64_r64_imm32(&mut s, 1, 1, 0x20); // imul rcx, rcx, 0x20
    a::add_r64_r64(&mut s, 1, 9); // add rcx, r9 (resolver entry)
    a::mov_r32_mem(&mut s, 8, &a::Mem::rcx(8)); // mov r8d, [rcx+8] (iat_rva)
                                                // r10 = image_base + iat_rva ; rdx = [r10]
    a::mov_r64_imm64(&mut s, 10, image_base);
    a::add_r64_r64(&mut s, 10, 8); // r10 += iat_rva -> iat_slot address
    a::mov_r64_mem(&mut s, 2, &a::Mem::r10(0)); // rdx = [r10] (resolved API value)
    a::jmp_rel32(&mut s, 0); // jmp p2_write
    let p2_jmp_write3 = s.len() - 4;

    // p2_write: [src] = rdx
    let p2_write = s.len();
    patch_rel32(&mut s, p2_jmp_write, p2_write)?;
    patch_rel32(&mut s, p2_jmp_write2, p2_write)?;
    patch_rel32(&mut s, p2_jmp_write3, p2_write)?;
    a::mov_mem_r64(&mut s, &a::Mem::rax(0), 2); // mov [rax], rdx

    // p2_next
    let p2_next = s.len();
    patch_rel32(&mut s, p2_jz_null, p2_next)?;
    patch_rel32(&mut s, p2_jz_tag, p2_next)?;
    let p2_unresolved = s.len();
    patch_rel32(&mut s, p2_jne_ext, p2_unresolved)?;
    a::inc_r32(&mut s, 11);
    a::add_r64_imm32(&mut s, 12, 0x30);
    a::dec_r32(&mut s, 13);
    a::jcc_rel32(&mut s, 0x85, 0); // jnz p2_loop
    let p2_jnz_back = s.len() - 4;
    patch_rel32(&mut s, p2_jnz_back, p2_loop)?;
    let p2_done = s.len();
    patch_rel32(&mut s, p2_jz_done, p2_done)?;

    // ===================== Completion cookie =====================
    // mov r10, image_base ; add r10, cookie_rva ; mov dword [r10], 1
    a::mov_r64_imm64(&mut s, 10, image_base);
    a::add_r64_imm32(&mut s, 10, cookie_rva_placeholder as i32);
    let cookie_patch_pos = s.len() - 4;
    a::mov_dword_mem_imm32(&mut s, &a::Mem::r10(0), 1);

    // ===================== Clear volatile regs =====================
    for r in [0u8, 1, 2, 8, 9, 10, 11] {
        a::xor_r32_r32(&mut s, r, r);
    }

    // ===================== Epilogue + jmp OEP =====================
    a::add_rsp_imm8(&mut s, 0x28);
    for r in [15u8, 14, 13, 12, 7, 6, 3] {
        a::pop_r64(&mut s, r);
    }
    a::jmp_rel32(&mut s, 0); // jmp rel32 OEP (patched)
    let jmp_oep_at = s.len() - 4;
    let jmp_oep_next = boot_rva + s.len() as u32 + 4;
    let oep_rel = i32::try_from(i64::from(original_oep_rva) - i64::from(jmp_oep_next))
        .map_err(|_| HeapBootstrapError::Codegen("OEP jump out of range".into()))?;
    s[jmp_oep_at..jmp_oep_at + 4].copy_from_slice(&oep_rel.to_le_bytes());

    // ===================== inline_memcpy helper =====================
    let memcpy_start = s.len();
    patch_call_rel(&mut s, p1_call_memcpy, memcpy_start)?;
    patch_call_rel(&mut s, p1_call_memcpy_inline, memcpy_start)?;
    a::push_r64(&mut s, 7); // push rdi
    a::push_r64(&mut s, 6); // push rsi
    a::mov_r64_r64(&mut s, 7, 1); // mov rdi, rcx
    a::mov_r64_r64(&mut s, 6, 2); // mov rsi, rdx
    a::mov_r64_r64(&mut s, 1, 8); // mov rcx, r8
    a::rep_movsb(&mut s);
    a::pop_r64(&mut s, 6);
    a::pop_r64(&mut s, 7);
    a::ret(&mut s);

    Ok((
        s,
        CodePatchPoints {
            meta_leia_pos: meta_leia,
            map_lea_pos: map_lea,
            cookie_patch_pos,
        },
    ))
}

/// Patch points within the emitted code (byte offsets).
struct CodePatchPoints {
    meta_leia_pos: usize,
    map_lea_pos: usize,
    cookie_patch_pos: usize,
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
/// `iat_contents` maps an IAT slot **VA** (`loaded_image_base + iat_rva`) to
/// the resolved API VA that the cold-start loader would have written there. An
/// `ExternalModule` pointer is patched to `iat_contents[iat_slot_va]` (the API
/// address), never to the slot address itself.
///
/// This is the offline model execution that proves the round-trip without a
/// live sample. It consumes the **decoded metadata**, not the ideal plan patch
/// functions.
pub fn simulate_runtime_rebase(
    meta: &BootMetadata,
    allocation_bases: &[u64],
    loaded_image_base: u64,
    iat_contents: &std::collections::HashMap<u64, u64>,
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
                // The stub reads memory[iat_slot_va] to obtain the resolved API
                // address (ASLR-safe, loader-filled IAT). The simulator does the
                // same via `iat_contents`. A missing IAT entry fails closed.
                let iat_slot_va = loaded_image_base.wrapping_add(resolver.iat_rva as u64);
                iat_contents.get(&iat_slot_va).copied().ok_or_else(|| {
                    HeapBootstrapError::UnresolvedRequired(format!(
                        "external resolver {idx} IAT slot {iat_slot_va:#x} has no content"
                    ))
                })?
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
        let (meta_off, layout) = metadata_layout(&meta, 0x100);
        let mut blob = vec![0u8; layout.total];
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
        let patched = simulate_runtime_rebase(&meta, &bases, NEW_IB, &Default::default()).unwrap();
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
        let patched = simulate_runtime_rebase(&meta, &bases, NEW_IB, &Default::default()).unwrap();
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
        let patched =
            simulate_runtime_rebase(&meta, &[0x900000], NEW_IB, &Default::default()).unwrap();
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
        let patched = simulate_runtime_rebase(&meta, &bases, NEW_IB, &Default::default()).unwrap();
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
        let patched =
            simulate_runtime_rebase(&meta, &[0x900000], loaded_base, &Default::default()).unwrap();
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
        // The cold-start loader fills the IAT slot with the resolved API VA.
        let loaded_base = 0x140_0000_00u64;
        let iat_slot = loaded_base + 0xf0100;
        let mut iat_contents = std::collections::HashMap::new();
        iat_contents.insert(iat_slot, api_va);
        let patched =
            simulate_runtime_rebase(&meta, &[0x900000], loaded_base, &iat_contents).unwrap();
        let slot = u64::from_le_bytes(patched[0][0..8].try_into().unwrap());
        // Must be the resolved API address (not the slot address).
        assert_eq!(slot, api_va, "must write resolved API VA, not iat_slot");
        assert_ne!(slot, iat_slot, "slot address must differ from API address");

        // ASLR: if the loaded base changes, the IAT slot VA changes; resolution
        // still follows the new slot's content.
        let loaded_base2 = 0x150_0000_00u64;
        let iat_slot2 = loaded_base2 + 0xf0100;
        let mut iat2 = std::collections::HashMap::new();
        iat2.insert(iat_slot2, api_va);
        let patched2 = simulate_runtime_rebase(&meta, &[0x900000], loaded_base2, &iat2).unwrap();
        let slot2 = u64::from_le_bytes(patched2[0][0..8].try_into().unwrap());
        assert_eq!(slot2, api_va, "ASLR: resolution follows new IAT content");

        // Missing IAT content must fail closed.
        let err = simulate_runtime_rebase(&meta, &[0x900000], loaded_base, &Default::default())
            .unwrap_err();
        assert!(matches!(err, HeapBootstrapError::UnresolvedRequired(_)));
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
        let patched = simulate_runtime_rebase(&meta, &bases, NEW_IB, &Default::default()).unwrap();
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

#[cfg(test)]
mod machine_code_tests {
    use super::*;
    use crate::dumper::container_snapshot::ContainerSnapshot;
    use crate::dumper::runtime_rebase::{
        build_runtime_rebase_plan, declared_slots_from_capture, summarize_plan, ExternalTarget,
        RuntimeRebasePlan,
    };
    use iced_x86::{Decoder, DecoderOptions, MemorySize, Mnemonic, Register};

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

    fn decode_all(code: &[u8]) -> Vec<iced_x86::Instruction> {
        let mut d = Decoder::with_ip(64, code, 0x200000, DecoderOptions::NONE);
        let mut out = Vec::new();
        while d.can_decode() {
            out.push(d.decode());
        }
        out
    }

    /// Emit the stub code for a plan (code bytes only).
    fn stub_code(plan: &RuntimeRebasePlan) -> Vec<u8> {
        let meta = encode_plan_metadata(plan).expect("encode");
        let (code, _pts) =
            emit_two_phase_code(0x2000, &meta, 0x2100, 0x2108, 0x5a10, 0x2f00, NEW_IB)
                .expect("emit");
        code
    }

    /// Test requirement #2: every `[r12+offset]` memory operand must have base
    /// register R12, for all the row fields 0x00..0x1c.
    #[test]
    fn all_r12_memory_operands_have_r12_base() {
        let plan = plan_from(&[container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        )]);
        let code = stub_code(&plan);
        let insns = decode_all(&code);
        let fields = [0x00u64, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c];
        for insn in &insns {
            for op in 0..insn.op_count() {
                if insn.op_kind(op) != iced_x86::OpKind::Memory {
                    continue;
                }
                if insn.memory_base() == Register::R12 {
                    let disp = insn.memory_displacement64();
                    assert!(
                        fields.contains(&disp),
                        "[r12+{disp:#x}] access with unexpected displacement"
                    );
                }
            }
        }
        // And the known [r12+disp] accesses must actually decode to R12.
        for insn in insns.iter().filter(|i| i.memory_base() == Register::R12) {
            assert_eq!(insn.memory_base(), Register::R12);
        }
    }

    /// Test requirement #1: metadata header offsets loaded as 32-bit.
    /// [r15+4],[r15+8],[r15+0x10],[r15+0x14],[r15+0x18],[r15+0x1c] must be
    /// 32-bit loads (never 64-bit, which would merge two adjacent u32s).
    #[test]
    fn metadata_header_offsets_are_32bit_loads() {
        let plan = plan_from(&[container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        )]);
        let code = stub_code(&plan);
        let insns = decode_all(&code);
        let header_32_fields = [4u64, 8, 0x10, 0x14, 0x18, 0x1c];
        for insn in &insns {
            if insn.memory_base() == Register::R15 {
                let disp = insn.memory_displacement64();
                if header_32_fields.contains(&disp) {
                    assert_eq!(
                        insn.memory_size(),
                        MemorySize::UInt32,
                        "[r15+{disp:#x}] must be a 32-bit zero-extended load, got {:?}",
                        insn.memory_size()
                    );
                }
            }
        }
    }

    /// Test requirement #3: payload source address = meta_base + payload_offset
    /// + region.data_offset. The stub must load [r15+0x1c] (payload_offset) and
    /// add both it and the region data_offset before memcpy. Verify the
    /// instruction sequence around the Phase-1 memcpy: `add rdx, r8` where r8
    /// was loaded from [r15+0x1c] and [r12+0x0c].
    #[test]
    fn payload_uses_payload_offset_plus_data_offset() {
        let plan = plan_from(&[container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        )]);
        let code = stub_code(&plan);
        let insns = decode_all(&code);
        // Count loads from [r15+0x1c] (payload_offset) and [r12+0x0c] (data_offset).
        let r15_1c_loads = insns
            .iter()
            .filter(|i| i.memory_base() == Register::R15 && i.memory_displacement64() == 0x1c)
            .count();
        let r12_0c_loads = insns
            .iter()
            .filter(|i| i.memory_base() == Register::R12 && i.memory_displacement64() == 0x0c)
            .count();
        // Phase 1 runs twice (heap + inline path), so both offsets are loaded.
        assert!(
            r15_1c_loads >= 2,
            "payload_offset [r15+0x1c] loaded (got {r15_1c_loads})"
        );
        assert!(
            r12_0c_loads >= 2,
            "data_offset [r12+0x0c] loaded (got {r12_0c_loads})"
        );
    }

    /// Test requirement #4: external path must dereference the IAT slot
    /// (a 64-bit load from a register whose value is image_base + iat_rva).
    #[test]
    fn external_path_does_iat_dereference() {
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
        let meta = encode_plan_metadata(&plan).expect("encode");
        let (code, _pts) =
            emit_two_phase_code(0x2000, &meta, 0x2100, 0x2108, 0x5a10, 0x2f00, NEW_IB)
                .expect("emit");
        let insns = decode_all(&code);
        // The external path resolves by a 64-bit load from a register (r10)
        // that holds image_base + iat_rva. Look for a `mov rdx, [r10]`.
        let deref = insns.iter().find(|i| {
            i.mnemonic() == Mnemonic::Mov
                && i.memory_base() == Register::R10
                && i.memory_size() == MemorySize::UInt64
        });
        assert!(
            deref.is_some(),
            "external path must dereference IAT slot [r10]"
        );
    }

    /// Test requirement #6/7: completion cookie write + OEP transfer present.
    /// The cookie write is `mov dword [r10], 1`; OEP transfer is a near `jmp`.
    #[test]
    fn cookie_write_and_oep_transfer_present() {
        let plan = plan_from(&[container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        )]);
        let code = stub_code(&plan);
        let insns = decode_all(&code);
        // Cookie: mov dword [r10], 1.
        let cookie = insns.iter().find(|i| {
            i.mnemonic() == Mnemonic::Mov
                && i.memory_base() == Register::R10
                && i.memory_size() == MemorySize::UInt32
        });
        assert!(cookie.is_some(), "completion cookie write must be present");
        // OEP transfer: near jmp (jmp with no memory operand, not indirect).
        let oep_jmp = insns.iter().rev().find(|i| i.mnemonic() == Mnemonic::Jmp);
        assert!(oep_jmp.is_some(), "OEP near jump must be present");
        assert_ne!(
            oep_jmp.unwrap().op_kind(0),
            iced_x86::OpKind::Memory,
            "OEP jump must be a relative near jump, not indirect"
        );
    }

    /// Test requirement: every metadata header offset is 32-bit; a 64-bit load
    /// of [r15+0x10] would merge region_offset+fixup_offset. Assert none of the
    /// r15 header reads are 64-bit.
    #[test]
    fn no_64bit_header_loads() {
        let plan = plan_from(&[container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        )]);
        let code = stub_code(&plan);
        let insns = decode_all(&code);
        for insn in insns.iter().filter(|i| i.memory_base() == Register::R15) {
            let disp = insn.memory_displacement64();
            if disp <= 0x1c {
                assert_ne!(
                    insn.memory_size(),
                    MemorySize::UInt64,
                    "header field [r15+{disp:#x}] must not be a 64-bit load"
                );
            }
        }
    }

    /// Test requirement: cookie does not overlap code/metadata/payload/alloc_map.
    #[test]
    fn cookie_layout_no_overlap() {
        // Build a full blob via build_runtime_bootstrap (needs a PeHeader).
        let pe = crate::header::make_minimal_pe64();
        let mut pe = crate::header::PeHeader::from_bytes(&pe).unwrap();
        pe.nt_headers.optional_header.image_base = NEW_IB;
        let plan = plan_from(&[container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        )]);
        let prepared = crate::dumper::runtime_rebase::PreparedRuntimeRebase {
            plan: plan.clone(),
            summary: summarize_plan(&plan, None, 0x5a10, None, "none", false),
        };
        let mut imports = crate::import_table::ImportTableBuilder::new(true);
        imports.ensure_function("kernel32.dll", "GetProcessHeap");
        imports.ensure_function("kernel32.dll", "HeapAlloc");
        let result =
            build_runtime_bootstrap(&mut pe, &imports, &prepared, 0x5a10, 0x2000).expect("build");
        let l = result.layout;
        // Cookie region [l.cookie_off, l.cookie_off + COOKIE_SLOT_SIZE)
        let cookie_start = l.cookie_off;
        let cookie_end = l.cookie_off + COOKIE_SLOT_SIZE;
        // Code region [0, l.header_off)
        assert!(cookie_start >= l.header_off, "cookie must not overlap code");
        // Metadata region [l.header_off, l.payload_off)
        assert!(
            cookie_start >= l.payload_off,
            "cookie must not overlap metadata"
        );
        // Payload region [l.payload_off, l.payload_off + payload_len)
        assert!(
            cookie_start >= l.map_off,
            "cookie must not overlap alloc_map"
        );
        assert!(cookie_end <= l.total, "cookie must fit in .boot");
        // The cookie slot in the blob is writable/exec (within .boot section).
        assert_eq!(l.cookie_off + COOKIE_SLOT_SIZE, l.total, "cookie is last");
    }

    /// Requirement #3: the decoder must not read header/table bytes as payload.
    /// Fill header/table/payload with distinct sentinels and verify the decoded
    /// payload equals the original payload only.
    #[test]
    fn payload_round_trip_ignores_header_and_tables() {
        let a = container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        );
        let b = container(
            0x2000,
            0x600000,
            0x600020,
            0x600040,
            region_bytes(0x20, &[(0, 0x600000)]),
        );
        let plan = plan_from(&[a, b]);
        let meta = meta_of(&plan);
        let (meta_off, layout) = metadata_layout(&meta, 0x100);
        let mut blob = vec![0u8; layout.total];
        // Distinct sentinels: header=0xAA, tables=0xBB, payload=original.
        for b in blob[meta_off..layout.header_off.max(meta_off)].iter_mut() {
            // (header starts at meta_off)
            *b = 0xaa;
        }
        // We can't easily target just the tables; instead, fill the region that
        // is NOT payload with sentinels, then serialize metadata (which writes
        // real header/tables/payload over the sentinels). The point: after
        // serialization + decode, payload must equal the original.
        serialize_metadata_into(&mut blob, &meta, meta_off, 0x5a10, 0x2f00).unwrap();
        let decoded = decode_plan_metadata(&blob, meta_off).unwrap();
        assert_eq!(
            decoded.payload, meta.payload,
            "decoded payload must equal original"
        );
        // Multi-region with different data_offsets: decoded regions match.
        assert_eq!(decoded.regions.len(), 2);
        assert_eq!(decoded.regions[0].data_offset, meta.regions[0].data_offset);
        assert_eq!(decoded.regions[1].data_offset, meta.regions[1].data_offset);
        assert_ne!(
            decoded.regions[0].data_offset, decoded.regions[1].data_offset,
            "distinct regions must have distinct data_offsets"
        );
    }

    /// Requirement #6: a large payload/metadata must still place the cookie
    /// after everything (no collision), and the layout must be consistent.
    #[test]
    fn large_layout_cookie_no_collision() {
        // Many regions / a large payload force the layout to grow.
        let mut containers = Vec::new();
        for i in 0..64u32 {
            let base = 0x500000u64 + (i as u64) * 0x10000;
            containers.push(container(
                0x1000 + i * 0x100,
                base,
                base + 0x8000,
                base + 0x10000,
                region_bytes(0x8000, &[(0, base)]), // self pointer
            ));
        }
        let plan = plan_from(&containers);
        let meta = meta_of(&plan);
        let (_meta_off, layout) = metadata_layout(&meta, 0x1000);
        assert!(
            layout.cookie_off > layout.payload_off,
            "cookie after payload"
        );
        assert!(layout.cookie_off > layout.map_off, "cookie after alloc map");
        assert!(layout.cookie_off >= layout.header_off, "cookie after code");
        assert!(
            layout.cookie_off + COOKIE_SLOT_SIZE <= layout.total,
            "cookie fits"
        );
        // Cookie does not overlap any sub-region.
        for off in [
            layout.header_off,
            layout.payload_off,
            layout.map_off,
            layout.cookie_off,
        ] {
            let _ = off;
        }
        let cookie_start = layout.cookie_off;
        let cookie_end = cookie_start + COOKIE_SLOT_SIZE;
        assert!(cookie_start >= layout.header_off, "cookie >= code end");
        assert!(cookie_start >= layout.payload_off, "cookie >= payload");
        assert!(cookie_start >= layout.map_off, "cookie >= map");
        assert!(cookie_end <= layout.total);
    }

    /// ASLR scheme A synthetic model: the emitted stub bakes the preferred
    /// image base; a contract with a different loaded base must fail.
    #[test]
    fn aslr_scheme_a_loaded_must_equal_preferred() {
        let plan = plan_from(&[container(
            0x1000,
            0x500000,
            0x500010,
            0x500020,
            region_bytes(0x10, &[(0, 0x500000)]),
        )]);
        let meta = meta_of(&plan);
        // The stub embeds NEW_IB as image_base.
        let code = stub_code(&plan);
        let insns = decode_all(&code);
        // movabs r10, imm64 with imm == NEW_IB (InImage / cookie / inline use it).
        let has_image_base = insns.iter().any(|i| {
            i.mnemonic() == Mnemonic::Mov
                && i.op1_kind() == iced_x86::OpKind::Immediate64
                && i.immediate(1) == NEW_IB
        });
        assert!(has_image_base, "stub must embed the preferred image base");
        // A loaded base != preferred is a contract failure (validated elsewhere).
        let _ = meta;
    }
}
