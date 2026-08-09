//! Snapshot process-local heap objects referenced from zero-raw writable image
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
    /// Captured string-buffer child (refcounted shell).
    StringBufferChild,
    /// Captured dangling edge (final walk).
    DanglingEdge,
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
        if g.is_heap_handle || g.is_image_inline || g.content.is_empty() {
            continue;
        }
        if g.live_ptr < MIN_USER_POINTER || g.live_ptr > MAX_USER_POINTER {
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
        .filter(|g| !g.is_heap_handle && !g.is_image_inline && !g.content.is_empty())
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
) -> Vec<HeapGlobalSnapshot> {
    if !pe.is_64bit {
        return Vec::new();
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
        return Vec::new();
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
        return Vec::new();
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
        out.push(HeapGlobalSnapshot {
            rva,
            live_ptr: value,
            content,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
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
    normalize_cmd_table_capture(&mut out, &mut total_bytes, dump_buf, debugger);

    // R-GTO-UI r13: cmd/dispatch table @0x147868 is a pointer array. Without
    // exact children, scrub zeros almost all entries → WinMain AV @0x5747a
    // even when the table slot + count are restored.
    exhaust_pointer_table_first_hop(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        0x147868,
        policy.first_hop_probe(),
    );

    // R-GTO-UI r14: AHK global @0x141bf0 field +0xd8 held interior of a
    // 1KiB child (not exact base) → multi_fixup left stale VA → AV @0x49055
    // `cmp byte [rax+0x78],0x62` after MessageBox path (r13=[0x141bf0]).
    // Span capped: full 13KiB root is not a dense pointer table.
    exhaust_pointer_table_first_hop_span(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        0x141bf0,
        0x200, // cover +0xd8 and nearby fields only
        policy.first_hop_probe(),
    );

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
    split_swallowed_siblings(
        &mut out,
        &mut total_bytes,
        &mut seen_heaps,
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
    drop_ahk_string_arena_slots(&mut out, &mut total_bytes);

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
    out
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

    let mut content = match alloc_capped(size, cap, "gscript image-inline") {
        Ok(b) => b,
        Err(_) => return,
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
        // R-GTO-UI r13: AHK cmd table at 0x147868 has live count dword at
        // 0x147888 (entries). Prefer count*8 over RPM ladder (ladder swallows
        // free-list → unreadable first qword after plant / AV @0x5747a).
        if rva == 0x147868 {
            let count_off = 0x147888usize;
            if count_off + 4 <= dump_buf.len() {
                let n = u32::from_le_bytes(
                    dump_buf[count_off..count_off + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                if (1..0x10000).contains(&n) {
                    let want = (n as usize).saturating_mul(8).max(8);
                    if can_read(debugger, value, want, HOT_XREF_SIZE_PROBE_CAP) {
                        info!(
                            rva = format_args!("{rva:#x}"),
                            count = n,
                            size = want,
                            "Hot-root ensure: cmd table sized from live count"
                        );
                        size = want;
                    }
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
                if rva == 0x147868 {
                    let count_off = 0x147888usize;
                    if count_off + 4 <= dump_buf.len() {
                        let n = u32::from_le_bytes(
                            dump_buf[count_off..count_off + 4]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        if (1..0x10000).contains(&n) {
                            let want = (n as usize).saturating_mul(8).max(8);
                            if can_read(debugger, value, want, HOT_XREF_SIZE_PROBE_CAP) {
                                size = want;
                            }
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
                extent_evidence: CaptureExtentEvidence::default(),
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
        let mut content = match alloc_capped(
            size,
            MAX_HEAP_GLOBAL_BYTES.min(MAX_HEAP_CONTAINER_BYTES),
            "hot root ensure",
        ) {
            Ok(buf) => buf,
            Err(_) => continue,
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
        if rva != 0x147868 {
            content = trim_trailing_zero_pages(content);
        }
        content = truncate_to_avoid_overlap(out, value, content);
        if policy.gscript_root() == Some(rva) && content.len() > policy.gscript_content_cap() {
            content.truncate(policy.gscript_content_cap());
        }
        if content.len() < 8 {
            continue;
        }
        if rva != 0x147868 {
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
            extent_evidence: CaptureExtentEvidence::default(),
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
        let mut child = match alloc_capped(
            size,
            policy.first_hop_probe().min(MAX_HEAP_CONTAINER_BYTES),
            "gscript first-hop child",
        ) {
            Ok(buf) => buf,
            Err(_) => {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            }
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
        });
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
fn exhaust_gscript_child_link_fields(
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
            let mut child = match alloc_capped(
                size,
                policy.first_hop_probe().min(MAX_HEAP_CONTAINER_BYTES),
                "gscript child link",
            ) {
                Ok(buf) => buf,
                Err(_) => {
                    seen_heaps.remove(&value);
                    skipped += 1;
                    continue;
                }
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
            out.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: value,
                content: child,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
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

/// Force gscript window class/title strings for RegisterClass / CreateWindow.
///
/// R-GTO-UI r22b: after skip-LoadFile, WinMain reaches `0x34db0` but
/// `gscript+0xbd8` held a dump **path** string (not `NewClassName`) →
/// RegisterClass path returned 0 and WinMain exited without a product window.
/// Plant exact wide-string snapshots and repoint +0xbd8 (+0xbd0 title).
pub fn repair_gscript_window_strings(heap_globals: &mut Vec<HeapGlobalSnapshot>) {
    const CLASS_NAME: &str = "NewClassName";
    const TITLE_NAME: &str = "ZhuChuangKou";
    const OFF_TITLE: usize = 0xbd0;
    const OFF_CLASS: usize = 0xbd8;

    let Some(gscript_idx) = heap_globals
        .iter()
        .position(|g| g.is_image_inline && g.content.len() > OFF_CLASS + 8)
    else {
        return;
    };

    // Low user-space synthetic lives (must be plantable HeapAlloc targets and
    // within multi_fixup / is_heap_pointer acceptance). High VAs like
    // 0x50c1a550001 failed at runtime (r22b: +0xbd8 fell back to 0x106644).
    //
    // R0-D: these are SyntheticDerived regions — synthesized by this transform
    // for product recovery, with NO raw source in the captured heap slab. They
    // are excluded from raw-coherence overlay (no raw child exists by design)
    // and must never be reported as raw-captured. Their old_base is a logical
    // placement target, not an observed live allocation.
    const CLASS_LIVE: u64 = 0x0020_0000;
    const TITLE_LIVE: u64 = 0x0020_1000;

    let mut added = 0usize;
    for (live, text) in [(CLASS_LIVE, CLASS_NAME), (TITLE_LIVE, TITLE_NAME)] {
        if heap_globals.iter().any(|g| g.live_ptr == live) {
            continue;
        }
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
        let anchor = if live == CLASS_LIVE {
            "gscript+0xbd8 (RegisterClass lpszClassName)"
        } else {
            "gscript+0xbd0 (CreateWindow title)"
        };
        heap_globals.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: live,
            content: body,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            provenance: RegionProvenance::SyntheticDerived {
                transform_id: "repair_gscript_window_strings".to_string(),
                source_anchor: anchor.to_string(),
                construction_digest,
            },
        });
        added += 1;
    }

    let g = &mut heap_globals[gscript_idx];
    let old_class = u64::from_le_bytes(
        g.content[OFF_CLASS..OFF_CLASS + 8]
            .try_into()
            .unwrap_or([0; 8]),
    );
    let old_title = u64::from_le_bytes(
        g.content[OFF_TITLE..OFF_TITLE + 8]
            .try_into()
            .unwrap_or([0; 8]),
    );
    g.content[OFF_CLASS..OFF_CLASS + 8].copy_from_slice(&CLASS_LIVE.to_le_bytes());
    g.content[OFF_TITLE..OFF_TITLE + 8].copy_from_slice(&TITLE_LIVE.to_le_bytes());
    info!(
        added,
        old_class = format_args!("{old_class:#x}"),
        old_title = format_args!("{old_title:#x}"),
        class_live = format_args!("{CLASS_LIVE:#x}"),
        title_live = format_args!("{TITLE_LIVE:#x}"),
        "Repaired gscript window class/title strings (NewClassName / ZhuChuangKou)"
    );
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
    let count =
        u32::from_le_bytes(gscript.content[0x10..0x14].try_into().unwrap_or_default()) as usize;
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
pub fn repair_label_names_after_scrub(heap_globals: &mut Vec<HeapGlobalSnapshot>) {
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
    let Some(table) = heap_globals
        .iter()
        .find(|g| g.live_ptr == table_ptr && g.content.len() >= 8)
    else {
        return;
    };
    let count = {
        let c = u32::from_le_bytes(gscript.content[0x10..0x14].try_into().unwrap_or_default());
        if c > 0 {
            c as usize
        } else {
            table.content.len() / 8
        }
    };
    let table_content = table.content.clone();
    let mut repaired = 0usize;
    let mut names_added = 0usize;
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

        // R-GTO-UI r19b: most label names are *interiors* of a large capture
        // (scrub keeps the ptr, multi_fixup exact-base does not remap). Slice
        // the wide string out of the parent and plant an exact snapshot.
        let mut str_live = 0u64;
        let mut bytes: Option<Vec<u8>> = None;
        if name_ptr != 0 {
            if let Some((parent_live, parent_content)) = heap_globals.iter().find_map(|g| {
                if g.is_heap_handle || g.content.len() < 4 {
                    return None;
                }
                let end = g.live_ptr.saturating_add(g.content.len() as u64);
                if name_ptr > g.live_ptr && name_ptr < end {
                    Some((g.live_ptr, g.content.clone()))
                } else {
                    None
                }
            }) {
                let off = (name_ptr - parent_live) as usize;
                if let Some(b) = extract_wide_string_from_bytes(&parent_content[off..]) {
                    str_live = name_ptr;
                    bytes = Some(b);
                    let _ = parent_live;
                }
            }
        }
        if bytes.is_none() {
            // Prefer inline +0x30 (SSO / residual after scrub).
            if let Some(b) = extract_inline_wide_name(&heap_globals[idx].content) {
                str_live = label_live.saturating_add(LABEL_INLINE_NAME_OFF as u64);
                bytes = Some(b);
            }
        }
        let Some(mut body) = bytes else {
            // Uncaptured external mName with no recoverable bytes: null to
            // avoid wcscmp(stale) / call-obfusc AV.
            if name_ptr != 0 {
                heap_globals[idx].content[LABEL_NAME_OFF..LABEL_NAME_OFF + 8].fill(0);
            }
            continue;
        };
        if body.len() < 2 || body[body.len() - 2..] != [0, 0] {
            body.extend_from_slice(&[0, 0]);
        }
        // Ensure string snapshot exists (may exceed soft cap — still required).
        if !heap_globals.iter().any(|g| g.live_ptr == str_live) {
            if heap_globals.len() >= MAX_HEAP_GLOBAL_SLOTS + 256 {
                continue;
            }
            heap_globals.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: str_live,
                content: body,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            });
            names_added += 1;
        }
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
        // Reject obvious non-pointers (small integers, high kernel).
        if v < 0x1_0000 || v >= 0x1_0000_0000 {
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
fn exhaust_gscript_label_table_entries(
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
    let Some(table_idx) = out
        .iter()
        .position(|g| g.live_ptr == table_ptr && g.content.len() >= 8)
    else {
        return;
    };
    // Bound by synthesized count if present, else full table content.
    let count = {
        let g = out.iter().find(|g| g.is_image_inline).unwrap();
        let c = u32::from_le_bytes(g.content[0x10..0x14].try_into().unwrap_or_default());
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
        if value >= 0x1_0000_0000 {
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
        let mut child = match alloc_capped(
            size,
            policy.first_hop_probe().min(MAX_HEAP_CONTAINER_BYTES),
            "gscript label entry",
        ) {
            Ok(buf) => buf,
            Err(_) => {
                seen_heaps.remove(&value);
                skipped += 1;
                continue;
            }
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
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: value,
            content: child,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
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
            extent_evidence: CaptureExtentEvidence::default(),
            provenance: RegionProvenance::default(),
        });
    }

    // Point mName at the exact string base so multi_fixup remaps it.
    label[LABEL_NAME_OFF..LABEL_NAME_OFF + 8].copy_from_slice(&str_live.to_le_bytes());
}

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
        let g = out.iter().find(|g| g.is_image_inline).unwrap();
        let c = u32::from_le_bytes(g.content[0x10..0x14].try_into().unwrap_or_default());
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
                extent_evidence: CaptureExtentEvidence::default(),
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
        if v >= 0x1_0000 && v < 0x1_0000_0000 {
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
    const TABLE_RVA: u32 = 0x147868;
    const COUNT_RVA: u32 = 0x147888;
    let Some(idx) = out
        .iter()
        .position(|g| g.rva == TABLE_RVA && !g.is_heap_handle && g.content.len() >= 8)
    else {
        return;
    };
    let count_off = COUNT_RVA as usize;
    if count_off + 4 > dump_buf.len() {
        return;
    }
    let n = u32::from_le_bytes(
        dump_buf[count_off..count_off + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    if !(1..0x10000).contains(&n) {
        return;
    }
    let want = (n as usize).saturating_mul(8).max(8);
    let g = &mut out[idx];
    let old = g.content.len();
    if old == want {
        return;
    }
    if old > want {
        g.content.truncate(want);
        *total_bytes = total_bytes.saturating_sub(old - want);
        info!(
            rva = format_args!("{TABLE_RVA:#x}"),
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
    let mut buf = match alloc_capped(want, HOT_XREF_SIZE_PROBE_CAP, "cmd table normalize") {
        Ok(b) => b,
        Err(_) => return,
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
        rva = format_args!("{TABLE_RVA:#x}"),
        count = n,
        old_size = old,
        new_size = g.content.len(),
        "Normalized cmd table capture to live count*8 (re-read)"
    );
}

/// Force-admit every heap pointer in a captured pointer-table root (full content).
///
/// Used for AHK cmd/dispatch table @0x147868: entries are heap object pointers.
/// Scrub zeros uncaptured entries → null table → AV at `mov rcx,[rax+rcx*8]`.
fn exhaust_pointer_table_first_hop(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    table_rva: u32,
    probe: usize,
) {
    exhaust_pointer_table_first_hop_span(
        out,
        total_bytes,
        seen_heaps,
        image_base,
        image_end,
        dump_buf,
        debugger,
        table_rva,
        usize::MAX,
        probe,
    );
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
        let mut child = match alloc_capped(
            size,
            probe.min(MAX_HEAP_CONTAINER_BYTES),
            "pointer-table first-hop child",
        ) {
            Ok(b) => b,
            Err(_) => {
                skipped += 1;
                continue;
            }
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
            extent_evidence: CaptureExtentEvidence::default(),
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
            let mut content = match alloc_capped(
                size,
                HOT_CHILD_PROBE.min(MAX_HEAP_CONTAINER_BYTES),
                "heap hot-root child",
            ) {
                Ok(buf) => buf,
                Err(_) => {
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
                extent_evidence: CaptureExtentEvidence::default(),
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

            let mut content = match alloc_capped(
                size,
                GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_CONTAINER_BYTES),
                "heap graph",
            ) {
                Ok(buf) => buf,
                Err(_) => {
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
                extent_evidence: CaptureExtentEvidence::default(),
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

/// Admit the string buffer when possible. Always shrink the shell to the
/// freeable 0x28 header so oversized probes do not swallow neighbours
/// (HeapFree c0000374). Keep `buf` pointers when the buffer was snapshotted
/// so multi_fixup remaps title/path wide strings; only null when the buffer
/// cannot be captured.
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
    let Some((buf, _)) = parse_refcounted_string_shell(content) else {
        return;
    };
    // R-GTO-UI r12: only an *exact* live_ptr match means the buffer is a
    // freeable standalone snapshot. `range_contains` is wrong here — a large
    // parent (e.g. 0x144358 @ 32KiB) can swallow path/title buffers as
    // interior addresses; multi_fixup is exact-base only so those pointers
    // stay stale OR get remapped to parent interiors, then HeapFree →
    // c0000374 (WinMain path string release after MessageBox).
    let covered = is_exact_live_ptr(out, buf) || seen_heaps.contains(&buf);
    let admitted = covered
        || admit_string_buffer_child(
            content,
            out,
            total_bytes,
            seen_heaps,
            image_base,
            image_end,
            dump_buf,
            debugger,
            slot_cap,
        );
    // Exact freeable shell size — never leave multi-KiB false parent.
    if content.len() > 0x28 {
        content.truncate(0x28);
    }
    if admitted {
        // Keep buf pointers; multi_fixup remaps them to the buffer snapshot.
        return;
    }
    // Buffer unreachable — null so AHK dtor does not free a stale absolute.
    content[0..16].fill(0);
}

/// If `content` is a string shell, capture `buf` as a graph child **and keep**
/// the buffer pointers so multi_fixup remaps them (do not null). Used on the
/// hot gscript path where login-title strings must stay live.
fn admit_string_buffer_child(
    content: &[u8],
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    slot_cap: usize,
) -> bool {
    let Some((buf, want)) = parse_refcounted_string_shell(content) else {
        return false;
    };
    if !is_heap_pointer(buf, image_base, image_end) || buf < MIN_GRAPH_CHILD_POINTER {
        return false;
    }
    // Exact base only (see handle_string_shell_on_capture). Interior coverage
    // of a large parent is NOT free-safe for AHK string dtors.
    if seen_heaps.contains(&buf) || is_exact_live_ptr(out, buf) {
        return true; // already covered — keep shell pointers for remap
    }
    if out.len() >= slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
        return false;
    }
    if looks_like_heap_handle(debugger, buf) {
        return false;
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
            return false;
        }
    }
    size = shrink_to_avoid_overlap(out, buf, size);
    if size < 8 {
        return false;
    }
    if total_bytes.saturating_add(size) > MAX_HEAP_GLOBAL_TOTAL_BYTES {
        return false;
    }
    let mut body = match alloc_capped(
        size,
        GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_CONTAINER_BYTES),
        "string buffer child",
    ) {
        Ok(b) => b,
        Err(_) => return false,
    };
    match debugger.read_memory(buf as usize, &mut body) {
        Ok(n) if n >= 2 => {
            if n < body.len() {
                body.truncate(n);
            }
        }
        _ => return false,
    }
    body = trim_trailing_zero_pages(body);
    body = truncate_to_avoid_overlap(out, buf, body);
    if body.len() < 2 {
        return false;
    }
    if !seen_heaps.insert(buf) {
        return true;
    }
    info!(
        heap = format_args!("{buf:#x}"),
        size = body.len(),
        "Captured string-buffer child (keep shell ptrs for multi_fixup)"
    );
    *total_bytes = total_bytes.saturating_add(body.len());
    out.push(HeapGlobalSnapshot {
        rva: 0,
        live_ptr: buf,
        content: body,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        provenance: RegionProvenance::default(),
    });
    true
}

/// Promote heap pointers that land *strictly inside* an existing capture to
/// their own snapshot entries, and shrink the swallowing parent so multi_fixup
/// remaps freeable leaves to exact `HeapAlloc` bases (not interiors).
fn split_swallowed_siblings(
    out: &mut Vec<HeapGlobalSnapshot>,
    total_bytes: &mut usize,
    seen_heaps: &mut BTreeSet<u64>,
    image_base: u64,
    image_end: u64,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
) {
    const MAX_SPLIT_ROUNDS: usize = 4;
    const MAX_SPLIT_PER_ROUND: usize = 24;

    let split_slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE);
    for round in 0..MAX_SPLIT_ROUNDS {
        if out.len() >= split_slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            break;
        }

        let mut interiors: BTreeSet<u64> = BTreeSet::new();
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
                let swallowed = out.iter().any(|o| {
                    if o.is_heap_handle || o.content.is_empty() {
                        return false;
                    }
                    let end = o.live_ptr.saturating_add(o.content.len() as u64);
                    v > o.live_ptr && v < end
                });
                if swallowed {
                    interiors.insert(v);
                }
            }
        }

        if interiors.is_empty() {
            break;
        }

        // Prefer higher VAs so useful mid-heap leaves win over residual junk.
        let interiors_ordered: Vec<u64> = {
            let mut v: Vec<u64> = interiors.into_iter().collect();
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

            // Shrink every parent that swallowed this address *before* admitting
            // the child, so ranges never overlap in the fixup map.
            for g in out.iter_mut() {
                if g.is_heap_handle || g.content.is_empty() {
                    continue;
                }
                let end = g.live_ptr.saturating_add(g.content.len() as u64);
                if value > g.live_ptr && value < end {
                    let new_len = (value - g.live_ptr) as usize;
                    if new_len >= 8 && new_len < g.content.len() {
                        let dropped = g.content.len() - new_len;
                        g.content.truncate(new_len);
                        *total_bytes = total_bytes.saturating_sub(dropped);
                    }
                }
            }

            if !seen_heaps.insert(value) {
                continue;
            }

            let mut size = estimate_object_size(
                dump_buf,
                usize::MAX,
                value,
                debugger,
                GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES),
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

            let mut content = match alloc_capped(
                size,
                GRAPH_CHILD_SIZE_PROBE_CAP.min(MAX_HEAP_CONTAINER_BYTES),
                "heap split sibling",
            ) {
                Ok(buf) => buf,
                Err(_) => {
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
                split_slot_cap,
            );

            info!(
                heap = format_args!("{value:#x}"),
                size = content.len(),
                round = round + 1,
                "Split swallowed heap sibling into own snapshot (free-safe base)"
            );
            *total_bytes = total_bytes.saturating_add(content.len());
            out.push(HeapGlobalSnapshot {
                rva: 0,
                live_ptr: value,
                content,
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            });
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
}

/// Final pass: walk every captured blob and admit still-external heap pointers
/// that are readable in the live process. Prefer hot / high-VA targets; stop at
/// slot/byte caps. Remaining uncaptured edges are scrubbed later.
fn capture_dangling_edges(
    out: &mut Vec<HeapGlobalSnapshot>,
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

        let mut content = match alloc_capped(
            size,
            DANGLING_PROBE_CAP.min(MAX_HEAP_CONTAINER_BYTES),
            "heap dangling edge",
        ) {
            Ok(buf) => buf,
            Err(_) => {
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
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: value,
            content,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
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

    let mut scrubbed = 0usize;
    for c in containers.iter_mut() {
        scrubbed += scrub_buffer_external_ptrs(&mut c.heap_content, &ranges, image_base, image_end);
    }
    for g in heap_globals.iter_mut() {
        scrubbed += scrub_buffer_external_ptrs(&mut g.content, &ranges, image_base, image_end);
    }
    if scrubbed > 0 {
        info!(
            scrubbed_qwords = scrubbed,
            ranges = ranges.len(),
            "Scrubbed uncaptured external heap pointers in snapshots"
        );
    }
}

fn scrub_buffer_external_ptrs(
    buf: &mut [u8],
    ranges: &[(u64, u64)],
    image_base: u64,
    image_end: u64,
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
    let mut buf = match alloc_capped(size, cap.max(size), "heap global probe") {
        Ok(b) => b,
        Err(_) => return false,
    };
    match debugger.read_memory(addr as usize, &mut buf) {
        Ok(n) => n == size,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_image_pointers() {
        assert!(!is_heap_pointer(
            0x1400_0000_0,
            0x1400_0000_0,
            0x1401_0000_0
        ));
        // Below MIN_HEAP_POINTER (1 MiB) — PE noise / segment heads.
        // Note: 0x31a0_b30 (~50 MiB) is ABOVE the floor and is a valid heap-shaped
        // candidate; use a true sub-1MiB address for this rejection case.
        assert!(!is_heap_pointer(0x9_0000, 0x1400_0000_0, 0x1401_0000_0));
        assert!(!is_heap_pointer(0x1_0000, 0x1400_0000_0, 0x1401_0000_0));
        // Real user heap above 1 MiB.
        assert!(is_heap_pointer(0x85a_380, 0x1400_0000_0, 0x1401_0000_0));
    }

    #[test]
    fn accepts_high_user_heap() {
        // Real x64 heaps often sit above 4 GiB but below system DLL region.
        assert!(is_heap_pointer(
            0x0000_01a0_1234_5600,
            0x1400_0000_0,
            0x1401_0000_0
        ));
    }

    #[test]
    fn rejects_system_dll_pointers() {
        assert!(!is_heap_pointer(
            0x0000_7ffa_33b4_1a30,
            0x1400_0000_0,
            0x1401_0000_0
        ));
    }

    #[test]
    fn rejects_unaligned() {
        assert!(!is_heap_pointer(0x31a0_b31, 0x1400_0000_0, 0x1401_0000_0));
    }

    #[test]
    fn policy_hot_root_outside_fill_data_is_still_hot() {
        // Mirrors GTO 0x18a898: listed in ahk_gto defaults, not in .data/.fill.
        let p = DumpCapturePolicy::ahk_gto_default();
        assert!(p.is_hot_root(0x18a898));
        assert!(p.hot_root_rvas.contains(&0x18a898));
    }

    #[test]
    fn sanitize_ahk_runtime_global_zeros_for_cold_start() {
        let mut globals = vec![
            HeapGlobalSnapshot {
                rva: 0x141bf0,
                live_ptr: 0x12345678,
                content: vec![0x1; 0x100],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
            HeapGlobalSnapshot {
                rva: 0x149d50,
                live_ptr: 0x87654321,
                content: vec![0x2; 0x200],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
        ];
        sanitize_ahk_runtime_global(&mut globals);
        let ahk_g = globals.iter().find(|g| g.rva == 0x141bf0).unwrap();
        assert_eq!(ahk_g.content.len(), 0x180);
        assert!(ahk_g.content.iter().all(|&b| b == 0));
    }

    /// Route F / r27: pre-object gap `0x846898` must fall interior to the slab
    /// when the nearest captured object is at `0x846bb0` (0x318-byte hole).
    #[test]
    fn heap_slab_span_covers_r27_pre_object_gap() {
        // Historical r27 layout (simplified): object at 0x846bb0; computed
        // stale ptr 0x846898 = 0x830000 + 0x16898 sits 0x318 bytes before it.
        let globals = vec![
            HeapGlobalSnapshot {
                rva: 0x1000,
                live_ptr: 0x846bb0,
                content: vec![0u8; 0x40],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
            HeapGlobalSnapshot {
                rva: 0x2000,
                live_ptr: 0x847000,
                content: vec![0u8; 0x20],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
            // Heap handle must not set min_obj by itself.
            HeapGlobalSnapshot {
                rva: 0x3000,
                live_ptr: 0x830000,
                content: vec![0u8; 8],
                is_heap_handle: true,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
        ];
        let (old_base, end) = compute_heap_slab_span(&globals).expect("span");
        let len = end - old_base;
        // Without prefix pad, old_base would be 0x846bb0 and 0x846898 is outside.
        assert!(
            old_base < 0x846898,
            "old_base={old_base:#x} must be below gap ptr 0x846898"
        );
        assert!(
            heap_slab_covers_interior(old_base, len, 0x846898),
            "slab [{old_base:#x},{end:#x}) must cover 0x846898"
        );
        assert!(heap_slab_covers_interior(old_base, len, 0x846bb0));
        // Strict interior: old_base itself is not rebased.
        assert!(!heap_slab_covers_interior(old_base, len, old_base));
        // Prefix is at least HEAP_SLAB_PREFIX_PAD below min object (page aligned).
        assert!(0x846bb0 - old_base >= HEAP_SLAB_PREFIX_PAD);
    }

    #[test]
    fn heap_slab_span_none_for_single_object() {
        let globals = vec![HeapGlobalSnapshot {
            rva: 0x1000,
            live_ptr: 0x846bb0,
            content: vec![0u8; 0x40],
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            provenance: RegionProvenance::default(),
        }];
        assert!(compute_heap_slab_span(&globals).is_none());
    }

    // GTO Core Recovery R0-D: the window-string repair must mark its synthetic
    // children with SyntheticDerived provenance (not RawCaptured), and repoint
    // gscript+0xbd8/0xbd0 to those synthetic lives.
    #[test]
    fn r0d_window_string_repair_marks_synthetic_derived() {
        // gscript-like inline global with class/title slots at +0xbd0/+0xbd8
        // holding old (dump-path) strings.
        let mut gscript = HeapGlobalSnapshot {
            rva: 0x149d50,
            live_ptr: 0x1400_0000_0 + 0x149d50,
            content: vec![0u8; 0xbd8 + 16],
            is_heap_handle: false,
            is_image_inline: true,
            extent_kind: CaptureExtentKind::default(),
            extent_evidence: CaptureExtentEvidence::default(),
            provenance: RegionProvenance::ImageInline,
        };
        gscript.content[0xbd0..0xbd8].copy_from_slice(&0xa190a8u64.to_le_bytes());
        gscript.content[0xbd8..0xbd0 + 8 + 8].copy_from_slice(&0xa18ec0u64.to_le_bytes());
        let mut globals = vec![gscript];
        repair_gscript_window_strings(&mut globals);
        // Two synthetic children added (0x200000 class, 0x201000 title).
        let synth: Vec<_> = globals
            .iter()
            .filter(|g| g.live_ptr == 0x200000 || g.live_ptr == 0x201000)
            .collect();
        assert_eq!(synth.len(), 2);
        for g in &synth {
            assert!(!g.is_image_inline);
            assert!(!g.is_heap_handle);
            match &g.provenance {
                RegionProvenance::SyntheticDerived {
                    transform_id,
                    construction_digest,
                    ..
                } => {
                    assert_eq!(transform_id, "repair_gscript_window_strings");
                    // construction digest == sha256 of the content bytes.
                    assert_eq!(
                        *construction_digest,
                        format!("{:x}", {
                            let mut h = Sha256::new();
                            h.update(&g.content);
                            h.finalize()
                        })
                    );
                }
                other => panic!("expected SyntheticDerived, got {other:?}"),
            }
        }
        // Class slot +0xbd8 == 0x200000, title slot +0xbd0 == 0x201000.
        let gscript = &globals[0];
        assert_eq!(
            u64::from_le_bytes(gscript.content[0xbd8..0xbd8 + 8].try_into().unwrap()),
            0x200000
        );
        assert_eq!(
            u64::from_le_bytes(gscript.content[0xbd0..0xbd0 + 8].try_into().unwrap()),
            0x201000
        );
    }

    // GTO Core Recovery R0-E: identical-bytes duplicate at the same live_ptr is
    // a redundant capture and is reconciled to a single entry.
    #[test]
    fn r0e_identical_bytes_duplicate_deduped() {
        let mut globals = vec![
            HeapGlobalSnapshot {
                rva: 0x146890,
                live_ptr: 0x8d8d60,
                content: vec![0x41u8; 0x400],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0x41u8; 0x400],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
        ];
        reconcile_duplicate_heap_globals(&mut globals, None);
        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0].live_ptr, 0x8d8d60);
        assert_eq!(globals[0].content, vec![0x41u8; 0x400]);
    }

    // GTO Core Recovery R0-E: two entries at the same live_ptr with differing
    // bytes are reconciled to the one coherent with the raw slab (physical
    // memory ground truth). Reproduces the Route M R1 conflict geometry.
    #[test]
    fn r0e_differing_bytes_prefers_raw_slab_coherent() {
        // Slab: [0x89f000, ...). The physical bytes at 0x8d8d60 (= offset
        // 0x39d60 in the slab) are [0xBB; 0x400]. One capture is coherent with
        // the slab; the other (stale/drifted) is not.
        let slab_off = (0x8d8d60u64 - 0x89f000u64) as usize; // 0x39d60
        let mut slab_content = vec![0u8; slab_off + 0x400];
        for b in slab_content[slab_off..slab_off + 0x400].iter_mut() {
            *b = 0xBB;
        }
        let slab = HeapSlab {
            old_base: 0x89f000,
            content: slab_content,
        };
        let mut globals = vec![
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0xBBu8; 0x400], // coherent with slab
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0xAAu8; 0x400], // NOT coherent (drift)
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
        ];
        reconcile_duplicate_heap_globals(&mut globals, Some(&slab));
        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0].content, vec![0xBBu8; 0x400]);
    }

    // GTO Core Recovery R0-E: a duplicate whose raw bytes match the slab is
    // preferred over a non-coherent one regardless of insertion order.
    #[test]
    fn r0e_coherent_wins_over_noncoherent_any_order() {
        let slab_off = (0x8d8d60u64 - 0x89f000u64) as usize;
        let mut slab_content = vec![0u8; slab_off + 0x20];
        for b in slab_content[slab_off..slab_off + 0x20].iter_mut() {
            *b = 0x77;
        }
        let slab = HeapSlab {
            old_base: 0x89f000,
            content: slab_content,
        };
        // Non-coherent first, coherent second.
        let mut globals = vec![
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0x11u8; 0x20],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0x77u8; 0x20],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
        ];
        reconcile_duplicate_heap_globals(&mut globals, Some(&slab));
        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0].content, vec![0x77u8; 0x20]);
    }

    // GTO Core Recovery R0-E: differing bytes with no raw slab (no slab
    // capture) prefer the larger snapshot; an exact-size tie with differing
    // bytes is retained so the overlay fail-closes with provenance rather than
    // silently picking.
    #[test]
    fn r0e_no_slab_prefers_larger_keeps_tie_conflict() {
        // Larger wins.
        let mut a = vec![
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0xAAu8; 0x400],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0xBBu8; 0x200],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
        ];
        reconcile_duplicate_heap_globals(&mut a, None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].content, vec![0xAAu8; 0x400]);

        // Exact-size tie with differing bytes and no slab → retained (fail-closed).
        let mut b = vec![
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0xAAu8; 0x400],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x8d8d60,
                content: vec![0xBBu8; 0x400],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                provenance: RegionProvenance::default(),
            },
        ];
        reconcile_duplicate_heap_globals(&mut b, None);
        assert_eq!(b.len(), 2); // both retained; overlay will fail-closed
    }
}
