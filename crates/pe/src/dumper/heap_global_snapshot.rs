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

use tracing::{debug, info, warn};

use crate::header::PeHeader;

use super::helpers::{alloc_capped, MAX_HEAP_CONTAINER_BYTES};

const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const MIN_USER_POINTER: u64 = 0x1_0000;
/// Full canonical user-mode ceiling (x64 Windows). Do NOT cap at 4 GiB —
/// modern heaps routinely live above `0x1_0000_0000`.
const MAX_USER_POINTER: u64 = 0x0000_7fff_ffff_ffff;
/// Hard ceiling per object (explicit size field or very hot xref only).
const MAX_HEAP_GLOBAL_BYTES: usize = 32 * 1024;
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
/// Known AHK hot roots for this sample family — expand their children first so
/// high-VA free-list arenas (0x82xxxxxx series in p19c) cannot starve gscript.
/// Includes string-table pair 0x148cb8/0x148cc0: planting only 0x148cc0 makes
/// AHK skip init then `mov rdx,[0x148cb8]; cmp rbx,[rdx+10h]` AVs (p20).
const HOT_GSCRIPT_RVAS: &[u32] = &[
    0x149d50, // gscript / main script object
    0x18a898, // hot fill root (title path)
    0x141bf0, // AHK global object
    0x148bf8, // large table
    0x148cb8, // string capacity object (must pair with 0x148cc0)
    0x148cc0, // string table base (lazy-init gate)
    0x148cb0, // related string machinery
    0x148ca8, 0x148c98, 0x148c00,
];
/// Large table roots — allow hot size probe. Everything else in HOT_GSCRIPT_RVAS
/// is a compact object; force-seed xref=64 used to trigger 32 KiB probes that
/// swallowed free-list neighbours and scrubbed real string edges (p20c).
///
/// p21d: keep `0x149d50` as a large-table root (p20f planted it only with the
/// 32 KiB probe; capping to 4 KiB left `0x149d50=0` at runtime). First-hop
/// edges are force-admitted as exact children so scrub/multi_fixup no longer
/// depends on the oversize blob covering them as interiors alone.
const HOT_LARGE_TABLE_RVAS: &[u32] = &[0x149d50, 0x141bf0, 0x148bf8, 0x148c00, 0x148c98];
/// gscript / main script object (HOT_GSCRIPT_RVAS[0]).
const GSCRIPT_ROOT_RVA: u32 = 0x149d50;
/// Soft cap after capture: keep the dense AHK field table (~0xef0 packed) plus
/// a little headroom. Still allow HOT probe for readability; trim free-list
/// tail so expand does not walk 32 KiB of noise.
const GSCRIPT_ROOT_CONTENT_CAP: usize = 0x2000;
/// Force-admit every heap pointer in this prefix of gscript before ranked
/// expand. Packed has 32 live edges in the first 0x100; 0x200 covers the
/// second half of the object table without free-list flood.
const GSCRIPT_FIRST_HOP_SPAN: usize = 0x200;
/// Modest probe for gscript first-hop children (AHK sub-objects ~0x40–0x400).
const GSCRIPT_FIRST_HOP_PROBE: usize = 0x800;
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
#[derive(Debug, Clone)]
pub struct HeapGlobalSnapshot {
    /// Image RVA of the 8-byte slot that holds the heap pointer (`0` = no plant).
    pub rva: u32,
    /// Live heap address (for fixup math at runtime).
    pub live_ptr: u64,
    /// Bytes captured from the live heap object (empty when `is_heap_handle`).
    pub content: Vec<u8>,
    /// Slot holds a heap handle, not a data blob.
    pub is_heap_handle: bool,
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
    let mut forced = 0usize;
    for &rva in HOT_GSCRIPT_RVAS {
        let in_capture = capture_ranges.iter().any(|&(lo, hi)| rva >= lo && rva < hi);
        if !in_capture {
            continue;
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
        // Fill/zero-raw always eligible (subject to xref/size filters).
        // .data only via code xref — early overlay zeros heap roots there.
        if !in_preferred && !in_data {
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
        if in_data && !in_preferred && xref == 0 {
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
            });
            continue;
        }

        let probe_cap = if HOT_LARGE_TABLE_RVAS.contains(&rva)
            || (xref >= HOT_XREF_THRESHOLD && !HOT_GSCRIPT_RVAS.contains(&rva))
        {
            HOT_XREF_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        } else if HOT_GSCRIPT_RVAS.contains(&rva) {
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
        if rva == GSCRIPT_ROOT_RVA && content.len() > GSCRIPT_ROOT_CONTENT_CAP {
            content.truncate(GSCRIPT_ROOT_CONTENT_CAP);
            info!(
                rva = format_args!("{rva:#x}"),
                cap = GSCRIPT_ROOT_CONTENT_CAP,
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
    );

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
    out
}

/// Second-chance capture for `HOT_GSCRIPT_RVAS` missing after the main pass.
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
) {
    for &rva in HOT_GSCRIPT_RVAS {
        if out.iter().any(|g| g.rva == rva) {
            continue;
        }
        let in_preferred = preferred.iter().any(|&(lo, hi)| rva >= lo && rva < hi);
        let in_data = data_sec.iter().any(|&(lo, hi)| rva >= lo && rva < hi);
        if !in_preferred && !in_data {
            warn!(
                rva = format_args!("{rva:#x}"),
                "Hot-root ensure skipped: RVA outside fill/.data"
            );
            continue;
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
            });
            continue;
        }

        let ensure_probe = if HOT_LARGE_TABLE_RVAS.contains(&rva) {
            HOT_XREF_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        } else {
            DEFAULT_SIZE_PROBE_CAP.min(MAX_HEAP_GLOBAL_BYTES)
        };
        let mut size = estimate_object_size(dump_buf, rva as usize, value, debugger, ensure_probe);
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
            // Overlap with an existing capture: multi_fixup already covers the
            // bytes; we still need the *slot* planted. Clone a plant-only
            // snapshot that reuses the live_ptr with a tiny header so bootstrap
            // writes the slot (content can be empty only for handles — so read
            // 8 bytes at base for a non-empty body).
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
            // Do not register a second multi_fixup range for the same base —
            // mark as plant-only by using is_heap_handle=false with content
            // that multi_fixup will treat as a 8-byte range (same begin).
            // Prefer skipping duplicate range: plant via zero-length is not
            // supported. Instead attach as a root with content=[live 8B] and
            // live_ptr; multi_fixup first-match may use the larger sibling.
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
        content = trim_trailing_zero_pages(content);
        content = truncate_to_avoid_overlap(out, value, content);
        if rva == GSCRIPT_ROOT_RVA && content.len() > GSCRIPT_ROOT_CONTENT_CAP {
            content.truncate(GSCRIPT_ROOT_CONTENT_CAP);
        }
        if content.len() < 8 {
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
        });
    }
}

fn process_heaps_or_handle(debugger: &mut dyn mida_core::DebuggerCore, value: u64) -> bool {
    looks_like_heap_handle(debugger, value)
}

/// Force-admit every heap pointer in the first `GSCRIPT_FIRST_HOP_SPAN` of the
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
) {
    // Reserve room for later expand/dangling; still admit up to ~64 first-hops.
    let slot_cap = MAX_HEAP_GLOBAL_SLOTS.saturating_sub(HEAP_DANGLING_SLOT_RESERVE / 2);
    let Some(gscript_idx) = out
        .iter()
        .position(|g| g.rva == GSCRIPT_ROOT_RVA && !g.is_heap_handle && g.content.len() >= 8)
    else {
        warn!("gscript first-hop exhaust skipped: 0x149d50 not captured");
        return;
    };

    // Collect first-hop targets (including interiors of other captures).
    let span = GSCRIPT_FIRST_HOP_SPAN.min(out[gscript_idx].content.len());
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
            GSCRIPT_FIRST_HOP_PROBE.min(MAX_HEAP_GLOBAL_BYTES),
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
            GSCRIPT_FIRST_HOP_PROBE.min(MAX_HEAP_CONTAINER_BYTES),
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
        out.push(HeapGlobalSnapshot {
            rva: 0,
            live_ptr: value,
            content: child,
            is_heap_handle: false,
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

    // Seed ONLY the critical script/title roots. Expanding every HOT_GSCRIPT_RVAS
    // table (0x148c00/0x148c98…) floods the budget with free-list neighbours
    // while 0x149d50 keeps ~2 live heap_ptrs at runtime (packed has ~32).
    // p21: gscript first-hop already exhaust-admitted; also seed multi-hop from
    // those exact children (matched by live_ptr in gscript first-hop span).
    const HOT_EXPAND_SEED_RVAS: &[u32] = &[0x149d50, 0x18a898, 0x148cb8, 0x148cc0];
    let mut frontier: Vec<usize> = out
        .iter()
        .enumerate()
        .filter(|(_, g)| {
            HOT_EXPAND_SEED_RVAS.contains(&g.rva) && !g.is_heap_handle && g.content.len() >= 8
        })
        .map(|(i, _)| i)
        .collect();
    // Collect first-hop heap targets from gscript blob, then map to admitted
    // child indices so hop-2 BFS walks real AHK objects not free-list noise.
    if let Some(g_idx) = out
        .iter()
        .position(|g| g.rva == GSCRIPT_ROOT_RVA && !g.is_heap_handle)
    {
        let span = GSCRIPT_FIRST_HOP_SPAN.min(out[g_idx].content.len());
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
            let walk_len = if out[idx].rva == GSCRIPT_ROOT_RVA {
                GSCRIPT_FIRST_HOP_SPAN.min(content.len())
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
fn expand_source_priority(g: &HeapGlobalSnapshot) -> u32 {
    if g.is_heap_handle || g.content.len() < 8 {
        return 0;
    }
    if HOT_GSCRIPT_RVAS.contains(&g.rva) {
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
    let mut node_priority: Vec<u32> = out.iter().map(expand_source_priority).collect();
    for round in 0..MAX_GRAPH_EXPAND_ROUNDS {
        if out.len() >= expand_slot_cap || *total_bytes >= MAX_HEAP_GLOBAL_TOTAL_BYTES {
            break;
        }
        // Keep priority vector aligned (split may have grown `out` between calls).
        while node_priority.len() < out.len() {
            let idx = node_priority.len();
            node_priority.push(expand_source_priority(&out[idx]));
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
    let covered = range_contains(out, buf) || seen_heaps.contains(&buf);
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
    if seen_heaps.contains(&buf) || range_contains(out, buf) {
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
        let weight: u32 = if HOT_GSCRIPT_RVAS.contains(&g.rva) {
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
        if is_external_dangling_ptr(v, ranges, image_base, image_end) {
            buf[off..off + 8].fill(0);
            n += 1;
        }
        off += 8;
    }
    n
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
}
