//! Materialize code pages that still live in zero-raw `.fill` gaps.

//!
//! Production `.unwrap()`s are invariants: `pages_to_spans` returns early on
//! an empty page set, so `next()`/`next_back()` are non-empty (WO-10). Test
//! unwraps are assertions.
#![allow(clippy::unwrap_used)]
//!
//! After shrink removes Themida sections, zero-raw `.fill` gaps replace them.
//! Two classes of callers then land in empty BSS:
//!
//! 1. **IAT wrappers** — unresolved slots that still point at image-local stubs.
//! 2. **Direct call/jmp chains** — e.g. `.wfix` `E8 rel32` into former Themida
//!    code at `0x334c98` (page never written because `RawSize=0`).
//!
//! Code uses rip-relative addressing against its original VA, so pages MUST
//! stay at the original RVA. We split the covering zero-raw `.fill` around
//! needed ranges and inject executable raw sections.
//!
//! **Important:** pages are merged into contiguous *spans* (one CODE section
//! per span). Injecting one section per 4 KiB page blows past the PE section
//! table / SizeOfHeaders budget (observed: nsec=223 → unloadable PE).

use std::collections::{BTreeMap, BTreeSet};

use tracing::{info, warn};

use crate::header::{ImageSectionHeader, PeHeader, PeSection};

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const PAGE: u32 = 0x1000;
/// Hard cap on materialized *requested* pages (holes in spans not counted).
const MAX_MATERIALIZE_PAGES: usize = 512;
/// Follow call chains out of newly injected pages this many times.
const MAX_MATERIALIZE_PASSES: usize = 12;
/// Page must have this many non-zero bytes in the live dump to count as code.
const MIN_PAGE_NONZERO: usize = 32;
/// Prefer at most this many CODE sections per covering `.fill` region.
const MAX_SPANS_PER_COVER: usize = 8;
/// Global hard cap on `.wfix` CODE sections (modern loaders accept well over 96).
const MAX_CODE_SECTIONS_TOTAL: usize = 72;
/// Hard cap on a single span size (pages). Avoid multi-MB min..=max spans.
const MAX_SPAN_PAGES: u32 = 256; // 1 MiB
/// When merging, allow holes of at most this many pages between needed pages.
const MERGE_GAP_PAGES_TIGHT: u32 = 8; // 32 KiB holes folded in
const MERGE_GAP_PAGES_LOOSE: u32 = 64; // 256 KiB holes folded in
/// Grow live islands around call targets this many BFS steps.
const LIVE_EXPAND_ROUNDS: usize = 8;

/// Ensure image-local IAT wrapper pages are present as raw PE data at their
/// original RVAs by splitting zero-raw `.fill` gaps around them.
///
/// Returns the number of pages written.
pub(crate) fn materialize_image_iat_wrappers(
    pe: &mut PeHeader,
    dump_buf: &mut [u8],
    original_iat_rva: u32,
    iat_size: usize,
    image_base: u64,
) -> usize {
    if !pe.is_64bit || original_iat_rva == 0 || iat_size < 8 {
        return 0;
    }

    let image_size = pe.size_of_image() as u64;
    let image_end = image_base.saturating_add(image_size);
    let iat_start = original_iat_rva as usize;
    let iat_end = iat_start.saturating_add(iat_size).min(dump_buf.len());
    if iat_end.saturating_sub(iat_start) < 8 {
        return 0;
    }

    let mut pages: BTreeSet<u32> = BTreeSet::new();
    for off in (iat_start..iat_end).step_by(8) {
        let target = u64::from_le_bytes(dump_buf[off..off + 8].try_into().unwrap_or_default());
        if target < image_base + 0x1000 || target >= image_end {
            continue;
        }
        let rva = (target - image_base) as u32;
        if section_has_raw_for_rva(pe, rva) {
            continue;
        }
        if !is_zero_raw_cover(pe, rva) {
            continue;
        }
        if !page_looks_live(dump_buf, rva & !(PAGE - 1)) {
            continue;
        }
        pages.insert(rva & !(PAGE - 1));
    }

    let written = inject_pages(pe, dump_buf, &pages);
    if written > 0 {
        info!(
            pages = written,
            "Materialized image-local IAT wrappers at original RVAs (span-merged .fill)"
        );
    }
    written
}

/// Materialize zero-raw `.fill` pages that are **call/jmp targets** of code
/// already present in the dump (`.text`, existing `.wfix`, and newly injected
/// pages across multiple passes).
///
/// Fixes the post-heap-global crash class:
/// `call 0x334c98` from `.wfix` landing on a zero page because shrink dropped
/// the Themida code that used to live there.
pub(crate) fn materialize_fill_code_refs(
    pe: &mut PeHeader,
    dump_buf: &mut [u8],
    image_base: u64,
) -> usize {
    if !pe.is_64bit {
        return 0;
    }

    let mut total = 0usize;
    for pass in 0..MAX_MATERIALIZE_PASSES {
        if total >= MAX_MATERIALIZE_PAGES {
            break;
        }
        let mut pages = collect_call_target_fill_pages(pe, dump_buf, image_base);
        pages.retain(|p| !section_has_raw_for_rva(pe, *p));
        pages.retain(|p| is_zero_raw_cover(pe, *p));
        pages.retain(|p| page_looks_live(dump_buf, *p));
        // Expand islands: fall-through / near-call live pages often lack E8 xrefs
        // (e.g. crash at 0x68ebee inside a live fill island with no direct rel32).
        pages = expand_live_fill_islands(pe, dump_buf, pages);

        let budget = MAX_MATERIALIZE_PAGES.saturating_sub(total);
        // Prefer call-target islands first, then fill remaining budget with any
        // other live zero-raw pages (indirect control flow has no E8 edge).
        if pages.len() < budget {
            for p in collect_all_live_fill_pages(pe, dump_buf) {
                if pages.len() >= budget {
                    break;
                }
                pages.insert(p);
            }
        }
        let batch: BTreeSet<u32> = pages.into_iter().take(budget).collect();
        if batch.is_empty() {
            break;
        }
        let wrote = inject_pages(pe, dump_buf, &batch);
        total = total.saturating_add(wrote);
        if wrote == 0 {
            break;
        }
        info!(
            pass = pass + 1,
            pages = wrote,
            total,
            nsec = pe.sections.len(),
            "Materialized fill code-ref pages (call/jmp targets, span-merged)"
        );
    }

    if total > 0 {
        pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;
        info!(
            pages = total,
            nsec = pe.sections.len(),
            "Materialized fill code pages for direct call/jmp targets"
        );
    }
    total
}

/// Inject needed pages by merging them into spans and splitting each covering
/// `.fill` at most once (one splice → few CODE sections, not one per page).
fn inject_pages(pe: &mut PeHeader, dump_buf: &[u8], pages: &BTreeSet<u32>) -> usize {
    // Group pages by the virtual_address of their covering zero-raw section.
    let mut by_cover: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for &page in pages {
        if section_has_raw_for_rva(pe, page) {
            continue;
        }
        let Some(cover_va) = cover_section_va(pe, page) else {
            warn!(page = format_args!("{page:#x}"), "no section covers page");
            continue;
        };
        by_cover.entry(cover_va).or_default().insert(page);
    }

    if by_cover.is_empty() {
        return 0;
    }

    // Process high→low VA so earlier splices do not shift later cover indices.
    let mut cover_vas: Vec<u32> = by_cover.keys().copied().collect();
    cover_vas.sort_unstable_by(|a, b| b.cmp(a));

    let already_wfix = pe
        .sections
        .iter()
        .filter(|s| s.name.starts_with(".wfix"))
        .count();
    let mut written = 0usize;
    let mut code_sections = 0usize;
    for cover_va in cover_vas {
        let total_wfix = already_wfix.saturating_add(code_sections);
        if total_wfix >= MAX_CODE_SECTIONS_TOTAL {
            warn!(
                cap = MAX_CODE_SECTIONS_TOTAL,
                already = already_wfix,
                "Materialize CODE section budget exhausted; remaining covers skipped"
            );
            break;
        }
        let cover_pages = match by_cover.remove(&cover_va) {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };
        let budget = MAX_CODE_SECTIONS_TOTAL.saturating_sub(total_wfix);
        match inject_spans_in_cover(pe, dump_buf, cover_va, &cover_pages, budget) {
            Ok((pages_n, spans_n)) => {
                written = written.saturating_add(pages_n);
                code_sections = code_sections.saturating_add(spans_n);
            }
            Err(msg) => warn!(cover = format_args!("{cover_va:#x}"), "{msg}"),
        }
    }

    if written > 0 {
        pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;
        info!(
            pages = written,
            code_sections,
            nsec = pe.sections.len(),
            "Injected span-merged materialize CODE sections"
        );
    }
    written
}

/// Build spans for a page set.
///
/// Prefer a single min..=max envelope (chunked to `MAX_SPAN_PAGES`) when the
/// hole density is acceptable — that yields far fewer PE sections than many
/// 4 KiB islands (critical for loader SizeOfHeaders budget).
fn pages_to_spans(pages: &BTreeSet<u32>, max_spans: usize) -> Vec<(u32, u32)> {
    if pages.is_empty() {
        return Vec::new();
    }
    let max_spans = max_spans.max(1);
    let lo = *pages.iter().next().unwrap();
    let hi = pages
        .iter()
        .next_back()
        .copied()
        .unwrap()
        .saturating_add(PAGE);
    let envelope = hi.saturating_sub(lo);
    let max_envelope = MAX_SPAN_PAGES
        .saturating_mul(PAGE)
        .saturating_mul(max_spans as u32)
        .max(MAX_SPAN_PAGES.saturating_mul(PAGE));

    // Dense enough (or small enough): one envelope, split only by size cap.
    let page_count = pages.len() as u32;
    let span_pages = envelope / PAGE;
    let density = if span_pages == 0 {
        1.0
    } else {
        page_count as f64 / span_pages as f64
    };
    if envelope <= max_envelope && (density >= 0.15 || span_pages <= MAX_SPAN_PAGES) {
        return split_oversized_spans(vec![(lo, envelope)], MAX_SPAN_PAGES.saturating_mul(PAGE));
    }

    let mut spans = merge_pages_with_gap(pages, MERGE_GAP_PAGES_TIGHT);
    if spans.len() > max_spans {
        spans = merge_pages_with_gap(pages, MERGE_GAP_PAGES_LOOSE);
    }
    spans = split_oversized_spans(spans, MAX_SPAN_PAGES.saturating_mul(PAGE));

    if spans.len() > max_spans {
        let score = |start: u32, size: u32| -> usize {
            let end = start.saturating_add(size);
            pages.range(start..end).count()
        };
        spans.sort_by(|a, b| {
            score(b.0, b.1)
                .cmp(&score(a.0, a.1))
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.0.cmp(&b.0))
        });
        spans.truncate(max_spans);
        spans.sort_by_key(|(start, _)| *start);
    }
    spans
}

/// Every zero-raw page that still holds non-trivial live dump bytes.
fn collect_all_live_fill_pages(pe: &PeHeader, dump_buf: &[u8]) -> BTreeSet<u32> {
    let mut pages = BTreeSet::new();
    let image_size = pe.size_of_image().min(dump_buf.len() as u32);
    let mut p = 0x1000u32;
    while p.saturating_add(PAGE) <= image_size {
        if is_zero_raw_cover(pe, p)
            && !section_has_raw_for_rva(pe, p)
            && page_looks_live(dump_buf, p)
        {
            pages.insert(p);
        }
        p = p.saturating_add(PAGE);
    }
    pages
}

/// BFS-expand live zero-raw pages around seeds so fall-through code islands
/// are materialized even without a direct E8/E9 edge into every page.
fn expand_live_fill_islands(pe: &PeHeader, dump_buf: &[u8], seeds: BTreeSet<u32>) -> BTreeSet<u32> {
    let mut out = seeds;
    let mut frontier: BTreeSet<u32> = out.clone();
    for _ in 0..LIVE_EXPAND_ROUNDS {
        if out.len() >= MAX_MATERIALIZE_PAGES {
            break;
        }
        let mut next = BTreeSet::new();
        for &p in &frontier {
            for delta in [PAGE as i64, -(PAGE as i64)] {
                let n = (p as i64 + delta) as u32;
                if n < 0x1000 {
                    continue;
                }
                if out.contains(&n) {
                    continue;
                }
                if !is_zero_raw_cover(pe, n) || section_has_raw_for_rva(pe, n) {
                    continue;
                }
                if !page_looks_live(dump_buf, n) {
                    continue;
                }
                if out.len() >= MAX_MATERIALIZE_PAGES {
                    break;
                }
                out.insert(n);
                next.insert(n);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    out
}

fn split_oversized_spans(spans: Vec<(u32, u32)>, max_bytes: u32) -> Vec<(u32, u32)> {
    let max_bytes = max_bytes.max(PAGE);
    let mut out = Vec::new();
    for (start, size) in spans {
        if size <= max_bytes {
            out.push((start, size));
            continue;
        }
        let mut cur = start;
        let end = start.saturating_add(size);
        while cur < end {
            let chunk = max_bytes.min(end.saturating_sub(cur));
            out.push((cur, chunk));
            cur = cur.saturating_add(chunk);
        }
    }
    out
}

fn merge_pages_with_gap(pages: &BTreeSet<u32>, gap_pages: u32) -> Vec<(u32, u32)> {
    let mut spans: Vec<(u32, u32)> = Vec::new();
    let mut iter = pages.iter().copied();
    let Some(mut start) = iter.next() else {
        return spans;
    };
    let mut end = start.saturating_add(PAGE);
    let max_gap = gap_pages.saturating_mul(PAGE);
    for p in iter {
        if p <= end.saturating_add(max_gap) {
            end = p.saturating_add(PAGE);
        } else {
            spans.push((start, end.saturating_sub(start)));
            start = p;
            end = p.saturating_add(PAGE);
        }
    }
    spans.push((start, end.saturating_sub(start)));
    spans
}

fn cover_section_va(pe: &PeHeader, rva: u32) -> Option<u32> {
    pe.sections.iter().find_map(|s| {
        let end = s.virtual_address.saturating_add(s.virtual_size.max(PAGE));
        if rva >= s.virtual_address && rva < end {
            Some(s.virtual_address)
        } else {
            None
        }
    })
}

fn inject_spans_in_cover(
    pe: &mut PeHeader,
    dump_buf: &[u8],
    cover_va: u32,
    pages: &BTreeSet<u32>,
    max_spans: usize,
) -> Result<(usize /*pages*/, usize /*spans*/), String> {
    let idx = pe
        .sections
        .iter()
        .position(|s| s.virtual_address == cover_va)
        .or_else(|| {
            // Cover may have been partially split already; find by any page.
            pages.iter().find_map(|&p| {
                pe.sections.iter().position(|s| {
                    let end = s.virtual_address.saturating_add(s.virtual_size.max(PAGE));
                    p >= s.virtual_address && p < end
                })
            })
        })
        .ok_or_else(|| "covering section not found".to_string())?;

    let cover = pe.sections[idx].clone();
    let cover_start = cover.virtual_address;
    let cover_end = cover.virtual_address.saturating_add(cover.virtual_size);

    // Only split zero-raw fillers / non-code gaps.
    if cover.raw_size > 0 && !cover.name.starts_with(".fill") {
        return Err(format!(
            "covering section {} already has raw data; refusing split",
            cover.name
        ));
    }

    // Keep only pages fully inside this cover.
    let mut in_cover: BTreeSet<u32> = BTreeSet::new();
    for &p in pages {
        if p >= cover_start && p.saturating_add(PAGE) <= cover_end {
            // Skip if this page already has raw after a prior partial inject.
            if section_has_raw_for_rva(pe, p) {
                continue;
            }
            in_cover.insert(p);
        }
    }
    if in_cover.is_empty() {
        return Ok((0, 0));
    }

    let spans = pages_to_spans(&in_cover, max_spans.min(MAX_SPANS_PER_COVER));
    if spans.is_empty() {
        return Ok((0, 0));
    }

    // Sequential file offsets for every CODE span in this splice.
    let mut next_raw = next_file_raw_offset(pe);
    let file_align = file_alignment(pe);

    let mut replacement: Vec<PeSection> = Vec::new();
    let mut cursor = cover_start;
    let mut page_count = 0usize;
    let mut span_count = 0usize;

    for (span_start, span_size) in &spans {
        let span_start = *span_start;
        let span_size = *span_size;
        if span_start < cover_start || span_start.saturating_add(span_size) > cover_end {
            warn!(
                span = format_args!("{span_start:#x}+{span_size:#x}"),
                "span outside cover; skipped"
            );
            continue;
        }
        if span_start > cursor {
            replacement.push(zero_fill_section(cursor, span_start - cursor));
        }

        let src = span_start as usize;
        let end = src.saturating_add(span_size as usize);
        if end > dump_buf.len() {
            return Err(format!(
                "span {span_start:#x}+{span_size:#x} outside dump ({} bytes)",
                dump_buf.len()
            ));
        }
        let bytes = dump_buf[src..end].to_vec();
        let (sec, used_raw) =
            wrapper_span_section(span_start, span_size, bytes, next_raw, file_align);
        next_raw = used_raw;
        replacement.push(sec);
        // Count only pages that were requested (not hole pages in the span).
        let span_end = span_start.saturating_add(span_size);
        let needed = in_cover.range(span_start..span_end).count();
        page_count = page_count.saturating_add(needed.max(1));
        span_count = span_count.saturating_add(1);
        cursor = span_start.saturating_add(span_size);
    }

    if cursor < cover_end {
        replacement.push(zero_fill_section(cursor, cover_end - cursor));
    }

    if span_count == 0 {
        return Ok((0, 0));
    }

    pe.sections.splice(idx..=idx, replacement);
    Ok((page_count, span_count))
}

/// Scan live dump for `E8`/`E9` rel32 whose target falls in a zero-raw gap.
fn collect_call_target_fill_pages(
    pe: &PeHeader,
    dump_buf: &[u8],
    image_base: u64,
) -> BTreeSet<u32> {
    let mut pages = BTreeSet::new();
    let image_size = pe.size_of_image() as u32;

    // Prefer scanning sections that already have raw / are known code carriers.
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for s in &pe.sections {
        let start = s.virtual_address;
        let end = start.saturating_add(s.virtual_size.max(s.raw_size).max(PAGE));
        let end = end.min(image_size).min(dump_buf.len() as u32);
        if end <= start {
            continue;
        }
        // Skip pure data directories for the *source* scan — too many false E8s.
        if s.name == ".data" || s.name == ".rdata" || s.name == ".rsrc" || s.name == ".reloc" {
            continue;
        }
        let is_code = s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            || s.name.starts_with(".text")
            || s.name.starts_with(".wfix")
            || s.name.starts_with(".boot");
        let is_gap_carrier = s.name.starts_with(".fill") || s.raw_size == 0;
        if is_code || (s.raw_size > 0 && !is_gap_carrier) {
            ranges.push((start, end));
        }
    }

    ranges.sort_unstable();
    ranges.dedup();

    for (start, end) in ranges {
        let lo = start as usize;
        let hi = (end as usize).min(dump_buf.len());
        if hi.saturating_sub(lo) < 5 {
            continue;
        }
        let code = &dump_buf[lo..hi];
        let mut i = 0usize;
        while i + 5 <= code.len() {
            let op = code[i];
            if op == 0xe8 || op == 0xe9 {
                let rel = i32::from_le_bytes([code[i + 1], code[i + 2], code[i + 3], code[i + 4]]);
                let next_rva = start.saturating_add(i as u32).saturating_add(5);
                let target = (next_rva as i64 + rel as i64) as u32;
                if target >= 0x1000 && target < image_size {
                    let page = target & !(PAGE - 1);
                    if is_zero_raw_cover(pe, page) && page_looks_live(dump_buf, page) {
                        pages.insert(page);
                    }
                }
                i += 5;
                continue;
            }
            i += 1;
        }
    }

    // Absolute image pointers in already-raw code pages (mov r64, imm64).
    for s in pe.sections.iter().filter(|s| {
        s.raw_size > 0
            && (s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                || s.name.starts_with(".wfix")
                || s.name.starts_with(".text"))
    }) {
        let lo = s.virtual_address as usize;
        let hi = lo.saturating_add(s.raw_size as usize).min(dump_buf.len());
        if hi.saturating_sub(lo) < 10 {
            continue;
        }
        let code = &dump_buf[lo..hi];
        let mut i = 0usize;
        while i + 10 <= code.len() {
            // REX.W + B8+r : mov r64, imm64
            if (code[i] & 0xF8) == 0x48 && (code[i + 1] & 0xF8) == 0xB8 {
                let imm = u64::from_le_bytes(code[i + 2..i + 10].try_into().unwrap_or_default());
                if imm >= image_base + 0x1000 && imm < image_base.saturating_add(image_size as u64)
                {
                    let rva = (imm - image_base) as u32;
                    let page = rva & !(PAGE - 1);
                    if is_zero_raw_cover(pe, page) && page_looks_live(dump_buf, page) {
                        pages.insert(page);
                    }
                }
                i += 10;
                continue;
            }
            i += 1;
        }
    }

    pages
}

fn is_zero_raw_cover(pe: &PeHeader, rva: u32) -> bool {
    pe.sections.iter().any(|s| {
        let end = s.virtual_address.saturating_add(s.virtual_size.max(PAGE));
        if rva < s.virtual_address || rva >= end {
            return false;
        }
        s.raw_size == 0 || s.header.size_of_raw_data == 0 || s.name.starts_with(".fill")
    })
}

fn page_looks_live(dump_buf: &[u8], page: u32) -> bool {
    let start = page as usize;
    let end = start.saturating_add(PAGE as usize);
    if end > dump_buf.len() {
        return false;
    }
    let non_zero = dump_buf[start..end].iter().filter(|&&b| b != 0).count();
    non_zero >= MIN_PAGE_NONZERO
}

fn zero_fill_section(va: u32, size: u32) -> PeSection {
    PeSection {
        header: ImageSectionHeader {
            name: *b".fill\0\0\0",
            virtual_size: size,
            virtual_address: va,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        },
        name: ".fill".to_string(),
        virtual_address: va,
        virtual_size: size,
        raw_offset: 0,
        raw_size: 0,
        characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        extra_data: None,
    }
}

fn file_alignment(pe: &PeHeader) -> u32 {
    let fa = pe.nt_headers.optional_header.file_alignment;
    if fa.is_power_of_two() && fa >= 0x200 {
        fa
    } else {
        0x200
    }
}

fn next_file_raw_offset(pe: &PeHeader) -> u32 {
    let mut raw_offset = 0u32;
    for s in &pe.sections {
        if s.header.size_of_raw_data == 0 {
            continue;
        }
        let end = s
            .header
            .pointer_to_raw_data
            .saturating_add(s.header.size_of_raw_data);
        if end > raw_offset {
            raw_offset = end;
        }
        // Also account for extra_data not yet reflected in header (defensive).
        if let Some(ref extra) = s.extra_data {
            let end2 = s
                .header
                .pointer_to_raw_data
                .saturating_add(extra.len() as u32);
            if end2 > raw_offset {
                raw_offset = end2;
            }
        }
    }
    crate::utils::align_up(raw_offset, file_alignment(pe))
}

/// Build one executable CODE section covering `[va, va+size)`.
/// Returns the section and the next free file raw offset after it.
fn wrapper_span_section(
    va: u32,
    size: u32,
    bytes: Vec<u8>,
    raw_offset: u32,
    file_align: u32,
) -> (PeSection, u32) {
    let raw_size = crate::utils::align_up(bytes.len() as u32, file_align.max(0x200));
    let mut raw = bytes;
    if (raw.len() as u32) < raw_size {
        raw.resize(raw_size as usize, 0xCC);
    }
    let next = crate::utils::align_up(raw_offset.saturating_add(raw_size), file_align);

    let sec = PeSection {
        header: ImageSectionHeader {
            name: *b".wfix\0\0\0",
            virtual_size: size,
            virtual_address: va,
            size_of_raw_data: raw_size,
            pointer_to_raw_data: raw_offset,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: IMAGE_SCN_CNT_CODE
                | IMAGE_SCN_MEM_EXECUTE
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
        },
        name: ".wfix".to_string(),
        virtual_address: va,
        virtual_size: size,
        raw_offset,
        raw_size,
        characteristics: IMAGE_SCN_CNT_CODE
            | IMAGE_SCN_MEM_EXECUTE
            | IMAGE_SCN_MEM_READ
            | IMAGE_SCN_MEM_WRITE,
        extra_data: Some(raw),
    };
    (sec, next)
}

fn section_has_raw_for_rva(pe: &PeHeader, rva: u32) -> bool {
    pe.sections.iter().any(|s| {
        let end = s
            .virtual_address
            .saturating_add(s.virtual_size.max(s.raw_size));
        s.raw_size > 0 && rva >= s.virtual_address && rva < end
    })
}
