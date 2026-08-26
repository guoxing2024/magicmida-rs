# GTO-COLD-START-HEAP-REBASE-1 — H1 Heap/Container Model Recovery

> status: MILESTONE — heap/container model recovered from observation-only runs (2026-08-20)
> stage: H1 (deliverables 1-5 present; deliverable 6 = cold-start failure timeline, see H3 report)
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H1_model\
> source revision: cd727d44674d9759ece14aeeda322d5b23fba60a
> input: rev-2 vault object sha256 11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86
> method: observation-only channel (MIDA_GTO_OBSERVATION_ONLY=1), no-bураs​s,
>         no bypass/semantic-repair, debugger-side reads only

## 1. Heap region inventory (deliverable 1)

Two runs (attempt_006, attempt_007) on the SAME immutable input, different
ASLR layouts:

| class | attempt_006 | attempt_007 |
|---|---|---|
| image-inline heap-global slots | 8 | 7 |
| heap-handle plant slots | 1 | 1 |
| heap-graph children (log lines) | 192 | 192 |
| dangling-edge pass (pre-scrub) | 75 | 80 |
| summary count (post-CRT restore) | 320 | 320 |
| graph_children | 311 | 312 |
| heap_handle_slots | 1 | 1 |
| total_bytes | 715432 | 886512 |
| rejected_fill_only / rejected_cookie | 0 / 0 | 0 / 0 |

The 192 log-line children are the direct heap-graph edges from image slots;
the dangling pass adds the rest. Every region has: heap VA (ASLR-moved),
size, round, parent priority, provenance (slot / handle / graph child /
dangling).

### Image-inline slots (stable RVAs — the deterministic anchor set)

| rva | attempt_006 heap | attempt_007 heap | size | xref |
|---|---|---|---|---|
| 0x180940 | 0x8cffa0 | 0x90ff30 | 32512 | 54 |
| 0x181698 | 0x2ff0ff8 | 0x3160ff8 | 7936 | 18 |
| 0x181088 | 0x8bb070 | 0x8facd0 | 8192 | 16 |
| 0x183eb0 | 0x324b3d0 | 0x319b3d0 | 8192 | 12 |
| 0x183ea8 | 0x3276720 | 0x31c6720 | 8192 | 10 |
| 0x180880 | 0x8be5b0 | 0x8fd440 | 8000 | 5 |
| 0x180628 | 0x8a8ce0 | 0x8e8ce0 | 8192 | 2 |
| 0x180620 | 0x8ba380 | (absent run2) | 3312 | 8 |

Common across BOTH runs: 7/8 RVAs (0x180628 0x180880 0x180940 0x181088
0x181698 0x183ea8 0x183eb0). 0x180620 present only in run 1.

### Heap handle slot

rva=0x180fb0 -> PEB process-heap (count=1), xref=26 (run1) / xref=16 (run2).

## 2. Allocation timeline (deliverable 2)

- round=1 children (parent_pri=100): direct heap objects from image slots —
  sizes 40..8192; 33+ objects in 0x40..0x100 range (AHK String objects)
- round=2 children (parent_pri=99): second-level objects (containers/lists)
- rounds 3-4: deeper graph
- dangling-edge pass: 75/80 edges added AFTER the graph rounds (pre-scrub)
- PEB heap handle enumerated BEFORE slots; post-CRT restore count computed
  AFTER capture (Detected ... count=320)

Timeline (ms): process create @0 → PEB patch → main thread resumed → IAT
resolved @1000 → first .text exec @2000-2001 → frozen @2001 → capture @~3.6s
(all within the 120 s authorized window).

## 3. Region hash/diff (deliverable 3)

- per-region content hashes are produced by the dump pipeline (raw_slab
  coherence, capture identity bind); the H1 inventory records structural
  identity (rva/heap/size/xref/round)
- cross-run deltas: heap VA moves (ASLR), sizes stable, counts stable
  (320/320), graph children 311 vs 312 (1-edge nondeterminism), dangling
  75 vs 80 (5-edge nondeterminism) — the nondeterminism is confined to
  low-priority graph edges, not the anchor set
- the two runs' full slot tables are in h1_inventory.json (all_slots)

## 4. Pointer graph (deliverable 4)

Classes observed:

- image slot → heap object (8+ edges from stable RVAs)
- heap object → heap object (round 1-4 children, parent_pri 100..)
- PEB heap handle → heap base (1 edge)
- image slot → module VA (IAT slots, e.g. 0x175b7c)
- gscript label table → child (GscriptFirstHop probe; the 8-byte probe
  children are the wall class — see H3 report §3)
- code xrefs into fill/.data candidate ranges (xref_sites=1935,
  unique_slots=276, data_ranges=1)

Pointer widths: 8 bytes; tagged pointers suspected in AHK object headers
(see H2 classification candidates); relative displacements in .text remain
module-relative (OEP wrapper 0x140105a58 -> 0x106114 rule=msvc_x64_pe_entry_wrapper).

## 5. Base-relative field candidates (deliverable 5)

Stable image-slot RVAs (7/8 common) are the deterministic base-relative
anchor: slot VA = image_base + rva ALWAYS (0x140000000 + rva), while the
heap target VA moves with ASLR. Candidates for H2 rebasing:

- image slot content: heap-relative pointer (delta = heap_target - old_heap_base)
- image slot content: module-relative (IAT thunk 0x175b7c style)
- heap object header fields: self-pointers, size fields, cookie
  (container cookie 0x555fbf7273b3 observed in baseline r27 manifest)
- gscript label table count at +0x10 (stable offset, synthesized 128)
- AHK runtime global 0x141bf0 (sanitize_ahk_runtime_global zeroed re-init
  slab rva=0x141bf0 old_size=32320 new_size=384 — a base-relative candidate)

## 6. Cold-start failure timeline (deliverable 6)

See docs/GTO_COLD_START_HEAP_REBASE_1_H3_OBSERVATION_REPORT.md:
- stage timeline: capture_heap_slab (0 items) -> normalize_authoritative_slabs
  (75/80) -> capture_identity_bind (320) -> capture_coverage_bind (FAIL)
- deterministic fail-closed wall: GscriptFirstHop 8-byte probe children
  outside authoritative slab coverage
- no candidate produced; exit 1; every observation fail-closed

## 7. Tooling

tools/_gto_h1_inventory.py — parses observation stderr into structured
inventory (ANSI-aware, BOM-aware); reproducible:

    python tools/_gto_h1_inventory.py <stderr1> <stderr2> --out h1_inventory.json

## 8. H2 input summary

- rebasing axes: old_heap_base->new_heap_base (heap VA), old_module_base->
  new_module_base (module VA); anchor = stable image-slot RVAs
- classification categories needed: heap-internal ptr, module VA, RVA,
  vtable/fnptr, tagged ptr, relative displacement, non-pointer int,
  checksum/encoded field
- nondeterminism budget: 1-5 graph edges per run (must NOT break the model)

## 9. Non-claims

- NOT product 1.0; NOT wall-passed; NOT a candidate; observation-only
- heap content hashes are pipeline-produced (not re-hashed here); the H1
  inventory records structural identity only
- ADR7 frozen; Oreans gate untouched
