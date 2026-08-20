# GTO-COLD-START-HEAP-REBASE-1 — H1 heap/container model (2026-08-20)

> status: H1 MODEL DELIVERABLES DONE (offline evidence synthesis)
> inputs: pinned manifest rev 2 sample (11473d2e…), source revision 96cd929
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H1_model\
> tools: tools/_gto_h1_snapshot_analyzer.py, tools/_gto_h1_failure_timeline.py

## 1. Heap region inventory (deliverable 1)

Snapshot manifest analysis (mida.dump-snapshot-manifest/v0) of 4 baseline runs:

| run | regions | container | heap_global | roots | children | handles |
|---|---|---|---|---|---|---|
| r27_nobypass_round0 | 322 | 1 | 321 | 33 | 287 | 1 |
| scan60 | 321 | 1 | 320 | 32 | 287 | 1 |
| r4c | 321 | 1 | 320 | 31 | 288 | 1 |
| r25b | 322 | 1 | 321 | 29 | 291 | 1 |

- container: 1 per run, rva 0x145710, content 72 B, capacity 256 B, cookie varies
- heap_global roots: 29–33 per run (hot roots + capture roots)
- graph children: 287–291 per run (linked-list/table children)
- heap handles: exactly 1 per run (rva 0x145d50)

Full inventory: snapshot_region_inventory.json (runs.*.regions).

## 2. Allocation timeline (deliverable 2)

- live_ptr span per run:
  - r27: 0x1f1b40..0x140149d50 (span 0x13ff58210) — one pointer inside image range
  - scan60: 0x870000..0x6352200 (span 0x5ae2200)
  - r4c: 0x8f0000..0x7b38e80 (span 0x7248e80)
  - r25b: 0x200000..0x140149d50 (span 0x13ff49d50)
- every cold start allocates the heap/container graph at DIFFERENT bases
  (cross-run common live_ptrs: 1 of ~320) — the rebasing problem is real:
  no single fixed layout can be reused.
- size histogram (r27): <=0x40:134, <=0x400:144, <=0x1000:12, <=0x10000:23

## 3. Region hash/diff (deliverable 3)

- manifest sha256 per run recorded (see inventory file)
- cross-run live_ptr set diff (r27 vs scan60): only_a=320 only_b=319 common=1
- pointer graph edges: r27=1734, scan60=87, r4c=93, r25b=1788
  (edge count depends on capture depth: synthetic manifests capture fewer edges)

## 4. Pointer graph (deliverable 4)

- containment edges derived per run (from live_ptr + size) — see
  snapshot_region_inventory.json runs.*.pointer_graph_edges
- r27/r25b (deeper captures) show ~1700+ edges: dense internal graph
- scan60/r4c (synthetic, shallower) show ~90 edges

## 5. Base-relative field candidates (deliverable 5)

- r27: 3 candidates — 0x830000 (heap handle container live), 0x200000,
  0x201000 (low-base allocations — likely heap/container base anchors)
- r25b: 5 candidates — 0x940000 (container), 0x999000, 0x9e7000,
  0x200000, 0x201000
- 0x200000/0x201000 appear in BOTH r27 and r25b: candidate stable
  container/heap base region (or CRT heap anchor)
- image-range pointer in r27/r25b (0x140149d50) = module-VA-bound slot
  (candidate for module-base-relative field)

## 6. Cold-start failure timeline (deliverable 6)

Parsed from mida-cli stderr with ANSI stripping; full file:
cold_start_failure_timeline.json.

| run | terminal stage | failure |
|---|---|---|
| Route O R1 | raw_slab_overlay | raw capture drift: child 0x9f93e8 size 0x70 slab [0x9bf000,+0x2db3750) offset 0x3a3e8 first_mismatch=0x28 (probe-size over-estimate: child captured 0x70 but slab matches to 0x28) |
| Route X R1 | raw_slab_overlay | transform run ledger invalid: sanitize_ahk_runtime_global raw identity drift 32768 -> 384 (content.len) for old_base 0x3437e50 |
| Route Y1A6 | raw_slab_overlay | transformed write conflict: [0x8e93c8,+0x2000)@+0xa03 vs [0x8e9da8,+0x400)@+0x23 (scrub_uncaptured_heap_pointers vs scrub+mark_labels_non_nested) |

Interpretation: all three walls converge on the same root class — the
no-bypass cold candidate's heap/container raw state is NOT byte-identical to
the captured epoch state. Either (a) the capture over-estimates child size
(O), (b) the sanitize transform's raw identity expectation is stale (X), or
(c) two transforms write overlapping slabs with conflicting bytes (Y1A6).
These are exactly the "which fields are base-relative / which regions are
missing-or-delayed at cold start" questions H1 must answer before H2
(rebasing primitives) can be generic.

## 7. Non-claims

- NOT product 1.0; NOT perfect unpack; NOT heap-rebasing wall closed
- No sample bytes read; no target executed this stage; no bypass
- ADR7 frozen; Oreans gate untouched
