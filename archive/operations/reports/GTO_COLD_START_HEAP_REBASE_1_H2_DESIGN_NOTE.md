# GTO-COLD-START-HEAP-REBASE-1 — H2 Design Note: first-hop slab coverage gap

> status: ANALYSIS COMPLETE — fix direction established (2026-08-20)
> stage: H2 input (rebasing primitives + capture model completeness)
> source revision: 8aa90d2 (this analysis; no code change yet)

## 1. Root cause of the current wall (capture_coverage_bind)

Deterministic failure (2/2 runs, different ASLR layouts):

```text
GTO_UNPACK_FAILED stage=capture_coverage_bind
probe/interior HeapGlobal <addr>,+0x8 extent=ProbeWindow
  not covered by any authoritative slab
  (candidate_slab_count=75/80, gap=0x9ccf0 / 0x2dd1300)
producer provenance: capture_id="graph_child:<addr>"
  capture_path="GscriptFirstHop"
```

## 2. Mechanism (verified in source)

1. detect_heap_globals (heap_global_snapshot.rs:874) runs:
   - hot roots -> image-inline gscript -> **exhaust_gscript_first_hop** (p21,
     force-admits every heap pointer in the gscript first-hop span) ->
     child-link fields -> label table exhaust -> sanitize
2. capture_heap_slab (heap_global_snapshot.rs:798) then computes ONE
   contiguous span via compute_heap_slab_span (line 738):
   - min_ptr..max_end over raw-coherence participants
   - **DanglingEdge captures are explicitly EXCLUDED** (they get their own
     dedicated slabs — Route T R0-B)
   - returns None if span > MAX_HEAP_SLAB_BYTES
3. normalize_authoritative_slabs folds main slab + dedicated dangling slabs
   + closure candidates -> authoritative set (75/80 items)
4. capture_coverage_bind (dump_process.rs:1237 -> validate_probe_coverage
   raw_slab_coherence.rs:3282) requires EVERY ProbeWindow/InteriorSubview
   child to be contained in EXACTLY ONE authoritative slab
5. FAIL: first-hop children whose address lies OUTSIDE the single main span
   (AHK multi-heap layout: process heap + private heaps + CRT heap) are
   uncovered -> ProbeCoverageMissing

## 3. Why fail-closed is CORRECT (do not weaken the gate)

- an 8-byte window at an arbitrary address is NOT proof of a heap extent
- the gate runs BEFORE transforms/overlay; relaxing it would let a stale or
  misread pointer flow into the rebase planner and corrupt the object graph
- Route T R0-A/TAF1-D designed this gate explicitly; ADR7/raw-coherence
  evidence stack depends on it

## 4. Fix direction (H2 implementation task)

Mirror the Route T R0-B dangling-edge pattern for first-hop children:

- in detect_heap_globals, when exhaust_gscript_first_hop admits a child at a
  VA outside the eventual main-slab span, surface it as a DEDICATED
  authoritative slab candidate (role="first_hop") instead of relying on the
  single main span
- the dedicated slab must carry capture-path provenance (GscriptFirstHop)
  and exact-size evidence (the child's probe size is NOT an allocation
  boundary proof — use the child's own read window + parent-slot offset
  evidence; mark extent_kind accordingly)
- coverage gate stays unchanged: any child inside a dedicated slab is then
  covered exactly once
- children whose address is NOT heap-like (below MIN_USER_POINTER, above
  MAX_USER_POINTER, or unreadable) must still fail closed (they are bad
  pointers, not missing slabs)

Acceptance for the fix:
- attempt_006/007 both pass capture_coverage_bind
- every admitted first-hop child is covered by exactly one slab
- no blanket +delta; no relaxation of fail-closed semantics
- regression: cargo test -p mida-pe --lib (raw_slab_coherence tests),
  ADR7 verifier PASS, Oreans offline gate

## 5. H2 rebasing primitives (unchanged scope)

- old_heap_base->new_heap_base + old_module_base->new_module_base
- classification categories: heap-internal ptr, module VA, RVA, vtable/fnptr,
  tagged ptr, relative displacement, non-pointer int, checksum/encoded
- unknown fields fail closed; classification provenance per slot
- acceptance: two different ASLR layouts rebuild the same logical object
  graph (attempt_006 vs attempt_007 ARE the two layouts — the fix can be
  validated directly on them)

## 6. Non-claims

- analysis only; NO code change committed with this note
- the wall remains a capture-model gap, not a gate defect
- ADR7 frozen; Oreans gate untouched
