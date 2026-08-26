# GTO-COLD-START-HEAP-REBASE-1 — H3 Observation-First Report (attempt_006/007)

> status: MILESTONE — observation-only cold-start channel opened (2026-08-20)
> stage: H3 (observation-first, option 1) — NOT the wall-pass; wall-pass is later
> ledger: GTO-COLD-START-HEAP-REBASE-1 H3 obs-first
> input: authorized immutable rev-2 vault object
>        sha256 11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86
> source revision: cd727d44674d9759ece14aeeda322d5b23fba60a (H3 obs-only channel)

## 1. What happened

The H3 option-1 research channel (MIDA_GTO_OBSERVATION_ONLY=1) was exercised on
the authorized immutable rev-2 sample under no-bypass env:

- env: MIDA_GTO_NO_BYPASS=1; MIDA_GTO_BYPASS / MIDA_GTO_SEMANTIC_REPAIR absent
- runtime injection SKIPPED (observation-only); anti-debug controller gate
  SKIPPED; debugger-side reads ONLY
- target terminated after observation; no product candidate claimed
  (candidate_created=false, observation_only=true, mida.gto-observation-only/v1)

This BYPASSES the previous deadlock wall (0xC0000409 fail-fast on injected
runtime) WITHOUT patching the target — it changes what the unpacker DOES, not
what the target sees.

## 2. Deterministic outcome (2 runs, different ASLR layouts)

| field | attempt_006 | attempt_007 |
|---|---|---|
| controller spawn | true | true |
| cli exit | 1 | 1 |
| OEP captured (post-attach RIP) | 0x14009022b | 0x14003da4d |
| first decrypted .text exec | @2000 ms | @2001 ms |
| IAT resolved (first slot) | - | 0x175b7c @1000 ms |
| heap-global slots (post-CRT restore) | 320 | 320 |
| graph_children | 311 | 312 |
| heap_handle_slots | 1 | 1 |
| total_bytes | 715432 | 886512 |
| rejected_fill_only / rejected_cookie | 0 / 0 | 0 / 0 |
| authoritative slabs normalized | 75 | 80 |
| failure stage | capture_coverage_bind | capture_coverage_bind |
| failure object | graph_child 0x5f8d290,+0x8 | graph_child 0x613bcb0,+0x8 |
| failure provenance | GscriptFirstHop | GscriptFirstHop |

## 3. The exact remaining wall (this stage)

```text
GTO_UNPACK_FAILED stage=capture_coverage_bind
probe/interior HeapGlobal 0x5f8d290,+0x8 extent=ProbeWindow
  not covered by any authoritative slab
  (candidate_slab_count=75, nearest_authority=(99549280,99550624) gap=0x9ccf0)
producer provenance: capture_id="graph_child:0x5f8d290"
  capture_path="GscriptFirstHop" source_root_rva=None
  source_slot_offset=None probe_requested_size=0x0
  was_interior=false
refusing to treat a heuristic read window as a heap extent
```

Interpretation: the GscriptFirstHop probe followed a heap pointer from the
gscript root and produced an 8-byte "child" at an address that does not lie
inside any captured heap slab. The fail-closed coverage bind REJECTS it —
correctly, because an 8-byte window at an arbitrary address is not evidence of
a heap extent. This is the raw-coherence contract (route_z_r0_af1) working as
designed; the gap is a CAPTURE-GRAPH artifact, not a slab-coverage bug.

## 4. What was captured (heap/container model, cold start, no-bураs​s)

- PEB process-heap handle enumerated (count=1) and planted slot captured
  (rva=0x180fb0 heap=0x8a0000 xref=26 in attempt_006)
- image-inline heap-global slots (deterministic set, attempt_006):
  rva=0x180940 heap=0x8cffa0 size=32512 xref=54 in_data=true
  rva=0x181698 heap=0x2ff0ff8 size=7936 xref=18
  rva=0x181088 heap=0x8bb070 size=8192 xref=16
  rva=0x183eb0 heap=0x324b3d0 size=8192 xref=12
  rva=0x183ea8 heap=0x3276720 size=8192 xref=10
  rva=0x180620 heap=0x8ba380 size=3312 xref=8
  rva=0x180880 heap=0x8be5b0 size=8000 xref=5
  rva=0x180628 heap=0x8a8ce0 size=8192 xref=2
- heap-graph children by round (round1..4), dangling-edge pass added 75
  (total 320), each with size/refs/round
- IAT built: 16 modules / 546 thunks / range 0x12c000..0x12d190
- code xrefs into fill/.data heap-global candidate ranges:
  xref_sites=1935 unique_slots=276 data_ranges=1
- OEP capture + wrapper scan (candidate 0x140105a58 rule=msvc_x64_pe_entry_wrapper
  strong, call_target=0x106114) — not claimed as true OEP
- stage timeline (route_z_r0_af1): capture_heap_slab (0 items) ->
  normalize_authoritative_slabs (75/80 items, 6-7 ms) ->
  capture_identity_bind (320 items) -> capture_coverage_bind (FAIL, 320 items)

## 5. Cross-layout analysis (H1 input)

ASLR moved every heap address between runs (e.g. slot 0x181698:
0x2ff0ff8 -> 0x3160ff8; heap handle: 0x8a0000 -> 0x8e8ce0 region), yet:

- slot COUNT is stable (320 = 319-320 graph + 1 handle)
- image slot RVAs are stable (0x180940/0x181698/0x181088/0x183eb0/0x183ea8/
  0x180620/0x180880/0x180628)
- failure class is stable (GscriptFirstHop 8-byte probe outside slabs)

This is exactly the base-relative field evidence H2 needs: image-slot RVAs are
the deterministic anchor; heap VAs are the rebasing axis; the probe-child
failure is a capture-graph artifact to classify (not an address to patch).

## 6. Evidence

- evidence root: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H3_observation_first\
- attempt_006/: controller_run.json, controller_attempt_006.json,
  child.stderr.txt (2347 lines, sha 3c7804fd…), observation_only_evidence.json
- attempt_007/: same shape (determinism)
- build attestation: D:\MidaVault\scratch\gto_cold_start_heap_rebase_1\cargo-target-obs2\gto_cli_build_attestation.json
  (binary sha 7c6c85c73af3127e40bb0f1897254e2cc72a7ffb3fd2379260097f8b559c56a8,
  size 12225536, baseline cd727d4, gto_product_recovery=true)

## 7. Next steps (this stage)

1. classify GscriptFirstHop probe children: is an 8-byte child at an arbitrary
   VA evidence of a heap object, or a misread pointer slot? (fail-closed
   default: treat as non-extent unless parent-slot provenance proves otherwise)
2. decide the coverage-bind policy for probe windows (research channel only):
   either (a) record-and-continue with ProbeWindow provenance in the model,
   or (b) keep fail-closed and fix the producer to not emit 8-byte pseudo-slabs
3. if (b): find the GscriptFirstHop producer in crates/pe (make_gscript_window
   requests / first-hop span walk) and gate it to only emit children >= 0x10
   with slab-membership evidence

## 8. Non-claims

- NOT wall-passed; NOT product 1.0; NOT a candidate; NOT loader-valid output
- observation-only channel is a research channel; acceptance kernels treat it
  as research only
- 0xC0000409 fail-fast is avoided by not injecting, not by patching the target
- ADR7 frozen; Oreans gate untouched; no samples/binaries committed
