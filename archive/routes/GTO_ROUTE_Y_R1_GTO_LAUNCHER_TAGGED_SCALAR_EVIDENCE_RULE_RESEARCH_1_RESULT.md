# RouteY_R1_GTO_LAUNCHER_TAGGED_SCALAR_EVIDENCE_RULE_RESEARCH_1 — Result

**Status:** `RouteY_R1_GTO_LAUNCHER_TAGGED_SCALAR_EVIDENCE_RULE_RESEARCH_1_Residual`
**Mode:** OFFLINE / EVIDENCE / STATIC-ANALYSIS-ONLY
**Date:** 2026-08-14T11:03:09.460Z

## What 0x2ffeeffee is (corpus-derived)

An **AHK tagged value in a SimpleHeap bump-allocated object/array value slot**:
8-byte `[payload 32-bit][tag byte][len byte][pad 16-bit]`, tag byte `0x02` at byte[4],
payload `0xEEFFEEFF` at bytes[0..3], zero pad bytes[5..7]. Evidence:

- Slot structure: at every research_run2 site, +8/+0x10 neighbors are REAL captured heap pointers
  (0x3200018, 0x1780120, ...) — tag slot adjacent to object data pointers.
- 0x30000 (192KB) stride between sites = same slot index in consecutive SimpleHeap buckets.
- Identical bytes across 2 ASLR-different runs (layout-independent constant, NOT an address).
- 55,135 tag-namespace values; 0x02 family carries 4CC ASCII identifiers (MLKR/TIOX/HReq/HCon).

## Producer evidence

**write_site = unresolved** — the artifact .text is PACKED (entropy 7.998 bits/byte); direct
disassembly impossible without unpacking. 0 static hits of the value bytes in the image.

## Counterexample proof (decisive)

Proposed rule (tag namespace + tag byte set + zero-pad + **membership override**) tested on the
full 192,575-entry corpus:

```text
tag-namespace values              55,135
rule excludes (tag-sig + outside) 47,324
real image pointers in tag-ns     7,811  (all preserved)
false negatives                   0
false positives                   0
```

The membership override is the structural safeguard: `0x140000000` (image base) has tag-like
shape but is inside the image span → preserved. No real heap/module/handle-relative/image pointer
is mis-excluded.

## Decision

**B — evidence insufficient for a future implementation ticket.**

The rule is general (not value/address/threshold-specific) and passes every counterexample check,
but the encoding model is CORPUS-DERIVED only. The producer write-site is unresolved (packed code).
Per the strict gate, producer semantics must be confirmed at code level (after unpacking) before
authorizing `RouteY_R1_GTO_LAUNCHER_TAGGED_SCALAR_EVIDENCE_EXCLUSION_IMPLEMENTATION_1`.

`0x2ffeeffee` remains **unknown + required = true**.

## Deliverables

14 files in `D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_tagged_scalar_evidence_rule_research_1_20260814T113000Z\
` (9 payloads + manifest/sidecar/selfcheck/freeze_before/freeze_after).
Manifest SHA `f6d4f84a59039425e1ceabe825a9cef2da8eea60262981b1da784e3d7984de89`, selfcheck PASS,
strict order verified.

## Boundaries

No source change, no rebuild, no sample rerun, no production driver, no A6, no scheduled task,
no module resolver / heap-hole / slab normalization / declaration-pipeline change, no value/address-
specific rule, no commit/push/git add, no historical evidence-root overwrite.
