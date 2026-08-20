# GTO-COLD-START-HEAP-REBASE-1 — H2 rebasing primitives: COMPLETE (2026-08-20)

> status: H2 DONE — plan builds complete; wall moved to bootstrap_install (H4 marker)
> input: pinned manifest rev 2 sample (11473d2e…), immutable authorized GTO
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H3_observation_first\attempt_006..021 (pre-fix walls) + H2_cross_layout_correction_1\layout_A, layout_B (post-fix cross-layout)
> env: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1, no bypass/semantic-repair
> gate: capture_coverage_bind fail-closed, unchanged throughout

## 1. Deliverables vs boundary §5-H2

| deliverable | state |
|---|---|
| old_heap_base -> new_heap_base primitive | DONE (ViaCapturedRegion, plan/alias model) |
| old_module_base -> new_module_base primitive | DONE (ViaStableBinding, plan layer) |
| classification-driven (PointerClassification) | DONE (InImage/InCapturedRegion/ExternalModule/StackEphemeral/ModuleBoundaryCache) |
| two different ASLR layouts rebuild same logical graph | VERIFIED (post-fix cross-layout: attempt_021 + H2_cross_layout_correction_1/layout_A + layout_B — regions_total=319/319/319, unresolved_required=0/0/0) |
| unknown fields fail closed | PRESERVED (empty module_ranges; ambiguous; conflicts) |
| classification provenance recorded per slot | DONE (ledger, kind_counts, reason, confidence) |

## 2. Wall sequence crossed (each a commit, evidence attempt)

1. capture_coverage_bind ProbeCoverageMissing — 5226aff (H2 first version)
   - first-hop probe children outside single main-slab span (AHK multi-heap)
2. split-sibling interior child with LOST parent authority — b3441b4
   - was_interior=true + containing_parent_old_base=None (heuristic parent)
3. duplicate external resolver (ws2_32 rva 0x25770) — 3bba2ff
   - forwarder DLL / alias imports: one export, one resolver
4. stack/TEB-reserved pointer 0x7ffffffdefff — 03a5533
   - ephemeral per-process state, never a persistent edge
5. external_candidate ntdll rva 0x1d3070 — 457caf1
   - module-attributed pointer without IAT resolver -> ViaStableBinding
6. ntdll base+0x2662a4 deterministic — d1bc465
   - Toolhelp modBaseSize under-reports; PE SizeOfImage is loader truth
7. module boundary cache (158/158 module-zone values) — cce8407 + b883691
   - AHK module address-range boundary cache slots, not pointers

## 3. Terminal observation (attempt_021)

Full pipeline success until bootstrap_install:
- capture_coverage_bind: exit OK
- raw_slab_overlay: exit OK (2366 ms) — Route O historical failure point cleared
- IAT rebuild: written=562 total=562
- runtime_rebase_plan_build: regions_total=319 required=319
  bytes_captured=701816 pointer_slots=10532
- bootstrap_install: FAIL-CLOSED by design:
  "ViaStableBinding resolver present — cold-start module re-base (H4) not
   yet implemented in the two-phase stub; refusing to emit a broken fixup"

This is the H2/H4 boundary: H2 supplies the PLAN primitive; the cold-start
stub execution of ViaStableBinding (GetModuleHandleW + rva, metadata module
name table) is H4 work.

## 4. Evidence

- attempts 006-021: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H3_observation_first\
- plan_research.json (attempt_019): full 158-value unresolved analysis
- commits: 5226aff b3441b4 3bba2ff 03a5533 457caf1 d1bc465 cce8407 b883691 (implementation), 4b8f8fb (report)
- CROSS-LAYOUT post-fix evidence (GTO-H2-AUDIT-CORRECTION-1 / 派单 B):
  - H2_cross_layout_correction_1/layout_A/  (pid 18808)
  - H2_cross_layout_correction_1/layout_B/  (pid 8196)
  - H2_cross_layout_correction_1/cross_layout_acceptance.json
  - 3 layouts (attempt_021 + A + B): regions_total=319/319/319, regions_required=319/319/319,
    unresolved_required=0/0/0, IAT 562/562 each, terminal bootstrap_install fail-closed
    (ViaStableBinding resolver present — H4 marker, expected)
- NOTE attempt_006/007: PRE-FIX deterministic capture_coverage_bind failures (exit 1,
  ProbeCoverageMissing). They are NOT post-fix two-layout rebuild evidence; they
  document the deterministic pre-fix wall (2 different ASLR layouts, same failure
  class). Post-fix cross-layout evidence is attempt_021 + layout_A + layout_B.

## 5. Non-claims

- NOT product 1.0; NOT perfect unpack; NOT cold-start wall closed
- No bypass; no target patching; no gate removal
- ADR7 frozen; Oreans gate untouched; no samples/binaries committed
- ViaStableBinding stub execution NOT done (explicit H4 marker)
