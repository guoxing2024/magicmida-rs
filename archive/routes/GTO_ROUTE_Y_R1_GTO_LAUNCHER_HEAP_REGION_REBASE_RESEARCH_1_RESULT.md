# RouteY_R1_GTO_LAUNCHER_HEAP_REGION_REBASE_RESEARCH_1 — Research Ready

**Status:** `RouteY_R1_GTO_LAUNCHER_HEAP_REGION_REBASE_RESEARCH_1_ResearchReady` (Result A: research complete, ready for implementation)
**Class:** OFFLINE / CONTROLLED RESEARCH — no production qualification, no A6 rerun, no driver start, no scheduled task, no historical evidence rewrite.

## 1. Work-order residual — uniquely identified

`runtime_rebase_plan_validation: declared pointer (unmapped, region 2 @ 0x7b0) is unresolved-required`

- **round2b region 2** = main heap slab (old_base 0x2ff000, span 0x3209980). Slot @ 0x7b0 held **0x846898** — a stale heap
  pointer computed at runtime, falling in an uncaptured **0x318-byte gap** before object 0x846bb0 (WORKER_HANDOFF r27).
- **Fresh reproduction** (same input, diagnostic build) is **layout-dependent**: run2 first-unresolved was
  `(external_candidate, region 2 @ 0x178)` = **0x7ffd47493070 ∈ ntdll.dll**, source = a dedicated dangling-edge heap slab
  (0x960150,+0x1000). Research run1 hit an earlier wall: `capture_slab_normalize` authoritative slab overlap
  `[0x87b000,+0x2ee7080) vs [0x87aca0,+0x670) partial_overlap`.
- **Wall class is deterministic** (declared-pointer resolution failure); **instance is ASLR-dependent** (which slot sorts first).

## 2. Full census (env-gated plan dump, run2)

192,575 declared pointer slots, 5 regions, **129,797 unresolved-required**:

| bucket | count | semantics |
|---|---|---|
| A in-gap heap pointers [0x961150,0x96b000) | 144 | real interior pointers into uncaptured holes → must capture+rebase |
| B external_candidate in module range | 4,620 | real API pointers (ntdll/kernel32/user32) → must resolve (non-IAT) |
| C external_candidate outside module | 2,357 | unknown → classify or ignore |
| D tags/bitfields ≥0x100000000 | 89,603 | **NOT pointers** (AHK type tags/sentinels) → exclude |
| E small <0x1000000 | 27,848 | **NOT pointers** (offsets/counts) → exclude |
| F mid-range 0x1000000..0x100000000 | 5,369 | mixed → per-value classify |

**90.5% of the unresolved-required wall is non-pointer qwords mis-declared by the raw qword sweep** in
`declared_slots_from_capture`. The genuine wall is 144 in-gap heap pointers + 4,620 unresolvable-but-real API pointers.

## 3. Root cause (answers every work-order question)

See `root_cause_report.md` (13.5 KB) — covers: which pointer/object/field (region 2 @ 0x7b0 = 0x846898; run2 region 2 @
0x178 = 0x7ffd47493070); why the target falls in an uncaptured region (prefix-pad/inter-region holes + IAT-only resolvers +
blind qword sweep); hole class (pre-object gap / dangling-edge slab overlap / non-IAT external / tag non-pointer); why capture
misses it; why the plan marks it required (correct fail-closed semantics, upstream over-declaration defect); reference
existence (inherent to the sample's AHK object graph; protected run resolves the same classes natively); whether to capture /
rebuild / reclassify (table); and how to fix without weakening fail-closed (5-step design).

## 4. Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_heap_region_rebase_research_1_20260814T052046Z\`
37 payloads, manifest SHA256 `971fc1f712f9b3622ee0edcdbe676ba35fbdbdf319c5f99a920f5d5bda7439a2`, selfcheck PASS (37/37, 0 mismatch, 0 missing).
Required deliverables: heap_region_inventory.json, pointer_resolution_trace.json, unresolved_required_pointer.json,
capture_region_map_before/after.json, runtime_rebase_plan_before/after.json, pointer_graph_oracle.json,
reference_vs_candidate_comparison.json, root_cause_report.md, patch_identity.json, rebuild_identity.json,
freeze_before/after.json, evidence_freeze.json/.sha256/selfcheck, final_status.json + traces + diffs + SHAs.

## 5. Working-tree baseline (preserved, per work order)

- HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403`, branch `oreans/two-sample-mainline`, diff --check = 0.
- `git diff -- crates/pe/src/dumper/dump_process.rs` frozen in `diff_dump_process_before.txt` (939 B).
- Worktree SHAs frozen: dump_process 355c4968, heap_global_snapshot (r2), raw_slab_coherence (r2), snapshot_manifest (r2).
- R2 artifact SHAs frozen (round2b stderr both copies).
- R2 experimental patch **not discarded, not overwritten** — research change is additive (runtime_rebase.rs only).
- Nothing committed/pushed (git status 57 lines: 5 modified tracked + untracked docs).

## 6. Discipline attestation

- Validator semantics unchanged (`is_unresolved_required`/validation loop untouched); fail-closed error prefix byte-identical.
- Research-only diagnostics: env-gated plan dump + enriched error suffix. No sample-specific branch, no SHA check, no bypass.
- production_driver_started=false, a6_rerun=false, scheduled_task_created=false, historical_evidence_rewritten=false.
