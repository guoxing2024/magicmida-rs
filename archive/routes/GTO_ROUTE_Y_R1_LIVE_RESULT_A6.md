# Route Y R1 A6 — Qualified Native Controller Single Protected Live Truth Run — RESULT

**Status:** `RouteY_R1_A6_CandidateNotReady`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This was the **single authorized protected-sample live truth run**. The live authorization **was consumed** (`controller_run.spawned=true`, `protected_sample_spawn_count=1`, `controller_pid=22388`). The mida-cli unpacked the frozen protected artifact through the full upstream production chain and **failed closed at the Q0-C overlay stage (`raw_slab_overlay`)** with a transformed write conflict. **No candidate was generated.**

---

## Final status

**`RouteY_R1_A6_CandidateNotReady`**

- spawn count: **1** (authorization consumed)
- candidate count: **0**
- live auth consumed: **true**
- **last successful stage:** `sanitize_ahk_runtime_global` (exit) — then `raw_slab_overlay` enter
- **first failing stage:** `raw_slab_overlay` (Q0-C overlay), event=error
- **first failing gate detail:** transformed write conflict between two transform chains

### Production-chain result

The full upstream chain **executed successfully** in production on the protected sample:

```
capture_heap_slab (exit)
normalize_authoritative_slabs (exit)
reconcile_duplicate_heap_globals (exit)
capture_identity_bind (exit)
capture_coverage_bind (exit, item_count=318)
raw_children_from_capture (exit, item_count=317)
transform_input_seed (exit)
scrub_uncaptured_heap_pointers (exit)
resynthesize_gscript_label_count (exit)
repair_label_names_after_scrub (exit)
sort_gscript_label_table (exit)
mark_labels_non_nested (exit)
sanitize_ahk_runtime_global (exit)
raw_slab_overlay (ERROR)  ← first failure
```

### Capture epoch (production, OS-proofed)

From child.stderr telemetry:
```
capture epoch handled; target unfrozen before offline seed/transforms
epoch_begun=true suspended_thread_count=7
suspended_thread_ids=[3000, 8060, 10564, 21600, 22040, 26132, 26976]
epoch_elapsed_ms=162 epoch_started_ms=1786469760083
```
The atomic capture epoch froze **7 target threads** and restored them (target unfrozen before offline seed/transforms) — the raw child C and authoritative slab S were captured in the same stationary epoch. Container/heap detection, raw children (317), and heap-global slots (318) were all captured.

### First-failing stage: raw_slab_overlay (Q0-C overlay)

```
[WARN] gto_stage_error stage="raw_slab_overlay" event="error" error="transformed write conflict:
[0x8e93c8,+0x2000)@+0xa03 vs [0x8e9da8,+0x400)@+0x23 first_mismatch_slab_offset=0x6fadcb
before=0x04 a_after=0x00 b_after=0x01
a_transform=["scrub_uncaptured_heap_pointers"]
b_transform=["scrub_uncaptured_heap_pointers", "mark_labels_non_nested"]"
[FATAL] Dump failed: GTO_UNPACK_FAILED stage=raw_slab_overlay ...
```
The Q0-C overlay **fail-closed** on a transformed write conflict: two transform chains (`scrub_uncaptured_heap_pointers` alone vs. +`mark_labels_non_nested`) wrote differing bytes (`a_after=0x00` vs `b_after=0x01`) into overlapping ranges `[0x8e93c8,+0x2000)` and `[0x8e9da8,+0x400)`. This conflict check correctly **rejected a bad candidate** (no `max(raw.size)`, no slab fallback, no binding relaxation) and produced **0 candidates** with exit code 1. The runtime rebase plan and bound transform manifest were **not reached** because the overlay gate failed first.

---

## Evidence

- **Bootstrap:** `D:\MidaVault\lab\evidence\gto_launcher\bootstrap_20260811T173546Z_route_y1_a6_live\`
  - `launch_record.json`, `driver_journal.jsonl` (15 phases; verdict CandidateNotReady), `driver_self_result.json` (success=false, final_status=CandidateNotReady, live_auth_consumed=true, spawn_count=1, candidate_count=0), `driver_finish.json`, `git_preflight.json` (0/0/21), `native_powershell_environment.json` (native, parent chain svchost→services→wininit, no MSYS), `supervisor_parent_chain.json`, `ps51_newitem_compat.json`, `exit_capture_negative_control.json` (7), `live_driver_delta.json` / `live_supervisor_delta.json` (both `all_forbidden_invariants_ok=true`), `driver_frozen_live.ps1.txt`, `driver.start.json`
  - **Note:** `driver.stdout.log`, `driver.stderr.log`, `driver.exit.json`, `supervisor_final_result.json` were **NOT written** — the supervisor process was aborted (Task Scheduler `LastTaskResult=-1073741510` = 0xC000013A STATUS_CONTROL_C_EXIT) after the driver completed its work but before the supervisor's post-driver final-result phase. The **driver's authoritative evidence is complete and correct**; this is a supervisor plumbing gap, not a driver/production failure.
- **Live evidence:** `D:\MidaVault\lab\evidence\gto_launcher\live_20260811T173546Z_route_y1_a6_declared_size_reinit\`
  - `controller_run.json` (spawned=true, pid=22388, exit_code=1, elapsed_ms=349969, timed_out=false, no_bypass_verified=true, build/policy preflight ok, last_observed_stage=raw_slab_overlay/error), `controller_attempt_001.json`, `live_result.json` (verdict CandidateNotReady, spawn_count=1, candidate_count=0), `child.stderr.bin` (102749 B, full stage sequence), `child.stdout.bin`/`child.stderr.txt`, `child.stdout.txt`, `controller.stdout.log`/`controller.stderr.log`, `binary_verification.json`, `build_attestation_copy.json`, `sample_controller_policy_contract.json`, `powershell_python_argv_transport_probe.json`, `argv_static_verification.json`, `controller_argv_ready.json`, `capture_policy.json`, `evidence_freshness.json`, `evidence_write_probe.json`, `candidate/` (empty)

### Script identities (live `Get-Item.Length`)

| Script | SHA-256 | Size | Parent |
|---|---|---|---|
| `route_y1_a6_live_driver.ps1` | `d4ae91aa1a2ac9a3efea769b2823baca307acf898f70811080f37bff430b2985` | 23305 | C2 `38112eea…` |
| `route_y1_a6_live_supervisor.ps1` | `806098bbabfd79f43f311f459bdec84142ede04191b6a7ee7642f8f197f32535` | 8484 | C2 `60ee7982…` |

Delta vs C2: both `live_driver_delta.json` and `live_supervisor_delta.json` report `all_forbidden_invariants_ok=true` (PS5.1, native chain, freshness, journal, ProcessStartInfo, OS exit capture, negative control, failure propagation, no-MSYS, no LiteralPath, env allowlist w/o benign, timeout=600, no-bypass, no semantic-repair, no `--`, no `//unpack`). Static gate `New-Item.*-LiteralPath`=0.

### Frozen inputs (recomputed live)

| Item | Path | SHA-256 | Size |
|---|---|---|---|
| canonical mida-cli | `D:\MidaVault\scratch\cargo-target-route-y1-a6-live\debug\mida-cli.exe` | `20e10bf3…` | 11072000 |
| fresh attestation | `…\gto_cli_build_attestation.json` | gto_product_recovery=true, baseline=f386b49a… | — |
| protected sample | `D:\MidaVault\vault\sha256\4d\4d5770af…\artifact.exe` | `4d5770af…` | 8583680 |
| controller | `D:\Claude project\magicmida-rs\tools\gto_live_route_controller.py` | `512b26df…` | — |
| capture policy | `…\capture_policy.json` | `{"preset":"ahk_gto_defaults"}` | 31 |

`sample/controller contract_ok=true`, binary/attestation match, no capture_epoch_helper.exe in canonical target. argv[0]=attested canonical mida-cli, argv[1]=`/unpack` literal, no Git/MSYS path, no `--`, no `//unpack`.

### Verification summary

- **argv transport:** PASS (controller argv[0]=attested binary, argv[1]=`/unpack`, exact array, no Git)
- **capture epoch freeze:** epoch_begun=true, suspended_thread_count=7, IDs non-empty, epoch_started_ms non-zero
- **container / heap / raw-children:** detect + capture PASS (heap slots 318, raw children 317)
- **capture_heap_slab / restore:** raw child C + slab S same frozen epoch; target unfrozen before offline seed (restore PASS)
- **transform_input_seed:** PASS
- **transform recorder / sanitize_ahk_runtime_global:** PASS (sanitize stage exited)
- **Q0-C overlay:** **FAIL** (transformed write conflict, fail-closed, 0 candidates)
- **runtime rebase plan / bound manifest:** NOT reached (overlay gate failed first)
- **candidate:** 0

### Exit codes / counts

- controller (OS, child return): exit_code=**1** (GTO_UNPACK_FAILED)
- controller numeric: true; timed_out=false; process_tree_cleanup_status=exited_naturally
- live driver intended exit: 1 (CandidateNotReady, success=false)
- **Task Scheduler LastTaskResult = -1073741510** (0xC000013A, supervisor abort — see supervisor note above)
- protected sample spawn: 1; second spawn: false; rerun: false; candidate: 0
- negative control (supervisor bootstrap): exit=7, matches_expected=true
- no residual mida-cli / benign_smoke / artifact processes

---

## Required report fields (final status)

- **final status:** `RouteY_R1_A6_CandidateNotReady`
- **live driver:** `D:\MidaVault\scratch\route_y1_a6_live_driver.ps1` SHA `d4ae91aa…` size 23305
- **live supervisor:** `D:\MidaVault\scratch\route_y1_a6_live_supervisor.ps1` SHA `806098bb…` size 8484
- **C2 parent SHA / delta verdict:** driver parent `38112eea…`, supervisor parent `60ee7982…`; both deltas `all_forbidden_invariants_ok=true`
- **native PS / parent chain:** PS 5.1, native, chain svchost→services→wininit, no MSYS
- **evidence freshness:** bootstrap + live dirs created once (fresh, pre-existed=false)
- **Git baseline:** branch/HEAD/HEAD^ correct, 0 tracked / 0 source / 21 docs untracked (live count)
- **binary/attestation:** mida-cli `20e10bf3…`/11072000, attestation gto_product_recovery=true baseline=f386b49a…
- **sample/controller/policy hash:** sample `4d5770af…`/8583680, controller `512b26df…`, policy preset ahk_gto_defaults
- **argv[0]/argv[1]:** attested canonical mida-cli / `/unpack`
- **controller preflight:** build-capability ok, capture-policy ok, no-bypass verified
- **spawned/PID/count:** spawned=true, pid=22388, count=1
- **authorization consumed:** **true**
- **elapsed/timeout/timed_out:** 349969 ms / configured 600s / timed_out=false
- **driver/controller/supervisor exit:** driver intended=1, controller=1, supervisor (TaskScheduler)=abort (see note)
- **capture epoch count/IDs/elapsed/restore:** 7 threads, IDs [3000,8060,10564,21600,22040,26132,26976], elapsed=162ms, restore PASS (unfrozen before seed)
- **last successful stage:** `sanitize_ahk_runtime_global`
- **first failing stage:** `raw_slab_overlay` (transformed write conflict)
- **A2 child outcome:** the 0x3327260 / RVA 0x144400 seed-transform core validated at `transform_input_seed` (exit); sanitize at RVA 0x141bf0 completed
- **sanitize transition / Q0-C overlay:** sanitize PASS; Q0-C overlay FAIL fail-closed (no candidate)
- **runtime plan / manifest:** NOT reached (overlay gate failed first)
- **candidate count/path/SHA/size:** 0 / n/a / n/a / n/a
- **residual process result:** no residual mida-cli / benign_smoke / artifact
- **Git status/docs count:** 0 tracked / 0 source / 21 docs untracked (before report); 22 after report
- **no rerun / no second spawn / no cold-start / no promote:** all confirmed

---

## Honesty statement

- The single protected live authorization **was consumed** exactly once (`spawned=true`). No second controller, no second spawn, no rerun.
- The **full upstream production chain executed successfully** on the real protected sample (capture epoch with 7 frozen threads, heap slab, containers, raw children, transform, sanitize) — this is genuine live evidence, not synthetic.
- The run **failed closed at the Q0-C overlay** (`raw_slab_overlay`) with a transformed write conflict between `scrub_uncaptured_heap_pointers` (alone) and +`mark_labels_non_nested` chains. **0 candidates** were generated. This is a real production-chain fail-closed result, correctly rejecting an inconsistent overlay.
- **Supervisor plumbing gap (disclosed):** the driver completed and wrote its complete verdict, but the supervisor's post-driver final-result files were not written because the supervisor process aborted (Task Scheduler `LastTaskResult=-1073741510` = STATUS_CONTROL_C_EXIT). This does **not** change the driver's authoritative verdict (`CandidateNotReady`), but the supervisor final-exit/`driver.exit.json`/`supervisor_final_result.json` evidence is absent. This is an infrastructure gap, not a production-code failure.
- The candidate is **NOT** ready for offline audit (0 generated). **No cold-start, no promote, no Route Z R1, no second live** — execution stopped.

---

## Post-execution boundary

- Live bootstrap + live evidence preserved (not deleted); C0/C1/C2/A3/A4/A5/A6 D0 evidence untouched.
- No source/Cargo/controller/policy modification; no git add/commit; temp scheduled task deleted; no residual processes.
- Only new file allowed: `docs/GTO_ROUTE_Y_R1_LIVE_RESULT_A6.md` (untracked).
