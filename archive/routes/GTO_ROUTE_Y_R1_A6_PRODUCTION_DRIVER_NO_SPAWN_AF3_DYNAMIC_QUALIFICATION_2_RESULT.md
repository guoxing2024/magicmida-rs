# Route Y R1 A6 — Production Driver No-Spawn AF3 Dynamic Qualification 2 Result

**Work order:** `RouteY_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF3_DYNAMIC_QUALIFICATION_2`

**Authorization:** `AF3_DynamicQualificationAuthorized = true` (basis: Correction4ImplementationAudit PASS, Correction4HarnessAudit PASS, EPC2FinalPackageAudit PASS)

**Execution class:** `DYNAMIC QUALIFICATION - SINGLE PRODUCTION DRIVER START` (`ProductionDriverStartAllowance = 1`)

**Result:** **TERMINAL = ReviewCandidate, EXIT CODE = 0.** The single authorized production AF3 driver start completed in `QualificationNoSpawn` mode with `RouteY_R1_A6_ProductionDriverNoSpawnQualified`; all orchestrator, validator, observer, runner and driver evidence gates pass; cleanup complete with zero residual tasks/processes.

---

## 1. Terminal result

| Item | Value |
|---|---|
| Orchestrator terminal | **ReviewCandidate** |
| Orchestrator exit code | **0** |
| Validator v4 | passed=16, failed=0, all_pass=true |
| Driver final status | `RouteY_R1_A6_ProductionDriverNoSpawnQualified` |
| Driver OS exit code | 0 (numeric, not timed out) |
| Production driver starts | **1** (exactly one, PID 13872) |
| Result write channel | primary |
| Cleanup | success=true (task_removed, observer_job_removed, matching_task_count=0, residual=0) |

## 2. Production driver identity (verified before launch + by runner + by validator)

```
path    = D:\MidaVault\scratch\route_y1_a6_live_driver_v3_no_spawn_af3.ps1
version = route_y1_a6_live_driver/v3-no-spawn-af3
SHA-256 = 4ea9d6e4246a6b02004655910418827317984322f54d679cf64fd43d98a2559c
size    = 39246
```

Verified at three independent points: (1) orchestrator preflight `Get-FileHash` before launch; (2) runner `driver_started.json`/`driver.exit.json` SHA+size; (3) validator v4 actual `Get-FileHash` gate (`driver_sha256_match=true`, `driver_size_match=true`).

## 3. Frozen component identities (Correction 4 archives, byte-verified)

| Component | Path in DQ2 root | SHA-256 | Size | Verified |
|---|---|---|---|---|
| Orchestrator v4 | `orchestrator\orchestrator_failclosed_v4_archive.ps1` | `6cfba5ca…` | 25897 | ✓ |
| Validator v4 | `validator\observer_evidence_validator_v4_archive.ps1` | `d2b4e926…` | 10644 | ✓ |
| Observer v2 | `observer\process_observer_coop_v2_archive.ps1` | `11910085…` | 10438 | ✓ |
| Runner | `runner\no_spawn_runner_archive.ps1` | `f5e94056…` | 4642 | ✓ |

The DQ2 launch cmd (`launch\dq2_dynamic_launch.cmd`) invokes the **frozen runner archive** in the evidence root, which launches the production driver once. The observer's captured runner sample confirms the exact frozen runner path.

## 4. Evidence freshness (driver-internal gate)

```
existed_before_creation = false
created_once            = true
exists_after_creation   = true
initially_empty         = true
write_test_ok           = true
freshness_gate_pass     = true
```

## 5. Observer evidence (mandatory ready / stop / final observer.json)

- `observer.ready.json`: run_id `7bcb5c3bf24d49069836eed0d04ed729`, ready 03:45:01.290Z, driver_path_target = production driver.
- `observer.stop.json`: same run_id, reason `orchestrator_driver_completed`, driver_pid 13872, runner_pid 27608.
- `observer.json` (final): same run_id; shutdown_mode `cooperative_stop_signal`; final_sample_records_added = **104** (>0); sample_iteration_count 9; total samples 946; `final_flush_completed=true`, `output_atomic_commit=true`.

**Observer classification:** driver_start_count=1 (PID 13872), runner_count=1 (27608), launcher_count=1 (5184), controller_seen=false, mida_cli_seen=false, artifact_seen=false, capture_epoch_helper_seen=false — **no-spawn safety classifications all false**.

## 6. Runner evidence

- `driver_started.json`: driver_started_pid=13872, runner_pid=27608, SHA/size/mode exact.
- `driver.exit.json`: driver_os_exit_code=0, numeric, not timed out, driver_pid=13872, start 03:45:05.754Z, end 03:45:08.725Z (authoritative `end_utc`).
- `runner_final_result.json`: runner_pid 27608 ≠ driver_pid 13872; stdout `A6_NO_SPAWN_QUALIFIED mode=QualificationNoSpawn ctl=0 sample=0 cand=0`; stderr empty.

## 7. Driver no-spawn qualification evidence

`driver_no_spawn_qualification.json`: final_status `RouteY_R1_A6_ProductionDriverNoSpawnQualified`; would_spawn=false; controller_invocation_count=0; protected_sample_spawn_count=0; candidate_count=0; live_authorization_consumed=false; protected_sample_executed=false; controller_process_created=false; mida_cli_process_created=false; canonical binary SHA `20e10bf3…`; protected sample `4d5770af…`; controller `512b26df…`; child argv contiguous tail of controller argv=true; git_boundary_verified=true; binary_attestation_verified=true; sample_read_only_attested=true.

`driver_self_result.json`: completed=true, success=true, intended_exit_code=0, last_journal_sequence=14, last_journal_phase=`qualification_no_spawn_finish`.

`driver_journal.jsonl`: 14/14 gate passes (mode_guard → ps51_compat → native_environment → git_preflight → disk_preflight → evidence_freshness_check → evidence_directory_create → evidence_directory_write_test → canonical_binary → protected_contract → argv_transport_probe → qualification_no_spawn_argv → qualification_no_spawn_finish).

## 8. Validator gates (16/16)

`driver_sha256_match`, `driver_size_match`, `observer_json_mandatory_and_parseable`, `ready_json_mandatory_and_parseable`, `stop_json_mandatory_and_parseable`, `run_id_triple_consistent`, `ready_driver_path_target_matches`, `stop_pid_binding`, `driver_pid_exact_match`, `driver_start_count_exactly_1`, `runner_pid_not_driver`, `safety_classifications_false`, `cooperative_shutdown`, `final_flush_and_atomic`, `final_sample_actually_executed`, `coverage_time_comparisons` — **all true**.

## 9. Evidence root

```
D:\MidaVault\lab\analysis\
route_y_r1_a6_production_driver_no_spawn_af3_dynamic_qualification_2_20260814T034300Z\
```

Contains: `orchestrator/`, `validator/`, `observer/`, `runner/` frozen archives; `launch/dq2_dynamic_launch.cmd`; `expected_identities.json`; `freeze_before.json`; `run/` (orchestrator-created: bootstrap/evidence/attempt dirs, driver journal, lock, freshness, qualification, self-result, finish, stdout/stderr, runner evidence, observer.ready/stop, validator_result); `observer.json`; `orchestrator_result.json`; final report; `freeze_after.json` (written last); `evidence_freeze.json` + `.sha256` + `evidence_freeze_selfcheck.json`.

## 10. Discipline and boundary

- HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403` unchanged; branch `oreans/two-sample-mainline` unchanged.
- Q0-C three files unchanged; supervisor (`8863898f…`, 10820) unchanged; AF3 driver (`4ea9d6e4…`, 39246) unchanged.
- No commit / push / `git add`. No historical evidence root modified/overwritten. No production scheduled task created (transient task removed by orchestrator cleanup).
- Matching scheduled tasks after run: **0**; matching residual processes: **0**; `git diff --check` = 0.
- Historical DQ1 (`AF3_EvidenceInsufficient`, 2026-08-13) not re-run, not overwritten, not reinterpreted. This DQ2 consumed the single authorized start.

## 11. Status

**ReviewCandidate / exit 0 — stopped for final audit.** This is not final project success; the evidence package is submitted for independent audit.
