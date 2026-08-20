# Route Y R1 A6 — Production Driver No-Spawn AF3 Observer-Flush Correction 2

**Work order:** `RouteY_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF3_OBSERVER_FLUSH_CORRECTION_2`

**Target state:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ObserverFlushCorrection2ReviewRequested`

**Nature:** Observer/orchestrator machinery only. **NO production driver run.**

---

## 1. What this correction fixed

Correction 1's positive prototype worked but had four P1 gaps + two P2 gaps blocking new dynamic
authorization. Correction 2 closes all of them.

### A. Observer fixes (all applied to `_af6_process_observer_coop_v2.ps1`)
1. Real `Sample-Once` function — invoked by the normal loop AND once more after a valid stop
   signal; records `final_sample_started_utc`, `final_sample_completed_utc`,
   `final_sample_records_added`, `sample_iteration_count`.
2. Stop JSON is parsed and validated: `observer_run_id` must match the ready run_id, `reason`
   must be `orchestrator_driver_completed`, `stop_requested_utc` must parse as a valid time.
3. `shutdown_mode` distinguishes `cooperative_stop_signal` from `nominal_window_expired`.
4. Single final commit: build record with `final_flush_completed=true` + `output_atomic_commit=true`
   pre-set, serialize once to `.tmp`, `Flush(true)`, Close, atomic `Move-Item`. On failure, delete
   `.tmp` and exit non-zero (no fake-success final JSON).

### B. Corrected production orchestrator delivered (`orchestrator_corrected_archive.ps1`)
Normal path: start observer → wait ready → validate ready run_id/driver path → register
zero-trigger task → single explicit Run → wait driver done → observe ≥3 s → atomic stop.json
(same run_id) → `Wait-Job` (NOT Stop-Job) → verify Completed → parse observer.json → run
validator → Receive-Job → Remove-Job. Stop-Job only on `Wait-Job` timeout → `ObserverFlushTimedOut`.

### C. Reusable validator (`observer_evidence_validator.ps1`)
Performs real `DateTimeOffset` coverage comparisons (not just field-presence):
`ready ≤ task_run`, `observation_start ≤ task_run`, `stop_file ≥ driver_end + grace`,
`stop_requested ≥ driver_end + grace`, `final_sample_end ≥ stop_requested`,
`final_sample_end ≥ driver_end`, `observation_end ≥ final_sample_end`. Plus run-id consistency,
PID exact match, runner≠driver, start count exactly 1, safety false, cooperative shutdown,
flush/atomic, actual final sample records added. 11 checks.

### D. Six negative tests actually executed
Each negative scenario produced `scenario.json`, `observer.json`/`stdout.log`/`stderr.log`,
and `validator_result.json` with expected vs actual terminal state, all feeding `$allPass`.

## 2. Harness results

- **Positive test: PASS** (validator 11/11, driver_start_count=1, driver PID exact match,
  runner≠driver, safety false, cooperative shutdown, flush/atomic true, coverage all true).
- **Negative tests: 6/6 PASS** (`negative_pass_count=6`, `negative_fail_count=0`):
  - `negative_stop_missing` → `nominal_window_expired` (fail-closed)
  - `negative_output_unwritable` → no observer.json (fail-closed)
  - `negative_flush_timeout` → `ObserverFlushTimedOut` (fail-closed)
  - `negative_malformed_json` → validator fail (fail-closed)
  - `negative_coverage_early` → validator coverage fail (fail-closed)
  - `negative_pid_mismatch` → validator PID fail (fail-closed)

`all_pass = true`.

## 3. Root-cause note (fixed during this correction)

`[DateTimeOffset]::TryParse($s, [ref]$dt)` throws `MethodCountCouldNotFindBest` under
PowerShell StrictMode (the `[ref]` out-param does not resolve). This caused the observer's
stop-signal validation to silently fail (never seeing a valid stop signal). Replaced with
`try { [DateTimeOffset]::Parse($s) } catch { $null }` in both the observer and validator.

## 4. Driver unchanged

AF3 production driver unchanged: SHA256 `4ea9d6e4246a6b02004655910418827317984322f54d679cf64fd43d98a2559c`, size 39246, version `route_y1_a6_live_driver/v3-no-spawn-af3`.

## 5. Boundary

HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403` unchanged; Q0-C 3 files unchanged; supervisor
`8863898f…`/10820 unchanged; tracked=3, untracked source=0, docs=45 (after this report);
git diff --check clean; no commit/push/git add.

## 6. Dynamic qualification

NOT RUN. `single_dynamic_attempt_consumed=false`. Awaiting audit to issue a NEW dynamic
authorization (new number, new evidence root, max one start).

---

**Evidence root:** `D:\MidaVault\lab\analysis\route_y_r1_a6_production_driver_no_spawn_af3_observer_flush_correction_2_20260813T061500Z\`
