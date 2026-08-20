# Route Y R1 A6 — Production Driver No-Spawn AF3 Observer/Orchestrator Correction 3 Result

**Work order:** `RouteY_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF3_OBSERVER_ORCHESTRATOR_CORRECTION_3`

**Target state:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ObserverOrchestratorCorrection3ReviewRequested`

**Result:** Correction 3 complete — the production orchestrator is now fail-closed and the full chain is exercised end-to-end by a synthetic dependency-injection harness. All 10 scenarios pass.

---

## 1. What was rejected in Correction 2

The independent audit confirmed observer v2 core was PASS, but rejected the production orchestrator because it was **fail-open**:

1. Validator failure was swallowed — the orchestrator unconditionally `exit 0`.
2. `driver.exit.json` was only *waited for* existence, never *verified* (exit code, timeout, numeric, PIDs, times, SHA/size, runner-final evidence).
3. Driver end time was estimated with `Get-Date` instead of read from `driver.exit.json.end_utc`.
4. `$ResultOut` was declared but never used — no structured authoritative terminal.
5. No unified `try/finally` cleanup state machine — multiple `exit` paths left task/job/process cleanup unproven.
6. Validator still had fail-open input semantics (optional Ready/Stop, no driver path/hash binding, hardcoded `observation_start_before_driver_start=$true`, `final_sample_records_added -ge 0`, coverage detail mixed into boolean count).
7. The six negative tests were observer/validator-local, **not** end-to-end orchestrator tests — they did not prove `orchestrator failure → structured terminal → nonzero OS exit → unified cleanup`.

---

## 2. What Correction 3 delivers

### 2.1 Fail-closed orchestrator — `orchestrator/orchestrator_failclosed_archive.ps1`

Every terminal writes `orchestrator_result.json` (structured: `terminal_state`, `os_exit_code`, `cleanup`, `caught_exception`, driver/runner PIDs) and returns a **distinct non-zero OS exit**. Only `ReviewCandidate` returns `exit 0`.

Distinct terminals (exit code):
| Terminal | Exit |
|---|---|
| ReviewCandidate | 0 |
| TaskDisciplineViolation | 73 |
| DriverScriptMissing | 74 |
| ObserverReadyFailed | 75 |
| ObserverFlushTimedOut | 76 |
| ObserverReadyDriverMismatch | 77 |
| DriverEvidenceTimedOut | 78 |
| RunnerEvidenceMissing | 79 |
| DriverTimedOut | 80 |
| DriverExitNonNumeric | 81 |
| DriverQualificationFailed | 82 |
| DriverIdentityMismatch | 83 |
| DriverPidMismatch | 84 |
| RunnerPidEqualsDriverPid | 85 |
| DriverResultInvalid | 86 |
| ObserverEvidenceMissing | 87 |
| ObserverValidationFailed | 88 |
| ObserverCoverageFailed | 89 |
| ObserverAttributionFailed | 90 |
| ObserverSafetyClassificationFailed | 91 |
| CleanupFailed | 92 |
| TaskPreexisted | 93 |
| RootPreexisted | 94 |
| OrchestratorError | 99 |

Validator non-zero exit now **propagates upward** — no unconditional `exit 0` anywhere. Validator failure is mapped to a distinct terminal by its `failed_checks`:
- any `coverage*` failed check → `ObserverCoverageFailed`
- `driver_pid_exact_match` / `driver_start_count_exactly_1` / `stop_pid_binding` / `runner_pid_not_driver` → `ObserverAttributionFailed`
- `safety_classifications_false` → `ObserverSafetyClassificationFailed`
- otherwise → `ObserverValidationFailed`

### 2.2 Real runner evidence binding

The orchestrator reads and cross-verifies:
- `driver_started.json` → `driver_started_pid`, `runner_pid`
- `driver.exit.json` → `driver_os_exit_code`, `exit_code_is_numeric`, `driver_timed_out`, `driver_pid`, `driver_sha256`, `driver_size`, `mode`, `start_utc`, `end_utc`
- `runner_final_result.json` → `driver_pid`, `driver_os_exit_code`

`driver_end_utc` is read from `driver.exit.json.end_utc` (never `Get-Date`). The driver result is rejected unless: exit code 0, numeric, not timed out, SHA+size match the authorized driver, mode `QualificationNoSpawn`, `driver_pid` equals `driver_started_pid` (cross-checked against both `driver.exit` and `runner_final`), and `runner_pid != driver_pid`.

### 2.3 Strict validator — `validator/observer_evidence_validator_v3_archive.ps1`

Mandatory: `observer.ready.json`, `observer.stop.json`, `observer.json` all must exist and parse. Booleans in `checks`; timestamps in `details` (not counted as gates).

14 boolean gates (all passed in positive): three mandatory-parseable gates, run-id triple consistency, `ready.driver_path_target` equals authorized driver path, stop driver/runner PID binding, driver PID exact match, driver start count exactly 1, runner PID != driver PID, safety classifications false, cooperative shutdown, final flush + atomic, final sample records `> 0`, coverage time comparisons (real `driver_start_utc`).

`observation_start_before_driver_start` is a **real** `DateTimeOffset` comparison against `driver.exit.json.start_utc` — no hardcoding.

### 2.4 Unified cleanup — single `try/finally`

Regardless of pass or fail, the `finally` block always:
- unregisters the scheduled task
- force-stops the observer job **only if still running** (cooperative flush is attempted first via `Invoke-CooperativeObserverFlush`)
- receives and removes the observer job
- records `task_removed`, `observer_job_state`, `observer_job_removed`, `matching_task_count`, `residual_driver_runner_observer_process_count`, `cleanup_success`, `cleanup_failure_reason`

If cleanup itself fails while terminal was `ReviewCandidate`, the terminal is rewritten to `CleanupFailed` (exit 92). The orchestrator excludes its **own** PID from the residual scan (its own command line legitimately contains the injected driver path via `-InjectDriverPath`).

On the driver-evidence-timeout path (and any other mid-flight failure), the observer is **cooperative-flushed first** (stop signal + `Wait-Job`), never silently killed.

### 2.5 End-to-end synthetic harness — `harness/corr3_harness_archive.ps1`

The harness actually launches the orchestrator as a child process, substituting a synthetic driver / synthetic runner / synthetic launch cmd / synthetic task name / synthetic expected identity via dependency injection. **No production driver is run.**

10 scenarios, each verifying `expected_terminal == actual`, `expected_exit == actual`, `structured_result_exists`, and cleanup attestation:

| # | Scenario | Expected terminal | Exit | Result |
|---|---|---|---|---|
| 1 | positive_e2e | ReviewCandidate | 0 | PASS |
| 2 | validator_fail | ObserverValidationFailed | 88 | PASS |
| 3 | driver_exit7 | DriverQualificationFailed | 82 | PASS |
| 4 | driver_evidence_timeout | DriverEvidenceTimedOut | 78 | PASS |
| 5 | observer_ready_timeout | ObserverReadyFailed | 75 | PASS |
| 6 | observer_flush_timeout | ObserverFlushTimedOut | 76 | PASS |
| 7 | pid_mismatch (forged driver.exit.driver_pid) | DriverPidMismatch | 84 | PASS |
| 8 | coverage_failure (validator emits coverage failed_check) | ObserverCoverageFailed | 89 | PASS |
| 9 | attribution_failure (validator emits driver_pid_exact_match) | ObserverAttributionFailed | 90 | PASS |
| 10 | cleanup_failure (lingering process) | CleanupFailed | 92 | PASS |

**Harness aggregate:** `primary_pass=8, primary_fail=0, secondary_pass=2, secondary_fail=0, all_pass=true`.

The positive E2E validator result confirms the real chain ran end-to-end: `14/14` gates, real `driver_start_utc`/`driver_end_utc` from `driver.exit.json`, final sample actually executed (`records > 0`, iterations `>= 2`), triple run-id consistent, PID binding correct, cooperative flush + atomic commit.

---

## 3. Key bug fixed during Correction 3

The orchestrator's residual-process scan matched **its own process** (its `CommandLine` contains the injected driver path via `-InjectDriverPath`), which forced `CleanupFailed` in every scenario. Fixed by excluding `$PID` from the residual scan. Without this fix, the production orchestrator would have permanently misreported its own presence as a residual driver process.

---

## 4. Discipline and boundary

- **Production driver NOT run.** `single_dynamic_attempt_consumed = false`.
- AF3 driver identity unchanged: SHA `4ea9d6e4…`, size 39246.
- HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403` unchanged; branch unchanged.
- Q0-C three files + supervisor unchanged.
- tracked=3, untracked source=0, docs 45→46 (this report added), diff check clean.
- Residual synthetic processes 0; residual synthetic scheduled tasks 0.
- No commit / push / `git add`.

---

## 5. Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_a6_production_driver_no_spawn_af3_observer_orchestrator_correction_3_20260813T072709Z\`

- `freeze_before.json` / `freeze_after.json`
- `final_status.json`
- `orchestrator/orchestrator_failclosed_archive.ps1`
- `validator/observer_evidence_validator_v3_archive.ps1`
- `harness/corr3_harness_archive.ps1`
- `harness/corr3_harness_result.json`
- `harness/scenarios/<10 scenario dirs>/` (each: raw evidence root, `scenario_result.json`, `orchestrator.stdout.log`, `orchestrator.stderr.log`, `cleanup_attestation.json`)
- `evidence_freeze.json` + `evidence_freeze.json.sha256` (detached manifest, self-verified)

---

## 6. Status

**`RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ObserverOrchestratorCorrection3ReviewRequested`**

Stopped for independent audit. Upon audit passing, a **new-numbered, new-evidence-root, at-most-one-start** dynamic authorization is required before the single production QualificationNoSpawn run.
