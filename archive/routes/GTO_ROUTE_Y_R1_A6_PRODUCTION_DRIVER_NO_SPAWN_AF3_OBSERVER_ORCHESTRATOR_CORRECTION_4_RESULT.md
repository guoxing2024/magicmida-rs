# Route Y R1 A6 — Production Driver No-Spawn AF3 Observer/Orchestrator Correction 4 Result

**Work order:** `RouteY_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF3_OBSERVER_ORCHESTRATOR_CORRECTION_4`

**Target state:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ObserverOrchestratorCorrection4ReviewRequested`

**Result:** Correction 4 complete. The six P1 findings from the Correction 3 audit are fixed, the identity-bound harness executes **only archive copies** from the evidence root with a live SHA/size gate before every scenario, and the full 26-scenario matrix passes (26/26, fail=0). The production AF3 driver was **not run**; `single_dynamic_attempt_consumed = false`.

---

## 1. What was rejected in Correction 3 (audit findings)

The independent audit issued `Correction 4 Required` with concrete P1 findings:

| # | Finding | Severity |
|---|---|---|
| P1-1 | E2E execution identity not bound to the delivered archives (harness ran scratch paths, post-hoc hash equality is not runtime binding) | P1 |
| P1-2 | Validator declared `ExpectedDriverSha256` but never executed `Get-FileHash` / no boolean SHA gate | P1 |
| P1-3 | `observer_job_removed=true` derived from the stale job object state, not from a repository re-query | P1 |
| P1-4 | `Write-Result` had `catch {}` — a failed authoritative result write could silently fail open | P1 |
| P1-5 | `finally` re-parsed runner evidence without fail-closed parsing; malformed/partial files could throw and lose the terminal | P1 |
| P1-6 | Cleanup failure only overrode `ReviewCandidate`; other primary failures + cleanup failure did not become `CleanupFailed` | P1 |
| P2 | Harness called `ReadToEnd()` before `WaitForExit()` — a hung child could block the watchdog | P2 |
| P2 | Residual scan covered only `powershell.exe`; `pwsh.exe`/exact-PID coverage absent | P2 |

---

## 2. What Correction 4 delivers

### 2.1 Runtime identity binding (P1-1) — `harness/corr4_harness_archive.ps1`

The harness executes **only the archive copies inside the evidence root**:

| Role | Archive | SHA-256 | Size |
|---|---|---|---|
| orchestrator | `orchestrator/orchestrator_failclosed_v4_archive.ps1` | `6cfba5ca48f7cf4d7dd77302726b8a1ed8516ee9157ec84393488d46b07c78d6` | 25897 |
| validator | `validator/observer_evidence_validator_v4_archive.ps1` | `d2b4e926dc7aeba474d0ad5d83dd32cb80167fc1957b0fbd8cdf2f57bc38c673` | 10644 |
| observer | `observer/process_observer_coop_v2_archive.ps1` | `11910085b61f6eddcb0026a7853af58c05ccb93e0dd81f5c8bda5af143daced2` | 10438 |
| runner | `runner/no_spawn_runner_archive.ps1` | `f5e9405652a5cf638b5f21bce2144fe671ce3033c4ea07a30283e38494ad83c5` | 4642 |
| harness | `harness/corr4_harness_archive.ps1` | `7d9eebcc2c5659136e161f27b5eb168b8519785b828be8a3c8cb0ca73c787adf` | 44961 |

Before **any** scenario launch, `Test-IdentityGate` computes live SHA-256/size of all four archives and compares against `harness/expected_identities.json` (recorded before the run). Any mismatch:
- **blocks the scenario launch** (orchestrator is never started),
- returns a distinct non-zero terminal (`orchestratorIdentityMismatch`/41, `validatorIdentityMismatch`/42, `observerIdentityMismatch`/43, `runnerIdentityMismatch`/44),
- and writes `execution_identity.json` with the gate details.

Every scenario (including positive) records `execution_identity.json` containing harness + 4 archive identities + the AF3 driver expected identity. The audit's "post-hoc hash equality is not runtime binding" objection is answered: the identity check runs **before each launch**, not after the whole run.

**Also fixed during development:** the harness argument construction bug — `@('-' + $k, [string]$v)` merged name+value into a single token, so `-InjectTaskName af3_c4_x` never bound and the orchestrator silently fell back to **production defaults**. This would have run the production driver in synthetic scenarios. Fixed to append name and value as separate elements; verified empirically that injected values bind correctly (the positive scenario's synthetic driver hash/path is present in evidence, never the production driver).

### 2.2 Validator driver SHA/size gate (P1-2) — `validator/observer_evidence_validator_v4_archive.ps1`

Validator v4 **actually hashes the driver file** with `Get-FileHash` and adds two boolean gates:

- `driver_sha256_match` — `actual_driver_sha256 == expected_driver_sha256`
- `driver_size_match` — `actual_driver_size == expected_driver_size`

These are first-class checks (16 total in the positive case, all passing). The orchestrator additionally maps `driver_sha256_match`/`driver_size_match` failures to a distinct terminal `ObserverDriverIdentityFailed` / 94.

### 2.3 Real job-removal proof (P1-3)

The orchestrator now records all four fields and derives `observer_job_removed` from a **repository re-query** (`Get-Job -Id` after `Remove-Job`), never from the stale job object:

- `observer_job_terminal`, `observer_job_remove_attempted`, `observer_job_remove_succeeded`, `observer_job_repository_absent`
- `observer_job_removed = observer_job_remove_succeeded AND observer_job_repository_absent`

The `job_remove_failure` scenario injects `InjectSkipObserverJobRemove` so the job stays in the repository; the orchestrator correctly reports `observer_job_removed=false` and fails closed to `CleanupFailed` / 92.

### 2.4 Durable authoritative result write (P1-4)

`Write-DurableJson` implements: serialize once → write `.tmp` → `Flush(true)` → `Close` → atomic `Move-Item`. No empty `catch {}`. A writable probe runs before the primary write; if the primary commit fails, the orchestrator:
- writes `orchestrator_result_fallback.json` (pre-probed writable),
- records `result_write_channel=fallback` and `result_write_primary_failed=true`,
- terminates with `OrchestratorResultWriteFailed` / 93.

The `result_out_unwritable` scenario (primary `Z:` nonexistent path) proves the fallback exists with the correct terminal and exit.

### 2.5 Fail-closed runner-evidence parsing (P1-5)

`Read-JsonFailClosed` distinguishes `missing` / `empty` / `malformed` / `ok`; the field-extraction block is wrapped so a wrong field type (e.g. `driver_pid="12abc"`) maps to `RunnerEvidenceMalformed` / 70. The `finally` block only ever calls this safe reader — a malformed file can never throw inside `finally` and lose the terminal. The result exposes `evidence_parse` (per-file status) so the audit can see exactly which file was faulted.

Scenarios exercised: malformed `driver_started.json`, empty `driver.exit.json`, malformed `driver.exit.json`, field-type-invalid `driver.exit.json`, malformed `runner_final_result.json` — all → `RunnerEvidenceMalformed` / 70 with structured result and clean cleanup.

### 2.6 Cleanup-failure terminal priority (P1-6)

The `finally` block records `primary_terminal` / `primary_exit_code` and then applies:

```
cleanup_success = false  =>  terminal = CleanupFailed, exit_code = 92
```

**regardless of the primary terminal**. The primary failure is preserved in `primary_terminal` / `primary_exit_code`. The `primary_failure_plus_cleanup_failure` scenario (driver exit 7 + lingering child) proves: terminal 92, exit 92, `primary_terminal=DriverQualificationFailed`, `primary_exit_code=82`.

### 2.7 Harness watchdog + residual scan (P2)

- `Invoke-ChildProcess` uses `ReadToEndAsync()` + a real deadline loop + `taskkill /T /F` on timeout. `ReadToEnd()` can never block the watchdog. The `watchdog_kill` scenario spawns a child that never exits; the harness kills it within the timeout and records residual 0.
- The residual scan now covers `powershell.exe` + `pwsh.exe` + `cmd.exe` by command line, **plus exact driver/runner PID liveness**, excluding the orchestrator's own `$PID`. The `residual_pwsh_child` scenario proves a detached `pwsh.exe` child is detected → `CleanupFailed` / 92.
- Between-scenario isolation: lingering/hang markers from one scenario are killed before the next scenario's identity gate so they cannot pollute the next residual scan.

---

## 3. Test matrix (26 scenarios, all pass)

| # | Scenario | Expected terminal | Exit | Result |
|---|---|---|---|---|
| 1 | positive_e2e | ReviewCandidate | 0 | PASS |
| 2 | validator_fail | ObserverValidationFailed | 88 | PASS |
| 3 | driver_exit7 | DriverQualificationFailed | 82 | PASS |
| 4 | driver_evidence_timeout | DriverEvidenceTimedOut | 78 | PASS |
| 5 | observer_ready_timeout | ObserverReadyFailed | 75 | PASS |
| 6 | observer_flush_timeout | ObserverFlushTimedOut | 76 | PASS |
| 7 | pid_mismatch | DriverPidMismatch | 84 | PASS |
| 8 | coverage_failure | ObserverCoverageFailed | 89 | PASS |
| 9 | attribution_failure | ObserverAttributionFailed | 90 | PASS |
| 10 | cleanup_failure (lingering) | CleanupFailed | 92 | PASS |
| 11 | orch_identity_mismatch | orchestratorIdentityMismatch | 41 | PASS |
| 12 | val_identity_mismatch | validatorIdentityMismatch | 42 | PASS |
| 13 | obs_identity_mismatch | observerIdentityMismatch | 43 | PASS |
| 14 | run_identity_mismatch | runnerIdentityMismatch | 44 | PASS |
| 15 | validator_driver_sha_mismatch | ObserverDriverIdentityFailed | 94 | PASS |
| 16 | malformed_driver_started | RunnerEvidenceMalformed | 70 | PASS |
| 17 | empty_driver_exit | RunnerEvidenceMalformed | 70 | PASS |
| 18 | malformed_driver_exit | RunnerEvidenceMalformed | 70 | PASS |
| 19 | fieldtype_driver_exit | RunnerEvidenceMalformed | 70 | PASS |
| 20 | malformed_runner_final | RunnerEvidenceMalformed | 70 | PASS |
| 21 | result_out_unwritable | OrchestratorResultWriteFailed | 93 | PASS |
| 22 | job_remove_failure | CleanupFailed | 92 | PASS |
| 23 | primary_failure_plus_cleanup_failure | CleanupFailed (primary preserved) | 92 | PASS |
| 24 | synth_child_hang | DriverEvidenceTimedOut | 78 | PASS |
| 25 | residual_pwsh_child | CleanupFailed | 92 | PASS |
| 26 | watchdog_kill | HarnessWatchdogKilledChild | — | PASS |

**Aggregate:** `scenario_count=26, pass=26, fail=0, all_pass=true`.

Every orchestrator scenario verifies: expected terminal == actual, expected exit == actual, structured result exists (or fallback for #21), cleanup attestation matches, and `execution_identity.json` exists.

---

## 4. Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_a6_production_driver_no_spawn_af3_observer_orchestrator_correction_4_20260813T100524Z\`

- `freeze_before.json` / `freeze_after.json` (after all tests, final status and this report)
- `final_status.json`
- `orchestrator/orchestrator_failclosed_v4_archive.ps1`
- `validator/observer_evidence_validator_v4_archive.ps1`
- `observer/process_observer_coop_v2_archive.ps1`
- `runner/no_spawn_runner_archive.ps1`
- `harness/corr4_harness_archive.ps1`, `harness/expected_identities.json`, `harness/corr4_malformed_runner.ps1`, `harness/cleanup_leftovers.ps1`
- `harness/corr4_harness_result.json`
- `harness/scenarios/<26 dirs>/` — each with `execution_identity.json`, `scenario_result.json`, `orchestrator.stdout.log`, `orchestrator.stderr.log`, `cleanup_attestation.json`, raw evidence root (`observer.json`, `observer.ready.json`, `observer.stop.json`, `orchestrator_result.json`, `validator_result.json`, `evidence/...`)
- `evidence_freeze.json` + `evidence_freeze.json.sha256` (detached manifest)
- `evidence_freeze_selfcheck.json`

**Manifest self-check:** payload = 296, missing = 0, hash_mismatch = 0, size_mismatch = 0, unlisted = 0 — PASS. (`evidence_freeze_selfcheck.json` is a derived verification artifact excluded from the hashed payload set, consistent with the detached-manifest policy.)

```
evidence_freeze.json.sha256:
8014c5d320e2ded615e0b43be9f88c97d8f844fc84dbf04865ee63318a980eea  evidence_freeze.json
```

---

## 5. Discipline and boundary

- **Production AF3 driver NOT run.** Frozen: SHA `4ea9d6e4…`, size 39246, version `route_y1_a6_live_driver/v3-no-spawn-af3` (unchanged).
- No production scheduled task created or started. Only `af3_c4_*` synthetic tasks (all unregistered by the orchestrator's own cleanup).
- `single_dynamic_attempt_consumed = false`.
- HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403` unchanged; branch unchanged.
- Q0-C three files unchanged; supervisor (`route_y1_a6_live_supervisor.ps1`, SHA `8863898f…`) unchanged.
- tracked=3 (pre-existing), untracked source=0, untracked docs 45→46 (this report added).
- No commit / push / `git add`. No evidence root deleted or overwritten (AF2/AF3/Correction 1/2/3 roots untouched).
- Residual synthetic processes after the run: 0; residual synthetic scheduled tasks: 0.

---

## 6. Status

**`RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ObserverOrchestratorCorrection4ReviewRequested`**

Stopped for independent audit. Per the work order, `AF3_DynamicQualificationAuthorized = false`; `ProductionDriverStartAllowance = 0`. Upon audit passing, a **new-numbered, new-evidence-root, at-most-one-start** dynamic qualification authorization is required before the single production QualificationNoSpawn run.