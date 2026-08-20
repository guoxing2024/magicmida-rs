# Route Y R1 A6 — Production Driver No-Spawn AF3 Observer-Flush Correction 1

**Work order:** `RouteY_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF3_OBSERVER_FLUSH_CORRECTION_1`

**Title:** Cooperative Observer Shutdown, Atomic Final Evidence Flush, Coverage Attestation, and Fast-Driver Regression Harness.

**Target state:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ObserverFlushReviewRequested`

**Nature:** Observer/orchestrator evidence-flush machinery only. **NO production driver run.**

---

## 1. Root cause being fixed

AF3 Dynamic Qualification 1's `observer.json` was missing because the orchestrator used
`Stop-Job` (non-cooperative termination) on the observer background job after the driver
completed in ~3 s, before the observer (which only serialized at the end of its 300 s
window) could write its final output.

## 2. Fix: cooperative-flush observer

New observer `_af6_process_observer_coop.ps1` implements:
1. Write `observer.ready.json` atomically on start.
2. Sample loop (bulk WMI per process name — also fixes the fast-driver CommandLine race).
3. Watch for `observer.stop.json` (cooperative stop signal) each iteration.
4. On stop signal: one final sample, then write `observer.json.tmp` → Flush/Close → atomic `Move-Item` → `observer.json`.
5. Exit 0 normally. **No `Stop-Job` on the normal path.**

Coverage attestation fields embedded in `observer.json`:
`observer_run_id`, `ready_utc`, `observation_start_utc`, `stop_requested_utc`, `final_sample_utc`,
`observation_end_utc`, `stop_reason`, `shutdown_mode`, `final_flush_completed`,
`output_atomic_commit`, plus the full classification (driver_start_count, driver_pids, runner_pids, controller/mida/artifact/epoch).

## 3. Fix: bulk WMI sampling (fast-driver race)

The prior observer's `Get-Process` + per-PID `Get-CimInstance Win32_Process` race caused a
2–3 s driver to be captured with a null CommandLine. The cooperative observer now issues a
single bulk `Get-CimInstance Win32_Process -Filter "Name='powershell.exe'"` per process name,
capturing CommandLine + ParentProcessId atomically in the same query.

## 4. Regression harness (fast-driver reproduction)

`_af6_obsflush_harness.ps1` reproduces the exact fast-driver signature (synthetic driver sleeps
2 s, exits 0) and validates the positive path. **Positive test PASS**:

| Check | Result |
|-------|--------|
| observer.ready.json written | true |
| observer.json valid | true |
| final_flush_completed | true |
| output_atomic_commit | true |
| driver_start_count | 1 |
| observer driver PID == runner driver_started_pid | true (21844 == 21844) |
| runner PID != driver PID | true (21636 != 21844) |
| controller / mida / artifact / epoch | all false |
| stop signal observed | true |
| coverage attestation present | true |
| observer job completed normally | true |

Negative validation matrix (fail-closed predicates) documented:
- stop signal missing → `ObserverFlushTimedOut`/`ObserverEvidenceMissing`
- observer.json unwritable → `ObserverEvidenceMissing`
- observer flush timeout → `ObserverFlushTimedOut`
- observer.json malformed → `ObserverEvidenceMissing`
- observation end earlier than driver end → `ObserverCoverageFailed`
- PID attribution mismatch → `ObserverAttributionFailed`

## 5. Driver unchanged

AF3 production driver identity unchanged: SHA256 `4ea9d6e4246a6b02004655910418827317984322f54d679cf64fd43d98a2559c`, size 39246, version `route_y1_a6_live_driver/v3-no-spawn-af3`.

## 6. Boundary

HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403` unchanged; Q0-C 3 files unchanged; supervisor
`8863898f…`/10820 unchanged; tracked=3, untracked source=0, docs=44 (after this report);
git diff --check clean; no commit/push/git add.

## 7. Dynamic qualification

NOT RUN. `single_dynamic_attempt_consumed=false`. Awaiting audit to issue a NEW dynamic
authorization (new number, new evidence root, max one start).

---

**Evidence root:** `D:\MidaVault\lab\analysis\route_y_r1_a6_production_driver_no_spawn_af3_observer_flush_correction_1_20260813T055302Z\`
