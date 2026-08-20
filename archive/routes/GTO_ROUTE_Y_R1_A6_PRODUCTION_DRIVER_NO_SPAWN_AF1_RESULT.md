# GTO ROUTE Y R1 A6 — Production Driver No-Spawn AF1: Evidence-Contract Repair and Clean Exactly-One Dynamic Qualification

**Target state:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF1_ReviewRequested`
**Final status:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF1_QualificationFailed`
**Authorization:** offline execution-infrastructure code change + one no-spawn qualification execution
**Report path:** `docs/GTO_ROUTE_Y_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF1_RESULT.md` (untracked)

---

## 0. Prior work-order terminal state correction (audit-mandated)

The prior work order was reported as `RouteY_R1_A6_ProductionDriverNoSpawnMode_ReviewRequested`, which the audit corrected to **`RouteY_R1_A6_ProductionDriverNoSpawnMode_QualificationFailed`** (four production-driver starts breached the single-execution discipline; attempt-3 numeric exit evidence was overwritten; process observer missing; shared evidence polluted across attempts; `child_argv` schema error; self-result claimed an unwritten finish phase). This is recorded in `prior_work_order_terminal_state_correction.json`.

---

## 1. Repo / Q0-C work-tree freeze (BEFORE == AFTER, no modification)

| Boundary | Value |
|----------|-------|
| branch | `oreans/two-sample-mainline` |
| HEAD | `f386b49af8f547a16f3d107dc6e80c02ea6e4403` |
| HEAD^ | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` |
| tracked modified | 3 (heap_global_snapshot.rs, raw_slab_coherence.rs, snapshot_manifest.rs) |
| untracked source | 0 |
| untracked docs | 38 (unchanged; +1 for this report → 39) |
| `git diff --check` | PASS |

Q0-C file hashes/sizes and `git diff --binary` SHA identical before/after (`q0c_worktree_freeze_before.json` == `q0c_worktree_freeze_after.json`). Canonical supervisor unchanged (SHA `8863898f...`, 10820 bytes). Driver v2 archived as `driver_v2_no_spawn_original.ps1.bin`; AF1 driver installed (SHA `9c97c919...`, 34576 bytes, `route_y1_a6_live_driver/v2-no-spawn-af1`).

---

## 2. Static branch isolation — ACCEPTED (unchanged from prior round)

`ValidateSet('DryRun','QualificationNoSpawn')` present. No-spawn cutoff at line 290 → exit 0 at line 359 → `controllerInvocationCount++` at 363 → controller `ProcessStartInfo` at 366 → `Process.Start` at 373. No-spawn branch contains zero `Process.Start` / `Start-Process` / controller / mida-cli / protected-sample execution. `DryRun` live path never executed. (20 static gates PASS; `production_driver_no_spawn_static_verification.json`)

---

## 3. AF1 evidence-contract fixes (static, all verified)

- **[P1] Single child/controller argv owner**: `$controllerArgsNoSpawn` removed; one `$childArgv` + one `$controllerArgs = controller_options + $childArgv`, shared by both modes. `driver_no_spawn_qualification.json` has separate `child_argv` and `controller_argv`; `child_argv[0/1/2]` derived from `child_argv` itself; `child_argv_is_contiguous_tail_of_controller_argv` verified. (`child_argv_static_verification.json` written)
- **[P1] Finish/journal/self-result order**: finish journal written FIRST, then qualification + self-result derived from ACTUAL post-finish `$seq`/`$lastPhase`, atomic temp→rename, self-result last, stdout, exit 0.
- **[P1] Exclusive attempt lock + per-attempt isolation**: `driver_attempt.lock` via `FileMode.CreateNew`; duplicate/concurrent start fails closed (exit 20, collision evidence only); each attempt writes to isolated `attempt_<UUID>` dirs; never shared journal/self-result/finish.
- Live-path static equivalence vs v2: controller argv options/order, protected-sample position, timeout, no-bypass env, candidate naming, authorized head, launch mechanism all identical. (`live_path_static_equivalence.json`)

---

## 4. Offline harness gates (all PASS before the single production run)

- Runner synthetic exit-0: `driver_os_exit_code=0`, numeric, immutable evidence files written (driver.stdout.log, driver.stderr.log, driver.exit.json, runner_final_result.json). (`runner_synthetic_exit0.json`)
- Runner negative control: `exit 7` captured → `captured_os_exit_code=7`, `matches_expected=true`. (`negative_control_exit_capture.json`)
- Process observer synthetic qualification (3 runs): observer detects benign PowerShell child (`Start-Sleep`) and Python child (`synthetic_ok`), command-line patterns, parent-child lineage, start+exit, and writes summary. (`observer_synthetic_events_{1,2,3}.jsonl`, `observer_synthetic_summary_{1,2,3}.json`)
- On-demand-only Task Scheduler task: `TRIGGER_COUNT=0` (no calendar/time trigger), only explicit `/Run`.

---

## 5. Single dynamic production-driver qualification — **FAILED (QualificationFailed)**

The single production-driver `QualificationNoSpawn` attempt (via the on-demand task, native svchost ancestry) **failed with `driver_os_exit_code = 1`** due to a **driver code bug in the attempt-lock metadata write**:

> `$lockStream.Write(byte[])` — PowerShell could not resolve the `FileStream.Write` overload (requires `Write(byte[], int, int)`), throwing `MethodCountCouldNotFindBest` (`找不到"Write"的重载`), at the very start of the driver, **before** the mode guard / preflight / no-spawn branch.

Evidence:
- `driver_os_exit_code = 1`, `exit_code_is_numeric = true`, `driver_timed_out = false`, driver PID 26884, start 16:09:00.900Z / end 16:09:01.564Z. (`runner_final_result.json`, `driver.exit.json`)
- `driver.stderr.log`: `Cannot find an overload for "Write" and the argument count: "1"`.
- The `driver_attempt.lock` was created, but the `attempt_<UUID>` evidence subdirs are **empty** (driver died at the lock Write before any journal/self-result/qualification).
- Observer (`observer_events.jsonl`): `production_driver_process_seen=true`, `production_driver_start_count_observed=1`, `controller_seen=false`, `mida_cli_seen=false`, `artifact_seen=false`, `epoch_helper_seen=false`.

**Single-execution discipline honored:** the single production-driver attempt was consumed and FAILED. Per Section 10, I did **not** re-run. Not re-running avoids creating a second driver PID (which would be `ExecutionDisciplineViolation`).

**No ExecutionDisciplineViolation** (exactly one driver PID observed). **No SafetyViolation** (zero controller/mida-cli/protected-sample/candidate).

The driver bug fix (`$lockStream.Write($lockBytes, 0, $lockBytes.Length)`) is documented in `driver_bug_note.json` but **not applied** to the canonical driver in this work order (single-execution discipline forbids re-run after the attempt is consumed).

---

## 6. Repo & evidence boundary (after)

- HEAD = `f386b49...`, no commit/push.
- tracked modified = same 3 Q0-C files; SHA/size and `git diff --binary` SHA identical to freeze-before.
- untracked source = 0.
- canonical supervisor unchanged (`8863898f...` / 10820 bytes).
- Evidence dir: `D:\MidaVault\lab\analysis\route_y_r1_a6_production_driver_no_spawn_af1_20260812T234800Z\`, recursive `evidence_freeze.json` (27 entries incl. failed-attempt evidence). No prior evidence overwritten/deleted.
- Only new untracked report: `docs/GTO_ROUTE_Y_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF1_RESULT.md`; untracked docs 38 → 39.

---

## 7. Gates

| Gate | Result |
|------|--------|
| `git diff --check` | PASS (exit 0) |
| Driver static gates (20) | PASS |
| AF1 evidence-contract static fixes | PASS (single argv owner, finish-order, lock, atomic, per-attempt isolation) |
| Live-path static equivalence | PASS |
| Runner synthetic exit-0 | PASS |
| Runner negative control (exit 7) | PASS |
| Observer synthetic qualification | PASS |
| On-demand-only task (TRIGGER_COUNT=0) | PASS |
| Production-driver dynamic qualification | **FAILED** (exit 1, driver lock `Write` overload bug) |
| `python tools/test_gto_live_route_controller.py` (offline) | not re-run this round (no repo change); recorded from prior where applicable |
| Cargo re-run | NOT performed (no repo source changed) |

---

## 8. Final classification

**Status: `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF1_QualificationFailed`**

- Static no-spawn branch isolation: ACCEPTED (unchanged).
- AF1 evidence-contract static fixes: implemented and verified.
- Single dynamic qualification: **FAILED** (driver lock-metadata `Write` overload bug, exit 1, before any no-spawn logic).
- Single-execution discipline: honored (attempt consumed, not re-run).
- No ExecutionDisciplineViolation, no SafetyViolation.
- **Stopped, awaiting independent audit.**

**Next step:** a NEW work order to fix the driver lock-metadata `Write` overload bug and run a fresh, clean single `QualificationNoSpawn`. Not authorized to proceed to Supervisor Production Integration R1, Q0-C commit, or protected live.

**Honesty notes:** worker gates ≠ independent audit. Static no-spawn core accepted from the v2 round. This round repaired the evidence contract and attempted one clean single run; the dynamic run failed on a driver code bug, reported as `QualificationFailed` per Section 10. `DryRun`/controller/protected/mida-cli/candidate were never executed.
