# Route Y R1 A6 — Production Driver No-Spawn AF2 Result

**Final status:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF2_QualificationFailed`

**Target success state:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF2_ReviewRequested`

**Work order:** Lock-Write Repair, Exact PID Attribution, Same-Runner Negative Control, Clean Exactly-One Dynamic Qualification.

---

## Summary

The AF2 work order delivered all four required repairs and passed every static and
harness gate. The single production-driver `QualificationNoSpawn` attempt **failed with
a non-zero exit (1)**, but the failure was **not** the AF2 lock-write bug (that was fixed
and verified) — it was a **second, previously-masked pre-existing bug** in the
evidence-freshness gate. Per the work order's explicit terminal-state rule ("一次非零 =
AF2_QualificationFailed"), the attempt was not re-run; evidence is preserved and the
terminal state is `AF2_QualificationFailed`.

---

## 1. AF1 Correction (completed)

- Exported stale task `af1_no_spawn_qual2` (XML + action + trigger + status + last-result).
- Confirmed it was an **on-demand-only task with zero triggers** (`<Triggers />`); the
  prior AF1 report's "trigger_count=1" was a PowerShell `@($null).Count` artifact.
- Deleted it and confirmed **0 stale tasks** match `route_y1_a6|a6_no_spawn|af1|af2`.

## 2. Driver (v2-no-spawn-af2)

- Archived AF1 driver: SHA `9c97c919…` / 34576 bytes (unchanged).
- Bumped version to `route_y1_a6_live_driver/v2-no-spawn-af2`; new SHA `1615283e…` / 37735 bytes.
- **Lock-Write Repair applied and VERIFIED:**
  - `$lockStream.Write($lockBytes, 0, $lockBytes.Length)` + `Flush()` + `Dispose()`
    wrapped in `try/finally`.
  - Write failure → `attempt_lock_failure.json` + exit 30.
  - Read-back consistency verify: lock file must be non-empty JSON with matching
    attempt_id/driver_pid/driver_sha256/mode/bootstrap_dir/evidence_dir.
  - `FileMode.CreateNew` preserved (concurrent/duplicate start → collision evidence + exit 20).
- DryRun/live argv, controller SHA, supervisor all unchanged.

## 3. Preflight Static Gates (all PASS)

No `controllerArgsNoSpawn`; single `$childArgv` + single `$controllerArgs` shared by both
modes; child argv index 0 = canonical binary, index 1 = literal `/unpack`, index 2 =
protected sample; child argv is contiguous tail of controller argv; no single-arg
`Write(byte[])`; lock dispose in try/finally; no-spawn cutoff (line 331) before
`$controllerInvocationCount++` (404) / ProcessStartInfo (407) / Process.Start (414); no
controller/mida/protected in the no-spawn branch.

## 4. Harness Gates (all PASS)

- **PS5.1 lock primitive:** non-empty JSON lock round-trips attempt_id/PID/mode/dirs;
  second `CreateNew` open correctly rejected (collision).
- **Runner exit-capture:** synthetic exit 0 → numeric 0, synthetic exit 7 → numeric 7,
  both present in `driver.exit.json` AND `runner_final_result.json`.
- **Observer exact attribution:** driver PID == runner `driver_started_pid` (1464 == 1464),
  runner PID (18580) != driver PID, driver count == 1, controller/mida/artifact/epoch all false.

## 5. Dynamic Qualification (single attempt)

- Fresh bootstrap/evidence/runner dirs; on-demand task `af2_no_spawn_qual` registered with
  **zero triggers** (verified null-safe); observer started; single explicit `Run`.
- Driver PID **21380**, runner PID **26000**. Observer confirmed **driver start count == 1**,
  no controller/mida/artifact/epoch.

### Failure (AF2_QualificationFailed)

- **Lock fix SUCCEEDED**: the driver advanced past the lock (journal sequence 1-8) and wrote
  a valid non-empty lock file (`driver_attempt.lock`, 464 bytes) with consistent metadata.
- **New failure**: the driver threw `evidence dir pre-existed` at line 193
  (gate `evidence_preexisted`). Root cause: line 39 eagerly creates `$attemptEvidenceDir`,
  so the freshness check `Test-Path $attemptEvidenceDir` at line 191 is always true.
- This is a **pre-existing bug masked by AF1's lock failure** (AF1 died at the lock before
  reaching line 190; this line was never exercised). It is independent of the AF2 lock fix.
- Driver exit code 1, `driver_timed_out=false`, no re-run (Section 10 discipline).

### Safety / discipline

- `controller_invocation_count=0`, `protected_sample_spawn_count=0`, `candidate_count=0`,
  `mida_cli_spawn=0`, `protected_sample_executed=false`.
- No ExecutionDisciplineViolation (single attempt), no SafetyViolation.
- Residual driver/runner/observer process count = 0; matching task count after delete = 0.

## 6. Boundary (freeze before == after)

- HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (unchanged).
- Q0-C 3 files unchanged (heap_global `5a60ded9…`/402997, raw_slab `bf6da4d3…`/780270,
  snapshot_manifest `91c3a392…`/57963).
- Supervisor `8863898f…`/10820 unchanged.
- tracked modified = 3 (Q0-C only), untracked source = 0, git diff --check clean.
- No commit / push / git add.

## 7. Next work order

Fix the evidence-freshness gate (remove the eager `CreateDirectory` at line 39, or test a
distinct sentinel instead of the dir the driver itself created), then run a fresh single
`QualificationNoSpawn`.

---

**Evidence root:** `D:\MidaVault\lab\analysis\route_y_r1_a6_production_driver_no_spawn_af2_20260812T182400Z\` (recursive `evidence_freeze.json`, 31 files).
