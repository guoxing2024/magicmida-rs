# Route Y R1 A6 D0 R2 — OS Exit-Code-Proven No-Spawn Qualification — RESULT

**Status:** `RouteY_R1_A6_D0_DriverQualifiedNoSpawnExitProven`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This was a **no-spawn driver qualification** (no live authorization) that adds real OS exit-code evidence and supervisor failure propagation. **0 protected-sample spawn, 0 controller invocation, 0 Popen, 0 candidate.**

---

## Result classification

**`RouteY_R1_A6_D0_DriverQualifiedNoSpawnExitProven`** — all exit-code and failure-propagation criteria satisfied:

- **negative control OS exit = 7** (capture helper distinguishes non-zero)
- **formal driver OS exit = 0** (numeric)
- **driver self-result = 0**
- **codes_match = true**
- **supervisor final exit = 0**
- **Task Scheduler LastTaskResult = 0** (matches supervisor final exit)
- 17/17 journal pass; transport probe PASS; build/attestation PASS
- controller=0, Popen=0, spawned=false, candidate=0

---

## Blockers fixed

### [P1] `driver.exit.json` exit code was null → now numeric OS exit code

Previous evidence had `"exit_code": null` (PS 5.1 `Start-Process -PassThru` + redirects returns null ExitCode). R2 replaced the child launch with **direct `System.Diagnostics.ProcessStartInfo` + `Process.Start()` + `WaitForExit()`**, which materializes the OS exit code reliably (verified on `exit 7` → 7). New evidence:

```json
// driver.exit.json
{
  "driver_os_exit_code": 0,
  "exit_code_is_numeric": true,
  "driver_self_result_code": 0,
  "codes_match": true,
  "qualification_ok": true,
  "spawned": false
}
```

`driver_self_result.json` (written by the driver before its own `exit 0`):
```json
{ "completed": true, "success": true, "intended_exit_code": 0, "exception": null,
  "last_journal_sequence": 17, "last_journal_phase": "driver_finish" }
```

### [P1] Supervisor did not propagate driver failure → now propagates

The supervisor now: (a) runs a **negative-control** child (`exit 7`) through the same capture helper (proving it distinguishes 0 vs non-zero); (b) captures the driver's numeric OS exit code; (c) fails the qualification if the code is null / nonzero / mismatched / artifacts missing; (d) exits 0 only on full success, otherwise exits nonzero (10/11/12). Task Scheduler `LastTaskResult=0` therefore now corresponds to a genuine qualified run.

`exit_capture_negative_control.json`:
```json
{ "child_command": "powershell.exe -NoProfile -Command \"exit 7\"",
  "captured_os_exit_code": 7, "exit_code_is_numeric": true, "matches_expected": true,
  "is_negative_control_only": true, "qualification_failure": false }
```

`supervisor_final_result.json`:
```json
{ "supervisor_final_exit": 0, "qual_ok": true, "driver_os_exit_code": 0,
  "codes_match": true, "artifacts_complete": true, "negative_control_captured_code": 7,
  "spawned": false }
```

### [P2] "no rerun" claim corrected → honest accounting

| Category | Count |
|---|---|
| offline qualification attempts (rounds 1–4 prior + R2) | **4 prior + 1 R2** (all preserved as bootstrap/dryrun dirs) |
| final successful dry-run attempt | R2 |
| live attempts in D0 | **0** |

This report declares **"no live rerun"** (correct), and does **not** claim "no rerun" of the offline qualification.

---

## Script identities (live, `Get-Item.Length`)

| Script | SHA-256 | Size (bytes) | Version | Parent SHA |
|---|---|---|---|---|
| `route_y1_a6_d0_r2_driver.ps1` | `222a2362ff4afb7af72df845bbd8e762c017143702f245af69ab1f4c408ca2d7` | 17467 | `route_y1_a6_d0_r2/v1` | `b3e7588f…` (requal driver) |
| `route_y1_a6_d0_r2_supervisor.ps1` | `0f09f793fd684d61f9f8a43b243b8055152485a2994374889498cbb75226d7fc` | 8918 | `route_y1_a6_d0_r2_supervisor/v1` | `de2ddab8…` (requal supervisor) |

Static gate `New-Item.*-LiteralPath` = **0**. Windows PowerShell 5.1 (`LiteralPath=False`, `Path=True`).

---

## Evidence

- Bootstrap: `D:\MidaVault\lab\evidence\gto_launcher\bootstrap_20260811T164057Z_route_y1_a6_d0_r2`
  - `driver_journal.jsonl` (17/17 pass), `driver_self_result.json`, `driver.exit.json`, `exit_capture_negative_control.json`, `supervisor_final_result.json`, `driver_frozen_r2.ps1.txt`, `launch_record.json`, `driver.stdout.log`, `driver.stderr.log`, `driver.start.json`, `native_powershell_environment.json`, `git_preflight.json`, `input_contract.json`, `ps51_newitem_compat.json`, `supervisor_parent_chain.json`, `capture_policy.json`
- Final dry-run: `D:\MidaVault\lab\evidence\gto_launcher\dryrun_20260811T164057Z_route_y1_a6_d0_r2`
  - `ready_to_spawn.json`, `dry_run_complete.json`, `evidence_freshness.json`, `evidence_write_probe.json`, `powershell_python_argv_transport_probe.json`, `build_attestation_copy.json`, `build_binary_verify.json`, `controller_argv_ready.json`
- All prior rounds (1–4) evidence dirs preserved; all prior scripts preserved.

## Git boundary (live)

`tracked_modified=0`, `untracked_source=0`, `untracked_docs=17`. No source/Cargo/controller/policy modified. No git add/commit. Scheduled task (temp) deleted.

---

## Required report fields

- **final status:** `RouteY_R1_A6_D0_DriverQualifiedNoSpawnExitProven`
- **prior offline attempts:** 4 (rounds 1–4) + 1 R2 formal = 5 total offline qualification attempts; live attempts = 0
- **R2 formal qualification attempts:** 1 (single invocation; no re-run after a fix)
- **negative control OS exit:** 7 (numeric, matches_expected=true)
- **formal driver OS exit:** 0 (numeric, from `driver.exit.json`)
- **driver self-result:** 0 (`driver_self_result.json`, success=true, phase=driver_finish)
- **codes_match:** true
- **supervisor final exit:** 0 (`supervisor_final_result.json`)
- **Task Scheduler LastTaskResult:** 0
- **journal:** 17/17 pass (driver_start → driver_finish)
- **transport probe:** argv[0]=`/unpack`, exact_array_equality=true
- **build/attestation:** binary SHA `f55c70ea…` size 11072000, gto=true, helper absent
- **controller/Popen/spawn/candidate:** 0 / 0 / false / 0
- **residual processes:** none
- **Git status / docs count:** clean; 17 docs untracked
- **no live rerun:** yes (honored); no second spawn; no cold-start/promote

---

## Post-execution boundary

- R2 bootstrap + dryrun evidence preserved (not deleted), alongside all prior rounds.
- Frozen driver, stdout/stderr, exit evidence, self-result, journal all preserved.
- Scratch driver/supervisor scripts (old defective, requal, R2) all retained.
- No protected sample spawn, no controller, no Popen, no candidate, no live authorization.
