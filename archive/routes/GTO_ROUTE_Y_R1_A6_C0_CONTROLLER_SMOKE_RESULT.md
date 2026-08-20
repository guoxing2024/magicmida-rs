# Route Y R1 A6 C0 — Native Controller Transport Smoke Without Protected Sample — RESULT

**Status:** `RouteY_R1_A6_C0_ControllerSmokeFailed`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This was a **benign controller transport smoke** (no protected live authorization). One controller invocation ran against a harmless attested fixture child. The **core transport was proven**, but one smoke-success criterion (the fixture's own argv self-log) failed because the fixture's logging env var was not in the controller's allowlist. **0 protected-sample spawn, 0 candidate.**

---

## Result classification

**`RouteY_R1_A6_C0_ControllerSmokeFailed`** — the smoke did not meet all success criteria. The failure is narrow and precisely root-caused; per the work order's "no fix-and-rerun" rule, no rerun was performed.

### Root cause (precise)

The benign fixture records its argv via the `BENIGN_SMOKE_LOG` environment variable. The controller spawns the child with **only the allowlisted env** (`SystemRoot, WINDIR, PATH, TEMP, TMP, COMSPEC, MIDA_GTO_NO_BYPASS`); `BENIGN_SMOKE_LOG` was **not allowlisted**, so the fixture could not write its argv self-log (`benign_child_log_present=false`). This is a **smoke-evidence gap** (fixture env not allowlisted), NOT a transport failure.

### What WAS proven (controller-side transport)

The controller's own `controller_run.json` recorded:
- `spawned=true` (the benign child was spawned exactly once)
- `command_argv[1] == "/unpack"` (literal, no MSYS mangling)
- `exit_code=0` (controller + child)
- `effective_env_contract.no_bypass_verified=true` (MIDA_GTO_NO_BYPASS=1 propagated, no bypass)
- no protected sample path/hash anywhere in argv
- controller OS exit code numeric = 0

**The native PowerShell → Python controller → benign child argument transport is proven** by `command_argv[1]=='/unpack'`. The only unmet criterion was the fixture's redundant self-log.

### Failure propagation worked (a positive C0 result)

- supervisor `driver_os_exit_code=1`, `smoke_ok=false`, `qual_ok=false`
- supervisor final exit = **10** (driver OS exit nonzero → propagated)
- **Task Scheduler `LastTaskResult=10`** — the smoke failure was NOT masked (unlike the earlier "always 0" supervisor). This validates the R2 failure-propagation plumbing end-to-end.
- negative control: `captured_os_exit_code=7`, `matches_expected=true`.

---

## Evidence

- Bootstrap: `D:\MidaVault\lab\evidence\gto_launcher\bootstrap_20260811T165910Z_route_y1_a6_c0_controller_smoke`
  - `driver_journal.jsonl` (13 phases, driver_start → driver_finish; smoke_verdict ok=False), `driver_self_result.json` (success=false, code=1), `driver.exit.json` (os=1, numeric, codes_match=true), `exit_capture_negative_control.json` (7), `supervisor_final_result.json` (final=10, qual_ok=false), `driver_frozen_c0.ps1.txt`, `launch_record.json`, `native_powershell_environment.json`, `git_preflight.json`, `ps51_newitem_compat.json`, `supervisor_parent_chain.json`, `driver.stdout.log`, `driver.stderr.log`, `driver.start.json`
- Smoke: `D:\MidaVault\lab\evidence\gto_launcher\smoke_20260811T165910Z_route_y1_a6_c0_controller_smoke`
  - `controller_run.json` (spawned=true, command_argv[1]=/unpack, exit=0, no_bypass), `controller.stdout.log`, `controller.stderr.log`, `smoke_qualification.json` (ok=false, child_received_literal_unpack=false due to missing env), `benign_fixture.json`, `benign_test_attestation.json` (smoke_test=true, protected_sample=false, candidate_generation=false), `argv_static_verification.json`, `capture_policy.json`, `evidence_freshness.json`, `evidence_write_probe.json`

### Script identities (live `Get-Item.Length`)

| Script | SHA-256 | Size |
|---|---|---|
| `route_y1_a6_c0_driver.ps1` | `c9ad7f05028152ca625371f1353b2333503b3ce681b31a8ec2bea018589f924b` | 14718 |
| `route_y1_a6_c0_supervisor.ps1` | `4888b3e1f0e778e99a261452e8b111abcd7635ca966eb1332df755b1202e1085` | 7477 |

Parent SHAs recorded (driver ← `222a2362…` R2, supervisor ← `0f09f793…` R2). Static gate `New-Item.*-LiteralPath` = 0. Native PS 5.1, parent chain clean (no MSYS).

### Benign fixture

`D:\MidaVault\scratch\benign_smoke.exe` (133632 bytes, records argv to `BENIGN_SMOKE_LOG`, exits 0). Not the protected sample. Test attestation marked `smoke_test=true, protected_sample=false, candidate_generation=false`.

---

## Required report fields

- **final status:** `RouteY_R1_A6_C0_ControllerSmokeFailed`
- **D0 rounds 1–4 + R2:** offline qualification (accepted)
- **C0:** one benign controller smoke (this run)
- **protected live attempts:** 0
- **protected sample spawn:** 0
- **candidate:** 0
- **controller invocation count:** 1
- **benign child spawn count:** 1
- **Popen count:** only the controller's expected benign child (1)
- **`command_argv[1] == "/unpack"`:** true
- **child received literal `/unpack`:** not evidenced (fixture log missing due to un-allowlisted `BENIGN_SMOKE_LOG` env); transport itself proven by `command_argv`
- **child/controller exit numeric:** child exit_code=0 (controller_run), controller OS exit=0
- **no protected process / no residual:** yes / none
- **supervisor failure propagation:** proven (LastTaskResult=10 ≠ 0)
- **Git status / docs:** 0 tracked / 0 source / 18 docs untracked
- **no live / no candidate / no protected sample:** honored

## Honesty statement

- The C0 result is a **benign controller smoke**, NOT a live truth run and NOT Route Y semantic success.
- The core transport (`/unpack` literal through native PowerShell → controller → child) IS proven by `command_argv[1]=='/unpack'`, but the smoke did not fully qualify because the fixture's own argv self-log was not captured (env not allowlisted).
- The failure was propagated (supervisor exit 10, LastTaskResult 10) — the exit-capture/failure-propagation plumbing is validated.

---

## Post-execution boundary

- C0 bootstrap + smoke evidence preserved (not deleted).
- No protected sample spawn, no controller rerun, no candidate, no live authorization.
- Scheduled task (temp) deleted; no residual processes.
