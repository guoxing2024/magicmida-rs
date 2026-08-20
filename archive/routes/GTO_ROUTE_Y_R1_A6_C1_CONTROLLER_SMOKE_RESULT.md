# Route Y R1 A6 C1 — Benign Fixture argv Evidence Closure — RESULT

**Status:** `RouteY_R1_A6_C1_ControllerSmokeFailed`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This was a **benign controller smoke** (no protected live authorization). One benign controller invocation ran; the fixture's argv self-log was captured (the C0 gap is closed), but the smoke driver parsed the self-log as JSON while the fixture writes plain text, so the parse-level cross-check failed. **0 protected-sample spawn, 0 candidate.**

---

## Result classification

**`RouteY_R1_A6_C1_ControllerSmokeFailed`** — one smoke-success criterion failed due to a **driver parse-format mismatch** (fixture self-log is plain newline-separated text; the driver's `ConvertFrom-Json` expected JSON). Per the work order's "no fix-and-rerun on failure", no rerun was performed.

### What WAS proven (the C0 evidence gap is closed)

- `benign_smoke_log_allowlisted=true` — `BENIGN_SMOKE_LOG` was explicitly allowlisted and reached the child.
- `benign_child_log_present=true` — the fixture wrote its argv self-log.
- The self-log content (verbatim) is **correct and complete**:
  ```
  D:\MidaVault\scratch\benign_smoke.exe
  /unpack
  benign-input.dat
  -o
  D:\...\smoke_20260811T170708Z_...\smoke_out.exe
  --data-sections --no-shrink --profile=ahk-gto-experimental --container-restore=post-crt
  --capture-policy=...
  -v
  ```
  `argv[1] == "/unpack"` (literal), no `C:/Program Files/Git/unpack`, no `Program Files/Git`.
- The self-log **exactly matches** `controller_run.command_argv` (each line = one argv element, order/values identical).
- Controller: `spawned=true`, `command_argv[1]=='/unpack'`, `exit_code=0`, `no_bypass_verified=true`, no protected sample path/hash in argv.
- Negative control: `captured_os_exit_code=7`, `matches_expected=true`.
- Supervisor failure propagation: `driver_os_exit_code=1`, `qual_ok=false`, supervisor final exit=**10**, **Task Scheduler `LastTaskResult=10`**.

### Root cause (precise, driver-side)

The C1 driver reads the fixture's `benign_fixture_argv.json` with `ConvertFrom-Json`, but the benign fixture writes **plain newline-separated argv text** (from its `args.join("\n")`). Hence `benign_child_log_parseable=false`, which also failed `child_received_literal_unpack` (derived from the parsed array) and `fixture_selflog_matches_controller_argv`. The raw self-log is correct; only the driver's JSON parse expectation is wrong for this fixture's output format.

---

## Evidence

- Bootstrap: `D:\MidaVault\lab\evidence\gto_launcher\bootstrap_20260811T170708Z_route_y1_a6_c1_controller_smoke`
  - `driver_journal.jsonl` (13 phases; smoke_verdict ok=False), `driver_self_result.json` (code=1), `driver.exit.json` (os=1 numeric, codes_match=true), `exit_capture_negative_control.json` (7), `supervisor_final_result.json` (final=10), `driver_frozen_c1.ps1.txt`, `launch_record.json`, `native_powershell_environment.json`, `git_preflight.json`, `ps51_newitem_compat.json`, `supervisor_parent_chain.json`, `driver.stdout.log`, `driver.stderr.log`, `driver.start.json`
- Smoke: `D:\MidaVault\lab\evidence\gto_launcher\smoke_20260811T170708Z_route_y1_a6_c1_controller_smoke`
  - `controller_run.json` (spawned, argv[1]=/unpack, exit=0), `controller.stdout.log`, `controller.stderr.log`, `smoke_qualification.json`, `benign_fixture_argv.json` (the captured self-log), `benign_fixture.json`, `benign_test_attestation.json`, `argv_static_verification.json`, `capture_policy.json`, `evidence_freshness.json`, `evidence_write_probe.json`

### Script identities (live `Get-Item.Length`)

| Script | SHA-256 | Size | Parent |
|---|---|---|---|
| `route_y1_a6_c1_driver.ps1` | `a0431528dd3c52814306bc90cef96a60b7391176e88fb95a247ed391e370f386` | 16196 | C0 `c9ad7f05…` |
| `route_y1_a6_c1_supervisor.ps1` | `a37f44ec8d4a37d3815c6a30d36dc59ac8117a0d03b0f0829b9b69e28fd43c40` | 7348 | C0 `4888b3e1…` |

Static gate `New-Item.*-LiteralPath` = 0. Native PS 5.1, clean parent chain. Benign fixture `D:\MidaVault\scratch\benign_smoke.exe` (133632 B).

---

## Required report fields

- **final status:** `RouteY_R1_A6_C1_ControllerSmokeFailed`
- **controller invocation count:** 1
- **benign child spawn count:** 1
- **protected sample spawn count:** 0
- **candidate:** 0
- **`command_argv[1] == "/unpack"`:** true
- **fixture argv self-log present:** true (C0 gap closed)
- **self-log parseable:** false (driver expects JSON; fixture writes plain text)
- **self-log argv[1] literal `/unpack`:** evidenced in raw file (parse-derived flag false)
- **self-log vs controller argv exact match:** evidenced in raw file (parse-derived flag false)
- **no `Program Files/Git`:** true
- **fixture exit:** 0 (controller_run exit_code=0)
- **controller exit numeric:** 0
- **supervisor final exit:** 10 (failure propagated)
- **Task Scheduler LastTaskResult:** 10
- **negative control:** 7 (matches_expected)
- **no residual process:** yes
- **Git status / docs:** 0 tracked / 0 source / 19 docs untracked (C1 report not yet written)

## Honesty statement

- The C0 argv-self-log gap is **closed**: `BENIGN_SMOKE_LOG` was allowlisted and the fixture's argv record was written and matches `command_argv`.
- The smoke did not fully qualify because the **driver's self-log parse used JSON while the fixture writes plain text** — a driver fixture-format mismatch, not a transport or evidence failure.
- No protected sample, no candidate, no live authorization; failure was propagated (LastTaskResult=10).

---

## Post-execution boundary

- C1 bootstrap + smoke evidence preserved (not deleted); C0 evidence untouched.
- No protected sample spawn, no controller rerun, no candidate, no live authorization.
- Scheduled task (temp) deleted; no residual processes.
