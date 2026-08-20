# Route Y R1 A6 C2 — Benign Fixture Text-Log Parser Closure — RESULT

**Status:** `RouteY_R1_A6_C2_ControllerQualifiedNoProtectedSample`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This was a **benign controller smoke** (no protected live authorization). One benign controller invocation ran against the harmless attested fixture; the fixture's plain newline-separated argv self-log was parsed with the corrected **newline parser** and matched `controller_run.json.command_argv` exactly, per-element, byte-for-byte. The C1 parser-format mismatch is closed. **0 protected-sample spawn, 0 candidate.**

---

## Result classification

**`RouteY_R1_A6_C2_ControllerQualifiedNoProtectedSample`** — the C2 smoke met ALL success criteria. The fixture's argv self-log is present, parseable, and exactly matches the controller-side argv.

### What WAS proven

- `benign_smoke_log_allowlisted=true` — `BENIGN_SMOKE_LOG` allowlisted and reached the child.
- `benign_child_log_present=true` — the fixture wrote its argv self-log.
- **`benign_child_log_parseable=true`** — the C1 parser-format mismatch is fixed: the driver reads the raw log bytes, UTF-8 decodes, normalizes CRLF→LF, strips ONE trailing LF, and splits on LF with .NET `String.Split` (`StringSplitOptions.None`: preserves every element, never silently drops empty args, never trims interior whitespace, no `ConvertFrom-Json`).
- `benign_fixture_argv_parse.json`: `parse_format="newline-separated"`, `parser="raw-bytes-utf8-crlf-normalize-dotnet-split"`, `parse_ok=true`, `parsed_argv_count=11`, `raw_sha256=476a6ec7…`, `raw_size=395`.
- **`child_received_literal_unpack=true`** — `argv[1] == "/unpack"` (literal) in the fixture self-log.
- **`fixture_selflog_matches_controller_argv=true`** — per-element ordinal compare vs `controller_run.json.command_argv`: count equal (11=11), order preserved, `all_elements_byte_equal=true`, `per_element_mismatches=[]`.
- No `C:/Program Files/Git/unpack`, no `Program Files/Git`, no protected sample path/hash in the self-log or controller argv.
- Controller: `spawned=true`, `command_argv[1]=='/unpack'`, `exit_code=0`, `no_bypass_verified=true`, `build_capability_preflight.ok=true`, `capture_policy_preflight.ok=true`, `process_tree_cleanup_status="exited_naturally"`.
- Negative control: `captured_os_exit_code=7`, `matches_expected=true`.
- Supervisor: `driver_os_exit_code=0`, `codes_match=true`, `qual_ok=true`, **supervisor final exit=0**, **Task Scheduler `LastTaskResult=0`**.
- No residual processes.

### Zero-spawn pre-validation (before the live run)

The newline parser was pre-validated offline against the frozen C1 raw log (`smoke_20260811T170708Z…/benign_fixture_argv.json`): parsed 11 elements, ordinal-equal and byte-equal to the C1 `controller_run.command_argv`, `argv[1]=='/unpack'`, no git/protected. This confirmed the parser logic before the single controller invocation.

---

## Evidence

- Bootstrap: `D:\MidaVault\lab\evidence\gto_launcher\bootstrap_20260811T172134Z_route_y1_a6_c2_controller_smoke`
  - `driver_journal.jsonl` (13 phases; smoke_verdict ok=True, parse=True), `driver_self_result.json` (success=true, code=0), `driver.exit.json` (os=0, numeric, codes_match=true), `exit_capture_negative_control.json` (7), `supervisor_final_result.json` (final=0, qual_ok=true), `driver_frozen_c2.ps1.txt`, `launch_record.json`, `native_powershell_environment.json` (parent chain svchost→services→wininit, no MSYS), `git_preflight.json` (0/0/20, docs=20 LIVE), `ps51_newitem_compat.json`, `supervisor_parent_chain.json`, `driver.stdout.log` (`C2_SMOKE_OK`), `driver.stderr.log` (empty), `driver.start.json`
- Smoke: `D:\MidaVault\lab\evidence\gto_launcher\smoke_20260811T172134Z_route_y1_a6_c2_controller_smoke`
  - `controller_run.json` (spawned=true, command_argv[1]=/unpack, exit=0, no_bypass, allowlist includes BENIGN_SMOKE_LOG), `controller_attempt_001.json`, `controller.stdout.log`, `controller.stderr.log`, `smoke_qualification.json` (ok=true), `benign_fixture_argv.json` (raw self-log), `benign_fixture_argv_parse.json`, `benign_fixture_argv_compare.json`, `benign_fixture.json`, `benign_test_attestation.json` (smoke_test=true, protected_sample=false, candidate_generation=false), `argv_static_verification.json`, `capture_policy.json`, `evidence_freshness.json`, `evidence_write_probe.json`

### Script identities (live `Get-Item.Length`)

| Script | SHA-256 | Size | Parent |
|---|---|---|---|
| `route_y1_a6_c2_driver.ps1` | `38112eea91a4deddd18d3386a65f2a4a6142384614ea82cf0a06e5dbb4cc689c` | 18967 | C1 `a0431528…` |
| `route_y1_a6_c2_supervisor.ps1` | `60ee7982c228350c73caa19397d8bbe3d4bbf5d94e3a3013598dcac049802752` | 7348 | C1 `a37f44ec…` |

Static gate `New-Item.*-LiteralPath` = 0. Native PS 5.1, clean parent chain. Benign fixture `D:\MidaVault\scratch\benign_smoke.exe` (133632 B, SHA `96383097…`, UNCHANGED — no fixture modification, no JSON rewrite). Controller `tools\gto_live_route_controller.py` SHA `512b26df…` (unchanged).

---

## Required report fields

- **final status:** `RouteY_R1_A6_C2_ControllerQualifiedNoProtectedSample`
- **controller invocation count:** 1
- **benign child spawn count:** 1
- **protected sample spawn count:** 0
- **candidate:** 0
- **`command_argv[1] == "/unpack"`:** true (controller-side)
- **fixture argv self-log present:** true
- **self-log parseable (newline parser):** true (`parse_format="newline-separated"`, .NET Split, 11 elements)
- **parsed argv exact match vs `command_argv`:** true (count/order/byte-for-byte)
- **`child_received_literal_unpack`:** true
- **no `Program Files/Git`:** true (self-log and controller argv)
- **no protected sample / candidate path in argv:** true
- **fixture exit:** 0 (controller_run exit_code=0)
- **controller exit numeric:** 0
- **supervisor final exit:** 0
- **Task Scheduler LastTaskResult:** 0
- **negative control:** 7 (matches_expected)
- **no residual process:** yes
- **Git status at execution:** 0 tracked / 0 source / 20 docs untracked (LIVE count, not hardcoded)
- **Git status after C2 report:** 0 tracked / 0 source / 21 docs untracked

## Honesty statement

- C0 was an **allowlist gap** (`BENIGN_SMOKE_LOG` not allowlisted → no fixture self-log).
- C1 closed the allowlist gap (self-log captured and correct) but failed on a **driver parse-format mismatch** (`ConvertFrom-Json` on plain newline-separated text).
- **C2 closes the parser mismatch**: the fixture's real newline-separated format is parsed with a raw-byte UTF-8 + CRLF-normalize + `String.Split` (keeps empties) parser, and the parsed argv **exactly matches** `controller_run.json.command_argv` (count/order/byte-for-byte). No fixture or controller change was needed or made.
- This is a **benign controller smoke**, NOT a live truth run and NOT Route Y semantic success. 0 protected sample, 0 candidate, no live authorization.
- The smoke fully qualified: supervisor exit 0, Task Scheduler `LastTaskResult=0`, negative control 7.

---

## Post-execution boundary

- C2 bootstrap + smoke evidence preserved (not deleted); C0/C1 evidence untouched.
- No protected sample spawn, no controller rerun, no candidate, no live authorization.
- Scheduled task (temp) deleted; no residual processes.
