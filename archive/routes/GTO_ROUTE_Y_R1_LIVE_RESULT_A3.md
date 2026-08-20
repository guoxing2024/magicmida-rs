# Route Y R1 A3 — Atomic Capture Epoch Single Live Truth Run — RESULT

**Status:** `RouteY_R1_A3_CandidateNotReady`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This work order authorized a **single** protected-sample live truth run. It ran once (controller recorded `spawned=true`), so the live authorization is **consumed**. **No second spawn was performed.**

---

## Result classification

**`RouteY_R1_A3_CandidateNotReady`** — the child spawned but failed **before any dump stage** due to a **shell invocation defect**, not a dump-pipeline failure. No candidate was produced. **No rerun was performed** (single-spawn rule respected).

### Root cause: Git-Bash `/unpack` path-mangling

The controller was invoked from a Git Bash shell, which (via MSYS path conversion) rewrote the literal `/unpack` argument into a Git path **before Python received the argv**. The child (`mida-cli.exe`) therefore received:

```
mida-cli.exe "C:/Program Files/Git/unpack" D:/MidaVault/vault/sha256/4d/.../artifact.exe ...
```

and rejected it immediately:

```
Error: Unknown command 'C:/Program Files/Git/unpack'. Use --help for usage information.
```

Confirmed in the controller's own `command_line_display` (`controller_attempt_001.json`). The dump pipeline **never started** (`last_observed_stage=null`, `elapsed_ms=329`), the protected sample was **never loaded/executed** by `mida-cli` (its SHA-256 `4d5770af…` is unchanged), and no candidate was produced.

**This is an invocation-environment defect on the driver side (Git-Bash mangling), not a code or dump failure.** A correct invocation must preserve `/unpack` as a literal (e.g. via PowerShell/cmd, or `MSYS_NO_PATHCONV=1`).

---

## Evidence directory

`D:\MidaVault\lab\evidence\gto_launcher\live_20260811T150831Z_route_y_r1_declared_size_reinit_a3`

Retained raw files: `controller_run.json`, `controller_attempt_001.json`, `child.stdout.bin/.txt`, `child.stderr.bin/.txt`, `argv_static_verification.json`, `build_attestation.json`, `build_binary_verify.json`, `git_preflight.json`, `sample_policy_contract.json`, `capture_policy.json`. All raw evidence kept; no manual summary only.

---

## Preflight (all PASS)

| Gate | Result |
|---|---|
| branch | `oreans/two-sample-mainline` ✓ |
| HEAD | `f386b49…` ✓ |
| HEAD^ | `68b8032…` ✓ |
| tracked working tree | clean (0 modified) ✓ |
| untracked | exactly 12 existing docs ✓ |
| disk space | 191G avail ✓ |
| evidence dir | created fresh, unique, pre-existing=no ✓ |
| sample path/hash | `D:\MidaVault\vault\sha256\4d\4d5770af…\artifact.exe` = `4d5770af…` (matches A2 frozen) ✓ |
| capture policy | `{"preset":"ahk_gto_defaults"}` (matches A2 frozen) ✓ |
| canonical build | `D:\MidaVault\scratch\cargo-target-route-y1-a3\debug\mida-cli.exe` ✓ |
| binary SHA-256 | `c26ae9c5663a631127d3afe5d0b2a9e76f9b4168f4a3fd73ae3975942f0826c8` ✓ |
| binary size | 11072000 ✓ |
| attestation HEAD | `f386b49…` (authorized) ✓ |
| gto_product_recovery | true ✓ |
| `capture_epoch_helper.exe` in canonical target | absent (P1-4) ✓ |
| controller | sha256 `512b26dffc685fe2077a9b84c124d47f1340ade1a76402342e699da6986cda36` (matches A2) ✓ |
| env contract | `MIDA_GTO_NO_BYPASS=1`, no bypass/semantic-repair ✓ |

## Controller run (single, live authorization consumed)

| Field | Value |
|---|---|
| spawned | **true** (pid 13596) |
| spawn count | 1 |
| exit_code | 1 (child arg-parse rejection) |
| timed_out | false |
| elapsed_ms | 329 |
| last_observed_stage | null (no dump stage reached) |
| process_tree_cleanup_status | exited_naturally |
| controller_error | null |
| build_capability_preflight_error | null |
| live_environment_preflight_error | null |
| candidate | **0** (no candidate produced) |

## Production chain outcomes

| Stage | Outcome |
|---|---|
| capture_epoch_freeze | NOT reached (child rejected arg before any dump work) |
| detect_containers | NOT reached |
| detect_heap_globals / raw_children | NOT reached |
| capture_heap_slab | NOT reached |
| capture_epoch_restore | NOT reached |
| transform_input_seed (A2 child 0x3327260 / RVA 0x144400) | NOT reached — A3 did not re-test this live |
| transform recorder | NOT reached |
| sanitize declared-size transition | NOT reached |
| Q0-C overlay | NOT reached |
| runtime rebase plan | NOT reached |
| bound transform manifest | NOT reached |
| candidate | none |

Because the child never executed the dump pipeline, the A2 drift (child 0x3327260 / RVA 0x144400) was **not** re-tested in this run. No raw child/slab drift evidence was produced.

## Post-execution boundary

- Residual processes: **none** (`mida-cli`, `capture_epoch_helper`, `artifact` all absent).
- Protected sample hash unchanged (`4d5770af…`) — not modified.
- No evidence deleted.
- No source/Cargo/controller/policy modified.
- No `git add`/`git commit`.
- Git working tree clean; exactly 12 existing docs untracked.
- Only new doc: `docs/GTO_ROUTE_Y_R1_LIVE_RESULT_A3.md` (this file, untracked). Expected untracked docs = 13.

## Summary (required fields)

- **final status:** `RouteY_R1_A3_CandidateNotReady`
- **branch/HEAD/HEAD^:** `oreans/two-sample-mainline` / `f386b49…` / `68b8032…`
- **canonical binary:** `D:\MidaVault\scratch\cargo-target-route-y1-a3\debug\mida-cli.exe`, SHA `c26ae9c5…`, size 11072000
- **attestation:** `D:\MidaVault\scratch\cargo-target-route-y1-a3\gto_cli_build_attestation.json`, verdict = PASS (HEAD/branch/feature/sha match)
- **argv[0] raw/resolved:** matched (attested binary path used verbatim)
- **evidence dir:** `…\live_20260811T150831Z_route_y_r1_declared_size_reinit_a3`
- **controller exit:** child exit 1 (arg-parse); controller preflight gates all passed
- **preflight verdict:** PASS (all gates), then child rejected mangled arg
- **spawned/pid/spawn count:** true / 13596 / 1
- **live authorization consumed:** **yes** (spawned=true recorded; single-spawn rule respected, no rerun)
- **elapsed/timeout/timed_out:** 329ms / 600s / false
- **capture epoch count/ids/elapsed/restore verdict:** n/a (epoch never begun; no stage ran)
- **last successful stage:** none
- **first failing stage:** pre-dump command-line argument parsing (Git-Bash `/unpack` → `C:/Program Files/Git/unpack`)
- **A2 child 0x3327260 / RVA 0x144400 outcome:** NOT re-tested (pipeline never started)
- **sanitize declared transition outcome:** n/a
- **Q0-C overlay outcome:** n/a
- **runtime plan outcome:** n/a
- **manifest outcome:** n/a
- **candidate count/path/SHA/size:** 0 / n/a / n/a / n/a
- **residual process check:** none
- **git status:** working tree clean; 12 existing docs untracked; only new doc is this A3 report (untracked; total untracked docs = 13)
- **no rerun / no second spawn / no cold-start / no promote:** yes (all honored)

## Next-step recommendation (NOT executed in this work order)

The live authorization for A3 was consumed by a defective invocation (Git-Bash `/unpack` mangling) that never executed the protected sample. A **corrected, freshly-authorized** A3 run (invoked via PowerShell/cmd or with `MSYS_NO_PATHCONV=1` so `/unpack` stays literal) would be required to actually re-test the A2 drift (child 0x3327260 / RVA 0x144400) under the Route Z atomic capture epoch. This requires a new explicit authorization; it was not performed here.
