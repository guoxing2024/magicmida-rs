# Route Y R1 A4 — Native PowerShell Argument-Transport-Proven Single Live Truth Run — RESULT

**Status:** `RouteY_R1_A4_NotRun`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This work order authorized a **single** protected-sample live truth run under a native-PowerShell, argument-transport-proven environment. The run aborted **before any build or spawn** due to a defect in a **scratch driver script** (not the authorized controller/build/sample/policy tooling). **Live authorization was NOT consumed** (`spawned=false`, no controller invocation, no Popen). No re-run was performed.

---

## Result classification

**`RouteY_R1_A4_NotRun`** — preflight gate failed before spawn. Live authorization NOT consumed.

### Root cause: scratch-driver ordering bug (evidence-dir freshness check)

The A4 driver ran under a **clean native PowerShell parent chain** (verified: `svchost.exe → services.exe → wininit.exe`, no bash/mintty/wsl/git-bash), and all native-environment and Git preflight gates passed. The driver then created the evidence directory at an early step (to record the native environment) **before** its own evidence-dir-freshness check, so the freshness check saw the just-created directory as "pre-existing" and aborted with `A4_FATAL evidence dir pre-exists`.

This is a **defect in the temporary scratch driver script** (`D:\MidaVault\scratch\route_y1_a4_driver.ps1`), an orchestration file outside the repo. It is **not** a defect in the authorized controller, build script, protected sample, or capture policy, and **not** a Route Z / Route Y code regression.

Per the work order's strict rule ("严禁同工单修脚本…后重跑"), the driver was **not** modified and re-run. The aborted `_a4` evidence directory was left intact (not deleted, per "不删除 evidence").

---

## Evidence directory (aborted, pre-spawn)

`D:\MidaVault\lab\evidence\gto_launcher\live_20260811T152509Z_route_y_r1_declared_size_reinit_a4`

Retained (pre-spawn only, no build/spawn):
- `native_powershell_environment.json` — PS version, PID, path, parent chain (clean), MSYS env
- `git_preflight.json` — branch/HEAD/HEAD^/tracked-clean/13-docs

No `controller_run.json`, no `controller_attempt_*.json`, no build, no child output, no candidate.

---

## Native environment / parent-chain verdict (PASS)

| Field | Value |
|---|---|
| PS version | (recorded in `native_powershell_environment.json`) |
| driver PID | 19484 |
| parent chain | `svchost.exe → services.exe → wininit.exe` (Task Scheduler, detached from bash) |
| parent_chain_has_msys | **false** (no bash/mintty/wsl/git-bash) |
| shell_is_native_powershell | **true** |

## Git preflight (PASS)

| Field | Value |
|---|---|
| branch | `oreans/two-sample-mainline` ✓ |
| HEAD | `f386b49af8f547a16f3d107dc6e80c02ea6e4403` ✓ |
| HEAD^ | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` ✓ |
| tracked working tree | clean (0) ✓ |
| untracked | 13 docs, 0 extra source ✓ |

## Preflight gates before abort

| Gate | Result |
|---|---|
| native PowerShell parent chain clean | PASS |
| Git preflight | PASS |
| disk space | 189.5 GB avail (PASS) |
| evidence dir freshness | **FAIL** (scratch-driver ordering bug: dir created by the driver's own earlier step) |
| → **aborted here, before build/spawn** | |

---

## Summary (required fields)

- **final status:** `RouteY_R1_A4_NotRun`
- **native PowerShell / parent-chain verdict:** clean (no MSYS); verified via Task-Scheduler-detached launch
- **transport probe observed argv:** NOT executed (aborted before the probe; the freshness-gate failure preceded it)
- **command_argv[0] / command_argv[1]:** n/a (no controller invocation)
- **branch/HEAD/HEAD^:** `oreans/two-sample-mainline` / `f386b49…` / `68b8032…`
- **canonical binary / SHA / size:** n/a (not built — aborted before build)
- **attestation verdict:** n/a
- **controller / sample / policy digests:** controller `512b26dffc685fe2077a9b84c124d47f1340ade1a76402342e699da6986cda36` (matched frozen); sample `4d5770af…` (matched frozen); policy `{"preset":"ahk_gto_defaults"}` (matched frozen) — all recorded, though no spawn followed
- **evidence directory:** `…\live_20260811T152509Z_route_y_r1_declared_size_reinit_a4`
- **preflight / spawn / PID / count:** first-failing gate = evidence-dir freshness (scratch-driver bug); spawned=false; PID=n/a; spawn count=0
- **authorization consumed:** **NO** (spawned=false)
- **elapsed / timeout / timed_out:** n/a (no spawn)
- **capture epoch telemetry / restore:** n/a (never reached)
- **last successful stage / first failing stage:** n/a / pre-spawn evidence-dir freshness gate
- **A2 child outcome:** n/a (not re-tested)
- **sanitize / Q0-C / runtime plan / manifest / candidate:** n/a (no pipeline ran)

---

## Post-execution boundary

- No residual processes (`mida-cli`, `capture_epoch_helper`, `artifact` all absent).
- Protected sample hash unchanged (`4d5770af…`).
- No build, no spawn, no candidate.
- Repo: 0 tracked changes, 0 untracked source (only 13 docs untracked). No source/Cargo/controller/policy modified.
- Scheduled task `route_y1_a4` (my temp artifact) deleted; scratch driver script removed.
- The aborted `_a4` evidence dir was left intact (not deleted).

## Next-step recommendation (NOT executed in this work order)

The live authorization for A4 was **not** consumed (pre-spawn NotRun). A **freshly authorized** A4 run with a corrected driver (evidence-dir freshness checked BEFORE the dir is created for env recording) would be able to proceed to the transport probe, build, and the single live spawn. Because the work order forbids fix-and-rerun within the same order, this requires a new explicit authorization. It was not performed here.
