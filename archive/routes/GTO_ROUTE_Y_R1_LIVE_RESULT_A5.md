# Route Y R1 A5 — Freshness-Order-Proven Native PowerShell Single Live Truth Run — RESULT

**Status:** `RouteY_R1_A5_NotRun`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This work order authorized a **single** protected-sample live truth run under a native-PowerShell, argument-transport-proven, evidence-freshness-order-proven environment. The scratch driver aborted **after the evidence-freshness gate and BEFORE creating the evidence directory / build / spawn**. **Live authorization was NOT consumed** (`spawned=false`, no controller invocation, no Popen). No re-run was performed.

---

## Result classification

**`RouteY_R1_A5_NotRun`** — pre-spawn failure. Live authorization NOT consumed.

### What was verified before abort (all PASS)

| Gate | Result |
|---|---|
| driver identity (SHA-256 `3e07b087…`, size 12060) | recorded |
| native PowerShell parent chain | clean (`shell_is_native_powershell=true`, `parent_chain_has_msys=false`) |
| Git preflight | PASS (branch/HEAD/HEAD^/tracked-clean/14 docs) |
| disk space | 189.5 GB avail (PASS) |
| **evidence freshness (A5 fix)** | **PASS**: `existed_before_creation=false`, then create-once |
| → next step: create evidence dir + write evidence | **aborted here (driver exited)** |

### Root cause: second scratch-driver defect (pre-spawn abort)

The driver logged `A5_FRESH existed_before_creation=False` (the A4 ordering bug was fixed and the freshness gate passed), then **exited without creating the evidence directory or writing any further evidence**. No A5 evidence directory exists. The driver process was no longer alive after the abort. Because `$ErrorActionPreference = 'Stop'`, a terminating error in the step immediately following the freshness check (evidence-dir creation / evidence write) would exit the script silently to the Task Scheduler host (not visible to the driver log).

This is a **defect in the temporary scratch driver** (`D:\MidaVault\scratch\route_y1_a5_driver.ps1`), **not** the authorized controller / build script / sample / policy, and **not** a Route Z / Route Y code regression. The protected sample was never executed.

Per the work order's strict rule ("禁止同工单修 driver 后重跑"), the driver was **not** modified and re-run.

### Observation on the driver approach

This is the second consecutive scratch-driver pre-spawn failure (A4: freshness ordering bug; A5: post-freshness abort). The detached Task-Scheduler driver pattern appears to have reliability issues in this environment (silent termination without evidence write). A corrected approach under a fresh authorization would need to (a) write evidence incrementally as it goes, so a mid-driver abort still leaves a durable audit trail, and (b) capture the driver's own stderr/exit into the evidence dir. This was not attempted here.

---

## Evidence

**No A5 evidence directory was created** (the driver aborted before `New-Item`). Therefore no `route_y1_a5_driver.ps1.frozen.txt`, `driver_identity.json`, `evidence_freshness.json`, `native_powershell_environment.json`, `git_preflight.json`, `powershell_python_argv_transport_probe.json`, `argv_static_verification.json`, build attestation, `controller_run.json`, child output, or candidate exist. The driver log (`D:\MidaVault\scratch\a5_driver.log`, since removed) recorded up to the freshness line only.

A3 and A4 evidence remain untouched and frozen.

---

## Summary (required fields)

- **final status:** `RouteY_R1_A5_NotRun`
- **evidence freshness ordering verdict:** freshness gate PASS (`existed_before_creation=false`), but evidence-dir creation never completed (driver aborted immediately after)
- **driver SHA/path/version:** `3e07b08767a332a634027d4b2f18938d6ab46d0d4427eea7fc7c4d113c6891c5` / `D:\MidaVault\scratch\route_y1_a5_driver.ps1` / `route_y1_a5/v1` (frozen copy was NOT written because the evidence dir was never created)
- **native PowerShell / parent chain:** clean (no MSYS)
- **transport probe observed argv:** NOT executed (driver aborted before the probe)
- **controller command_argv[0]/[1]:** n/a (no controller invocation)
- **branch/HEAD/HEAD^:** `oreans/two-sample-mainline` / `f386b49…` / `68b8032…`
- **binary / attestation SHA/size:** n/a (no build)
- **controller/sample/policy digests:** not re-verified in-run (no evidence dir); controller `512b26d…`, sample `4d5770af…`, policy `{"preset":"ahk_gto_defaults"}` per frozen contract
- **evidence directory:** none created
- **preflight / spawn / PID / count:** first-failing gate = post-freshness evidence-dir creation (driver abort); spawned=false; PID=n/a; spawn count=0
- **authorization consumed:** **NO**
- **elapsed / timeout / timed_out:** n/a (no spawn)
- **capture epoch telemetry / restore:** n/a
- **last successful stage / first failing stage:** n/a / pre-spawn driver abort
- **A2 child outcome:** n/a (not re-tested)
- **sanitize / Q0-C / runtime plan / manifest / candidate:** n/a (no pipeline ran)

---

## Post-execution boundary

- No residual processes (`mida-cli`, `capture_epoch_helper`, `artifact` absent).
- Protected sample hash unchanged (`4d5770af…`).
- No build, no spawn, no candidate.
- No A5 evidence dir created; A3/A4 evidence untouched.
- Repo: 0 tracked changes, 0 untracked source (only 14 docs untracked). No source/Cargo/controller/policy modified.
- Scheduled task `route_y1_a5` (my temp artifact) deleted; scratch driver script removed.

## Next-step recommendation (NOT executed in this work order)

The A5 live authorization was **not** consumed (pre-spawn NotRun). A **freshly authorized** run with a more robust driver (incremental evidence writes, driver stderr/exit captured into evidence, corrected post-freshness sequence) would be required to actually reach the transport probe, build, and the single live spawn. Because the work order forbids fix-and-rerun within the same order, this was not performed.
