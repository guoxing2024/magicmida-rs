# Route Y R1 A6 D0 — Native Driver Bootstrap Evidence and No-Spawn Qualification — RESULT

**Status:** `RouteY_R1_A6_D0_DriverNotQualified`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This was a **no-spawn driver qualification** (no live authorization). It confirmed a concrete, reproducible driver defect with an exact exception. **0 protected-sample spawn, 0 controller invocation, 0 Popen, 0 candidate, 0 live authorization.**

---

## Result classification

**`RouteY_R1_A6_D0_DriverNotQualified`** — the supervisor and driver fail at the very first evidence-directory step due to a **Windows PowerShell 5.1 incompatibility**, producing **zero evidence** (the silent-death-with-no-evidence failure this work order was designed to expose and fix).

---

## CONFIRMED root cause (exact, reproducible)

Both the **supervisor** (`route_y1_a6_d0_supervisor.ps1`) and the **driver** (`route_y1_a6_d0_driver.ps1`) call:

```powershell
New-Item -ItemType Directory -LiteralPath $path
```

**`New-Item -LiteralPath` is NOT supported in Windows PowerShell 5.1** (`powershell.exe`); it was introduced in PowerShell Core 6+. In 5.1 it throws:

```
New-Item : 找不到与参数名称“LiteralPath”匹配的参数。
+ New-Item -ItemType Directory -LiteralPath $bootstrapDir | Out-Null
+                              ~~~~~~~~~~~~
+ CategoryInfo : InvalidArgument: (:) [New-Item]，ParentContainsErrorRecordException
+ FullyQualifiedErrorId : NamedParameterNotFound,Microsoft.PowerShell.Commands.NewItemCommand
```

With `$ErrorActionPreference = 'Stop'`, this terminates the script immediately **before creating the bootstrap directory**, so no evidence is written.

### This EXPLAINS the A5 mystery

The A5 driver's log stopped at `A5_FRESH existed_before_creation=False` and the driver exited with no evidence — the very next statement was `New-Item -ItemType Directory -LiteralPath $evidenceDir`, which fails on Windows PowerShell 5.1. **A5's "unknown" root cause is now confirmed: `New-Item -LiteralPath` is unsupported in Windows PowerShell 5.1.**

---

## What was verified / what failed

| Item | Result |
|---|---|
| Git boundary (branch/HEAD/HEAD^/tracked-clean/0-source/15-docs) | PASS |
| Native PowerShell target | Windows PowerShell 5.1 (`C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe`) |
| Supervisor scheduled via Task Scheduler | task ran (LastRunTime 2026-08-11T23:45:52Z), **LastTaskResult=1** |
| Supervisor bootstrap-dir creation | **FAIL** (`New-Item -LiteralPath` unsupported) |
| Driver launch | NOT reached (supervisor failed first) |
| driver_journal.jsonl / stdout / stderr / exit evidence | **none produced** (bootstrap dir never created) |
| Final dry-run evidence dir | not created |
| transport probe / build / controller argv | not reached |
| controller invocation count | **0** |
| spawned | **false** |
| protected sample execution | **0** |
| candidate | **0** |

---

## Evidence

No bootstrap directory, no final dry-run evidence directory, no frozen driver copy, no journal were produced (the failure precedes bootstrap-dir creation). The supervisor/driver scratch scripts remain at `D:\MidaVault\scratch\route_y1_a6_d0_supervisor.ps1` / `route_y1_a6_d0_driver.ps1` as evidence of the defect. Scheduled task `route_y1_a6_d0` (my temp artifact) was deleted; no residual processes.

---

## Required report fields

- **final status:** `RouteY_R1_A6_D0_DriverNotQualified`
- **bootstrap directory:** none (creation failed)
- **final dry-run evidence directory:** none
- **driver path/SHA/size/version:** `D:\MidaVault\scratch\route_y1_a6_d0_driver.ps1` / `4a1812a457f2f10ea1be111db140449c14094abd468f694f7ff979551aecea47` / 21968 / `route_y1_a6_d0/v1`
- **supervisor identity:** `D:\MidaVault\scratch\route_y1_a6_d0_supervisor.ps1` / SHA `cb26beff3b8ea122bfa975564b3287a06a21627af54c88fafc4b07be88daf11e` / Task-Scheduler task `route_y1_a6_d0` (LastTaskResult=1)
- **driver exit code:** n/a (supervisor failed before launching driver)
- **stdout/stderr paths:** n/a (bootstrap not created)
- **last journal phase:** `evidence_directory_create` / `evidence_directory_write_test` (would be the failing step) — journal never created
- **native PowerShell / parent chain:** Windows PowerShell 5.1 (native target); supervisor launched via Task Scheduler (clean chain)
- **freshness result:** not reached (supervisor failed before the driver's freshness gate)
- **transport probe observed argv:** not reached
- **build binary / attestation:** not reached
- **controller argv[0]/argv[1]:** not assembled
- **controller invocation count:** 0
- **Popen count:** 0
- **spawned:** false
- **protected sample execution count:** 0
- **candidate:** 0
- **residual processes:** none
- **Git status:** clean; 15 docs untracked; 0 extra source
- **no live / no controller / no rerun:** yes (honored)

---

## Fix required for a follow-up qualification (NOT applied in this work order)

Replace every `New-Item -ItemType Directory -LiteralPath $path` with either `New-Item -ItemType Directory -Path $path` (supported in both PS 5.1 and pwsh) or `[System.IO.Directory]::CreateDirectory($path)`. This affects the supervisor's bootstrap-dir creation and the driver's evidence-dir creation. A fresh `RouteY_R1_A6_D0` qualification (or a D0-reissue) with this one-line fix per site should then reach the full journal / freshness / probe / build / controller-argv / ready_to_spawn pipeline.

---

## Post-execution boundary

- No residual processes (`mida-cli`, `capture_epoch_helper`, `artifact` absent).
- No build target created, no protected sample touched.
- Repo: 0 tracked changes, 0 untracked source, 15 docs untracked.
- Scheduled task and temp task-XML dir cleaned up; scratch driver/supervisor scripts retained as evidence.
- No live authorization granted or consumed.
