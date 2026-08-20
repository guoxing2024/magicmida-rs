# Route Y R1 A6 D0 Requalification — Windows PowerShell 5.1-Compatible Driver Qualification — RESULT

**Status:** `RouteY_R1_A6_D0_DriverQualifiedNoSpawn`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`
**subject:** `fix(dumper): capture raw slabs in an atomic thread epoch`

This was a **no-spawn driver qualification** (no live authorization). The PS 5.1-compatible requal driver completed the full offline dry-run pipeline and stopped at `ready_to_spawn`. **0 protected-sample spawn, 0 controller invocation, 0 Popen, 0 candidate.**

---

## Result classification

**`RouteY_R1_A6_D0_DriverQualifiedNoSpawn`**

- supervisor exit: **0** (Task Scheduler `LastTaskResult=0`)
- driver exit: **0** (driver stdout: `A6D0_REQUAL_QUALIFIED exit=0`; driver `driver_finish.json` success)
- journal reached `driver_finish` (17/17 phases pass)
- bootstrap evidence complete; final dry-run evidence complete
- freshness/create-once PASS; transport probe PASS; build/attestation PASS
- controller argv ready; `would_invoke_controller=false`, `would_spawn=false`
- **controller invocation count=0, Popen=0, spawned=false, candidate=0**
- no residual process

---

## Fixes applied in this requalification (scratch driver only)

The original D0 driver failed on **Windows PowerShell 5.1** for two reasons, both now confirmed and fixed:

1. **`New-Item -LiteralPath` unsupported in PS 5.1** (`NamedParameterNotFound`) — all directory creation changed to `New-Item -ItemType Directory -Path` / `[System.IO.Directory]::CreateDirectory`. Static gate `Select-String "New-Item.*-LiteralPath"` = **0**.
2. **Ordering**: pre-freshness evidence (native env, git preflight, input contract) was written to the final evidence dir before it was created — now written to the **bootstrap dir** (always exists) until the freshness create-once step.
3. **MSYS parent-chain regex false positive**: `(bash|sh|...)` matched the "sh" inside "**power**sh**ell**" — now word-bounded `\b(bash|sh|mintty|wsl|git-bash)\b` (verified: "powershell"→False, "bash"→True).
4. **Supervisor `Start-Process -Wait` hang**: PS 5.1 `-Wait` with redirects blocks until all descendants release the handles — replaced with `-PassThru` + bounded `HasExited` poll, so the supervisor exits cleanly and writes `driver.exit.json`.

---

## Evidence

### Driver / supervisor identities (live, `Get-Item.Length`)

| Script | SHA-256 | Size (bytes) | Version |
|---|---|---|---|
| `route_y1_a6_d0_driver_requal.ps1` | `b3e7588fe9049ec2a0f1b296dd83c6c86e50aadc74e4ce1a81eabe53db96e934` | 17350 | `route_y1_a6_d0_requal/v1` |
| `route_y1_a6_d0_supervisor_requal.ps1` | `de2ddab83dd758d84e4e15c36012a496d85c3e55b0574d82ed1d4a587b0f0d76` | 4801 | — |

(Old defective scripts preserved: `route_y1_a6_d0_driver.ps1` 15813 bytes SHA `4a1812a4…`, `route_y1_a6_d0_supervisor.ps1` 4142 bytes SHA `cb26beff…`.)

### Windows PowerShell 5.1 compatibility gate (recorded)

```
PSVersion=5.1.26100.8875
NewItem_LiteralPath_supported=False
NewItem_Path_supported=True
```

Static gate `New-Item.*-LiteralPath` count = **0**.

### Bootstrap audit directory (round 4, successful)

`D:\MidaVault\lab\evidence\gto_launcher\bootstrap_20260811T162323Z_route_y1_a6_d0_requal`

Files: `capture_policy.json`, `driver.exit.json`, `driver.start.json`, `driver.stderr.log`, `driver.stdout.log`, `driver_finish.json`, `driver_frozen_requal.ps1.txt`, `driver_journal.jsonl`, `git_preflight.json`, `input_contract.json`, `launch_record.json`, `native_powershell_environment.json`, `ps51_newitem_compat.json`, `supervisor_parent_chain.json`.

### Final dry-run evidence directory (round 4, successful)

`D:\MidaVault\lab\evidence\gto_launcher\dryrun_20260811T162323Z_route_y1_a6_d0_requal`

Files: `build_attestation_copy.json`, `build_binary_verify.json`, `controller_argv_ready.json`, `dry_run_complete.json`, `evidence_freshness.json`, `evidence_write_probe.json`, `powershell_python_argv_transport_probe.json`, `ready_to_spawn.json`.

Earlier failed rounds (1–3) are preserved as bootstrap `…_161031Z / …_161433Z / …_161924Z` and dryrun `…_161924Z` dirs.

### Native PowerShell / parent chain

`native=True`, `msys=False`. Chain: `powershell.exe → svchost.exe → services.exe → wininit.exe` (Task-Scheduler detached; no bash/sh/mintty/wsl/git-bash).

### Freshness (create-once)

`existed_before_creation=false`, `created_once=true`, `exists_after_creation=true`, `initially_empty=true`, `write_test_ok=true`, `freshness_gate_pass=true`. (A4's ordering bug — create-then-Test-Path — is gone.)

### Transport probe (native PowerShell → Python argv)

`observed argv[0] == "/unpack"`, `exact_array_equality=true`, `probe_ok=true`, `probe_exit=0`. Observed argv (verbatim): `/unpack <sample> -o <candidate-placeholder> --data-sections --no-shrink --profile=ahk-gto-experimental --container-restore=post-crt --capture-policy=<policy> -v`. No `C:/Program Files/Git/unpack`.

### Canonical build / attestation

- Binary: `D:\MidaVault\scratch\cargo-target-route-y1-a6-d0-requal\debug\mida-cli.exe`
- SHA-256: `f55c70ea6f34044235e08938144724def891517dd892ea3339aca0d548ed2b4f` (attestation matches)
- Size: 11072000 bytes
- `gto_product_recovery=true`, HEAD `f386b49…`, `capture_epoch_helper.exe` **absent** in canonical target
- Build **never run** (offline only)

### Controller argv assembly (generated, NOT invoked)

- `child_argv0` = canonical `mida-cli.exe`
- `child_argv1` = literal `/unpack`
- `would_invoke_controller=false`, `would_spawn=false`, `dry_run=true`
- authorized HEAD `f386b49…`, attestation path, timeout 600, env allowlist incl. `MIDA_GTO_NO_BYPASS`, policy path, candidate placeholder — all recorded in `controller_argv_ready.json`

### Git boundary (live)

`tracked_modified=0`, `untracked_source=0`, `untracked_docs=16`. No source/Cargo/controller/policy modified. No git add/commit.

---

## Required report fields

- **final status:** `RouteY_R1_A6_D0_DriverQualifiedNoSpawn`
- **bootstrap directory:** `…\bootstrap_20260811T162323Z_route_y1_a6_d0_requal`
- **final dry-run evidence directory:** `…\dryrun_20260811T162323Z_route_y1_a6_d0_requal`
- **driver path/SHA/size/version:** `…\route_y1_a6_d0_driver_requal.ps1` / `b3e7588f…` / 17350 / `route_y1_a6_d0_requal/v1`
- **supervisor / Task Scheduler identity:** supervisor SHA `de2ddab8…`; task `route_y1_a6_d0_requal` `LastTaskResult=0`
- **driver exit code:** 0 (stdout `A6D0_REQUAL_QUALIFIED exit=0`)
- **stdout/stderr paths:** `…\bootstrap_20260811T162323Z…\driver.stdout.log` / `driver.stderr.log` (readable; stderr holds cargo build output, no driver error)
- **last journal phase:** `driver_finish` (17/17 pass)
- **native PowerShell / parent chain:** native=True, msys=False, clean chain
- **freshness result:** PASS (create-once, write probe ok)
- **transport probe observed argv:** `/unpack …` (exact, probe_ok=true)
- **build binary/attestation:** SHA `f55c70ea…`, size 11072000, gto=true, helper absent
- **controller argv[0]/argv[1]:** canonical binary / `/unpack`
- **controller invocation count=0, Popen count=0, spawned=false, protected sample execution count=0, candidate=0**
- **residual processes:** none
- **Git status / docs count:** clean; 16 docs untracked
- **no live / no controller / no rerun:** yes (honored)

---

## Post-execution boundary

- Bootstrap + final dry-run evidence directories preserved (all rounds), not deleted.
- Frozen driver copy, driver stdout/stderr, exit evidence, journal all preserved.
- Scratch driver/supervisor scripts retained (old defective + new requal).
- Scheduled task (my temp artifact) deleted; no residual processes.
- No protected sample spawn, no controller, no Popen, no candidate, no live authorization.
