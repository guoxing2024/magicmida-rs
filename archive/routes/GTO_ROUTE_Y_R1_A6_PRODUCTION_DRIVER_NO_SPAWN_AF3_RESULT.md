# Route Y R1 A6 — Production Driver No-Spawn AF3 Result

**Work order:** `RouteY_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF3_EVIDENCE_FRESHNESS_CORRECTION`

**Title:** Evidence-Freshness Gate Correction + Clean Exactly-One QualificationNoSpawn

**Target success state:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ReviewRequested`

**Current state (this delivery):** Static + harness gates PASS; **dynamic qualification NOT yet run** (per management conclusion — it must not run until static+harness evidence passes audit).

---

## 1. Fix applied (Option A: remove eager creation)

**Chosen approach: Option A — remove the eager `CreateDirectory($attemptEvidenceDir)`.**

The AF2 bug was a self-inflicted false-positive: the driver created `$attemptEvidenceDir`
at initialization, then the evidence-freshness gate tested that SAME directory with
`Test-Path`, which was always `true`, throwing `evidence dir pre-existed`.

**Fix:** removed the eager `[System.IO.Directory]::CreateDirectory($attemptEvidenceDir)`
from the driver initialization block. The single legal creation point is now the
freshness gate's own `New-Item` after its existed-before check. Correct order (as required):

1. create bootstrap parent (`$attemptBootstrapDir`) only
2. check `$attemptEvidenceDir` existence (existed_before)
3. if exists → fail (exit non-zero, gate `evidence_preexisted`)
4. create `$attemptEvidenceDir` (single legal point)
5. verify exists + empty
6. write evidence probe
7. verify write success

### Before (AF2, broken)
```powershell
$attemptBootstrapDir = Join-Path $BootstrapDir ("attempt_" + $attemptId)
$attemptEvidenceDir = Join-Path $EvidenceDir ("attempt_" + $attemptId)
[System.IO.Directory]::CreateDirectory($attemptBootstrapDir) | Out-Null
[System.IO.Directory]::CreateDirectory($attemptEvidenceDir) | Out-Null   # <-- eager, causes false-positive
```

### After (AF3, fixed)
```powershell
$attemptBootstrapDir = Join-Path $BootstrapDir ("attempt_" + $attemptId)
$attemptEvidenceDir = Join-Path $EvidenceDir ("attempt_" + $attemptId)
# AF3 (Option A): create ONLY the bootstrap parent here. Do NOT eagerly create
# $attemptEvidenceDir — the evidence-freshness gate is the single legal creation point.
[System.IO.Directory]::CreateDirectory($attemptBootstrapDir) | Out-Null
```

The freshness gate (unchanged ordering, now correct) is:
```powershell
$existedBefore = Test-Path -Path $attemptEvidenceDir          # now genuinely false
if ($existedBefore) { throw "evidence dir pre-existed" }       # no longer falsely triggered
New-Item -ItemType Directory -Path $attemptEvidenceDir | Out-Null  # single legal create point
```

## 2. Driver identities

| Item | Value |
|------|-------|
| AF3 driver version | `route_y1_a6_live_driver/v3-no-spawn-af3` |
| AF3 driver path | `D:\MidaVault\scratch\route_y1_a6_live_driver_v3_no_spawn_af3.ps1` |
| AF3 driver SHA256 | `4ea9d6e4246a6b02004655910418827317984322f54d679cf64fd43d98a2559c` |
| AF3 driver size | 39246 |
| AF2 driver SHA256 (parent) | `1615283eeca308ad63e6a8b80170da93f4987783630a9f3e7fafb0d6007e1da9` |
| AF2 driver size (parent) | 37735 |

## 3. Static gates (Section A) — PASS

`preflight_static_verification.json`: **check_count=21, passed=21, failed=0**.

Key checks (all true):
- freshness check before creation
- single legal evidence create point
- no eager `CreateDirectory($attemptEvidenceDir)`
- freshness gate does not flag a driver-self-created dir
- lock-write repair not regressed (3-arg `Write`, no 1-arg)
- `FileMode.CreateNew` preserved
- lock read-back consistency verify preserved
- no-spawn branch has no controller / mida-cli / protected-sample invocation
- single childArgv + single controllerArgs owner, no `controllerArgsNoSpawn`
- child argv 0/1/2 derived from childArgv, contiguous tail verify
- no-spawn cutoff before controller counter
- controller invocation count logic unchanged
- version is v3-no-spawn-af3

## 4. Harness gates (Section B) — PASS (re-run on AF3 version)

`harness_gates_result.json`: **lock=True runner=True observer=True ALL=True**.

- **lock primitive**: non-empty JSON, metadata round-trip, duplicate `CreateNew` collision rejected.
- **runner exit-capture**: synthetic exit 0 → numeric 0, exit 7 → numeric 7 (in both driver.exit.json and runner_final_result.json).
- **observer exact attribution**: driver start count=1, driver PID (24972) == runner driver_started_pid (24972), runner PID (25372) != driver PID, controller/mida/artifact/epoch all false.

AF2's harness result is history only; this is the AF3 re-run.

## 5. Dynamic qualification — NOT RUN (awaiting audit)

Per the work order's management conclusion: **"AF2 关闭为失败态；AF3 允许立项，但在静态和
harness 证据经审计通过前，不得执行那一次唯一的动态 qualification。"**

The single dynamic `QualificationNoSpawn` is intentionally deferred. It will be run in a
follow-up only after this static+harness evidence passes independent audit.

## 6. Boundary (freeze before == after)

- HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (unchanged)
- branch `oreans/two-sample-mainline` (unchanged)
- Q0-C 3 files unchanged (heap_global `5a60ded9…`/402997, raw_slab `bf6da4d3…`/780270, snapshot_manifest `91c3a392…`/57963)
- supervisor `8863898f…`/10820 (unchanged)
- tracked modified = 3 (Q0-C only), untracked source = 0, git diff --check clean
- no commit / push / git add
- AF2 evidence dir preserved read-only; AF2 dir not in any AF3 mutable output path.

## 7. Delivery checklist

| # | Item | Status |
|---|------|--------|
| 1 | AF3 driver SHA256 + size | `4ea9d6e4…` / 39246 |
| 2 | Fix before/after code lines | Section 1 above |
| 3 | Static gate raw result | `preflight_static_verification.json` (21/21) |
| 4 | Harness raw result | `harness_gates_result.json` (3/3) |
| 5 | Single dynamic qualification raw dir | NOT RUN (deferred) |
| 6 | observer.json | produced in harness only (dynamic observer deferred) |
| 7 | driver journal | NOT RUN (deferred) |
| 8 | lock file | harness-only synthetic; dynamic lock deferred |
| 9 | runner/driver exit evidence | harness-only synthetic; dynamic deferred |
| 10 | safety counters | 0 (no dynamic run) |
| 11 | freeze_before.json | present |
| 12 | freeze_after.json | present |
| 13 | evidence_freeze.json self-verify | see below |
| 14 | AF3 final report | this file |

---

**Evidence root:** `D:\MidaVault\lab\analysis\route_y_r1_a6_production_driver_no_spawn_af3_20260813T042232Z\`
