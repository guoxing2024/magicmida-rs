# Unattended Execution Plan — MagicMida vNext

**Mode:** operator-absent continuous engineering  
**Branch:** `baseline/legacy-recovery-20260722`  
**Opened:** 2026-07-24  
**Definition of done (project “complete” for audit):** structure + load + behavior + repro + multi-family, with scheduled gates and vault evidence — **not** a marketing 1.0 claim without **VNEXT-BEH**.

This document is the single long-horizon plan for unattended work. Short handoff
lives in [WORKER_HANDOFF.md](../WORKER_HANDOFF.md). Architecture truth remains
in [PROJECT_AUDIT_AND_ROADMAP.md](PROJECT_AUDIT_AND_ROADMAP.md) and the VNEXT-*
path docs.

---

## 0. Hard non-negotiables (never violate unattended)

| Rule | Action if pressure to break |
|------|-----------------------------|
| R0B `check-static` never returns `Accepted` | Refuse; keep Pending/Rejected only |
| Pure dump default remains **legacy** until explicit flip decision | Do not flip |
| GTO stages only with `--profile=ahk-gto-experimental` | Do not auto-enable |
| Oreans ≠ GTO (family identity + IAT trace gates) | Keep dual_select + uses_oreans_iat_trace |
| Vault-only PE; no sample bytes in git | Hygiene scripts; refuse commits of PE |
| VNEXT-BEH / B-B only on deliberate scheduled gate with evidence | Do not write task `VNEXT-BEH` early |
| Dali remains OOS | No live unpack claim |
| No false re-close of R3 10× / R4 structural without re-run | Engineering smokes ≠ gates |

---

## 1. Current baseline (facts at plan open)

| Item | Status |
|------|--------|
| R0B / R1-E synthetic / R2 slices / R3 structural / R4 structural | **Closed** (historical; see `validation_summary.json` task **VNEXT-R4**) |
| B-A0..B-A3 (synthetic compose path) | **Done** |
| B-B / VNEXT-BEH | **Not open** |
| Pure default | **No** |
| Host thin split | `post_loop`, `early_snapshots`, (+ `post_attach` when landed) |
| Shared `ThemidaState` for GTO | Honest residual (not independent GTO host) |
| ScyllaHide x64 hashes | MATCH (vault hygiene) |
| ScyllaHide x86 hashes | Placeholder until real x86 binaries available |
| Latest engineering smokes | Origin / GTO 1× green after early_snapshots |

**“Perfect unpack” distance:** structural multi-family path works; load/behavior
equivalence and full multi-family productization remain open. Unattended work
closes the **largest safe gaps** without lying about gates.

---

## 2. Phased program (execute in order; skip only with written residual)

### U0 — Truth sync (immediate)

1. Write this plan + refresh `WORKER_HANDOFF.md` + roadmap §Phase 6 note.
2. Record residual audit list (section 4).
3. Durable MSVC wrappers already present (`_rebuild_cli.cmd`, `_enter_msvc_env.ps1`).

**Exit:** docs match HEAD; no gate claims advanced.

### U1 — Host thin-split (engineering ROI)

1. Extract post-attach observation path → `post_attach.rs`.
2. Optional further extracts only if net LOC reduction + tests green:
   - CREATE_PROCESS / guard install helpers
   - LoopState-adjacent pure helpers
3. Do **not** claim independent GTO host or full R2 loop migration.

**Exit:** `mida-cli` dual_select + Origin/GTO engineering smokes green; mod.rs smaller.

### U2 — Regression cadence (continuous)

1. `archive/gto-20260730/tools/_smoke_p1_origin_gto.cmd` after each host-touching commit.
2. On demand (not every micro-commit): Lunlun 1×, holdout 1× (not R3 10× re-gate).
3. Synthetic: `cargo test -p mida-acceptance --offline`; B-A1/B-A3 smokes if behavior code touched.

**Exit:** vault batch dirs under `lab/evidence/_repeat` / `_gto_smoke` for each run.

### U3 — Quality residuals (Oreans path)

| Work | Priority | Unattended rule |
|------|----------|-----------------|
| Lunlun residual quality (OEP / IAT notes only if code change) | P1 | Evidence-only unless clear bug |
| ScyllaHide **x86** real hashes | P1 | Only if trusted x86 helpers appear on disk; else document residual |
| TLS `global_vars` use | P2 | Defer unless sample blocks |
| R1-F typed import → pure builder | P2 | Optional; pure still opt-in |
| Pure default flip | Closed No | Do not reopen without operator |

### U4 — Behavioral path (only up to engineering, not gate)

1. Keep B-A2/B-A3 synthetic green.
2. Optional Origin **offline** behavior probe experiments under vault evidence —
   **must not** set `validation_summary` task to VNEXT-BEH.
3. B-B opens only when:
   - synthetic compose remains green,
   - at least one vault candidate has bound Pass evidence under policy,
   - residual risks documented,
   - explicit note that product default path is still structural Pending unless operators schedule Accepted.

**Default unattended stance:** **do not open B-B** unless all criteria above are
met with vault evidence; prefer stopping at “audit-ready residual list” over a
premature gate.

### U5 — Audit package (user acceptance)

Deliver without requiring further human steps:

1. Updated roadmap / handoff / this plan with final HEAD.
2. Table of closed vs residual vs non-claims.
3. Pointers to vault evidence batches (paths only).
4. Command matrix for auditor re-run (MSVC env + smokes + acceptance tests).
5. Explicit list of what still blocks “perfect unpack 1.0”.

---

## 3. Unattended execution loop

```text
while residual_work and safe_slice_exists:
    pick highest-ROI safe slice (U1 > U2 hygiene > U3 if evidence)
    implement + unit/lib tests
    Origin 1× + GTO 1× if host/unpack path touched
    commit if green
    update WORKER_HANDOFF status table
if no safe slice without false gate:
    freeze at U5 audit package
    stop (user audits)
```

**Stop conditions (success for this mode):**

- No remaining **safe** engineering slice that reduces perfect-unpack distance
  without opening pure/VNEXT-BEH/R3-reclaim falsely, **and**
- Audit package is complete and honest.

**Stop conditions (blocked):**

- MSVC/link broken and not self-healable via known VsDevCmd wrappers.
- Vault missing / cases dematerialized (document; do not invent samples).
- Live unpack flaky beyond retry budget (3×) — record residual, pivot.

---

## 4. Residual audit list (living)

| ID | Residual | Blocks 1.0? | Unattended path |
|----|----------|-------------|-----------------|
| R-BEH | No VNEXT-BEH; no product Accepted | **Yes** | B-A* only; B-B deliberate |
| R-PURE | pure default still No | Medium | Keep No; optional R1-F later |
| R-HOST | Shared ThemidaState; debug loop in cli | High (arch) | Thin-split only; full plugin host later |
| R-GTO | Experimental profile; residual cookie/CRT | Medium | Smokes only; no auto profile |
| R-LUN | Historical degraded OEP path notes | Medium | Evidence; fix only with repro |
| R-X86 | ScyllaHide x86 hash placeholders | Medium (x86 samples) | Fill when binaries present |
| R-TLS | TLS global_vars unused | Medium | Deferred |
| R-DALI | Managed OOS | No (scope) | Keep OOS |

---

## 5. Command matrix (auditor)

```powershell
# MSVC
cmd /c tools\_rebuild_cli.cmd
# or
powershell -File tools\_enter_msvc_env.ps1

$env:CARGO_TARGET_DIR = 'D:\MidaVault\scratch\cargo-target'
cargo test -p mida-acceptance --offline
cargo test -p mida-cli --lib --offline dual_select
python tools\_behavior_ba3_smoke.py
python lab\cases\verify_manifests.py --objects-root D:\MidaVault\objects\sha256
cmd /c archive\gto-20260730\tools\_smoke_p1_origin_gto.cmd
```

Non-claims after green smokes: **not** R3 10×, **not** R4 re-gate, **not**
Behavioral Accepted, **not** pure default.

---

## 6. Progress log (append-only)

| UTC date | HEAD (short) | Slice | Result |
|----------|--------------|-------|--------|
| 2026-07-24 | 4ac8edd | Plan open; prior post_loop+early_snapshots | baseline |
| 2026-07-24 | e99cda6 | U1 post_attach extract + dual_select green | Origin `…011521`; GTO `…011543`; Lunlun `…011721`; holdout `…011818`; B-A3 `…011835` |
| 2026-07-24 | f66e157 | U1 LoopState + Scylla x86 residual note + audit package | Origin `…012108`; GTO `…012147`; freeze for human audit (R-BEH blocks 1.0) |
