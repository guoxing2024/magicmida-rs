# Audit Package — Unattended baseline (2026-07-24)

**Audience:** human auditor / acceptance only (no operator required for re-run).  
**Branch:** `baseline/legacy-recovery-20260722`  
**HEAD at package open:** `e99cda6` (post_attach extract + unattended plan)  
**Validation summary task:** still **VNEXT-R4** (not VNEXT-BEH)

Plan source: [UNATTENDED_EXECUTION_PLAN.md](UNATTENDED_EXECUTION_PLAN.md)  
Handoff: [WORKER_HANDOFF.md](../WORKER_HANDOFF.md)

---

## 1. Executive verdict (honest)

| Claim | Status |
|-------|--------|
| Independent structural acceptance (R0B) | **Yes** — never `Accepted` on `check-static` |
| Pure PE rebuild path (opt-in) | **Yes** (synthetic + Origin/Lunlun structural_equal history); **default still legacy** |
| Oreans structural multi-case (R3 gate historically closed) | **Yes** (historical 10×); engineering 1× regressions green on 2026-07-24 |
| Second family AHK/GTO structural (R4) | **Yes** (historical); experimental profile only |
| Behavioral `Accepted` / VNEXT-BEH | **No** — B-A0..B-A3 synthetic only |
| Perfect unpack (structure+load+behavior+repro+multi-family product) | **Not claimed** |

**Auditor bottom line:** Research baseline is **audit-ready for structural multi-family work** and **not** ready to claim product 1.0 or Behavioral Accepted.

---

## 2. Closed gates (do not re-open as new claims)

| Gate | Evidence anchor |
|------|-----------------|
| R0B | `crates/acceptance`, `docs/ACCEPTANCE_CONTRACT.md`, offline tests |
| R1-E synthetic pure | pe purity/rebuild tests; pure default flip **No** |
| R3 Oreans structural | `validation_summary.prev_20260723-230214.json` + vault R3 batches |
| R4 AHK/GTO structural | `validation_summary.json` task VNEXT-R4 |
| B-A0..B-A3 | `docs/VNEXT_BEHAVIORAL_PATH.md`; compose CLI `check-with-behavior` |

---

## 3. Engineering smokes (2026-07-24 post_attach) — not gates

| Case | Tag / batch | Result |
|------|-------------|--------|
| origin_macro 1× | `batch_20260724-011521_u1_post_attach_origin` | EP `0x13e0`, R0B StructuralPassBehaviorPending |
| lunlun_software 1× | `batch_20260724-011721_u1_lunlun_reg` | EP `0x1656f4`, R0B Pending |
| gto_launcher 1× | `batch_20260724-011543_u1_post_attach_gto` | family=ahk_gto conf=80 EP `0xecc000`, R0B Pending |
| xiongxiong_duokai 1× | `batch_20260724-011818_u1_holdout_reg` | EP `0x35000`, R0B Pending |
| B-A3 synthetic | `lab/behavior/evidence/batch_20260724-011835_ba3` | all_ok; check-static never Accepted |

Non-claims: not R3 10×, not R4 re-gate, not Behavioral Accepted, not pure default.

---

## 4. Residual list (blocks / non-blocks)

| ID | Item | Blocks 1.0? | Notes |
|----|------|-------------|-------|
| R-BEH | No scheduled VNEXT-BEH | **Yes** | Synthetic compose only; no vault behavioral Pass bound as product gate |
| R-HOST | Shared ThemidaState + large debug loop | Arch debt | Thin-split in progress; not independent GTO host |
| R-PURE | pure default = false | Product choice | Explicit No; residual packing size on pure |
| R-GTO | Experimental profile + CRT/cookie residual | Quality | Explicit profile required |
| R-X86 | ScyllaHide x86 hash placeholders | x86 samples | No trusted x86 helpers on host at audit time |
| R-TLS | global_vars unused in restore | Risk on complex TLS | Deferred |
| R-DALI | Managed out_of_scope | Scope | Correct non-goal |

---

## 5. Re-run matrix (auditor)

```powershell
cmd /c tools\_rebuild_cli.cmd
$env:CARGO_TARGET_DIR='D:\MidaVault\scratch\cargo-target'
cargo test -p mida-acceptance --offline
cargo test -p mida-cli --lib --offline dual_select
python tools\_behavior_ba3_smoke.py
python lab\cases\verify_manifests.py --objects-root D:\MidaVault\objects\sha256
cmd /c tools\_unattended_regression.cmd
```

Expect: tests green; Origin+GTO engineering smokes exit 0; `validation_summary.json` task remains **VNEXT-R4**.

---

## 6. Host module map (cli unpacker)

| Module | Role |
|--------|------|
| `mod.rs` | debug loop + unpack orchestration (~1.3k lines) |
| `post_attach.rs` | no-debug-port observe/freeze/dump |
| `post_loop.rs` | IAT / post-process / dump |
| `early_snapshots.rs` | zero-raw `.data` baseline |
| `plugin_host.rs` | dual_select + PackerPlugin milestones |
| `av_handler.rs` / `iat_trace.rs` / `oep_scan.rs` | loop helpers |

---

## 7. What “complete” still requires

1. Deliberate **B-B** with vault-bound behavioral evidence and `validation_summary` **VNEXT-BEH**.  
2. Product decision on pure default (still **No** unless approved).  
3. Host/plugin separation beyond thin-split (optional for research, needed for maintainable multi-family product).  
4. x86 ScyllaHide integrity when x86 helpers are in the trusted set.  
5. Explicit multi-family load/behavior criteria beyond R0B structural.

Until then, the correct public status remains: **vNext research baseline with closed structural gates R0B–R4 and open behavioral product gate.**
