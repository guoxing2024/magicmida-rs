# WORKER_HANDOFF — Unattended freeze (audit-ready)

## Status

| Item | Status |
|------|--------|
| P0 / P1 dual_select / post_loop / early_snapshots | **DONE** |
| U1 post_attach | **DONE** (`e99cda6`) |
| U1 loop_state | **DONE** (`f66e157`) |
| Shared `ThemidaState` / main debug loop body | **residual** (honest) |
| B-A0..B-A3 synthetic | **DONE** |
| Pure default / VNEXT-BEH | **not** opened |
| Unattended plan | [docs/UNATTENDED_EXECUTION_PLAN.md](docs/UNATTENDED_EXECUTION_PLAN.md) |
| **Audit package (accept here)** | [docs/AUDIT_PACKAGE_20260724.md](docs/AUDIT_PACKAGE_20260724.md) |

## HEAD

`f66e157` on `baseline/legacy-recovery-20260722`

## Engineering smokes (not gates)

| Case | Batch | OK |
|------|-------|----|
| Origin | `…012108_u1_loop_state_origin` | EP 0x13e0 R0B Pending IAT 295/295 |
| Lunlun | `…011721_u1_lunlun_reg` | EP 0x1656f4 R0B Pending |
| Holdout | `…011818_u1_holdout_reg` | EP 0x35000 R0B Pending |
| GTO | `…012147_u1_loop_state_gto` | EP 0xecc000 ahk_gto R0B Pending |
| B-A3 | `batch_20260724-011835_ba3` | all_ok; check-static never Accepted |

## Freeze reason

No further **safe** unattended slice closes perfect-unpack without deliberately
opening B-B (VNEXT-BEH) or pure default. Human decisions listed in audit package §8.

## Re-run

```text
cmd /c tools\_unattended_regression.cmd
cargo test -p mida-acceptance --offline
python tools\_behavior_ba3_smoke.py
```
