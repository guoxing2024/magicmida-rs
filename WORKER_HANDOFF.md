# WORKER_HANDOFF - Behavioral B-A0 (post R4 structural)

## Status

| Item | Status |
|------|--------|
| R3 structural gate | **CLOSED** (VNEXT-R3; commit `f621451` lineage) |
| R4 structural gate | **CLOSED** (VNEXT-R4) |
| Pure default | **still No** |
| Behavioral Accepted | **not claimed** / **not enabled** |
| **B-A0** behavioral contract | **DONE** — [docs/VNEXT_BEHAVIORAL_PATH.md](docs/VNEXT_BEHAVIORAL_PATH.md) |
| **B-A1** synthetic probe harness | **next** |
| Default dump profile | **OreansClassic** (GTO stages explicit only) |

## Just committed

`feat(vnext): close R3 Oreans + R4 AHK/GTO structural gates` — dual plugin,
holdout, smoke harnesses, validation_summary VNEXT-R4 (prior R3 archived).

## B-A0 deliverable (this turn)

- Contract path: scope, non-claims, evidence schema `mida.behavior-evidence/v0`,
  verdict composition rules, milestones B-A1…B-B.
- Pointers from `ACCEPTANCE_CONTRACT.md`, `VNEXT_ARCHITECTURE.md`,
  `PROJECT_AUDIT_AND_ROADMAP.md`.
- **No** `Accepted` code path; `validation_summary` remains **VNEXT-R4**.

## Next (B-A1 only when continuing)

1. Synthetic console PE fixture (in-repo or lab synthetic; not vault malware).
2. Offline probe harness: job-bounded, network deny, wall-clock cap; emit
   evidence JSON matching the schema in VNEXT_BEHAVIORAL_PATH.
3. Positive + negative tests (exit 0 + marker; wrong exit; timeout).
4. Do **not** open B-B / write VNEXT-BEH / return `Accepted` without a scheduled gate.

## Explicit non-claims

- Structure green ≠ behavioral pass.
- B-A0 docs ≠ Accepted enabled.
- Pure flip still separate (still No).
- Dali OOS.

## Tools (structural; unchanged)

```text
python tools\_gto_live_smoke.py --cases gto_launcher --tag <tag> --require-r0b
python tools\_oreans_repeat_smoke.py --cases origin_macro,lunlun_software,xiongxiong_duokai --count 1 --tag <tag> --require-r0b --require-holdout --expect-ep origin_macro=0x13e0,lunlun_software=0x1656f4,xiongxiong_duokai=0x35000
```
