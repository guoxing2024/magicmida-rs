# WORKER_HANDOFF - Behavioral B-A1 done

## Status

| Item | Status |
|------|--------|
| R3 / R4 structural | **CLOSED** (VNEXT-R3 / VNEXT-R4) |
| Pure default | **still No** |
| Behavioral Accepted | **not claimed** / **not enabled** |
| **B-A0** contract | **DONE** |
| **B-A1** synthetic probe harness | **DONE** (2026-07-23 smoke all_ok) |
| **B-A2** acceptance evidence load + compose CLI | **next** |
| Default dump profile | **OreansClassic** |

## B-A1 evidence

Smoke: `lab/behavior/evidence/batch_*_ba1/summary.json` (local; gitignored bodies)

| Case | Verdict |
|------|---------|
| `pass` | Pass |
| `fail_exit` | Fail |
| `no_marker` | Fail |
| `hang` (800ms wall) | Inconclusive |

Artifacts:

- Fixture: `lab/behavior/synthetic/marker_exit/`
- Harness: `tools/_behavior_probe.py`
- Smoke: `tools/_behavior_ba1_smoke.py`
- Schema: `lab/behavior/schema/behavior-evidence.v0.schema.json`
- Path: `docs/VNEXT_BEHAVIORAL_PATH.md`

**Explicit non-claims:** not VNEXT-BEH; not `Accepted`; not vault samples; pure still No.

## Next (B-A2)

1. In `mida-acceptance`: parse/validate `mida.behavior-evidence/v0` JSON.
2. Bind evidence.candidate sha256/size to on-disk PE (fail closed on mismatch).
3. Explicit CLI mode e.g. `check-with-behavior` (name TBD) — **default**
   `check-static` unchanged (Pending only; never Accepted without flag).
4. Unit tests: Pass+structure→Accepted **only** when mode on; mismatch→Rejected;
   missing evidence→Pending; Inconclusive never upgrades to Accepted.
5. Do **not** open B-B / write validation_summary VNEXT-BEH without schedule.

## Tools

```text
python tools\_behavior_ba1_smoke.py
python tools\_behavior_probe.py --use-fixture --mode pass --expect-verdict Pass
```
