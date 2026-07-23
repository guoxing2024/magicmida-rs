# Behavioral lab (post-R4)

Engineering surface for VNEXT behavioral acceptance path.

| Path | Role |
|------|------|
| `synthetic/marker_exit/` | Tiny console PE fixture (pass / fail_exit / no_marker / hang) |
| `schema/behavior-evidence.v0.schema.json` | Evidence document shape |
| `evidence/` | Probe outputs (local; may be gitignored partially) |
| `../tools/_behavior_probe.py` | Offline probe harness |
| `../tools/_behavior_ba1_smoke.py` | B-A1 positive/negative probe smoke |
| `../tools/_behavior_ba3_smoke.py` | B-A3 wire: check-static → probe → check-with-behavior |

**Not** vault malware. **Not** VNEXT-BEH gate. **Not** pure default flip.

`check-with-behavior` may emit engineering `Accepted` when structure passes and
evidence binds with `Pass`. `check-static` never does.

See [docs/VNEXT_BEHAVIORAL_PATH.md](../../docs/VNEXT_BEHAVIORAL_PATH.md).
