# Behavioral lab (post-R4)

Engineering surface for VNEXT behavioral acceptance path.

| Path | Role |
|------|------|
| `synthetic/marker_exit/` | Tiny console PE fixture (pass / fail_exit / no_marker / hang) |
| `schema/behavior-evidence.v0.schema.json` | Evidence document shape |
| `evidence/` | Probe outputs (local; may be gitignored partially) |
| `../tools/_behavior_probe.py` | Offline probe harness |
| `../tools/_behavior_ba1_smoke.py` | B-A1 positive/negative smoke |

**Not** vault malware. **Not** VNEXT-BEH gate. **Not** `Accepted`.

See [docs/VNEXT_BEHAVIORAL_PATH.md](../../docs/VNEXT_BEHAVIORAL_PATH.md).
