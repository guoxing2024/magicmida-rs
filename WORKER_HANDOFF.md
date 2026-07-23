# WORKER_HANDOFF - B-A3 synthetic wire + B-A2 compose

## Status

| Item | Status |
|------|--------|
| P0 unaligned PE + candidate semantics | **DONE** (`9d496a3`) |
| P1 dual identify pre-process + Oreans IAT family gate | **DONE** (`2ba1ab0`) |
| Shared `ThemidaState` host | **still** (honest debt) |
| **B-A2** load/bind/compose + `check-with-behavior` | **DONE** (code; may be uncommitted) |
| **B-A3** synthetic structural → probe → compose smoke | **DONE** |
| Pure default / VNEXT-BEH scheduled gate | **not** opened |
| Live smoke Origin 1× + GTO experimental 1× after P1 | **DONE** (engineering) |

## What changed (B-A3)

1. `tools/_behavior_ba3_smoke.py` — end-to-end lab wire:
   - `mida-acceptance check-static` on synthetic `marker_exit`
   - probe → `mida.behavior-evidence/v0`
   - `mida-acceptance check-with-behavior` compose
2. Cases: Pass→Accepted, Fail→Rejected, hang→Pending, identity mismatch→Rejected,
   `check-static` still never Accepted.
3. Docs: `VNEXT_BEHAVIORAL_PATH.md` B-A3 **done** (synthetic), lab README, roadmap note.

### Validate batch

`lab/behavior/evidence/batch_20260724-003808_ba3` — `all_ok: true`

## Honesty

- Synthetic only; Origin/vault malware **not** required for B-A3.
- Engineering `Accepted` via compose ≠ product pure flip ≠ VNEXT-BEH.
- Kernel still does not run probes; harness is outside `mida-acceptance`.
- Host remains shared Themida-shaped for GTO.

## Next

1. Optional: commit B-A2 + B-A3 as one or two commits.
2. Optional further P1 host split (`ThemidaState` / post-loop).
3. Do **not** schedule VNEXT-BEH without deliberate open.
4. Origin behavioral wire remains optional post-B-A3, not a gate.

## Validate

```text
cargo test -p mida-acceptance --offline
python tools\_behavior_ba3_smoke.py
# expect summary all_ok true
```
