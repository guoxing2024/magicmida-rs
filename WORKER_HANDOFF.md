# WORKER_HANDOFF — Unattended mode (U0/U1)

## Status

| Item | Status |
|------|--------|
| P0 unaligned PE + candidate semantics | **DONE** (`9d496a3`) |
| P1 dual identify + Oreans IAT family gate | **DONE** (`2ba1ab0`) |
| P1 post_loop extract | **DONE** (`cdb0adb`) |
| P1 early_snapshots extract | **DONE** (`4ac8edd`) |
| **U1 post_attach extract** | **DONE** (this handoff) |
| Shared `ThemidaState` / main debug loop body | **still** (honest debt) |
| B-A2 + B-A3 | **DONE** (`8995f46`) |
| Pure default / VNEXT-BEH | **not** opened |
| Long-horizon plan | [docs/UNATTENDED_EXECUTION_PLAN.md](docs/UNATTENDED_EXECUTION_PLAN.md) |

## What changed (U1)

1. `post_attach.rs` — no-debug-port observation / freeze / dump handoff extracted from `mod.rs`
2. `mod.rs` ~1668 → ~1420 lines (main debug loop still here)
3. `docs/UNATTENDED_EXECUTION_PLAN.md` — operator-absent program through audit package

## Validate

```text
cargo test -p mida-cli --lib --offline dual_select
cargo test -p mida-acceptance --offline
python tools\_oreans_repeat_smoke.py --cases origin_macro --count 1 --tag u1_post_attach_origin --expect-ep origin_macro=0x13e0
python tools\_gto_live_smoke.py --cases gto_launcher --tag u1_post_attach_gto --require-r0b
```

Smoke after post_attach (engineering, not R3/R4 re-gate):

| Case | Batch | Result |
|------|-------|--------|
| Origin 1× | `batch_20260724-011521_u1_post_attach_origin` | EP `0x13e0` R0B StructuralPass* |
| GTO 1× | (see progress log) | require-r0b |

## Next (unattended order)

1. Finish U1 optional micro-extracts only if ROI remains; else U2 cadence + U5 residual honesty.
2. ScyllaHide x86 hashes **only** when trusted x86 helpers exist on disk (currently placeholder).
3. Do **not** open VNEXT-BEH or pure default without deliberate schedule.
4. Stop when safe slices are exhausted → deliver audit package (plan §U5).
