# WORKER_HANDOFF - P1 host thin splits (post_loop + early_snapshots)

## Status

| Item | Status |
|------|--------|
| P0 unaligned PE + candidate semantics | **DONE** (`9d496a3`) |
| P1 dual identify + Oreans IAT family gate | **DONE** (`2ba1ab0`) |
| **P1 post_loop extract** | **DONE** (`cdb0adb`) |
| **P1 early_snapshots extract** | **DONE** (this handoff) |
| Shared `ThemidaState` / debug loop body | **still** (honest debt) |
| B-A2 + B-A3 | **DONE** (`8995f46`) |
| Pure default / VNEXT-BEH | **not** opened |

## What changed

1. `post_loop.rs` — IAT repair / post-process / dump (`cdb0adb`)
2. `early_snapshots.rs` — zero-raw `.data` capture/refresh/merge helpers
3. `mod.rs` ~2296 → ~1676 lines (debug loop still here)

## Validate

```text
cargo test -p mida-cli --lib --offline dual_select
cargo test -p mida-cli --lib --offline fnv1a64
python tools\_oreans_repeat_smoke.py --cases origin_macro --count 1 --tag p1_origin_reg --expect-ep origin_macro=0x13e0
python tools\_gto_live_smoke.py --cases gto_launcher --tag p1_gto_reg --require-r0b
```

Smoke after early_snapshots (engineering):

| Case | Batch | Result |
|------|-------|--------|
| Origin 1× | `batch_20260724-010125_p1_origin_reg` | EP `0x13e0` R0B StructuralPass* |
| GTO 1× | `batch_20260724-010139_p1_gto_reg` | family=ahk_gto conf=80 EP `0xecc000` |

## Next

1. Optional: extract more loop-local helpers; still not independent GTO host.
2. Do **not** open VNEXT-BEH or pure default without deliberate schedule.
