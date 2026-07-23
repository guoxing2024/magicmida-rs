# WORKER_HANDOFF - P1 host thin split (post_loop extract)

## Status

| Item | Status |
|------|--------|
| P0 unaligned PE + candidate semantics | **DONE** (`9d496a3`) |
| P1 dual identify pre-process + Oreans IAT family gate | **DONE** (`2ba1ab0`) |
| **P1 post_loop extract** | **DONE** (this handoff; commit pending) |
| Shared `ThemidaState` host | **still** (honest debt) |
| B-A2 + B-A3 synthetic wire | **DONE** (`8995f46`) |
| Pure default / VNEXT-BEH | **not** opened |

## What changed (post_loop extract)

1. New `crates/cli/src/unpacker/post_loop.rs` holds `run_post_loop_phases`
   (IAT repair / post-process / dump + structure-hint lines).
2. `mod.rs` shrinks (~2.3k → ~1.9k lines); still owns identify + debug loop.
3. Family gates unchanged: `uses_oreans_iat_trace`, x86 call-site skip for GTO.
4. Candidate semantics preserved: Ok = candidate written, not R0B.

## Validate

```text
cargo test -p mida-cli --lib --offline dual_select
cargo test -p mida-cli --lib --offline selected_
python tools\_oreans_repeat_smoke.py --cases origin_macro --count 1 --tag p1_origin_reg --expect-ep origin_macro=0x13e0
python tools\_gto_live_smoke.py --cases gto_launcher --tag p1_gto_reg --require-r0b
```

Smoke after extract (engineering):

| Case | Batch | Result |
|------|-------|--------|
| Origin 1× | `batch_20260724-004651_p1_origin_reg` | EP `0x13e0` R0B StructuralPass* |
| GTO 1× | `batch_20260724-004707_p1_gto_reg` | family=ahk_gto conf=80 EP `0xecc000` |

## Honesty

Not an independent GTO host. `ThemidaState` / `init_pe_details` / AV loop remain shared.

## Next

1. Commit this extract when ready.
2. Optional: further extract AV loop helpers / early snapshots from `mod.rs`.
3. Do **not** open VNEXT-BEH or pure default without deliberate schedule.
