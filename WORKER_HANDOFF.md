# WORKER_HANDOFF - Audit P1 thin slice (family before host)

## Status

| Item | Status |
|------|--------|
| P0 unaligned PE + candidate semantics + cargo_test hygiene | **DONE** (`9d496a3`) |
| **P1 dual identify pre-process** | **DONE** |
| **P1 Oreans IAT gated by family** | **DONE** |
| Shared `ThemidaState` host | **still** (honest debt) |
| Pure default / Accepted / B-A2 | unchanged |
| Giant `unpacker/mod.rs` | still large; not fully split |

## What changed (P1)

1. `dual_select_packer` in `plugin_host` runs **before** `init_pe_details` / process create.
2. `run_post_loop_phases` takes `uses_oreans_iat_trace` + `family_id`:
   - Oreans: existing V3 / skip_v3 / post-attach rules
   - AHK/GTO: skip Oreans V3 trace + skip Oreans API call-site fixup
3. Tests: dual_select GTO vs Oreans, select preference, `uses_oreans_iat_trace`.

## Honesty

This is a **thin** host improvement, not independent GTO pipeline. Layout probe
is still `ThemidaPeInfo` for both families.

## Next

1. Optional live smoke: Origin 1× + GTO experimental 1× after rebuild
2. Further P1: extract more of post-loop / loop from `mod.rs`
3. Or B-A2: acceptance evidence composition
4. fmt/clippy debt still open

## Validate

```text
cargo test -p mida-cli --lib --offline dual_select
cargo test -p mida-cli --lib --offline selected_
cargo test -p mida-cli --lib --offline select_
```
