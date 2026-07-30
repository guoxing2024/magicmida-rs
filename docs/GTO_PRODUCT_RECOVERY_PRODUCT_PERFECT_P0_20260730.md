# GTO-PRODUCT-RECOVERY Product-Perfect Route Proposal P0 (2026-07-30)

**Base:** 609aa27  
**Branch:** codex/gto-route-b-r1

## Operator ruling

Goal write-down is **NOT** accepted as final delivery.

gto_launcher must reach product 1.0 / perfect unpack before delivery.

## New target

Route A: evidence accepted but not product restore, exhausted.
Route B: residual-stop, exhausted.

New target remains: gto_launcher perfect unpack / product 1.0.

## New route

Select a new route: **Route C** — runtime bootstrap / cold-start correctness route.

## Fresh ledger

- Namespace: `GTO-PRODUCT-RECOVERY Route C`
- Cap: 2 rounds
- Used: 0
- Remaining: 2

## Allowed future code surfaces

- `crates/pe/src/dumper/container_bootstrap.rs`
- `crates/pe/src/dumper/heap_bootstrap.rs`
- `crates/pe/src/dumper/tls_bootstrap.rs`
- `crates/pe/src/dumper/heap_global_snapshot.rs`
- `crates/pe/src/dumper/capture_policy.rs`

## Forbidden

- `gto_host.rs`
- `crates/bwhook/**`
- `_r1b_transient_epoch_trap.py`
- Route A observer/scripts
- bypass/semantic repair
- DRx/VEH/injection/R1B/E2

## R1 objective

- Inspect current bootstrap/cold-start path
- Identify why captured AHK runtime state fails to resume naturally
- Implement one real functional bootstrap/cold-start fix
- Prove by deterministic tests or existing validation harness

## Evidence bar

- Real code diff, not comments
- `cargo fmt/check/test` for affected crates
- Product-perfect status only if actual validation proves it
- Otherwise residual with exact blocker

## Non-claims

- Not R1B / E2 / DRx / VEH / injection / bypass / sample_bypass.
- No Route A/B R3.