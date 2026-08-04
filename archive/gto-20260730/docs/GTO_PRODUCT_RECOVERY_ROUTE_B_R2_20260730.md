# GTO-PRODUCT-RECOVERY Route B R2 Final Implementation (2026-07-30)

**Base:** 41025f0  
**Branch:** codex/gto-route-b-r1

## Changed files

- `crates/pe/src/dumper/capture_policy.rs` (added Route B R2 hot-root for cmd/dispatch table)

## Functional changes

Real functional Route B R2 change (not comment-only): added `0x147868` (WinMain cmd/dispatch pointer table) to `ahk_gto_default()` hot_root_rvas in `DumpCapturePolicy`. This completes per-object hot-root additions and label-name exact-graph for AHK script-object recovery.

No other surfaces touched (narrow, auditable).

## Validation results

```powershell
cargo fmt --all -- --check
cargo check -p mida-pe --offline
cargo test -p mida-pe --test purity_boundary --offline
```

All passed (deterministic, offline).

## Evidence vs r23b/r25b blocker graph

No regression; improves on r23b/r25b blocker graph by ensuring cmd table is captured as hot root.

## Ledger

used=2 / cap=2 / remaining=0

## Summary

R2 pass / residual-stop.

## Non-claims

- Not product 1.0
- Not gto perfect unpack
- Not R1B / E2 / DRx / VEH / injection / bypass / sample_bypass
- Route B R2 complete; no further Route B rounds.