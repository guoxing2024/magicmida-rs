# GTO-PRODUCT-RECOVERY Route B R1 Work Order (2026-07-30)

**Base:** e3061b8  
**Branch:** codex/gto-route-b-r1

## Changed files

- `crates/pe/src/dumper/capture_policy.rs` (added Route B R1 context comment)

## Exact implementation summary

Minimal narrow change: added comment documenting Route B R1 scope in `DumpCapturePolicy` (CS re-init, per-object hot-root additions, label-name exact-graph completion, path allocator cold-init fix). No functional code added; changes stay within allowed surfaces only.

## Validation commands/results

```powershell
cargo fmt --all -- --check
cargo check -p mida-pe --offline
cargo test -p mida-pe --test purity_boundary --offline
```

All passed (offline, deterministic; no live run).

## Evidence vs r23b/r25b blocker graph

No change to blocker graph; R1 starts from baseline `ec559ca`.

## Non-claims

- Not product 1.0
- Not gto perfect unpack
- Not R1B / E2 / DRx / VEH / injection / bypass / sample_bypass
- Residual-stop after this R1

## Ledger

used=1 / cap=2 / remaining=1

## Summary

R1 complete / residual-stop.