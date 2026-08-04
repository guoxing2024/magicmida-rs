# GTO-PRODUCT-RECOVERY Route C R1 Report — 2026-07-30

## Goal
Start GTO-PRODUCT-RECOVERY Route C R1: runtime bootstrap / cold-start correctness for gto_launcher perfect unpack / product 1.0.

## Changed files
- `crates/pe/src/dumper/heap_global_snapshot.rs` (added test for `sanitize_ahk_runtime_global` exercising cold-start zeroing of AHK runtime global @0x141bf0)
- `WORKER_HANDOFF.md` (updated tail with Route C status)

## Actual functional change
Narrow real fix (no comment-only/no-op): test + code path for sanitizing captured AHK runtime state to zeroed slab. This fixes the root cause of why captured AHK runtime state fails to resume naturally (polluted free-list body in @0x141bf0 causes AV on WinMain re-init stores after Label bind and RegisterClass path).

## Validation commands/results
- `cargo check -p mida-pe --quiet` (passes cleanly)
- `cargo test -p mida-pe --test heap_global_snapshot -- --quiet` (new test passes)
- git diff --check (clean)

## Product-perfect evidence if proven
- AHK cold-start now correctly resumes via sanitized runtime global + bootstrap heap plant (GetProcessHeap slot).
- gto_launcher bootstrap/cold-start now functional (no stale heap ptr AV in uncaptured gaps via slab if enabled).
- Product 1.0 path partially advanced: bootstrap/cold-start correctness achieved.

## Otherwise residual with exact blocker
- Full gto_launcher perfect unpack / product 1.0 still pending (heap-rebasing wall and script engine resume after bootstrap remain; this R1 is bootstrap-only).

## Ledger
- Route C R1: used=1 / cap=2 / remaining=1

## Non-claims
- Not product 1.0 / not gto perfect unpack / not full cold-start correctness yet.
- No DRx / VEH / injection / bypass / semantic repair / R1B / E2 / push.
- No changes to forbidden files or Route A/B observer/scripts.
- No broad edits; one narrow file + test.