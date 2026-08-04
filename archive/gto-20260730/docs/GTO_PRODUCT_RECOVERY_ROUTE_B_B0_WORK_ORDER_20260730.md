# GTO-PRODUCT-RECOVERY Route B B0 Work Order (2026-07-30)

**Base:** ec559ca  
**Branch:** codex/gto-route-a-candidate-metadata

## Goal

Docs/governance-only work order for GTO-PRODUCT-RECOVERY Route B R1 (AHK runtime / script-object recovery).

## Scope

- Docs/governance only.
- No code.
- No cargo.
- No live measurement.
- No target execution.
- No vault write.
- No push.
- Do not start R1.
- Do not touch Route A / R1B / E2 / DRx / VEH / injection / bypass.

## Fresh ledger

- Namespace: `GTO-PRODUCT-RECOVERY Route B`
- Cap: 2 rounds
- Used: 0
- Remaining: 2

## Allowed future implementation surfaces (charter)

- `crates/pe/src/dumper/heap_global_snapshot.rs`
- `crates/pe/src/dumper/capture_policy.rs`
- `crates/pe/src/dumper/container_bootstrap.rs`

**Explicitly forbidden (no implementation or reference in this work order):**
- `crates/cli/src/unpacker/gto_host.rs`
- `crates/bwhook/**`
- `_r1b_transient_epoch_trap.py`
- Route A observer
- DRx / VEH / injection / bypass

## R1 objective

- CS re-init at known CS RVAs
- per-object hot-root addition to DumpCapturePolicy
- label-name exact-graph completion
- path allocator cold-init fix

## R1 evidence bar

- build/check passes
- deterministic output artifact/manifest generated
- compare against prior r23b/r25b blocker graph
- no bypass / semantic repair
- report written before any final pass

## B0 consumption

B0 consumes **0** fix rounds. Implementation has **not started**.