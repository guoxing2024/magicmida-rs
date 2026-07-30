# GTO-PRODUCT-RECOVERY Route D P0 Proposal — 2026-07-30

## Goal (binding)
Operator still requires gto_launcher product 1.0 / perfect unpack. No half-delivery after A/B/C.

## Current Route status
- Route A: evidence-only (stable VM-owned primary-anchor candidate), not restore.
- Route B: residual-stop (no-op R1/R2).
- Route C: residual-stop (invalid R2 production stub patch rolled back as invalid); R1 test-only residual.
- Product 1.0 / gto perfect unpack still not achieved.

## Route D proposal
**Name:** product-perfect validation harness + bootstrap correctness route.

**Ledger:**
- Namespace: `GTO-PRODUCT-RECOVERY Route D`
- Cap: 2 rounds
- Used: 0
- Remaining: 2

**R1 objective**
- Define deterministic product-perfect validation harness first.
- Assert all 5 bypass patches absent.
- Assert no semantic repair/bypass env.
- Verify dumped candidate reaches product UI/script path **only by natural execution**.
- **Only then** permit bootstrap/cold-start fix.

**Allowed future surfaces**
- tools/validation harness script (under tools/)
- crates/pe/src/dumper/container_bootstrap.rs
- crates/pe/src/dumper/heap_bootstrap.rs
- crates/pe/src/dumper/tls_bootstrap.rs
- crates/pe/src/dumper/heap_global_snapshot.rs
- crates/pe/src/dumper/capture_policy.rs

**Forbidden**
- gto_host.rs
- crates/bwhook/**
- _r1b_transient_epoch_trap.py
- Route A observer/scripts
- bypass / semantic repair
- DRx / VEH / injection / R1B / E2

**Evidence bar**
- R1 must produce executable validation harness or residual-stop.
- No product 1.0 claim without actual harness evidence.
- Any code-only fix without validation harness is insufficient.

**P0 status**
- P0 consumes **0** fix rounds (docs-only).
- Implementation not started.
- No live measurement, no vault write, no push.

## Next action
Operator names `GTO-PRODUCT-RECOVERY Phase 1 on Route D` literally + new expert ruling/charter amendment allocating the 2 rounds in the Route D ledger (explicitly separate from Route C).