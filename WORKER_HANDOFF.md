# WORKER_HANDOFF — R-REPRO-10× CLOSED (battlefield 1 toward 1.0)

## 1.0 distance (after battlefield 1)

| Dimension | Bar | Status |
|-----------|-----|--------|
| Structure (R0B) | independent static gate | **Pass** (4/4 StructuralPassBehaviorPending) |
| Load | loader-valid | **Pass** (4/4) |
| Reproducibility | Oreans 10× consecutive isolated | **Pass** (4/4 × 10/10) ← closed this battlefield |
| Behavioral equivalence | product logic parity | **NOT MET** (R-PURE-LOGIC) |
| Multi-family production | ≥2 production-grade plugins | **NOT MET** (GTO still experimental opt-in) |
| product 1.0 | all dimensions | **Still NO** |

## Battlefield 1 — R-REPRO-10× (CLOSED, zero code change)

- Strict 10× isolated attempt=1 revealed bb_gate_pin used **stale pre-W1/W2 candidates**.
- Origin pin (pre-scrub) = 6/10; GTO r4c pin (pre-clearregs) = 4/10.
- Refreshed to current-CLI dumps: Origin fresh pure = 10/10; GTO fresh gtoexp (r26b) = 10/10.
- All 4 R0B StructuralPassBehaviorPending.
- Evidence: `D:\MidaVault\lab\evidence\_beh_gateepro10x_baseline_20260725epro10x_summary.json`
- Code changes: 0.

## Next battlefields (toward 1.0)

1. **R-PURE-LOGIC** — behavioral equivalence (the real 1.0 wall). Needs a stronger oracle than load survival. Research-level; no clean 2-round path yet.
2. **Multi-family production** — promote GTO from experimental opt-in to production default. Risks sample-specific patch surface.

Per Q2: each battlefield max 2 rounds code→rebuild→live, then residual stop.

## Freeze

product 1.0 = NO. Reproducibility dimension now honestly met. Stop unless next battlefield authorized.
