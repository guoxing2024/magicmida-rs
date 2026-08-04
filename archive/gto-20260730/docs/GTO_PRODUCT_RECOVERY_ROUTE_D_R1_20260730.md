# GTO-PRODUCT-RECOVERY Route D R1 Report (2026-07-30)

**Branch:** `codex/gto-route-d-r1`  
**Base:** `57b536d`  
**Class:** product-perfect validation harness (static/env only)

## R1 objective

Create a deterministic product-perfect validation harness for `gto_launcher`
that can gate future claims without inventing live/UI/script evidence.

## Harness

`tools/_mtr_gto_product_perfect_validate.py`

| Flag | Role |
|------|------|
| `--help` | usage |
| `--self-test` | offline deterministic self-tests |
| `--candidate` | optional path; computes sha256 + size |
| `--output` | optional deterministic JSON path |

### Gates

1. `no_bypass_patches` — static scan for forbidden env-name strings in candidate (or INCONCLUSIVE if no candidate)
2. `no_semantic_repair` — `MIDA_GTO_BYPASS` / `MIDA_GTO_SEMANTIC_REPAIR` must be absent from process env
3. `natural_execution` — live execution evidence required for PASS (R1: always INCONCLUSIVE)
4. `ui_script_path` — UI + script-engine evidence required for PASS (R1: always INCONCLUSIVE)
5. `product_1_0` — true only if every gate is PASS (impossible in R1 without live evidence)

### Verdict rule (hard)

Without live + UI/script evidence, overall status is **INCONCLUSIVE**.  
Harness must **not** emit overall `PASS` or `product_1_0=true` in R1.

## Changed files

- `tools/_mtr_gto_product_perfect_validate.py` (new)
- `docs/GTO_PRODUCT_RECOVERY_ROUTE_D_R1_20260730.md` (this report)
- `WORKER_HANDOFF.md` (tail update)

## Validation

```text
python tools/_mtr_gto_product_perfect_validate.py --help
python tools/_mtr_gto_product_perfect_validate.py --self-test
```

Self-test expectations:

- no forbidden env → overall INCONCLUSIVE, product_1_0 false
- forbidden env set → overall FAIL
- candidate supplied → sha256/size populated; still INCONCLUSIVE without live evidence
- JSON dumps are byte-stable across two calls

## Status

**INCONCLUSIVE** (static/env gates exercised; live execution evidence required for PASS; no product 1.0 claim)

## Ledger

`GTO-PRODUCT-RECOVERY Route D` — used=1 / cap=2 / remaining=1

## Non-claims

- Not product 1.0 / not gto perfect unpack
- No live measurement / no target execution / no vault write / no push
- No cargo
- No Route A/B/C reopening
- No R1B / E2 / DRx / VEH / injection / bypass
- No R2/R3 in this commit
