# GTO Product-Recovery Archive (2026-07-30)

**Status:** sealed read-only history. This directory is not part of the Oreans
two-sample mainline; it exists so the GTO product-recovery governance trail
remains resolvable instead of being deleted and forgotten.

## What this is

On 2026-08-01 the repository mainline pivoted from `gto_launcher` product
recovery to the Oreans two-sample perfect-unpack goal
(`docs/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md`). The GTO product-recovery
workstream (Routes A-H) reached residual-stop with every ledger exhausted
(used=2/cap=2/remaining=0 per route). Its documents, tools, and observation
binary are archived here unchanged, except for repo-root path depth fixes in
the Python tools after the move.

The active mainline keeps `docs/GTO_RESEARCH_CHARTER_20260728.md` in `docs/`
and feature-gates the AHK/GTO route behind
`--features gto-product-recovery` (off by default; `gto_host` fails closed in
default builds).

## Contents

- `docs/` - all `GTO_PRODUCT_RECOVERY_*` governance records, route reports,
  seals, goal write-downs, and evidence JSON (37 files). Internal references
  may still point at the pre-archive `docs/` paths; treat them as historical
  text, not live links.
- `tools/` - GTO live-smoke and route-harness scripts (6 files). Vault paths
  inside them (`D:\MidaVault\...`) are historical machine references only.
- `src/` - `mida_gto_product_recovery_observer.rs`, the Route A R1/R2
  observation-only binary removed from `crates/cli` (was built as
  `mida_gto_product_recovery_observer`; the `[[bin]]` entry was removed).
- `validation/` - superseded `validation_summary.prev_*` snapshots.

## Non-claims

Nothing in this archive proves product 1.0, GTO perfect unpack, or any Oreans
result. It is evidence of what was tried and stopped, per the governance
ledgers in `WORKER_HANDOFF.md`.

## Referencing these files

After the archive move, rewrite references as:

- `docs/GTO_PRODUCT_RECOVERY_*` -> `archive/gto-20260730/docs/GTO_PRODUCT_RECOVERY_*`
- `tools/_gto_live_smoke.py`, `tools/_mtr_*`, `tools/_smoke_p1_origin_gto.cmd`
  -> `archive/gto-20260730/tools/...`
