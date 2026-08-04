# GTO-PRODUCT-RECOVERY Route E P0 Proposal (2026-07-30)

**Base:** `9686221`  
**Branch:** `codex/gto-route-d-r1`  
**Class:** governance proposal only (docs)  
**P0 rounds consumed:** **0** (does not start implementation)

---

## Operator context

Product 1.0 / perfect unpack for `gto_launcher` remains required.

Route D harness is **accepted** as the product-perfect gate surface but remains
**INCONCLUSIVE**. Two explicit blockers remain:

1. **Clean/original bytes** for the five r26b bypass patch sites are **not sealed**.
2. **Live / UI / script** evidence is **absent**.

---

## Prior routes (exhausted)

| Route | Ledger | Outcome |
|-------|--------|---------|
| A | used=2/cap=2/remaining=0 | Evidence accepted; not product restore; no R3 |
| B | used=2/cap=2/remaining=0 | Residual-stop (no-op rounds); no R3 |
| C | used=2/cap=2/remaining=0 | Residual-stop; no R3 |
| D | used=2/cap=2/remaining=0 | Harness accepted, INCONCLUSIVE residual; **no R3** |

Do **not** reopen Route A/B/C/D R3.

---

## New route: Route E

**Name:** clean-byte sealing + live-evidence acquisition route  
**Purpose:** close the two Route D blockers so the existing harness can
deterministically decide `product_1_0`.

### Fresh ledger

- Namespace: `GTO-PRODUCT-RECOVERY Route E`
- Cap: **2**
- Used: **0**
- Remaining: **2**
- Separate from A/B/C/D (no inheritance)

### R1 objective (if separately authorized)

- Seal clean/original bytes for the five r26b patch sites:
  - `0x5c5d` MessageBoxW skip
  - `0x63f4` LoadFile skip
  - `0x34f66` CreateWindowEx forced NewClassName
  - `0x34f59` WS_VISIBLE forced
  - `0x6757` msg-loop AV skip
- Produce a **deterministic clean-byte manifest** (repo- or vault-referenced by SHA-256).
- Either feed the manifest into `tools/_mtr_gto_product_perfect_validate.py`, or
  define the exact R2 integration contract (flag/path/schema) without claiming PASS.

### R2 objective (if separately authorized)

- Acquire or ingest **authorized** live / UI / script evidence
  (`natural_execution_evidence`, `ui_script_path_evidence`,
  `script_engine_execution_evidence` with explicit true + source/hash/timestamp).
- Run the Route D harness against candidate + sealed clean bytes + evidence JSON
  to determine `product_1_0`.

### Evidence bar

- No sealed clean bytes ⇒ **no PASS**
- No live/UI/script evidence ⇒ **no PASS**
- Product 1.0 **only if** harness overall status is PASS and `product_1_0` is true

### Forbidden (Route E)

- bypass / semantic repair
- DRx / VEH / injection
- R1B / E2
- Route A observer/scripts
- `crates/cli/src/unpacker/gto_host.rs`
- `crates/bwhook/**`
- inventing clean bytes or live evidence
- vault rewrite without separate authorization
- push unless separately ordered

---

## Authorization bar

P0 is **proposal only**. It:

- consumes **0** fix rounds
- does **not** start R1 implementation
- does **not** allocate work until operator names Route E Phase 1 literally
  and a separate expert ruling records the ledger allocation

Bare "continue" / "proceed" does **not** open Route E R1.

---

## Non-claims

- Not product 1.0 / not gto perfect unpack
- Not Route D PASS
- Not clean-byte seal complete
- Not live evidence acquired
- No code / cargo / live / vault write / push in this P0 filing
