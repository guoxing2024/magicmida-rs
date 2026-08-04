# GTO-PRODUCT-RECOVERY Route E R1 Report (2026-07-30)

**Branch:** `codex/gto-route-e-r1`  
**Base:** `249a96c`  
**Ledger after R1:** used=1 / cap=2 / remaining=1

---

## Objective

Seal clean/original bytes for five r26b bypass patch sites and integrate the
manifest into the product-perfect validation harness via `--clean-bytes-json`.

---

## Sources and limits

| Source | Used? | Note |
|--------|-------|------|
| Authorized protected PE offline extract | **No** | Not available in this offline R1 scope |
| Historical r26b peel notes (WORKER_HANDOFF) | Yes (site list only) | RVAs + descriptions; **no** clean opcode bytes |
| Invented hex | **Forbidden** | Explicit non-goal |
| Synthetic self-test seals | Yes (tests only) | Not production seals |

**Limit:** Without an authorized clean dump / oracle PE, production clean bytes
cannot be sealed honestly. R1 records an **unsealed** production manifest and
wires harness integration for when seals exist.

---

## Clean-byte site table (production manifest)

Manifest: `docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json`

| RVA | site_id | Description | Sealed | expected_clean_hex |
|-----|---------|-------------|--------|--------------------|
| `0x5c5d` | `r26b_0x5c5d` | MessageBoxW skip | **no** | null |
| `0x63f4` | `r26b_0x63f4` | LoadFile skip | **no** | null |
| `0x34f66` | `r26b_0x34f66` | CreateWindowEx forced NewClassName | **no** | null |
| `0x34f59` | `r26b_0x34f59` | WS_VISIBLE forced | **no** | null |
| `0x6757` | `r26b_0x6757` | msg-loop AV skip | **no** | null |

Unsealed reason (all five): no authorized offline source for clean/original
bytes; inventing hex is forbidden.

---

## Harness changes

`tools/_mtr_gto_product_perfect_validate.py`:

- New flag: `--clean-bytes-json <path>`
- Loads sealed/unsealed site entries; applies to `no_bypass_patches`
- Behavior:
  - sealed + match → site **PASS**
  - sealed + mismatch → site **FAIL**
  - unsealed / no manifest → site **INCONCLUSIVE**
  - all five PASS required for `no_bypass_patches` PASS
- Self-test covers synthetic sealed match/mismatch, unsealed, no-manifest
- `product_1_0` still requires live/UI/script evidence; R1 production run remains INCONCLUSIVE

---

## Validation

```text
python tools/_mtr_gto_product_perfect_validate.py --help
python tools/_mtr_gto_product_perfect_validate.py --self-test
python tools/_mtr_gto_product_perfect_validate.py --clean-bytes-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json
```

Expected production posture with unsealed manifest (no candidate): overall
**INCONCLUSIVE**, `product_1_0=false`, bypass gate INCONCLUSIVE.

---

## Status

**INCONCLUSIVE / residual toward product 1.0**

- Integration complete
- Production clean bytes **not** sealed (honest)
- Live/UI/script evidence still required for product_1_0 (Route E R2)

## Ledger

used=1 / cap=2 / remaining=1

## Non-claims

- Not product 1.0 / not gto perfect unpack
- Not no_bypass_patches PASS on production candidates
- No live execution / cargo / vault write / push
- No inventing clean bytes
- No Route A/B/C/D R3; no R1B/E2/DRx/VEH/injection/bypass
