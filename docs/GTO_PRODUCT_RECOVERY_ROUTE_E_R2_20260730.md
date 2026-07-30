# GTO-PRODUCT-RECOVERY Route E R2 Report (2026-07-30)

**Branch:** `codex/gto-route-e-r1`  
**Base:** `7981e31`  
**Ledger after R2:** used=2 / cap=2 / remaining=0  
**No Route E R3.**

> **Hygiene note:** absolute host vault paths scrubbed from committed manifests;
> identity is `evidence_set_id` + `artifact_role` + `sha256` + `size_bytes`.

---

## Goal

Close Route D/E harness gates with real vault evidence (read-only):

1. Seal clean/original bytes for five r26b sites from authorized existing artifacts
2. Ingest live/UI/script evidence if authorized/available
3. Run harness → PASS only if `product_1_0=true`; else **RESIDUAL-STOP**

---

## Clean-byte sealing (DONE)

**Source (authorized, existing vault, READ-ONLY):**

| Field | Value |
|-------|-------|
| evidence_set_id | `gto_launcher/r27_nobypass_round0_20260725` |
| artifact_role | `r27_nobypass_unpacked_candidate` |
| artifact_name | `gto_unpacked.exe` |
| SHA-256 | `88a726e30397782834a77eaffd23304f9886db717854a79f23bff3fd77d70422` |
| size_bytes | 16052736 |
| Addressing | PE `.text` has `rawptr==va` for these RVAs → file offset == RVA |
| provenance | existing vault lab evidence; MIDA_GTO_NO_BYPASS path; read-only |

**Contrast (bypass path, not used as clean):**  
`evidence_set_id=gto_launcher/live_r26b_final_newclass` role `r26b_bypassed_unpacked_candidate` sha256 `4d722619…af28` — all five sites **DIFF**.

| RVA | Description | Clean hex (r27) | r26b hex | DIFF |
|-----|-------------|-----------------|----------|------|
| `0x5c5d` | MessageBoxW skip | `ff1555810f00488d` | `b80100000090488d` | yes |
| `0x63f4` | LoadFile skip | `e8e700030083f8ff` | `b80100000083f8ff` | yes |
| `0x34f66` | CreateWindowEx forced NewClassName | `488b158bcc10004c` | `488d153dc2ed004c` | yes |
| `0x34f59` | WS_VISIBLE forced | `41b90000cf004c8b` | `41b90000cf014c8b` | yes |
| `0x6757` | msg-loop AV skip | `e8c4ed020085c075` | `b80100000085c075` | yes |

Manifest: `docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json` (all five **sealed**).

Harness check with r27 candidate supplied: all five sites **PASS** (`no_bypass_patches=PASS`).

---

## Live / UI / script evidence (NOT PASS)

| Gate | Claim | Reason |
|------|-------|--------|
| natural_execution | **false / FAIL** | r27 AVs on cold start (heap rebasing); AV log under evidence_set `r27_nobypass_round0_20260725` |
| ui_script_path | **false / FAIL** | `NewClassName` UI Pass only on **r26b bypassed** candidates; not no-bypass product path |
| script_engine_execution | **false / FAIL** | no authorized no-bypass script-engine Pass artifact |

Evidence package: `docs/GTO_PRODUCT_RECOVERY_ROUTE_E_EVIDENCE_20260730.json`

---

## Harness run

```text
python tools/_mtr_gto_product_perfect_validate.py --self-test
python tools/_mtr_gto_product_perfect_validate.py \
  --clean-bytes-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json \
  --evidence-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_EVIDENCE_20260730.json
```

With explicit `true:false` evidence blobs, live gates are **FAIL** → overall **FAIL**, `product_1_0=false`.

With r27 candidate + sealed clean bytes: bypass sites PASS, but live/UI/script still FAIL → still not product 1.0.

---

## Final status

### **RESIDUAL-STOP**

| Item | Status |
|------|--------|
| Clean bytes sealed | **Yes** (5/5 from r27 no-bypass) |
| no_bypass_patches (vs r27) | **PASS** when candidate supplied |
| natural_execution | **FAIL** (r27 AV) |
| ui_script_path | **FAIL** (only bypass-path UI evidence) |
| script_engine_execution | **FAIL** (absent no-bypass) |
| product_1_0 | **false** |
| product 1.0 / perfect unpack | **NOT achieved** |

**Exact residual blocker:** no-bypass candidate still does not naturally resume to product UI + script engine (r27 cold-start AV / heap-rebasing wall). Clean-byte seal closes the bypass-site gate only.

## Ledger

used=2 / cap=2 / remaining=0 — **no Route E R3**

## Non-claims

- Not product 1.0 / not gto perfect unpack
- r26b UI Pass is not product-perfect evidence
- No vault write / push / live re-run this round
- No R1B/E2/DRx/VEH/injection/bypass
- No absolute vault paths in committed Route E manifests
