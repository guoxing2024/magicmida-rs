# GTO-PRODUCT-RECOVERY Route D R2 Report (2026-07-30)

**Branch:** `codex/gto-route-d-r1`  
**Base:** `0dd5607`  
**Class:** final Route D round — validation harness hardening  
**Ledger after R2:** used=2 / cap=2 / remaining=0  
**No Route D R3.**

---

## R1 audit

| Item | R1 fact |
|------|---------|
| Commit | `0dd5607` harness baseline |
| Status | **INCONCLUSIVE** (accepted as baseline, not product 1.0) |
| Defect | `no_bypass_patches` only scanned forbidden env *name strings* in the candidate image |
| Gap | Did **not** verify the five historical r26b bypass patch sites |
| Consequence | Env-string absence was incorrectly usable as a soft “no bypass” signal |

R2 supersedes that gate design.

---

## Hardened gates (R2)

### 1. r26b bypass site model

| RVA | Id | Description |
|-----|-----|-------------|
| `0x5c5d` | `r26b_0x5c5d` | MessageBoxW skip |
| `0x63f4` | `r26b_0x63f4` | LoadFile skip |
| `0x34f66` | `r26b_0x34f66` | CreateWindowEx forced NewClassName |
| `0x34f59` | `r26b_0x34f59` | WS_VISIBLE forced |
| `0x6757` | `r26b_0x6757` | msg-loop AV skip |

Rules:

- Candidate required for site checks; missing candidate → **INCONCLUSIVE**
- Candidate too small for a site → site **FAIL** (fail-closed)
- If sealed clean/original bytes are **unknown** (current default) → site **INCONCLUSIVE**, **never PASS**
- Env-string scan retained only as residual note; `env_string_scan_proves_patch_absence=false`

### 2. External evidence (`--evidence-json`)

Required blobs (each must be explicit `true`/`present=true` plus non-empty `source`, `hash`, `timestamp`):

- `natural_execution_evidence`
- `ui_script_path_evidence`
- `script_engine_execution_evidence`

Absent → **INCONCLUSIVE**. Missing fields → **FAIL**. Incomplete → not PASS.

### 3. `product_1_0`

True **only if all** of:

- all five bypass sites **PASS**
- `no_semantic_repair` **PASS**
- `natural_execution` **PASS**
- `ui_script_path` **PASS**
- `script_engine_execution` **PASS**

Otherwise overall is **FAIL** or **INCONCLUSIVE**. Harness does not invent live/UI/script evidence.

---

## Changed files

- `tools/_mtr_gto_product_perfect_validate.py` (R2 harden)
- `docs/GTO_PRODUCT_RECOVERY_ROUTE_D_R2_20260730.md` (this report)
- `WORKER_HANDOFF.md` (tail)

---

## Validation

```text
python tools/_mtr_gto_product_perfect_validate.py --help
python tools/_mtr_gto_product_perfect_validate.py --self-test
```

Self-test covers: no candidate → INCONCLUSIVE; forbidden env → FAIL; tiny candidate → not PASS; evidence absent → INCONCLUSIVE; fake evidence missing fields → not PASS; JSON deterministic.

**Result:** self-test OK. Overall harness posture without sealed clean bytes + real evidence remains **INCONCLUSIVE** (residual). **Not product 1.0.**

---

## Final ledger

`GTO-PRODUCT-RECOVERY Route D` — **used=2 / cap=2 / remaining=0**

No Route D R3.

---

## Non-claims

- Not product 1.0 / not gto perfect unpack
- No cargo / live execution / vault write / push
- No Route A/B/C reopen
- No R1B / E2 / DRx / VEH / injection / bypass
- Clean original bytes for r26b sites are **not** sealed by this round
