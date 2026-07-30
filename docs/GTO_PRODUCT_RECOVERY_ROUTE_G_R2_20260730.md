# GTO-PRODUCT-RECOVERY Route G R2 Report (2026-07-30)

**Branch:** `codex/gto-route-g-r1`  
**Base:** `b702571`  
**Ledger after R2:** used=2 / cap=2 / remaining=0  
**No Route G R3.**

---

## Goal

Use Route G R1 no-bypass candidate to prove or disprove **product 1.0**.

---

## Candidate

| Field | Value |
|-------|-------|
| evidence_set_id | `gto_launcher/live_20260730-224305_route_g_r1b_nobypass_gtoexp` |
| sha256 | `fde04b4321a73aedd8dec58e68a5ded1e9fbe873e389270c6c565596f23dd29f` |
| size_bytes | `71803392` |
| env | `MIDA_GTO_NO_BYPASS=1`; bypass/semantic-repair **absent** |

---

## Probes (real, no-bypass env)

Scratch evidence set: `scratch/product_recovery_route_g_r2_n1_20260730`

| Gate | Probe | Verdict | Detail |
|------|-------|---------|--------|
| natural_execution | `load_no_crash_v0` | **Pass** | survived wall then killed; quality 1/3 pass_rate=0.3333 |
| ui_script_path | `gui_window_class_v0` expect `NewClassName` | **Fail** | 3/3 `nt_exception_exit:0xc0000005`; classes_seen=[] |
| script_engine_execution | `pe_string_v0` / runtime | **Fail** | static AutoHotkey/NewClassName present; **no** runtime script-engine Pass; `g_script` string missing |

Evidence package: `docs/GTO_PRODUCT_RECOVERY_ROUTE_G_EVIDENCE_20260730.json`

---

## Harness command

```text
python tools/_mtr_gto_product_perfect_validate.py \
  --candidate <Route G candidate> \
  --clean-bytes-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json \
  --evidence-json docs/GTO_PRODUCT_RECOVERY_ROUTE_G_EVIDENCE_20260730.json
```

### Verdict

| Field | Value |
|-------|-------|
| `no_bypass_patches` | **PASS** (5/5 sealed clean-byte sites) |
| `no_semantic_repair` | **PASS** |
| `natural_execution` | **PASS** (load evidence sealed) |
| `ui_script_path` | **FAIL** |
| `script_engine_execution` | **FAIL** |
| `overall_status` | **FAIL** |
| `product_1_0` | **false** |

**Product 1.0 PASS criteria not met.**

---

## Final status

### **RESIDUAL-STOP**

| Item | Status |
|------|--------|
| No-bypass acquisition (G R1) | candidate available |
| Clean-byte gate | PASS |
| Natural load survive | weak Pass (flaky 1/3) |
| Product UI `NewClassName` | **FAIL** (AV 0xc0000005) |
| AHK script engine execution | **FAIL** (no runtime proof) |
| product_1_0 | **false** |
| Product 1.0 / perfect unpack | **NOT achieved** |

**Exact residual blocker:** no-bypass cold candidate still **AVs** on product UI path (`0xc0000005`) and does not demonstrate AHK script-engine execution; clean-byte / acquisition gates are not sufficient for product 1.0.

## Ledger

used=2 / cap=2 / remaining=0 — **no Route G R3**

## Non-claims

- Not product 1.0 / not gto perfect unpack
- load_no_crash Pass ≠ product UI/script Pass
- No bypass / semantic repair / DRx / VEH / injection / R1B / E2
- No push
