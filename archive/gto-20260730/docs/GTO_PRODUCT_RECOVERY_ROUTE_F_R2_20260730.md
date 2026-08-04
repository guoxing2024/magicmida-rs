# GTO-PRODUCT-RECOVERY Route F R2 Report (2026-07-30)

**Branch:** `codex/gto-route-f-r1`  
**Base:** `18d1a13`  
**Ledger after R2:** used=2 / cap=2 / remaining=0  
**No Route F R3.**

---

## Goal

Validate whether Route F R1 heap-slab prefix fix makes `gto_launcher` **no-bypass**
candidate reach product UI + AHK script engine naturally.

---

## Environment

| Key | Value |
|-----|-------|
| `MIDA_GTO_NO_BYPASS` | `1` |
| `MIDA_GTO_BYPASS` | **absent** |
| `MIDA_GTO_SEMANTIC_REPAIR` | **absent** |
| CLI | vault `scratch/cargo-target/debug/mida-cli.exe` built from `18d1a13` + R1 slab prefix |
| Profile | `ahk-gto-experimental` |
| Capture | `ahk_gto_defaults` (case path) / hot_roots=8 |
| Protected input | sha256 `4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8` size `8583680` |

---

## Commands

```text
# MSVC env + build
. .\tools\_enter_msvc_env.ps1
$env:CARGO_TARGET_DIR = "<vault>/scratch/cargo-target"
cargo build -p mida-cli

# No-bypass live unpack (attempts)
$env:MIDA_GTO_NO_BYPASS = "1"
# MIDA_GTO_BYPASS / MIDA_GTO_SEMANTIC_REPAIR unset
python tools/_case_live_unpack.py gto_launcher --profile=ahk-gto-experimental --tag route_f_r2_nobypass
# also direct mida-cli /unpack attempts under scratch product_recovery_route_f_r2_*

# Offline validation
cargo check -p mida-pe
python tools/_mtr_gto_product_perfect_validate.py --self-test
python tools/_mtr_gto_product_perfect_validate.py \
  --clean-bytes-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json \
  --evidence-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_EVIDENCE_20260730.json
```

---

## Vault / scratch output roots (logical)

| evidence_set_id | Role |
|-----------------|------|
| `scratch/product_recovery_route_f_r2_n1_20260730-215341` | direct mida-cli attempt (failed dump) |
| `scratch/product_recovery_route_f_r2_n1_20260730-220000` | direct mida-cli attempt (failed dump) |
| `scratch/product_recovery_route_f_r2_n1_20260730-215551` | archive of case_live_unpack attempt |
| `gto_launcher/live_20260730-215551_route_f_r2_nobypass_gtoexp` | case_live_unpack live dir (failed dump) |

**No successful `gto_unpacked.exe` produced this round.**

---

## Live remeasure result

| Attempt | Result |
|---------|--------|
| 1–3 no-bypass dumps | **FATAL**: `GTO host: target exited during observation (exit_code=0x0); IAT_resolved=true frozen_rip=None` |
| Dump complete | **No** |
| Heap slab prefix exercised on live dump | **Not measured** (dump never reached heap capture/plant) |
| Candidate sha256/size | **N/A** (no candidate) |
| Product UI / script engine | **Not observed** on cold candidate (no candidate) |

---

## Harness JSON verdict

With Route E clean-byte + evidence manifests (no new F R2 candidate):

| Field | Value |
|-------|-------|
| `overall_status` | `FAIL` |
| `product_1_0` | `false` |
| clean-byte sites sealed | 5/5 (Route E) |
| natural_execution | FAIL (explicit false) |
| ui_script_path | FAIL |
| script_engine_execution | FAIL |

**Product 1.0 PASS criteria not met.**

---

## Final status

### **RESIDUAL-STOP**

| Item | Status |
|------|--------|
| Route F R1 slab prefix | code landed + unit-proven |
| Route F R2 live no-bypass remeasure | **failed before dump** (host observation exit) |
| product_1_0 | **false** |
| Product 1.0 / perfect unpack | **NOT achieved** |

**Exact residual blocker:** no-bypass live dump could not complete under Route F R2 environment — target exits during GTO host observation after IAT resolve with `frozen_rip=None`, so the heap-slab prefix fix was **not remeasured** on a fresh no-bypass candidate; product UI/script gates remain unproven. (Host flakiness / observation-path; `gto_host.rs` is out of Route F allowed surfaces.)

## Ledger

used=2 / cap=2 / remaining=0 — **no Route F R3**

## Non-claims

- Not product 1.0 / not gto perfect unpack
- Does not claim heap-rebasing wall is closed on live no-bypass
- No bypass / semantic repair / DRx / VEH / injection / R1B / E2
- No gto_host code change
- No push
