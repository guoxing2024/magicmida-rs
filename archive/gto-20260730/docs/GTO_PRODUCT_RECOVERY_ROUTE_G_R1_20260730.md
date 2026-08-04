# GTO-PRODUCT-RECOVERY Route G R1 Report (2026-07-30)

**Branch:** `codex/gto-route-g-r1`  
**Base:** `485f584`  
**Ledger after R1:** used=1 / cap=2 / remaining=1

---

## Goal

Fix/diagnose no-bypass acquisition failure:

> `GTO host: target exited during observation (exit_code=0x0); IAT_resolved=true frozen_rip=None`

---

## Root cause

1. After IAT resolve, host waited ~58s for UI / long settle.
2. No-bypass targets on this host often **self-exit ~10–15s post-IAT** with exit 0 and **no UI**.
3. Prior code treated process exit as **hard FATAL** even when IAT was already resolved → **no candidate PE**.
4. Dump-after-exit then failed `ReadProcessMemory` (process already gone).

---

## Functional changes

### `crates/cli/src/unpacker/gto_host.rs`

1. **Dump-before-exit after IAT:** if process exits and `iat_resolved`, **break to dump** instead of FATAL.
2. **Freeze soft-fail:** if freeze fails after post-IAT exit, continue dump while handle open.
3. **No-bypass early dump:** when `MIDA_GTO_NO_BYPASS=1` and no UI, dump at **IAT+10s** (while alive) instead of waiting ~58s.

Default/bypass path keep long post-IAT settle (r4c quality).

### `tools/_case_live_unpack.py`

1. Record no-bypass env in `run_meta.json`.
2. **One retry** on observation/exit acquisition failure with no PE.

---

## Acquisition attempt (no-bypass)

| Field | Value |
|-------|-------|
| Env | `MIDA_GTO_NO_BYPASS=1`; bypass/semantic-repair **absent** |
| Profile | `ahk-gto-experimental` |
| evidence_set_id | `gto_launcher/live_20260730-224305_route_g_r1b_nobypass_gtoexp` |
| Result | **candidate written** (after retry) |
| Size | `71803392` |
| SHA-256 | `fde04b4321a73aedd8dec58e68a5ded1e9fbe873e389270c6c565596f23dd29f` |
| Structure EP | `0xecf000` |
| R0B | `StructuralPassBehaviorPending` |
| Log | `IAT+10047 ms without UI … no_bypass_early=true settle_ms=10000` |
| Slab | `Captured heap slab … Route F prefix pad old_base=0x1ff000` |

---

## Harness (Route E clean-bytes + evidence)

```text
python tools/_mtr_gto_product_perfect_validate.py \
  --candidate <route_g candidate> \
  --clean-bytes-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json \
  --evidence-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_EVIDENCE_20260730.json
```

| Field | Value |
|-------|-------|
| `no_bypass_patches` | **PASS** (5/5 sealed sites match) |
| natural/UI/script | **FAIL** (evidence still false / absent product proof) |
| `overall_status` | `FAIL` |
| `product_1_0` | **false** |

---

## Status

**PARTIAL PASS (acquisition)** / **not product 1.0**

- Acquisition reliability fix **works**: no-bypass candidate produced.
- Clean-byte gate **PASS**.
- Product UI / script natural execution **not claimed** (harness live gates still FAIL).
- Residual toward product 1.0: still need authorized live/UI/script evidence on a no-bypass cold start that reaches product window (separate from acquisition).

## Ledger

used=1 / cap=2 / remaining=1

## Non-claims

- Not product 1.0 / not gto perfect unpack
- No bypass / semantic repair / DRx / VEH / injection / R1B / E2
- No bwhook / Route A observer
- No push
