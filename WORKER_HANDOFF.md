# WORKER_HANDOFF - R4-C structural gate CLOSED

## Status

| Item | Status |
|------|--------|
| R3 structural gate | **CLOSED** (prior; not re-opened as 10x) |
| Holdout IAT quality | **DONE** (100% non-zero rebuild) |
| **R4-A0…A3** AHK/GTO path engineering | **DONE** |
| **R4-B** Oreans Origin+Lunlun+holdout after dual-plugin | **DONE** |
| **R4-C** scheduled structural gate + `validation_summary` VNEXT-R4 | **CLOSED** (2026-07-23) |
| Pure default | **still No** |
| Behavioral Accepted | **not claimed** |
| Default dump profile | **OreansClassic** (never auto GTO stages) |

## R4-C gate evidence

| Leg | Batch | Result |
|-----|-------|--------|
| GTO experimental | `batch_20260723-225951_r4c_gto` | `gto_launcher` family=ahk_gto conf=80 EP `0xecc000` R0B StructuralPass* |
| Oreans regression | `batch_20260723-230053_r4c_oreans_reg` | Origin `0x13e0` IAT 100%; Lunlun `0x1656f4` IAT 99%; holdout `0x35000` IAT 100%; all oreans_themida + R0B StructuralPass* |

Envelope: `D:\MidaVault\lab\evidence\_r4_gate\r4_gate_envelope.json`  
Repo summary: `validation_summary.json` task **VNEXT-R4** (prior R3 archived as `validation_summary.prev_20260723-230214.json`).

**Explicit non-claims:** not Behavioral Accepted; pure still No; GTO stages still require `--profile=ahk-gto-experimental`; not R3 10x re-gate; Dali OOS.

## Next (post-R4 structural)

Suggested order (verification-first; do not invent gates):

1. Optional: Phase2 pure flip decision / Lunlun pure smoke (still opt-in only unless scheduled)
2. Behavioral acceptance path (R0B Behavioral Accepted — separate contract)
3. 1.0 release rule review once behavioral + dual-plugin + Oreans holdout history stay green
4. Dali remains OOS / managed line — not R4

## Tools

```text
# GTO (always explicit profile):
python tools\_gto_live_smoke.py --cases gto_launcher --tag <tag> --require-r0b
# Oreans broader reg:
python tools\_oreans_repeat_smoke.py --cases origin_macro,lunlun_software,xiongxiong_duokai --count 1 --tag <tag> --require-r0b --require-holdout --expect-ep origin_macro=0x13e0,lunlun_software=0x1656f4,xiongxiong_duokai=0x35000
# R3 formal 10x (only if deliberately re-scheduled):
python tools\_r3_gate_run.py
```
