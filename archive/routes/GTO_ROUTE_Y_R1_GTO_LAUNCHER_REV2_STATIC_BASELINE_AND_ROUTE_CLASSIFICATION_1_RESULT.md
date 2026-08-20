# RouteY_R1_GTO_LAUNCHER_REV2_STATIC_BASELINE_AND_ROUTE_CLASSIFICATION_1 — Result

**Status:** `RouteY_R1_GTO_LAUNCHER_REV2_STATIC_BASELINE_AND_ROUTE_CLASSIFICATION_1_ReviewRequested`
**Mode:** OFFLINE / IMMUTABLE-VAULT / STATIC-ANALYSIS-ONLY / NO EXECUTION / EVIDENCE-FIRST
**Date:** 2026-08-14T13:33:40.960Z

## Target & authority

- authorized target `11473d2e6b00...` / 24,636,416 B (vault, manifest rev 2, commit `9419ce9c`)
- identity gate: HEAD/branch/verifier/vault re-hash all pass; verifier exit 0 (6 manifests / 8 objects, all-zero errors)

## PE baseline (two independent parsers agree)

```text
PE32+ / 0x8664 / image_base 0x140000000 / entry RVA 0x16fb532
entry section .rdata2 [0x15a3000, 0x2d1ac00) — interval-proven, both parsers
9 sections; 6 zero-raw virtual-only; 16 import descriptors; TLS 4 callbacks; no reloc; no overlay; no Authenticode
```

## Protector indicators (fail-closed)

- `.rdata2` is EXECUTABLE (`0x68000060`) with entropy 7.944 — 24.6 MB protected blob
- entrypoint high-entropy (7.42); linear decode incomplete (102/128 unknown)
- 4 TLS callbacks, 3 pointing into zero-raw virtual-only `.text`
- `.fptable` present (Themida FPU name marker — indicative ONLY, not conclusive)

**protector_family_decision = `unknown_protected_pe`** (confidence: medium; anomalies confirmed, protector not conclusively identified)

## Rev-2 OWN AutoHotkey v2 evidence

`.rdata2` @ file 0x2528d0 / RVA 0x17f14d0 contains a contiguous plaintext **AutoHotkey v2 DLL export name table**:

```text
MinHookDisable . MinHookEnable . NewThread . addScript
. ahkAssign . ahkExec . ahkExecuteLine . ahkFindFunc . ahkFindLabel
. ahkFunction . ahkGetApi . ahkGetVar . ahkLabel . ahkPause
. ahkPostFunction . ahkReady . vcomp140.dll
```

This is rev-2 **self-evidence** inside the protected blob (not a rev-1 migration). `vcomp140.dll` is the standard AutoHotkey v2 dependency. Route label `future_plugin_ahk_gto` stays pending/fail-closed — confirmation requires future authorized dynamic work.

## Rev-1 non-transfer

All rev-1 conclusions (SimpleHeap, tagged scalar, 0x2ffeeffee, heap rebase, declaration provenance, resolver, r26b bypass, UI/OEP behavior) are NOT transferred. `.KI3` absent in rev 2. dcc411af oracle inactive.

## Future dynamic plan

Designed only (1-run budget / 120 s / network deny / no children / no tasks / observer / module map / fail-closed matrix). `dynamic_authorized = false`, no script created or executed.

## Next route

```text
STATIC_ANALYSIS_EXTENSION (primary) — deep-dive .rdata2 for embedded AHK DLL PE header
PROTECTOR_CLASSIFICATION_RESEARCH (secondary)
CONTROLLED_DYNAMIC_BASELINE_AUTHORIZATION_REVIEW (after static exhausted)
```

## Boundaries

target_dynamic_start_count = 0 · candidate_dynamic_start_count = 0 · mutable_locator_read = false ·
no debugger/Frida/WinDbg/hook/dump/injection · no sandbox/emulator · no network · no rebuild ·
no commit/push/git add · no manifest/source modification · no historical root modification.

## Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_rev2_static_baseline_and_route_classification_1_20260814T132654Z\`
