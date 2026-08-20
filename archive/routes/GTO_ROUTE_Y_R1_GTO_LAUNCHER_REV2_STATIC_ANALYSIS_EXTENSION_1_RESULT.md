# RouteY_R1_GTO_LAUNCHER_REV2_STATIC_ANALYSIS_EXTENSION_1 — Result

**Status:** `RouteY_R1_GTO_LAUNCHER_REV2_STATIC_ANALYSIS_EXTENSION_1_ReviewRequested`
**Mode:** OFFLINE / IMMUTABLE-VAULT / STATIC-ANALYSIS-ONLY / NO EXECUTION / NO LOCATOR READ / EVIDENCE-FIRST
**Date:** 2026-08-14T14:48:21.316Z

## Identity gate (pass)

target `11473d2e.../24,636,416` · manifest rev 2 · HEAD `9419ce9c`/parent `f386b49a` · authorities verified.

## Embedded PE search: NO valid inner PE

- 347 MZ byte-coincidences in .rdata2; **0 valid** (pre-filter + two independent validators agree: all false_positive_mz)
- `no_valid_inner_pe_found = true`

## Outer export table (rev-2 OWN AHK evidence)

```text
DLL name : vcomp140.dll (AutoHotkey v2 standard dependency)
exports  : 17 named — full AHK v2 C API (ahkAssign/ahkExec/ahkExecuteLine/ahkFindFunc/ahkFindLabel/
           ahkFunction/ahkGetApi/ahkGetVar/ahkLabel/ahkPause/ahkPostFunction/ahkReady + addScript + NewThread)
           + MinHookEnable/MinHookDisable
function RVAs 0xd28b0-0xe4b80 → ALL in zero-raw virtual .text (raw_backed=false)
```

The outer shell is a loader exposing an AutoHotkey v2 runtime API surface; code is materialized at runtime. Export names do NOT prove execution.

## TLS / entropy / protector

- 4 TLS callbacks; only callback[0] raw-backed; callbacks[1..3] in virtual .text (static bytes unavailable)
- .rdata2: 6008 windows, 4690 > 7.5 entropy, 0 < 3.0, overall 7.944 — uniformly high-entropy blob
- protector_family_decision = `unknown_protected_pe` (fail-closed)

## AHK route evidence (layered, fail-closed)

A direct static evidence (valid export table with full AHK v2 C API) strengthens the pending route label;
B protected/ambiguous (virtual code region); C unsupported inference (no protector/runtime claims);
D prohibited rev1 transfer. `rev1_research_transferred=false`, `dynamic_authorized=false`,
`future_plugin_ahk_gto_is_pending_route_label_only=true`.

## Boundaries

target/candidate start=0 · locator not read · no debugger/Frida/WinDbg/hook/dump/unpack · no sandbox/emulator ·
no network · no runtime binding · no rebuild · no commit/push/git add · no manifest/source change ·
no historical root modification. **No dynamic authorization granted.**

## Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_rev2_static_analysis_extension_1_20260814T144101Z\`
