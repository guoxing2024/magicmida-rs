# RouteY_R1_GTO_LAUNCHER_REV2_STATIC_RUNTIME_SURFACE_RESEARCH_1 — Result

**Status:** `..._RESEARCH_1_ReviewRequested`
**Date:** 2026-08-14T16:45:13.205Z

## Section/directory/export/TLS surface

- 3 raw-backed sections (rdata1/rdata2/rsrc); .rdata2 EXECUTABLE 0x68000060 entropy 7.944; 6 virtual-only incl. .text
- 8 dirs raw-backed (export/import/resource/exception/debug/tls/loadconfig/iat); 8 absent
- vcomp140.dll 17 exports; 17/17 RVAs in virtual .text; 0 forwarder/invalid
- 4 TLS callbacks (1 raw, 3 virtual); entry .rdata2 raw

## Materialization

Structural indicators support runtime code materialization from .rdata2 into virtual .text; mechanism/protector undetermined. Dual validator consistent; no conflict.

## Route

```text
primary_route = B_STATIC_RUNTIME_SURFACE_RESEARCH_CONTINUE
prerequisite  = C_DYNAMIC_HARNESS_TIMEOUT_CONTROL_CORRECTION
dynamic_authorized = false
```

## Boundaries

No start · no harness · no debugger/hook/dump/decrypt · no commit/push/git add · historical roots preserved.

## Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_rev2_static_runtime_surface_research_1_20260814T164155Z\`
