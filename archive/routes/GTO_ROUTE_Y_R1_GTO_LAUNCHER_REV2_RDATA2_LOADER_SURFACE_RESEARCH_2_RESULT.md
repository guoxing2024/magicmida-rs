# RouteY_R1_GTO_LAUNCHER_REV2_RDATA2_LOADER_SURFACE_RESEARCH_2 — Result

**Status:** `..._RESEARCH_2_ReviewRequested`
**Date:** 2026-08-14T17:27:03.846Z

## Key findings

- entrypoint .rdata2 raw, entropy 7.73; **no repeatable loader-stub structure**
- .rdata2: 5747 high / 261 mid / 0 low entropy windows; 638 notable string islands (AHK v2 name island 49 strings)
- **0 pointer-like aligned qword tables**
- compression/crypto signatures: **all false positives** (random coincidence); no crypto constants
- 6 dirs in .rdata2 (export/import/exception/debug/tls/loadconfig); IAT in .rdata1; resource in .rsrc
- loader indicators: all 10 categories = structural inference only
- new field crosscheck 17/17 dual-path verified

## Route

```text
static_research_has_substantive_remaining_work = false
primary_route = C_DYNAMIC_HARNESS_TIMEOUT_CONTROL_CORRECTION
dynamic_authorized = false
```

## Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_rev2_rdata2_loader_surface_research_2_20260814T172206Z\`
