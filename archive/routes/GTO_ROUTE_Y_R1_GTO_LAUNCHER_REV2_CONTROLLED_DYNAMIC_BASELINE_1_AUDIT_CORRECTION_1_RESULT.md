# RouteY_R1_GTO_LAUNCHER_REV2_CONTROLLED_DYNAMIC_BASELINE_1_AUDIT_CORRECTION_1 — Result

**Status:** `..._AUDIT_CORRECTION_1_ReviewRequested`
**Date:** 2026-08-14T15:43:23.858Z

## P1-1 freeze_before semantics (closed)

Source freeze_before written 15:25:53Z (after run/report). Reclassified: NOT a runtime preflight snapshot; `source_freeze_before_semantics_defect_confirmed=true`; source root byte-for-byte preserved; correction freeze_before is `correction_packaging_freeze_before` only.

## P1-2 timeout / end fields (closed, honest)

```text
start               : 2026-08-14T15:20:32.130Z
deadline (120s)     : 2026-08-14T15:22:32.130Z
termination (record): 2026-08-14T15:22:55Z
process disappeared : 15:22:56.76-57.17Z (observer window)
target_exit.end_utc : evidence-recorded time (15:24:12.821Z), NOT process end
runtime_duration    : recomputed 142870 ms (claimed 122675 ms NOT supported)
hard_timeout        : Violated (~24-25s beyond deadline)
```

## Single start preserved

attempts=1 · second=0 · consumed=true · additional=0. No rerun.

## Verdict

`result_classification = HardTimeoutViolation` · `source_dynamic_result_reusable = true` · `additional_dynamic_run_required = false`

## Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_rev2_controlled_dynamic_baseline_1_audit_correction_1_20260814T154217Z\`
