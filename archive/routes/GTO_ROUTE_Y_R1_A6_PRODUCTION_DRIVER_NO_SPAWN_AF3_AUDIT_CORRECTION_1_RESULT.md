# Route Y R1 A6 — Production Driver No-Spawn AF3 Audit Correction 1

**Work order:** `RouteY_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF3_AUDIT_CORRECTION_1`

**Title:** Harness Driver-Identity Binding, Raw Harness Evidence Preservation, Detached Manifest Repair, and Final Boundary Re-Freeze.

**Nature:** Evidence + harness binding correction (NOT a driver fix). The AF3 driver is unchanged.

**Target state (returned to audit):** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_StaticHarnessReviewRequested`

---

## 1. Driver unchanged

The AF3 driver was NOT modified. Its identity is re-confirmed and bound:

| Item | Value |
|------|-------|
| path | `D:\MidaVault\scratch\route_y1_a6_live_driver_v3_no_spawn_af3.ps1` |
| SHA256 | `4ea9d6e4246a6b02004655910418827317984322f54d679cf64fd43d98a2559c` |
| size | 39246 |
| version | `route_y1_a6_live_driver/v3-no-spawn-af3` |

## 2. Corrected defects

### [P1] Manifest self-reference — FIXED (detached manifest design)
The new manifest `evidence_freeze.json` **excludes itself** from its `files` array (payload only),
with an explicit `manifest_policy = manifest_file_excluded_from_hashed_payload_set`. A detached
checksum `evidence_freeze.json.sha256` is emitted OUTSIDE the manifest payload for external
verification. Self-verification re-walk confirms `missing=0, hash_mismatch=0, size_mismatch=0, unlisted=0`.

### [P1] Harness not bound to AF3 driver — FIXED (identity binding)
The harness now begins by verifying `$DriverPath` exists, computing SHA-256, size, and parsing
version; any mismatch exits non-zero (60). The result carries an explicit `driver_binding` block:
```json
"driver_binding": {
  "path": "...",
  "sha256": "4ea9d6e4...",
  "size": 39246,
  "version": "route_y1_a6_live_driver/v3-no-spawn-af3",
  "identity_match": true
}
```
The harness still uses synthetic runners/observers (infrastructure unit tests) and labels them
accurately. It does NOT claim the production AF3 driver was executed.

### [P1] freeze_after not final — FIXED (re-freeze after all deliverables)
`freeze_after.json` was re-collected AFTER harness result, final status, and this report were
written. It records the actual `untracked_docs_count` (see Section 5).

### [P2] Harness raw outputs not preserved — FIXED
All raw harness outputs are preserved under `harness/` (lock, observer_synthetic.json, synthetic
drivers, exit0/exit7 dirs with stdout/stderr, observer_driver_started.json) and are all listed in
the manifest.

## 3. Harness result (re-run, identity-bound)

`harness_gates_result.json`:
- `driver_binding.identity_match = true`
- `lock_primitive_pass = true` (non-empty, metadata round-trip, duplicate CreateNew collision rejected)
- `runner_exit_capture_pass = true` (synthetic exit 0 → 0, exit 7 → 7)
- `observer_exact_attribution_pass = true` (driver count=1, driver PID == runner driver_started_pid, runner PID != driver, controller/mida/artifact/epoch all false)
- `production_af3_execution = "NOT RUN"`

## 4. Static gates (unchanged from AF3, re-confirmed)

`check_count=21, passed=21, failed=0` (recorded in the original AF3 dir; not modified here).

## 5. Boundary (freeze before == after)

- HEAD `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (unchanged)
- branch `oreans/two-sample-mainline` (unchanged)
- Q0-C 3 files unchanged (heap_global `5a60ded9…`/402997, raw_slab `bf6da4d3…`/780270, snapshot_manifest `91c3a392…`/57963)
- supervisor `8863898f…`/10820 (unchanged)
- tracked modified = 3, untracked source = 0, git diff --check clean
- no commit / push / git add
- original AF3 dir and AF2 dir preserved read-only; not in any correction output path

## 6. Dynamic qualification

**NOT RUN.** `single_dynamic_attempt_consumed = false`. Awaiting explicit
`RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_DynamicQualificationAuthorized` from audit.

---

**Evidence root:** `D:\MidaVault\lab\analysis\route_y_r1_a6_production_driver_no_spawn_af3_audit_correction_1_20260813T044729Z\`
