# Route Y R1 A6 — Production Driver No-Spawn AF3 Observer/Orchestrator Correction 4 — Evidence Packaging Correction 1 Result

**Work order:** `RouteY_R1_A6_PRODUCTION_DRIVER_NO_SPAWN_AF3_OBSERVER_ORCHESTRATOR_CORRECTION_4_EVIDENCE_PACKAGING_CORRECTION_1`

**Execution class:** `EVIDENCE REPACKAGING ONLY`

**Target state:** `RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ObserverOrchestratorCorrection4EvidencePackagingCorrection1ReviewRequested`

**Result:** Evidence Packaging Correction 1 complete. The Correction 4 implementation and 26-scenario harness passed independent audit; the sole defect was the final evidence-package closure (`unlisted=1`). This work order repackaged the frozen Correction 4 deliverables into a **brand-new evidence root** under an exact exclusion policy (Option B), with byte-for-byte source comparison. **No harness rerun, no orchestrator execution, no production driver.**

---

## 1. Audit disposition

| Item | Disposition |
|---|---|
| Correction 4 implementation | PASS |
| 26-scenario synthetic harness | PASS |
| Evidence package final closure | **FAIL** |
| Dynamic qualification authorization | DENIED |
| Production driver start allowance | 0 |

**The single finding:** the Correction 4 manifest froze 296 payloads, then `evidence_freeze_selfcheck.json` was written afterwards. The selfcheck file was **not** a manifest payload, and **no exact exclusion policy** listed it — so the final directory had `unlisted = 1` (`evidence_freeze_selfcheck.json`, SHA `ef20010fc185b20a95afcd288b23776d1e3fb7d62c5af9a8e033dc2a0185ec3c`, size 323), while the selfcheck itself declared `unlisted = 0`. Directory state and selfcheck declaration conflicted. Implementation layer passed, but evidence packaging closure failed.

Correction 4's orchestrator, validator, observer, runner and harness were **not modified and not re-run** by this work order.

---

## 2. Manifest policy (Option B — exact exclusion list)

The work order offered two strategies. This repack chose **Option B**: the detached metadata files are written **after** the manifest, and the manifest declares an **exact** exclusion list (no wildcards, no blanket "all selfcheck files" rule):

```json
"excluded_metadata_exact_list": [
  "evidence_freeze.json",
  "evidence_freeze.json.sha256",
  "evidence_freeze_selfcheck.json"
]
```

The independent self-check recomputes the directory scan and applies **exactly this list** — no file outside it may be unlisted.

---

## 3. New evidence root

```
D:\MidaVault\lab\analysis\
route_y_r1_a6_production_driver_no_spawn_af3_observer_orchestrator_correction_4_evidence_packaging_correction_1_20260813T211300Z\
```

Contents:

| Artifact | Role |
|---|---|
| `repack_freeze_before.json` | Boundary snapshot recorded before any copy (head, branch, tracked/untracked, Q0-C, supervisor, driver, task/process residuals) |
| `source_correction4_root.json` | Provenance: source root path, source manifest SHA, source selfcheck, known defect, byte-for-byte source comparison, frozen script identities, repack operations |
| `repack_freeze_after.json` | Boundary snapshot recorded after the new report, new `final_status.json`, all copies and verifications |
| `final_status.json` | EPC1 status: `...EvidencePackagingCorrection1ReviewRequested`, attempt unconsumed |
| `source_evidence_freeze.json` | Original Correction 4 manifest (byte-identical, renamed to free the new slot) |
| `source_evidence_freeze.json.sha256` | Original sidecar (byte-identical) |
| `source_evidence_freeze_selfcheck.json` | Original (defective) selfcheck, preserved as-is (byte-identical) |
| `source_freeze_before.json` / `source_freeze_after.json` / `source_final_status.json` | Original C4 freeze/status artifacts (byte-identical, renamed) |
| `orchestrator/`, `validator/`, `observer/`, `runner/`, `harness/` | Frozen Correction 4 archives + `harness/scenarios/<26 dirs>` + `harness/corr4_harness_result.json` + `harness/expected_identities.json` + `harness/corr4_malformed_runner.ps1` + `harness/cleanup_leftovers.ps1` (byte-identical) |
| `evidence_freeze.json` | **New** manifest for the EPC1 root (Option B policy) |
| `evidence_freeze.json.sha256` | Detached SHA-256 of the new manifest |
| `evidence_freeze_selfcheck.json` | **New** selfcheck, written last, covered by the exact exclusion list |

The original Correction 4 root was **not modified or overwritten**; the six colliding meta artifacts were copied byte-for-byte into the new root under `source_*` names so the new `evidence_freeze.json` / `freeze_after.json` / `final_status.json` slots hold EPC1 artifacts.

---

## 4. Source provenance and byte-for-byte comparison

**Source Correction 4 manifest:** `8014c5d320e2ded615e0b43be9f88c97d8f844fc84dbf04865ee63318a980eea` (size 61311, payload_file_count 296). Sidecar matches.

**All 299 source files copied** and verified byte-for-byte (SHA-256 + size) against the source: `checked = 299, missing = 0, mismatch = 0`.

**296 source manifest payloads** re-verified against the new root copies (3 meta payloads preserved under `source_*` names, bytes identical):

```
payload_checked             = 296
source_payload_missing      = 0
source_payload_hash_changed = 0
source_payload_size_changed = 0
```

**Source directory unlisted scan (independent re-computation):** exactly 3 non-payload files — `evidence_freeze_selfcheck.json`, `evidence_freeze.json`, `evidence_freeze.json.sha256` — confirming the C4 defect was limited to the selfcheck missing an exact exclusion.

Frozen script identities (unchanged, re-hashed in the new root):

| Role | SHA-256 | Size |
|---|---|---|
| orchestrator v4 | `6cfba5ca48f7cf4d7dd77302726b8a1ed8516ee9157ec84393488d46b07c78d6` | 25897 |
| validator v4 | `d2b4e926dc7aeba474d0ad5d83dd32cb80167fc1957b0fbd8cdf2f57bc38c673` | 10644 |
| observer | `11910085b61f6eddcb0026a7853af58c05ccb93e0dd81f5c8bda5af143daced2` | 10438 |
| runner | `f5e9405652a5cf638b5f21bce2144fe671ce3033c4ea07a30283e38494ad83c5` | 4642 |
| harness | `7d9eebcc2c5659136e161f27b5eb168b8519785b828be8a3c8cb0ca73c787adf` | 44961 |

---

## 5. New manifest

```
manifest_policy               = excluded_metadata_exact_list
excluded_metadata_exact_list  = [evidence_freeze.json, evidence_freeze.json.sha256, evidence_freeze_selfcheck.json]
payload_file_count            = 303
manifest SHA-256              = 301089e314346f07cd673b7395d4e1e8b170dcb5b15edc3b665c55d45789d1c6
manifest size                 = 62687
```

Payload count = 303 = 299 copied source files + 4 new EPC1 artifacts (`source_correction4_root.json`, `final_status.json`, `repack_freeze_before.json`, `repack_freeze_after.json`). The six original C4 meta artifacts are preserved under `source_*` names and remain payloads. Only the three files in `excluded_metadata_exact_list` are outside the payload set.

## 6. Self-check

```
manifest_sha256_actual          = 301089e314346f07cd673b7395d4e1e8b170dcb5b15edc3b665c55d45789d1c6
manifest_sha256_sidecar         = 301089e314346f07cd673b7395d4e1e8b170dcb5b15edc3b665c55d45789d1c6
manifest_sidecar_match          = true
payload_declared_count          = 303
payload_listed_count            = 303
actual_payload_count            = 303
missing_count                   = 0
hash_mismatch_count             = 0
size_mismatch_count             = 0
unlisted_count                  = 0
excluded_metadata_exact_list    = [evidence_freeze.json, evidence_freeze.json.sha256, evidence_freeze_selfcheck.json]
self_check_pass                 = true
verified_utc                    = 2026-08-13T21:24:52Z
```

The selfcheck verifies against the **exact** exclusion list recorded in the manifest — no wildcard, no blanket selfcheck exclusion.

---

## 7. Freeze before / after

`repack_freeze_before.json` (boundary snapshot taken `2026-08-13T21:17:38Z` before any copy; file finalized `2026-08-13T21:24:51Z` after correcting a null source-manifest-SHA field) and `repack_freeze_after.json` (recorded after the new report, new `final_status.json`, all copies and verifications):

| Boundary item | Before | After |
|---|---|---|
| HEAD | `f386b49af8f547a16f3d107dc6e80c02ea6e4403` | unchanged |
| Branch | `oreans/two-sample-mainline` | unchanged |
| Tracked modified | 3 (Q0-C files, pre-existing) | unchanged |
| Untracked source | 0 | unchanged |
| Untracked docs | 47 | 47 → 48 (this report added) |
| `git diff --check` | clean (CRLF warnings only) | clean |
| Matching scheduled tasks | 0 | 0 |
| Matching residual processes | 0 | 0 |
| Q0-C three files | unchanged (SHA/size frozen) | unchanged |
| Supervisor | `8863898f…` / 10820 | unchanged |
| AF3 driver | `4ea9d6e4…` / 39246 | unchanged |

---

## 8. Discipline and boundary

- **Production AF3 driver NOT run** — EPC1 executed no script, no orchestrator, no observer/runner/synthetic driver, no scheduled task. Frozen driver identity unchanged: SHA `4ea9d6e4246a6b02004655910418827317984322f54d679cf64fd43d98a2559c`, size 39246, version `route_y1_a6_live_driver/v3-no-spawn-af3`.
- **Harness NOT re-run** — the 26-scenario matrix remains the frozen C4 result (`pass=26, fail=0`), copied byte-for-byte.
- `single_dynamic_attempt_consumed = false`.
- No commit / push / `git add`. No old evidence root modified or overwritten (C4 root intact; AF2/AF3/Correction 1/2/3 roots untouched).
- Q0-C, supervisor, AF3 driver, and the five Correction 4 archives unchanged.

---

## 9. Status

**`RouteY_R1_A6_ProductionDriverNoSpawnMode_AF3_ObserverOrchestratorCorrection4EvidencePackagingCorrection1ReviewRequested`**

Stopped for independent audit. Current authorization state: `Correction4ImplementationAudit = PASS`, `Correction4HarnessAudit = PASS`, `Correction4EvidencePackageAudit = FAIL (pending this repack)`, `EvidencePackagingCorrection1Authorized = true`, `AF3_DynamicQualificationAuthorized = false`, `ProductionDriverStartAllowance = 0`. Upon this evidence-package audit passing, a **new-numbered, new-evidence-root, at-most-one-start** dynamic qualification authorization is required before the single production QualificationNoSpawn run.