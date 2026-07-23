# Oreans holdout slot (R3-path-B)

This is a **contract slot**, not a sample. No PE bytes live in Git.

## Purpose

R3 gate requires a third Oreans case that was **not** used to drive day-to-day
fixes on Origin/Lunlun. That case is registered here when (and only when) a
vault object exists and a real manifest is filled in.

## Registration checklist (operator)

**Preferred (one shot):**

1. Drop the protected PE under `D:\MidaVault\scratch\holdout_drop\` (or any path).
2. Dry-run then apply:
   ```text
   python tools\_register_oreans_holdout.py --pe D:\MidaVault\scratch\holdout_drop\YOUR.exe --case-id your_holdout_id
   python tools\_register_oreans_holdout.py --pe D:\MidaVault\scratch\holdout_drop\YOUR.exe --case-id your_holdout_id --apply
   ```
   The tool: hashes PE → vault CAS → materialize → writes `lab/cases/v2/{id}.json`
   with `corpus_role=holdout` → preflight. Refuses forbidden ids and known corpus hashes.
3. Smoke (still not R3):
   ```text
   python tools\_case_live_unpack.py your_holdout_id --tag holdout_smoke
   python tools\_oreans_repeat_smoke.py --require-holdout --cases origin_macro,lunlun_software,your_holdout_id --count 1 --tag holdout_prep
   ```
4. Only after smoke green may a **scheduled** 10× batch include that `case_id`.
   Still do **not** claim R3 until continuous 10× + `validation_summary` close.

**Manual equivalent:**

1. Place the protected PE in the vault object store (SHA-256 CAS).
2. Materialize under `D:\MidaVault\scratch\materialized\` as
   `{case_id}__protected_input__{sha256[:12]}.bin`
3. Add `lab/cases/v2/{case_id}.json` with:
   - `capability_cell.protection_family`: `oreans_candidate`
   - `capability_cell.engine_route`: `mida_plugin_oreans`
   - `capability_cell.corpus_role`: **`holdout`**
   - `static_fingerprint` filled from a retained static report (no success claims)
   - `execution_policy.dynamic.mode`: `explicit_authorization_required`
4. Run:
   ```text
   python -B lab\cases\verify_manifests.py --objects-root D:\MidaVault\objects\sha256
   python tools\_r3_gate_preflight.py
   ```

## Explicit forbidden substitutions

| Not holdout | Why |
|-------------|-----|
| `origin_macro` | Regression primary; used during development |
| `lunlun_software` | Development second path; known degraded IAT |
| `gto_launcher` | Wrong family (`ahk_gto_candidate`) — R4, not R3 |
| `dali_plugin` | Out of scope managed path |
| `plain_pe32` | Negative control, not Oreans |

## Current status

**Slot empty.** Preflight must report `holdout_status=empty` until a real
holdout manifest is added. Engineering Origin+Lunlun batches remain non-R3.
