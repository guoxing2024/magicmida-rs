# VNEXT-R3 Oreans Path

Status: **R3 structural gate CLOSED** (2026-07-23). Pure flip still **No**.
Behavioral Accepted **not** claimed.

Prerequisites: R0B + R1 + R2 Slice 0–4 + PackerPlugin 3b-1..6 + R3-prep harness.
Pure flip = **No**. PE samples stay vault-only.

## What R3 is

Architecture delivery step 4: Oreans family plugin quality under independent
acceptance, measured on:

| Sample | Role |
|--------|------|
| Origin macro | Primary regression (oracle comparison only) |
| Lunlun software | Second Oreans live path (IAT quality fixed on R3-path-C) |
| **Blind holdout** | Third case, not used while developing; revealed at gate |

**Gate pass** (only when deliberately scheduled):

1. Origin + Lunlun + holdout each succeed **10 consecutive** live runs.
2. Each run: structure gate green + R0B at least
   `StructuralPassBehaviorPending` (or better).
3. Batch evidence under vault; `validation_summary` task `VNEXT-R3` closed.
4. No pure default flip required for R3 structural path.

Anything short of that is **R3-path engineering**, not R3 closed.

## Explicit non-claims

- Multi-run Origin-only or Origin+Lunlun without holdout is **not** R3.
- `--claim-r3` on engineering tools is **refused**.
- Pre-C Lunlun low IAT coverage was residual debt; **R3-path-C fixed live IAT
  rebuild to ~95%** (still not a 10× R3 claim without holdout).
- Gate still needs structure + R0B pass criteria agreed before opening 10×
  (do not paper over with false green).

## R3-path milestones (this phase)

| ID | Work | Status |
|----|------|--------|
| R3-A0 | Contract doc (this file) + handoff | **done** |
| R3-A1 | Offline replay: skip_v3 / dump after scanned OEP | **done** |
| R3-A2 | Multi-run harness: EP parse, expect-ep, R0B rollup | **done** |
| R3-A3 | Origin+Lunlun engineering batch (small N, not 10×) | **done** (`batch_20260723-201638_r3a`) |
| R3-B0 | Schema `corpus_role=holdout` + [HOLDOUT_SLOT.md](../lab/cases/v2/HOLDOUT_SLOT.md) | **done** |
| R3-B1 | `tools/_r3_corpus.py` + `_r3_gate_preflight.py` (empty slot OK) | **done** |
| R3-B2 | Case live / repeat smoke accept future holdout case_id | **done** |
| R3-B3 | Register real holdout PE in vault + manifest | **done** (`xiongxiong_duokai`) |
| R3-path-C | Lunlun IAT quality (storm freeze → post-loop v3) | **done** (11%→95%; not R3 gate) |
| R3-path-D | Origin+Lunlun ×3 stability + IAT coverage in harness | **done** (`batch_20260723-204853_r3d`) |
| R3-B4 | Holdout register helper `tools/_register_oreans_holdout.py` | **done** |
| R3-B5 | Holdout live smoke + R0B | **done** — R0B StructuralPassBehaviorPending |
| R3-B5b | No-shrink `.pdata` when Exception in zero-raw `.themida` | **done** (`dump_process` pre-sanitize force) |
| R3-C | Scheduled 10× gate + validation_summary | **done** (`batch_20260723-214718_r3c_gate`, `r3_gate=true`) |

### Holdout `xiongxiong_duokai` (2026-07-23)

| Item | Detail |
|------|--------|
| sha256 | `2848fcc0d61f…e81bc9` (Themida `.boot`/`.themida`, x64) |
| Smoke (R0B red) | `live_20260723-211212_holdout_smoke` — `exception_no_raw` |
| Smoke (R0B green) | `live_20260723-213537_holdout_pdata2` EP `0x35000`, sections=25, `.pdata` |
| Origin reg | `live_20260723-213623_origin_pdata_reg` R0B StructuralPass* |
| R0B | **StructuralPassBehaviorPending** after no-shrink `.pdata` materialization |
| Gate | Included in formal 10×; R0B StructuralPass* ×10 |

### R3-C formal gate (2026-07-23)

| Item | Detail |
|------|--------|
| Command | `python tools\_r3_gate_run.py --write-validation-summary` |
| Batch | `D:\MidaVault\lab\evidence\_repeat\batch_20260723-214718_r3c_gate` |
| Result | **30/30** OK; EP stable; R0B StructuralPassBehaviorPending all runs |
| Summary | repo `validation_summary.json` task **VNEXT-R3** (prior R1-E archived as `validation_summary.prev_*.json`) |
| Non-claims | pure default still false; Behavioral Accepted not claimed |

### Holdout IAT quality (post-gate engineering, 2026-07-23)

| Item | Detail |
|------|--------|
| Bug | v3 `trash_counter` counted zeros + already-resolved APIs; stop at slot 178 mid-table |
| Fix | `classify_iat_slot_for_trace` — only low/unknown is trash (align CLI `advance_to_next_slot`) |
| Holdout | `live_…_holdout_iat2_n1`: v3 137/0; rebuild **277/277 (100%)**; was 221/277 (79%) |
| Origin reg | rebuild **295/295 (100%)** |
| Lunlun reg | rebuild **336/338 (99%)** |
| Non-claim | Not a re-open of R3 10×; optional re-gate only if desired |

### R3-path-C notes

| Item | Detail |
|------|--------|
| Bug | Storm escape resumed at PossibleOEP → ExitProcess → skip_v3 → 41/352 |
| Fix | Freeze (no OEP Rip); `storm_escape_freeze` defers v3 to post-loop |
| Lunlun | `live_20260723-203635_lun_iat_v3defer`: 295 traced, **336/352 (95%)** rebuild |
| Origin | `live_20260723-203747_lun_iat_origin_reg`: EP 0x13e0, 295/305 (96%) |

### R3-path-D notes

| Item | Detail |
|------|--------|
| Batch | `batch_20260723-204853_r3d` — Origin+Lunlun ×3, all_ok |
| Origin | EP 0x13e0, IAT **96%** ×3, no storm freeze |
| Lunlun | EP 0x1656f4, IAT **95%** ×3, storm_freeze **3/3**, no skip_v3 |
| Harness | `iat_rebuild` / `v3_trace` / `storm_escape_freeze` in summary rollup |
| Non-claim | Still not R3 (holdout empty; N=3 not 10) |

## Still host-owned at R3-path open

ScyllaHide inject, HW BP install body, AV OEP algorithm, IAT single-step body,
dump emit. Plugin owns identify / path policy / loop flags / milestones /
thresholds. Further body moves are optional and must stay smoke-verified.

## Validate (engineering)

```text
tools\_test_plugin_3b.cmd
python tools\_r3_gate_preflight.py --require-core --require-holdout --write
python tools\_r3_gate_run.py --dry-run
python tools\_r3_gate_run.py --write-validation-summary   # formal 10x + summary
python tools\_oreans_repeat_smoke.py --cases origin_macro,lunlun_software --count 3 --tag eng --require-r0b --expect-ep origin_macro=0x13e0,lunlun_software=0x1656f4
python -B -m unittest lab.cases.test_verify_manifests -v
```

Engineering smoke: do **not** pass `--claim-r3` (refused). Formal close only via `_r3_gate_run.py`.
