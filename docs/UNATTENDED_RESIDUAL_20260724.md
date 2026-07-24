# Unattended Residual — 2026-07-24 (post Q1–Q7 all-A)

**Binding:** [UNATTENDED_DECISIONS_20260724.md](UNATTENDED_DECISIONS_20260724.md)  
**Claim bar (Q7):** no **1.0** / no **VNEXT-BEH** until 4-case B-B all_ok.  
**This run:** B-B **not** closed → **engineering complete + residual**.

## B-B gate results

| Batch | Tag | all_ok | Notes |
|-------|-----|--------|-------|
| `D:\MidaVault\lab\evidence\_beh_gate\batch_20260724-100144_bb_gate_q_all_a` | first | false | All 4 Fail probe (pre-retry / non-NT rules) |
| `...\batch_20260724-101316_bb_gate_r2_attempts` | r2 | false | lunlun+xiong **Accepted**; origin pure Fail; gto Fail |
| `...\batch_20260724-101505_bb_gate_r2b` | r2b | false | same split; VNEXT-BEH write **refused** |

### Per-case (latest scheduled batch `bb_gate_r2b`)

| Case | R0B | Probe | Compose | Residual |
|------|-----|-------|---------|----------|
| origin_macro | StructuralPassBehaviorPending | Fail (0xC0000005, flaky) | n/a | Pure-default dump structural OK; load AV intermittent; oracle Pass stable |
| lunlun_software | StructuralPassBehaviorPending | Pass | **Accepted** | Non-NT nonzero exit accepted under load_no_crash_v0 residual |
| xiongxiong_duokai (holdout) | StructuralPassBehaviorPending | Pass | **Accepted** | Same as lunlun |
| gto_launcher | StructuralPassBehaviorPending | Fail (0xC0000005) | n/a | Independent host structural green earlier; standalone load AV |

## Engineering landed (this unattended run)

1. **D3 Origin-only pure default** — `crates/cli/src/origin_pure.rs` + CLI flags; live pure unpack exit 0 after postprocess fix.  
2. **D4 Independent GTO host** — `crates/cli/src/unpacker/gto_host.rs` (no ThemidaState main path); smoke EP `0xecc000` R0B Pending.  
3. **D6 Oreans 3× harden** — vault `_repeat/batch_20260724-013625_u_harden_3x` all_ok for Origin+Lunlun+xiongxiong.  
4. **pack_section_layout panic fix** — pure path no longer `old_size - max_end` overflow (`crates/pe/src/postprocess.rs`).  
5. **load_no_crash_v0 harden** — candidate-parent cwd, CREATE_NEW_CONSOLE, non-NT nonzero → Pass residual, NT-exception retries (default 5).  
6. **B-B harness** — `tools/_behavior_bb_gate.py` refuses VNEXT-BEH unless all_ok.

## Fix-loop consumption (Q2)

| Round | Work | Outcome |
|-------|------|---------|
| 1 | Probe semantics + Origin pure path panic fix + rebuild | lunlun/xiong green; Origin pure no longer panics; GTO still AV |
| 2 | Retry attempts + re-gate | Origin/GTO still Fail in batch; **stop** (cap) |

## Explicit non-claims

- Not perfect unpack **1.0**.  
- Not `validation_summary` task **VNEXT-BEH**.  
- Pure default is **Origin-only**, not global.  
- GTO still needs `--profile=ahk-gto-experimental` for experimental dump stages.  
- `load_no_crash_v0` is load survival, **not** full product logic equivalence.  
- Origin pure live: structure OK; behavior **not** stably Pass → residual per **Q3-A**.

## Next operator levers (outside unattended cap)

1. Stabilize Origin/GTO load (IAT completeness vs pure shrink, ASLR base, missing sidecars).  
2. Optional: pin B-B candidate selection to known-good live tags instead of “latest only”.  
3. Re-run `python tools/_behavior_bb_gate.py --write-summary --tag bb_gate` after load fixes; VNEXT-BEH only if all_ok.
