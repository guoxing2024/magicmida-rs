# VNEXT-R4 AHK/GTO Path

Status: **R4 structural gate CLOSED** (2026-07-23, R4-C) under the
**narrow** close criteria in this file (identify plugin + experimental live
R0B + Oreans regression + no auto GTO stages + `validation_summary` VNEXT-R4).

**Architecture honesty (post-audit 2026-07-24; P1 slice 2026-07-24):** R4 is
**not** a fully independent protection-family pipeline. Progress since audit:

- Dual identify runs **before** process create / `ThemidaState`.
- Oreans V3 IAT single-step and x86 call-site fixup are **gated** by
  `SelectedPacker::uses_oreans_iat_trace()` (AHK/GTO skips them).

Still shared host debt: `ThemidaState` / `init_pe_details` / debug loop body
remain Oreans-shaped. P1 thin split (2026-07-24): post-loop B/C/D moved to
`crates/cli/src/unpacker/post_loop.rs` (behavior unchanged). Do not read
"R4 CLOSED" as "second family pipeline complete."

Default dump profile remains **OreansClassic**. Pure flip still **No**.
Behavioral Accepted **not** claimed. GTO dump stages still require explicit
`--profile=ahk-gto-experimental`.

Prerequisites: R0B + R1 + R2 Slice 0–4 + PackerPlugin 3b + **R3 structural gate closed**.

## What R4 is

Architecture delivery step 5: a **second independent protection-family plugin**,
measured separately from Oreans.

| Sample | Role |
|--------|------|
| `gto_launcher` | Primary AHK/GTO research sample (vault SHA fixed) |
| Origin / Lunlun / holdout | **Oreans regression only** — GTO failure must not fail Oreans |

**R4 structural close** (later, deliberately scheduled):

1. `AhkGtoPlugin` is a real `PackerPlugin` (identify + policy surface), not only a dump profile flag.
2. GTO live unpack with **explicit** `--profile=ahk-gto-experimental` succeeds structure + R0B ≥ `StructuralPassBehaviorPending`.
3. Oreans Origin+Lunlun(+holdout) regression still green.
4. Default profile never auto-selects GTO stages from filename/SHA alone.
5. `validation_summary` task `VNEXT-R4` written when gate is scheduled.

Anything short of that is **R4-path engineering**.

## Explicit non-claims

- Existing GTO experimental smoke (`live_…_p1exp`) is **not** R4 closed.
- DumpProfile `AhkGtoExperimental` alone is **not** a second plugin.
- Dali remains OOS / managed line — not R4.
- No pure default flip; no Behavioral Accepted.

## Family markers (identify)

GTO protected input (sha256 `4d5770af…`):

| Signal | Notes |
|--------|-------|
| Entry section `.KI3` | Primary fingerprint |
| Scrambled section names | e.g. `.,\\W`, `.|lT` |
| Section0 named `.text` | Often post-attach / text-poll path |
| `has_relocations=false` | Residual risk; not an identify-only signal |

Oreans markers (`.themida`, `.boot`, `.winlice`) must **not** Match as AHK/GTO.

## R4-path milestones

| ID | Work | Status |
|----|------|--------|
| R4-A0 | Contract doc (this file) + `mida-packers-ahk-gto` crate + identify + dual-plugin CLI select | **done** |
| R4-A1 | Host uses `SelectedPacker` for milestones / session defaults (not Themida-only) | **done** |
| R4-A2 | Case harness: `gto_launcher` live smoke + explicit profile flags | **done** |
| R4-A3 | GTO residual quality (cookie plant + PostCrt non-wrapper path) | **done** |
| R4-B | Broader Oreans Origin+Lunlun+holdout regression after dual-plugin | **done** |
| R4-C | Scheduled gate + `validation_summary` VNEXT-R4 | **done** |

## Engine route

Manifest `engine_route` for GTO:

| Value | Meaning |
|-------|---------|
| `future_plugin_ahk_gto` | Pre-plugin research label |
| `mida_plugin_ahk_gto` | Plugin crate registered (R4-A0+) |

Dump still requires CLI `--profile=ahk-gto-experimental` for heap/container stages.
Plugin identify does **not** enable those stages by itself.

## Evidence

| Item | Detail |
|------|--------|
| Case | `gto_launcher` |
| Prior smoke | `live_20260723-164707_p1exp` R0B StructuralPass* (experimental residuals) |
| R4-A0 identify | `live_20260723-223131_r4a0_id`: dual-select **ahk_gto** conf=80; oreans=NoMatch |
| R4-A1 GTO | `live_20260723-223852_r4a1_gto`: selected=**ahk_gto** conf=80; dump family=ahk_gto; R0B StructuralPass* |
| R4-A1 Origin | `batch_…_r4a1_oreans_reg`: selected=**oreans_themida** conf=83; EP `0x13e0`; IAT 295/295 |
| R4-A2 harness | `tools/_gto_live_smoke.py` → `batch_…_r4a2_gto`: family=ahk_gto conf=80 EP `0xecc000` R0B StructuralPass* |
| R4-A2 Origin | `batch_…_r4a2_oreans_reg` EP `0x13e0` R0B StructuralPass* (no GTO profile) |
| R4-A3 GTO | `batch_…_r4a3b_gto`: recovered cookie site + Planted MSVC default; PostCrt→pre-OEP INFO; R0B StructuralPass* |
| R4-A3 Origin | `batch_…_r4a3_oreans_reg` EP `0x13e0` R0B StructuralPass* |
| R4-B Oreans | `batch_20260723-225654_r4b_oreans_reg`: Origin EP `0x13e0` IAT 100%; Lunlun EP `0x1656f4` IAT 99%; holdout `xiongxiong_duokai` EP `0x35000` IAT 100%; all family=oreans_themida; R0B StructuralPass* |
| **R4-C GTO** | `batch_20260723-225951_r4c_gto`: family=ahk_gto conf=80 EP `0xecc000` R0B StructuralPass* |
| **R4-C Oreans** | `batch_20260723-230053_r4c_oreans_reg`: Origin/Lunlun/holdout EP stable + R0B StructuralPass*; IAT 100%/99%/100% |
| **R4-C summary** | repo `validation_summary.json` task **VNEXT-R4**; envelope `D:\MidaVault\lab\evidence\_r4_gate\r4_gate_envelope.json` |
| Command | `--profile=ahk-gto-experimental --data-sections --no-shrink` |

## Validate (engineering)

```text
tools\_rebuild_cli.cmd
cargo test -p mida-packers-ahk-gto --offline
# VsDevCmd env required for mida-cli link:
cargo test -p mida-cli --lib --offline selected_
cargo test -p mida-cli --lib --offline r4_select
# GTO harness (explicit profile; not R4/R3 gate):
python tools\_gto_live_smoke.py --cases gto_launcher --tag r4a3_gto --require-r0b
# Oreans broader reg (engineering R4-B; not R3 10x, not R4-C):
python tools\_oreans_repeat_smoke.py --cases origin_macro,lunlun_software,xiongxiong_duokai --count 1 --tag r4b_oreans_reg --require-r0b --require-holdout --expect-ep origin_macro=0x13e0
```

## R4-C formal gate (2026-07-23)

| Item | Detail |
|------|--------|
| GTO command | `python tools\_gto_live_smoke.py --cases gto_launcher --tag r4c_gto --require-r0b` |
| Oreans command | `python tools\_oreans_repeat_smoke.py --cases origin_macro,lunlun_software,xiongxiong_duokai --count 1 --tag r4c_oreans_reg --require-r0b --require-holdout --expect-ep …` |
| GTO batch | `D:\MidaVault\lab\evidence\_gto_smoke\batch_20260723-225951_r4c_gto` |
| Oreans batch | `D:\MidaVault\lab\evidence\_repeat\batch_20260723-230053_r4c_oreans_reg` |
| Result | GTO + Oreans all_ok; R0B StructuralPassBehaviorPending all legs |
| Summary | repo `validation_summary.json` task **VNEXT-R4** (prior R3 archived as `validation_summary.prev_20260723-230214.json`) |
| Non-claims | pure default still false; Behavioral Accepted not claimed; GTO stages still explicit profile only |

## Residual risks (carry-forward)

- Structure EP is bootstrap `.boot` when GTO heap/container restore is on (continue → app OEP)
- OEP may still be scan-fallback (`via_scan`) on some freezes; RIP capture when available
- Full RW cookie scan still ambiguous on heap-rich dumps — R4-A3 recovers via container cookie + adjacent `.data` pair when unique
- PostCrt cannot patch non-CRT EP — correctly falls through to pre-OEP bootstrap (INFO, not error)
- analysis_reference is observation only
- ASLR/reloc residual (`has_relocations=false`)
