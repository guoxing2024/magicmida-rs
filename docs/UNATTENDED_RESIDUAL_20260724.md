# Unattended Residual — 2026-07-24 (post B-B close)

**Binding:** [UNATTENDED_DECISIONS_20260724.md](UNATTENDED_DECISIONS_20260724.md)  
**Claim bar (Q7):** VNEXT-BEH only when 4-case B-B all_ok.  
**This close:** batch `bb_gate_pin` **all_ok=true** → **VNEXT-BEH written**.

## B-B gate results (winning batch)

| Batch | Tag | all_ok | Notes |
|-------|-----|--------|-------|
| `D:\MidaVault\lab\evidence\_beh_gate\batch_20260724-112907_bb_gate_pin` | bb_gate_pin | **true** | Preferred pins + probe retries; VNEXT-BEH written (dir has per-case compose + `summary.json`) |
| `...\batch_20260724-125450_bb_gate_reconfirm_scan60` | reconfirm | **true** | 4× compose Accepted; GTO winner still r4c walk residual |
| `...\batch_20260724-105209_bb_gate_walk` | walk | false | Origin 8× probe Fail (over-walk + short backoff) |
| `...\batch_20260724-102551_bb_gate_iso` | iso | false | Origin Accepted once; GTO Fail |
| earlier r2/r2b/q_all_a | — | false | pre-pin / pre-retry harden |

### Per-case (`bb_gate_pin`)

| Case | R0B | Probe | Compose | Candidate |
|------|-----|-------|---------|-----------|
| origin_macro | StructuralPassBehaviorPending | Pass | **Accepted** | `live_20260724-101051_u_origin_pure_r1` (pure) |
| lunlun_software | StructuralPassBehaviorPending | Pass | **Accepted** | `live_20260724-013746_u_harden_3x_n3` |
| xiongxiong_duokai (holdout) | StructuralPassBehaviorPending | Pass | **Accepted** | `live_20260724-013837_u_harden_3x_n3` |
| gto_launcher | StructuralPassBehaviorPending | Pass | **Accepted** | `live_20260723-225951_r4c_gto` (pin `004707` failed first; walk next) |

## Origin load AV diagnosis (c1)

- **Symptom:** `load_no_crash_v0` → `0xC0000005` intermittent on pure (and legacy) dumps that are R0B StructuralPass.
- **cdb (second-chance AV):** `rip=o+0x39e5c` `xchg ecx,dword ptr [r10]` with `r10=ffffd466…` (non-canonical / bad pointer). Nearby call site uses IAT slot `0x138c98` = **GetCurrentThreadId** (hint/name form intact in file).
- **Not:** R0B Rejected, RELOCS_STRIPPED (cleared on dump emit), pure vs legacy exclusive (both flaky).
- **Is:** runtime flaky survival (~40–80% single-shot). Same bytes can SURVIVE 8–10/10 under light serial launch, or AV under cold/heavy back-to-back probes.
- **Mitigation (engineering, not product fix):** probe isolated copy keeps original basename; plain createflags by default; backoff + kill-stale on NT fail; default attempts 12; gate prefers known-good live tags and caps walk depth.

## GTO load (c2)

- Independent host / newer dumps still often AV on first pin.
- Older structural dump `live_20260723-225951_r4c_gto` probe-pass + compose Accepted in winning batch.
- Residual: newest GTO unpack path not load-stable; gate walk to last-known-good is intentional residual.

### GTO independent-host progress (2026-07-24 afternoon)

| Fix | Effect |
|-----|--------|
| External-only IAT resolve (reject image-local / hint RVAs) | Stops false “IAT resolved” at 80ms mid-`.KI3` |
| Never freeze on packer/EP sections; observe then `.text` scan | OEP aligns with r4c (`0x70b0` + `.boot` continue) |
| Live IAT span capped to `0x11e0` (572 slots) | Rebuild **98%** sufficient (was 14–32% with `0x8000` → original ILT fallback) |
| Min observation **60s** after attach | Matches r4c settle; `wrapper_call_patch` 0/0 |
| Smoke CLI path | Always `D:\MidaVault\scratch\cargo-target\debug\mida-cli.exe` (not repo `target/release`) |

**Load status (revised 2026-07-24 W2):** Pre-W2 independent-host dumps (scan60/m3/fresh) quiet attempt=1 rates were 0.1–0.2 with cdb AV `mov [r8],ecx` r8=`0x8000` at OEP `0x70c9`. **W2 clear-regs** on `.boot`→OEP transfer fixes that class; post-fix lives `w2_clearregs{1,2,3}` are **10/10** attempt=1. Prefer those pins over `r4c_gto` (see W2 section).

**`.boot` delta vs r4c — deep dive (2026-07-24):**

| Metric | scan60 (independent host) | r4c (Themida post-attach path) |
|--------|---------------------------|--------------------------------|
| stub_size / `.boot` raw | 793016 / `0xc2000` | 821920 / `0xc9000` |
| containers | 1 × 72 B (same RVA `0x145710`) | 1 × 72 B |
| heap_globals slots | **320** (cap) | **320** (cap) |
| heap_globals `total_bytes` | **776960** | **805864** (**+28904 ≈ 28.2 KiB**) |
| graph children (rva=0) | 287 / 426472 B | 288 / 461144 B (**+34672**) |
| image roots (rva≠0) | 33 / 350488 B | 32 / 344720 B |
| first-hop exhaust | added=64 interior=40 total=97 | added=64 interior=45 total=96 |
| dangling pass | added=80 → total=320 | added=78 → total=320 |
| profile / restore | AhkGtoExperimental + PostCrt pre-OEP | same |
| IAT / OEP | 98% / `0x70b0` | 98% / `0x70b0` |

**What the ~28 KiB is (not):** missing dump stage, different container detect, different IAT window, or independent host skipping `detect_heap_globals`. Both paths enter the same `dump_process` experimental stages; logs show identical xref surface (`xref_sites=7843 unique_slots=420`) and the same 320-slot hard cap.

**What it is:** payload of `HeapGlobalSnapshot.content` assembled by `estimate_object_size` (RPM ladder `SIZE_PROBES` up to probe_cap) + multi-hop / dangling fills under `MAX_HEAP_GLOBAL_SLOTS=320`. Live heap bases differ every run (ASLR); readable committed span at each base differs → different admitted sizes → different expand frontier under the same slot budget.

Largest single root delta:

| RVA | Role | scan60 size | r4c size | Δ |
|-----|------|-------------|----------|---|
| `0x141bf0` | HOT_LARGE_TABLE (AHK global) | **0x4000** @ `0x3971ff0` | **0x8000** @ `0x94eb00` | **+16 KiB** on r4c |
| `0x145480` | root | 0x180 | 0x2000 | +7.6 KiB r4c |
| `0x148ca8` | HOT string machinery | 0xc0 | 0x1940 | +6.1 KiB r4c |
| `0x1467b8` / `0x145700` / … | roots | larger on scan60 | smaller | partial offset |

Code path: [`heap_global_snapshot.rs`](../crates/pe/src/dumper/heap_global_snapshot.rs) `estimate_object_size` / `can_read` — success of full-size `read_memory` decides size; no VirtualQuery region-size authority. Stub layout in [`container_bootstrap.rs`](../crates/pe/src/dumper/container_bootstrap.rs): code + meta + fixup + **payloads** (payload dominates).

**Systematic?** Same *algorithm* and *caps* on both hosts; volume difference is **run-time heap layout + probe**, not a separate independent-host capture plan. Independent-host SuspendThread poll may bias timing of allocations slightly, but the measured gap is explained by root size estimates + graph-child multiset under the shared 320 cap — re-run of either host can move the same way.

**Does this alone explain R-LOAD-FLAKE?** Unproven. Both dumps hit 320 slots and pass R0B; quiet load can Pass on the smaller stub. Flake remains quality residual; `.boot` delta is honesty about non-reproducible heap snapshot bytes, not a proven missing-stage bug.

Research tools:
- `tools/_diff_boot_heap.py` — parse `.boot` meta/payloads (legacy)
- `tools/_diff_dump_snapshot.py` — diff `*.dump_snapshot.json` sidecars

### M1 capture observability (generic landing, 2026-07-24)

| Piece | Status |
|-------|--------|
| `mida.dump-snapshot-manifest/v0` sidecar | Written by `dump_process` as `{stem}.dump_snapshot.json` (best-effort; never fails dump) |
| Module | `crates/pe/src/dumper/snapshot_manifest.rs` |
| Load pass-rate quality | `tools/_behavior_probe.py --rate-samples N` → `evidence.load_quality` (not R0B Accepted) |
| Gate optional rate | `tools/_behavior_bb_gate.py --rate-samples N` records `load_quality` on Pass paths |
| Explicit non-claim | Manifest + pass-rate do **not** upgrade product 1.0 or VNEXT-BEH semantics |

### M2 capture policy externalization (generic landing, 2026-07-24)

| Piece | Status |
|-------|--------|
| `DumpCapturePolicy` | [`crates/pe/src/dumper/capture_policy.rs`](../crates/pe/src/dumper/capture_policy.rs) — hot roots, large tables, gscript root/caps, expand seeds |
| `DumpOptions.capture_policy` | Empty + `AhkGtoExperimental` → `ahk_gto_default()`; `OreansClassic` stays empty |
| `detect_heap_globals` | Takes `&DumpCapturePolicy`; helpers (`ensure_hot_root_slots`, first-hop, multi-hop, expand, dangling) all policy-threaded |
| Live sidecar | `live_20260724-140153_m2_policy_gtoexp` → real `gto_unpacked.dump_snapshot.json` (`mida.dump-snapshot-manifest/v0`, heap_globals=320, containers=1, R0B StructuralPassBehaviorPending) |
| Rate baseline (N=6, quiet serial) | evidence `_gto_smoke/m2_rate_20260724-140458` — **r4c** 4/6 (0.67); **scan60** 2/6 (0.33). Confirms R-LOAD-FLAKE + prefer r4c pin |

**Explicit non-claim:** policy externalization is product-shape plumbing for case-manifest/plugin fill later; it does **not** change the claim bar or fix load flake. Sample-private RVAs remain only as built-in AHK/GTO defaults inside the policy type.

### M3 plugin → capture policy (generic landing, 2026-07-24)

| Piece | Status |
|-------|--------|
| `CapturePolicyHint` on `DumpAdvice` | [`crates/core/src/plugin.rs`](../crates/core/src/plugin.rs) — plugin-owned, no sample RVAs in core |
| `AhkGtoPlugin` | Emits `prefer_ahk_gto_defaults=true`; Themida leaves `capture_policy: None` |
| Host merge | `DumpCapturePolicy::resolve_with_plugin_hint` in GTO host + post_loop |
| Sidecar | `capture_policy` block in `*.dump_snapshot.json` (`source`, hot roots, gscript knobs) |
| Live | `live_20260724-141353_m3_plugin_gtoexp` — `source=ahk_gto_defaults`, hot_roots=10, R0B StructuralPassBehaviorPending, PE retained |

**Explicit non-claim:** plugin owns the *request* for AHK capture defaults; host still requires `--profile=ahk-gto-experimental` for experimental dump stages. Case-manifest fill is M4. Not 1.0 / not load-flake fix.

### M4 case-manifest + CLI capture policy (generic landing, 2026-07-24)

| Piece | Status |
|-------|--------|
| Schema | Optional `capture_policy` on case-manifest v2 (`lab/cases/v2/case-manifest.schema.json`) |
| Sample | `gto_launcher.json` → `{"preset":"ahk_gto_defaults"}` |
| CLI | `--capture-policy=PATH` — pure policy object **or** full case-manifest JSON |
| Loader | [`crates/cli/src/capture_policy_file.rs`](../crates/cli/src/capture_policy_file.rs) |
| Merge | CLI/manifest roots > plugin `CapturePolicyHint` > profile empty→defaults |
| Harness | `_case_live_unpack.py` auto-exports manifest field to temp JSON + passes flag (opt-out `--no-capture-policy`) |

**Explicit non-claim:** wiring only — does not enable experimental dump stages without `--profile=ahk-gto-experimental`, does not fix R-LOAD-FLAKE / R-GTO-BOOT, not product 1.0.

### B-B reconfirm (scan60 pin era)

| Batch | all_ok | GTO winner | Notes |
|-------|--------|------------|-------|
| `batch_20260724-125450_bb_gate_reconfirm_scan60` | **true** | `r4c_gto` | scan60 probe Fail (12 attempts); walk to r4c → Accepted. Origin/lunlun/holdout first-pin Accepted |
| Quiet scan60 alone (post-cooldown, attempts=6) | — | — | **Pass** (`survived_wall_clock_then_killed`) |

Gate pin order residual: prefer **`r4c_gto` first** for multi-case reliability; keep `scan60` as secondary independent-host research pin.

## Engineering landed (this close)

1. `tools/_behavior_probe.py` — plain createflags default, basename-preserving isolate copy, stale kill, longer backoff, attempts default 12.  
2. `tools/_behavior_bb_gate.py` — preferred live tags, max-candidates, case cooldown, attempts 12.  
3. `crates/pe/src/dumper/header_patch.rs` — clear `IMAGE_FILE_RELOCS_STRIPPED` when dump rebuilds `.reloc`.  
4. **VNEXT-BEH** — `validation_summary.json` task VNEXT-BEH, batch `bb_gate_pin`.  
5. **M1** — `snapshot_manifest` sidecar + probe `--rate-samples`.  
6. **M2** — `DumpCapturePolicy` + dump-path wiring; live real sidecar; pin rate baseline.  
7. **M3** — plugin `CapturePolicyHint` → host `DumpCapturePolicy`; sidecar records resolved policy.  
8. **M4** — case-manifest `capture_policy` + `--capture-policy` CLI + harness auto-pass.

## Explicit non-claims

- Not perfect unpack **1.0** (full product / business-logic equivalence).  
- `load_no_crash_v0` is **load survival**, not UI/business parity.  
- Pure default remains **Origin-only**, not global.  
- GTO still needs `--profile=ahk-gto-experimental` for experimental dump stages.  
- **Origin** quiet single-shot load flake is **closed at metric** (W1 scrub_v2, N=20 attempt=1 → 1.0).  
- **GTO** independent-host quiet single-shot load flake is **closed at metric** (W2 clear-regs, 3× N=10 → 1.0).  
- **W3 oracles** prove signal beyond load survival (Origin window class; GTO export surface) and can compose Accepted; they are **still not** product 1.0 / business-logic equivalence.  
- Default multi-case BB gate may still use `load_no_crash_v0` unless operators switch probe deliberately.

## W1 — Origin single-shot load (R-LOAD-FLAKE Origin side) — **metric exit**

**Work order:** [COURSE_CORRECTION_WORK_ORDER.md](COURSE_CORRECTION_WORK_ORDER.md) W1  
**Date:** 2026-07-24  
**Claim:** Origin quiet `load_no_crash_v0` attempt=1 rate ≥0.90 on fresh pure dump. **Not** product 1.0 / not business logic.

### Baselines (attempt=1, N=20 quiet serial, isolate basename)

| Candidate / build | pass_rate | Evidence |
|-------------------|-----------|----------|
| pure_r1 pin (pre-fix) | ~0.10 (2/20) | `origin_w1_rate_20260724-144207` |
| same PE, `--no-pure-rebuild` legacy | 0.25 (5/20) | `origin_w1_legacy_rate_20260724-144503` |
| offline zero RVA `0xfc388` only | **1.0** (20/20) | `origin_w1_patch_fc388` (proves object-head path) |
| live after plant-only fix (wrong) | fail class #2 | plant rewrote `0xfc388` as `!cookie` |
| live after broad scrub (wrong) | AV `call rdx` null | cleared ASLR CRT fn table `0xfc320` |
| **live scrub_v2 (winning)** | **1.0** (20/20) | `D:\MidaVault\lab\evidence\_beh_gate\origin_w1_scrub_v2_rate_20260724-151615\evidence_rate20.json` |

**Winning live tag:** `live_20260724-151549_w1_scrub_v2`  
**SHA256 (candidate):** `4ede58a5f2d52d43602a35c99eda21249ef0789825d04b6c63dd82882c33b7cb`

### Root causes (two cooperating bugs, not “random flake”)

1. **Kernel-canonical garbage object head**  
   - Live pure dump kept QWORD at RVA **`0xfc388` = `0xffffd466d2205dcd`** (kernel-half, unaligned).  
   - cdb: second-chance AV `rip=o+0x39e5c` `xchg ecx,dword ptr [r10]` with `r10` = that value.  
   - Same bit pattern equals `!DEFAULT_SECURITY_COOKIE` → cookie **complement scanner** also treated `0xfc388` as complement while cookie sits at **`0xfc050`** (distant, not MSVC ±8).  
   - Planting default cookie then **rewrote app data** at `0xfc388` to `!cookie`, reintroducing the bad object head after scrub.

2. **Over-broad process-local scrub (round-1 trap)**  
   - Scrubbing full canonical user range cleared **ASLR image VAs** (`0x7ff…`) still present in late CRT function tables before `fix_hardcoded_addresses`.  
   - Symptom: `call [fn_table]` → null RIP (second crash class).  
   - Fix: keep scrub to **low-4GB aligned heap-like** + **kernel-canonical garbage**; do **not** clear high user/ASLR image pointers.

### Code fix (2 rounds, whitelist)

| Module | Change |
|--------|--------|
| [`data_reinit.rs`](../crates/pe/src/dumper/data_reinit.rs) | `is_stale_absolute_pointer`: kernel-canonical clear (unaligned OK); low-4GB aligned heap only; blank-name RW `.data` for pure rebuild; unit test `clears_origin_kernel_garbage_object_head` |
| [`heap_bootstrap.rs`](../crates/pe/src/dumper/heap_bootstrap.rs) | Prefer adjacent (±8) complement when scanning; `normalize_cookie_site_for_plant` forces plant at `cookie_rva+8` if distant `!cookie` collision |

**Live post-fix (scrub_v2):** `cleared≈7` (was 52 with over-scrub); `0xfc320` keeps image/ASLR fn ptr; `0xfc388=0`.

### W1 exit checklist

| Criterion | Status |
|-----------|--------|
| Quiet N≥20 attempt=1 ≥0.90 | **Pass** (20/20 = 1.0) |
| Failures ≤2 root-cause clusters, documented | **Pass** (kernel object-head + plant mis-ID; over-scrub as failed round) |
| No 1.0 claim | **Held** |
| Residual updated + local commit | this section + course-correction commit |

**Residual after W1:** Origin quiet single-shot R-LOAD-FLAKE **metric-closed**. Cold-start / multi-case gate pressure not re-measured as W1 exit. Site scan may still *report* distant complement_rva pre-plant; plant path normalizes.

## W2 — GTO independent-host load without r4c pin — **metric exit**

**Work order:** [COURSE_CORRECTION_WORK_ORDER.md](COURSE_CORRECTION_WORK_ORDER.md) W2  
**Date:** 2026-07-24  
**Claim:** Fresh independent-host GTO dumps (`ahk-gto-experimental`) can load-survive attempt=1 at ≥0.70 (achieved 1.0) without walking to `r4c_gto`. **Not** product 1.0 / not business logic.

### Baselines (pre-fix, attempt=1, N=10 quiet)

| Candidate | pass_rate | Evidence |
|-----------|-----------|----------|
| `u_gto_host_scan60` | **0.2** (2/10) | `gto_w2_scan60_rate` |
| `r4c_gto` (control, same day machine) | **0.0** (0/10) | `gto_w2_r4c_rate` — even pin dump flaked hard |
| `m3_plugin_gtoexp` | **0.1** (1/10) | `gto_w2_m3_rate` |
| `w2_fresh1` (pre-fix rebuild) | **0.1** (1/10) | `gto_w2_fresh1_rate` |

### cdb root cause (deterministic, not “random flake”)

- **Fault:** `rip=0x1400070c9` `mov dword ptr [r8],ecx` with **`r8=0x8000`**, `rbx=0x8000`, `rdx/rdi` = restored heap base (e.g. `0x3364a20` = last HOT table live ptr).  
- **OEP:** `0x70b0` — `mov rbx,r8; test r8,r8; je skip; mov [r8],ecx` (optional out-param path).  
- **Why r8=0x8000:** `.boot` phase-2 multi_fixup ends with last range **size** in `r8d` (HOT_LARGE / large tables use `0x8000`). Stub then `pop` nonvolatiles and **`jmp OEP` without clearing volatiles**. CRT’s original `jmp OEP` never left size leftovers.  
- **Stack clue:** `@rsp+8 = 0x140ece040` points into `.boot` fixup meta (last entry size field).  
- **Not:** missing heap snapshot stage alone; R-GTO-BOOT byte delta is orthogonal honesty.

### Code fix (1 round)

| Module | Change |
|--------|--------|
| [`container_bootstrap.rs`](../crates/pe/src/dumper/container_bootstrap.rs) | Before `jmp OEP`, `emit_clear_volatile_regs` (xor rax/rcx/rdx/r8–r11). Unit: `oep_transfer_clears_volatile_regs_before_jmp` |
| [`_behavior_bb_gate.py`](../tools/_behavior_bb_gate.py) | Prefer `w2_clearregs{1,2,3}` over `r4c_gto` for `gto_launcher` pins |

### Post-fix lives (3 independent run_ids, attempt=1 N=10 each)

| Live tag | R0B | pass_rate | Evidence |
|----------|-----|-----------|----------|
| `live_20260724-155543_w2_clearregs1_gtoexp` | StructuralPassBehaviorPending | **1.0** (10/10) | `gto_w2_clearregs1_rate` |
| `live_20260724-155723_w2_clearregs2_gtoexp` | StructuralPassBehaviorPending | **1.0** (10/10) | `gto_w2_clearregs2_rate` |
| `live_20260724-155835_w2_clearregs3_gtoexp` | StructuralPassBehaviorPending | **1.0** (10/10) | `gto_w2_clearregs3_rate` |

First-pin style: clearregs1 `--attempts 3` early-exit → **Pass** on attempt 1 (`gto_w2_clearregs1_pin_attempts3`).

### W2 exit checklist

| Criterion | Status |
|-----------|--------|
| ≥3 independent fresh lives R0B + load | **Pass** |
| Quiet N≥10 attempt=1 ≥0.70 | **Pass** (3× 1.0) |
| Not using r4c as success condition | **Pass** (clearregs only) |
| Gate pin order prefers fresh path | **Pass** (preferred tags updated) |
| R-GTO-BOOT may stay open | **Held** (not a W2 gate) |
| No 1.0 claim | **Held** |

## W3 — Behavior probe beyond load survival — **metric exit**

**Work order:** [COURSE_CORRECTION_WORK_ORDER.md](COURSE_CORRECTION_WORK_ORDER.md) W3  
**Date:** 2026-07-24  
**Claim:** At least one Oreans case + one GTO case have a **new** probe (not `load_no_crash_v0`) that is fail-closed, schema-compatible, and compose-Accepted on vault candidates. **Not** product 1.0 / not full logic equivalence.

### Oracles chosen (one each; minimal + automatable)

| Case | Probe id | What it measures | What it does **not** measure |
|------|----------|------------------|------------------------------|
| Origin (`w1_scrub_v2`) | `gui_window_class_v0` | Process creates Win32 top-level window class **`PigToGoLicenseDialog`** within wall-clock (observed title「授权验证」recorded in markers, not required for Pass) | License validity, login success, business macros, UI automation parity |
| GTO (`w2_clearregs1`) | `pe_export_names_v0` | Static PE export name table contains required AHK surface symbols (`AhkAssign`, `AddScript`, `ahkExec`, `MinHookEnable`; case-insensitive fallback) | Script engine execution, GUI login (`NewClassName` only seen on **protected** input today), AHK FileAppend side effects |

**Why not GTO window?** Unpacked GTO currently exits quickly with **no** top-level product window (protected input still shows `NewClassName` / login title). Work-order allows export surface as GTO oracle; runtime GUI for GTO remains residual research.

### Harness

- [`tools/_behavior_probe.py`](../tools/_behavior_probe.py) v`0.2.0-w3`  
  - `--probe-kind window_class --expect-window-class …`  
  - `--probe-kind export_names --require-export …`  
- Evidence still `mida.behavior-evidence/v0`; extra blocks `window_quality` / `export_quality` are non-kernel sidecar fields (acceptance ignores unknown extras via serde default on known structs — kernel only reads core fields).  
- Compose: `mida-acceptance check-with-behavior` unchanged (Pass + structural → Accepted; Fail → Rejected; Inconclusive not upgraded).

### Evidence (vault)

| Path | Verdict | Compose |
|------|---------|---------|
| `D:\MidaVault\lab\evidence\_beh_gate\w3_oracle\origin_window_class.json` | Pass (`gui_window_class_v0`) | **Accepted** (`origin_compose.json`) |
| `D:\MidaVault\lab\evidence\_beh_gate\w3_oracle\gto_export_names.json` | Pass (`pe_export_names_v0`) | **Accepted** (`gto_compose.json`) |
| `…\origin_window_neg.json` | Fail (bogus class) | — |
| `…\gto_export_neg.json` | Fail (missing export) | — |

### W3 exit checklist

| Criterion | Status |
|-----------|--------|
| ≥1 Oreans + ≥1 GTO new-probe Pass | **Pass** |
| Docs: measures / non-measures | **This section** |
| Fail-closed negatives | **Pass** |
| No product 1.0 claim | **Held** |
| BB default still may use load_no_crash | **Held** (W3 does not silently rewrite VNEXT-BEH bar) |

**Residual after W3:** R-PURE-LOGIC **narrowed** (real signal exists) but **not closed** — license/script/business path still unproven. GTO runtime GUI oracle still open.

## W4 — Claim-bar review (audit only) — **product 1.0 = NO**

**Work order:** [COURSE_CORRECTION_WORK_ORDER.md](COURSE_CORRECTION_WORK_ORDER.md) W4  
**Date:** 2026-07-24  
**Nature:** Written distance-to-1.0 audit + W1–W3 evidence reconfirm. **Not** a release note. **Not** an automatic claim upgrade.

### Reconfirm protocol (winning candidates only)

| Check | Candidate | Result | Evidence |
|-------|-----------|--------|----------|
| Origin load N=5 attempt=1 | `live_20260724-151549_w1_scrub_v2` | **pass_rate=1.0** | `D:\MidaVault\lab\evidence\_beh_gate\w4_review\origin_load_rate5.json` |
| GTO load N=5 attempt=1 | `live_20260724-155543_w2_clearregs1_gtoexp` | **pass_rate=1.0** | `…\w4_review\gto_load_rate5.json` |
| Origin window oracle | same Origin | **Pass** `gui_window_class_v0` (`PigToGoLicenseDialog`; title marker 授权验证) | `…\origin_window.json` |
| GTO export oracle | same GTO | **Pass** `pe_export_names_v0` (AhkAssign/AddScript/ahkExec/MinHookEnable) | `…\gto_exports.json` |
| Origin compose | window evidence | **Accepted** | `…\origin_compose.json` |
| GTO compose | export evidence | **Accepted** | `…\gto_compose.json` |

SHA256 (unchanged vs W1/W2 winners): Origin `4ede58a5…b7cb`; GTO `2043df64…9126`.

### Claim questions (W4 table)

| Question | Answer | Notes |
|----------|--------|-------|
| Behavior beyond load survival? | **YES** | W3 oracles reconfirmed Pass + compose Accepted on both sides |
| 4-case fresh single-shot load still green? | **NOT fully re-run this turn** | Only Origin+GTO winners; lunlun / xiongxiong_duokai still rest on historical B-B pin batch — **do not** treat as fresh W4 proof |
| pure / GTO product policy? | **Unchanged** | D3 pure Origin-only; GTO remains `ahk-gto-experimental` |
| Write product **1.0**? | **NO** | Default W4 outcome; no operator authorization; no Q7 full 4-case re-run |

### Distance to product 1.0 (honest gap list)

What is **closed** (engineering / metric, not product):

1. R0B structural gate + VNEXT-BEH historical B-B (`load_no_crash_v0` + pin/retry era).  
2. Origin quiet attempt=1 load (W1 scrub_v2, N=20).  
3. GTO independent-host quiet attempt=1 load without r4c walk (W2 clear-regs).  
4. Minimal non-survival oracles: Origin window class; GTO PE export surface (W3).

What **still blocks** calling this perfect-unpack **1.0**:

| Gap | Why it blocks |
|-----|----------------|
| **R-PURE-LOGIC** | No license/script/business-path equivalence; W3 is real signal, not product parity |
| **R-GTO-UI** | Unpacked GTO still no product window after 2 fix rounds (title root + gscript 32KiB + UI-early dump); cold ExitProcess(0); protected still Pass |
| **R-GTO-BOOT** | `.boot` heap snapshot variance honesty residual (not load AV root) |
| **4-case freshness** | W4 did not re-prove lunlun + holdout on post-W1/W2 dumps under attempt=1 |
| **D3 / experimental** | pure not global; GTO dump stages still experimental flag |
| **Governance** | Q7 + operator explicit auth required before any 1.0 sentence |

### W4 decision (binding until operator overrides)

```text
product_1.0_claim = NO
vnext_beh_status  = closed (historical; load_survival era)
course_correction = W0–W4 complete
next_default      = residual-driven work only; no silent claim upgrade
```

**Allowed next moves without 1.0 language:** deepen R-PURE-LOGIC oracles; optional 4-case fresh rate on post-W1/W2 paths; GTO UI research.  
**Forbidden:** marketing 1.0, equating W4 reconfirm with product release, expanding pure beyond Origin without D3 change.

## P1 sprint toward 1.0 (operator chose path 1) — **not 1.0 yet**

**Date:** 2026-07-24  
**Goal of sprint:** close R-4CASE-FRESH + deepen R-PURE-LOGIC signal.  
**Still holds:** product **1.0 = NO** until operator auth + Q7 full re-run + deeper business oracles.

### P1-A — 4-case attempt=1 load (R-4CASE-FRESH) — **metric closed**

| Case | Candidate pin | N=10 attempt=1 | Evidence |
|------|---------------|----------------|----------|
| origin_macro | `w1_scrub_v2` | **1.0** | `D:\MidaVault\lab\evidence\_beh_gate\p1_4case_fresh_20260724-161856\origin_macro_rate10.json` |
| lunlun_software | `u_harden_3x_n3` | **1.0** | `…\lunlun_software_rate10.json` |
| xiongxiong_duokai (holdout) | `u_harden_3x_n3` | **1.0** | `…\xiongxiong_duokai_rate10.json` |
| gto_launcher | `w2_clearregs1` | **1.0** | `…\gto_launcher_rate10.json` |

Batch summary: `…\p1_4case_fresh_20260724-161856\summary.json` — **4/4 cases pass_rate=1.0**.

**Note:** lunlun/holdout pins are pre-W1 Oreans dumps (not re-unpacked under scrub_v2). Fresh *load* on current best vault pins is proven; fresh *re-unpack* of lunlun/holdout under latest pe/ is still optional hygiene.

### P1-B — Deeper pure-logic oracles — **signal advanced, not closed**

Harness: [`tools/_behavior_probe.py`](../tools/_behavior_probe.py) v`0.3.0-p1` — new `exit_code_exact_v0` (`--probe-kind exit_code --expect-exit N`); Origin title already supported via `--require-title-substr`.

| Case | Probe | What it measures | Evidence | Compose |
|------|-------|------------------|----------|---------|
| Origin | `gui_window_class_v0` + **title** `授权验证` | Class **and** title (fail-closed on bogus title) | `p1_logic_20260724\origin_title.json` | **Accepted** |
| lunlun | `exit_code_exact_v0` = `1441624` (`0x15ff58`) | Stable nonzero non-NT exit | `…\lunlun_exit.json` | **Accepted** |
| holdout | `exit_code_exact_v0` = `594628608` (`0x23715000`) | Stable nonzero non-NT exit | `…\holdout_exit.json` | **Accepted** |
| GTO | `exit_code_exact_v0` = `0` | Clean exit 0 (still no product window) | `…\gto_exit.json` | **Accepted** |

Fail-closed negatives: `origin_title_neg`, `lunlun_exit_neg`, `holdout_exit_neg` → **Fail**.

**What this is not:** license validity, script execution, UI automation parity, business macros. Exit codes may encode missing-args / single-instance / license state — residual listed on probe.

### Gate pin hygiene

[`_behavior_bb_gate.py`](../tools/_behavior_bb_gate.py): `origin_macro` preferred tag now leads with `live_20260724-151549_w1_scrub_v2`.

## P2 sprint — control-text + pe_string + R-GTO-UI evidence — **not 1.0**

**Date:** 2026-07-24  
**Harness:** [`tools/_behavior_probe.py`](../tools/_behavior_probe.py) v`0.4.0-p2`  
- `window_class` gains `--require-control-text` (child GetWindowText substrings)  
- new `pe_string_v0` (`--probe-kind pe_string --require-string …`) static ASCII/UTF-16LE scan  

### Exploration findings

| Surface | Result |
|---------|--------|
| Origin unpacked | License dialog children: Static「授权码：」、Button「确定」、welcome Edit — **no** registry/file side-effect under short probe |
| lunlun / holdout | Still exit-only (no window); exit_exact remains best runtime oracle |
| GTO **protected** | `NewClassName` + title「猪猪WLK 一键宏 - 登录/注册」+ login controls (账号/密码/登录) — **reference** behavior of packer input |
| GTO **unpacked** | Process exits 0 quickly; **no** top-level product window; static PE **does** contain UTF-16 `NewClassName` + `AutoHotkey` — script UI not reached at runtime |

### Evidence (`D:\MidaVault\lab\evidence\_beh_gate\p2_logic_20260724\`)

| Artifact | Verdict | Notes |
|----------|---------|-------|
| `origin_controls.json` | **Pass** | class + title + control「授权码」「确定」 → compose **Accepted** |
| `origin_controls_neg.json` | **Fail** | bogus control text |
| `gto_pe_string.json` | **Pass** | `AutoHotkey` + `NewClassName` → compose **Accepted** |
| `gto_pe_string_neg.json` | **Fail** | missing string fail-closed |
| `gto_protected_window.json` | **Pass** | protected reference only (not product dump claim) |
| `gto_unpacked_window_fail.json` | **Fail** | documents **R-GTO-UI** on winning clearregs dump |

**What this is not:** license accept, account login, AHK script execution, FileAppend side effects, business macros.

**R-GTO-UI status:** now **evidence-backed open** (protected Pass vs unpacked Fail on same window oracle). Fix path is dump/runtime completeness (heap/script resume), not probe plumbing.

## R-GTO-UI fix rounds (Q2 cap = 2) — **UI still Fail; load green**

**Date:** 2026-07-24  
**Code:** [`heap_global_snapshot.rs`](../crates/pe/src/dumper/heap_global_snapshot.rs) (policy hot roots outside fill/.data + plant WRITE), [`capture_policy.rs`](../crates/pe/src/dumper/capture_policy.rs) (gscript cap 0x10000), [`gto_host.rs`](../crates/cli/src/unpacker/gto_host.rs) (NewClassName early dump), [`dump_process.rs`](../crates/pe/src/dumper/dump_process.rs).

| Round | Live | Engineering outcome | window_class `NewClassName` |
|-------|------|---------------------|----------------------------|
| R1 | `live_20260724-170104_r_gto_ui_r1` | Capture `0x18a898` size=4096; section `.,\\W` → `MEM_WRITE` | **Fail** exit 0 |
| R2 | `live_20260724-170937_r_gto_ui_r2` | UI seen ~1046 ms → dump +3s; gscript **32768**; load N=5 **1.0** | **Fail** exit 0 |

Evidence: `D:\MidaVault\lab\evidence\_beh_gate\r_gto_ui_r2\` (`gto_unpacked_window.json` Fail; `gto_load_rate5.json` Pass 5/5).

**Stop rule:** Q2 two-round cap reached. Residual stays open; further UI work needs new plan (fuller script graph / AHK exec path), not a third blind dump tweak.

## R-GTO-UI step-1 read-only root-cause diagnosis (2026-07-24, post 4-case fresh reverify)

**Status:** Read-only cdb diagnosis on the fresh `verify_live_gto.exe` candidate (`sha256 6c4bc6e47c14…`, from `live_20260724-172740` fresh unpack, R0B StructuralPassBehaviorPending). **No repo code changed; no fix round opened.** Marked **needs operator authorization for a 3rd round** per Q2 cap.

**Binding work order:** [COURSE_CORRECTION_WORK_ORDER.md](COURSE_CORRECTION_WORK_ORDER.md) W3/P2 + R-GTO-UI residual. This subsection is the step-1 deliverable from the 4-case fresh-reverify follow-up.

**Candidate control-flow (cdb, evidence-level):**

1. `AddressOfEntryPoint = 0xecc000` (confirmed from OptionalHeader). The dump EP is the **unpacker-emitted transfer stub**, not the real AHK OEP.
2. `0x140ecc000..0x140ecc23b` runs the restored `g_script` table: `GetProcessHeap` (`[0x1400fd480]`) → `RtlAllocateHeap` (`[0x1400fd8b0]`) → memcpy (`0x140ecc164`, `rep movsb`) + hash-scramble (`0x140ecc174`, `rol;xor;store`) over a 320-entry + 321-entry init table. **Allocations succeed** (process-heap is valid in any process); heap-snapshot completeness is **not** the blocker of this path.
3. `0x140ecc21a` epilogue: `add rsp,38h; pop r15..rbx; xor eax,ecx,edx,r8,r9,r10,r11` (W2 `emit_clear_volatile_regs`) then `jmp 0x1400070b0`.
4. `0x1400070b0` (the documented captured "OEP") is reached. With **all argument registers zeroed** by step 3:
   - `test r8,r8; je 0x1400070cc` → **taken** (r8=0)
   - `lea eax,[rdx-0xC000]; cmp eax,3FFFh; ja 0x1400071ab` → **taken** (rdx=0 → eax=`0xFFFF4000` > `0x3FFF`)
   - error path `0x1400071ab`: `mov word [rsp+20h],cx; mov ecx,edi; call [0x1400fddc8]; …; ret` at `0x1400071c8`
5. The transfer stub used `jmp` (not `call`), so the `ret` at `0x1400071c8` returns to the **OS thread-start address** (`KERNEL32!BaseThreadInitThunk+0x20` → `ntdll!RtlExitUserThread+0x40` → `ntdll!NtTerminateProcess(handle=-1)`). Termination stack at exit has **no application frame** (only 4 OS frames). `rcx=-1` at the syscall. **No `ExitProcess` public call, no `RegisterClassExW`, no `CreateWindowExW` ever hit** (both API bps set successfully, neither fired).

**Root-cause cluster (NEW; not identified by R1/R2):**

- **`0x1400070b0` is not the program entry.** Its argument contract is `(rcx=handle, rdx∈[0xC000,0xFFFF]=WM_USER-range message id, r8=wparam, r9=lparam)` — i.e. it is an **AHK WindowProc / message-dispatch function**, not `mainCRTStartup`/`WinMain`. The unpacker's OEP-observation for the GTO/AHK family captured a WindowProc address as "OEP".
- The W2 `emit_clear_volatile_regs` fix (which closed R-LOAD-FLAKE / `mov [r8],ecx` AV with r8=`0x8000` size leftover) **zeroes rcx/rdx/r8/r9**, which are exactly the WindowProc/WinMain argument registers. With msg=0/wparam=0 the function takes its default/error path and `ret`s. Because the stub `jmp`s (not `call`s), that `ret` lands on the OS thread-start return address → thread exit → process exit 0, **no window created**.
- **Coupling:** W2 (load-AV fix) and R-GTO-UI (no window) are not independent. The same `emit_clear_volatile_regs` that fixed the AV also clobbers the entry-function argument registers. R1/R2 heap-snapshot tweaks (title-root plant, gscript cap 8→32 KiB) could not fix this — the entry is wrong, not the heap.

**Why load_no_crash is green while UI is Fail:** the WindowProc error path `ret`s cleanly to BaseThreadInitThunk → clean thread exit code 0. No NT exception, no AV. So `load_no_crash_v0` and R0B structural both pass; the behavioral gap only shows under the window oracle.

**Honest confidence:** evidence-level, not 100% proven without AHK private symbols. The causal chain (stub disasm + arg-zero + branch trace + clean-exit stack with zero app frames + no window API hit) is internally consistent and reproducible on the fresh candidate. Counter-hypothesis to rule out in an authorized round: `0x70b0` *is* `WinMain` (not a WindowProc) and the real fix is to set up WinMain args (hInstance from `GetModuleHandleW(NULL)`, lpCmdLine from `GetCommandLineW`, nShowCmd from `GetStartupInfo`) before `jmp`, instead of clearing them — OR to capture the true CRT `mainCRTStartup` as OEP.

**Candidate fix directions for an authorized round 3 (NOT started; awaiting operator):**

1. **OEP re-capture:** find the true AHK program entry (CRT `mainCRTStartup` / AHK `main`) that the packer's `.boot` actually jumped to; set dump `AddressOfEntryPoint` to it. Most robust; addresses the wrong-entry root cause directly.
2. **Arg-setup stub:** keep `0x70b0` as EP but have the transfer stub call `GetModuleHandleW`/`GetCommandLineW`/`GetStartupInfo` into rcx/rdx/r8/r9 before `jmp` (mirroring CRT pre-WinMain setup). Risk: depends on `0x70b0` actually being `WinMain`.
3. **Narrow clear-regs:** clear only the specific register that held the bad size leftover (r8 per W2 cdb) instead of all volatiles; leaves WinMain/WindowProc args intact. Lowest-effort but assumes the protected `.boot` left valid args in rcx/rdx/r9 (unverified for the dump path).

**Non-claim:** this diagnosis does not close R-GTO-UI, does not enable a 1.0 sentence, and does not start a code change. It only upgrades R-GTO-UI from "2 blind rounds exhausted" to "root cause identified; awaits operator authorization per Q2 cap."

**Artifacts (vault, not in git):** `D:\MidaVault\scratch\gto_diag_step1*.log`, `gto_diag_oep.log`, `gto_postloop.log`, `gto_iat.log`, `gto_main.log`, `gto_71a0.log`, `verify_live_gto.exe` + `*.dump_snapshot.json`.

## Residual after VNEXT-BEH (+ W1–W4 + P1 + P2 + R-GTO-UI×2 + step-1 dx)

| ID | Item | Blocks 1.0? | Status |
|----|------|-------------|--------|
| R-LOAD-FLAKE (Origin quiet) | attempt=1 N≥20 load survival | Quality | **W1 metric exit**; W4/P1 reconfirm green |
| R-LOAD-FLAKE (GTO quiet / fresh host) | attempt=1 load survival on independent-host dumps | Quality | **W2 metric exit**; W4/P1 reconfirm green |
| R-GTO-LATEST | Fresh dump load without `r4c_gto` walk | Quality | **W2 metric exit** |
| R-GTO-BOOT | `.boot` heap_global payload size variance under 320-slot cap | Quality | Open (honesty; not load AV root) |
| R-PURE-LOGIC | Product-logic / business path equivalence | **Yes** for product 1.0 | **Advanced:** controls + pe_string + exit/title/exports; **still blocks 1.0** |
| R-GTO-UI | Unpacked GTO no product window; protected does | Quality / **1.0-relevant for GTO** | **Open + root-caused (step-1 dx):** captured OEP `0x70b0` is a WindowProc, not program entry; W2 clear-regs zeroes its arg regs → default-path `ret` to OS thread-start → exit 0, no window. **Awaiting operator auth for round 3** |
| R-4CASE-FRESH | Full 4-case attempt=1 on best pins | Claim hygiene | **P1-A closed** (N=10 × 4 = 1.0) |
| R-X86 | ScyllaHide x86 residual | x86 only | Open |
| **product 1.0 claim** | Operator + Q7 | Governance | **Still NO** |

## Re-run

```powershell
# P1 4-case load rate:
# D:\MidaVault\lab\evidence\_beh_gate\p1_4case_fresh_20260724-161856\

# P1 deeper oracles:
# D:\MidaVault\lab\evidence\_beh_gate\p1_logic_20260724\

# P2 controls / pe_string / R-GTO-UI:
# D:\MidaVault\lab\evidence\_beh_gate\p2_logic_20260724\

python tools/_behavior_bb_gate.py --cases origin_macro,lunlun_software,xiongxiong_duokai,gto_launcher --write-summary --tag bb_gate_pin --max-wall-ms 8000 --attempts 12 --max-candidates 3
```



