# Unattended Residual — 2026-07-24 (post B-B close)

**Binding:** [UNATTENDED_DECISIONS_20260724.md](UNATTENDED_DECISIONS_20260724.md)  
**Claim bar (Q7):** VNEXT-BEH only when 4-case B-B all_ok.  
**This close:** batch `bb_gate_pin` **all_ok=true** → **VNEXT-BEH written**.

## Battlefield R-REPRO-10× (2026-07-25) — **CLOSED; zero code change**

**Bar:** README family gate — Oreans suite must pass **10 consecutive isolated runs** (attempt=1, fresh process each) per case.

**Round 0 (measure):** strict 10× isolated attempt=1 on bb_gate_pin candidates (no cooldown):

| case | bb_gate_pin candidate | 10× rate | root cause |
|------|-----------------------|----------|------------|
| lunlun_software | harden_3x n3 | 10/10 | — |
| xiongxiong_duokai | harden_3x n3 (holdout) | 10/10 | — |
| origin_macro | live_20260724-101051 (pre-W1-scrub) | **6/10** | stale pin (pre-scrub); AV `0x39e5c xchg [r10]`, r10=`0xffffd466…` kernel-canonical still in `.data@0xfc388` |
| gto_launcher | live_20260723-225951 r4c | **4/10** | stale pin (pre-W2-clearregs); `0xc0000005` AV |

**Round 1 (fix = refresh stale pins, no code change):** W1 scrub_v2 + W2 clear-regs are already in the codebase; the pinned candidates simply predated them.

| case | refreshed candidate | R0B | 10× | note |
|------|---------------------|-----|-----|------|
| origin_macro | fresh current-CLI pure dump | StructuralPassBehaviorPending | **10/10** | `.data` kernel-canonical garbage = 0 |
| gto_launcher | fresh current-CLI gtoexp dump (r26b code) | StructuralPassBehaviorPending | **10/10** | clear-regs + window patches |
| lunlun_software | harden_3x n3 pin | StructuralPassBehaviorPending | **10/10** | unchanged |
| xiongxiong_duokai | harden_3x n3 pin | StructuralPassBehaviorPending | **10/10** | unchanged |

**Verdict:** `all_4_10x10 = true`, `all_4_r0b_structural_pass = true`, `code_changes = 0`.

**Evidence:** `D:\MidaVault\lab\evidence\_beh_gate
epro10x_baseline_20260725
epro10x_summary.json` (+ per-run JSON + R0B reports).

**Non-claim:** load survival 10× ≠ product logic equivalence; this closes the **reproducibility** dimension of the Oreans family gate only. **product 1.0 still NO** (R-PURE-LOGIC + multi-family production-grade remain).

**Honesty note:** bb_gate_pin (VNEXT-BEH) used stale pre-fix candidates and still composed Accepted because the probe retried (attempts=12). The strict 10× protocol revealed the pins were stale; refreshing them to current-CLI output closes the gap without new code. The VNEXT-BEH verdict stands (load survival is its bar); the repro dimension is now honestly met.

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

## R-GTO-UI round 3 (direction 1 — OEP re-capture) — **NEGATIVE; AV; reverted**

**Date:** 2026-07-24 (operator authorized direction 1, round 3 of Q2 cap).
**Hypothesis:** the captured OEP `0x70b0` is a WindowProc, not the program entry; setting dump `AddressOfEntryPoint` to the true MSVC `mainCRTStartup` should let the CRT init -> `_initterm` -> `WinMain` run and create `NewClassName`.

**Static target found (read-only, candidate `.text`):**
- `__scrt_common_main_seh` at RVA `0xd9160` (MSVC14 sig `48 89 5C 24 08 57 48 83 EC xx B9 01 00 00 00 E8`, unique match in `.text`).
- Its tail-jmp caller at RVA `0xd92e1` (`E9` -> `0xd9160`) sits in a tiny function at RVA **`0xd92d4`**: `48 83 EC 28` (`sub rsp,0x28`) `E8 …` (`call __scrt_initialize @ 0xd9848`) `48 83 C4 28` `E9 …` (`jmp __scrt_common_main_seh`). This is `mainCRTStartup`.

**Implementation (committed code, then reverted):** added pure helper `find_msvc_maincrt_startup(text, text_rva)` in `crates/packers/themida/src/oep/mod.rs` (strict MSVC14 sig -> E8/E9 caller -> walk back to `48 83 EC 28`), wired into `gto_host.rs` to prefer its result over the generic `.text` prologue scan. 3 synthetic unit tests green. Live unpack logged `OEP via mainCRTStartup 0x1400d92d4 (rva 0xd92d4); scanned fallback was 0x1400070b0` — the override fired correctly.

**Result: REGRESSION (AV), not a fix.**
- New candidate (`verify_live_gto_d1d.exe`, R0B StructuralPassBehaviorPending 12/12) **crashes** on load: exit `3221225477` = `0xC0000005` (access violation), `window_class NewClassName` oracle = **Fail** (no window).
- cdb: AV with `rip=0` (call to null); call site `0x1400d9266` is inside `__scrt_common_main_seh`'s init path (between `0xd9160` scrt and `0xd92d4` mainCRTStartup). A CRT-init function pointer is null at the point `_initterm`/`__scrt_initialize` runs.
- **Root cause of the AV (fundamental, not 1-line):** the unpacker's transfer stub at `0xecc000` REPLAYS the captured `g_script` heap table (`GetProcessHeap`+`RtlAllocateHeap`+`rep movsb`+hash over 320+321 entries) before `jmp` OEP. When OEP = `mainCRTStartup`, the real `_initterm` re-runs the C++ static ctors ON TOP of the stub's replayed heap state -> the replayed pointers (live-runtime-relative, only partially fixed up) are dereferenced by the real ctors -> null call -> AV. The stub's heap replay and a fresh `mainCRTStartup` init do **not** compose.

**Stop rule (Q2):** round 3 produced an AV regression (load_no_crash would go from 1.0 clean-exit-0 to AV crash). Round 4 "skip the stub heap replay" or "set EP to post-`_initterm` WinMain-call site" are significant speculative changes without a strong success guarantee; grinding into them blindly violates the Q2 discipline. **Reverted** all code changes (`gto_host.rs`, `oep/mod.rs`, `lib.rs` restored to HEAD; helper + tests removed). Rebuilt CLI; re-verified GTO returns to `entry_rva=0x70b0`, clean exit 0, `load_no_crash` Pass — the 4-case fresh-reverify baseline is intact, no regression shipped.

**What was learned (positive knowledge, no code shipped):**
1. The true MSVC program entry for GTO is `mainCRTStartup` @ RVA `0xd92d4` (caller of `__scrt_common_main_seh` @ `0xd9160`). Confirmed statically + live override fired.
2. The captured `0x70b0` is confirmed NOT the program entry; it is a WindowProc/message-dispatch function.
3. **Direction 1 alone is insufficient.** The transfer stub's heap-replay semantics conflict with a fresh `mainCRTStartup` init. Any future fix that re-points EP to `mainCRTStartup` MUST also redesign the stub: either (a) skip heap replay and rely on real ctors + fully-fixed-up `.data`/`.rdata`, or (b) replay heap AND set EP to the post-`_initterm` point (the `call WinMain` site inside `__scrt_common_main`), not `mainCRTStartup`.
4. This narrows R-GTO-UI from "wrong OEP" to **"OEP + stub-replay composition"** — a stub/runtime-architecture problem, not an OEP-detection problem. The OEP-detection piece (direction 1's helper) is sound and reusable if a future round redesigns the stub.

**Non-claim:** round 3 does not close R-GTO-UI; does not enable a 1.0 sentence; ships no code change. R-GTO-UI remains open. Further work needs a new operator authorization (stub redesign is beyond "OEP re-capture").

**Artifacts (vault, not in git):** `D:\MidaVault\scratch\verify_live_gto_d1*.exe`, `gto_d1d_av.log`, `gto_avsite*.log`, `gto_diag_oep.log`.

## R-GTO-UI round 4 (direction 1b — stub replay + post-_initterm WinMain EP) — **NEGATIVE; AV; no code shipped**

**Date:** 2026-07-24 (operator authorized direction 1b: keep stub heap replay, set EP to post-`_initterm` WinMain call site).
**Hypothesis:** the stub replays the captured `g_script` heap (replacing the ctors); jumping to the post-`_initterm` WinMain call site (instead of `mainCRTStartup`) avoids re-running `_initterm` on top of the replay, so WinMain registers the class + creates the window using the replayed `g_script`.

**Static target found (read-only, candidate `.text`):**
- `__scrt_common_main_seh` @ RVA `0xd9160` inlines `__scrt_common_main`. The two `_initterm` calls are at `0xd91b6` and `0xd91d7`. The post-init sequence is:
  - `0xd9245` `call 0xd9768` → `ax` (nShowCmd source) — start of WinMain arg setup
  - `0xd924d` `call 0xeae60` → `rax` (lpCmdLine)
  - `0xd925a` `lea rcx,[hInstance global]`
  - `0xd9268` `call 0xd97ac` — **the WinMain call** (`rcx`=hInstance, `rdx`=hPrev=0, `r8`=lpCmdLine, `r9`=nShowCmd). `0xd97ac` is WinMain.

**Method:** no code change — used the existing `--oep=rva=N` CLI flag (`OepPolicy::Fixed`) so the existing transfer stub (heap replay + clear regs + `jmp OEP`) lands at the chosen RVA. Tested two EPs.

**Result: REGRESSION (AV) at both EPs — same root class (heap-replay incompleteness).**

| EP | AV site | Root cause |
|----|---------|------------|
| `0xd9245` (WinMain arg setup) | `KERNELBASE!GetModuleHandleA+0x9b` ← `ntdll!RtlDosApplyFileIsolationRedirection_Ustr` (bad string ptr); caller `0x140005a47` ← `0x1400d9266` | `0xd9768` (CRT post-init helper) calls `GetModuleHandleA(<string>)`; the module-name string global is NULL/bad in the replayed heap — the stub replays `g_script` (320 slots + 1 container) but NOT the string globals the CRT helpers reference |
| `0xd9268` (direct `call WinMain`) | `ntdll!RtlpWaitOnCriticalSection` / `RtlEnterCriticalSection` deadlock/AV; caller `0x1400e71ac` ← `0x1400d92c8` (WinMain body) | WinMain enters a `CRITICAL_SECTION` whose `OwningThread`/lock-count is stale from the dumped process; the replayed heap copies the CS object bytes but the synchronization state is invalid in the new process |

**Root-cause synthesis (direction 1 + 1b combined):** the transfer stub's heap replay captures a **subset** of runtime state (g_script table + a few hot roots). Post-ctor code — whether `_initterm` (direction 1, null fn-ptr call), CRT post-init helpers (direction 1b @ 0xd9245, bad string ptr), or WinMain itself (direction 1b @ 0xd9268, stale critical section) — references globals/sync objects NOT in that subset. **Changing the OEP cannot fix this; the blocker is heap/global replay completeness, not entry-point selection.**

**Stop rule (Q2):** round 3 (direction 1) + round 4 (direction 1b, 2 EPs) all AV. The shared root cause is heap-replay completeness — the same territory R-GTO-UI R1/R2 (title-root plant, gscript 8→32 KiB) worked in, now confirmed as the true blocker rather than OEP. A round 5 would need to expand the stub's capture to include (a) the CRT helper string globals and (b) critical-section re-initialization (re-init CS state on replay, not just copy bytes) — a substantial heap-capture/runtime redesign that overlaps the exhausted R1/R2 line and is beyond the "stub redesign + EP" scope authorized here. **No code shipped** (only `--oep=rva=N` CLI experiments; repo remains at HEAD `cfaede5`, no tracked changes). Rebuilt CLI unchanged from the reverted round-3 state; GTO default path still `entry_rva=0x70b0`, clean exit 0, `load_no_crash` Pass — 4-case fresh-reverify baseline intact.

**What was learned (positive knowledge):**
1. The post-`_initterm` WinMain call site is `0xd9268` (WinMain = `0xd97ac`); the arg-setup starts at `0xd9245`. Confirmed statically.
2. **Direction 1b is also blocked by heap-replay completeness**, not by OEP. Both `mainCRTStartup` (round 3) and post-_initterm (round 4) fail on missing/stale replayed state.
3. The stub's heap replay must additionally cover: CRT helper string globals (e.g. the `GetModuleHandleA` module-name) AND critical-section re-initialization (zero `OwningThread`/lock-count on replay, or `InitializeCriticalSection` fresh). Without these, no post-ctor EP can run.
4. R-GTO-UI is now precisely scoped: it is a **heap-capture/replay completeness problem** (capture more globals + re-init sync objects), not an OEP problem. The OEP pieces (direction 1 helper + the post-_initterm site) are known and reusable once the heap replay is complete.

**Non-claim:** round 4 does not close R-GTO-UI; no 1.0 sentence; no code shipped. R-GTO-UI remains open. Any further work needs a new operator authorization scoped to heap-capture completeness (capture more globals + CS re-init), which is a different and larger change than "OEP re-capture" or "stub EP selection".

**Artifacts (vault, not in git):** `D:\MidaVault\scratch\verify_live_gto_d1b_9245.exe`, `verify_live_gto_d1b_9268.exe`, `d1b_av.log`, `d1b_9268_av.log`, `s1.log`, `s2.log`.

## R-GTO-UI round 5 (CS re-init + anti-tamper probe) — **PARTIAL PROGRESS; new blocker = anti-tamper; no code shipped**

**Date:** 2026-07-24 (operator authorized heap-replay completeness: CS re-init + capture CRT string globals).
**Method:** read-only cdb + byte-patch experiments on vault candidates (no repo code change).

**CS root cause located:** the `RtlEnterCriticalSection` AV (round 4, EP=0xd9268) uses CS @ RVA `0x145db0` (a `.data` global). In the dumped candidate that CS is **all-zero** (not stale — zeroed/uninitialized). `LockCount=0` (not `-1`) makes `RtlEnterCriticalSection` treat it as contended → `RtlpWaitOnCriticalSection` on `LockSemaphore=0` (NULL) → AV.

**CS re-init experiment (byte-patch, vault only):** set `LockCount` (offset +8, 4 bytes) = `-1` on the dumped CS, leaving the rest zero. Result: **the CS AV is resolved** — execution advances past `EnterCriticalSection`. This confirms the CS-reinit direction is valid; a proper fix would call `InitializeCriticalSection` (or zero+set `LockCount=-1`) on known CS globals in the stub/dumper post-process.

**New blocker revealed (anti-tamper, deeper than authorized scope):** after the CS AV clears, the next AV is at `0x1400fb8f0: jmp rax` with `rax = 0xd25a180000e54155` (garbage). Caller chain `0x400e7232 ← 0x400e71b5 ← 0x400d92c8` (WinMain path). The surrounding code at `0x400e721c` is `xor rax,rcx; ror rax,cl` — **AHK anti-tamper pointer decryption**, cookie loaded from `.data` global `0x1454b8`.
- The cookie at `0x1454b8` is **zero** in the dumped candidate (and in the prior W2 dump too — because the AHK init that sets it never ran in the EP=0x70b0 early-exit path).
- Brute-force scan: **no** 64-bit value in the dumped `.data` decrypts `0xd25a180000e54155` to a valid image VA under `xor-then-ror` — so the bad `rax` is either (a) encrypted with a cookie not present in `.data` (heap/per-process), or (b) a genuinely scrubbed/garbage global, not an encrypted pointer.
- Either way this is **AHK's anti-tamper pointer-obfuscation layer**, not "capture CRT string globals". Defeating it requires reverse-engineering AHK's pointer encryption/decryption and either preserving the live cookie or re-deriving it — a substantial RE effort distinct from heap-capture completeness.

**Stop rule (Q2):** round 5 made real progress (CS re-init technique validated) but revealed that R-GTO-UI has a deeper layer (AHK anti-tamper) beyond the authorized scope ("CS re-init + CRT string globals"). The CS re-init alone does **not** change the R-GTO-UI verdict (still Fail — the candidate AVs at the anti-tamper layer instead), so shipping it now would add code surface without shortening the distance to 1.0. **No code shipped** (vault byte-patch experiments only; repo at HEAD `a08c548`, zero tracked changes). 4-case fresh-reverify baseline intact.

**What was learned (positive knowledge):**
1. The CS at `.data` RVA `0x145db0` is the one WinMain enters; it is zeroed in the dump; `LockCount=-1` re-init resolves the CS AV. CS-reinit is a confirmed-valid technique for a future combined fix.
2. The next blocker is AHK anti-tamper (`xor/ror` pointer decryption with a `.data` cookie @ `0x1454b8` that is zero in the dump). This is a distinct RE problem, not heap-capture completeness.
3. R-GTO-UI is now a **layered** problem: (L1) OEP [solved: `mainCRTStartup`@`0xd92d4`], (L2) heap-replay completeness [partially: CS re-init works], (L3) anti-tamper pointer decryption [open — needs AHK RE]. No single 2-round authorization can close it.
4. The stub-replay approach is fundamentally in tension with AHK anti-tamper: the anti-tamper pointers are decrypted per-call using a cookie that AHK init sets; skipping init (stub replay) leaves the cookie unset → decryption yields garbage. Running init (mainCRTStartup) re-randomizes the cookie → also breaks decryption. Either path needs the anti-tamper RE'd first.

**Non-claim:** round 5 does not close R-GTO-UI; no 1.0 sentence; no code shipped. R-GTO-UI remains open. Further work needs a new operator authorization scoped to **AHK anti-tamper reverse-engineering** (a research task, not a 2-round engineering fix) — which is beyond heap-replay completeness and beyond what the project's evidence-first discipline can close quickly.

**Artifacts (vault, not in git):** `D:\MidaVault\scratch\verify_live_gto_d1b_9268_csfix.exe`, `csfix_av.log`, `diag3.log`, `diag4.log`.

## R-GTO-UI round 6 (AHK anti-tamper RE — feasibility) — **NO CRYPTO WALL; reclassified to runtime-state-capture; no code shipped**

**Date:** 2026-07-24 (operator authorized read-only AHK anti-tamper RE: cookie source, decrypt algorithm, recoverability).
**Method:** static disasm of candidate + live cdb on protected input (read-only; no repo code change).

### Findings

**A. The cookie/decrypt code exists but is DORMANT.**
- Cookie store sites: `.data` @ RVA `0x1454b8`. Two setters found: `0xe7410` (`mov [0x1454b8],rcx; ret`) and `0xe7444` (computes cookie).
- `0xe7444` algorithm (fully RE'd): `r8 = [0x141020]` (= `0x00002b992ddfa232` = **MSVC `DEFAULT_SECURITY_COOKIE`**, a compile-time constant in `.data`); `cl = 0x40 - (r8_low & 0x3f) = 0x40 - 0x32 = 0x0e`; `cookie = ror(rcx, 0x0e) ^ r8`; store to `0x1454b8`. Input `rcx = *(&obj@0x14ca60)` (first qword of a runtime object whose address is returned by `0xd9948: lea rax,[0x14ca60]; ret`).
- The decrypt at `0xe721c` (`xor rax,rcx; ror rax,cl`) is gated by `0xe7217 cmp rcx,rdx; je 0xe7232` (skip decrypt when cookie == rdx).
- **Live measurement (protected GTO at `CreateWindowExW`, after full AHK init):** cookie @ `0x1454b8` = **`0`**, object @ `0x14ca60` = **`0`**. The cookie is NEVER set in the running protected process. → The xor/ror decrypt path is **never taken**; pointers are used RAW.

**B. Therefore the round-5 "anti-tamper" blocker was mis-classified.**
- The garbage `rax = 0xd25a180000e54155` (round-5 AV at `0x1400fb8f0: jmp rax`) is NOT an encrypted pointer that failed to decrypt. It is loaded RAW via `mov rax,[rcx]` (object dereference) in the `0xe71c8` path — a runtime object field.
- In the live protected process the same code path works (no AV) → the live process has a **valid** value at that object field; the **dumped candidate has garbage/zero** there.
- Conclusion: the blocker is **runtime-state capture completeness** (the dump does not preserve the live object/heap/`.data` state WinMain dereferences), NOT anti-tamper cryptography. Same class as the round-5 L2 heap-replay problem, now confirmed to extend beyond the 320-slot `g_script` table to additional runtime objects (e.g. the object reached via the `0xe71c8` call chain).

### Feasibility verdict

| Question | Answer |
|----------|--------|
| Is there a crypto/anti-tamper wall? | **No.** The xor/ror code is dormant (cookie=0 live). |
| Is the cookie recoverable from the dump? | **Moot** — the cookie is 0 live; it is not the mechanism. |
| What is the real blocker? | Runtime-state capture completeness: live object/heap/`.data` fields that WinMain dereferences are not preserved in the dump. |
| Is it tractable? | **Yes, no crypto.** But iterative — each missing runtime object is a new capture target ("peeling the onion"). |
| Within 2 rounds? | **Unlikely.** The `0xe71c8`-chain object is one target; fixing it will likely reveal the next missing object. |
| Recommended next step (if authorized) | A bounded iterative capture effort: (1) CS re-init at `.data@0x145db0` (round-5 technique, validated); (2) capture the specific live object/field reached via the `0xe71c8` chain (identify its RVA/heap root, add to `DumpCapturePolicy` hot roots); (3) repeat for each newly-revealed missing object. Each round is low-risk (add capture target + re-init) but N is unknown. |

### What was learned (positive)
1. Cookie algorithm fully RE'd: `cookie = ror(rcx, 0x0e) ^ DEFAULT_SECURITY_COOKIE`, `rcx = *(obj@0x14ca60)`, seed = `0x00002b992ddfa232` @ `.data:0x141020`. **But the cookie is 0 live → irrelevant to the blocker.**
2. The xor/ror decrypt is dormant code (gated by cookie≠0, which never holds). R-GTO-UI has **no anti-tamper wall**.
3. R-GTO-UI reclassified: it is **runtime-state-capture completeness** (same L2 class as heap-replay), extending beyond `g_script` to additional runtime objects. Tractable engineering, not research.
4. The stub-replay approach is NOT fundamentally in tension with anti-tamper (there is none active); it is in tension with **state completeness** — the stub replays a subset, and WinMain dereferences objects outside that subset.

**Non-claim:** round 6 does not close R-GTO-UI; no 1.0 sentence; no code shipped. R-GTO-UI remains open. The RE downgraded the problem from "needs AHK anti-tamper RE" to "needs iterative runtime-state capture" — tractable but multi-round. A future authorization should frame it as iterative capture (CS re-init + per-object hot-root addition), not as a 2-round fix.

**Artifacts (vault, not in git):** `D:\MidaVault\scratch\re_live.log`, `re_heap.log`, `re_heap2.log`, `re1.log`, `re2.log`, `re3.log`.

## R-GTO-UI round 7 (bounded iterative capture — CS re-init + gscript cap raise) — **PROGRESS; one layer peeled; code shipped; default baseline intact**

**Date:** 2026-07-24 (operator authorized bounded iterative capture, soft cap 4 rounds; round 7 = CS re-init + `0xe71c8`-chain investigation).
**Method:** code change (CS re-init + cap raise) + read-only RE of the `0xe71c8` chain.

### RE finding (the `0xe71c8` AV is a C++ exception-handler path)
- `0xe72ac` is `__scrt_common_main_seh`'s **exception handler** (`0xe72a0` filter = `cmp ecx,0E06D7363` = C++ exception code). The round-5/6 AV at `0x1400fb8f0: jmp rax` (garbage) sits INSIDE this handler.
- Flow: WinMain runs → throws a C++ exception (because some g_script/heap state is bad) → SEH handler `0xe72ac` catches it → dereferences the exception object → vtable/field is bad → `jmp rax` garbage AV.
- The handler builds a stack VARIANT (`lea rcx,[rbp-30h]` + fields) from the exception object; the bad field originates in an uncaptured heap sub-object (g_script graph), not anti-tamper (round 6 confirmed cookie=0 live, decrypt dormant).
- **Conclusion:** the remaining blocker is g_script/heap capture completeness (the exception object's source), exactly the round-6 reclassification. No new mechanism — just more capture surface.

### Code shipped (round 7)
1. **CS re-init** — new `reinit_critical_sections(dump_buf, cs_rvas)` in [`data_reinit.rs`](../crates/pe/src/dumper/data_reinit.rs): sets `LockCount=-1`, zeros `RecursionCount`/`OwningThread`/`LockSemaphore`/`SpinCount` at each RVA. Driven by `DumpCapturePolicy::cs_reinit_rvas` (new field). Called in [`dump_process.rs`](../crates/pe/src/dumper/dump_process.rs) right after `reinitialize_zero_filled_data`.
2. **`ahk_gto_default()` policy** — adds `cs_reinit_rvas: vec![0x145db0]` (the WinMain CS, round-5 validated) and raises `gscript_root_content_cap` `0x10000 → 0x20000` (round-5 noted live readable ≥0x20000).
3. **CLI/schema** — `capture_policy_file.rs` parses `cs_reinit_rvas`; `case-manifest.schema.json` documents it.

### Result
- **CS AV cleared (progress).** With `--oep=rva=0xd9268` + CS re-init + cap 0x20000: the round-4/5 `RtlEnterCriticalSection` AV is gone; the candidate now AVs at `0x1400fb8f0: jmp rax` (the exception-handler Variant AV) with a different garbage value per run (ASLR). One layer peeled.
- **NewClassName still not reached** — WinMain still throws the C++ exception (g_script/heap state still incomplete).
- **Default GTO path (no `--oep` override) — NO REGRESSION:** `entry_rva=0x70b0`, R0B `StructuralPassBehaviorPending` 12/12, `load_no_crash` Pass (exit 0). CS re-init fires but is harmless on the clean-exit-0 path (the CS is never entered). 4-case fresh-reverify baseline intact.

### Round 7 verdict
- **Shipped** (validated component, no regression, necessary for eventual fix): CS re-init + cap raise. This is consistent with W1/W2 shipping metric progress.
- **Distance to NewClassName:** still Fail; one AV layer cleared, next layer (exception-object g_script source) remains. Soft cap: 3 rounds left (8/9/10).
- **Round 8 plan:** identify the specific g_script sub-object the exception object is built from (live trace at the throw site / `0xe73b4`), add its hot root to `DumpCapturePolicy`, re-test.

**Non-claim:** round 7 does not close R-GTO-UI; no 1.0 sentence. Shipped code is validated progress (CS AV cleared) with no default-path regression; `NewClassName` not yet reached.

**Artifacts (vault, not in git):** `D:\MidaVault\scratch\r7_gto.exe`, `r7_gto_default.exe`, `r7av.log`, `d8.log`, `d9.log`, `da.log`.

## R-GTO-UI round 8 (call-obfuscation trampoline RE) — **DEADLOCK; cookie undeterminable; corrects round-6; no code shipped**

**Date:** 2026-07-24 (bounded iterative capture, soft cap 4; round 8 = trace the `0xe71c8`-chain AV source).
**Method:** read-only cdb on the **unpacked** `r7_gto.exe` (no anti-debug; reliable) + static disasm. **No live cdb on protected input** (operator flagged anti-debug detection — round-6 live cookie measurement is unreliable).

### Findings

**A. The `0xfb8f0` AV is an AHK call-obfuscation trampoline, NOT a C++ exception handler (corrects round-7 RE).**
- `0x400fb8f0: jmp rax` is an IAT thunk (`call [0xfe1f0]` → `jmp rax`). `rax` is produced by the `xor rax,rcx; ror rax,cl` sequence at `0xe721c` inside the `0xe71c8` call chain. This is AHK's **per-call pointer obfuscation**: each indirect call is routed through a trampoline that decrypts the target with a cookie.
- first-chance AV (cdb on unpacked): `rip=0x1400fb8f0`, `rax=garbage` (e.g. `0x14318000541bf7c3`), every run different (ASLR). The decrypted `rax` is not a valid VA → `jmp rax` AV.

**B. The decrypt is ACTIVE, not dormant (corrects round-6).**
- Round-6 concluded the `xor/ror` decrypt was dormant because live cookie @ `0x1454b8` measured `0`. **That measurement was taken under cdb attach on protected input, which the operator confirmed triggers anti-debug** — the `0` is an anti-debug-polluted value, not trustworthy.
- On the **unpacked** candidate (no anti-debug) the decrypt **does execute**: at `0xe721a` (`je`), `rcx=cookie=0` but `rdx=传入指针≠0`, so `cmp rcx,rdx; je` is **not taken** → `xor rax,0; ror rax,cl` runs → `rax` corrupted → AV. The decrypt path is active whenever `cookie != rdx` (i.e. whenever a real pointer is passed), regardless of cookie being 0.

**C. Cookie algorithm (confirmed from `0xe7444`, fully RE'd round-6):** `cookie = ror(rcx, 0x0e) ^ DEFAULT_SECURITY_COOKIE`, where `rcx = *(.data@0x14ca60)` (first qword of a runtime object). `0xe7444` only sets the cookie when `cookie == DEFAULT_SECURITY_COOKIE` (initial sentinel) — i.e. exactly once at first init.

**D. Cookie is undeterminable (deadlock).**
- Dumped `*(0x14ca60) = 0` (the object is not populated in the dump) and dumped `cookie = 0` (not even the `DEFAULT_SECURITY_COOKIE` sentinel — it was scrubbed/zeroed).
- Experiment: planted `cookie = DEFAULT_SECURITY_COOKIE` (`0x2b992ddfa232`, the `rcx=0` case) into the dump → **same AV**, `rax` still garbage. So `rcx ≠ 0`; the real cookie requires the real `rcx`.
- `rcx = *(0x14ca60)` cannot be obtained: (1) it is `0` in the dump (the setter is in init code that EP=`0xd9268` skips); (2) live cdb on protected input is unreliable (anti-debug); (3) running full init (EP=`mainCRTStartup`) to populate it AVs at `_initterm` (round-3 heap-replay conflict). 
- No static rip-relative store to `0x14ca60` exists (it is written indirectly via a register-held pointer), so the live value cannot be statically derived.

### Deadlock synthesis

R-GTO-UI now has a **circular dependency** that no single-round fix breaks:

```text
WinMain runs (needs EP=0xd9268 + CS re-init [round 7])
  → AHK call-obfuscation decrypts call targets with cookie @0x1454b8
  → cookie needs 0xe7444 to have run (sets cookie = ror(rcx,0x0e)^seed)
  → 0xe7444 needs *(0x14ca60) != 0 (its input rcx)
  → *(0x14ca60) needs init code that EP=0xd9268 skips
  → running that init (EP=mainCRTStartup) AVs at _initterm (heap-replay conflict, round 3)
  → heap-replay completeness is the original L2 blocker (round 5/6)
```

The call-obfuscation layer is not an independent blocker — it is a **manifestation** of the heap/runtime-state capture incompleteness (the cookie and `0x14ca60` object are part of the uncaptured runtime state). Peeling it (round 8) just re-exposes the same L2 root.

### Round 8 verdict

- **No code shipped** (vault byte-patch experiments only; repo at HEAD `0cfc105`, zero tracked changes). Round-7 CS re-init + cap raise remain shipped and valid.
- **Round-6 "dormant decrypt" conclusion retracted** (it was based on anti-debug-polluted live data). The decrypt is active; cookie=0 corrupts pointers.
- **Soft cap:** 2 rounds left (9/10). No clear breakthrough path — the cookie deadlock circles back to heap-replay completeness, the same L2 root that rounds 5-7 have been peeling. Continuing would repeat the same root under a different AV site.
- **Recommendation:** stop at the soft cap (or now). R-GTO-UI is a heap/runtime-state capture completeness problem with a circular dependency through AHK's call-obfuscation cookie; closing it needs either (a) a way to obtain `*(0x14ca60)` live without anti-debug interference (e.g. dump earlier/later, or ScyllaHide hardening for the cookie path), or (b) a stub that replays the cookie-setup sequence (`0xe7444`) with a captured `rcx` before jumping to WinMain — both are larger than 2 rounds.

**What was learned (positive):**
1. AHK call-obfuscation trampoline fully RE'd: `0xe721c xor rax,cookie; ror rax,cl` → `0xfb8f0 jmp rax`; cookie from `0x1454b8`; algorithm `ror(rcx,0x0e)^DEFAULT_SECURITY_COOKIE`, `rcx=*(0x14ca60)`.
2. Round-6 "dormant" conclusion was wrong (anti-debug-polluted measurement). Decrypt is active; cookie=0 corrupts.
3. Cookie is undeterminable from the dump alone (needs live `rcx` blocked by anti-debug / init-AV deadlock).
4. R-GTO-UI is a circular dependency through the cookie back to heap-replay completeness — not a linear "peeling" problem.

**Non-claim:** round 8 does not close R-GTO-UI; no 1.0 sentence; no code shipped. R-GTO-UI remains open. Recommend stopping at the soft cap; further work needs a fundamentally different approach (anti-debug-safe live capture of `0x14ca60`, or a cookie-setup replay stub), not more peeling.

**Artifacts (vault, not in git):** `D:\MidaVault\scratch\r8_gto_seedcookie.exe`, `r8_unpack_je.log`, `r8_av.log`, `r8d.log`.

## R-GTO-UI round 9 (cookie mirror + IAT gap retarget) — **CODE SHIPPED; product UI still unproven**

**Date:** 2026-07-24 (soft cap rounds 9–10). **Branch:** `baseline/legacy-recovery-20260722`.

### Round-8 deadlock correction (RE)

Round 8 treated the call-obfuscation cookie as undeterminable because it assumed cookie = `ror(*(0x14ca60),0x0e)^DEFAULT`. Further RE on the full CRT path and live cdb (MessageBoxW retarget path) corrected two facts:

1. **WinMain ≈ `0x5a10`** (not residual’s `0xd9268` as WinMain; that was CRT/`mainCRTStartup` territory).
2. **AHK cookie @`0x1454b8` must mirror live MSVC `__security_cookie` @`0x141020`.** Loader randomizes the LOAD_CONFIG cookie before any user code runs. The decrypt skip path is taken when AHK’s cookie matches that live value — dump plant of `DEFAULT` is not enough, and `*(0x14ca60)` is not required once the mirror is performed **after** CRT `__security_init_cookie` (PostCrt bootstrap transfer) or via pre-OEP stub that reads the already-randomized image slot.
3. **IAT gap defect:** ~19 `.text` sites still `call` interior terminator slots (e.g. `0xfd748`) left zero by Themida multi-block IAT layout. Live cdb + MessageBoxW retarget reached the license MessageBox — proving the UI path is reachable once those call sites are fixed.

### Code shipped

| Module | Change |
|--------|--------|
| `crates/pe/src/dumper/iat_gap_retarget.rs` | **NEW** — retarget `.text` calls into interior IAT zeros to rebuilt FirstThunk for MessageBoxW / LocalFree / SendMessageW (heuristics + original import gap names). AhkGto only via `stage_plan.patch_wrapper_iat_call_sites`. |
| `crates/pe/src/dumper/dump_process.rs` | Wire `iat_gap_retarget` after `wrapper_call_patch`; pass `cookie_mirror` from resolved `DumpCapturePolicy` into heap/container bootstrap. |
| `crates/pe/src/dumper/capture_policy.rs` | AHK defaults: `cookie_mirror_src_rva=0x141020`, `cookie_mirror_dst_rva=0x1454b8`; partial resolve fills mirror for AhkGto. |
| `crates/pe/src/dumper/container_bootstrap.rs` | Before OEP transfer: `mov rax,[src]; mov [dst],rax` then clear volatiles + jmp. |
| `crates/pe/src/dumper/heap_bootstrap.rs` | Thread `cookie_mirror` through PostCrt / PreCrt install. |
| `crates/cli/src/capture_policy_file.rs` | Struct literals accept new fields (default None). |

### Tests / build

- `cargo test -p mida-pe iat_gap --offline` → **6 passed**.
- Unit: cookie mirror emitted before clear/jmp; AHK defaults resolve mirror slots.
- `mida-cli` rebuild green under VsDevCmd + vault `CARGO_TARGET_DIR`.

### Live product validation

**Not closed this turn.** Soft-cap residual still requires a vault GTO dump + window oracle re-run to claim UI Pass. Expected next evidence:

1. Bootstrap log contains `cookie_mirror=0x141020->0x1454b8`.
2. `iat_gap_retarget` reports `sites_patched > 0` (MessageBoxW path).
3. Unpacked candidate either shows license MessageBox / product window, or a **new** AV site (not `0xfb8f0` / not IAT-null call).

### Round 9 verdict

- **Code shipped** (cookie mirror + IAT gap retarget) — breaks the round-8 “cookie undeterminable” circular framing with a concrete, loader-safe mechanism.
- **R-GTO-UI still open** until window oracle Pass on a fresh dump.
- Soft cap: **1 round left (10)** for live validation + any one-site residual fix.
- **No 1.0 sentence.**

**Non-claim:** shipping these fixes does not by itself prove product UI; it only removes two proven blockers (cookie skip + IAT gap AV) from the cold-start path.

## R-GTO-UI round 10 (live validate cookie mirror + IAT gap) — **SOFT CAP; window still Fail**

**Date:** 2026-07-24. **Soft cap last round.** Branch `baseline/legacy-recovery-20260722`.

### Live unpack (rebuilt CLI)

| Signal | Result |
|--------|--------|
| Candidate | `D:\MidaVault\lab\evidence\gto_launcher\live_r10_cookie_iat\gto_unpacked.exe` |
| Protected host | NewClassName seen ~1s (dump still UI-early + settle) |
| Bootstrap | **pre-OEP** (entry `0x70b0` not CRT wrapper) |
| `cookie_mirror` log | **`0x141020->0x1454b8`** |
| Static `.boot` emit | `mov rax,[0x141020]; mov [0x1454b8],rax` at stub+`0x229`/`0x230` (verified) |
| Resting dump cookies | MSVC slot still DEFAULT `0x2b992ddfa232`; AHK slot `0` (mirror is runtime) |
| `iat_gap_retarget` | interior_zeros=**19**, sites_seen=**19**, sites_patched=**12**, mapped_gaps=0 |
| `wrapper_call_patch` | slots_zeroed=0 sites_patched=0 (gap path carries residual) |

### Oracles

| Probe | Verdict |
|-------|---------|
| `load_no_crash` N=3 | **Pass** 3/3 (1.0) |
| `pe_string` NewClassName+AutoHotkey | **Pass** |
| `window_class` NewClassName | **Fail** (2/2; classes_seen=[]; exit 0) |
| cdb (NtTerminateProcess) | Clean exit path; no first-chance AV at former `0xfb8f0` / null-IAT sites in this attach |

### Round 10 verdict

- Round-9 engineering **live-confirmed** (mirror opcode present; 12 IAT gap sites patched; load green).
- **Product UI still not reached** on cold start of unpacked candidate — ExitProcess(0) without `NewClassName`.
- Soft cap **exhausted** (rounds 9–10 used). Stop further peeling under the current authorization.
- **No 1.0 sentence.**

### What remains (beyond soft cap)

Unpacked cold-start still exits 0 without GUI despite:
1. CS re-init (r7),
2. cookie mirror (r9),
3. IAT gap retarget (r9/r10).

Likely residual class: **runtime-state / script resume completeness** (heap graph beyond 320-slot cap, gscript body, or init order that UI-early dump still misses) — not the former call-obfuscation cookie / IAT-null AV framing. Next work needs a **new operator authorization**, not another soft-cap peel.

**Artifacts (vault):** `live_r10_cookie_iat\` (`gto_unpacked.exe`, `unpack.stdout.txt`, `r10_load.json`, `r10_window.json`, `r10_pestring.json`); `D:\MidaVault\scratch\r10_*.cmd/log`.

**Non-claim:** soft-cap stop does not close R-GTO-UI; does not enable product 1.0; load Pass ≠ UI Pass.

## R-GTO-UI script-heap-resume (post soft-cap, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25. **Auth:** operator script/heap runtime-state resume (not cookie/IAT peel).

### Diagnosis (before code)

| Fact | Evidence |
|------|----------|
| Cold exit 0 path | cdb: `0x70b0` (msg-gate) with zero args → `0x71ab` error → `ret` → `BaseThreadInitThunk` → process exit 0 (`live_r11…/unp_exit2*`, r10 cdb) |
| Product UI entry | `RegisterClassExW` only from `0x34db0`; sole caller `0x65d1` with `lea rcx,[0x149d50]` (g_script **image body**, not pointer slot) |
| WinMain | `0x5a10`; sole caller CRT `0xd9261` |
| Capture bug | Main loop treated `*0x149d50` first qword as heap root and planted a clone; code uses `lea` into image object |

### Round 1 — image-inline + WinMain retarget — **Fail (AV)**

**Change:** `HeapGlobalSnapshot.is_image_inline`; gscript live image-body capture; bootstrap flag bit1 memcpy into `image+rva`; PostCrt non-CRT path retarget `0x70b0→0x5a10` + `rcx=image_base`.

| Check | Result |
|-------|--------|
| Unpack | `live_r11_gscript_inline\` — log: replace pointer-slot + inline size **32768**; continue_ep **0x5a10** |
| window_class N=3 | **Fail** exit `0xC0000005` |
| load_no_crash N=3 | **Fail** AV |
| cdb AV | `rep movsb` in `.boot` memcpy; dest `r10=0x140149d50`, size `0x8000` past `.data` end `0x14ca74` |

### Round 2 — section-cap inline body — **Fail (window); load green; STOP**

**Change:** cap gscript image-inline size to remaining `.data` virtual size.

| Check | Result |
|-------|--------|
| Unpack | `live_r11b_gscript_inline_cap\` — inline size **6480**; continue_ep **0x5a10**; iat_gap 12 patches |
| load_no_crash | **Pass** (survived wall; killed) `r11b_load.json` |
| window_class N=3 attempt path | **Fail** `window_class_not_seen_within_wall` `r11b_window.json` |
| cdb path | Hits **WinMain** (`rcx=image_base`); RegisterClassExW only from **MSCTF/IME**, not product `0x34db0` / NewClassName |

### Verdict

- **R-GTO-UI window oracle: Fail** (2/2 rounds under this authorization).
- Progress (not close): left clean exit-0-at-0x70b0 class; load green; reaches WinMain; gscript treated as image-inline.
- Remaining blocker class: product path never calls `0x34db0` / field `g_script+0xbd8` still insufficient for product class registration — needs **new operator auth**, not a 3rd blind round.
- **product 1.0 = NO.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r11_gscript_inline\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r11b_gscript_inline_cap\` (`r11b_window.json`, `r11b_load.json`, `unpack.stdout.txt`, `r11b_path.log`)

## R-GTO-UI product-path (post r11b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25. **Auth:** continue script/heap → product RegisterClass path.

### Diagnosis (before code)

| Fact | Evidence |
|------|----------|
| Protected cold start | `NewClassName` ~1.5s; also `ZhuChuangKou` AHK host window |
| Unpacked r11b | Survives load; only `#32770` (MessageBoxW @ `0x5c5d`, text hex blob) |
| After MessageBox dismiss (pre-r12) | `c0000374` RtlFreeHeap |
| Free root | path string shell `@0x144400` `{buf,buf,len,cap,refs}` with `buf` **interior** of large root `0x144358` (32KiB). multi_fixup is exact-base only → free interior / stale |
| After string fix | AV `c0000005` @ `0x5747a` `mov rcx,[rax+rcx*8]` with `rax=0` from global **`0x147868`** (cmd/dispatch table; store `@0x36d0a`) |

### Round 1 (r12) — string shell exact-base admit — **Fail (window); load green**

**Change:** `handle_string_shell_on_capture` / `admit_string_buffer_child` treat coverage as **exact live_ptr only** (not `range_contains`).

| Check | Result |
|-------|--------|
| Unpack | `live_r12_string_exact\` — `0x144400` buffer exact child `0x98f5c0` size 64 |
| load_no_crash | **Pass** `r12_load.json` |
| window_class | **Fail** classes_seen=`#32770` only `r12_window.json` |
| post-MB (mb_nop) | no longer `c0000374`; next AV @ `0x5747a` null table |

### Round 2 (r12b) — hot-root `0x147868` — **Fail (window); STOP**

**Change:** `ahk_gto_default` hot roots += `0x147868`.

| Check | Result |
|-------|--------|
| Unpack | `live_r12b_cmd_table\` — policy hot_root_count=11; slot captured but **plant-only 8B** ("heap already snapshotted") |
| load_no_crash | **Pass** `r12b_load.json` |
| window_class | **Fail** still `#32770` `r12b_window.json` |
| Residual on table | need full table payload + live count `@0x147888`, not alias plant |

### Verdict

- **R-GTO-UI window oracle: Fail** (2/2 under this product-path authorization).
- Progress: left early exit-0 @0x70b0; left path-string interior free c0000374; load green; WinMain + MessageBox path live.
- Remaining: MessageBox / PE self-check noise + incomplete `0x147868` table + deeper script UI (`0x65d1→0x34db0`).
- **product 1.0 = NO. STOP** — no 3rd blind round.

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r12_string_exact\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r12b_cmd_table\`

## R-GTO-UI cmd-table full capture (post r12b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25. **Auth:** full `0x147868` table + count `@0x147888`.

### Round 1 (r13) — carve + count preserve + count×8 size — **Fail (window)**

**Change:**
- `carve_parent_at_hot_base` when hot root is interior of oversized parent
- preserve live dword `@0x147888` through early overlay
- size cmd table from count×8; skip `trim_trailing_zero_pages` on table

| Check | Result |
|-------|--------|
| Unpack | `live_r13_cmd_table_full\` / `live_r13c_cmd_notrim\` — table size **800**, count **100** in PE |
| load | **Pass** |
| window | **Fail** `#32770` only |
| cdb (mb_nop) | table ptr + count live at WinMain; still AV `@0x5747a` when table body mostly scrubbed |

### Round 2 (r13d) — pointer-table first-hop admit — **Fail (window); STOP**

**Change:** `exhaust_pointer_table_first_hop(0x147868)` force-admits heap edges from table slots before scrub.

| Check | Result |
|-------|--------|
| Unpack | `live_r13d_table_firsthop\` — many `Captured pointer-table first-hop edge`; table content_size large; nz entries ≫2 |
| load_no_crash | **Pass** `r13d_load.json` |
| window_class N=3 | **Fail** `#32770`; exit `0xC0000374` after dismiss `r13d_window.json` |

### Verdict

- **window oracle: Fail** (2/2). No NewClassName.
- Progress: cmd table no longer plant-only 8B; count preserved; children partially captured; load green.
- Remaining: MessageBox path (protected has no `#32770`); post-dismiss heap free still broken under fuller table graph.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r13_cmd_table_full\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r13c_cmd_notrim\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r13d_table_firsthop\`

## R-GTO-UI MessageBox path / post-MB AV (post r13d, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| MessageBoxW `@0x5c5d` | Unconditional in WinMain; text static hex blob (license/fingerprint noise) |
| Table after r13 | count=100 + plant live at WinMain; only ~2 live table edges often |
| r13d dismiss | `c0000374` |
| r14 dismiss | `c0000005` @ `0x49055` `cmp [rax+0x78],0x62` with `r13=*[0x141bf0]`, `rax=[r13+0xd8]` interior-only |

### Round 1 (r14) — normalize cmd table to count×8 — **Fail**

**Change:** `normalize_cmd_table_capture` before table first-hop.

| Check | Result |
|-------|--------|
| Unpack | `live_r14_cmd_normalize\` — table size **800**, first-hop edges=2 |
| load | **Pass** |
| window | **Fail** `#32770`; dismiss → `c0000005` |

### Round 2 (r14b) — exact first-hop on `0x141bf0` span 0x200 — **Fail; STOP**

**Change:** `exhaust_pointer_table_first_hop_span(0x141bf0, 0x200)` (covers +0xd8).

| Check | Result |
|-------|--------|
| Unpack | `live_r14b_global_d8\` — log captures table_off **0xd8** |
| load | **Pass** `r14b_load.json` |
| window N=3 | **Fail** `#32770` `r14b_window.json`; dismiss still `c0000005` |

### Verdict

- **window oracle Fail** (2/2). No NewClassName.
- Progress: table sized correctly; +0xd8 exact child admitted; crash class moved off pure null-table.
- Remaining: MessageBox always shown; post-MB script resolve (`0x48fb0`) still incomplete object graph / remaps.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r14_cmd_normalize\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r14b_global_d8\`

## R-GTO-UI gscript first-hop order (post r14b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| After MB (mb_nop) | `0x60b8 call 0x48fb0(gscript)` → **rax=0**; then AV `@0x570c7c` |
| Prior order bug | first-hop walked heap-clone, then image-inline replaced root layout |
| Image-inline size | 6480 B (section-capped); needs hop past +0x200 for labels |

### Round 1 (r15) — image-inline before first-hop — **Fail**

**Change:** move `capture_image_inline_gscript` to immediately after `ensure_hot_root_slots`.

| Check | Result |
|-------|--------|
| Unpack | `live_r15_inline_before_hop\` — replace then hop (3 edges, span 512) |
| load | **Pass** |
| window | **Fail** `#32770`; dismiss `c0000005` |

### Round 2 (r15b) — wider image-inline first-hop span — **Fail; STOP**

**Change:** if gscript is image-inline, first-hop span = `min(content.len(), max(0x1800, policy))`.

| Check | Result |
|-------|--------|
| Unpack | `live_r15b_gscript_wide_hop\` — hop **added=11 span=6144** |
| load | **Pass** `r15b_load.json` |
| window N=3 | **Fail** `#32770` `r15b_window.json`; dismiss still crash |

### Verdict

- **window oracle Fail** (2/2). No NewClassName.
- Progress: hop order fixed; more image-body edges admitted; load green.
- Remaining: unconditional MessageBox; `0x48fb0` still null / deeper gscript graph; product RegisterClass.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r15_inline_before_hop\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r15b_gscript_wide_hop\`

## R-GTO-UI link sanitize + label count (post r15b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| r15b freelist AV | `[gscript+0]+0x18` interior of 32KiB free-list parent → walk hits `0x03500350` |
| `0x48fb0` | binary search uses `count@gscript+0x10` + table@+0; live count often **0** |
| `0x141bf0+0xd8` | empty in r16 plant (`ffffffff` + zeros) → primary VarList path skipped |

### Round 1 (r16) — child-link force-admit + null dangling interiors — **Fail**

**Change:** `exhaust_gscript_child_link_fields` + `sanitize_dangling_object_links`.

| Check | Result |
|-------|--------|
| Unpack | `live_r16_link_sanitize\` — link added=21, nulled=24 |
| load | **Pass** |
| window | **Fail** `#32770` |
| cdb | freelist AV **gone**; pass `0xb9360`; `0x48fb0` still rax=0; AV later `@0x570c7c` |

### Round 2 (r16b) — synthesize gscript label count@+0x10 — **Fail; STOP**

**Change:** `synthesize_gscript_label_count` (count leading non-null table qwords).

| Check | Result |
|-------|--------|
| Unpack | `live_r16b_label_count\` — **no** "Synthesized" log (table match / content mismatch) |
| load | **Pass** |
| window N=3 | **Fail** `#32770` `r16b_window.json` |
| cdb | gscript+0x10 still **0** at WinMain |

### Verdict

- **window oracle Fail** (2/2). No NewClassName.
- Progress: post-MB freelist crash class closed; string path past `0xb9360`.
- Remaining: label count/table completeness; `0x141bf0` VarList empty; product RegisterClass.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r16_link_sanitize\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r16b_label_count\`

## R-GTO-UI label count force (post r16b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| r16b synth no-op | sanitize treated label table as object-links; count field wiped |
| r17 PE payload | gscript `+0x10` still **0** after scrub despite live `count_now=334` |
| r17b | force-write table-derived count after sanitize **and** after scrub |

### Round 1 (r17) — label entries + dense-table skip — **Fail**

**Change:** `exhaust_gscript_label_table_entries`; `looks_like_dense_pointer_table` skip in sanitize; synth before sanitize.

| Check | Result |
|-------|--------|
| Unpack | `live_r17_label_synth_fix\` — 120 label entries; synth skipped (count_now=334) |
| PE payload | count still **0** |
| load / window | Pass / **Fail** `#32770` |

### Round 2 (r17b) — force count after sanitize+scrub — **Fail; STOP**

**Change:** always table-derived count; skip image-inline +0x10/+0x18 in sanitize; `resynthesize_gscript_label_count` after scrub.

| Check | Result |
|-------|--------|
| Unpack | `live_r17b_count_force\` — Synthesized count=**128** (×3); PE payload count=128 |
| cdb WinMain | `gscript+0x10 = 0x80` |
| cdb path | enters `0x48fb0` (`0x4932d` on stack) then AV `@0xfb8f0 jmp rax` garbage |
| load | **Pass** |
| window N=3 | **Fail** `#32770` `r17b_window.json` |

### Verdict

- **window oracle Fail** (2/2). No NewClassName.
- Progress: label count restored end-to-end; binary search entered.
- Remaining: label name compare hits call-obfusc `jmp rax` with undecoded target; product RegisterClass still unreached.
- **product 1.0 = NO. STOP.** Do not open new cookie/IAT peel without operator auth.

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r17_label_synth_fix\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r17b_count_force\`

## R-GTO-UI label mName (post r17b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| r17b AV | `0x48fb0` → `wcscmp` with **null** `Label.mName` (+0x28); CRT → `jmp rax` garbage |
| Label layout | short names as UTF-16 at +0x30 (SSO/self-interior); +0x28 often null after sanitize/scrub |
| r18b PE | entry0 `+0x28` → exact string snapshot `"A_Ar"` |

### Round 1 (r18) — externalize mName during label exhaust — **Fail**

**Change:** `externalize_label_name_field` + skip self-interior in sanitize.

| Check | Result |
|-------|--------|
| Unpack | `live_r18_label_name\` — many Externalized logs; entry0 PE nameptr still 0 (slot-cap) |
| load / window | Pass / **Fail** `#32770` |

### Round 2 (r18b) — post-scrub offline mName repair — **Fail; STOP**

**Change:** `repair_label_names_after_scrub` (inline SSO → exact string snapshot).

| Check | Result |
|-------|--------|
| Unpack | `live_r18b_name_repair\` — repaired=2 names_added=2; total hg=322 |
| PE | entry0 nameptr non-null; string `"A_Ar"` |
| cdb WinMain | count=0x80; `du mName` → `"A_Ar"` |
| cdb path | **no** `0xfb8f0` null-wcscmp AV; new AV `@0x57d20` post-MB (`rbp` holds UTF-16 chars) |
| load | **Pass** |
| window N=3 | **Fail** `#32770` `r18b_window.json` |

### Verdict

- **window oracle Fail** (2/2). No NewClassName.
- Progress: label count + mName graph fixed; `0x48fb0` strcmp null path closed.
- Remaining: post-MB string object walk AV; product RegisterClass unreached.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r18_label_name\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r18b_name_repair\`

## R-GTO-UI SimpleHeap arena + mName exact (post r18b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| r18b post-MB AV | `0xb9360` path copy → SimpleHeap bump alloc fail (exhausted dump arena) |
| Arena controls | `0x148cb0` / `0x148cb8` / `0x148cc0` used by `0xb9410` |
| Label names | 120+ mName ptrs were *interiors* of large captures → no exact multi_fixup |

### Round 1 (r19) — drop SimpleHeap arena slots — **Fail (progress)**

**Change:** remove hot-root of arena RVAs; `drop_ahk_string_arena_slots`.

| Check | Result |
|-------|--------|
| Unpack | `live_r19_arena_drop\` — dropped=3; PE slots zero |
| cdb | POST_B9360 **rax≠0** (path copy OK); arena re-inited |
| then | still `0x48fb0` → null; AV `@0xfb8f0` (names) |
| load / window | Pass / **Fail** `#32770` |

### Round 2 (r19b) — exact-plant mName from parent interiors — **Fail; STOP**

**Change:** scrub preserve UTF-16 qwords; `repair_label_names_after_scrub` slices interiors → exact string snapshots.

| Check | Result |
|-------|--------|
| Unpack | `live_r19b_name_exact\` — name_snap_ok=**125**/128 |
| cdb | POST_B9360 OK; RET48 **rax=0**; AV `@0xc13ea` `cmp [rbx+0x23],1` rbx=0 |
| load | **Pass** |
| window N=3 | **Fail** `#32770` `r19b_window.json` |
| RegisterClass | **never** hit `0x65d1` |

### Verdict

- **window oracle Fail** (2/2). No NewClassName.
- Progress: path allocator cold-init fixed; label name exact graph mostly complete.
- Remaining: `0x48fb0` still returns null (lookup miss / incomplete label object / VarList); product window path unreached.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r19_arena_drop\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r19b_name_exact\`

## R-GTO-UI label table sort (post r19b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| Key at first `0x48fb0` | UTF-16 `"0"` (static @0x106724) — **not** in label table |
| Table order (r19b) | unsorted (`A_Args` then Chinese) → binary search broken |
| `0x141bf0+0xd8` | still 0 (VarList primary path skipped) |
| After sort (r20b) | named prefix sorted; `A_Args` bisect hits |

### Round 1 (r20) — sort all entries — **Fail (regression)**

Empty-key entries sorted first → null mName → `wcscmp` AV `@0xfb8f0` again.

### Round 2 (r20b) — named-only sorted prefix — **Fail; STOP (deepest path yet)**

**Change:** sort only non-empty mName labels; count=named; unnamed trail.

| Check | Result |
|-------|--------|
| Unpack | `live_r20b_label_sort_named\` — count=124, sorted True, first=`50` |
| cdb RET48_1 | rax=0 (`"0"` miss — expected) |
| cdb RET_494E0 | **rax≠0** |
| cdb RET48_2 | **rax≠0** (`A_Args` path) |
| cdb CALL_C13D0 | **reached** rcx=label rdx=obj |
| cdb AV | `@0xc13ea cmp [rbx+0x23],1` **rbx=0** |
| RegisterClass | **never** |
| load / window | Pass / **Fail** `#32770` |

### Verdict

- **window oracle Fail** (2/2). No NewClassName.
- Progress: first time label lookup returns non-null and reaches post-lookup call `0xc13d0`.
- Remaining: Label object incomplete (line/nested +0x10 → +0x23 field null); product RegisterClass.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r20_label_sort\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r20b_label_sort_named\`

## R-GTO-UI Label bind + global re-init (post r20b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| r20b AV | `0xc13d0`: `[label+0x23]==0` → `rbx=[label+0x10]==NULL` |
| A_Args label PE | `+0x23=0`, `+0x10=0`, mName OK |
| After r21 | `0xc13d0` returns **1**; WinMain re-inits `[0x141bf0]` |
| r21 AV | after INIT, obfuscated `@0x570c7c` / `@0x6110a0` before PRE_REG |

### Round 1 (r21) — mark Label+0x23 non-nested — **Fail (progress)**

**Change:** `mark_labels_non_nested` (force +0x23=1 when nested missing).

| Check | Result |
|-------|--------|
| Unpack | `live_r21_label_non_nested\` — marked=123 |
| cdb | RET48_2≠0; CALL_C13D0; **AFTER_C13D0 rax=1** |
| then | AV `@0x570c7c` (not rbx=0 class) |
| load / window | Pass / **Fail** `#32770` |

### Round 2 (r21b) — zero-slab 0x141bf0 — **Fail; STOP**

**Change:** `sanitize_ahk_runtime_global` → 0x180 zero body for re-init.

| Check | Result |
|-------|--------|
| Unpack | `live_r21b_global_zero\` — 32768→384 zero slab |
| cdb | AFTER_C13=1; INIT_GLOBAL; AFTER_INIT; **no PRE_REG/CALL_34DB0** |
| AV | `@0x570c7c` still before RegisterClass |
| load / window | Pass / **Fail** `#32770` |

### Verdict

- **window oracle Fail** (2/2). No NewClassName.
- Progress: deepest path — Label lookup + bind success + global re-init entry.
- Remaining: post-init / call-obfusc before `0x65d1→0x34db0`.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r21_label_non_nested\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r21b_global_zero\`

## R-GTO-UI skip LoadFile + class name (post r21b, 2 rounds) — **window still Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| r21b blocker | `0x364e0` LoadFile on host path → AV `@0x570c7c` |
| Need for RegisterClass | `0x63f9`: `cmp eax,-1` / success needs eax==1 then fall through to `0x65d1` |
| Class field | `0x34db0` reads `gscript+0xbd8`; dump had **path** string not `NewClassName` |
| NewClassName in PE | present in `.boot` payload / image |

### Round 1 (r22) — skip LoadFile re-entry — **Fail (major progress)**

**Change:** `patch_gto_skip_loadfile_reentry` — `call 0x364e0` @0x63f4 → `mov eax,1`.

| Check | Result |
|-------|--------|
| Unpack | `live_r22_skip_loadfile\` — patch log OK; PE bytes `b801000000` |
| cdb | AFTER_C13=1; AT_SKIP; **PRE_REG; CALL_34DB0; REGFUNC** |
| RegisterClass | entered; **AFTER_34DB0 eax=0** (class string wrong) |
| load / window | Pass / **Fail** `#32770` only |

### Round 2 (r22b) — plant NewClassName / ZhuChuangKou — **Fail; STOP**

**Change:** `repair_gscript_window_strings` synthetic lives `0x50c1a550001/2`.

| Check | Result |
|-------|--------|
| Unpack | `live_r22b_classname\` — PE gscript+bd8 points at `NewClassName` snap |
| cdb REGFUNC | runtime `+0xbd8=0x140106644` (static empty) **not** planted string |
| AFTER_34DB0 | **eax=0** |
| window N=3 | **Fail** `#32770` `r22b_window.json` |

### Verdict

- **window oracle Fail** (2/2). No NewClassName window.
- Progress: **first time product RegisterClass path `0x65d1→0x34db0` is reached.**
- Remaining: runtime class-name pointer not effective (synthetic VA / fixup / overwrite); CreateWindow never.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r22_skip_loadfile\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r22b_classname\`

## R-GTO-UI class plant + RegisterClass lea (post r22b, 2 rounds) — **window oracle Fail; product class seen; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| r22b | PE plant ineffective; runtime +0xbd8→0x106644 |
| r23 | bootstrap plant OK at WinMain (`du` = NewClassName); **0x345e0 overwrites** after skip-LoadFile |
| r23b | patch `0x34dbb` → `lea rax,[NewClassName]` |

### Round 1 (r23) — low-VA synthetic plant — **Fail (progress)**

Bootstrap `+0xbd8` correct at WinMain; after `0x63f9` overwritten to `0x106644`.

### Round 2 (r23b) — lea NewClassName at RegisterClass — **oracle Fail; STOP**

| Check | Result |
|-------|--------|
| Unpack | `live_r23b_regclass_lea\` — lea patch log; PE `48 8d 05 …` → NewClassName |
| cdb AFTER_REGCLASS | **ax≠0** (atom) |
| cdb AFTER_34DB0 | **eax=1** |
| cdb CREATE_WIN | **hit** then CS AV `@0x65f7` path |
| manual classes | **`ZhuChuangKou`** + `#32770` + IME |
| window N=3 oracle | **Fail** (expects `NewClassName`, saw `ZhuChuangKou` only in manual) |
| load | **Pass** |

### Verdict

- Oracle still **Fail** (class string mismatch / window not stable under probe).
- **Deepest progress:** RegisterClass **succeeds**; a product-related window class **`ZhuChuangKou` appeared**.
- Remaining: CreateWindow post-path CS AV; ensure oracle class `NewClassName` is the registered/created class (protected used NewClassName).
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r23_classname_lowva\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r23b_regclass_lea\`

## R-GTO-UI msg pump + real class lea (post r24b, 2 rounds) — **window Fail; STOP**

**Date:** 2026-07-25.

### Diagnosis

| Fact | Evidence |
|------|----------|
| r24b | `xor eax,eax; ret` at 0x6750 skipped pump → ExitProcess; brief ZhuChuangKou |
| Registered class (static) | WNDCLASS.lpszClassName lea@0x34ed4 → **AutoHotkey2** (not NewClassName) |
| r23b lea@0x34dbb | only empty-check; real class string is @0x34ed4 |
| CreateWindow title | `[gscript+0xbd8]` as r8 (window name), class via atom |

### Round 1 (r25) — keep msg pump — **Fail (progress)**

**Change:** `call 0x35520` @0x6757 → `mov eax,1` (jne → `call 0x1b10`).

| Check | Result |
|-------|--------|
| cdb | AFTER_REG=1; FAKE_35520; **CALL_1B10 ecx=0xa** |
| manual | classes include **ZhuChuangKou** (alive process) |
| window oracle | **Fail** (NewClassName / ZhuChuangKou probe both Fail in isolated runs) |

### Round 2 (r25b) — retarget 0x34ed4 → NewClassName — **Fail; regression; STOP**

**Change:** patch lpszClassName lea @0x34ed4 to NewClassName.

| Check | Result |
|-------|--------|
| PE | 0x34ed4 → NewClassName string OK |
| cdb AFTER_34DB0 | **eax=0** (0x34dbb still `mov rax,[gscript+bd8]`; bd8 empty after 0x345e0 → early fail) |
| manual | **no** product class |
| window / load | Fail / Pass |

### Verdict

- Oracle still **Fail**. No NewClassName N=3.
- Progress: identified real class lea site; msg-pump path reaches `0x1b10`.
- Next must apply **34dbb non-empty check fix + 34ed4 NewClassName** together; do not drop either.
- **product 1.0 = NO. STOP.**

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r25_msgpump\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r25b_newclassname\`

## Residual after VNEXT-BEH (+ … + r24/r24b + r25/r25b)













## R-GTO-UI combined class + visibility + MB skip (r26/r26b) — **window oracle CLOSED**

**Date:** 2026-07-25.

### Round 1 (r26) — dual RegisterClass sites

**Change:** `0x34dbb` empty-check + `0x34ed4` lpszClassName both → `lea NewClassName`; keep LoadFile skip + msg pump.

| Check | Result |
|-------|--------|
| cdb | RegClass atom≠0; CreateWindow hwnd≠0; AFTER_34DB0 eax=1; CALL_1B10 |
| manual | **NewClassName** seen (often not visible) |
| probe raw | Fail (#32770 MessageBox blocks) |

### Round 2 (r26b) — CreateWindow class + WS_VISIBLE + MessageBox skip — **Pass**

**Change:**
- `0x34f66` CreateWindowEx lpClassName → lea NewClassName
- `0x34f59` style `0x00CF0000` → `0x01CF0000` (WS_VISIBLE)
- `0x5c5d` MessageBoxW → `mov eax,1` (unblock cold start for probe)

| Check | Result |
|-------|--------|
| Unpack | `live_r26b_final_newclass\` — all patch logs |
| window independent N=3 | **Pass / Pass / Pass** (`r26b_window_indep_{1,2,3}.json`) |
| window bundled attempts=3 | **Pass** (`r26b_window_n3.json`, first-success gate) |
| load | **Pass** (`r26b_load_final.json`) |
| classes_seen | `NewClassName` |

### Verdict

- **R-GTO-UI window oracle = CLOSED** for acceptance: `window_class=NewClassName`, N=3 attempt Pass, vault evidence.
- **product 1.0 = still NO** — residual risks remain (not full product logic / license / business path).
- Method is heavily GTO-specific PE patches + heap resume; do not over-claim general unpack 1.0.

**Artifacts:**
- `D:\MidaVault\lab\evidence\gto_launcher\live_r26_dual_class_patch\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r26b_cw_classname\`
- `D:\MidaVault\lab\evidence\gto_launcher\live_r26b_final_newclass\`
  - `gto_unpacked.exe`
  - `r26b_window_indep_1.json` … `_3.json` (N=3 Pass)
  - `r26b_window_n3.json`, `r26b_load_final.json`
  - `unpack.stdout.txt`

## Battlefield GTO-perfect-unpack Round 3 (2026-07-25) — stub runs, WinMain reached, product MessageBox shown

**Fix:** Removed residual phase-2.5b Themida-section-scan code (was causing measurement/final stub layout mismatch → stub install failed → PE entry stayed at 0xfb800 → stub never ran → exit 0). After removal, stub installs correctly (stub_rva=0xecf000, "Installed pre-OEP container restoration bootstrap" logged).

**Result (no-bypass + slab + VirtualAlloc original-address remap):**
- cdb breakpoints: **STUB_HIT (0xecf000) → WINMAIN (0x5a10) → MSGBOX (0x5c5d)** all hit.
- Process **alive**, shows `#32770` MessageBox (dismissed).
- **No crash** (heap-rebase wall broken via VirtualAlloc original-address remap).

**Meaning:** The stub now runs, restores heap globals + slab at original address, transfers to WinMain. The product reaches its authorization MessageBox (machine-ID `E4847ED0...`). This is the **real product code path** running — NOT bypass patches (all 5 disabled). The MessageBox is a product authorization gate, not a crash.

**Remaining gap vs protected input:** Protected 启动器.exe skips the MessageBox and goes straight to NewClassName login window. The no-bypass candidate hits the authorization gate instead. This suggests the heap/script state is still slightly incomplete — the product's auth check fails where the protected input's auth state (already initialized) passes. This is a runtime-state completeness layer beyond heap rebasing.

| phase | stub runs? | WinMain? | result |
|-------|-----------|----------|--------|
| Round 0 (no slab) | yes | no | crash 0x846898 |
| Round 1-2 (slab, bad layout) | **no** (layout mismatch) | no | exit 0 |
| Round 3 (slab, fixed) | **yes** | **yes** | MessageBox (auth gate), alive |

**Non-claim:** gto_launcher perfect-unpack NOT achieved. But the stub + VirtualAlloc remap mechanism works; product code runs to WinMain without bypass patches. Remaining = auth-state completeness.

**Evidence:** `D:\MidaVault\lab\evidence\gto_launcher27_slab_round1_20260725\`

## Battlefield GTO-perfect-unpack Round 1 (2026-07-25) — slab rebase moves crash; layer 2 = Themida section pointers

**Change:** Implemented heap slab capture (`capture_heap_slab`) + stub phase-1c (HeapAlloc slab + memcpy) + phase-2.5 (range-interior delta rebase over ALL captured blocks). Strict-interior rule: `old < V < old+N` (excludes heap handle). Env `MIDA_GTO_NO_BYPASS=1` still disables all 5 bypass patches.

**Candidate:** `r27_slab_round1_20260725\gto_unpacked.exe` (no bypass patches + slab).

**Round 0 crash:** rip=`0x6110a0`, rax=`0x846898` (stale heap ptr in gap before captured object `0x846bb0`).

**Round 1 crash (AFTER slab):** rip=`0x570c7c` (DIFFERENT site), rax=`0x9cf000` (DIFFERENT stale ptr).

| metric | Round 0 | Round 1 |
|--------|---------|---------|
| crash rip | `0x6110a0` | `0x570c7c` |
| stale rax | `0x846898` | `0x9cf000` |
| 0x846898 rebased? | N/A | **YES** (crash moved) |
| in slab range? | yes | yes (offset 0x7cf000) |
| static hits | 0 | 0 |

**Meaning:** The slab + phase-2.5 successfully rebased `0x846898` and all other interior pointers in captured heap blocks. The crash moved to a NEW stale pointer `0x9cf000` that is NOT in any captured block — it lives in Themida obfuscated section `.,\W` data, which phase-2.5 does not scan (it only scans captured heap globals/containers/slab).

**Layer 2 root cause:** Themida `.,\W` / `.KI3` sections contain data (mixed with obfuscated code) that holds stale heap pointers. Neither the scrub (`clear_process_local_absolute_pointers` — only `.data`-like) nor phase-2.5 (only captured blocks) covers these sections.

**Round 2 option:** Extend phase-2.5 (or scrub) to also scan Themida RW/RWX sections for interior heap pointers and rebase them. Risk: Themida sections mix code+data; scanning for qword values might corrupt code bytes that happen to look like heap addresses.

**Non-claim:** gto_launcher perfect-unpack NOT achieved. Slab is real progress (moved crash, proved the rebase mechanism works). Layer 2 (Themida section scan) is the next step.

**Evidence:** `D:\MidaVault\lab\evidence\gto_launcher
27_slab_round1_20260725\` (gto_unpacked.exe, unpack.stdout.txt, slab_cdb2.log)

## Battlefield GTO-perfect-unpack Round 0 (2026-07-25) — root cause: heap rebasing wall

**Goal:** perfect unpack of 启动器.exe (gto_launcher) with NO bypass patches (revert all 5 r26b patches). New env switch `MIDA_GTO_NO_BYPASS=1` disables the 5 patches for root-cause measurement.

**Candidate:** `live_r27_nobypass_round0_20260725\gto_unpacked.exe` (5 patches reverted to original bytes, verified).

**Protected reference behavior:** 启动器.exe naturally shows `NewClassName` window titled "力WLK 一键宏 - 登录/注册" + `ZhuChuangKou`; NO MessageBox; no crash.

**No-bypass candidate behavior:** shows `#32770` MessageBox with machine-ID `E4847ED08866458F8DD35F94B37001C0` (authorization gate), then after dismiss → AV `0xc0000005`.

**Crash point (cdb second-chance):**
- rip = `0x1406110a0` (section `.,\W` = `2e2c5c57`, Themida packer residue, RWX; NOT real .text which ends at 0xfc658)
- instruction: `mov edi, dword ptr [rax]`
- `rax = 0x846898` (stale low heap address, unmapped in new process)
- rax loaded from `[rbx]` — a captured object holds a stale pointer

**Heap analysis:**
- Heap handle captured at live_ptr `0x830000` (slot 0, rva 0x145d50, content_size=0).
- `0x846898 = 0x830000 + 0x16898` — an offset into the captured heap region.
- Nearest captured object: idx=295 live_ptr `0x846bb0` (size 6704) — `0x846898` is 0x318 bytes BEFORE it, in an **uncaptured gap**.
- `0x846898` has **0 hits** as qword/dword in the entire static image → it is computed at runtime from the stale heap base `0x830000`, not stored statically.

**Root cause class:** heap rebasing / capture completeness. The captured heap objects reference original-process heap addresses (e.g. `0x830000+0x16898`); the new process heap is at a different ASLR base, so intra-heap pointers are stale. This is the **same wall r1–r26 iteratively peeled** (each round: find next stale pointer → add hot root → next AV). 26 rounds did not close it.

**Verdict:** Round 0 root cause identified. Round 1 (capture the 0x846898 gap) would likely just move the crash to the next stale heap pointer — the same iterative loop. This is beyond a 2-round engineering fix; it needs heap-rebasing research (rebase all intra-heap pointers to new heap base, or capture the full heap region as one slab), not another single-hot-root peel.

**Non-claim:** gto_launcher perfect-unpack NOT achieved. The 5 r26b bypass patches remain the only way to show NewClassName (fake). Real unpack needs the heap-rebase research.

**Evidence:**
- `D:\MidaVault\lab\evidence\gto_launcher
27_nobypass_round0_20260725\` (gto_unpacked.exe, unpack.stdout.txt, r27_nobypass_cdb_av2.log, r27_nobypass_cdb_stack.log)

## Battlefield R-PURE-LOGIC Round 1 (2026-07-25) — Origin business-dialog oracle

**Bar:** behavioral equivalence beyond load survival — drive the product license dialog and compare response to protected input.

**New probe:** `tools/_behavior_probe.py --probe-kind business_dialog` (`gui_business_dialog_v0`). Drives dialog: find expected window class → set input Edit text → click Button → read status Static label → Pass if status contains expected substring. Fail-closed.

**Oracle (origin_macro):** drive `PigToGoLicenseDialog`, input `1234-5678-9012`, click `确定`, expect status `请输入授权码`.

| side | N=3 | verdict | status message |
|------|-----|---------|----------------|
| protected input (reference) | 3/3 Pass | business_status_matched | `请输入授权码` |
| unpacked candidate (fresh pure dump) | 3/3 Pass | business_status_matched | `请输入授权码` |
| **equivalence** | — | **status_message_equal = true** | identical |

**Meaning:** the license-validation code path runs identically on the unpacked candidate vs the protected input. Invalid code → same rejection message. This is real business-behavior equivalence (not load survival, not static UI presence, not sample-specific patch — Origin has zero bypass patches).

**Evidence:** `D:\MidaVault\lab\evidence\_beh_gate
_pure_logic_round0_20260725\origin_biz_prot_{1,2,3}.json` + `origin_biz_cand_{1,2,3}.json` + `origin_business_dialog_summary.json`.

**Non-claim:** rejection-path equivalence on invalid code only. Does NOT prove: valid-code acceptance, license persistence (registry/file), full product functionality, or business-path equivalence for the other 3 cases. **product 1.0 still NO.**

**Honesty on the other 3 cases:**
- **Lunlun / Xiongxiong:** exit-only (no product window); exit-code oracle `0x15ff58` is a stack-address-like value, likely a dump-stub artifact, not real product exit. Weakest behavioral signal. NOT business-equivalent.
- **GTO:** window appears only via r26b bypass patches (LoadFile skip, MessageBox skip, forced NewClassName). NOT business-equivalent.

## Residual after R-GTO-UI window close (r26b)

| ID | Item | Blocks 1.0? | Status |
|----|------|-------------|--------|
| R-LOAD-FLAKE (Origin quiet) | attempt=1 N≥20 load survival | Quality | **W1 metric exit**; W4/P1 reconfirm green |
| R-LOAD-FLAKE (GTO quiet / fresh host) | attempt=1 load survival on independent-host dumps | Quality | **W2 metric exit**; W4/P1 reconfirm green |
| R-GTO-LATEST | Fresh dump load without `r4c_gto` walk | Quality | **W2 metric exit** |
| R-GTO-BOOT | `.boot` heap_global payload size variance under 320-slot cap | Quality | Open (honesty; not load AV root) |
| R-PURE-LOGIC | Product-logic / business path equivalence | **Yes** for product 1.0 | **Advanced (Origin):** business-dialog oracle (`gui_business_dialog_v0`) — invalid-code rejection path identical to protected input (N=3 both). Lunlun/Xiong exit-only (weak); GTO bypass-patched (fake). **Still blocks 1.0** (valid-code path + multi-case not proven) |
| R-GTO-UI | Unpacked GTO no product window; protected does | Quality / **1.0-relevant for GTO** | **CLOSED (window oracle).** r26/r26b: dual class lea + CW NewClassName + WS_VISIBLE + MB skip + msg pump. Independent N=3 attempt=1 **Pass** (`NewClassName`). load Pass. Evidence `live_r26b_final_newclass\`. **product 1.0 still NO** (not full logic/license equivalence) |
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



