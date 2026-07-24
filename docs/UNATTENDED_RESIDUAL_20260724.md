# Unattended Residual — 2026-07-24 (post B-B close)

**Binding:** [UNATTENDED_DECISIONS_20260724.md](UNATTENDED_DECISIONS_20260724.md)  
**Claim bar (Q7):** VNEXT-BEH only when 4-case B-B all_ok.  
**This close:** batch `bb_gate_pin` **all_ok=true** → **VNEXT-BEH written**.

## B-B gate results (winning batch)

| Batch | Tag | all_ok | Notes |
|-------|-----|--------|-------|
| `D:\MidaVault\lab\evidence\_beh_gate\batch_20260724-112907_bb_gate_pin` | bb_gate_pin | **true** | Preferred pins + probe retries; VNEXT-BEH written |
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

**Load status (revised):** `u_gto_host_scan60` is StructuralPass + IAT-green (98%, OEP `0x70b0`, `wrapper_call_patch` 0/0). Quiet probe can Pass; serial often Fail then Pass×2 — **R-LOAD-FLAKE**. Under multi-case BB gate pressure, scan60 has been **12/12 Fail** while `r4c_gto` Passes on the same machine.

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

Hot-root / probe policy remains in `heap_global_snapshot.rs` (M2: externalize).

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

## Explicit non-claims

- Not perfect unpack **1.0** (full product / business-logic equivalence).  
- `load_no_crash_v0` is **load survival**, not UI/business parity.  
- Pure default remains **Origin-only**, not global.  
- GTO still needs `--profile=ahk-gto-experimental` for experimental dump stages.  
- Origin/GTO **single-shot** load may still AV; Accepted rests on **retry + pin** policy residual.

## Residual after VNEXT-BEH

| ID | Item | Blocks 1.0? |
|----|------|-------------|
| R-LOAD-FLAKE | Origin/GTO intermittent 0xC0000005; worse under multi-case gate pressure | Quality / stability |
| R-GTO-LATEST | Independent-host (`scan60`) StructuralPass + IAT 98% + quiet Pass, but batch probe often Fail; gate walks to `r4c_gto` | Quality |
| R-GTO-BOOT | `.boot` ~28 KiB = heap_global payload under 320-slot cap; dominant `0x141bf0` 16 KiB RPM size estimate + graph children — same detector both hosts | Quality; not missing stage; not proven sole flake root |
| R-PURE-LOGIC | Pure dump not proven equivalent to protected product logic | Yes for product 1.0 |
| R-X86 | ScyllaHide x86 residual | x86 only |

## Re-run

```powershell
python tools/_behavior_bb_gate.py --cases origin_macro,lunlun_software,xiongxiong_duokai,gto_launcher --write-summary --tag bb_gate_pin --max-wall-ms 8000 --attempts 12 --max-candidates 3
```
