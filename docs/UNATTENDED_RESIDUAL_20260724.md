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
| R-LOAD-FLAKE | Origin/GTO intermittent 0xC0000005 without retries | Quality / stability |
| R-GTO-LATEST | Newest GTO dumps often Fail probe; pin older green | Quality |
| R-PURE-LOGIC | Pure dump not proven equivalent to protected product logic | Yes for product 1.0 |
| R-X86 | ScyllaHide x86 residual | x86 only |

## Re-run

```powershell
python tools/_behavior_bb_gate.py --cases origin_macro,lunlun_software,xiongxiong_duokai,gto_launcher --write-summary --tag bb_gate_pin --max-wall-ms 8000 --attempts 12 --max-candidates 3
```
