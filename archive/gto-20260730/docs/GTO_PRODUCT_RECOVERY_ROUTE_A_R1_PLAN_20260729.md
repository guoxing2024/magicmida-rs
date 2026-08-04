# GTO-PRODUCT-RECOVERY Phase 1 — Route A R1 plan (2026-07-29)

> **Status:** **PLAN** — pre-implementation plan, **0 budget rounds consumed** (docs-only).
> **Authorization:** expert ruling 2026-07-29 (`GTO-PRODUCT-RECOVERY Phase 1 on Route A`).
> **Branch:** `codex/gto-product-recovery-route-a` @ `1ca2fdefd5014ce9f043d6aab84c434542d9ca6b` (from `baseline/legacy-recovery-20260722`).
> **Ledger:** `GTO-PRODUCT-RECOVERY Route A` — separate from `GTO-POINTEE-EPOCH` (`used=2/cap=2/remaining=0`, frozen).
> **Hard scope:** **non-DRx memory-state epoch capture only**. No `gto_host.rs` research-branch version touched. No `bwhook/**`. No `_r1b_transient_epoch_trap.py`. No VEH+DR0 short-window. No `sample_bypass`. No push.

---

## 0. One-sentence R1

Build an **external observer host** that, without DRx, VEH, or any in-process instrumentation, observes the protected `gto_protected.exe` process from outside via `ReadProcessMemory` + `VirtualQueryEx` polling, and stably identifies a **named memory-state epoch** that has clear evidence-binding to `.boot` / VM-owned execution / allocation transition.

---

## 1. R1 method class (named, what it is)

### 1.1 Named method class

`memory-state-epoch external observer` (abbreviated `mtr_acq_observe`):

- **External** observer (separate process) — no DLL injection, no in-process hook.
- **Read-only** `ReadProcessMemory` + `VirtualQueryEx` polling at 10–20 ms cadence.
- **State coverage**: per-iteration region snapshot of every `MEM_COMMIT` region in the protected process; diff deltas between consecutive snapshots = "state transition events".
- **No DRx** — debug registers are never touched.
- **No VEH** — no in-process exception handler.
- **No `GetThreadContext` debug-register fetch** — debug-register classes are not requested.
- **No `bwhook` / `gto_host` / `_r1b_transient_epoch_trap`** — parked code is strictly untouched.

### 1.2 What counts as a "named memory-state epoch"

A *named epoch* is a **categorized transition event** that we label with:

| Epoch name | Trigger condition |
|------------|-------------------|
| `boot_section_first_committed` | A region whose name/path contains `\.boot` (Themida VM byte-code container; per `4c2b545:docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` §0) transitions to `MEM_COMMIT` for the first time. |
| `vm_owned_region_write_storm` | A region observed to have ≥K memory writes within a single 10 ms tick (K = 64 by default; counts region-relative patched pages). |
| `vm_protection_transition` | A region whose `Protect` field changes between observations (e.g. `PAGE_NOACCESS` → `PAGE_EXECUTE_READWRITE` or `PAGE_READWRITE` → `PAGE_EXECUTE_READWRITE`). |
| `vm_codegen_region_expand` | A region whose `RegionSize` strictly grows between two consecutive observations. |
| `vm_codegen_region_split` | A previously contiguous region is observed as two separate regions in the next tick. |
| `vm_allocation_anchor` | A new region appears at a base address ≥ `process_image_base + 0x10000000` (heap-style allocator) — a candidate `VirtualAlloc` anchor. |

These are **observational labels**, not semantic claims. They do not assert any named function or VM opcode; they assert only what the process mapping table shows.

### 1.3 Evidence-binding requirement (per authorization §六)

For an epoch to count toward the R1 evidence bar, it must:

- Have **clear evidence-binding** to one of: `.boot` (Themida VM byte-code container), VM-owned execution, or allocation transition.
- Be **stable across runs** (≥ 2/3 of N=3 independent runs observe at least one of the same epoch names).
- Be **non-bypass** (`bypass_used=false`, `semantic_repair_used=false`).
- Be **non-DRx** (no debug-register subclass in the observation path).

---

## 2. Files to touch (per authorization §四)

### 2.1 New files (allowed)

| Path | Purpose | Bytes estimate |
|------|---------|----------------|
| `crates/cli/src/bin/mida_gto_product_recovery_observer.rs` | New CLI binary: external observer host. Spawns `gto_protected.exe` (or attaches to a pre-spawned process), polls `ReadProcessMemory` + `VirtualQueryEx`, writes per-run JSON sidecar. | ~400 lines |
| `tools/_mtr_acq_route_a_observer.py` | New Python driver: launches the observer CLI on N=3 independent runs, aggregates JSON sidecars, computes stability score. Filename starts with `_mtr_acq_` (per authorization §四: "文件名必须带 route_a / product_recovery"). | ~250 lines |
| `tools/_mtr_acq_route_a_aggregate.py` | New Python aggregator: reads N JSON sidecars, produces `route_a_r1_aggregate.json` with `same_epoch_observations[]`, `stability_score`, `named_epoch_candidates[]`. | ~150 lines |
| `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_20260729.md` | R1 evidence report (written after R1 measurement). | ~200 lines |
| `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_20260729.md` | This plan + R1+R2 ledger record (will be updated after R1). | ~150 lines |

### 2.2 NOT touched (per authorization §四)

| Path | Why |
|------|-----|
| `crates/bwhook/**` | Forbidden by authorization §四. |
| `crates/cli/src/unpacker/gto_host.rs` (research-branch version) | Forbidden by authorization §四. |
| `tools/_r1b_transient_epoch_trap.py` | Forbidden by authorization §四. |
| `crates/cli/src/unpacker/gto_host.rs` (baseline version) | On baseline only — not modified in R1. The new observer runs as a **separate binary** (`mida_gto_product_recovery_observer`). |
| `tools/_r1b_transient_epoch_trap.py` | Identical to above — strict no-touch. |
| `docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` | Immutable seal. |
| Vault evidence files | Read-only inputs. |

### 2.3 Conditional touches (only if R1 implementation requires — justified case-by-case)

| Path | Conditionality |
|------|----------------|
| `crates/core/src/windows_debugger.rs` | **Only if** R1 needs a new `MemoryRegionInfo` query variant that doesn't already exist. The authorization §四 allows "non-DRx memory region / allocation observation API addition". R1 does not require this — `ReadProcessMemory` + `VirtualQueryEx` are exposed via `windows` / `winapi` directly. **Expected: no touch.** |
| `crates/core/src/lib.rs` | **Only if** a new module export is needed. **Expected: no touch.** |
| `Cargo.toml` (workspace) | **No touch.** |
| `crates/cli/Cargo.toml` | **Expected**: +1 `[[bin]]` entry for `mida_gto_product_recovery_observer` pointing to `crates/cli/src/bin/mida_gto_product_recovery_observer.rs`. This is additive — does not modify the existing `[[bin]] mida-cli` from `crates/cli/src/main.rs`. |
| `crates/cli/src/main.rs` | **No touch.** The existing `mida-cli` binary is untouched; the new observer is a separate `[[bin]]` entry. |

---

## 3. Evidence bar (R1 pass criteria)

Per authorization §六:

1. **N ≥ 3** independent runs (`N=3` minimum).
2. **At least 2/3 runs** observe at least one of the **same named epoch** names (i.e. two runs see `boot_section_first_committed` and a third sees `vm_protection_transition` — that does NOT count; the runs must agree on the same named epoch).
3. **Clear evidence-binding** to one of `.boot` / VM-owned execution / allocation transition.
4. **Bypass-free** (`bypass_used=false`, `semantic_repair_used=false`).
5. **No sample_bypass** patches.
6. **No DRx** in the observation path.
7. **Full JSON sidecars** at `D:\MidaVault\scratch\product_recovery_route_a_r1_n3_<ts>\run_<i>\outcomes.json` + aggregate at `D:\MidaVault\scratch\product_recovery_route_a_r1_n3_<ts>\aggregate.json`.
8. **Report** at `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_20260729.md`.

### 3.1 R1 pass notation

PASS = N≥3 + ≥2/3 stable named epoch + evidence-binding + bypass-free + no-DRx + JSON sidecars + report.

### 3.2 R1 fail residual

If R1 fails: write `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_RESIDUAL_20260729.md` explaining which evidence bar item failed and which named epoch (if any) was observed. **STOP** — do not proceed to R2. Per authorization §四: "R1 失败，R2 不准进入除非 residual 明确给出 R2 hypothesis."

### 3.3 R1 does NOT require

- product Accepted
- UI pass
- E2 restore
- same_epoch pointee restore
- perfect unpack
- AHK script engine execute
- every named epoch observed (only ≥2/3 stable)

---

## 4. Implementation steps (single R1 round)

The R1 round is **one Rust+Python diff + rebuild + measure**. All steps happen inside this single round. Step 4 is the implementation boundary; step 5 is the measurement boundary. Burn rule: any Rust/Python edit that affects capture is 1 round.

### 4.1 Rust: `crates/cli/src/bin/mida_gto_product_recovery_observer.rs`

A new binary that:

1. Takes CLI args: `--target-pid <pid>` or `--spawn <path>`; `--observation-window-ms <u32>`; `--poll-period-ms <u32>`; `--out-dir <path>`.
2. If `--spawn`, calls `CreateProcessW` with `MIDA_GTO_NO_BYPASS=1`, `MIDA_GTO_BYPASS` absent, `MIDA_GTO_SEMANTIC_REPAIR` absent (default). Spawns the protected binary in suspended state.
3. Resumes the protected process (or attaches to a pre-spawned PID).
4. Polls `VirtualQueryEx(NULL, 0, &m, sizeof(m))` in a loop for `observation_window_ms` (default 60 000 ms = 60 s). Each iteration walks the entire region list (50–500 regions depending on process state).
5. For each region, reads `RegionSize`/`Protect`/`State`/`Type` and (for `MEM_COMMIT` private regions) reads 4 KiB at `BaseAddress` via `ReadProcessMemory` — record only a 64-bit XOR checksum (NOT the byte content — preserve privacy and reduce log size).
6. Per tick: compute deltas (new region, size change, protection change, content checksum change). Bucket deltas into the §1.2 named-epoch labels.
7. After window expires, write JSON sidecar:
   - `run_id` (uuid v4)
   - `route = "GTO-PRODUCT-RECOVERY/RouteA"`
   - `method_class = "memory-state-epoch external observer"`
   - `bypass_used = false`
   - `semantic_repair_used = false`
   - `target_sample = "gto_launcher"`
   - `target_pid`
   - `target_image_path`
   - `observation_window_ms`
   - `poll_period_ms`
   - `tick_count`
   - `observed_regions[]` — per-region summary (base, size, protect, state, type, checksum)
   - `vm_owned_region_candidates[]` — regions matching `.boot` pattern or VM-owned heuristic
   - `boot_region_candidates[]` — regions whose section name contains `.boot`
   - `allocation_epoch[]` — `{name, first_tick, evidence_kind, base, size}`
   - `protection_transitions[]` — `{base, from_protect, to_protect, tick}`
   - `named_observations[]` — `{name, first_tick, count, evidence_binding}` (the formal named-epoch list)
   - `failure_class` — `none` / `spawn_failed` / `attach_failed` / `poll_window_truncated` / `read_failed`
   - `source_commit` — `git rev-parse HEAD` of the binary
   - `artifact_hashes` — `{binary_sha256, manifest_sha256}`
   - `rsp_source` — `external-observer` (NOT same-epoch pointee; R1 does not pursue same_epoch)

### 4.2 Python: `tools/_mtr_acq_route_a_observer.py`

Orchestrator that:

1. Reads `tools/_r1b_transient_epoch_trap.py` shape (read-only reference) but **does not import** it.
2. Finds `gto_protected.exe` from vault (latest non-recent timestamp).
3. For each of N=3 runs:
   - Spawns `cargo run --release -p mida-cli --bin mida_gto_product_recovery_observer -- --spawn <path> --out-dir <run_dir>`.
   - Captures stdout/stderr to log file.
   - On exit, computes sha256 of `outcomes.json`.
4. After all N runs, calls `tools/_mtr_acq_route_a_aggregate.py` to produce the aggregate.

### 4.3 Python: `tools/_mtr_acq_route_a_aggregate.py`

Aggregator that:

1. Reads all N `outcomes.json` sidecars.
2. Computes **stability_score** = `count(names observed in ≥2/3 runs) / count(unique names across all runs)`.
3. Builds `same_epoch_observations[]` where each entry is a named epoch name + evidence-binding classification.
4. Writes `aggregate.json` with:
   - `route = "GTO-PRODUCT-RECOVERY/RouteA"`
   - `method_class = "memory-state-epoch external observer"`
   - `n_runs`
   - `pass` (boolean per §3.1)
   - `stability_score`
   - `same_epoch_observations[]`
   - `evidence_bar_checklist` (verbatim 8 items of §3)
   - `artifact_hashes[]` (one per run)

### 4.4 Pre-flight checks (before measurement)

- `cargo check -p mida-cli --offline` (per authorization §八).
- `cargo test -p mida-pe --lib --offline` (per authorization §八: only if shared dumper touched; R1 does not touch shared dumper, but run anyway as a regression guard).
- `cargo test -p mida-acceptance --lib --offline` (per authorization §八: only if acceptance logic touched; R1 does not touch acceptance, but run anyway as a regression guard).

### 4.5 Origin Phase C non-regression

Per authorization §八: "如果改了 shared dumper / mida-pe: 必须跑: cargo test -p mida-pe --lib --offline + Origin Phase C non-regression smoke". R1 does **not** touch `crates/pe/src/dumper/**` (the new observer is in `crates/cli/src/bin/`). **Origin Phase C non-regression is NOT required for R1** unless R1 also touches `crates/pe/src/dumper/**` — which is not planned. This is documented here as a deliberate non-trigger.

---

## 5. Evidence bar checklist (pre-implementation self-check)

| # | Item | Plan-stage answer |
|---|------|-------------------|
| 1 | N≥3 | Plan: N=3 |
| 2 | ≥2/3 stable named epoch | Plan: `stability_score ≥ 0.5` (heuristic) |
| 3 | .boot / VM / alloc binding | Plan: `boot_region_candidates[]` flagged by name pattern; `vm_protection_transition` flagged by THEMIDA-typical `RW → RX` |
| 4 | bypass_used=false | Enforced by env: `MIDA_GTO_NO_BYPASS=1`, `MIDA_GTO_BYPASS` absent |
| 5 | no sample_bypass | Inherited from `sample_bypass` taxonomy rule |
| 6 | no DRx | Observer uses only `ReadProcessMemory` + `VirtualQueryEx`; no `GetThreadContext(DEBUG_REGISTERS)` |
| 7 | JSON sidecars | Per §4.1 schema |
| 8 | report | `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_20260729.md` |

---

## 6. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Anti-debug kills the observer after some N ticks | `ReadProcessMemory` failures are recorded per-tick as `read_failed`; observer continues until window expires. |
| `PROCESS_VM_READ` rights denied | `observation_window_ms` short enough that we triage; if 1/3 or 0/3 runs fail, R1 fails (insufficient evidence). |
| Named-epoch labels are too generic (e.g. every region flips RW→RX) | Add `boot_region_candidates` filter: only count as `vm_protection_transition` if the region is flagged as `vm_owned` by `.boot` name pattern or RWX residue. |
| Vault `gto_protected.exe` produces different entropy than a fresh copy | Single-vault-source: one canonical `gto_protected.exe` path across all 3 runs. |
| Three runs run on the same OS state and converge trivially | Each run is a fresh process spawn, separate scratch directory, separate timer. Anti-affinity per run. |
| Sample missing in vault | Pre-flight: `--target` existence check; if missing, fail before measurement. |

---

## 7. What R1 does NOT do (be explicit)

- ❌ No DRx / VEH / debug-register code path in the observer.
- ❌ No `bwhook` / `gto_host` / `_r1b_transient_epoch_trap` modification.
- ❌ No `sample_bypass` patch introduction.
- ❌ No `MIDA_GTO_BYPASS=1` or `MIDA_GTO_SEMANTIC_REPAIR` in the env.
- ❌ No `git push` — local commits only, on `codex/gto-product-recovery-route-a`.
- ❌ No auto-margin-of-R2 — R1 only.
- ❌ No product Accepted / no UI pass / no E2 restore / no same_epoch pointee restore / no perfect unpack.

---

## 8. Reporting after R1

Per authorization §八:

- `git status --short --branch`
- `git rev-parse HEAD`
- `git diff --stat`
- `git diff --name-status`
- `git diff --check`
- Commands run.
- Exact env vars.
- Evidence directories.
- JSON sidecar paths.
- SHA-256 for all produced artifacts.
- Pass/fail against evidence bar.
- Whether budget consumed (R1 = 1 round consumed if Rust+Python diff + rebuild + re-measure happened).

---

## 9. Self-discipline check

- Anti-revival: `crates/bwhook/**` unchanged (verified by `git diff --name-status` after R1).
- Anti-revival: `tools/_r1b_transient_epoch_trap.py` unchanged (verified by `git diff --name-status` after R1).
- Anti-revival: `crates/cli/src/unpacker/gto_host.rs` (research version) unchanged (verified by checkout — this branch is derived from baseline, not from `research/gto-bootwatch-20260728`; this branch does not contain `gto_host.rs` research edits).
- Anti-rename: new observer binary is in `crates/cli/src/bin/`, not renamed from any R1B path.
- Anti-default: env default is `MIDA_GTO_NO_BYPASS=1`; bypass is not set.
- Anti-push: local commits only.

---

## 10. State check (post-plan, pre-implementation)

- Plan doc is **NOT committed** yet (per authorization §九: "R1 完成后: 不自动 commit; 先给专家验收; 专家通过后才 commit").
- Branch `codex/gto-product-recovery-route-a` exists, on `1ca2fdefd5014ce9f043d6aab84c434542d9ca6b`.
- Working tree clean.

**Next action** (in this turn, after this plan is filed):

- Worker pauses and reports the plan for **expert pre-review** before implementing R1 code. **Per the spirit of authorization §九** ("不自动 commit ... 先给专家验收"), an early review gate before Rust+Python diff is well-aligned with the budget discipline.

**However**, if the operator's explicit instruction in §十 is to proceed end-to-end without an intermediate review gate, the worker will execute steps 4–6 immediately after this plan is filed. The decision is the operator's.
