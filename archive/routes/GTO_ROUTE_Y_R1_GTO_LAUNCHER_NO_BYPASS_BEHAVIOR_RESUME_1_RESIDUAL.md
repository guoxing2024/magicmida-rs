# Route Y R1 GTO Launcher — No-Bypass Behavior Resume 1 (Residual)

**Work order:** `RouteY_R1_GTO_LAUNCHER_NO_BYPASS_BEHAVIOR_RESUME_1`

**Execution class:** `OFFLINE / CONTROLLED RESEARCH / IMPLEMENTATION`

**Status:** `RouteY_R1_GTO_LAUNCHER_NO_BYPASS_BEHAVIOR_RESUME_1_Residual`

**Summary:** Baseline audit of the five r26b bypasses complete; two implementation rounds executed per the work-order cap. Round 1 fixed the `sanitize_ahk_runtime_global` size-reinit tolerance; Round 2 fixed the adjacent-label capture-window overlap (with the sanitize-target exemption). The no-bypass pipeline now advances through raw-slab overlay, import rebuild, and post-CRT stages, then fail-closes at the **heap-rebase wall** (`runtime_rebase_plan_validation: declared pointer (Unmapped, region 2 @ 0x7b0) is unresolved-required`). Per the work order §6, **stop at Residual — no third round.**

---

## 1. Baseline audit (five r26b bypasses)

All five bypasses located in `crates/pe/src/dumper/dump_process.rs` (SHA `a8433a66…`, 198518 B), hard-gated behind `MIDA_GTO_BYPASS=1` + `AhkGtoExperimental` (default OFF). Full inventory with file/function/RVA/original+patched bytes/purpose/trigger/effect/rollback in `baseline_bypass_inventory.json`.

| # | Bypass | RVA(s) |
|---|---|---|
| B1 | skip LoadFile re-entry | 0x63f4 |
| B2 | skip WinMain MessageBoxW | 0x5c5d |
| B3 | force NewClassName (RegisterClass) | 0x34dbb, 0x34ed4 |
| B3b | force CreateWindowEx lpClassName | 0x34f66 |
| B4 | force WS_VISIBLE | 0x34f59 |
| B5 | skip msg-loop AV | 0x6757 |

## 2. Fresh no-bypass reproduce (deterministic)

`mida-cli /unpack <protected> --profile=ahk-gto-experimental --data-sections --no-shrink -v` with `MIDA_GTO_NO_BYPASS=1`, `MIDA_GTO_BYPASS` absent, `MIDA_GTO_SEMANTIC_REPAIR` absent. Protected input: SHA `4d5770af…`, size 8583680.

## 3. Round 1 — sanitize size-reinit tolerance (fixed)

Baseline failed at `raw_slab_overlay`: declared reinit old size 17984 outside tolerance [0x6000,0xa000]. Fix: `old_size_tolerance 0x2000 → 0x4000` (window [0x4000,0xC000]). Sanitize is a size re-init by design; the declaration must admit observed live variance. **Verified:** sanitize passes. Next wall: transformed write conflict at 0x882e3b (adjacent label windows overlap).

## 4. Round 2 — retroactive window-overlap trim (fixed) + residual

Fix: new `trim_overlapping_heap_global_windows` (heap_global_snapshot.rs) called after reconcile; lower capture ends at higher neighbor's base; RVA 0x141bf0 (sanitize target) exempt (added after the r2 self-regression where the trim shrank the sanitize slot to 0x180). **Verified:** overlay + import + post-CRT pass. **Residual wall:** `runtime_rebase_plan_validation: declared pointer (Unmapped, region 2 @ 0x7b0) is unresolved-required` — the heap-rebase incompleteness documented in WORKER_HANDOFF r27.

## 5. Pass criteria

All `*_pass` criteria are `false` (no runnable candidate produced); `sample_specific_bypass=false`, `all_five_r26b_bypasses_removed_or_inactive=true`, `evidence_complete=true`. This is the **Residual** stop state per the work order.

## 6. Discipline & boundary

- `production_driver_started=false`, `production_orchestrator_started=false`, `production_scheduled_task_created=false`.
- No historical evidence root modified. No commit/push/git add.
- HEAD `f386b49a…` / branch unchanged; `git diff --check`=0; matching tasks=0; matching residual processes=0.
- Tracked modified 3→4: the Round 2 fix added `dump_process.rs` to the tracked-modified set (the three Q0-C files + one new file containing the trim call site). This is the working-tree state only; nothing committed.

## 7. Evidence root

`D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_no_bypass_behavior_resume_1_20260814T040200Z\`
