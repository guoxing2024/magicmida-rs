# WORKER_HANDOFF — operational takeover 2026-07-29 (1 of 2 samples)

## Goal (binding): docs/PROJECT_GOAL_20260725.md

Perfect unpack of exactly two samples.

| sample | status |
|--------|--------|
| 时光一键宏.exe (origin_macro) | **✅ PERFECT UNPACK COMPLETE** (protected; Phase C reconfirmed 2026-07-29) |
| 启动器.exe (gto_launcher) | ❌ far / **Blocked** — Themida VM owns execution (r27 r5); not residual polish |

## Takeover status (2026-07-29)

| Phase | Status | Evidence |
|-------|--------|----------|
| **B** Set A P0 ship | **Done** | commit `7c86595` on `baseline/legacy-recovery-20260722` |
| **C** Origin non-regression | **Done (2026-07-29 re-run)** | live unpack EP=`0x13e0`; R0B `StructuralPassBehaviorPending`; 1× smoke `all_ok`; artifact-bound manifest sha256 `ae1e6344…` |
| **D** Park Set B | **Done** | branch `research/gto-bootwatch-20260728` @ `4be4ee5` (BootWatch/R1B bwhook/KI3) |
| **Set C** lab honesty | **Done** | superseded `validation_summary` + BA3/BB contract adaptation |
| **E** GTO research | **REJECTED 2026-07-29** — §6 E **not opened**; R1B trench **FROZEN**; **budget exhausted (used=2/cap=2/remaining=0)** | `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §0 (status); charter `§4.4` (third-pass 2026-07-29) + §4.5 dormant (2026-07-29) define re-entry + E2 protocol; **operator must name `R1B re-entry`** — "continue" / "proceed" / passing C-1 do **not** satisfy §4.4; **R1B already consumed 1 round** (`4be4ee5` + 4× smoke in `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\`) — re-entry alone does **not** expand budget; only separate governance (charter amendment / new expert ruling) can re-open |
| Product 1.0 | **NO** | gto perfect unpack not achieved; **§0.1 binding unchanged** |

### Phase C re-run (2026-07-29) evidence pointers

- Live dump: `D:\MidaVault\lab\evidence\origin_macro\live_20260729-165727\origin_unpacked.exe` (18 sections, 13,769,216 bytes, sha256 `ae1e6344…`)
- Bound manifest written (0 transforms): sha256 `ae1e6344683dfc193932faf96b06b3bba45a59af6ee8f8d403928eeef09cc7cc`  (== live dump sha256)
- Smoke batch: `D:\MidaVault\lab\evidence\_repeat\batch_20260729-165829_phase_c_origin_reg\summary.json` — `all_ok=True` (artifact sha256 `aa99fa05…`)
- R0B report: `D:\MidaVault\scratch\phase_c_origin_r0b.json` — 12 gates pass, 0 failures, 0 warnings (artifact sha256 `ae1e6344…`)
- **Distinction (corrected 2026-07-29 per expert review):** the smoke artifact (`aa99fa05…`) and the R0B/manifest-bound artifact (`ae1e6344…`) are **two independent runs** of the unpacker, not one artifact running through a unified "all-gates" pipeline. Each individually satisfies its own contract; "Origin non-regression" is the conjunction of these two independent observations, **not** "the same artifact is green across both pipelines." Future evidence descriptions must keep them separate.
- Offline gates re-verified on `baseline/legacy-recovery-20260722` (after Set B park):
  - `cargo test -p mida-pe --lib` → **175/175 ok**
  - `cargo test -p mida-packers-themida --lib` → **121/121 ok**
  - `cargo test -p mida-acceptance --lib` → **25/25 ok**
  - `cargo check -p mida-cli` → **ok** (1 warning: `mut` unused in `gto_host.rs:120`)
  - `cargo build -p mida-cli` → **ok** (CLI matches current baseline source)

### Expert ruling on §6 E battlefield (2026-07-29)

**§6 E field = REJECTED / NOT OPENED** (expert ruling 2026-07-29, second pass). C-1 (operational takeover) accepted; E battlefield not opened; R1B capture trench remains FROZEN. Re-entry bar = `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 (2026-07-29 amendment) + immutable seal at `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §4. No code change to bwhook / gto_host / `_r1b_transient_epoch_trap.py` authorized by this handoff. **Operator must name `R1B re-entry`; "continue" / "proceed" do not satisfy §4.4.**

### Baseline vs research

- **baseline** = P0 fail-closed + origin-safe path only (no BootWatch mega-diff in tree)
- **research/gto-bootwatch-20260728** = GTO host residual + R1B capture harness (`crates/bwhook` + `tools/_r1b_transient_epoch_trap.py`); `crates/bwhook` remains workspace-`exclude`
- Set C committed: `validation_summary.json` status=superseded; BB writer no longer re-certifies product Accepted via load_no_crash
- GTO charter: `docs/GTO_RESEARCH_CHARTER_20260728.md` — current status **Residual-stop after R1A** (per §0); re-entry only per charter §4.4 / seal `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §4. **"execute charter Round 0" alone is not admissible** under Residual-stop — operator must name **R1B re-entry** and produce evidence per §4.4.

### Open discipline notes (2026-07-29 — corrected 2026-07-29 per expert review)

- **WITHDRAWN — prior claim about CONTEXT_FLAGS fix was wrong.** Earlier draft described "OR in `CONTEXT_AMD64`" as a one-line fix for `GetThreadContext` returning `ERROR_INVALID_PARAMETER`. That claim is **incorrect**: `0x100013` already encodes the architecture bit (the high `0x100000` is set inside both `CONTEXT_DEBUG_REGISTERS_AMD64 (0x100010)` and `CONTEXT_CONTROL_INTEGER_AMD64 (0x100003)`). OR-ing `CONTEXT_AMD64` again is a no-op and does not fix anything. The actual root cause of the `GetThreadContext` Err in the R1B smoke is **not established** — candidates remain: (i) non-standard flag combination behavior on this Win10/11 build; (ii) suspend-count / handle race (earlier session observed `SuspendThread(prev=0)` while host had skipped its own suspend); (iii) thread-state precondition not actually met at the moment of DLL arming. **No "one-line fix" is to be trusted or committed without empirical `ERROR_INVALID_PARAMETER` reproduction under controlled flags, and without showing the flag value Windows actually accepted.**
- bwhook diagnostic log path: `D:\MidaVault\scratch\r1b_smoke_log\` (vault only, not committed)
- Race note observed earlier in this session: `SuspendThread(prev=0)` showed up while BootWatch had already frozen the RIP — handled by host's `if frozen_rip.is_none() && bootwatch_vm_enter_rip.is_none()` gate, but worth a hygiene pass if R1B is reopened.
- **R1B trench remains FROZEN** per expert 2026-07-29 ruling (third pass, 2026-07-29); re-entry bar = charter §4.4 + §4.5 dormant (third-pass 2026-07-29) + immutable seal `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §4. Per-round fix budget = ≤2 (per `docs/COURSE_CORRECTION_WORK_ORDER.md` §3 — workspace-auditable). **Budget exhausted, ledger 2026-07-29:** R1A = 1 round consumed (host instrument, closed 2026-07-28, see `4c2b545:docs/GTO_POINTEE_EPOCH_R1A_20260728.md` §1); **R1B = 1 round already consumed** (commit `4be4ee5` on `research/gto-bootwatch-20260728` — bwhook + gto_host + runner +1342 lines + 4× live smoke at `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\`); E2 = **0 remaining**, **forbidden** under current charter. **used=2 / cap=2 / remaining=0.** The earlier "operator pre-declaration" policy was withdrawn on third-pass: declaration expresses intent only; the ledger is determined by actual Rust/Python diff + clean tree + rebuild + re-measure. **Only separate governance** (charter amendment or new expert ruling recorded here) can re-open budget — `R1B re-entry` / `E2 implementation` instructions do **not** themselves expand budget.

## origin_macro — DONE (evidence)

- Structure R0B StructuralPassBehaviorPending
- Load 10× isolated 10/10
- .text entropy 6.045 (plaintext), x64 prologues present
- Product strings (授权验证/授权码) GBK plaintext in .rdata
- Modifiable: patched 1 byte @0xfe5c5 → R0B still Pass + load still Pass + business_dialog still Pass (no integrity lock)
- Behavior: license rejection path bilateral N=3 Pass, status message identical
- Zero bypass patches
- Reproducible: current CLI fresh dump → all green

valid-code acceptance path not tested (no valid license) — that is a licensing-layer concern, NOT an unpacking-layer concern. Unpack goal met.

## gto_launcher — OPEN (the remaining sample)

5 r26b bypass patches in candidate:
- 0x5c5d MessageBoxW skip
- 0x63f4 LoadFile skip (script not actually loaded!)
- 0x34f66 CreateWindowEx → forced NewClassName
- 0x34f59 WS_VISIBLE forced
- 0x6757 msg-loop AV skip

"Perfect unpack" for gto requires: revert ALL 5 patches + product code naturally runs to UI + AHK script engine loads/executes. This is the r1–r26 unsolved heap/script resume root cause.

product 1.0 = NO until gto perfect-unpacks.

## gto_launcher Round 0 (r27 no-bypass) — root cause: heap rebasing wall

- Reverted all 5 r26b bypass patches via `MIDA_GTO_NO_BYPASS=1`; re-dumped.
- Protected input naturally shows NewClassName login window (no MB, no crash).
- No-bypass candidate: shows #32770 MessageBox (machine-ID E4847ED08866458F8DD35F94B37001C0) then AV 0xc0000005.
- Crash: rip=0x1406110a0 (Themida `.,\W` section), `mov edi,[rax]`, rax=0x846898 (stale heap ptr).
- 0x846898 = 0x830000 (captured heap handle) + 0x16898; falls in an uncaptured 0x318-byte gap before the object at 0x846bb0.
- 0x846898 has 0 static hits → computed at runtime from stale heap base. This is heap-rebasing incompleteness, same wall r1-r26 peeled for 26 rounds.
- Round 1 (capture the gap) would just move crash to next stale ptr. STOP per discipline; needs heap-rebase research, not another peel.

gto_launcher perfect-unpack = NOT achieved. product 1.0 = NO.
