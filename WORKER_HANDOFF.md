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
| **E** GTO research | **Trigger report filed — awaiting expert charter** | R1B capture harness parked on research branch; **battlefield not opened** without expert ack |
| Product 1.0 | **NO** | gto perfect unpack not achieved; **§0.1 binding unchanged** |

### Phase C re-run (2026-07-29) evidence pointers

- Live dump: `D:\MidaVault\lab\evidence\origin_macro\live_20260729-165727\origin_unpacked.exe` (18 sections, 13,769,216 bytes)
- Bound manifest written (0 transforms): sha256 `ae1e6344683dfc193932faf96b06b3bba45a59af6ee8f8d403928eeef09cc7cc`
- Smoke batch: `D:\MidaVault\lab\evidence\_repeat\batch_20260729-165829_phase_c_origin_reg\summary.json` — `all_ok=True`
- R0B report: `D:\MidaVault\scratch\phase_c_origin_r0b.json` — 12 gates pass, 0 failures, 0 warnings
- Offline gates re-verified on `baseline/legacy-recovery-20260722` (after Set B park):
  - `cargo test -p mida-pe --lib` → **175/175 ok**
  - `cargo test -p mida-packers-themida --lib` → **121/121 ok**
  - `cargo test -p mida-acceptance --lib` → **25/25 ok**
  - `cargo check -p mida-cli` → **ok** (1 warning: `mut` unused in `gto_host.rs:120`)
  - `cargo build -p mida-cli` → **ok** (CLI matches current baseline source)

### §6 trigger report (filed 2026-07-29)

Condition **C-1** (operational takeover per plan §12.1 — three-piece suite green) reached:

- [x] Phase B Set A landed (`7c86595`)
- [x] Phase C Origin non-regression reconfirmed (`ae1e6344…`)
- [x] Phase D Set B parked on research branch (`4be4ee5`)

Conditions C-2 / C-3 (R1B capture hits / independent-PE evidence) = **0/1** — R1B capture harness parked per operator instruction; battlefield **not auto-opened**.

**Status language held honest:** product 1.0 = NO (gto second vote still blocked). §6 E field must wait for explicit expert charter per plan §6.3.

### Baseline vs research

- **baseline** = P0 fail-closed + origin-safe path only (no BootWatch mega-diff in tree)
- **research/gto-bootwatch-20260728** = GTO host residual + R1B capture harness (`crates/bwhook` + `tools/_r1b_transient_epoch_trap.py`); `crates/bwhook` remains workspace-`exclude`
- Set C committed: `validation_summary.json` status=superseded; BB writer no longer re-certifies product Accepted via load_no_crash
- GTO charter: `docs/GTO_RESEARCH_CHARTER_20260728.md` (battlefield `GTO-POINTEE-EPOCH` on research branch; execute Round 0 only on operator command)

### Open discipline notes (2026-07-29)

- R1B DR0 arming is currently blocked on a single `CONTEXT_FLAGS` field: `CONTEXT_DEBUG_REGISTERS_AMD64 | CONTEXT_CONTROL_INTEGER_AMD64` = `0x100013` does **not** include `CONTEXT_AMD64 (0x100000)` architecture bit. Windows `GetThreadContext` rejects with `ERROR_INVALID_PARAMETER`. Fix: OR in `CONTEXT_AMD64`. This is **fix round #1 of #2 budget** in the R1B trench if/when reopened on research branch — **not in scope of plan §6 default**.
- bwhook diagnostic log path: `D:\MidaVault\scratch\r1b_smoke_log\` (vault only, not committed)
- Race note observed earlier in this session: `SuspendThread(prev=0)` showed up while BootWatch had already frozen the RIP — handled by host's `if frozen_rip.is_none() && bootwatch_vm_enter_rip.is_none()` gate, but worth a hygiene pass if R1B is reopened.

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
