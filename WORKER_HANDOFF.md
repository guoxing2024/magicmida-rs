# WORKER_HANDOFF — operational takeover 2026-07-28 (1 of 2 samples)

## Goal (binding): docs/PROJECT_GOAL_20260725.md

Perfect unpack of exactly two samples.

| sample | status |
|--------|--------|
| 时光一键宏.exe (origin_macro) | **✅ PERFECT UNPACK COMPLETE** (protected; Phase C reconfirmed 2026-07-28) |
| 启动器.exe (gto_launcher) | ❌ far / **Blocked** — Themida VM owns execution (r27 r5); not residual polish |

## Takeover status (2026-07-28)

| Phase | Status | Evidence |
|-------|--------|----------|
| **B** Set A P0 ship | **Done** | commit `7c86595` on `baseline/legacy-recovery-20260722` |
| **C** Origin non-regression | **Done** | live unpack EP=`0x13e0`; R0B `StructuralPassBehaviorPending`; 1× smoke `all_ok` |
| **D** Park Set B | **Done** | branch `research/gto-bootwatch-20260728` @ `41ff5d4` (BootWatch/softbp/bwhook/KI3) |
| **E** GTO research | **Closed by default** | open only with explicit expert charter |
| Product 1.0 | **NO** | gto perfect unpack not achieved |

### Phase C evidence pointers

- Fresh dump: `D:\MidaVault\lab\evidence\origin_macro\live_20260728-153937\origin_unpacked.exe`
- Bound manifest written (0 transforms)
- Smoke batch: `D:\MidaVault\lab\evidence\_repeat\batch_20260728-153953_phase_c_origin_reg\summary.json`
- Offline gates log: `D:\MidaVault\scratch\phase_b_summary.txt`

### Baseline vs research

- **baseline** = P0 fail-closed + origin-safe path only (no BootWatch mega-diff in tree)
- **research/gto-bootwatch-20260728** = GTO host residual; `crates/bwhook` remains workspace-`exclude`
- Set C still dirty on baseline if present: `validation_summary.json` (superseded), BA3/BB tool churn — do not treat as product certificate

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
