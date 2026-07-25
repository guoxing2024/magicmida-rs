# WORKER_HANDOFF — 1 of 2 samples perfect-unpacked (2026-07-25)

## Goal (binding): docs/PROJECT_GOAL_20260725.md

Perfect unpack of exactly two samples.

| sample | status |
|--------|--------|
| 时光一键宏.exe (origin_macro) | **✅ PERFECT UNPACK COMPLETE** |
| 启动器.exe (gto_launcher) | ❌ far — 5 r26b bypass patches fake the window; needs real heap/script resume |

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
