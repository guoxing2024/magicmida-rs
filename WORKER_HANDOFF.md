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
