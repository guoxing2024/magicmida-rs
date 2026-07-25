# WORKER_HANDOFF — goal redefined: perfect unpack of 2 samples (2026-07-25)

## New goal (binding)

**Perfect unpack of exactly two samples** — see [docs/PROJECT_GOAL_20260725.md](docs/PROJECT_GOAL_20260725.md):

| sample | case_id | distance |
|--------|--------|----------|
| 时光一键宏.exe | origin_macro | **near** — only valid-code acceptance path unproven |
| 启动器.exe | gto_launcher | **far** — NewClassName window is fake (5 r26b bypass patches); real heap/script resume needed |

Lunlun/Xiongxiong demoted to regression controls (not 1.0 gates).

## Distance (after goal redefinition)

| dimension | origin | gto |
|-----------|--------|-----|
| structure R0B | ✅ | ✅ |
| load | ✅ | ✅ |
| 10× repro | ✅ | ✅ |
| behavior equivalence | ✅ license rejection path (N=3 both) | ❌ fake (bypass patches) |
| no bypass patches | ✅ zero | ❌ 5 patches (LoadFile skip / MB skip / NewClassName / WS_VISIBLE / msg-loop AV) |
| **perfect unpack** | near (valid-code path only) | far (heap/script resume) |

## Next battlefields (per goal)

1. **origin_macro valid-code / full-function** — needs a valid license OR an acceptable product-function oracle. Rejection path already equivalent.
2. **gto_launcher revert bypass patches + real resume** — r1–r26 unsolved root cause; research-level; not 2 rounds.

product 1.0 = NO for both until gto reverts patches + origin proves acceptance path.
