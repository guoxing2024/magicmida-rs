# GTO Product Recovery — Route Y R1 Declared Size-Reinit Live Truth Run (A2)

> 状态：**`RouteY_R1_A2_CandidateNotReady`**（protected sample 已 spawn，在 `transform_input_seed`
> stage 因 `raw capture drift` fail-closed，**未到达** sanitize declared transition；candidate = 0）。
> 授权：Route Y R1 Reissued Live Truth Run Authorization A2。唯一授权 baseline = `68b8032`。
> 第一次 NotRun attempt（`live_20260811T063619Z_...`）证据冻结、未覆盖。

---

## 1. 授权 baseline 核对（只读）

| 检查 | 预期 | 实际 | 结果 |
|---|---|---|---|
| branch | `oreans/two-sample-mainline` | 一致 | ✅ |
| HEAD | `68b8032` | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` | ✅ |
| HEAD^ | `9450b3a` | `9450b3aed570ff42c62a248f7e7013540a7e1348` | ✅ |
| 无 tracked 工作树修改 | 是 | 是 | ✅ |
| untracked 仅 3 个 docs | 是 | X R1 / Y R0 / Y R1 结果 | ✅ |
| `git diff --check` | 干净 | 干净 | ✅ |

**baseline 全部匹配。** 第一次 NotRun report（`docs/GTO_ROUTE_Y_R1_LIVE_RESULT.md`）未修改。

## 2. 第一次 NotRun attempt 引用

- 第一次 evidence：`D:\MidaVault\lab\evidence\gto_launcher\live_20260811T063619Z_route_y_r1_declared_size_reinit\`
- 第一次 report：`docs\GTO_ROUTE_Y_R1_LIVE_RESULT.md`（`RouteY_R1_NotRun`，冻结）
- 第一次原因：`build_binary_path_mismatch`（`child_argv0 == "--"`，controller invocation 参数错误，未 spawn）

## 3. A2 UTC timestamp

- started：`2026-08-11T06:54:34.429Z`
- finished：`2026-08-11T06:56:35.980Z`

## 4. A2 evidence 路径

```
D:\MidaVault\lab\evidence\gto_launcher\live_20260811T065313Z_route_y_r1_declared_size_reinit_a2\
  argv_static_verification.json
  capture_policy.json
  child.stderr.bin / child.stderr.txt   (原始 binary 原件保留)
  child.stdout.bin / child.stdout.txt
  controller_attempt_001.json
  controller_run.json
  candidate\  (空)
```

## 5. Corrected argv

修正点：controller 的 `args.command` 使用 argparse `REMAINDER`。第一次调用在 child 命令前放置了独立 `--`，
被 argparse 捕获为 `command[0] == "--"`。本次**移除独立 `--`**，让 canonical binary 直接作为第一个位置参数。

```
controller [options] D:\MidaVault\scratch\cargo-target-route-y1\debug\mida-cli.exe /unpack <sample> -o <candidate>\gto_unpacked.exe --data-sections --no-shrink --profile=ahk-gto-experimental --container-restore=post-crt --capture-policy=<policy> -v
```

## 6. child argv[0] 与 attested path 一致性（调用前静态核验）

- **child argv[0]**：`D:\MidaVault\scratch\cargo-target-route-y1\debug\mida-cli.exe`
- **attested binary path**：`D:\MidaVault\scratch\cargo-target-route-y1\debug\mida-cli.exe`
- **child argv len**：11（≥ 1）
- **child argv[0] != "--"**：true
- **child argv[0] == attested path（raw）**：true
- **Resolve-Path(child argv[0]) == Resolve-Path(attested)**：true
- **静态核验 verdict**：**PASS**（`argv_static_verification.json` 已落盘）

## 7. Build attestation verdict

| 项 | 值 | 与 attestation 一致 |
|---|---|---|
| baseline_commit | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` | ✅ |
| binary_path | `D:\...\cargo-target-route-y1\debug\mida-cli.exe` | ✅ |
| binary_sha256 | `ecaffb07b3f1e413fa2dcf894a7ce1c7156ef27b4f6a4de7ab77c4219eab1871` | ✅（独立复验一致） |
| binary_size | `10998272` | ✅（独立复验一致） |
| gto_product_recovery | `true` | ✅（`--build-capabilities-json` 确认） |
| binary regular file | 是 | ✅ |
| requested_features | `["gto-product-recovery"]` | ✅ |

**Build verdict：PASS**（canonical build 有效，未自第一次后变化，未静默复用旧 attestation）。

## 8. Five-layer preflight

| 层 | 结果 |
|---|---|
| 1. Git baseline/head gate | ✅（68b8032 / 9450b3a） |
| 2. Build capability/attestation gate | ✅（`build_capability_preflight_error=null`） |
| 3. Authorized effective environment gate | ✅（`MIDA_GTO_NO_BYPASS=1`，bypass/semantic 均 absent，`ok=true`） |
| 4. Capture policy argument/file gate | ✅（`capture_policy_arg_present/exists=true`，`ok=true`） |
| 5. Live environment/sample/controller gate | ✅（`live_environment_preflight_error=null`） |

**五层 preflight 全部通过 → spawn。**

## 9. Spawn count / PID

- **protected sample spawn count**：1（`spawned=true`）
- **child PID**：`17936`（mida-cli）
- **protected sample PID**：`1820`（artifact.exe）
- 进程自然退出：`process_tree_cleanup_status = exited_naturally`（Drop terminated owned target, wait=signaled）

## 10. Elapsed / Timeout

- configured timeout：`600.0` s
- actual elapsed：**`121547` ms**（约 121.5 s）
- timed_out：**false**（自然退出，未超时）

## 11. 完整 stage timeline

| monotonic_ms | stage | event |
|---|---|---|
| 0 → 221 | capture_heap_slab | enter → exit（byte_count=44642952，主堆 slab 捕获） |
| 240 → 1949 | normalize_authoritative_slabs | exit（4 个 slab） |
| 1961 | reconcile_duplicate_heap_globals | exit |
| 1962 → 1964 | capture_identity_bind | exit（317 个 child） |
| 1964 | capture_coverage_bind | exit（317） |
| 1964 → 1977 | raw_children_from_capture | exit（316） |
| 1977 → 110811 | **transform_input_seed** | **error**（raw capture drift） |

## 12. sanitize declared transition evidence

**未到达。** 管线在 `transform_input_seed`（sanitize 之前）fail-closed。
`sanitize_ahk_runtime_global`（RVA `0x141bf0`，old `0x8000±0x2000` → new `0x180` 全零）**未在本次 live 中执行**。

## 13. raw_slab_overlay verdict

**未到达**（管线在 transform_input_seed 失败，早于 raw_slab_overlay）。

## 14. runtime rebase plan / manifest verdict

**未到达 / 未生成。**

## 15. candidate count / path / hash / size

**0**（`candidate\` 目录为空）。

## 16. 第一失败 stage / reason

- **stage**：`transform_input_seed`
- **event**：`error`
- **reason（typed）**：
  ```
  raw capture drift: kind=heap_global child 0x3327260 size 0x28 slab [0x894000,+0x2a93288)
  offset 0x2a93260 first_mismatch=0x0
  raw_child_sha=adbb0c0a6842e2fed5cebcca7915c3c3a085d1a227e2f5e8626c502b906be56c
  raw_slab_slice_sha=a6ec10866244f8906f4f14db1a9521b9077ede0856fcf5bab5cdda5678af395e
  ```
- child 0x3327260 = RVA `0x144400` 的 heap-global slot（size 0x28），非 declared reinit 目标。

## 17. 与 Route X R1 的精确差异

| 项 | Route X R1（9450b3a） | Route Y R1 A2（68b8032） |
|---|---|---|
| transform_input_seed | **成功**（exit，item_count=316，~272s） | **失败**（error，item_count=0，~108s） |
| 下一 stage | sanitize_ahk_runtime_global | 无（fail-closed） |
| sanitize | 执行，size drift（32768→384）fail-closed | **未到达** |
| 失败点 | sanitize（declared size 误判，Route Y 已修复） | transform_input_seed（raw capture drift，child 0x3327260） |
| 状态 | RouteX_R1_CandidateNotReady | RouteY_R1_A2_CandidateNotReady |

## 18. 严谨判断：非 Route Y 语义回归

本次失败在 `transform_input_seed` stage（seed 阶段），**早于** Route Y R0 修复的 sanitize / overlay。
已只读核实：
- `seed_transform_inputs_from_authoritative_slab` 函数体在 Route Y commit（9450b3a → 68b8032）**逐字一致（IDENTICAL）**；
- `is_raw_coherence_participant` 谓词定义于未改动的 `heap_global_snapshot.rs`，未变；
- `capture_identity_bind` / `capture_coverage_bind` / `raw_children_from_capture` 均未改动；
- Route Y 改动集中在 seed **之后**的 `validate_run_membership` 与 `build_patched_backing_slab_q0c`（overlay）。

child 0x3327260（RVA 0x144400）**未出现在 Route X R1 捕获集合中**（两次 live 进程内存布局不同）。
本次为 live 样本**数据/时序不确定性**：child 的 raw bytes 与权威 slab 不一致，触发 seed 阶段固有的
fail-closed 完整性保护（raw capture drift）。**这不是 Route Y R0 引入的语义回归。**

**重要限制**：因失败点在 sanitize 之前，本次 live **无法验证** Route Y R0 的核心修复
（declared size-reinit 是否被 recorder/Q0-C 接受）。该验证需要一次能越过 `transform_input_seed`
的 live run。

## 19. 禁止事项执行确认

- ✅ 未修改任何 Rust/Python/PowerShell 源代码、Cargo、capture policy
- ✅ 未修改 `docs/GTO_ROUTE_X_R1_LIVE_RESULT.md`、`docs/GTO_ROUTE_Y_R0_OFFLINE_RESULT.md`、`docs/GTO_ROUTE_Y_R1_LIVE_RESULT.md`
- ✅ 未 git add/commit/amend/reset/checkout/push
- ✅ 第二次 protected-sample spawn = 0（本次为唯一 1 次授权）
- ✅ 失败后未修正参数重跑（A2 已终止）
- ✅ 未手工绕过 controller 启动 sample
- ✅ 未注入 bypass/semantic-repair 环境变量
- ✅ 未单独启动/cold-start/promote candidate
- ✅ 未将失败改写为成功
- ✅ 未删除/覆盖/复用第一次 NotRun evidence
- ✅ 保留原始 binary evidence（child.stderr.bin 89192 字节原件）

## 20. 最终状态

**`RouteY_R1_A2_CandidateNotReady`**

> protected sample 已 spawn（唯一 live 授权已消耗），管线在 `transform_input_seed` 因
> `raw capture drift`（child 0x3327260）fail-closed，candidate=0，未到达 sanitize。
> 失败非 Route Y 语义回归（seed 阶段既有 fail-closed；Route Y 未改 seed 路径）。
> 因未到达 sanitize，Route Y R0 的 declared size-reinit 修复本次 live 未能验证。
> 按工单边界，A2 终止；Route Y R1 修复/重跑须另行授权。

---

## 最终回报

- **baseline/head**：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`）
- **corrected child argv[0]**：`D:\MidaVault\scratch\cargo-target-route-y1\debug\mida-cli.exe`
- **attested binary path**：`D:\MidaVault\scratch\cargo-target-route-y1\debug\mida-cli.exe`
- **path equality**：**PASS**（raw + Resolve-Path 均相等）
- **build verdict**：**PASS**（SHA `ecaffb07...` / size `10998272` / `gto_product_recovery=true` / baseline `68b8032`）
- **preflight verdict**：**PASS**（五层全过）
- **protected sample spawn count**：1（PID 17936 mida-cli / PID 1820 artifact）
- **elapsed / timeout**：121547 ms / 600 s（timed_out=false，自然退出）
- **last successful stage**：`raw_children_from_capture`
- **first failing stage**：`transform_input_seed`（raw capture drift，child 0x3327260）
- **raw_slab_overlay verdict**：未到达
- **runtime plan verdict**：未到达
- **manifest verdict**：未生成
- **candidate count / path / hash / size**：0 / - / - / -
- **A2 evidence directory**：`D:\MidaVault\lab\evidence\gto_launcher\live_20260811T065313Z_route_y_r1_declared_size_reinit_a2\`
- **A2 report path**：`docs\GTO_ROUTE_Y_R1_LIVE_RESULT_A2.md`（untracked）
- **git status**：branch `oreans/two-sample-mainline`，HEAD `68b8032`，无 tracked 修改，untracked 4 个 docs
  （X R1 结果 / Y R0 结果 / Y R1 NotRun / Y R1 A2 结果）
- **A2 最终状态**：**`RouteY_R1_A2_CandidateNotReady`**
