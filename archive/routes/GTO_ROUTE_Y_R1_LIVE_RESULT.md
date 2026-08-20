# GTO Product Recovery — Route Y R1 Declared Size-Reinit Live Truth Run

> 状态：**`RouteY_R1_NotRun`**（preflight 未通过，**未 spawn**，未消耗 live 授权，未重跑）。
> 授权 baseline：`68b8032`。branch = `oreans/two-sample-mainline`。

---

## 1. 授权 baseline 核对（只读）

| 检查 | 预期 | 实际 | 结果 |
|---|---|---|---|
| branch | `oreans/two-sample-mainline` | `oreans/two-sample-mainline` | ✅ |
| HEAD | `68b8032` | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` | ✅ |
| HEAD^ | `9450b3a` | `9450b3aed570ff42c62a248f7e7013540a7e1348` | ✅ |
| HEAD commit 仅含 `raw_slab_coherence.rs` | +1858/−190 | +1858/−190 | ✅ |
| 无 tracked 工作树修改 | 是 | 是 | ✅ |
| untracked 仅两个 docs | 是 | `docs/GTO_ROUTE_X_R1_LIVE_RESULT.md`、`docs/GTO_ROUTE_Y_R0_OFFLINE_RESULT.md` | ✅ |

**baseline 全部匹配。**

---

## 2. UTC run timestamp

- 运行开始：`2026-08-11T06:41:37.126Z`
- 结束：`2026-08-11T06:41:37Z`（controller 立即以 exit 7 返回，未 spawn）

## 3. Evidence 绝对路径

```
D:\MidaVault\lab\evidence\gto_launcher\live_20260811T063619Z_route_y_r1_declared_size_reinit\
  capture_policy.json
  controller_attempt_001.json
  controller_run.json
```

## 4. 五层 preflight 结果

| 层 | 结果 |
|---|---|
| 1. Git baseline/head gate | ✅ 通过（HEAD=68b8032, HEAD^=9450b3a, 无 tracked 修改） |
| 2. Build capability/attestation gate | ❌ **`build_binary_path_mismatch`**（见下） |
| 3. Authorized effective environment gate | ⏸ 未到达（build gate 先失败） |
| 4. Capture policy argument/file gate | ⏸ 未到达 |
| 5. Live environment/sample/controller gate | ⏸ 未到达 |

**Build capability rejection 详情**（`controller_run.json` / `build_capability_preflight`）：
```json
{
  "attested_path": "D:\\MidaVault\\scratch\\cargo-target-route-y1\\debug\\mida-cli.exe",
  "build_attestation_arg_present": true,
  "build_attestation_exists": true,
  "child_argv0": "--",
  "failure_reason": "build_binary_path_mismatch",
  "ok": false
}
```

**根因**（调用方式，非 baseline/代码问题）：controller 的 `args.command` 是 argparse
`REMAINDER`；本次调用在子命令前使用了 `--` 分隔符，argparse 把 `--` 本身捕获为
`command[0]`，导致 controller 读取的 `child_argv0 == "--"`，与 attestation 中登记的
binary path 不匹配。attestation 登记的 binary path 本身是正确的
（`D:\MidaVault\scratch\cargo-target-route-y1\debug\mida-cli.exe`）。

- canonical build **成功**：baseline `68b8032`，`gto_product_recovery=true`，
  binary SHA-256 `ecaffb07b3f1e413fa2dcf894a7ce1c7156ef27b4f6a4de7ab77c4219eab1871`，
  size `10998272`（与 attestation 独立复验一致）。
- controller 返回值：**exit 7**（build-capability gate 失败专用码）。
- **未调用 Popen/Start-Process**；**未 spawn 保护样本**。

## 5. Spawn 次数

**0**（`spawned=false`, `pid=null`）。未消耗唯一 live 授权。

## 6. Configured / Actual timeout

- configured：`600.0` s
- actual elapsed：`0` ms（preflight 在 spawn 前失败，未进入等待）

## 7. 完整 stage timeline

无 —— 保护样本从未 spawn，未进入任何 stage。

## 8. sanitize declared transition 证据

未到达 —— preflight 在 spawn 前终止。Route Y R0 的 declared size-reinit 修复
（`sanitize_ahk_runtime_global`，RVA `0x141bf0`，old `0x8000±0x2000` → new `0x180` 全零）
**未在本次 live 中执行**。

## 9. raw_slab_overlay 是否通过

未到达（未 spawn）。

## 10. runtime rebase plan 是否到达

未到达。

## 11. manifest 是否生成

未生成。

## 12. candidate count / path / hash / size

**0**。`candidate\` 目录存在但为空（仅预建）。

## 13. 第一失败 stage / reason

- 阶段：**preflight（spawn 前）**，非 live 管线 stage。
- reason：`build_binary_path_mismatch`（`child_argv0 == "--"`，与 attestation binary path 不符）。
- 完整 typed 信息保留于 `controller_run.json`。

## 14. 与 Route X R1 的精确差异

| 项 | Route X R1 | Route Y R1（本次） |
|---|---|---|
| 授权 baseline | `9450b3a` | `68b8032` |
| spawn | 1（真实执行至 sanitize） | **0（preflight 未过）** |
| raw_slab_overlay | 到达，sanitize size drift 失败 | 未到达 |
| 状态 | `RouteX_R1_CandidateNotReady` | **`RouteY_R1_NotRun`** |

## 15. 禁止事项执行确认

- ✅ 未修改任何 Rust/Python/PowerShell 源代码
- ✅ 未修改 Cargo.toml/Cargo.lock / capture policy
- ✅ 未修改 `docs/GTO_ROUTE_X_R1_LIVE_RESULT.md`、`docs/GTO_ROUTE_Y_R0_OFFLINE_RESULT.md`
- ✅ 未 git add/commit/amend/reset/checkout/push
- ✅ 无第二次 protected-sample spawn（本次为 0 次）
- ✅ 未修复后重跑（严格按工单终止）
- ✅ 未手工启动 launcher/sample 绕过 controller
- ✅ 未注入 bypass/semantic-repair 环境变量（`MIDA_GTO_NO_BYPASS=1` 已显式 set，bypass/semantic 均缺失）
- ✅ 未启动/cold-start/promote candidate
- ✅ 未将失败改写为成功
- ✅ 未删除/覆盖/复用已有 evidence 目录（新目录 `live_20260811T063619Z_route_y_r1_declared_size_reinit\`）
- ✅ 保留原始 binary evidence（本次无 child 输出，因为未 spawn）

## 16. 最终状态

**`RouteY_R1_NotRun`**

> preflight 未通过（`build_binary_path_mismatch`，调用方式问题）且未 spawn。
> 按工单执行边界，本工单终止，未消耗 live 授权，未重跑。
> 修正 controller 调用参数（使子命令 argv[0] 直接为 canonical binary、不带 `--` 前缀）
> 后，需**重新单独签发** Route Y R1 授权方可重跑。

---

## 现场只读事实汇总

- **build attestation verdict**：binary SHA-256 `ecaffb07b3f1e413fa2dcf894a7ce1c7156ef27b4f6a4de7ab77c4219eab1871` / size `10998272` / `gto_product_recovery=true` / baseline `68b8032`，**与 attestation 一致，build 有效**。
- **preflight verdict**：`build_binary_path_mismatch`（`child_argv0="--"`），exit 7，spawned=false。
- **protected sample spawn count**：0
- **elapsed / timeout**：0 ms / 600 s
- **last successful stage**：无（未 spawn）
- **first failing stage**：preflight（build-capability gate）
- **raw_slab_overlay verdict**：未到达
- **runtime plan verdict**：未到达
- **manifest verdict**：未生成
- **candidate**：0
- **evidence directory**：`D:\MidaVault\lab\evidence\gto_launcher\live_20260811T063619Z_route_y_r1_declared_size_reinit\`
- **live report path**：`docs\GTO_ROUTE_Y_R1_LIVE_RESULT.md`（本文件，untracked）
- **git status**：branch `oreans/two-sample-mainline`，HEAD `68b8032`，无 tracked 修改，untracked 仅 3 个 docs（X R1 结果 / Y R0 结果 / Y R1 结果）
