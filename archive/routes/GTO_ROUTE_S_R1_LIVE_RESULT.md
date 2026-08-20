# GTO Product Recovery — Route S R1 Capture-Identity Closure Live Truth Run

**日期：** 2026-08-10
**授权：** Route S R1（单次受保护 live truth run）
**起点提交：** `90ee9abfd675a340cf384fe4b276b64d85e9a6b9`
**分支：** `oreans/two-sample-mainline`
**终态：** **`RouteS_R1_CandidateNotReady`**

> 本文档是 **live 结果**。Route S R1 是一次 live truth run，不是 offline 修复。

---

## 1. 终态结论

本次唯一受保护 live run 在 **`runtime_rebase_plan_validation`** 阶段 **fail-closed**，**未生成 candidate**。

```
terminal_status:  RouteS_R1_CandidateNotReady
failure_stage:    runtime_rebase_plan_validation
failure_reason:   rebase plan: probe/interior region 2 (0x850150,+0x1000,
                  extent=ProbeWindow) is not contained in any authoritative
                  slab/parent; refusing independent allocation
```

## 2. 关键进展：Route R R1 阻断已消除

Route R R1 的根因链
（`DanglingEdgeCaptureIdentityMissing → EmptyTransformPreimageBindingCaptureId → ExactBindingRejected`）
**已修复并被本 live run 证实**：

- 管线 **越过** `capture_identity_bind` 与 `raw_slab_overlay` 阶段；
- **未出现** `TransformPreimageDrift` / `TransformPreimageBindingMissing` /
  `TransformPreimageBindingAmbiguous` / `TransformPreimageBindingIdentityInvalid` /
  `TransformRunLedgerInvalid` 任何一项；
- 原 `child=0x9a4d40 size=0x710` dangling-edge 不再产生错误；
- Route P 的 `child 0x8aa5f8 +0x28` 阻断未重新出现；
- 捕获到的新 failure 出现在 **更低地址** `0x850150`，发生在 overlay 之后的
  `runtime_rebase_plan_validation` —— 属路由后续阶段，非旧阻断回归。

## 3. 首要观察点核验（10 项成功判据）

| # | 判据 | 状态 | 证据 |
|---|---|---|---|
| 1 | `capture_id` 非空确定性值 | 通过（未失败） | 无 identity-gate 失败；管线越过该阶段 |
| 2 | raw child / binding / transformed child 三阶段 identity 一致 | 通过（未失败） | 无 identity 冲突错误 |
| 3 | `capture_identity_bind` 不失败 | ✅ | 管线未在此阶段报错 |
| 4 | `C=S=T=0x50` byte 0 不再报错 | ✅ | 无 `TransformPreimageDrift` |
| 5 | 真实 scrub 只记录实际变化字节 | 通过（未失败） | 无 `TransformRunLedgerInvalid` |
| 6 | scrub run 的 identity/size/digest/replay | 通过（未失败） | 无 binding/ledger 错误 |
| 7 | `TransformRunLedgerInvalid` 不出现 | ✅ | stderr 无该错误 |
| 8 | raw slab overlay 完成 | ✅ | 管线越过 overlay，到达 runtime_rebase |
| 9 | Route P `0x8aa5f8 +0x28` 不重新出现 | ✅ | 无该地址错误 |
| 10 | manifest / runtime plan / BootFixup / candidate 全自然产生 | ❌ **失败** | 在 runtime_rebase_plan_validation fail-closed，candidate 目录为空 |

**判据 10 未满足 → 不声明 `RouteS_R1_CandidateReady`。**

依据证据，**不声明** `ScriptRecovered` / `UiRecovered` / `OepReached`（无 manifest、runtime、
candidate 证据）。

## 4. 新阻断根因（初步）

`runtime_rebase.rs` GTO R0-F.1（fail-closed）要求每个 `ProbeWindow` / `InteriorSubview`
region 必须**被某个 authoritative `HeapSlab` 吸收**（pre-pass 吸收），否则拒绝独立分配。
本 run 中：

```
region 2: old_base=0x850150  size=0x1000  extent=ProbeWindow
```

没有任何 `HeapSlab` 覆盖 `0x850150..0x850150+0x1000`，故未吸收，触发 R0-F.1 fail-closed。

这是一个 **capture 阶段记录到 probe window、但无对应 slab seeding** 的 coverage 缺口，
与 Route R R1 的 identity/binding 问题不同源。具体是否属捕获缺口、应 seed 的 slab
范围、还是 probe window 应被上游忽略，需 offline 诊断（不属本次 live 授权范围）。

## 5. 预算执行

| 预算项 | 上限 | 使用 |
|---|---|---|
| route attempt | 1 | 1 |
| protected spawn | 1 | 1（debuggee PID 22972, terminated cleanly） |
| rerun / cold-start | 0 | 0 |
| candidate | 1（natural） | 0 |

- 首次 controller 调用因 argv[0] 用了 `"mida-cli"`（非真实可执行名）而 `pid=None`
  未 spawn 任何进程，**不计入 protected spawn**；
- 受保护 spawn 仅一次：debuggee **PID 22972**（日志 line 12 创建，line 599
  `Drop: terminated owned target + bounded wait (clean)`）；
- CLI **PID 15024**，exit 1，process tree `exited_naturally`，无 timeout（elapsed 65.5s）；
- 二次 spawn / rerun / cold-start / 手工 candidate：**0**。

## 6. 证据

工作区：`D:\MidaVault\lab\evidence\gto_launcher\live_20260810T035848Z_route_s_r1_capture_identity_closure\`
- `preflight.json` / `resolved_source.json` / `controller_run.json` / `route_ledger.json`
- `child.stdout.bin/txt` / `child.stderr.bin/txt`（stderr 权威证据，601 行）
- `capture_policy.json`
- `candidate/` **为空**（未生成 candidate）

CLI 二进制：`D:\MidaVault\scratch\cargo-target-route-s-r1\debug\mida-cli.exe`
sha256 `d7c4c8d87e45f73167d17dfa2acc01a890bc764c0d468b66f46cd5e89ceabc3a`

## 7. 边界与清理（已遵守）

- 未 rerun、未 cold-start、未手工修补 candidate、未伪造 acceptance；
- 仓库代码未改动：HEAD `90ee9ab`，tracked files unchanged，`git status --short` 为空；
- firewall deny_all（`gto-sr1-block-cli` / `gto-sr1-block-sample`）已清理；
- 无残留进程（PID 22972 / 15024 均已结束；无 mida/launcher/artifact 进程）；
- `.hermes/` 未纳入任何 commit；
- live budget：0 额外 attempt / 0 额外 spawn。

## 8. 结论

`RouteS_R1_CandidateNotReady`，fail-closed 于 `runtime_rebase_plan_validation`。

Route R R1 的 capture-identity 阻断已**确认修复**。新阻断是 capture coverage 缺口
（`0x850150` probe window 无 authoritative slab backing），属 offline 可诊断范围。

**下一步：** 请审计负责人核验本 live 证据。Route S R2 或后续 offline 诊断需另行书面授权。
