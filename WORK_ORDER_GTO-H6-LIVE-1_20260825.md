# WORK ORDER — GTO-H6-LIVE-1: WALKER DISPATCH LIVE EXECUTION (SIGNED AUTH)

**签发依据**: GTO-H6-LIVE-AUTHORIZATION-1（owner 已签署, commit e7767d7）
**签发**: Hermes 总审计 2026-08-25
**性质**: 实弹执行单 — 对 vault 锚定 GTO 样本的 walker dispatch 首轮 live smoke
**账本**: GTO-H6-LIVE · Round 1 · used=0/2（每次 attempt 消耗一格）
**基线**: HEAD `8ee457a`（workspace 2714/0 绿）

## 1. 执行前提（attempt_001 前逐项实测，任何一项不满足即 STOP）

1. **样本身份**: `tools/resolve_gto_source_revision.ps1` revision_match=true，
   只执行匹配的 vault 对象（`11473d2e…`），mismatch 即 STOP;
2. **授权变量**: `MIDA_GTO_LIVE_AUTHORIZED=1` 仅在单命令窗口内设置，
   运行后立即清除并记录 AUTH_CLEARED 证据（沿用 H5-LIVE-2/3 先例）;
3. **环境护栏**: `MIDA_GTO_NO_BYPASS=1` 全程; 观察优先，禁止 bypass/
   semantic-repair 类操作;
4. **桥接构造**: `RemoteWalkerExecuteBridge` 经 §D 接线由 controller 在
   bind 成功后构造——本单是 LIVE 门打开后的唯一合法接线点；构造必须
   走双 sealed 交叉校验路径，任何手工构造 VA 即违规。

## 2. 执行序列（顺序不可调换）

| 步 | 动作 | 记录 |
|---|---|---|
| ① | preflight 身份解析 | resolved_source.json |
| ② | 授权窗口设置 + 清除证据 | auth_evidence.json |
| ③ | 调试启动 vault 样本（CREATE_PROCESS 路径） | launch log |
| ④ | runtime 注入 + exports 远程解析 | loader evidence |
| ⑤ | walker bind（install_walker_session_verified） | bind evidence |
| ⑥ | **dispatch 实弹**：WalkerExecute(params_va) 经桥接 CreateRemoteThread | dispatch observation |
| ⑦ | 双 round section 读回 + V2 attestation digest 校验 | consumer evidence |
| ⑧ | teardown 结构化释放 + 账本清零断言 | teardown report |
| ⑨ | 目标进程终止（观察窗硬上限 120s） | exit record |

## 3. 判据（二值）

- **LIVE-PASS**: 步⑥ raw status==0 且 步⑦ 两轮 DONE + digest MATCH
  且 步⑧ teardown Released+账本空 → GTO-H6-LIVE-2 申请开放
  （行为验证阶段）；
- **LIVE-FAIL**: 任何步失败/崩溃/超时 → 完整 DIAGNOSTIC 现场归档
  （崩点 RVA/section/regs/faulting addr），记账 used+1。
- FAIL 不自动重试设计变更；attempt_002 仅允许在总审计分析后重发
  **同一工单的参数级修正**（如等待预算），代码语义修改需新卡。

## 4. 禁止

- 执行任何非 vault 锚定的文件；就地修改样本；
- 关闭 NO_BYPASS、放宽 R5-R2/R3/R4 冻结门、伪造 raw status;
- attempt 上限 2（账本硬顶）；超时上限 120s/attempt;
- 把本轮结果写成 acceptance/perfect-unpack 声明——它是注入链
  首轮实弹验证，PASS 也只证明 dispatch mechanics 可用。

## 5. 交付物

- vault: `D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H6_LIVE1_R1\
  attempt_NNN\`（全量 sidecar + cdb/raw 日志；DSH 写不进 vault 则落
  evidence_staging 由总审计转移，沿用先例）
- repo: `docs/GTO_H6_LIVE1_REPORT.md` — 判定 + 判据对照表 + 账本更新
- 出口门 ini:

```ini
GTO_H6_LIVE1 = PASS / FAIL
LEDGER_USED = n/2
AUTH_CLEARED = true
NO_BYPASS_HONORED = true
TEARDOWN_CLEAN = true/false
OREANS_GATE_RECHECK = 17/17 (事后必跑)
```
