# WORK ORDER — IMP-09-CARRIER-R5-R4-TEARDOWN-OBSERVABILITY

**签发**: Hermes 总审计，owner 授权
**日期**: 2026-08-25
**前置**: R5-R3 PASS（独立审计 242/0，21 个 R5-R3 测试全绿）
**基线**: 当前工作树（R5-R3 未提交改动先行提交后以此为基线）

## 1. 目标

为 walker session 的完整生命周期补上 teardown 可观测性：

1. 生产 teardown 路径：session 结束（COMPLETED 或 ABORTED）后的远程内存
   释放序列（`VirtualFreeEx` / 失败时 `GetLastError` 捕获）；
2. 每步释放的结构化事件记录（地址、大小、free type、raw status、错误码）；
3. fail-closed：任一释放失败不吞错、不 silent retry、记录完整失败事件序列，
   但**不得阻断已成功产出的 output 的消费结果**（teardown 失败与 execute
   结果分离上报）；
4. rollback 兼容：teardown 必须复用 R5-R2 事务性 guard 的既有分配账本，
   禁止第二套记账。

## 2. 范围

允许：teardown 模块（新文件或 walker_session.rs 内限定区块）、对应协议
事件类型、测试、evidence writer。

禁止（沿用 R5-R3 全部禁止项）：不改 runner_preflight.rs、不接 live
dispatch/CreateRemoteThread/WPM、不动 R5-R2/R5-R3 已封存语义（round_flags
扩展布局不得改动）、不用 mock 冒充生产路径、不 silent retry。

## 3. 协议硬要求

- **T1 分离上报**: `TeardownOutcome { Released, PartiallyReleased{failed_steps},
  Failed{step, error} }` 与 WalkerExecute outcome 并列返回，不合并；
- **T2 事件完整性**: 每次 VirtualFreeEx 调用记录 (sequence, address, size,
  free_type, ok, last_error)；PartiallyReleased/Failed 时该记录必须可导出；
- **T3 幂等防护**: 同一分配二次释放必须被账本拒绝并记事件；
- **T4 ABORTED session**: abort 路径同样走 teardown，不留孤儿分配；
- **T5 无泄漏断言**: 测试证明正常/异常/abort 三条路径结束后 guard 账本清零。

## 4. 必须交付

1. 正向: COMPLETED 后全部释放；ABORTED 后全部释放；
2. 负向 ≥4: free 失败（injectable）→ PartiallyReleased；double-free 拒绝；
   账本不一致检测；teardown 失败不影响已产出 output 的消费；
3. 设计说明（释放顺序 + 与 R5-R2 guard 账本的关系图）；
4. raw evidence 从简一套 + 出口门 ini 实测值；
5. `offline_mock=true` / `live_authorized=false` 声明。

## 5. 出口门

```ini
R5_R4_TEARDOWN = PROVEN
R5_R4_EVENT_LEDGER = PROVEN
R5_R4_IDEMPOTENCY = PROVEN
R5_R4_ABORT_PATH = PROVEN
R5_R4_NO_LEAK = PROVEN
R5_R3_GATES_UNCHANGED = true
LIVE_AUTHORIZED = false
```

Correction 上限 = 1（同前）；证据从简（同前）。
