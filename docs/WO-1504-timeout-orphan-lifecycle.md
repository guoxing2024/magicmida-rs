# WO-1504 — Timeout/orphan 生命周期合同

**工单编号**: WO-1504
**优先级**: P1
**性质**: design-only（不改 loader 实现）
**日期**: 2026-08-22
**基线**: 786630b（WO-1401-R1 条件接收）
**状态**: 冻结候选 — 待总指挥联审

## 0. 目的

P1-D 审计要求：TimedOut 后"由 target 进程退出回收"没有 controller 侧可审计生命周期。
本文件定义 controller-owned durable orphan ledger 的完整状态机、持久化、恢复与禁止重入规则，
以及释放 blob/section 的唯一安全条件。

## 1. 生命周期状态机

每个 walker 会话（一次 round 的 params blob + result section）在 controller 侧持有
一条 durable ledger 记录，状态迁移如下：

~~~text
created
  │
  ├─(wait Finished 且 completed_flag ∈ {1, 0xDEAD****}) → reclaimed（正常路径：
  │    读取结果 → 记录 → 释放 blob/section → ledger 关闭）
  ├─(wait TimedOut / WaitFailed) → timed_out
  │       │
  │       ├─(target exit 观察到) → target_exit_observed
  │       │       │
  │       │       ├─(OS 回收确认有观察证据) → os_reclaimed
  │       │       └─(无法确认) → unconfirmed（终态，可人工复核）
  │       └─(target 仍存活，无法观察 exit) → unconfirmed
  └─(创建阶段失败: section/params/attach 失败) → failed_no_resources（无远程资源，直接关闭）
~~~

### 1.1 状态定义

| 状态 | 含义 | 允许释放远程资源？ | 退出条件 |
|------|------|------------------|---------|
| created | 资源已创建，线程未启动或等待中 | 否（线程可能已启动） | Finished + flag 校验通过 |
| timed_out | wait 超时，线程状态未知（可能仍运行） | **否** | target exit 观察 |
| target_exit_observed | 已确认 target 进程退出（WaitForSingleObject(target_handle) 或进程枚举消失） | **仍否**：OS 回收是异步的，且我们不知道 kernel 何时完成地址空间销毁；仅当有额外证据（如 handle 关闭回调）才可 | os_reclaimed 或 unconfirmed |
| os_reclaimed | 有明确观察证据表明 OS 已回收（如 NtQueryInformationProcess 失败 + 句柄失效，或专用回收观察器确认） | 是（仅作记账；不主动 VirtualFreeEx——进程已死，调用本身无意义且可能失败） | 关闭 ledger |
| unconfirmed | 无法获得回收证据；**永久保持** | 否 | 人工复核后可人工关闭（带说明） |
| failed_no_resources | 创建阶段失败，无远程线程 | 是 | 关闭 ledger |

### 1.2 释放的唯一安全条件

**远程线程 Finished 且结果状态已读取/记录**（completed_flag ∈ {1, 0xDEAD****} 且 wait == Finished）
才是释放 blob/section 的唯一充分条件。除此之外（created 中途、timed_out、wait_failed、
unconfirmed）一律禁止释放——这是 §5.4 铁律的持久化版本。

## 2. durable ledger 存储

### 2.1 存储位置与格式

- ledger 文件：controller 运行目录下 walker_orphan_ledger.json（每次会话追加/更新，原子写：
  写临时文件 + rename）。
- 记录字段（与 WO-1503 §3.4 Orphan 对齐）：

~~~json
{
  "ledger_version": 1,
  "records": [
    {
      "session_id": "hex",            // = derive_session_id(nonce, base, count)
      "target_pid": 4242,
      "created_ts": "2026-08-22T00:00:00Z",
      "timeout_ts": null,
      "state": "timed_out",
      "blob_base_va": "0x...",
      "section_name": "Local\\MidaWalkerResult-...",
      "round_index": 1,
      "reclaim_note": null
    }
  ]
}
~~~

### 2.2 写时机

- created：会话开始时写入（非孤儿也写，正常完成时标记 reclaimed 并保留 N 天审计）。
- timed_out：wait 超时**立即**写（不能依赖 target 返回 attestation——超时恰恰是拿不到返回）。
- target_exit_observed / os_reclaimed / unconfirmed：观察事件发生时更新。

## 3. target exit 观察

### 3.1 观察方式（controller 侧，不注入 target）

1. target 进程句柄（controller 启动 target 时持有）：WaitForSingleObject(handle, 0) 返回
   WAIT_OBJECT_0 → 已退出。
2. 进程枚举：OpenProcess 失败（ERROR_INVALID_PARAMETER 或 ACCESS_DENIED 需区分）——仅作为辅助。
3. 退出码读取：GetExitCodeProcess 返回 STILL_ACTIVE 判定。

### 3.2 观察失败

- controller 崩溃重启：重启后扫描 ledger，所有 state ∈ {created, timed_out} 的记录必须
  重新评估 target 存活；无法确认 → 置 unconfirmed，**绝不静默转 os_reclaimed**。
- 观察超时（如 target 是守护进程不退出）：ledger 保持 timed_out 直至人工处置；
  禁止自动强制杀 target（无 LIVE-4 授权）。

## 4. 禁止重入与重复 PID

### 4.1 禁止重入规则

- 同一 session_id 不得在 ledger 中出现两次 active（state ∈ {created, timed_out,
  target_exit_observed, unconfirmed}）记录；启动新 round 前必须确认无 active 记录。
- 同一 target PID 上存在 active 记录时，**禁止**再次对同一 target 发起 walker（避免旁路
  同一 blob / 双重探针污染证据）。
- round 2 进入条件：round 1 无 orphan 或 orphan 已终态（os_reclaimed / 人工关闭），
  且获得显式人工授权（§6 治理）。

### 4.2 重复 PID 处理

- 新会话 target_pid 与 ledger 中 os_reclaimed / reclaimed 记录相同：允许（进程已死，PID 可能
  被复用），但 session_id（含 nonce）不同，证据链不受影响。
- 新会话 target_pid 与 ledger 中 timed_out / unconfirmed 记录相同：**拒绝启动**（禁止重入），
  除非人工复核并显式关闭旧记录。

## 5. 与 WalkerAttestation 的绑定

- orphan 记录是 controller 侧事实；WalkerAttestation.orphaned_resources 是 target 侧报告。
  两者**必须一致**才能关闭会话：controller 记账的 orphan 数 == target 报告的 orphan 数；
  不一致 → 以 controller 记账为准 + 标记 EvidenceInsufficient（WO-1503 §7）。
- timed_out 会话**没有** WalkerAttestation（target 未返回）——ledger 独立成立，
  不依赖 attestation 写入。
- unconfirmed 状态在 acceptance 中映射为 EvidenceInsufficient，不产生任何 walker 结论。

## 6. 治理与人工处置

- 自动重试：**禁止**（与 WO-1301A §6.2 auto_retry=false 一致）。
- 人工关闭 unconfirmed 记录：必须附带说明（何时、以何方式确认回收），写 reclaim_note。
- 人工授权 round 2：ledger 无 active 记录 + 总指挥显式批准（LIVE-4 范围外不自动）。

## 7. 实现前 checklist

- [ ] ledger 读写（原子写 + rename）+ 崩溃恢复扫描
- [ ] 状态机枚举与迁移函数（纯离线可测）
- [ ] 禁止重入检查（session_id / target_pid active 判定）
- [ ] target exit 观察三种方式
- [ ] 释放唯一条件断言（Finished + flag 校验）
- [ ] acceptance 映射 EvidenceInsufficient

## 8. 状态

| 对象 | 状态 |
|-----|------|
| WO-1504 生命周期合同 | design-only；待联审 |
| loader 实现 | 未修改 |
