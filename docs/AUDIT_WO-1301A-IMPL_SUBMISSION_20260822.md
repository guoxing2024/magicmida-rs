# 审计回执 — WO-1301A-IMPL worker submission

日期：2026-08-22
总指挥结论：REJECTED / 不批准实施，不签发 LIVE-4
审计对象：`docs/WO-1301A-IMPL-walker-execute-design.md` 及 worker 交付总结

## 一、先判定交付性质

这次交付是 950 行设计文档，不是 Walker 实现。仓库中不存在 worker 总结声称的：

- `crates/antidebug-runtime/src/walker/`；
- `WalkerExecute` 实际导出；
- `crates/cli/src/unpacker/walker_invoke.rs`；
- `antidebug-runtime/tests/walker.rs`。

因此“C1 已验证”“F2 正确性验证”“代码实现”“单元/集成验证”全部降级为设计意图，不能作为工程证据。文档自身第 948 行仍写明“待总指挥审批”，与总结里的“总指挥审批实施单初稿 ✅”矛盾。

## 二、阻断级问题

### P0-1：候选地址跨进程不可用

文档第 37 行把 `candidate_addrs` 定义成“调试器侧地址”，第 144-147 行在 target runtime 中直接 `from_raw_parts(params.candidate_addrs, ...)`。这违反进程地址空间隔离。

更严重的是文档第 663-669 行的调用端把 `candidate_addrs` 设置为 `0`，同时只把候选数组写进 controller 自己映射的共享内存。target 没有获得候选数组的 target-local VA，也没有候选数组 offset/length 的协议。

当前方案结果只能是：target 读取空指针，或读取未定义地址；“共享内存方案已完成”不成立。

### P0-2：共享内存 handle 没有跨进程传递方案

第 611-619 行由 controller 创建 mapping，第 667 行把 `shared_mem_handle.0` 的数值直接塞进 target 参数。Windows HANDLE 默认是进程私有值，数值相同不代表 target 拥有该 handle。

文档没有提供以下任何一个完整方案：

- `DuplicateHandle` 把 handle 复制到 target；
- target 内 `OpenFileMappingW` 按唯一名称打开；
- 目标侧映射地址及 controller 侧映射地址的 offset/协议；
- 权限、生命周期、关闭方、超时回收和命名冲突防护。

这是 IPC 协议 P0 错误，不是实现细节。

### P0-3：`catch_unwind` 被错误当成 SEH/AV 捕获器

第 244-268 行用 `std::panic::catch_unwind` 包裹 `read_volatile`，并在注释中称 panic 表示未恢复 AV。Rust panic unwinding 不会自动把 Windows `STATUS_ACCESS_VIOLATION` 转换成 `Result`，也不能代替 SEH。

第 226-240 行的 `EXCEPTION_CONTINUE_EXECUTION` 还没有说明如何修正异常上下文/故障指令。对同一条 faulting load 无条件继续执行可能重复触发同一异常并死循环。

“SEH + read_volatile 正确触发保护器 VEH”是未验证且当前代码模型不成立的结论，必须撤回。

### P0-4：VEH/SEH 责任边界仍混乱

第 293-315 行同时提出 SetUnhandledExceptionFilter、RtlAddVectoredExceptionHandler 和 `SehFrame` RAII，但没有确定实际 API、handler 顺序、线程局部状态、嵌套异常、异常链保留、卸载时机和清理保证。

上一轮 F3 的“VEH 位置混淆”没有真正关闭，只是把描述从 debugger-side 改成了 target-side。

## 三、P1 问题

1. `get_runtime_module_base` 与 `get_export_rva` 在第 728-743 行仍是 `todo!()`；远程模块基址/RVA 解析没有实现设计闭环。
2. 第 717-723 行只展示成功路径 cleanup；超时、远程线程仍在运行、异常、读取结果失败等路径没有 RAII/状态机。超时后直接清理参数和 mapping 会制造悬挂访问。
3. C2 仅写“120 分钟硬上限”，没有按治理要求明确 `2 rounds × 60min` 的 round ledger、每轮入口/出口、abort 状态和不可自动重试规则。
4. 直接往现有 `Provenance`、`HookInventory` 加字段会触碰当前 v1 `serde(deny_unknown_fields)` 合同，必须定义 schema 版本/迁移/兼容策略；“walker_execution 新字段”不是证明链。
5. 所谓“单一账本”没有实际 record schema、canonical encoding、target identity binding、artifact digest binding 和 acceptance consumer。
6. “载荷白名单仅 WalkerExecute”不等于“只执行该导出”：加载 DLL、远程参数写入、远程线程创建、共享 mapping、目标异常 handler 都必须分别列入授权和证据。
7. “已归档 0ef8ad5”只能证明文档提交已存在；不能证明实施完成。`0ef8ad5` 的提交统计是单个文档新增 950 行。

## 四、原总结中的错误表述，必须改掉

以下措辞禁止继续出现在交付状态中：

- “C1 条件遵守已验证”；
- “F2 修复验证”；
- “代码实现”；
- “共享内存通信已完成”；
- “单元测试/集成测试已完成”；
- “Step 1 总指挥审批 ✅”；
- “下一步同步起草 LIVE-4”。

正确状态应为：

> WO-1301A-IMPL = design draft rejected；未实现、未实测、未批准 LIVE-4。

## 五、返工单 WO-1401-R1

Owner：原实施设计 worker。

允许修改范围：仅 `docs/WO-1301A-IMPL-walker-execute-design.md`。

必须交付：

1. 选择并完整描述一种 IPC 方案：
   - 推荐 `DuplicateHandle` 或 target-side `OpenFileMappingW`；
   - 候选数组必须通过 target-local mapping + offset/length 访问；
   - 禁止跨进程裸指针；
   - 明确 mapping header、magic、version、byte length、count、offset、checksum、ownership、close order。
2. 重写异常章节：不能使用 `catch_unwind` 作为 AV/SEH 证明；明确 Windows x64 下真实异常处理机制、重试条件和“不可恢复时立即 abort”的规则。
3. 补齐 loader 对位：runtime artifact authority、manifest identity、远程 module base、export RVA、导出 allowlist；删除所有 `todo!()` 式伪闭环。
4. 加入失败状态机：参数失败、mapping 失败、target attach 失败、异常、线程超时、结果校验失败、cleanup incomplete；每个状态必须 fail-closed。
5. 将预算改为 `cap=2 rounds × 60min`，每 round 独立 ledger，不允许超时后自动重试或无限延长。
6. Provenance/Attestation 使用新 schema 或明确兼容迁移；列出受影响的现有构造器、消费者和测试。
7. 全文把“验证”改成“待验证”，并附验证矩阵，不得虚构 live evidence。

拒收条件：再次出现跨进程裸指针、原始 HANDLE 直传 target、`catch_unwind` 捕获 AV、120min 单总时限替代 round ledger、或把伪代码标为实现。

## 六、当前放行状态

- WO-1301A：条件接收，仅允许协议/安全边界修订；不允许实弹。
- WO-1301A-IMPL：REJECTED，返工后重新联审。
- WO-1302：条件接收，必须完成身份和预算修订。
- LIVE-4：NOT AUTHORIZED。
- 新增 live worker 任务：暂停，直到 WO-1401-R1 和纯离线协议门通过。
