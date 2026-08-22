# WO-1006 架构对位图

**派单前置交付物** | 2026-08-22  
**关联工单**: WO-1005 复审 | **审批人**: owner

---

## 一、生产实况（已入链/运行中）

### 1.1 Runtime DLL 栈（antidebug-runtime）

**角色**: C ABI DLL，注入到目标进程内部执行  
**生产入口**: `MidaAntidebugInitialize` (exports.rs:182)  
**调用链**:

```
CLI unpacker::run_runtime_loader (L561)
  → 注入 antidebug-runtime.dll
  → VirtualAllocEx + WriteProcessMemory (参数序列化)
  → CreateRemoteThread 执行 thunk
  → MidaAntidebugInitialize(params, attestation_out)
    → install_proc_surfaces (exports.rs:244)
      → install_proc_002 (BeingDebugged)
      → install_proc_003 (pShimData)
      → install_proc_004 (NtGlobalFlag) [WO-1001]
      → install_proc_005 (Heap ForceFlags) [WO-1001]
```

**已激活 Surfaces**:

| Surface ID    | 目标字段              | 操作          | 生产状态 | 证据位置                     |
|---------------|---------------------|---------------|---------|----------------------------|
| AD-PROC-002   | PEB.BeingDebugged   | 清零 + 回读    | ✅ 已入链 | exports.rs:244, proc.rs:615 |
| AD-PROC-003   | PEB.pShimData       | 清零 + 回读    | ✅ 已入链 | exports.rs:244, proc.rs:615 |
| AD-PROC-004   | PEB.NtGlobalFlag    | 清除调试标志    | ✅ 已入链 | proc.rs:406, L16测试通过    |
| AD-PROC-005   | ProcessHeap.ForceFlags | 清除调试标志 | ✅ 已入链 | proc.rs:469, L16测试通过    |

**设计意图**: 目标进程**自修改 PEB/堆结构**，在调试器读取前就伪装成未调试状态。

---

### 1.2 调试器侧栈（themida/antiantidebug handlers - 部分接线）

**角色**: 调试器进程内的事件响应器，篡改目标进程的寄存器/栈/返回值  
**生产入口**: CLI unpacker 调试事件循环 (unpacker/mod.rs:1106+)  
**调用链**:

```
CLI unpacker::run (观察轮调试循环)
  → WaitForDebugEvent
  → EXCEPTION_BREAKPOINT 事件
  → handle_nt_set_information_thread(dbg, thread_id) [unpacker/mod.rs:L1106]
    ↳ 检测 ThreadHideFromDebugger (0x11)
    ↳ 跳过调用 + 设置 EAX=STATUS_SUCCESS
```

**已接线 Handlers** (Phase 1 - 部分):

| Handler                                  | 反调试检测点                  | 生产状态       | 证据位置                        |
|------------------------------------------|---------------------------|--------------|-------------------------------|
| `handle_nt_set_information_thread`       | ThreadHideFromDebugger    | ✅ **已接线**  | unpacker/mod.rs:1106 (调试循环) |
| `handle_nt_query_information_process`    | ProcessDebugPort/Flags    | ❓ 待确认      | 需审查调试循环完整分支             |
| `handle_check_remote_debugger_present`   | CheckRemoteDebuggerPresent| ❓ 待确认      | 需审查调试循环完整分支             |
| `handle_output_debug_string`             | OutputDebugStringW        | ❓ 待确认      | 需审查调试循环完整分支             |

**设计意图**: 在调试器侧**拦截反调试 API 调用**，篡改参数/返回值后跳过原始调用。

---

## 二、休眠代码（零生产调用）

### 2.1 themida/antiantidebug - 未接线部分

**Phase 2 - CRDP/NtQueryObject 时序防御**:

| Handler                          | 设计意图                         | 状态         | 位置                   |
|----------------------------------|-------------------------------|--------------|----------------------|
| `handle_nt_query_object`         | 拦截句柄名称查询（检测调试对象）       | ⚠️ **休眠**   | handlers.rs:200+      |
| `handle_rdtsc`                   | 篡改时间戳计数器防时序检测            | ⚠️ **休眠**   | timings.rs            |
| `handle_query_performance_counter`| 篡改性能计数器防时序检测             | ⚠️ **休眠**   | timings.rs            |

**Phase 3 - KiFastSystemCall Hook (x86)**:

| 模块                  | 设计意图                    | 状态         | 位置           |
|----------------------|--------------------------|--------------|---------------|
| `install_kifast_syscall_hook` | x86 系统调用拦截层    | ⚠️ **休眠**   | kifast.rs:50+ |
| `handle_kifast_syscall`       | KiFastSystemCall 钩子 | ⚠️ **休眠**   | kifast.rs:80+ |

---

### 2.2 Legacy ScyllaHide 路径

| 模块                  | 设计意图                    | 状态             | 证据                          |
|----------------------|--------------------------|-----------------|------------------------------|
| `inject_scylla_hide` | 注入第三方反反调试 DLL      | ⚠️ **休眠**      | scyllahide.rs:20+            |
| `activate_antidebug` | WO-1005 双轨分支入口      | ⚠️ **零调用者**   | mod.rs:102（仅导出未调用）      |

**关键发现**:
```rust
// crates/packers/themida/src/lib.rs:44
pub use antiantidebug::{
    activate_antidebug, current_mode, handle_nt_query_information_process,
    // ...
};
```
→ `activate_antidebug` 仅被导出到 crate public API，**但无任何调用者**  
→ 原因：CLI unpacker 在观察轮（observation-only）阶段**跳过了反反调试注入**  
→ GTO 观察轮中 ScyllaHide 路径从未激活

---

## 三、架构分层决策矩阵

| 反调试技术           | 实现位置              | 理由                                                   | 现状        |
|---------------------|---------------------|------------------------------------------------------|-----------|
| **PEB 直接改写**     | Runtime DLL (目标内)  | 必须在目标进程地址空间内操作 gs:[0x60]                     | ✅ 已实现   |
| **堆标志清零**       | Runtime DLL (目标内)  | 需读取 PEB.ProcessHeap 并修改堆结构（目标地址空间专属）      | ✅ 已实现   |
| **API 调用拦截**     | 调试器进程（外部）      | 调试器持有 CONTEXT 句柄，可修改寄存器/栈后 ContinueDebugEvent | ✅ 部分接线 |
| **时序对抗**         | 调试器进程（外部）      | 需拦截 RDTSC/QPC 断点事件，篡改返回值                      | ⚠️ 未接线   |
| **句柄名称欺骗**     | 调试器进程（外部）      | NtQueryObject 拦截 + 返回值改写                          | ⚠️ 未接线   |
| **系统调用层钩子**   | ❓ **待论证**         | x86 KiFastSystemCall 全局钩子（侵入性强，稳定性风险）       | ⚠️ 未接线   |

---

## 四、WO-1006 前置问题清单

### Q1: Phase 2-3 归属决策

**Phase 2 (CRDP/NtQueryObject)**:
- 当前位置：`themida/antiantidebug/handlers.rs` (调试器侧，休眠)
- 候选方案 A：保持调试器侧，在 CLI unpacker 调试循环中接线（类似 `handle_nt_set_information_thread`）
- 候选方案 B：迁移到 Runtime DLL 的 surface 层（作为 AD-PROC-006/007）
- 论证点：NtQueryObject 能否在目标进程内拦截？是否需要调试器权限？

**Phase 3 (时序对抗)**:
- 当前位置：`themida/antiantidebug/timings.rs` (调试器侧，休眠)
- 候选方案 A：调试器侧接线（RDTSC/QPC 断点 + 寄存器改写）
- 候选方案 B：Runtime DLL inline hook（目标进程内 hook ntdll!NtQueryPerformanceCounter）
- 论证点：时序对抗的性能开销 vs 检测覆盖率权衡

---

### Q2: activate_antidebug 接线路径

**现状**: WO-1005 交付的 `activate_antidebug` 函数零调用者  
**原因**: CLI unpacker 在观察轮中直接调用 `runtime_loader::run_runtime_loader`，跳过了 Oreans 原有的 ScyllaHide 注入逻辑

**待确认**:
1. Oreans 生产线（非 GTO 观察轮）中 `activate_antidebug` 的实际调用点在哪？
2. 如调用点存在，Self 模式的接线方案是什么？（调试循环中根据 `current_mode()` 激活 Phase 1-3 handlers）
3. 如调用点不存在，是否应删除 `activate_antidebug` 并直接在调试循环中硬编码 handler 调用？

---

### Q3: Surface 边界扩展评估

**已有 Surfaces** (AD-PROC-002/003/004/005): 全部是 PEB/堆字段的**直接内存改写**  
**候选 Surfaces**:
- AD-PROC-006: NtQueryObject 钩子（如迁移到 Runtime）
- AD-PROC-007: RDTSC/QPC 钩子（如迁移到 Runtime）
- AD-PROC-008: OutputDebugString 钩子（如迁移到 Runtime）

**论证点**:
- Surface 模型是否应限定为"纯内存改写"（当前 002-005 的共性）？
- 还是扩展到"API 行为改写"（inline hook / IAT patch）？
- 如扩展，attestation 合同如何表达 hook 状态？（当前只有 `installed: bool`）

---

## 五、下一步 (WO-1006 正式工单需包含)

1. **架构归属论证**:
   - [ ] Phase 2 (NtQueryObject) → 调试器侧 or Runtime 侧？（技术可行性 + 权限边界分析）
   - [ ] Phase 3 (Timings) → 调试器侧 or Runtime 侧？（性能 vs 覆盖率权衡）
   - [ ] KiFastSystemCall hook → 保留 or 废弃？（x86-only，稳定性风险评估）

2. **接线方案设计**:
   - [ ] 如 Phase 2-3 归属调试器侧：补全 CLI unpacker 调试循环的断点处理分支
   - [ ] 如 Phase 2-3 归属 Runtime 侧：设计 surface 扩展模型（inline hook 的 install/restore/attest 合同）

3. **activate_antidebug 处置**:
   - [ ] 定位 Oreans 生产线的实际调用点（如存在）
   - [ ] 设计 Self 模式的完整接线路径（调试循环 + handler 激活时机）
   - [ ] 或论证其应废弃，直接在调试循环硬编码

4. **代码迁移执行** (架构对位图批准后):
   - [ ] 根据归属决策，将休眠 handlers 迁移到目标位置
   - [ ] 补全测试覆盖（单元测试 + E2E）
   - [ ] 更新 attestation 合同（如 surface 模型扩展）

---

## 附录：关键证据索引

| 主张                                | 证据位置                                      |
|-------------------------------------|---------------------------------------------|
| Runtime 002-005 已入链               | `exports.rs:244` + `proc.rs:615`            |
| handle_nt_set_information_thread 已接线 | `unpacker/mod.rs:1106` (grep 确认)       |
| activate_antidebug 零调用者          | `grep -r activate_antidebug crates/cli` 空输出 |
| Phase 2-3 handlers 休眠             | `grep -r handle_rdtsc crates/cli` 空输出    |
| GTO 观察轮跳过反反调试注入            | `unpacker/mod.rs:561` 直接调用 runtime_loader |

---

**审批流程**: 本对位图需 owner 审查上述 Q1-Q3 并批准归属方案后，方可启动 WO-1006 代码迁移。
