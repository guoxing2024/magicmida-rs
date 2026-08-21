# GTO-H5 PostSelfDecrypt 设计说明（WO-302，条件工单）

**触发条件**: WO-301 Round 1 数据支持——Immediate 时刻 .rdata2 熵 7.878 bits/byte > 7.5 阈值（确为高熵密文）；.rdata0 熵 7.426 逼近阈值。密文假设成立 → 本设计说明启动。
**状态**: DESIGN ONLY — 零代码改动；实现须另批（授权文件 §三：报总指挥批准后实施）。
**依据**: WO-102 修复路径设计（路径 d）+ WO-301 R1 报告 + GTO-H5-LIVE-AUTHORIZATION-2 §三。

---

## 一、目标与边界

**目标**: 在**有界观察窗**内观察受保护程序自身完成 .rdata0/.rdata2 解密（dump 时机后移），使候选 .rdata 内容为解密后状态，为 loader smoke 提供可执行内容。

**边界（授权文件 §四）**:
- ❌ 对目标进程写入（核心调试器既有语义除外：soft breakpoint 的 int3 指令修改、SuspendThread/ResumeThread 属调试器既有语义）
- ❌ 注入 / DRx 硬件断点 / VEH / bypass / semantic repair
- ❌ 样本/产物入 git；ADR7/Oreans 门/封存证据触碰
- ✅ 仅用 core 既有调试原语（DebugActiveProcess / WaitForDebugEvent / ContinueDebugEvent / ReadProcessMemory / SuspendThread / ResumeThread / soft breakpoint）

## 二、有界观察窗设计

### 2.1 观察窗定义
- **起点**: 候选进程创建 + 主线程恢复（现管线 Immediate 时刻）
- **终点**: 任一**客观完成判据**触发（见 §三），或**硬上限**（默认 60 秒，可配置）到达
- **窗内动作**: 仅**周期性只读采样**（ReadProcessMemory 读 .rdata0/.rdata2 前 4KB 抽样）+ 事件循环（WaitForDebugEvent 处理既有事件）

### 2.2 采样策略
- 每 500ms 对 .rdata0/.rdata2 各采样 4KB（与 R2 熵测量同口径）
- 计算采样熵（复用 section_reference::shannon_entropy_bits）
- 记录熵时间序列: [(t0, e0), (t1, e1), ...] → 证据 JSON

### 2.3 观察窗内零写入清单（硬约束）
| 动作 | 允许 |
|---|---|
| ReadProcessMemory（采样 .rdata0/.rdata2） | ✅ |
| WaitForDebugEvent / ContinueDebugEvent | ✅（调试器既有语义） |
| SuspendThread / ResumeThread | ✅（调试器既有语义） |
| soft breakpoint（int3 注入） | ✅（调试器既有语义；仅用于事件定位） |
| WriteProcessMemory | ❌（禁止） |
| VirtualAllocEx / 注入 | ❌ |
| 修改 PE 头 / 节表 | ❌ |
| DRx 硬件断点 | ❌（授权禁止） |

## 三、完成判据（不许猜解密完成）

**原则**: 任何判据必须是**可观测、可复现、非猜测**的客观信号。以下判据按优先级：

### C1（首选）: 熵稳定下降
- .rdata0 与 .rdata2 采样熵均 < 6.5 bits/byte（密文 7.8+ → 代码/数据 6.0-）
- **且**连续 3 个采样点（≥1.5s）保持 < 6.5 → 判定解密完成
- 拒绝猜解密完成：熵下降是直接观测，不是推断

### C2（辅助）: 执行流进入 .text
- 事件循环观测到 RIP ∈ .text（0x1000-0x12BECB）且稳定执行 > 2s（非单步路过）
- 表示 Themida 已把控制权交给真实代码

### C3（备用）: 硬上限到期
- 60s 观察窗耗尽仍无 C1/C2 → 记录未观察到解密完成 → **fail-closed 拒绝 PostSelfDecrypt dump**（不产出候选）
- 此判据保证有界性，不猜测

**判定组合**: C1 ∧ (C2 ∨ 无需 C2) 为解密完成；仅 C3 → 失败。C1/C2 均需事件循环持续运行（不冻结目标，保持进程推进）。

## 四、仅用 core 既有调试原语

| 原语 | 来源 | 用途 |
|---|---|---|
| DebuggerCore::new / CreateProcess | core/debugger.rs | 创建带调试的候选进程 |
| WaitForDebugEvent / ContinueDebugEvent | core/debug_event_lifecycle.rs | 事件循环 |
| read_memory | core/windows_debugger.rs:1251 | 采样 .rdata 熵 |
| SuspendThread / ResumeThread | core/windows_debugger.rs | 冻结/恢复（既有 freeze_process_threads） |
| set_soft_breakpoint | core/windows_debugger.rs:641 | 事件定位（可选） |
| runtime_engine::read | core/runtime_engine.rs:224 | 只读采样 |
| section_reference::shannon_entropy_bits | mida-pe（WO-201 新增） | 熵计算 |

**明确不使用**: 注入、DRx、VEH、WriteProcessMemory（目标写入）、VirtualAllocEx。

## 五、离线单元测试方案

| 测试 | 描述 | 验证点 |
|---|---|---|
| T1 熵序列检测 | 构造密文→解密字节序列（高熵 8KB → 低熵 8KB），断言 C1 判定触发 | 完成判据 C1 正确性 |
| T2 无解密不误判 | 全程高熵序列（模拟未解密），断言 C3 触发（fail-closed） | 无假阳性 |
| T3 判据边界 | 熵恰在 6.5 附近抖动（6.4/6.6 交替），断言不触发 C1（需连续 3 点 < 6.5） | 判据严格性 |
| T4 观察窗上限 | 采样序列超 60s 无 C1/C2，断言返回未观察到解密完成 | 有界性 |
| T5 零写入审计 | 静态审查观察窗代码路径：断言无 WriteProcessMemory 调用 | 零写入约束 |
| T6 熵 API 复用 | shannon_entropy_bits 对已知序列的确定性 | R2 复用正确性 |

全部离线（无真实样本），复用现有 mida-pe 测试基建。

## 六、失败模式表

| # | 失败模式 | 观测信号 | 处置 |
|---|---|---|---|
| F1 | Themida 依赖反调试/VM 环境，解密不启动 | 熵持续 > 7.5，无下降 | C3 超时 → fail-closed 拒绝 dump；记录环境不支持 |
| F2 | 解密中途崩溃（AV 在加密区） | 事件循环收到 EXCEPTION_ACCESS_VIOLATION | 记录崩溃现场 → 本轮失败，不产出候选 |
| F3 | 解密完成但 .text 执行不稳定（C2 不满足） | RIP 未稳定进入 .text | C1 满足但 C2 不满足 → 记录部分完成，按 C1 判定（保守） |
| F4 | 采样读失败（页保护变化） | ReadProcessMemory 返回错误 | 记录采样失败次数；连续 5 次失败 → C3 等效处理 |
| F5 | 观察窗内目标自行退出 | 进程退出事件 | 记录退出码 → 本轮失败 |
| F6 | 熵阈值误判（代码本身高熵） | C1 触发但 smoke 仍 AV | 记录判据误判 → 设计需迭代（另批） |

## 七、对 WO-102 路径 (d) 的落地映射

- WO-102 R1（opt-in 一致性检查）: 已实现（WO-201），PostSelfDecrypt dump 前可选启用（传 SectionContentReference）
- WO-102 R2（熵观察）: 已实现（WO-201），观察窗采样复用同一 API
- 本设计新增: **观察窗时序**（dump_process 的 dump_timing=PostSelfDecrypt 分支）——**实现需另批**（授权文件 §四红线：未签 Round 2 设计前禁止实现）

## 八、结论

- 条件工单触发确认: .rdata2 熵 7.878 > 7.5（WO-301 §三）→ **密文假设成立**
- 本设计提供: 有界观察窗（60s 硬上限）、非猜测完成判据（C1 熵稳定下降/C2 执行流/C3 超时）、零写入清单、core 原语映射、离线单测（T1-T6）、失败模式表（F1-F6）
- **零代码改动**；实现须报总指挥批准（Round 2 授权）
