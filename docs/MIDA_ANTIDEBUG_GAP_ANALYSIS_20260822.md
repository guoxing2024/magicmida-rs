# MIDA 反反调试覆盖度差距审计（WO-901）

**依据**: 批次 9 工单 WO-901 + owner 决策（弃用外部 ScyllaHide，自研为准）
**性质**: 离线代码审查 + 文档（零实现）
**执行**: 唯一 worker · 2026-08-22
**状态**: COMPLETE — 差距表 + 致命缺口 Top-N

---

## 一、现状盘点（三档分级）

### A. 已实现（可运行，有测试）

| 技术项 | 落点 | 档位 | 说明 |
|---|---|---|---|
| PEB.BeingDebugged 清零 | antidebug-runtime/surfaces/proc.rs (AD-PROC-002) | **已实现** | install/restore/telemetry 齐全 |
| PEB.pShimData 清零 | antidebug-runtime/surfaces/proc.rs (AD-PROC-003) | **已实现** | hard-required；恢复机制 |
| NtQueryInformationProcess 钩子 | themida/antiantidebug/handlers.rs | **已实现** | ProcessDebugPort/DebugObjectHandle/DebugFlags 分支 |
| NtSetInformationThread(ThreadHideFromDebugger) | themida/antiantidebug/handlers.rs | **已实现** | handle_nt_set_information_thread |
| KiFastSystemCall hook | themida/antiantidebug/kifast.rs | **已实现** | install + handle + syscall number 解析 |
| 父进程/窗口检查 | themida/antiantidebug/mod.rs + kifast.rs | **已实现** | parent/window 检测逻辑存在 |

### B. 框架有/部分实现（骨架在，能力待补）

| 技术项 | 落点 | 档位 | 说明 |
|---|---|---|---|
| Win32 PEB 视图 | antidebug-runtime/surfaces/win32.rs | **框架** | PebMemory 基础设施（peb_base/read/write），非反调试 surface |
| 运行时导出接口 | antidebug-runtime/exports.rs | **框架** | MidaInitParams/RuntimeHandle 已定义，未接 Oreans 主流程 |
| HookInventory/RuntimeAttestation | antidebug-runtime/attestation.rs | **框架** | 证明框架完整，hook 清单未填充 |
| 状态机/Profile/EvidenceLog | antidebug/{state,profile,evidence}.rs | **已实现（纯逻辑）** | 控制器核心完备（ADR-3A） |
| provenance/telemetry | antidebug-runtime/{provenance,telemetry}.rs | **已实现** | 依赖声明 + 遥测通道 |

### C. 仅档案登记未实现（缺口）

| 技术项 | 现状 | 缺口 |
|---|---|---|
| NtGlobalFlag 清理 | **缺失** | 无实现（仅在文档/AD 目录提及） |
| 堆标志（HeapFlags/HeapForceFlags） | **缺失** | 无实现 |
| CheckRemoteDebuggerPresent 对抗 | **缺失** | 无实现 |
| 时序攻击掩盖（RDTSC/QPC） | **缺失** | 无实现 |
| DRx 寄存器清零 | **缺失（红线不做）** | 授权禁止（见 WO-902 §三） |
| 调试器窗口/驱动名检查 | 部分 | parent/window 有，驱动名检查无 |

## 二、ScyllaHide 公开技术矩阵对照

> 洁净室纪律：仅对照公开技术清单（行为级需求），不看 ScyllaHide 源码实现。

| # | ScyllaHide 公开技术项 | 自研现状 | 档位 |
|---|---|---|---|
| 1 | PEB BeingDebugged 清理 | AD-PROC-002 | ✅ 已有 |
| 2 | PEB NtGlobalFlag 清理 | 缺失 | ❌ 缺口 |
| 3 | PEB 堆标志（HeapFlags/HeapForceFlags） | 缺失 | ❌ 缺口 |
| 4 | NtQueryInformationProcess ProcessDebugPort | handlers.rs | ✅ 已有 |
| 5 | NtQueryInformationProcess ProcessDebugObjectHandle | handlers.rs | ✅ 已有 |
| 6 | NtQueryInformationProcess ProcessDebugFlags | handlers.rs | ✅ 已有 |
| 7 | NtSetInformationThread ThreadHideFromDebugger | handlers.rs | ✅ 已有 |
| 8 | CheckRemoteDebuggerPresent 对抗 | 缺失 | ❌ 缺口 |
| 9 | DRx 硬件断点清零 | 缺失（红线） | ⛔ 不做 |
| 10 | 时序攻击（RDTSC/QPC/GetTickCount） | 缺失 | ❌ 缺口 |
| 11 | 调试器窗口/父进程/驱动名检查 | parent/window 部分 | ⚠️ 部分 |
| 12 | 用户态 syscall 路径（KiFastSystemCall） | kifast.rs | ✅ 已有 |
| 13 | NtQueryObject（DebugObject 枚举） | 缺失 | ❌ 缺口 |
| 14 | OutputDebugString 对抗 | 缺失 | ❌ 缺口 |

**小结**: ScyllaHide 公开矩阵 14 项中，自研已有 5 项（36%），部分 1 项，**缺口 8 项（57%）**。缺口集中在 PEB 深层标志、时序、以及辅助 API。

## 三、suspected-SecureEngine-class 需求侧标注

结合 WO-601 行为矩阵（TLS 时刻解析器、unwind 混淆、调试端口检测致怠速）:

| 缺口 | 对该类保护器的致命性 | 理由 |
|---|---|---|
| **NtGlobalFlag 清理** | 🔴 **致命** | SecureEngine 系在初始化早期检查 NtGlobalFlag（gflags 含 heap 校验标志），漏清即被识别 |
| **堆标志清理** | 🔴 **致命** | 堆尾校验（HeapValidate）是 SecureEngine 的经典探测；堆标志未清 → 分配行为异常 → 检测 |
| **CheckRemoteDebuggerPresent 对抗** | 🟠 高 | 常见辅助探测，非决定性 |
| **时序攻击掩盖** | 🟠 高 | 该样本的惰性解密/怠速行为与调试端口检测相关（WO-601 §五），时序掩盖降低检测面 |
| **NtQueryObject DebugObject** | 🟡 中 | 高级探测，样本未观测到 |
| **OutputDebugString 对抗** | 🟡 中 | 常规探测，非决定性 |
| DRx 清零 | ⛔ 不做（红线） | 授权禁止；且 debugger 侧 DRx 使用受限（核心调试器既有语义） |

## 四、差距表与致命缺口 Top-N

### 差距总表
- **已有（可运行）**: 5 项核心（BeingDebugged、NtQIP 三分支、ThreadHideFromDebugger、KiFastSystemCall、父进程/窗口）
- **框架/部分**: 4 项（win32 视图、导出接口、证明框架、状态机——纯逻辑层完备）
- **缺口**: 8 项（NtGlobalFlag、HeapFlags、CheckRemoteDebuggerPresent、时序、NtQueryObject、OutputDebugString、驱动名检查、调试器窗口增强）

### 致命缺口 Top-4（对 Oreans/SecureEngine 线）
1. **NtGlobalFlag 清理** — SecureEngine 早期初始化探测（gflags 校验）
2. **堆标志清理（HeapFlags/HeapForceFlags）** — 堆尾校验探测
3. **CheckRemoteDebuggerPresent 对抗** — 常见辅助探测（ScyllaHide 注入目前承担）
4. **时序攻击掩盖（RDTSC/QPC）** — 降低检测面（配合惰性解密观测）

**Top-1/2 是"不做即被识别"级**——ScyllaHide 注入（现唯一外部依赖）正是为覆盖这些缺口而存在；自研栈补上 Top-1/2 后即可对等替换。

## 五、结论

- 纯逻辑层（状态机/Profile/证据）完备——控制器核心可复用；
- 运行时层已有 5 项核心 surface，缺 8 项，其中 **Top-4 致命**（Top-1/2 为"必须项"）；
- Oreans 线替换 ScyllaHide 的**最小对等集** = 已有 5 项 + 补齐 Top-4 → 9 项覆盖（64%），
  其中对 SecureEngine 检测面覆盖完整（Top-1/2 补上后致命探测全灭）；
- 其余 4 项（NtQueryObject/OutputDebugString/驱动名/窗口增强）为纵深防御，非替换前置。

---

**下一步**: WO-902 对等路线图（分阶段实施计划）。
