# MIDA-ADR-2 Probe Catalog（probe 契约）

> **工作令：** MIDA-ADR-2 —— 基于 ADR-1 建立 clean-room anti-debug 行为规范与 probe 契约。
> **状态：** 规范设计定稿（文档阶段）。未执行样本、未执行 ScyllaHide、未做 live 差分。
> **基线：** `e98a6a61051a734a14cf53ebe9e64e5b1099374b`。
> 配套：[BEHAVIOR_SPEC](MIDA_ADR_2_BEHAVIOR_SPEC.md) · [PROFILE_DRAFT](MIDA_ADR_2_PROFILE_DRAFT.md)

## 0. 阅读约定

- **proof levels**（每 surface 四个，互斥取最高确认级）：`presence_observed` → `call_site_confirmed` → `runtime_observed` → `decision_semantics_confirmed`。
- **per-sample action**：`required` / `observe-only` / `defer` / `unknown`。
- **一致性约束**：24 个 surface 与 ADR-1 Matrix A/B 完全一致；每个 sample × surface 只有一个 primary confidence bucket（与 ADR-1 §6 相同）。
- **硬规则**：`presence_observed=true` 不能进入 `required`；required 只能来自 call_site_confirmed / runtime_observed / decision_semantics_confirmed。

## 1. 总览表（24 surfaces）

| surface_id | surface | proof（origin / lunlun） | action origin | action lunlun |
|---|---|---|---|---|
| AD-PROC-001 | IsDebuggerPresent | call-site-presence（IAT slot 92） / presence-none（IAT 未重建） | **required**（保留项） | observe-only |
| AD-PROC-002 | PEB.BeingDebugged | decision-confirmed（行为） / decision-confirmed（行为） | **required** | **required** |
| AD-PROC-003 | PEB.pShimData | decision-confirmed（行为） / decision-confirmed（行为） | **required** | **required** |
| AD-PROC-004 | CheckRemoteDebuggerPresent | none / none | observe-only | observe-only |
| AD-PROC-005 | NtQueryInformationProcess debug class | none / none | observe-only（防御性候选） | observe-only（防御性候选） |
| AD-PROC-006 | debug object | none / none | defer | defer |
| AD-PROC-007 | parent process | none / none | defer | defer |
| AD-THR-001 | ThreadHideFromDebugger | none / none | observe-only（防御性候选） | observe-only（防御性候选） |
| AD-THR-002 | thread enumeration/count | none / none | defer | defer |
| AD-THR-003 | DR0-DR7 marker | presence-observed（weak） / none | observe-only | observe-only |
| AD-HEAP-001 | heap flags / NtGlobalFlag | none / none | defer | defer |
| AD-TIM-001 | RDTSC/RDTSCP/CPUID | presence-observed（加密载荷） / presence-observed（加密载荷） | observe-only | observe-only |
| AD-TIM-002 | QueryPerformanceCounter | presence-observed（IAT） / none | observe-only | defer |
| AD-TIM-003 | GetTickCount | presence-observed（IAT） / none | observe-only | defer |
| AD-TIM-004 | GetSystemTimeAdjustment/GetProcessTimes/GetThreadTimes | presence-observed（IAT） / none | observe-only | defer |
| AD-EXC-001 | SetUnhandledExceptionFilter | presence-observed（IAT） / none | observe-only | defer |
| AD-EXC-002 | INT2D/INT3/单步/非法指令 | presence-observed（加密载荷） / presence-observed（加密载荷） | observe-only | observe-only |
| AD-EXC-003 | exception 目录 raw-backing | decision-confirmed（结构 anti-dump） / decision-confirmed（结构） | observe-only（非 anti-debug hook） | observe-only |
| AD-TLS-001 | TLS 目录 + 运行时 callback | runtime-observed（3 callbacks） / runtime-observed（2 callbacks） | observe-only | observe-only |
| AD-TLS-002 | TLS callback 内 anti-debug probe | unknown / unknown | defer | defer |
| AD-INT-001 | IAT integrity/runtime fill | runtime-observed / runtime-observed | observe-only | observe-only |
| AD-INT-002 | PE header anti-dump mutation | decision-confirmed（结构） / decision-confirmed（结构） | observe-only（非 anti-debug hook） | observe-only |
| AD-UI-001 | debugger/window title | none / none | observe-only | observe-only |
| AD-ENV-001 | VM/sandbox/process identity | none / none | defer | defer |

## 2. A. Process/debug state

### AD-PROC-001 IsDebuggerPresent

- 目标：原程序或壳是否调用 IsDebuggerPresent 判断 PEB.BeingDebugged。
- phase：oep_post（原程序面）。
- input：无参数调用；读 PEB.BeingDebugged。
- expected no-debugger：返回 0（PEB.BeingDebugged=0）。
- current debugger：PEB.BeingDebugged=1（patch 前）。
- proof levels：
  - origin_macro：presence_observed=true（IAT slot 92 resolved）；call_site_confirmed=unknown；runtime_observed=unknown；decision_semantics_confirmed=unknown。
  - lunlun_software：presence_observed=false（IAT 未重建）；其余 unknown。
- MIDA action：origin=required（保留项，见 PROFILE_DRAFT §3 说明）；lunlun=observe-only。
- 成功/失败：expected=0；observed≠0 → fail。
- 证据记录：mida.antidebug-probe-result/v1（expected/observed/match）。
- ScyllaHide 关系：oracle-only。

### AD-PROC-002 PEB.BeingDebugged

- 目标：壳/原程序读取 PEB+0x02。
- phase：loader（CREATE_PROCESS 后）。
- input：PEB 字段。
- expected no-debugger：{"peb_being_debugged": 0}；allowed_variance：[]（零容忍）。
- current debugger：1（live logs "Patching PEB.BeingDebugged (was 1)"，66/38 次运行）。
- proof levels：origin/lunlun 均 decision_semantics_confirmed=true（行为证据：patch 后样本正常运行并成功 unpack）。
- MIDA action：**required**（两样本）。
- 成功/失败：patch 后 PEB 字段必须为 0；读回非 0 → fail。
- 证据：live logs（existing-live-evidence）。

### AD-PROC-003 PEB.pShimData

- 目标：壳/原程序读取 PEB+0x0C。
- phase：loader。
- expected no-debugger：{"p_shim_data": 0}；allowed_variance：[]。
- current debugger：非 0（apphelp 钩子存在时）。
- proof levels：origin/lunlun 均 decision_semantics_confirmed=true（行为证据：清除后正常运行）。
- MIDA action：**required**（两样本）。
- 成功/失败：pShimData 必须为 0。

### AD-PROC-004 CheckRemoteDebuggerPresent

- 目标：是否调用 CRDP 检测远程调试器。
- phase：未知。
- proof：origin/lunlun 均 presence_observed=false（IAT 无、字符串无）。
- MIDA action：observe-only（两样本）。required=false。
- decision：未观察到 → not-run（不是 pass）。

### AD-PROC-005 NtQueryInformationProcess（debug class）

- 目标：壳是否经 ntdll 直呼 NtQIP 查询 DebugPort(7)/DebugFlags(31)/DebugObjectHandle(30)。
- phase：任意（壳直呼，不经 IAT）。
- proof：origin/lunlun presence_observed=false（无 import、无字符串）；live 拦截器 0 命中。
- MIDA action：observe-only（防御性候选，低优先）。required=false。
- 备注：live 0 命中可能是"未使用"或"已被 ScyllaHide 静默处理"；需未来差分分辨（本任务不做）。

### AD-PROC-006 debug object

- 目标：NtQueryObject(DebugObject) / ProcessDebugObjectHandle。
- proof：无任何证据。
- MIDA action：defer（两样本）。

### AD-PROC-007 parent process

- 目标：读取父进程 ID/名称检测调试器宿主。
- proof：无任何证据。
- MIDA action：defer（两样本）。

## 3. B. Thread state

### AD-THR-001 ThreadHideFromDebugger

- 目标：壳是否调用 NtSetInformationThread(ThreadHideFromDebugger=0x11) 隐藏线程。
- phase：任意。
- proof：origin/lunlun presence_observed=false（无 import、无字符串）；live 拦截器 0 命中。
- MIDA action：observe-only（防御性候选，低优先）。**不能**直接列为 required emulate hook（ADR-1 unknown）。

### AD-THR-002 thread enumeration/count

- 目标：CreateToolhelp32Snapshot / Thread32First 等线程枚举。
- proof：无 import 证据（壳 IAT 极简）。
- MIDA action：defer（两样本）。

### AD-THR-003 DR0-DR7 marker

- 目标：DR0/DR7 字符串（origin 加密载荷 offset 0x30e8e9/0x419d30）是否指示硬件断点检测。
- proof：origin presence_observed=true（weak，仅字符串）；lunlun presence_observed=false。
- MIDA action：observe-only（两样本；仅记录 observation，不 emulate）。
- 备注：可能只是 VM 指令数据，语义未知。

## 4. C. Heap/environment

### AD-HEAP-001 heap flags / NtGlobalFlag

- 目标：读取 HeapFlags/ForceFlags/NtGlobalFlag 检测调试堆。
- proof：无任何证据（GetProcessHeap/HeapAlloc 不在 import）。
- 定义：confidence=unknown、action=observe-only/defer、required=false。
- MIDA action：defer（两样本）。

## 5. D. Timing

### AD-TIM-001 RDTSC/RDTSCP/CPUID

- 目标：壳是否用 RDTSC/RDTSCP/CPUID 做计时差检测。
- phase：runtime（壳）。
- proof：origin/lunlun presence_observed=true（字节 91/3/62 与 92/0/73，**位于加密载荷**）；call_site_confirmed=unknown；runtime_observed=unknown；decision_semantics_confirmed=false。
- **边界：** encrypted payload byte marker != confirmed check。
- MIDA action：observe-only（两样本）。**不进入 required_hooks**。
- 备注：需 unpack 后静态（candidate 已解密）或受控动态采样验证语义（未来任务）。

### AD-TIM-002 QueryPerformanceCounter

- 目标：原程序是否用 QPC 做计时/anti-debug 决策。
- phase：oep_post（原程序面）。
- proof：origin presence_observed=true（IAT 有 QPC）；call_site_confirmed=unknown；runtime_observed=unknown；decision_semantics_confirmed=false。lunlun presence_observed=false。
- **边界：** IAT presence != timing anti-debug semantics。无 comparison/threshold/branch 证据。
- MIDA action：origin=observe-only（**修正 ADR-1 的 emulate 防御性**）；lunlun=defer。
- 备注：profile 级不得因 IAT presence 进入 required。

### AD-TIM-003 GetTickCount

- 目标：原程序是否用 GetTickCount 做计时/anti-debug 决策。
- proof：origin presence_observed=true（IAT 有）；其余 unknown。lunlun presence_observed=false。
- MIDA action：origin=observe-only；lunlun=defer。

### AD-TIM-004 GetSystemTimeAdjustment / GetProcessTimes / GetThreadTimes

- 目标：时间戳类 API 是否用于 debugger 检测。
- proof：origin presence_observed=true（IAT 有）；其余 unknown。lunlun presence_observed=false。
- MIDA action：origin=observe-only；lunlun=defer。

## 6. E. Exception

### AD-EXC-001 SetUnhandledExceptionFilter

- 目标：原程序是否注册 UEF 并在异常路径检测调试器。
- proof：origin presence_observed=true（IAT 有）；其余 unknown。lunlun presence_observed=false。
- **边界：** 异常 API 存在 ≠ 异常被用于 debugger detection。
- MIDA action：origin=observe-only；lunlun=defer。

### AD-EXC-002 INT2D/INT3/单步/非法指令

- 目标：壳是否用异常指令检测单步/断点。
- proof：origin/lunlun presence_observed=true（字节模式，**加密载荷**）；语义 unknown。
- MIDA action：observe-only（两样本；防御性候选低优先）。

### AD-EXC-003 exception 目录 raw-backing

- 目标：exception 目录无 raw backing（r0b: exception_no_raw）是否为 anti-dump。
- proof：origin/lunlun decision_semantics_confirmed=true（结构证据：PE 反 dump）。
- **边界：** 这是 PE structural / anti-dump evidence，**不应自动等同于 anti-debug runtime hook**。
- MIDA action：observe-only（两样本；记录 observation，不进 required hooks）。

## 7. F. TLS/early loader

### AD-TLS-001 TLS 目录 + 运行时 callback

- 目标：TLS 目录存在；运行时 Themida 填充 callbacks（origin 3 / lunlun 2）。
- phase：early loader。
- proof：origin/lunlun runtime_observed=true（tls_evidence runtime.callback_slots）；decision_semantics_confirmed=false。
- **边界：** TLS callback 存在 ≠ callback 内容含 anti-debug。TLS structure evidence、TLS callback execution、TLS callback body semantics、TLS anti-debug decision 四层严格拆开。
- MIDA action：observe-only（记录 callback 数量/地址）。

### AD-TLS-002 TLS callback 内 anti-debug probe

- 目标：callback body 是否含 debugger probe。
- proof：origin/lunlun unknown（代码加密，静态无法反汇编）。
- MIDA action：defer（两样本；MIDA-ADR-5 覆盖动态验证）。
- **不得因为 TLS callback 存在就把 callback 内容标成 anti-debug。**

## 8. G. Integrity

### AD-INT-001 IAT integrity / runtime fill

- 目标：壳运行时重建 IAT（origin 296 resolved / lunlun 1423 unresolved）。
- proof：origin/lunlun runtime_observed=true（iat_evidence）。
- **边界：** 结构反 dump / IAT 完整性 ≠ debugger detection。
- MIDA action：observe-only（记录 IAT 状态，不进 anti-debug hooks）。

### AD-INT-002 PE header anti-dump mutation

- 目标：壳移除 exception 目录 raw backing（反 dump）。
- proof：origin/lunlun decision_semantics_confirmed=true（结构证据 r0b）。
- **边界：** 与 debugger detection 不同类；不统一叫 anti-debug hook。
- MIDA action：observe-only。

## 9. H. UI/environment

### AD-UI-001 debugger/window title

- 目标：窗口标题/调试器名检查。
- proof：无静态证据（资源仅 manifest/版本信息）。
- 定义：required=false、action=observe-only（两样本）。

### AD-ENV-001 VM/sandbox/process identity

- 目标：VM/沙箱/进程名检查。
- proof：无字符串命中（VirtualBox/VMware/QEMU/sandbox 均无）。
- 定义：required=false、action=defer（两样本）。

## 10. Probe catalog 汇总统计

### origin_macro

| action | count | surface_ids |
|---|---|---|
| required | 3 | AD-PROC-001（保留项）、AD-PROC-002、AD-PROC-003 |
| observe-only | 15 | AD-PROC-004/005、AD-THR-001/003、AD-TIM-001/002/003/004、AD-EXC-001/002/003、AD-TLS-001、AD-INT-001/002、AD-UI-001 |
| defer | 6 | AD-PROC-006/007、AD-THR-002、AD-HEAP-001、AD-TLS-002、AD-ENV-001 |
| unknown | 0 | — |
| **合计** | **24** ✅ | 3 + 15 + 6 = 24 |

### lunlun_software

| action | count | surface_ids |
|---|---|---|
| required | 2 | AD-PROC-002、AD-PROC-003 |
| observe-only | 16 | AD-PROC-001/004/005、AD-THR-001/003、AD-TIM-001/002/003/004、AD-EXC-001/002/003、AD-TLS-001、AD-INT-001/002、AD-UI-001 |
| defer | 6 | AD-PROC-006/007、AD-THR-002、AD-HEAP-001、AD-TLS-002、AD-ENV-001 |
| unknown | 0 | — |
| **合计** | **24** ✅ | 2 + 16 + 6 = 24 |

> **保留项说明（AD-PROC-001 / origin）：** 按 ADR-2 严格 proof 规则，IsDebuggerPresent 仅有 IAT presence（call-site-presence），未达到 call_site_confirmed。它作为 required **候选**进入 origin profile（因为 PEB.BeingDebugged 已确认、IsDebuggerPresent 是同一检测面且 IAT 恢复证据确凿），但必须由 ADR-3 接线时的受控动态验证（call_site_confirmed 或 decision_semantics_confirmed）确认后方可锁定为硬 required；确认失败则降为 observe-only。lunlun 的 AD-PROC-001 保持 observe-only（不得复制 origin 结论）。