# MIDA-ADR-1 Surface Inventory（只读静态审计）

> **工作令：** MIDA-ADR-1 —— 对 origin_macro 与 lunlun_software 建立只读 anti-debug surface inventory。
> **状态：** 已封版（MIDA-ADR-1-CLOSEOUT 修正统计口径后提交）。文档阶段：未执行样本、未实现 hook、未注入 runtime、未修改 `crates/**`、未复制第三方内容。
> **基线：** `4fe2cc350378faf8a1408dadb0caf5c30fd20786`（分支 `oreans/two-sample-mainline`）
> **ADR-0 前置：** 三份文档已提交封版（Commit 1）；本 inventory 为独立提交（Commit 2）。
> **性质：** 只读。未执行样本、未注入任何 runtime、未修改 `crates/**`、未复制第三方内容。

## 0. 输入与身份

| 项 | origin_macro | lunlun_software |
|---|---|---|
| case_id | `origin_macro` | `lunlun_software` |
| manifest | `lab/cases/v2/origin_macro.json` | `lab/cases/v2/lunlun_software.json` |
| protected SHA-256 | `1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7` | `8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07` |
| size | 5,232,656 | 4,976,144 |
| architecture | PE32+ / x86_64 | PE32+ / x86_64 |
| vault object | `D:\MidaVault\objects\sha256\1a\1af62999…`（hash+size 复核通过） | `D:\MidaVault\objects\sha256\8a\8a0118d0…`（hash+size 复核通过） |
| 分析证据目录 | `D:\MidaVault\lab\analysis\mida_adr_1_origin_macro\` | `D:\MidaVault\lab\analysis\mida_adr_1_lunlun_software\` |

输入仅来自 immutable vault object；未使用 mutable locator。分析产物（`pe_static.json`、`tls_callbacks.json`、`instruction_sites.json`、IAT/TLS evidence 摘要）在外部 vault；仓库仅保留本摘要与引用。

## 1. 静态轮廓（两样本对照）

| 属性 | origin_macro | lunlun_software |
|---|---|---|
| 入口 RVA | `0x8c8058`（.boot） | `0x885058`（.boot） |
| 入口 stub 字节 | `E8 82 01 00 00 41 52 49 89 E2 …` | **逐字节相同** |
| 段 | 16；`.winlice`(rsize=0, vsize=0x73A000)、`.boot`(0x450C00) | 13；`.themida`(rsize=0, vsize=0x672000)、`.boot`(0x3D8E00) |
| import 描述符 | 11 DLL × 1 API | 17 DLL × 1 API |
| TLS 目录 | 有（`0x166030`，size 0x28） | 有（`0x2105a0`，size 0x28） |
| TLS 静态 callbacks | **0**（数组全零；运行时填充 3 个） | **0**（运行时填充 2 个） |
| exception 目录 | `0x8bac58`，无 raw backing（r0b: exception_no_raw） | `0x85fe40`，无 raw backing |
| load_config / debug 目录 | 无 / 无 | 无 / 无 |
| export | 无 | 无 |
| 字符串 | 仅 `GetModuleHandleA` import 名；marker: `winlice`、`DR0`、`DR7`（offset 0x30e8e9、0x419d30） | 无 debugger marker；版本信息 "Windsoft Technology Co., Ltd." |
| 资源 | manifest 类（Windows 10 兼容声明等） | manifest + 版本信息 |

**结论（同族同版模板）：** 两个样本是同一 Themida/WinLicense 版本生成的 PE32+（入口 stub 逐字节相同、段布局模式一致、TLS 目录结构一致）。差异在业务代码与保护选项。

## 2. 指令模式统计（静态字节，注意：加密载荷）

| pattern | origin_macro 全文件 / .boot | lunlun_software 全文件 / .boot |
|---|---|---|
| INT3 (`CC`) | 20001+ / 19653 | 18431 / 14904 |
| ICEBP (`F1`) | 19164 / 16607 | 20001+ / 15885 |
| RDTSC (`0F 31`) | 91 / 85 | 92 / 77 |
| CPUID (`0F A2`) | 62 / 51 | 73 / 58 |
| INT 2D (`CD 2D`) | 68 / 65 | 101 / 86 |
| RDTSCP (`0F 01 F9`) | 3 / 3 | 0 / 0 |

**重要限制：** 反汇编验证显示这些指令位点位于**加密/加壳载荷**内（上下文为随机字节、无有效指令流）。即静态只能证明"壳载荷中存在这些字节模式"，**不能**证明解密后是真实的 timing/异常检查。唯一明文可执行代码是入口 stub（压缩解包循环，无任何 debugger API 调用）。

## 3. 关键证据（per-surface）

### 3.1 Process/debug state（A 面）

| surface | origin_macro | lunlun_software | 证据 |
|---|---|---|---|
| IsDebuggerPresent（原程序 IAT） | **confirmed**：unpacked candidate IAT slot 92 = kernel32!IsDebuggerPresent（Resolved） | **unknown**：IAT 未重建（1423 unresolved），原程序 IAT 不可见 | `pf_origin_candidate.exe.iat_evidence.json` slot_index 92, slot_rva 0x138C68；lunlun blocker "live IAT report incomplete: Unresolved=1423" |
| PEB.BeingDebugged | **confirmed（行为）**：debugger 每次 patch（"Patching PEB.BeingDebugged (was 1)"），样本在 ScyllaHide+patch 下成功运行 | 同左（38 次运行均 patch） | live logs 全部运行 |
| CheckRemoteDebuggerPresent | 未在 IAT 中出现 | 未可见 | 静态无 |
| NtQueryInformationProcess / NtSetInformationThread | 无 import、无静态字符串；现有 debugger 拦截器未触发（0 命中） | 同左 | live logs（0 NtSIT bypassed） |
| debug object / parent process | 无静态证据 | 无静态证据 | - |
| GetCurrentProcessId | IAT 有（原程序） | 壳 IAT 无 | iat_evidence |

### 3.2 Thread state（B 面）

| surface | 证据 |
|---|---|
| NtSetInformationThread / ThreadHideFromDebugger | 无 import、无静态字符串、无 live 命中。**unknown**（不能推测为"没有检查"；壳可能经 syscall 直呼 ntdll，不经 IAT） |
| 线程枚举 / 线程数量 | 无静态证据（`CreateToolhelp32Snapshot` 不在 import 中；原程序 IAT 不可见部分 unknown） |
| DR0-DR7 / debug register | 字符串 `DR0`/`DR7` 出现在 origin 加密载荷（offset 0x30e8e9/0x419d30），无调用语义 → **weak** |

### 3.3 Heap / environment（C 面）

| surface | 证据 |
|---|---|
| heap flags / NtGlobalFlag | 无静态引用。`GetProcessHeap`/`HeapAlloc` 不在 import（壳 IAT 极简）。**unknown** |
| PE header flags / loader module list | exception 目录无 raw backing（r0b fail）→ 壳对 PE 头做了反 dump 处理（运行时填充）；`GetModuleHandleA` 是唯一引导 import（原程序也有）。**confirmed（结构）**：入口 stub 无 PE 头检查 |
| debugger-created module | 无静态证据 |

### 3.4 Timing（D 面）

| surface | origin_macro | lunlun_software | 证据 |
|---|---|---|---|
| RDTSC/RDTSCP/CPUID | 字节存在（91/3/62）但位于**加密载荷** | 字节存在（92/0/73）但位于**加密载荷** | `instruction_sites.json` + 反汇编上下文（随机字节） |
| QueryPerformanceCounter/Frequency | IAT 有（原程序，kernel32） | 壳 IAT 无 | iat_evidence |
| GetTickCount | IAT 有（原程序） | 壳 IAT 无 | iat_evidence |
| GetSystemTimeAdjustment / GetProcessTimes / GetThreadTimes | IAT 有（原程序） | 壳 IAT 无 | iat_evidence |
| Sleep/Wait 时间差 | `Sleep` 在原程序 IAT；壳运行时行为不可静态判定 | 同左 | iat_evidence |

**结论：** 原程序面（origin）存在 timing API 导入；壳面存在大量 RDTSC/CPUID 字节模式但静态不可判定语义。阈值是否可静态恢复：**不能**（加密）。

### 3.5 Exception / VEH / SEH（E 面）

| surface | 证据 |
|---|---|
| SetUnhandledExceptionFilter / RaiseException / FatalExit | origin 原程序 IAT 有；lunlun 壳 IAT 无 | iat_evidence |
| RtlCaptureContext / RtlLookupFunctionEntry / RtlUnwindEx / RtlVirtualUnwind | origin 原程序 IAT 有（SEH/unwind 基础设施） | iat_evidence |
| INT 2D / INT 3 / 非法指令 / 单步 | 静态字节模式存在但加密；异常目录无 raw backing（r0b） | pe_static + r0b |
| VEH/SEH 链枚举 | 无静态证据 | - |

### 3.6 TLS / early loader（F 面）

| surface | origin_macro | lunlun_software | 证据 |
|---|---|---|---|
| TLS 目录存在 | 是（`0x166030`，0x28） | 是（`0x2105a0`，0x28） | pe_static |
| 静态 callback 数组 | **0 个**（全零） | **0 个**（全零） | `tls_callbacks.json` |
| 运行时 callback | **3 个**：RVA 0x28A60、0x28A80、0x3B6C0（位于首段，文件字节为加密数据） | **2 个**：RVA 0x165290、0x1656F4（文件字节加密） | `pf_*_candidate.exe.tls_evidence.json`（runtime.callback_slots） |
| callback 内是否有 debugger probe | **unknown**（代码加密；静态无法反汇编） | **unknown** | - |
| TLS 结构保留 | final_candidate 保留 3 个 callback + null terminator（preserved=true） | 保留 2 个 callback（preserved=true） | tls_evidence final_candidate |
| TLS 阶段对 unpack 影响 | T5 TLS evidence pass=true；与 anti-debug **无关**（TLS structure evidence ≠ TLS anti-debug check） | 同左 | `tls_acceptance_report.json` |

**区分声明：** 本 inventory 的"TLS 结构证据"（目录存在、callback 数量、保留状态）来自 T5 TLS evidence sidecar；"TLS anti-debug check"（callback 内是否有 probe）**静态未知**，两者不是一回事。

### 3.7 Integrity / self-check（G 面）

| surface | 证据 |
|---|---|
| 代码段 hash / checksum | 无静态证据；壳有 VM（.winlice/.themida）与运行时解密，理论上具备自校验能力，但**静态不可证实**。**unknown** |
| IAT/EAT integrity | 壳行为：运行时填充 IAT（origin 296 resolved；lunlun 1423 unresolved → 壳对 IAT 有完整性影响）；EAT 无。**confirmed（行为）** |
| 模块列表 / loaded DLL identity | 无静态证据。**unknown** |
| 断点字节扫描 / hook detection | 无静态证据。**unknown** |
| PE header mutation | exception 目录无 raw backing（r0b fail）→ **confirmed（结构）**：壳修改了 PE 头（反 dump） |

### 3.8 UI / environment（H 面）

| surface | 证据 |
|---|---|
| 窗口/调试器标题 | origin 资源仅 manifest；lunlun 版本信息无调试器字样。**无静态证据** |
| 进程名 / 服务名 / VM artifact | 无字符串命中（`VirtualBox`/`VMware`/`QEMU`/sandbox 均无）。**unknown**（壳运行时可能动态构造） |
| session/user/environment | 无静态证据 |

### 3.9 L6 kernel/hypervisor

两个样本均无内核态检查的静态证据（无驱动字符串、无 `KdDebuggerEnabled` 引用）。**不进入实现范围**（与 ADR-0 一致）。

## 4. Matrix A —— 样本 surface 矩阵

surface_id | surface | primitive | origin_macro | lunlun_software | origin_conf | lunlun_conf | phase | static_location | check_shape | expected_no_debugger | current_debugger | trigger_effect | evidence_ref | MIDA_action | ScyllaHide_relation
---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
AD-PROC-001 | IsDebuggerPresent 导入 | API（kernel32） | confirmed（IAT slot 92, rva 0x138C68） | unknown（IAT 未重建） | confirmed | unknown | OEP 后（原程序） | candidate IAT | 原程序/壳调用 IsDebuggerPresent 判断 PEB.BeingDebugged | PEB 被 patch → 返回 0 | PEB.BeingDebugged=1（patch 前） | 分支/退出（潜在） | iat_evidence slot 92 | emulate | oracle-only
AD-PROC-002 | PEB.BeingDebugged | PEB 字段 | confirmed（行为：debugger patch "was 1"） | confirmed（行为） | confirmed | confirmed | loader | CREATE_PROCESS | 壳或原程序读 PEB+0x02 | 0 | 1（patch 前） | 分支/退出（潜在） | live logs | emulate | oracle-only
AD-PROC-003 | PEB.pShimData | PEB 字段 | confirmed（行为：debugger 清除） | confirmed（行为） | confirmed | confirmed | loader | CREATE_PROCESS | 读 PEB+0x0C | 0 | 非 0 | apphelp 钩子 | live logs | emulate | oracle-only
AD-PROC-004 | CheckRemoteDebuggerPresent | API | 未发现 | 未发现 | unknown | unknown | - | - | - | - | - | - | 无 | observe-only | unrelated
AD-PROC-005 | NtQueryInformationProcess (debug class) | NT syscall | 未发现静态；拦截器 0 命中 | 未发现静态；拦截器 0 命中 | unknown | unknown | 任意（壳直呼） | 加密载荷 | 查询 DebugPort/DebugFlags | 无 debugger | 有 debugger | 退出/分支 | live logs（0 命中） | emulate（防御性） | oracle-only
AD-PROC-006 | debug object | NT | 无 | 无 | unknown | unknown | - | - | - | - | - | - | - | defer | unrelated
AD-PROC-007 | parent process | API/PEB | 无 | 无 | unknown | unknown | - | - | - | - | - | - | - | defer | unrelated
AD-THR-001 | NtSetInformationThread(ThreadHideFromDebugger) | NT syscall | 未发现静态；拦截器 0 命中 | 未发现静态；0 命中 | unknown | unknown | 任意 | 加密载荷 | 隐藏线程 | 线程可见 | 线程隐藏 | 失去线程可见性 | live logs | emulate（防御性） | oracle-only
AD-THR-002 | 线程枚举/数量 | API | 无 import 证据 | 无 import 证据 | unknown | unknown | - | - | - | - | - | - | - | observe-only | unrelated
AD-THR-003 | DR0-DR7 字符串 | 数据 | 字符串存在（0x30e8e9/0x419d30）加密载荷 | 无 | weak | unknown | loader/runtime | 加密载荷 | 未知 | - | - | - | pe_static marker_hits | observe-only | unknown
AD-HEAP-001 | heap flags / NtGlobalFlag | PEB/heap | 无 | 无 | unknown | unknown | - | - | - | - | - | - | - | observe-only | unrelated
AD-TIM-001 | RDTSC/RDTSCP/CPUID | 指令 | 字节 91/3/62（加密载荷） | 字节 92/0/73（加密载荷） | strong | strong | runtime（壳） | .boot | 计时差检测（推断） | 无大跳变 | debugger 引起跳变 | 退出/分支 | instruction_sites.json | emulate（防御性） | oracle-only
AD-TIM-002 | QueryPerformanceCounter | API | 原程序 IAT 有 | 壳 IAT 无 | confirmed | unknown | OEP 后 | candidate IAT | 原程序计时 | 一致 | - | - | iat_evidence | emulate（防御性） | unrelated
AD-TIM-003 | GetTickCount | API | 原程序 IAT 有 | 壳 IAT 无 | confirmed | unknown | OEP 后 | candidate IAT | 原程序计时 | 一致 | - | - | iat_evidence | emulate（防御性） | unrelated
AD-TIM-004 | GetSystemTimeAdjustment / GetProcessTimes / GetThreadTimes | API | 原程序 IAT 有 | 壳 IAT 无 | confirmed | unknown | OEP 后 | candidate IAT | 时间戳对比（推断） | 一致 | - | - | iat_evidence | observe-only | unrelated
AD-EXC-001 | SetUnhandledExceptionFilter | API | 原程序 IAT 有 | 壳 IAT 无 | confirmed | unknown | OEP 后 | candidate IAT | 异常过滤（推断） | - | - | - | iat_evidence | observe-only | unrelated
AD-EXC-002 | INT2D/INT3/单步/非法指令 | 异常 | 字节模式（加密载荷） | 字节模式（加密载荷） | strong | strong | runtime | .boot | 异常检测（推断） | - | - | - | pe_static | emulate（防御性） | oracle-only
AD-EXC-003 | exception 目录无 raw backing | PE 结构 | confirmed（r0b fail） | confirmed（r0b fail） | confirmed | confirmed | loader | data dir 3 | 反 dump/延迟填充 | - | - | - | r0b_protected_input.json | observe-only | unrelated
AD-TLS-001 | TLS 目录 + 运行时 callback | TLS | confirmed：3 callbacks（0x28A60/0x28A80/0x3B6C0） | confirmed：2 callbacks（0x165290/0x1656F4） | confirmed | confirmed | early loader | .tls + 首段 | 壳初始化（内容加密） | - | - | - | tls_evidence runtime | observe-only | unrelated
AD-TLS-002 | TLS callback 内 anti-debug probe | TLS | 未知（代码加密） | 未知（代码加密） | unknown | unknown | TLS callback | 加密载荷 | 可能含 probe | - | - | - | tls_evidence | defer（动态验证） | unknown
AD-INT-001 | IAT 完整性（壳运行时填充） | 结构 | confirmed（296 resolved） | confirmed（1423 unresolved） | confirmed | confirmed | pre-OEP→OEP | IAT | 壳重建 IAT | 完整 IAT | 部分 IAT | 影响 dump 完整性 | iat_evidence | observe-only | unrelated
AD-INT-002 | PE header 反 dump | 结构 | confirmed（exception_no_raw） | confirmed（exception_no_raw） | confirmed | confirmed | loader | headers | 移除 raw backing | - | - | - | r0b | observe-only | unrelated
AD-UI-001 | 窗口/调试器标题检查 | API/string | 无静态证据 | 无静态证据 | unknown | unknown | runtime | .rsrc | 无 | - | - | - | pe_static | observe-only | unrelated
AD-ENV-001 | VM/沙箱/进程名检查 | string/API | 无字符串命中 | 无字符串命中 | unknown | unknown | runtime | 加密载荷 | 无 | - | - | - | pe_static | defer | unrelated

## 5. Matrix B —— MIDA 需求矩阵

surface_id | MIDA controller | MIDA runtime | MIDA evidence | action | required evidence | ScyllaHide relation
---|---|---|---|---|---|---
AD-PROC-001 | profile 校验（IAT 恢复后确认导入存在） | 拦截 IsDebuggerPresent → 返回 0 | probe-result（expected=0/observed=0） | **emulate** | `mida.antidebug-probe-result/v1` | oracle-only
AD-PROC-002 | PEB patch 校验（当前已有） | 维持 PEB.BeingDebugged=0 | attestation（peb_state） | **emulate**（已有实现） | attestation 字段 | oracle-only
AD-PROC-003 | PEB patch 校验 | 维持 pShimData=0 | attestation | **emulate**（已有实现） | attestation 字段 | oracle-only
AD-PROC-004 | - | - | - | observe-only | - | unrelated
AD-PROC-005 | - | 防御性 hook NtQueryInformationProcess debug class | probe-result | **emulate（防御性，低优先）** | probe-result | oracle-only
AD-PROC-006 | - | - | - | defer | - | unrelated
AD-PROC-007 | - | - | - | defer | - | unrelated
AD-THR-001 | - | 防御性 hook NtSetInformationThread(0x11) | probe-result | **emulate（防御性，低优先）** | probe-result | oracle-only
AD-THR-002 | - | - | - | observe-only | - | unrelated
AD-THR-003 | - | - | - | observe-only（仅记录） | observation | unknown
AD-HEAP-001 | - | - | - | observe-only | - | unrelated
AD-TIM-001 | profile（timing_consistency） | RDTSC/CPUID 虚拟化（延迟补偿） | probe-result（前后采样） | **emulate（防御性）** | probe-result | oracle-only
AD-TIM-002 | profile | QPC 一致性 | probe-result | **emulate（防御性）** | probe-result | unrelated
AD-TIM-003 | profile | GetTickCount 一致性 | probe-result | **emulate（防御性）** | probe-result | unrelated
AD-TIM-004 | - | - | - | observe-only | observation | unrelated
AD-EXC-001 | - | - | - | observe-only | observation | unrelated
AD-EXC-002 | - | 防御性处理 INT2D/INT3 语义（保持异常链一致） | observation | **emulate（防御性，低优先）** | observation | oracle-only
AD-EXC-003 | - | - | - | observe-only | - | unrelated
AD-TLS-001 | - | - | - | observe-only（记录 callback 数量/地址） | observation | unrelated
AD-TLS-002 | - | - | - | **defer**（需动态验证 callback 内容；MIDA-ADR-5 覆盖） | deferred | unknown
AD-INT-001 | - | - | - | observe-only | - | unrelated
AD-INT-002 | - | - | - | observe-only | - | unrelated
AD-UI-001 | - | - | - | observe-only | - | unrelated
AD-ENV-001 | - | - | - | defer | - | unrelated

## 6. 分类统计（primary bucket 规则）

**规则（本 inventory 采用）：** 每个 sample × 每个 surface 只进入一个 primary confidence bucket。单元格含多个级别（如"字节存在（strong）/语义 unknown"）时，按 **confirmed > strong > weak > unknown** 取最高级。每个 sample 的四个 bucket 总和必须等于 Matrix A unique surface 数（24）。

| 级别 | origin_macro | lunlun_software |
|---|---|---|
| confirmed（11 / 6） | AD-PROC-001、AD-PROC-002、AD-PROC-003、AD-TIM-002、AD-TIM-003、AD-TIM-004、AD-EXC-001、AD-EXC-003、AD-TLS-001、AD-INT-001、AD-INT-002 | AD-PROC-002、AD-PROC-003、AD-EXC-003、AD-TLS-001、AD-INT-001、AD-INT-002 |
| strong（2 / 2） | AD-TIM-001（字节存在）、AD-EXC-002（字节存在） | AD-TIM-001（字节存在）、AD-EXC-002（字节存在） |
| weak（1 / 0） | AD-THR-003（DR 字符串） | （无） |
| unknown（10 / 16） | AD-PROC-004、AD-PROC-005、AD-PROC-006、AD-PROC-007、AD-THR-001、AD-THR-002、AD-HEAP-001、AD-TLS-002、AD-UI-001、AD-ENV-001 | AD-PROC-001、AD-PROC-004、AD-PROC-005、AD-PROC-006、AD-PROC-007、AD-THR-001、AD-THR-002、AD-THR-003、AD-HEAP-001、AD-TIM-002、AD-TIM-003、AD-TIM-004、AD-EXC-001、AD-TLS-002、AD-UI-001、AD-ENV-001 |
| **合计** | **11 + 2 + 1 + 10 = 24** ✅ | **6 + 2 + 0 + 16 = 24** ✅ |

**统计口径修正记录（MIDA-ADR-1-CLOSEOUT）：** 上一版 §6 将 AD-TLS-001 同时计入 confirmed 与 strong（重复计数），导致 origin 总和 25 ≠ 24。本版将 Matrix A 的 confidence 拆为 per-sample 两列（`origin_conf` / `lunlun_conf`），§6 直接从 Matrix A 派生，单一数据源，不再双轨。

### 6.1 Matrix A / Matrix B 一致性校验

| 校验项 | 结果 |
|---|---|
| Matrix A unique surface_id 数 | **24**（A7 + B3 + C1 + D4 + E3 + F2 + G2 + H2 = 24） |
| Matrix B unique surface_id 数 | **24** |
| Matrix A ⊆ Matrix B（A 中每个 id 在 B 出现一次） | ✅ 0 缺失 |
| Matrix B ⊆ Matrix A（B 中每个 id 在 A 有定义） | ✅ 0 多余 |
| 重复计数 | 无（A 与 B 均 24 unique，无重复行） |
| 每 sample confidence bucket 总和 | origin 24 ✅ / lunlun 24 ✅ |

## 7. 两样本差异

1. **origin_macro**：OEP confirmed（`0x13e0` valid prologue）+ IAT 完整重建（296 导入，全 Resolved）→ **原程序级 anti-debug API 面可见**（IsDebuggerPresent、QPC、GetTickCount、SetUnhandledExceptionFilter、OutputDebugStringA 等）。
2. **lunlun_software**：OEP ambiguous（fallback entry = TLS callback 2 地址 `0x1656F4`）+ IAT 未重建（1423 unresolved）→ **原程序级 anti-debug 面不可见（unknown）**；其 unpack 流程在 TLS 阶段未完成，说明壳行为更复杂或当前 pipeline 对该样本的 hook/OEP 定位不足。
3. 两者壳面一致：同模板、TLS 运行时填充、加密载荷含 timing/exception 字节模式、无 UI/VM 字符串。

## 8. 未决问题（后续验证项）

1. **TLS callback 内容**（AD-TLS-002）：运行时解密后是否含 anti-debug probe？→ 需动态（受控探针）或差分（MIDA-ADR-7）验证。
2. **NtSetInformationThread / NtQueryInformationProcess 是否被壳直呼**（AD-PROC-005/AD-THR-001）：静态 0 证据、live 0 命中 → 可能是"未使用"或"已由 ScyllaHide 静默处理"。差分实验（无 ScyllaHide vs 有 ScyllaHide）可分辨。
3. **timing 检查是否真实存在**（AD-TIM-001）：加密载荷中的 RDTSC 是否在解密后成为真实检查？→ 需受控动态采样或 unpack 后静态分析（candidate 已解密）。
4. **lunlun 的 OEP/IAT 失败**：是 anti-debug 导致还是 pipeline 局限？→ 需对照（无 ScyllaHide 运行）确认。
5. **DR0/DR7 字符串语义**（AD-THR-003）：可能只是 VM 指令数据。

## 9. 对 MIDA-ADR 的输入

- **profile 初稿（oreans_x64_v1 候选 surface）**：`peb_debug_flags`（confirmed）、`is_debugger_present`（origin confirmed；lunlun unknown → profile 必须支持 per-sample 差异）、`timing_consistency`（防御性）、`nt_set_information_thread`（防御性）、`nt_query_information_process`（防御性）。
- **ScyllaHide 角色**：本 inventory **未使用** ScyllaHide hook list 作为 surface 来源；ScyllaHide 仅作为后续 differential oracle（MIDA-ADR-7）。
- **fail-closed 映射**：origin 的 `IsDebuggerPresent` 为 confirmed 需求 → runtime 必须 hook 且 attestation 记录；lunlun 为 unknown → 不写入 required_hooks，作为 observe-only/防御性。

## 10. 审计声明

- 未执行任何样本进程（全部证据来自 vault 对象的只读解析与既有 live evidence 日志的只读检索）。
- 未修改 `crates/**`、未新增仓库内样本/二进制/大体积反汇编输出。
- 未复制 ScyllaHide 任何内容；ScyllaHide 引用仅存在于 live 日志（历史运行记录）与本文档的 oracle 角色声明。
- 分析脚本位于 `D:\MidaVault\scratch\mida_adr1_*.py`（外部 vault），不入仓库。
- `git diff --check` 无错误；工作区变更仅本文档（+ADR-0 三份）。

## 11. 下一阶段建议

1. **MIDA-ADR-2**：基于本 inventory 建立 clean-room 行为规范（AntiDebugObservation / AntiDebugExpectedState / AntiDebugProbeResult），把 confirmed 面转成 probe 定义。
2. **受控差分实验（进 ADR-2/7）**：同一样本在"无 ScyllaHide / 有 ScyllaHide"下的行为差异，用于分辨 unknown 面（NtSIT/NtQIP/timing）。
3. **lunlun OEP/IAT 专项**：验证是否 anti-debug 相关（若无关，则是 pipeline 问题，不进 MIDA-ADR runtime 需求）。

---

## 12. MIDA-ADR-1-CLOSEOUT 记录

- **修正内容：** (a) Matrix A 增加 per-sample confidence 列（`origin_conf` / `lunlun_conf`），移除原单一 `confidence` 列；(b) §6 采用 primary bucket 规则（每 sample×surface 唯一 bucket，多级别取最高级 confirmed > strong > weak > unknown）；(c) 新增 §6.1 Matrix A/B 一致性校验。
- **修正前后对比：**

| 项 | 修正前 | 修正后 |
|---|---|---|
| Matrix A unique surface 数 | 24（未显式声明） | **24**（显式声明，A7+B3+C1+D4+E3+F2+G2+H2） |
| Matrix B unique surface 数 | 24（未显式声明） | **24**（显式声明） |
| origin confidence 合计 | 11+3+1+10 = **25**（AD-TLS-001 重复计入 confirmed+strong） | **11+2+1+10 = 24** ✅ |
| lunlun confidence 合计 | 6+2+0+16 = 24（但 strong 列含 AD-TLS-001，口径混叠） | **6+2+0+16 = 24** ✅ |
| Matrix A/B 漂移 | 未校验 | ✅ 双向无漂移（A-B=∅，B-A=∅） |

- **验收对照：** `git diff --check` 通过；ADR-0 三份文档（Commit 1）与 ADR-1 inventory（Commit 2）已分别提交；tracked source / Cargo / CI / lab raw evidence 均无变化；未修改外部 vault raw evidence；未 push。
