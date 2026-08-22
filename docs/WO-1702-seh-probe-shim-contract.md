# WO-1702 — SEH Probe Shim 冻结合同（唯一机制：MSVC C __try/__except）

**工单编号**: WO-1702（Batch 17）
**优先级**: P0
**性质**: design-only；不得实现、不得运行目标样本、不声称 Windows 行为已验证
**日期**: 2026-08-23
**基线**: 07c02db（Batch 16 出口门未过）
**状态**: 冻结候选 — 待总指挥联审

## 0. 目的

关闭 P0-1602-1（SEH 收口机制未冻结、错误替代项并存）与 P0-1602-2（probe span 与实际读取
宽度矛盾）、P1-1602-3（未知异常 TLS 生命周期不完整）。本文件是**唯一权威**的探针收口
机制合同；WO-1301A-IMPL-walker-execute-design.md §3 以此为据改写，不再保留其它候选。

## 1. 机制选择（唯一，无候选并存）

### 1.1 冻结：MSVC x64 C __try/__except shim

探针原语实现为一个 **C 源文件（probe_shim.c）**，随 runtime DLL 一起由 MSVC 编译链接
（build.rs 经 cc crate 调用 cl.exe；MSVC 缺失则构建失败，无替代机制）。DLL 内同时导出
WalkerExecute 与 shim 的 C ABI 符号。shim 是普通静态函数，**无动态代码、无手写汇编、
无函数表回调**。

理由：
- __try/__except 由编译器生成完整的 x64 SEH 帧与 unwind metadata（.pdata/.xdata），
  装载时由加载器注册、卸载时自动注销——不依赖任何手写展开信息。
- 异常过滤器（filter）与 handler continuation 由编译器的 __C_specific_handler 表驱动，
  可审查、可单测。
- 探针循环无需修改 ContextRecord.Rip：__except 块执行后控制流自然从 __try 块之后
  继续（__leave 语义）——**废除**旧设计的 RIP→resume_stub 跳转。

### 1.2 明确拒绝的替代项（从此不再出现在设计中）

| 候选 | 拒绝理由 |
|------|---------|
| RtlInstallFunctionTableCallback | 只是为动态生成的代码注册函数表/unwind 信息；**它不创建任何异常捕获帧**。用它实现 SEH 收口需要先自造带 .xdata 的代码，属于手写路径 |
| 手写汇编 SEH 帧（ml64 + 自写 .pdata/.xdata） | 脆弱、难审计、展开信息一旦错误即进程崩溃；拒绝 |
| Rust 内联 / catch_unwind 收口 | Rust 无 __try/__except；catch_unwind 只捕 panic，不捕 STATUS_ACCESS_VIOLATION / STATUS_GUARD_PAGE_VIOLATION（已撤回） |
| “等价 FFI 边界”等未命名方案 | 无具体机制即不可审查；删除 |
| 伪结构中的 unimplemented!() | 删除；收口机制以本文件为准 |

## 2. C shim ABI（冻结）

### 2.1 probe_shim.h（合同原文，实现工单必须原样落地）

~~~c
/* probe_shim.h — WO-1702 frozen contract. Compiled with MSVC x64. */
#pragma once
#include <windows.h>

/* Probe outcome status (written to the caller-provided status slot and
 * returned by the function).
 *   OK   = no exception; out16[0..16) fully valid.
 *   FAULT= guard/AV collected by the __except frame; out16 content is
 *          NOT valid (bytes written before the fault are unspecified).
 *   ABORT= exception code other than guard/AV reached the frame; the
 *          walker MUST abort (fail-closed).
 */
enum MidaProbeStatus {
    MIDA_PROBE_OK = 0,
    MIDA_PROBE_FAULT = 1,
    MIDA_PROBE_ABORT = 2,
};

/* Probed 16-byte window of the shim body: [start, end) covers every
 * instruction inside mida_probe_read that may fault (the two 8-byte
 * loads). The walker VEH uses this to attribute faults by RIP.
 */
typedef struct MidaProbeWindow {
    const void* start;
    const void* end;
} MidaProbeWindow;

/* Reads exactly 16 bytes at va into out16. va may fault (guard/AV).
 * Returns the status and stores it into *status_slot.
 * - va          : target VA to read (may be unmapped/protected).
 * - out16       : caller-owned 16-byte buffer (probe-thread stack).
 * - status_slot : caller-owned 32-bit slot (probe-thread stack, 8-aligned).
 * Windows x64 calling convention; caller provides 32-byte shadow space.
 * The function performs no calls on the success path; on exception the
 * kernel dispatch runs the VEH chain, then this frame's __except.
 */
__declspec(dllexport) uint32_t mida_probe_read(
    const void* va, void* out16, uint32_t* status_slot);

/* Publishes the probe window for VEH attribution.
 * Returns a pointer to a static MidaProbeWindow.
 */
__declspec(dllexport) const MidaProbeWindow* mida_probe_window(void);
~~~

### 2.2 shim 实现约束（冻结）

- __try { __movsb(out16, va, 16); } __except(filter) { handler }：
  __movsb/两个 8 字节 load 是函数内**唯一**可能 fault 的指令；va 之外的全部输入
  （out16、status_slot）由调用方保证有效（探针线程栈），故函数体内任何 fault 均归属探针。
- **过滤器必须对到达本帧的任意异常返回 EXCEPTION_EXECUTE_HANDLER**（本帧是探针线程的
  最后防线；返回 CONTINUE_SEARCH 会把异常泄漏到未处理路径 = 进程终止 = walker 永久失联）。
- handler 按异常码分派：STATUS_GUARD_PAGE_VIOLATION (0x80000001) / STATUS_ACCESS_VIOLATION
  (0xC0000005) → *status_slot = MIDA_PROBE_FAULT；其它任何码 → *status_slot = MIDA_PROBE_ABORT。
- 过滤器只读 ExceptionRecord（分派栈上，已提交页），不触碰 TLS、不调用任何函数、不做分配。
- 探针窗口 = [mida_probe_read, mida_probe_read_end)：MSVC 保证同一 obj 内函数地址有序；
  mida_probe_window() 返回该区间。

### 2.3 Rust FFI 调用转换（fixture，实现工单照抄）

~~~rust
// walker 侧 FFI 声明（探针循环所在模块）
#[repr(C)]
struct MidaProbeWindow { start: *const u8, end: *const u8 }

extern "C" {
    fn mida_probe_read(va: *const u8, out16: *mut u8, status_slot: *mut u32) -> u32;
    fn mida_probe_window() -> *const MidaProbeWindow;
}

// 调用点合同（探针循环内，每候选一次）：
//   status_slot 为探针线程栈上的 32 位槽（8 字节对齐，初值 0xFF）；
//   out16 为探针线程栈上的 [u8; 16]；
//   status = mida_probe_read(va, out16, &mut slot);
//   status != 0 时不得使用 out16 内容；分类一律读 TLS 标记（§5）。
~~~

### 2.4 volatile 寄存器与 shadow space

- Windows x64 ABI volatile：rcx/rdx/r8/r9/r10/r11/rax 及 xmm0-5；探针循环不得在这些
  寄存器中保存跨调用状态（状态一律走栈/状态槽/TLS）。
- 调用方（Rust extern "C"）按 ABI 自动提供 32 字节 shadow space；shim 正常路径不调用
  函数，异常路径的展开/分派由内核与 __C_specific_handler 驱动，不额外占用调用方栈。

## 3. probe span 冻结 = 16（关闭 P0-1602-2）

- 探针 ABI **读取宽度恒为 16 字节**（两条 8 字节 load）；不存在按 1–64 变化的读取。
- WalkerParamsV2.probe_span 作为 Walker ABI 输入**必须 == 16**；运行时入口对
  probe_span != 16 的 params 直接拒收（BadProbeSpan，fail-closed，零探针）。
- 协议线范围 [1, 64] 在本设计语境下收紧为 **{16}**：实现工单必须同步把
  WalkerParamsV2::validate 收紧为 probe_span == DEFAULT_PROBE_SPAN（本单不改协议代码，
  只冻结 ABI 合同；收紧列入实现前 checklist §8）。
- ProbeResultV2.observed 恰为 16 字节，与读取宽度一致；probe_span 字段写入 16。

## 4. 异常流与完整状态表（关闭 P0-1602-1 的顺序/收口合同）

### 4.1 注册与顺序（WO-1702 裁决：观测-only 的 walker VEH 置于链首）

walker VEH 用 AddVectoredExceptionHandler(First=TRUE) 注册（链首），但**只观测、永不处理**：
- VEH 回调对探针 fault 只写 TLS 标记后一律返回 EXCEPTION_CONTINUE_SEARCH（0）；
  从不返回 EXCEPTION_CONTINUE_EXECUTION（恢复由保护器或 shim 帧完成），
  从不吞异常。
- 因此**保护器永远在 walker 之后仍获得同一异常**（若保护器已注册）；“保护器机会”
  由“walker 不截断”保证，与链序无关——旧设计 first=0 的顾虑在观测-only 语义下不成立。
- 链首注册的唯一目的：**Type B 可观测性**。保护器以 CONTINUE_EXECUTION 解密并重放成功后
  walker 若排在保护器之后将永远看不到 guard（误分类为 Type C，route-α 证据丢失）；
  链首观测使 guard_seen 在保护器解密前被记录。
- 若保护器在 walker 之后才以 First=TRUE 注册（运行时注册晚于本 walker），链序为
  保护器→walker：此时 walker 观测不到该 fault，按“未观测”诚实分类（§4.2 行 8）。

### 4.2 CONTINUE_SEARCH / CONTINUE_EXECUTION 完整状态表

| # | 事件 | walker VEH（链首，观测-only） | 保护器 VEH | 收口 | 探针结果 | walker 分类 |
|---|------|------------------------------|-----------|------|---------|------------|
| 1 | guard fault，保护器解密 | guard_seen=1 → CS | CE（解密） | 无（load 重放成功） | OK | **Type B**（guard_seen && OK） |
| 2 | guard fault，保护器未处理 | guard_seen=1 → CS | CS / 无 handler | shim __except → FAULT | FAULT | guard；重试 1 次（§3.4）后仍 FAULT → **Type A(guard)** |
| 3 | AV fault（非 guard），保护器 CE（异常但解密） | av_seen=1 → CS | CE | 无 | OK | 按 av_seen 重试 1 次；仍 OK → **Type C**（带 AV 标记，不虚报） |
| 4 | AV fault，保护器未处理 | av_seen=1 → CS | CS / 无 | shim → FAULT | FAULT | **AV**；重试 1 次后仍 AV → **Type A** |
| 5 | 未知异常码（如 breakpoint/illegal instr） | unknown_code=code → CS | CS / 无 | shim → ABORT | ABORT | **walker abort**（fail-closed，WALKER_ERROR_PROBE_ABORTED） |
| 6 | 未知异常码，保护器 CE（重放成功） | unknown_code=code → CS | CE | 无 | OK | **仍 abort**：unknown_code != 0 即 fail-closed，不因重放成功而继续 |
| 7 | 非探针线程 / 非 active / RIP 不在窗口的异常 | 不观测，CS | 照常 | 不达 shim（若达：filter 判 RIP 不在窗口 → ABORT） | — | 与 walker 无关；保护器链与其它 handler 观测权完整 |
| 8 | 探针 fault 但 walker VEH 未被调用（保护器后注册覆盖链首） | 未观测（TLS 无标记） | CE 解密 / CS | CS 时达 shim → FAULT | OK / FAULT | 未观测 + OK → **Type C**（诚实：无 guard 证据）；未观测 + FAULT → guard/AV 按 shim 结果 |

**不变量**：active 阶段内、探针线程上、窗口 RIP 处的异常，要么被保护器解密重放（行 1/3），
要么被 shim 帧收口（行 2/4/5）；不存在“未处理异常 → 进程终止”路径。unknown_code 置位
（行 5/6）→ 无条件 abort。

## 5. TLS 生命周期与候选绑定（关闭 P1-1602-3）

### 5.1 字段（探针线程 TLS，单线程独占）

| 字段 | 类型 | 语义 |
|------|------|------|
| active | bool | 探针循环阶段标记（装载/卸载/解析阶段 false） |
| guard_seen | bool | 本次候选已观测到 STATUS_GUARD_PAGE_VIOLATION |
| av_seen | bool | 本次候选已观测到 STATUS_ACCESS_VIOLATION |
| unknown_code | u32 | 本次候选观测到的未知异常码；0 = 无 |

### 5.2 生命周期规则（冻结）

1. **候选入口清零**：每个候选在调用 mida_probe_read 之前，walker 清零 guard_seen/
   av_seen/unknown_code——候选之间零状态继承（防 stale state 污染下一候选）。
2. **置位**：仅 walker VEH 在“active && 探针线程 && RIP∈窗口”时置位；任何其它条件不写 TLS。
3. **读取时序**：mida_probe_read 返回后、进入下一候选前，walker 一次性读取三个标记并
   据此分类（§4.2）；unknown_code != 0 → abort（行 5/6）。
4. **清理**：walker_inner 退出（成功/失败/abort）前清空全部字段并卸载 VEH（VehGuard RAII，
   §3.3.5）；卸载失败按既有 VEH_UNLOAD_FAILED 语义写入结果头。
5. **绑定**：标记只绑定“最近一次完成的候选”（入口清零 + 退出清理保证）；VEH 回调内
   只写不读、不判断，判定权在探针循环主路径。

## 6. x64 unwind metadata 与 DLL 生命周期

### 6.1 unwind metadata

- shim 的 .pdata/.xdata 由 MSVC 编译器生成，随 DLL PE 装载注册（LdrpInsertModuleTableEntry），
  FreeLibrary 卸载时自动注销；**全程零动态函数表操作**（不调用 RtlInstallFunctionTableCallback）。
- 要求：probe_shim.c 以 /O2 编译；禁止 /volatile:ms 之外的非常规开关；禁止内联汇编。

### 6.2 DLL 生命周期与卸载失败

| 场景 | 合同 |
|------|------|
| 正常卸载 | controller 先确认远程线程终止（RemoteWaitOutcome::Finished）→ 才允许释放 params/结果 section → 之后才 FreeLibrary（既有 §5 顺序铁律）；探针线程栈中不存在 mida_probe_read 帧时 DLL 方可卸载 |
| FreeLibrary 失败 | 按既有悬挂资源规则记录 orphaned_resources（§5.4），不强行重试 |
| 探针线程悬挂（TimedOut） | 禁止释放任何远程内存与 DLL（远程线程可能仍在该函数栈上）；最终回收方 = target 进程退出 |

## 7. 未验证声明（design-only）

- 本文件是设计合同；**不含任何 Windows 行为验证**。
- __try/__except 在 MSVC x64 下的 SEH 帧行为、VEH 链序、CONTINUE_EXECUTION 重放语义均
  属“待实现后验证”（V10），未在本仓库任何位置声称已验证。
- 实现工单必须提供：probe_shim.c 编译门（cl 编译 + 符号导出检查）、Rust FFI 编译门、
  探针原语单测（status_slot/FAULT/ABORT 路径）、VEH 观测单测、窗口归属单测；
  Windows 实弹行为仍需 LIVE-4 独立审批。

## 8. 实现前 checklist

- [ ] build.rs 集成：cc crate 编译 probe_shim.c（cl.exe /O2），失败即构建失败
- [ ] probe_shim.h/2.1 原样落地；符号 mida_probe_read / mida_probe_window 导出检查
- [ ] 协议收紧：WalkerParamsV2::validate 要求 probe_span == 16（§3，单独实现单）
- [ ] Rust FFI（2.3）与调用点合同落地；探针循环不跨调用保存 volatile 状态
- [ ] VEH：First=TRUE 注册、观测-only、恒 CS；归属过滤（线程/active/RIP∈窗口）
- [ ] TLS 生命周期（§5.2 五项）单测：候选清零、stale 防护、unknown abort
- [ ] 状态表 §4.2 行 1-8 逐行单测/仿真（离线：VEH+shim 逻辑；实弹：LIVE-4）
- [ ] 卸载顺序（§6.2）接入既有 wait-before-free 规则并回归
- [ ] WO-1301A-IMPL §3 与本文件一致（本单已同步）

## 9. 状态

| 对象 | 状态 |
|------|------|
| WO-1702 冻结合同 | design-only；待联审 |
| probe_shim.c / walker 代码 | 不存在（未派工） |
| Windows 行为 | NOT VERIFIED（V10 待 LIVE-4） |