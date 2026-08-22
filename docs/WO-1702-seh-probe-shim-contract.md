# WO-1702 — SEH Probe Shim 冻结合同（唯一机制：MSVC C __try/__except）

**工单编号**: WO-1702 / WO-1802-R1（Batch 17 返工）
**优先级**: P0
**性质**: design-only；不得实现、不得运行目标样本、不声称 Windows 行为已验证
**日期**: 2026-08-23
**基线**: e71445d → 0e5732f（Batch 18）
**状态**: 冻结候选 R2 — 待总指挥联审（WO-1802 fault attribution 修订）

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

/* Probe TLS record (WO-1901 frozen shared storage).
 * OWNER: the C shim. Declared as a __declspec(thread) static in
 * probe_shim.c; the compiler generates the x64 TLS access sequence
 * (TEB+0x58 ThreadLocalStoragePointer -> tls_array[_tls_index] -> +offset)
 * for EVERY access, including inside the SEH filter. Thread-locality of
 * the storage IS the thread-attribution filter: a fault on a non-probe
 * thread reads that thread's TLS where active==0.
 * Rust writes/reads ONLY through the exported accessors below; it never
 * touches the TLS slot directly (single owner = C).
 */
typedef struct MidaProbeTls {
    uint32_t magic;     /* +0x00 MIDA_TLS_MAGIC (0x4D504354 "MPCT") */
    uint32_t active;    /* +0x04 1 while a probe is in flight, else 0 */
    uint32_t seq;       /* +0x08 per-candidate monotonic probe sequence */
    uint32_t flags;     /* +0x0C mark bits: 1=guard_seen, 2=av_seen, 0x80000000=unknown */
    uint64_t token_va;  /* +0x10 current probe VA (8-aligned) */
    uint64_t unknown_code; /* +0x18 unknown exception code (0 = none) */
} MidaProbeTls;         /* size 0x20, align 8 */

/* Mark bits (flags field) */
#define MIDA_TLS_MARK_GUARD   0x00000001u
#define MIDA_TLS_MARK_AV      0x00000002u
#define MIDA_TLS_MARK_UNKNOWN 0x80000000u

_Static_assert(sizeof(MidaProbeTls) == 0x20, "MidaProbeTls size");
_Static_assert(offsetof(MidaProbeTls, token_va) == 0x10, "token_va offset");
_Static_assert(offsetof(MidaProbeTls, unknown_code) == 0x18, "unknown_code offset");

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

/* ---- TLS accessors (Rust side uses ONLY these; owner = C) ---- */

/* Begin a probe: writes magic/active=1/seq/token_va into the current
 * thread's TLS. Returns 0 on success, non-zero if the TLS slot was
 * already active (re-entry) or magic was corrupted -> caller must ABORT.
 */
__declspec(dllexport) uint32_t mida_probe_tls_begin(uint64_t va, uint32_t seq);

/* Clear the current thread's TLS (active=0, token_va=0, seq unchanged
 * is allowed; magic preserved). Called after mida_probe_read returns and
 * before the next candidate.
 */
__declspec(dllexport) void mida_probe_tls_clear(void);

/* Snapshot the current thread's TLS (read-only pointer into the TLS
 * slot; valid only while the probe thread lives). Used by the walker to
 * read seq/active after a probe and by tests to inspect state.
 */
__declspec(dllexport) const MidaProbeTls* mida_probe_tls_snapshot(void);

/* Mark the current thread's TLS with an observed exception code
 * (called ONLY by the walker VEH, single owner = C):
 *   code == 0x80000001 (guard) -> flags |= MIDA_TLS_MARK_GUARD
 *   code == 0xC0000005 (AV)    -> flags |= MIDA_TLS_MARK_AV
 *   anything else              -> flags |= MIDA_TLS_MARK_UNKNOWN;
 *                                unknown_code = code
 * Rust reads marks via snapshot() and clears them via mida_probe_tls_clear.
 */
__declspec(dllexport) void mida_probe_tls_mark(uint32_t code);
~~~

### 2.2 shim 实现约束（WO-1802 冻结）

- **faulting primitive（唯一，冻结）**：__try 块内执行**两条 8 字节 load**，各带一条
  mov 写入 out16：
  ~~~c
  __try {
      const uint64_t lo = *(const volatile uint64_t*)va;   /* load 1 (fault possible) */
      ((volatile uint64_t*)out16)[0] = lo;
      const uint64_t hi = *(const volatile uint64_t*)((const char*)va + 8); /* load 2 */
      ((volatile uint64_t*)out16)[1] = hi;
  } __except (mida_probe_filter(GetExceptionInformation())) { handler }
  ~~~
  **禁止 __movsb / rep movsb / 单条 16 字节 load（movups）**：movups 是单指令跨 8 字节
  边界，fault 归属与部分写入语义模糊；两条 8 字节 load 的 faulting 访问地址（AV 的
  ExceptionInformation[1]）分别精确等于 va 与 va+8，归属无歧义。
- **调用点写入 TLS.token_va**：探针循环在调用前把 (va, seq) 写入 TLS
  （token_va.va = va；token_va.seq = 本候选的单调序号）；返回后清零。
- **过滤器必须对到达本帧的任意异常返回 EXCEPTION_EXECUTE_HANDLER**（本帧是探针线程的
  最后防线；返回 CONTINUE_SEARCH 会把异常泄漏到未处理路径 = 进程终止 = walker 永久失联）。
- **过滤器判别（WO-1802 新增）**：
  1. 读 ExceptionRecord：code、Rip、ExceptionInformation[0]（Write/Data）、[1]（访问地址）。
  2. **非 probe fault 必须 ABORT**：若 Rip 不在本函数 __try 体内（编译器报告的函数地址
     范围由 __C_specific_handler 表驱动，帧本身只接受本函数异常）→ 不可能发生
     （该帧只包裹本函数）；若访问地址 != MidaProbeTls.token_va 且 != token_va+8（load 2）→
     说明 fault 不是当前探针的读取 → status_slot = ABORT（fail-closed，不静默分类）。
  3. 访问地址 == token_va.va 或 va+8 且码为 guard/AV → FAULT。
  4. 其它码（breakpoint 等）→ ABORT（沿用 §4.2 行 5/6）。
- handler 按异常码分派：STATUS_GUARD_PAGE_VIOLATION (0x80000001) / STATUS_ACCESS_VIOLATION
  (0xC0000005) 且访问地址匹配 → *status_slot = MIDA_PROBE_FAULT；其它 → MIDA_PROBE_ABORT。
- 过滤器只读 ExceptionRecord 与 TLS.token_va（已提交页），不调用任何函数、不做分配。
- **无 RIP window 合同**：mida_probe_read_end 符号**不存在**；不依赖任何函数地址排序/
  linker section。归属 = 线程 + token_va 访问地址匹配（§4.3）。
### 2.3 Rust FFI 调用转换（fixture，实现工单照抄）

~~~rust
// walker 侧 FFI 声明（探针循环所在模块；WO-1901 冻结）
#[repr(C)]
struct MidaProbeTls {
    magic: u32,
    active: u32,
    seq: u32,
    reserved: u32,
    token_va: u64,
}

extern "C" {
    fn mida_probe_read(va: *const u8, out16: *mut u8, status_slot: *mut u32) -> u32;
    fn mida_probe_tls_begin(va: u64, seq: u32) -> u32;   // 0 ok, !=0 re-entry -> ABORT
    fn mida_probe_tls_clear();
    fn mida_probe_tls_snapshot() -> *const MidaProbeTls;
}

// 调用点合同（探针循环内，每候选一次）：
//   status_slot 为探针线程栈上的 32 位槽（8 字节对齐，初值 0xFF）；
//   out16 为探针线程栈上的 [u8; 16]；
//   1. seq += 1（探针循环局部计数器）；
//   2. rc = mida_probe_tls_begin(va as u64, seq)；rc != 0 → abort（重入/损坏）；
//   3. status = mida_probe_read(va, out16, &mut slot);
//   4. tls = *mida_probe_tls_snapshot()（读 active/seq/token_va，仅探针线程）；
//   5. mida_probe_tls_clear();
//   6. status != OK 时不得使用 out16 内容；分类按 status + TLS 标记（§4.2/§5）。
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
- 协议线范围已由 **WO-1801 同步收紧为 {16}**（walker_protocol.rs：MIN/MAX/DEFAULT 全部
  == 16；WalkerParamsV2::validate 与 ProbeResultV2::validate 均精确等于 16；1/15/17/64
  拒收 fixture 已通过；walkler_protocol tests 15 + section tests 27 全绿）。
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
| 7 | 非探针线程 / 非 active / 访问地址 ≠ token_va.va(va+8) 的异常 | 不观测，CS | 照常 | 不达 shim（若达：filter 判访问地址不匹配 → ABORT） | — | 与 walker 无关；保护器链与其它 handler 观测权完整 |
| 8 | 探针 fault 但 walker VEH 未被调用（保护器后注册覆盖链首） | 未观测（TLS 无标记） | CE 解密 / CS | CS 时达 shim → FAULT | OK / FAULT | 未观测 + OK → **Type C**（诚实：无 guard 证据）；未观测 + FAULT → guard/AV 按 shim 结果 |

**不变量**：active 阶段内、探针线程上、访问地址匹配 token_va 的异常，要么被保护器解密重放（行 1/3），
要么被 shim 帧收口（行 2/4/5）；不存在“未处理异常 → 进程终止”路径。unknown_code 置位
（行 5/6）→ 无条件 abort。

### 4.3 fault attribution 合同（WO-1802 冻结，替代 RIP window）

归属 = 三条件**同时**成立：
1. **线程**：faulting 线程 == 探针线程（TLS 线程身份匹配）；
2. **阶段**：TLS.active == true（探针循环阶段内）；
3. **访问地址**：ExceptionRecord.ExceptionInformation[1]（AV/guard 的 faulting 访问地址）
   ∈ { MidaProbeTls.token_va, MidaProbeTls.token_va + 8 }（两条 8 字节 load 的唯一可能访问地址）。

- **无 RIP window**：不定义 mida_probe_read_end；不依赖函数地址排序、linker section、
  或任何代码布局假设。编译器/链接器可任意重排/内联/优化 shim 而不影响归属。
- **VEH 侧归属**：walker VEH 用同一三条件判断是否为本探针 fault（只观测）；任何一条
  不满足 → 不写 TLS、CONTINUE_SEARCH。
- **shim filter 侧归属**：访问地址不匹配（或 code 非 guard/AV）→ ABORT；匹配 →
  FAULT。**非 probe fault 到达 shim 帧 = ABORT（fail-closed）**：帧只包裹本函数，
  若访问地址不属于本探针读取，说明发生了未预期 fault（如 out16/status_slot 因调用方
  缺陷而失效）→ 不得继续。
- **C 可离线审查 fixture（§7.1）**：纯函数归属判定（thread_ok && active && addr_match）
  与状态转换（表 §4.2 行 1-8）可脱离 Windows 用单元测试验证（输入为模拟的
  ExceptionRecord/TLS 值）；这不构成 Windows 行为已验证（V10 仍待 LIVE-4）。
### 4.4 TLS 共享存储与生命周期（WO-1901 冻结，owner = C shim）

**owner 裁定**：TLS 槽（MidaProbeTls，__declspec(thread) static）**唯一属主为 C shim**；
Rust 侧绝不直接访问 TLS 槽（不声明同名 thread_local），只经导出 accessor
（mida_probe_tls_begin/clear/snapshot）。SEH filter 在异常分派上下文内**直接读同一槽**
（编译器生成的 TLS 访问序列，无函数调用）——这就是 filter 读取"当前探针 token"的真实 ABI。

**x64 TLS 表示**（编译器生成，冻结假设）：
- __declspec(thread) static → TEB+0x58（ThreadLocalStoragePointer）→
  tls_array[_tls_index]（tls_index 由链接器分配）→ +slot offset；
- 访问序列对 begin/clear/snapshot/filter 一致；MSVC 保证同一 DLL 内 thread-local
  访问通过同一 _tls_index；禁止 /Gs 之外的 TLS 相关开关改动。

**生命周期时序（冻结）**：
1. 探针线程创建后、首候选前：TLS 零初始化（active=0, magic=0）→ 首调用 begin 写入 magic；
2. 每候选：seq += 1（Rust 局部）→ begin(va, seq)：校验 magic 非 0（首写）或 ==MIDA_TLS_MAGIC，
   且 active==0（否则返回 1 = 重入）；写入 active=1/token_va=va/seq；
3. mida_probe_read 执行（异常可能发生：VEH 观测 → filter 读 TLS → handler 写 status_slot）；
4. 返回后：Rust 读 snapshot（active/seq/token_va）→ clear（active=0, token_va=0）；
5. 探针线程退出前：clear + 线程终止（OS 回收 TLS）；
6. 异常返回路径：handler 只写 status_slot，**不**改 TLS（VEH 已写标记；TLS 由主路径 clear）；
7. 嵌套/重入：begin 返回非 0 → 探针循环 abort（fail-closed）；filter 若在 begin 前
   被调（不可能：filter 只被本函数 __try 触发）→ active==0 → ABORT。

**stale-token 防护**：候选间 clear 保证下一候选 begin 前 active==0、token_va==0；
任何"旧 token 残留"场景（begin 失败、异常后未 clear）都在下一步 begin 时被检测 → abort。

**线程身份**：TLS 天然线程局部——非探针线程读到的 active==0，归属失败 → VEH 不观测、
filter 若达（不可能）→ ABORT。无需额外线程 ID 存储。

**fail-closed 判定矩阵（filter 内，WO-1901）**：

| 条件 | 结果 |
|------|------|
| active==0（本线程无探针） | ABORT（若达本帧即异常异常路径；VEH 侧则 CONTINUE_SEARCH） |
| magic != MIDA_TLS_MAGIC | ABORT（槽损坏） |
| token_va==0 | ABORT（未 begin 却 fault） |
| 访问地址 == token_va 或 token_va+8，码为 guard/AV | FAULT |
| 访问地址 == 其它值 | ABORT（out16/status_slot 故障或非本探针 fault） |
| 码为未知（非 guard/AV） | ABORT |
| seq 与调用方期望不符（VEH 侧记录，主路径比对） | abort（分类时检测） |
| 地址溢出（token_va+8 回绕） | begin 时拒绝：token_va 必须 canonical 且 token_va <= MAX-8 → 否则 begin 返回非 0 |

### 4.4a 状态模型（WO-2001 冻结：单一槽，逐字段 owner/reader/writer）

**单一槽裁定**：token 状态与异常标记**同一 C-owned TLS 槽**（MidaProbeTls，0x20）；
不存在第二份 Rust thread_local 或 controller-owned memory 状态。

| 字段 | offset | owner | writer | reader | 清零时序 |
|------|--------|-------|--------|--------|---------|
| magic | 0x00 | C shim | mida_probe_tls_begin（首写/校验） | VEH（snapshot）、filter、Rust 主路径（snapshot） | 线程退出（OS 回收） |
| active | 0x04 | C shim | begin(=1) / clear(=0) | VEH、filter、Rust 主路径 | 每候选 clear |
| seq | 0x08 | C shim | begin（来自调用方参数） | Rust 主路径（snapshot 后与局部期望比对）；filter 不读 | 不主动清零（单调递增） |
| flags | 0x0C | C shim | mida_probe_tls_mark（VEH 内） | Rust 主路径（分类）；filter 不读 | 每候选 begin 前置零（begin 内部） |
| token_va | 0x10 | C shim | begin | VEH（归属）、filter（归属） | 每候选 clear |
| unknown_code | 0x18 | C shim | mida_probe_tls_mark（unknown 时） | Rust 主路径（abort 判定） | 每候选 begin 前置零 |

**accessor 契约**：
- mida_probe_tls_begin(va, seq)：校验 magic（首写或 ==MIDA_TLS_MAGIC）与 active==0；
  置 flags=0、unknown_code=0、active=1、token_va=va、seq=seq；返回 0 或错误码；
- mida_probe_tls_mark(code)：仅 VEH 调用；按 code 置 flags 位（unknown 时同时写 unknown_code）；
- mida_probe_tls_snapshot()：返回当前线程槽指针（只读）；
- mida_probe_tls_clear()：active=0、token_va=0、flags=0、unknown_code=0（magic/seq 保留）。

**Rust 侧禁止**：声明同名 thread_local、直接访问槽字段、绕过 accessor 写状态。

### 4.4b seq attribution 闭环（WO-2001 冻结）

- **expected seq 来源**：Rust 探针循环的局部计数器（每候选 ++），经 begin(va, seq) 写入；
- **filter 不读 seq**：filter 只做归属（magic/active/token_va/访问地址/异常码）与分类；
- **主路径比较点**：mida_probe_read 返回后、clear 前，Rust 读 snapshot 得 (active, seq, flags,
  unknown_code)；seq 必须 == 局部期望值；
  - seq 不符 → abort（WALKER_ERROR_PROBE_ABORTED）——证明"当前调用被另一探针/重入污染"；
- **旧 fault / 迟到异常**：上一候选的异常已在上一候选的 clear 中被清（flags/unknown_code=0）；
  若 VEH 在本候选 begin 前被调用（不可能：VEH 只在探针 load 时触发）→ active==0 → 不观测；
  若异常迟到达（handler 已返回但 VEH 后写）→ 本候选 clear 后 flags 归零，下一候选 begin
  前检测 flags!=0 → abort（stale mark 检测，fail-closed）；
- **fixture**：mida_attr_classify 增加 seq 输入与 expected_seq 比较断言（见
  docs/fixtures/WO-1901-probe-tls-fixture.h 更新后版本）。

## 5. TLS 生命周期与候选绑定（关闭 P1-1602-3）

### 5.1 字段（探针线程 TLS，单线程独占）

| 字段 | 类型 | 语义（WO-2001：MidaProbeTls 槽内） |
|------|------|------|
| active | u32（槽 +0x04） | 探针循环阶段标记（装载/卸载/解析阶段 false） |
| flags.GUARD（位 0） | u32（槽 +0x0C） | 本次候选已观测到 STATUS_GUARD_PAGE_VIOLATION |
| flags.AV（位 1） | u32（槽 +0x0C） | 本次候选已观测到 STATUS_ACCESS_VIOLATION |
| unknown_code | u64（槽 +0x18） | 本次候选观测到的未知异常码；0 = 无 |

### 5.2 生命周期规则（冻结）

1. **候选入口清零**：每个候选在调用 mida_probe_read 之前，walker 经
   mida_probe_tls_begin(va, seq) 置零 flags/unknown_code（begin 内部动作）——候选之间
   零状态继承（防 stale state 污染下一候选）。
2. **置位**：仅 walker VEH 在“active && 访问地址匹配 MidaProbeTls.token_va（或 token_va+8）”
   时经 mida_probe_tls_mark(code) 置 flags；任何其它条件不写 TLS。
3. **读取时序**：mida_probe_read 返回后、clear 前，walker 一次性读 snapshot
   （flags/unknown_code/seq）并据此分类（§4.2）；unknown_code != 0 → abort（行 5/6）；
   seq != 局部期望 → abort（§4.4b）。
4. **清理**：walker_inner 退出（成功/失败/abort）前经 mida_probe_tls_clear 清空并卸载
   VEH（VehGuard RAII，§3.3.5）；卸载失败按既有 VEH_UNLOAD_FAILED 语义写入结果头。
5. **绑定**：标记只绑定“最近一次完成的候选”（begin 置零 + clear 清理保证）；VEH 回调内
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

### 7.1 可离线审查的 C header / 状态转换 fixture（WO-1802 交付）

- **归属判定纯函数**（fixture，实现工单照抄；完整文件见
  docs/fixtures/WO-1901-probe-tls-fixture.h，含 MidaProbeTls 布局 static_assert）：
  ~~~c
  /* attribution_contract.h — WO-1802/WO-1901 */
  typedef struct AttrInput {
      int    probe_thread;      /* faulting thread == probe thread ? */
      int    active;            /* TLS.active */
      uint64_t access_addr;     /* ExceptionInformation[1] */
      uint64_t token_va;        /* TLS.token_va.va */
      uint32_t code;            /* exception code */
  } AttrInput;
  typedef enum { ATTR_NONE, ATTR_PROBE_FAULT, ATTR_PROBE_ABORT } AttrResult;

  /* Returns ATTR_PROBE_FAULT iff probe_thread && active &&
   * (access_addr == token_va || access_addr == token_va + 8) &&
   * (code == 0x80000001 || code == 0xC0000005);
   * ATTR_PROBE_ABORT iff probe_thread && active && access matches but code is
   *   anything else (unknown code reaches shim frame);
   * ATTR_NONE otherwise (not our probe fault -> walker VEH continues search).
   */
  AttrResult mida_attr_classify(AttrInput in);
  ~~~
- **状态转换 fixture**：§4.2 行 1-8 的每一行一个可执行断言
  （输入 AttrInput + 保护器结果 → 期望 status_slot + TLS 标记 + 分类），
  与 Rust 探针循环分类函数一一对应。
- 这些 fixture 是**纯逻辑**，不触碰 Windows API；证明归属/分类逻辑正确，
  **不等于** Windows 下 __try/__except/VEH 链行为已验证（V10 仍待实现后 LIVE-4 验证）。
## 8. 实现前 checklist

- [ ] build.rs 集成：cc crate 编译 probe_shim.c（cl.exe /O2），失败即构建失败
- [ ] probe_shim.h/2.1 原样落地；符号 mida_probe_read / mida_probe_tls_begin / mida_probe_tls_clear / mida_probe_tls_snapshot 导出检查
- [ ] 协议收紧：WalkerParamsV2::validate 要求 probe_span == 16（§3，单独实现单）
- [ ] Rust FFI（2.3）与调用点合同落地；TLS 仅经 accessor（begin/clear/snapshot）访问；探针循环不跨调用保存 volatile 状态
- [ ] VEH：First=TRUE 注册、观测-only、恒 CS；归属过滤（线程/active/访问地址==token_va.va 或 va+8）
- [ ] TLS 生命周期（§4.4 + §5.2）单测：begin/clear 时序、重入 abort、stale 防护、unknown abort、filter 判定矩阵逐行
- [ ] 状态表 §4.2 行 1-8 逐行单测/仿真（离线：VEH+shim 逻辑；实弹：LIVE-4）
- [ ] 卸载顺序（§6.2）接入既有 wait-before-free 规则并回归
- [ ] WO-1301A-IMPL §3 与本文件一致（本单已同步）

## 9. 状态

| 对象 | 状态 |
|------|------|
| WO-1702 冻结合同 | design-only；待联审 |
| probe_shim.c / walker 代码 | 不存在（未派工） |
| Windows 行为 | NOT VERIFIED（V10 待 LIVE-4） |