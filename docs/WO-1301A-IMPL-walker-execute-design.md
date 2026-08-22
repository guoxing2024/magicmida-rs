# WO-1301A-IMPL：WalkerExecute 实施设计（返工版 R1，WO-1401-R1）

**工单编号**: WO-1401-R1（WO-1301A-IMPL 返工）
**优先级**: P0
**类型**: 设计文档（docs-only，零实弹零代码）
**日期**: 2026-08-22
**状态**: **design draft — 待总指挥重新联审**

---

## 0. 返工声明（先定交付性质）

本文件是 **设计草案**，不是实现。特此声明并撤回上一版总结中的全部虚假状态：

> **WO-1301A-IMPL = design draft rejected；未实现、未实测、未批准 LIVE-4。**

以下措辞在本文件及任何交付状态中**禁止再出现**：
"C1 条件遵守已验证"、"F2 修复验证"、"代码实现"、"共享内存通信已完成"、
"单元测试/集成测试已完成"、"Step 1 总指挥审批 ✅"、"下一步同步起草 LIVE-4"。

本文件所有能力描述一律为**设计意图（待验证）**，不得作为工程证据。仓库中当前**不存在**
`crates/antidebug-runtime/src/walker/`、`WalkerExecute` 导出、`walker_invoke.rs`、
`antidebug-runtime/tests/walker.rs`；`0ef8ad5` 仅证明文档提交存在，不证明实施完成。

### 0.1 本次返工关闭的 8 项

| # | 审计问题 | 关闭方式 | 章节 |
|---|---------|---------|------|
| 1 | 跨进程裸指针 | 候选数组改为 target-local mapping + offset/length，全程禁止裸指针跨进程 | §2.4 |
| 2 | 原始 HANDLE 直传 target | 命名 section + nonce + target 侧 `OpenFileMappingW`，不传 HANDLE 数值 | §2.5 |
| 3 | `catch_unwind` 捕获 AV 的错误论断 | 撤回；AV/guard 由 VEH 处理，`catch_unwind` 仅作 FFI panic 防火墙 | §3 |
| 4 | `todo!()` 伪闭环 | 全删；loader 对位复用真实 `resolve_mida_exports_remote`（module_base+RVA） | §4 |
| 5 | 超时/异常/线程仍运行时 cleanup 缺口 | fail-closed 失败状态机；`TimedOut` 下禁止释放远程可触碰内存 | §5 |
| 6 | `120min` 单总时限 | 改为 `cap = 2 rounds × 60min`，每轮独立账本，禁止自动重试/无限延长 | §6 |
| 7 | Provenance/Attestation schema 漂移 | 定义 `v2` schema + 迁移策略，列出受影响构造器/消费者/测试 | §7 |
| 8 | "已验证/已完成"虚假状态 | 全文改"待验证"，附验证矩阵，无 live 证据 | §9 |

---

## 1. C1 / C2 遵守边界（设计约束，待验证）

### 1.1 C1：单一 DLL 强制

WalkerExecute **必须**作为现有 `mida_antidebug_runtime` DLL 的一个 C ABI 导出新增，
**禁止**引入第二个自研 payload DLL。理由（引 WO-1301A 批准条件）：单一证据链、
最小化授权面、复用已验证加载路径、避免双账本。

**对位现状**（真实，仓库已存在）：
- 导出宿主：`crates/antidebug-runtime/src/exports.rs`，现有导出 `MidaAntidebugInitialize`（L182）、`install_proc_surfaces`。
- 加载链：`crates/cli/src/unpacker/runtime_loader.rs` 的 `RuntimeLoader::load_and_initialize`（L1029）跑完整 ADR-6 链。
- 导出解析：同文件 `resolve_mida_exports_remote(target, module_base)`（L1275），target 内解析 PE 导出目录，返回 `module_base + RVA`。

**新增导出（设计意图，待实现）**：`WalkerExecute`，与 `MidaAntidebugInitialize` 并列，
经同一 `resolve_mida_exports_remote` 的 wanted 列表解析，无需第二个 DLL、无需第二条加载链。

### 1.2 C2：注入原语授权枚举（待 LIVE-4 明确）

除 PEB surfaces 与 payload 字节外，任何对 target 的写入仍是红线。walker 允许的写入原语与用途，
逐项列入授权与证据（本设计仅登记，实弹授权由总指挥在 LIVE-4 签发）：

| 原语 | 用途 | 授权边界 | 证据要求 |
|-----|------|---------|---------|
| `VirtualAllocEx(PAGE_READWRITE)` | 分配 target-local WalkerParams blob + 结果 section 备用 | 仅 walker 参数/结果区，非 .text | 记录基址、大小、保护属性 |
| `WriteProcessMemory` | 写入 params blob（候选 offset/length，非目标代码） | 仅 walker 参数区 | 记录写入范围、字节数、CRC |
| `CreateRemoteThread` | 调用 `WalkerExecute` 导出入口 | 入口地址必须 == `module_base + WalkerExecute RVA` | 记录入口地址、参数 VA |
| `CreateFileMappingW` / `MapViewOfFile` | 结果回传 section（命名 + nonce） | 只读结果，不映射进 .text | 记录 section 名、nonce、字节长度 |

**载荷白名单**："仅执行 `WalkerExecute` 导出"不等于"只加载该导出"：加载 DLL、远程参数写入、
远程线程创建、命名 section、目标异常 handler 均**分别**列入上表授权与证据，缺一不放行。

---

## 2. IPC 协议（关闭 #1 跨进程裸指针、#2 原始 HANDLE 直传）

### 2.1 方案选择

采用 **target-local 参数 blob（自相对寻址）+ 命名 section 结果回传（target 侧 `OpenFileMappingW`）**。

- 参数下行：复用 `load_and_initialize` 已验证范式——controller 用 `VirtualAllocEx`+`WriteProcessMemory`
  在 **target 地址空间**内构造 params blob，把 **target-local VA** 交给 `CreateRemoteThread` 的 lpParameter。
  候选数组随 blob 一同写入 target，通过 **blob 内 offset/length** 访问，**全程无跨进程裸指针**。
- 结果上行：命名 file-mapping section，controller 创建、target 侧按**唯一 nonce 名** `OpenFileMappingW` 打开，
  **不传 HANDLE 数值**。

**明确废弃**（原设计 P0-1/P0-2 错误）：
- ❌ `candidate_addrs: *const usize` 作为"调试器侧地址"跨进程传递；
- ❌ `shared_memory_handle: shared_mem_handle.0 as usize` 数值直传（HANDLE 进程私有，数值相同 ≠ target 拥有该 handle）。

### 2.2 下行：WalkerParams blob 布局（target-local，自相对寻址）

blob 由 controller 在 **target** 内一次性 `VirtualAllocEx` + `WriteProcessMemory`。所有指针字段写
**target-local VA**（= `blob_base_va + 字段在 blob 内 offset`），不写 controller 侧地址。

```
偏移    字段              类型      说明
0x00    magic             u32       0x57414C4B ("WALK")
0x04    version           u16       2（本设计版本）
0x06    header_bytes      u16       固定头长度（= 候选数组 offset）
0x08    blob_total_bytes  u64       整个 blob 字节数（含头 + 候选数组）
0x10    blob_base_va      u64       本 blob 在 target 的基址（自相对锚点）
0x18    candidate_off     u32       候选数组相对 blob_base 的 offset（= header_bytes）
0x1C    candidate_count   u32       候选地址数量
0x20    candidate_stride  u16       每候选字节数（= 8，u64 VA）
0x22    options_flags     u16       WalkerOptions 位标志
0x24    probe_span        u16       每次探针读取字节数（默认 16）
0x26    _reserved         u16
0x28    result_nonce      u64       结果 section 名的 nonce（见 §2.3）
0x30    result_bytes      u64       结果 section 期望字节数（controller 预分配）
0x38    header_crc32      u32       头部 [0x00,0x38) 的 CRC32（校验）
0x3C    _pad              u32
0x40..  candidate[i]      u64 ×N    候选 target VA 数组（就在同一 blob 内）
```

**访问规则**：target 内 `WalkerExecute` 从 `lpParameter`（= `blob_base_va`）读头，校验 `magic`/`version`/`header_crc32`，
再按 `candidate_off`/`candidate_count`/`candidate_stride` 就地遍历候选数组。**不从任何 controller 侧指针取数**。

### 2.3 上行：命名 section 协议（target 侧 OpenFileMappingW）

- **命名**：`Local\\MidaWalkerResult-{target_pid}-{result_nonce:016x}`。nonce 由 controller 生成（≥64-bit CSPRNG），
  经 params blob（`result_nonce`）下达，防止命名冲突与旁进程抢占。
- **创建方**：controller `CreateFileMappingW`（`PAGE_READWRITE`，大小 = `result_bytes`），持有 owner handle。
- **打开方**：target 内 `OpenFileMappingW(FILE_MAP_WRITE, FALSE, name)` + `MapViewOfFile`，得到 **target-local 视图基址**，
  **不接收任何 controller HANDLE 或地址**。
- **权限**：section DACL 限定当前用户；`FILE_MAP_WRITE` 仅授予结果写入所需权限。

### 2.4 结果 section header（关闭 #1：结果也走 offset/length，非裸指针）

```
偏移    字段              类型      说明
0x00    magic             u32       0x57524553 ("WRES")
0x04    version           u16       2
0x06    _reserved         u16
0x08    section_bytes     u64       section 总字节数（= params.result_bytes）
0x10    result_count      u32       walker 已写入的 ProbeResult 数量
0x14    result_stride     u32       每条 ProbeResult 字节数（固定）
0x18    results_off       u32       结果数组相对 section 基址的 offset
0x1C    walker_status     u32       WalkerExecute 返回码镜像（见 §5.3）
0x20    payload_crc32     u32       [results_off, results_off+count*stride) 的 CRC32
0x24    completed_flag    u32       0=运行中，1=正常完成，0xDEAD****=abort 码
0x28..  ProbeResult[i]              固定布局，无内嵌指针
```

controller 读取时：先校验 `magic`/`version`，确认 `completed_flag==1`，再按 `results_off`/`result_count`/`result_stride`
就地解析，末以 `payload_crc32` 校验。**ProbeResult 内不含任何指针**（`data` 为定长 `[u8; probe_span]` 内联）。

### 2.5 生命周期与 ownership / close order（fail-closed）

| 步骤 | 动作 | 拥有方 | 失败处理 |
|-----|------|-------|---------|
| 1 | controller `CreateFileMappingW`（命名+nonce） | controller | 失败 → 不注入，abort（§5） |
| 2 | controller `VirtualAllocEx`+`WriteProcessMemory`(params blob) | controller（target 内存） | 失败 → 释放 section，abort |
| 3 | controller `CreateRemoteThread(WalkerExecute, blob_base_va)` | controller（thread handle） | 失败 → 释放 blob + section，abort |
| 4 | target `OpenFileMappingW`+`MapViewOfFile` | target（target-local 视图） | 失败 → walker 返回错误码，controller 走 §5 |
| 5 | walker 写结果 + `completed_flag=1` | target | walker 崩溃 → `completed_flag` 停在 0，controller 超时 fail-closed |
| 6 | controller 等线程（bounded wait，见 §6） | controller | `TimedOut` → **禁止释放** blob/section（远程线程可能仍在触碰），见 §5.4 |
| 7 | 成功：controller `UnmapViewOfFile`（若映射）→ `CloseHandle(section)` → 保留/回收 blob 依 §5.4 | controller | — |

**关闭顺序铁律**：section 与 params blob 的释放**必须**在确认远程线程已终止（`RemoteWaitOutcome::Finished`）之后。
`TimedOut` 状态下一律不释放，交给 §5.4 的悬挂内存处置规则。

---

## 3. 异常处理（关闭 #3：撤回 catch_unwind 捕获 AV 的错误论断）

### 3.1 明确撤回

原设计声称 `std::panic::catch_unwind(|| read_volatile(ptr))` 能把 `STATUS_ACCESS_VIOLATION` 转成
`Err`，并以 panic 表示"未恢复的 AV"。**此论断错误，予以撤回**：

- Rust 标准库**不会**把 Windows 结构化异常（`STATUS_ACCESS_VIOLATION` = 0xC0000005 /
  `STATUS_GUARD_PAGE_VIOLATION` = 0x80000001）自动转换为 panic 或 `Result`。
- `catch_unwind` 只捕获 **Rust panic 的 unwind**；一条 faulting load 触发的是 CPU 异常，
  经内核分发到 **SEH / VEH**，不经过 Rust 的 panic 机制。默认 `read_volatile` 命中无效页时，
  未被 SEH/VEH 处理则进程直接崩溃，`catch_unwind` 的 `Ok/Err` 分支根本不会执行到"AV 分支"。
- 因此"SEH + read_volatile 正确触发保护器 VEH"是**未验证且当前代码模型不成立**的结论，撤回。

### 3.2 catch_unwind 的唯一合法用途：FFI panic 防火墙

保留 `catch_unwind`，但**仅用于**导出边界防止 Rust panic 跨 FFI 展开（UB），与 AV 无关——
这与现有 `MidaAntidebugInitialize` 一致（`exports.rs:190`，panic → `InternalPanic` 错误码）：

```rust
// WalkerExecute 导出边界：catch_unwind 只挡 Rust panic，不挡 CPU 异常
#[no_mangle]
pub unsafe extern "C" fn WalkerExecute(params_va: usize) -> u32 {
    std::panic::catch_unwind(|| walker_inner(params_va))
        .unwrap_or(WALKER_ERROR_INTERNAL_PANIC)  // 仅 Rust panic 落这里
}
```

### 3.3 真实机制：VEH（AddVectoredExceptionHandler）+ 上下文修正

target 内探针的异常处理**唯一机制**为 VEH，理由与责任边界：

1. **谁装 handler**：walker 在 target 内调用 `AddVectoredExceptionHandler(first=1, veh_callback)`，
   进程级、优先于 SEH 帧展开被调用。**walker 的 VEH 只做分类与决策，不冒充保护器解密。**
2. **保护器 VEH 的位置**：解密由**保护器自己的 VEH**完成（Route α 假说核心）。walker 的读取触发
   guard/AV，先经内核分发；若保护器 handler 完成解密并 `EXCEPTION_CONTINUE_EXECUTION`，读取重试即得明文。
   walker VEH 仅在保护器未处理时兜底分类，**不修改目标内存、不逆向解密算法**。
3. **handler 顺序 / 链保留**：`AddVectoredExceptionHandler` 返回 handle，`RemoveVectoredExceptionHandler`
   卸载；walker 装/卸成对，`first=1` 确保早于既有 handler 观测，但**分类为 guard/保护器相关时一律
   `EXCEPTION_CONTINUE_SEARCH`**，把控制权交回保护器链，绝不截断。
4. **线程局部状态**：探针地址、guard_triggered 标志、重试计数存 TLS（`#[thread_local]`），
   避免多线程竞争；walker 探针**单线程串行**执行以简化状态机。

### 3.4 分类与"不可恢复即 abort"规则

```rust
unsafe extern "system" fn veh_callback(info: *mut EXCEPTION_POINTERS) -> i32 {
    let rec = (*(*info).ExceptionRecord);
    let code = rec.ExceptionCode.0 as u32;
    match code {
        STATUS_GUARD_PAGE_VIOLATION => {
            // 保护器可能正在解密；把机会让回保护器链，不自行 CONTINUE_EXECUTION。
            PROBE_TLS.with(|t| t.guard_seen.set(true));
            EXCEPTION_CONTINUE_SEARCH        // 交回保护器 VEH
        }
        STATUS_ACCESS_VIOLATION => {
            // 真实 AV（加密态或无效地址）：记录一次，交回链；由 walker_inner 决定跳过该候选。
            PROBE_TLS.with(|t| t.av_seen.set(true));
            EXCEPTION_CONTINUE_SEARCH
        }
        _ => EXCEPTION_CONTINUE_SEARCH,
    }
}
```

**重试条件（有界）**：同一候选地址，仅当 `guard_seen` 由保护器清除（读取成功）才算解密完成；
否则每候选**最多重试 1 次**。**不可恢复即 abort 规则**：

- 同一 faulting 地址连续 2 次仍为 AV（非 guard）→ 判该候选为 Type A（加密/无效），**跳过**，不再重读。
- **禁止对同一 faulting load 无条件 `EXCEPTION_CONTINUE_EXECUTION`**（原设计的死循环风险，撤回）。
- 若 VEH 装载失败、TLS 不可用、或探针线程收到非预期异常码 → walker 立即写 `walker_status=abort`、
  `completed_flag=0xDEAD0001`，返回错误码，**fail-closed**（§5）。

### 3.5 卸载时机

walker_inner 退出前（无论成功/失败）必须 `RemoveVectoredExceptionHandler`，并清空 TLS。
卸载是 RAII（`VehGuard::drop`），panic 路径由 §3.2 的 `catch_unwind` 兜住后仍会析构本地 guard。

---

## 4. Loader 对位（关闭 #4：删除全部 todo!() 伪闭环）

原设计的 `get_runtime_module_base()` 与 `get_export_rva()` 是 `todo!()` 桩，且**函数不存在于仓库**。
本节改为**复用已在生产的真实解析路径**，不新增任何解析器。

### 4.1 runtime artifact authority + manifest identity（已存在，复用）

- `RuntimeLoader::load_and_initialize`（runtime_loader.rs:1029）在**任何远程写入前**先
  `self.authority.verify_file(runtime_path)`（L1040）做 artifact authority 校验，并要求
  `architecture == "x86_64"`。walker 调用**必须复用同一 loaded runtime**，不重新加载、不旁路 authority。
- manifest identity：LIVE-4 的样本身份预检为硬门（vault rev2），walker 不引入第二身份源。

### 4.2 远程 module base（已存在，复用）

`load_and_initialize` 步骤 2（L1084-1089）经 `loadlib_call` 拿到 `module_base`（64-bit HMODULE，
经 stub 写回 target 内存以避开 `GetExitCodeThread` 32-bit 截断，ADR-5B）。walker **复用同一
`module_base`**，不自行探测。

### 4.3 export RVA + allowlist（复用 resolve_mida_exports_remote）

`resolve_mida_exports_remote(target, module_base)`（runtime_loader.rs:1275）从 target 内存解析 PE
导出目录，返回 `module_base + RVA`。返工把 `WalkerExecute` **加入该函数的 wanted 导出列表**，
其入口地址 = `module_base + WalkerExecute_RVA`，与 `MidaAntidebugInitialize` 走**同一解析器**。

```
控制流（全部复用现有真实函数，无 todo!()）:
load_and_initialize
  → authority.verify_file           (L1040, 真实)
  → loadlib_call → module_base      (L1088, 真实)
  → resolve_mida_exports_remote     (L1275, 真实) ── wanted 列表 += "WalkerExecute"
  → [新增] invoke_walker(target, module_base + walker_rva, params_blob_va)
```

**导出 allowlist**：`CreateRemoteThread` 的入口地址在调用前**断言** `== module_base + walker_rva`
（来自 `resolve_mida_exports_remote` 的解析结果）；任何其它入口一律拒绝。这是 C2 载荷白名单的强制点。

### 4.4 MidaExports 扩展（设计意图，待实现）

`MidaExports` 结构（现含 `initialize`/`shutdown`）新增 `walker_execute: u64` 字段，由
`resolve_exports_from_buffers`（runtime_loader.rs:1525）在同一次解析中填充。**无独立解析路径。**

### 4.5 本节残留 todo!() 清点

**零**。所有解析、authority、module base 步骤均映射到上列真实函数行号；不存在 `get_runtime_module_base`
/ `get_export_rva` 之类伪闭环。若实现阶段发现需要新函数，须先回联审补设计，不得以 `todo!()` 充数。

---

## 5. 失败状态机（关闭 #5：超时/异常/线程仍运行时的 cleanup 缺口，全程 fail-closed）

原设计只展示成功路径 cleanup，超时后直接释放 params 与 mapping 会制造悬挂访问。本节定义
**每个失败态显式 fail-closed** 的状态机。

### 5.1 状态与转移

```
S0 Init
  ├─(section 创建失败)──────────→ Fx_SectionFail        [无远程内存，安全 abort]
  └─ok→ S1 ParamsWritten
        ├─(alloc/write 失败)─────→ Fx_ParamsFail         [释放 section；无远程线程，安全]
        └─ok→ S2 ThreadCreated
              ├─(CreateRemoteThread 失败)→ Fx_AttachFail  [释放 blob+section；线程未起，安全]
              └─ok→ S3 Waiting (bounded, §6)
                    ├─(Finished, status=ok)──→ S4 ResultRead
                    ├─(Finished, status=abort)→ Fx_WalkerAbort [线程已终止→可释放]
                    ├─(TimedOut)─────────────→ Fx_ThreadHung  [线程可能在跑→禁止释放，见 §5.4]
                    └─(WaitFailed)───────────→ Fx_WaitFail    [线程状态未知→按 Hung 处置]
        S4 ResultRead
              ├─(crc/magic/count 校验失败)─→ Fx_ResultCorrupt [线程已终止→可释放]
              └─ok→ S5 Done
```

### 5.2 每个失败态的 cleanup 契约

| 状态 | 远程线程状态 | 允许释放 blob？ | 允许释放/关 section？ | round 记账 |
|-----|------------|--------------|--------------------|-----------|
| Fx_SectionFail | 未创建 | N/A | N/A | 本 round 失败，不重试 |
| Fx_ParamsFail | 未创建 | ✅（仅本次已 alloc 部分） | ✅ | 本 round 失败，不重试 |
| Fx_AttachFail | 未起 | ✅ | ✅ | 本 round 失败，不重试 |
| Fx_WalkerAbort | **已终止**（Finished） | ✅ | ✅ | 本 round 失败，不重试 |
| Fx_ResultCorrupt | **已终止**（Finished） | ✅ | ✅ | 本 round 失败，不重试 |
| **Fx_ThreadHung** | **可能仍运行**（TimedOut） | ❌ **禁止** | ❌ **禁止** | 本 round 失败，abort，见 §5.4 |
| **Fx_WaitFail** | **未知** | ❌ **禁止** | ❌ **禁止** | 同 Hung 处置 |

### 5.3 walker_status 码（写入结果 header 0x1C 与返回码镜像）

```
WALKER_SUCCESS               = 0
WALKER_ERROR_BAD_PARAMS      = 1   // magic/version/crc 校验失败
WALKER_ERROR_MAP_FAILED      = 2   // OpenFileMappingW/MapViewOfFile 失败
WALKER_ERROR_VEH_FAILED      = 3   // AddVectoredExceptionHandler 失败
WALKER_ERROR_PROBE_ABORTED   = 4   // 止损触发（§6.3）
WALKER_ERROR_INTERNAL_PANIC  = 5   // catch_unwind 捕获 Rust panic（§3.2）
```

### 5.4 悬挂内存处置（TimedOut / WaitFailed 的核心 fail-closed）

依据现有 `RemoteWaitOutcome::TimedOut` 契约（runtime_loader.rs:304-308，注释原文："the remote code may
STILL be running in the target. The caller must NOT free any memory the remote thread can touch"）：

1. **禁止** `VirtualFreeEx(blob)`、**禁止** `UnmapViewOfFile`/`CloseHandle(section)`——远程线程可能仍在读候选、写结果。
2. controller 记录 `leaked_blob_va` / `leaked_section_name` 到 round 账本（§6），标注 `orphaned=true`。
3. 悬挂资源的最终回收方 = **target 进程退出**（OS 回收其地址空间与该进程持有的 section 视图）。
   controller 不得强行释放，也不得对同一 target 重入 walker（避免旁路同一 blob）。
4. `TimedOut` → 本 round 直接判失败，触发 abort，**不自动重试**（§6.2）。

### 5.5 与 catch_unwind / VEH 卸载的协同

- target 侧：`walker_inner` 任意早退（含 abort）前经 `VehGuard::drop` 卸载 VEH（§3.5），并把
  `walker_status` + `completed_flag` 写入结果 header，使 controller 能区分"已终止 abort"（可释放）与
  "线程失联"（禁止释放）。
- controller 侧：只有读到 `completed_flag ∈ {1, 0xDEAD****}` **且** wait == `Finished` 才进入可释放路径。

---

## 6. 预算与 round 账本（关闭 #6：120min 单总时限 → cap = 2 rounds × 60min）

### 6.1 预算模型

**废弃** "120 分钟硬上限" 单总时限。改为：

```
cap = 2 rounds × 60 min
- 每 round 独立 60 分钟墙钟上限，独立账本；
- 总上限 = 2 rounds（第 2 round 需第 1 round 出口显式判定后方可进入）；
- 禁止超时后自动重试；禁止把任一 round 无限延长或借用另一 round 的剩余时间。
```

### 6.2 round 账本字段（每 round 一份，独立记录）

| 字段 | 说明 |
|-----|------|
| `round_index` | 1 或 2 |
| `entry_ts` / `exit_ts` | 本 round 入口/出口墙钟时间戳 |
| `wall_budget_ms` | 60 × 60 × 1000（硬上限） |
| `wall_spent_ms` | 实际耗时（≤ budget） |
| `candidates_probed` | 本 round 探针候选数 |
| `abort_state` | `none` / `thread_hung` / `wait_fail` / `walker_abort` / `budget_exhausted` / `stop_loss` |
| `orphaned_resources` | §5.4 悬挂 blob/section 列表（若有） |
| `auto_retry` | **恒为 false**（治理硬规则） |
| `next_round_authorized` | 第 1 round 出口是否显式批准进入第 2 round |

### 6.3 每 round 入口 / 出口 / abort

- **入口门**：进入前确认 target 存活（不在死进程上执行触碰，WO-1302 附加约束）、上一 round（若有）
  `abort_state != thread_hung/wait_fail`（悬挂态不得重入）。
- **出口门**：写满账本；若 `abort_state != none` 则本 round 判失败。
- **abort 触发**（任一即止损，写 `WALKER_ERROR_PROBE_ABORTED`）：连续 10 次非 guard AV、
  target CPU > 80% 持续 5s、target 新建线程（疑似反调试响应）、或 `wall_spent_ms` 达 budget。
- **不可自动重试**：任何 abort 后**不得**自动开新 round；第 2 round 的进入是**人工授权**决策（LIVE-4 范围）。

### 6.4 与旧阈值对照

| 项 | 原设计 | 返工 R1 |
|---|-------|---------|
| 预算结构 | 120min 单总时限 | 2 rounds × 60min，独立账本 |
| 超时后 | 语义含糊 | fail-closed，不自动重试 |
| round 记账 | 无 | 每 round 强制账本（§6.2） |

---

## 7. Provenance / Attestation schema（关闭 #7：定义 v2 + 迁移，禁止 deny_unknown_fields 漂移）

### 7.1 问题

直接往现有 `Provenance` / `HookInventory` / attestation JSON 加 `walker_execution` 字段会触碰当前 v1
`serde(deny_unknown_fields)` 合同——旧消费者见到未知字段即反序列化失败。必须走版本化迁移，不得裸加字段。

### 7.2 迁移策略：显式 v2 + 版本判别

1. attestation 顶层新增 `schema_version: u16`（v1 缺省视为 1）。
2. walker 证据装入**新增的可选容器** `walker_attestation: Option<WalkerAttestation>`，仅在 `schema_version >= 2` 出现。
3. 反序列化按 `schema_version` 分派：v1 走旧结构（保持 `deny_unknown_fields`），v2 走含 walker 容器的新结构。
4. **禁止**在 v1 结构上直接加字段；v2 为独立 `#[serde(deny_unknown_fields)]` 结构，新增字段集封闭。

### 7.3 WalkerAttestation 记录 schema（真实字段，非占位）

```
WalkerAttestation {
  schema_version: u16,               // == 2
  target_pid: u32,                   // target identity binding
  target_image_sha256: String,       // 样本身份（vault rev2 digest 绑定）
  runtime_module_sha256: String,     // 加载的 runtime artifact digest
  walker_export_rva: u64,            // resolve_mida_exports_remote 结果
  walker_entry_va: u64,              // module_base + rva（allowlist 断言值）
  rounds: Vec<RoundLedger>,          // §6.2 每 round 账本
  probe_summary: ProbeSummary,       // 计数：type_a/type_b/type_c/av/guard
  orphaned_resources: Vec<Orphan>,   // §5.4
  canonical_encoding: "json-c14n",   // canonical 编码声明
  record_digest: String,             // 本记录 canonical 编码后的 sha256
}
```

### 7.4 受影响的现有构造器 / 消费者 / 测试（须在实现阶段同步改，本设计仅登记）

| 位置 | 类型 | 需要的改动 |
|-----|------|----------|
| `antidebug-runtime/src/exports.rs` attestation 构造（`initialize_inner` L203+） | 构造器 | 写入 `schema_version`；walker 路径填 `walker_attestation` |
| attestation JSON 反序列化消费者（controller 侧 acceptance） | 消费者 | 按 `schema_version` 分派 v1/v2；acceptance consumer 读取 `walker_attestation` |
| `Provenance` / `HookInventory`（`deny_unknown_fields`） | 结构 | 不动 v1；walker 证据只进 v2 容器 |
| 现有 attestation 单测 | 测试 | 补 v1→v2 兼容用例 + v2 round-trip |

### 7.5 单一账本要求

walker 证据的**唯一**权威记录 = `WalkerAttestation`（含 `canonical_encoding` + `record_digest` +
`target identity binding` + `artifact digest binding`），由 acceptance consumer 单点消费。不得散落多份，
不得与 PEB surfaces attestation 混淆为同一 record。

---

## 8. 候选与探针规格（引用 WO-1301A，无跨进程裸指针）

候选生成沿用 WO-1301A §3 的 coverage_measure 数据驱动方案（guard_violations 历史 / cold_regions /
hotspot 邻域），此处不重复。**唯一实施约束**：候选数组以 **target VA 的 u64 数组**形式写入 §2.2 的
params blob（`candidate[]`），target 内经 `candidate_off`/`candidate_count` 就地遍历，**不经任何 controller 侧指针**。

探针原语（§3 已定案）：VEH 分类 + 单次有界重试 + 熵/x64 prologue 判据（沿用 WO-1301A §4.2）。
节流：单探针 10ms、批 50、批间 500ms、每 round 预算见 §6。ProbeResult 定长内联（§2.4），无内嵌指针。

---

## 9. 验证矩阵（关闭 #8：全文"已验证"→"待验证"，无 live 证据）

**声明**：下表所有条目当前状态一律为 **待验证（NOT YET VERIFIED）**。本文件不含任何 live 证据；
仓库中 walker 相关代码、导出、测试**尚不存在**。

| # | 验证项 | 方法（待执行） | 当前状态 |
|---|-------|--------------|---------|
| V1 | WalkerExecute 作为 antidebug-runtime 单一导出（C1） | 编译后 `resolve_mida_exports_remote` 解析出 walker_rva | 待验证 |
| V2 | 无跨进程裸指针（#1） | 代码审查 + params blob 全字段为 offset/VA-in-target | 待验证 |
| V3 | 无原始 HANDLE 直传（#2） | 代码审查：target 侧仅 `OpenFileMappingW`，无 HANDLE 参数 | 待验证 |
| V4 | catch_unwind 不用于捕获 AV（#3） | 代码审查 + VEH 单测（guard/AV 分类） | 待验证 |
| V5 | 无 todo!() 伪闭环（#4） | `grep todo!` = 0；解析走真实 `resolve_mida_exports_remote` | 待验证 |
| V6 | 失败状态机 fail-closed（#5） | 每失败态单测；TimedOut 下断言未释放 blob/section | 待验证 |
| V7 | 2 rounds × 60min 账本（#6） | round 账本字段完整；断言 `auto_retry == false` | 待验证 |
| V8 | Provenance/Attestation v2 迁移（#7） | v1→v2 兼容测 + v2 round-trip；旧消费者不 panic | 待验证 |
| V9 | 假说：目标内触碰触发保护器解密 | LIVE-4 Phase 1 PoC（≥3/5 guard 命中，熵<6.0） | 待验证（需 LIVE-4 授权） |

### 9.1 前置门（离线，须先过）

- 离线协议门：§2 IPC、§3 异常、§5 状态机、§6 账本、§7 schema 通过联审。
- 编译门：walker 代码实现后 `cargo check` + walker 单测绿；全量 `cargo test` 不回归。
- **以上未过前，不申请 LIVE-4，不实弹。**

### 9.2 拒收条件自检（本文件对照）

| 拒收条件 | 本文件是否触犯 |
|---------|--------------|
| 跨进程裸指针 | 否（§2 全 offset/VA-in-target） |
| 原始 HANDLE 直传 target | 否（§2.3 命名 section + OpenFileMappingW） |
| catch_unwind 捕获 AV | 否（§3.1 撤回，§3.2 仅挡 panic） |
| 120min 单总时限替代 round ledger | 否（§6 已改 2×60min 账本） |
| 伪代码标为实现 | 否（§0 声明 design draft，§9 全"待验证"） |

---

## 10. 状态总表

| 对象 | 状态 |
|-----|------|
| WO-1301A-IMPL（本文件） | **design draft — 待重新联审**；未实现、未实测、未批准 LIVE-4 |
| WalkerExecute 代码 | 不存在（未派工） |
| LIVE-4 | NOT AUTHORIZED |
| 提交策略 | 全程本地提交，禁 push |

### 10.1 文档版本

| 版本 | 日期 | 变更 |
|-----|------|------|
| v0.1 | 2026-08-22 | 原实施设计（REJECTED，P0-1..P0-4 + P1） |
| **R1 (WO-1401-R1)** | 2026-08-22 | 关闭 8 项返工要求；全文改设计草案 + 待验证 |

