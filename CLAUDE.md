# CLAUDE.md — Magicmida-RS

## 项目概述

Themida 自动脱壳器，用 Rust 重写。参考实现：`reference/Magicmida/`（Hendi48/Magicmida, Pascal）。
后续将扩展支持 VMProtect、Enigma 等主流加壳工具。

## 技术栈

- **反汇编**：iced-x86
- **PE 操作**：pelite
- **Windows API**：windows-rs（微软官方绑定）
- **错误处理**：thiserror（库错误）+ anyhow（应用错误）
- **日志**：tracing + tracing-subscriber

## 架构

Cargo workspace，每个 crate 是一个独立模块：

crates/
├── core/           # 调试器核心：进程创建、断点、调试事件循环
├── pe/             # PE 解析、节区操作、导入表重建
├── disasm/         # iced-x86 封装，模式匹配
├── tracer/         # 单步跟踪器
├── packers/        # 各壳实现（trait Packer）
│   └── themida/    # Themida 脱壳
└── cli/            # 命令行入口

## Guardrails

### 必须遵守

1. **所有 Windows API 调用必须处理错误**——用 windows-rs 的 Result 类型，不要用 .unwrap() 跳过
2. **进程内存读写必须检查返回值**——ReadProcessMemory/WriteProcessMemory 的返回值和实际字节数都要验证
3. **指针运算前必须做边界检查**——Rust 的 slice 会帮你，但裸指针操作不会
4. **unsafe 块必须有注释说明为什么 unsafe 是安全的**——或者为什么这里不得不 unsafe
5. **每个 crate 的公开 API 必须有文档注释**（///）
6. **错误用枚举表达，不要用 String**——thiserror::Error derive
7. **跨 crate 通信只通过公开 trait 和结构体**，不要暴露内部实现

### 编码风格

- 优先用 trait + 泛型而非动态分发，除非确实需要运行时多态（如 packer 插件）
- 模块文件不超过 500 行；超过就拆子模块
  - **例外**：包含单一超大编排函数的文件（如 `dumper.rs` 的 `dump_process` 943行、`windows_debugger.rs` 的 `impl WindowsDebugger` 整块、`cli/unpacker/mod.rs` 的 `unpack()` 主流程），强拆会破坏逻辑内聚性，允许超标但必须在文件头注明 `// eslint-allow-over-500-lines: <reason>`
  - **例外**：纯数据表文件（如 `apiset_data.rs` 1540行 const 数组）不受此规则约束
- 测试和代码放一起（#[cfg(test)] mod tests）
- 公开类型实现 Debug；敏感类型（含句柄/指针）手动实现 Debug 脱敏

### 参考源码

Pascal 原版在 `reference/Magicmida/`。遇到不确定的逻辑时，参考对应文件：
- `DebuggerCore.pas` → `crates/core/`
- `ThemidaCommon.pas` + `Themida.pas` + `Themida64.pas` → `crates/packers/themida/`
- `Dumper.pas` → `crates/pe/`（导入表重建部分）
- `Tracer.pas` → `crates/tracer/`
- `PEInfo.pas` → `crates/pe/`
- `Utils.pas` → 各 crate 的 utils
- `Patcher.pas` → `crates/pe/` 或 `crates/packers/themida/`（后处理）
- `AntiDumpFix.pas` → `crates/packers/themida/`

### 不要做

- 不要用 unwrap() / expect() 在生产代码路径中（测试里可以）
- 不要用 unsafe 除非确实需要（Windows FFI、内联汇编、裸内存操作）
- 不要在 core crate 里引用任何 packer 特定逻辑——core 是通用的
- 不要硬编码地址偏移——用常量或配置
- 不要忽略 Windows API 的 GetLastError()——出错时 log 它
- 不要在 crate 里重复实现调试循环 / 句柄所有权——唯一的调试器是 `mida_core::WindowsDebugger`，CLI 和其他 crate 只能通过 `DebuggerCore` trait 与它交互
- 不要在库/生产路径用 `eprintln! / println!` 打诊断日志——用 `tracing::debug! / info! / warn!`；只在 CLI 顶层或测试里用标准输出
- 不要提交未固定校验的外部二进制到仓库——见"外部二进制"

### 工作方式

- 每次只完成一个明确任务，不要自行扩展范围
- 任务完成后停下来，不要主动开始下一个任务
- 遇到不确定的设计决策时停下来问，不要自己猜
- 不要一次性创建所有文件，只创建当前任务需要的文件

## 构建

cargo build --release            # 构建
cargo test --workspace            # 测试整个 workspace（注意：必须 --workspace，否则跨 crate 的测试回归不会被 CI / 人工发现）
cargo run -- --unpack <file>      # 运行

目标平台：Windows x86/x64.交叉编译不需要考虑。

## 必须记住的实测经验（这次审计踩过的）

- 调试器双实现合并完成(2026-07-03):`crates/cli/src/unpacker.rs` 的 `DebugLoopContext` 双实现已删除,改名为 `ProcessSession` —— 一个围绕 `mida_core::WindowsDebugger` 的薄 RAII 壳,Deref + 手动 `impl DebuggerCore` trait 转发给核心。CLI 原始 debug loop / 线程表 / 硬断点 / 句柄所有权现唯一由 core 拥有。改动范围 ≈ 600 行删除 + 新建 90 行 wrapper + 104 处 `dbg.` 调用点适配。
    - 关键的 core 改动:`WindowsDebugger::set_hw_breakpoint` 等现有 pub 方法直接复用,CLI 的 `get/set_thread_context_control`(CONTEXT_CONTROL 快速路径)抽出为 CLI 本地的 `fn get_thread_context_control(&ProcessSession, ...) / fn set_thread_context_control(...)`。core 新增 `pub fn main_thread_id() / hw_breakpoint_addr(slot) / apply_debug_registers_thread(thread_id)`;CreateThread 事件处理也更新为自动把当前 DR 状态同步到新创建的线程。
    - 样本冒烟测试:`D:\Tools\RE\dumps\newproject\时光单开.exe`(Themida V3) 工具至今创建了 debuggee 并跑着 OEP trace,关键路径未回归(硬断点重复设置是之前已有的 `HwbpSlotInUse`,不是新 bug)。
- 外部二进制完整性校验(2026-07-03):`crates/packers/themida/src/binaries.rs` 新增 SHA-256 清单 + `inject_scylla_hide` 在 spawn InjectorCLI 前校验 hash;不匹配则返回 `ThemidaError::ScyllaHide` 中止。清单用项目实际文件哈希:`InjectorCLIx64.exe = 211f7b80...`,`HookLibraryx64.dll = d4b20eed...`。x86 哈希位需手工补。

### SECTION 返回值已经改成 index
- `PeHeader::create_section_index(name, virtual_size) -> usize` —— 新方法的返回是新节在 `pe.sections` 里的下标，**不是** `&PeSection`。由于 borrow 限制，调用者必须先拿 index，再下标访问 `pe.sections[idx]`。任何测试和调用方写 `let sect = pe.create_section(...)` 这种旧签名/旧用法的都是编译错误。
- 删节：`delete_section(0)` 会 panic（没有前驱可合并），这是设计如此,不是 bug。

### make_memory_readable 必须用真正的 MEM_COMMIT
- `mbi.State == VIRTUAL_ALLOCATION_TYPE::default()` 是错的（`VIRTUAL_ALLOCATION_TYPE::default()` 是 `MEM_FREE = 0`，而 `MEM_COMMIT = 0x1000`）。跨页 dump 时 NOACCESS 页根本不会被改成 READONLY，dump 就残了。正确写法：`mbi.State == MEM_COMMIT`,然后把 `MEM_COMMIT` 加到顶层 `use windows::Win32::System::Memory::{...}` 里。
- **windows-rs 0.58 的坑**：`MEM_COMMIT` / `PAGE_NOACCESS` 是 `const VIRTUAL_ALLOCATION_TYPE(pub u32)` 这种**自由 const**，不是 associated const——所以 `VIRTUAL_ALLOCATION_TYPE::MEM_COMMIT` 会报"no associated function or constant named MEM_COMMIT"。直接用导入的自由 const。

### 句柄 / 资源 RAII
- 核心资源（进程、主线程、stub EXE）都挂在 `WindowsDebugger` / `TargetProcess` 上统一 Drop。`?` 半路的错误传播会绕过尾部手工 cleanup，所以必须用 RAII guard——**不要**在函数尾部集中写 "cleanup" 段来兜底。
- 不要给 CLI 开 struct 把句柄/线程表/hw_breakpoints 等字段都 pub 出来绕过 RAII —— `ProcessSession` 唯一 pub 态是 `apis`,所有 debug 操作必须经过 `DebuggerCore` trait(现转发到 core 实现)。
- 跨 crate 通信只通过 `DebuggerCore` trait 暴露的 `process_handle / read_memory / write_memory / wait_event / continue_event`，**不要**给 CLI 直接开一个 struct 把 fields 都 pub 出来绕开 RAII。

### Themida 样本对齐(Pascal 原版对照,2026-07-03)
- Sample `D:\Tools\RE\dumps\newproject\时光单开.exe`(Themida V3,PE32+ x86-64,16 sections,5 MB) 是黄金用例,持续跟踪 Rust 实现与 Pascal 原版的脱壳路径差异。
- 已经对齐的 Pascal 语义项(crates/core/windows_debugger.rs + crates/packers/themida/src/guard.rs + antiantidebug.rs):
  - `apply_debug_registers_thread` 不再调 `SuspendThread/ResumeThread`(对齐 Pascal `UpdateDR`,后者直接在已挂起的 debuggee 线程上 Get/Set Context)。CreateThread 事件里对每新线程 DR 同步,任一线程失败 tolerate 不阻塞关键路径。
  - `DebugEvent::AccessViolation` 加 `exc_type: u8`(ExceptionInformation[0],8=execute 用于回调检测,1=write,0=read)。
  - ScyllaHide 注入对齐 Pascal 风格(ScyllaHideConfig 构造 → 校验 binary 存在 → spawn injector → sleep → log → mem::forget)。
- **2026-07-03 逻辑审计修复(4 项关键 gap)**:
  1. **`process_guarded_access` 分支顺序对齐 Pascal**:原 Rust 顺序是 FTMGuard → TLS → OutsideImage → ThemidaWrite;Pascal 是 FTMGuard → OutsideImage → ThemidaWrite → TLS。已修正为 Pascal 顺序,避免 TLS 回调计数器被非 TLS 的 execute fault 误增。`guard.rs` 分支 2/3 移至 TLS 分支之前。
  2. **`guard_stepping` 守护重武装**:Pascal `OnSinglestep` 在 `FGuardStepping=true` 时调用 `VirtualProtectEx` 恢复 `PAGE_NOACCESS`。原 Rust SingleStep 处理器完全没有重武装逻辑——库读 `.text` 或 Themida 写 `.text` 后守护丢失,后续写入静默通过。已添加 `ThemidaState.guard_stepping` 字段 + `unpacker.rs` SingleStep 处理器中的检查。
  3. **PE header anti-dump 早期修复**:Pascal `TMInit` 在进程初始化时修补 section 2 的首字节(`'i'` → `'p'`,修复 `.pdata` 被改成 `.idata` 的 anti-dump)。原 Rust 只在 Phase C 后处理阶段修复,调试循环期间 PE header 损坏可能导致 x64 SEH 异常派发失败(`STATUS_FATAL_APP_EXIT`)。已在 CreateProcess 处理器中添加早期修复。
  - `trace_start_sp` 每 slot 刷新:Pascal `ThemidaCommon.pas` 在每个 IAT slot 跟踪前读取当前 RSP 更新 `FTraceStartSP`。原 Rust 使用缓存值(只设置一次),导致 anti-trace API 跳过逻辑随 slot 漂移。已在 `trace_imports.rs` 的 `trace_one_slot` 中添加 per-slot 上下文读取。
- **已知待解问题(非 Rust 实现 bug)**:该 sample 用 ScyllaHide 注入后 `WaitForDebugEvent` 返回 `ERROR_PARTIAL_COPY` 破坏 session;去掉 ScyllaHide 后进程直接 exit `STATUS_FATAL_APP_EXIT`(0x8000004,快速失败自杀)。`NtSetContextThread/NtGetContextThread` Hook 开关与此无关;真正的差异在 Pascal 原版 "走得更远" **但没有拿到 Pascal 版本的执行日志**,所以最终定位到 ScyllaHide 版本兼容性或更早的 DLL 注入时序。
- **下次机会**:脱壳成功的 Pascal Magicmida.exe 二进制路径或关键阶段的 Debug 日志 —— 拿到的那一天就是定位差异的破局点。

### Pascal 逻辑审计发现的其他 gap(尚未修复,非关键路径)
- **V2 IAT Fix 链**:Pascal 有完整的运行时断点驱动 IAT 修复链(`TMIATFix` → `TMIATFix5` + `InstallEFLPatch` + `GetIATBPAddressNew`)。Rust `fix_iat_v2` 是简化版静态 stub 解析器,不会做 Themida 段内的模式扫描或写入 trampoline。影响 Themida V2 二进制。
- **`trace_is_at_api` in-image-continue**:Rust 在 IP 落在 image 内但不在 Themida 段内时返回 `Continue`(继续跟踪);Pascal 直接设置 `FTracedAPI` 并停止。可能导致 Rust 跟踪器错过有效 API 解析或跟踪过深。
- **`is_within_image` 启发式过于宽松**:Rust 版对 `0x10000` ~ `0x7FFF_FFFF_0000` 范围内都返回 true;Pascal 的 `IsAPIAddress` 更精确。
- **MSVC6 OEP 恢复不完整**:Pascal 从栈读取异常结构体和 handler 指针;Rust 版用零填充。
- **`IsTMExceptionHandler` 检查缺失**:Pascal 在 OEP 检测时检查 `$00B8838B`(mov eax,[ebx+CONTEXT._Eip])区分异常处理器;Rust 无此检查。
- **VirtualProtect HW BP 缺失**:Pascal 在 `VirtualProtect` 上设硬件断点,当 Themida 恢复页面保护时重新安装守护;Rust 无此机制。
- **压缩二进体检测缺失**:Pascal 通过 `VirtualSize != SizeOfRawData` 判断压缩状态,影响 AllocMem 计数阈值;Rust 使用固定阈值。
- **`.NET` dump 支持**:Pascal 有完整 `TDumperDotnet`;Rust 有 `_CorExeMain` HW BP 路径但 dump 逻辑待验证。
- **ScanData 代码段回退**:Pascal 的 `ScanData` 在数据段扫描失败后回退到代码段(Themida V1 极端合并);Rust 只扫描数据段。

### 外部二进制
- 仓库根直接带 `HookLibraryx64.dll`、`InjectorCLIx64.exe`、`scylla_hide.ini`。`crates/packers/themida/src/antiantidebug.rs` 会调用这些 stub 完成 DLL 注入 / 反反调试。
- **2026-07-03 起已加 SHA-256 完整性校验**:`crates/packers/themida/src/binaries.rs` 硬编码了已知文件的 SHA-256 清单,`inject_scylla_hide` 在 `Command::spawn` 前读取二进制文件并比对。不匹配则返回 `ThemidaError::ScyllaHide` 中止,不允许静默降级。当前已知清单只覆盖 x64 文件(`InjectorCLIx64.exe = 211f7b80...`,`HookLibraryx64.dll = d4b20eed...`),x86 占位需要人工补充真实 hash。

### 测试
- 回归测试现在在 workspace 级别通过：40 pe + 98 themida + 30 core/disasm + ... 共 ~180 个用例。任何破坏 `cargo test --workspace` 的改动都不准合。
- 样本冒烟测试可用真实 Themida V3 加壳二进制: `D:\Tools\RE\dumps\newproject\时光单开.exe` (PE32+ x86-64, 16 sections, ~5 MB)。建议 POEP / 断点相关改动后用这个样本完整跑一遍 `/unpack`,看是否 OEP 命中并执行脱壳。
- 测试里仍然允许 `unwrap() / expect()`——但仅限 `tests` 模块内、且 message 要写清楚期望；生产路径已经有这个约束，不重复声明。
- **命名 / 重命名测试友好提示**：如果改公开函数签名，要同时扫 `#[cfg(test)] mod tests` 里旧签名。这次 PeHeader::create_section → create_section_index 就是只在非测试的生产调用方改了，同文件 `tests/section.rs` 还剩三处旧名，埋在 `#[cfg(test)]` 分支里躲开了 `cargo check`,只被 `cargo test` 暴露。
