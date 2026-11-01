# 缺陷复盘编年

> 2026-10-25 从内部工作区笔记拆出（原文逐字节搬移，未改写）。按原文件顺序，
> 每条都是"实测 → 根因 → 修法 → 判别力"的记录。
> 运行步骤在 [`RUNBOOK.md`](RUNBOOK.md)，已验证能力与黄金值在
> [`README.md`](../README.md)。
>
> 读法：先看标题找现象，再看表里的实测数字。**别把这里当"待办"** —— 全部已修。

## 目录

- not-an-import：三个槽不是失败，是数据
- 踩过的坑（别重犯）
- .pdata：零填充是数据丢失（2026-10-23 修掉）
- loader host 不再污染样本目录
- 别再弹 CMD 黑窗（2026-10-23 修掉）
- GUI 窗口不再撑出屏幕
- ERROR_SEM_TIMEOUT 映射终于对了
- 假警报 Real OEP not found 降级为 DEBUG
- x86 测试套件首次真正跑起来（2026-10-23）
- 真缺陷：classify_iat_slot 的地址参数是 usize
- 真缺陷：find_security_cookie 只认 x64 指令形态
- 环境限制（已于 2026-10-24 全部解除）
- 架构相关的测试必须门控
- x86 CLI 实跑验证
- x86 样本（自己造的，已就绪）
- x86 线的第一个真缺陷：异常事件被当成致命错误
- x86 OEP 链在压缩配置下完全正常（2026-10-24）
- 决定性测量：壳根本不写 .text
- 真缺陷：风暴看门狗被无条件 reset 静默禁用
- 真缺陷：DBG_CONTINUE 对首次机会异常会死循环
- 真缺陷：major_linker_version == 2 被当作"没有 CRT 模式"
- gate 稳定性：两处竞态
- 已解决：ScyllaHide 注入把调试循环锁死（2026-10-24 修掉）
- 已解决：PE32 上 TLS 回调检测完全失效（2026-10-24 修掉）
- 已解决：EXE gate 的启动判定改为对照法（2026-10-24）
- 已解决：DLL 的 golden 哈希重录过两次（2026-10-24）
- 已解决：DLL 线的 IAT 定位退化（resolved 289 → 14，2026-10-24 修掉）
- 五个独立缺陷，全部实测定位
- 槽数断言改成"下限"，不是精确值
- 别再重复这些测量
- x86 OEP guard 不再依赖 DEP（2026-10-24 修掉）

## `not-an-import`：三个槽不是失败，是数据

DLL 的槽 901/965/1057（EXE 是 8 个）曾长期被记成 `failed`。实测它们存的是
**裸 RVA**（`0x141000`/`0x141064`/`0x1410DC`，指向只读 `.rdata` 段），
而真实 Windows loader 里**一模一样**——壳把数据停在表里，不是导入。

判定依据（都已实测）：thunk 必须可调用 → 目标须在**可执行**段，指向只读数据就不是
thunk；这 3 个槽**零代码引用**（无任何 RIP 相对操作数指向它们，其地址作为绝对
qword 在全镜像里出现 **0 次**）。EXE 那 8 个槽同理（裸 RVA `0x113000..0x1130A0`），
改判后**产物字节不变**。

分类器新增 `IatSlotDecision::NotAnImport`；`classify_iat_slot_in()` 接收
`(rva, size, is_executable)` 三元组，指向非可执行段的裸 RVA 归此类。
**不传 section 信息时行为完全不变**（`no_section_info_keeps_old_behaviour` 守着）。

日志现在是：
```
IAT trace complete: 289 resolved, 0 failed, 3 not-an-import
```
两个 manifest 都有 `expect_not_import`，gate 单独断言它 ——
这样真失败不会藏在"数据"里。


## 踩过的坑（别重犯）

- **整文件 sha256 曾经不是稳定判据（两次踩坑，同一个根因族）。**
  第一次：TLS 的 `EndRawData` 被 Themida 延迟更新，同一输入 10 次出两种结果
  （`StartRawData+0x8` / `+0x8008`），由 `normalize_tls_directory()` 修掉。
  第二次：dump 把**调试进程里的活体地址**（`0x7FFx…` / `0x000001xx…`）拷进了
  文件，由 `clear_stale_live_pointers()` 修掉（见下）。
  **再出现哈希漂移，先怀疑活内存里有别的延迟更新字段或活体指针，
  不要直接改期望值。**
- **活体指针归一化**（`clear_stale_live_pointers()`，在 `dump_process.rs`）：
  对每个可写、非可执行段里的指针宽度 qword，若它的值是本进程的活体地址
  （模块 `0x7FFx_xxxx_xxxx` 或堆 `0x0000_01xx…` 区间）且**不在镜像内**，
  就清零。EXE 案例清了 21 个，DLL 清了 28 个。
  - **不能靠重定位表过滤**：packed 输入的重定位表几乎是空的（实测
    `size = 0x10`），产品真正的表是之后由 `build_relocation_table()` 才建的。
  - **不能靠字节级引用扫描过滤**：早期版本用"RIP 相对 disp32 命中槽 RVA"
    判断"代码在读"，误报了 `.bss` 的 `0x13C000`/`0x13C290`（无关指令的
    disp32 恰好相同）。误报只会**保留**脏指针，正好把要消除的不确定性放回来。
    所以删掉了这个启发式，改由两个端到端 gate 做经验保证。
  - **注意 `dump_buf` 是内存镜像**：文件偏移 == RVA，**不能**走
    `rva_to_offset()`（那是给文件镜像用的，会加 `PointerToRawData`）。
    这里曾经出过一次 bug，导致重定位表解析出 0 条。
- 模块快照顺序曾经不稳定（`TH32CS_SNAPMODULE` 是加载器顺序，异步依赖会变），
  已按 base 排序。
- 崩溃取证法: cdb 打开 `%LOCALAPPDATA%\CrashDumps\*.dmp`，`.ecxr; dps @rsp`，
  IAT 间接 call 落在镜像外 = 导入槽没解析（本项目产出文件用 RVA≠文件偏移，核对时注意）。

## `.pdata`：零填充是数据丢失（2026-10-23 修掉）

两个产物长期带着**全零的异常表**：DLL 50376 字节、EXE 48132 字节，非零字节 **0**。
那不是"无害警告" —— 是一个 50 KB 的 `.pdata`，异常分发器会拿它当
`RUNTIME_FUNCTION` 数组去解释。

**根因**：`shrink_sections()` 先把头部压紧（`SizeOfImage` → 0x198000）之后才读
活体镜像，而异常表在 `.winlice` 里（RVA `0x886a28`，EXE 是 `0x8175a0`）已被排除在
缓冲之外，`create_pdata_section` 于是走 `else` 零填充。注意 `Exception dir to
preserve` 那行日志**在零填充之前**就打印了，看起来像成功。

**实测活体里是真数据**（探针 `OUT/exc_shape.c`）：`core.dll` 4198 条（4193 指向
存活 `.text`、5 指向已删 `.winlice`），EXE 4011 条（4008 / 3），两者都已排序。

**修法**：在 shrink **之前**从活体内存读表，再按产物自身的段表过滤掉指向已删段的
条目（`build_pdata_payload`）。存活条目**无需 rebase** —— shrink 只删
`.winlice`/`.boot`/`.reloc`，它们都在保留下来的段之后，`.text`/`.rdata` 的 VA 不变。
过滤后为空就不建 `.pdata`，并把 Exception 目录留空：全零表比没有表更糟。

**副作用**：EXE 产物尺寸 1539584 → 1539072（sha256 已变，后被两次重录覆盖，
现值见文件头）。已 3/3 复现验证，产物仍能启动到 `授权验证` 窗口。
DLL gate 新增断言：条目数是 12 的整数倍、非零字节过半、每条落在产物段内、已排序。

## loader host 不再污染样本目录

`ensure_loader_host` 曾把 host 写在样本旁边（`core.dllMMHost.exe` + `.host.c` +
`.host.log`），每次 DLL 运行都往用户样本目录丢三个文件。

**为什么删不掉**：被调试进程终止后仍保持"正在退出"，直到调试器消费并确认
`EXIT_PROCESS_DEBUG_EVENT`，它的映像段因此一直被映射。实测 `TerminateProcess`
返回成功、`DebugActiveProcessStop` 被拒（`0x80070005`）、重试 5 秒仍
`ERROR_ACCESS_DENIED`，但 CLI 一退出就能删 —— 正是挂起退出事件的特征。

**修法**（两条，缺一不可）：
1. host 改写到 `%TEMP%\magicmida-hosts\<stem>_<hash>MMHost.exe`，样本目录保持干净；
   日志也改到 temp（`host-<pid>.log`）。
2. `cleanup_stub_exe` 把"删不掉"降级为 `debug!` 而不是 `WARN` —— host 是**缓存**，
   留着下次复用能省 gcc 编译；`sweep_stale_loader_hosts()` 在构建前清掉超过
   24 小时的陈旧项。

**踩的坑**：host 移到 temp 后 `CreateProcess` 把子进程 CWD 设成 host 目录，
相对的 DLL 路径就解析错了，`LoadLibraryW` 返回 `ok=0`，运行以
`OEP not found` 失败。所以传给 host 的 DLL 参数必须是**绝对路径**
（`canonicalize`）。

## 别再弹 CMD 黑窗（2026-10-23 修掉）

**四个来源**全部要治：被调试进程 `core/process.rs` 的 `CreateProcessW`
（`CREATE_NEW_CONSOLE` → `CREATE_NO_WINDOW`，后者从初始 commit `db1ad7e` 起就在）；
编译 loader host 的 `gcc`；ScyllaHide `InjectorCLI`（均 `.creation_flags`）；
GUI 自己（`windows_subsystem = "windows"`，只在 release）。

`mida-gui.exe` 现在 `Subsystem = 2`；`mida-cli.exe` 保持 `3`（它要打印）。
只在 release 加 `windows_subsystem`。验证：枚举全部可见窗口数
`ConsoleWindowClass`，GUI 全程 **0** 个。两条 gate 已验不影响任何东西。

## GUI 窗口不再撑出屏幕

屏幕 1600×900（工作区仅 852 高）。`main.rs` 初始 `1060×660`、最小 `820×520`；
`ui.rs` 的 `fit_to_screen()` 在**第一帧**读 `monitor_size`，超了就压回
`screen - (48, 96)`，只跑一次。实测自然尺寸 `1076×699`，客户区在屏内。

**截图坑**：`GetWindowRect` 含 DWM 阴影，判溢出要用 `DWMWA_EXTENDED_FRAME_BOUNDS`；
反复 `SetForegroundWindow` 会把 winit 窗口搞成 6×6 僵尸句柄。

## `ERROR_SEM_TIMEOUT` 映射终于对了

`windows_debugger.rs` 曾拿**整个 HRESULT** 比 121：

```
HRESULT_FROM_WIN32(121) = 0x80070079 = 2147942521
2147942521 == 121  ->  False
```

所以 `CoreError::Timeout` **永远不可达**，每个空闲 tick 都变成硬错误；
`av_handler.rs` 的 `sem_timeout()`、`mod.rs` 的内联判断、`drain_exit_events`
都在各自绕它。现在统一成 `windows_debugger::is_sem_timeout(hresult)`
（`& 0xFFFF == 121`），`CoreError::Windows` 也改成存**低 16 位** Win32 码。
两处 workaround 保留但注释已改为 "belt-and-braces"。

4 个单测守着（`real_hresult_is_recognised` 里还有 `assert_ne!(hresult, 121)`
把原 bug 钉住）。

## 假警报 `Real OEP not found` 降级为 DEBUG

`oep/mod.rs` 的 `find_real_oep_by_scanning` 是**一次尝试**，允许失败——调用方会走
"OEP is virtualized — scanning .text" 重试并成功。它却用 `warn!` 报
`Real OEP not found near 0x… — target likely won't run`，每次成功的 EXE 运行都打
**4 条**黄字，而这句话本身是**假的**。现在改成 `debug!`——warn 该在"所有策略都
失败"的地方报，那是调用方的决定。实测计数 **0**，OEP 仍解析到 `0x7ff6622e1010`。

## x86 测试套件首次真正跑起来（2026-10-23）

把 **x86 测试套件本身**跑通时暴露的缺陷比编译期更隐蔽（当时 192 / 210 passed）。

### 真缺陷：`classify_iat_slot` 的地址参数是 `usize`

地址是 `u64` 概念，不是指针宽度概念。参数用 `usize` 导致 **22 处编译期硬错**
（`literal out of range for usize`），更糟的是溢出后**静默变 `0usize`**，会把每个
地址都判成"不在 API 范围"。**修法**：`classify_iat_slot` / `_in` /
`_with_sections` 的 5 个地址参数全部 `usize` → `u64`，
`IatSlotDecision::{Resolved,Trace,TraceRva}` 载荷同步；唯一生产调用点
（`trace_imports/mod.rs:258`）`as u64` 宽化、回写 `as usize` 收窄。
**架构无关了**：同一套 x64 夹具两种宿主都能编译。

### 真缺陷：`find_security_cookie` 只认 x64 指令形态

上一轮我写的 cookie 检测器**只匹配 x64**：

```
48 B8 EF BE AD DE EF BE AD DE    movabs rax, 0xDEADBEEFDEADBEEF
48 89 05 <disp32>                mov    [rip+disp32], rax
```

x86 CRT 没有 `movabs`（无 64 位寄存器），它发的是两个 `push imm32` +
`pop`/`pop` + 两条绝对 `mov dword [abs32], reg`：

```
68 DE AD BE EF                   push 0xEFBEADDE
68 DE AD BE EF                   push 0xEFBEADDE
5F                               pop  edi
5E                               pop  esi
89 3D <abs32>                    mov  dword [abs32], edi
89 35 <abs32+4>                  mov  dword [abs32+4], esi
```

**不逐一枚举 MSVC 可能选的寄存器**，而是匹配不变量：**同一个 32 位立即数写两次**，
再读随后的绝对 `89 3?` 存储。返回 `SecurityCookie { rva, via }`，`via` 记命中哪条
签名。**宽度也对**：x86 cookie 4 字节，重置只清 4 字节不碰相邻 dword。7 个单测，
其中 `cookie_scanners_are_architecture_specific` 断言两条签名不会互相误认。

### 环境限制（**已于 2026-10-24 全部解除**）

两条曾长期存在、现已修掉：`should_panic` 测试让整个进程 `0xc000001d`（手搓 stub 的
`_Unwind_Resume` 是 `__builtin_trap`）；`mida-disasm` 3 个 doctest 链接失败
（`unwind-dw2-fde.o` 需要 `pthread_mutex_*`）。都随真 `libgcc_eh.a` 消失，
**x86 套件现无任何跳过**（2 个 ignored 是本来就 `#[ignore]` 的端到端 gate）。

### 架构相关的测试必须门控

`classify_iat_slot` 的"合理 API 范围"来自**宿主**架构
（`cfg!(target_arch)`），这是对的：CLI 为它要脱壳的架构编译。
所以 **x64 夹具在 i686 宿主上本来就该判成 Trash**。这类测试加
`#[cfg(target_pointer_width = "64")]`：

涉及 `decision.rs`（5 个，如 `outside_image_is_real_api`）、
`regression_guoxing_shiguang.rs`（2 个）、`antiantidebug/tests.rs` 的
`ptr_from_bytes_x64`（`ptr_from_bytes` 返回 `usize`，i686 上 8 字节读被截断）。

**`cfg!` 是运行时宏，两个分支都会被类型检查** —— 想在测试里按架构选
不同字面量，必须用 `#[cfg]` 属性，不能用 `if cfg!(...)`。踩过一次：
`get_themida_section_bounds` 的测试用 `if cfg!(target_pointer_width = "64")`
包着 `0x140000000`，照样编译失败。

### x86 CLI 实跑验证

32 位 PE 解析、EP 读取、版本分诊路径都是活的（`/unpack adb.exe` 报
`Themida detection failed: Not a Themida protected binary`，exit=1）。

### x86 样本（自己造的，已就绪）

全机扫过 `D:\Projects`、`D:\Tools`、Downloads、Desktop：2489 个 x86 PE 中
103 个带 Themida 标记，**全部是 x64**。所以样本自己造，见 `docs/RUNBOOK.md` 的「自己造 x86 样本」。

现有样本在 `OUT\x86\`：

| 文件 | 大小 | 配置 |
|---|---|---|
| `x86_sample.exe` | 51,704 | 原始未加壳（EP rva `0x1450`） |
| `x86_sample_protected.exe` | 7,016,456 | **未压缩**（`COMPRESS_APPLICATION=false`）→ OEP 链第一步永不触发 |
| `x86_c.exe` | 6,598,664 | **已压缩**（`COMPRESS_APPLICATION=true`）→ OEP 链完整跑通 |

**跑 x86 端到端必须用 `x86_c.exe`。**

## x86 线的第一个真缺陷：异常事件被当成致命错误

x86 样本第一次跑就死在：

```
[FATAL] wait_event returned error: Windows API error: code 3221225622
```

`3221225622` = `0xC0000096` = **`STATUS_PRIVILEGED_INSTRUCTION`**。
Themida 用它作反调试探针。

**根因**（`windows_debugger.rs` 的 `decode_event`）：`EXCEPTION_DEBUG_EVENT`
只认 `BREAKPOINT` / `SINGLE_STEP` / `ACCESS_VIOLATION` 三种，其余一律

```rust
other => return Err(CoreError::Windows(other.0 as u32)),
```

这错了两层：在 `DEBUG_ONLY_THIS_PROCESS` 下调试器**先于**程序的 SEH 看到**每一个**
异常（包括程序自己会处理的），返回错误会杀掉本来能成功的运行；而 Themida 正是
拿这个当反调试，x64 参考样本从不触发这条路径，所以长期没被发现。

**修法**：新增 `DebugEvent::UnhandledException { thread_id, address, code }`，
不再返回错误，交给调用方决定。

## x86 OEP 链在压缩配置下完全正常（2026-10-24）

上一轮 x86 卡在"壳进入长驻等待"。根因查清了，**不是代码缺陷，是样本配置**。

### 决定性测量：壳根本不写 `.text`

用 `ReadProcessMemory` 把活体 `.text` 和磁盘 `.text` 逐字节比对：

未压缩 x86 的 `.text` 是 `0x1bf0` / `0x1c00`（raw **>** vsize），活体与磁盘
**0 / 7168 字节不同**；压缩后是 `0x1bf0` / `0x1000`（raw **<** vsize），壳必须解压。

`OPTION_COMPRESSION_COMPRESS_APPLICATION=false` 时，Themida 把原始 `.text` **原样保留**，
没有解压动作 → x64 那条 OEP 链的第一步（`.text` **写**断点）**永远不触发**。

**修法**：把 `.tmd` 里 `COMPRESS_APPLICATION` 改成 `true` 重新加壳。

改完后 x86 OEP 链**完整跑通**：

```
CloseHandle/NtClose hit      → switching to .text write BP
Write to .text base          → switching to VirtualAlloc execute BP
VirtualAlloc hit             → installing code section guard
Possible OEP at 0x401810     → guard faulted correctly (exc_type=8)
```

所以**"x86 OEP 检测不工作"这个判断是错的**——它在正确的样本配置下完全正常。

### 真缺陷：风暴看门狗被无条件 reset 静默禁用

压缩样本之后暴露的：壳在 `.themida+0x538866` 读地址 `0x5`，**15.6 万次**，
日志涨到 1.6 GB 也不停。

根因在 `av_handler.rs`：guard 故障时无条件 `ls.av_storm.reset()`。但
`0x538866 → 0x5` 这个故障**根本不在 guard 页内**——它是壳自己在解引用空指针。
每次 reset 都把计数器清零，看门狗永远看不到重复。

**修法**：只有故障 **target 落在 guard 的 `.text` 范围内**才 reset
（`is_guarded_text_fault`）。现在 4 秒内以明确诊断失败：

```
Target is stuck: 1024 consecutive identical access violations
at 0x538866 (target 0x5)
```

**宁可给出可诊断的错误，也不要无限循环。** 8 个单测守着这条语义。

### 真缺陷：`DBG_CONTINUE` 对首次机会异常会死循环

`decode_event` 原先把未建模的异常一律 `return Err(CoreError::Windows(code))`，
这让 `STATUS_PRIVILEGED_INSTRUCTION`（`0xC0000096`，Themida 反调试探针）直接杀掉运行。

改成 `DebugEvent::UnhandledException` 后，**continue 状态必须是
`DBG_EXCEPTION_NOT_HANDLED`（`0x8001_0001`），不能是 `DBG_CONTINUE`** ——
后者等于"调试器已处理"，在故障指令处恢复会再抛同一异常，死循环；
前者交给程序自己的 SEH。三处调用点都要用对：主循环、DLL free-run、
`trace_imports/slot.rs`。

### 真缺陷：`major_linker_version == 2` 被当作"没有 CRT 模式"

`av_handler.rs` 重试兜底路径里写死 `if version == 2 { None }`。但 MinGW/GCC 产出的
PE 报 **`MajorLinkerVersion = 2`**（实测 i686-w64-mingw32-gcc 16.2.0 → 2.47），
它的 CRT 有同样的 `call rel32; jmp rel32` 形状。这行让**每个 MinGW 目标**都跳过 OEP 模式匹配。

**修法**：删掉特例，交给 `try_find_correct_oep` 按 `KNOWN_MSVC_VERSIONS`（已含 2）
判断（该常量已提升为 `pub` 并 re-export）。重试上限也从 1000 降到 64
（`VIRTUALIZED_OEP_RETRY_LIMIT`）——每个 retry 是一次完整 guard 周期，
1000 次在卡住时要等几分钟，看起来像挂起。

### gate 稳定性：两处竞态

EXE gate 之前约 1/5 概率红。两个原因，都不是产物坏了：**固定 5 s sleep +
单次检查**（壳启动时间随负载变化，慢的时候还没起来就被判死）→ 改成轮询
250 ms 一次、20 s 预算，进程一死立刻失败；**上一次 gate 的产物残留**（单实例
对话框会让新实例 exit 1）→ 启动前 `taskkill` 同名进程且失败重试一次。
改完 6/6 稳定通过，判别力没削弱：真正坏掉的 dump 两次都会失败。

### 已解决：ScyllaHide 注入把调试循环锁死（2026-10-24 修掉）

x86 端到端在日志打出 `ScyllaHide injected` 之后**就没了**。实测现场：
目标主线程 `state=Wait / wait=Suspended`，CLI 阻塞在 `WaitForDebugEvent`，
而 `InjectorCLIx86.exe` 11 分钟后仍在运行。

**根因**：`inject_scylla_hide` 会**等注入器退出**。`InjectorCLIx86.exe`
的注入方式是挂起并劫持目标主线程，只有那条线程真正跑起被劫持的
`LoadLibraryW` 它才返回。而调试目标一旦有**未应答的调试事件**，
内核就会冻结它的全部线程，直到调试器调用 `ContinueDebugEvent`。
于是在 `CREATE_PROCESS` 处理器里等注入器 = 死锁：注入器等一条只有
（被阻塞的）调试循环才能放开的线程。

**决定性测量**（探针 `OUT\inj_probe*.c`，同一目标二进制）：

| 场景 | 注入器耗时 |
|---|---|
| 目标在跑，spawn 注入器 | **47 ms**，exit 0 |
| 目标 `CREATE_SUSPENDED`，spawn 注入器 | **>15 s 不退出** |
| 先把挂起计数排空到 0 再 spawn | **仍然 >15 s 不退出** |
| 先 resume 目标，再 spawn（settle 0/200/600 ms 都试） | **47 ms** |
| x64 注入器 vs 挂起目标 | 41 ms（x64 无此问题） |

**修法**：`inject_scylla_hide` 只 spawn、**立即返回**，绝不等待。
调用点保持"在 CREATE_PROCESS 里 spawn"，随后 `continue_event` 放开目标，
注入器自己跑完。`dll_probe.rs` 同样处理。

`reap_hung_injector()`（新增，导出为 `mida_packers_themida::reap_hung_injector`）
用于会话结束后清掉没退出的注入器（`tasklist` + `taskkill`，全部
`CREATE_NO_WINDOW`）。

**别再往这个函数里加等待。** 注入器只有"快"和"永不返回"两种结局，
没有"慢但会完成"。

修完后 x86 调试循环恢复运转，OEP 链一路跑到
`Possible OEP at 0x401810`。

### 已解决：PE32 上 TLS 回调检测完全失效（2026-10-24 修掉）

追 `0x9ae2b6` 追出了 x86 OEP 路径死亡的真正原因——**三层缺陷叠加**。

**先纠正一个错误结论**：上一轮记的"`0x9ae2b6` 落在任何段之外"是**错的**，
那是拿 RVA 区间比的、忘了加 image base。加上 `image_base=0x400000` 后，
`0x9ae2b6` 就在 `.themida`（`0x417000–0xa57000`）内，
**`ret_in_themida` 判据从头到尾都是对的**。

**`0x401810` 是 TLS 回调，不是 EP**。证据两条：
- 它是 `.rdata` 里 `0x404570` 回调数组的**第一项**（TLS 的 `AddressOfCallbacks` 指向）
- 函数体是 `DllMain` 形态：`sub esp,0x10` → `[esp+0x18]` 取 `fdwReason` →
  `cmp eax,2` 遍历 `0x404580` 的 atexit 表 → `cmp eax,1` → `ret 0xc`

**三层缺陷**（全部实测）：

| # | 缺陷 | 实测 |
|---|---|---|
| ① | `tls_dir.size < 40` 硬编码 | 40 是 `IMAGE_TLS_DIRECTORY64` 的尺寸，PE32 是 **24**。x86 样本报 `0x18` → **每个 PE32 目标都返回 0**。x64 只是侥幸（`0x28 >= 40`） |
| ② | `AddressOfCallBacks` 读 `+0x18` | PE32 该字段在 **`+0x0C`**。实测目录 `00 60 41 00 \| 04 60 41 00 \| 08 60 41 00 \| 10 60 41 00 \| 00…`：`0x416010` 在 `0x0C`，`0x18` 是零 |
| ③ | 用 `(tls_dir_rva - callbacks_va)/ptr_size` 数回调 | **跨单位**：`callbacks_va` 是绝对 VA，`tls_dir.virtual_address` 是 RVA。减法无意义，guard 一触发就返回 0 |

**更深的问题：加壳样本的回调数组在磁盘上根本读不到。** 两个样本实测都是全零
（壳加密，运行时才写）：

| 样本 | 磁盘上的回调数组 |
|---|---|
| `x86_c.exe` | `.tls` raw @ `0x4410`，16 字节，**全 0x00** |
| `时光一键宏.exe` | 回调数组 64 字节，**全 0x00** |

而**未加壳**的原始样本里有真值（`0x401810`、`0x4017d0`）。
所以从磁盘数回调**永远**数不出来，而这里又拿不到活体（调试会话还没建立）。
回退到 Themida 自己的有界假设（4 个回调）。

**回退只对 x86 生效 —— 这是实测决定，不是图方便**：

- x86 `handle_tls_callbacks` 在跳过前校验回调**参数签名**
  `(hInstance & 0xFFF) == 0 && fdwReason <= 3`，所以非零预算安全：
  真 OEP 若不是回调，签名测试失败，仍会被接受为 OEP。
- x64 只按 `execution_type == 8` 就跳过，**不校验参数**。给它非零预算
  会让它把**真 OEP** 当回调跳过：实测
  `TLS callback 1/4 at 0x7ff6c13e2820` → `FATAL: OEP not found`，
  gate 从绿变红并跑 **466 秒**。所以 x64 必须保持 0。

**x86 行为对比**（`x86_c.exe`）：

```
修复前: Possible OEP at 0x401810 → "返回地址在 Themida 段" → 重试
        → 0x538866 读 0x5 重复 1024 次 → 约 4 秒 FATAL

修复后: TLS callback 1/4 at 0x401810 → guard 切到 Themida 段
        → 壳正常持续运行，风暴事件 0 次
```

**x86 仍未产出脱壳结果** —— 现在卡在"guard 等真正 EP"，壳在正常线程循环里
（`CreateThread`/`ExitThread` 周期性），不再是风暴。这是下一个独立问题。

### 已解决：EXE gate 的启动判定改为对照法（2026-10-24）

**旧判据**："20 秒后进程还活着" = 产物跑起来了。它把两个无关的问题混在一起：
产物有没有到 GUI，以及产物**要不要连网**。

**实测的误报**（`OUT/win_probe2.c`，同一台机器）：原始加壳样本弹 `#32770`/
「程序启动」（"无法获取程序模块，请检查网络后重试"）后到 20s 仍活着；脱壳产物
**零个顶层窗口**、198ms 后 exit 0。两者**都没**出现「授权验证」——样本要连远端
模块服务器。旧判据看到产物没窗口就报 `dump is not loadable`，**而那个产物的字节与
golden 逐字节一致**。之前用"重试一次 + 拉长 sleep"打了两次补丁，都没治根。

**新判据：拿原始样本当对照。** 同一环境、同一台机器上跑一遍，

```
对照能到授权窗口 + 产物也能到  -> GUI 正常
对照能到授权窗口 + 产物不能    -> 产物侧缺陷（只有这一种会指控 dump）
对照也不能到授权窗口           -> 这台机器跑不了这个样本，本项检查不成立
```

**第三种不会静默通过**：仍要求产物**不许崩溃**（exit 0 或仍存活），
并把全部观测打出来：

```
WARNING: GUI check NOT exercised — the original packed sample could not reach
`授权验证` on this machine either, so the sample's remote dependency is
unavailable.  Byte-level and structural checks above still passed.
```

**判别力是端到端验过的，不是嘴上说的**：把 manifest 的标题临时改成对照
**能**触达的 `程序启动`，gate 立刻红并打印两侧观测 + 

```
the control reached the licence dialog but the product did not — this is a
dump-side defect, not an environment problem.
```

验完已改回 `授权验证`。分类器本身是**纯函数**，9 个新单测覆盖每个分支，
包括"标题写错时不能凭它指控产物"和"环境分支不能变成无条件放行"。

**三个观测细节都是实测出来的**：10ms 轮询（不是 250ms，产物整轮只有 198ms）；
标题不看可见位一起收（正在创建还没显示也算证据）；丢掉 `IME` / `MSCTFIME UI` /
`Default IME` 这些每个 GUI 进程都有的辅助窗口。

还要**同时清掉对照样本的残留实例**，不只是产物的：产物是单实例对话框，
对照那一轮留下的实例会让下一次启动立刻退出。

### 已解决：DLL 的 golden 哈希重录过两次（2026-10-24）

第一次：旧记录 `088d5727…` 对应的产物 `.bss` 只有 **1** 个非零字节，现在是 **81** ——
`.bss` 是壳停放已初始化全局量的地方，1 字节 = "壳没初始化完就 dump 了"，81 = "壳跑完了"。
多出的 11 个 qword 是 in-image 指针（`runtime_base + 0x13c0xx`），被**故意保留**
（代码注释 `Already an in-image address: the product's own pointer, keep it`）后由
`fix_hardcoded_addresses` 重定位成 `file_base + 0x13c0xx`，**与 OS 把目标加载到哪无关**——
这正是它能复现的原因（4/4 次字节一致，行为 `VERSION=1.1` / `PigToGoLicenseDialog` /
`RUN_THREAD_ALIVE=1`，IAT 计数 289/3、尺寸 1737216 全不变）。

第二次就是 `.text` 保真度修复（见本文件「x64 的 `.text` 保真度缺口已收掉」），当前值 `97b9f20f…`。

**为什么这两次可以改期望值**：那条"哈希漂移先怀疑活体指针、别动期望值"的规矩是为了
防止用改期望值掩盖**不确定性**；这两次的新值都是**确定性**的，旧值才是错的。

**别再重复这些测量**（上一轮踩过的弯路）：
- `shiguang\coreU.dll` / `coreUD.dll` **不是** golden 副本，是 `.pdata` 还零填充的
  更早产物；`OUT\coreU.dll` 是**当前输出路径**，每次 `/unpack` 都会覆盖。
- "54 段差异、`0x103014` 被清零"是**误导**：那是旧产物 `.pdata` 全零，不是缺陷；
  `.pdata` 与 `.rdata` 内容相同是**正常布局**（EXE 产物同样如此）。
- 判"活体指针"的上界要用 `clear_stale_live_pointers` 自己的
  `0x0001_0000_0000_0000`，写成 `0x7FF0_0000_0000` 会漏判 `0x7ffb…`，得出假结论。

### 已解决：DLL 线的 IAT 定位退化（`resolved` 289 → 14，2026-10-24 修掉）

`dll_e2e_gate` **首次通过**。现在两样本都对：

| 样本 | 起点 rva | resolved | failed | not-an-import | 产物 sha256 |
|---|---|---|---|---|---|
| DLL | `0x141a80` | 289 | 0 | 3 | `97b9f20f…aa9f67` ✅ |
| EXE | `0x1136e0` | 186 | 0 | 8 | `af092f96…09b9fdd` ✅ |

两个产物哈希都与 golden **逐字节一致**，尺寸也对（1737216 / 1539072）。

#### 五个独立缺陷，全部实测定位

**① 向后走查被"裸 RVA"骗过**

走查原先接受一切"像地址"的值，于是**裸 RVA**（`0x14365a` 那类，正是 trace 引擎
判成 `not-an-import` 的东西）被当成"未知、继续走"，而它其实是**边界**。
DLL 上因此多走了 `0x5A0` 进无关 `.rdata`。现在裸 RVA 直接终止走查——
两个样本的表头前面**都**是一个裸 RVA，所以这条对二者一致。

**② 走查结果被丢弃两次**

- `select_primary_block` 找"包含 start 的块"，走查停在块间空隙时它 miss，
  回退到**最大块**——DLL 上选了 1289 槽的 `.rdata` 区域。
- `combined_start = primary.start_slot` 把 padding 和表外前导**又放回去了**。

现在走查是权威，任何合并后都要**重新 trim** 表头。

**③ 合并条件才是两样本真正冲突的地方**

两样本都需要**向后合并**，但理由相反，且**无法共用一个 gap 宽度**：

| 样本 | `iat_ref` 距表头 | 无向后合并时 |
|---|---|---|
| EXE | `0x328` | **2 槽**（186 resolved 塌成 1） |
| DLL | `0x860` | 起点正确，但向后合并会拖进 `.rdata` |

判别器是**走查走了多远**（`MAX_EARLIER_REF_GAP`），不是 gap 宽度。
前向则相反：两样本内部 gap 都很小（DLL 46 槽、EXE 39），而下一区域在 54 槽外，
所以 **48 槽**上限能分开，旧的 640 槽上限会把下一区域整个吞掉（EXE 出 2437 槽 vs 1063）。

**④ 读窗口是单侧的**

`iat_ref` 落在缓冲**最后一槽**，前向空间为 0，表只能从表头量到引用处。
改为 `iat_ref` 后留 1/4 缓冲（3840 槽前向），超过两样本所需（DLL 3018、EXE 1062）。

**⑤ 表头前导没被 trim**

走查停在边界后，表头仍以 padding 开头，DLL 上还多一个**系统模块的已解析 API**。
把它算进去就得到 290 而非 289。现在表头推进到**第一个仍需处理**的槽
（镜像内指针或裸 RVA）。

#### 槽数断言改成"下限"，不是精确值

旧的精确值（DLL 3283、EXE 1063）是**单侧窗口恰好停在哪**，不是表的属性：
活数据里没有任何边界落在那里（DLL 最后一个非零槽在 3322；EXE 的 1063 落在零区中间）。
两个 manifest 现在都用 `expect_iat_slots_min`，仍能抓"提前中断"，
而**字节级可复现性单独断言，是更强的检查**——它通过了。

#### 别再重复这些测量

磁盘映像**不能**判这张表（加壳输入里全零，必须量活内存；转储在
`OUT\dll_iat_live.bin` / `OUT\exe_iat_live.bin`）；导入描述符表与它**无关**，
不能用来推边界。
**全量单测 230 passed / 0 failed / 2 ignored（x64），x86 223 / 0 / 2。**
**两条 e2e gate 均绿**：两个产物哈希都与 golden 逐字节一致（EXE 的 GUI 一项按
对照法判定，本机 2026-10-24 实测对照与产物都到了 `授权验证`）。

## x86 OEP guard 不再依赖 DEP（2026-10-24 修掉）

x86 参考样本在调试器下**从未到达自己的 EP**，根因不是 guard 逻辑，
而是 guard 对页保护做了一个假设。

分支 4（TLS 回调分支）把 `.text` 放宽成 `PAGE_EXECUTE_READWRITE`、
把 Themida 段设成 `PAGE_READWRITE`，然后**指望**回调返回进那个段时 fault ——
因为分支 1（唯一会把 `.text` 重新设成 `PAGE_NOACCESS` 的路径）只在该 fault 上跑。

**当 DEP 对该映像不生效时这个假设是假的**：

| 文件 | DllCharacteristics |
|---|---|
| `x86_c.exe` | `0x0000`（**NX_COMPAT 未置**） |
| 未加壳 `x86_sample.exe` | `0x0140`（NX_COMPAT 已置） |

32 位映像不声明 NX_COMPAT 就退出 DEP，于是 `PAGE_READWRITE` 仍可执行，
返回直接跑过去。**40 秒实测**：`.text` 钉在 `0x40`、`.themida` 在 `0x4`、
**零**后续访问违规、真 EP `0x401450` 从未执行。
而**不挂调试器**的对照运行同一份样本一切正常（`.text` 5748/7152 非零、
窗口 1094 ms 出现），所以壳是健康的，缺的只是重新布防的触发点。

修法：在回调返回地址上埋 `int3`。它与 DEP 无关，回调返回时必定抛
`EXCEPTION_BREAKPOINT`，调试循环把它转成同一个"重新布防 `.text`"动作。
**是叠加的**——若返回确实先 fault（DEP 生效），断点根本不会被执行。

消费断点时必须**把 Eip 回退**到埋点处：断点异常让 Eip 停在 `int3` 之后，
从那里继续会跳过壳的第一条真指令（返回处那个字节是 `0x9c`，`pushfd`）。
实测跳过它会跑到 `0x77f70c30` 执行不可执行内存并风暴 1024 次。

同一次运行还暴露 TLS 判别缺陷：`tls_total` 在回调数组被壳加密时是**有界猜测**（4），
而 x86 样本真实只有 **2** 个（`0x401810`、`0x4017d0`），所以预算 4 吞掉了真 EP ——
实测走到 `0x401810 → 0x4017d0 → **0x401450**` 并把最后一个记成 "TLS callback 3/4"。
现在 guard 也校验 x86 回调参数签名 `(hInstance & 0xFFF) == 0 && fdwReason <= 3`
（`oep::handle_tls_callbacks` 早就这么做），不匹配就走 OEP 分支。

### 随后暴露的三个 dump 路径缺陷

- **`find_iat_ref_from_address` 无环检测**：递归跟进 `call rel32` 目标既无深度上限
  也无访问集，而 x86 `.text` 有互递归 → 主线程栈溢出
  （实测 `thread 'main' has overflowed its stack`，扫 `0x401470..0x40148d` 时）。
  现在带访问集 + 深度上限。
- **`.reloc` 预留量与声明不一致 → 虚拟布局开洞**：`create_reloc_section` 预留
  `0x2000` 并当作 `virtual_size`，`build_relocation_table` 之后改成真实长度却
  **不移动**后面的段，于是段间留下空隙。**loader 拒绝任何段 VA 不连续的映像**：
  实测 `ERROR_BAD_EXE_FORMAT (193)`，而该产物通过 `pefile` 全部结构检查；往
  **能正常工作的对照样本**里注入一个洞，它也用同样的 193 失败。
  **修法不是缩小预留量**（上一轮改成 `0x1000` 是错的：装不下 x64 的 5972 字节表，
  且预留量决定 `.import` 落在哪、`SizeOfImage` 多大，缩小它会让 x64 产物不再逐字节
  等于 golden；**193 是被 `create_section_index` 的对齐吸附修掉的**）。现在的做法：
  预留量保持 `0x2000`，由 `build_relocation_table` 在真实表长已知后把 `.reloc` 的
  `virtual_size` 撑到下一个段的 VA——撑大它不移动任何 header，loader 只读
  `BaseReloc.size` 字节、其余零填充。**x64 golden 本来就没有洞**，那个分支不触发。
- **稀疏 IAT 写入可能落进头部**：`section_rva_to_file_offset` 对任何段外 RVA
  回退成 `rva as usize`，所以 trace 定位不到的 thunk 把 `BF 90 01 00` 写到了
  文件偏移 0，覆盖 `MZ`，dump 以 `Invalid DOS signature` 失败。现在跳过并报告。

## 两条 golden 在同一台机器上不再复现：环境漂移，不是代码（2026-10-25）

**症状**：发 `0.3.0` 前的例行 gate 复跑，DLL 与 x86 两条报
`product SHA-256 drifted from the golden record`，EXE 那条**通过但降级**——
它的对照样本只到 `程序启动`，没能到 `授权验证`。

**第一反应必须是查代码，而不是改 golden。** 我改过的东西确实可能影响 dump：
CLI 里加了前置 packer 闸、多了一次 `fs::read(input)`、ScyllaHide profile
从预检阶段被重写。所以先做 A/B。

### A/B 的做法：用**发布过的旧二进制**跑同一条命令

DLL：`git worktree add _wt_4df2c09 4df2c09` → 在 worktree 里
`cargo build --release -p mida-cli` → 用它跑同一样本、同样参数。
x86 更省事：`target\release\mida-cli-x86.exe` 就是 v0.2.0 发布时复制的那份
（6,076,471 B，`/version` 自报 `0.2.0`），**旧二进制本来就躺在磁盘上**。

| 样本 | golden（2026-10-24） | 旧代码产出 | 新代码产出 |
|---|---|---|---|
| `OUT\core.dll` | `97b9f20f…` | `a27eb68a…` | `a27eb68a…` |
| `OUT\x86\x86_c.exe` | `cf176ac9…` | `53eace5e…` | `53eace5e…` |

**旧代码 = 新代码 = 当前机器上的确定值。** 所以漂移与本次改动无关。

### 漂移到底在哪：一个 API 地址

DLL 的结构指标**没动**：trace 仍是 `289 resolved, 0 failed, 3 not-an-import`，
产物仍是 1,737,216 B。动的是 **dump 自己**解析到的地址数：

```
[INFO] Resolved 288 API addresses from live IAT image     ← 记录期是 289
```

**新旧二进制都是 288。** x86 侧同样只有字节差、结构指标全同（`55/0/55`）。

### 判据：同一环境漂移在第三条 gate 上看得见

EXE gate 用对照法判定"产物是否起来"。这一轮它的**对照样本**（原始加壳的
`时光一键宏.exe`）只到 `程序启动`，没到 `授权验证`，而 2026-10-24 的记录是
**对照与产物都到了**授权窗口。同一天、同一台机器、三条 gate 里两条字节变化 +
一条行为降级 ⇒ 环境整体位移，而不是某段代码回归。

### 处理：重录，但按项目既有规矩重录

`core_dll.case` 自己在 2026-10-24 就有一次重录，理由格式是"改动不是代码 +
用 `git show` 证明 + 实测 3/3 一致"。这次照同一格式写进 case 文件头部，
并**先让行为断言真跑过**再确认：

- DLL 的哈希断言在行为断言**之前**，所以之前一红就停，`expect_version` /
  窗口类 / 窗口标题 / 首段特性从未被执行。重录后它们全部跑过并通过。
- 中间有一次 `window exists but is not visible`（`WINDOW_VISIBLE=0`）。**没有改断言**，
  而是直接手工调 `dll_gate_harness.exe` 复测：**对照样本与产物都报 `WINDOW_VISIBLE=1`**，
  其余指标与记录逐项一致。所以那是 gate 采样窗口的偶发竞态，随后 3/3 通过。
- x86 重录后 2/2 通过（`MidaX86Sample` / `验证 x86 样本`）。

**新值都是确定的**：DLL 4/4（3 次 gate + 1 次 A/B），x86 3/3（1 次 gate 失败取样 +
2 次通过 + 1 次 A/B）。

### 留下的教训

1. **`4df2c09` 这类"发布过的二进制"是免费的对照组**，别再花时间重建 worktree
   （x86 那份甚至一直躺在 `target\release`）。发现漂移的第一步就是拿它跑一遍。
2. **重录 golden 之前，必须让排在哈希断言之后的断言真跑过。** 这次差点就把
   "哈希改了、行为没验"当成"gate 绿了"。
3. **门响应"产物不可见"时先手工复测再动断言。** `WINDOW_VISIBLE=0` 一次就被
   手工复测推翻；若当时直接放宽断言，就永久丢掉了一项真实检查。
4. 三条 gate 里 EXE 那条**依旧是绿的**——它已经有对照法，所以环境降级被正确
   降级成 `GUI check NOT exercised` 而保留硬断言。**这个模式值得推广到 DLL gate**：
   目前 DLL gate 对 `WINDOW_VISIBLE` 是硬断言，若同类环境降级发生，它会红。
   单列出来是**已知缺口**，不是这一轮要修的事。

## DLL gate 对照法落地 + gate 二进制的 profile 陷阱（2026-10-26）

上一节教训 4 单列的已知缺口，本节收掉；顺带挖出一个埋了很久的 gate 缺陷。

### 缺陷一：三条 e2e gate 跑的是 debug 管线

`mida_cli_path()` 用 `current_exe` 推导 CLI 路径（deps → profile），`cargo test`
不带 `--release` 时解析到 **`target\debug\mida-cli.exe`**。而 RUNBOOK 的运行路径、
golden 的录制、MCP 的发布物全是 release。实测（同机、同会话、分钟间隔）：
release 二进制 9/9 完成 DLL trace；debug 二进制**可复现地**在 trace 前丢失壳的
主线程——`OpenThread` 成功而 `GetThreadContext` 返回 `ERROR_INVALID_HANDLE`
（线程正在退出），`trace_start_sp=0` → trace 整段跳过 → dump 照写 → gate 在
trace 计数断言上红。这不是时序抖动（7/7 vs 9/9，与启动参数、cwd、管道、环境变量
无关——逐项排除过），是 debug 构建下壳的初始化节奏整个不同。
（排查期间在 `get_thread_context` 里临时加过 `[diag]` 输出，定位后已还原。）
**修法**：三个 gate 的 `mida_cli_path` 改为优先同 target triple 的 release 二进制
（x86 gate 需要 triple 内的 release，故不能跨 triple），release 缺席时回退本
profile 并打印 note。

### 缺陷二：环境的 dial 不止 288/289 一个

DLL gate 修好 profile 后第一跑，字节 golden（`a27eb68a…`）又漂了。本节上文的
归因是 live-IAT 解析计数 288/289；**今天日志读到的正是 288——计数没动，字节
还是动了**。A/B 定责照旧：`48fa9d4`（本分支最后一个"绿色基线"提交）worktree
二进制，同机同会话同命令，产物 **`8ba37a79…` 与当前管线逐字节相同**——代码
无罪，重录 golden（manifest 带 A/B 证据注释）。同一天里环境至少翻过三次：
失败窗口（14:08–14:11）→ 恢复（14:19 起）→ 对照基线 `WINDOW_VISIBLE` 在
14:31 量到 0、14:5x 量到 1。**结论：这个会话状态是多 dial 的、会自翻的；
golden 锁的是"会话指纹"，跨会话不复现属于已记录的常态，不是回归。**

### DLL gate 对照法落地

把 EXE gate 的判定表（上文 477–479）移植进 DLL gate 第 7 节：

- **对照 = 受保护原始样本本身**（`sample_path` 那个文件），先于产物跑同一
  harness——DLL 的壳用普通 `LoadLibraryW` 就能跑起来（无调试器无反调，
  实测 `LOADED=1 VERSION=1.1`），不需要 EXE 那样的特殊处置。
- 对照必须 `LOADED=1` 且 `VERSION` 命中期望，否则本次会话**没有资格评判**，
  gate 红并点名"this session cannot judge"——宁可响也不假绿。
- 窗口断言按判定表门控：对照能创建+显示窗口 → 产物窗口断言全硬；对照自身
  `WINDOW_FOUND=0` / `WINDOW_VISIBLE=0` → 打印 `NOT EXERCISED`（写明是环境、
  指向本节），`LOADED`/`VERSION` 保持硬。产物若在对照缺席时自己创建了窗口，
  class/title 照断（产物比对照强时检查只多不少）。
- `injector` 类副作用样本不进对照（EXE gate 同款取舍）。

**判别力**：manifest 的 `expect_window_title` 临时改成错值 → gate 红在
`WINDOW_TITLE`（ exercising 分支的牙口）；`NOT EXERCISED` 分支由当日实测的
`WINDOW_VISIBLE=0` 会话背书（该分支就是那次会话的形状）。教训 3 的"手工复测"
在这里被结构化成对照轮：真实检查没有丢——会话允许时它照跑、照硬。

### 留下的教训（本节）

1. **gate 解析"自己的 CLI"时，profile 是陷阱**：`cargo test` 的默认 profile
   与 RUNBOOK 的运行路径不同，`current_exe` 相对推导会静默错配。golden 是
   哪个二进制录的，gate 就必须跑哪个。
2. **"归因于一个计数器"的漂移解释要用下一次会话复核**——288/289 解释了
   10-25 那次，解释不了这次；环境的 dial 数量只能多不能少。
3. **对照轮是"手工复测"的脚本化**：把教训 3 的动作固化进 gate，检查项既不丢、
   也不再依赖有人在旁边手工判断。

## classic IAT 交错桶 vs loader 的并行数组契约（2026-10-27 修掉）

上轮"仍死在加载期"的 0xC0000139 修掉之后，真实缺陷比当时定位的深一层。

### 上轮定位只对了一半

当时：2 个无候选槽（combase#11/ole32#2，live 地址 `0x761b0a0d`）被 loader 当
名字 RVA 读。**这是真缺陷但不是主缺陷**。用 walk 脚本模拟 loader 走查
（`OUT/v1v2/walk_loader.py`），产物里全部 8 个描述符都在跨桶：

- user32 描述符（FT=0x60de8）的走查读到第 7/8/21 项是 **win32u 的
  `NtUserRedrawWindow/InvalidateRect/SetActiveWindow`**——user32 名字表里没有
  这三个名字（pefile 验过）→ `0xC0000139`，且排在一切之前；
- win32u 描述符的 FT（密集偏移算出 0x60e80）落在 user32 数组内部，读到的
  `GetSysColor/GetWindowTextLengthA` win32u 不导出；
- combase/ole32 同形：ole32 真名（OleInitialize 等）散在 combase 的走查里，
  combase 真名（CLSIDFromString 等）散在 ole32 的走查里。

关键澄清：**pass2 的名字/模块配对与 regroup 校验都没有失效**（moved=0 是对的，
每个 (模块,名字) 对单独看都合法）——错的是**序列化器的契约**：
`build_import_section_no_iat` 按"每桶一段连续数组"假设写描述符（密集 FT + 组尾
终止符），而 loader 从 FT **线性走到第一个 0**，跨桶读到的每个槽都按描述符自己的
DLL 名解释。桶按名字分组（正确）+ 槽按地址记录（正确）= 数组按地址交错（不可避免）。
三处事实互相矛盾：**builder 对、槽值对、数组边界错**。

### 修法：run 归一化 + 簇收编 + 不可表达就整簇不描述

`normalize_module_runs`（classic 门控，v3 密集路径逐字节不动）：

1. 全部 thunk 按记录地址排序，切成**极大同模块连续 run**（任何地址间隙都断开——
   间隙槽就是 loader 的天然终止符位置）；
2. 相邻 run（前 run 的终止位 = 后 run 的首槽）**成簇**——两个描述符不可能共享
   一个终止槽，硬写会砸掉后者的第一个 thunk；
3. 簇内找一个"所有名字都有效"的模块整簇收编。**转发器名字串是关键**：
   `ole32!CLSIDFromString` 的名字串在 ole32 的导出表里（RVA 指向导出目录内的
   转发串 `api-ms-win-core-com-l1-1-0.CLSIDFromString`），pefile 验证
   combase/ole32 混合区的全部 12 个名字都在 ole32 名字表内——整簇写成一个
   ole32 描述符，loader 沿转发链解到**与壳会话相同的活体地址**，可移植；
4. 无公共模块的簇（user32/win32u：`NtUser*` 不在 user32 名字表、user32 名不在
   win32u 名字表——**两边都收编不了**）整簇**不描述**：槽保留壳会话 live 地址，
   无描述符走查它们，loader 不碰；OEP 代码的调用同 boot 直达。

配套两处：描述符 FT 改用记录地址（`ft_from_records`，v3 走密集分支）；
写入器对覆盖簇跨度内的**无主槽清零**（簇内间隙 = 前一段的终止符）。

### 实测（1.9.1 样本，8 桶 74 thunk）

| 项 | 修复前 | 修复后 |
|---|---|---|
| 描述符 | 8（全部跨桶/重叠） | 6（winmm/winspool/comdlg32/ole32×2/oledlg） |
| loader 走查 | user32 数组含 3 个无效名对；combase#11、ole32#2 live 槽 | 每数组只含自己的有效项，逐一对系统 DLL 验证 **NONE invalid** |
| 加载 | `0xC0000139`，未过解析期 | 通过解析期 |
| 收编 | — | 2 簇收编（ole32 系）；40 槽（user32/win32u 簇）留 live 同 boot |

测试钉子：`normalize_tests` 5 条（簇收编/不可收编留活/独立 run/间隙断桶/序数
只在自家模块下收编）+ `classic_iat_tests::loader_walk_never_crosses_buckets_
or_gap_slots`（合成实测形态，模拟 loader 走查断言永不跨桶/永不读到 live 槽/
不可收编簇的 live 地址原样保留）。

### 宣称边界

**"v1 产物可运行"成立**（对照法：窗口标题同加壳对照，线程 28→4，两次可复现），
**"v1 产物可移植"不宣称**——40/74 槽依赖同 boot 的系统 DLL 基址。跨 boot 需要
从 user32 的 RX stub 反汇编推回原始导入名（`NtUserRedrawWindow` ↔
`RedrawWindow`），是下一个增量的输入，本轮不做。

## classic 首段的 RWX 位：live 头与输入声明不一致（2026-10-27 修掉）

导入修完，产物死在 `0xC0000005`，事件日志给出错偏移 `0x271e0` = **OEP RVA
(0x271dc) + 4**。反汇编：`33 d2 | 8a d4 | 89 15 34 e6 45 00`——第四条
`mov [0x45e634], edx`（原程序存全局量）访问违例。**0x5e634 在 .text 跨度内**。

三层事实：

| 来源 | 首段特性 |
|---|---|
| 加壳输入的段表 | `0xe0000040`（RWX + 初始化数据）——壳自己的解压工作区 |
| live 头（dump 读到的） | `0x60000020`——壳运行时改写了自己的段表，丢掉 W，INIT→CODE |
| live 内存实际 | RWX——home-guard 验证窗口里同样的 store 成功过 |

`sanitize()` 的 merge 规则（CODE 且 INIT 才给 W）不触发——live 头既没有 INIT
也没有 W。修法：classic 门控下把**输入文件首段的声明并回** dump 模型
（`validate_and_patch_pe_header`，输入已在手）：实测产物首段
`0xe0000060`，OEP 四条 store 全过。v3 走 live 头原样（字节 golden）。

教训与 x64 `.text` 保真度那轮（2026-10-24）同源但方向相反：那次是"别把壳的
签名当目标"，这次是"别把壳运行时改写的头当权威"——**声明以输入文件为准，
行为以实测为准，golden 只属于 v3**。关联小节：「classic IAT 交错桶」。

## classic 跨 boot 可移植：stub 反汇编推 NtUser* ↔ 原名（2026-10-27 落地）

上一节（classic IAT 交错桶）之后，产物里仍有 40 槽（user32/win32u 簇）保留
壳会话 live 地址——loader 描述不了，只能同 boot 用。本轮把这条缺口收掉。

### 前提实测：user32 的 RX stub 形态

SysWOW64 的 user32.dll 上量（pefile，2026-10-27）：

```
user32!RedrawWindow      @0x3b0e0: ff 25 90 ee 0e 10  → jmp [0x100eee90]
user32!InvalidateRect    @0x3ad10: ff 25 84 ef 0e 10  → jmp [0x100eef84]
user32!SetActiveWindow   @0x3b270: ff 25 2c ee 0e 10  → jmp [0x100ee2c]
user32!GetSysColor       @0x37c80: 8b ff 55 8b ec ...  （真函数，非 stub）
```

user32 的 `NtUser*` 类 stub 是五字节 `ff 25 [abs32]` 一跳，`[abs32]` 指向
user32 自己 IAT 里的指针——**该指针的值恰是 win32u!NtUser* 的函数地址**，
也就是壳塞进重建 IAT 槽的活体地址。静态文件里的 IAT 指针是重定位前值，
直接相等比较只有在 live 进程里成立——所以映射必须在 dump 期建。

### 修法：stub 目标映射 + regroup 推导优先

`build_stub_target_map`（classic 门控，dump 期执行）：扫描快照里**所有**
模块的所有导出地址，前 6 字节是 `ff 25`/`ff 15`（jmp/call [abs32]）的读
指针；指针落在**别的**模块范围内就记 `target_addr → (stub模块, 原名)`。
实测一次扫出 1,394 条（user32 的 679 条 win32u 导入 + gdi32 系）。

`validate_and_regroup` 里**推导优先**：槽的活体地址命中 stub map 时，
thunk 归到 (user32, "RedrawWindow") 而不是 (win32u, "NtUserRedrawWindow")
——两对都合法且解析到同一函数，但只有前者是原始导入表的名字。实测
moved=3，win32u 组空被丢，**uncovered_slots=0**：user32 簇自然连续成
一个 40 槽描述符，74/74 全部 loader 描述，same-boot 依赖消失。

### 收益与边界

| 项 | 2026-10-27 前 | 现在 |
|---|---|---|
| loader 解析槽 | 34/74 | **74/74**（实测样本） |
| same-boot 依赖 | 40 槽 | 无（本样本） |
| 加载 | ✓ | ✓（另有一次干净 exit 0——原程序自结束，壳的 28 线程才是它常活的原因） |

宣称边界：**"v1 产物可运行"成立**；本样本已不依赖同 boot，但那是
"实测样本的形态"——user32 之外的 stub 模块（gdi32 系）形态未逐一验证，
`_unknown_` 占位名（解析失败的槽）仍会迫使簇不描述。1.1.1 文件映射壳
形状仍未覆盖。

测试钉子：`stub_tests` 4 条（真实 user32 stub 字节逐字节钉死 + re-bucket
三态：推导归桶/无推导留原桶/无名槽拿推导名）+ 既有 loader-walk pin。

## 两条 golden 的第六、第七次漂移（2026-10-27，A/B 定责：环境，非代码）

本 session 两条 v3 e2e gate 的字节 golden 各漂一次，结构指标一项没动，
A/B 定责同上文方法（worktree 取 `351ed2f` 二进制、同机同命令）：

| gate | 旧值 | 新值 | A/B 证据 |
|---|---|---|---|
| DLL (`core_dll.case`) | `8ba37a79…` | `5ac104f2…` | 旧二进制产出 `5ac104f2…` 逐字节同 |
| x86 (`x86_sample.case`) | `4761923d…` | `5ba5dd53…` | 旧二进制产出 `5ba5dd53…` 逐字节同 |

结构指标照旧（DLL：289/0/3、288 resolved、1,737,216 B；x86：55/0/55、
110,592 B、Resolved 55）。本轮改动全部 classic 门控（`classic_imports`），
两个目标都是 V3，相关代码路径根本不跑——漂移归因照旧：会话多 dial。
golden 按 manifest 规程重录，证据注释留在两个 case 文件里。

## Themida 1.1.1 文件映射壳：管线路径已落地，验收被壳的运行时方差挡住（2026-10-27）

1.1.1 的壳与 1.9.1 的壳形状不同：壳把原程序解压进**文件映射**，再
`LoadLibrary` 素材化镜像运行——`.text` 守护链（写故障→OEP 候选）对它完全
无效（首段零写活动）。本轮把这条线做成一条独立管线路径。

### 实测（t111.exe，Themida 1.1.1.0）

| 观测 | 结果 |
|---|---|
| 加壳文件 | EP=0x6c014（Themida 段内），经典 stub 对（kernel32+comctl32） |
| 无调试器直跑 | 窗口 `Themida - http://www.oreans.com`，壳正常跑完 |
| 壳的素材化 | 文件映射视图（0x31000×3 + 0xA9000 解压区，READONLY）渐进填充 40s+；`LoadLibrary` 的镜像族在 0x61xxxxxx（退出时 UnloadDll 确认） |
| 管线内（debugger+ScyllaHide） | **方差极大**：今天 7 轮只有第 1 轮命中 CloseHandle（3.98 min，解压已完成）；其余 6 轮壳在 4–12 min 内 exit 0，素材化镜像**只在退出瞬间**（80ms）出现，运行期间从未加载 |

### 落地的管线路径（全部 classic 门控，v3 三 gate 绿、golden 不动）

1. `scan_mapped_images`（pe crate）：VirtualQueryEx 走遍目标地址空间，
   每个 committed 区读 0x400 找 MZ+PE，解析 ep/size_of_image/导入目录/节表。
2. **双路周期扫描**：事件循环超时（wait_event_timeout 2s，静默期）+ 循环
   尾部（2s 门控，繁忙期）——素材化镜像在解压风暴期间加载，单一触发器
   （CloseHandle 命中或超时）都会错过。首扫记录启动镜像集，后续只认新镜像
   （壳自己的 DLL 与系统 DLL 全在首扫里）。
3. **单步 OEP**：TF 装在壳的**主线程**（CreateProcess 的线程；工作线程在
   风暴里送事件，装错线程必错过跳转）；wait_event_timeout 防护 pause 自旋
   （TF 在 paused 线程上不触发，阻塞等待会挂死）。
4. `dump_mapped_image_product`：读镜像内容 → 头部修补（EP=单步得到的 OEP、
   base=0x400000、ASLR 关）→ 镜像内扫 IAT（最长 API 地址 run）→ 复用
   `rebuild_import_table_complete`（含 stub 推导/run 归一化全套）→ 组装
   产品（sanitize → .import 段 → 输出 → fix_hardcoded_addresses **传映射
   基址**做重定基 → reloc）。

### 未达成的验收与下一步输入

**t111 产物可运行未达成**：壳在管线下 6/7 轮不完成解压（素材化镜像不出现），
扫描无从触发。这是壳的运行时行为（2005 壳 + ScyllaHide hooks + Win11
debugger），不是管线缺陷——第 1 轮（无扫描 hook 的旧二进制）解压是完成的
（命中在 3.98 min）。下一步输入：① 用无 hook 的裸 debugger 环境跑
1.1.1（hook 是解压失败的嫌疑）；② 或者接受"1.1.1 在管线内不稳定"，
把素材化镜像的识别做成离线后处理（dump 进程内存后离线找镜像）。
1.9.1 形状的 classic 目标（守卫链）不受影响，照常工作。

## Themida 1.1.1 的"物化镜像"是 KernelBase.dll.mui——Ancient 是 VM 解释型（2026-10-28 定案）

上一节的"下一步输入②"做了，结论**推翻了本文件上一节的前提**：1.1.1 根本
不存在"素材化的原程序镜像"。离线后处理路线（dump raw.bin → 离线找 MZ+PE →
重建产物）作为机器已全部落地并在 1.1.1 上跑了 3 轮全窗口采样，采到的
"素材化镜像"逐字节验明是**旁证文件**，不是原程序。

### 决定性证据链（每条都是实测，可复现）

1. **CloseHandle 命中时扫描**：进程内存里只有加壳镜像（0x400000）和系统
   DLL——"素材化镜像"不存在。
2. **退出窗口（CloseHandle→ExitProcess 之间 ~450ms 墙钟）**：原程序确实
   **在跑**——TSF/IME 栈被拉起，`wetype_tip_core.dll`（腾讯微信输入法，
   4.5MB）、`d2d1.dll`、`DWrite.dll`、`ws2_32.dll`、`rsaenh.dll`、
   `cryptsp.dll` 等在窗口内逐一加载。每个 debug 事件都是一次进程冻结，
   轮转采样在每个冻结点抓全部候选。
3. **那个 0xb0000 (720KB)、ep=0、import_rva=0 的"素材化镜像"**：在 56+ 个
   冻结点（两轮运行，创建→执行中→退出）内容**逐字节不变**，全镜像
   **0 个函数序言**（`55 8B EC`）、0 个 DLL 名字符串。版本资源验明：
   **`Kernelbase.dll.mui`**（"Windows NT 基本 API 客户端 DLL"，10.0.26100）。
   ep=0/import_rva=0/≥64KB/新基址——这个"素材化签名"匹配的天然就是
   **MUI 资源 DLL**（资源镜像本来就没有入口点和导入目录）。
   中文 AD 术语串（FSMO/objectVersion/schema.ini/"Windows 2000"）是
   KernelBase 消息表条目——原程序弹了消息，系统加载了中文 MUI。
4. **加壳镜像自身也在采样里**（合成候选，每 3 个冻结点轮入一次）：运行时
   第一节在全部 11 个冻结点哈希一致（壳改写过一次，之后不变），0 序言；
   整镜像 1.4MB 只有 4 个序言（Themida 段里 VM 解释器的热循环残片——
   自解密自再加密，冻结时几乎全密文）。
5. `.text` 守护（CloseHandle 后装的）全程零故障——守护装上后没有代码
   从加壳镜像首段执行。

### 判定

**Ancient（1.1.1）= VM 解释型**。原程序逻辑以数据形态被壳 VM 消费，从未
以原生 x86 代码存在于进程地址空间的任何可观测位置（MZ 镜像、加壳节、
匿名区都排除了）。退出窗口里加载 UI/网络/加密 DLL 的调用来自 VM 代原程序
发起的真 API 调用。**"dump 出可重建的原生镜像"这条路对 1.1.1 物理上不存在**；
要出产物只剩 devirtualization（同 VMProtect 的先例：不做、不承诺）。
1.9.x（classic，V1）不受影响——那条线的守卫链有真 OEP 候选，产物已可运行。

### 本轮顺带修掉的缺陷与落地物

- `scan_mapped_images`：VirtualQueryEx 失败时原本整个 `break`——ExitProcess
  时进程撕除中区域已释放，扫描提前截断。改为跳 0x1000 继续走。
- `dump_mapped_image_raw`：单次大读在撕除中会整读失败（720896 B 全丢），
  改为逐页读、失败页记零并**打印失败页 RVA**（0xae000/0xaf000——尾部两页，
  MUI 镜像的尾巴）。
- `try_exit_dump`（ExitProcess 兜底）：忽略 `seen_image_bases`、用
  `import_rva==0 && ep==0` 双零签名——旧过滤器（只查 import_rva、排除
  seen）两次都放过了真候选。
- **退出窗口 watch**（`try_ancient_watch_scan`，Ancient 门控）：CloseHandle
  命中后每个 debug 事件做一次无门控扫描，候选**轮转**采样写
  `<stem>.rawNNN.bin` 编号快照。轮转而非 max_by_key 是实测教训：旁观 DLL
  （wetype 4.5MB）比"目标镜像"大，max_by_key 让一个候选霸占全部冻结点，
  目标在执行中阶段一张都没采到。
- `RemoteModule::base()` 公开访问器（模块基址集合用于过滤已注册模块）。
- 离线脚本 `OUT/v1v2/offline_rebuild.py`（全镜像 API 扫描版）与快照分析
  脚本（熵图/序言计数/版本资源识别）——机器已就绪，等一个真的会物化
  原生镜像的样本。

### 教训

**"签名匹配"必须验内容**。ep=0+import_rva=0+大尺寸+新基址这个签名连中
三个目标（三轮运行三个不同基址的 720KB 镜像），但它同样天然匹配所有
资源型 DLL——签名命中≠抓到了想抓的东西，打开看（序言/字符串/版本资源）
才算数。以及：max_by_key 式"选最大"会在多候选场景静默饿死小候选，轮转
采样是通用解。

## Ancient 阶梯运行时画像：1.8.2 裸跑原生执行、管线解码循环卡死（2026-10-28）

1.1.1 定案后把阶梯其余 Ancient 版本过了一遍裸跑/管线对照（RUNBOOK 有表），
三个发现：

1. **1.2.3 / 1.5.0：样本自身在 Win11 26300 上解码不收敛**（裸跑 96% CPU
   永久空转、无窗口、线程收缩），与调试器无关——管线对它们的秒级死亡
   是忠实的。老壳依赖的 OS 行为在新系统上变了，这类样本只能换 OS 环境。
2. **1.8.2：裸跑成功**（~25 s 出记事本窗口，低 CPU=壳完成、原程序原生
   执行）——**"VM 解释型"只属于 1.1.1，不是 Ancient 整代结论**。但同一样本
   在管线内（hooks / `--no-scylla` / `MAGICMIDA_NO_CHBP=1` 三环境）都死于
   0x1218235 处 1024 连发同一 AV（target 0xffffffff），DR0 硬件断点排除
   （NO_CHBP 实验无效果）。**调试器兼容性缺陷，下一增量的输入**：嫌疑集中在
   DEBUG_ONLY_THIS_PROCESS 的首异常递送路径与壳 SEH 的交互（解码期
   SEH fixup 在我们环境下不推进），或壳的直接系统调用反调探测（绕过
   ScyllaHide 的用户态 hook）。攻克它 = 1.8.2 原生镜像可采 =
   `offline_rebuild.py` 的端到端验证料。
3. `MAGICMIDA_NO_CHBP=1` 诊断开关保留（默认关，RUNBOOK 有记录）——
   虽然这次排掉的是错的嫌疑，但"跳过 DR0 武装跑一轮"是这类问题
   最便宜的第一刀。

## 1.8.2 攻坚：两处 DBG_CONTINUE 吞异常修复落地，壳推进两个解码期（2026-10-28）

上面的"调试器兼容性缺陷"当轮就攻了一半。根因不在反调试，在**我们自己的
AV 处理路径**——两个吞点：

1. **守护安装前**（`handle_access_violation` 的 `!guard_installed` 分支）：
   所有 AV 一律 `DBG_CONTINUE`——异常被调试器吞掉，故障指令原样重执行。
   1.2–1.8.2 的解码期是**首异常驱动**的（解码器故意故障、自己的 SEH 改
   CONTEXT 推进），吞掉=死循环。裸跑 25 s 收敛 vs 管线秒级 1,024 连发，
   差别就是异常有没有到达壳 SEH。
   修：Ancient 门控下改 `ExceptionNotHandled`（递给壳自己的 SEH = 裸跑
   等价行为）。**v3/V1 保持原样**：实测 x86 v3 样本吞 156,309 个故障也
   收敛（它们的解码期不依赖首异常 SEH），字节 golden 依赖现有行为。
2. **守护安装后**（`NotGuarded` 分支）：故障不在守护区内同样吞。
   修：同款 Ancient 门控。

修复的实测推进（1.8.2）：

| 轮 | 修复 | 走到哪 |
|---|---|---|
| 0 | 无 | 秒死于解码期一（0x1218235） |
| 1 | ① | **解码期一收敛**、CloseHandle 命中、watch 武装，死于解码期二（0x1227153） |
| 2 | ①+② | **解码期二也过**，事件风暴里活了 ~5 min（25,644 个事件），死于第三处（0x976dab20，垃圾区域） |
| 3 | ①+②+快照封顶 | 死回解码期二——**时序依赖**（轮 2 的 25K 次扫描大幅拖慢事件处理，封顶后全速处理时序变了） |

顺带修的运营缺陷：**watch 快照无上限**——轮 2 的事件风暴拍了 25,644 张
快照 ≈ 37 GB。现封顶 64 张（前期快照才是信息量所在的窗口）。

同轮排掉的分支：`NO_CHBP`（无 CloseHandle 命中 → 无守护）下壳解码后
**无限闲置**（0 CPU、无窗口、无子进程、5 线程等内部对象）——又一处
调试器可观测性差异，未解。

**现状如实**：1.8.2 仍不可脱壳。剩余阻塞 = 解码期二的时序依赖 + 第三处
故障循环 + 闲置分支，三个都在"壳推进得比以前远得多"的地带。回归全绿：
x64 413 / x86 406、三 e2e gate 全绿（字节 golden 持住）、1.1.1 行为不变
（watch + 兜底 dump 照常）。两处修复是保真度修正（向裸跑行为对齐），
对任何首异常驱动的壳都是纯收益。

## 1.8.2 攻坚下半场：OUTPUT_DEBUG_STRING 冻结 + DR0 规避 → 壳全生命周期跑通（2026-10-28）

上半场的"剩余阻塞"当轮继续攻，三个根因全部落定：

1. **闲置分支根因 = `OUTPUT_DEBUG_STRING_EVENT` 被吞且从不 continue**（core
   `decode_event`）：目标调 OutputDebugString → 内核把线程冻在
   `kernelbase!RaiseException` 里等调试器应答 → 我们"忽略"该事件却不
   `ContinueDebugEvent` → **线程永久冻结**。实测证据：闲置诊断（超时臂
   5 秒无事件后 dump 主线程上下文）显示主线程 EIP 恰在 RaiseException+0x64、
   栈顶 0x40010006（DBG_* 状态族）、栈上有壳解码区返回址 0x122163d。
   修：读出字符串（INFO 记录——壳的调试输出是脱壳金矿）+ `DBG_CONTINUE`
   继续。**这是 core 级缺陷，任何被调试目标踩到 OutputDebugString 都会冻死。**
2. **解码期二毒源 = DR0**（AV 流形态 + NO_CHBP 对照确证）：DR0 武装时壳的
   SEH 校验调试寄存器、拒绝推进（2,047 连发 -1 指针），NO_CHBP 则一帆风顺。
   修：**Ancient 门控跳过 CloseHandle 硬件断点**（watch 改从 CreateProcess
   武装——1.8.2 不再经过 CloseHandle 里程碑，1.9.x V1 的经典链不受影响）。
3. **快照轮转被旁观 DLL 淹没**：模块基址缓存在首个事件就灌入（级联未完），
   后加载的 DLL 全成"候选"——63/64 张快照是系统 DLL。修：模块基址**每扫
   现取**（ToolHelp ~5-20ms，与地址空间扫描同量级），候选收缩到加壳镜像
   合成候选 + 真非模块镜像。

**结果：1.8.2 在管线内跑完全生命周期**（解码 → 载荷运行 → ExitProcess 0,
74 s；裸跑 25 s）。终态仍是 "OEP not found"——因为**原程序不在任何 MZ
镜像里**：全轮 64 张快照 + ExitProcess 兜底 dump 验明，载荷（裸跑出现记事本
窗口的那个）是壳工作区（0x12xxxxx）里的微型裸码 stub,不是 PE 镜像——
OEP 链（.text 守护/OEP 候选）对它物理上不适用。1.8.2 的"脱壳产物"要换
采集目标（工作区 stub 转储），那是新的 scope 决策。

**深扫最终确证（同日）**：`scan_private_images`——逐页探查所有
`MEM_PRIVATE` ≥64KB 区域的 MZ 签名（关闭"区域中部"盲区：head-only 扫描
只看 region 前 0x400 字节）——在 1.8.2 全生命周期内**零命中**。壳解压载荷
到工作区时连 MZ 头都不建：微型载荷以裸码形态存在，"重建 PE"无从谈起。
深扫能力保留：对会物化 PE 到 region 中部的壳是必备采集面。

## 1.8.2 stub 捕获战役：四条路线全部被规避，ODS 事件化落地（2026-10-28）

用户拍板"工作区 stub 转储 + 手工重构 PE"后的攻坚。先离线分析 24 张全镜像
快照确证 **stub 是瞬态明文**（解密→执行→再加密：0x221000 页在 raw018 从全零
变 85% 非零后熵恒定 7.18，任何被动冻结点都抓不到明文；闲置轮栈上的
0x122163d 返回址证明它原生执行过）。随后四条主动捕获路线：

| 路线 | 机制 | 结果 |
|---|---|---|
| ① 被动快照 | watch 轮转 | 永远 7.18 熵，瞬态窗口 missed |
| ② ODS 活体捕获 | 壳调 OutputDebugString 时线程冻在 stub 的 call 里，栈上即返回址 | ODS 本身 ~1/4 运行才出现；三连跑零命中 |
| ③ 页守护 | PAGE_NOACCESS 盖 stub 页（0x122000），stub 一执行就故障 | 9 分钟零命中——stub 页逐轮变化，硬编码地址不可行 |
| ④ API 断点 | 解码后 DR0-3 武装 WinExec/CreateProcessA/W/ShellExecuteA，命中读栈顶返回址自定位 | 32 分钟全程武装零命中——载荷启动不走 kernel32 进程创建 API（直接 syscall 或 VM 代行） |

**诚实结论**：壳在每个层面主动对抗捕获（无 MZ、瞬态明文、位置漂移、API
旁路）。"工作区 stub 转储"需要更高等级的手段（单步追踪 shell VM 的
dispatch 循环、或 TEE 级内存监控），投入产出比不支持继续——1.8.2 线到此
为止， capabilities 保留，"脱壳产物"不宣称。

### 本轮落地的机器（保留价值）

- **`DebugEvent::OutputDebugString` 正式事件化**：core 不再吞 ODS——读出
  字符串、surface 给管线、由管线 continue（防冻结的 continue 责任转移到
  事件消费者，管线可在冻住的瞬间做活体捕获）。壳的调试输出是脱壳金矿。
- `MAGICMIDA_STUB_TRAP=<hex|1>` 诊断开关：hex=页守护模式，1=API 断点模式
  （解码后延迟武装——DR 武装在解码期内会毒害相位二，10 秒后解码必已结束）。
- `RemoteModule::exports()` 访问器（API 陷阱从活体模块快照解析地址）。

### 同轮的两条 golden 第 8 次环境漂移（A/B 定责：环境）

x86（5ba5dd53→397c259c）与 DLL（5ac104f2→e129fe26）双 golden 同时漂。
A/B 定责：`3f5cf8d` 工作树二进制（`-p mida-cli` 构建——全量构建会被 DSH
持有的 mida-mcp.exe 锁挡住，os error 5）同机同命令产出**逐字节相同**的新值
——代码无罪。结构指标原封不动：x86 55 resolved/110,592 B。两条 golden 已
按 manifest 规程重录（x86 第六录、DLL 第五录）。**教训重申**：全量构建在
本机永远会被 mida-mcp.exe 锁打断，A/B 用 `-p mida-cli`。

**顺带的假回归惊魂**：外来 int3 透传（把非我们武装的断点递给目标 VEH）
一度让 v3 EXE gate 红——查实 v3 的 golden 依赖旧的吞掉行为（RF+Continue）,
该透传是错误假设的产物（1.8.2 的真根因是 ODS 冻结,其运行里零个外来
int3）,已整体移除。另：x86/x64 gate 各出现过一次 4-10 s 快速失败,
重跑即绿——既有的桌面会话方差,与改动无关（stash 二分 + 复跑三连绿确证）。

**回归全绿**：x64 413 / x86 406、三 e2e gate 绿（字节 golden 持住）。

## gdi32 系 stub 推导：静态形状验证（2026-10-27）

stub 推导机制是模块无关的（扫所有已加载模块的导出地址、认 `ff 25/ff 15
[abs32]` 形状、指针落在别的模块内就记 `target → (模块, 原名)`）。
user32 的实测已钉死（1.9.1 样本三槽 NtUser* 归回 RedrawWindow 等）；
gdi32 系本轮做了静态形状验证：SysWOW64\gdi32.dll 的 995 个导出里 **496 个
是 `ff 25` thunk**（AbortPath、AddFontMemResourceEx…，与 user32 的
277/1043 同形），推导机制适用。活体样本级验证需要 classic 样本带
gdi32!NtGdi* 槽——语料样本（s1/s2）在管线内的壳行为不稳定（见上节
1.1.1 的方差记录），本轮未取到活体命中；形状验证 + 机制单测构成当前证据。

## V2 (SecureEngine 2.x) 战役：dd[0]/dd[1] 假阳性定案（2026-10-28，未发布）

**此节推翻下面两节**："载荷区探测 + 诚实收束"的"不物化"结论和"PE 找到 + dump +
离线重建"的"物化"结论——两个相反的结论都建立在同一个读错数据目录的 bug 上。
定案后回到：**V2 载荷不物化 PE 映像**（这次带着排除了假阳性的干净证据链）。

**样本**：`OUT/v1v2/unpackmes/x/WinLicense 2.0.6.5/(CISC-1) Examples-LCF-AT/CISC-1.exe`，
Themida V2，x86，image_base 0x1000000，EP RVA 0x371000，6 节（节名随机化）。

**触发**：用户指示"ExitProcess 时 dump IAT 区域（0x5804e000）+ 匹配 API 地址 +
重建导入表"（基于上一节的"载荷 PE"）。本轮把管线落地（`capture_stub_iat`：
ff15/ff25 聚类 + 模块导出表解析 + `.v2iat.bin`/`.v2iat.txt` sidecar）并实跑，
IAT 捕获门没触发——离线打开"载荷 PE" dump 对账，发现它根本不是载荷。

**铁证清单（dump = CoreUIComponents.dll，Windows 系统 DLL）**：
- 版本资源 `ProductName = Microsoft® Windows® Operating System`；`.rdata` PDB
  路径 `mincore\CoreUIComponents\Messaging\Proxy\MessageProxyN.cpp`。
- 与 `C:\Windows\SysWOW64\CoreUIComponents.dll` 对账：EP 0x6a710、
  SizeOfImage 0x295000、6 节（.text/.rdata/.data/.didat/.rsrc/.reloc）全同。
- 两次会话的 dump 逐字节比对新旧仅差 **41 字节**，全在 .data 可变全局。
- 真·导入目录 dd[1] = 0x22b5b8 指向 msvcrt.dll 描述符，
  FT[0] = 0x76816160（loader 已解析的绝对地址）——它是被正常加载的旁观模块，
  壳从没碰过它的导入表。
- "外部 IAT 0x5804e000（0x454 B）" = 加载基址 0x57ed0000 + dd[12]（IAT 目录）
  0x17e000 + 0x454 尺寸——**它自己的 IAT**，从不在任何"独立 VirtualAlloc 区域"。
  （"PE base 0x50c0000" 的归因也是错的：两个 dump 的头里 ImageBase 都是
  0x57ed0000——同一天同一 boot，系统 DLL 基址只随机化一次。）
- ".reloc XOR 增长密钥"假：0x271000 处是**明文有效重定位**
  （PageRVA 0x1000，HIGHLOW 条目）——在噪声上选密钥总能"解出"第一块。

**根因：`parse_image` 读 dd[0]（导出目录）当导入目录。** PE 数据目录
索引 0 = 导出、1 = 导入；代码读 `dd_off + 0`，注释还把颠倒写死
（"An earlier revision read dd_off + 8, which is the *Export* directory"——
dd_off+8 恰是导入目录，旧读法是对的，"修复"把对的改成错的）。
`MappedImage.import_rva` 从此语义为"导出 RVA"，而所有过滤器的意图是"有没有
导入"。"无导出 ≈ EXE"的代理判据在 MUI（无导出的资源 DLL）上失效——
1.1.1 战役的 KernelBase.dll.mui 假阳性是同一根因的第一次发作；LoadDll
handler 里复制粘贴的同款注释 + 同款读法是第二处。

**修复清单（本轮全部落地，x64 413 / x86 406 全绿）**：
- `parse_image`：改读 dd[1]（导入），注释重写为真话；新增
  `MappedImage.is_dll`（COFF `IMAGE_FILE_DLL`）——旁观 DLL 的诚实判据。
- `iat_capture.rs`（新，IAT 捕获机器）：门改为 EP>0 + EXE 标志 + 导入目录
  不可用（dd[1]==0 或首描述符全零）；ff15/ff25 目标聚类 + 边界按模块地址
  扩张 + 逐槽对 live 模块快照解析；产出 `<stem>.v2iat.bin`/`.v2iat.txt`。
  **当前无已确证消费者**——为未来真物化载荷的壳保留。
- 过滤器全面从 `import_rva==0` 代理改为 `!is_dll`：LoadDll handler、
  `try_exit_dump` 双分支、watch scan 一二次候选、ancient 级联（strict/
  relaxed）、CloseHandle immediate scan。
- 同样修正了 `iat_capture.rs` 首稿里复制的 dd[0] 读法（写新代码时把
  parse_image 的错当成了事实）。

**验证**：修复后在同一样本重跑——CoreUIComponents 的 LoadDll（0x57ed0000）
照常出现，但 watch scan 不再 dump 它；38 张/轮的旁观 DLL 快照噪声归零。

**保留（独立于假阳性、实测有效）**：
- `.text` 写 BP 防 bail（移除 → 壳 ~38s 内 exit_code=2；恢复 → 正常解码）——
  行为观察，与"载荷 PE"无关。
- `scan_private_images` 深扫修复（每页 0x400→0x1000 字节、PE base =
  page+mz_off）——真实的覆盖率缺陷。
- 载荷区探测机器（`v2_watch`/`try_v2_watch_scan`/CreateThread region dump/
  idle 诊断）——机器本身无误，只是此样本无真载荷可抓。

**结论**：V2 载荷不物化 PE 映像（1.1.1 = VM 解释型的同族判断）。**不宣称
V2 脱壳可用**。下一增量若再做 V2，输入应是"壳工作区裸码"分析（同 1.8.2
的瞬态明文死路）或 devirt——两者都先不承诺。

**教训（第二次犯同一课）**：签名命中必须开内容验——版本资源、与系统盘文件
对账、跨 dump 逐字节 diff，三样都是十分钟级的事，"PE 头结构完整"证明不了
"这是载荷"。数据目录索引是 0=导出、1=导入；注释与代码要一起对着
独立来源（remote_modules 的导出读取就是对的）验，不能互为论据。

## devirt 侦察："载荷区"是 WeType 输入法注入（2026-10-29，未发布）

**用户指示 devirt**（V2 线的最后一条路）。按"不承诺先侦察"的规矩，第一步
用上一轮留下的 6 个 v2payload 区 dump 做离线侦察——回答"载荷区里有没有
可分析的 VM（解释器循环 + 字节码）"。答案：**这些区根本不是载荷**。

**侦察链条（全部离线，样本不必重跑）**：
1. **熵剖面**：6 个区零高熵页（≥7.2）——无页级加密；中熵（6.0-7.2）为主，
   每个区的**末尾**带低熵代码块（124KB / 56KB）。
2. **线程起点反汇编**：全是干净 MSVC 代码——标准 prologue、C++ vtable 调用
   （`mov eax,[ecx]; call [eax+4]`）、int3 填充。线程起点读 `[esi+0x3c]`
   （e_lfanew 偏移）——在检查 PE 头。
3. **dispatch loop 搜索**：270 处 `jmp/call [reg*4+imm32]` 全部是编译器
   switch 跳转表（`cmp N; ja default; movzx; jmp [table]`），**零 VM 取指
   形状**（movzx byte [ptr]; inc; jmp [table] 不存在）。
4. **ff15/ff25 聚类**：数千个 `call [abs32]` 调用点收束到**两页密集指针表**
   （0x56162000 页 272 槽、0x564c3000 页 125 槽），各自紧贴一个代码区末尾
   ——**这是导入表形状**（每调用点直指自己的槽），不是 VM（VM 会经一个
   寄存器索引的中央分发器调 API）。
5. **导入剖面**：IAT 解析（管线新增 `resolve_pointer_report`，live 模块
   快照逐槽解析）= **现代 GUI 应用**：kernel32 177 / advapi32 34（注册表
   +加密）/ gdi32 20 / imm32 10 / combase / dbghelp / d2d1 / dwrite /
   input.dll / **crashrpt1500.dll 5**。2011 年代的 LCF-AT crackme 不可能
   导入 CrashRpt 1.5.0（2017 年的库）。
6. ** smoking gun**：`C:\Program Files\Tencent\WeType\3.0.0.38\CrashRpt1500.dll`
   ——本机装着微信输入法 3.0.0.38。

**判定：v2payload 区 = WeType 注入到被调进程的工作线程**（被调进程弹了
窗口 → TSF/IME 激活 → WeType 注入 worker，其代码在 VirtualAlloc 区里、
自带 IAT）。内存映射在毫秒间churn（区被释放重分配，同一 IAT 页服务多个
代码区；55f91ad0 的"下一区"查询直接跳过了已释放的 0x560b5000 落到
0x56162000）。所谓"载荷运行两轮 exit 0"= WeType worker 的两轮工作。

**波及面（本机测量的第三次环境污染，KernelBase.dll.mui → CoreUIComponents.dll
→ WeType）**：
- run1 的"载荷线程 0x64035dc0 等"、本日 0x55f9xxxx 全系——都是 WeType。
- **1.1.1"VM 解释型"定案的根基动摇**：该定案依赖 64 张快照 + 兜底 dump +
  深扫全零命中——但那三样**只搜 MZ+PE**。无头原生码（今天实锤存在的形状：
  WeType 的注入代码就是无头原生码 + 私有 IAT）对全部既有扫描**不可见**。
  "原程序从未以原生代码存在"从未被证明，只被"没搜到 PE"替代过。
- V2 同理：载荷可能以无头原生码形态瞬态物化，从未被搜到过。

**管线落地（保留）**：
- `resolve_pointer_report`（mida-pe，pub）：对任意 dump 逐 DWORD 对 live
  模块导出表解析，产出报告 + per_module 计数。
- `capture_v2_payload_iat`（CLI，V2 门控）：CreateThread 载荷区 dump 后
  追加"下一区"dump（64KB 上限）+ 指针解析；`crashrpt/wetype/input.dll`
  剖面 → 判定 IME 噪声 → 大 dump 改名 `.imenoise`——**磁盘上的
  v2payload_\* 从此只剩真候选**。

**下一步（下一个增量的输入）**：无头原生码扫描——枚举私有 RX 区、按导入
剖面分类（排除 WeType/已知注入组件）、非噪声候选全量 dump → 若原程序真以
无头原生码物化，走重建路线（合成 PE 头 + IAT 重建，机器全在）；**devirt
仍未开始——没有任何一个已定位的 VM 可供 devirtualize，继续不承诺**。

## V2 突破：原程序 = XP calc，就地解进镜像；bail = 许可检查（2026-10-29，未发布）

**无头扫描落地后的两连击**：

1. **无头扫描零命中 = 干净的排除证据**：全生命周期（含 ExitProcess 末次）
   私有 RX 区里，除壳自己的 API thunk 区（0x4e0000/0x510000，ntdll+win32u
   剖面，32KB）外**没有任何非噪声代码区**——载荷不在私有内存里，WeType 之外
   连一个代码区都没有。
2. **镜像快照抓到真相**（CloseHandle 首个 watch tick 全镜像 dump）：
   - `.rsrc`（va 0x16000）**已解密**：VS_VERSION_INFO 完整可读——
     **"Windows Calculator application file"，FileVersion 5.1.2600.0
     （xpclient.010817-1148）**——原程序是 **XP 版 calc.exe**（LCF-AT 教程
     拿它打包的 WinLicense 2.0.6.5）。
   - `.text`（va 0x1000-0x8000）仍加密（熵 7.93，与盘上逐字节同头）；
     0x9000-0x15000 全零；`.idata` 清零（壳代管导入）。
   - **ExitProcess 时 .text 逐字节仍加密**、.rsrc 头被擦——壳在拆栈前擦自己。

**V2 生命周期定案**：壳把原程序（XP calc）**就地解进加壳镜像自己的节**
（.text/.rsrc/.idata 的 RVA 与原 PE 相同），.rsrc 在 CloseHandle 前解完；
**.text 只在最终 OEP 跳转前才解密**——调试器和裸跑都到不了那一步：
裸跑同样 `exit 2`（与被调试完全一致 = **许可/环境检查失败，不是反调试**；
Themida 阶梯样本裸跑能活、WinLicense 2.0.6.5 裸跑死——差的就是许可层，
2008 年的 eval 早已过期）。"VM 解释型"定案彻底死亡：calc 从头到尾是
原生码，只是没解出来。

**bailtrace（MAGICMIDA_V2_BAILTRACE=1）**：CloseHandle 时在 ExitProcess
武装 exec BP（slot 1），命中时栈回溯 + **bail 时全镜像 dump**。实测：
- 13 个返回址入壳镜像（最深 0x10e35a3 = `jmp rel32` 进 ExitProcess 的尾调；
  0x10a4135 帧可见 `0f 85` jne + 变异 `e8+10` 跨垃圾调用的检查形状）。
- **exit 时镜像快照与活体字节不同**——壳拆栈时重加密自己的代码，
  bail 命中瞬间（进程冻结在 ExitProcess 首指令）是唯一稳定视图。

**bailtrace 迭代（同日第二轮）**：
- 地址校验 bug：bail/time 分支最初只查槽配置没查异常地址——一次 GetLocalTime
  命中（武装后 28ms）被误标成 bail，还清掉了 ExitProcess 的槽。修正后：
  bail 分支要求 eip==ExitProcess 本尊，time 分支要求 eip==各自 API。
- 观察 BP 从 CloseHandle 挪到进程启动：快 bail 变体 CloseHandle 后 15ms 就退，
  检查在解码期就跑完了。exec 型 HW-BP 命中后必须 RF（EFlags|0x10000）再继续，
  否则原地重触发。
- **时间观察结论**：壳解码期只调一次 GetLocalTime（ret=0x107547e，武装后
  28ms），GetTickCount 零调用。0x107547e 的调用链是 `push <续址>;
  jmp 0x102888a` thunk 链——解析器 BP（slot 2 = 0x102888a）一次拿到
  **127 个按序 API 调用点**，全部落在加壳镜像第 4 节（ASLR 基址下
  RVA 0x2bxxxx）——**壳的引擎按块解密在镜像大节里，用完即再加密**（快照
  熵 7.74 的原因；1.8.2 瞬态明文同款机制）。ExitProcess 无静态引用
  （运行期解析，`call [edx+disp]` 寄存器分发表）；栈上 13 个候选
  返回址经 bail 镜像验证**全都不是真返回址**（前面没有 call 操作码）——
  壳的栈充满 push/ret 混淆残渣，栈回溯不可信。
- 下一增量：resolver 命中时读名字指针出 API 名（名字表在节内数据区/
  工作区）→ bail 前的最后几个调用 = 检查行为 → 对症补丁（时间 shim 或
  条件跳转翻转）→ .text 解密 → 快照抓解码后 calc（XP calc 公开可对账）
  → 重建产品。**devirt 不需要**——calc 从未被虚拟化。

## V2：运行时"副本"= 加壳文件的空拷贝；检查 hunt 改走 GetLocalTime 命中 dump（2026-10-29，未发布）

**副本追踪定案（4 轮重试 + 旧 run 对比）**：05:27 那次 run（Ancient 闸之前）
的 immediate scan 在 resolver 风暴末（15.571）抓到过 base 0x3690000 /
size 0x372000 / EP 0x371000 的"运行时副本"。离线分析 `CISC-1U21.raw.bin`：
**副本 = 加壳文件本身的内存拷贝**——PE 头逐字段相同（EP RVA 0x1000000
就是盘上文件的 EP，此前日志的 "Entry point RVA: 0x371000" 是另一处读法）、
段表同构（6 段、同名同 VA），但**大节（omxsqdds）全零、.rsrc 仍加密
（熵 7.61）**——壳从未往里解码任何东西。它是壳为原程序准备的**全新
分配**（风暴末才创建，晚于 GetLocalTime 检查调用），检查失败 → bail →
原程序永不落进副本。**对产品是红鲱鱼**；"壳解码进副本"的旧假设作废。

**采样频率教训**：旧 build 的 immediate scan 在**每次 resolver 命中**上跑
（无冷却），副本在风暴末出现的瞬间被抓住；新 build 的 watch scan 有
500ms 冷却，4 轮重试 ~70 次扫描全部错过（副本瞬态 <500ms）。两轮壳行为
完全一致（同样异常点 0x108b4ee/0x108b6ad、同样 ~24 线程爆发节奏、同样
GetLocalTime ret=0x107547e）——差异纯在采样频率。

**引擎代码瞬态明文 → 检查 hunt 仪器**：bail 快照里引擎代码已重新加密
（整镜像熵 ~7.9，只有 RVA 0x10000 与 0x370000 低熵），检查点（GetLocalTime
续址 RVA 0x7547e）在 bail 时不可读。但**命中瞬间代码是解码的**（正在执行）
——新 instrumentation：GetLocalTime 命中时全镜像 dump
（`<stem>.v2image_getlocaltime.bin`）+ resolver 命中时镜像内 continuation
的逐点 0x400B dump（`v2cont_{:03}.bin`，按调用序编号，上限 200）。
工作区 dump 全线皆零（壳 bail 前清零工作区）——名字表不可回收，
代码本身带比较常量（过期日期），走反汇编路线。

**修订（同日，`WinSta0` 隐藏桌面）**：把桌面建在 **`WinSta0` 上**（不建新
站，`CreateDesktopW` 在调用者当前站创建）得到中间态，比新建站好得多：

| 形态 | 存活 | 弹窗上屏 | 相位深度 |
|---|---|---|---|
| 交互桌面（默认） | ~50% 挂死 / 否则跑完 | **有** | 达 5.6 s |
| 新站 `MagicmidaV2Station` | **0.5 s exit 0** | 无 | 不过解码 |
| **`WinSta0` 隐藏桌面** | 12–60 s | **无（实测 0 窗）** | 仅 150–376 ms |

`WinSta0` 隐藏桌面是**唯一既能长时间存活、又不弹窗**的形态，适合安静批量
run；但 8 次 run 全部只到解码期（≤376 ms），**没有一次进入 license 相位**，
而交互桌面曾抓到 5.6 s。**要 license 相位的数据，目前只能交互桌面。**
CLI 默认值因此改为：V2 post-attach 下**默认隐藏桌面**（不打扰操作者），
需要相位数据时显式 `MAGICMIDA_INTERACTIVE_DESKTOP=1`。

## V2：mini-devirt 开工——VM 寻址与状态银行定位（2026-10-31，未发布）

**Step 1 落地（VMSNAP 序列快照）**：`MAGICMIDA_V2_VMSNAP[=<gate_ms>]` ——
检查窗口内首个池命中冻结主线程，dump 全镜像（3.6 MB）+ 栈 16 KB + 寄存器
原始 CONTEXT，然后**恢复执行**（单次 run 产出同一时间线的快照序列，上限
32 张；跨 run 快照时间线不对齐，第一次差分 5 张跨 run 快照全是噪声，
同 run 序列才有干净差分）。

**VM 寻址机制破译**：EBP = `0xEEDC0014`（每张快照同值）是**环绕基址**——
`[ebp + 0x122624E5]` 溢出 32 位落回镜像（0xEEDC0014 + 0x122624E5 mod 2^32
= 0x010224F9）。VM 的上下文/工作区/字节码**全部在镜像内的低 RVA**。快照
改为整镜像 dump 的依据。

**VM 状态银行定位（RVA 0x28580-0x285c0，64 B）**：14 张同时间线快照的差分
显示这 64 B **每步都变**，结构：
- 0x00-0x1F：常量（`91ae5efc ebe90b00 …`，全部快照相同）
- 0x20 起：每步变化——镜像内续址（0x010dcda9 等）、数据值、栈地址
  （0x000efeac ≈ 主线程栈 0xefe4c！）、**保存的 EBP**（RVA 0x285b4 处
  `1400dcee` = 0xEEDC0014 的 LE 字节，所有快照同位同值）
- 快照间栈槽的值序列 = 检查的控制流路径（续址链）

**注册表路径构造**：RVA 0x21a00 附近出现 `\Registry\Machine\SOFTWARE…`
分片字符串——检查在构建注册表路径（授权状态/指纹数据的存取）。

**Step 2 完成（同日）——状态银行字段图（字节级稳定图）**：
- 0x28580-0x2859D（30B）：**恒定 VM 钥匙** `91ae5efc ebe90b00…`
- 0x285A0-0x285B1：**两条续址链**（镜像地址，每步变）
  - 终态（快照 14，对话框前）：`0xffffa595 / 0x01182519 / 0x0117e9ef` =
    **trap 场景 bail 链地址**——快照 13→14 之间 VM 从检查流切入 bail 路径，
    转换瞬间被捕获。bail 地址（0x1176xxx/0x117d896/0x1182519）在转换时被
    写入低数据区多个槽（0x200c0/0x20180/0x20200 全见到）。
- 0x285B4-0x285B7：**VM 数据指针**——高半字 0xEEDC 恒定、低半字每步变
  （0xDF63→0x0B5D→0x3EB9→0x0000）；与 EBP 的环绕常量**不同**
  （EBP 常量 0x1123FFEC 对它不成立），目标区尚未定位。
- 0x285B8-0x285BB：opcode/handler 序号（0x112/0x115/0x116/0x354…）
- 0x285BC-0x285BF：flags（0x20/0x0220）
- 0x285AC 反复出现 **0x0000000e = 14** = 指纹字节数（8 WORD），VM 在
  14 字节粒度上操作指纹数据。

**指纹值三形态全负 + 工作区未映射**：14 张快照全镜像搜索
1051-BCEC-…（16B LE / 8B 双端序片段 / ASCII）全空；快照里无 WKSP 段
（0x12200000 在检查时 MEM_FREE）。**比较是哈希式或逐字节瞬态解密的，
指纹从未整体落进可扫描内存。**

**bank-kill（2026-10-31，弹窗的最终解）**：dialog-killer（EnumWindows 轮询）
只能在弹窗出现后压帧；银行 bail 签名（RVA 0x285B4 起 8 字节
`19 25 18 01 ef e9 17 01` = 两条 fail 续址）**先于 MessageBox 创建**——
RPM 轮询该签名（5ms，无挂起）、命中即终止 = 弹窗从未存在。已实现
（`spawn_dialog_killer` 重写，窗口枚举删除）。4 次验证 run 全是停车型
（签名未出现即无弹窗，静默）——完成型 run 的零弹窗验证待停车潮解除。

**停车点精确定性 + 唤醒实验（2026-10-31）**：syscall 读数更正——停车桩
RVA 0x1230 的 syscall 是 **0x1100a = NtUserWaitMessage**（此前漏一位误读
0x110a；win32u 导出表实测：NtUserGetMessage=0x1004、NtUserWaitMessage=
0x1100a）。WaitMessage = **等线程消息**的 API（无窗口线程专用）。
- 唤醒实验（`MAGICMIDA_V2_WAKE=1`，PostThreadMessage WM_TIMER/WM_NULL
  每 200ms）：线程确实被周期唤醒（WaitMessage 返回→重新等待），但壳无
  进展——**它在等特定的消息**（worker 完成检查后的结果消息），不是任意
  消息。消息猜测路线（WM_USER 扫描）风险大于收益，搁置。
- 数据指针环绕常量的静态推导失败（0xEEDB0000+RVA 假设与差分区不完全
  吻合）——银行的访问是动态计算，继续指向指令级分析。

**停车潮与鼠标 wiggle 实验（2026-10-31 深夜）**：今晚交互桌面停车率
~100%（对照：无 banktrace 也全停车——RPM 追踪非扰动源）。合成鼠标移动
（mouse_event MOVE，300 次/3s）不解除停车，且产生**新退出码 1**（非
0/2/143）+ 主线程全程在 KERNELBASE 一带（非镜像非 win32u）+ 银行静止于
非检查态——合成输入把壳引向了另一分支。停车触发器仍未定位（桌面活动？
DWM 状态？会话年龄？），完成型 run 的出现条件是 mini-devirt 剩余的
唯一环境依赖。

**Step 3 首轮（同日）——指针格式与静态搜索的边界**：
- 数据指针槽（0x285B4）以**字节交换形态**存储：槽 LE 值 `0x0023eedc` 对
  EBP 家族（0xEEDC0014 = 0xEEDC0000 | 0x0014）；指针 = `0xEEDC0000 | offset`
  （offset 每步变：0x63df/0x0b5d/0x3eb9/0x0000）。EBP = 基 | 0x14。
- EBP 环绕常量**二次验证**：`[ebp+0x122624E5]` → RVA 0x24F9，即
  disp = RVA + 0x1225FFEC（EBP = -0x1225FFEC mod 2^32）。
- **银行无静态引用**：以 disp 原值（0x122885xx 段）与 data-space 值
  （0xEEDB0000+RVA / 0xEEDC0014+RVA / 0xEEDC0000+RVA）三种形态搜索全镜像
  全部零命中——银行地址由 VM **动态计算**（基址 + 累计偏移），这是混淆
  核心；静态分析到此为止，下一步必须指令级（解释器块全反汇编）或
  1ms 终态采样。
- VM 钥匙常量（银行前 30B）全镜像仅出现 1 次 = 其自身位置。

## V2：license 检查 = VM 虚拟化（主项目当前边界，2026-10-30，未发布）

**快跑形态（sleep 修复后的重大变化）**：整个壳生命周期在 **1 秒内**完成——
解码 ~0.4 s → license 检查 ~0.4 s → CALC 对话框 ~1 s。旧测的 15-22 s 全是
忙转扰动时代的数字。每次实验的壳时间成本从 20 s+ 降到 1 s。

**本轮机器（全部落地并验证）**：
- **dialog-killer**（`MAGICMIDA_V2_DIALOG_KILL=1`）：50 ms 轮询
  `EnumWindows`，发现目标的 `#32770` 即 `TerminateProcess`——交互桌面
  license 狩猎时弹窗可见 ≤1-2 帧；相位样本靠周期落盘幸存。回调提升为模块
  级 `extern "system" fn`（`WNDENUMPROC::Some(inline fn)` 语法不可用）。
- **worker 轮转采样**：post-attach 看不到 CREATE_THREAD 事件，worker 对
  调试器不可见——`list_target_thread_ids`（ToolHelp）+
  `sample_worker_rip`（OpenThread 直采）。每 tick 主线程 + 4 个 worker
  轮转。样本结构扩为 (t_ms, rip, tid, 64B)。
- **指纹狩猎**（`MAGICMIDA_V2_FPHUNT=1`）：VirtualQueryEx 走查全部已提交
  内存（64 MB/tick 上限），搜 `BCEC-14F2`（ASCII/UTF-16/LE 二进制三形态）。
  命中即冻结 + dump 256 KB 邻域 + 全场景 + 终止（弹窗前完成）。
  windows-0.58 的 `GetThreadContext`-族签名是泛型（`P0: Param<HWND>` +
  `Option<*mut u32>`），与 0.48 不同。

**决定性负结果 ×2**：
1. **指纹串从不以可扫描形态存在**（ASCII/UTF-16/二进制三形态 × 25 ms 扫描
   全空）——检查比较的可能是哈希，或串只在对话框格式化的瞬间存在。
2. **检查是 VM 虚拟化的**：K6 捕获（5 ms 密度，覆盖 5-455 ms 全生命周期）
   的最后 10 个池样本全是 VM 解释器的变异块（`jmp` 链 + 变异指令 + EBP
   相对工作区寻址），无原生比较逻辑。**决策在字节码里，catch-and-patch
   需要先重建 VM 上下文（寄存器银行/PC/handler 表）= mini-devirt。**

**当前边界**：license 检查通过 → `.text` 才解密（实测 bail 时 `.text`
仍加密）。检查在 VM 里 = 三条路：**A.** mini-devirt 这个检查（重建 VM
上下文——工程量大但有界，只此一个检查）；**B.** 假造硬件指纹输入（API
补丁被完整性检查封死）；**C.** 接受边界（授权保护按设计工作）。主项目
的 V2 线在 A/C 之间待用户决策。

## V2：隔离桌面停掉 CALC 弹窗，但壳随即放弃检查（2026-10-30，未发布）

**动机**：V2 样本在 license 检查失败时弹「CALC」硬件锁对话框，弹在当前
用户交互桌面上——每次 attempt 一次，重试循环变成**弹窗风暴**，干扰操作者。

**实现**：`CreateProcessOptions.isolated_desktop` →
`create_isolated_desktop()` 建 `MagicmidaV2Station` / `MagicmidaV2Desktop`
（`CreateWindowStationW` + `CreateDesktopW`），`STARTUPINFOW::lpDesktop`
注入 `"station\\desktop"`。CLI 在 post-attach 下默认开，env
`MAGICMIDA_NO_ISOLATED_DESKTOP=1` 可关。
两个 Windows 0.58 特有的坑：① `DESKTOP_ALL_ACCESS`/`WINSTA_ALL_ACCESS`
**不在 crate 里**（用 winuser.h 字面值 `0x000F_01FF` / `0x000F_037F`）；
② `CreateDesktopW` 的 **`lpszDevice` 必须 NULL**——第一次错传了桌面名，
返回 `0x80070057`（ERROR_INVALID_PARAMETER），修后成功。

**结果（诚实的负结果）**：弹窗**确实不再上屏**（交互桌面 `EnumWindows`
按 PID 过滤为 0 个窗口），但壳的行为整个变了：

| 桌面 | 行为（同一 exe，各 3+ 次） | 弹窗 |
|---|---|---|
| 交互 | ~50% 挂死在 `win32u!NtBindCompositionSurface`；否则 license | **有** |
| 隔离 | **稳定 0.5 s exit 0**，连解码期都不过 | 无 |

`exit_code=0` 且**无 v2phase 文件** = 壳在隔离桌面上直接放弃，根本没跑到
license 相位。**结论：隔离桌面解决了弹窗，但毁掉了被测行为；此形态下不能
用来推进 V2。** 保留实现（它是唯一能保证不打扰操作者的开关），V2 实跑仍需
交互桌面 + 人工在场。

**顺带确定的一条**：交互桌面下的停车由壳自身随机分支决定，与
`CREATE_SUSPENDED`/PEB 补丁/本仓轮询无关——纯 `CreateProcessW` 最小启动器
（`OUT/vmp_launcher/launch_test.ps1`，不含本仓任何代码）两种 flag 组合都
40 s 仍活着、CPU 0.3 s、29 线程。

## V2：采样窗盲区（RIPSAMPLE 从 t=15s 才加密）+ 停车是壳自身行为（2026-10-30 重启后，未发布）

**缺陷：RIPSAMPLE 的 tick 收紧门控在 15 s，系统性错过镜像执行窗。**
主线程第一次穿过引擎池只有 **150-370 ms 宽**（实测：相位录制器 20 个样本，
`CISC-1U60.v2phase.bin`），而默认 tick 是 500 ms —— 一个都采不到。
**三个 run 各 1000 样本全部 `image samples=0`**，一度被读成"主线程从未执行
镜像代码"。修：`rip_sample_on` 下 tick **从 t=0 起就是 50 ms**（不再等 15 s）。
验证：同一命令改后 `image samples=5`，窗口 0.12–0.32 s。**教训：采样密度必须
匹配被测窗口宽度；把一个"窗口很窄"的事实读成"从未发生"，是测量设计错误。**

**停车 = 壳自身行为，与本仓管线无关（判别实验）**：重启后仍停车，于是做了
最小启动器对照（`OUT/vmp_launcher/launch_test.ps1`，纯 Win32
CreateProcess，不含本仓任何代码）：
- `plain`（无 flag）→ **40 s 仍活着**，CPU 0.34 s、29 线程；
- `suspend`（CREATE_SUSPENDED + Resume）→ 同样 40 s 活着，CPU 0.31 s。

即**裸 CreateProcess 一样停车**，与 `CREATE_SUSPENDED` / PEB 补丁 / 我们的
轮询都无关。同一 exe 同一 shell 启动方式连跑三次：**2 次 exit 2、1 次挂死**
——壳在无交互条件下的随机分支，不是确定可复现的阻塞。

**停车点定案**：主线程 EIP = `win32u.dll+0x123c`，该字节是 syscall stub 的
`ret`；其 syscall **`0x110a`** 的 stub RVA `0x2230`，**正是导出
`NtBindCompositionSurface` 的入口**（DWM 合成绑定）。全进程 29 线程零 CPU、
无 socket、worker 全在 ntdll 等待桩。窗口枚举：`#32770`/标题 CALC 的对话框
**时有时无**（同一次 45 s 采样里两次枚举结果不同），点掉它进程也不恢复
——**说明主线程等的不是这个对话框**，对话框是伴生现象。

**结论与下一步**：V2 推进需要"跑完 license 相位"的成功 run，而壳在无人值守
条件下约 1/3~1/2 概率停在 GUI 合成等待。可行手段是既定重试循环（
memory 第 5 条），成功判据用相位文件大小而非退出码。桌面会话有真实交互
（人在机器前）时成功率更高——这是环境属性，不是代码缺陷。

## VMProtect：stub 误报 6→50，及"导出字节是密文时不得下结论"（2026-10-30，未发布）

**样本**：`E:\Download\启动器10.9\vcomp140.dll`（12,782,080 B，sha256
`c6bc91f1…`）——启动器家族 `启动器10.9.exe`（`804fd7c1…`，与
`D:\Projects\zz_test.exe` 逐字节同）的**解码载荷明文版**。它伪装成 MSVC
OpenMP 运行库（正版 System32 只有 193,152 B，它是 66 倍），pefile 实读
导出表名为 `vcomp140.dll`，60 个导出**全部无名称纯序号**，5 个导入全是
敏感 API（`WriteProcessMemory`/`SendInput`/`GetPixel`/`RegOpenKeyExW`/
`WinHttpReceiveResponse`）。

**缺陷①：`/analyze` 报 6 个虚拟化 stub，真值 50。** 根因是
`trampolines()` 只排除 `is_not_paged` 段；样本的 `.rdata0`（6.4 MiB 变异
VM 码，特征 `0x60000020`）不满足 `is_not_paged`，于是被当**普通代码**线性
反汇编（实测解出 1,674,701 条指令，绝大多数是噪声），其零散 `jmp` 落进
`.rdata2` 就被计成 trampoline。6 个地址逐个反汇编确认是 `jmp` 接垃圾。

修法两层：**（a）** `is_vm_carrier(sec, image)` = 可执行 && 熵 ≥ 7.1
（实测 `.rdata0`/`.rdata2` 7.35，同文件真代码 `.text` 6.97），
`trampolines()` 跳过载体段；**（b）** 新增 **字节特征码**计数
`vm_stubs()`，扫描 x64 stub 序言 `41 52 9C 49 BA`
（`push r10; pushfq; movabs r10, imm64`）。真值 50 =
`.rdata0` 45 + `.rdata2` 4 + `.text` 1，与 Python 独立测量逐项一致。
`/analyze` 现分两行输出（`vm stubs (sig)` / `jmp trampolines`），不再混用。

**缺陷②（新发现，比①重要）：打包态下"0/17 virtualised"是假结论。**
加了导出覆盖率后，`启动器10.9.exe`（Packed、`.text` 无文件字节）报出
`0/17 virtualised`——但那些导出 RVAs 指向**加密载体**，解码的是密文，
"0 个虚拟化"是假阳性结论。修：`ExportCoverage.in_encrypted_carrier` +
`meaningful()`，非明码时改报
`17 exports, 16 in encrypted carriers — UNDETERMINED`。**规则钉死：
静态判定只在字节处于明文的段上做；密文上量出来的数只能标 UNDETERMINED。**

**交叉验证**：Rust `0/58 virtualised` 与 C 探针
`EXPORT_PROLOGUE ok=60 bad_rva=0 bad_first_byte=0 jmp_rel32=3
jmp_into_vm=0` 一致——3 个 `E9` 首字节的导出目标全在 `.text` 内
（0x13dc0 / 0x8b40 / 0x14000），**没有一个跳进 VM 区**。只数裸 `E9` 会
误导，必须分类落点。探针 `vmp_load_probe_v2.exe` 为此新增
`jmp_into_vm` 计数。

**同一文件的续期测量（补正上一轮的错数）**：上轮报"`.text` 514 条指令"
是 capstone 遇无效字节即停的产物；开 `skipdata` 后真值是 **40,864 条**。
结论未翻转：`.text` 仍**零处**引用 stub（`.rdata0` 167 万条里 10 处、
`.rdata2` 150 万条里 1 处）。

**保护边界（本样本定案）**：50 个 stub 全部在导出范围之外（导出 RVA
0x1740–0x15cd0，stub 首达 0x50e7 但**无一个是导出入口**）；58 个唯一导出
RVA **0 个**以 VM `jmp` 开头。**功能面 100% 原生明文，VM 只锁初始化/校验。**

**运行时不加密（新增测量）**：把该 DLL 载入进程后逐段与磁盘对比——熵
`.rdata0` 7.35→7.35、`.rdata2` 7.35→7.35，变化字节仅 3901 / 116 个；
`.fptable` 磁盘全零 → 运行时 18 非零字节（跳表运行时构建）。**VM 字节码
全生命周期无明文时刻**，这是"完全明码"不可达的实证依据。

## V2：post-attach 忙转缺陷 + 对话框停车定案（2026-10-30 深夜，未发布）

**真缺陷：post-attach 轮询从不等待（忙转 2 kHz）**——`WaitForDebugEvent`
对无端口进程**立即**返回 ERROR_INVALID_HANDLE，映射成 Timeout 后调用方的
"500 ms 轮询"实为全速空转（实测每秒数千次 tick，一个核 100%）。所有采样
模式（RIPSAMPLE/RECORD/FREEZE）因此变成每秒数千次 `SuspendThread` 风暴；
此前把三连挂归因"采样扰动""环境负载"各错一轮。修：post-attach 的
Timeout 映射处真 `sleep(timeout_ms)`（wait_event 无参版补 100 ms）。
**教训：把一个"立即返回的错误"映射成"超时"时，超时的语义（消耗时间）
必须由映射方补齐。**

**停车 run = 对话框在等点击（不是挂死）**：晚间的 run 亚秒级跑完
license 相位（比下午的 21.7 s 快得多），弹出硬件锁对话框后**全线程停车
等 OK**——主线程 win32u（GUI 系统调用）、全部 worker ntdll 等待桩、
零 CPU、无 socket。窗口枚举实锤：`#32770` 类、标题 CALC、**可见**。
下午与晚间的差异是壳走了不同分支（下午：解码 → 硬件锁失败；晚间：
跳过解码 → 直达 trial-nag 分支——场景代码里有 "This is a …tion"
字符串解密立即数），触发器未定位。

**会话级停滞排查 10 连排除**（裸跑也挂、换路径拷贝也挂 = 全局状态）：
机器负载、采样扰动、锁屏（截图验证桌面活跃）、注册表（键名+值双 diff
零变化）、socket（netstat 空）、TSF/输入服务重启、GDI/桌面堆（大户
explorer 187 句柄，正常）、僵尸进程（无）、路径派生命名对象（换名照挂）、
WeType 全家重启（照挂）。**剩余杠杆：重启/注销登录会话**（04:30 由
用户侧决定）。

**机器增量**：bail 场景新增**全线程停车图**（ToolHelp 线程快照 +
OpenThread 逐个 SuspendThread/GetThreadContext，主线程已挂起时挂起计数
平衡）；RIPSAMPLE 轨迹每 200 样本周期落盘（被杀不丢）；RECORD_PHASE
周期落盘阈值 1000→100（license 相位只有 ~40 样本量）；**陈旧上下文探针
移除**——`GetThreadContext` 不挂起时返回内核上次保存的上下文，对
CPU 密集线程永不刷新（实测探针只在前 0.5 s 触发，解码一开跑就全盲）；
真实 20 Hz 挂起采样替代（开销 ~0.1%）。

## V2：post-attach 打通 + 硬件锁定案（2026-10-30，未发布）

**post-attach 移植成功（上游 magicmida vNext 模式）**：V2 样本改走
`CreateProcess(CREATE_SUSPENDED)` **不带** `DEBUG_ONLY_THIS_PROCESS` ——
无调试端口从 t=0 存在。`WindowsDebugger::new` 里挂起态补 PEB，
`resume_post_attach_main_thread` 恢复主线程；`WaitForDebugEvent` 对无端口
进程返回 ERROR_INVALID_HANDLE → post-attach 下映射为 Timeout（轮询形态）。
**实测：零 AccessViolation** —— 上游 C-8（attach 即触发反调试、.text 拒解）
被整体绕过。退出检测用 `GetExitCodeProcess`（Timeout 分支），exit 2 干净
检出，不再挂死。附赠发现：`SuspendThread + GetThreadContext +
ReadProcessMemory` 在无端口进程上全部可用 = 完整外部观测能力。

**exit 2 = 硬件锁拒绝，不是 eval 过期（截图实锤，eval-expiry 假设死亡）**：
桌面截图抓到「CALC」对话框——"The current key has been locked to a
different machine. 1051-BCEC-14F2-0C16-3748-5E66-5E6D-2536" + 确定按钮。
样本是 LCF-AT 的**授权版**，key 锁在他机器的硬件指纹上；本机指纹不匹配 →
对话框（1-2 s 自动关）→ ExitProcess(2)。全部时间 shim 实验对"决定"无效
——决定在比较指纹，不在读时间。2026-10-29 的"WinLicense eval 过期"解释
正式作废。

**license 相位定案（RIPSAMPLE 轨迹）**：unpatched 跑 9-211 s（方差极大，
疑似网络形等待 + 机器负载）；相位本体在 **t=21.7-22.4 s，引擎池
RVA 0x29000-0x3c000**，最后调用 GetLocalTime（0x7747d580+0x185）后线程
进入 **wetype_tip_core.dll**（0x62f10000，4.7 MB——对话框窗口创建触发
TSF/WeType 注入，CrashRpt1500/d2d1/input.dll/MSCTF/OLEACC 全套随行），
消息循环跑完即退出，镜像引擎页全部再加密（熵 7.7-7.9）。

**系统 DLL 补丁 = 秒级死刑（完整性检查实测）**：
- kernelbase!GetLocalTime/GetSystemTime 补假日期 stub → fake 2000-06-15
  bail 14 s、fake **当天** bail 4 s——值无关，补丁本身被检；
- kernelbase/kernel32/ntdll 的 ExitProcess `jmp $` 陷阱 → bail 提前到
  22 s（完整性与 license 共用 bail 链，场景抓到调用链
  rva 0xe35a3→0xe03b8→0xb7551/0xb754d→0xe3247→0xa4135→0x21fff→0x964f9，
  引擎页执行时明文、落盘时已再加密）。
  **结论：任何代码补丁都必须避开系统 DLL；壳自己的引擎池块是剩余目标**
  （块用完即再加密，需 catch-and-patch：探针发现块在执行 → 挂起 → 补丁
  → 恢复）。

**shim 三形状失败根因更正（2026-10-29 的"自修改块"结论推翻）**：旧
FAKE_WRITER 三个真 bug——①年份立即数字节转置（0xD007=53255，非 2008）；
②`add esp,4; ret` 弹出的是**实参值** → EIP=SYSTEMTIME 缓冲区
（0x1075404）→ 1024 次 AV 循环——"检查块自修改"从未存在，AV 是自己
stub 的返回路径；③用 EDI（callee-saved）做指针践踏壳状态。已修
（EAX + `ret 4`）。教训钉死：**x86 stdcall stub 的返回要么 `ret n`，
要么先弹出返回址再跳；写完必查 内存布局 逐字段对 SYSTEMTIME**。

**本轮落地机器（全部 env 门控，默认零行为变化；x86 门控）**：
- `MAGICMIDA_V2_FAKE_TIME=1|YYYY-MM-DD`——kernelbase 时间 API 假日期
  （已证被完整性检查拒绝，保留作判别工具）；
- `MAGICMIDA_V2_TRAP_EXIT=1|<secs>`——ExitProcess `jmp $` 陷阱 +
  bail 场景 dump（寄存器/栈/返回址代码/检查块/模块清单）；延迟武装
  （`=<secs>`）躲早期完整性检查；
- `MAGICMIDA_V2_FREEZE_RVA=<lo>-<hi>`——RIP 入区即挂起 + 全场景 dump
  （≥0x400000 的值按绝对地址解释）——**无补丁、完整性不可见**；
- `MAGICMIDA_V2_RIPSAMPLE=1`——50 ms 轨迹采样（区域变化 + 尾部栈）；
- `MAGICMIDA_V2_RECORD_PHASE=<secs>`——两级采样：免挂起陈旧上下文探针
  （GetThreadContext on running thread，零扰动）触发 → 2 s @5 ms 突发
  （挂起 + RIP 处 64 B 明文代码），池命中即录，每 1000 样本落盘。
  **教训：平坦 5 ms 采样从头挂到尾的三连挂起初判为采样扰动，后经
  零扰动探针仍挂证伪——是壳自身的等待方差（负载/网络），采样无罪。**

**下一增量**：相位录制（RECORD_PHASE）抓决策分支明文 → capstone 反汇编
→ 定位指纹比较 → catch-and-patch（freeze + 改分支/操作数 + 恢复）。
风险已知：引擎池块完整性自检未知；对话框前的窗口只有亚秒级。

## V2：检查点 = 壳自修改块；shim 两条路线实测（2026-10-29，已被上节更正）

**检查点定位（GetLocalTime 命中 dump）**：壳的检查在镜像 RVA 0x75404 附近
调用 GetLocalTime——ret=0x107547e（thunk 区 push），SYSTEMTIME 缓冲区
st=0x1075404；同一次解码期还有第二次调用（ret=0x110871c / st=0x11038e7）。

**壳的自修改设计（shim 实测暴露）**：SYSTEMTIME 缓冲区 = **检查代码自己的
块**——壳把检查块解码进镜像大节，GetLocalTime 把 SYSTEMTIME 写进该块
（覆盖检查代码），块用完即弃、下次再解码。证据：补丁式 shim（API 首字节
改 ret）在写假日期后，壳的**指令地址 0x1075404**（= 缓冲区地址）读
0xffffffff → AccessViolation 循环 1024 次 → 管线 FATAL（stuck loop）。
跳过式 shim（esp+=8, rip=ret）不写缓冲区，但破坏壳解析器状态 →
154 次垃圾 ret（0x62d81111）循环后 bail exit 2。

**引擎代码不可离线读**：GetLocalTime 命中时工作区 2MB dump **pages_ok=0**
（全部读失败）——引擎区 execute-only 或已搬走；bail 时工作区全零（壳清零）；
bail 快照里引擎代码已重新加密（整镜像熵 ~7.9）。检查代码（比较常量 =
过期日期）三条采集路线全部不可达。

**结论**：检查 hunt 的下一步不是继续 shim（壳的自修改设计让任何写缓冲区
的 shim 都摧毁检查代码），而是**在 API 层做假日期注入的第三种形状**——
让 API 自己把假 SYSTEMTIME 写进缓冲区（补丁 API 的写入指令，而非外部
write_memory），或直接找检查的比较常量（需要先解决引擎区读取）。

**引擎区诊断（2026-10-29 第三轮）**：GetLocalTime 命中时对工作区做
VirtualQueryEx + 直接探针读——
- **工作区 0x12200000-0x12400000 命中时是 MEM_FREE + PAGE_NOACCESS**——
  壳把工作区**释放**了（churn 的另一半：用时分配、用完释放）。
- **引擎续址 0x122b6057/0x122b5474 全部 unmapped**（读失败）——引擎代码
  搬走了，固定地址 dump 时机全错。
- **检查块 0x1075404（镜像 RVA 0x75404）可读但全零**——检查代码此刻不
  在那儿；壳的检查代码随引擎代码一起在 churn 的内存里。
- 推论：检查 hunt 需要**实时追踪引擎代码位置**（VirtualQueryEx 全空间走
  查 committed RX 区找引擎块），而不是固定地址 dump；shim 路线（三种形状）
  全部被"缓冲区=检查块"的自修改设计封死。

## V2 (SecureEngine 2.x) 战役：历史小节（均已推翻，仅供追溯）

**"载荷区探测 + 诚实收束"（2026-10-28）**：A/B 定责壳方差大、hang 非管线
导致；当时结论"V2 载荷不物化 PE 映像"。
**"PE 找到 + dump + 离线重建"（2026-10-28）**：声称模块 PE scan 在 0x50c0000
找到载荷 PE（v2raw026.bin），导入表被 scrub、IAT 外置 0x5804e000、.reloc
XOR 编码——**全部是 dd[0]/dd[1] 假阳性 + 错误基址归因的产物**，见上节铁证
清单。载荷区探测机器（`try_exit_dump`/`v2_watch`/CreateThread handler）
保留。

## 环境突变：组织 Device Guard 策略封掉样本语料（2026-10-29，环境回归）

今日 ~02:06 UTC（约 10:06 本地）起，本机的**组织 Device Guard 策略**开始
阻止受保护样本语料的进程创建：
- CISC-1.exe 裸跑与管线 CreateProcessW 均 `0x8007109A`（"应用程序控制策略
  已阻止此文件"；cmd 直跑报"已被组织的 Device Guard 策略阻止"）。
- UnPackMe_Themida 1.9.1.0 同命。
- **我们的工具/测试二进制全部放行**（mida-cli x64/x86、各 gate 测试二进制、
  golden_product.exe 实测运行）；被堵的只是 crackme 语料本身（哈希/信誉级，
  非路径级——Temp 拷贝同样被堵）。
- 连带：三个 e2e gate 的 debuggee 是受保护样本 → DLL/EXE gate 现红（管线
  在创建 debuggee 处失败，非哈希漂移）；x86 gate 同。默认单元套件
  （413 passed / 0 failed）不受影响。
- 瞬态：vmprotect_packed_gate 有一次 os error 4551（cargo spawn 被堵），
  直接执行与随后 cargo test 复跑均正常——策略部署中的瞬态。

**波及**：V2 线的全部实跑（bailtrace 重试循环、镜像快照）与经典线样本的
实跑在策略解除前无法进行。离线资产全部在（bail 镜像、127 个解析器调用
点、WeType 判定、XP calc 定案）。**V2 实跑战役暂停，等待策略放行**。
策略归属组织，解封路径需用户侧决定。

## V2 路线甲：银行解剖 + fail-freeze 机器（2026-11-01，未发布）

mini-devirt 路线甲（解释器块全反汇编）的全离线战果 + 一件新实跑机器。
全部在既有语料上完成（31 个 phase 捕获 824 样本、20 个 vmsnap、27 个
banktrace），仅 4 次验证 run，零弹窗（bank-kill 全程兜底）。

**① "解释器" = 原生混淆块，不是字节码取指环**。每个 EIP 处都是
`push imm; mov [esp],reg; jmp 下一块` 形式的混淆原生码 + `pop esp` 栈旋转
（snap_001 链尾在 0xefeb4 于 VM 栈上执行 `loopne` 自旋 = 延时环真实存在）。
指令词汇：push/pop/mov/xchg/add/sub/xor/shl/lea/jmp + pushad/popad/lodsb
（0x10288d1 的 lodsb = 真字节码取指点，esi = VM 程序计数器）+ 16/32 位
混合 push/pop（66 前缀，esp 步长 2/4 混用——模拟器最初在这里全错位）。

**② 状态银行字段图（64 B @ RVA 0x28580，banktrace u32 解剖）**：
- +0x00..+0x1B：常量 VM key（28 B，全 run 不变）
- +0x1E：**continuation A**（code VA；检查期间在微派发区 0x1021a1c-0x1021a5b
  循环；bail 时变 0xFFFFA595）
- +0x22：**continuation B**（code VA；检查期间 0x10dcd5x 一带轮换）
- +0x2A：VM 栈指针（0xefe78-0xefeb4，与快照真实 esp 吻合；bail 后被
  0x9eee18eb 破坏）
- +0x32：EBP 锚（0xEEDC0014，恒定）
- +0x36/+0x3A：c2（旋转值流：56f9b8c4→6f9b8c45→b8c456f9，密钥流）与
  opcode index（0x202/0x206/0x246/0x286/0x282/0xa12）
- **银行访问走 VM 栈，不走 ebp 相对**：全空间指针狩猎只在栈上找到银行
  字段地址（bank+0x22/bank+0x1e 被当值推栈），零 ebp 相对命中——VM 把
  esp 旋转进银行后用 push/pop 读写。27 个 VMCTX 目标（0x201fd 计数器、
  0x22cf5 等）是 VM 寄存器堆。

**③ 失败分支机制（本轮最大定案）**：
- **判定发生在 t≈401 ms，每次 run 都一样**（Y1test 全程 banktrace +
  H6 + S1_014 三方一致）——此前"license 相位 t=21.7 s"量的是判定后的
  余留（弹窗/停车），不是检查本身。停车 run 也已走完全部检查。
- fail write = 银行写入失败路径续延对 (0x01182519, 0x0117e9ef)（瞬态
  1-2 ms），稳定态散落为 +0x2e=0x0117e9ef、+0x36=0x01182522；
  contA=0xFFFFA595（负计数器）。
- **可靠的 bail 标记 = contA==0xFFFFA595**（三个独立观测全出现、稳定态
  持存）；连续 8 字节签名只在瞬态存在，5 ms 轮询约 60% 概率错过
  （Y1test 实测 kill 未触发）。
- fail 处理器区域 = 0x1182436/0x1182519/0x117e9ef（IMG-HI，池窗外）；
  bail 链帧序 0xe35a3→0xe03b8→0xb7551/0xb754d→0xe3247→0xa4135→0x21fff
  →0x964f9 与 ExitProcess 陷阱场景逐项吻合；VM 栈帧 = {续延对, EBP 锚,
  保存的 vmsp} 三元组（0x20 步距），failfreeze 栈上新帧对
  (0x01182523, 0x010208a9)。

**④ 新机器（全部 env 门控，x86 门控，默认零变化）**：
- `MAGICMIDA_V2_FAILFREEZE=1`：bank-kill 升级版——1 ms RPM 轮询银行，
  标记命中 → ToolHelp 枚举全部线程挂起 → 自包含 dump（CTX×N/BANK/
  STCK 0xefd00+0x3000/CTXM 0x1020000+0x8000/IMAG 全镜像）→ 终止。
  实测 Y2test：28 线程、3.67 MB、判定后 ~1-2 ms 冻结、零弹窗。
  （两个实现坑：ToolHelp 线程过滤必须用 pid 不能用 HANDLE 截断；
  Python 改写的源文件 mtime 不触发 cargo 重编——touch 后新代码才进
  二进制，第一轮 FAILSNAP/banktrace 验证全部跑在旧代码上。）
- banktrace 全程化：1 ms × 1000 条（解码期）后转 5 ms 直到 60k 条
  （旧 1000 条上限只覆盖前 2 s，license 判定从未被录过）；
  刷盘每 1000 条（防 O(n²) 全量重写）。
- `MAGICMIDA_V2_FAILSNAP=1`：VMSNAP 门换区域到失败处理器
  (0x117E000-0x1183000)。
- vm_snapshot_tick 栈窗改 [esp-0x4000, esp+0x4000)（STCK 段地址记录
  读取起点）：旧抓法只抓 esp 上方，VM 弹栈复用模式引用的 esp 下方
  数据缺失——离线模拟器每条链都死在这上面。
- bank-kill：全银行扫签名（位置漂移实测）+ contA 标记 + 1 ms 轮询。

**⑤ 离线模拟器（OUT/v2_emu.py）**：子集 x86 解释器（~40 条指令白名单 +
真实 vmsnap 状态），代码源 = 同 run phase 库 ∪ 快照 EIP 块 ∪ 19 个 IMAG
并集（明文校验）。链长 100-300 条常规、snap_010 达 53k 条；未映射读改
记 0 继续后仍止于数据墙 = esp 下方栈字节（已由 ④ 修掉下次 run 的采集）。
**⑥ 快车教训：`-o` 绝对 Windows 路径在本机管线报 os error 3（快照写出
失败连坐 banktrace 全空），相对 Windows 形式（`OUT\X.exe`）必成**——
与旧记录"-o 必须 C:\ 形式"相反，以本轮为准。

**下一增量（数据已就绪）**：fail-freeze 场景里比较的两 operand
（算出的指纹哈希 vs 存储哈希）在判定前 ~2 ms 才物质化。两条路：
(a) PRE-fail 冻结——把 FAILFREEZE 的触发条件改成"bank opidx 进入
0x246 且 contB==0x0110344f（fail 前最后状态）"提前 ~2 ms 挂起，全场景
dump 出来直接读 VM 栈/VMCTX 上的两个操作数；(b) S1_001-013（判定前
快照）栈上找重复 14 B 窗口（本轮 342 命中里 0xf2xxx 全是模板重复，
0xefe8e 的帧对是已知结构——需要按帧结构过滤再缩小）。operand 定位后
= 把存储哈希补丁成本机指纹哈希 → 检查合法通过 → VM 自己走 pass 路径
→ .text 解密 → OEP → 产物。

## V2 比较操作数战役：HASHPATCH / PREFREEZE / µs 状态环（2026-11-01 续，未发布）

上一节的「下一增量」当轮执行完。4 个新 env 门 + 两个新 dump 形态，5 次
实验 run（Y4-Y7test，全部零弹窗）。

**① 两个比较 operand 定案（跨 run 逐字节验证）**：
- **本机指纹哈希 = `50 fc 39 64 05 31 66 a5`**（8B）——判定瞬间写入
  0x98 填充槽 RVA 0x224ED；S1_014 与 Y2test 两次独立 run 相同 = 机器
  派生确定性。全语料搜索：**除 0x224ED 外无副本**（直接算进槽，从
  不在别处物质化）。
- **存储 blob = RVA 0x2056F 起 40B**（`2e 15 77 e5 1f ef 05 b3 …`，全部
  快照全部 run 恒定，post-decode 才物化）；数据指针在比较前恰好停在
  它的头部 0x20568（banktrace t=371）。0x20560 的 `4a 19 00 00` =
  头部（0x194a）。
- 数据指针解码更正：**字交换**不是字节交换（`0x0023EEDC` ↔
  `0xEEDC0023`；槽 LE 值低 16 位 = 指针高 16 位）。轨迹显示 0x2B92A
  = 比较循环的**代码**窗口（判定前访问 5 次），0x25Bxx/0x25Cxx =
  顺序推进的代码块。

**② HASHPATCH 实验（`MAGICMIDA_V2_HASHPATCH=1`）**：1ms 监视等 blob
物化 → WriteProcessMemory 把存储槽前 8B := 本机计算哈希。实测
（Y4/Y5test）：**补丁写成功且存活到判定时刻**（failfreeze 场景验证
0x2056F = `50 fc…` 原样）——**检查仍然失败**。结论：比较读的不是这
8 字节（或不是直接读这个槽）。
**③ 三个比较哨兵槽**：0x216F5 / 0x22D7D / 0x233FD 各含
`{0xffffffff, value}`——判定前为 0，判定后 -1 = **三次比较全部未命中**
的形状（命中应给 ≥0 的索引/位置）。value 两个机器恒定
（0x7DC80DE6 / 0x022869C8）、一个逐 run 变（0x51F5DB34 vs 0x8CC0706F）。
res3 的值还出现在池内代码块（0x117DA79 的立即数）。
**④ PREFREEZE + µs 状态环（`MAGICMIDA_V2_PREFREEZE=1`）**：零睡眠紧
循环轮询 (contA, contB, opidx)，8192 条环形缓冲（14B/条 →
`.v2statering.bin`）。实测（Y7test）：**判定前状态
{contA=0x0102114D, contB=0x0110344F, opidx=0x246} 在 t=342.006ms 被
命中**，场景落盘。两个地面真值：
- VM 状态机节奏：微派发区**逐字节行走**（0x01021A1B→…→0x01021A26，
  每 2-20µs 一步），opidx 类别 {0x202, 0x206, 0x246, 0x282-7,
  0x293-7, 0x216}；整个状态驻留 2-20µs —— **1ms 轮询永远追不上单步，
  冻结必然晚 ~100-500µs**（ToolHelp 枚举 28 线程的延迟）。
- 冻结点落在「**比较已完、fail write 未发**」的中间态：VM 栈上
  0xEFE78-0xEFE84 已备好 fail 值（0xFFFFA595 + 0x01182523 + 计数
  0x17），银行还是检查态。主线程已在 syscall 里（指纹采集?）。
**⑤ failfreeze dump 改进清单（下一轮）**：STCK 固定 0xEFD00+0x3000
   应加宽（比较帧更深的部分在 0xEFC00-0xEFD00，本轮没抓到）；热路径
   预开线程句柄（跳过 ToolHelp）把冻结延迟压到 ~10µs。
**下一增量**：(a) 哨兵语义下找比较搜的**列表**（三份存储值在哪）；
(b) 预开句柄冻结抓比较中态；(c) 直接试补丁哨兵槽（命中值 = 0 或
索引——语义未证，低优先）。所有场景/状态环文件：
`OUT\Y{2,4,5,6,7}test.v2failfreeze.bin` + `Y7test.v2statering.bin`。

## V2 指纹机制簇现形 + 快冻结命中（2026-11-01 续 2，未发布）

**① 快冻结（预开主线程句柄）命中镜像内**：`spawn_dialog_killer` 增加
main_tid 参数，watcher 启动时 OpenThread 预存句柄；触发时先
`SuspendThread(h_main)`（~2µs）再做 ToolHelp 走查。实测（Y8test）：
主线程 **eip=0x10296D5（镜像内派发点）**、ebp=0xEEDC0014、
**edi=0x102859E = 银行 contA 槽指针**（正要读写银行）。failfreeze 的
STCK 加宽到 [0xEF800, 0xF7800)（0xEFC00-0xEFD00 曾漏抓）。

**② 重大更正：POSTMORTEMS 的 disp 锚点公式算错并传播**。真实锚 =
**0x1223FFEC**（disp = RVA + 0x1223FFEC；验证：块内
`lea edi,[ebp+0x12262885]` → rva 0x22899 ✓，且
`0x122624E5 - 0x24F9 = 0x1223FFEC`——旧记录 0x1225FFEC 是减法错）。
据此 disp 字节搜索重跑：pathslot(0x22899) 有 **9 个跨 run 恒定的引用
点**；哨兵/computed/stored 槽零命中——它们走运行时数据指针（dp 值
0xEEDC0000|off，off+0x1FFEC=rva；t=371 的 dp=0xEEDC0583 → rva 0x2056F
= 存储 blob，读法证实）。dp 槽本身的装载 disp 也搜不到 = **变异引擎
逐 run 重写立即数**，静态 disp 搜索对多数数据访问无效。

**③ contA = 字节码程序计数器**（不再是"当前块"）：0x102114D 处是
数据（字节码流）非代码——**字节码存在 VMCTX (0x20000-0x28000)**，
原生 handler 块解释它。字节码级补丁（改条件跳转字节）成为可能路线。

**④ 指纹机制簇（全部明文、跨 run 恒定）**：
- **rva 0xE3198**：`push [ebp+0x122607B1]; call eax（API thunk）;
  push 0x22899 槽; push 0x104(=MAX_PATH); call ebx` =
  **GetModuleFileName——指纹输入之一 = 被保护文件自身路径**；
  随后 `push 0x8307F8BF`（哈希常量）。
- **rva 0x963B7 / 0x13EC33**：pathslot 的逐字节处理循环
  （pushal; lea edi,[ebp+0x12262885]; lodsb...）= 哈希循环本体。
- **rva 0x110344F 簇**：自修改续延机制（`lea ebx,[ebp+disp]` 指向
  自己的 push 立即数，`mov [ebx+1],eax` 把下一块地址写进跳转指令）；
  **0x1103465 = `rep stosd` 清零 0x22899 起 256B**（fail 路径擦指纹
  缓冲——与 0x22899 处 "This application has been registered…" 文案
  替换路径的观测吻合）；**0x1103477 = `cmp [eax+0xA], 0x6863614D
  ("Mach") + push 0x80000002 (HKEY_LOCAL_MACHINE)` = 注册表机器数据
  读取**。API 经 `call [ebp+0x1233E07A]` 式 thunk 表（→rva 0xFE08E）。
- 结论：**指纹 = f(模块路径, HKLM 注册表机器数据)**，哈希循环在
  0x963xx/0x13ECxx，三个 {-1, value} 哨兵 = 三次比较（路径哈希 /
  注册表哈希 / key 校验的形状）。

**⑤ 下一增量**：(a) 从 0x963xx/0x13ECxx 的哈希循环恢复算法（明文在
手，capstone 可推），离线验证 f(本机路径+注册表) == 0x7DC80DE6/0x224ED
值之一 → 得到完整比较模型；(b) 或直接字节码级补丁：contA(PC) 在
VMCTX，把判定点的条件跳转字节翻面（pass 路径的目标未知是唯一缺口）；
(c) 哨兵语义实验（补丁 -1 → 0）风险最低可先试。所有实验产物：
`OUT\Y{2,4,5,6,7,8}test.*`；快冻结代码已在 helpers.rs
（main_tid 预开 + SuspendThread-first + STCK 加宽）。回归 x64 415/0。

## V2 比较/校验管线全明文复原（2026-11-01 续 3，未发布）

从 Y8test 明文镜像完整反汇编出**指纹校验的字符串级管线**：

1. **格式化循环（rva 0x13EC31-0x13EC87）**：逐字节走源串（esi，调用方
   设置），写回 0x22899 缓冲（edi）：每 4 字符插一个 `-`（edx 计数），
   `[a-f]`→大写，已有 `-` 跳过——**输出 `XXXX-XXXX-…` 39 字符
   （ecx=0x27）= 对话框指纹格式**（"1051-BCEC-14F2-…" 形状）。
2. **rol 校验和（0x113ECC3-0x113ECE6）**：从缓冲头走 35 字符（ecx-4），
   跳过 `-`（bl=0x2D）：`add al,[esi]; rol eax,1`，最后
   `and eax, 0xffff0000`。
3. **比较（0x113ECEB）**：`cmp eax, [ebp+0x1237ECF3]` → 目标
   **rva 0x13ED07**（在本簇块后面）；`jne fail; mov eax,1`——
   **eax=1 = 本项校验通过**。`75 0E` 的 jne 在 rva 0x13ECF1。
4. 引用值由 `call eax`（0x113ECA9，函数指针 [ebp+0x1230E777] →
   **rva 0xCE78B**，参数形状 (4, …)）在判定瞬间填入——快照全状态
   （pre/fail/post）读 0x13ED07 均 = `00 00 00 00`（比较后清回）。
5. Y8test 冻结（比较前一瞬）时 0x22899 仍是**原始路径**
   "D:\Projects\…CISC-1.exe"——格式化+校验全部发生在判定瞬间的
   handler 内。

**三个候选终补丁**（下一轮按性价比排序）：
- (a) **jne 补丁**：rva 0x13ECF1 的 `75 0E` → `90 90`——但块是即时
  解密的，watcher 必须 1ms 内抓到"已解密未执行"窗口（解密→执行间隔
  未测，可能可行：最终相位 342-401ms，块解密时机未知）。
- (b) **引用值补丁**：反汇编 rva 0xCE78B 的函数，找它读的存储引用
  （license 数据里），HASHPATCH 式提前写本机校验和——需要先离线算出
  本机格式化串的 rolchk（需先拿到格式化串 = 判定瞬间 dump，或离线
  复现格式化算法：输入 = 原始指纹 hex 串，其来源在 0x22899 之前的
  缓冲——0x8BE9B 的 0x40 字节拷贝簇疑似）。
- (c) **字节码补丁**：contA=PC 已定案，判定点的条件跳转在字节码流里，
  翻面即 pass——pass 目标未知是缺口。

另：Y8test.v2failfreeze.bin 文件被截断（IMAG 头声明 0x371000 但文件
只有 ~0x37E004，STCK/CTX 段丢失；此前读过的分析结果全部有效，从
S1_013/Y2test 补读即可）。教训：场景写盘后无完整性校验。
