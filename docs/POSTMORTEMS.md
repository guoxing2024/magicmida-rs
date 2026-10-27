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

## gdi32 系 stub 推导：静态形状验证（2026-10-27）

stub 推导机制是模块无关的（扫所有已加载模块的导出地址、认 `ff 25/ff 15
[abs32]` 形状、指针落在别的模块内就记 `target → (模块, 原名)`）。
user32 的实测已钉死（1.9.1 样本三槽 NtUser* 归回 RedrawWindow 等）；
gdi32 系本轮做了静态形状验证：SysWOW64\gdi32.dll 的 995 个导出里 **496 个
是 `ff 25` thunk**（AbortPath、AddFontMemResourceEx…，与 user32 的
277/1043 同形），推导机制适用。活体样本级验证需要 classic 样本带
gdi32!NtGdi* 槽——语料样本（s1/s2）在管线内的壳行为不稳定（见上节
1.1.1 的方差记录），本轮未取到活体命中；形状验证 + 机制单测构成当前证据。
