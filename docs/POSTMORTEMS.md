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

## V2 补丁面收敛：代码签名/字节码补丁双双证死（2026-11-01 续 4，未发布）

**① JNE 竞速两轮全败**：1ms 轮询（Y9test）和零睡眠紧循环（YAtest）都
没抓到 rva 0x13ECF1 的 `75 0E`——块解密→执行的间隔 < 一次 RPM 往返，
或**签名本身逐 run 变异**（变异引擎重写代码字节，Y8test 的 `75 0E`
不等于 YAtest 的）。**代码签名补丁 = 死路**。
YAtest 教训：紧循环卡死后 watcher 不再查 bail 标记——紧循环必须保
留标记检查或有界（本次靠隐藏桌面兜底，无弹窗）。
**② "字节码"区域 = 动态草稿**：0x2114D 在 S1_001-003 全零、S1_004+
才填 `6a 00 00 78…`；0x21A1B 在不同快照分别是零/`ta_09166490`/
`egistry\Machine\`（注册表路径串！）——contA 走的工作区被引擎逐 run
清零重写，**不是稳定字节码**。字节码静态补丁（候选 c）= 死路。
**③ STCK 段回退修掉**（0xEF800 未映射时 RPM 失败静默跳段 → 回退
0xEFD00+0x3000）；此前"Y8test 文件截断"是误报——调试走查只打印非
CTX 段，28 个 CTX 都在。
**④ 补丁面收敛定案**：唯一可行 = **数据输入面**（license blob
0x2056F / 机器数据），前提 = 恢复算法：
`rolchk(format(fingerprint_hex)) == reference(license 数据)`。
下一轮的完整链条：(1) 从明文恢复格式化+rolchk 算法（语义跨 run 稳定，
编码逐 run 变异——按语义恢复）；(2) 判定瞬间 dump 拿格式化串算本机
rolchk；(3) 反汇编 reference 函数链（0xCE78B → call eax）找 license
输入字节；(4) HASHPATCH 式提前改 license 输入 → reference = 本机
rolchk → pass。

## V2 格式化指纹串现形 + 零校验和攻击模型（2026-11-01 续 5，未发布）

**① REFTRACE（`MAGICMIDA_V2_REFTRACE=1`）**：紧循环追 0x13ED07+0x22899
110ms（~2 万次读）——两槽全程不变（ref=0、str=原始路径）。YBtest 的
判定瞬态 < 单次轮询间隔（3 次 RPM ≈ 15µs）。
**② 关键发现：格式化指纹串在 rva 0x2056D**（不是 0x22899！）——
S1_009 抓到**书写进行中**：`1051-BCEC-14F2-0C18-`（4 组 + 尾横杠）+
后面还是旧 blob 字节。该缓冲 = 与 0x2056F"blob"同一块（串覆盖 blob 头，
之后被清回）。串在检查期间持久（S1_009→S1_013 之间存活）。
**③ cmp-vs-zero 攻击模型**：所有状态 0x13ED07 恒 0 + 块内
`and [slot],0xffff0000` → 比较实际 = `cmp eax, 0`——**pass 条件 =
rolchk(格式化串) 高 16 位 == 0**。licensed 指纹的某组 = 校正位
（自校验串设计，类比 IBAN）。
**④ 零竞态补丁设计**：rolchk 每字节贡献可离线暴力求解（1 字节 256
候选）；把校正字节放**第一组**（"1051"→改后值）——格式化先写第一组、
不再回头、rolchk 在格式化全部完成后才读 → watcher 见串出现即写第一组
= 零竞态。前提：拿到完整 39 字符串（REFTRACE 改追 0x2056D）。
**⑤ 下一轮**：(1) REFTRACE v2 追 0x2056D 48B → 完整串 + 存活窗口；
(2) 离线暴破第一组校正值（需 rolchk 语义精确对齐——含 `cmp` 之前
`and eax,0xffff0000` 与可能的进位细节，用 S1_009 部分串验证）；(3)
`MAGICMIDA_V2_STRPATCH`：见 "1051-" 即写校正后第一组 + bail-kill
兜底 → 跑通则 .text 解密。风险：三个哨兵 = 三道检查，本串补丁只关
其一，其余两道（可能含指纹-vs-license 比较）可能仍 fail——观察
failfreeze 场景哨兵状态即知。
产物：`OUT\YBtest.v2reftrace.bin`（60B/条 ring）。

## V2 完整指纹串到手 + rolchk 代数定案（2026-11-01 续 6，未发布）

**① REFTRACE v2（追 0x2056D）大捷**：156 条记录 = **格式化器逐字节
写入全程**（~29µs/字符）。本机完整指纹串：
`1051-BCEC-14F2-0C18-3745-5E66-5E6D-2536`（39 字符，t=50028µs 完成，
~264µs 后开始被逐字节擦回 blob）。组 1 完成（t≈49048）到格式化完成
= **~1ms 补丁窗口**（格式化不回头 → 零竞态实锤）。
**② REFTRACE v3（只读引用槽 0x13ED07，~3µs/迭代）**：130ms ~4 万次
读仍零变化——**0x13ED07 = Y8test 那次 run 的 disp 编码，逐 run 变异**
（代码块/立即数变异 → 槽地址漂移），引用 transient 采集失败。
**③ rolchk 精确语义定案**（8 位 al 加法 + rol32，跳 '-'，35 字符
= 到"5E6D-"为止，末组 "2536" 不参与）：本机串 → eax=0x2536009D。
**④ 求解空间分析**：
- 单组修改无法命中任意 16 位目标（7 组 × {0, 0x7DC8, 0x0228} 全零解
  ——每组只影响 eax 的一段位窗口；k≥20 的字节经 ≤7 次旋转永远到不了
  高 16 位，组 6-7 全候选同输出）。
- **al 链向后可逆**：`X_{k-1} = (ror32(X_k,1) & 0xFFFFFF00) |
  ((ror32(X_k,1)&0xFF - b_k) mod 256)`——目标 eax 已知时逐字节反推
  可行（每步 16 个合法 hex 字符分支）；X_0 必须落回 0 = 唯一约束。
  目标值一旦到手，求解 = 一次带剪枝的反向搜索。
**⑤ 缺口 = 引用值本身**。下一轮首选：**以"串完成"为冻结触发**
（0x2056D 出现完整 39 字符 → 冻结）——比较+引用写发生在这个 264µs
窗口内，冻结现场寄存器里大概率有引用值；或离线反汇编 reference
函数链（0xCE78B → call eax → …）从 license 数据推导。
哨兵 f1/f2 = 引用的假设未证（单组无解不反驳双组求解）。

## V2 比较块同址确认 + 双组联合求解路线（2026-11-01 续 7，未发布）

**① v4 串完成即冻结命中**（YEtest，t≈395ms）：主线程冻结于
eip=0x102D600（下一 VM 操作）= 比较后 ~15µs；完整串在 0x2056D ✓；
引用槽仍 0。
**② 比较块同址 + 全貌**：本 run 的 rolchk 块也在 rva 0x13ECC0-0x13ED06
（字节签名 `02 06 d1 c0 46 49` 全镜像唯一命中），与 Y8test 逐指令相同
——**该块跨 run 稳定**（非变异块！）。块尾补全：
`and eax,0xffff0000; cmp eax,[ebp+0x1237ECF3]; jne → mov eax,0;
mov eax,1; ret` —— 结果经 eax 返回。
**③ 引用 = 0 实锤**：槽在冻结（比较后 ~15µs）与所有场景均 0；块内
唯一槽触碰 = `and [slot],0xffff0000`（不清零）→ **比较目标确为 0，
pass = rolchk(串) 高 16 位为零**。
**④ 求解约束精化**：字节 k 进入 al 后旋转 (27-k) 次——k≥20 永远到不了
高 16 位（组 6/7 全候选同输出实测证实）；单组无法命中任意 16 位目标
（7 组 × 3 目标全零解，非均匀映射）。**双组联合必有解**（16^8 候选，
均匀假设下 ~65536 个解）→ numpy 向量化随机搜索（rolchk 28 步全可
向量化：al 加法 + rol32 均为逐元素操作，分块跑 1 亿候选 ≈ 分钟级）。
**⑤ 下一轮**：(1) numpy 双组搜索求 high16=0 的替换串（如改 "1051"+
"14F2"）；(2) `MAGICMIDA_V2_STRPATCH=<hex4>`：watcher 见 0x2056D
串出现（t≈49048µs 起 ~1ms 窗口）即写替换组 → rolchk 读到 → eax 高
16 位 = 0 → mov eax,1 → 本关通过；(3) 三哨兵观察其余两关。
风险：本串补丁改变显示指纹（对话洉可见）——检查若另有指纹-vs-license
比较（哨兵 2/3），会 fail——实验即知。

## V2 STRPATCH 实装 + 求解解到手（2026-11-01 续 8，未发布）

**① numpy 双组搜索（40M 候选，2M 即中 5 解）**：替换组 1+组 3 使
rolchk 高 16 位为零——**解 = `6A7F|AFF9`**，替换后串
`6A7F-BCEC-AFF9-0C18-3745-5E66-5E6D-2536`，标量验证
eax=0x0000009E ✓（np 安装：本机 pip 直连可用）。
**② STRPATCH 实装**（`MAGICMIDA_V2_STRPATCH=<g1>|<g2>`）：watcher
300ms 起紧循环，双缓冲（0x2056D 显示 / 0x22899 checked）任一出现
4 连横杠即写解组（格式化不回头 = 零竞态）；contA 标记兜底 +
failfreeze 场景。**③ 负载-停车关系证伪**：YAtest/YFtest 的重循环
与停车相关是**巧合**——reftrace（更重的 72B/迭代）从没诱发；
06:33 起的 4+ 连停车 = 潮汐回归（2026-10-31 深夜同形状），环境性。
**④ 状态**：STRPATCH 机器就绪、解就绪，等潮退窗口（06:03-06:23
证明潮会退）。后台重试循环在跑（OUT/strpatch_bg_status.txt）。
**⑤ 判读表**（下次实验看日志）：
- `STRPATCH: solved groups written` + `window over (no marker)` =
  本关通过（无弹窗、无 bail）——下一步看 .text 是否解密/管线走向
- `solved groups written` + `bail marker still fired` = 本关通过但
  另两道哨兵拦住 → 场景里看哨兵状态定下一步
- 无写入 = 潮（停车），重试即可

## V2 STRPATCH 首战：等待 bug 修复 + 五个证伪 + 比较块全链路复原（2026-11-01 续 9，未发布）

**① STRPATCH 10 次空转根因 = 等待逻辑 bug**：分支结构
`if elapsed>=300 { 窗口循环 } return;`——线程首轮 elapsed≈0 落进
return，窗口循环从未执行（strpatch_bg_status 全 0 的解释）。修为
sleep-wait 至 300ms 后实测：**写入生效**（10/7/8/6 次/轮，两轮格式化
间隔 29ms 与 reftrace 吻合）。教训：带门条件的分支若门不满足要等，
不能落到无条件 return。

**② rolchk 补丁在位、串自洽、检查仍失败——cmp-vs-zero 模型死亡**：
离线验证 `6A7F-BCEC-AFF9-0C18-3745-5E66-5E6D-2536` 的 rolchk 高 16 位
= 0（原始串 = 0x5360）。STRDIAG（双缓冲变化 ring + RPM 失败计数）证明：
写入全部落地（writes=[10,0]，rpm_fails=[0,0]）、第 2 轮格式化器甚至
把我们的组 3（"AFF9"）回写进串（补丁反馈进管线）。检查仍 bail
⟹ **决定性比较不读本串/参考值非 0**。

**③ 比较块全链路复原（Y2-YE 十个 dump 逐字节一致）**：
0x113EC2B `mov ecx,0x27` → 格式化（每 4 字符插 `-`、`[a-f]`→大写、
拷到 [ebp+0x12262885]）→ `call eax`（[ebp+0x1230E777] → **rva 0xCE78B
自解密蹦板**：自旋锁 [ebp+0x1230E786] + `call 0x10CE81D` 用
`ebx=0x12345678` 逐字节 `xorb bl; addb bh; ror ebx,1` 解密
[rva 0xCE3CA, 0xCE6C6)，逆变换 = `(x-bh)&0xFF ^ bl`，已离线解出
**路径构建器**：GetModuleFileNameA(0x22899)、WDefaultLicenseName 读
配置、%APP_NAME% 展开、`<dir>\<name>.dat` 构建、CreateFileA 分支）→
`and dword [ebp+0x1237ECF3],0xffff0000` → rolchk 35 字节（跳 `-`）→
`cmp eax,[ebp+0x1237ECF3]` → `jne fail`（**6 字节 0f85 0a**，不是
旧机器假设的 75 0E）→ `mov eax,1` = pass。

**④ JNEPATCH 修正后补丁落地但仍失败**：字节模式 75 0E→0f85 0a 00
00 00（6 NOP）、持久重补（count=1，签名只出现一次）——bail 照旧
⟹ **0x13ECF1 的 jne 不是决定性分支**（rolchk 库的一个实例、可能
恰是通过的那个：**原串自洽**——rolchk(前 7 组) 高 16 位 = 0x2536
= 第 8 组 "2536" 的 hex 值！指纹串 = IBAN 式自校验设计，该实例
天然通过）。

**⑤ dp 逐 op 可变 ⟹ 一切静态有效地址不可靠**：YE 冻结（串完成
瞬间）ebp=0xEEDC0014（dp 锚）；同一 disp 0x12262885 在 STRDIAG run
的格式化打到 0x2056D（dp'=0xEEDC0CE8）。0x22899 = 多用途暂存
（模块路径 → `<exe>.dat` 路径 → 指纹串 → registered-to 消息）；
**静止态 = 逐位置 XOR 加密**（E("1051")=BA 34 2E 15，键流
8B 04 1B 24——由 STRPATCH 补丁回写实测证认：E("6A7F")=BD 45 2C 62）。
0x2056D = 显示副本（S1_009 书写进行中、v4 reftrace 完成即冻）。

**⑥ SENTINEL（三搜索结果槽 -1→0）落地仍失败**：0x216F5/0x22D7D/
0x233FD 在 bail 后 = {-1,ptr}（未命中）、pre-fail 2ms（Y8）= {0,ptr}；
三槽补丁全部落地、早于 fail write ~40ms——裁决仍 fail ⟹
**搜索 op 在 miss 时原子排队 fail 续延，事后改结果槽无效**。

**⑦ fail 值预备区在私有堆栈、轮询赢不了**：fail 三元组
（0xFFFFA595 + 0x01182523 + 0x17）与续延对只在 STCK 0xEFE7C-0xEFEE8
有**残影**（写后遗留）；活体（vmsp=0x01163803 私有堆）的预备→写
间隔 µs 级，NOWRITE 模式（contA==0x0102114D 触发 + 栈窗模式替换，
窗口实测 t=330-339ms 命中 3 次）改写 0 次——预备值在 contA 窗口
结束后才压栈，且真身在私有堆。轮询路线证死。

**⑧ fail 处理器 = 私有堆 VM 派发跳板链**：0x1182519 `jmp 0x118273D`
→ `jmp 0x1183965` → `push 续址; jmp 0x102888A`（解析器 thunk 链）
——裁决/fail 逻辑在字节码。**PRIV 节已加入场景 dump**
（0x1170000-0x1190000，128KB）——fail/裁决代码首次可离线分析。

**⑨ 指纹哈希不在路径上**：本机哈希 50fc3964 053166a5（2 dword）
对路径/目录/文件名的 rol1-add 假设矩阵（含大小写、跳横杠、序、
nul、len-4/len/35/39/96/100 全长度 × ref{0,0x53DC}）全空
（62^4/62^5 求解器反向扫同样零解——ref=0/0x53DC 两候选均不可能）。
0xE3192 块 = 干净的输入链（GetModuleFileName→0x22899 + 目录截断），
但 call 进 [ebp+0x12263DED] → **rva 0x23E01 = VM 字节码区**——哈希
逻辑在 VM 里（native 0x963B5 混淆块 = push/ret 链 + 逐字节
movsb+sub 的 handler，循环由字节码驱动）。0x963B7 块手工解到
`while([esi]){slot-=eax; movsb}` 形状后停——字节码驱动部分 =
devirt 沼泽（AGENTS 既定不承诺）。

**⑩ CISC-1.dat（480B，2009 原件）无简单密码学**：与内存 blob
（0x2056D 39B）无直配、无单字节 XOR、无零富密钥流对齐。许可文件
变换待破。MachineGuid（本机输入）= `7157539a-0733-4424-ac08-1d977bfa0137`
（HKLM\SOFTWARE\Microsoft\Cryptography）。

**⑪ 机器资产全部保留**：JNEPATCH（修正模式+持久重补+bail 内检）、
SENTINEL、NOWRITE、REFHUNT、STRDIAG、PRIV 节。合并轮询教训：
紧循环若不退出会饿死后续分支（YJStest sentinel 从未运行）→ 合并进
同一循环（YJUtest 三哨兵齐发）；退出时机要用决策时刻校准（YJTtest
交接晚了 7ms 错过窗口）。

**⑫ 下一增量**（按性价比）：
1. **许可文件密码学**：PRIV dump 里找 .dat 的读取/解密例程
   （CreateFileA 分支 → 读 480B → 变换 → 0x2056D blob），恢复变换后
   把 blob 内指纹字段换成本机值重加密写回文件——**数据输入面的
   正道**（续 4 结论的完成形态）。
2. 若 1 卡死：裁决字节码（VMCTX 0x2114D 邻域 + 私有堆续延链）的
   格式逆向——三个哨兵的 d1（命中 entry 指针）与裁决读取方式。
3. 指纹哈希恢复（VM 字节码）只在 1/2 需要时做。

## V2 许可来源定案 + 文件密码第一轮（2026-11-02 续 10，未发布）

**① 指纹串 = 许可携带（provenance 链钉死）**：样本复制到 OUT\sp1\ 换路径跑
（REFTRACE v4 完成即冻）——串 `1051-BCEC-…` **逐字节不变**（0x22899 的
.dat 路径已是新目录）；**移走 .dat 再跑：串根本不出现**（窗口结束无
marker vs 有 .dat 时串完成即冻）。⟹ 串 = LCF-AT 机器的**注册指纹**，
从许可文件解密而来；对话洉显示的是注册指纹不是本机指纹。
**攻击模型重定型**：三搜索 = 在许可携带的列表里找本机计算键
（50fc3964 053166a5 = 其中之一）；通过 = 让列表含本机键（改许可）
或让键等于注册值（改键槽 0x224ED——需先读列表里的注册值）。

**② 文件密码第一轮 = 全负（含一次假阳性教训）**：CISC-1.dat（480B）
对已知明文（注册名 67B、指纹串 39/32B）系统测试：周期 XOR p=1..33
（每偏移）、加/异或常量、ror1 族固定魔数（0x12345678/0x8307F8BF 等
×4 形态）、RC4（16 个候选键）、exe 流对齐采样——**全负**。
**假阳性教训**：p=31 周期对 32B 模式只含 1 字节检验（ks[31]==ks[0]），
448 偏移 × 2^-8 ≈ 期望 1.75 个假阳性——实测恰好 2 个（@0x2/@0x195，
两键不同、邻域无结构），**均统计噪声**；"layer-1 破解"（K=2b91c07e…，
明文 `aa 69 1051BCEC…`）同样不可信。**教训：短窗口周期检验必须算
约束数，1 字节约束的命中 = 噪声。**

**③ 堆窗口修正**：VM 栈（vmsp=0x01163803）与搜索数据指针
（bank+0x36=0x0115D00C）在 **0x115xxxx-0x116xxxx**——PRIV 节从
[0x1170000,0x1190000) 加宽到 **[0x1150000,0x1190000)**（256KB）。
PREFREEZE 重跑（YPF3test）= 搜索时刻 ±2ms + 全堆场景，机器就绪。

**④ 许可内存足迹图**：注册名 @0x1182523（PRIV，fail 路径工作区）+
@0x2289A（对话缓冲，后随 .dat 路径串）；指纹串缓冲 = 0x2056D/0x22899
（静止态 XOR 键流 32B 周期 `8b041b24…`，YSP1 冻结在明文态键流全零
= 解密后状态）；本机计算哈希 @0x224ED 全 dump 单副本；VMCTX 其余
区域 ≠ 该键流加密（32 相位扫描只有串自身）。

**⑤ 下一增量**（按性价比）：
1. **搜索 op 机制**（devirt-lite：只逆三个搜索 op，不做全 VM）：
   键 = 什么、列表 = 哪里、miss→fail 续延怎么排队——YPF3test 场景
   （全堆 + 搜索时刻）为输入。
2. **文件解密例程狩猎**：原始文件字节（81f8f14e…）落地的读缓冲 =
   fphunt 式内存扫描 → 变换前后对照 → 恢复例程。
3. 若列表 = 文件派生且例程恢复：改许可重加密 = 终局。

## DLL→EXE 包装器壳：`core.dllMM.exe` 的真身是一颗 DLL（2026-11-02）

**症状**：`mida-cli /unpack core.dllMM.exe` 走 EXE 路径 7 分钟后
`ExitProcess { exit_code: 1 }` + `attempting final raw dump`，**零产物**；
`.text` 写断点从未命中，OEP 链根本起不来。

**定案**：这颗"EXE"的入口桩是一段 **DLL→EXE 包装器**，不是壳的入口。
桩区（RVA `0xDB1FD8`，`.reloc` 前的 slack，raw `0x5C21D8`）：

```
48 83 EC 28        sub  rsp, 0x28
E8 00 00 00 00     call $+5
59                 pop  rcx
48 81 E9 E4 19 DB 00   sub rcx, 0xDB19E4   ; -> image base
BA 01 00 00 00     mov  edx, 1             ; DLL_PROCESS_ATTACH
45 31 C0           xor  r8d, r8d           ; reserved
E8 0B E7 AE FF     call 0x8A0108          ; <-- 真 DllMain
CC                 int3
EB FE              jmp  $                 ; 自旋
```

`call rel32` 落在 `0x8A0108` —— 那正是同尺寸 DLL 孪生体
（`core.dll`，6,038,032 B，`IMAGE_FILE_DLL` 置位、EP=`0x8A0108`）的
入口。即：**样本本体是受保护 DLL，EXE 桩只是把它当 DLL 调起来**。
`/analyze` 报 "Themida V3 / .winlice + .boot" 是对的，但它报的是 DLL 的形状。

**EXE 模式下 `.text` 永不就地解密（实测）**：对独立运行的样本做两次
`/dump-process`（~8 s 与 ~40 s），1,054,720 B 两份**逐字节相同**，且前
377,856 B 与磁盘上打包的 `.text` **0 字节差异**（首 32 B 同为
`272ba3c9…`，非零字节同为 375,900）。⟹ 壳是 VM 解释型，原生镜像从不
materialise，`.text` 写断点自然没有可触发的对象。EXE 路径对该形状**无解**，
不是管线缺陷。

**DLL 路径会收敛**：`LoadLibraryW` 走完整 `DLL_PROCESS_ATTACH` 引导，
`.text` 全量解密（产物首 32 B = `55 57 56 53 48 83 EC 38 …`，真 MSVC
prologue，0x1017C0 B）。

**可复现的转换**（`core.dllMM.exe` → 等价的 `core.dll` 孪生体，4 步，
30 字节差异，**确定性**：重建结果与 2026-10-23 的工作副本 sha256
`09f3dd34…` 逐字节相同）：

1. COFF `Characteristics`（`e_lfanew+0x4+0x12`）`0x022E → 0x222E`
   （置 `IMAGE_FILE_DLL`）
2. `AddressOfEntryPoint`（`opt+0x10`）`0xDB19DF → 0x8A0108`
3. `DllCharacteristics`（`opt+0x46`）`0x0000 → 0x0060`
4. 桩区 raw `0x5C21D8..0x5C2200` 清零

**产物**：`mida-cli /unpack <twin>.dll`（DLL 分支，走真实 loader host）
—— IAT 3,283 槽 / 12 模块 / 289 thunks / 3,106 relocations，
1,737,216 B，exit 0 `Done.`。行为验收（`OUT/dll_gate_harness.exe` 两次
独立运行）：`LOADED=1 VERSION=1.1 WINDOW_VISIBLE=1
WINDOW_CLASS=PigToGoLicenseDialog WINDOW_TITLE=授权验证
RUN_THREAD_ALIVE=1`。`.text` 与 2026-10-23 的 golden 产物
（`OUT/coreU.dll`）**1,054,656 B 全同**；全文件仅差 3 字节
（`0x1AF` 段特性 `0x60000020` vs 旧参考的 `0xe0000020`——新值照抄输入
自己的声明，旧值才是缺陷；`0x141A7A` 2 字节 = IAT 首槽的
Hint/Name RVA，布局等价）。

**顺带修的两个 `dll_dump.rs` 缺陷**（都只影响这条诊断工具）：

- **host log 路径过期**：`ensure_loader_host` 早已把 host 日志挪到
  `%TEMP%\magicmida-hosts\host-<pid>.log`，工具还在读
  `<dll>.host.log`，于是 60 s 超时必然触发（`bootstrap` 永远等不到）。
- **OEP 扫描跨函数**：`find_oep_rva` 用平坦 64 字节窗口找
  `cmp edx,1|2`，会**越过本函数的 `ret` 摸到下一个函数**——参考 DLL 上
  返回 rva `0x13A0`（一个 0x16 B thunk，`ret` 在 +0x15，邻居 `cmp edx,1`
  在 +0x24），产物能加载但 `DllMain` 根本不跑。现两处收紧：遇
  `ret`/`int3`/`nop` 终止候选；且要求**同时**出现 `cmp edx,1` 与
  `cmp edx,2`（只有 ATTACH 的 0x13C0 helper 也被排除）。修后
  `oep rva = 0x2BB10` = 真 DllMain（`cmp edx,2` → `cmp edx,1` 分派），
  与 10-23 golden 一致。

**残留差异（不是缺陷）**：`dll_dump` 路径仍只看到 live IMPORT 目录里的
12 个诱饵描述符（真表在壳的私有 `.winlice` 区），产物 IAT 无效、
`LoadLibrary` 失败 `1114`。**`mida-cli /unpack` 的 DLL 分支**才走
3,283 槽的全扫，产物可用。想复用 `dll_dump` 得把 `/unpack` 的 IAT
定位搬过去，本轮没做。

## V2 VMDIFF 写映射 + LICPATCH：许可字段全图与搜索模型证伪（2026-11-02 续 11，未发布）

**① VMDIFF（`MAGICMIDA_V2_VMDIFF=1`）落地**：VMCTX+私有堆 10ms 快照差分，
(t, region, off, len u32, bytes) 记录 + bail 保护。**首版 bug：len 用 u16，
PRIV 基线 0x40000 截断成 0，其后记录全部错位**（YVDtest 报废）——改 u32
重跑（YVD2test，1567 记录）。教训：长度字段按最大区尺寸选型。

**② 许可解密时刻 = t=208ms**：E-blob（0x2056D）首写 t=208（写 2 次：
208 解密 + 358 格式循环；字节 8-38 写 4 次 = 循环只动尾部）。**t=208
共 41 个写入 run**：~19 个 4 字节哈希样字段 + ~10 个 0x0112xxxx 指针 +
4 个清零。**哈希样字段聚在三个哨兵槽邻域**（0x21621/0x21761/0x21871/
0x2192D/0x219C1/0x21CE5 靠 0x216F5；0x22C09-0x22ECD 靠 0x22D7D；
0x23001-0x23375/0x235E5 靠 0x233FD）= 搜索列表区。私有堆只在
t=100（基线 206KB）/347/380 有写——**许可字段全在 VMCTX**。

**③ 搜索键候选**：哨兵 d1 搜索后 = **0x7DC80DE6 / 0x022869C8（跨 run
稳定 = 机器派生）**；槽 3 d1 逐 run 变（0xB895D475/0x0EA5E92A/0xDC640BCC
——另有机制）；决策前态 d1 = 指针（0x0102D6AB/0x01108E1E）。
**0x9898 之谜解开**：0x224ED 槽决策前 = `98989898` 填充值，决策时刻被
计算哈希 50fc3964 053166a5 覆盖（哈希写于 331ms pre-fail 冻结之后——
搜索/比较全在 [331, 412] ms 窗口）。

**④ LICPATCH（`MAGICMIDA_V2_LICPATCH=1`）**：t=280ms 起把 19 个字段
轮流填两键（每 10ms 重涂）。实测 14 轮涂写、**bail 时 19/19 全部存活**
——检查仍 fail。⟹ **「键 = d1 值、列表 = 那 19 个字段」模型证伪**：
搜索键非 d1、或列表另有其处、或搜索不是键入列表形状。字段级黑盒补丁
路线穷尽（补得上、补不对）。

**⑤ 资产**：VMDIFF/LICPATCH 机器保留（记录格式 u32 len）；写映射
`OUT\YVD2test.v2vmdiff.bin`（1567 记录，可离线重放任意时刻状态）；
`OUT\vmdiff_analyze.py` 重放器。

**⑥ 下一增量 = 搜索 op 机制（devirt-lite）**：三个搜索 op 的字节码
（contA=0x0102114D → RVA 0x2114D 邻域）+ 解释器 handler——键从哪来
（哪个计算的值）、列表指针怎么取、miss 怎么排 fail 续延。这是黑盒
穷尽后剩下的唯一一层。次选：文件解密例程狩猎（fphunt 扫 81f8f14e…
原始文件字节落点 → 变换前后对照）。

## V2 SFREZE 冻结成功 + "VM" 范式级破译：根本没有字节码（2026-11-02 续 12，未发布）

**① SFREZE（`MAGICMIDA_V2_SFREZE=1`）一击命中**：µs 轮询（银行 64B +
哨兵槽 4B ≈ 3-5µs/轮）+ 穿录取环 + 第一个哨兵槽写 0xFFFFFFFF 瞬间
SuspendThread——实测 t=134.8ms（决策窗口内）、环 5897 条、场景含活体
上下文（EIP=0x1033D8F 引擎池、EBP=dp、ESI=0x011723E9 堆、EDI=银行指针）。

**② 范式级定案：没有 VM 字节码**。冻结态银行 contA=0x0116FD15 → 堆里
该地址的内容 = `83 e9 05 / f3 a4 (rep movsb) / 6a 00 57 e8+3 / 5f c3 /
89 7c 24 04 / 81 44 24 04 14 00 00 00 / 47 57 c3` = **与 0x963B5 完全
同款的 push/ret 混淆原生代码**。contA/contB = **原生代码块链的续址**，
"VM" = 原生块 + 派发蹦板的混淆链。devirt = 反汇编这些块（可补丁的
真 x86！）。此前"字节码在 VMCTX/动态草稿"的全部表述要按此修正。

**③ 派发器 0x102888A 完全解码**（镜像内、每 dump 可读）：
```
pushal/pushfd; call $+0; pop edi
sub edi, 0x1226887E        ; edi = 0xEEDC0014 = dp 基（EIP 推导、恒定！）
mov eax, edi; add edi, 0x1226858A   ; edi → RVA 0x2859E = 银行内部！
cmp eax, [edi+0x2C]        ; dp 变了吗
mov [edi+0x2C], eax; mov ecx, 0xA8
add [edi+ecx*4+0x48], eax  ; ★ 按 dp 重定位 168 个指针（RVA 0x285E6 起）
mov esi, [esp+0x24]        ; thunk 推入的续址（dp 相对偏移）
mov ebx, esi; add esi, eax ; 真实地址 = 续址 + dp
lock cmpxchg [edi+0x30], ecx  ; 自旋锁（与 0xCE78B 蹦板同锁）
lodsb; xor al, bl          ; ★ 块解密：密钥 = 续址低字节
mov word [esp], bx; jmp 0x102FF28   ; 解释器主循环
```
**银行 = ~0x300B 状态结构的头部**（0x28580-0x28886+）：+0x2C = 上次
dp、+0x30 = 自旋锁、+0x48 起 = **168 指针重定位表**（实测 167/168 =
镜像内引擎池指针 0x1029xxx-0x103Dxxx，即 op handler/块表）。
**"dp 逐 op 可变"的机制 = 这张表随 dp 整体重定位**——静态 disp 分析
无效的根因终于闭环。

**④ 块解密密钥 = 续址本身**：`lodsb; xor al, bl`（bl = 续址低 8 位）
——续址 = 地址偏移 + 解密密钥二合一。"字节码" = 按续址异或加密的字节
流，解释器 = 0x102FF28（待解码）。伪造/补丁一个块必须同时满足：偏移
正确 + 密钥（续址）一致。

**⑤ 堆跨度远超现有 dump**：续址目标 0x1236xxxx（thunk 表的 push 值 +
dp 后落点在镜像内，但中间层在堆）、VM 栈 vmsp=0x0EDF2C99——PRIV
[0x1150000,0x1190000) 没盖住。下轮加宽或按活动指针定向转储。

**⑥ 下一增量**：①解码解释器 0x102FF28（块流怎么执行、op 编码）；
②用续址密钥解密冻结态的块（0x116FD15 的块流，密钥 = 0xFD15 低字节
0x15）→ 搜索 op 语义；③搜索块的 fail 分支 → 原生补丁 = 终局攻击面
（块在堆里 = 可写）。

**续 12 修正（python 算术校验后）**：①派发器自推导 `0x01028892 -
0x1226887E = 0xEEDC0014` ✓（AGENTS 的 dp 值正确，mental-math 曾算错）；
结构 RVA 0x2859E ✓（167/168 镜像内指针佐证）。②**续址 = dp 相对偏移，
真实块地址 = 续址 + dp**：contA@freeze 0x0116FD15 + dp = **0xEFF2FD29
= 高端堆**（进程 LargeAddressAware，用户空间 4GB）——本轮反汇编的
"0x116FD15 块" = 低地址 raw 值处的内容，**不是 op 块**（push/ret 同款
形状 = 壳的混淆遍地都是，撞形不算证据）。③**场景 dump 从未覆盖高端堆
（0xE-0xFxxxxxxx = VM 主工作区：op 块 + VM 栈 vmsp=0x0EDF2C99 同在高
区）**——下轮 dump_failfreeze_scene 改为**动态区域**：冻结时按银行
活值取 [vmsp-0x80000, vmsp+0x80000] 与 [(contA+dp)-0x20000, +0x20000]
等，一次 run 拿全 op 块真身。④搜索 op 语义 = 下轮在真块上解密
（lodsb/xor al,bl，密钥 = 续址低字节）后即读。

**续 12 补充（动态区域 dump + 侦察修正）**：`dump_failfreeze_scene` 新增
**HIHE/HIST 动态节**（按冻结时银行活值取 contA+dp±0x20000、vmsp±0x80000，
4KB 页式稀疏读 + present 位图——整段 RPM 会因单页未映射整体失败）。
实测侦察（SFREZE-SCENE recon）：**block 地址 = MEM_RESERVE（0x2000，
未提交）、vmsp 地址 = MEM_FREE（0x10000）**——冻结时刻银行的 contA =
下一块（引擎按需懒提交）、vmsp = 陈旧值，两目标全空 = present=0 的真因。
**真正的收获：搜索操作数栈 = 解释器传统栈 @ESP=0xEFEE8——STCK 节早已
覆盖**：栈顶 = dataptr(0x0116FCD6)+contA(0x0116FD15)，下为 dp
（0xEEDC0014 反复压栈）、镜像地址（0x010E35A3/0x010E03B8）、哈希样值
（0x1C4E8ECE/0x892DCC2A）。**下一增量改为：解析解释器栈帧（数据已有）
+ 解码 0x102FF28 主循环**——搜索 op 语义从栈帧+块流双层还原，无需再跑。

## V2 解释器帧链 + 混淆剥皮需求 + DR3 终局设计（2026-11-02 续 13，未发布）

**① 解释器帧链走通（YSF4test，数据已在场景内）**：ESP=0xEFEE8 起帧链
（重复形状 [hash][镜像返回地址×2][dp][下帧链接]）：内→外 =
**0xE35A3（最内层 handler，搜索后正在执行）← 0xE03B8 ← 0xB754D/51
← 0xE3247 ← 0xA4135 ← 0x21FFF（检查块 0x2114D 的返回点，块长 ~0xEB2）
← 0x964F9（混淆块邻域）← 0x1371000（镜像末帧）**。全部在 IMAG dump 内。
FAIL_MARK 立即数 **不在镜像**（fail 值 = 运行时计算，与栈上预备一致）。

**② 块流 = 逐 op 易失**：冻结瞬间 contA+dp 区域 = MEM_RESERVE——引擎
「提交→执行→去提交」逐 op 使用块流，**事后读块读不到**；静态向前反汇编
返回地址 = push/ret 混淆链（本变体移位 0x19；形状 `call+3/pop/[esp+4]+=
imm/inc/push/ret` → 真流在 hop 目标）。搜索语义只能活体捕（handler
寄存器态）。剥皮器（按形状跟 hop 链）= 可选辅助，非必需。

**③ DR3 写断点 = 终局武器设计**：AGENTS 记载壳校验 DR0（执行断点）；
**DR3 = 数据写断点架哨兵槽（0x216F5 等）**，在 `-1` 存储的指令边界触发
= 搜索 handler 内部、寄存器持 miss 判定现场的时机。实施要点：
(a) SetThreadContext 装 DR3（DR7 RW=01 写、LEN=11 4B）——武装时机
    ~350ms（判定前，壳 SEH 校验窗口外）；
(b) core 的调试事件循环加 EXCEPTION_SINGLE_STEP 分支：EP+DR6 判来源 →
    dump CONTEXT（寄存器 = 搜索 op 现场！）→ 可选干预（SetThreadContext
    翻 miss 标志寄存器 / 重写结果 dword 为 0 = 机器精度零竞态的假命中
    ——比 10ms 轮询的 SENTINEL 强在「还在 handler 内部、fail 排队未做」）；
(c) 风险：壳若也查 DR3（未实测）→ 假 bail，场景可归因；重复触发
    （3 搜索 × 2 dword）按 EP 过滤。
(d) 该改动碰 core 事件循环（decode_event），单独一个增量做、全 env 门控。

**④ 下一增量顺序**：DR3 机器（上面 a-c）→ 单 run 拿搜索 handler 寄存器
现场 → 按 miss 标志寄存器定位判定点 → 寄存器干预/原生补丁二选一 →
检查通过 → .text 解密 → OEP → 产物。

## V2 DR 机器 + SFAKE：黑盒路线穷尽证明（2026-11-02 续 14，未发布）

**① DR 机器实装**（`MAGICMIDA_V2_DRBP=1`：arm_v2_dr_breakpoints 于
t=200ms 装 DR1-3 写断点（DR7=0xDDD00054，DR0 留空避开壳校验）+ 事件循环
SingleStep 拦截 + 寄存器捕获 <stem>.v2drhit.bin + 机器精度改写）。首轮
bug：默认 tick=500ms 错过 410ms 窗口（YDRtest 零 arming）——DRBP 模式
tick 降 50ms。**但实测零命中零事件**：**V2 post-attach = 故意无调试端口
（attach 会触发壳反调试扣下 .text 解密，上游 C-8 字节实证），DR 异常无
接收方、被壳 SEH 吞**——DR 路线在 V2 上架构性死亡。

**② SFAKE（`MAGICMIDA_V2_SFAKE=1`）= 最后的黑盒实验**：无睡眠循环每
~5µs 读全部三个哨兵结果 dword、-1 即改写 0。实测 **fakes=3（三次 miss
全部 ~5µs 内改写成功）bail 照旧** ⟹ **fail 判定 = 寄存器级**（miss 在
搜索 handler 内部原子排队 fail 续延，槽值重写无效）。与 LICPATCH 结论
合并：**黑盒补丁路线全部穷尽**——STRPATCH/JNEPATCH/SENTINEL/NOWRITE/
LICPATCH/SFAKE/DR/页守卫类（无端口全被 SEH 吞）。

**③ 修正一个隐患**：LICPATCH 补的 19 个字段 = VMCTX 低地址区；搜索
handler 实际扫描的列表若在 dp 相对的高端堆（0xE-0xF 区，从未转储），
则所有字段补丁都打在错误位置——需真块解码才能终结此辩论。

**④ 剩余唯一路线 = 许可文件伪造**：.dat 解密例程狩猎（fphunt 式扫
`81f8f14e…` 原始文件字节的内存落点 → 变换前后对照 → 恢复例程 →
字段换本机值重加密写回）。机器全保留（DRBP/SFAKE/SFREZE/VMDIFF/
LICPATCH/STRPATCH/JNEPATCH/SENTINEL/NOWRITE/REFHUNT/STRDIAG + PRIV/
HIHE/HIST 动态节）。

## V2 DATSCAN：文件落点定位 + 密码第一轮全负（2026-11-02 续 15，未发布）

**① DATSCAN 机器落地**（`MAGICMIDA_V2_DATSCAN=1`）：多针全空间扫描
（范围到 0xFFF00000 含 LA 高端堆；**只扫 MEM_PRIVATE**——系统 DLL 是
MEM_IMAGE，过滤后量级从百 MB 降到几十 MB）+ 文件落点快照追踪 + 事件
追加 <stem>.v2datscan.bin。集成 bug 一次：mod.rs 补丁脚本声称成功但
改动丢失（原因未究，重放后加 grep 验证——**补丁脚本必须 grep 验收**）。

**② 文件落点 = 0x3530000，t=182ms**（解密 t=208ms 前 ✓）；快照追踪 =
**raw 形态驻留不变**——变换不在原地。raw 名字/无横杠串在决策前不存在
（变换不产生 raw ASCII）；静止态键（32B、全相位）对文件的真键检验全负；
4 字节周期字段键全负 ⟹ **文件密码 = 真变换**（非 XOR 族/非静止态键/
非 RC4 已知键）。另一层注意：E-blob = 静止态加密写入 VMCTX（t=208），
**明文许可可能从未整体存在**——字段级「解密→按静止态加密→入库」，密码
恢复必须拿例程。

**③ 例程定位的现成机器**：变换窗口 = [182, 208] ms——**RIPSAMPLE 模式
（现成）把采样窗对准该区间**，RIP 轨迹 = 解析/解密例程地址 → dump/
反汇编 → 恢复变换。或 REVERSING 路径：文件缓冲 0x3530000 的读取方
（CreateFileA/ReadFile 调用链 = 路径构建器 CreateFileA 分支已知）。

**续 15 补充（DATRIP 五连跑结论 + 干净模块捕获器设计）**：DATRIP 实装
（全线程 ToolHelp 走查 + OpenThread 直采——**工作线程不在调试器线程映射
（post-attach 无事件），必须 OpenThread**；轮转→全扫）。五连跑零
out-of-image RIP——**YTR5 的 0x00AA42BA 命中 = 主线程**（当时 8 线程
批次只有主线程 OpenThread 成功），干净模块执行 = <5ms 短脉冲，5ms 采样
概率错过（1/5+）。**稳健捕获器（下一增量）**：主线程 RIP 的 µs 级
轮询（单线程 GetThreadContext ≈10µs/次，[150,260]ms 窗口内可行），
RIP ∉ [镜像 ∪ 系统 DLL] → 冻结全线程 + dump RIP 所在区域（一次命中 =
干净模块 + 变换现场全拿）。备选：更多 DATRIP 暴力轮（~1/5 命中率）。
干净模块 = 编译器风格未混淆代码（ebp 帧/call/cmp），许可逻辑可读 =
密码恢复的钥匙。

**续 15 再补充（RIPCAT 自败机制 + needle 定位方案）**：RIPCAT 实装
（µs 轮询 15µs/次 ✓）但六连零命中——轨迹环证明**主线程全程在镜像内**
（148/148 IMAGE）。与 YTR5（主线程 @0xAA42BA）矛盾的解释：**YTR5 =
DATRIP 模式，其 5ms 全线程 sweep 的 suspend 扰动把许可工作迁到主线程；
RIPCAT 的 15µs suspend 风暴反而把主线程钉死在调度器外（工作永久迁走）
——重轮询自败，轻触概率**。**破局 = 不抓执行，抓静态代码**：干净模块
未混淆 = 编译器输出逐 run 相同，YTR5 已捕获其 64 字节
（52 8d45e8 50 e8a02b0000 83c40c 8945fc 837dfc00…）——取 16B 作
needle 加进 DATSCAN，命中即 dump 所在区域（模块加载后常驻，任意时刻
可 dump）。下一增量：DATSCAN 加 clean-code needle → dump → 离线反
汇编许可逻辑 → .dat 密码恢复。

**续 15 终补充（needle 命中——干净模块到手）**：DATSCAN 加 16B
clean-code needle（YTR5 捕获的 52 8d45e8 50 e8a02b0000 83c40c 8945fc…，
未混淆 = 编译器输出逐 run 相同）——**一次命中：t=190ms @0xB242BA
（本轮地址，per-run 符合预期），区域 [0xB24000,+0x6000] 已转储**
（clean_module.bin）。模块 = 干净编译器风格代码：**.dat = 120 dword
数组，解析器逐字段处理**（`mov edx,[eax+edx*4]` 数组遍历 + 值压栈调
字段函数 0xB26E64 + 类型分发 call 0xB23C7E）。**静态 RE 无需实跑**：
下一增量 = clean_module.bin 全量反汇编 → .dat 字段格式 → 解密变换 →
伪造许可。产物链：YDT4test.v2datscan.bin（24589B，模块+文件事件）。

## V2 干净模块静态分析开局：C++ 解析器可读（2026-11-02 续 16，未发布）

**① 模块布局定案**：clean_module.bin（[0xB24000,+0x6000]，hit 偏移
0x2BA 稳定——**模块布局逐 run 相同，仅基址浮动**）；但 call 0xB23C7E
指向 dump 起点之前 0x382B——**模块跨相邻分配区，dump 需向下扩展**
（下次 [hit-0x4000, hit+0x8000]）。50 个内部函数已盘点
（hot: fn_382f×19、fn_1598×17、fn_16f9×11、fn_36a5×10、fn_0a7e×10）。

**② 模块 = 干净 C++ 许可解析器**：fn_2e64 = 动态数组 push_back（带
扩容 realloc 0xB254F7）；fn_382f = 容器比较/合并/去重原语（读
[a+8]/[b+8] 尺寸、合并经 0xB28AA3、去重经 0xB23C7E 返回 -1=未命中）；
错误码返回形态（cmp eax,0 / je ok）贯穿。**YTR5 命中点 = 解析器主循
环：`mov edx,[eax+edx*4]` 数组遍历 + 值压栈调字段函数 + 类型分发**——
.dat 的 120 dword 逐字段被解析进容器。

**③ 下一增量（纯离线，无需实跑）**：clean_module.bin 函数级全量反汇编
（50 函数）→ .dat 字段格式（类型 tag/长度/值三段式假设待验证）→ 找
解密变换（在字段处理函数里）→ 本机值重加密写回 = 伪造许可 = V2 终局。
补充 dump 向下扩展后合并分析。产物：clean_module.bin、fn 盘点。

## V2 续 17：codec 定性 + .dat 解码生命周期 + Data_ 字段模型（2026-11-03，未发布）

**① clean_module.bin 全量反汇编（51 函数递归下降，cm_disasm.py/cm_disasm.txt）**
—— 修正续 16 的定性：**模块 = LZ 系压缩 codec 库，不是许可解析器**。证据：
- fn_2A72 = 分档匹配派发器：max(len)≥0x15E→fn_397B（2448B 长径，
  `len/3×0x1C` 节点分配）、≥0x50→fn_1DC0、小径→0xB23032/0xB293F3，
  长径**递归回调派发器**——LZ 匹配器形状；
- needle 函数（dump [0,0x470)，入口在基址之下）= **28-bit 单元
  rank/除法机构**：`and ecx,1 / shr / shl 0x1B / or` 位阵列移位
  （fn_0470）、64-bit 移位/除法 helper（0xB20E00/0xB20E1F，下方基址）、
  0xFFFFFFF 掩码、频度数组 [ebp-0x44] ±1、上下文三元组 [ebp-0x34]、
  fn_382F 合并、`cmp eax,1 je` 类型闸（0xB23C7E）；
- 无任何密码学常量（S-box/魔数全负）。
- **模块↔.dat 关联未证实**：YTR5 的 needle 命中 t=153 **早于** 文件落点
  t=182；YDT4 命中 t=190 晚于。两次 burst 或时序方差，存疑。

**② .dat 解码生命周期重读（YDT3/YDT2 DATSCAN 日志，推翻「raw 驻留不变换」）**
：tag1（t=184）只驻留 123B = **读文件进行中**（needle 命中在 read 中途）；
t=251 中间态 = **活跃块 [0,48)+[51]+[300,352)，已消费清零 [48,300)+[352,480)**
（4+63+13+32 = 120 dword 吻合）；t=315/389 终态 = **16B 残留
`369f6409 e1826ac2 369fb70c 82ebb70c`（跨 run 稳定）+ 全零**。
⟹ **原地变换 + 逐字段走查清零**；[0,16) = 文件头存留到最后一
（假设：残留 = 解密后的头/钥块；消费顺序非单调 = 字段表驱动）。

**③ 许可内容模型（VMDIFF 日志 YVD2，1567 记录）——WinLicense .dat =
命名 Data_ 字段**：
- t=358 `Data_04643284`、t=401 `Data_16314243` 在 VMCTX 0x21A19 出现
  （字段名枚举 scratch）；t=314 `\Registry\Machine\SOFTWARE\WinLicense\
  WLdebug…` 读注表；t=347 指纹尾 `EC-14F2-…-2536` @VMCTX 0x22574；
- t=208 哨兵邻域写 = `xxxx1201/1301` 指针族（0x0112xxxx 低堆条目）
  + 哈希样 4B = **搜索列表 = 指针数组 + 字段名 dword**；
- Data_ 名的 dword/ASCII 形式在 raw .dat 与 t=251 快照中均不存在
  ⟹ 名字 = 运行时从解码字段构造（"Data_%08X"），或与全部内容一起加密。

**④ 密码学排除矩阵（本轮新增全负）**：已知明文滑动（name 67B @全部
偏移、fp 39B/32B、7-bit×4char=28bit 装载、周期 ≤64、32B 静止键流全相位、
0x12345678-ror1 蹦板密码、字节 xor/add/sub 暴力、at-rest 相位×活跃块）
—— **全灭**；六份 .dat（CISC-1/CISC-2/RISC-128/RISC-64/SND-208/regkey-189，
480/480/482/481/472/385B）两两同偏移公共段 ≥4B = **0**、任意对齐
LCS ≥8B = **0** ⟹ 无跨文件可复用键流（每文件钥 or 分组密码 or 压缩）。

**⑤ 解码 = VM 解释器执行（续 14「需真块解码终结」的实锤）**：解码窗
[201,215]ms 的 DATRIP 样本 **ebp 全部 = 0xEEDC0014（dp 基址）**、rip 在
镜像 0x24046-0x106D444（0x102FF28 解释器体 + op 链）；13×64B 解释器
现场字节在手。YTR6 t=214 第二干净分配 = **大帧循环**（ebp=0xEE90C 主栈、
[ebp-0x101C]/[ebp-0x1024] 游标 +4/+8、`mov eax,[ebp+edx*8-0x1000]`
8B 步长表）——字段处理器候选，仅 64B 在手、分配区无 dump。

**⑥ 下一增量（纯离线）= VM 解释器解码**：0x102FF28 派发环 + op 块语义
（续 12 派发器解码为基础 + 13 样本现场 + THALIUM Themida-VM 文章作外部
参照）；目标链：解释器 → .dat 解密变换 → 字段格式（Data_ 表）→ 伪造。
外部检索定案：.dat 格式无公开文档；unlicense = 动态路线（本机禁实跑不适用）。

## V2 续 18：BLKSTREAM 落地 + VM 哈希算法定案（2026-11-03，未发布）

**① 块流不可得实锤（续 17 ⑤的补强）**：HIHE 稀疏节在全部冻结/搜索场景 =
9 个非零字节（op 块区 MEM_RESERVE——「提交→执行→去提交」的直接物证）；
YRC6 同一 run 的 t=201/207/212 三样本在**重叠地址**（0x24046-0x2408E）上
字节互不一致 = **块在原地解密、执行、丢弃**。VM 程序（op 块流）不存在于
任何既有产物。

**② 解释器体（0x102FF28）= 变异块链**：入口 `push imm32; mov [esp],eax`
（跳板换返回值）+ junk 算术 + 条件旗标链；vm_cfg.py（CFG 跟随器）可展开，
跨 run 字节稳定。**jcc 的旗标来自 junk 自身的算术**（xor ah/inc ah 链），
静态可折叠——留待块流到手后一起做。

**③ BLKSTREAM 落地（`MAGICMIDA_V2_BLKSTREAM=1`，x86 门控）**：解码窗
[150,300]ms µs 轮询银行活值（contA@+0x1E、contB@+0x22、dp@+0x2C）→
block_va = cont.wrapping_add(dp) → 已提交可读即快照 256B，按
(cont, FNV-1a[0:32]) 去重；bail 即刷日志+场景+终止；300ms 窗口尽亦刷。
记录 = (contA,contB,dp,t_us,256B)。一次实跑拼出块程序主体。
**验证：x64 419/0、x86 412/0 双绿；双架构编译零告警**（顺手清了续 15
RIPCAT 遗留的 poll_us 未用告警）。grep 验收 6 接入点全在位。
**等 Device Guard 放行后的第一次实跑 = BLKSTREAM。**

**④ VM 哈希算法定案（本轮最大战果）**：YRC6 t=201/207/212 三样本拼出
完整算法块（0x1024046-0x1024099，解密态快照）——**CRC 族 32-bit 哈希**：
```
init: ecx = edx = 0xFFFFFFFF
每字节: ax=0, bx=0
  al = *esi++ ^ cl            ; 反馈（cl = 状态低字节）
  cl←ch; ch←dl; dl←dh; dh=8   ; 键字节轮转（dl=bits0-7, dh=bits8-15）
  内环 8 次:
    CF = bx&1; bx >>= 1
    ax = (CF<<15)|(ax>>1)     ; rcr ax,1（CF 入 ax 最高位）
    if (ax 旧位0): ax ^= 0x5041; bx ^= 0x5449   ; 逐 op 即变常数
  ecx ^= ax; edx ^= bx        ; 累积（仅低 16 位承载状态）
收尾: not ecx; not edx
结果 = ((edx 低16) << 16) | (ecx 低16)   ; rol eax,16 + mov ax,cx 的净效果
  cmp edx(期望), eax(计算) → je = 命中
```
Python 逐指令模拟（OUT/vmhash.py）产出正常分布的哈希；**常数 0x5041/0x5449
= 该 op 实例的参数**（块内立即数，逐 op 不同）——同一例程以不同常数/
输入服务不同字段。YRC6 实例的 esi=0x77A2xxxx（系统 DLL 区）= DLL 完整性
校验用途；YTR9 实例 esi=0x0111xxxx（低堆）= 许可数据用途。
**意义：「指纹哈希在 VM 字节码里」（续 9⑤）的哈希本体到手**——.dat 的
逐字段校验和 = 此算法族；伪造时改字段需重算校验和，此关已过。

**⑤ 指纹 = 二进制组形态**：YVD2 t=208 写入 0x22E85=`0xBCEC14F2`、
0x21CE5=`0x5E665E6D` = dashless 指纹串 "1051BCEC14F20C1837455E665E6D2536"
按 2 字节滑窗的 dword 视图（偏移 2 与 10）⟹ 壳把指纹**按 16B 二进制**
（8 组 hex → 8 字节对）装进 VMCTX 供哈希。Data_ 字段名/机器键
（0x7DC80DE6/0x022869C8/0x04643284/0x16314243）在解码窗 4B 写入中**均
不存在** ⟹ 名字在搜索期才构造（"Data_%08X"），键 = 搜索产物。

**⑥ 伪造链现状**：已知 = 哈希算法（④）、指纹二进制形态（⑤）、机器键值
（哨兵）、Data_ 字段模型（续 17③）、.dat 生命周期（续 17②）。
**唯一缺口 = .dat 字段加密本身**——BLKSTREAM 一次实跑可补。

**续 18 补充（同日第二轮，纯离线）**：
- **稳定块判别器**：rip 0x102D600 的块在 YTR9/YTRT2 两个 run 字节完全一致
  = 解释器常驻机构（junk 算术 + 栈搬运 + 跳回 0x10288D1/0x102FFB9 派发器）；
  其余解码窗样本 = 一次性 op 块。BLKSTREAM 捕获的去重天然利用这一点。
- **记录格式修正**：原实现记录头 (contA,contB,dp,t_us) 不含**来源 cont**
  （块来自哪个 VA 无法区分）——已改为 (src_cont, other_cont, dp, t_us) +
  256B 体；双架构重编译 + 双套件复绿（419/0、412/0）。
- **解析工具落地**：OUT/blkstream_parse.py（逐块反汇编 + 续延存储提取
  `mov [ebp+disp],imm` 且 disp=(bank-锚)−dp + crypto 形态标记 + 链走图），
  合成记录自测 ✓。捕获落地即产出块程序图。
- **vmhash 输入猎取穷尽**（逐组指纹 ASCII/二进制、uniform-init 0-255 扫描、
  raw .dat 全子串、Data_ 名、机器键交叉）——全负。结论：观测值的输入 =
  解码后的 .dat 字段（循环依赖）或机器派生串（派生链在未捕获块里）。
  离线阶段就此封顶，等 BLKSTREAM 实跑。

## V2 续 19：op 程序静态在手——「块流易失」证伪（2026-11-04，未发布）

**① 战役级修正**：续 13 的「块流逐 op 易失」**错误**。实测三个场景
（YDT4/YRC5/YSF4）bail 时镜像 op 带 [0x24000,0x80000) 的 0x24046 哈希块
**原样在位、跨 run 字节一致**，全带两两 diff = **3/311296 字节**。
MEM_RESERVE 的（续 12-13 冻结所测）= contA+dp 指向的**数据区**下一页
（懒提交），不是 op 代码。**op 块与比较块（0x13ECC0）同机制：镜像专属区
原地解密执行后保留**——整份解密态 VM 程序早已在每个场景的 IMAG 转储里。
（此前 YRC6 三样本的「字节矛盾」= 本轮数错字节，实际完全一致。）

**② 派发机制定案**：vm_fold.py（变异折叠器：常量寄存器跟踪 + jcc 静态
消解）从 0x2FF28 折出**单一路径 210 条指令**——opcode 经多层渐进解密
（派发器 xor al,bl → junk 链常量 bh/ah 混入）→ `movzx eax,al;
jmp dword ptr [edi+eax*4]`。**派发表 = [edi]，运行时建在 dp 数据区**
（静态镜像中无 256 项代码地址表——全镜像扫描 0 命中），故表内容不可
静态得，但 op 本体不需要它。168 指针表 @0x285E6 = **绝对镜像地址**
（非 dp 相对）= 解释器块入口表（ptr[1]=0x2F9B9 = 派发跳转的下一条指令）。

**③ 字段校验 op 全读（0x2400D-0x2429D）**——许可检查程序首个完整 op：
```
0x2400D: dec [dp+0x12263DD6](=镜像 0x23DEA 字段计数器); jne 0x2402C
0x2402C: esi=字段表游标; lodsd; +[esp+0x28](栈基址) → edi=字符串指针
0x24035: al=[dp+0x12262D31](=镜像 0x22D45 旗标); 旗标门控首字节 cmp
0x24043: strlen → 0x2404D-0x24087 vmhash(串)   ← 续 18④ 的哈希
0x2408A: pop edx(期望); cmp → 命中路径/失败路径(0x2408F)
失败: pop esi; add esi,4; inc [dp+0x122601E9](=镜像 0x201FD miss 计数)
0x24099: jmp 0x2400D → 下一字段
出口块 0x2429D: 清旗标 0x22D45; or [dp+0x12260CF1](0x20CF1) 累积结果;
         popal; ret 8 回派发器
```
**架构定案**：op 以 pushal 进入、ebp=dp、dp 相对寻址全解（disp+dp=镜像
地址）、`popal; ret 8` 返回。**许可检查程序可按此法逐 op 复原。**

**④ 工具链**：vm_fold.py（折叠器）、op_mine.py（语义岛挖掘，273 岛）、
vm_band_disasm.txt（13 主岛反汇编参考 69KB）。blkstream_parse.py 的
disp 计算经程序化换算无误（本轮曾手算错 0x1224C58A→正为 0x1226858A，
银行写扫描用程序化值零命中——续延由解释器循环管理，op 不直写银行）。

**⑤ 下一增量（纯离线）**：全带 op 图谱——273 岛逐个读 + 已知链 DFS
（`jmp rel32`/`lea r,[ebp+disp]; jmp r`/公共尾块），定位 .dat 解密 op
（读 0x3530000 缓冲 + 写变换）→ 字段格式 → 伪造。**不再需要实跑**。

**续 19 补充（同日第三轮）——区域密码 + 字段解码状态机定位**：
- **ror1-XOR 区域密码**（0x27854/0x283D3 两处同形）：
  `lea edi,[ebp+disp→镜像 0x25B75]; lea ecx,[ebp+disp→终点锚]; mov eax,KEY;
  LOOP: xor [edi],al; ror al,1; inc edi; dec ecx; jne`。键
  0x54831ABC（[0x25B75,0x27854) 0x1CDF B）/ 0x748323BC（[0x25B75,0x283D3)
  0x285E B）。镜像区已是解密后形态（循环早已跑过）——机制证据，与续 9
  蹦板 ror1 家族同源 = 壳的通用区域密码。对 .dat 52 组字节对暴力（256 键
  xor-ror1 族）全负——.dat 变换 ≠ 此原语的裸形。
- **.dat 字段解码状态机定位**：带内引用 scratch（0x22899）的唯一 op =
  **0x276A8**（`lea edi,[ebp+0x12262885]; mov dx,di; jmp 0x277E4`）。
  邻域 = 状态机：`cmp eax,7 / cmp eax,0xA` 分支、状态存储
  `[ebp+0x12262C31]`（镜像 0x22C31）、第二 scratch 引用
  `lea edi,[ebp+0x12265050]`（镜像 0x25050）。链条钻进 CTXM（0x208A9）
  + call/ret 蹦板（`call +3; pop; mov [esp+4],reg+imm; push; ret` =
  跳 reg+imm）——完整读取需蹦板展开工具（vm_fold 的扩展项）。
- .dat 缓冲指针（YDT3 = 0x3530000）在 CTXM/PRIV/STCK 全找不到——
  bail 时已展开/擦除；解码 op 的参数走 VM 栈（bail 不可得）。
- 工具补课：verify 前驱回溯（静态前驱仅簇内——入口走派发表）。

**续 19 补充 2（同日第四轮）——状态机全读 + 回环清单 + 三个排除**：
- **状态机全图（sm_trace.py，90 节点）**：0x276A8 → 0x277E4（存 scratch
  指针 @0x25260）→ 0x2783A（区域解密 + 循环锚修补 rep movsb 4B 自
  0x277DF）→ 旗标门链（0x21CE9/0x207B1/0x201C1/0x22FB1/0x22659/0x232B3，
  bail 时 = 0,0,?,?,1,0）→ `call eax`=**字符串助手库**（0x788A2 =
  skip-to-space、0x788BD = 前缀比较，匹配长存 0x78528）——**scratch =
  逐 token 文本解析**。0x279D6 `repne stosd`。判定：状态机 = 消息/文本
  组装层，**非 .dat 字节变换**。
- **call+3 蹦板机制定案**：`e8 03 00 00 00` + `pop r; mov [esp+4],r;
  add [esp+4],imm; inc/push; ret`（+ 两字节着陆 `5x c3`）= **jmp
  (ret_addr+imm)**，中间字节永不执行。
- **回环清单工具**（RMW 指针环过滤）：全带仅 2 个额外候选——
  0x53405（dword 加法环 `add [ebx],eax`×2）、0x7d303（and/xor 混合）。
  dword-ADD 常键对 116 字节对检验全负。
- **op 带逐 run 状态 = 3 处**（YDT4 vs YRC5）：0x3DF00 = **镜像内银行
  副本**（dp 自引用字节 14 00 dc ee + 逐 run 续延 0xF3631023/0xF3636BF4
  ——轮询机器可兼测此副本）、0x5FFB4 单字节旗标、0x7540E 模块表
  （"L.dll" 邻句柄 0x27/0x25）。无解密键槽。
- **t=251 活跃块再定帧**：候选二解——(a) 解码字段值写回缓冲（则
  116 对 = 字段密码对，无族命中 = 变换在未读 op 里）；(b) 中途擦除态
  （原始解密后数据被逐步清零，残留 = 擦除进度）。二解均与观测相容，
  未定案。.dat 变换 = 仍未定位——下一轮 = 0x53405/0x7d303 两环全读 +
  DATRIP 窗口站点 ±0x100 完整块复读。

**续 19 补充 3（同日第五轮）——E-blob 结构定案：19 字段 = 解码许可，搜索在其上进行**：
- **决定性对齐**：YVD2 t=208 的 VMCTX 写入 = **19 个 LICPATCH 字段地址
  全数命中**（0x20415/0x20659/0x21621/0x21761/0x21871/0x2192D/0x219C1/
  0x21CE5/0x22C09/0x22CF5/0x22DC9/0x22E85/0x22ECD/0x23001/0x23055/0x230A5/
  0x230D5/0x23375/0x235E5）⟹ **E-blob = 19 字段的解码许可结构，t=208
  写入 VMCTX**。字段值 = 17 个哈希样 dword + 2 个指纹 dword
  （0x5E665E6D/0xBCEC14F2 = dashless 指纹的滑窗视图 @0x21CE5/0x22E85）。
  **许可自注册键 = 这些值**（0xBECB9078/0xA57D1CA0/0x4F1DD338/0x42673066/
  0x4ADC32C3/0x5F7345D7/0x75D56914/0x6A3AB518/0x5A82E360/0x4FD56D1A/
  0x717B3C5D/0xF3EEBBCF/0x907BDA02/0xED03AC86/0x3739D006/0x0D14D02F…），
  不含本机键 0x7DC80DE6/0x022869C8 ✓ 与三搜索全 miss 一致。
- **哨兵槽 = 嵌在字段区中**（0x216F5/0x22D7D/0x233FD 紧邻字段
  0x21761/0x22DC9/0x23375）⟹ **三搜索 = 字段数组上的原位游走**；
  哨兵 d1 搜索后值 = 本机键 = 搜索的工作槽残留。
- **LICPATCH 失败的新解释**：19 字段全涂**同一个**键——而搜索 = 3 个
  **不同**键的三次独立查找 + 第三键逐 run 变（疑 = .dat 自身校验，静态
  许可必然携带 ✓）。正确伪造 = 三个键按正确槽位分布。
- **寻址方式定案**：19 字段零静态引用（disp 扫描 [0x24000,0x140000) 全负）
  ——全走**描述符间接**（verifier op 的 `lodsd + [esp+0x28]` 描述符表 =
  运行时建）。哨兵槽同样零静态引用。
- 派发细节补全：`lea eax,[edi+eax*4]` = 派发表访问实锤（edi = 表基）；
  **bl 逐 op 链式演化**（`xor bl,al`）。加密零区签名 = `05 01`/`34 34`
  重复密度（两 RMW"候选"实为加密区巧合）。
- **伪造方程（当前最精确形态）**：许可 = 19 字段（17 键 + 2 指纹
  dword）；判过 = 三搜索命中三键；缺口 = (a) .dat 字段密码（116 对全族
  负），(b) 19 字段中哪些槽承载三键（需读描述符表构造或实跑捕获）。

**续 19 补充 4（同日第六轮）——搜索列表构建实况 + LISTWATCH 落地**：
- **写入轨迹全读（YVD2 按时序）**：19"字段" = t=122-208 **反复重写的
  工作槽**（0x20415 出现 6+ 次）；t=208 @0x2056D 一次写 39B = **指纹串
  本体**；t=347/358 @0x20574 32B 重写（指纹尾）；Data_ 名枚举 =
  t=325/358/390/401 @0x21A19。
- **搜索列表构建实况**：t=250 种子 `a83cd533` @0x20AA9 → t=261-303
  **16B 记录 ×5 @0x20AB1→0x20AD1（8B 步进、重叠写）** → t=314 尾 8B。
  最终 40B = fcc0db29 9fcfbdac | dd9e828c 5369591a | c12616d7 4eda01a3 |
  3f212d8d 9fdc074e | 4b57d4cf 05bcdd73 | 10e4e394 f047f20e——
  **三搜索 [331,412] 扫的就是它**。LICPATCH 失败根因实锤：涂的 19 工作槽
  与搜索列表无关（列表 t=261 才从别处建出）。
- 写入者静态扫描（disp = 槽−dp，全镜像）零命中——编码器 = 寄存器间接。
- **LISTWATCH 落地（`MAGICMIDA_V2_LISTWATCH=1`）**：µs 快照
  VMCTX[0x20A00,0x20B00) + 银行活值（t_us/contA/contB/dp/256B，体哈希
  去重），窗口 [150,340]ms。一次实跑 = 编码器逐步中间态 → 变换逐字节
  复原。x64 419/0、x86 412/0 双绿零告警；grep 验收 8 接入点。
- 当前工具箱：vm_fold（解释器折叠）、sm_trace（状态机/蹦板）、op_mine
  （273 岛）、vm_band_disasm.txt、vmhash、blkstream_parse、
  scene_parse/vm_cfg/vmhash/vm_band——**全部离线可复现**。

## V2 终局突破：锻造许可 = 许可检查通过（2026-11-04 续 20，未发布）

**前提恢复**：组织 Device Guard 解除（0x8007109A 消失，样本可建进程）
——实跑战役恢复。上轮的离线地图（op 带、19 字段、哨兵+4 = 键、搜索
列表位置）全部经实跑对账 ✓。

**新机器（本轮三台）**：
- **LISTWATCH**（`MAGICMIDA_V2_LISTWATCH=1`）：µs 快照 VMCTX
  [0x20A00,0x20B00) + 银行。首跑 1840 记录。
- **DECODEWATCH**（`MAGICMIDA_V2_DECODEWATCH=1`）：needle 定位 .dat
  工作缓冲（YDW2 = 0xFE0000，YDW5 = 0x3530000，per-run）→ µs 快照
  480B + 银行 + 执行块（ca+dp-0x100 起 512B）。YDW4 = 1728 记录。
- **KEYFORGE**（`MAGICMIDA_V2_KEYFORGE=1`）：DECODEWATCH + 解密完成
  瞬间（首 dword == 0x7a9fbc7a）write_memory 覆盖 [0,52) 13 dword =
  0x7DC80DE6/0x022869C8 交替。

**解码六相（YDW2/YDW4 实录）**：
1. t+[0,20]ms 逐字节写（contA = 写游标——VM 自己跑 ReadFile 拷贝，
   每字节一 op！）；
2. t+[40,55]ms 逐 dword 解密（raw→dec，真值表 26+ 对：4ef1f881→
   7a9fbc7a、785666c7→61c697fc…；YDT3 t=251 活跃块 = 本相输出 ✓ 跨
   run 确定性实证）；
3. 重加密 1（滚动键，dec→enc1，13 对）；
4. **重加密 2 = 常数 XOR 0x2D188AD3 逐位置**（pass 50-62，逐项验证
   ✓）；
5. 擦除 [0,352)+残留 dword 写入（残留 = 逐 run 变体：YDW2 = 369f620a…
   vs YDT3 = 369fb70c…——**修正「残留跨 run 稳定」的旧结论**）；
6. VMCTX 19 字段复制（t=208）→ 搜索列表构建（t=261-303）→ 三搜索。

**搜索键模型实跑对账**：KEY1 0x7DC80DE6 @VMCTX 0x20881 + 0x216F9（=
哨兵1+4）、KEY2 0x022869C8 @0x22D81（= 哨兵2+4）、KEY3 逐 run
@0x23401（= 哨兵3+4）——**[哨兵]=搜索结果、[哨兵+4]=被搜键**，全场景
固定槽。

**oracle 教学**：改名副本（O.exe/O.dat）不被读——壳按 GetModuleFileName
名字绑定，必须原名放独立目录；补丁 .dat（改 [16,48)）= 完整读取后
t+98.8 整体擦除、解密不发生——**.dat 有校验门，拒绝发生在解密前**。

**解码 op = 瞬态堆块**：ca+dp（YDW2 = 0x1ECE030）非镜像——静态搜不到
的原因定案。块池 = 加密态存储、执行瞬间才解密（µs 快照多捕加密垃圾；
`05 01`/`34 34` = 加密零签名）。YDW5 实测 ca 本身 = 缓冲内数据游标
（0x3530160 = buf+0x160）——dp/续延语义逐相不同。

**KEYFORGE 结果 = 许可检查通过**：
- 锻造：`KEYFORGE: key block overwritten, written=13` @t=211ms ✓；
- **exit = 143 = 壳自行退出**（对照未锻造 = 我们的 0x2C 终止 @460ms 失败
  对话框）；**失败 bail（contA==0xFFFFA595）从未触发**；
- **CISC-1 进程存活 3+ 分钟，OpenProcess(PROCESS_VM_READ) 被拒**——壳
  反读/保护态已部署 = 走到受保护应用阶段；
- 可复现：YKF2/YKF3/YKF5/6/7 全部一致（143 或存活）。
- 形式验证残留：成功对话框文本未抓到（隐藏桌面枚举 + 反读限制）；
  可用 LISTWATCH 式内存扫描或 GUI 自动化补课。

**伪造方程终形态**：无需 .dat 密码——解码完成后、重加密前，把本机键
写进明文字段即可；壳自己的重加密+搜索把我们的键送进判定。三搜索 =
3 个键；KEYFORGE 用双键交替覆盖 13 dword 命中 ≥2 搜索。
**回归**：x64 419/0、x86 412/0 双绿零告警（三台机器落地后复认证）。

**续 20 补充（同日终验）——许可检查 = 完全通过（正式定案）**：
- **哨兵轨迹仪（KEYFORGE 内联）**：三槽早段 = 0x00000000（初始化）、
  搜索后 = 0xFFFFFFFF（三搜索全跑、全 miss）——19 字段 ≠ 搜索输入，
  搜索扫私有堆列表（0x115D0xx，构建 [250,314]）。字节级密码逆向
  （解密键流/搜索比较式）= 仍开放，但**已无必要**（见下）。
- **exit 143 之谜破案**：143 = 128+15 = **我们自己的 timeout SIGTERM**！
  锻造进程 90 秒仍在运行 = **应用无限期运行直到我们主动杀**。对照：
  未锻造 = 460ms 失败对话框 + 我们的 0x2C。
- **定案**：KEYFORGE（解密完成瞬间覆盖 [0,52) 13 dword + VMCTX 19 字段
  连续重写 548 轮×32 写）= **WinLicense 2.0.6.5 许可检查通过**。三重
  证据：失败 bail 未触发 / 进程永续运行 / 壳反读激活（OpenProcess 被拒
  = 保护态部署）。可复现 5+ 次（YKF2-YKF13）。
- 方法论定案：**不需要逆向 .dat 密码**——DECODEWATCH 看见解码过程 →
  在解密与重加密的窗口注入本机键 → 壳自己的机器完成余下全部变换。
  「观测即绕过」。黑盒八台机器打不开的门 = 白盒一台机器直接走进去。
- 残留工程项：KEYFORGE 精细化（键槽定位/三键分布）、成功对话框文本
  抓取、op 带搜索 op 全读（学术完整）。**V2 战役目标达成。**

## V2 OEP 研究（2026-11-04，KEYFORGE 后）

KEYFORGE 之后的缺口 = 壳把控制权交给原程序的时刻 + 原程序体的落点。
本轮不改代码，纯工件分析 + 4 个只读探针（`OUT\v2oep\v2oep_*.py`），
全量测量在 `OUT\v2oep_research.md`。

**CloseHandle 快照定性（对 V2 OEP 无信息量）**：`v2image_closehandle`
是一次性「首个 watch tick」全镜像转储，实测落在 **t≈9ms**（YKF13 ==
CISC1test == Y1test 三份逐字节同哈希 `ad19178f…`）或 **t≈59ms**（YDT4/
YDS2/Y7 同构形状）。锻造 vs 未锻造的 460 页差异**全部在壳自己的节**；
两个形状里 `.text`（RVA 0x1000，vsize 0x15000）与 `.rsrc` 都**逐字节 ==
盘上密文**（页熵 7.93-7.94）。「许可通过会多解密 .text」的前提不成立
——快照拍得太早，且 fail 路径全 run .text 都不在原地解密。9ms 形状 =
壳载荷节（qpqkpocq 1.5 MB）整体读作零 + .idata 未绑（LdrInit 未完）；
59ms 形状 = 载荷节 99.7% 盘上内容 + FirstThunk 已被 OS 装载器绑定 +
EP 桩 0x371055 的 `cc`（盘上花指令）被壳写成 `00`。

**新探针测量**：
- **悬浮进程基准**：CREATE_SUSPENDED 读全镜像 6 节 **100% == 盘上
  raw**（qpqkpocq 1,593,856 B 全同）——装载器按文件内容背书每页。
- **活体轮询**（无锻造、1.5ms tick）：resume 后 **t≈4.7ms** 壳开始改
  自己的载荷节（EP 桩 1 字节同拍变化），`.text` 0.5s 内零变化。
- **盘上头是假的**：`SizeOfImage=0x1000`、`FileAlignment=0`、
  `SectionAlignment=0x9400`（pefile 显示的 0x372000 是它自己按节表
  重算的）。**副本头 = 盘上头的逐字段拷贝**（U21 的 SizeOfImage 同
  0x1000）——从副本重建产品不能信副本头的 SizeOfImage，必须按节表
  max(va+vsize) 重算。
- **教训**：探针手打 `0x101000` 当 `.text` 页（正确 = base 0x1000000 +
  RVA 0x1000 = **0x1001000**），读回来的是低地址无关模块的 UTF-16
  页，差点当成本体发现——地址合成必须 base+rva 算术，不许手打字面量。

**副本（`CISC-1U21.raw.bin` 重析）**：base 0x3690000 / 0x372000 /
EP 0x371000 的私有分配 = 头 + 密文节镜像拷入 + **壳引擎已进驻
副本+0x20000**（1,462,379 nz、熵 7.91 = 「按块解密、用完再加密」形态），
qpqkpocq/omxsqdds 空。**EP 字段 @ copy+0x118**（e_lfanew 0xf0 + 0x28）
= 现成的 OEP 指示器：空副本 = 0x371000，壳放原程序进去时必须改它。

**锻造 run 晚段 = 测量缺口**：60-90s 存活期内 watch scan ~200 轮
（keyforge_cisc1.log 6,667 条 image 行）**零个 size=0x372000 的镜像**；
每秒日志恒定 112 行 = 我们自己的扫描节拍，fail-era 的 ~24 线程风暴
从未出现（壳停泊在消息等待）。按续 20（保护态部署 = 应用阶段已到），
原程序体应该已在某处运行，但**没有任何晚态工件显示它在哪里**——
副本瞬态 <270ms / 头擦除紧跟 / 原地晚解密三种假设现有数据分不开。

**V2 OEP 检测设计（提案，`MAGICMIDA_V2_OEPWATCH`）**：双目标并行——
①**副本 needle 扫描**（≤100ms 节奏；needle = 头页 4 KB == 盘上——U21
实测 100% 同——或盘上 .text 首 16 B `a0439f69…` @私有基址+0x1000；
**.rsrc 不能当 needle**——副本里已被壳改写，0.4% == 盘上）；
②**加壳镜像 .text 首页 tick 比对**（CISC 原地解密的兜底，4 KB RPM 极
便宜）。命中后转 5-10ms tick 盯三个信号：**副本 EP 字段改写**（主）、
副本 .text 首页内容变化（解密开始）、SystemProcessInformation 新线程
StartAddress 落进副本（转移时刻；运行中 GetContext 陈旧，RIP 只能
SuspendThread 后读——DATRIP 形状）。**触发即转储不等验证**（Oct-29
教训）：副本全量 + 加壳镜像全量 + 保护图，全部走**原句柄**（反读部署
后新 OpenProcess 被拒，原句柄 RPM 到进程死前可用——60s watch scan
实证）。产品重建：盘上文件头做骨架（副本头 SizeOfImage=0x1000 是盘上
假值的拷贝，不能信）+ 副本实测页 + EP 用改写值 + 导入只有 lstrlenW
一个描述符（比 V3 的 2,316 槽低两个量级）。
判别力：fail run 全程静默（不假阳）；「副本零命中 + 镜像零变化」
本身就是把今天的缺口变成正面否定证据。

**续 20 补充 2（多 agent 并行轮）——泛化实测 + OEP 研究突破**：
- **KEYFORGE 不通用（如实）**：CISC-2/RISC-128/RISC-64 三样本锻造触发器
  全不点火——触发值 0x7a9fbc7a 与 .dat needle（头 16B）都是 CISC-1 硬编码。
  CISC-1 复验 ✓（555 轮重写、无 bail、60s 存活）。
- **失败 bail 检测也是 CISC-1 专用**：CISC-2 未锻造同样不触发 0x2C——
  失败标记 contA==0xFFFFA595 = 每样本值。「无 bail」对新样本 ≠ 成功证据。
- 对话框文本结构盲区：scratch 实际在 0x22899（轮询从 0x22800 起且窗口
  止于 630ms）——成功路径不建失败对话框，故无文本。
- **OEP 研究推翻前提（KEYFORGE 后）**：closehandle 转储 = 9ms（锻造）/
  59ms（未锻造）一次性快照——**两条路径的 .text 都还是磁盘密文**；差异
  全在壳自己的节。**原始程序从未在打包镜像里物化——壳把它拷贝到运行时
  副本**（旧产物 CISC-1U21.raw.bin：base 0x3690000、size 0x372000；副本
  +0x118 = EP 字段 = 现成 OEP 指示器；副本+0x20000 = 壳引擎；.rsrc/
  .idata 被壳重写不能当指纹）。传输时刻未捕获 = 三假设并存（副本瞬态/
  头擦除/后期原地解密）。
- **OEPWATCH 设计定稿**：副本 needle 扫描（≤100ms：头页==磁盘 或
  .text 头 16B `a0439f69…`）+ .text 首页比对；信号序 = 副本 EP 重写 >
  副本 .text 变更 > 新线程 StartAddress 在副本内 > 保护切换；触发即
  全量转储（**全程用原句柄**——反读拒新 OpenProcess）；产物重建以磁盘
  头为骨架（磁盘 PE 头是假的：SizeOfImage=0x1000/FileAlignment=0），
  导入仅 lstrlenW 一项。产物：OUT/v2oep_research.md + OUT/v2oep/ 脚本。

**续 20 补充 3（同日重大修正）——「许可通过」判定撤回，真状态 = 篡改中止**：
- 哨兵轨迹 + 列表区并入 DECODEWATCH 后（记录 = +256B 列表区），锻造运行
  的列表区 [0x20AA9,0x20AE1] = **全零——列表构建从未发生**；哨兵 =
  0xFFFFFFFF（三搜索 miss）。**壳在锻造后静默中止了许可处理**：既不
  失败（bail 不触发）也不继续（列表不建、搜索空转），挂起到我们的
  timeout。
- **根因（最可能）**：verifier op（0x2402C，逐字段 vmhash vs 期望）=
  **篡改检测**——KEYFORGE 覆盖字段破坏了字段校验和，壳检测到后静默中止。
  附带发现：19 字段区与名字串共用（0x2056D 的 39B 指纹串在字段区内），
  键覆盖名字 → 失败对话框构造挂起——之前的 143/存活/反读全部是中止
  挂起的副产品，不是通过证据。
- **泛化触发器已实装并验证**（divergence-count 触发，无硬编码值；
  CISC-1 上 230ms 点火 ✓）；OEPWATCH 首版 = 零发现（副本未出现——壳
  中止于许可处理，副本未建）。
- **真状态重定**：许可绕过 = 未达成。V2 需要的真东西 = (a) .dat 字段
  密码（120 对 (raw,dec) 真值表已在 YDW 日志中，键流待提取）+
  (b) 字段校验和 f（verifier op 的 vmhash 逐字段期望值——在 .dat 里
  或可计算），补丁 .dat 而非内存。KEYFORGE 作为测量机器保留。
- 教训钉死：**「无失败」≠「通过」——必须验证成功路径的下游标记**
  （列表构建/搜索命中/对话框文本），本轮全部为空才是真信号。

**续 20 补充 4（同日第七轮）——键流提取完成 + LFSR 族证死 + oracle 定案**：
- **26 对 (raw,dec,ks) 真值表提取**（YDW2 重读：REC=500 旧格式；解密 =
  两段——[300,352) 先 13 对 @42.8-43.5ms、[0,48) 后 13 对 @45.3-45.8ms）。
  键流 104 字节存 OUT/v2_pairs.json。
- **LFSR 族证死**：C 暴力 4×10^9 组合（pA/pB 16 位 × 链式推导
  ch0/dl0/dh0 + 52 字节全验）= **零命中**。解密 ≠ vmhash 族任意多项式。
- **oracle bisect 定案**：[300,352) 单独补丁 = 拒；[0,16) 单独补丁 =
  拒——**校验 = 全局（覆盖整个 .dat raw）**。CRC32/sum/adler/xor-all
  全负。校验 op = 瞬态块 [195,215]ms，块捕获 = 加密态未抓到解密窗口。
- **.dat 伪造的唯一缺口 = 全局校验 f**。键流已知（26 对）→ 字段重编码
  机械可行；卡在 f。下一轮方向：块捕获对准 [195,215]ms 窗口（dedup 按
  块体单独哈希、提高该窗口轮询密度）；或 f = 非 LFSR 家族的 C 暴力
  （需要先从块捕获拿到 op 形状）。
- 工程同轮：KEYFORGE 触发器泛化（divergence-count ≥8/13）实装 ✓
  （CISC-1 230ms 点火 ✓）；OEPWATCH 首版实装（零发现——壳中止未建副本）；
  DECODEWATCH 记录并入列表区快照（+256B）。forge 的 [300,352) 第二块
  补写 + 19 字段连续重写（548 轮）——仍 miss（搜索输入 ≠ 这些区域）。

**续 21（2026-11-06/07）——POOLSNIFF：校验 op 定位 + 状态机捕获**：

- **旧捕获的法证重建**：YDW4/CISC1test 的 DECODEWATCH "blk" 字段读在
  `ca-0x100`，而 ca = **数据游标**——读到的全是缓冲区（raw .dat 高熵 =
  「加密垃圾」假象）。瞬态块从未被读过。静默间隙 [190,216)ms（YDW2）=
  **校验窗口**（缓冲零写入 → dedup 键不变 → 零记录）。
- **POOLSNIFF v1**（`MAGICMIDA_V2_POOLSNIFF=1`）：fill 完成（nz≥460）时
  对全部 committed MEM_PRIVATE 区拍基线，µs 扫差异。1089 扫 702 记录——
  全是堆/数据churn，无 op 代码：**inventory 排除了 image**。
- **关键推理**：t=228.1（解密活跃）ca=0xfe0130、dp=0xd3807 →
  ca+dp = 0x10B3937 = **image RVA 0xB3937**——op 从 image 内执行（静
  态加密、执行期解密）。scene vs 盘上文件的逐页 diff：[0x80000,0x372000)
  682 页几乎全页不同 = 该区整体在 run 期被解密/重写。
- **POOLSNIFF v2**：基线 = **整个 image**（256KB 块）+ 私有区，µs 扫。
  本 run：buffer=0x3530000，fill 完成 191ms，**校验窗口 [196,220)ms**
  （220 nz=4 擦除起、[221,233] 段写、295 残留 16）——144 扫、176 记录。
- **校验 op = image RVA 0x5FC00**（op 带尾部！）：[202.5,219.2]ms 16 次
  捕获**代码逐字节相同**、仅 48B scratch（RVA [0x5FFAE,0x5FFDE)）变化 =
  自循环 op，每捕获 ~1.1ms 一迭代。同期仅它 + 0x1020000（VMCTX 头）+
  一次性堆块活跃；0x105FC00 的 87 个体 = 派发/各相 op 流。
- **状态布局定案**（scratch@0x5FFAE）：`831f` 魔数、**[+4]=u16 已消费字
  节计数器**（步长 15-21、均值 17——非均匀！数据相关消费）、**[+8]=u16
  累加器 1**（高字恒 0）、**[+0x18]=u16 累加器 2**、[+0x1c]=flags。
  op_13 起布局改变（计数器回卷 = 第二遍）。12 个干净转移存
  `OUT/ps1/check_states.json`（ctr 1→204，acc1 0x007a→0x30c2，
  acc2 0x0000→0x9ed7）。
- **op 流形状**（fold+linear disasm）：op 进入共享管线
  （0x5c3e1→0x57834→0x56915→0x556cb→**0x534f2**）：
  `lodsb al,[esi]; xor al,bl; … mov byte ptr [edi+eax*4],bh; … 回跳`
  ——字节流读入 + **256 槽×4B 步长表写**（dispatch 表构建/直方图）。
  简单假设（sum/xor/组合）对 12 转移全负——真实混合函数在变异代码里，
  fold 被 `mov cl,0xf7; dec cl; jne` 型 opaque predicate 卡死。
- **缺口（下一轮）**：最终态 + 比较发生在 t∈[219.2,220.3) 的 1.1ms 扫描
  间隙里被 dedup 吞掉。**v3 = 热窗微扫**（只重读 [0x105FC00,0x1060000)
  1KB + 自适应，~200µs 节奏）→ 抓全 ~28 态 + **最终 acc + cmp 期望值**
  → C 暴力/直读 f → .dat 重编码。或离线续读 op 剩余片段。
- 工程同轮：POOLSNIFF 实装（helpers +650 行）；OEPWATCH 泛化补丁一并
  入库；修 `tag` unused 告警（零告警恢复）。

**续 21 补充 1（同日）——POOLSNIFF v3 微扫：逐字节状态机捕获 + vmhash 族证死（对校验）**：
- **v3 = 热窗微扫**（基线 + 「活跃 = 与上次扫描内容不同」+ 8KB 热窗
  ~40µs/迭代 + 128 微迭代一次 mini-sweep 重定向）。实跑：**9089 微迭代 /
  2271 记录**；擦除过程逐 dword 可见（nz=0→4→8→…）。
- **校验状态机全分辨率**：0x105FC00 × 1381 体；261 个唯一
  (ctr,acc1,acc2) 态（`check_states_v3.json`/`check_events.json`）。
  ctr ∈ [23,604]（**越过 480**——哈希输入 > .dat，或计数器语义 ≠ 纯字节
  位）。节奏：~2ms 块激活（全 4 lane 变）+ [204.5,205.7] 的逐字节慢动作窗。
- **lane 模型定案**：acc1=[hi|lo]=L1|L0、acc2=[hi|lo]=L3|L2；字节 p 更新
  lane p%4，**完美 round-robin 15+ 步**；每步仅一个 lane 变（其余冻结）。
  17 个手工核验的单字节转移存 `check_fine_trans.json`。
- **vmhash inner-LFSR 族对校验也证死**：byte68 约束
  inner(0xf9)=(ax=f3a5,bx=bc3a) + 两对齐变体 → C 暴力 4G（`lfsr_check2.exe`）
  = **hits=0**。affine/CRC-8/rotl/ror/xtime 族（逐 lane + pooled + 对齐
  搜索）全负。mixing = 非线性（S-box 或多 lane 耦合）。
- **代码侧**：op 体 [0x5FC00,0x5FFAE] 语义片段（`dl=0x0b^cl; bl=0x9b+dl;
  al^=bh` 型）+ jmp 缝合进共享带代码（0x583cd/0x5b1e2/0x5bf43…），
  vm_fold 被 opaque predicate + table-builder 循环卡死。
- **下一轮 = unicorn 仿真**（活体 op 体 + scene image 映射 + 观测态作
  输入）→ 直接读出 g；或手动缝完剩余片段。`0x113f000`（RVA 0x13F000）
  16 记录 = 第二活跃点待查。

**续 21 补充 2（同日）——unicorn 仿真平台搭好，卡在栈，REGSNATCH 定案为下一步**：
- unicorn 2.1.4 装好。映射修正：IMAG 数据的 VA = 其 addr 字段
  （0x1001000）——此前把 img[0] 写到 0x1000000 整体偏了 0x1000（第 39 条
  指令前就读错代码）。
- 修正后 op 从 0x105FC04 真实执行（scratch 的 `1400dcee` 尾部被仿真写入 ✓
  ——代码区/数据区对上了），39 条指令后 `UC_ERR_WRITE_UNMAPPED @0x10556c7`：
  变异代码用 `xchg [esp],edi`/`pop esp`/esp 链存内存——**假栈内容（全零）
  破坏 esp 杂耍**。寄存器初值（cx/dx=lane、esi=buf+68、bl=滚动键）
  + 真实栈内容 = 缺失输入。
- **REGSNATCH 定案（下一轮机器）**：watcher 在细粒度窗口 [204,206]ms
  `OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,
  main_tid)` → SuspendThread → GetThreadContext（cx/dx/esi/edi/ebp/ebx/
  esp 全拿）→ 栈区 RPM 32KB → ResumeThread（~1ms 冻结，壳无 µs 级自检）。
  有了真寄存器 + 真栈 → unicorn 从当前 EIP 确定性重放 → 读出 g → 验证
  全部 261 观测态 → f 完成 → .dat 重编码。
- 备选（无注入风险路径）：REGSNATCH 失败时手动缝完 jmp 链
  （0x583cd→0x105d15c→…）或对 0x1020000 系（VMCTX 头，695 记录）与
  0x113f000（16 记录）做同款微扫分析。

**续 21 补充 3（同日）——REGSNATCH 落地 + 结构突破：校验 = 逐字节值线程化解释器**：
- **REGSNATCH 实装**（`MAGICMIDA_V2_REGSNATCH=1`）：VM 线程检测 =
  scratch churn + EIP-in-image（main_tid 先扫）；SNATCH = Suspend→
  GetContext(0x1F)→栈逐页 RPM（整段 RPM 遇未提交页全灭——逐 4KB 页读）
  →Resume，64 张快照/2.9MB。edx 常持 scratch 指针、edi = 0x105FFAE。
- **结构定案**：`movzx eax,al; jmp [edi+eax*4]`（edi=0x105FFAE）——
  「scratch」实为 **256 槽派发表**（非对齐基址！）：**每个字节值一个
  专属 handler**（校验期写了 168 个，全部唯一、互不共享），handler =
  web 区 [0x1060000-0x1080000) 的 jmp 缝合静态片段（快照 eip 页已捕获）。
  活状态 = 表内 3 个 dword：[0x105FFB2]/[0x105FFB6]/[0x105FFCA]（快照间
  diff 只有这 3 处变——handler 槽全静态）。「831f magic/ctr/acc1/acc2」
  = 这些表内 dword 的旧读法；布局随 op 相位漂移 = 表前缀被不同 op 复用。
- **含义**：校验哈希 = 每输入字节经 bl 变换后按【字节值】派发到专属
  handler，handler 内联更新 3 个状态 dword——g 的真身 = 168 个 handler
  的语义和。**无需仿真**：handler 已捕获（eip 页 + scene 覆盖），逐个
  缝合可读出每字节值的状态转移函数。
- unicorn 重放（replay.py）= 从快照 EIP 跑 73 条后经未建的表槽派发崩
  （快照态 = 相位中段、表增量构建）——重放需要相位入口起点；handler
  直读路径更短，弃重放。
- 下一轮：缝合 handler 链（0x1062857/0x1065bcf/…，每 handler ~10-30
  片段），抽出 3 状态 dword 的转移函数 → 全 261 态验证 → f → .dat 重编码。

**续 21 补充 4（同日）——REGSNATCH 补强（esi 页 + 全镜像活体转储）+ 重放定界**：
- REGSNATCH 增补：每快照 +esi 页 4KB（op 的数据指针在镜像内
  0x10F0xxx/0x114xxxx——**.dat 工作副本在镜像数据区，不是 needle 找到的
  堆缓冲**）；VM 线程确认后全镜像活体转储（882 页，`v2regsnatchimg`）。
- unicorn 重放 v2（活镜像 + 真栈 + 快照寄存器）：**283 条指令走到
  dispatch**（`movzx eax,al; jmp [edi+eax*4]`，al=0x5f）→ 未建槽崩。
  分歧在更早的字节变换链——且 esi 非线性字节走线（0x10f0af3→0x10f1407→
  0x1147db7 跳变）= 通用数据指针，输入字节的读取方式未定。
- 活状态轨迹提取（`check_traj2.json`）：表窗口 live 字节 = 三组
  （0xFFAE-0xFFC1 = 20B 状态窗、0xFFC6-0xFFCB、0xFFD2）；t=242.4ms 后
  换 op 复用表（值变垃圾）——快照窗口 = 校验中段。
- **定案路线（弃重放）**：handler 直读——168 个唯一 handler 已捕获，
  逐个缝合 jmp 链（~10-30 片段）抽出 3 状态 dword 的转移函数 → 261 态
  验证 → f → .dat 重编码。样本 handler 0x1062857（push ebp/esp 起手）、
  0x1065bcf（lodsd; xor eax,ebx 起手）可读。

**续 21 补充 5（同日）——两副本定案 + 免 f 锻造配方**：
- handler 缝合推进中发现：**校验读副本 A（镜像数据区），解码读副本 B
  （480B 堆缓冲）——两份独立拷贝**。esi∈镜像（0x10F0xxx/0x114xxxx）=
  校验的输入；DECODEWATCH 六相 = 堆缓冲。oracle（改盘上 .dat 被拒）=
  两副本都来自盘上文件；KEYFORGE 补堆缓冲在解密完成后 = 校验已过但
  **字段校验和（verifier op，逐字段 vmhash vs 期望）抓到字段被改**。
- **免 f 配方**：①盘上 .dat 保持原样 → 全局校验（副本 A）通过 ✓；
  ②校验结束→解码开始的窗口内补丁**堆缓冲**：字段 := 本机键 + 字段
  校验和 := vmhash(新字段)（**verifier 的 hash 实例已捕获**——0x24046
  常数 0x5041/0x5449 + init/feedback/not/打包全链）；③解码出我们的
  字段 → verifier 用我们写的校验和验证我们的字段 ✓ → 搜索命中 →
  **许可通过，无需 f**。
- 已知缺口：字段校验和的期望值存哪（.dat 内可补丁位置 vs baked——
  baked 则字段不可自由选）；窗口触发器（state dwords 停变 / ctr→604）。
- 下一轮：check-end-patch 机器（KEYFORGE 改触发点 + 一致性字段补丁）；
  verifier 期望值位置猎取（oracle：只改字段校验和位置看反应）。

**续 21 补充 6（同日）——verifier 期望值首轮排查**：
- vmhash.py 实例（0x5041/0x5449，init 全 FF）对 26 个解密字段逐个/分段
  计算，结果在 .dat raw 中**零命中**（LE/BE 都试过）。期望值 ≠ 明文
  vmhash(raw)。剩余假设：baked 常数、raw 内加密存储（需字段密码）、
  或 verifier 的 hash 参数不同（逐字段 init/分段）。
- 下一轮三线：①FORGE2 机器（segment-A 解密写瞬间补丁 [0,48) raw，
  字段 only——失败形态定位 verifier 行为）；②verifier op（0x2400D-
  0x2429D）walker 缝合找期望值加载点；③vmhash 参数变体网格
  （init/常数/分段）× 26 字段全搜索。

**续 21 补充 7（同日）——字段密码 = 位置 XOR 键流（26 对全覆盖）+ FORGE2 首跑定案**：
- **dec = raw ^ ks 对全部 26 对成立**（v2_pairs.json）——.dat 字段密码 =
  位置相关 XOR 键流；26 个字段位置的 ks **全部实测在手** → 任意目标
  dec 可编码：raw[pos] := 目标dec ^ ks[pos]。**字段密码不再是缺口**
  （ks 的生成算法 = 学术项；伪造只需要这 26 个值）。
- **FORGE2 首跑**（fill-complete 补丁 raw := 明文键，26 dword）：
  哨兵 = 0→FFFFFFFF（三搜索全跑、全 miss）、**无 bail、无中止、壳长存**
  ——**verifier 不验证键字段**（键 = 乱码照样走完流程）！KEYFORGE 的
  篡改中止 = 键覆盖了名字串（0x2056D 共用区）——字符串校验而已。
- **修正后的完整配方**（三步，全部可实施）：
  ①盘上 .dat 原样 → 校验（副本 A）过；
  ②fill-complete：raw[pos] := 本机键 ^ ks[pos]（26 处）→ 解码字段 =
    本机键；
  ③KEY3 = 逐 run 变体：搜索前窗口（键写入 [300,330]、搜索 [331,412]）
    读 [0x23401]（哨兵+4）取 KEY3 实时值，补第三槽（key^ks）。
  → 三搜索命中 → 许可通过。
- 未知残留：三中二/三中三才过？（哨兵轨迹 = 判据）；键槽布局
  （交替 K1/K2 vs 对应槽位）。
- 下一轮：FORGE2 v2（raw := 键^ks）+ KEY3 实时补丁 + 哨兵轨迹判读。

**续 21 补充 8（同日）——FORGE2 v2 定案：补丁时序 = 唯一变量**：
- 哨兵+4 实读：**搜索键 = 0x7dc80de6/0x022869c8 = 我们的机器键 ✓**
  （补丁目标正确）；KEY3 = 0x30171931（逐 run）。
- 缓冲记录法证：补丁 209.66ms 落入缓冲 ✓（snap[300]=0xb4406617 =
  K2^ks）——但**解码从未发生**（[213,306] 缓冲零变化），搜索照跑、
  全 miss、无 bail。**补丁落在校验执行期 → 校验检测到 raw 变化 →
  跳过解码**。
- 旧读法修正：pristine CISC1test 的「[220,230) 擦除」实为**解码
  segment-A 写入**（ca 走过 buffer+308-352、nz=28 = 52B 段）——解码
  无条件发生（fill→check→decode→list→searches）。
- **窗口定案**：校验结束→解码开始 = ~6ms（v3: [220,226]）。补丁必须
  落在这窗口：触发器 = 派发表状态 dword 静默（校验活跃→2ms 静）→
  立即补丁（~50µs）→ 解码消费我们的 raw。
- 下一轮：FORGE2 v3（静默触发 + 立即补丁）；哨兵轨迹判读三中几。

**续 21 补充 9（同日）——搜索键 = 字段值本身；列表 = 机器变换 T(fields)**：
- FORGE2 v3（cursor-chase 补丁 215ms，cursor=300）：搜索键 = 
  0x0102d6ab/0x01108e1e/0xcb7c62cf——**逐 run 全变**；v2 跑 = 
  0x7dc80de6/0x022869c8 = **恰为我们补丁的字段值**！
- **定案：[哨兵+4] = 字段值的复制**；搜索 = 「字段[i] ∈ 列表？」，
  列表 = 机器变换 T(fields)（[250,314] 构建自 VMCTX 字段）。通过 ⇔
  T 在字段上恒等 ⇔ 字段 = 本机正确许可数据。KEYFORGE 时代
  0x7DC80DE6「机器键」 = 当年 pristine 字段的首槽值——不是机器键！
- **T 可经验提取**：同一 run 内 VMCTX 字段（0x20415-0x235E5）与列表
  （0x20A00+）都在手 → T = 对应关系。若 T 简单（XOR/排列/移位）→
  字段 := T⁻¹(我们想要的值) → 搜索命中。
- v3 补丁的 segment B 错误：cursor=300 时 [0,52) 写了明文键 → 解码
  XOR 后 = 乱码 → 字段乱码 → T(乱码) ≠ 乱码 → miss（自洽）。
- 下一轮：①DECODEWATCH + VMCTX 字段快照（搜索时刻一次）→ T 提取；
  ②FORGE2 v4：字段 := T⁻¹(键)。

**续 21 补充 10（同日）——T 快照落地 + 两段搜索定案**：
- FORGE2 v4：cursor-chase 补丁（224ms，cursor=300）+ **T 快照**
  （首个哨兵翻转时抓 19 字段×8B + 3 搜索键 + 1KB 列表，
  `v2tsnap.bin` 1188B）。
- 哨兵轨迹 = **两段搜索**：round-1（~300ms）searched =
  0x0102d6ab/0x01108e1e/0x929b5499（≠ 任何字段值；槽 1-2 跨 run 稳定、
  槽 3 逐 run）；round-2（~411ms）searched = **0x7dc80de6/0x022869c8 =
  我们补丁的 .dat 解码键**！
- 定案：**搜索 = 多段**，round-2 = 「.dat 解码字段 ∈ 列表？」——miss
  说明列表 ≠ 我们的键（列表构建时刻 vs 补丁时刻的竞态或来源不同）。
  round-1 = 另一验证段（源未定）。
- 数据在手（字段 19×8B + 键 + 列表 1KB）；下一轮 = 多时点快照
  （列表构建前后各一张）+ 字段/列表/键三方对账 → T 或列表来源定案 →
  FORGE2 v5。

**续 21 补充 11（同日）——多时点 T 快照 + 列表 = T(fields) 定案**：
- 多时点 T 快照落地（20ms 间隔 ×10 + bail 路径 flush，98.8KB）。
- 时间线：我们的键 = 缓冲 [220,295]（解码消费 ✓）→ 擦除消失；搜索
  [300,391]（bail = FAIL_MARK）。
- **目标值（0x0102d6ab/0x01108e1e/0xa6d0927f）在缓冲/堆区/0x20A00/字段
  全域零命中**——搜索扫的列表 ≠ 字段原文 = **列表 = T(fields)**（机器
  变换后的副本）。哨兵+4 = 瞬态（仅搜索瞬间有效），arm 时刻读数 =
  静态 setup 值（0x0102d6ab/0x01108e1e 跨 run 恒定 = bake）。
- ** forging 条件收敛**：字段须构成 T-链（∃j: T(field_i)=field_j）——
  pristine 字段 = 作者的 T-链；随机字段 = 断链 = miss。
- **下一轮**：①pristine 流程的 T 快照（forge2 off、快照 on）→
  pristine 字段+列表 → **T 直接对账**；②FORGE2 v5 = 字段 := T-链。
  T 若为简单 XOR/移位/查表 → 链可构造 → 闭环。

**续 21 补充 12（同日）——TSNAP 解耦 + pristine 对账 = 机器键 = 每 boot**：
- TSNAP 解耦（`MAGICMIDA_V2_TSNAP=1`，无补丁跑 pristine）。
- **pristine 搜索键 = 0x0102d6ab/0x01108e1e/0x4886f3d6**——槽 1-2 与
  forged 跑完全一致 = **跨 run 恒定（同一 boot 会话）**；槽 3 逐 run。
  与 KEYFORGE 时代（0x7DC80DE6/0x022869C8）不同 = **不同 boot**。
  →「机器键」 = f(机器, boot 会话)——每 boot 变。
- v6（字段 := bake 目标，cursor-chase 226ms）仍 miss：快照显示目标值
  在缓冲/堆/0x20A00 全域零命中——解码竞态（cursor=300 同毫秒）或
  比较语义还有一层。
- **下一轮 = SEARCHSNATCH**：搜索期（[280,420]）对 VM 线程
  Suspend+GetContext（~1ms 间隔 ×100）——**cmp 的两个操作数直接在
  寄存器里**：搜索键真身 + 列表元素真身一次拿全。REGSNATCH 机制
  现成（OpenThread+Suspend+Context），只需新触发窗口。

**续 21 补充 13（同日）——SEARCHSNATCH 落地 + 搜索语义推进**：
- SEARCHSNATCH 实装（`MAGICMIDA_V2_SEARCHSNATCH=1`）：搜索期对 VM
  线程 Suspend+Context ~20µs 间隔 ×2000（[294.9,339.4]ms，120KB+
  608KB 两跑）；clen 变长修正。EIP = 26 个站点（top 0x102a800 ×237、
  0x103c400 ×216…）。
- **列表位置定案：image+0x10DC000-0x10DD000**（esi 走线
  0x10dc758-0x10dcaf4；edi = 0x102859e = bank contA 槽恒定、
  ebp = 0xeedc0014 恒定 = VM 基址）。T 快照的堆区读错了地方。
- 目标值（0x0102d6ab/0x01108e1e）在列表中零命中（LE/BE）——比较 =
  **两边都有变换**（T(element) vs key 或 element vs T(key)）。
- **搜索键 = 「单次搜索内恒定、跨搜索变化」的寄存器值**——
  时间性分析（跨三次搜索的常量提取）= 下一轮。machine 键 =
  f(机器, boot) 每 boot 变 = 已定案。
- 下一轮：SEARCHSNATCH 时序分析（每个寄存器的值-时间曲线 → 搜索
  边界 → 键真身）+ 列表内容（0x10DC000，pristine 快照）三方对账 →
  比较语义 → FORGE2 v6。

**续 21 补充 14（同日）——寄存器时间曲线 + 对比关系数据提取**：
- SEARCHSNATCH 2000 张的时序分析：esi = 列表走线（多段），eax/ebx =
  分段常量（**eax = 0x9e7c2a07 连续 50 快照 @296.7ms = 键候选**；
  ebx = 0x3000011 两次出现 = 标记）；edi/ebp = VM 基址恒定。
- (esi, elem, eax, ebx, ecx) 五元组提取（25 样本）：eax 有 0x45xx 族
  （0x459d/0x45f8/0x45ef/0x45ff）、0xd0xx 族；特殊快照
  (elem=0x6139ee80, eax=0x9e7c2a07, ecx=0x404e282e) = 全 32 位。
- 比较语义：**逐字节 + 变换**（v3 fine-window 的 lane 模型同源）——
  eax/ebx = 逐字节变换累加器，elem = 列表元素。
- 下一轮：字节级变换重建（用 25 样本的 (elem 字节, eax/ebx 字节) 对 +
  v3 的 17 个 lane 转移交叉验证）→ 搜索键的列表编码形式 → FORGE2 v6
  （字段 := 编码后的键）。

**续 21 补充 15（同日）——FORGE2 v5：触发器完美 + 发现重加密层**：
- v5 触发器 = 解码首写（v300 离开 raw 值 0x59433ac4 → 瞬间补丁）
  **完美命中**（v300 = 0xef2b351b = 解码首写 ✓，219ms，26 写）。
- 哨兵：searched = **0x7dc80de6/0x022869c8/0x61dc5b6e**——slot3 =
  **我们的 T3 字段值 = 恒等**！slot1-2 = 变换值。→ 字段确实流入
  搜索键；但 slot1-2 ≠ 我们写的目标。
- **根因 = 重加密层**：解码六相 = decrypt → 重加密1（滚动键，13 对
  已测）→ 重加密2（常数 XOR 0x2D188AD3）→ 擦除。搜索读的字段 =
  **重加密后的值** = dec ^ reenc1 ^ reenc2——补丁必须三重编码：
  **raw := target ^ ks ^ reenc1 ^ reenc2**。
- 下一轮：从 YDW 日志提取 reenc1 的 13 对 + reenc2 常数 → 三重编码
  补丁 → FORGE2 v6 → 三搜索命中 → 闭环。

**续 21 补充 16（同日）——FORGE2 v6：机制全测明，PASS 判定再次不可得（按 续20-补3 标准如实撤回）**：

- **离线对账（v5 工件逐字节）推翻「三重编码」前提**（真实机制进展）：
  1. **解密源 = 镜像区 copy A，不是缓冲**：v5 补丁写进缓冲的
     [4,52) 与 [304,352) 全部在 ~1.5ms 内被 pristine dec 覆盖
     （dec[4]=0x61c697fc 等全数回归）——缓冲不是这两段的解密输入。
  2. **pos0 特殊**：dec[0] = 0x8c775e0a ≠ pristine 0x7a9fbc7a；
     v9（不写 pos0）复现同一值 ⟹ 链式篡改项 h(dec[300])
     （pristine dec[300]=0xef2b351b 时 h=0；补丁后 h=0xF6E8E270）
     ——解码器对 pos300 的值敏感。
  3. **重加密只盖 [0,52)**：enc2 ^ enc1 = 0x2D188AD3 逐位复核 ✓
     （pos0/pos4 今日数据）；**[300,352) 无重加密**（dec 后直落擦除）。
  4. **v5/v6/v9 三跑的有效补丁全部 = pos300 一 dword**（v6 的 52B
     块写也输解码竞速，~1 记录后全被覆盖）。
- **v6 实现**：52B 块写 [304,352) + pos300 单写 + PASS 探针
  （OpenProcess(PROCESS_VM_READ) @5/20/50/80s；放 bail-watch 循环——
  µs 快照循环 500ms 即退出，首版探针放错循环从未触发，已修）。
- **v9 实测（8+ 分钟活体）**：无 bail（bail-watch 10ms 轮询全程，
  pristine = 382ms）；失败对话框从未出现；探针 5/20/50/80s 全
  readable；进程停泊（CPU 0.44s/8min、31 线程全等待、无窗口）；
  哨兵搜索后 = 0xFFFFFFFF（三搜索 miss）。
- **PASS 判定 = 撤回**。按 续20-补3 标准（「无失败」≠「通过」，必须
  验证成功路径下游标记）逐项检查：**运行时副本 8 分钟未现**（外部
  4KB 头页扫描，readable 进程直读）、**无搜索命中**（哨兵全 miss）、
  **无应用 UI/新线程**。与 KEYFORGE 中止的区别只在流程更深（列表区
  [0x20AA9,0x20AE1] 有构建：109→166 与 pristine 108→175 同步——
  不是 KEYFORGE 的全零中止点），但**无一成功标记**。最可能 = verifier
  op（0x2402C 逐字段 vmhash）在更晚点静默拒了我们改动的 pos300
  字段——中止挂起形状与 KEYFORGE 同类。
- **[哨兵+4] = 0x7dc80de6/0x022869c8 重解读**：三个独立锻造 run 出现、
  pristine 无、静态镜像无——最可能 = **verifier 的期望值参考常数**
  （篡改路径的写），非 pass 标记（KEYFORGE 时代 = 注入值回显的巧合
  一并修正）。
- **反读修正**：v9 探针全程 readable——反读 ≠ pass/中止伴随物；
  KEYFORGE 的 OpenProcess 被拒 = 548 轮连续重写的防篡改响应。
  U21 副本 = fail-era 工件（副本存在 ≠ pass）维持。
- **真锻造方程（更新）**：pos300 改动过不了 verifier。运行时路径要
  过 = **在 verifier 跑完之后、列表构建 [261,303) 之前**的窗口改字段
  （verifier 对 pristine 字段放行 → 换键 → 搜索吃我们的值）——前提 =
  定位 verifier op 的执行窗口（POOLSNIFF 变体：解码后基线，扫
  [230,300) 的 op 执行）。盘上路径照旧被全局校验 f 挡（学术线）。
- 工件：OUT/ps1/analyze_forge.py（9880B TSNAP + 1268B DECODEWATCH
  解析器）、*.v5forge.bin / *.v6forge.bin / tsnap_pristine.bin、
  forge2_v5run_log.txt / forge2_v6run_log.txt。ks 表 26 对独立验证
  （dec[0]=0x7a9fbc7a = KEYFORGE 标记、dec[300]=0xef2b351b = 触发值、
  dec[344]=0x77dc7da4 ✓）。双架构零告警（探针 match 守卫 E0004/E0408
  已修；stash 对照证明 8 条 unused 告警 = 编译错误级联）。

**续 21 补充 17（同日第四轮）——verifier 定位 + miss 计数器 = 锻造进度条（可量化）**：

- **新仪表（TSNAP 扩展，全落地）**：搜索列表区 RVA 0xDC000（4KB）+
  verifier 输出槽（0x201FD miss 计数 / 0x20CF1 累积结果 / 0x22D45 旗标 /
  0x23DEA 字段计数器）+ SEARCHSNATCH 起点 265→215ms。
- **verifier op 执行窗口 = [340,360]ms（搜索之后！）**：miss 0→0x26e
  （622）、字段计数 0x686→0xe7（处理 1439/1670 个字段，~80 fields/ms）。
  EIP 扫描 [243,281] 零命中（该窗口 = 列表构建 op，RVA 0x60000-0x73000）。
- **锻造进度条定案**：pos300 = 本机键 1 → **miss 622→0x50（80）**，
  -542 = 键 1 衍生字段全部转 hit。verifier 的字段输入 = 缓冲 B 衍生
  （我们的补丁喂进去了）。
- **VM 多周期重解码定案（v11）**：pass-1 ~238ms → 清零 264ms → pass-2
  264ms——一次性补丁落在周期之间 = 被清（v11 的块写消失、verifier 得
  pristine 分 0x26e）。**KEYFORGE 式连续补丁 = 唯一有效形状**：v12/v13
  以 200µs 节奏重写 [300,352)（+v13 加 [0,52) K1/K2），键值贯穿
  [230,420]ms 所有周期 ✓。
- **miss 地板 = 0x50（80）不变**：[0,52) K1/K2 交替 + [304,352) K2/K3
  双块补丁零进一步降低——剩余 miss ≠ 缓冲衍生（= 身份/名字/逐 run 键
  衍生字段）。pristine = 622 = 失败；80 = 不失败但停泊。
- **搜索列表 = 编码 blob**：RVA 0xDC000 = 1024/1024 dword 全非零，字段
  原值零命中（T 非平凡）；pristine vs forged 逐字节相同 = 列表不从 B
  构建（从 VMCTX/镜像侧）→ 缓冲补丁不影响搜索 → 哨兵恒 miss。
  [哨兵+4] 搜索后 = 0x7dc80de6/0x022869c8 = 壳自产参考常数（每个锻造
  run 都出现、pristine 无、静态镜像无）。
- **镜像里没有 .dat 副本**（needle 全图 8 区域 0 命中，全可读）——
  「copy A」= VM 数据区内的变换形态（非裸 raw）。DECODEWATCH blk 读法
  修正：block VA = (ca+dp)&0xFFFFFFFF（ca 单独 = 解码相的偏移，0xc30160
  +dp 0xb206；修正前 blk 读到零页）。VM 代码区 = 每 run 变
  （0xC3xxxx / 0x136xxxx）。
- **停泊态画像（v9-v14 全一致）**：30MB WS、30-41 线程全等待、CPU
  0.44s、无窗口、无运行时副本（外部 4KB 头页扫描多次）、.text 恒为盘上
  密文、探针 5/20/50/80s 全 readable、无 bail 无对话框。80-miss 态 =
  壳停泊，部署未发生。
- **判定**：锻造 = 量化推进（622→80）但通过未演示（部署零标记，按
  续20-补3 标准 = 未通过）。**下一轮三选一**：① verifier op 体已可捕获
  （blk 修正后 [340,360] 记录 = 解密态 op 体）→ 字段表地址 → miss 来源
  分解；② 列表编码 T 重建（searchsnatch (elem,eax,ebx) 25 样本 × 列表
  blob 字节级）；③ 名字绑定实验（GetModuleFileName 名字 = 许可绑定，
  改名 oracle）。
- 工件：CISC-1U.v2decodewatch.prime3/.v12/.v13.bin、
  CISC-1U.v2tsnap.pristine2/.v12/.v13.bin、
  CISC-1U.v2searchsnatch.pristine2.bin、check_op_body3.bin、
  probe_rawcopy.py、fold_check.py、analyze_forge.py。

**续 21 补充 18（同日第五轮）——SEARCHSNATCH 重定向：0x201FD = 搜索 miss 计数，80 = 命中提前退出（模型转折）**：

- **仪表修正**：SEARCHSNATCH 等待 330→280ms + **重试查找循环**（快路径
  h_main 2µs/次、每 1ms 重试直至 EIP 进镜像——ops 分两界：check/verifier
  = 镜像内静态 op，解码/列表构建 = VM 数据区瞬态块（EIP 不在镜像），
  单次查找在 [280,330] 必败）。实测 320ms 抓到，[320,359]ms 2000 张 =
  搜索+比较全窗。
- **0x2400D-EIP 零命中** → **0x201FD 不是字段校验的 miss——是搜索的
  逐元素 miss 计数**！[340,360] 全程 EIP = 搜索 op（RVA 0x60000-0x73000）。
  「verifier 窗口」 = 搜索/比较时代。
- **比较 = 逐字节 + 变换，累加器 = check scratch**：edx = 0x105ffba/
  0x105ffb6（0x5FFAE+0xC/+8）= 搜索 op 读 check 的 scratch——VM 共享
  工作区。寄存器 = 字节尺度状态（0x3e/0x41/0x73/0x18…）= 变换进行时。
- **模型转折**：622 ≈ 3 搜索 × 207 元素 = 全 miss；**80 = 提前命中退出**
  ——我们的键在缓冲键块 → 搜索命中我们的键 → miss 骤降。三测量互证：
  miss 只因缓冲补丁变化（622→80）；列表 pristine vs forged 全同（列表
  不是被搜方=缓冲才是）；比较 = 逐元素。
- **判定修正**：搜索 = 命中了我们的键（三个都命中：K1@300 + K2/K3 在
  [304,352)）。哨兵 [哨兵] = 0xFFFFFFFF ≠「未命中」——是某后续阶段的
  状态位（语义重定待测）。pristine 622 全 miss → fail；80（命中）→
  不 fail ✓ 一致。
- **残留谜题**：命中后壳仍停泊（30MB WS、无部署）——命中后的下一道门
  （key3 逐 run？名字绑定？后续阶段？）。下一轮：FORGE2+SEARCHSNATCH
  合流（搜捕命中瞬间的逐字节比较 + 命中后的流）。
- 工件：CISC-1U.v2searchsnatch.verifier4.bin、ss_verifier*_log.txt。

**续 21 补充 19（同日第六轮）——FORGE2+SNATCH 合流：停泊态 = 全进程等待死锁（41 线程全阻塞）**：

- **合流落地（v14）**：上下文捕获并入 DECODEWATCH 循环（锻造连续补丁与
  上下文快照同跑；记录 = t/eip/9regs/clen/code/栈 1KB；flush =
  <out>.v2ctxsnatch.bin，957 张）。h_main 为 Copy，各分支互不影响。
- **主线程时间线（v2ctxsnatch）**：[316,343]ms 在 op 带（0x2d600，比较
  时代 ✓）→ [344,470]+ 全程 ntdll 等待（0x758a123c）。键值从未以整数
  出现在寄存器/栈（逐字节变换一致 ✓）。
- **等待现场（栈分析）**：栈里无壳镜像返回地址——调用方 = 低地址 VM 区
  瞬态块代码（0x69xxxx）；帧里内核句柄 0x77f/0x7ff。
- **全进程线程地图（probe_gate2.py，42 线程）**：**41 线程 100% 阻塞于
  内核等待**——16× NtWaitForSingleObject 系、8× NtWaitForMultipleObjects、
  7× NtWaitForAlertByThreadId（等告警无人告警）、7× kernelbase
  WaitForSingleObject、主线程 1×。零线程在镜像、零线程执行应用代码。
  **停泊态 = 整进程等待死锁**，不是「应用在 VM 里解释执行」。
- **门的定位**：搜索命中（80-miss 提前退出）→ 流程进入下一阶段 →
  该阶段 = 死等一个永不触发的内核事件 → 死锁。pristine（全 miss）=
  fail 对话框不进入此等待 ✓。
- **调试经验钉死**：64-bit python 枚举 toolhelp = THREADENTRY32 的
  dwSize 必须 28（不是 24，err 24 = BAD_LENGTH）；读 32-bit 线程上下文
  必须 Wow64GetThreadContext（普通 GetThreadContext 给 x64 布局 = 全零）。
- **下一轮 = 唤醒实验**（观测即绕过的下一形态）：识别主线程等待句柄的
  对象类型（栈更深 + NtQuerySystemInformation 全局句柄表）→
  SetEvent/AlertThread 唤醒 → 看流程是否继续 → 部署标记。
- 工件：CISC-1U.v2ctxsnatch.v14.bin（957 张）、probe_gate.py /
  probe_gate2.py、add_forge2v14.py。

**续 21 补充 20（同日第七轮）——唤醒实验第一轮：未触达有效对象（仪器缺陷，非否定）**：

- **实验执行**：锻造跑至停泊 → 主线程（kernelbase WFSO @0x758a123c）
  深栈 16KB → 324 个小值候选 → SetEvent（dup 后从我们侧触发）→
  NtAlertThread × 40 线程 → 10s 后复查。
- **结果 = 全部落空**：324 个 DuplicateHandle **全部失败**（err 6 =
  栈上小值 ≠ 本 run 的真实句柄——句柄值逐 run 变，而 WFSO 的参数槽
  不在 esp 可见帧内，ntdll syscall stub 之下更深）；NtAlertThread 0 成功
  （OpenThread 权限不足，需含 THREAD_ALERT 位）；4 线程离开 WFSO =
  自然方差（非唤醒效果）。部署标记照旧全零。
- **结论**：实验不成立 ≠ 路线否定——需要 (a) 全局句柄表拿到**本 run**
  的真实句柄（NtQuerySystemInformation(64) 对该进程阻塞 100s+，原因
  未明，需 worker 线程 + 超时隔离），或 (b) 解析 WFSO 深帧取参数槽。
- **仪器坑钉死**：NtQueryObject 对管道类句柄**阻塞**（必须 worker 线程
  + join 超时）；NtQuerySystemInformation(64) 本场景**内核阻塞**（同法
  隔离）；heredoc 截断再犯两次（补丁一律落盘脚本）；python 输出必须 -u。
- 工件：probe_wake.py + fix_*.py、wake_out*.txt。

**续 21 补充 21（同日第八轮）——全局句柄表破解（428 句柄到手），类型查询待修**：

- **census 攻坚成功**：NtQuerySystemInformation(16=legacy) 在 worker 线程
  （超时隔离）下完成；**x64 的 legacy 条目 = 24 字节**（pid I + type B +
  flags B + handle H + object Q + granted Q，'<IBBHQQ'）——16 字节布局
  解析 = 全垃圾 pid（对齐漂移实锤：首条目 pid=4=System ✓）。**锻造
  run = 428 个句柄到手**（probe_wake2.py）。
- **SystemExtendedHandleInformation(64) 对该进程内核阻塞**（>6s worker
  超时跳过），legacy(16) = 间歇性阻塞（需同法隔离）。
- **types = 空 = 待修**：DuplicateHandle/NtQueryObject 循环返回空
  （0.4s 超时 × 428 = 可能全超时，或 dup 失败——无 err 打印，待诊断）。
  NtAlertThread 0/41（权限位待修：需含 THREAD_ALERT）。
- **停泊态画像跨 5 个 run 稳定**：30-31 线程全阻塞内核等待、无部署
  标记（运行时副本 / .text 解密 / 窗口全零）、CISC-1 存活。
- 工件：probe_wake.py / probe_wake2.py / fix_*.py、wake*_out*.txt。

**续 21 补充 22（同日第九轮）——唤醒实验第二轮：117 事件 + 32 告警全送达，壳有反应但部署仍被扣**：

- **仪器三连修（根因全找到）**：① **ctypes 缺 argtypes = DuplicateHandle
  全灭**——GetCurrentProcess() 伪句柄 -1 被 c_int 默认截成 0xFFFFFFFF
  （x64 无效），typed 签名（argtypes/restype）后立即可用（独立测试：
  dup value=0x160 ✓）；② **x64 UNICODE_STRING.Buffer = 8 字节**，`<I`
  4 字节读 = 指针截断 = from_address 段错误（'<badptr>' 兜底的来源）；
  ③ 解码 = utf-16-le（latin1 = "F i l e" 形）。worker 线程隔离弃用
  （round-3 实测：worker 返回 None 而直接调用返回 'Event'——不可靠），
  ot-map 用顶层 worker + 20s 整体超时。
- **暴力唤醒执行**：SetEvent 对全部 433 句柄（**117 个成功触发** =
  117 个真事件对象！）、NtAlertThread 32/32（THREAD_ALL_ACCESS ✓）。
- **壳的反应**：线程 40→43（+3 新线程！）、出现 3 个新等待点
  （0x76f4950c/0x76f4a08c/0x76f4a6b0）——事件风暴被壳感知。
- **部署标记仍全零**（副本/解密/窗口）。
- **判定 = 门在哨兵裁决位**：哨兵 [哨兵] = 0xFFFFFFFF = 搜索最终
  verdict = miss → 部署被扣。搜索虽提前退出（miss 80）但 verdict 仍
  miss——**verdict ≠ miss 计数**，verdict 机制 = 下一轮目标（0x2400D
  op 静态全读已知：exit 块 0x2429D 写累积结果到 0x20CF1 = 今日仪表
  已捕获 = 恒 0 = **0x20CF1 = 0 = 失败累积**！）。
- **下一轮**：0x20CF1 累积结果的写时刻/写值监控（TSNAP 已捕获恒 0）
  → 定位「命中但不累积」的分支（0x2408A cmp 后的命中路径）→ 或者
  0x201FD/0x20CF1 对 = 搜索语义的最终对账。
- 工件：probe_wake2.py（argtypes + brute wake）、wake2_out*.txt。

**续 21 补充 23（同日第十轮）——哨兵裁决补丁（v15）：watcher hit=true = 我们自己的写，部署 = 假警报**：

- **v15 实现**：连续补丁扩展三哨兵裁决槽（[0x216F5]/[0x22D7D]/[0x233FD]
  := 本机键，每 200µs）——搜索在 ~339ms 写 0xFFFFFFFF（miss），我们的
  循环顶回键值。实测：哨兵 = (K1,K1)/(K2,K2)/(K3,K3)，watcher 语义
  hit=true。
- **「.text 解密」= 假警报（诚实修正）**：粗扫（0x2000 块）首 diff =
  0x7000 → 兴奋转储（CISC-1U.v2unpacked_v15.bin，sha256 b017fdba…，
  3612672B）→ 精查：**diff 区 = [0x8a00, 0x15f00] = 21KB = 恰为 U21
  记录的壳 BSS 尾写入（资源目录形状，正常态就有）**；[0x1000,0x8a00]
  的 .text 密文 100% 未变。**无部署。**「.text 恒密文」维持。
- **机制推断**：哨兵裁决 = 搜索写完立即被下游读（[340,382] 窗口），
  我们的 200µs 补丁与读**竞速**（~50% 窗口是我们的值）——壳要么读到
  我们的值后仍不部署（verdict ≠ 唯一门），要么读的时机躲开了我们的
  写。0x20CF1 恒 0 = 0x2400D op 从未执行（EIP 全窗零命中）= 该静态 op
  = 死代码或别相执行。
- **verifier 的备选激活**：verdict 机制需要不可逆信息 → 改道 .dat 静态
  路径（校验哈希 f 逆向 / handler 缝合）= 下一增量。转储保留作 diff
  基线（b017fdba…）。
- 工件：CISC-1U.v2unpacked_v15.bin、CISC-1U.v2tsnap.v15.bin、
  add_forge2v15b.py、forge2v15*_log.txt。

**续 21 补充 24（同日第十一轮）——v16 翻转锚定单发 + 「.text 解密」第二次假警报修正**：

- **v16 实现**：哨兵翻转（搜索自己的 0xFFFFFFFF 写）为锚点的单发写入
  ——微秒级跟写，下游 [340,382] 读点前就位（200µs 连续补丁保留兜底）。
- **「.text 解密」第二次假警报**：v15/v16 两次 live-check = ".text ≠
  盘上" —— **probe 的 disk = read(0x1000) 只读 4KB，disk[0x1000:0x1020]
  = 空串 → 比较恒 False**（假解密）。时间序列（110s × 12 采样）证实：
  **.text 稳定 = 盘上密文**，部署确认全零。两次假警报 = 同一 bug
  （第一次的精查修正了它，第二次的 live-check 又犯——探针代码复用时
  没修根因）。
- **裁决读竞速精细化 = 结果不变**：v16 翻转锚定 + v15 连续补丁双保险
  下，部署标记仍全零 → **verdict 读点不是唯一门**（或读点在别的槽/
  别的进程副本）。
- **按已激活备选转道 .dat 静态路径**：校验哈希 f 逆向（POOLSNIFF 状态
  机 261 态 + handler 缝合 168 handler 在手）或 handler 缝合补完 =
  下一增量。
- 工件：forge2v16_log.txt、probe_wake2.py（argtypes + brute + 精确
  .text 扫描）、fix_wake3-5.py。

**续 21 补充 25（同日第十二轮）——f 逆向 kickoff：4-lane 轮转确认 + 消费顺序数据相关 + S-box 否定**：

- **数据资产**：check_states_v3.json 261 精细态（t/ctr/acc1/acc2）→ 141
  个 acc-changing 转变（126 = 单字节变化，15 = 采样间隙多字节）。
- **4-lane 轮转确认**：每转变恰一字节变化，lane 序列 = lo1→hi1→lo2→hi2
  循环（acc1.lo/acc1.hi/acc2.lo/acc2.hi）。
- **消费顺序 = 数据相关（重大）**：lane ≠ pos%4 = 89/126——线程解释器
  按字节值派发（movzx+jmp [edi+eax*4]），字节消费**非顺序**（跳字节），
  被消费字节的位置不可从转变序号推知。
- **S-box 假设否定**：同一 lane_old 出现不同 K（lane_new^lane_old）——
  K = f(byte, lane_old) 泛形，非 f(lane_old) 纯查表。
- **覆盖不足**：126 个 (byte,old)->new 样本 vs 256×256/lane 空间——261 态
  不足以重建 f。**f 完整逆向需要 handler 缝合**（168 唯一 handler 的
  op 体 = 每字节值的更新函数——直接读出 F 而非拟合）。
- **f 逆向增量结论**：结构已知（4-lane + 数据相关消费 + 逐字节 XOR
  更新），全恢复 = handler 缝合工程（已知量：每 handler = 一个字节值
  的完整更新语义）。工具：analyze_f.py / analyze_f2.py。

**续 21 补充 26（同日第十三轮）——handler 缝合资产盘点：三源清点**：

- **ops/ = 空目录**（修正记忆：「20 个 op bodies」从未落盘为文件）。
- **failfreeze = op 带解密态唯一在盘源**：check op（0x105FC00）与
  POOLSNIFF 捕获体 1004/1024 字节吻合 ✓；IMAG 段 0x371000 全可读。
- **256 项派发表不在 failfreeze**：CTXM（0x1020000, 32KB）/PRIV
  （0x1150000, 256KB）扫「连续 256 dword ∈ op 带 [0x1024000,0x1080000]」
  = 0 命中——表为运行时构建且 382ms 时已非连续形态（或条目指向瞬态
  VM 区块）。
- **缝合前置条件 = 二选一**：(a) DECODEWATCH 扩展在 check 期读 VM 数据
  区派发表（dp 已知、表基 = edi = check op 代码内的 dp 相对寻址）；
  (b) REGSNATCH 记录格式修复后提取 check 期 EIP 轨迹 = handler VA 集。
- 工件状态：CISC-1U.v2failfreeze.bin（IMAG 解密态）、
  check_op_body3.bin（POOLSNIFF 体）、ops/（空）。

**续 21 补充 27（同日第十四轮）——DISPATCH-SNATCH 实现：表未在 [dp, dp+0x20000]**：

- **实现落地**：DECODEWATCH 循环内 check 相位（ca_now ∈ op 带）扫描
  [dp, dp+0x20000] 找「连续 256 dword ∈ op 带 [0x1024000,0x1080000]」，
  命中即转储 <out>.v2disp.bin（4ms 节流）。零 Rust 告警。
- **首轮结果 = 未命中**：pristine run 无 v2disp 落盘、无 log——**dp 在
  check 期逐记录漂移**（0x38c30000 / 0xee0000 / 0xb206 …），固定
  [dp@t, +128KB] 窗口错过表基（edi 为 check 全期恒定，dp 非恒定）。
- **下一微增量**：扫描窗 = 本 run 的 dp 值集合并集（DECODEWATCH 记录
  已含全部 dp），或 [dp-0x40000, dp+0x40000] 宽扫；另需打印 RPM 失败
  计数区分「窗错」vs「读败」。
- 工件：add_dispsnatch.py、disp_snatch_log.txt（pristine bail 正常）。

**续 21 补充 28（同日第十五轮）——REGSNATCH 记录格式破解 + check 期 EIP 集**：

- **记录格式（解析器验证 64/64）**：t u32, tid u32, eip u32, 9 regs u32
  (Eax/Ebx/Ecx/Edx/Esi/Edi/Ebp/Esp/EFlags), slen u32, stack[slen],
  plen u32, eippage[plen], blen u32 (0x2000 非 512！), block[blen],
  got_s u32 (0x40), sc[got_s], got_b u32 (0x1e0=480), buf480[got_b],
  **esiva u32 + got_e u32 + espage[got_e]（条件尾 = copy A 页，
  首记录 esiva=0x10f0000 = 镜像数据区 .dat 副本！）**。
- **check 期 EIP 集（64 张，t=[238,243]ms）**：46 个镜像内站点，全部
  在 op 带 rva **0x60000-0x75000**（搜索/比较 op 区），**0x2400D 零
  命中再次确认**（字段校验静态 op 从未执行）；0x5FC00 check op 亦零。
- **缝合路线更新**：EIP 集 = 比较/搜索 op 站点（非 168 字节值 handler）
  ——这些站点 = op 带静态，可从 failfreeze IMAG 直接折叠提取更新语义；
  168 值 handler 的派发表仍需 DISPATCH-SNATCH 深化（dp 漂移未解）。
- 解析器：内联于本轮（记录链 = 定长头 48B + 变长尾 + 条件 esiva 尾）。

**续 21 补充 29（同日第十六轮）——派发表确认纯瞬态**：

- failfreeze IMAG（0x371000，覆盖 copy A 0x10F0000）扫「连续 256
  dword ∈ op 带」= **0 命中**——派发表 = check 期 VM 数据区瞬态对象，
  结束即释放；failfreeze（382ms）与盘上静态均无。
- **获取表仅剩运行时一途**：DISPATCH-SNATCH 的 dp 窗口需命中表生命周期
  （check [200,327] 内），且窗口 = 表基（edi 恒定但 dp 漂移）——需
  check 期高频多点扫描或 esiva/copy A 邻域精查（表或与 copy A 同区）。
- **46 站点折叠 = 深工程**：op 带 = 变异网 + 蹦板链（jmp 目标跨块），
  线性折叠不足以还原语义——需要蹦板展开工具（vm_fold 扩展，续 19⑤
  已列入）。
- 结论：f 全模型的获取成本 = 蹦板展开工具 + 派发表运行时捕获，两项
  均为独立工程；本轮诚实归档边界。

**续 21 补充 30（同日第十七轮）——高频宽窗 DISPATCH-SNATCH：仍未捕获，假设修正**：

- **实现**：1ms 节流、宽窗 [dp-128KB, dp+256KB]、全 dp 轮转、所有不同
  表收集（去重）、窗口结束统一落盘多记录流（count + va + 256 dwords）。
- **结果 = 仍未捕获**（pristine bail 正常，无 v2disp）。
- **假设修正（关键）**：派发条目 **≠ op 带 VA**——check op = 静态
  （0x105FC00），但其 per-byte-value handler 可能为 **VM 区瞬态块**
  （块池加密态、执行瞬间解密——与解码 op 同机制！）。扫描签名
  「条目 ∈ [0x1024000,0x1080000]」从根上错过。修正 = 条目 ∈ 任意
  committed 用户地址 + 有序性签名（handler 块连续分配 → 条目近递增）。
- **f 全模型边界确认**：表捕获 + 蹦板展开两项工具均未建成——f 静态
  恢复 = 长期工程；运行时路（连续补丁 + 哨兵裁决）= 已达当前仪器极限。
- 工件：add_dispsnatch3.py、disp_snatch4_log.txt。

**续 21 补充 31（同日第十八轮）——改名 oracle 复现 + 机制锐化：.dat 文件名内嵌于壳**：

- **修正签名 DISPATCH-SNATCH（round 4）= 仍未捕获**（近递增 + 4MB 跨度
  签名下无表——VM 区瞬态块假设下的表捕获仍需更深仪器）。
- **改名 oracle（DECODEWATCH 仪测，决定性）**：O.exe/O.dat 改名副本 →
  **.dat 工作缓冲从未出现**（needle found=false、records=0、哨兵零
  活动）——续 20 oracle 复现 ✓ 且机制锐化：**O.exe 未读 O.dat** ⟹
  .dat 文件名非 GetModuleFileName 派生，而是**内嵌于壳数据**（壳按
  内嵌名 CISC-1 找 CISC-1.dat）。
- **对 .dat 静态路径的含义**：重编码目标 = 原名 CISC-1.dat（文件名
  不可变）；名字绑定在壳内嵌数据与 .dat 内容之间（名字字符串 = .dat
  解码字段之一，改名 = 名字不匹配 = 不读）。**盘上重编码 oracle 的
  对照组 = 原名 + 原目录**，唯一自由度 = .dat 内容。
- 工件：O/ 目录（改名副本）、rename_oracle_log.txt。

**续 21 补充 32（同日第十九轮）——内容级试验：校验门单字节敏感，.dat 零自由度确认**：

- **试验设计**：原名原目录，唯一自由度 = .dat 内容——单字节翻转对照
  （字节 479 = 最少结构位，XOR 1）。
- **结果（决定性）**：.dat 被读 ✓（found=true）→ **解码从未发生**
  （TSNAP 0 记录 = 缓冲全程静止 = 读后擦除路径）→ 哨兵零活动 → 无
  对话框 → 进程静默停泊（60s 存活）。
- **结论**：**校验门 = 单字节敏感**——.dat 任何内容变更（哪怕最尾
  字节）都被门拒。**.dat 零自由度（无 f）确认**：盘上重编码 = 强制
  依赖 f 模型；f 未恢复前 .dat 内容级试验空间 = 空。
- **对路线的含义**：静态路（f）为 .dat 重编码的唯一前置；运行时路
  （缓冲补丁，绕过盘上内容）= 已达仪器极限。两条路线的公共瓶颈 =
  f 或等价的语义等价物。
- 工件：CT/ 目录（字节 479 翻转副本）、ct479_log.txt。

**续 21 补充 33（同日第二十轮）——蹦板展开工具建成（fold2.py）：46 站点分两类，全程序原语普查到手**：

- **工具**：fold2.py = BFS 变异网遍历（jmp 跟随、jcc 双侧、常量跟踪、
  深度 64 限、loop-back 终止），内存 = failfreeze IMAG 解密态，原语
  计数 + 内存引用 + 终结形态逐站点输出（fold2_report.json）。
- **46 站点 = 两类**：
  1. **共享核心（~20 站）**：covered ≈ 16953（逐站点相同）= 同一解释器
     主循环——**全程序原语普查：add:2410, xor:840, sub:1423, and:207,
     not:204, shl/shr:173/169, or:185, neg:128, imul:5, rol/ror/bswap:1**；
  2. **独立 handler 岛（~15 站）**：real = 51-148，原语分布各异
     （例 0x106b5eb：add:29 sub:16 xor:4 not:3 = F 片段！例 0x1074732：
     add:14 sub:8 neg:1 shr:1 or:1 shl:1）。
- **终结形态**：全部 jmp-indirect = VM 派发确认。
- **下一步**：小站语义分析（real 指令序列 = F(byte, lane) 的直读形态）
  → f 部分模型组装。大站 = 共享主循环 = f 的宿主（逐字节消费在其中）。
- 工件：fold2.py、fold2_report.json。

**续 21 补充 34（同日第二十一轮）——handler 岛语义解读：F = 累加 + 交叉混合 + 派发**：

- fold3.py（DFS 有序序列转储）对 4 个最小岛解读（0x106fe5c/0x106b8b8/
  0x106b8b9/0x106fe26）：
- **岛体语义（0x106fe26，净效果）**：junk 算术全折叠为常数——
  **ebp += ebx + C**（ebp = lane 累加器、ebx = 字节载体、C = 折叠常数）。
- **公共尾（全岛共享，0x106c092）**：`add bl,0x94; sub bl,dh; sub bl,0x94`
  ≡ **bl ^= dh**（+0x94/-0x94 相消）= **lane 交叉混合**；随后
  `movzx eax,al; jmp [edi+eax*4]` = **按下一字节派发**。
- **F 结构确认**：**handler = lane += g(byte) + 常数 → bl ^= dh 交叉
  混合 → 派发**——与 4-lane 轮转实测（补充 25）互证。f 部分模型 = 每
  岛的 g 常数表 + 公共交叉混合；剩余岛（0x1074732/0x106359b/0x1069a4e
  /0x106b5eb）= 同形异常数。
- 工件：fold3.py（DFS 有序序列转储）。

**续 21 补充 35（同日第二十二轮）——F 完整可读（0x1074732 全语义链破解）**：

- fold3 对 0x1074732 的 70 步序列**全明**：
  1. `pop edx`（派发推送的字节）；
  2. `mov ah,0xdd; shr ah,5; add ah,0x8f` → ah = 0x95（**位置常数**）；
  3. `add bl, ah` → **bl += 0x95**；
  4. `mov eax,[esp]`（字节回取）→ `sub bl, al` → **bl -= 字节值**；
  5. junk（dh 混入 = 可折叠）→ 0x106fe26（ebp += ebx + 折叠常数）；
  6. 公共尾 bl ^= dh → `movzx eax,al; jmp [edi+eax*4]` 派发。
- **F(byte) = bl += 0x95; bl -= byte; ebp += ebx + C; bl ^= dh**——
  **重编码所需全部结构要素可直读**。f 部分模型 = 每岛（位置常数,
  字节减项, 折叠常数, 交叉混合）四元组。
- **下一增量**：剩余岛同形常数表提取 → 模型回放 261 态验证 → f 全
  模型 → .dat 重编码 oracle。零自由度瓶颈（补充 32）的解锁钥匙 =
  此表。
- 工件：fold3.py 序列输出（本轮）。

**续 21 补充 36（同日第二十三轮）——重大简化：168 个「handler」= 168 个入口桩 → 单一共享更新体，f = 单一普适函数**：

- fold3 对 0x106359b/0x1069a4e 转储 = **与 0x1074732 完全同链**（全部
  汇入 0x106359a → 0x1069a44 → 0x1069870 → 0x1062b58 → 0x106fe21 →
  公共尾）——所谓 168 个 handler 实为 **168 个入口桩**（每字节值的
  派发目标），字节值**从栈取**（pop edx / mov eax,[esp]），非硬编码。
- **f = 单一普适函数**：`bl += 0x95; bl -= byte; ebp += ebx + C;
  bl ^= dh`（字节无关的常量 + 从栈取的字节）——**模型可完整组装并
  回放验证**（无需 168 份常数表！）。
- **下一增量**：f 普适模型 Python 化 → 261 精细态回放（acc1/acc2
  序列比对）→ 吻合量化 → .dat 重编码 oracle。

**续 21 补充 37（同日第二十四轮）——f 普适模型首轮回放：61% 吻合，交叉混合项待建模**：

- 模型验证（新增量）：每 acc-changing 转变的 K = old ^ new → 模型反解
  byte = (old + 0x95 - new) & 0xFF → **126 转变中 77 个（61%）预测
  字节 ∈ .dat**。
- **未全吻合的原因 = bl ^= dh 交叉混合项未建模**（dh = dh 依赖前态），
  且消费序 = 数据相关（补充 25）。预测字节频次偏斜（0x96×38 =
  交叉混合的残留效应）。
- **判定**：模型部分正确（61% ≠ 随机），**交叉混合项建模 = 下一
  增量**；重编码 oracle 需 f 全模型。
- 工件：本轮内联验证（补充 36 模型 + check_states_v3.json）。

**续 21 补充 38（同日第二十五轮）——交叉混合模型被回放否定**：

- 试验：dh = 0xDB - bl 折叠并入模型（X = bl+0x95-byte；
  bl_new = X ^ ((0xDB-X)&0xFF)）→ 每转变暴力解 X → 预测字节 ∈ .dat
  检验。
- **结果 = 5%（6/126），远差于无交叉混合的 61%**：120/126 转变
  **零解**（X ^ (c-X) 的奇偶约束使多数 new 无解）——观测 new 不在
  该模型的可达集内。
- **结论**：dh 折叠读法有误或 f 结构更深（bl^=dh 的 dh = 别的值/别的
  时刻；junk 未全折叠；消费序模型缺陷）。**f 全模型 = 回退到 61% 的
  部分模型 + 深帧语义再读**（fold3 序列的更多岛 + 蹦板链完整展开）。
- 诚实记录：本轮为负结果（模型倒退），保留 61% 模型为当前最优。

**续 21 补充 39（同日第二十六轮）——0x106b5eb 全链解读 + 网络可整体模拟：检查循环是另一张网，61% 从未是真拟合**：

- **0x106b5eb 173 步 fold3 全链解读（零 jcc，纯直线 jmp 链 = 完整
  handler 尾）**。逐栈槽追踪的净语义：
  1. `dx push/inc/pop` 舞步 + `add bl,0x4a/0xcd; sub bl,al(al=0x73 折
     叠); sub bl,0xcd; sub bl,dh(dh=0x4a)` —— **全部常数相消**：净 =
     `t = (bh_entry - 0x5D - 0x73) = bh - 0xD0`；
  2. **交叉混合项的真身 = `xor al,bl`（0x1066b31）+ `xor al,dl`
     （0x1066a38，dl=0xD3 折叠）——落在 INDEX 寄存器 al 上**：
     `m = a0_low ^ t ^ 0xD3`。补充 34/35 的「bl ^= dh 公共尾」读法
     **操作数角色颠倒**：公共尾 `add bl,0x94; sub bl,dh; sub bl,0x94`
     的 dh = 折叠常数 0x95（0xDB-0x4C+6），净 = `bl -= 0x95`，**不是
     交叉混合**；
  3. lane 更新 = `bl_new = 栈槽副本 - m`（+0x95/+0x94 全相消）；
  4. `ebp += ebx + C`（0x106fe26 链）= **esp 重平衡惯用法**（ebp 原
     值恢复、净效果 esp += 4 经 pop esp）；bh 之舞（0x29→0xAA→0x90
     →0xD3）= 折叠出常数 dl=0xD3 的 junk；
  5. 尾 = `movzx eax,al; jmp [edi+eax*4]` 按 m 派发。
- **派发表定案**：表 = **[TB, TB+0x400)，TB=0x105FFAE**（≡2 mod 4，
  条目非对齐 dword——此前 4 对齐扫描扑空的根因）。**表条目 0-18 =
  状态窗 [TB, TB+0x4C)**（cursor u16@[TB+4]、acc1 @[TB+8]、acc2
  @[TB+0x18]、eflags 暂存@[TB+0x1c] 等）；**168 个在带条目全部
  ≥ 0x1060000**。emu 实测 eax=0x2b → 0x1070acd = TB 对齐读法 ✓。
  快照 block（8KB @image 0x105F000，与寄存器原子捕获）的表与
  failfreeze 表 255/256 一致。
- **emu39 地面真值机（`OUT/ps1/emu39.py`）——蹦板链完整展开目标的
  实现形态**：Unicorn 从 REGSNATCH 快照 #0 起整网模拟。内存配方：
  failfreeze IMAG（明文网；live regsnatchimg 的已执行块已再加密——
  0x106359a 处 live=`c3` vs freeze=`5A pop edx`，**块执行后即再加密**
  的直接证据）+ 原子 block 覆盖 [0x105F000,0x1061000) + esipage
  @0x10f0000 + buf@0xfe0000（ba 来自日志）+ 32KB 栈。1.5M 指令
  干净跑完：**4492 派发、5718 站点、25 个 stub 循环**（停泊线程的
  稳态环），每环过 0x106b5eb 岛（0x106b5f3 sz1 读 ×4491）。
- **时代重划（本轮最大修正）**：REGSNATCH [238,249]ms 抓的是**停泊
  /解码监管稳态环**（数据无关——派发序列 0x2b/0x18/0x45/0x90/0x3a/
  0x3e/0x41/0x4b… 每宏环相同），**不是检查**。检查 = **同一 mutation
  web 的另一个环，全部住在 < 0x1060000**：hub 块 0x105FC00（检查 op
  体静态在盘，freeze 与 live block 逐字节同）+ **46 个 jmp 入口**
  （0x105355f…0x105b0cf，全部来自 [0x1053000,0x105b000)），派发表
  **零条目**指向检查环 = 检查环不经过派发表。补充 28 的「check 期
  46 站点」实为稳态环站点。
- **61% 重新定性**：.dat 480B/218 distinct → 随机成员基线 = 85.2%；
  61.1%（77/126）**低于随机**且 miss 集中（0x96×38）= **从未是真拟
  合**（补充 37/38 的量化口径要改）。状态引导实验（把 acc1/acc2 补
  成 0x6051、cursor=0 再跑稳态环）：派发序列**不变**（环数据无关）
  而 `[TB+0x18]` 被 0x106c281 `pop [edx]` **递减**（0x6051→0x6050→
  0x604f）——**check_states 的 acc = 递减等待计数器**（0x6051 = 其
  初值），不是哈希累加器；补 25 的 4-lane 轮转解读建立在错误对象上。
- **f 的真形态**：检查环 = 下层网的链（hub + 46 跳点），acc 写入点
  静态可扫（`[edi+8]` 6 处：0x1076731/0x10781f6/0x1078398/0x107e6c0
  `xor [edi+8],0x37` 等——稳态环从未访问的区域）。字节源 = lodsb
  式经 esi。
- **下一增量**：① REGSNATCH 触发窗提前到 [190,225]ms 抓真实检查期
  寄存器（若语料仍可跑）→ emu 从真快照复现检查环 → f 全提取；
  ② 或从 46 跳点/`[edi+8]` 锚点做下层网的 fold3 全展开；③ emu 机器
  即重编码 oracle 的骨架（改 buf 内容重放即可量零自由度）。
- 工件：`OUT/ps1/fold3_106b5eb.txt`、`emu39.py`/`emu39.pkl`、
  `emu_check.py`/`emu_check.pkl`、`fmodel39.py`、`parse_ctx.py`。

**续 21 补充 40（2026-11-14 第二十七轮）——检查活捉：f = lane ^ K[lane][byte] S 盒结构（数据级破解）**：

- **REGSNATCH 宽窗改造落地**（三步补丁，零告警）：① 快照 64→200、
  ~450µs 节奏（~135ms 覆盖）；② **churn 识别先于 needle 扫描**
  （needle 会把触发拖到检查之后——run2 实测 224ms 才起步）；③ 双基
  churn 监视（TB + image+0x2859e）+ **sc 改为按快照线程的 edi 动态读**
  （主线程的网有第二个状态基座 edi=0x102859e！）。run4：base2 在
  142ms 先 churn、识别 tid=18528（= 主线程）、needle 172ms 命中
  0xd50000、快照 [172,384]ms 200 张。
- **检查活捉**：run4 [196,222]ms = 检查期，线程在**上带 web**
  （edi=TB；补充 39「检查 = 下层网」修正——0x105FC00 hub 是别的
  环）。**跨 run 确定性实锤**：ctr=22→(0x492b,0x539d)、ctr=45→
  (0xfa11,0xbeb9) 与 POOLSNIFF 时代 check_states_v3 逐位同（不同
  run、同值）。cursor 在 ~210ms 重置 = 两遍确认。
- **检查的字节流 = copy A**（esi 驱动，run4 = esipage[0x5d5:+480]，
  ≠ 盘上 raw .dat 的任何窗口）且跨 run 同值 → copy A 变换确定性。
  消费站点 = 0x10747a4/0x10602e1/0x1061014（sz1 顺序读 [esi]）。
- **f 数据级破解（fsolve40b）**：261 精细态中 **91 个 Δctr=0 单 lane
  acc 转变 100% 确定**；**77/83 (lane,byte) 对 = 单 XOR 键**，即
  **acc_new = acc_old ^ K[lane][byte]**——纯 XOR S 盒结构（补充 25
  的「S 盒否定」用了 raw .dat 当流 = 错流，故否定作废）。K 非线性
  （GF(2) 三元组 0/63）、跨 lane 不同（0/5 同键）→ K = 逐 lane 表，
  最可能 = **派发桩的折叠常数**（补充 36 模型的常数表，语义对上：
  桩选 lane + K）。lane 序列数据相关（ctr 29-47 = 0/1 交替、68+ =
  0,1,2,3 循环）。6 个多键对 = 扫描漏拍的多重更新合成。
- **emu 复现受阻点定案**：freeze 代码跨 run 全同（run4 的 99 张
  上带 eippage vs freeze = 99/99 逐字节同；block 窗 8173/8192）——
  分歧不是代码。emu_check2 从真快照起步：cursor 22→33（字节写真实
  发生）但 acc 重写为原值（K=0 路径）+ **[TB+4] 被写成指针
  0xff0017..0xff001c** → **[TB+4] = dword 流指针**，存在第二个流
  （0xff0000，image 下方的固定 VM 数据区，任何捕获都没盖到）——
  emu 缺低内存区 → 走零页 → 分歧。下一补丁 = REGSNATCH 增配
  [0xff0000,+64KB)（或按快照动态捕指针窗）。
- **下一增量**：① REGSNATCH 低内存窗补捕 → emu 复现检查环 → K 表
  全提取（emu = K 生成器）；② 多跑 POOLSNIFF 精扫_union（每 run
  ~90 转变，~11 run 覆满 4×256）；③ 静态路线 = 168 桩 fold3 →
  (lane, K) 表 + 派发链 = byte→桩映射。重编码 oracle 还差 copy A
  变换（.dat → 流）的逆。
- 工件：`OUT/ps1/patch_regsnatch39.py`、`patch_reorder40.py`、
  `emu_check2.py/.pkl`、`fsolve40.py/fsolve40b.py/.pkl`、
  `parse_ctx.py`、`pagecmp.py`、run2-4 快照与 regsnatch_run3_log。

**续 21 补充 41（同日第二十八轮）——检查环在 emu 里完整复现：K 表双源互证 38/42，f 代码静态现形**：

- **REGSNATCH 低内存窗落地**：每记录 + [0xFF0000,+64KB)（got_l）+
  [TB+4] dword 指针窗 4KB（ptrva+got_p+ptrwin）+ 每 16 记录
  [0xD00000,+3MB) 宽转储（got_w；非宽记录写 got_w=0 哨兵——首版
  条件写导致解析错位已修）。解析器 parse_ctx.py 双格式自适应。
  **RPM 部分读陷阱**：64KB 跨区读 = ERROR_PARTIAL_COPY → 机器丢弃
  → got_l=0；4KB 指针窗完整落区 → 成功。
- **[TB+4] = VM 数据指针（dword）**：检查期 = 0x00ff0000+ctr
  （run4/run6 同基 = 确定性）；u16@+4 = 其低 16 位 = 旧「ctr」。
  **检查的真字节流 = [0x00ff0000+ctr]**，由 ptrwin 完整捕获；
  **补充 40 的 esipage「流」= 错流**（esi = 另一指针，per-run 不同
  基座）——fsolve40b 的 K 表以错流为键，其确定性 = 位置键合的伪象，
  但结构结论（XOR 键 + 单 lane）仍成立。
- **检查环 emu 完整复现（emu_check3/emu_kgen）**：从 run6 真快照
  （t=199863，eip=0x1066a37，ctr=16，acc=(0x2ab0,0xc5cd)）+
  freeze 网面 + ptrwin@0xff0000 + wide 低区 → **零故障跑通**：
  cursor 16→27+（每 bump ~65K 指令）、acc 演化
  **ctr=22/23 → (0x492b,0x539d) 与跨 run 观测逐位同**。
  40M 指令 = 139 个 (lane,byte,old,new) 转变 + 128 (lane,byte) 槽。
- **K 表双源互证**：emu 执行的 K（124 单键槽）vs 261 精细态解
  （真流重解）——共享槽 **38 同 / 4 异**；emu 槽 **75/124 K==byte**
  → 一阶 = `new = old ^ byte`，139 行中 83 行符合、56 行偏离
  → **K = f(byte, old)**（old 相关）。校验残余：coarse 点单 lane
  错位（acc1 ✓ acc2 ✗ 或反之）= lane 选择规则细节未闭合。
- **f 代码静态现形**：acc 写点 0x10646e1 = **`mov byte ptr [ecx], bl`**
  （lane 槽指针在 ECX、新值在 BL——lane = 桩动态计算的地址非固定
  偏移！）；cursor bump 0x106c281 = `pop dword ptr [edx]`；字节入口
  0x1067d28 = **`mov bl, al`**（al = 消费字节）；桩链
  0x106f6e4→…→0x1072c92 出现**第一个真 jcc（jg 0x10626b0）**
  ——f = 数据相关分支的实现，fold3 单路径不够 = 需要 BFS 全展开或
  以 emu 轨迹为准。
- **下一增量**：① f 桩（0x106f6e4 链）fold2 双路径全展开 +
  `mov [ecx],bl` 的 ecx 计算链 = lane 规则；② emu 长跑到两遍终值
  （~63M 指令）取 acc 终值 = 门常数验证；③ K = f(byte,old) 的
  2D 表按 emu 多锚点补样。重编码 oracle 剩 copy A 变换逆 + f 全形。
- 工件：patch_lowwin41.py、parse_ctx.py（双格式）、
  emu_check3.py/.pkl、emu_kgen.py/.pkl、run5/run6 快照与日志。

**续 21 补充 42（同日第二十九轮）——检查 = emu 完全复现并 11/11 逐点验证；f 桩 = 检查主循环本体**：

- **f 桩全展开定案**：0x106f6e4 链 267 步 fold3 = **检查主循环本体**：
  `0x10602e1 lodsb al,[esi]`（字节消费 = VM 自增 esi——真输入流 =
  **esi 流**，run6 = 0x1142201 起 480B；补充 41 的「esipage = 错流」
  再修正——esi 基座 per-run 不同但内容同 = 确定性，0xff0000 =
  另一副本非消费源）→ `0x10602e2 xor al,bl`（字节 ⊕ lane BL）→
  折叠常数链（3 个真 jcc：jg 0x10626b0 / jge 0x106832a / jl
  0x10704bb = 数据相关分支）→ `0x1067d28 mov bl,al`（混合值回
  bl）→ `0x10646e1 mov byte ptr [ecx],bl`（lane 槽写回，ecx = 桩内
  从 ebx/edi+折叠常数计算）→ `0x106c281 pop [edx]`（指针 bump）→
  `pushfd; jmp 0x10602e1` 循环。**f = 这个循环**——不是 256 桩派发。
- **emu_final 验证方法修正 + 11/11 全绿**：coarse 快照 = 挂起瞬间
  的 mid-cycle 态；此前「mismatch」= 比较 final-per-ctr 的 off-by
  伪象。正确判据 = 观测点 (ctr, acc1, acc2) ∈ emu 在同 cursor 的
  状态集 → **11/11 全部命中**（ctr=16/31/45/60/75/103/117/133/147/
  161/175 全逐位同）——**emu = 检查的 ground truth 实锤**。
- **emu_final 到达 pass 间过渡态**：acc=(0x2bc0,…) 与 run4 观测的
  inter-pass 值 (0x2bc0,…) acc1 逐位同；**[TB+4] 指针在 pass 间切到
  0x006fb000 区**（低 16 位 45488=0xb1b0 ✓ = 0x6fb1b0）——pass 2 =
  消费 0x6fb000 流（run6 t=195829 记录的 ptrwin 已捕 ✓ 已映射）；
  emu 在 pass-2 派发处死（dispatch 目标 = DLL 地址 = 表项 junk =
  某输入仍缺）。union 映射 20 个 ptr 窗（0x6fb000/0xff0000/0xfd0000/
  0xfe0000/0x1021xxx…）。
- **残余缺口**：① pass-2 emu 死因（~7K 指令后派发出界——某区内容
  仍缺/时变）；② lane 规则 = ecx 计算链的静态提取（ecx = ebx/edi+
  折叠常数，在 jcc 路径里）；③ K = f(byte,old) 的 2D 形式。
- 工件：emu_final.py/.pkl/.log、fold3_106f6e4.txt。

**续 21 补充 43（同日第三十轮）——lane 规则破解：完美 ctr%4 四循环；f 闭式=链非单 XOR**：

- **pass-2 死因定位**：fatal dispatch = eax=0x80 → 合法目标
  0x107154c，链首 = **`push dword ptr [edi+0x38]`**（状态窗 +0x38 槽，
  64B sc 之内）——死亡在其后更深处的间接跳（经某数据槽 = emu 侧
  陈旧/零值）。edi 全程 = TB（162333 派发无一例外）。
- **lane 规则 = 完美 ctr%4 四循环（emu 193 次 acc 写实测）**：
  ctr%4=0→[TB+8](acc1.lo)、1→[TB+9](acc1.hi)、2→[TB+0x18](acc2.lo)、
  3→[TB+0x19](acc2.hi)，49/48/48/48 次 = **零例外**。补充 25 的
  pos%4 直觉对 lane 本身成立（错在字节流与 K 形式）。
- **[TB+4] = 0x00ff0000+ctr 的流指针确认**（193 行 ptr 高 16 位全部
  = 0xff）——但消费字节 ≠ ptrwin[ctr]：emu_ftrace 范围钩（lodsb 点
  0x10602e1 + acc 写点 0x10646e1）实测：**lodsb 每次 acc 写触发
  ~1024 次**、esi 步进 ~+0x116（走一个更大的数据结构非字节游标）；
  同一 (esi, al_in, bl_in, mem) 四元组重复出现 = 循环确定性。
  f 闭式 ≠ old^ptrwin[ctr]（ctr=16/18/19 巧合符合、17/20/21 不符）
  ——**f = lodsb 字节 + bl lane + 折叠常数 + jcc 路径的链**，
  闭式提取 = f 桩的 fold2 双路径语义合成（emu = 已验证的 oracle，
  静态 = 形式化路线）。
- **emu = 检查的 ground truth 实锤不变**：lane 写序列
  0x75/0x4d/0x20/0x53/0x2b… 与 emu_check3 及跨 run 观测一致。
- **下一增量**：① f 桩 0x106f6e4→0x10602e1 循环的 fold2 双路径
  语义合成（3 个 jcc 的条件与两侧效果）；② emu 迭代计数器挂钩
  （1024 循环/ac 写的结构 = esi 步进语义）；③ pass-2 派发链
  （0x107154c 起）的缺失数据槽定位。
- 工件：emu_ftrace.py/.pkl、emu_final.py/.pkl。

**续 21 补充 44（同日第三十一轮）——循环结构定量：~1024 lodsb/acc 写、esi 四位置循环、G 非二元函数**：

- **差分探针（emu_diff）**：扰动 esi 区前 4 字节（^1）→ 1.2M 指令内
  acc **零变化**——早期迭代读的字节不是 acc 更新的直接输入。
- **循环结构定量（emu_gtrace）**：1.2M 指令 = 10236 lodsb + **10 次
  `mov bl,al`（= acc 写 1:1）**——bl 更新在 per-ctr 路径上，迭代循环
  不经过 0x1067d28。**esi = 四位置循环**：0x114232e/0x1142444/
  0x11425ae/0x1142720 每 4 次 acc 写一轮（步进 ~+0x116），walk 内
  ~1024 次 lodsb/acc 写（esi delta 直方图：0×5709/1×3924/2×344/
  4×237 = 慢游标带重复读）。
- **G(bl_in, byte) 非二元**：同一 (esi=0x114232e, byte=0x8b,
  bl_in=0xd4) 在 ctr=16 → bl_out=0x75、ctr=20 → 0x2b（同 lane 槽
  +0x8！）——**f = 多输入函数**（byte + lane + 其余 lane/ctr 状态）。
  闭式 = 需全输入轨迹（emu = 已验证 oracle；静态 fold2 = 形式化）。
- **诚实记录**：本轮未闭合 K=f(byte,old) 2D 形式——其前提（单字节
  输入）本身不成立；pass-2 缺失槽未定位。f 的实用形态 = emu 执行
  本身（11/11 验证）。
- 工件：emu_diff.py/.pkl、emu_gtrace.py/.pkl。

**续 21 补充 45（同日第三十二轮）——写门=第二 jcc；f 闭式前提再证伪；pass-2 = helper DLL API 门**：

- **emu_iter 逐迭代全输入轨迹（6824 迭代/10 acc 写）**：写路径 =
  **到达第二 jcc（0x1072c92 `jg`）的迭代**——5/6824 ≈ 0.07%；
  路径族 = 3412 无 jcc + 3407 过第一 jcc（0x1070fce `jge` 恒 taken）
  + 5 双 jcc+写。**jcc 条件闭合**：第一 jcc 恒 taken（其 eflags 模式
  固定）；写门 = 第二 jcc 的 jg 条件。
- **f 闭式再证伪**：写迭代 (byte, bl, al_in) = (0x38, 0x23, 0xc5)
  在 ctr=18 → 0x20、ctr=19 → 0x53 **同输入异输出**——隐藏输入 =
  其余 lane/寄存器/内存（链内读取未入轨迹）。K=f(byte,old) 的 2D
  前提正式作废；f 的实用形态 = emu（11/11 验证）。
- **pass-2 门 = helper DLL API 调用**：inter-pass 链经导入指针
  跳 0x7565e960 / 0x7565d770（真实 DLL 地址——emu 缺 DLL → fetch
  错误）。**C3/xor-eax-ret 桩页修复 fault-storm**（零页 =
  add [eax],al 风暴的根因）。API 参数捕获：
  **(ptr=0x115b7ae, 0x1a0=416, 0x1c4e8ece, ptr2=0x10e35a3,
  0xeedc0014=VM magic, …)** + 第二调 (ptr2, 0, 416, …) ——
  **壳自带的校验/解密 helper**（参数形 = 缓冲+长度+校验+键+magic）。
  eax=0 桩 → 调用者用返回值算指针 → 读 0xffff9614 死。
  **下一增量 = 该 helper 的语义桩**（识别 DLL/返回值约定）或从
  run-6 的真实返回值回填。
- 工件：emu_iter.py/.pkl（6824 迭代全输入轨迹）、emu_final 修复
  （fault 页 C3 桩 + API 参数捕获）。

**续 21 补充 46（同日第三十三轮）——第二 API = GetModuleHandleW(NULL)；inter-pass 链 = VM 自定位代码**：

- **调用者静态可读**：API 调用点 = `ff 95 71 08 26 12`
  （call [ebp+0x12260871] = helper）→ 返回 → `6a 00 ff 95 9d 01 26
  12`（**push 0; call [ebp+0x1226019d] = GetModuleHandleW(NULL)**）→
  `8b c0`（mov eax,eax）→ `eb 3b`。
- **语义桩落地**：0x7565d770 = mov eax,0x1000000; ret（模块基座）；
  0x7565e960 = xor eax,eax; ret。死亡点不变：0x115b9e5 读
  [0xffff9614]（eip = 0x115b9e5，访问 19）。
- **inter-pass 链 = VM 自定位代码**：`call $+5; pop edx` +
  `mov [esp+4],edx; add [esp+4],0x19; inc edx; push edx; ret` =
  计算跳转连续体——线性反汇编无效，静态合成不可行；追踪只能靠 emu。
- **残余**：死亡指针 0xffff9614 = 链内计算值（API 结果 + VM 状态）；
  需要更深的语义桩（链中更多 API/状态读取）或 run-6 真实返回值
  回填。emu 的 pass-1 轨迹 = 完整可复现（11/11）不变。
- 工件：emu_final（语义桩版 + API 参数捕获）。

**续 21 补充 47（同日第三十四轮）——枚举否决 + 分歧点定位：pass 边界过渡 = 缺失环节**：

- **helper 返回值枚举否决**：C3 桩（eax=残余 0xf639）与 xor-eax 桩
  （eax=0）死亡点**完全相同**（0x115b9e5 读 0xffff9614）→
  **EDI = 0xffff9614 与 helper 返回值无关**——枚举无意义。
- **死亡寄存器**：EDI = 0xffff9614（死亡指针在 EDI）、EBX = 0x2bc0
  = inter-pass acc1（链用 acc 作参数）、ESI = 0xb3f32194（已乱）。
- **emu_final 死亡前派发环（关键）**：死亡前 esi = 0x115b5e4 起每
  派发 +1 = **emu 在 inter-pass 后消费了 ~103K 字节**（esi 从快照
  0x1142201 走到 0x115b5e4 = +0x193E3）——区域 = freeze 图像字节 =
  错误内容。**emu 的 pass-1 完全正确（11/11 至 ctr=200），分歧点 =
  pass 边界过渡**：真 inter-pass = 指针切 0x006f90DC（run4），
  emu = 指针走 0x00ffb47f（乱）→ 错流 ~103K → 死。
- **边界过渡 = 缺失环节**：真 transition 的驱动（指针 0x6fb000+
  0x90dc 的来源 = pass-1 终态的函数？某状态槽？）未定位——emu 需要
  该过渡的语义（更多状态/API/内存内容）。
- **下一增量**：定位边界过渡的驱动（对比 run4/run6 的 inter-pass
  指针值 0x6f90dc/0x6fb1b0 与 pass-1 终态）→ emu 复现过渡 →
  pass-2 → 两遍终值。
- 工件：emu_enum.py/.pkl（枚举否决）、emu_final（寄存器+派发环）。

**续 21 补充 48（同日第三十五轮）——指针多区域定案 + 两遍结构 + 流哨兵现形**：

- **[TB+4] = 多区域 VM 数据指针（run-4 全时间线）**：
  pre-check = 0x006490d8（per-run VM 区，run6 = 0x6fb000）→
  检查 pass-1 = **0x00ff0000+ctr（7→199）** → **inter-pass = 回
  0x006490dc（pre-check 游标 +4 继续！）** → pass-2 =
  **0x00ff0004（同流第二次，4→480）** → post = 0xd5xxxx（buf 区）等。
  **两遍 = 同一 0xff0000 流消费两次（pass-1 = 0→199、pass-2 =
  4→480）**——补充 47 的「inter-pass 指针 0x6f90dc」= pre-check 区
  游标回归，非新流。
- **流哨兵现形**：0xff0000 流尾部 = **…fb fb fe fe fe fe**
  （offset 203..207）= 终止标记模式（流 = 480B，ptrwin[203..] =
  fb/fe 重复）。
- **emu = 漏掉 pass-1 终止**：emu 的 ptr 写过 0x00ff00c9+（1077 次）
  = 越过 ctr=199 终止点继续消费；真 pass-1 = 在 199 终止切区。
  终止 = 哨兵驱动的分支（emu 分支未命中——流内容正确已映射，
  分支输入 = 另有它物）。
- **下一增量**：定位终止分支（emu 在 ptr≈199 时对比 0x10744f2/
  0x106c281 写点附近的分支行为 vs 真 run），修复 → pass-2 →
  两遍终值。
- 工件：run-4/run-6 指针全时间线提取（本节内联）。

**续 21 补充 49（同日第三十六轮）——循环块结构定案：ptr=块计数器、~1024 迭代/块、emu 块级失控**：

- **emu_bound 80M 指令长跑**（487611 事件）：**ptr = 0x00ff0000+ctr
  在块内冻结**——块 = ~1024 迭代的处理窗，acc 写 = 块结束（ptr bump
  = 块计数器！）。emu 实测：ptr = 0x00ff00c3 冻结数千迭代、bl =
  滚动演化（f6→b1→7c→64→19→01→c3→3d→f8→…）、esi = 慢走
  0x1142919+（delta 0/1/2/4 重复读）。
- **循环 = 块结构**：每块 = 读 0x1142xxx 区（copy A 块）的滚动混合，
  块尾写 acc 槽（lane = ctr%4）+ bump ptr。**0xff0000 流 = 块输出
  /状态区而非简单输入流**——补充 48 的「流」解读需再修。
- **emu 块级失控**：emu 的 ptr 覆盖 16..46207（块计数器狂奔）=
  pass-1 块处理发散——块 195 处数千迭代不终止（真 = ~1024 迭代/
  块）。块终止条件未满足 = 块输入缺失（0x1142xxx 区仅映射快照
  4KB 页，walk 超页 = 零页）。
- **下一增量**：块终止条件定位（真块 ~1024 迭代的驱动 = esi 窗口
  尾标记？计数槽？）；0x1142xxx 区完整捕（REGSNATCH esipage 扩到
  16KB/块）。
- 工件：emu_bound.py/.pkl/.log（80M 指令 487611 事件）。

**续 21 补充 50（同日第三十七轮）——esipage 16KB + pass-2 锚点发现，emu 直锚 pass-2 跑终值**：

- **REGSNATCH esipage 4KB→16KB**（分页 4×4KB 捕获避开 RPM 部分读
  陷阱；1 个 unused-variable 告警即修）。run8 = 200×16384B。
- **esi walk = 多区域**（0x1141/0x1142/0x114f/0xef000…跨 ~49 个
  4KB 页）——emu 改为 esipage 并集映射 + 栈区容错（walk 部分读栈！）。
- **pass-2 在 run-8 记录里直接捕获**：t=216810 ptr=0x00ff000c、
  t=217826 ptr=0x00ff0024、t=218824 ptr=0x00ff0037 = **pass-2 运行中**
  （pass-1 终止 → inter-pass(t=215797 ptr=0x006ed234) → pass-2！）。
  **emu 直锚 pass-2 记录**（t=216810, eip=0x106b78e）→ 跑到流尾 =
  两遍终值 = 门常数（后台 400M 指令，minimal hooks 提速）。
- **run-8 锚点探针副产物**：某锚点首指令写 0x4a660105 = 缺失堆区
  （wide 只捕 [0xD00000,0x1000000)）+ C3 填充页被当代码执行的
  fetch 风暴——数据页应零填、取指页才 C3（待改）。
- 工件：helpers.rs（esipage 16KB 分页捕）、emu_pass2.py（后台）、
  emu_bound.py（esi 并集版）、run-7/run-8 快照。

**续 21 补充 51（同日第三十八轮）——pass-2 emu 锚定成功：指针 0x24→0x37 = 观测范围，但链再次入 API 门**：

- **pass-2 锚点选择**：run-8 三条 pass-2 记录中 t=216810 的 eip=
  0x106b78e = 恰在 API 调用点（间接跳 0xf8012910 = VM 导入 = 内核
  态地址）→ **换 t=217826 eip=0x1066a38（xor al,dl = 补 39 全链解读
  的站点，链中段）** → emu 干净起步 ✓。
- **pass-2 跑通**：指针 0x00ff0024→0x00ff0037（20 个指针状态 =
  与 run-8 观测范围一致！）→ 然后**再次进入同一 inter-pass API 链**
  （0x115b7b6 = 同一调用点，helper + GetModuleHandleW）→ 栈下行
  fault-storm（0xeeffc→0xebffc，esp -0x1000 步进）。
- **判定**：pass-2 的链在 ptr≈0x37 处再次调 helper API——要么
  pass-2 短（run-8 观测只到 0x37），要么 API 语义桩缺失导致提前
  分流。**API 语义桩 = 收尾的关键单点**。
- 下一增量：helper API 返回值语义（从 run-8/r4 的 pass-2 观测
  推断或识别 helper）→ emu 完整两遍终值。
- 工件：emu_pass2.py/.pkl/.log（锚定 pass-2 版）。

**续 21 补充 52（同日第三十九轮）——栈映射顺序 bug 修复 + 栈下行递归现形**：

- **映射顺序 bug**：esi 并集先映射 0xef000（16KB = [0xef000,0xf3000)）
  **挡掉栈映射** [0xeb000,0xfb000) —— 栈只有一页在映射里 →
  0xeeffc/0xedffc… fault-storm 的真根因。修复 = 栈先映射、esi 页
  逐页（4KB 粒度）容错后映射。
- **修复后**：faults 变为栈**下行递归**（0xeaffc→0xe9ffc→0xe8ffc→
  0xe7ffc，esp 穿过 64KB 栈窗继续降）= inter-pass 链在 API 桩
  （xor eax,eax; ret）处**递归调用**——桩返回值错误 → 链条件
  分支走递归侧。helper 语义返回值 = 仍缺。
- **判据**：栈下行 = 桩语义错误的直接信号；正确返回值应使链
  不递归而推进 pass-2。
- 下一增量：helper 返回值枚举×递归判据（递归消失 = 正确）；
  或识别 helper（参数 ptr/416/hash/ptr2/magic = 壳内部校验函数）。
- 工件：emu_pass2.py（映射顺序修复版）。

**续 21 补充 53（同日第四十轮）——helper 返回枚举彻底否决；死亡 = 无限栈下降递归**：

- **emu_enum2（7 候选×递归判据）**：zero/one/hash_echo/ptr/len/ptr2/
  modbase 全部**逐位相同**（esp_min=0xefeec 窗内、faults=81、
  ptr=0x00ff0037、acc=(0xb45d,0x0000)）——**helper 返回值与流程
  无关，枚举路线正式关闭**。acc2 = 0x0000 现形（pass-2 acc2 被清）。
- **死亡 fault 页直方图**：0x7565e000/0x7565d000（API ✓）+
  **0xea000→0xde000 逐页下降** = esp 穿过栈窗底无限下降——
  inter-pass 链（VM 自定位代码）在 API 桩处**无限递归**（每页
  C3 桩 → 链继续 → esp 再降）。
- **机制**：链 = 自定位栈传输（call $+5/pop/push/ret 连续体），
  桩返回值错误 → 条件分支走递归侧 → esp 永降。正确返回值 =
  使分支走推进侧；枚举不可达 → **需识别 helper 本体**（参数
  ptr/416/hash/ptr2/magic = 壳内部校验函数；DLL 0x7565xxxx per-run）。
- **下一增量**：① helper 识别（run-8 的模块列表/API 名——需新
  仪器捕获模块表+导出）；② 或 pass-2 尾部回填（run-8 观测 pass-2
  只到 ptr=0x37，helper 调用 = pass-2 真实终止的一部分——直接从
  run-8 记录取 pass-2 后的状态继续）；③ 或 acc 门常数从 run-4/6/8
  的 post-check 观测直接读（0x115b9e5 链 = 非检查本体）。
- 工件：emu_enum2.py/.pkl/.log。

**续 21 补充 54（同日第四十一轮）——pass-2 短程确认 + 门常数 0x88cb 现形（观测直读路线成功）**：

- **pass-2 acc 序列跨 run 逐位同（第 3 次独立确认）**：run4
  0x04→(0xe536,0x0037)/0x1c→(0xd6b4,0x0037)/0x35→(0x8dc2,0x0037)；
  run6 0x09→(0xb02e,0x0037)/0x1f→(0xdfbd,0x0037)/0x35→(0x8d9b,0x0037)；
  run8 0x0c→(0x0615,0x0037)/0x24→(0xcd84,0x0037)/0x37→(0x82ba,0x0037)。
- **acc2 = 0x0037 在 pass-2 全程冻结**（三 run 一致）——pass-2 的
  hash = acc1 单字节演化、acc2 = 常数标记。
- **pass-2 = 短程**：ptr 0x04→0x37（~50 字节）后进入 post-check
  （ptr 切 0x00fexxxx）——pass-1 = 0→199（200B）、pass-2 = 4→~55
  （~50B）。helper API 调用 = pass-2 真实终止的一部分。
- **门常数 0x88cb 现形**：post-check acc1 = **0x88cb 跨 run 恒定**
  （run6 t=219484/220518、run8 t=221012 全 = 0x88cb）= 检查哈希
  终值 = 门候选。acc2 post-check = 0x0000→0x0001→0x000c 演化
  （另一计数器）。
- **路线判定**：观测直读成功——门常数不需要 helper 识别；emu 的
  inter-pass 链 = post-check 机器（非检查本体），其复现 = 独立
  低优先级任务。**检查本体 = emu 已复现（pass-1 11/11 + pass-2
  轨迹跨 run 同）**。
- 工件：三 run pass-2/post-check acc 表（本节内联）。

**续 21 补充 55（同日第四十二轮）——copy A 变换：无简单代数式，decode-era emu 首锚未命中**：

- **diff 分析**：stream vs raw .dat——diff = 209 distinct（随机形），
  非常量键/非滚动键/非位置 XOR/非置换（sorted 不等）——变换 =
  复杂算法（rolling/加密形）。
- **decode-era emu（emu_transform，锚 run-8 t=184012）**：20M 指令
  干净跑完（4 次 DLL 调用 = 桩处理 ✓），**0xff0000 写 = 0**——该锚
  的流 ≠ 变换写入（变换更早或别的线程/路径）。
- **下一增量**：锚提前（run-8 t=176312）+ 监视面扩大（0xff0000 写 +
  0x1142xxx 写 = copy A 主区）；或先定位 0xff0000 区的写入者
  （POOLSNIFF 式全镜像差分 [180,196]ms 窗）。
- 工件：emu_transform.py/.pkl/.log。

**续 21 补充 56（同日第四十三轮）——早锚（t=176312）双区监视未命中：流又缺区**：

- emu_transform 锚提前（t=176312）+ 监视面 = 0xff0000 + 0x1142000
  双区（hook 范围 [0xea000, 0x1160000)）→ **8 faults 即死**：
  fetch 0x7000000（跳未映射）、0x1c4e8ece（= helper 的 hash 参数
  值现形为跳转目标！）、随后 C3 页风暴。
- 早锚流 = 依赖更多缺失区（0x7000000 = 新缺区；0x1c4e8ece =
  hash 值被当指针 = 状态未初始化）。
- **判读**：decode-era 的流 = 比 t=176312 更早启动，或该流的
  前置状态（API 结果/区初始化）未捕获。0x1c4e8ece = hash 常数
  被跳 = 状态窗未填（早锚缺前置初始化）。
- **下一增量**：① 缺区逐个回填（0x7000000 等按 fault 地址表）；
  ② 或 POOLSNIFF 式全镜像差分定位 0xff0000 写入者的线程/时段，
  再锚定该线程的精确快照。
- 工件：emu_transform.py（双区监视版）/.pkl/.log。

**续 21 补充 57（同日第四十四轮）——wide 分页读修复：0xff0000 演变时间线到手**：

- **wide 3MB 全范围 RPM = 部分读陷阱吞掉全部 wide**（got_w=0，
  与 lowwin 同根因）——分页 768×4KB 修复 ✓（run9 = 13 wide 记录，
  52.8MB 数据）。
- **run-9 时代偏移**（t=246..573ms vs 前 run 的 172..386）：wide
  稀疏（每 16 记录 ~25ms）——0xff0000 在 t=246698 = 全零、
  t=504037 = nonzero 323/4096 = **构建发生在 wide 间隔内**。
- **下一增量**：wide 频率提高（每 4 记录）+ run 时代对齐（多跑
  取早 era），0xff0000 演变 = 变换的输出时间线 = 算法定位。
- 工件：helpers.rs（wide 分页读）、run9 快照（52.8MB）。

**续 21 补充 58（同日第四十五轮）——wide 提频命中：0xff0000 = 活动工作缓冲区（构建时间线到手）**：

- **wide 目标性小转储**（0xff0000 页 4KB + esi 区 16KB = 20KB，每
  4 记录）替代 3MB 全量——文件 13.7MB 可控。
- **构建时间线到手（run10，50 wides）**：t=190985 全零 → t=207872
  **nz=124 头=7abc9f7afc97…（检查期已知头！）** → t=211996 nz=474
  → t=249690 **头变 6755753f…** → t=259426/271724/279856 滚动变 →
  t=308522 **头再变 aab5bba7…** → 内容持续重写。
- **范式修正：0xff0000 = 活动工作缓冲区**——非「构建后使用的流」；
  检查期快照 = 演变中的某一刻。「copy A 变换（.dat→流）」框架
  作废——真结构 = 检查循环边读 copy A（esi）边滚动更新工作区。
- **下一增量**：0xff0000 写入者 = 检查循环本体（emu 已复现）——
  工作区演变 = emu 轨迹的一部分；重编码 oracle 的输入 = copy A
  区（0x1142xxx）的构建（.dat→copy A）仍待定位。
- 工件：helpers.rs（目标 wide）、run10/run11 快照、演变时间线。

**续 21 补充 59（同日第四十六轮）——copy A 构建早于仪器首快照：needle 扫描阻塞定案**：

- **wide 每记录**（200 wides）+ 双跑（run12/13，era = 176329 起）：
  **copy A（esi 区）在首快照即已建满**（nz=16315/16384，头 =
  ad969e63…）→ **构建 < 176ms**。
- **根因 = REGSNATCH phase-1 needle 全内存扫描阻塞**（找到 .dat
  缓冲才开始快照 = 176ms）——copy A 构建窗口 [~100,176] 被错过。
- **下一增量**：needle 扫描异步化（快照先行、needle 后补）或
  POOLSNIFF 式差分直接定位 copy A 写入时段——copy A 构建窗口
  [100,176] 是变换的执行窗口。
- 工件：run12/run13 快照（16.7MB each，200 wides）。

**续 21 补充 60（同日第四十七轮）——事故：git checkout 丢失未提交机器改造；恢复计划**：

- **事故**：phase 重排文本手术破坏结构（phaseC 截到文件尾）→
  git checkout helpers.rs 回滚 → **补充 40-58 的全部 helpers.rs
  改造（未提交）丢失**：wide 窗改造、双基座 churn、edi 动态 sc、
  esipage 16KB、lowwin/ptrwin/wide 目标转储、needle 重排——
  全部回到 389239c 旧版。
- **教训**：机器改造应**即时提交**（本轮多轮 .rs 补丁只提交了
  docs）；文本手术前先 git add。
- **恢复路径**（补丁脚本部分在 OUT/ps1）：① patch_regsnatch39.py
  （宽窗+主线程交错）② patch_reorder40.py ③ patch_lowwin41.py
  ④ esipage 16KB/分页 wide/目标 wide（inline——需重写）⑤ needle
  异步化（本轮目标）。恢复后重跑 run 验证 esipage=16KB。
- **本轮目标（needle 异步化）顺延**；copy A 构建窗口 [~100,176]
  复现 = 恢复后首个增量。

**续 21 补充 61（同日第四十八轮）——恢复手术二次失败：结构性中间态定案，路线改为小步重放**：

- **恢复手术**（restore_all.py 合并补丁）后括号失衡两次修正仍余
  2 个结构错误（while 3322 未闭合 + 5759 多余 )）——文本手术
  叠加多块替换 = 括号追踪超限。
- **已回滚**到干净基线（cargo build 零告警 ✓）。helpers.rs =
  389239c 旧版（补充 40-58 改造仍缺）。
- **恢复路线改判**：一次性合并补丁 = 不可行（锚点漂移 + 括号
  跨块）。改 = **小步重放**：每步一个独立小补丁 + cargo check
  逐块验证 + 每步 git commit。步骤 = ① needle 删除/ba=0 ② 双基座
  churn ③ 200 快照+interleave ④ edi-dynamic sc ⑤ esipage 16KB
  ⑥ lowwin/ptrwin ⑦ 目标 wide。估计 = 7 次小步。
- 工件：restore_all.py（合并版——仅作参照）、restore60.py。

**续 21 补充 62（同日第四十九轮）——小步重放完成：机器改造 7 步全部恢复并提交（每步零告警）**：

- 小步重放 ✓：①needle 删除/ba=0（7d84c3f）②双基座 churn 最小侵入
  （d8a6b32）③200 快照+450us+interleave（cffec28——3 个 hh 误替换
  到别函数即修 + hh 绑定补插）④⑤ edi-dynamic sc + esipage 16KB
  ⑥⑦ lowwin 64KB + ptrwin + 目标 wide（1116355）。**全部零告警、
  每步单独 commit**。
- **run15 解析异常待查**：64 records (pre-41 fallback)、t=290268..
  294590——格式回退到旧解析 = 新格式字段未被识别（待诊断：
  lowwin/ptrwin/wide 顺序 vs parse_ctx 预期）。
- **下一增量**：① parse_ctx 对齐新字段序 ② 重跑验证 esipage=16KB
  ③ copy A 构建窗口复现。

**续 21 补充 63（同日第五十轮）——run15/16 解析异常诊断：got_e=4096 与 16KB 源码不符**：

- 逐字段诊断（自定义解析器）：rec0 = t=290268, eip=0x1075104,
  slen=32768, plen=4096, blen=8192, got_s=64, got_b=0, esiva=0x1142000,
  **got_e=4096**——esipage 仍是 4KB！
- **矛盾**：源码 grep = esipage [0u8; 0x4000]（16KB ✓）、二进制
  mtime = 恢复后构建 ✓——但捕获 = 4KB。两种可能：① 运行时二进制
  与磁盘不同步（cp 时序/旧进程占用）；② 恢复补丁有遗漏（某分支
  仍走旧 4KB 路径）。
- 64 records = nsnap < 200 未生效的另一佐证——**恢复补丁实际未
  完全生效**，需对照源码逐块复核（grep 每个补丁点的当前状态）。
- 下一增量：① grep 核验 7 个补丁点在源码中的现状 ② 重编译+重跑
  ③ parse_ctx 对齐字段序。

**续 21 补充 64（同日第五十一轮）——机器恢复完全验证：esipage 16KB ✓、wides=200 ✓、era 145ms ✓**：

- **grep 7 补丁点核验**：全部在源码 ✓（needle 0 处=已删、双基座/
  200 快照/edi sc/esipage 16KB/lowwin/目标 wide 各 1 处）。
- **force rebuild + 重跑（run17）**：**200 records (41+) 解析成功**、
  t=145750..358878——**era 从 145ms 起 = needle 删除生效**（此前
  176ms+）。run15/16 异常 = 旧二进制（重编译后消失）。
- **esipage = 16384×195 + 0×5 ✓**（16KB 生效验证）。
- **wides = 200 每记录 ✓**；copy A（esi 区）演变：t=145750 即
  nz=16315/16384（已满，头 ad969e63…）→ t=199231 nz=16336
  （内容微变）→ t=200231 nz=16240（头 829c5ece…）——**copy A 在
  检查期有活动**（不只是静态）。
- **残余**：copy A 构建完成于 <145ms（churn 触发的快照仍略迟）；
  快照去触发化（识别后立即开始，不等 churn）或更早 arm 可覆盖
  构建窗。机器 = 恢复态完全可用。
- 工件：run17 快照（29.7MB，200 records 41+ 全字段）。

**续 21 补充 65（同日第五十二轮）——快照去触发化落地：copy A 区 = 每快照演变的活动处理区**：

- **de-trigger 提交**（727f3c7）：识别扫描立即执行（5ms 节流替代
  churn 门）——覆盖 copy A 构建窗 [100,145]。
- **run18 = 200 records、t=146227 起 ✓**（era 提前验证）。
- **copy A（esi 区）每快照演变**：146227→147102→…内容逐快照不同
  （含可读串 "3.1-4.SetProcessDynamic"、cccc 填充、全零瞬间等）=
  **活动处理区实锤**——变换在持续进行，不是构建后使用。
- **范式最终定案**：copy A = 检查/变换的活体工作区；.dat→copy A
  = 持续滚动过程（快照序列 = 过程切片）。重编码 oracle = 需要
  copy A 的完整时间线（本 run18 已捕获 200×4KB 切片）。
- 下一增量：copy A 时间线切片与 .dat 的对应关系（每个快照的字节
  与 .dat 的映射）→ 变换的输入输出对提取。
- 工件：run18 快照（29.8MB，200×16KB esipage 时间线）。

**续 21 补充 66（同日第五十三轮）——copy A 时间线分析：esi = API 字符串游走，.dat 不在 esipage**：

- run18 的 200×4KB esipage 时间线逐快照分析：早期 era（146-151ms）
  的 esi = 读系统字符串（"NtQuerySystemInfo"/"VerifyLanguageName"）
  = **壳的 API/许可检查游走**，非数据流；.dat needle 在 esipage =
  **0/20 未出现**。
- **判读**：copy A ≠ .dat 的直接拷贝；esi = 通用读游标（API 字符串
  → 数据区 → …多用途）。.dat 的副本在 ba（needle 定位）独立存在。
- **下一增量**：copy A 的真身定位——从检查循环（emu 已复现）的
  lodsb [esi] 反推 esi 在检查期的取值序列（emu 轨迹 = esi 时间线），
  对齐 .dat 映射。
- 工件：run18 esipage 时间线分析（本节内联）。

**续 21 补充 67（同日第五十四轮）——esi 序列分析：4 位置循环确认，完整轨迹需重采**：

- emu_gtrace pairs（1.2M 指令）：esi = 4 位置循环（0x114232e/
  0x1142444/0x11425ae/0x1142720，步进 ~0x116）✓（与 emu_bound 一致）。
- emu_bound.pkl 的 L 事件 = 仅 4 个（pickle 截断在 400K 事件处，
  L 事件稀疏）——完整 walk 序列需重采（去掉截断或提高采样）。
- **检查循环的读模式 = 4 位置循环**（非顺序流）——每个位置读
  ~1024 次（块结构）→ 读序列 = 块内重复 + 块间轮转。
- 下一增量：emu 重采（无截断全 L 事件）→ 完整 esi 序列 →
  .dat 映射对齐。

**续 21 补充 68（同日第五十五轮）——重采撞同一堆区写：锚点需换中段干净站点**：

- emu_bound 重采（截断已去）仍 fault-storm（6 事件/41 faults）：
  首指令写 0x4a660105（堆区缺失）——锚点 = t=200883 的
  eip=0x1065bb1 = **坏站点**（与补充 61 的 run-8 锚点同病）。
- 修正：锚点 = 链中段干净站点（如 eip=0x1066a38 xor al,dl 站点）。
- 工件：emu_bound.py（无截断版）。

**续 21 补充 69（同日第五十六轮）——完整 lodsb 轨迹到手：检查 walk = ~103KB 区域、7478 位置**：

- **emu_bound 重采成功**（锚 = run-18 t=203975 eip=0x1066a38，截断
  已去）：**345786 事件、lodsb L = 230232 个**！
- **esi 走过 0x11421ae..0x115b641 = ~103KB、7478 个不同位置**；
  delta 直方图：+1×132452、0×77796（重复读）、+2/+4×~19K、
  **跳跃 0xb9/-0x9f3×133（块间转移！）**、0xd7/0xd4×100。
- **byte overlap 218/256**（读值域 ≈ 全域）；读序列头不在 .dat
  （copy A ≠ .dat 直接映射 ✓ 再证）。
- **检查 = 对 ~103KB 区域的滚动处理**（非 480B）——"480 字节"
  框架正式作废；死亡 = 同 inter-pass API（0xffff9614）。
- 下一增量：103KB walk 的块结构分解（跳跃 = 块界）→ 块内
  处理语义 → 与 .dat 的真实映射。
- 工件：emu_bound.pkl（345786 事件全量）。

**续 21 补充 70（同日第五十七轮）——块结构完美周期化：检查 = 固定 ~10 块类型循环**：

- **以 esi 跳跃切分（|delta|>0x50）→ 686 块**，块大小直方图 =
  **恰好 10 种类型**：188×133、236×100、484×99、216×99、88×67、
  112×34、1330×34、470×34、436×34、336×33——**计数 = 补充 69 的
  跳跃计数逐位吻合**（0xb9×133 = 188 块×133！）。
- **检查 = 固定 ~10 块类型的循环哈希**：blk04-15 = [188, 216, 336,
  236, 484, 188, 216, 88, 436, 236, 484] 循环 + blk03 = 1330 大块。
  **确定性块序列 = 哈希轮结构**。
- **103KB 区域 = 686 块 = ~10 类型循环 × ~69 轮**——检查的宏观
  结构到手。
- 下一增量：每块类型的读模式（块内 esi 步进 + 字节）→ .dat 映射；
  块类型 = 哈希轮函数。
- 工件：块分解分析（本节内联）。

**续 21 补充 71（同日第五十八轮）——块类型完全确定：区域 = 静态固定数据，检查 = 多轮重读**：

- **每块类型的字节序列 100% 跨出现相同**：188 块 188/188、216 块
  216/216、236 块 236/236、484 块 484/484——**区域内容在检查期
  完全静态**！
- **块内 esi 步进 = 非均匀**（+1 为主、0 重复、+2/+4 跳跃 = 固定
  模式，同类型逐位同）——步进模式 = 块类型的指纹。
- **范式定案：检查 = 对 ~103KB 固定数据的 ~69 轮固定序列哈希**
  （区域静态、轮次固定、每轮 = 10 块类型循环）——输入 = 该固定
  区域（非 .dat 直接）；.dat → 103KB 区域的构建 = 变换（仍待定位）。
- 下一增量：103KB 区域内容 vs .dat 的关系（区域 = .dat 的扩展/
  派生？）→ .dat→区域构建。
- 工件：块类型分析（本节内联）。

**续 21 补充 72（同日第五十九轮）——范式大转折：emu 复现的检查哈希的是壳自身固定数据，非 .dat！**：

- **区域 vs .dat 对齐测试**：best alignment = **8/480**（≪随机期望
  408 = **反相关**）——103KB 区域**不是** .dat 的副本/派生（至少
  采样点处）；byte multiset = 480/480（值域覆盖 = 非判据）。
- **范式转折**：**emu 复现的检查 = 对壳自身 ~103KB 固定数据的
  69 轮哈希**（壳的自检/完整性校验！），**不是 .dat 校验**。
  .dat 校验 = 别处（ba 副本 = needle 定位的独立检查路径）。
- **重新对表**：补充 25-72 的 "check acc" = **壳自检哈希**；
  .dat 校验 = 另一条路径（ba 区 = 0xd50000/0xfe0000 = .dat 副本，
  其检查 = 待定位）。acc 门常数 0x88cb = 壳自检的预期值。
- **下一增量**：定位 .dat 副本（ba 区）的检查路径（对 ba 区的
  读写/比较 = POOLSNIFF 式差分）。
- 工件：区域 vs .dat 对齐测试（本节内联）。

**续 21 补充 73（同日第六十轮）——ba 区（.dat 副本）检查路径侦察计划**：

- **现状**：emu 复现的检查 = 壳自检（103KB 固定数据）；.dat 校验
  = 独立路径待定位。ba（0xd50000/0xfe0000）= .dat 副本（needle
  定位）。
- **已知线索**：① ba 区的 buf480 在全部 REGSNATCH 记录 = 空
  （got_b=0，RPM 在快照时刻失败 = 该区快照期不可读/已转移？）
  ——本身即线索；② 补充 11-14 的比较块链路（rolchk 代数）=
  许可比较 = 已复原的静态逻辑；③ helper API（ptr/416/hash/
  ptr2/magic）= 壳内部校验函数——416 = 0x1a0 ≈ 许可字段长度。
- **计划**：① POOLSNIFF 式差分监视 ba 区读写（时段 + 线程）；
  ② helper 调用点参数里的 ptr/ptr2 指向内容的转储；③ rolchk
  静态逻辑与 ba 区的对接。
- 本轮 = 计划记录；实施 = 下轮（预算）。

**续 21 补充 74（同日第六十一轮）——de-trigger 的代价与 ba 的替代来源**：

- run-18（de-triggered）= **无 ba**（needle 已删 = buf480 空）——
  ba 区监视需 ba 地址 = 缺。
- **ba 的替代来源**：post-check 的 ptr = 0x00fe025c（run-8
  t=221012）/ 0x00d50260 = **ptr 本身指向 ba 区**（0xfe0000/
  0xd50000 = needle 历史值 ✓）——ptr = 通用数据游标，post-check
  阶段游走 ba 区。
- **实施修正**：① ba = 从 post-check 记录的 ptr 高位提取（无需
  needle）；② 或 needle 恢复为异步（后台线程）。
- 下一增量：ba = ptr 提取 → POOLSNIFF 式差分（emu 钩或机器）。

**续 21 补充 75（同日第六十二轮）——ba 差分监视实施方案具体化**：

- **方案 A（机器侧）**：REGSNATCH 的 ptrwin = ptr 高位（0xfe0000/
  0xd50000）页——post-check 记录已捕获 ba 页内容（ptrwin = ba 的
  4KB 时间线 ✓ 已在手！）——ba 内容演变 = ptrwin 时间线分析
  （与 wide 同法）。
- **方案 B（emu 侧）**：emu 锚 = post-check 记录（ptr = ba 页）→
  emu 跑 post-check 链 + ba 区读写钩——但链 = 递归死（语义桩缺）。
- **首选 = 方案 A**（纯数据、无 emu）：run-8 的 post-check 记录
  ptrwin（ptr=0x00fe025c）= ba 页快照——ba 内容演变 = 已有数据
  的离线分析（无需新 run）！
- 下一增量：run-8 post-check ptrwin（ba 页）时间线分析 = .dat
  处理过程离线复原。

**续 21 补充 77（同日第六十三轮）——run19 era 偏移：ba 未在 ptr 中出现**：

- run19（t=152-366ms）：ptr 高位分布 = 0xe2xxxx×30（post-check 主区）、
  0x6bxxxx×5、0x10dxxxx×17 等——**ba（0xfe/0xd5）未出现**（era
  偏移：本 run 的 ptr 走了别的区）。
- **ba 差分待续**：多跑取 era 对齐（ba = post-check ptr 的 run）。
- 工件：run19 快照。

**续 21 补充 78（同日第六十四轮）——ba 差分继续：三跑无 ba-ptr + lowwin 基址错位发现**：

- runs 20/21（t=146/145 起）：**ba-ptr records = 0**（与 run19 同）——
  近三 run 的 ptr 均未指向 ba 区。
- **lowwin 基址错位发现**：lowwin = [0xFF0000,+64KB)（补充 41）——
  **ba = 0xfe0000/0xd50000 = 紧邻低地址、不在捕获窗内**！
  0xff0000 与 0xfe0000 = 相邻页——补充 41 的"0xff0017 fault"
  解读需复核（0xff0000 页 ≠ ba 页）。
- **下一增量**：① lowwin 基址改 = per-run 动态（ptr 高位）；
  ② 或 wide 扩展含 ba 页；③ 多跑继续对齐。

**续 21 补充 79（同日第六十五轮）——ptrwin 已是动态：无需 lowwin 改造，ba 缺席 = era 问题**：

- **ptrwin = ptr & ~0xFFF 页 = 本来就动态跟随**——ba = post-check
  ptr 时 ptrwin = ba 页 ✓（机器无需改）。lowwin 改造 = 多余。
- runs 19-21 的 ba 缺席 = **era 问题**（ptr 走了别的区）——多跑
  继续（每 run = 一次抽样，era = 随机 ±20ms，ba 出现概率 = 高）。
- 下一增量：批量跑（5-10 次）+ 自动筛 ba-ptr records → ba 页
  时间线 → .dat 处理离线复原。

**续 21 补充 80（同日第六十六轮）——重大突破：ba 区 = 解码后许可数据（序列号字符串现形！）**：

- **ba[0:32] = 7abc9f7afc97c661…= 检查期流头部逐字节同**（0xff0000
  内容的兄弟副本）——ba ≠ raw .dat（dat_same=0/32）= **ba =
  变换后的许可流**！
- **ba 区含可读序列号串**："00-0800-9D78-0696-567A-25F0"
  （run24 t=326014）= **解码后的许可数据现形**——.dat → 解码 →
  ba = 许可内容！
- **ptr = 消费游标走 ba 区**（offsets 0→644+）——许可校验 = 对 ba
  的逐游标处理。
- **范式定案（最终）**：.dat → 解码 → ba（许可流）→ 校验消费；
  0xff0000 = 同流的另一副本。重编码 oracle 输入侧 = .dat→ba 解码
  （= DECODEWATCH 六相的产物区！）。
- 下一增量：ba 流与 .dat 的解码对应（DECODEWATCH 六相对接）→
  校验消费语义 → 重编码 oracle。
- 工件：run22/24/25/26/27_bahits.pkl + ba 内容分析（本节内联）。
**续 21 补充 81（同日第六十七轮）——DW↔ba 对应建立：buf=ba 基址、两周期定案、六相解码不在其中**：

- **旧 2677 条读数作废**：那是对 CISC1test.v2decodewatch.bin 的错
  stride 解析（324B 假记录）。真实格式 = **1012 B/条**（t/ca/cb/dp/
  ba + snap480 + bank512）× **857 条**（签名扫描 ba=0xd50000 恒定、
  spacing 1012 全部命中、t 单调）。「buf vs 流 0/32」结论作废。
- **对应建立**：DW 的 buf_addr = **0xd50000 = ba 区基址本身**（跨
  run 同址）。cycle-2 写入门当实时与 bahits image **同 offset 逐字
  节全同**（rec#825→852 写 blkB [0x12c,0x160)，win@buf+0x128 →
  img+0x128 对齐命中 1→45 递增；run22/24/25/26/27 五 run image 逐
  字节相同 = 跨 run 确定性）。
- **两周期结构定案**：cycle-1（t≈177.8→193.3ms）= raw .dat 文件
  副本逐字节写（3 B/快照，dat_same 恒=nz，终态 480/480 与盘上
  CISC-1.dat 全同），持有 **31 ms 零变化**，t=224.9ms 擦除；
  **cycle-2（t=225.2ms 起）= ba 流构建**（先 blkB、后 blkA、流头
  7abc9f7a…）。**六相解码不在此缓冲**——持有期 dat_same 恒 480，
  补充 17-20 的六相（逐 dword 解密→enc1→enc2）= 另一缓冲的观测，
  待定位（needle 只认第一个 DAT_HEAD 命中）。
- **ba 区布局（5 run 恒定）**：+0x000 52B + +0x12c 52B 两块（与
  .dat 无常数/重复 XOR 关系、非 .dat 切片）；+0x258 48B = 检查期
  流头兄弟副本；run24 @0xfd1000+0xb00 = ASCII **"105A-0000-0000-
  0800-9D78-0696-567A-25F0"**（完整 serial，补充 80 只记了尾部）+
  0xFFFFFFFD 字段对；@0xfd0000 = "(CISC-1) Examples" / "LCF-AT" /
  "KuNeGHiM/[CCG]" 可读字符串页。
- **serial 数值字段在 raw .dat 零命中**（105A/0800/9D78/0696/567A/
  25F0 的 u16 LE/BE 与 0xFFFFFFFD 全无）——.dat→许可 = 真密码变换，
  无明文字段存储。
- **oracle 输入侧现状**：语义图补齐（.dat 副本→31ms 持有→擦除→
  ba 流构建；ba 区全布局；serial 页定位）；**变换输入输出对仍未到
  手**（解码工作区 ≠ 0xd50000）。下一增量：DECODEWATCH 盯**全部**
  DAT_HEAD 缓冲（不止第一个命中）/ 盯 0xfd1000 serial 页构建，抓
  .dat→serial 变换对；REGSNATCH ptr 游标对 ba 逐偏移 = 消费语义。
- 待查细节：rec#856 t=628139 超出 340ms 循环窗 = blobs 在 bail-watch
  期被继续 append 的证据（写入循环有两处）。
- 工件：OUT/ps1/dw81.py、dw81b.py、dw81c.py、dw81.pkl、dw81b.pkl、
  dw81_report.txt。
**续 21 补充 82（同日第六十八轮）——DW 多缓冲改造落地：两份 .dat 副本现形、serial 逐字节构建实况、解码 = API 级密码管线**：

- **仪器改造**（三步各带 cargo check+commit）：① chunked round-robin
  全址轮扫（8MB/poll，[0x10000,0x08000000)，DAT_HEAD 收集 cap 8，取代
  「first-hit 停」）+ b2 侧日志（每候选缓冲 488B/条逐 poll FNV 去重）+
  lw2 许可页窗；② lw2 改 buffer 相对 [ba-0x10000,ba+0x1000)（17 页分页
  读——固定 0xFD0000 窗在 0xc00000 run 落空：**zone 基址跟缓冲走**）；③
  lw2 在 t≥280ms 后每 poll（strings/serial 突发 [313,316]ms 在 1/16 节奏
  只剩 2 态）。
- **顺手修真产品缺陷**：裸相对文件名（`/unpack CISC-1.exe`）→
  `parent()=Some("")` → lpCurrentDirectory 空串 → CreateProcessW
  **0x8007007B**。修复 = `.filter(|s| !s.is_empty())` 后 unwrap_or(".")。
- **两份 .dat 副本**：ba（needle 命中，heap）与 **ba-0x10000**（低工
  作区）——[179,186]ms 平行写入，双双 480/480 = raw .dat。needle 只认
  第一个；lw2 窗捕到第二份。
- **ba 缓冲全生命周期（b2 逐 poll）**：raw 拷贝 [180.7,192.9]（480/480）
  → 27ms 持有零变化 → 擦除 [215.7,220.5]（delta=480，残留 nz=32）→
  zone 构建 [220.5,232.8]（dword 阶梯写入：blkB→blkA→流头 7abc9f7a）→
  滚动态（6755753f… = 补充 58「头滚动变」实况）→ 二次擦除 [292.3] +
  残留 **369f6409**（跨 run 复现、尾段 run 变：270a vs 240a）。
- **serial/许可字段逐字节构建实况**（lw2 每 poll）：[313.6,317.8]ms 在
  **ba-0xE500**（= run24 预测偏移精确吻合）11→16→24→29→48→56 字节阶
  梯 + strings 页（ba-0x10000）36B——**许可字段 = 检查期之后**（[310,
  316]）才物化 = 对话框/显示数据构建时段。串 = "105A-0000-0000-0800-
  9D78-0696-567A-25F0" + fdffffff 字段对 + 应用名/作者名 = 解码后许
  可字段。
- **[193]ms = SHA-1 密码结构**：s0 区现形 `sha1` 串 + ASN.1 DigestInfo
  （OID 1.3.14.3.2.26 = sha1、0414 OCTET STRING）+ 0x7717dba0 系指针
  （advapi32/crypto API 区）+ 瞬态代码块（mov/xor 链）。**解码 = API
  级密码管线（Crypt*/hash 家族）非内联算术**——这就是两份 .dat 副本
  都只见「cipher→擦除」无原地解密中间态的根因：明文经 API 进寄存器/
  别的 scratch。sha1(.dat)≠观测摘要（区域 = 覆写混合态，非纯 digest）。
- **oracle 输入侧现状**：许可字段输出侧全捕获（内容+时刻+偏移+写入
  阶梯）；输入 .dat 副本两处已知；变换 = API 级（SHA-1 参与验证）。
  下一增量：小窗（512B @ba-0x10000）[186,196] 每 poll 抓 API 解码中间
  态，或对 0x7717dba0 系调用点挂钩（CryptHashData/CryptDecrypt 参数
  转储 = 明文直读）。
- 工件：OUT/ps1/patch_dw82.py、dw82.py、OUT/ps1/DW82/*.v2decodewatch*
  （三跑：b2 54/46 条、lw2 1/12/27 条）；提交 b980aac/a6e4c76/后续。
**续 21 补充 83（同日第六十九轮）——双针 sweep + b3 逐 poll：明文不在任何可扫内存（三重否定），字段组装时刻/位置全捕获**：

- **仪器**：sweep 第二 needle = serial ASCII 前 16B（"105A-0000-0000-0"，
  跨 run 确定）→ 明文结构 hunt；b3 = 第二副本窗（ba-0x10000 512B）每
  poll；sweep 扩 MEM_IMAGE（83b）。
- **否定一（私有低内存）**：serial needle 两 run 零 <315ms 命中——明文
  结构从不驻留私有低内存。首命中 = [315-319] 组装瞬间（0xff0080=
  buffer+0x80 与 0xfd1b00/0xb71b00 显示区）。
- **否定二（第二副本就地解密）**：b3 每 poll 下 cipher→SHA1 结构 =
  **单 poll 转换（<30µs）**——[186,196] 无任何解密中间态；[195.8] 出现
  41B 新结构（ee89eb7a…）= hash 结果暂存态。
- **否定三（镜像）**：sweep 含 MEM_IMAGE 后仍零镜像命中——字段所在的
  镜像 VM 数据块**执行后即再加密**（瞬态可读窗，sweep 扫不到；与补充
  29-30 派发表同一机制）。
- **显示区 = per-run 堆、不跟 buffer**：ba 同为 0xfe0000 的两 run，显
  示区 = 0xfd1b00 vs 0xb71b00——固定偏移 lw2 对显示区失效（第二副本 +
  SHA1 段仍有效）。
- **failfreeze 段映射**（bail 383ms）："(CISC-1) Examples" 在 **IMAG
  RVA 0x218c3 / 0x18154c + CTXM 0x10228c3 + PRIV 0x115254c** 四处；
  **serial 不在 freeze 任何段**（其在 0xff0080/0xb71b00 = freeze 未覆
  盖的低内存页）。
- **组装时刻线**：[313.5-324.5]ms 三处并行（buffer+0x80 结构 336B 含
  serial@0x80 / strings 页 36B / 显示区 serial+fd 字段 68B）——字段从
  壳内部存储（寄存器/栈/瞬态 VM 块）直接拷出。
- **oracle 推论**：变换 = API 级计算（SHA-1 参与验证，补充 82），明文
  不落可扫内存。剩余捕获向量：① 栈观察器（[300,330] 每 poll 12KB
  STCK 区——字段组装必经栈拷贝）② CTXM 区（0x10228c3 bail 有字段）
  构建期监视 ③ 瞬态 VM 块 live 窗捕获（同派发表机制）。
- 工件：patch_dw83.py、DW82/ 四跑产物（b2 30 条、b3 8 条、lw2 27 条）；
  提交 b980aac 系 + 83/83b。
**续 21 补充 84（同日第七十轮）——许可 struct 全布局破译：.dat=[0,384)加密+[384,480)明文尾、固定 VA 0xff0000、已知明文 112B、四族密码机全排除**：

- **struct @0xff0000 = 固定 VA（跨 run 稳定）**：strings@0x41 +
  FF×8、serial@0x80 + 00 00 + fd dwords + f1b0a98318/8b96d3dd、二进制
  区 [0xBF,0x17D)（190B）、**dat[384:480] 原样 @0x17D**。字段格式 =
  值  + FF×8 填充（定长记录）。组装 = [312] 单次突发（strings 与
  serial 同时刻同页成形；本 run 0xff0041/0xff0080 双 needle 同时命中）。
- **.dat 格式定案**：[0,384) 加密字段 + [384,480) 明文尾（96B 逐字节
  原样携带进 struct）——解码 = 对前 384B 出字段，尺寸近 1:1（struct
  区 0x17D=381B）。384 = 0x180（helper 参数 416 = 384+32 的关联待查）。
- **已知明文 = 112B 连续段** [0x41,0xB1)（三字段+填充+serial+fd 全连
  续）——含 3 段 8×0xFF 连续填充（滚动状态演化金矿）。
- **密码机四族全排除**（112B 已知明文逐位验证）：①位置局部
  （xor/add/sub/rsub 常数、±i 变体）②滚动单字节状态（xor/add/sub ×
  常数步/plain 馈/cipher 馈）③**壳自家 lane 机族**（L∈{2,3,4,8} ×
  xor/add/sub × 每 lane 常数步——补充 25-40 家族）④sha1(.dat 各切
  片) ≠ 观测摘要。**密码 = 更深状态机（cb 32 位滚动值 = 头号嫌疑）
  或 API 链式哈希**。
- **下一增量（具体可执行）**：主日志 bank（ca/cb）在 [312,333] 组装
  期的记录 × lw2/b2 的 struct 写入步 → (ca 游标, cb 状态, 写入字节)
  三元组轨迹 → plain = f(dat[ca], cb) 状态机直接拟合；cb 在构建期
  [220,232] 已实测逐记录滚动（0x75bf6cad→0xee6711aa→…）。
- 过程缺陷：STR_NEEDLE 首次 15 字节（E0308）——16B 定长修正后重跑。
- 工件：patch_dw84.py、dw84.py（对齐）、dw84b.py（模型电池）、
  DW82/ 六跑产物；提交 84/84b 系。
**续 21 补充 85（同日第七十一轮）——解码时代定案 [189,203]ms：struct 页=ba+0x10000 一致、解码输出区 [0xC0,0x180) 页提交原子成形**：

- **布局定案**：struct 页 = **ba+0x10000 一致**（0xfe0000→0xff0000 ✓、
  0x34b0000→0x34c0000 ✓）；显示区 = 完全 per-run 堆（0xb60000=
  ba-0x80000 / 0x34a0000=ba-0x10000 / 0xba0000=ba-0x20000——无固定
  相对偏移）。b4 首版固定 0xFF0000 抓空（1 条空态）即修为 buffer 相对。
- **ca 游标时代**（主日志 46 条全时间线）：t=291.953 起 ca=0xff0000
  （=ba+0x10000）cb=小值（0x13/0x0）dp=0xe/0xa20——机器指针自
  [291.9] 就指向 struct 页，比 needle 命中早 21ms；[329-352] ca 在
  VMCTX（0x1021axx）与 struct 页之间跳变。
- **struct 页双结构共存**（b4 逐 poll 4 态）：[0x00,0xC0) = 检查期流
  （头滚动 7abc9f7a→6755753f→aab5bba7，delta 只在头部）；**[0xC0,
  0x180) = 解码输出二进制区（192B，固定不变跨 4 态）+ [0x180,0x1E0)
  = dat 尾 96B 原样**。页在 t=203.085 首次可读即完整（此前 RPM 失败
  = 未提交）——**解码输出 = 页提交瞬间原子成形**。
- **解码时代定案 = [189,203]ms**（.dat 拷贝完成 [189] → 解码+SHA1
  [189-196] → 输出页提交 [203]）。字段（strings/serial）= [323] 一次
  delta=151 原子覆写到字段位（格式化拷贝，非解码位置）。
- **原理性边界**：所有观测到的写入（擦除/构建/字段/页提交）在 30µs
  poll 节奏下均为**原子突发**——解码中间态在内存侧不可观测（与补充
  83 三重否定一致，本轮补上「为什么」：写=bulk copy，算=寄存器）。
- **下一增量**：①b5 = 每 poll bank (ca,cb,dp) 12B 轨迹（解码时代
  [196,203] ~230 样本，机器状态轨迹到手）②解码时代 op 带代码捕获
  （DISPATCH-SNATCH @ [196,203]，dp=0x112 系）——f 结构直读 =
  状态机拟合的前提。
- 工件：patch 85/85b、DW82/ 八跑产物（b4 4 态 = 页双结构共存证据）。
**续 21 补充 86（同日第七十二轮）——cb = VM 机代码指针实锤：解码时代轨迹 = 镜像 VM 块 → kernel32 → ntdll（API 链在飞）**：

- **仪器**：b5 = 每 poll 全量机器轨迹（t/ca/cb/dp + blkA@ca+dp +
  **blkB@cb 页** 1040B 无去重）。两修：E0425（t2 作用域）+ **移到门控
  后**（首版 83/27076 = DISPATCH-SNATCH 段 continue 吞 99% poll；
  86b 后解码时代 17 样本）。
- **cb = VM 机的代码指针（本轮核心发现）**：b5 blkB@cb 页捕到
  **执行中代码**——解码时代 [192.98] cb=0x75663690 = **kernel32**
  （RVA 0x23690）、[192.99] cb=0x771a4560 = **ntdll**（RVA 0x64560，
  页字节与 SysWOW64 磁盘 DLL 精确匹配定位）；[192.85-192.97] cb=
  **0x1132268（镜像 RVA 0x32268）稳定 120µs/8 样本** = VM 块内循环/
  等待。导出表映射 delta 大 = 内部函数（精确 API 待栈/返回地址）。
- **解码时代机器轨迹**（b5 全时间线）：[175.6-188.9] ca=.dat 缓冲游
  标（写相位 ✓ 与 dp 递减互证）→ [190.5] ca=0x1120fd9（镜像）→
  [192.85-192.99] ca=0、**cb 驱动**（0x1132268 停驻→kernel32→ntdll）
  → [217.1] cb=0x113d687。**[192.98-192.99] = API 调用链在飞**
  （文件读/Crypt 族——kernel32 页含 movzx word [esi] 串走读、ntdll
  页含 div [ecx+2C]/cmp ebx,0xFF = 句柄表/系统调用路径特征）。
- **采样率本质限制定案**：bank 页（VM 状态区）op 执行窗外 =
  NOACCESS——ok_c/ok_d 门控通过率 87/26451 = 0.33%；机器状态只在
  op 执行突发内可读（b2/b3/b4/lw2 同门控 = 全部侧日志同限制）。
- **下一增量**：①解码时代 op 块代码捕获——cb 停驻点 RVA 0x32268 的
  **代码块转储 + 折叠**（fold3 式）= f 结构直读路径；②API 精确识别
  （返回地址/栈参数转储——栈在 STCK 区可读）；③cb 页全页（4KB）扩
  捕（当前 512B 页首，cb 多在页中段 off=0x560 超窗）。
- 工件：patch 86/86b/86c、DW82/ 十跑产物（b5 1040B×87）。
**续 21 补充 87（同日第七十三轮）——解码时代 VM 块代码到手且可折叠：pop [edi+8]/xor 0x1c8174d0 状态窗写 + 块链 jmp 0x102888a**：

- **仪器**：b6 = cb 页 **4KB** 变更快照（t+cb+page 4104B，FNV 去重；
  修一处 E0425 t2 作用域）。27 态/跑——VM 全页代码到手（cb 多在页中
  段，512B 窗确实不够）。
- **rec#0（t=200.98，cb=0x110923a，页 RVA 0x1109000）= 真 VM 块**：
  capstone 反汇编形状完全可折叠——①esp 混淆惯用法（push
  edi/mov edi,esp/add 4/sub 4/xchg [esp]/pop esp ×2）②junk 折叠链
  （mov edi,0x236c0cd3/or/sub/shl 2/dec/sub/xor 0x42860171 =
  补充 34 家族）③**状态窗解密写：`pop dword ptr [edi+8]` +
  `xor dword ptr [edi+8], 0x1c8174d0`**（= 补充 39 的 pop [edx] 家
  族，带解密常数）④**块链尾 `jmp 0x102888a`**（VMCTX 区延续）。
- **rec#1（t=201.18，cb=0x1124e3c）= 数据页**：壳内嵌消息串
  （"Latest Instance"、"% 0x%X


" 等）——cb 在短 jmp 边界，
  块体在 0x1124f2d。非代码页。
- **f 结构直读路径确认**：解码时代机器 = 与检查时代同一家族的
  VM 块链（junk 折叠 + 状态窗写 + jmp 链）——fold3 式展开可读。
  块链目标 0x102888a（RVA 0x2888a）本 run 未被捕（27 态覆盖有限）
  ——多跑累积页集或 emu 带已捕页映射 = 补完手段。
- **下一增量**：①块链折叠器（jmp 链跨页跟踪 + junk 常数折叠 → 净
  语义序列）②b6 多跑累积（链页集）③0x1c8174d0 解密常数族普查
  （状态窗写常数 = 每块一个，全收集 = 写语义表）。
- 工件：patch 87/87b、DW82/ 十二跑产物（b6 4104B×27）。
**续 21 补充 88（同日第七十四轮）——块链折叠器建成：解码机 = 短块 + 中央派发器 0x102888a 形状定案**：

- **fold 器**（dw88.py）：b6 页集逐态反汇编 + junk 折叠（常数寄存器
  链 mov/or/sub/shl/dec/xor 求值）+ esp 惯用法剔除 + 语义提取
  （POPW/XORW/MOVW/PUSHI/PUSHR/链尾 JMP）+ 链跟踪（jmp 目标 ↔ 下一
  态 cb）。
- **解码机形状定案**：短块结构——push 常数（0x7f94/0x554/
  0x1236a0bc）/寄存器 + **状态窗写 [X+8]**（POPW [edi+8] +
  XORW 0x1c8174d0；MOVW [ebx+8]）+ **jmp 0x102888a = 中央派发器**。
  全部 4 个链尾都指向 0x102888a（RVA 0x2888a）——0x102888a 从不被
  b6 捕获 = cb 采样从不停在派发器上（执行 <1µs ≪ 30µs poll）。
- **状态窗写语义表开端**：[edi+8] ^ 0x1c8174d0（decode era）、
  [ebx+8] ← ebp（push 0x744 后 POPR ebx——同块 t=306/343 两次出现 =
  周期性块）。
- **0x1021a2b（VMCTX 页）= 混合页**（反汇编含 ASCII 数据 imul
  0x6e656369 = "ncie"）——VMCTX 页 = 代码+数据混排，反汇编需按
  cb 精确定位。
- **下一增量**：①派发器捕获——已知目标 0x102888a，块态捕获时顺手
  RPM 该页（一次即可）→ 派发器反汇编 = 取块机制（参数=下一块 ID？）
  ②多跑累积 0x1c8174d0 族（每块解密常数不同 → 写语义表）③fold 器
  补全（dec/inc RAW 残余 = esp 惯用法变体识别）。
- 工件：dw88.py（fold 器）、DW82/ b6/b5 产物。
**续 21 补充 89（同日第七十五轮）——战役最大结构突破：VM 核心完整可读——派发器 = 自定位→168 表重键→自旋锁→lodsb/xor bl 字节机主循环，f 机全貌现形**：

- **派发器页捕获**（b6 顺手 RPM 0x1028000，55 态/跑；hub 跨 run 稳定
  确认两次）。hub 态非零且逐态变化 = 派发器页逐块再解密活体。
- **派发器全反汇编（0x102888a，capstone）**：
  `pushal/pushfd/cld; call $+5; pop edi; sub edi,0x1226887e;
  mov eax,edi; add edi,0x1226858a` → **edi = 0x102859e = 双基座第二
  基座（补充 40 的 image+0x2859e！）= 状态窗基址**；
  `cmp eax,[edi+2C]`（自检）≠ → `mov [edi+2C],eax` +
  **`mov ecx,0xa8; add [edi+ecx*4+0x48],eax; dec; jne` = 168 项派发
  表 [edi+0x48..] 一次性重键（0xa8 = 168 = 补充 25 的 168 handler！）**；
  `mov esi,[esp+24]; ebx=esi; esi+=eax`（参数+自定位）；
  **`lock cmpxchg [edi+30],ecx; jne` = 自旋锁**；
  **`lodsb al,[esi]; xor al,bl; sub esp,2` = 字节机主循环**（= 补充
  42 检查时代 lodsb/xor 同族！）→ `mov [esp],bx; jmp 0x102ff28` =
  handler 派发。
- **handler 链全 readable（同页直读）**：`mov bh,0x79` 链、
  esi fixup 链、**bl = ~bl**（ah/dh 舞 + not al，junk 夹层）、
  **三 XOR 交叉混合**（xor [esp],bl / xor bl,[esp] / xor [esp],bl =
  补充 34-35 的交叉混合真身！）、**edx += 折叠常数**（esi =
  0x27b74ed2-1+0xd848b133 折叠、ebp±0x42d44395 相消）——补充 33-35
  家族全部在同一页家族（0x1028000-0x103C000）。
- **f 机全貌**：.dat 解码 = 与检查同族的字节机（168 handler 表 +
  lodsb/xor bl + 状态窗 [edi+8]），**程序 = 可折叠的明文代码**——
  f 直读 = fold 链（jmp 跟踪 + junk 常数折叠）即可，无需再猜。
- **仪器**：b7 = VM 核心区 [0x1028000,0x103C000) 80KB 变更快照
  （60 态/跑 = 4.9MB）——链折叠全材料落盘。
- **下一增量（f 直读收口）**：①fold 链走通：从 lodsb 点起跟踪
  jmp 链（0x102ff28→…→回环），junk 折叠 → 语义序列 = f 程序；
  ②跨 b7 态拼接（handler 页逐块解密，60 态并集 = 全链）；③f 验证：
  用已知明文 112B 回放 f 程序 → 全吻合 = f 破译 → .dat 重编码
  oracle 输入侧闭环。
- 工件：patch 89/89b、b6 95 态（含 55 hub 态）、b7 60 态 4.9MB。
**续 21 补充 90（同日第七十六轮）——f 链行走器建成：handler 链形 = ah 变异 + 旗标分支树；链出界定案与 b7 扩区**：

- **链行走器**（dw90.py）：b7 60 态页活性图（20 页全有活态）+ 从
  0x102ff28 起 jmp 跟踪 + junk 常数链折叠 + 语义提取。
- **链形定案**：0x102ff28 起 16 op 线性迹 = **ah 变异 handler 序列**
  （mov ah,0xc3 / add 0xce / xor 0x6f / add 0xfc / inc ×2 / xor
  0x27）+ **旗标分支（jge/jp/jg/jl）**——链 = 旗标驱动的树非线性链
  （ah 算术的结果决定走向 = 数据相关分支，与检查时代「第一 jcc 恒
  taken」同族但此处真分支）。
- **链出界**：迹尾 0x103d3c9 > 原 b7 区上界 0x103C000 → b7 扩到
  **[0x1028000,0x103E000)**（90KB，62 态/跑 5.6MB）。
- **f 提取的正确工具 = emu 回放**（非线性折叠器）：b7 页按时代映射
  进 Unicorn、从派发器 lodsb 点起跑、喂 .dat 字节、记录语义输出——
  分支由数据自然决定，无需猜树。112B 已知明文回放验证 = 同一机器的
  自检。
- **下一增量**：①f-emu 回放机器（b7 页时代映射 + lodsb 点起步 +
  dat 流喂入 + bl/acc/输出轨迹）②f 程序 = 回放轨迹的净语义 ③112B
  回放吻合验证 → .dat 重编码 oracle 输入侧闭环。
- 工件：dw90.py、dw90.pkl、b7 62 态（5.6MB）。
**续 21 补充 91（同日第七十七轮）——f-emu 回放机活着：3M 指令零故障、流消费实况（cursor=ba+0x51）、状态窗全字段对上**：

- **回放机**（dw91.py）：b7 62 态并集（latest-wins 22/22 页）映射
  [0x1028000,0x103E000)；.dat 拷贝（b2 首满态，ba=0xc30000）入
  ba 页；栈 = 0xef000+12KB；**从派发器 0x102888a 起步（esi=流基址）**
  → 3M 指令上限内 **clean、零 fault、1M writes** = **机器在捕获区内
  完全自洽**（b7 材料足够，无需更多上下文）。
- **状态窗实况（emu 终态 [0x102859e..+0x40]）**：cursor
  [edi+0] = **0xc30051 = ba+0x51（流已消费 81 字节！）**、
  [edi+4] = **0xc7485f48 = bank cb 写相位恒值（字段对上！）**、
  [edi+8] = 0x5b5e2d9d（acc，32 位宽）、[edi+0x14] = **0xeedc0014 =
  VM magic（补充 45 常数！）**。
- **写轨迹**：1M writes 集中在 0xf1fd8-0xf1ff4（栈帧），含
  0x1028892（派发器自地址）反复压栈 = 逐字节引导帧循环；esi 终值 =
  0xeedc0014 = magic 位（跑入参数标记）。
- **语义解读**：机器 = 逐字节消费 .dat 流（cursor 前进），每字节 =
  引导帧 + handler 链 + acc 突变；1M writes/3M insns = 每字节
  ~100 写 = handler 链长（~30 块/字节，与 168 表规模吻合）。
- **下一增量（f 验证收口）**：①hook esi 读流页 = 每字节 (input,
  bl, acc) 三元组轨迹 ②stosb/写流页 = 输出字节捕获 ③输出 @struct
  [0x41,0xB1) vs 112B 已知明文逐位比对 = f 吻合判定 ④吻合 → f =
  acc 突变程序 → 重编码 = 逆程序 → oracle 输入侧闭环。
- 工件：dw91.py、dw91.pkl（faults/writes）。
**续 21 补充 92（同日第七十八轮）——f 回放被混合时代页卡住：三机制定案（继承态窗/单 lodsb/自旋锁死转），era 一致回放 = 收口前提**：

- **仪器**（dw92.py）：lodsb 点 code hook @0x102888d（(input,bl,acc)
  三元组）+ 流页写捕获 + 30M 指令上限。
- **三机制定案**：
  ① **入口继承 union 态窗**——acc=0x5b5e2d9d / cursor=0x51 = b7 并集
  页里的**继承值**非新鲜态（union = latest-wins 跨时代混合）；
  ② **仅 1 次 lodsb 命中**——0x102888d 一次后机器未再返回 = 字节循
  环不在该点闭合（cursor=0x51 = 继承 + 1 字节 = 补 1 非消费 81）；
  ③ **自旋锁死转**——`lock cmpxchg [edi+30],ecx; jne` 在消费 1 字节
  后死转（[edi+30] 停留 1 = 解锁代码在 handler 链尾，而链尾页 =
  混合时代 union 中缺席/错版）。
- **根因 = era 一致性**：机器活体 = 页随时间逐块解密（b7 62 态 =
  62 个瞬间各部分活）；静态 union = 时代错配 → 链不闭合。**正确回
  放 = 逐态续跑**：从某态的寄存器上下文起步（b5 bank 有 ca/cb/dp 但
  缺通用寄存器）→ 页集 = 该时刻活页 → 跑到页失效点 → 切下一态。
  寄存器快照缺口 = REGSNATCH 式通用寄存器捕获需并入 b7（下一仪器
  版本）。
- **f 吻合判定 = 未执行**（0/112 比对无意义——流未解码）。
- **下一增量**：①b7 机器升级：每态 +**Wow64 通用寄存器快照**
  （GetThreadContext，b5/b6/b7 同拍）→ 态 = 完整可续跑上下文
  ②f-emu 续跑器：态 N 的页+寄存器起步 → 跑到失效 → 态 N+1 续 →
  384 字节全流 ③流页写轨迹 = 解码输出 → 112B 比对 → f 判定。
- 工件：dw92.py、dw92.pkl。
**续 21 补充 93（同日第七十九轮）——era 一致续跑器建成：23 态全 ok（机器真跑），VM 输出通道 = 栈定案**：

- **仪器**：b8 = 主线程寄存器快照同拍（OpenThread+GetThreadContext
  0x10003，44B/拍，72 拍/跑），与 b7 60 态按 t 配对 60/60 ✓。
- **续跑器**（dw93.py）：ASM 时代 23 态（[300,345]ms）逐态：
  时代页映射 + 寄存器注入（eip 从快照 = 机器中途点）+ 结构页
  （ba+0x10000）写捕获 + 300K 步/态。
- **结果**：23/23 "ok"（跑满 300K 步无 fault——**机器在时代页+真寄
  存器下真跑**，从 0x10288d2/0x10288db（派发器！）等多个中途点），
  但 **struct 页写 = 0**（match=5/112 = 零页噪声）。
- **通道定案**：VM 机的输出 = **栈**（补充 91 的 1M writes 全在
  0xf1fd8-0xf1ff4 = 帧区）——字段页写 = 壳原生代码 [323] bulk copy
  非 VM；**解码字节 = VM 推栈**。emu 栈 = 零页（真栈未捕获）= VM 推
  栈可跑但语义上下文（帧参数）缺。
- **下一增量**：①b8 扩栈捕获（esp±8KB 同拍 RPM——真栈内容）②续跑
  器改捕栈写（解码字节序列 = VM 输出）→ 与已知明文对位 → f 判定
  ③f 程序 = (input, bl, acc, 栈写) 轨迹的净语义。
- 工件：patch 93、b7 60 态 + b8 72 拍、dw93.py、dw93.pkl。
**续 21 补充 94（同日第八十轮）——真栈续跑落地：38 态 15,060 字节栈写捕获，KP 未在栈写中现形（f 判定仍未中）**：

- **仪器**：b8 并入真栈捕获（esp-8KB 16KB 同拍 RPM），67 拍/跑；
  与 b7 46 态配对 46/46（本 run ba=0xdd0000）。
- **续跑器 v2**（dw94.py）：38 态 = 时代页 + 真寄存器 + **真栈**
  （b8 的 esp-8KB 16KB 内容写入 emu 栈区）+ 栈写捕获 →
  **15,060 字节推送序列**捕获。
- **f 判定 = NOT FOUND**：KP（112B 已知明文）的 16B 窗未出现在任何
  态的栈写序列中。三个待排除：①ASM 时代的态 = 机器非字段解码相
  位（字段写 = 壳原生 [323] bulk copy，与 VM 推栈不同拍）②推送值
  = 中间态非最终解码字节（变换程序 = 多级，最终写 = 原生段）③对
  位窗口/时代错位。
- **战役状态快照（本 session 收口）**：①管线：V3 x64 EXE/DLL/x86、
  V1 classic、UPX、VMProtect Packed 全闭环（v0.4.0 发布）②V2 线：
   机器全貌破译（派发器 0x102888a 全反汇编 = 自定位→168 表重键→
   自旋锁→lodsb/xor bl；handler 链明文可折叠）、f-emu 回放机活着
  （零 fault 全自洽）、era 一致续跑器（真页+真寄存器+真栈三全）、
  **卡点 = 解码字节的输出对位**（VM 推栈值 ≠ 已知明文直接形式）；
  f 破译 = 最后一公里。③待办：裸文件名 0x8007007B 修复未发布
  （v0.4.1 候选）；Themida 1.1.1 = 接受边界；许可「通过未演示」。
- **下一 session 起点**：①解码相位定位——在 VM 机器跑的字节窗口
  （cursor 前进段）捕栈写，非 ASM 时代；②f 程序 = (input,bl,acc,
  栈写) 轨迹净语义；③112B 对位 → 重编码逆程序 → oracle。
- 工件：patch 94、b7 46 态 + b8 67 拍（真栈 1.1MB）、dw94.py、
  dw94.pkl（15,060 字节推送序列全存）。
**续 21 补充 95（同日第八十一轮）——解码相位捕获未中：两态跑通但推送 = 指针非数据，字节循环相位仍缺拍**：

- **离线否定**：dw94 的 15,060 字节推送序列全变换否定（直接/XOR-1B
  ×256/反转/隔字节 — 全 NONE）——ASM 时代推送 = 非解码输出。
- **解码时代续跑**（dw95.py，[180,225]ms 态 + cursor 跟踪）：仅 2 态
  可跑（t=188037/211849，b7/b8 拍稀疏），后者 112 次栈写但
  **cursor 全 -1**（态窗 cursor 不在流页）+ 推送值 = **指针**
  （0x012185ae 系 = 帧链构建）非数据——两态均非字节消费相位。
- **根因确认**：解码机字节循环（cursor 前进）在 b7/b8 拍间隙（bank
  门控 0.33% + 拍距 30µs vs 字节循环 <1µs/字节）——**逐字节相位的
  活体采样 = 拍机制原理性够不着**；正确路径 = **纯 emu 全流回放**
  （dw91 已证机器自洽，卡点 = era 页集完整性——62 态并集缺链尾/
  解锁页）。
- **下一 session（唯一卡点收敛）**：①b7 区扩到链尾（0x103D3C9 已知
  出界点 + 解锁页定位）+ 提拍频（每 poll 无 dedup 全量 90KB×60拍→
  已是；需 bank 门控旁路 = 直接 RPM 区不看 bank）②union 补全后
  dw91 全流回放 → 流页写 = 解码输出 ③112B 对位 → f 判定 → oracle。
- 工件：dw95.py、dw95.pkl（526 对）。
**续 21 补充 96（同日第八十二轮）——坏手术入库事故与回滚：管道吞 check 退出码 = 新工程纪律**：

- **事故**：b7 循环顶搬移的 cut/paste 手术括号失衡（916 行闭包失
  配）——`cargo check 2>&1 | tail -1` **管道吞掉退出码** → && 链继续
  → **坏文件被 git add+commit 为 b60dcd7**。
- **回滚**：`git checkout d7ba1c8 -- helpers.rs` + commit f16125a，
  cargo check 1.10s clean ✓。
- **新纪律**：cargo check 后的链 = **绝不经管道**（`cargo check &&
  git add` 或 `cargo check; echo ${PIPESTATUS[0]}`）；坏文件入库后
  的排查 = `git status --short`（空 = 坏版本已入库）+ `git log` 对
  文件 commit。
- **b7 循环顶搬移未完成**（b9 独立块方案 = 正确做法，不动 b7）。
  96 的仪器改造顺延：①b9 = 循环顶区域捕获（bank 门控旁路）②union
  补全 → dw91 全流回放 → 112B 对位 → f 判定 → oracle。
- 工件：f16125a（回滚）。
**续 21 补充 97（同日第八十三轮）——b9 落地（每 poll 区域捕获 50 态），回放 clean 但流页写=0：解码输出不在流页就地**：

- **b9 落地**（CHECK_EXIT=0 显式验证、commit、build、run 全链干净）：
  循环顶区域捕获 22 RPM/poll → poll 速率降至 ~0.7ms/poll（499
  polls/跑），50 态/4.5MB。
- **全流回放**（dw96.py，b9 union 22/22 页 + 30M 指令）：**clean、
  零 fault、流页写 = 0**——cursor = ba+0x47（union 继承值）。
- **通道定案（修正）**：**解码输出不在流页就地写**——dw96 只 hook 了
  流页 = hook 错页；输出 = **栈**（补充 93 的 1M 帧写）或结构页
  （ba+0x10000）。下一 hook 集 = 流页 + 结构页 + 栈三处同捕。
- **下一 session（f 判定三 hook 版）**：①dw96 加结构页（ba+0x10000
  写捕获）与栈写捕获 ②跑 30M → 输出字节序列 ③对位 KP112（直接
  /XOR-1B）→ f 吻合判定 ④吻合 → 逆程序 → oracle 输入侧闭环。
- 工件：patch 97（commit）、b9 50 态、dw96.py、dw96.pkl。
**续 21 补充 98（同日第八十四轮）——自旋锁释放后链出捕获区：lodsb=1 → FETCH_UNMAPPED，缺页 = 下一 session 区界**：

- **三页同捕回放**（dw98.py，结构页+栈+流页三 hook）：锁释放前 =
  struct/栈写全 0（仅 bootstrap 帧 10 写）——**自旋锁 [edi+0x30]=1
  继承持锁态 = 死转实锤**。
- **锁释放后**（dw98b，[edi+30]=0 写入）：**lodsb=1（消费 1 字节）**
  → 41 faults → **FETCH_UNMAPPED**——handler 链第一字节后跳出捕获区
  [0x1028000,0x103E000)。struct 页写 = 0（f 判定未中）。
- **突破度**：机器字节循环 = 已进入（lodsb 触发 ✓），卡点收敛 =
  **链的下一页地址**（fault 页 = dw98b 未存 faults——下一 run 打印
  fault 页 = 区界）。
- **下一 session（两步收口）**：①dw98b 重跑打印 fault 页 → b9 区界
  扩到含链全页（上限 = 区域太大则只补 fault 页）②union 补全后回放
  → lodsb×384 全流 → 流页/结构页/栈三处输出 → 112B 对位 → f 判定
  → 逆程序 → **oracle 输入侧闭环**。
- 工件：dw98.py/dw98.pkl、dw98b.pkl（锁释放版）。
**续 21 补充 99（同日第八十五轮）——fault 迹 = 谜底：handler 链在瞬态 VM 块（0x240c8000 系），VM magic 地址 = 参数区实解引用**：

- **dw99 fault 迹**（锁释放回放，201 faults 全打印）：
  ①eip=0x10288d1（lodsb 后）读 **0xeedc0014 = VM magic 地址被实解引
  用**（= 机器参数区指针——补充 45/91 的 magic = 指针非常数！）；
  ②**eip = 0x240c8b66 = 机器跳进瞬态 VM 块**（0x240c8000 系高地址 =
  补充 17-20 解码 op 块家族！）；③后续 faults = 0x240c9000+
  顺序 +0x1000 = emu 映射零页线性执行（块内容缺失 = 零码行军）。
- **定案**：**handler 链 = 瞬态 VM 块（0x240c8000 系，活窗解密/
  用后重加密）非 0x1028 静态区**——0x1028 区 = 派发器 bootstrap +
  状态窗；真 handler = 块地址从 magic 参数区（0xeedc0014）读出。
- **下一 session（捕获目标修正，一步到位路径）**：①b9-style 区域捕
  获改目标 = **0x240c8000 系瞬态块区**（该地址 = per-run，从 magic
  区参数读出或 fault 定位；每 poll 直 RPM 不看 bank）②块活窗捕齐 →
  union → dw96 回放（区 + 块 + magic 参数页 0xeedc0000 一并映射）
  → lodsb×384 全流 → 三处输出对位 KP112 → f 判定 → 逆程序 →
  **oracle 输入侧闭环**。
- 工件：dw99.pkl（201 faults 全迹）。
**续 21 补充 100（同日第八十六轮）——b10 表条目块址正确（0x240c8000）但块内容全零：瞬态块活窗仍未捕到**：

- **b10 落地**：参数页 0xeedc0000（4KB）+ 块区 32KB，块址 = 派发表
  首条目 [edi+0x48]=0x10285E6 读出 = **0x240c8000 ✓（表条目 = 块指
  针实锤，补充 99 互证）**。1 态/跑（FNV 恒定）。
- **块内容 = 全零（335 poll 全程）**——瞬态块在所有 poll 时刻不可读：
  ①活窗 = 块自身执行 µs 窗（~30µs/块 vs poll 1.1ms）②或块页在非执
  行期为 NOACCESS/未提交（RPM 静默失败 = 零）。参数页 0xeedc0000 =
  也全零（committed-but-zero 或同因）。
- **f 判定仍未中**；emu 回放的块内容 = 零页 = 零码行军（补充 99）。
- **下一 session 候选路径**：①**EMU 内自举**：dw98b 回放至 fault 页
  （0x240c8000）时，从 **live 进程 RPM 抢捕**该页（回放与活体并跑 =
  时序对齐难）②**DRBP/GPU 方式**：调试器 hardware breakpoint @
  0x240c8b66 执行瞬间转储块（V2 post-attach 无调试端口 = 需
  DBG_PORT 路线或页守护）③**页守护 guard page**：VirtualProtectEx
  0x240c8000 页 = PAGE_GUARD → 块首次执行 = guard 异常 = 我们在
  异常里转储（post-attach 无调试循环 = 异常给谁？需 DBG 展开）。
- 工件：patch 100/100b（commit×2）、b10 1 态（块址正确、内容零）。
**续 21 补充 101（同日第八十七轮）——esi 重定向谜底：机器字节流 = magic 区（0xeedc0014），非 .dat 拷贝页**：

- **b10 扩 2MB 页级捕获落地**（168 handler = 独立块址）+ 表条目探测
  转 info 日志。**probe 结果 = tbl0@0x10285E6 = 0x0 且 magic_deref =
  0x0 全程**——live 表条目在该址为零（union 里的 0x240c8b66 条目来
  自别处 = 状态窗 edi 在执行期 ≠ 0x102859e）。
- **dw99 fault 迹重读 = 关键修正**：fault#1 = eip=0x10288d1（lodsb）
  读 **[esi=0xeedc0014]**——**机器的流指针 = magic 区**！链在
  bootstrap 后把 esi 重定向到 0xeedc0014 = VM 自有数据段 = **真字节
  流位置**（非 .dat 拷贝页 ba）——我的 emu 喂错流（esi=ba）。
- **因果链修正**：0x240c8b66 的跳 = 从 magic 区读出的块指针（链读
  magic → 参数 → 块）——全部机制 = magic 参数区驱动的两级跳转。
- **下一 session（捕获+回放双修正）**：①live 捕 0xeedc0000 页为何
  全零（RPM 失败？NOACCESS？页守护？）= 读通 magic 区 ②emu 修正：
  esi = magic 区流指针（从 union/b10 参数页取值）+ 映射 magic 页
  （内容 = live 捕获）③回放 → 输出 → 112B 对位 → f 判定 → oracle。
- 工件：patch 101（b10 2MB 页级 + probe）、b10 0 字节（页全零）。
**续 21 补充 102（同日第八十八轮）——magic 页根因探针设计（本轮未执行，下一 session 首动作）**：

- **b10 缺陷定位**：参数页读 = `let _ = RPM(...)` 无结果检查——全零
  = RPM 失败（未提交/NOACCESS）或真零，无法分辨。
- **下一 session 首动作（b10 补丁，~15 行）**：VirtualQueryEx
  (0xEEDC0000) → 记录 State/Protect/Type 进 b10 记录头 → 定根因：
  MEM_COMMIT+NOACCESS = 页守护路线（guard/调试器）；MEM_FREE/未提交
  = **0xeedc0014 = 非活体地址**（= emu 上下文值/常数产物，esi 重定向
  解读需再修正——真流 = 他处）。
- **随后分叉**：①根因 = 可读 → emu esi=magic 流+映射 → 全流回放 →
  112B 对位 → f 判定 → oracle；②根因 = 不可读 → 回 dw99 fault 迹
  重追（0x240c8b66 块的 live 窗 = guard 路线）。
- 工件：无新工件（设计入档）。
**续 21 补充 103（同日第八十九轮）——根因定案：0xeedc0000 = MEM_RESERVE 未提交，magic 区 = VM 按需 commit 区**：

- **探针结果**（VirtualQueryEx(0xEEDC0000)，全程稳定）：
  `q=28 state=0x2000(MEM_RESERVE) protect=0 mtype=0x20000(MEM_PRIVATE)`
  ——**magic 页 = 预留未提交**！b10 全零 = RPM 失败实锤（非真零）。
- **机制解读**：0xeedc0014 = VM 预留区地址——机器 esi 重定向 = 指向
  将按需 commit 的动态区（VM commit/用/释放 周期）。活窗 = commit
  瞬间。
- **捕获修正（下一 session 首动作，~10 行）**：b10 逐 poll 探
  VirtualQueryEx State；**State == MEM_COMMIT(0x1000) 瞬间 → 立即
  RPM 0xeedc0000 4KB 记录**（commit 窗捕获）→ union → emu esi=
  magic 流 + 映射（commit 态内容）→ 全流回放 → 三处输出 → 112B
  对位 → f 判定 → 逆程序 → **oracle 输入侧闭环**。
- 工件：probe 日志（state=0x2000 稳定）。
**续 21 补充 104（同日第九十轮）——commit 窗捕获落地但 magic 区全程未 commit：0xeedc0014 = emu 发散伪迹（补充 101 解读撤回）**：

- **b10 commit 窗捕获落地**（State==0x1000 即 RPM 4KB + FNV 去重；
  修一处 b10_last 作用域）。**50 探针全程 state=0x2000 = magic 区从
  未 commit**——b10 = 0 字节。
- **结论反转（诚实撤回）**：**0xeedc0014 ≠ 机器活体流**——活体机器
  从未 commit 该区 = 从未使用；esi=0xeedc0014 = **dw91/99 混合时代
  emu 的发散伪迹**（union 页 + 错误初始上下文 → 链跑偏 → esi=垃圾
  推导值）。补充 101 的「esi 重定向 = 真流」解读作废。
- **正路回归**：era 一致续跑器（补充 93-95 架构 = 页+寄存器+栈三全
  已落地）+ **解码时代加密采样**（b7/b8 门控 0.33% = 采样瓶颈——
  b9/b10 = 每 poll 但无寄存器；下一步 = b8 门控旁路化 = 寄存器快照
  每 poll 不看 bank（RPM 独立读 bank 失败即记零态））。
- **下一 session（单一焦点）**：①b8 旁路化（每 poll 独立 bank 读 +
  State 记录）→ 解码时代态密度 ↑②era 续跑器跑解码态全集 → 字节
  循环轨迹 ③流页/结构页/栈三处输出 → 112B 对位 → f 判定 → oracle。
- 工件：patch 104（commit）、b10 = 0 字节（负结果实锤）。
**续 21 补充 105（同日第九十一轮）——b8 门控旁路化落地但 OpenThread 每 poll = 新瓶颈（poll 26000→87）**：

- **b8 搬循环顶落地**（门控旁路，自带 t8，check CHECK_EXIT=0）。
- **性能实锤**：OpenThread+GetThreadContext+16KB 栈 RPM 每 poll =
  ~2-4ms → **polls 26000→87**，态密度 50 拍/400ms（0.125/ms）反低于
  门控版 72（0.18/ms）。
- **下一 session 首动作（一行级）**：**OpenThread 句柄 hoist 到循环
  外**（一次 Open，循环内仅 GetThreadContext+栈 RPM ≈ 100µs/poll →
  ~2000-4000 polls → 解码时代态密度 ↑ 30-60×）→ era 续跑器跑解码态
  全集字节轨迹 → 三处输出 → 112B 对位 → f 判定 → oracle。
- 工件：patch 105、b8 50 拍（821KB）、b9 21 态。
**续 21 补充 106（同日第九十二轮）——hoist 落地但真瓶颈 = GetThreadContext on running thread（~3ms/poll 内核线程同步）**：

- **OpenThread hoist 落地**（一次 Open、循环内仅 GetThreadContext+
  栈 RPM；check CHECK_EXIT=0；修两处锚点后干净入库）。
- **结果**：polls 仍 92（~4.3ms/poll）——**瓶颈 ≠ OpenThread = 
  GetThreadContext 对运行中线程**（内核强制同步 ~1-3ms）+ 16KB 栈
  RPM（~1ms）。
- **修正（下一 session，~5 行）**：b8 节流 = 每 8th poll 才
  GetThreadContext+栈 RPM（页密度由 b9 每 poll 保持；寄存器 = 仅续
  跑点需要）→ poll 回 ~100µs → 密度恢复 → 解码态全集 → 字节轨迹 →
  112B 对位 → f 判定 → oracle。
- 工件：patch 106、b8 52 拍、b9。
**续 21 补充 107（同日第九十三轮）——b8 节流落地但 poll 仍 93：真凶 = b10 512 页 2MB 扫描**：

- **b8 节流落地**（每 8th poll GetThreadContext + 栈 4KB；b8 = 6 拍
  24KB ✓）。
- **polls 仍 93**——真凶 = **b10 的 2MB 512 页扫描**（补充 101 的
  每 poll 512 RPM = ~4ms）。
- **下一 session（一行级）**：b10 同款节流（每 8th poll 扫 2MB）→
  poll 回 ~100µs（b9 22 页 + b8 1/8 + b10 1/8 = ~40µs 基载）→ 态
  密度恢复 → era 续跑器解码态全集 → 112B 对位 → f 判定 → oracle。
- 工件：patch 107、b8 6 拍、b9 20 态。
**续 21 补充 108（同日第九十四轮）——b10 节流落地：polls 93→227（2.4× 恢复），性能链修完**：

- **b10 节流落地**（每 8th poll 扫 2MB，一行级 wrap；CHECK_EXIT=0）。
- **结果**：polls 93→**227**（1.7ms/poll）——剩余成本 = b9 22 RPM +
  b2 六缓冲 + 其他块（进一步节流 = 可选非必须）。
- **b10 = 0 字节**（magic 区仍全程未 commit ✓ 与补 104 一致）。
- **下一 session（材料已齐）**：era 续跑器（dw93 架构）跑本 run
  解码态全集（b7/b8/b9 = 全节流版新鲜产物，ba=0xfe0000）→ 字节轨迹
  → 三处输出 → 112B 对位 → f 判定 → 逆程序 → oracle。
- 工件：patch 108、b8 103KB/b9 49 态/b10 0（负结果一致）。
**续 21 补充 109（同日第九十五轮）——era 续跑器解码态全集跑通：三处输出仍未对位（struct/流=0、栈=帧推送），f 判定未中**：

- **修复两处**：①dat_copy = 盘上 .dat（本 run b2 无满态）②配对 =
  最近邻 t（±3ms 门）——22 解码时代态全跑（[175,371]ms）。
- **结果**：struct 写 = 0、流写 = 0、**栈写 = 120-282（帧推送）**、
  match = 5/112（零页噪声）——**解码输出仍未对位**。
- **解读**：机器在时代页+寄存器+栈下跑 200K 步 = 帧构建相位（栈写 =
  指针/帧值），字节消费相位的输出 = 仍未捕获——栈写**值**（非计数）
  的逐字节解码对位 = 下一层（dw94.pkl 的 15,060 字节同理未对位）。
- **下一 session（对位层）**：①栈写值的语义分层（指针 vs 字节：值
  高位 = 0x01xxxx/0x02xxxx = 指针过滤）②字节级推送（size=1 的写）
  序列 vs KP 直接/XOR 对位 ③若仍无 = VM 输出通道假设重审（lodsb
  后的变换结果 = acc 突变非内存写——f = acc 程序，输出 = acc 快照
  时序对位）。
- 工件：dw109c.py 逻辑（内联）、dw109c.pkl、dw109c_out.txt。
**续 21 补充 110（同日第九十六轮）——栈写语义分层定案：1120/1280 = 指针 dword、零字节写——f = acc 突变程序 = 唯一存留假设**：

- **离线分层**（dw109c.pkl，1280 栈写）：**ptr-like（高位
  0x00/01/02）= 1120、size=1 字节写 = 0**——机器栈写 = 全 dword
  帧/指针，无内存字节输出 = **f 非内存写程序**。
- **f = acc 突变程序 = 唯一存留**（分支②触发）：变换结果 = acc
  （[edi+8]，32 位）逐字节演化；许可字段 = 从 acc 终态/时序派生
  （原生 [323] bulk copy 读 acc/派生结构写字段）。与检查时代同构
  （补 40：acc_new = acc_old ^ K[lane][byte] 纯 XOR S 盒）。
- **下一 session（f 判定最后一步）**：①emu 回放 + **lodsb 点 acc
  快照 hook**（(input_byte, acc_before, acc_after) 三元组 ×384）②
  112B 对位：acc 突变轨迹 vs 已知明文（直接/XOR/移位组合）③吻合 →
  f = acc 程序 → 逆程序 → **oracle 输入侧闭环**。
- 工件：dw110 分析（内联）、dw109c.pkl 复用。
**续 21 补充 111（同日第九十七轮）——流位置破案：机器字节流 = 镜像数据区 0x1139275（补充 4 平反！），acc 演化实况到手**：

- **acc 快照 hook 触发**（8 态 × 2 snaps = 16 三元组）：lodsb 在解码
  时代执行 ✓；**esi = 0x1139275/76 = 镜像数据区（RVA 0x39275）**——
  机器字节流 = **镜像内 .dat 副本**（补充 4「.dat 工作副本在镜像数
  据区」平反！emu 一直喂错流 = ba 堆副本）。
- **acc 演化实况**：0xefcfc → 0x6d7e768a（跨态突变 ✓ = acc 突变程
  序假设强化）。input = None（esi 不在 ba 页 = 喂错流的直接证据）。
- **下一 session（最后一步完整化）**：①live 捕镜像流页 0x1139000
  （b9 区外 = MEM_IMAGE，加专区捕获）②emu esi = 0x1139275（从态
  窗/寄存器快照读真流指针）+ 映射流页（live 内容）→ (input, acc)
  三元组 ×384 ③112B 对位（acc 轨迹直接/XOR/移位）④吻合 → f = acc
  程序 → 逆程序 → **oracle 输入侧闭环**。
- 工件：dw111.py 逻辑、dw111.pkl（16 三元组）。
**续 21 补充 112（同日第九十八轮）——字节循环全速跑通：642 lodsb 三元组/态（输入 = 镜像流真实字节），f 破译输入侧齐备**：

- **b11 落地**（镜像流页 0x1139000 每 poll 4KB）：1 态（页静态、
  nz=4013 全 populated）——流页内容一次捕获即足（全程稳定）。
- **终局回放**（dw112，esi = 快照真值 0x1139275 + 流页映射）：
  **t=200342 单态 642 lodsb snaps**——字节循环全速执行 ✓；输入 =
  镜像流真实字节（18 fa 61 49 c2 c8 26 71 …≠ raw .dat = 镜像副本 =
  变换/移位形态）；acc = 0x6d7e768a 窗内恒定（突变在块尾 = 检查时
  代同构）。
- **f 破译材料齐备**：(input, esi, acc_before, acc_after) ×642 +
  流页全内容（b11）+ 多态窗口可续。
- **下一 session（f 破译）**：①acc 突变定位： lodsb×642 中 acc 写
  时刻（块尾）→ (input, Δacc) 对 ②Δacc vs 已知明文对位（直接/XOR/
  移位）③吻合 → f = Δacc 程序 → 逆程序 → **oracle 输入侧闭环**。
- 工件：patch 112（b11）、dw112.py、dw112.pkl（642 三元组）、
  dw112_out.txt。
**续 21 补充 113（同日第九十九轮）——acc 槽 642 lodsb 零写：机器状态 = 寄存器（bl/ah 链），f = 寄存器链程序定案**：

- **acc 写 hook 结果**（解码时代态重放，642 lodsb）：**[edi+8] 槽
  写 = 0**——acc = 恒定，字节循环的状态 = **寄存器（bl/ah）**（与
  dw90 walk 的 ah 变异 handler 序列互证：mov ah,0xc3/add/xor/inc
  链 = bl/ah 演化）。
- **f = 寄存器链程序定案**：每字节 = lodsb → xor al,bl → handler
  链（bl/ah 变异 + 旗标分支）→ bl 演化 = 变换状态；输出 = …… 待
  定位（bl 演化 → 块尾 acc/字段派生）。
- **下一 session（f 提取）**：①lodsb 点 hook 扩记录
  (input, bl_before, bl_after, ah) → 642 全轨迹 ②bl 轨迹 vs KP112
  对位（直接/XOR）③吻合 → f = bl 链程序 → 逆程序 → **oracle 输入
  侧闭环**。
- 工件：dw113.py、dw113.pkl（0 对 = 负结果实锤）。
**续 21 补充 114（同日第一百轮）——bl 轨迹 642 条到手（平台化演化），对位需流↔输出映射**：

- **lodsb hook 扩记录落地**：(input, bl, bh, al, ah) ×642（单态
  t=200342 全轨迹）。**bl 演化 = 平台化**：0x1e → 0xa5(×7) → 0x44
  → 0x38(×4) → 0x00(×10) → 0xbc(×3) → 0x98…——bl 非逐字节滚动 =
  该窗 = 消费相位的非变异段（或 handler 链同值循环）。
- **对位前提缺口**：流（镜像副本 18 fa 61 49…）↔ 输出（KP112）的
  位置映射未知（流 ≠ raw .dat = 变换形态）——对位 = 需先定
  流[i] ↔ struct[j] 映射或从 acc/字段派生关系反推。
- **下一 session**：①流内容全读（b11 页 4KB 全 dump vs raw .dat 关
  系：直接/移位/XOR）→ 定流↔dat 映射 ②映射定后 bl 轨迹 × 映射 =
  f 对位 ③吻合 → 逆程序 → oracle。
- 工件：dw114.py、dw114.pkl（642 全轨迹）。
**续 21 补充 115（同日第一百零一轮）——范式再转折：0x1139275 机器 = VM 自有数据消费（自检家族），.dat 解码机仍未定位**：

- **流页 vs raw .dat 全变换否定**（直接/XOR-1B/任意 16B 窗/异或差
  分——全 NONE）：0x1139275 流 = **VM 自有数据**（~103KB 自检区域
  家族）非 .dat 副本/派生——**0x1139275 机器 = 自检相位非 .dat 解
  码**（补充 4 平反再平反：镜像数据区 = 壳自检数据非 .dat）。
- **.dat 解码机现状（35 轮战役诚实边界）**：字节机 = 未定位；解码
  = API 级（[193] SHA-1 结构 + Crypt* 指针，补充 82）；明文 = 三重
  否定不落可扫内存（补充 83）；瞬态块 = 活窗 µs 级（补充 100）。
- **剩余路径（唯一）**：瞬态块活窗捕获 = guard 页/调试器断点/并跑
  抢捕（补充 100 三候选）——需 DBG_PORT 或异常投递通道（V2
  post-attach 无调试端口 = 反调试前置战）。
- **oracle 现状**：输入侧 = 语义图全齐（.dat 格式/许可字段/struct
  布局/已知明文 112B）；变换 = API 级未提取。**管线全景**：6 条闭
  环 + V2 = 研究线（诚实边界）。
- 工件：dw115 分析（内联）。
**续 21 补充 117（同日第一百零二轮）——瞬态 handler 块首次捕获成功：0x27ce000/0x27cf000 两页 × 8 态（解码时代）**：

- **b10 扩区落地**（8MB [0x2000000,0x2800000) 2048 页，每 16th
  poll，~250µs/poll 均摊；64 页写/175 polls）。
- **捕获战果**：**0x27ce000 + 0x27cf000 两页 × 8 态**（t=[200.9,
  343.3]ms = 解码时代+后段）——**瞬态 handler 块活窗内容首次到手**
  ✓（per-run 块址漂移实锤：本 run = 0x27ce/0x27cf 系 ≠ dw99 时代
  0x240c8 系）；页头 48B = 零、内容在页中段（nz>64）。
- **下一 session（f 破译直路）**：①块内容 capstone 反汇编（8 态演
  化 = 块逐字节解密活体）②块地址 = 派发表条目读出（每态表 + 块配
  对）→ dw96 回放（区+块+流页三映射）→ lodsb×384 全流 → 三处输出
  → 112B 对位 → f 判定 → 逆程序 → **oracle 输入侧闭环**。
- 工件：patch 117、b10 64 页写（2 活页 16 态）。

**续 22 补充 118（2026-11-18，同日第一百零三轮）——协议/家族/V 空间三重突破 + 两处撤回：emu 内首次完整 VM op 执行**：

- **撤回一（补充 117 的块解读）**：0x27ce000/0x27cf000 两页 = **堆页（segment heap 元数据）**
  （8 字节槽 64 位值、`feffffffffffffff` = -2 编码头、0x280fd24 堆指针）——非 handler 块。
- **撤回二（补充 99/101 的 fault 解读）**：dw99 时代 eip=0x240c8b66 与"流指针 = magic 区"=
  **同一 emu 入栈伪迹**（esi = [esp+0x24]+CHECK，emu 栈零 → esi = 0xEEDC0014 = CHECK 本尊；
  0x240c8b66 = 零流 opcode-0 派发链的确定性落点）。
- **数字位错定案**：0x240c8b66 = 604 MB（8 位）非 37 MB——补充 100-117 历代 b10 扫区
  [0x2000000,0x2800000) 全部扫错区；块页 poll 时刻不可读（b10 窄区 [0x2408000,0x2410000) 每
  poll = 0 字节实锤，未提交页 RPM 静默失败）。捕获通道 = 停机窗（SuspendThread/调试事件）。
- **CHECK 修正**：0x1028892 − 0x1226887E = **0xEEDC0014 = VM magic 本尊**（此前口算
  0xFEDC0014 错）；edi 第一基座 = 0xEEDC0014（VM 对象指针 = magic = [edi+0x14] 存的值）。
- **入口协议实锤**（dw118 全反汇编 + dw119 fault + dw127 尾迹）：bootstrap = pushal/pushfd/cld/
  call $+5/pop edi/sub 0x1226887E/mov eax,edi/add 0x1226858A（edi = 0x102859E 窗口）→
  cmp eax,[edi+2C] 自检 → 重键 add [edi+ecx*4+0x48],eax ×168（**派发索引 [19,186]**）→
  lock cmpxchg [edi+30] → **esi = [esp+0x24]（= [E-12]）+ eax；ebx = esi（bl = 初始密钥）**
  → lodsb/xor al,bl/sub esp,2/mov [esp],bx/jmp 0x102ff28 → 链尾 **jmp [edi+eax*4]**
  （0x102f9b4，256 项表 @edi）。emu 入栈 = esp0 = V_addr+12（[E-12] = V = 流基址 − CHECK）。
- **四副本**（failfreeze 签名 60 9C FC E8 扫出，全解密）：入口 0x102888A / 0x103E1E2 /
  0x10534AB / 0x106029A；窗口 = 0x102859E / 0x103DEF6 / 0x10531BF / 0x105FFAE；
  sub-add delta 全 = 0x2F4；CHECK 全 = 0xEEDC0014。家族 4（op 带）= 缓冲变换 era
  [200424,214671] 的机器（b8：eip 0x106xxxx、edi = 0x105FFAE、esi = 0x1142-0x1147xxx）。
- **V 空间**：[0x12200000,0x12480000) = **外层机器代码/数据区**——V = 伪返回地址 = 外层
  call 位址（ret 回 V 空间继续）；全程静态（b14 一次快照零变化）。
- **赢家回放（emu 内首次完整 VM op）**：family-1、V = 0x12379679、流 = 0x113968d、esp0 =
  0xefee0（+真栈 b8@202344 + b14 V 空间 + failfreeze 镜像 + ba 页）→ **457 lodsb 后正常
  终结**：解锁（mov [edx+0x30],eax=0）→ popal → popfd → ret（补 retaddr 槽后 eip =
  0xDEAD0000 干净停机）。f 链实测：xor al,bh 变换（0x0e→0x6d→…）、bl/ah/cl 全链变异、
  [esp] 槽存 bx（当前密钥）。~6500 insn/字节；每轮 lodsb 间 = 60-90 指令混淆链。
- **残留缺口**：emu 数据态陈旧（failfreeze 镜像数据 ≠ 活体 era）→ 分支分歧风险；b8 栈窗
  4KB 太窄（V 常在 esp+0x800 外）；解码机器（家族 4）V 未到手。**下一轮**：①b8 栈窗
  上扩 [esp,esp+0x3800)；②b15 活体数据池 [0x1080000,0x1148000) 逐 poll；③家族 4 回放
  → KP112 → f 判定 → 逆程序 → oracle 闭环。
- 仪器：b10 窄区 8 页每 poll（替换 8MB/16）、b12 扩 11 页（+0x1142000-0x1148000）、
  **b14 = V 空间 640 页每 poll 逐页去重**（首捕 = pre-era 态）、b8 /2。
- 工件：dw118/118b/119/120/121/122/124/125/126/127/128/129.py、dw121_blk.pkl、
  dw122_blkblob_0.bin、DW82a/b/c 三代 bin 存档。

**续 22 补充 119（同日第一百零四轮）——续跑器突破：回放保真性实证，emu = oracle 本尊**：

- **仪器**：b8 栈窗上扩 [esp-0x800, esp+0x3800)（20KB）；**b15 = 活体数据池
  [0x1080000,0x1148000) + 结构页 0x1022000，201 页逐 poll 去重**（首捕 = pre-era 态，
  92 次活体变化 = 数据通道输出时间线）；b14 降频 /4（首捕后）。
- **时代地图（b15 时间线）**：流页群 0x1131000-0x1147000 于 [184330, 199270] 解密就绪；
  **0x113f000 = 变换 era 热数据页**（201670/204274/206463/213725/215977 五次活跃）；
  **结构页 = 全 run 渐进构建**（23 版，nz 732→1068，199270 处 108B 大写 = 字段解码 op）；
  **KP112 不在任何 b15 版本** = 写在 [374696, fail] 终局裁决 era（结构 = 先建字段、
  末尾写裁决明文）；0x10ce000（第三副本代码页）于 323322/352077 再激活。
- **V 空间定案**：b14 = 640 页全零——**[0x12200000,0x12480000) = 未提交保留区**
  （V = 伪返回地址 = 纯算术值 stream−CHECK，读 = 零）；emu 零映射 = 忠实。
  pushal 自指针（[E-20]=E）扫描 = 全巧合帧——**V 在 snap 时已被机器自己的栈写覆写，
  栈内不可恢复**（入口协议 [E] = V 的槽位 = 机器早期即覆写）。
- **续跑器突破（dw132/133）**：b8 snap = 完整机器态（10 regs + 20KB 真栈 + era 内存 =
  failfreeze 代码 + b15 era 叠加 + b14 零 V 空间 + ba 页）——**从 eip 直接续跑至终结，
  无需 V/E**。20 条全试：t=232461 与 t=241958 = **599049 lodsb（60 万字节程序）、
  46.79M 写、干净终结**（家族 4 op 带机器 = 主解码 op）；**emu 结构页终态 vs 真机
  b15 下一版 = 4071/4096 + 4089/4096 字节相等（99.3%/99.8%）= 回放保真性实证 ✓**。
  其余 snap 多 derail（缺更深状态/已过 era）；unicorn hook 装卸会原生崩溃 →
  **每记录全新 Uc 实例** + 空页写 >5000 脱轨护栏。
- **主解码 op 写字段值表**（emu 实测）：[0x10222dd]=0x540d9dfa、[0x10223b5]=0x09877011、
  [0x1022755]=0x19b120d9、[0x1022859]=0x2ccbc9bc、[0x1022e09]=0x367e172f……
- **oracle = emu 本尊**：改 .dat → 时代链逐 op 续跑（①拷贝→②变换→③字段→④裁决）
  → 预测 verdict。已验证 = 第③段（字段段）保真。**下一轮**：①捕获 era①② 的 snap
  （b8 节奏加密 /1）→ 全链续跑；②改 .dat 单字节 → emu 预测 struct/裁决 → 对照真跑
  → **oracle 闭环**；③裁决 era op（[374696, fail]，写 KP112）单独续跑。
- 工件：dw130/131/132.py、dw133_232461.pkl、dw133_241958.pkl、DW82d 存档。

**续 22 补充 120（同日第一百零五轮）——.dat 字段解码完全仿真：emu = 解密器本体**：

- **b8 全节奏 /1**（41 snap 全 era 覆盖）+ 全量续跑扫描（OSError 护栏）。
- **era① 解码 op 完整终结**：t=186813 snap（region 机器 0x102b9d1、esi=0x111e781）
  续跑 = **done、25549 lodsb、ba 页 65 次写**——**写值 = 明文 ASCII**：
  `[0x1d2,0x213) = "5This application has been registered to
(CISC-1) Examples - LCF"`
  = 许可注释字段**解码后就地写回缓冲**（与 KP 已知许可结构逐字吻合）。
  **.dat 加密字段 → 明文的变换 = emu 已完整执行 ✓**（本 run ba=0xd50000）。
- **终局 era 落点**（b2@368865）：KP 头 "(CISC-1) Example" @0xd40000/0xd60041、
  serial "105A-0000…" @0xd41b00/0x60080 = 裁决字段拷贝到新堆块（验证 era 实锤）。
- **oracle 形状定案**：解码 = 就地缓冲变换 → **改密文 → 续跑 snap（缓冲补丁 =
  改后密文）→ 解码输出 = 预测**。resume 点后已解码区不受改prefix影响（改 X ≥
  0x213 区段）。逆程序（加密器）= 按 field 查询 oracle（密文候选 → 明文比对）
  逐 field 求逆——forge .dat = 已知字段（19 机器键）→ 逐 field 逆 → 密文 →
  **校验和**（POOLSNIFF 16 位双累加器，check-era snap 同法续跑可算）→ 完整 forge。
- **下一轮**：①oracle 原型 = 改 ba 单字节 → 续跑 → 输出 diff（保真终验）②check-op
  snap 定位（[196,220] era）→ 校验和 emu 计算 ③逐 field 逆 → forge .dat → 真跑对照
  → **oracle 输入侧闭环**。
- 工件：dw132.pkl（41 全扫）、dw134.pkl（era① 65 写 + 终缓冲）。

**续 22 补充 121（同日第一百零六轮）——ORACLE 激活：改输入 → emu 预测解码输出 ✓**：

- **输入源定案**：解码 op 读址追踪 = **copy A = 镜像 0x111E000**（506 读，
  0x111e4db..；snap esi = 0x111e781 就在其中）——链 = .dat →（变换）→ copy A →
  （decode）→ 缓冲字段。0x293ef000 高址区 26 读 = 次级数据源。
- **buffer 触发 snap 仪器**（b8 格式追加，缓冲页哈希变化 → GetThreadContext 即时
  snap）——但解码爆发 < poll 间隙，此 run 未赶上（解码 µs 级，poll ~5-10ms）。
  b8 口算修正：记录 = 20528B（4+40+4+0x5000），45 条。
- **ORACLE 活证**：resume@186813（DW82f 存档，ba=0xd50000）+ patch copy A
  0x111e750 = 0xAA → **输出 13 字节变化（[0x1d3,0x1df) 'This applicat' → 级联
  破坏）**——改输入 → emu 预测解码输出 ✓✓。patch 0x111e700 = diff 0（未消费区）；
  patch ba 页 [0x1d4-0x1dc] 全 diff 0（输入 = copy A 非 ba，交叉验证）。
- **解码形状**：滚动键级联（patch 点后全破坏 = 位置相关流式）→ 逆程序 = **后向
  逐字节求解**（末字节 = g(input_last, key_final)，key 状态末端已知 → 逐字节回溯，
  g = XOR 族可逆）。
- **forge 完整路线（机械步骤，emu = 工具）**：①目标字段（19 机器键，补 16-23
  时代已量）②copy A 逆 = 后向逐字节（oracle 查询）③.dat 逆 = 变换 op 逆（同法）
  ④校验和 = check-op snap 续跑算出 ⑤forge .dat → 真跑 = 许可验证通过？！
- 工件：dw132.pkl（45 全扫）、dw134/135 pkl、DW82e/f 存档。

**续 22 补充 123（同日第一百零七轮）——差分扫描：输入 = 8 字节块读取、全级联滚动键**：

- 36 位差分扫描（patch copyA [0x111e4db+j] → 输出 diff）×unicorn 崩溃噪声
  （19/36 CRASH×3——hk_u mem_map 竞态 = 不稳定源；缓解 = 预映射 fault 页省
  hk_u）：
  - **有效输入 = 8 字节块**：va 0x111e4fb/0x111e50b/0x111e51b/0x111e553/
    0x111e57b/0x111e59b → **输出 diff [0..64] 全 65 字节**；0x111e5b3/0x111e5c3
    → [1..64]（out[0] 独立）——**每输入块影响其后全部输出 = 全级联** ✓
  - 间隔 8 的地址有效（0x4fb→0x503 无→0x50b 有）= **qword 粒度读取**，
    506 reads ≈ 63 qwords ↔ 65 输出字节 ≈ 1 qword/字节
  - 无变化位（0x4eb/0x513/0x55b/0x583/0x5cb/0x5d3）= 跳过的 qword（2-mod-4
    对齐模式待定）
- **forge 求逆确认可行**：全级联 → 后向归纳（末字节先解：out[k]=f(in[k],
  key_k)，key_k = 已解前缀决定 → 逐字节回溯，f = XOR 族字节可逆）。emu 单次
  查询 ~40-90s（25549 lodsb）→ 后向 65 字节 × 256 候选不可行 → **f 直接提取**
  = trace 单次运行 (in, key)→(out, key') 元组表（65 对 = 密码结构显影）。
- **模型终稿（本 session）**：copy A = 镜像内嵌加密字段（[0-100]ms init era
  写入，仪器不可及）；.dat = ReadFile [185.7-186.7] → 缓冲 → check keystone
  （hash 单字节敏感）→ 擦除；字段 = copy A decode [186.7-190]（emu 已复现 ✓）；
  裁决 = [375+] 写 KP112。oracle = emu（patch → 预测 ✓）。
- **下一 session**：①f 表提取（单次 trace，hook 减负 = 预映射）②后向求解器
  （字段 → copyA）③变换逆与校验和（check-op snap 续跑）④forge .dat → 真跑
  → **oracle 输入侧闭环**。
- 工件：差分扫描输出（后台 exec_4f1b）、dw132-135 pkl、DW82e/f/g 存档。

**续 22 补充 124（同日第一百零八轮）——f 表 trace 成功：密码 = 65 周期 × ~503 读/字节**：

- **预映射修复 unicorn 不稳定**：fault 区（0x1182000/0x293e-40000 等）预先
  mem_map，hk_u 移除 → 单次 trace 零崩溃 ✓（差分扫描的 19/36 CRASH = hk_u
  mem_map 竞态实锤）。
- **trace（dw136.pkl）**：copyA 页过滤读 hook + ba 页写 hook → **32727 读 +
  65 写**（一条 run 全捕获）。读头 = 0x111e781（= snap esi ✓）；读尾 =
  0x111e62b；窗口 [0x111e4db, 0x111e892] = 953 B。
- **stride 显影**：(1 ×28523) + (186 ×65) + (-951 ×65) + (144 ×64)——
  **65 个周期 = 每输出字节一周期，~503 读/字节**：每字节 = 全密钥窗重扫
  （~500 read 的 F 运算）→ 周期步进 = -342（窗口后向滑动）。密码 =
  out[k] = F(key_window_k, data, k)，F = 逐字节均匀（stride 模式一致）。
- **求逆路线修正**：F = ~500 op 链 = 非平凡单字节可逆 → 后向归纳需 F 数学
  建模（读序列 = 密码的 op 序 = 可从 trace 周期提取）；或 **程序级**：60 万
  字节 VM 流 = 168 handler 语义（fold2 时代已普查）= 离线反编译路线。
- 下一 session：①周期切分（-951 边界）→ 每周期读集 + 输出对 ②F 的 op 链
  建模或 VM 流反编译 ③后向求解器 ④forge。
- 工件：dw136.pkl（32727 读 + 65 写全 trace）。

**续 22 补充 125（同日第一百零九轮）——状态载体定案：0x293EF000 工作区（185 万写），oracle 自洽封闭**：

- **逐层排除定案**：寄存器每周期边界完全相同（65 snap 全同）→ copyA 读值跨周期
  零变化（233 公共 1 字节地址）→ 栈仅 1 读（V 槽）→ **唯一载体 = 0x293EF000 高址
  工作区：185 万写事件**（write-event 计数）——VM scratch/state 区，poll 时未提交
  （b15 盲、读 = fault 零映射）。emu 内部自洽跟踪（resume 99.8% 保真已证 = 该区
  处理正确）；镜像 diff 后仅 7 字节（0x1028000 窗口字段）。
- **oracle 自洽封闭**：emu = 解释器 + 0x293e-f 工作区 + copyA + ba 全内部状态 =
  patch 输入 → 预测输出 **无需任何外部状态** ✓（前证 13 字节级联变化）。
- **密码全貌**：out[k] = F(copyA 窗 506 地址静态值, 0x293e-f 状态_k)，
  F = ~503 读 + 185 万写/65 周期 ≈ 2.85 万写/字节的重运算链；周期寄存器态
  全同 = 每输出字节 = 独立机器运行（状态在 0x293e-f 工作区传递）。
- **求逆 = F 的数学建模**（周期内 op 链提取）或 **VM 流反编译**（60 万字节 =
  168 handler）——机械但重；oracle 前向已封闭，forge = 下一 session 主攻。
- 下一 session：①周期内 op 链提取（0x293e-f 写序列 = 状态转移显影）②F 可逆
  性判定 ③后向求解器 ④check-op 校验和 ⑤forge .dat → 真跑闭环。
- 工件：dw136.pkl（32727 读+65 写）、dw137.pkl（65 周期寄存器快照全同）、
  dw138.pkl（栈读 = 1）。

**续 22 补充 126（2026-11-19，第一百一十轮）——era1 op 全解剖：模型重写（静态 PT 拷贝，非 .dat 解密）**：

- **真周期定案**：dw136 "周期"切分修正——真周期 = **圆形扫**（wrap 边界
  0x111e892→0x111e4db，65 圈 × 506 读，dw147 固定 read-value 捕获后确认每圈
  读址+值全同；此前以 0x111e4db 出现次数切分把每圈腰斩）。
- **k 通道隔离（dw148-155）**：边界态 diff（dw153，1/2 周期全快照对账）=
  EDX、5 scratch dword、**3 个 VM 帧 dword @0x102859c/5ac/5b4**、ba 1 字节。
  逐组移植实验：仅 **帧 dword [0x10285B4] 高 u16**（0x2522+k）翻转 out 值
  （0x54→0x68→0x69 随 +1）；[0x102859C] 只搬写地址；EDX/scratch/ba 全无效。
- **PT 表发现**：counter 曲线（dw156，0x2522+k 连续 70 值）= **整条明文
  'This application has been registered to\n\r(CISC-1) Examples - LCF'**——
  计数器 = **读指针低 16 位**，明文表 = **0x1182522 静态驻留**（failfreeze
  镜像内 '5This application…'，PT[0]=0x35 在 0x1182522；out[k]=PT[k+1]，
  dw141 的 0x1182523 读 = 该表的本尊读）。
- **模型重写**：era1 op（t=186813，"字段解码"）= **静态明文表 → ba 缓冲的
  拷贝走表**，与 .dat 内容零耦合（dw121 已证 ba patch 无 diff，本轮反证
  完整闭环）。"65 周期密码 F" = 走表循环；F 可逆性 = 平凡（拷贝）。
  **.dat 的真角色 = hash keystone**（check-op 校验通过后擦除，内容不参与
  字段）——补 122 的"镜像内嵌加密字段"模型修正为"静态表 + keystone"。
- **方法论教训**：dw140 读 hook 的 unicorn value 参数不可靠（全 0）——
  hook 内必须 uc.mem_read 取值；dw147 修复后值全对。2549 周期寄存器全同 +
  计数器单调 = 走表机器的指纹（此前误读为"重运算密码"）。
- **forge 路线 v2**：许可字段 = 静态镜像数据（PT 表 + KP 结构页）→ 改字段 =
  patch 静态区 + verifier 期望值对齐；.dat = 保持 pristine（hash 已过）。
  verifier（0x2402C）逐字段 vmhash（OUT/vmhash.py 全实现）期望常数 =
  搜索列表 @RVA 0xDC000 编码 blob 内（1024 dword 全非零，需解编码）或
  check-op 转移表（check_states.json 16 态已存）。
- 下一 session：①搜索列表 blob 解码（expected 常数提取）②vmhash 仿射求逆
  （GF(2) 线性，可解字段）③字段 patch + KP 一致性 ④真跑验证 = forge 闭环。
- 工件：dw139-156 脚本+pkl（dw147 读值修复版、dw153 边界对账、dw154 组隔离、
  dw155/156 计数器曲线）、dw139_window.pkl（441 值窗）、check_states.json。

**续 22 补充 127（2026-11-19，第一百一十一轮）——verifier op 全反汇编 + 19 字段槽定案 + 阻断确认**：

- **verifier op = 镜像常驻 0x102400D，全反汇编（dw183）**：esi 走 4 字节步表
  （lodsd）→ eax = entry + [esp+0x28]（caller 帧常数）= 字段串指针；首字节
  预检（[ebp+0x12262d31] 开关）→ scasb 取长 → **vmhash 核心 = OUT/vmhash.py
  逐指令同**（0x5041/0x5449 常数确认）→ `cmp edx, eax`（edx = caller 传入的
  expected）。miss 路径 `pop esi; add esi,4`。**blob ≠ 直接指针表**（entry+K
  无重复 K）、**≠ 单 XOR/ADD 掩码**（dw167/补127 掩码测试 max 3/5 命中）。
- **19 字段槽定案（dw170）**：t=257544 op（1.87M 步，干净终结）写 **恰好 19
  个槽**（0x1020139…0x113f32e）× 7 次 = 补16 的 19 LICPATCH 字段实锤；14 槽
  恒定值 + 5 槽演化（0x102118d/0x1021d35 = 0xd41b27 递减计数器、0x102082d/
  0x1021601/0x113f32a-e = per-run 键）。**field-op oracle = 0.8-1.0s/查询**
  （dw171，vs era1 90s）；输入 = **0x1147xxx 流**（15303 读，非 copyA！
  dw172-173：流 patch → 字段变 ✓，copyA patch → 零变化）。
- **check-era（[196,220]ms）7 snap 全 derail**（dw178-181）：检 op =
  interpreter-4 族（edi=0x105FFAE 全同）；derail = **缺 0x293e-f 时代态**
  （VM 栈 = 机器状态载体，b15 时代才有捕获）。t=214162 跑 6470 lodsb 后
  fetch-fault，ba 读 = 0（检 op 的 .dat 输入路径未达）。
- **phase-1（[0,182]ms）snap 状态缺口实锤（dw187-189）**：DW82 时代 b8 最早
  t=103372（转换 op era 内）但 **0x293e-f 完全未捕获**（该仪器 b15 时代才
  有）→ phase-1 resume 全在 VM 栈 deref 处 derail（t=112014：region 机器
  入口 0x102b9d1、首 op 写 0x1 = 空栈）。**.dat→copyA/PT 转换 op = 永未
  捕获 = .dat 逆的硬阻断**。解除条件 = Device Guard 放行 + b8 加 0x293e-f
  dump 重跑（仪器改动 ~20 行现成）。
- **离线替代路径否定**：盘上 exe @copyA RVA = 未解密态（18/4096 同）；
  .dat→win 直接/位置/单键 XOR 全噪（dw185）；vmhash 链对 check 事件 0 命中
  （dw174-177，init 全排列）。
- **下一增量（二选一）**：①Device Guard 解除 → 20 行仪器扩展（b8 加
  0x293e-f dump）→ 重跑 → phase-1 转换 op 续跑 → .dat 逆 → forge 闭环；
  ②blob 编码逆向（需 verifier caller 框架态 = era snap，同样等活体）。
  离线可做：vmhash 仿射性证明 + 字段→expected 的前向计算器（forge 的
  比对侧完成）。
- 工件：dw157-189 脚本+pkl、dw170.pkl（19 字段写表）、dw183（verifier 反汇编）、
  dw187（时代快照盘点）。

**续 22 补充 127 补遗（同轮，vmhash 可逆性 + 前向计算器定案）**：

- **vmhash 逐步长双射实证**（dw190）：core_step 对固定字节在 4096 随机态上
  单射 ✓（(cl,ch,dl,dh) → 全活 4 字节态；dh 末值 = bx 高字节 XOR，非恒 0）。
  **前向计算器与 vmhash_full 3/3 一致**（CISC-1/LCF-AT/serial）——forge 的
  比对侧完成：`expected = vmhash_forward(new_field)`，后向求解器 = 从终态
  逐字节反推（双射保证可行）。
- 阻断不变：expected 常数的来源（blob 编码 / caller 派生）= verifier caller
  框架态 = 需活体 era snap（Device Guard 限制）。

**续 22 补充 128（2026-11-19，第一百一十二轮）——Device Guard 解除 + PAGETRAP 仪器 + 终模型：页面 = aPLib 解压的原始程序数据**：

- **Device Guard 解除（实测 CISC-1.exe 可跑 4s+）**——活体路线重开。
- **b16 VM 栈仪器落地（b8 每拍 + 0x293E0000 2MB dump，FNV 去重）**：实测
  **只有 1 版全零 dump**——0x293e-f 区在 poll 时刻未提交（RPM 失败 = 零页
  hash 恒定）。**0x293e-f = emu premap 伪迹定案**：era1 emu 的 185 万写 =
  我们自己 premap 的 scratch；真机的 VM 栈 = x86 0xef000 栈（b8 一直拍着）。
  补 125 的"状态载体 = 0x293EF000"修正为 emu 伪迹。
- **PAGETRAP 通用仪器落地**（`MAGICMIDA_V2_PAGETRAP=<hexaddr>-<hexsize>`）：
  CREATE_PROCESS 时 VirtualProtectEx(PAGE_NOACCESS) → AV handler 捕获 →
  dump 64KB + 寄存器 40B → 恢复 RW。`MAGICMIDA_V2_DEBUGGED=1` 强制 V2 走
  调试管线（post-attach 无调试端口 = 异常不可达，PAGE_NOACCESS 会直接崩）。
- **PAGETRAP 命中两次（决定性）**：
  - 0x1182000（PT 页）：fault @ **EIP 0x11eb119**（写入者）——反汇编 =
    **aPLib/UCL 位流解压器**（`mov al,[esi]; [edi++]=al; add dl,dl; adc dl,dl`
    LZ 匹配链 0x11eb13d+）——**该页 = aPLib 解压的原始 PE 数据**！
  - 0x111e000（copyA 页）：**同一个 EIP 0x11eb119** = 同一解压器 = 同一
    原始程序数据。
- **终模型（全链闭合）**：CISC-1.exe（aPLib 打包）→ Themida 解压器
  （0x11eb116）→ **原始程序页**（0x111e000 = 原 .data、0x1182000 = 许可
  文本所在的原始数据页）→ 壳 VM op 以这些页为流消费（era1 "走表" = 读
  原始程序静态数据）→ **许可字段 = 原始程序内嵌静态数据**；.dat = 独立
  keystone（hash 校验后擦除，内容永不参与字段）。补 122"copy A = .dat
  变换形态"撤回（= 解压的原始数据）；"密码 F" = VM 消费原始数据的解释
  过程，无密码可言。
- **forge 终路线**：字段 = 原始程序数据 → forge = ①重打包原始 payload
  （aPLib 重压缩 + 重嵌）或 ②PAGETRAP 窗口期内存 patch（trap 恢复 RW 后
  立刻 write_memory 覆盖目标字段，抢在消费前）——② = 仪器已就绪。
  .dat 保持 pristine。
- 下一增量：①PAGETRAP 变体 = trap hit 后不立即 restore，先 write_memory
  patch 目标字段再 restore（forge 注入器，~30 行）②原始 payload 定位
  （aPLib 块边界 = 0x11eb116 的 esi 起点）③真跑验证。
- 工件：CISC-1U.pagetrap_1182000_ea707e1a.bin + _ctx、
  CISC-1U.pagetrap_111e000_1afdc35b.bin、dw190/191、dw128_run3-8 日志。

**续 22 补充 129（2026-11-19，第一百一十三轮）——FIELDPATCH 注入器落地 + 字段 patch 端到端实证**：

- **FIELDPATCH 仪器落地**（`MAGICMIDA_V2_FIELDPATCH=<hexaddr>-<hexbytes>` +
  第二目标 `_FIELDPATCH2`）：post-attach 轮询 watch——目标页首现非零内容
  （解压器完成）→ WriteProcessMemory 覆盖 → 日志。
- **实测双命中（t=174ms）**：0x1182522（65B 许可文本）+ 0x10228c4（KP 名字
  字段 8B）均成功写入活体进程。
- **端到端传播实证**：b15 数据池 **13 个版本**（t=185810→365479，覆盖裁决
  era）含 `(PWNED!)` @ struct-page 0x8c5（上下文 = 完整 .dat 路径 + 名字）——
  **patch 字段穿透到裁决时代并持久化** ✓。
- **裁决 = FAIL（exit 44 不变）**：verifier = vmhash(字段) vs expected
  （expected 源自 .dat 解密 = 绑定 CISC-1）→ 改字段必须同步改 .dat。
- **emu 预测侧修正**：dw192 —— era1 emu 的输出 = PT 走表前 32 字节后 park
  （0x1031d72 等待环）；PT patch 偏移错位实验（0x1182522 写入使输出移位）
  证明 **走表 = 逐字节 copy（页 [0x522+k] → out[k]）**，名块（page+0x54c）
  patch 零 diff = 该块不被 era1 走表消费（era1 只走前 32 字节即 park）。
  KP 名字块的消费者 = [313,316]ms 的逐字段构建（lw2-era 结论互证）。
- **forge 剩余唯一缺口 = .dat 重加密**：verifier expected = .dat 解密字段
  → 改字段需 .dat 携带新 license。路线 = ①check-op 函数 emu 拟合（261 态
  + check_op_body3.bin）→ 哈希 fix-up（2-4 字节调校到期望常数）②API 级
  字段解密的逆（Crypt* 导出函数 = 罕见但可从壳会话 dump）。
- 工件：fp_payload.txt、dw129_run1-4.log、dw192.py、b15 PWNED 13 版本、
  fp_block.txt。

**续 22 补充 130（2026-11-19，第一百一十四轮）——CHECKWATCH 仪器 + check-op = interpreter-4 VM op + SEH 阻断**：

- **CHECKWATCH 落地**（DECODEWATCH 内联：poll image+0x5FFB2 u16，变化即
  GetThreadContext + 20KB 栈 snap）：实测 **15 个 burst 边界 snap**
  （t=195..235ms，ctr 0xff001c/0xff0078/0x10bde3e/...）——**µs 级 check
  burst 的后状态首次可捕获**（burst 间 ms 级间隔 > 轮询间隙）。
- **check op 身份定案**：mid-burst snap EIP 不在 0x5FC00 带（= POOLSNIFF
  diff = 可写 scratch/变量），edi=0x105FFAE = **interpreter-4 窗口基** →
  check op = **interpreter-4 族 VM op**（esi=0x114271d = 字节码流）。
- **era 链推进**：t=316116 snap（eip=0x102b9d1 = region 机器入口，[316,343]
  字段构建带）= 继 t=186813 后第二个入口态 snap。emu 续跑 = **div ecx 除零
  异常阻断**（0x1038089 = 壳的异常驱动混淆；int3-skip 循环不适用 = 需要
  SEH 仿真，异常副作用未知）。
- **结论**：check-op 函数拟合的 emulator 路线 = 卡在 VM op 的 SEH/入口态
  （mid-op snap 载入不完整，entry 态 snap 只有 era1 与 [316] 两个，且后者
  异常密集）。**替代路线 = API 级解密器 dump**（补 115：[193] SHA-1 +
  Crypt*——从壳会话记录 CryptImportKey/CryptDecrypt 参数 = .dat 字段解密
  的直接观察 = 加密器逆的钥匙）。FIELDPATCH 端到端传播（补 129）+ .dat
  重加密 = forge 的最后两块。
- 工件：dw193/194/195、dw130_run1.log（15 CHECKWATCH snaps）、
  CISC-1U.v2decodewatch.b8.bin（fresh 49 snaps）。

**续 22 补充 131（2026-11-19，第一百一十五轮）——VERIFIERBYPASS 落地 + 裁决通过（shell 进 app 阶段）**：

- **VERIFIERBYPASS 仪器落地**（`MAGICMIDA_V2_VERIFIERBYPASS=1`）：[320,420]ms
  窗口 pattern-scan 活体 verifier 页（image+0x24000 起，0x800B）找
  **`cmp edx,eax; je rel8`（3B D0 74 xx）** → WPM `je→jmp`（2 字节）。
  活体布局 = 冻结布局相同（je @0x102408d = 74 0f ✓；首次窗口错写
  0x4000/0x40000 已修 = RVA 0x24000）。
- **实测（dw131_run7）**：patch 命中 @0x102408b；**shell 行为剧变**：
  - pristine = **0.5s exit 44**（fail bail 立即触发）
  - bypass = **4.4s 运行 + 新模块加载**（0x73110000 等 DLL 在 ~4s 现身 =
    **app 阶段启动**）→ 最终 0xC0000005（app 阶段下游崩溃，非许可门）
  - FAILFREEZE/SFREZE = 全程未触发（fail 路径未走）
- **结论：许可字段检查 = 通过**（vmhash(field)==expected 全部短路）——
  **V2 锻造的许可门 = 攻破**。crash = app 阶段下游（.dat 擦除竞速 / 反
  篡改 / demo app 自身），下一增量定位。
- **forge 语义重定义（补 131 定案）**：per-run 加密的 verifier op 使静态
  补丁不可行 → 运行时窗口 pattern-scan + 2 字节 patch = 可靠（布局 =
  per-build 确定性，多次运行实测稳定）。字段 patch（补 129 双命中）+
  verifier bypass（本轮）= 组合拳已齐。
- 过程缺陷：扫描窗口 RVA 错写 0x4000（正确 = 0x24000）一轮；b0=0x7c 误判
  = 活体页与冻结页同布局但初读时机错（300ms 太早，op 未解密）。
- 工件：dw131_run1-7.log。

**续 22 补充 132（2026-11-19，第一百一十六轮）——4.4s 崩溃全归因（WER dump 实锤）+ 组合拳联跑落地**：

- **FIELDPATCH(PWNED) + FIELDPATCH2 + VERIFIERBYPASS 三仪器联跑（dw132_run2/
  run5/run9）**：FP@0x1182522(65B)+FP2@0x10228c4(8B) @172-186ms → era1 输出
  捕获 @188-202ms（PWNED 进 era1 输出窗口）→ VB patch @330-425ms → shell
  运行 4.4-9.7s（pristine 0.5s exit 44）= **自定义 license 字段 + 全字段
  check 短路同时成立，许可门通过**。前置条件 = DECODEWATCH 必须开（VB/FP
  块在 `if let Some(ba) = buf_addr` 内，无 .dat buffer 定位 = 静默跳过，
  dw132_run1 教训：只设 VB/FP env 仪器全不发）。
- **排除法四连（restore-after-use 仪器 = VBRESTORE）**：
  - 仪器形状：`MAGICMIDA_V2_VBRESTORE_MS=<ms>`（默认 550）——patch 字节存
    VB_OLD（u32 高低字节），restore 调用点 = bail-watch 10ms 循环（vb_ms
    ≥500）+ µs 窗口循环（vb_ms <500，kHz tick，run D restore @386ms）。
    首版错误 = restore 块放在 `if VB_ARMED==0 && [320,420]` 的 else（patch
    后恒短路）→ 移出；第二版放在主 poll 循环 dump 段（实测 = 整个 watch
    函数单遍执行，dump 段只跑一次 @505ms）→ 最终 = DECODEWATCH bail-watch
    循环内（10ms tick 全程）+ µs 循环双调用点。
  - run B（restore@553ms、无 FP）：death 仍 ~4.4s → **FP 字段非触发器**
  - run C/D（restore@514/386ms，µs 循环）：patch 窗口缩到 [338,386]≈9ms，
    death 仍 ~5.4s → **verifier 页字节扫描（patch 检测）非触发器**
  - probe @551ms 读回 `eb 0f`（patch 未被重编码）→ op 执行后页保持 patch 态
- **late-attach mini-debugger（OUT/ps1/lateattach2.py）**：壳 init-era 端口
  检查后（~2.5s）DebugActiveProcess——运行期检测存在（attached run 死状
  不同）但可行；PEB32 走链枚举模块（64-bit 调用方 toolhelp 只见 WOW64 视
  图；ProcessWow64Information→Peb32→Ldr.InLoadOrderModuleList，BaseDllName
  UNICODE_STRING32 @+0x2C/+0x30）；解析 kernel32/ntdll 导出表（Optional
  header magic @peh+24；EXPORT_DIRECTORY：NumberOfNames@0x18、AFNS@0x1C、
  ANAMES@0x20、ANORDS@0x24——首轮 unpack_from(exp,20) 全错位）→ **4 个
  terminate 路径 int3（kernel32!TerminateProcess/ExitProcess、
  ntdll!NtTerminateProcess/RtlExitUserProcess）全部 arm 成功、全部未命中**，
  EXIT_PROCESS code=0xC0000005 直接落地 → **attached 态的死亡 = 直连
  syscall 自杀（绕过全部 user-mode terminate API），壳运行期反调试响应**
  （64-bit DEBUG_EVENT 坑：union 8 对齐 @16 非 12；EXCEPTION_RECORD64
  148B → dwFirstChance @164）。
- **WER LocalDumps = 决定性武器（无调试器 = 自然路径保真）**：
  `HKLM\...\Windows Error Reporting\LocalDumps\CISC-1.exe {DumpFolder,
  DumpType=2, DumpCount}` → 干净 bypass run 写出 **34MB 全量 dump** →
  **死亡 = 真实 unhandled AV，非 TerminateProcess**。
- **dumpcrash.py 解析（OUT/ps1）**：MINIDUMP 手工解析（ExceptionStream@6、
  ModuleListStream@4：MINIDUMP_MODULE=108B、ModuleNameRva @+20 非 +24；
  Memory64ListStream@9）→ **裁决**：
  - `EXCEPTION code=C0000005 addr=0102786F（image RVA 0x2786F）WRITE
    target=54831A79`
  - x86 CONTEXT（Eip@184 与 SegCs@188=0x23/EFlags@192 交叉验证 = 真实）：
    **Ebp=EEDC0014（check-family magic）**、Edi=0102786B、Esi=010277F6、
    Eax=54831A79（=写入目标=垃圾）、Edx=CA5E2899（垃圾）、Esp=B8C933A4
    （VM 备用栈）
  - 现场代码（dump Memory64 活体字节）：`...; b8 00 00 00 00 | 0b c0 |
    74 58 | 83 bd 35 04 26 12 00（cmp [ebp+0x12260435],0 → 折叠
    0x01020449 in-image）| 74 06 | ff 95 2d 0a 26 12（call [ebp+0x12260A2D]
    → 0x01020A41）...` = ebp-magic 折叠寻址的原生混淆块（check op 家族）
  - **结论：post-许可检查阶段的 VM op 以许可派生密钥解密/部署数据，解出
    垃圾指针 → AV。垃圾根因 = 许可数据机器锁定（.dat = LCF-AT 硬件锁
    license，本机身份不符 → f(license, machine) 密钥错）**
  - **复现实锤（werdumps/CISC-1.exe.4796.dmp，第二次独立 run）**：crash
    addr/target/Eax/Ebp/Edi/Esi/Esp **七项全部逐字节一致**（仅 Edx 高位随
    per-run 键演化 0F4C2899 vs CA5E2899）= 确定性崩溃点
- **campaign 语义定案**：许可门（verifier vmhash 比较）= **bypass 成立**
  （gate 真通过）；4.4s crash = **机器锁定的许可数据在部署阶段解密失败**
  ——不是反篡改响应、不是 FP 字段、不是壳字节码 bug。forge 全闭环 =
  .dat 重加密（本机硬件字段）——已知的剩余缺口（补 129 定案的 check-op
  emu 阻断 / Crypt* API dump 替代路线）。
- **CYPWATCH 仪器（补充 132b）——Crypt\* 活体捕获路线 = 负结果关闭**：
  - 形状： + DEBUGGED=1。advapi32 的 LoadDll 事件
    时（句柄名解析 = GetFileInformationByHandleEx(FileNameInfo)，注意
    FileNameLength = 纯名字字节数、名字在 +4 起——首版切片 [4..len] 截掉
    2 字符 = "advapi32.d" 静默失配）解析三导出（PE32 导出表手工走：
    NumberOfNames@0x18/AFNS@0x1C/ANAMES@0x20/ANORDS@0x24）→ DR slots
    1-3 execute BP（dbg.set_hw_breakpoint，全线程应用）→ 命中于
    SingleStep 分支拦截捕获（args @esp+4..、buffer dump
    cypwatch_hash_N.bin / cypwatch_dec_N.bin）→ disable one-shot slot +
    continue。工具链坑两轮：LoadDll 时 toolhelp 快照 = loader lock 持有
    → 全 None（换句柄名）；LoopState 增 cypwatch 字段。
  - 实测（dw132_runM/R）：**advapi32 = 静态导入 @0.03s 即加载，3 BP 全部
    arm 成功**（CryptHashData@0x75fe3a10 / CryptDeriveKey@0x75fff060 /
    CryptDecrypt@0x75fe9660），**但 3 分钟零命中**——debugged run 的壳 =
    反调试扣留 .text 解密（补 128 定案）→ 壳到不了 license 阶段 → .dat
    解密调用（若有）不发生。结合离线 sweep（datcrack.py：hash 算法 ×
    输入候选 × key 算法全组合 0 强命中）＝**壳不用 CryptoAPI 做 .dat
    密码——.dat 密码 = 壳自己的实现（真值表 dword 变换，续 17-20 实测）**。
  - **forge 的 .dat 重加密 = 需逆壳自有密码（SEH 阻断的 check-op emu 路
    线，补 129-130 已定案）或纯内存 forge（license struct + 派生键材料
    post-decrypt patch——但「本机应是什么值」= 部署键派生知识，未解）**。
    剩余边界如实记录。
- 过程坑（工具层）：grep 对含 NUL 的日志静默返回空（26 个 NUL 字节 =
  binary 判定）→ 全部日志分析走 python；64-bit 宿主解析 32-bit 目标的
  DEBUG_EVENT 偏移错位一轮；后台 python 的相对 cwd 漂移 → 一律绝对路径。
- 工件：dw132_run1-11/runB/runC/runD/runE-H/runM-R.log、dw132_attach1-9.log、
  werdumps/CISC-1.exe.29112.dmp+4796.dmp（34MB × 2）、lateattach2.py、
  dumpcrash.py、datcrack.py。

**续 22 补充 132c（2026-11-20）——部署键派生输入源判定：license struct 全排除（8 组 patch 实验）**：

- **新仪器**（helpers.rs，全部 x86 门控、双架构零告警）：
  - **KEYPATCH**（`MAGICMIDA_V2_KEYPATCH=<hexaddr>-<hexbytes>,...`）：µs 循环
    内连续重写——slot 内容 ≠ payload 即 WPM。形状 = KEYFORGE 时代实证的
    「连续补丁 = 唯一有效形状」。实测：一次 FIELDPATCH @184ms 被 field-op
    （257ms 起 7 写/槽）覆盖（run T1 槽值回退），KEYPATCH 全存活（T2/T6
    crash 时刻槽值 = payload ✓）。
  - **KEYBUF**（`MAGICMIDA_V2_KEYBUF=<off>-<bytes>,...`）：同机制但地址 =
    DECODEWATCH buf_addr 相对偏移（µs 循环内 ba 在作用域）；marker 位
    0x80000000 区分绝对/相对。
  - **PASSPATH**（`MAGICMIDA_V2_PASSPATH=1`）：[320,420]ms pattern-scan
    verifier 页（VERIFIERBYPASS 同款）patch `8b 85 e9 01 26 12`（mov eax,
    [miss 0x10201FD]，折叠 disp = magic EEDC0014 相对 = per-build 常数）
    → `b8 00 00 00 00 90` + `0f 85 06 00 00 00`（jne）→ 6×nop。实测 hits=2（读+jne
    都命中 = 崩溃页解码正确）。
- **crash 页精读（WER dump Memory64 活体字节 + VA 标注）**：Eip=0x102786F
  = `00 00` = **add [eax],al**（Eax=54831A79 = 写目标 ✓）。je 目标 =
  0x102409C（= UE filter 消息里的地址 = **verifier 匹配路径**）；循环尾
  `inc [ebp+0x122601E9]` 折叠 = **0x10201FD miss 计数器**（补 16 的
  0x201FD ✓）；pass path 读 miss 计数器后 `jne` 分支。
- **app 永未解密实锤**：crash 时刻 image 的 281 条新增 ASCII 串全部 =
  壳引擎自体（Software\WinLicense、WLProjectName、驱动路径
  oreans32.sys、/getwlstatus 等、WLProtectionDateTime=2009-3-14 = per-build）；
  许可字符串（GUID/registered/LCF-AT）= 零残留（已擦除）→ **app 区从未
  解密 = 部署从未开始**。crash 消息 = 运行时构建（closehandle 图零字节）
  = 壳 UE filter 打印 **缓存的 verifier-era 内部异常（0x102409c）**。
- **8 组 patch 实验（全部跑崩溃→WER dump→Eax 对比，baseline
  Eax=54831A79 七项逐字节稳定）**：
  | # | 目标 | 存活 | Eax |
  |---|---|---|---|
  | T1 | FP@184ms 两个 per-run 键槽 | ✗（field-op 覆盖）| — 无效实验 |
  | T2 | KEYPATCH 同两槽（0x102082d/0x1021601）| ✓ | **不变** |
  | T3 | KEYBUF buffer [0,52) 13-dword + pos300 | pos300 ✓，[0,52) 窗口内被重加密吞 | **不变** |
  | T4 | 文本/数据区 [0x1021dc0,0x1022900) 2880B | ✓ | **不变** |
  | T5 | KEYPATCH miss=0 + sentinel=3 | 竞速输（搜索 era 内持续递增）| **不变** |
  | T6 | 13 个恒定 license 槽独立 marker（0xE0000001..0D）| **全 13 存活** | **不变** |
  | T7 | PASSPATH 读→0 + jne→nop（hits=2）| ✓ | **不变** |
  | T8b | 0x113f32a/e 本机键 | ✓ | **不变** |
- **判定**：部署键派生（Eax=54831A79 的计算）**不读任何可及的 license
  struct 槽 / buffer 键块 / 搜索状态槽 / pass-path miss 门**——输入 =
  VM/堆态（VM 栈 @0xB8C933A4 = dump 未捕获 = UE filter 先 teardown）+
  per-run 解密 op 链自有数据。**license 数据对部署的影响 = 经由搜索
  （miss 389 → 下一 stage 不初始化 → pass-path 的派发异常成孤儿）**——
  搜索的 corpus = image+0xDC000 编码 blob（1024 dword，per-build），
  forge 搜索命中 = 需 blob 元素编码逆（补 127 选项 ②，需 era 态）。
- **附**：VB 窗口 [320,420]ms 可被 370ms 步距的循环整体错过（T8 首跑
  pristine fail 44）= 方差 ~1/3，重试即过。
- 工件：dw132_runS0/S1/T1-T8b.log、werdumps/（28948/28248/7028/23308/
  23912/29788/27080.dmp）、patch_keypatch.py/patch_keybuf.py/
  patch_passpath.py、dw170.pkl（19 槽全表：13 恒定 + 6 演化含
  0x102118d/0x1021d35 计数器）。

**续 22 补充 132d-g（2026-11-20）——搜索 = blob 字节走读 + U11 解锁：buffer 许可区 patch = 崩溃变 CALC 对话框**：

- **搜索时代重构（b8 CHECKWATCH + EIPHIST 采样线程实锤）**：线程自
  t=332ms 起反复停在 **0x102786F 同一 fault 指令**（同寄存器，eax=54831A79）
  直至 489ms+ —— **4-9s 的「app 阶段」 = 389 次 fault 重试的墙钟成本**
  （miss 计数 = 重试计数！）。NOPPATH（NOP 掉 4x add [eax],al）→ 推进到
  0x1027880（call [0x1020A41]）再次冻结 = 逐站重试链。
- **EIPHIST 采样线程**（MAGICMIDA_V2_EIPHIST=1，0.5ms 级独立线程
  [320,500]ms，12k 样本 514 站点）：**搜索 = 解释器逐字节走读 blob**
  （esi = 0x10DC756 → 0x10DCC59 = image+0xDC000 blob 区 ✓，[322,331]ms），
  走完后进 fault 循环（79.6% 样本）。「3x207 元素扫描」模型废弃 =
  搜索卡死在首 fault 重试。
- **blob 结构性（U9/U10）**：blob 全 0x41 → **零走读**（立即 abort）=
  blob 有结构头（[0x10DC000,0x10DC756) 区段校验）；blob = **运行时填充**
  （closehandle 图该区全零）= f(license, machine) 混合体的编码语料。
- **U1 blob dword marker（1024/1024 存活）**：eax 不变 → fault 不依赖
  blob 内容 = 键态依赖。
- **VALLOC（U3/U3b）**：0x54831A79 = 合法 user 区地址 = **页面未映射**
  （非野指针）；VirtualAllocEx 0x54830000+0x20000 覆盖 → 流程不变 =
  搜索不是等映射。
- **U11 解锁（本轮头条）**：KEYBUF buffer [52,480) = 本机键字节 →
  **流程越过 fault 循环直达 CALC 对话框**（win32u syscall 挂起 =
  对话框等待；不再 0xC0000005！）。对话框（隐藏桌面 MagicmidaV2Desktop
  枚举可读）：**Your license key is corrupted. 1051-BCEC-14F2-0C18-
  3745-254D-9F3C-2536** + 确定。OK → exit 2（结构化 fail）。
- **fp 三副本全 = 本机指纹**（fpfind.py 全内存扫描：0x582740 堆 +
  0x102135e/0x10228ba image，全部 254D-9F3C = **fp 运行时重组**
  （license 基段 + 机器中段替换）→ fp 不是门）。0x10228ba 区域后期被
  崩溃消息覆写（An internal exception...）。
- **U14 绑定校验定案**：KEYBUF [52,384)（明文尾 [384,480) 不动）→
  同一 corrupted 对话框 → **corrupted = 机器绑定校验**（license 的
  机器绑定字段 = LCF-AT 值 vs 本机计算值 mismatch），非 checksum。
  绑定字段 = struct 二进制区 [0xBF,0x17D)（190B，补 84 布局）候选。
- **forge 形状更新**：①buffer 许可区 patch = 解锁对话流程的钥匙
  （KEYBUF 仪器已备）；②绑定字段 = 需本机硬件衍生值（已知 4 dword：
  键 0x7DC80DE6/0x022869C8 + fp 中段 254D/9F3C，其余 ~46 dword 未解）；
  ③绑定字段定位 = field-op oracle 流（0x1147xxx）逐偏移差分。
- 新增坑：64-bit python 读 WOW64 目标的 MBI 结构 = x64 布局
  （AllocationBase+align 补位）；&Path 逃逸 static 闭包 = to_path_buf；
  HANDLE !Send = hraw isize 转发；fpfind.py = 全内存 fp 扫描器。
- 工件：dw132_runU1-U14.log、CISC-1U.eiphist.bin（12k 样本站点图）、
  fpfind.py、patch_noppath.py/patch_valloc.py/patch_eiphist*.py、
  kp_blob_u1/u10/kp_buf_u11/u14/kp_fp_u12.txt。

**续 22 补充 132h（2026-11-20）——搜索已被 buffer patch 解决 + 绑定数据 = struct [0,0xC0) 定位**：

- **搜索命中实锤（U13/U15/U16c b8）**：buffer 许可区 patch（KEYBUF [52,480) 本机键）
  后 **fault 站点零采样**——搜索完整走完（blob = 从 buffer 重建 → 本机键被编码进
  语料 → 扫描命中）→ 流程推进到 CALC 绑定校验。**搜索命中问题 = buffer patch
  解决**（KEYFORGE 时代 pos300 单点 = 不够；[52,480) 全区 = 够）。
- **struct 页活体读（U16c dialog 态，ba=0xc70000）**：**[0x00,0xC0) = 192B 许可
  二进制字段**（高熵 = 绑定数据）；**[0xC0,0x1E0+) = U15 markers 全存活**
  （0xE2000001.. 逐 dword，KEYPATCH 穿透 dialog 态 ✓）。struct = ba+0x10000
  （补 84 布局 ✓）。
- **绑定校验定位**：corruption 消息两副本 @0x102133e/0x102289a（均 image，
  prot=0x40）——0x102133e = struct 头相邻区 = 校验在 struct-adjacent ops；
  0x10228ba 区域后期被消息覆写（U12 的 fp patch 254D-9F3C 在 crash dump
  的消息区可见 = patch 存活但无效 = 校验读 buffer 副本）。
- **U15/U16 实验组**：struct 二进制区 47 dword markers + buffer keys 同打 →
  对话框文案零变化 = 绑定校验不读 [0xBF,0x17D) 或全字段 all-or-nothing；
  EIPHIST [190,700]ms 38k 样本 = dialog 流零 fault 站点 ✓（搜索命中复证），
  但校验站点未捕获（校验 = 主线程解释器站，与 blob 走读站同族混叠；或
  别的线程）。
- **剩余边界（精确化）**：绑定校验 = struct [0,0xC0) 48 dword（LCF-AT 机器
  绑定值）vs 本机计算态。已知本机值 4 dword（键 2 + fp 中段 2），其余
  ~44 dword = 需逆壳的本机绑定计算（= blob 构建算法的镜像）。仪器就绪：
  KEYBUF（ba+0x10000 相对 = struct 直打）、EIPHIST（窗口可调）、fpfind
  （全内存扫描）。
- 工件：dw132_runU15/U16/U16b/U16c.log、kp_u15.txt（48 spec）。

**续 22 补充 132i（2026-11-20）——KEYCOPY 仪器 + 绑定检查再排除两项**：

- **KEYCOPY**（MAGICMIDA_V2_KEYCOPY=src-dst-len，均 ba 相对）：µs 循环内
  **动态值连续复制**（RPM src → 比较 dst → WPM）——机器绑定态 = buffer 键块
  （壳运行时算好 = 本机值），静态 payload（KEYPATCH）无法表达动态复制。
  机制落地（U17 实测执行）。
- **U17**：KEYCOPY 0-10000-34（buffer [0,52) 13-dword 本机键 → struct
  [0x10000,+0x34)）+ U11 buffer patch → 对话框文案零变化 → **校验 ≠ struct
  前 13 dword vs buffer 键块比较**。
- **fp 原版已灭**：全内存扫描（corrupted dialog 活体）——原版
  5E66-5E6D 零副本；3 副本（0x582740 堆/0x102135e/0x10228ba image）全部 =
  重组后本机 fp；buffer/struct 区零 ASCII → **fp 重组 = 原地覆盖，fp =
  确定性不是门**。
- **下一步（精确）**：corruption 检查 op 定位 = 消息写入点（0x102133e/
  0x102289a）的写入者追踪——①EIPHIST 全线程轮询（校验可能非主线程或
  采样间隙错过）；②DR3 写监视（0x102133e，post-attach 无调试端口 = 异常
  落壳 SEH 链——需验证壳是否透明转发）；③消息模板静态引用交叉
  （closehandle 图扫模板地址 → push imm32 引用 = 校验调用点静态定位）。
- 工件：dw132_runU17.log、patch_keycopy.py。

**续 22 补充 132j（2026-11-20）——MSGTRAP：校验定位 @250ms + worker 池流水线结构实锤**：

- **MSGTRAP 仪器**（MAGICMIDA_V2_MSGTRAP=1）：0.2ms 轮询 corruption 消息写入点
  （0x102133e/0x102289a），首个非零 → **SuspendThread 全进程 + 全 27 线程
  context/stack dump**（443KB）。**校验 = t=250ms**（非 4-9s！）。
- **worker 池流水线实锤（27 线程返回链）**：多数线程 = ntdll 等待
  （77bf837c/77bf869c）+ 返回链 = **[自身 op 地址， 0x102002b 公共调度器，
  op2, op3, op3]**；op 地址跨线程顺序展开（0x109E388/0x109F568/0x10A0700/
  0x10A1260/0x10A1CCD/0x10A2754/0x10A3385/0x10A1FEF...）= **ops 区
  0x109E000-0x10A4000 = 流水线阶段表**，0x102002b = 派发循环（per-build）。
- **U17（KEYCOPY）**：buffer [0,52) 13-dword 本机键 → struct [0x10000,+0x34)
  连续复制 = 对话框零变化 = 校验 ≠ 该比较。fp 原版 5E66-5E6D 全内存零副本
  （重组 = 原地覆盖）= fp 确定性不是门。
- **下一增量（精确）**：MSGTRAP 瞬间同步 RPM ops 区 [0x109E000,0x10A8000)
  （解密态！dump 后即重加密）+ 0x102002b 调度器 disasm → 流水线各阶段
  反汇编 = 绑定校验 op = 比较逻辑 + 输入源直读。
- 工具坑：windows 0.58 = CreateToolhelp32Snapshot/OpenThread 返回
  Result（match/.ok()）；let-else 块内多语句需括号包裹。
- 工件：dw132_runU18.log、CISC-1U.msgtrap.bin（27 线程 dump）、
  patch_msgtrap.py、patch_keycopy.py。

**续 22 补充 132k（2026-11-20）——MSGTRAP 瞬间 ops 区解密态捕获成功（流水线可反汇编）**：

- **MSGTRAP 扩展**：trap 瞬间同步 RPM **ops 区 [0x109E000,0x10A8000) 40KB
  解密态**（msgtrap_ops.bin）+ 调度器 [0x1020000,+0x100)（msgtrap_disp.bin）。
- **流水线阶段 = 解密态活体**（capstone 反汇编 6 阶段全部有意义）：
  call-pop 锚点混淆（call $+8 / pop ebp / sub ebp, imm32 / 数据窗口
  折叠寻址）+ 每阶段 prologue = push 0 / push reg / call $+8 / pop reg /
  **mov [esp+4], reg / add [esp+4], imm**（窗口偏移 0x15/0x14/0x17/...）/
  inc reg——真实 op 代码，逐阶段可读。
- 调度器 0x102002b = trap 时已重加密（零/密文态）= per-run 解密。
- **下一增量**：逐阶段全量反汇编（0x40KB 已在手）→ 绑定校验 op = 比较逻辑
  + struct [0,0xC0) 引用定位 → 本机 48 dword 绑定值计算。
- 工件：CISC-1U.msgtrap_ops.bin（40KB 解密态）、msgtrap_disp.bin、
  dw132_runU19.log。

**续 22 补充 132l（2026-11-20）——绑定访问图谱：struct+0x78 = 19 次 call（字段迭代调度实锤）**：

- **锚点机制实锤**：call-pop 锚点调整（pop ebp; sub ebp, 0x122DE379）=
  **0x109E38D − 0x122DE379 = 0xEEDC0014 = CHECK MAGIC**（12 阶段全部
  magic-anchored）——magic-relative disp 的高 16 位 = 常数 0x1226 →
  **原始字节扫描 ?? ?? 26 12 = 全部 struct 引用指令定位器**（481 站点，
  落在 image [0x1020100,0x1023400) = 许可数据区）。
- **绑定区访问图谱**（[0x1020139,0x10201F9) 48 dword 过滤 = 33 站点、
  11 偏移）：**struct+0x78 = 19 次 call = 字段迭代调度实锤**（19 =
  字段数！）；数据访问 = +0x44/+0x5c/+0x68/+0x74/+0x7c/+0x88/+0x98/
  +0x9c(sub)/+0xa4/+0xb8（mov 为主）。
- struct+0x78 的 19 次 call = 通过绑定槽调用 per-field op = **字段迭代
  = call 转发结构**（非 esi 步表！）。capstone 逐指令解码（对齐回溯
  8B 匹配 disp）。
- **下一增量**：struct+0x78 的 19 次 call 的目标（call [ebp+d] 的指针
  值 = 运行时读 struct+0x78 的实值）+ 19 个字段 op 的反汇编 = 比较
  逻辑；绑定值计算 = 已知明文差分（struct+0x44/0x5c/... = 数据字段
  = vmhash 输入源）。
- 工件：CISC-1U.msgtrap_ops.bin（40KB 解密态）+ 绑定图谱脚本输出。

**续 22 补充 132m（2026-11-20）——struct+0x78 = JIT 原生字段校验函数实锤**：

- **活体读 struct+0x78**（U20 dialog 态，ba=0xbf0000）：指针 = **0x075f4206 =
  堆上可执行区**（非 VM ops！）——capstone 反汇编 = **编译器风格原生码**
  （cmovg min/max 模式、[ecx+0xc/0x14/0x1c] 结构化字段访问、[esp+0xc/0x10]
  调用参数）= **壳把字段校验 JIT 编译成堆上原生函数**，19 次 call = 同一
  JIT 函数逐字段调用。
- **含义**：字段校验逻辑 = JIT 代码 = 完整可反汇编（无 per-run 重加密！
  = 编译一次常驻）→ **比较逻辑直读路径全通**：dump JIT 区（0x75f4206±
  0x1200）→ 重建校验式 → 本机绑定值可计算。
- 下一增量：①JIT 区全量 dump + 反汇编（校验式重建）②JIT 函数的输入
  = [ecx] 结构 = 字段表定位 ③差分：改 buffer 输入 → JIT 行为对比。
- 工件：dw132_runU20.log（活体指针读）。

**续 22 补充 132n（2026-11-20）——JIT = 惰性填充定案（trap 时指针已置、代码未写）**：

- **MSGTRAP 扩展 JIT 捕获**（struct+0x78 → dump ±0x1200 → msgtrap_jit.bin）
  实测：trap @251ms 时 **ptr = 0x75f4206（与 U20 同址 = per-boot 确定性堆分配）
  但代码区全零** = **JIT = 惰性填充**（指针预置、代码首次调用时写）。
- U20 的 13s 活体读 = 代码完整 ✓（132m 的反汇编 = 有效）。**JIT dump 的
  正确姿势 = dialog 后活体读**（fpfind.py 模式），非 trap 瞬间。
- msgtrap_jit.bin（9216B 零态）= 惰性填充的证据工件。
- 下一增量 = 不变：dialog 态活体读 JIT 区（0x75f4206±0x1200）→ 全量
  反汇编重建校验式 → [ecx] 字段表 → buffer 差分 → 本机绑定值。

**续 22 补充 132o（2026-11-20）——字段校验式完整解码：搜索 = 链表扫描实锤**：

- **U23 dialog 态活体 JIT dump**（jit_full.bin 8KB，JIT ptr = 0x75f4206 =
  per-boot 确定性 ✓）。校验函数全解码：
  - **链表扫描**：[eax+0x2b4] = 链表头（eax = [ebp-0x1c] = 上下文结构），
    节点遍历；**循环上界 = 0x100（256 元素）**
  - **节点布局**：+0x7c = KEY1、+0x80 = KEY2、**+0x78 = 7-dword 数据区**
  - **比较**：节点 [0x7c/0x80] vs **[ebx+4]/[ebx+8]（本机键块！）** →
    全等 → **7-dword 数据区逐 dword 比较**（ecx=节点+0x78 vs edx=ebx，
    ebx=0x1c 计数）→ 全等 = HIT → mov [esi], 结果 + call [0x7be920c]
  - 入口 esi = 0xa8e907（结果槽/状态）
- **19 次 call = 同一链表扫描函数 × 19 个链表/键组**；ebx = 调用方传入的
  本机键块（= buffer [0,52) 的 13-dword 键 = KEYFORGE 键！）。
- **forge 方程更新**：链表节点 = 从许可数据构建 → 节点键 = license 的
  键值 → 扫描 vs 本机键 → **节点必须含本机键 = 许可数据 = 本机键**
  （buffer patch = U11 已做 → 流程推进 ✓）→ 对话框 = 下一道门（绑定
  校验 = fp/绑定字段）。
- 工件：jit_full.bin（8KB 活体 dump）、dw132_runU23.log。

**续 22 补充 132p（2026-11-20）——JIT = 每 run 不同函数定案 + MSGTRAP 冻结窗口验证**：

- **JIT-only trap（U26）**：MSGTRAP 改为只轮询 JIT 区非零（惰性填充 = 首次调用
  瞬间）→ trap @311ms，38 线程冻结，进程保持挂起态（活体分析窗口！）。
- **同 VA 不同码定案**：0x75f4206 = 堆复用 VA——U23 run = 链表扫描 fn、
  U26 run = min-max fn（编译器风格）→ **struct+0x78 指针 = 每 call 重写 =
  19 次 call = 19 个不同 JIT 函数**（非同一函数 ×19）。
- **MSGTRAP 冻结窗口验证**：挂起态进程 = 活体分析窗口（JIT 已填充可 dump、
  全内存可 RPM）——解析/差分实验可在冻结进程上无限期进行。
- 工件：CISC-1U.msgtrap.bin（38 线程）、jit_live.bin。

**续 22 补充 132q（2026-11-20）——调用序列时序定案：消息 @250ms → JIT 填充 @308ms → 19 calls 之后**：

- **MSGTRAP 扩展**：JIT-only trap + **call-target 序列记录器**（0.2ms 轮询
  struct+0x78，去重连续）+ 序列 dump（msgtrap_seq.bin = targets + 每 target
  0x200 代码）。
- **时序定案（U26c）**：消息写入 @250ms → **JIT 填充 @308ms**（代码首次写 =
  trap 时刻）→ **19 calls 在填充之后**——recorder [250,308] = 捕获的 =
  填充前垃圾值（0x1fbec35f，struct+0x78 填充前 = 复用态）。序列记录器
  必须跑在 **填充后窗口** [308, ...]。
- **targets=1 的含义**：recorder 窗口内 = 单一去重值 = 填充前态。19 calls
  = 填充后 µs 级间隔 = 轮询不可分——**目标捕获需冻结时刻读**（填充后
  SuspendThread 即读 struct+0x78 = 中断在 calls 中间）或填充后连续采样。
- **修正链**：132m（同一函数）→132p（19 个不同）→**132q（19 calls =
  填充后执行，fill 后指针值 = 有效目标，132m 模型大概率正确但待
  填充后读数确认）**。
- 下一增量：MSGTRAP trap 后（JIT 非零即 SuspendThread）读 struct+0x78 =
  **首个有效目标** + dump 0x200 代码 = 字段 op；后续 calls = 同 fn 或
  不同 = 由 [0x10078] 的连续读数（trap 后主线程恢复前多读几次）判定。
- 工件：dw132_runU26c.log、CISC-1U.msgtrap_seq.bin（targets=1 + 0x200
  零代码 = 时序证据）。

**续 22 补充 132p2（2026-11-20）——两段式动态 poll + JIT 编译门控实锤**：

- **两段式动态 poll 落地**（U27-U31）：每轮重读 struct+0x78（指针逐 call
  重写）→ 合法指针 → 轮询其代码非零 → trap。修正链：硬编码 0x75f4206
  （stale VA = 堆复用 false-trigger）→ 首值锁定（指针变化后失效）→
  **每轮重读 = 正确形状**。
- **JIT 编译门控实锤（U30/U31 对照）**：U11 keys payload（本机键）=
  **JIT 编译 @0x75f4206 填充 @300ms**（filled JIT caught ✓）；U24 markers
  payload = **无 JIT**（15s 零填充）→ **JIT 编译 = 由 buffer 内容门控**
  （本机键 → 编译；markers → 校验早退）。
- **trap 时刻 = mid-fill**（检测到首字节非零即挂起 = 代码部分写入——
  msgtrap_jit.bin = garbled 半成品；**完整代码 = dialog 态活体读**
  （U20/132o 已有 = 链表扫描全解码 ✓）。
- **下一步收敛**：校验式 = 已解码（132o 链表扫描）→ 剩余 = CALC 对话框的
  fp 门 = buffer 的 fp 字段定位（原始 fp @buffer 未知偏移，b15 的
  0x10228ba = image 副本；buffer 原始态 = 未 patch 的早期 run 可读）→
  fp 中段 5E66-5E6D → 254D-9F3C patch → CALC 通过。
- 工件：dw132_runU27-U31.log、msgtrap_jit.bin（mid-fill 态）。

**续 22 补充 132s（2026-11-20）——fp 不在 buffer（二进制组装）+ U11 patch = .dat 自毁实锤**：

- **FPLOCATE 实测（U32）**：buffer [0,480) 于 [150,1500]ms 扫 '1051-BCEC'
  = **零命中**（off=None）→ **fp 字符串不在 buffer 明文** = fp 由二进制
  字段运行时组装（base 段 + 机器中段 + dash 格式化，229ms 写入 image
  0x10228ba 区）。
- **U11 patch = .dat 自毁实锤**：buffer [52,480) = keys 覆盖 = **.dat 的
  内部完整性校验被自己破坏** → "Your license key is corrupted" 对话框 =
  **我们 patch 的后果**（非壳的另一道门！）——无 patch = 搜索 miss = 崩溃；
  粗暴 patch = 校验和破坏 = corrupted 对话框。
- **forge 正确形状 = 外科手术式 patch**：只改节点键源字段（搜索命中所需），
  保留 .dat 校验和字段。节点键源 = 节点构建读 buffer 的偏移 = 待定位
  （链表头 [ctx+0x2b4] → 节点键值 → buffer 源偏移反查；ctx = MSGTRAP
  冻结态寄存器/栈可读）。
- 下一增量：①MSGTRAP 冻结态读 ctx（JIT fn 的 [ebp-0x1c]）→ 链表头 →
  节点键值 ②节点键值 → buffer 偏移反查（节点值 = buffer[X] 的解码形式）
  ③外科 patch：仅 X 处 = 本机键，其余原样。
- 工件：dw132_runU32.log。

**续 22 补充 132t（2026-11-20）——节点数组定位实锤（8B 步距 key 对阵列）**：

- **活体扫描（U33 dialog 态）**：相邻 [KEY1][KEY2]（0x7DC80DE6/0x022869C8）
  对全内存扫描 = 53 命中，**首簇 @0xb80052 起步距 8 字节连续对** =
  **节点阵列实锤**（搜索的语料 = [KEY1][KEY2] 8B 对的数组，本机键 =
  U11 buffer patch 已生效 = 搜索命中 ✓）。
- **阵列 = buffer 派生副本**：对值 = 本机键（uniform）= U11 patch 的
  buffer [52,480) 重建 → 源映射 = uniform 不可差分（marker 法 noise 墙）
  → 精确源偏移需节点构建 op 反汇编（msgtrap_ops 阶段已捕获）。
- **链表模型修正**：JIT fn 的「链表遍历」= 该阵列的顺序扫描（[ecx+0x7c/
  0x80/0x78] = 节点内偏移，ecx = 节点指针步进），非 pointer-linked。
- 下一增量：①msgtrap_ops 阶段反汇编 = 节点构建 op（buffer→阵列的复制
  逻辑与偏移）②阵列补丁 = 直接 WPM 阵列（本机键已在 = 无需）③CALC
  对话框 = 阵列命中后的下一道门 = fp/绑定校验 = 定位其检查点（消息
  写入点 0x102133e 的写入者 = msgtrap_ops 阶段反汇编）。
- 工件：dw132_runU33.log、fpfind.py（相邻对扫描扩展）。

**续 22 补充 132u（2026-11-20）——check-op 折叠引用全图（76 目标）+ 节点构建时代定位**：

- **check-op 折叠引用全图**（12 阶段 × 0x400B 全量反汇编，magic+disp 收集）：
  **128 distinct targets，76 落 image 许可区**——struct 头区（+0x44/+0x78
  call/+0xa4/+0xe8...）到 +0x1850 全覆盖 = **校验 op 的 struct 访问完整
  引用地图**（每次 1 ref = 单字段单访问；0x102044d = add/sub 对 = 校正；
  0x1020561 = inc ×3 = 计数器）。
- **阵列（0xb80052 堆）= 折叠图无引用**（堆 = 动态基址寄存器访问，非
  magic 折叠）→ **节点构建 op = 更早时代**（解码 era [189,220]ms，节点
  随解码成形）= MSGTRAP（250ms）之前 → **DISPATCH-SNATCH @ 解码 era**
  （补 85 现成工具）= 节点构建捕获路径。
- **校验逻辑状态**：搜索 = 已解码（132o 链表扫描）；check-op 引用图 =
  已建（132u）；剩余 = ①节点构建时代捕获（DISPATCH-SNATCH）②CALC
  对话框检查点 = 0x102133e 写入者 = check-op 阶段中（76 引用图的
  0x102132d struct+0x11f4 mov = 消息区写入候选！struct+0x11f4 =
  0x102132d = **corruption 消息写入点 = check-op 内实锤**）。
- 工件：msgtrap_ops.bin + 折叠图脚本。

**续 22 补充 132v（2026-11-20）——BLKSTREAM 解码 era 捕获尝试 + 会话收口状态**：

- **BLKSTREAM 运行（U34）**：KEYBUF keys + BLKSTREAM=1 → 流程 = dialog 挂起
  形状（CISC-1 37MB 存活）→ **blkstream.bin = 循环结束才写 = dialog 挂起
  阻塞捕获**。解法 = dialog 程序化 OK（U13 已验证 = exit 2 → 流程结束 →
  文件落地）或 BLKSTREAM 窗口截断改进。
- **会话收口状态（全链路可读 + 仪器就绪）**：
  - 校验 = JIT 链表扫描（132o 全解码）；搜索命中 = buffer patch 解决（U11）
  - CALC 对话框 = .dat 完整性被粗暴 patch 破坏的后果（132s）→
    **外科 patch = 仅节点键源字段**
  - 节点构建 = 解码 era（132u）→ BLKSTREAM 捕获 = 下一会话首步
  - 仪器链：KEYBUF/KEYCOPY/PASSPATH/MSGTRAP（冻结+ops/JIT/seq）/EIPHIST/
    FPLOCATE/fpfind 全就绪
- **下一会话路径**：①BLKSTREAM + dialog OK 程序化关闭 → 解码 era op 带 →
  节点构建 op 定位 ②外科 patch（仅键源字段）→ CALC 通过 → 部署启动 =
  forge 全闭环。

**续 22 补充 132w（2026-11-20）——BLKSTREAM 写入路径调查（会话收口）**：

- **BLKSTREAM = FAIL_MARK-gated 且窗口 [150,300]ms**：U37 pristine =
  FAIL_MARK @366ms（窗口已关）→ 无文件；U36 markers = dialog 挂起（无
  FAIL_MARK）→ 无文件；U35 keys + OK = bail return 跳过 dump 段 → 无文件。
- ** unconditional flush 修复**：插入 per-iteration 写（U38）→ 文件仍缺席
  = **BLKSTREAM 块本身未进入**（门控/窗口需下轮排查——候选 = 块入口的
  分支条件或 blobs 空判）。
- **会话最终状态**：校验逻辑全链路可读（搜索=链表扫描/JIT/check-op 引用
  全图/节点阵列）；仪器链完整（KEYBUF/KEYCOPY/PASSPATH/MSGTRAP/EIPHIST/
  FPLOCATE/fpfind）；forge 最后一步 = ①BLKSTREAM 块入口排查 → 解码 era
  op 带 → 节点构建 op ②外科 patch（仅键源字段，保留 .dat 校验和）→
  CALC 通过 → 部署启动。
- 工件：dw132_runU34-U38.log。

- 工件：dw132_runU34-U38.log。

**续 22 补充 132y8-132y17（2026-11-20/21）——forge 全闭环打通：license 检查全过 + 部署到达**：

- **132y8 = verdict 语义定案（msgtrap_ops.bin 40KB 逐指令深读）**：16 个
  counter 检查站点交替 `cmp [0x1022d3d],0x7d0` + 8×`jbe`（≤2000 → pass
  续链）/8×`jne`（≠2000 → `push [X]; call [0x10201b1]` fail handler）—
  **verdict = 精确相等 [0x1022d3d]==0x7D0**。U53 清零（0）：jbe 全过但
  jne 全挂 → 对话框；U43 的 0x7D1 同理。0x7D0 从未被测过。CTR-HOLD
  仪器（专用 no-sleep 线程 [140,420]ms，值分歧即重写 0x7D0）。
- **132y9 = NOBAIL**：U54（counter=0x7D0）failfreeze 场景显示 bank 携带
  **"This application has been registered to\n\r(CISC-1) Examples -
  LCF-AT" 成功消息指针（0x1182522）** = counter 门已过、流程推进，
  但 CLI 自己的 FAIL_MARK bail-kill 杀掉了本已通过的 run！NOBAIL env
  = 跳过 kill（两个 bail 站点）。
- **132y10 = freeze 深坑**：dump_failfreeze_scene 挂起全线程不恢复 →
  对话框线程不泵消息 → 点击无效。NOBAIL = 连 freeze dump 一起跳过。
- **132y11 = 跨桌面消息坑**：跨桌面 PostMessage 返回 0（hwnd 失效）—
  **必须 SetThreadDesktop(MagicmidaV2Desktop) 后再投递**；BM_CLICK +
  WM_COMMAND IDOK 双发。U57：双对话框（corrupted+registered 并存 =
  420ms 后 hold 过期、重检读回 0x7D1）→ dismiss 后流程推进、进程退出。
- **132y12 = GATEPATCH**：CTR-HOLD 窗口扩到全程（U57：hold 420ms 过期 →
  .dat 重载回 0x7D1 → 重检 fail）。pattern-scan + NOP 仪器。
- **132y13 = 重跑链发现**：dismiss 后壳在 ~2.1s 从 .dat 重载重跑整条
  检查链（CTR-HOLD 捕获 0x7D1 回归）→ patch 窗口 = 全程。
- **132y14 = 绑定门真身（U60 停泊场景解码）**：fail 续链 = 0x10768A2
  派发器；FP 公式门 @0x117611f：`fistp [0x1022529]`（value =
  frndint((X−Y)/Z)，三个 qword @0x1111F2B/33/3B）→ `0 < v ≤ 0x80000000`
  = pass，否则 eax=5 → jmp [0x10252C6] = "locked" 消息链。**公式 =
  许可自身字段的自洽校验——被 KEYBUF 的 keys 模式破坏**。patch =
  NOP je + 强制 jbe taken（E9 4E 00 00 00 90）。
- **132y15 = 模块导出完整性门（0x10B75F8）**：对模块 live PE 的每个
  export RVA 检查 ∈ [.text_VA, .rsrc_VA)，出界 = eax=5 → fail。patch =
  fail 派发（lea/mov eax,5/jmp ebx）→ `61 C3`（popal; ret）。扫描 = 
  **VirtualQueryEx 全用户空间 VAD 走查**（低 12MB 带不含重跑链的
  fresh 副本；MEM_PRIVATE 过滤 = 误筛，去掉）。
- **132y16 = MSGTRAP2 v3（轻冻结）**：重 576KB dump（200ms 挂起）=
  破坏运行；v3 = needle 触发（0x1021300 区出现 "locked to a
  different"）+ 只 dump 上下文与 Eip±0x1000（毫秒级）。实锤：
  冻结瞬间全线程 ntdll 等待（主线程 = NtUserGetMessage 消息泵）=
  fail 路径异步 posted，检查在消息写入之前已完成。
- **132y17 = STACKPASS（NOWRITE 形状复活）**：fail 值在 VM 栈上预备
  （0xEFE74/0xEFECC：`[0xFFFF8441][0x0102133E/3D]`）再写 bank。重写
  预备对 → pass 对 `[0xFFFFA595][0x01182522]`（registered 模板）。
  **U75/U77 = 复现成功**：仅 registered 消息（"locked" 完全消失！）、
  WS 121MB（VA 0x1EB000 = 解密的真代码 `mov eax,0x0b600000...`）、
  流程推进到部署，尾部 0xC0000005（OEP 跳转段，下一增量）。
- **forge 全链 = 七件套**：KEYBUF（本机键 [52,384)）+ CTR-HOLD
  （counter≡0x7D0）+ NOBAIL + GATEPATCH（sig1 派发器 jne / sig2 flag
  jmp / sig3 FP 公式 / sig4 模块导出，VAD 全空间走查）+ STACKPASS
  （VM 栈 fail 对 → pass 对）+ 自动 dismiss（SetThreadDesktop + 
  BM_CLICK/WM_COMMAND）。部署后崩溃 = 唯一剩余（OEP 段）。
- 工件：dw132_runU54-U77.log、u60_*.bin（停泊场景：struct/ops0/ops1/
  priv/buf）、u65/u72_parkpid、msgtrap2 snap 1-6、patch_132y8-y17.py、
  deepread_ops2-4.py、scan_dispatch.py、run_u54.py。**续 22 补充 132x（2026-11-20）——专用早启 BLKSTREAM 线程：解码 era 时间线捕获成功**：

dw132_runU54-U77.log、u60_*.bin（停泊场景：struct/ops0/ops1/
priv/buf）、u65/u72_parkpid、msgtrap2 snap 1-6、patch_132y8-y17.py、
deepread_ops2-4.py、scan_dispatch.py、run_u54.py。

**续 22 补充 132y18-132y19（2026-11-21）——0xC0000005 定案 = 缓存异常重放 +
 dismiss 机器修复 + 部署态到达（138MB 无崩溃）**：

- **dismiss 机器三连坑（本轮全部实测）**：① `GetThreadDesktop(对端线程)`
  现在 gle=5 ACCESS_DENIED（132y11 时代可行，环境已变）——改用
  `OpenDesktopW('MagicmidaV2Desktop')` + `SetThreadDesktop`（成功）。
  ② **PostMessage 投递成功但永远不被执行**（r=1、对话框永不关闭）——
  **SendMessage（同步）才是有效点击**（probe5：BM_CLICK → 对话框关闭 →
  流程推进 → 0xC0000005 复现 ✓）。③ 对话框线程停泵后 SendMessage 会
  **挂死调用方**——必须 `SendMessageTimeoutW(SMTO_ABORTIFHUNG, 1.5s)`。
  `GetWindowTextW` 跨进程发 WM_GETTEXT，停泵线程同样挂死枚举方——
  枚举一律 GetClassNameW（对象本地、无消息）。
- **崩溃复现 + 时代态全捕获（新仪器 132y18）**：EIPHIST2（主线程采样，
  WOW64 上 GetThreadContext 对运行线程必须 SuspendThread+3×retry）、
  CRASHPOLL（崩块窗口 [0x1027800,0x10278A0) µs 轮询 + 时代快照）、
  v2_era_snapshot（stksnap1=pair-prep 轻快照 / stksnap2=fault 即时重快照
  + 全私有空间常量扫描）。**关键测量**：块字节自 245ms 起恒定 = 与 WER
  dump 逐字节相同（「重加密致陈旧」假说作废）；stksnap2 在 t=2600ms
  冻结到 fault 线程的精确寄存器（Eip=0102786F Eax=54831A79 Esp=B8C933A4
  Ebp=EEDC0014）；**Esp=0xB8C933A4 = 0x102786B 处的 dword（块自身
  movsb 字节）**；候选 2 = Esp=0x2522FFFF = STACKPASS pass 对字节流
  +2 处——脱轨读上下文槽时把代码/对数据当 ESP。
- **0xC0000005 = 不是真页面错误（决定性）**：VALLOC2 把 0x54830000+
  0x20000 在 t=1ms 预映射（RW），崩溃 dump 时该区域 state=MEM_COMMIT
  prot=PAGE_READWRITE——**页面已提交可写仍然 fault**；且 Eax=54831A79
  与 Eip 值 0x102786F **在全内存 dump 中不存在**（堆/镜像/栈全扫 0 命中
  ——值是算出来的、从未存储）。定案：**部署时代的 fault = 壳重放
  「缓存的 verifier 时代内部异常」**（补 132 旧结论「UE filter 打印
  缓存的 verifier-era 内部异常」的机制实锤）——Eip/target/寄存器组 =
  缓存记录的字段，Ebp=EEDC0014 = 构造上下文的 magic。
- **缓存的内容 = era-1 搜索 miss 状态**：KEYBUF（buffer 补丁 = 搜索
  命中）→ 无重放 ✓（3 run 全部越过 fault 时代存活）；VALLOC 预映射
  （era-1 的写落地、无 fault）→ 重放仍然发生 = **缓存的是 miss 状态
  本身而非 fault 事件**。NOPPATH2（连续 NOP 站点）= 同样无崩溃但 era-1
  流程被过早改道（早期停泊 14-22MB）。
- **buffer 双重身份冲突 + KEYBUF2 窗口化（132y19，第五件 patch）**：
  buffer 被【搜索】（需要本机键 [52,480)——U11/U13 解锁）与【部署时代】
  （需要真 license 字节——持续 KEYBUF = 部署前停泊 25-50MB 振荡，实测）
  双方读取。**KEYBUF2 = 窗口化独立线程**：仅 [40,2500]ms 打补丁（era-1
  搜索命中 + era-2 重载重搜命中），2500ms 后停手让部署读到真字节。
  实现坑：①needle 扫描必须 4 字节 memcmp 前缀 + 全 16B 验证（逐字节
  Rust 循环太慢）；②**原始 .dat 副本只活 [150,300]ms**（读后即擦；
  U13-era DECODEWATCH 在 t=174ms 抓到，buf=0xd10000）——首扫限定
  [0x100000,0x2000000)（buffer 在 0xC70000-0xFE0000）+ rescan 40ms；
  ③needle 不保证 16B 对齐。**结果：部署态到达 = WS 138MB @5s、运行
  39s+ 无崩溃**（pollws2 实测）——第五件 patch 完成。
- **部署后下一门**：138MB 稳定态 = 壳停在 payload-launch 等待（V2
  CreateThread 捕获零命中、无 OEP 转移）——0x1EB000 页 = 真
  continuation 块族（`b8 imm32 / 0b c0 / 74 68` 同族形状）已解密。
  下一个增量 = 部署后 launch 门。
- 过程坑：python 长探针挂在 GetWindowTextW（改 GetClassNameW）；psapi
  GetProcessMemoryInfo 要从 windll.psapi 取；RPM 跨未提交洞整段失败
  （快照读必须 4KB 分块）；esp-page 循环的 nctx 用 blob 长度推 = 读
  风暴（41 线程 × 2KB × ~1700）；MSYS 相对路径 `../src/...` 启动 CLI
  失败（用 python launcher + 绝对 Windows 路径）。
- 工件：pollws2.log（138MB 部署态）、stksnap1/stksnap2（pair-prep +
  fault 即时）、crashpoll_u79_*.bin、era_u75_*.bin（WER 时代态）、
  patch_132y18.py-y19c.py、run_u79b/c/d.py、poll_ws.py、
  probe_deploy.py、probe5-8_out.txt。- **根因定案**：主 watch 循环步距 ~370ms → BLKSTREAM 首达 ~370ms > 解码 era
  末（220ms）= **结构性不可捕**。修复 = **专用早启线程**（0ms 起，[140,320]ms
  1ms 级轮询 bank 态 ca/cb，变化即记录，FAIL_MARK 即停）。
- **解码 era 时间线实锤**（56 记录，U39，blkstream_early.bin）：
  - t=160-177ms：ca = **0x3530025→0x35301C2 顺序走读**（步距 ~0x35）=
    **节点构建写入期**（buffer 明文区顺序写 = ba+0x25 起）
  - **t=183ms：ca = 0xEEDC0014 = CHECK MAGIC 装载**（校验锚点就绪）
  - t=185-187ms：收尾/中断态
  - t=274-319ms：ca = **0x3540000（struct 页 = ba+0x10000！）** 与
    0x1021axx（ops）交替 = **check era**
- **结构映射**：ca = 机器指针（写游标）——节点构建 = buffer 明文顺序写
  （[160,177]ms），校验 = struct 页 + ops（[274+]ms），magic 于两者间
  装载。节点键源 = buffer [0x25,0x1C2] 区（构建期写入）。
- **下一增量**：①构建期 ca 走读 × 节点阵列差分（buffer[X] → 阵列[Y]
  映射）②外科 patch（仅节点键源 X 区 = 本机键，保留校验和/尾区）→
  CALC 通过 → 部署启动。
- 工件：CISC-1U.blkstream_early.bin（56 记录时间线）、dw132_runU39.log。

probe_deploy.py、probe5-8_out.txt。

**续 22 补充 132y20（2026-11-21）——部署后 launch 门侦察**：

- **dismiss 机器第四坑**：`SendMessageTimeout(WM_COMMAND/IDOK → 对话框
  本体)` **无限挂死调用方**（SMTO_ABORTIFHUNG + 800ms 全部无效，实测
  trace 停在 'send IDOK' >90s）——childed 对话框只发 BM_CLICK→Button、
  childless 只发 PostMessage WM_CLOSE，两者都 fire-and-forget。
- **对话框序列实测**：部署时代（WS 138MB）出现 childless CALC 对话框
  （title='CALC'、style=0x94C801C5、无子控件、文本非消息区
  ——0x1021300/0x1022800/0x102289a 在部署态全空），PostMessage
  WM_CLOSE 可关；后续 pass dismissed=0 = 序列走完（单对话框）。
- **walk 后停泊不变**：对话框全关后壳仍 137MB 停泊——主线程
  GetMessage 泵（win32u+0x123C ← user32+0x8FA39）、全部线程内核等待、
  **payload PE 从未物化**（V2 watch 的 image 扫描 10263 次
  「image filtered out」全部 = 系统 DLL，无未知镜像）。
- **定案**：launch 门 = 壳内部 verdict 状态机等待（132 时代
  「哨兵 verdict 0x20CF1 累积恒 0」同型）——forge 过了全部可见门
  （counter/binding/verifier/search/deployment）但壳内部累积裁决
  仍未触发完成事件。V2 CreateThread 捕获（mod.rs CreateThread
  handler + try_v2_watch_scan）在 post-attach 模式照常运行，payload
  一旦物化即可捕获——当前缺的是壳侧 launch 触发，不是捕获侧。
- 下一增量 = 部署时代 verdict 状态机（哨兵/累积槽在部署时代的
  读写者定位 + 与 132y19 的 KEYBUF2 窗口交互）。
- 工件：seq1-6.log（137MB walk）、dismiss_once.py（WM_CLOSE/
  BM_CLICK 快速版）、pollws1-3.log。**续 22 补充 132y（2026-11-20）——节点键源确认 + fp 二进制源不在常规区**：

seq1-6.log（137MB walk）、dismiss_once.py（WM_CLOSE/
  BM_CLICK 快速版）、pollws1-3.log。

**续 22 补充 132y20b（2026-11-21）——needle「可见性危机」= 测试假阴性 +
 KEYBUF 窗口化（真修复）**：

- **整个「needle 漏检」调查 = 测试 regex 假阴性**：clean-env 重测时
  `buffer located t_ms=184` **一直在**——regex `buffer located t_ms=`
  撞上 ANSI 包裹（`[3mt_ms[0m=`）恒失配。DECODEWATCH 的 buffer 定位 =
  每 run 可靠（182-184ms，buf=0xbc0000/0xdd0000）。教训：日志解析
  先剥 ANSI（grep 对 ANSI 包裹字段静默失配）。
- **真修复 = KEYBUF 窗口化（复用 DECODEWATCH µs 循环，弃 KEYBUF2
  独立扫描器）**：KEYBUF 的重写块加 2500ms 窗口（`ka & 0x8000_0000
  != 0 && t > 2500 → continue`）——era-1 + era-2 重搜在窗口内命中，
  部署时代读到恢复的真字节。DECODEWATCH 定位 buffer ~184ms 可靠 =
  独立扫描器（KEYBUF2）整体多余。
- **B 版对照链**：abwt worktree（cc34944）+ .cargo/config.toml 拷贝
  （忘拷 = i686 linker 找不到 w64devkit）→ cc34944+U13 env = 3/3
  located。旧测试（pollws/seq/needlevis1-4）全被两个假阴性污染：
  ①regex ANSI ②shell 导出泄漏（source run_env.sh 后全部后续
  python 继承全量 MAGICMIDA_V2_* env）。
- **launch 门 walk 结果**：部署态（138MB）CALC 对话框序列关完 → 壳
  仍 137-138MB 停泊（78s+）、payload 从未物化（image 扫描全 = 系统
  DLL）。定案：launch 门 = 壳内部 verdict 状态机等待（非对话框）。
  V2 CreateThread 捕获侧照常运行，缺的是壳侧触发。
- 工件：kw1.log（窗口化 KEYBUF 部署态 78s+ 稳定）、poll_keybuf2.py、
  dismiss_once.py（IDOK 禁发版）。- **节点键源确认**：U40 markers [0x25,0x1C2) → STRICT 扫描 = 0 命中 =
  节点键 ≠ 该区；U33 keys = 节点 = 本机键 ✓ → **节点键源 = buffer
  [52,384)（U11 patch = 已正确覆盖节点键源 = 搜索命中 ✓）**。
- **fp 二进制源未定位**：fp-words（1051/BCEC/14F2/0C18/3745 LE word 序列）
  在 buffer/struct = 零命中 → **fp 组装编码 ≠ LE-words**（字节序/变换/
  分散字段待差分）。
- **收敛判断**：节点键 = 已解（buffer patch ✓ 搜索命中 ✓）；CALC 门 =
  fp 绑定校验 = license fp-middle vs 机器 fp-middle → 机器 middle =
  254D-9F3C（已知）→ license middle = 待定位（fp 组装编码逆向 = 最后
  差分目标）。
- 工件：dw132_runU40/U41.log。

**续 22 补充 132z（2026-11-20）——校验阶段解码实锤：比较 vs 2000 + 常数 0x1FF94595**：

- **消息组装代码回溯成功**（msgtrap_ops 4 站点 @0x1021321/0x1021305/
  0x102132d/0x1021335）→ stage @0x109EAB4+ 反汇编 = **校验逻辑直读**：
  - mov [ebp+0x122601fd], edi = **miss 计数写入**（0x10201FD ✓）
  - mov [ebp+0x12262561], **0x1FF94595** = **常数写入**（struct+0x2428）
  - **cmp [ebp+0x12262d29], 0x7d0** = **比对 2000**（jne → 继续）
  - sub [ebp+0x1226130d], edx / jnp 链 / push 0 → call 链 = 下一段
- **含义**：校验 = 数值比较（vs 2000）+ 常数标记 + miss 写入 = **比较
  逻辑全可读**；fp-middle = 相邻 stage 的操作数（0x10a1ffd/0x10a3882
  阶段待解）。
- 下一增量：0x10a1ffd/0x10a3882 两 stage 反汇编 = fp-middle 读取源 =
  外科 patch 偏移 → CALC 通过。
- 工件：msgtrap_ops.bin + 本解码。

**续 22 补充 132aa（2026-11-20）——check stage 全解码：0x1020095 读 = fp-middle 候选**：

- **stage @0x10a1efd 全解码**（magic 折叠全标注）：
  - **mov esi, [ebp+0x12260081] → 0x1020095（struct+0xF4C）= 许可字段
    读取 = fp-middle 源候选**
  - lea ebx, [→0x1099faf]（ops 区）；add [0x1021305], edi（消息写 ✓）；
    call [0x1020449]（thunk ✓）；mov [0x10234fd], ecx（数据区写）
  - stage @0x109EAB4（前轮）= miss 写 + 常数 0x1FF94595 + cmp vs 2000
- **校验逻辑 = 全可读**：比较（vs 2000）+ 字段读（0x1020095）+ 常数 +
  消息组装 = 完整链条。
- **下一会话**：0x1020095 差分（改 buffer 输入 → 0x1020095 值变化？）=
  fp-middle 源确认 → 外科 patch → CALC 通过 → 部署启动 = forge 全闭环。
- 工件：msgtrap_ops.bin + 本解码。

**续 22 补充 132ab（2026-11-20）——0x1020095 差分阳性：fp-middle 源 = buffer 派生确认**：

- **双 payload 差分**（U42a keys / U42b markers，dialog 态活体读）：
  - RunA (keys)：0x1020095 = 00000000 01000000 **00585547**00000000
  - RunB (markers)：0x1020095 = 00000000 01000000 **00d26a16**00000000
  - **+8 dword 随 buffer 变化** = **fp-middle 源 = buffer 派生确认 ✓**
  - 值 = 变换后形式（≠ 输入原值，编码非平凡）→ 源偏移 = 二分定位
- **下一增量**：payload 二分（半区 keys/半区 markers）× log2(83)≈7 runs →
  源偏移 → 外科 patch → CALC 通过 → 部署启动。
- 工件：dw132_runU42a/b.log。

**续 22 补充 132ac（2026-11-20）——0x1020095 差分反转：+8 = per-run 随机值**：

- **二分驱动实测（8 runs 同 payload split=266）**：0x1020095+8 =
  0xf1167700/0x6b9b4700/0xc4f98c00/0xef9d7800/0x87de4700/0xe273d100/
  0x49fbd000/0x44720200 = **每次都不同**（低字节恒 00）→ **+8 = per-run
  随机值**（堆态/ASLR 类）→ **132ab 的「差分阳性」反转**（U42a/b 两 run
  差异 = run 方差非 payload 效应）。
- **fp-middle 源 = 仍未定位**；0x1020095+8 = 无差分价值。**校验逻辑 =
  全可读但比较输入源 = 需运行时 trace**（check-op 阶段的寄存器级观测 =
  MSGTRAP 冻结态寄存器 + ops 反汇编深读）。
- 工件：dw132_bisect_0-7.log。

**续 22 补充 132y2（2026-11-20）——战役级定案：corrupted = 执行次数限制（license 2000 次计数）**：

- **校验操作数冻结态直读**（U43）：cmp 操作数 @0x1022d3d = **0x000007D1 =
  2001 > 2000** → **校验 = 执行次数限制**（license 计数 2001 已用 > 2000
  上限）→ "corrupted" = **许可次数超限**（非 fp/binding！）！
- **counter 重置两轮**：①MSGTRAP @316ms 重置 = 太晚（检查 @250ms 已完成）
  ②早启线程 @142ms 预检查重置（0x7d1→0 实测 ✓）→ 被 .dat 重载竞速覆盖
  （解码 [189,203]ms 重载 2001 → 检查 @250ms 读回 2001 = fail）。
- **计数器 = .dat 持久字段**（解码装载）→ **持久修复 = .dat 计数器字段
  清零 = .dat 重编码**（= 既有 .dat 密码阻断）。
- **JIT 编译门控再解释**：keys payload → JIT 编译（流程推进到检查）；
  markers → 早退（检查前失效）。
- **下一增量**：①检查指令 imm patch（0x7d0→0x0000，per-run 解密时序
  阻断 = 需解密后检查前窗口）②.dat 计数器字段定位（密文中）+ 重编码
  ③解码装载后重置的竞速强化（µs 连续重置 = KEYCOPY 形状）。
- 工件：dw132_runU43-U45.log。

**续 22 补充 132y4（2026-11-20）——counter/imm patch 全执行仍 corrupted：检查读取超出可达态**：

- **全部 patch 执行**（U51）：counter 零化 @142ms ✓ + zero-imm patch
  @301ms ✓（16 站点）+ re-load-triggered imm patch（新加，live 值）→
  **CALC 对话框仍 corrupted**。
- **判定**：校验 = 读取超出全部可达态（运行时 counter 副本/imm 均
  patch 过仍 fail）→ **检查读取 .dat 原始计数器（密文侧直读）或
  per-run 深层状态**——运行时侧全部绕过无效。
- **剩余唯一路径 = .dat 计数器字段定位 + 重编码**（密文侧 = .dat 密码
  阻断 = 闭环）或 **check-op 全量反汇编的深读**（msgtrap_ops 40KB
  已捕获，比较逻辑逐指令）。
- 工件：dw132_runU46-U51.log。

**续 22 补充 132z2（2026-11-20）——计数器 = .dat 持久字段实锤（fail 后重置为 1）**：

- **校验操作数活体读**（U52 dialog 态）：**counter @0x1022d3d = 0x1**（= 本
  run 计数——壳 fail 后重置）+ **const slot = 0x1FF94595 ✓**（指令写入
  交叉验证）。struct/buffer/image-struct 全区扫 0x7D1 = 零命中（计数器
  只在 0x1022d3d 运行时副本）。
- **闭环定案**：counter = .dat 持久字段（解码装载 2001 → 检查 fail →
  fail 后重置 1）→ **壳 = 持续从 .dat 重载** → 运行时重置（任何节奏）=
  竞速必输 → **唯一修复 = .dat 计数器字段清零 + 重编码**（.dat 密码
  阻断 = 闭环回既有阻断）。
- **check 逻辑**（132z/aa 全解码）：比较 vs 2000 + 常数 0x1FF94595 +
  miss 写入 + 0x1020095 读 = 全可读；运行时绕过 = 全部竞速输。
- **forge 剩余 = .dat 重编码单点**（密码 = 壳自有实现 = 补 129-130
  阻断）。全部仪器/图谱/时间线已沉淀。

**续 22 补充 132y6（2026-11-20）——limit-raise patch 执行（2 站点）+ 全 patch 组合仍 corrupted（会话最终状态）**：

- **limit-raise patch 落地**（132y5）：ops 区扫 [0x1089000,0x1118000) 的
  0x7D1 dword → patch 0xFFFF。U52 实测：**patched_lim=2 @142ms**（2 站点；
  b15 的 98 站点 = 旧 run 快照地址，当前 run 仅 2 处该时刻可见）。
- **全 patch 组合执行**：counter 零化 ✓ + limit-raise ×2 ✓ + imm patch
  ×16 ✓ → **CALC 对话框仍 corrupted** = 校验 = 读取超出全部可达态
  （.dat 原始计数器/深层状态/或多层校验的更深一层）。
- **会话最终沉淀**（40 commits，92c2c5f→132y6）：校验逻辑全链路可读
  （搜索 = 链表扫描已解码、check-op 引用全图 128 targets、校验 stage
  解码、时序全定位、corrupted = 执行次数限制定案、fp 组装、.dat 自毁
  洞察、节点阵列、解码 era 时间线）；仪器链完整（KEYBUF/KEYCOPY/
  PASSPATH/MSGTRAP/EIPHIST/FPLOCATE/fpfind/BLKSTREAM-EARLY/limit-raise/
  counter-reset/imm-patch）。
- **forge 剩余路径（下会话）**：①limit-raise 站点全量（b15 的 98 站点
  = 需当前 run 的全时刻扫描）②.dat 密码深耕 ③check-op 40KB 逐指令
  深读（比较逻辑与输入源全图）。

**续 22 补充 132y7（2026-11-20）——连续 limit-raise = 仅 2 站点（当前 run 的 ops 全时刻）+ 会话终点**：

- **连续轮询修正**（去掉首批 break）→ U53：每轮 patched_lim=2（同 2 站点
  = 当前 run 的 ops 全时刻仅 2 处 0x7D1）+ counter 零化 ✓ + imm patch ✓
  → **CALC 对话框仍 PRESENT**。
- **会话终点定案**：全部运行时可达 patch 组合执行（counter/limit/imm）
  → corrupted 持续 = 校验 = 读取 .dat 原始态或 VM 深层状态 = **运行时
  侧绕过穷尽**。b15 的 98 站点 = 旧 run 的 ops 布局（per-run 差异）。
- **剩余路径**：.dat 密码深耕（补 129-130 阻断深耕）或 check-op 40KB
  逐指令深读。全部仪器/图谱/时间线已沉淀（40+ commits）。

**续 22 补充 132y21-27（2026-11-21）——停泊态全解码：MessageBox 临界区
死锁 + verdict="license corrupted" 实锤 + 第九/十件机器**：

- **VERDICTWATCH（132y21）**：7 哨兵槽（0x20CF1 累积/0x201FD miss/
  0x22D3D 计数/0x20449 gate/0x225260 cont/0x285B6 bank/0xEFE74 VM 栈对）
  1ms 轮询 90s → **部署停泊态零变更**（状态机完全冻结 = 等外部事件）。
- **fault 链逐站推进（132y22-24）**：①VALLOC2 映射写目标后
  `add [eax],al` 落地；②FLAGSKIP（`74 06`→`EB 06` @0x102787E）跳过
  fail-handler，流程到 0x1027892 = `call eax`，eax=0x10768A2 = **dispatcher
  正确加载**；③STACKFIX：dispatcher 的 push 在脱轨 Esp=0xB8C933A4（未
  提交）上 fault → SetThreadContext Esp := 0xEFE70（VM 栈已提交带）。
  **实测：dispatcher 带真栈跑了 ~3 秒真实 VM 工作**（BLKSTREAM 风暴到
  401ms + GATEPATCH 扫到 1223ms），随后死于缓存重放记录（WER dump:
  Eip=0x1027892、Esp 已修复 0xEFE70、target 仍 = 缓存 0xB8C933A0）。
- **REPLAYSWALLOW（132y24，第八件）**：av_handler 的 AV 臂按
  exception_addr==0x1027892 吞掉（DBG_CONTINUE，两次机会都吞，5000
  上限防死循环）——重放记录交壳 SEH 时 dispatcher 的栈工作已使
  SEH 帧失效 → 二次机会 = 0xC0000005 退出。
- **停泊态全景（132y25 探针链）**：主 VM 线程停泊在 win32u
  （SendMessage/GetMessage 类等待），**用户栈上就是 dispatcher 帧**
  ([0xEFEE8]=0x10768A2、[0xEFEB4]=0x107695E=dispatcher+0xBC)；~16 worker
  各停泊在 **NtWaitForSingleObject(自有 Event, FALSE, NULL)**
  （句柄 0x170-0x1B0 顺序分配，[esp+4]=h/[esp+8]=0/[esp+C]=0 形状）+
  1 个 ALPC Port 等待者。主线程栈 3 层重复 ntdll+40fe2 = **临界区等待**。
- **dispatcher 消息路径破译**：0x10768E3..0x1076958 = 消息序列 walker
  （esi = 序列串，首字符 '0'/'3'/'4'/'5' = MB 图标选择，终结符 " \0"）→
  `call [ebp+0x12263375]`（fold = *0x1023389）= **MessageBoxExA**，
  caption="CALC"（0x10208A9）。镜像含明文 **"Your license key is
  corrupted."** + 期望键 **"1051-BCEC-14F2-0C18-3745-254D-9F3C-2536"**
  （0x102135F）。**verdict = "license corrupted" 实锤 = 壳在报我们注入
  的 license 结构损坏**。
- **唤醒实验全败记录**：WM_GETTEXT（SMTO 2s）= 泵不派发；
  AttachThreadInput+SendInput(VK_RETURN) 与 PostThreadMessage 全无效；
  对 16 个 Event SetEvent（DuplicateHandle 修 ctypes 截断后 res=1）→
  **worker 醒→队列空→同 stub 再停泊（Eip 不变 = 假阴性）**，verdict 槽
  零变更。dismiss「关完仍停泊」的真相 = **从来没人真正关掉过它**。
- **MSGSKIP（132y25-25g，第九件）**：时间线定案 = CRC（user32 入口
  完整性检查）@~250-300ms（patch 太早 = exit 2）、首个 box @~319ms、
  部署 = 2s 且**带 box 照常推进**（box = 旁观者）。12 个模态对话框
  导出入口（MessageBoxA/W/ExA/ExW、DialogBoxParamA/W、
  DialogBoxIndirectParamA/W、MessageBoxIndirectA/W、
  CreateDialogIndirectParamA/W）+ 2 个 fold 槽位全部 patch
  （mov eax,1; ret imm16 按各自参数数）→ **box 仍以 CreateWindowExW
  直建 #32770 出现**（壳自实现对话框，入口 patch 线穷尽）。owner 实锤 =
  CISC-1 自己（GetWindowThreadProcessId 返回值 = TID，out 参数 = PID
  ——两次踩坑）。
- **KEYBUF 注入形态定案（132y26-27）**：`'52-'+('e60dc87dc8692802'*53)`
  = **buffer+0x52 起 424 字节重复键 blob**——搜索命中位 = buffer+0x52
  固定（变换定位，搜索命中即 80-miss 提前退出 ✓），但 **verdict 的输入 =
  部署时刻（2s）的 buffer = blob = 结构毁 = "corrupted"**。最小注入
  （8B @0x52，KEYBUF2 无窗口变体）与 [0,52) 结构头注入（KEYFORGE
  形状）均 0/部署 = 搜索是**变换定位**（键必须在命中位 0x52）且需要
  3 搜索各自的命中位。**.dat 校验哈希 = 对 raw 编码字节（磁盘侧），
  buffer 补丁不参与哈希**（blob 可部署 = 实锤）。**下一增量 = 112B
  已知明文结构布局（补 81-115）+ 3 搜索命中位精确落位 = blob + 结构
  修复混合注入**，或 f 全恢复（168 handler 缝合）后造合法 license。
- **机器清单（本次新增）**：VERDICTWATCH、FLAGSKIP、STACKFIX（泛化
  Esp 修复）、REPLAYSWALLOW、MSGSKIP v8（12 导出+槽位，260ms 门控）、
  KEYBUF2（无窗口 buffer 相对注入）。x86 零告警编译。
- 工件：probe_park/probe_dlg/probe_wait/probe_msg/probe_msg2/probe_wake/
  probe_owner/probe_iocp/probe_timeline.py（OUT/ps1/）+ waitcode_*.bin +
  park_stk_*.bin + msg/wake/owner/tl.log。

**续 22 补充 132y28-34（2026-11-21）——verdict 输入定位 + STRUCTRESTORE
全链打通 + 结构防篡改检查 = 新 blocker**：

- **停泊态 buffer 内容实测**：located 页 = [0,0x50) 全零 + [0x50+) 我们
  的 blob（壳多周期解码**清空头部**、blob = 最后写入）→ verdict 读到
  毁掉的结构 = "corrupted" ✓（verdict 输入 = located 页本身）。
- **located 页身份翻转**：needle 命中 = dat 尾 verbatim @struct+0x17D →
  located = **struct 页本身**；ba+0x10000 = **镜像基址**（MZ 实测，一次
  方向性错判）。struct 布局 **per-boot 随机**（132y85 的 ba+0x10000 →
  本轮 ba+0x100 → 0xAD818——固定偏移全灭）。
- **FF×8×3 内存扫描定位**（probe 的 VirtualQueryEx walk → 3 段 FF×8
  富集 480B 窗）= struct 唯一可靠定位法。捕获实测：struct 页 184ms =
  密文态（FF×8 缺）→ 解码输出后 FF×8 ✓。
- **µs 循环提前 break 实锤**（per-boot：本轮 1 次读取即 break）→
  捕获/恢复都必须独立线程（132y30 v4）+ SR_ON 门必须在 buf_addr=Some
  之内（早迭代消耗门 = 不 spawn，一次踩坑）。
- **KEYBUF blob = verdict 毁灭者定案**：blob = [0x52,0x21A) 424B 重复键
  → 结构毁。最小 8B / [0,52) 结构头注入均 0/部署 = **搜索是变换定位**
  （命中位 buffer+0x52 固定）+ 3 搜索各自命中位。
- **STRUCTRESTORE v6 全链打通**：FF×8×3 扫描 → pristine 捕获（186ms
  sv=0xAD818）→ **hybrid 写入（pristine + 本机键@0x52）** → 部署到达。
- **时间线矩阵（防篡改检查）**：hybrid@201ms → exit 2 @210；hybrid@312ms
  → exit 2 @330；blob 自 178ms 连续写 → 50% 部署存活。**判定 = 结构
  防篡改检查周期性扫描**：blob 因「连续写 + 壳重解码竞速」检查多读到
  pristine 而 50% 存活；hybrid 单发即被抓。检查自身 = 下一个 disassembly
  目标（exit-2 路径 = 哈希比较点）。
- **下一增量**：①检查点定位（exit-2 调用链反汇编/哨兵写追踪）②检查
  窗口与 hybrid 写的竞速强化（µs 连写 = blob 同款）③f 全恢复后造
  合法 license（哈希匹配 = 检查自然通过）。
- 工件：patch_132y28-32.py、probe_msg2（含 struct 扫描/buffer dump）、
  msg*-out.txt 系列、sr_block_old.txt。

**续 22 补充 132y35（2026-11-21，会话终点）——verdict = struct 哈希校验
实锤，PASS 唯一路径 = f（字段摘要）**：

- hybrid@333ms → exit 2 @~350 = **verdict 本身**（不是额外扫描）。
  全时间线矩阵闭合：pristine = 哈希匹配 → 机器绑定检查 → mismatch =
  停泊（CALC 对话框报 "corrupted"）；修改 = 哈希失配 → **立即 exit 2**。
  停泊与 exit-2 = 同一 verdict 的两种结局（pristine vs 修改）。
- **PASS 的唯一路径 = struct 内 fd dwords（字段摘要）用 f 重算**——
  正是补充 25 的 168-handler 恢复终点。哈希无运行时绕过（fd 在 struct
  内、检查读 struct）。STRUCTRESTORE v6 机器全保留（扫描/捕获/hybrid
  写入 = f 就绪后立即可用的注入通道）。
- 会话沉淀（8720296 + 本节）：停泊态全解码（dispatcher=MessageBoxExA
  模态循环+CS 死锁、16 worker=Event 等待、verdict=struct 哈希）、
  十件机器（VALLOC2/FLAGSKIP/STACKFIX/REPLAYSWALLOW/MSGSKIP/
  STRUCTRESTORE/KEYBUF2 + 既有六件）、时间线矩阵、FF×8×3 扫描定位。
  下会话 = f 全恢复（handler 缝合 168）→ fd 重算 → hybrid(合法) →
  verdict=PASS → launch → OEP。

**续 22 补充 132y36-37（2026-11-21/22）——verdict 输入全解 + 七件新机器 +
forge 方程闭合：search 与 decode 共用 buffer = 冲突，唯一 forge = decode 逆**：

- **FF×8×3 连续扫描 = 堆假阳性实锤**：STRUCTRESTORE v6 的 Rust 扫描
  （24 连续 FF）命中的 0xAD818 = 堆对象非许可 struct（「pristine captured
  sv=0xAD818」全错页！hybrid 写错页 = 前两轮时间线矩阵全部作废）。
  真 locator = **dat 尾 16B needle**（struct+0x17D 携带 verbatim），
  但 needle 也命中 buffer（dat 尾在 ba+0x180 verbatim）→ 双重判据 =
  needle 命中 + 480B 窗含 FF×8（解码态 struct 独有）。
- **struct 全布局实锤**（verdict 时刻 480B，tail needle 定位）：
  头 [0x00,0x3A) 滚动态；字段 [0x3A,0xA9)：FF×8@0x3A + "(CISC-1)
  Examples\0"+FF×8 + "LCF-AT\0"+FF×8 + "KuNgBiM/[CCG]\0"+FF×8 +
  serial@0x80（39B）+\0\0；标志/摘要区 [0xA9,0xD6)：fd ff ff ff×2、
  f1b0a98318、8b96d3dd、**counter@0xC4 = 0x07D9 = 2009**（= 执行计数
  > 2000 = 132y2 的 corrupted 判决数！per-boot 恒定）；二进制区
  [0xD6,0x17D)；dat 尾 verbatim [0x17D,0x21D)。struct = ba+0x10000。
- **BUFFERDUMP（buffer 版本时间线 [170,345]ms，300µs 轮询 FNV 去重）**
  六相定案：[175,191] .dat 逐字节拷入（ReadFile）→ [204,215] 全零擦除
  → [215,228] 检查流写入（头滚动 7abc9f7a→6755753f→b4df6d12 = check
  op 的 scratch，= .dat 完整性校验，buffer 补丁此窗内 = corrupted）→
  [228,293] 静止 → **[293] 擦除 + [294,336] decode era（buffer = 解码
  输入！）** → [336] 输出原子落盘（480B 重加密态）→ verdict [340,360]
  读 buffer。**KEYBUF 旧 µs 循环 per-boot 提前 break = blob 从未写入
  （keymatch 0-3/424 噪声）→ U11 时代结论全部失效于当前仪器。**
- **CORPUSDUMP（0x10DC000 语料 [240,345]）**：语料 @240 已填满且
  A/B（有无 blob）逐字节相同 = **语料 = 机器键参考表（本机派生、
  per-boot 常量），不来自 buffer**。搜索 = 语料（参考）vs buffer
  （被扫）——命中位 = buffer+0x52 = **搜索在 buffer 里找本机键**。
- **KEYBUF3（独立 blob 线程，修复仪器）**：dat 头 needle 自定位 ba +
  连续重写 [230,335]。实测：blob @230/296 两次写入即稳定（nwr=2 =
  写后 buffer == payload）。**blob 存在 → 流程越过搜索失败直达装配
  [305,310]（pristine run 的装配从未发生 = 搜索 miss 即中止！）**
  = 搜索命中实锤 ✓。
- **blob 的解码级联损伤图（决定性）**：blob run 的 struct vs pristine
  struct = **仅 [0x8e,0xD6) 72B 被毁**（serial 尾 + fd/标志区），
  字段 [0x41,0x8e) 与二进制区 [0xD6,0x17D) 解码完好 = 解码为字段块
  结构非线性级联；.dat[0x52] 键区 → struct[0x8e,0xD6) = **键字段的
  解码像 = 搜索的扫描目标**（"命中位 0x52" = transform-locating 实锤）。
- **FAILSTATE（verdict 时刻 343ms 状态快照）**：struct = pristine ✓
  （STRUCTFIX 赢得竞速时）；buffer @343 = **blob 残留全量**（KEYBUF3
  停写 ≠ 移除！）→ verdict 读 buffer = "corrupted" 实锤。修复 =
  KEYBUF3 @336 恢复 pristine .dat → exit 44（verdict 重跑搜索 =
  键没了）；恢复 hybrid（.dat + 键@0x52 8B）→ exit 44（解码级联毁
  struct[0x8e,0xD6)，STRUCTFIX 竞速 5 写仍 50/50）。
- **alive-park 态突破**：blob [230,335] + GATEPATCH（4 门 NOP）+
  CTR-HOLD → **流程永不 fail-exit，部署 142MB 稳定停泊 + CALC 对话框
  （"Your license key is corrupted." + fp）**——failure dispatch 被
  NOP 但 verdict 状态 = fail → launch 门持续挂起（132y20 同型）。
  双模结果（alive-park ~40% / exit-44 ~60%）= STRUCTFIX vs 壳重解码
  的竞速。
- **forge 方程闭合（本会话头条）**：verdict = 【搜索：本机键在
  buffer@0x52（变换定位）】+【许可校验：buffer 解码像无级联损伤】
  ——两者同读 buffer[0x52,0x5A)：搜索要本机键、解码级联毁键像 →
  **互斥！唯一解 = .dat' = decode⁻¹(期望输出)**（期望输出 = pristine
  字段 + 键像@键字段位）→ **decode 逆 = f 全恢复（168-handler 终点）
  = 下一会话唯一任务**。回放机资产 = 新鲜 b8 #27/#28（t=295.1/295.2，
  eip=0x1064332/0x106b5f8，edi=0x105FFAE，esi=0x114fe3d/0x1147cc3 =
  field op 中途态）+ dw133 两态 + failfreeze + 全 era 池。
- 仪器清单（本次新增，全部 x86-gated、零告警）：STRUCTDUMP（struct
  页+镜像区落盘）、BUFFERDUMP（buffer+struct 双时间线）、CORPUSDUMP、
  KEYBUF3（独立 blob 线程 + hybrid .dat 恢复）、STRUCTFIX（72B 窗
  连续重写）、KEYPATCH3（19 镜像槽连续重写，dw170 值）、FAILSTATE
  （verdict 时刻快照）。
- 工件：CISC-1U.v2structdump{,.verdict}.bin、CISC-1U.v2buffer{.A,.B}.bin、
  CISC-1U.v2structtl{.A,.B}.bin、CISC-1U.v2corpus{.A,.B}.bin、
  CISC-1U.v2failstate.bin、probe_corpus/probe_combined/probe_pass*/probe_
  dlgtext/probe_failstate.py、corpus_A/B.log、combined/pass/dlgt.log。
