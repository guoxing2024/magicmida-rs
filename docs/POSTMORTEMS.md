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
