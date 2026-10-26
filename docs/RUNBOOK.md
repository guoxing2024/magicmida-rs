# 运行手册

> 2026-10-25 从内部工作区笔记拆出（原文逐字节搬移，未改写）。
> 这里只放**怎么把东西跑起来**：工具链、测试顺序、gate、样本制备。
> 缺陷复盘在 [`POSTMORTEMS.md`](POSTMORTEMS.md)，黄金值与已验证能力在
> [`README.md`](../README.md)。

## VMProtect：识别 / 静态报告 / 载荷提取 / 内存镜像 dump（2026-10-25）

四个命令，**都不需要注入 ScyllaHide**：

```powershell
# 1) 纯静态：识别 packer + mode、打印结构报告、可选提取文件内的载荷
.\target\release\mida-cli.exe /analyze TARGET.exe
.\target\release\mida-cli.exe /analyze TARGET.exe --extract OUT\payload

# 2) 运行中的进程 -> 摊平镜像（每个段 offset == RVA），默认 rebase 回首选基址
.\target\release\mida-cli.exe /dump-image <pid> OUT\image.exe

# 3) 强制分支（诊断用；覆盖会被记录）
.\target\release\mida-cli.exe /unpack TARGET.exe --packer auto|themida|vmprotect
```

**三个命令只读文件或读目标内存，没有一条挂调试器** —— 所以它们都能进 CI，
而 `/unpack` 不能（要注入 + 目标要弹窗）。

### 两个已实测的 mode（判据量出来的，不是猜的）

| | `MinProtection` | `Packed` |
|---|---|---|
| 样本 | `lunlun\伦伦软件.exe` 19,005,952 B | `zz_test.exe` 21,415,936 B |
| DIE | `VMProtect 2.XX-3.XX [Min protection]` | `VMProtect 2.XX-3.XX` |
| `.text` | raw `0x72400`，解码 100% | **raw 0** —— 不在文件里 |
| EP | `0x4b274` in `.text` | `0x130bbfb` in `.rdata2` |
| 运行时大段 | `.vmp0` raw `0x217e00` ch `0x68000060` | `.rdata2` raw `0x1466400` ch `0x68000060` |
| 异常目录 | 在 `.vmp0` 内，triples 64/64 | 在 `.rdata2` 内，triples 64/64 |
| `.pdata` | raw `0x4e00`，triples **0/64** | raw 0 |
| RCDATA | id 101，16,102,969 B **在文件里**，sha256 `91d585e6…`，magic `XMP2QH_` | id 131，12,782,080 B **只在内存** |

判别规则在 **87 个受保护样本**上量过误报率：`MEM_NOT_PAGED` + 可执行段在两个
VMProtect 样本上都成立，在 **63 个 Themida 样本上 0 命中**。
**按 `.vmp0` 名字判会全漏 `Packed`** —— 它的等价段叫 `.rdata2`；
而 `is_themida_section` 的 `raw_size == 0` + 大 vsize 条件在 `Packed` 的 `.rdata0`
上**会误报**，也同时命中 6 个真 Themida 样本，所以那个误判无法靠收紧它自己修掉，
只能靠前置的 packer 闸。

### `/dump-image` 的实测（2026-10-25）

`Packed` 的原始段只在内存里，这是唯一能取到它们的方式。**故意不挂调试器**：同一个
`zz_test.exe` 裸跑退出码 `0`，挂上调试器后约 7 秒自退 `0xDEADBEEF`（`3735929054`），
唯一变量是调试器。

实测（`伦伦软件.exe`，ASLR 落在 `0x7ff789eb0000`，首选 `0x140000000`）：

| 段 | flat | rebase 前 / 后 与文件差异 |
|---|---|---|
| `.text` | ✓ | 0 / **0** |
| `.pdata` | ✓ | 0 / **0** |
| `.reloc` | ✓ | 0 / **0** |
| `.rsrc` | ✓ | 0 / **0** |
| `.vmp0` | ✓ | 80 / **0** |
| `.rdata` | ✓ | 7479 / 1975 |
| `.data` | ✓ | 789 / 445 |
| `.fptable` | ✓ | 72 / 72 |

**8 段全部 `praw == va`**（摊平不变式），dump 的 `.text` 解码 **100.0%**（140,220 条指令）。
rebase 应用 **1484 个重定位槽**，与静态量出的 `.reloc` 绝对重定位条数一致
（`.rdata` 1376 + `.data` 88 + `.vmp0` 20）。

**残差不是缺陷**：`.rdata` 的 IAT 在文件里是盘上 thunk 形态、在内存里是**已解析的
绝对地址**（IAT 目录 rva `0x74000` 正是 `.rdata` 起点），再加上 cookie / `InitOnce`
这类运行期写入；`.fptable` 那 72 字节是 VMProtect 运行期才写进去的。

参考产物（已给的，同一命令应产出同一种形状）：`qidongqi\out\ida\main.exe`，
43,315,200 B，sha256 `b6355439…`，9 段全部 `praw == va`，`.text` 解码 99.8%。

### ScyllaHide profile 按 packer 切

injector 的调用是 `InjectorCLIx64.exe pid:<pid> <HookLibraryx64.dll> nowait` ——
**没有 ini 参数**，所以 profile 只能靠改 injector 旁边那份 ini 里的 `CurrentProfile`
（`select_profile`，只改那一行，保留 CRLF 与手改内容）。
profile 文件在 `crates\cli\assets\scylla_hide.ini`（已跟踪），部署时复制到
`target\release\` 与 `target\debug\`；逐个键的来源与**未改动的缺口**见
`crates\cli\assets\README.md`。

**验 profile 是否真生效**：hook library 会在自己旁边写 `scylla_hide.log`，
`DEBUG: ApplyNtdllHook -> Hooking <名>` 就是实际挂上的钩子；值为 `0` 的键只会出现在
`_Nt…` 地址表里，不会出现在 `Hooking` 行 —— **所以钩子集合可以直接断言，不用假设**。

## `Packed` VMProtect：从活体抓产物（2026-10-25 打通）

`Packed` 的原始段 `SizeOfRawData == 0`，文件里**没有代码**，只能从运行中的进程读。

```powershell
# 必须 --wait：载荷是原地解密的，抓早了就是半成品
.\target\release\mida-cli.exe /dump-image <pid> OUT\image.exe --wait
# 产物：OUT\image.exe（43,315,200 B、9 段、摊平）
#       OUT\image.rcdata131.bin（12,782,080 B，自动 carve）
```

### 提升陷阱（不写清一定会被当成工具缺陷）

这个样本家族**会给自己注册 `RUNASADMIN` 层标记**：

```
HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
  D:\Projects\zz_test.exe                              -> ~ RUNASADMIN
  E:\Download\启动器10.9\启动器10.9.exe                -> ~ RUNASADMIN
  <你复制出来的任何新路径>                              -> ~ RUNASADMIN   ← 跑过一次就会被加上
```

三份清单里**都没有** `requestedExecutionLevel`（pefile 静态确认），所以提升不是二进制要的，
是它装上去的。后果：**同一个路径第二次跑就是提升进程，未提升会话读它 → `拒绝访问
(0x80070005)`**。所以每次测量都要**换新路径并删掉那条标记**：

```powershell
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /v "<完整路径>" /f
```

gate 里就是这么做的（`clear_runasadmin_layer`）。

### 捕获点：不能靠时间，也不能只靠"两帧一致"

实测（每 100 ms 采一次，载荷区 12,782,080 B）：

| t(s) | 载荷 sha256 前 16 位 | 说明 |
|---|---|---|
| 0.02 | `db4c050e…` | 还是全零 |
| 0.73 | `b8991af0…` | 开始变 |
| 0.84–1.53 | `3e6f024f` `4aa50cf5` `2fd77393` `36fb4454` `0a6a75e1` `73bafb30` `8f4c94ab` | 约 8 帧中间态 |
| **1.65** | **`14596cbd…`** | **终态，之后不再变** |
| 6.61 | — | 进程退出 |

两个坑：

1. **"连续两帧相同"不够** —— 前两帧可能都还是**未动过的文件字节**，于是判据在解密开始前
   就满足了。实测因此产出 `fcee1cb1…` 或根本没有载荷文件。
2. **终态与样本自身可推**：把输入文件的 `.rsrc` 按 RVA 映射出来读一遍（缺的部分按 0 补），
   那就是"壳动它之前"的样子；**镜像里的资源区只要不等于它，就说明壳动过了**。现在要求
   「已变化 + 连续两帧一致」两个条件同时成立，不依赖时间、不依赖对密码的任何假设。

### 两个哈希不是一回事（别记错）

| 值 | 尺寸 | 是什么 |
|---|---|---|
| `14596cbd…` | 12,782,080 B | 资源区在这个进程里的**终态**，也是参考镜像 `main.exe` 里那份 |
| `e7004e89…` | 12,782,080 B | **进一步解出来的合法 PE**（`MZ`、`e_lfanew 0x80`、`machine 0x8664`、9 段） |

**`e7004e89…` 不在这个进程里发生** —— 资源区到 1.65 s 定格后直到退出都没再变，
全地址空间 22 秒扫描没有 `MZ`、没有子进程。它是**下一阶段**的产物。

**2026-10-25 更新：那一阶段已经还原**，是 32 字节定长 XOR，见下一节 ——
所以它现在**是** `/dump-image` 和 `/analyze --extract` 都能产出的东西。

### 容器 → 可用 PE：32 字节定长 XOR（2026-10-25 还原）

密钥：

```
8f 2b f1 f6 d2 82 c0 26 13 e7 bc 85 c5 c9 a5 99
ab f0 ea 37 6e d4 22 7e 81 65 f7 d2 32 96 56 2f
```

**怎么来的（可重新推导，不用信我）**：拿两份同长度文件异或 —— 镜像里的容器
（`14596cbd…`）与样本自己写出来的解完 PE（`e7004e89…`）。得到的 keystream 结构
没有歧义：

- `K[i] == K[i-32]` 在 **12,782,080 字节上一次性不间断成立**（整文件一个 run），
  所以**没有分段边界**要找；
- 按 32 字节切块，全部 **399,440 块只有 1 种**块值；
- `K` 只有 **31 种不同字节值** —— 固定 32 字节密钥就是这个样子（真流密码应接近均匀）。

验证（三份独立副本，全部一致）：

| 输入 | sha256 | 输出 |
|---|---|---|
| `out\rsrc\RCDATA_131.bin` | `14596cbd…` | `e7004e89…` |
| `out\launcher_rsrc\ID131` | `14596cbd…` | `e7004e89…` |
| `/dump-image` 自己产出的 `out.rcdata131.bin` | `14596cbd…` | `e7004e89…` |

产物：PE32+ x64、9 段、`e_lfanew 0x80`。

**落地方式**：`crates/packers/vmprotect/src/payload_xor.rs` 是一张按
`(type_id, name_id)` 索引的**显式表**，不是自动探测。理由：这一步是**应用自己的**
逻辑，不是 VMProtect 的功能，所以只能按家族记录，不能从壳的行为推导。
**接受条件由数据自己判**：变换后必须是结构合法的 PE，否则拒绝并保留容器 ——
错误的密钥不能因为"表里有"就通过（gate 里有一条专门喂坏密钥的反向断言）。

CLI 两个入口都输出两份文件（**解码产物按它自己声明的 `IMAGE_FILE_DLL` 命名**，
不再一律 `.exe`，见下）：

```
img.rcdata131.bin           容器（14596cbd…）
img.rcdata131.decoded.dll   解完的载荷（e7004e89…）
```

**别把它当通用解密**：这条密钥只对这一个家族、这一个资源成立。表里加条目的门槛是
"从两份独立产物量出来"，猜的密钥比没有更糟 —— 它会产出看着很像的垃圾。

### 对账基准（2026-10-26 定义，宣称"第二类脱壳"的前置）

对账对象是**解码产物**（`e7004e89…`），不是整镜像。基准分三层，全部有 gate：

**① 字节层 —— 对账到家族自己的运行期产物。**
`zz_test.exe`（=`E:\Download\启动器10.9\启动器10.9.exe`，**逐字节同文件**，hash 同
`804fd7c1…`）运行时自己把解完的载荷写到 `%TEMP%\<guid>.log`（约半数启动，t≈3.5 s，
分支性行为）。这就是独立生产者 —— UPX 线的 `upx -d` 在这条线上的等价物。三份独立
容器副本（资源 dump / 样本自带 ID131 / `/dump-image` carve）全部解出同一
`e7004e89…`，launcher 自己写的文件也是它。gate：`the_decoded_payload_is_reproducible_
from_a_captured_image_alone`（CI，对参考镜像）+ `the_decoded_payload_is_a_pe_that_
the_sample_writes_to_temp`（活体，允许跳过 —— 写盘本身是分支性的）。

**② 结构层 —— 解码产物本身是什么，一条条钉死（CI）。**
`e7004e89…` 是 **PE32+ x64 / 9 段 / `IMAGE_FILE_DLL`**（file characteristics
`0x2022` 含 DLL 位）—— 它是**给宿主装载的 DLL，不是 CreateProcess 起的程序**。
`SizeOfImage` 与段表自洽（`0xc6b000`）；导入目录在（KERNEL32/USER32/GDI32/ADVAPI32/
WINHTTP）；**导出目录是纯序号形态：65,328 槽 / 0 个名字 / base 0x25 / 60 个真导出**
（套件按 ordinal 调它，名字被抹掉）；并且**重新分类为 VMProtect `MinProtection`**
—— 原始代码回到文件里，这正是"原始程序被还原"的结构定义。CLI 两个入口的解码产物
因此按字节自己声明命名 `.decoded.dll`（此前一律 `.exe`，用户双击就是 OS 的
"不是有效的应用程序"，是产品缺陷）。

**③ 行为层 —— 装载与初始化（`#[ignore]`，不进 CI）。**
探针 `crates\cli\tests\fixtures\vmp_load_probe.c`（gate 现场用 gcc 编，牺牲子进程）
`LoadLibraryW` 产物：LOADED=1、`DllMain` 跑完并起工作线程（实测 4 条）、
`GetProcAddress(ordinal 66)` 解析成功、退出码 0。判别力实测（2026-10-26）：
`.text` 里翻 1 字节（`DllMain` 不执行的死代码）**测不出** —— 那归字节 golden 管；
`.rdata2`（装载期必执行的 VM runtime 段）翻 1 字节 → 宿主访问违例崩 → gate 红。
分工：**golden 管"字节对不对"，行为 gate 管"能不能过 loader 并完成初始化"。**

**宣称边界**：本线宣称的是 *容器 → 字节对账到家族自身运行期产物 + 可被宿主装载并
完成初始化*。不宣称"完整功能跑起来"（那要套件按序号调用的上下文）、不宣称通用
解密（密钥按家族记录）、不宣称 devirt。

### 整镜像哈希**不是** golden

三次捕获三个值（`a68874e3…` / `28668aa3…` / `1963ed17…`），因为活体镜像带运行期状态
（已解析指针、`__security_cookie`、计时器）。**稳定的是形状**：43,315,200 B / 9 段，
与参考镜像相同。gate 就按形状 + 载荷哈希两条断言，不钉整文件哈希。

### gate

```powershell
cargo test --release -p mida-cli --test vmprotect_packed_gate -- --ignored --nocapture
```

`#[ignore]`（要真进程 + 桌面会话）。活体五条：捕获+carve、输入文件仍必须拒绝提取、
**解码产物装载与初始化（行为层，牺牲子进程 + gcc 现场编探针）**、launcher 自写载荷
的哈希对账（允许跳过 —— 写盘是分支性的）、以及一条**不需要样本**的常量自检
（参考镜像仍是 9 段 / 43,315,200 B）。CI 档两条：解码复现 + **结构基线**（DLL 位、
SizeOfImage 自洽、序号导出 65328/0、重新分类 MinProtection）与常量自检。

## UPX：静态解包（2026-10-26 打通）

无进程、无桌面会话，纯文件操作；头less 环境可用：

```powershell
.\target\release\mida-cli.exe /unpack <packed.exe> --packer upx
# auto 也行：检测到 UPX 就走静态解包（闸序 VMProtect → UPX → Themida）
```

对账：**`upx -d` 自己的输出**，不是加壳前的原始文件（UPX 打包时改写 DOS stub 区且从不还原，
7 样本实测尺寸全同、哈希全异）。golden sha256：injector `2f391f08…`、mida_x64 `459f4f8e…`、
x86 `da7a1dce…`——NRV2B（`upx --nrv2b`）/NRV2D（`--nrv2d`）样本与 NRV2E/LZMA 样本
同源，产物哈希两两相同，互为解码器交叉验证。gate：`cargo test -p mida-packers-upx`
（默认就跑；语料缺目录时显式 SKIP，样本在 `OUT\upx_samples\`，upx 5.2.1 可再生；
单测用手工位流向量——`OUT\nrv2e_encode.py` / `OUT\nrv2bd_encode.py`（BFS 编码器
内嵌解码器自校验），无样本也全绿）。移植参考：UPX v5.2.1 源码（`OUT\upx-5.2.1\`
+ `OUT\ucl_src\`）与 Python 原型（`OUT\upx_unpack_proto.py`）。

## x86 编译（2026-10-23 打通）

```powershell
$env:CARGO_HOME="D:\Tools\cargo"; $env:RUSTUP_HOME="D:\Tools\rustup"
rustup target add i686-pc-windows-gnu
cargo build --release --target i686-pc-windows-gnu
# 产物：target\i686-pc-windows-gnu\release\mida-cli.exe（pei-i386，可运行）
```

**本机现在有真正的 32 位 unwinder**（2026-10-24 换入）。三步环境准备
（`src\.cargo\config.toml` 已记录全部理由）：

1. **链接器**指向 `D:\Tools\RE\w64devkit\bin\i686-w64-mingw32-gcc.exe`
   （`D:\Tools\mingw64` 没有 i686 编译器）。
2. **`libgcc_eh.a` 已换成真库**（45810 B，sha256 `203d2474…a4ccae`），
   位置 `w64devkit\lib\gcc\x86_64-w64-mingw32\16.2.0\32\libgcc_eh.a`。
   来源：MSYS2 包 `mingw-w64-i686-gcc` **16.2.0-6**（与 w64devkit 的 GCC 版本一致），
   从 `repo.msys2.org/mingw/mingw32/` 取该 `.pkg.tar.zst`，7z 解 zstd 再解 tar，
   取 `mingw32\lib\gcc\i686-w64-mingw32\16.2.0\libgcc_eh.a`。
   成员：`unwind-dw2.o` / `unwind-dw2-fde.o` / `unwind-sjlj.o` / `unwind-c.o` / `emutls.o`，
   `unwind-dw2.o` 导出全部 `__Unwind_*`（含 `__Unwind_RaiseException`、`__Unwind_Resume`）。
   **与 `libgcc.a` 的 `unwind-sjlj.o` 不冲突**（实测链接通过），
   所以早先"别把 `_Unwind_DeleteException` 放进 stub"那条顾虑已不适用。
   旧的手搓 stub 备份在 `OUT\libgcc_eh.a.stub.bak`（808 B，`62b5de66…`）。
3. **`-lwinpthread -lkernel32 -lmsvcrt -lmingwex` 要包在 `--start-group` 里**，
   否则 `libwinpthread.a` 的 `_imp__CreateEventA@16` / `_assert` / `__ms_vsnprintf`
   解析不了。

## ⚠ 换库后必须删旧测试产物

cargo 按 **mtime** 判断是否重新链接，而换入的 `libgcc_eh.a` 的 mtime 是 MSYS2
打包时间（2026-10-13），**比旧产物更旧**，于是 cargo 认为产物是新的：一批仍链接
stub 的旧二进制继续 `ud2`，报 `0xc000001d STATUS_ILLEGAL_INSTRUCTION`，看起来像
"修了没用"。

```powershell
Get-ChildItem src\target\i686-pc-windows-gnu\release\deps -Filter *.exe |
  Where-Object { $_.LastWriteTime -lt (Get-Date '2026-10-24 03:00') } |
  Remove-Item -Force
cargo test --workspace --release --target i686-pc-windows-gnu --no-run
```

或者直接 `cargo clean --target i686-pc-windows-gnu`。

**修掉的 7 类 x86-only 缺陷**（全部只在 i686 编译时暴露，x64 一直是对的）：

| 文件 | 缺陷 |
|---|---|
| `core/windows_debugger.rs` | `Dr0..Dr7` 写死 `u64`，x86 的 `CONTEXT` 是 `u32`；加 `DrFields` trait 跟随架构 |
| `core/debugger.rs` | 新增 `ctx_ip`/`ctx_sp`/`set_ctx_ip`/`set_ctx_sp`（x86 上叫 `Eip`/`Esp`） |
| `packers/oep/mod.rs` | x86 分支用了不存在的 `thread_id`（签名里根本没这个参数）+ `trace` 宏未导入 → **这段代码从未编译过** |
| `pe/original_imports.rs` | thunk 宽度写死 8 字节 + `IMAGE_ORDINAL_FLAG64` 写死 |
| `packers/iat/discovery.rs` | 两处 `usize::from_le_bytes([0u8;8])` |
| `packers/iat/fix.rs` | imm32 读成 `usize` |
| `packers/trace_imports/decision.rs` | x64 地址常量写进 `usize` 字面量 → **静默变 0** |
| `cli/unpacker/av_handler.rs` | 同上，`0x7FFF_FFFF_FFFF` 字面量 |

**这两条最危险**：字面量溢出后变成 `0usize`，编译器只给警告；如果只求"能编译"
而放行，x86 会把每个已解析地址都判成"不在 API 范围"。

## 三层测试，改 trace 相关代码前按顺序跑

```powershell
# 1. 纯函数层（快，无样品）
cargo test -p mida-packers-themida --lib
# 2. 结构层（合成 PE，无样品）
cargo test -p mida-packers-themida --test regression_guoxing_shiguang
# 3. 端到端层（真样品 + ScyllaHide，约 12 秒）
cargo test -p mida-packers-themida --release --test e2e_gate -- --ignored --nocapture
# 4. DLL 端到端层（真 DLL 样品 + 桌面会话 + gcc，约 9 秒）
cargo test -p mida-packers-themida --release --test dll_e2e_gate -- --ignored --nocapture
```

样品身份与期望值来自 `tests\cases\*.case`，**不是**测试里的字面量；sha 不符会
拒绝运行。**换样品 = 改 manifest，不是改代码。** 判别力已验证（`expect_resolved`
从 186 改成 185 → `resolved-import count regressed`）。

## DLL 端到端 gate（第 4 层）

DLL 没有"启动后还活着"这种信号 —— `LoadLibrary` 成功只证明头和导入表没问题，
**不证明壳初始化完了**。本 gate 要抓的缺陷正是这个：产物能加载、导出能解析，
`GetAppVersion()` 却答 `"0.0"`。

所以它断言**行为**，通过 `tests/fixtures/dll_gate_harness.c`（gate 自己用 gcc 编译）
把产物当成真实宿主程序来用：`LoadLibraryW` → 调 `GetAppVersion()` →
在 worker 线程调 `Run()` → 轮询产物自己创建的窗口。

判据三项，全部来自 `tests\cases\core_dll.case`：
`expect_version: 1.1`、`expect_window_class: PigToGoLicenseDialog`、
`expect_window_title: 授权验证`；外加 trace 计数 289/3、3283 槽、产物结构。

**`expect_output_sha256` 现在记真实哈希**（原为 `none`）。
`clear_stale_live_pointers()` 消掉了 28 个活体指针，但 `.bss + 0x13EDB0` 那一个
qword 仍每轮变化。它**不是**脏指针，也**不是**哈希 —— 是 **`__security_cookie`**
（MSVC 栈保护种子），由 `__security_init_cookie` 每进程写一个随机值。

识别靠签名，不靠猜：该函数含 MSVC 的规范 fallback
`48 B8 EF BE AD DE EF BE AD DE`（`movabs rax, 0xDEADBEEFDEADBEEF`）+
`48 89 05 <disp32>`（`mov [rip+disp32], rax`），store 目标即 cookie 槽。
对全部可执行段做穷尽 RIP 相对操作数扫描，除该函数自身外**只有 4 处访问**，
全在函数体内，镜像里没有任何别的代码读它。

`find_security_cookie_rvas()`（`dump_process.rs`）在写文件前把它清零，
这是**语义正确**的文件期值：`__security_init_cookie` 开头是
`cmp qword ptr [rip+X], 0` / `je`，零才让 loader 重新随机化；留着捕获到的
非零值会让**所有**进程共用同一个 dump 期种子，比不确定性更糟。
EXE 那条线本来就是 0 —— 这正是它一直可复现的原因（`0x1121b0`）。

实测：**4/4 次独立运行字节完全一致**（当时 `1fce505e…`，后因 `.text` 保真度
修复变为 `97b9f20f…`——重录经过见 `docs/POSTMORTEMS.md` 的「DLL 的 golden
哈希重录过两次」；`.text` 保真度的经过见 `POSTMORTEMS.md` 的
「x64 的 `.text` 保真度缺口已收掉」）；
手工归零、MSVC 默认值 `0x2b992ddfa232`、原始随机值三种产物行为完全相同
（`GetAppVersion()=="1.1"`、`PigToGoLicenseDialog` / `授权验证`）。
**不要**再把它当"哈希"或"脏指针"处理。

判别力已验证（三项各测一次，都立刻红并给出对应断言）：
`expect_version: 9.9` → `GetAppVersion() regressed`；
`expect_window_class: SomeOtherWindow` → `window class changed`；
`expect_resolved: 288` → `resolved-import count regressed`。改回来绿。

**注意**：最后一项断言是真实窗口，无桌面/无头 CI 会挂。这是有意的取舍。

## 自己造 x86 样本（2026-10-23，已打通）

**本机装了 Themida 3.2.4**：`D:\Tools\Themida_x32_x64_v3.2.4\`。
`Themida.exe` 是 **32 位**加壳器，`Themida64.exe` 是 64 位的。
它能纯命令行加壳，所以 x86 样本不用等外部提供。

完整流水线（可复制）：

```powershell
# 1. 写一个行为可验证的 32 位程序
#    OUT\x86_sample.c 里导出了 GetSampleVersion()，建一个类名固定的窗口，
#    并 touch 了 kernel32/user32/gdi32 的多个导入，让 IAT trace 有宽度。
D:\Tools\RE\w64devkit\bin\i686-w64-mingw32-gcc.exe -O1 -m32 -mwindows `
  -o OUT\x86\x86_sample.exe OUT\x86_sample.c -luser32 -lgdi32 -lgcc

# 2. 造 .tmd 项目文件（它是 UTF-8 INI 文本，不是二进制）
#    拿现成模板改 INPUT_FILE_NAME / OUTPUT_FILE_NAME 即可：
#    D:\Tools\RE\VirtualizationObfuscatorAnalysis\Themida\hello_world_themida.tmd
#    → 只替换两行路径，其余保护选项保持原样（ANTIDEBUG=false 等）

# 3. 加壳
D:\Tools\Themida_x32_x64_v3.2.4\Themida.exe /protect OUT\x86\x86_sample.tmd
```

**`/protect` 必须接 `.tmd` 项目文件，不能直接接 exe** ——
`/inputfile` 是项目文件里的字段，命令行单独给 `/inputfile` 会报
`ERROR: Project File does not exist or invalid`。

产物实测：**6.69 MB，machine=0x14c，22 段**，段名是 Themida 的数字风格
（`/4` `/19` `/31` …）+ `.themida` 6.9 MB；加壳后仍能运行，窗口类
`MidaX86Sample` 不变——这就是行为验收判据。**踩的坑**：`ShellAboutA` 会弹模态
"关于"框挡住主窗口，`-mwindows` 不加则样本自带控制台窗口，两个都要去掉。

