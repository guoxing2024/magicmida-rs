# 运行手册

> 2026-10-25 从内部工作区笔记拆出（原文逐字节搬移，未改写）。
> 这里只放**怎么把东西跑起来**：工具链、测试顺序、gate、样本制备。
> 缺陷复盘在 [`POSTMORTEMS.md`](POSTMORTEMS.md)，黄金值与已验证能力在
> [`README.md`](../README.md)。

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

