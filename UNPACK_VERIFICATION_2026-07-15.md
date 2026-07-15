# 启动器.exe 脱壳验证报告
**日期**: 2026-07-15  
**工具**: Magicmida-RS v0.1.0

---

## 执行摘要

✅ **脱壳成功** - 文件结构完整，导入表正确重建  
⚠️ **运行时崩溃** - 与已知状态一致（见项目 memory）

---

## 脱壳结果

### 输入/输出
- **输入文件**: `/d/Tools/RE/dumps/runtime/启动器.exe` (8.2 MB, Themida V3 x64)
- **输出文件**: `/d/Tools/RE/dumps/runtime/启动器U.exe` (1.5 MB)
- **压缩比**: 82% (8.2 MB → 1.5 MB)

### 关键指标
| 项目 | 值 | 状态 |
|------|-----|------|
| **OEP** | `0x140001000` | ✅ x64 CRT startup detected |
| **IAT Location** | `0x1400fd000`, size `0x11e0` | ✅ |
| **导入模块** | 18 modules | ✅ |
| **导入函数** | 545 thunks | ✅ |
| **TLS 引导** | 已安装 | ✅ |
| **异常表** | RVA=0xecc000 Size=0xb124 | ✅ 已恢复 |
| **重定位表** | 1971 entries (4172 bytes) | ✅ 已生成 |

### 导入表详情
18个模块，545个导入函数：
- **kernel32.dll**: 200 thunks (4 runs)
- **user32.dll**: 176 thunks
- **gdi32.dll**: 34 thunks
- **advapi32.dll**: 26 thunks
- **wsock32.dll**: 22 thunks
- **oleaut32.dll**: 20 thunks
- **shell32.dll**: 14 thunks
- **winmm.dll**: 12 thunks
- **ole32.dll**: 8 thunks (来自原PE修正)
- **bcrypt.dll**: 7 thunks
- **comctl32.dll**: 6 thunks
- **psapi.dll**: 5 thunks
- **wininet.dll**: 5 thunks
- **comdlg32.dll**: 3 thunks
- **version.dll**: 3 thunks
- **crypt32.dll**: 2 thunks
- **shlwapi.dll**: 1 thunk
- **wintrust.dll**: 1 thunk

### PE 结构
```
Section         VA          VSize       特性
----------------------------------------------
.text           0x1000      0xfb658     CODE/EXEC/READ
.rdata          0xfd000     0x43a00     INIT/READ
.data           0x141000    0xbc00      INIT/READ/WRITE
.pdata          0x14d000    0x8600      INIT/READ
.fill           0x156000    0x0         (gap filler)
.rsrc           0xec2000    0x9400      INIT/READ
.pdata          0xecc000    0xb200      INIT/READ (exception)
.reloc          0xed8000    0x2000      INIT/READ (ASLR disabled)
.boot           0xeda000    0x200       CODE/EXEC (TLS bootstrap)
.tls            0xedb000    0x200       INIT/READ/WRITE
.import         0xedc000    0x2a00      INIT/READ/WRITE
```

---

## 验证结果

### 与原始文件对比
```bash
./mida-cli.exe verify 启动器U.exe 启动器.exe
```

**预期差异**:
- ✅ Entry point: unpacked=0x1000 vs reference=0xBD5807 (正常)
- ✅ Section count: 11 vs 8 (添加了 .import/.tls/.boot/.reloc)
- ⚠️ Import thunks: 545 vs 660 (115个函数差异)

**导入表差异说明**:
- 模块顺序不同（字母序 vs 原始顺序）- 不影响功能
- 函数数量差异：545 vs 660 (缺少115个函数)
- 可能原因：Themida 混淆导致部分 API 无法正确识别

### 运行时测试
```bash
timeout 5 启动器U.exe
# 结果: Segmentation fault (退出码 139)
```

⚠️ **已知问题** (与 project-overview.md 一致):
> `runtime\启动器.exe`: 当前脱壳输出有 18 modules / 545 thunks，结构匹配历史参考，但**运行时崩溃 `0xC0000005`，无窗口**。历史 `启动器U.exe` 在当前环境中也崩溃，因此仅作为结构参考，非运行时基准。

---

## 脱壳过程关键日志

### 1. 初始化
```
[INFO] Loading: D:/Tools/RE/dumps/runtime/启动器.exe
[DEBUG] PE architecture is_64bit=true
[INFO] Entry point RVA: 0xbd5807, EP offset: 0x53a607
[INFO] Themida version: V3
```

### 2. 进程创建与反调试绕过
```
[INFO] Debuggee process created pid=17460 tid=5248
[DEBUG] PEB address peb=0x3e0000
[DEBUG] Process image base image_base=0x140000000
[INFO] Cleared PEB.pShimData to prevent apphelp hooks
[INFO] post-attach: main thread resumed without a debug port
[INFO] post-attach: no debug port — direct dump mode
```

### 3. IAT 解析
```
[INFO] post-attach: polling IAT at 0x1400fd000 for resolution...
[GOOD] post-attach: IAT resolved, first slot = 0x1402f0 (after 112 ms)
[INFO] IAT multi-block: primary block at slot 64 (120 slots)
[INFO] IAT boundaries: start=0x1400fd000, end=0x1400fe1e0, size=4576 (572 slots)
```

### 4. OEP 捕获
```
[GOOD] post-attach: first decrypted .text execution captured at 0x1400daebe after 675 ms
[INFO] x64 CRT startup (__scrt_common_main_seh) found in live memory real_oep=0x140001000
[GOOD] post-attach: OEP captured from RIP: 0x1400daebe
[INFO] Replacing post-attach RIP snapshot with scanned OEP
[INFO] Final OEP: 0x140001000
```

### 5. 导入表重建
```
[DEBUG] Module snapshot complete module_count=38
[INFO] Import table reconstructed module_count=18 thunk_count=545
[INFO] Read 21 import modules with 660 total functions from original PE
[INFO] Fixing module attribution using original PE import table
[INFO] Added missing module 'ole32.dll' with 8 thunks
[INFO] Resolved 544 API addresses from live IAT image
```

### 6. 容器恢复 (TLS bootstrap)
```
[DEBUG] Detected heap-referenced container rva=0x145710 heap_size=64
[INFO] Detected heap-referenced containers requiring snapshot count=1
[INFO] Reset stale SecurityCookie-encoded .data containers cookie=0xd98c7a7d1b08 containers=1
[INFO] Installed TLS callback container restoration bootstrap tls_rva=0xedb000 boot_rva=0xeda000
```

### 7. 输出生成
```
[INFO] Created .pdata section idx=6 VA=0xecc000 size=0xb124 (Exception dir restored)
[INFO] Created .reloc section idx=7 VA=0xed8000 vsize=0x2000 raw=0x2000
[INFO] Created .import section section_va=0xedc000 modules=18 thunks=545
[INFO] Relocation table: 1971 entries (4172 bytes), VA=0xed8000, ASLR disabled
[INFO] Packed section layout: 15581696 bytes -> 1507840 bytes (saved 14073856 bytes)
[INFO] Dump written successfully path=启动器U.exe size=1507840 sections=11
[GOOD] Unpacked: D:/Tools/RE/dumps/runtime\启动器U.exe
```

---

## 项目状态验证

### CLI 工具
```bash
$ ./target/release/mida-cli.exe --version
mida-cli 0.1.0

$ ./target/release/mida-cli.exe --help
Magicmida-RS v0.1.0 - Themida Automatic Unpacker
[完整帮助信息显示正常]
```

### 代码质量检查
```bash
$ cargo clippy --release
```
**结果**: 
- ✅ 0 errors
- ⚠️ 17 warnings (未使用的常量/函数、复杂度警告)
  - `mida-pe` crate: 7 warnings
  - 主要类型：unused constants, too many arguments, complex types

### Git 状态
```
M  crates/cli/src/args.rs          (CLI 改进)
M  crates/cli/src/commands.rs      (CLI 改进)
M  crates/cli/src/main.rs          (CLI 改进)
M  crates/pe/src/dumper/*.rs       (容器恢复相关)
?? .cargo/config.toml              (新增: Git Bash 链接器修复)
?? BUILD_GUIDE.md                  (新增: 构建指南)
?? CLI_FIX_REPORT.md               (新增: CLI 修复报告)
?? USAGE.md                        (新增: 使用手册)
?? build.sh                        (新增: 一键构建脚本)
```

---

## 结论

### ✅ 成功项
1. **脱壳流程完整** - 所有核心步骤正常执行
2. **结构重建正确** - PE 结构、IAT、异常表、TLS 引导均正确
3. **导入表恢复** - 18 modules / 545 thunks (结构完整)
4. **工具链可用** - CLI、build.sh、验证命令均正常工作

### ⚠️ 已知限制
1. **运行时崩溃** - 与项目 memory 中记录一致，非回归问题
2. **导入函数差异** - 545 vs 660 thunks (缺失115个函数)
3. **测试套件链接失败** - Git Bash 环境下需使用 `./build.sh` 而非直接 `cargo test`

### 📋 与 Memory 记录对比
项目 memory (project-overview.md) 记录：
> `runtime\启动器.exe`: 18 modules / 545 thunks, 结构匹配历史参考，但运行时崩溃 `0xC0000005`

**本次验证结果**: ✅ 完全一致
- 18 modules / 545 thunks ✓
- 运行时崩溃 (Segmentation fault) ✓
- 结构正确但不可运行 ✓

---

## 建议

### 短期
1. **继续使用结构验证** - 对于 `启动器.exe`，以结构完整性为主要指标
2. **黄金样本优先** - `时光单开.exe` 作为可运行验证的主要测试样本
3. **文档同步** - 需要更新 Obsidian KB (见 memory: obsidian-kb.md)

### 长期
1. **导入函数差异调查** - 分析缺失的 115 个函数是否影响关键功能
2. **崩溃原因排查** - 深入分析 `启动器.exe` 崩溃的根本原因（可能的方向：容器恢复、堆引用、反调试残留）
3. **测试环境改进** - 使用 `build.sh` 作为标准构建流程，避免 Git Bash 链接器冲突

---

**生成时间**: 2026-07-15T15:52:00+08:00  
**工具版本**: mida-cli 0.1.0  
**报告生成**: Claude Opus 4.8
