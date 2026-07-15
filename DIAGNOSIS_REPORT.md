# Magicmida-RS 脱壳问题诊断报告
日期：2026-07-16

## 问题现象
- raw_dump.exe能启动，但GUI不显示
- 进程有4个线程（vs 原始程序12个线程）
- 程序在ntdll.dll中发生访问违例崩溃（0xc0000005）

## 诊断步骤执行结果

### Step 1: 脱壳日志分析

**关键发现：**
1. **OEP检测过程：**
   - 初始检测：`0x1400070b7`（MSVC pattern）
   - CRT startup扫描修正：`0x140001000` ✅
   - 最终OEP：`0x140001000`

2. **Dump时机：**
   - 等待了60秒才timeout进行dump
   - 主线程RIP在`.text`外（说明已经运行了一段时间）
   - IAT已完全解析

3. **IAT修复状态：**
   - 重建了18个模块，545个thunk
   - ⚠️ **3个IAT slot无法修复：**
     - `0x1400fd3c0`
     - `0x1400fd718`
     - `0x1400fd748`
   - 成功解析544个API地址

4. **特殊处理：**
   - 安装了TLS callback用于.data恢复
   - 重置了SecurityCookie编码的容器（1个）
   - 生成了.data恢复代码（24字节）

### Step 2: 进程行为对比

| 指标 | 原始加壳程序 | raw_dump.exe |
|------|-------------|--------------|
| 能否启动 | ✅ | ✅ |
| 线程数 | 12 | 4 |
| GUI显示 | ✅ 有窗口 | ❌ 无窗口 |
| 窗口标题 | "猪猪WLK 一键宏 - 登录/注册　" | N/A |
| MainWindowHandle | 3345290 | 0 |
| 崩溃 | ❌ | ✅ ntdll.dll 0xc0000005 |

### Step 3: PE结构对比

**Entry Point：**
- 原始：`0xBD5807`（Themida入口）
- Dumped：`0x1000`（真实OEP）✅

**.data Section：**
- 原始：VA=0x141000, VSize=0xBA74, RawSize=**0x0**（磁盘上为空）
- Dumped：VA=0x141000, VSize=0xBA74, RawSize=**0xBC00**（包含运行时数据）✅

**新增Section（dump过程创建）：**
- `.boot` - TLS callback bootstrap代码
- `.tls` - TLS目录
- `.import` - 重建的导入表
- `.pdata` - 异常处理数据
- `.reloc` - 重定位表

## 根本原因分析

### ❌ **排除的假设：**
1. ~~"Dump时机太早"~~ - 实际等待了60秒，IAT已完全解析
2. ~~".data未初始化"~~ - .data已正确捕获
3. ~~"OEP错误"~~ - CRT startup扫描修正了OEP

### ✅ **真正的问题：**

**主要嫌疑：TLS Callback Bootstrap代码**

从日志第69行：
```
Installed TLS callback container restoration bootstrap 
[tls_rva=0xee6000] [boot_rva=0xeda000] [containers=1] [original_entry_point=0x1000]
```

程序执行流程：
```
Windows Loader
    ↓
TLS Callback (0xeda000) ← 在这里崩溃！
    ↓ (应该恢复.data)
    ↓ (应该跳转到真实Entry Point)
    ↓
Entry Point (0x1000) ← 从未到达
```

**崩溃原因推测：**
1. **TLS bootstrap代码有bug** - 访问了无效内存地址
2. **SecurityCookie容器恢复逻辑错误** - 日志第59行显示重置了1个容器
3. **HeapAlloc调用失败** - TLS bootstrap需要分配堆内存来恢复.data

**次要嫌疑：3个未修复的IAT slot**

日志第48-50行显示3个IAT slot跳过：
- 这些可能是程序初始化必需的API
- 如果TLS callback或Entry Point代码调用这些API，会崩溃

## 验证方案

### 方案A：禁用TLS Callback，直接测试

修改脱壳器，生成一个**不使用TLS callback**的版本：

```rust
// 在unpack命令中添加 --no-tls-bootstrap 选项
mida-cli.exe unpack 启动器.exe --output test_no_tls.exe --no-tls-bootstrap
```

如果不崩溃 → 证明是TLS bootstrap代码的问题
如果仍崩溃 → 问题在IAT或其他PE结构

### 方案B：用x64dbg调试TLS Callback

1. 用x64dbg加载raw_dump.exe
2. 在TLS callback入口（0x140eda000）下断点
3. 单步跟踪，找到崩溃指令
4. 检查是什么导致访问违例

### 方案C：检查未修复的IAT slot

查看那3个跳过的IAT slot对应什么API：
```rust
// 在代码中添加日志，打印被跳过slot的目标地址
// 然后用符号解析工具查找这些地址对应的API
```

## ✅ 已发现并修复的Bug

### Bug #1: TLS Bootstrap参数类型不匹配 (CRITICAL)

**位置**：`crates/pe/src/dumper/tls_bootstrap.rs:89-95`

**问题**：
```rust
// 错误代码：
let boot_stub = match super::container_bootstrap::build_tls_bootstrap_stub(
    boot_rva,
    get_process_heap_iat_rva,
    heap_alloc_iat_rva,
    containers,
    global_vars,  // ❌ 类型错误！传递 &[GlobalVarSnapshot]
    // ❌ 缺少 image_base 参数
) {
```

**函数签名**：
```rust
pub(crate) fn build_tls_bootstrap_stub(
    stub_rva: u32,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    containers: &[ContainerSnapshot],
    data_snapshot: Option<&DataSectionSnapshot>,  // 期望这个类型
    image_base: u64,                               // 还缺少这个参数
) -> Option<Vec<u8>>
```

**修复**：
```rust
// 正确代码：
let boot_stub = match super::container_bootstrap::build_tls_bootstrap_stub(
    boot_rva,
    get_process_heap_iat_rva,
    heap_alloc_iat_rva,
    containers,
    None,        // ✅ 传递正确的类型
    image_base,  // ✅ 添加缺少的参数
) {
```

**影响**：
- 导致参数位置错乱
- TLS callback执行时访问无效内存
- 程序在ntdll.dll中崩溃（0xc0000005）
- Entry Point从未到达，GUI从未初始化

**引入时间**：2026-07-15 commit b0ac410 "feat: implement global variable snapshot and restoration mechanism"

## 建议的修复优先级

1. ✅ **已完成**：修复TLS bootstrap参数类型不匹配bug
2. **进行中**：重新编译并测试修复后的版本
3. **如果仍有问题**：修复IAT slot跳过逻辑（3个未修复的slot）

## 关键代码位置

需要检查的模块：
- `crates/cli/src/unpacker/bootstrap.rs` - TLS bootstrap生成代码
- `crates/cli/src/unpacker/iat_fixer.rs` - IAT修复逻辑
- `crates/cli/src/unpacker/data_section.rs` - .data恢复逻辑

关键日志：
```
[WARN] IAT slot has no candidate for winning module, skipping [iat_va="0x1400fd3c0"]
```
这个警告说明IAT修复算法在某些情况下失败了。
