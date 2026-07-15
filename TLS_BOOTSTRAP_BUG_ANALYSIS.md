# TLS Bootstrap Bug分析报告
日期：2026-07-16

## 🔴 已确认Bug

### Bug位置
**文件**：`crates/pe/src/dumper/tls_bootstrap.rs`  
**行号**：89-95

### Bug描述
```rust
// 错误代码（已修复）：
let boot_stub = match super::container_bootstrap::build_tls_bootstrap_stub(
    boot_rva,
    get_process_heap_iat_rva,
    heap_alloc_iat_rva,
    containers,
    global_vars,  // ❌ 类型错误！这是 &[GlobalVarSnapshot]
) {
```

**函数签名期望**：
```rust
pub(crate) fn build_tls_bootstrap_stub(
    stub_rva: u32,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    containers: &[ContainerSnapshot],
    data_snapshot: Option<&DataSectionSnapshot>,  // ← 期望这个类型
    image_base: u64,                               // ← 还缺少这个参数
) -> Option<Vec<u8>>
```

### 症状
1. **编译**: 因为参数数量不匹配，代码不应该能编译通过
2. **运行时**: 如果通过某种方式编译了，会导致：
   - 参数位置错乱
   - 内存访问违例
   - TLS callback崩溃

## 💥 崩溃证据

### Windows事件日志
```
出错应用程序名称： raw_dump.exe
出错模块名称： ntdll.dll
异常代码： 0xc0000005  ← 访问违例
错误偏移： 0x000000000003dcb4
```

### 进程状态
| 指标 | 原始程序 | raw_dump.exe |
|------|---------|--------------|
| 启动成功 | ✅ | ✅ |
| 线程数 | 12 | 4 |
| GUI显示 | ✅ | ❌ |
| 崩溃 | ❌ | ✅ (ntdll) |

**分析**：
- 4个线程说明只创建了最基本的线程（主线程+3个系统线程）
- GUI初始化代码从未执行
- 说明程序在Entry Point之前就崩溃了
- 唯一在Entry Point之前执行的是TLS Callback

## 🔧 修复方案

### 已实施修复
```rust
// 正确代码：
let boot_stub = match super::container_bootstrap::build_tls_bootstrap_stub(
    boot_rva,
    get_process_heap_iat_rva,
    heap_alloc_iat_rva,
    containers,
    None,        // ✅ 传递None作为data_snapshot
    image_base,  // ✅ 添加缺少的image_base参数
) {
```

### 为什么之前能编译？

这是关键问题。Rust编译器应该捕获参数不匹配。可能的原因：

1. **使用的是旧版本release二进制**：
   - 最后成功编译可能在bug引入之前
   - `target/release/mida-cli.exe`可能是旧版本

2. **条件编译**：
   - 可能有`#[cfg]`宏导致不同平台使用不同代码路径

3. **泛型/trait导致类型推断**：
   - 不太可能，因为这是具体类型

让我检查release二进制的编译时间：
