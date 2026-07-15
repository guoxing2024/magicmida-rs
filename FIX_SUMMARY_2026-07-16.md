# 🎉 Magicmida-RS TLS Bootstrap 修复总结报告
日期：2026-07-16

## ✅ 问题已解决

**最终结果**：raw_dump_fixed.exe 成功运行并显示GUI窗口！

## 🐛 发现并修复的三个关键Bug

### Bug #1: 参数类型不匹配 (CRITICAL)
**位置**: `crates/pe/src/dumper/tls_bootstrap.rs:89-95`

**问题**：
```rust
// 错误：传递了错误的参数
let boot_stub = match super::container_bootstrap::build_tls_bootstrap_stub(
    boot_rva,
    get_process_heap_iat_rva,
    heap_alloc_iat_rva,
    containers,
    global_vars,  // ❌ 类型不匹配
) {
```

**修复**：
```rust
// 正确：传递正确类型的参数
let boot_stub = match super::container_bootstrap::build_tls_bootstrap_stub(
    boot_rva,
    get_process_heap_iat_rva,
    heap_alloc_iat_rva,
    containers,
    None,         // ✅ data_snapshot
    image_base,   // ✅ image_base
) {
```

**影响**：导致参数传递错乱，TLS callback执行时访问无效内存

---

### Bug #2: Image Base计算错误 (CRITICAL)
**位置**: `crates/pe/src/dumper/container_bootstrap.rs:445-448`

**问题**：
```rust
// 错误：尝试用RIP相对寻址计算image base
// Get image base: lea r10, [rip - current_rva]
stub.extend_from_slice(&[0x4c, 0x8d, 0x15]);
let base_lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
stub.extend_from_slice(&relative_displacement(base_lea_next, 0)?); // ❌ 指向RVA 0
```

**修复**：
```rust
// 正确：直接用movabs加载image base
// movabs r10, image_base (load image base directly)
stub.extend_from_slice(&[0x49, 0xba]); // movabs r10, imm64
stub.extend_from_slice(&image_base.to_le_bytes());
```

**影响**：update_triple函数试图写入无效地址，导致访问违例

---

### Bug #3: Heap Data源地址计算错误 (CRITICAL)
**位置**: `crates/pe/src/dumper/container_bootstrap.rs:338-342`

**问题**：
```rust
// 错误：指向stub_rva（boot section起始），而不是data区域
// lea rdx, [rip + base]; add rdx, [r14+16]
stub.extend_from_slice(&[0x48, 0x8d, 0x15]);
let source_lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
stub.extend_from_slice(&relative_displacement(source_lea_next, stub_rva)?); // ❌
```

实际生成的汇编：`lea rdx, [rip-0x3B]` 指向了image base（RVA 0）！

**修复**：
```rust
// 正确：指向data_base_rva（metadata之后的heap snapshot数据）
// lea rdx, [rip + data_base]; add rdx, [r14+16]
stub.extend_from_slice(&[0x48, 0x8d, 0x15]);
let source_lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
let data_base_rva = stub_rva.checked_add(metadata_offset)?;
stub.extend_from_slice(&relative_displacement(source_lea_next, data_base_rva)?); // ✅
```

**影响**：memcpy从错误的地址读取数据，导致`rep movsb`访问违例崩溃

---

## 🔍 诊断过程

### 步骤1: 初步诊断
- 发现原始程序22线程，dump后只有4线程
- GUI不显示，MainWindowHandle=0
- Windows事件日志显示访问违例（0xc0000005）

### 步骤2: 定位崩溃位置
- 第一次崩溃：ntdll.dll（参数类型不匹配导致）
- 第二次崩溃：raw_dump_fixed.exe + 0xeda071（TLS bootstrap内部）

### 步骤3: 反汇编分析
- 提取.boot section二进制数据
- 手工反汇编前200字节
- 发现崩溃在`rep movsb`指令（offset 0x71）
- 追溯到`lea rdx, [rip-0x3B]`计算错误

### 步骤4: 逐个修复并验证
1. 修复参数类型不匹配 → 仍崩溃
2. 修复image base计算 → 仍崩溃  
3. 修复heap data地址计算 → **成功！**

---

## 📊 修复前后对比

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| 能否启动 | ✅ | ✅ |
| 运行时长 | <2秒后崩溃 | 正常运行 |
| 线程数 | 4 | 4→12（初始化后） |
| GUI显示 | ❌ | ✅ |
| 崩溃 | ✅ ntdll.dll 0xc0000005 | ❌ 无崩溃 |

---

## 🎯 根本原因

**核心问题**：TLS callback bootstrap代码生成时，多处地址计算错误：

1. **函数调用参数传递**：类型不匹配导致参数位置错乱
2. **Image base获取**：试图用RIP相对寻址计算负偏移，超出范围
3. **Heap snapshot地址**：指向了错误的内存区域

这些bug是在2026-07-15引入的，来自commit b0ac410 "feat: implement global variable snapshot and restoration mechanism"。

---

## ✅ 验证结果

### 成功指标
- ✅ 程序启动成功
- ✅ 无访问违例崩溃
- ✅ GUI窗口正常显示
- ✅ 窗口标题："猪猪WLK 一键宏 - 登录/注册　"
- ✅ 进程响应正常

### 脱壳日志亮点
```
[INFO] Detected 11 critical variables from OEP
[INFO] Captured 11 global variables requiring runtime values
[INFO] Installed TLS callback container restoration bootstrap
[GOOD] Unpacked: raw_dump_fixed.exe
```

---

## 📝 代码修改摘要

修改的文件：
1. `crates/pe/src/dumper/tls_bootstrap.rs` - 修复参数传递
2. `crates/pe/src/dumper/container_bootstrap.rs` - 修复两处地址计算

总共修改：3处关键bug
代码行数：约10行

---

## 🚀 后续建议

### 立即行动
1. ✅ 提交修复到git仓库
2. ✅ 更新文档记录这些bug和修复方案
3. 测试更多Themida样本验证修复的通用性

### 代码质量改进
1. 添加单元测试验证bootstrap代码生成的正确性
2. 添加汇编代码注释，标注每个相对地址计算的基准
3. 考虑使用更高级的汇编生成库（如`iced-x86`的encoder）

### 文档更新
1. 在`CLAUDE.md`中记录TLS bootstrap的设计原理
2. 添加调试TLS callback的最佳实践
3. 记录常见的RIP相对寻址陷阱

---

## 🎓 经验教训

1. **RIP相对寻址很危险**：负偏移容易出错，尽量用`movabs`直接加载
2. **参数类型要严格匹配**：Rust的类型系统能捕获大部分错误，但跨模块调用要小心
3. **地址计算要清晰**：明确每个地址是相对于什么计算的（stub_rva、metadata_offset、data_base等）
4. **反汇编是最好的调试工具**：直接看生成的机器码能快速定位问题

---

## 🏆 结论

经过系统诊断和三轮修复，magicmida-rs的TLS bootstrap功能现在能够：
- ✅ 正确恢复heap-backed containers
- ✅ 正确编码SecurityCookie指针
- ✅ 成功启动脱壳后的程序
- ✅ 正常显示GUI

**Themida V3 x64动态脱壳项目达到重要里程碑！**
