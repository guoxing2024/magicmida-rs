# Complete .data Section Restoration - Implementation Summary

## Date: 2026-07-15

## Problem
启动器.exe 脱壳后可以启动但GUI不显示，在0xEDA071崩溃（memcpy指令）。之前的全局变量自动检测方案只捕获了11个变量，其中4个是0，可能遗漏了关键变量。

## Solution: 完整.data段Dump和恢复

### 核心思想
不再尝试识别单个全局变量，而是：
1. 在OEP时从活动进程捕获**完整的**.data段
2. 将整个.data段快照嵌入到bootstrap stub中
3. 在TLS callback中**先恢复整个.data段**，然后再恢复heap容器

### 优势
- **彻底性**：不会遗漏任何变量
- **简单性**：避免复杂的启发式检测
- **正确性**：Themida在运行时初始化所有.data，我们捕获完整的运行时状态

## 实现细节

### 1. 新增模块: `data_snapshot.rs`

```rust
pub struct DataSectionSnapshot {
    pub data_rva: u32,
    pub data_size: u32,
    pub data_content: Vec<u8>,
    pub skip_regions: Vec<SkipRegion>,  // 容器元数据位置
}

pub fn capture_data_section(
    pe: &PeHeader,
    debugger: &mut dyn DebuggerCore,
    container_rvas: &[u32],
) -> Option<DataSectionSnapshot>
```

**关键点**：
- 从活动进程读取整个.data段
- 识别SecurityCookie-encoded容器的位置（24字节：3个u64指针）
- 这些位置会被标记为skip_regions，因为它们将由容器恢复代码处理

### 2. 修改 `heap_bootstrap.rs`

```rust
// OLD: 检测单个变量
let critical_rvas = detect_critical_vars_from_oep(pe, dump_buf, oep, 50);
let global_vars = detect_global_vars(pe, dbg, &critical_rvas, 8);

// NEW: 捕获完整.data段
let data_snapshot = capture_data_section(pe, dbg, &container_rvas);
```

### 3. 修改 `tls_bootstrap.rs`

函数签名从：
```rust
fn install_tls_callback_bootstrap(
    pe: &mut PeHeader,
    containers: &[ContainerSnapshot],
    global_vars: &[GlobalVarSnapshot],  // OLD
    ...
) -> Option<u32>
```

改为：
```rust
fn install_tls_callback_bootstrap(
    pe: &mut PeHeader,
    containers: &[ContainerSnapshot],
    data_snapshot: Option<&DataSectionSnapshot>,  // NEW
    ...
) -> Option<u32>
```

### 4. 修改 `container_bootstrap.rs`

#### 4.1 Bootstrap执行顺序

```asm
TLS Callback (在CRT初始化后，OEP之前):
  1. sub rsp, 0x38
  
  2. 【NEW】恢复完整.data段:
     mov rdi, data_va           ; 目标 = .data虚拟地址
     lea rsi, [rip + snapshot]  ; 源 = 嵌入的快照
     mov rcx, data_size         ; 字节数
     rep movsb                  ; memcpy
  
  3. 恢复heap容器:
     call GetProcessHeap
     for each container:
       HeapAlloc(size)
       memcpy(allocated, snapshot, size)
       update SecurityCookie-encoded triple in .data
  
  4. add rsp, 0x38
  5. ret  ; 返回到CRT，继续执行到OEP
```

#### 4.2 代码生成

新增 `restore_data_section()` 函数：
```rust
fn restore_data_section(
    stub: &mut Vec<u8>,
    stub_rva: u32,
    snapshot: &DataSectionSnapshot,
    data_snapshot_offset: usize,
    image_base: u64,
) -> Option<()>
```

生成的x64汇编：
- `movabs rdi, data_va`：使用绝对地址（因为.data在固定VA）
- `lea rsi, [rip + snapshot]`：相对寻址嵌入的快照
- `mov ecx, data_size`
- `rep movsb`

#### 4.3 Stub布局

```
.boot section:
  [stub code ~250 bytes]                      ; 代码区
  [container metadata array]                  ; 容器元数据
  [heap snapshot data for container 0]        ; 容器数据
  [heap snapshot data for container 1]
  ...
  [complete .data section snapshot]           ; NEW: 完整.data段快照
```

## 关键改进

### 1. 时序正确
- **先恢复.data段**：确保所有全局变量被初始化
- **再恢复容器**：容器恢复会覆盖SecurityCookie-encoded三元组，这是预期的行为

### 2. 覆盖率
- 旧方案：只捕获OEP前50条指令引用的11个变量
- 新方案：捕获整个.data段（通常几十KB）

### 3. 容器兼容性
- Skip regions机制确保容器元数据不会被破坏
- 但实际上，.data恢复会先写入整个段，然后容器恢复再覆盖容器位置
- 最终结果：.data完整初始化 + 容器正确恢复

## 测试计划

### 测试脚本: `test_data_restore.ps1`

1. 启动x64dbg加载样本
2. 运行`mida-cli unpack --attach <PID>`
3. 检查输出文件
4. 启动脱壳程序
5. 验证GUI是否显示

### 预期结果

如果方案成功：
- 进程启动不崩溃
- MainWindowHandle != 0
- GUI窗口正常显示

## 代码统计

**新增文件**：
- `crates/pe/src/dumper/data_snapshot.rs` (213行)

**修改文件**：
- `crates/pe/src/dumper/mod.rs` (+1行)
- `crates/pe/src/dumper/heap_bootstrap.rs` (~15行修改)
- `crates/pe/src/dumper/tls_bootstrap.rs` (~5行修改)
- `crates/pe/src/dumper/container_bootstrap.rs` (~50行修改)

**总计**：约 280行新增/修改代码

## 技术亮点

1. **完整性**：不依赖启发式检测，捕获所有运行时初始化的数据
2. **正确性**：执行顺序严格遵守Windows加载器规范
3. **效率**：使用`rep movsb`进行高效批量复制
4. **兼容性**：与现有容器恢复机制完美集成

## 潜在问题

### 1. .data段大小
- 如果.data段过大（>1MB），可能导致bootstrap stub过大
- 当前限制：最大1MB
- 实际情况：启动器.exe的.data段约50KB，完全可接受

### 2. Self-modifying代码
- 如果程序在运行时修改.data段的某些区域，可能会有竞争
- 但这种情况罕见，且TLS callback执行很早，风险低

### 3. 内存保护
- .data段必须是可写的
- 通常情况下.data都是RW，不会有问题

## 下一步

1. 运行`test_data_restore.ps1`验证方案
2. 如果成功，更新项目文档
3. 如果失败，使用x64dbg手动调试：
   - 在.data恢复代码设置断点
   - 验证rdi（目标地址）是否正确
   - 验证rsi（源地址）是否指向有效数据
   - 验证rcx（大小）是否合理

## 结论

这是最彻底的解决方案。通过恢复整个.data段，我们避免了：
- 漏掉关键变量
- 变量检测算法的复杂性
- 时序问题

如果这个方案也无法让GUI显示，那么问题可能在其他地方（如.text段的代码完整性、IAT重建、或者程序本身的反调试检测）。
