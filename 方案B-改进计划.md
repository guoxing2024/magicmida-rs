# 方案 B：改进容器检测 - 实施计划

**日期**: 2026-07-15  
**策略**: 扩展 TLS Bootstrap 以恢复普通全局变量

---

## 🎯 目标

让脱壳器能够自动捕获并恢复所有关键全局变量，不仅限于容器。

---

## 🔍 问题分析

### 发现

1. **36 个容器被检测到** ✅
2. **问题变量不是容器** ⚠️
   - 0x143332, 0x143338, 0x143340
   - 这些是普通全局变量

### 根本原因

这些变量的正确值只存在于运行时：
- 原始文件中被 Themida 加密
- 运行时解密初始化
- 静态转储捕获的是错误值

---

## 💡 改进策略

### 策略 1: 扩展 TLS Bootstrap (推荐)

**目标**: 让 Bootstrap 恢复非容器的全局变量

**实施步骤**:

#### 第 1 步: 创建全局变量快照机制

```rust
// 在 container_snapshot.rs 中添加

/// Snapshot of a non-container global variable
#[derive(Debug, Clone)]
pub struct GlobalVarSnapshot {
    /// RVA in .data where the variable is stored
    pub rva: u32,
    /// Runtime value from live process
    pub value: Vec<u8>,
}

/// Detect critical global variables that need runtime values
pub fn detect_global_vars(
    pe: &PeHeader,
    dump_buf: &[u8],
    debugger: &mut dyn mida_core::DebuggerCore,
    critical_rvas: &[u32],  // 关键 RVA 列表
) -> Vec<GlobalVarSnapshot> {
    let mut vars = Vec::new();
    let image_base = pe.nt_headers.optional_header.image_base;
    
    for &rva in critical_rvas {
        let va = image_base + rva as u64;
        
        // 从运行时读取值
        let mut buffer = vec![0u8; 8];
        if debugger.read_memory(va, &mut buffer).is_ok() {
            info!("Captured global var at RVA {:#x}: {:?}", rva, buffer);
            
            vars.push(GlobalVarSnapshot {
                rva,
                value: buffer,
            });
        }
    }
    
    vars
}
```

#### 第 2 步: 在转储时自动检测关键变量

```rust
// 分析 OEP 代码，找出前 N 条指令引用的所有 .data 地址
pub fn find_critical_vars_from_oep(
    pe: &PeHeader,
    dump_buf: &[u8],
    oep_rva: u32,
) -> Vec<u32> {
    let mut critical_rvas = Vec::new();
    
    // 反汇编 OEP 前 256 字节
    // 找出所有 RIP-relative 内存引用
    // 添加到 critical_rvas
    
    // 简化实现：硬编码已知的关键地址
    critical_rvas.extend_from_slice(&[
        0x143332,
        0x143338,
        0x143340,
    ]);
    
    critical_rvas
}
```

#### 第 3 步: 修改 TLS Bootstrap 恢复这些变量

```rust
// 在 tls_bootstrap.rs 中修改

pub(crate) fn install_tls_callback_bootstrap(
    pe: &mut PeHeader,
    containers: &[ContainerSnapshot],
    global_vars: &[GlobalVarSnapshot],  // 新增参数
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    original_entry_point: u32,
) -> Option<u32> {
    // ... 现有代码 ...
    
    // 创建扩展的 bootstrap
    let boot_stub = build_extended_tls_bootstrap_stub(
        boot_rva,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers,
        global_vars,  // 传递全局变量
    )?;
    
    // ...
}
```

#### 第 4 步: 生成扩展的 Bootstrap 代码

```rust
// 在 container_bootstrap.rs 中添加

fn build_extended_tls_bootstrap_stub(
    stub_rva: u32,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    containers: &[ContainerSnapshot],
    global_vars: &[GlobalVarSnapshot],
) -> Option<Vec<u8>> {
    let mut stub = Vec::new();
    
    // 1. 恢复容器（现有逻辑）
    // ...
    
    // 2. 恢复全局变量（新增）
    for var in global_vars {
        // mov rax, [rip + data]
        // lea rdx, [rip + target]
        // mov [rdx], rax
        
        // 简化：直接在 stub 中嵌入数据
        // 在运行时复制到目标地址
    }
    
    // 3. ret
    stub.push(0xC3);
    
    Some(stub)
}
```

---

## 📋 实施清单

### 阶段 1: 基础设施 (3-4 小时)

- [ ] 创建 `GlobalVarSnapshot` 结构
- [ ] 实现 `detect_global_vars` 函数
- [ ] 实现 `find_critical_vars_from_oep` 函数
- [ ] 添加测试

### 阶段 2: Bootstrap 扩展 (4-5 小时)

- [ ] 修改 `install_tls_callback_bootstrap` 接口
- [ ] 实现 `build_extended_tls_bootstrap_stub`
- [ ] 生成全局变量恢复的汇编代码
- [ ] 添加测试

### 阶段 3: 集成测试 (2-3 小时)

- [ ] 修改 `heap_bootstrap.rs` 调用新接口
- [ ] 重新脱壳测试程序
- [ ] 验证全局变量值
- [ ] 测试程序运行

### 阶段 4: 文档和优化 (1-2 小时)

- [ ] 更新技术文档
- [ ] 代码注释
- [ ] 性能优化

**总计预估**: 10-14 小时

---

## 🎲 替代方案

### 快速方案：使用内存补丁文件

**思路**: 不修改 Bootstrap，而是在输出时直接写入正确的值

```rust
// 在 output_writer.rs 中

// 从 global_vars 快照直接写入
for var in global_vars {
    let offset = rva_to_offset(var.rva);
    out_data[offset..offset+var.value.len()].copy_from_slice(&var.value);
}
```

**优点**:
- 实现简单（1-2 小时）
- 不需要修改 Bootstrap

**缺点**:
- 不够通用
- 每次转储都需要运行时

---

## 🚀 推荐执行路径

### 选项 A: 快速方案（推荐）

1. 实施快速内存补丁方案
2. 验证程序能否运行
3. 如果成功，再考虑完整实施

**时间**: 2-3 小时

### 选项 B: 完整实施

按照阶段 1-4 完整实施

**时间**: 10-14 小时

---

## 📊 风险评估

| 风险 | 可能性 | 影响 | 缓解措施 |
|------|--------|------|----------|
| 还有其他未知变量 | 中 | 高 | OEP 分析自动检测 |
| Bootstrap 代码过大 | 低 | 中 | 优化生成逻辑 |
| 运行时值不稳定 | 低 | 高 | 多次验证 |

---

## 🎯 下一步

**立即行动**: 实施快速方案

```powershell
# 1. 从运行时提取值（使用调试器）
# 2. 修改 output_writer.rs 写入这些值
# 3. 测试程序
```

如果快速方案成功，证明思路正确，再投入时间完整实施。
