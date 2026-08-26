# WO-1301A: Route α 设计方案（修订版） — ADR-6 注入链内触碰解密

**工单编号**: WO-1301A (WO-1301 修订)  
**优先级**: P0  
**类型**: 设计文档（docs-only，零实弹零代码）  
**日期**: 2026-08-22  
**状态**: 待总指挥批准  
**修订原因**: 原设计 F1-F5 缺陷（调试器侧探针失效、硬件断点禁用、VEH错位、样本身份、预算无界）

---

## 执行摘要

Route α 核心假说不变：**触碰受保护的 .text 区域触发保护器解密，guard 是已解密区域的标记**。本修订版采用 **ADR-6 注入链内的目标上下文 walker**，在目标进程内执行普通读取，让保护器自身的 VEH 完成解密，调试器只观测熵差。不拦截、不改写、不设硬件断点。

**关键修正**:
- ✅ **探针原语重写**: 调试器侧 RPM → ADR-6 注入的目标内 walker（F2 修复）
- ✅ **去除硬件断点**: 不依赖 DR0-DR3（F1 修复）
- ✅ **VEH 正确归属**: 保护器自有 VEH 处理，我们只读结果（F3 修复）
- ✅ **样本身份预检**: 使用 manifest 授权 vault 对象 rev2（F4 修复）
- ✅ **预算有界**: cap = 120 分钟（F5 修复）

**保留框架**:
- Type A/B/C 三态分类（加密/已执行/guard）
- 熵 + 反汇编判据
- 动态候选扩展策略
- 节流止损机制
- LIVE-4 分阶段结构

---

## 1. 假说陈述（不变，引用原文 §1.1-1.2）

### 1.1 核心假说

**Guard-触发解密假说**（Route α）:
> 保护器在运行时维护解密状态图，将 .text 划分为：
> 1. **Type A - 加密态**：未解密，读取触发 AV 或返回乱码
> 2. **Type B - 解密态-已执行**：控制流已到达
> 3. **Type C - 解密态-guard**：已解密但 RIP 未达，PAGE_GUARD 标记
> 
> **关键修正**: 触碰必须在**目标进程上下文内**执行，保护器的 VEH 才能介入解密。

### 1.2 证据链（保留）

| 证据来源 | 观察 | 支持假说 |
|---------|------|---------|
| Route L-Y AV 模式 | Guard page violations 集中 .text | Guard 是标记非异常 |
| Route U R1 | 120s 超时但进程存活 | 解密可能完成但覆盖不足 |
| ADR-6 现有能力 | runtime_loader 可注入 walker | 技术可行性已验证 |

---

## 2. ADR-6 注入链内 Walker 设计（核心修正）

### 2.1 架构对位

#### 2.1.1 调试器侧 RPM 的失效机制（F2 剖析）

**原设计错误**:
```rust
// ❌ 调试器进程调用 ReadProcessMemory
fn safe_probe(debugger: &dyn DebuggerCore, target_addr: usize) -> ProbeResult {
    let mut buffer = [0u8; 16];
    debugger.read_memory(target_addr, &mut buffer)?;  // RPM
    // ...
}
```

**失效原因**:
1. `ReadProcessMemory` 是**内核模式**操作，直接读取目标进程物理页
2. 不经过目标进程的**用户模式异常分发链**（VEH / SEH）
3. 保护器的 VEH handler 根本不被调用
4. Guard page 标志对 RPM 无效（内核绕过用户态保护）

**实验证据**: 调试器 RPM 读取 guard 页，返回加密内容，不触发 `STATUS_GUARD_PAGE_VIOLATION`

#### 2.1.2 目标上下文 Walker 的正确机制

**修订设计**:
```rust
// ✅ 目标进程内执行读取（通过注入代码）
// 注入的 walker_payload.dll 内：
fn target_context_probe(addr: usize) -> ProbeResult {
    // 1. 设置 SEH 帧（捕获目标自身的异常）
    let guard = install_seh_frame(|exception| {
        if exception.code == STATUS_GUARD_PAGE_VIOLATION {
            // Guard 触发，保护器的 VEH 已处理解密
            EXCEPTION_CONTINUE_EXECUTION
        } else {
            EXCEPTION_CONTINUE_SEARCH
        }
    });
    
    // 2. 普通读取（用户模式指针解引用）
    let result = unsafe {
        let ptr = addr as *const [u8; 16];
        match catch_unwind(|| *ptr) {  // 捕获 Rust panic（AV转换）
            Ok(data) => ProbeResult::Success { data: data.to_vec() },
            Err(_) => ProbeResult::AccessViolation,
        }
    };
    
    // 3. 清理 SEH 帧
    remove_seh_frame(guard);
    
    result
}
```

**关键差异**:

| 方面 | 调试器侧 RPM | 目标内 Walker |
|-----|-------------|--------------|
| **执行上下文** | 调试器进程 | 目标进程 |
| **访问路径** | 内核 API（NtReadVirtualMemory） | 用户模式指针解引用 |
| **异常分发** | 不经过目标的 VEH/SEH | 触发目标的完整异常链 |
| **Guard 响应** | 无效（内核绕过） | 有效（保护器 VEH 处理） |
| **解密触发** | ❌ 不触发 | ✅ 触发 |

### 2.2 ADR-6 注入链复用

**现有基础**（已在生产的 antidebug-runtime 注入链）:

```
CLI unpacker (L561)
  → CREATE_PROCESS 冻结目标
  → VirtualAllocEx 分配远程内存
  → WriteProcessMemory 写入 walker_payload.dll 路径
  → LoadLibrary thunk (CreateRemoteThread)
  → 目标加载 walker_payload.dll
  → DllMain 或导出函数执行 walker 逻辑
  → 通过共享内存或管道返回结果给调试器
```

**Walker Payload 结构**:
```rust
// walker_payload.dll 的 C ABI 导出
#[no_mangle]
pub unsafe extern "C" fn WalkerExecute(
    params: *const WalkerParams,
    results: *mut WalkerResults,
) -> u32 {
    // 1. 解析参数（候选地址列表）
    let params = &*params;
    let candidates = std::slice::from_raw_parts(
        params.candidate_addrs,
        params.candidate_count as usize,
    );
    
    // 2. 逐个触碰
    let mut results_vec = Vec::new();
    for &addr in candidates {
        let probe_result = target_context_probe(addr);
        results_vec.push(probe_result);
        
        // 节流（避免保护器检测高频访问）
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    
    // 3. 写入结果到共享内存
    write_results_to_shared_memory(&results_vec, results);
    
    0  // SUCCESS
}

#[repr(C)]
struct WalkerParams {
    candidate_addrs: *const usize,
    candidate_count: u32,
    options: WalkerOptions,
}

#[repr(C)]
struct WalkerResults {
    results: *mut ProbeResult,
    result_count: u32,
}
```

### 2.3 通信机制

**共享内存方案**（双向通信）:

```rust
// 调试器侧（CLI）
fn invoke_walker(candidates: &[usize]) -> Result<Vec<ProbeResult>> {
    // 1. 创建共享内存
    let shared_mem = create_shared_memory("Local\\WalkerSharedMem", 1024 * 1024)?;
    
    // 2. 写入候选地址列表
    write_candidates_to_shared_memory(&candidates, &shared_mem)?;
    
    // 3. 通过 CreateRemoteThread 调用 walker
    let walker_entry = get_walker_export_address(target_handle, "WalkerExecute")?;
    let thread = unsafe {
        CreateRemoteThread(
            target_handle,
            None,
            0,
            Some(std::mem::transmute(walker_entry)),
            shared_mem.as_ptr() as *const c_void,
            0,
            None,
        )?
    };
    
    // 4. 等待完成（带超时）
    let wait_result = unsafe {
        WaitForSingleObject(thread, 60_000)  // 60s 超时
    };
    
    if wait_result != WAIT_OBJECT_0 {
        return Err("Walker timeout or failed".into());
    }
    
    // 5. 读取结果
    read_results_from_shared_memory(&shared_mem)
}
```

**命名管道方案**（备选，流式传输）:

```rust
// 目标内 walker 实时推送结果
fn target_context_probe_streaming(addr: usize, pipe: &NamedPipe) {
    let result = target_context_probe(addr);
    pipe.write(&bincode::serialize(&result)?)?;
}

// 调试器侧实时接收
fn receive_probe_results(pipe: &NamedPipe) -> impl Iterator<Item = ProbeResult> {
    std::iter::from_fn(move || {
        pipe.read().ok().and_then(|bytes| bincode::deserialize(&bytes).ok())
    })
}
```

---

## 3. 候选地址筛选（修正：使用 LIVE-3 coverage_measure）

### 3.1 Coverage Measure 数据结构（已有产出）

**来源**: Route T/U/V 执行日志中的 `coverage_measure.json`

```json
{
  "text_section": {
    "base": "0x401000",
    "size": "0x8A000"
  },
  "rip_coverage": {
    "total_samples": 12450,
    "unique_addresses": 3820,
    "hotspots": [
      {"addr": "0x405120", "count": 450, "module": "sample.exe"},
      {"addr": "0x410340", "count": 320, "module": "sample.exe"}
    ]
  },
  "cold_regions": [
    {"start": "0x420000", "end": "0x428000", "entropy": 7.8},
    {"start": "0x450000", "end": "0x458000", "entropy": 7.6}
  ],
  "guard_violations": [
    {"addr": "0x410000", "timestamp": "2026-08-20T10:15:32Z"},
    {"addr": "0x438000", "timestamp": "2026-08-20T10:15:45Z"}
  ]
}
```

### 3.2 候选生成算法（修正）

**不再依赖 OEP 邻域猜测，使用实测数据**:

```rust
fn generate_candidates_from_coverage(
    coverage: &CoverageMeasure,
) -> Vec<CandidateAddress> {
    let mut candidates = Vec::new();
    
    // 规则 1: Guard violations 历史（最高优先级）
    for gv in &coverage.guard_violations {
        candidates.push(CandidateAddress {
            address: gv.addr,
            priority: Priority::High,
            reason: "guard_history",
            confidence: 0.95,
        });
    }
    
    // 规则 2: Cold regions（RIP 覆盖 < 5%）
    for cold in &coverage.cold_regions {
        // 在冷区内按页对齐采样
        let mut addr = align_to_page(cold.start);
        while addr < cold.end {
            if coverage.rip_coverage.contains(addr) == false {
                candidates.push(CandidateAddress {
                    address: addr,
                    priority: Priority::Medium,
                    reason: "cold_region",
                    confidence: 0.7,
                });
            }
            addr += 0x1000;  // 4KB 步长
        }
    }
    
    // 规则 3: Hotspot 邻域（已执行区域周围 ±4KB）
    for hotspot in coverage.rip_coverage.hotspots.iter().take(10) {
        for offset in [-0x1000, 0x1000] {
            let addr = (hotspot.addr as i64 + offset) as usize;
            if is_in_text_section(addr, &coverage.text_section) {
                candidates.push(CandidateAddress {
                    address: addr,
                    priority: Priority::Low,
                    reason: "hotspot_vicinity",
                    confidence: 0.5,
                });
            }
        }
    }
    
    // 去重 + 按优先级排序
    deduplicate_and_sort(candidates)
}
```

**预期候选数量**: 200 - 1000（取决于 cold region 大小）

---

## 4. 探针原语规格（完全重写）

### 4.1 目标内探针实现

```rust
// walker_payload/src/probe.rs

use std::panic::catch_unwind;
use winapi::um::errhandlingapi::*;
use winapi::um::winnt::*;

/// 目标上下文安全探针
pub fn safe_probe_in_target(addr: usize) -> ProbeResult {
    // 1. 安装 SEH 帧（结构化异常处理）
    let _seh_guard = SehFrame::new(|exception_record| {
        let code = unsafe { (*exception_record).ExceptionCode };
        
        match code {
            STATUS_GUARD_PAGE_VIOLATION => {
                // Guard 触发，保护器 VEH 已处理
                // 继续执行（重试读取）
                EXCEPTION_CONTINUE_EXECUTION
            },
            STATUS_ACCESS_VIOLATION => {
                // 真实 AV（加密区或无效地址）
                EXCEPTION_EXECUTE_HANDLER
            },
            _ => EXCEPTION_CONTINUE_SEARCH,
        }
    });
    
    // 2. 执行读取（带 Rust panic 捕获）
    let read_result = catch_unwind(|| unsafe {
        // 直接解引用指针（用户模式访问）
        let ptr = addr as *const [u8; 16];
        std::ptr::read_volatile(ptr)
    });
    
    // 3. 解析结果
    match read_result {
        Ok(data) => {
            let entropy = calculate_entropy(&data);
            let disasm_valid = is_valid_x64_prologue(&data);
            
            ProbeResult::Success {
                address: addr,
                data: data.to_vec(),
                entropy,
                appears_decrypted: entropy < 6.0 && disasm_valid,
            }
        },
        Err(_) => {
            // Panic 表示 AV 未被 SEH 恢复
            ProbeResult::AccessViolation { address: addr }
        }
    }
}

/// SEH 帧 RAII 封装
struct SehFrame {
    registration: EXCEPTION_REGISTRATION_RECORD,
}

impl SehFrame {
    fn new<F>(handler: F) -> Self
    where
        F: Fn(*mut EXCEPTION_RECORD) -> i32 + 'static,
    {
        // 实现 SEH 链注册（x64 通过 gs:[0] 访问 TEB）
        // ...
    }
}

impl Drop for SehFrame {
    fn drop(&mut self) {
        // 自动移除 SEH 帧
    }
}
```

### 4.2 熵计算与反汇编（保留原设计）

```rust
/// Shannon 熵（0-8 bits）
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// x64 函数 prologue 验证
fn is_valid_x64_prologue(data: &[u8]) -> bool {
    // 常见模式：
    // 0x55                  push rbp
    // 0x48 0x89 0xe5        mov rbp, rsp
    // 0x48 0x83 0xec 0x??   sub rsp, ??
    
    if data.len() < 4 {
        return false;
    }
    
    // 模式 1: push rbp + mov rbp, rsp
    if data[0] == 0x55 && data[1] == 0x48 && data[2] == 0x89 && data[3] == 0xe5 {
        return true;
    }
    
    // 模式 2: push rbx (0x53) / push rdi (0x57) / push rsi (0x56)
    if matches!(data[0], 0x53 | 0x56 | 0x57) {
        return true;
    }
    
    // 模式 3: sub rsp, imm32 (0x48 0x83 0xec)
    if data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xec {
        return true;
    }
    
    false
}
```

### 4.3 节流与止损（保留原设计）

| 参数 | 值 | 原理 |
|-----|---|------|
| 单次探针间隔 | 10 ms | 避免高频访问检测 |
| 批次大小 | 50 地址 | 平衡进度与风险 |
| 批次间延迟 | 500 ms | 模拟正常内存访问节奏 |
| 总探针预算 | 5,000 次 | 防止无限循环（约 50s） |

**止损信号**:
- 连续 10 次 ACCESS_VIOLATION（非 guard）
- 目标进程 CPU > 80% 持续 5s
- 新线程创建（可能是反调试响应）

---

## 5. Fail-Closed 决策表（保留框架，调整阈值）

### 5.1 触碰结果分类（不变）

```
探针结果
├── Success (熵 < 6.0, 有效指令) → Type B/C 已解密
├── Success (熵 > 7.5, 无效指令) → Type A 仍加密
├── AccessViolation (非 guard) → Type A 或保护器敏感
└── Timeout / 进程异常 → 止损
```

### 5.2 决策矩阵（调整阈值）

| 结果类型 | 计数阈值 | 决策 | 理由 |
|---------|---------|------|------|
| Type C 确认 | ≥ 30 | 继续触碰，扩展邻域 | 假说验证（降低自50） |
| Type A（加密态） | ≥ 70% 候选 | 转 β 路线 | 触碰无法解密（降低自80%） |
| 非 guard AV | 连续 10 次 | 立即止损 | 保护器敏感（不变） |
| 覆盖率停滞 | 100 次无新发现 | 结束触碰 | 饱和（降低自200） |
| 预算耗尽 | 5,000 次 | 强制终止 | 降低自10,000 |

---

## 6. 覆盖率迭代方案（保留框架，简化轮次）

### 6.1 度量指标（不变）

| 指标 | 目标值 |
|-----|-------|
| 字节覆盖率 | ≥ 70%（降低自80%） |
| 指令覆盖率 | ≥ 60%（降低自70%） |
| 熵均值 | < 6.0（不变） |

### 6.2 迭代策略（简化为3轮）

#### Round 1: Coverage-Guided Sweep

**输入**: Coverage measure 的 cold regions

```rust
for cold_region in coverage.cold_regions {
    let candidates = sample_cold_region(cold_region, step=0x1000);
    let results = invoke_walker(&candidates)?;
    update_coverage_map(&results);
}
```

**预期覆盖率**: 40-50%

---

#### Round 2: Boundary Refinement

**输入**: Round 1 的绿-红边界

```rust
let boundaries = find_coverage_boundaries(&coverage_map);
for boundary in boundaries {
    let candidates = dense_sample_boundary(boundary, step=0x100);
    let results = invoke_walker(&candidates)?;
    update_coverage_map(&results);
}
```

**预期覆盖率提升**: +15-20%

---

#### Round 3: Hotspot Vicinity

**输入**: RIP hotspot 的未覆盖邻域

```rust
for hotspot in coverage.rip_coverage.hotspots {
    let vicinity = expand_vicinity(hotspot, radius=0x2000);
    let uncovered = vicinity.subtract(&coverage_map);
    let results = invoke_walker(&uncovered)?;
    update_coverage_map(&results);
}
```

**预期覆盖率提升**: +10-15%

**总预期**: 65-85%

---

## 7. 前置依赖清单（修正）

| 依赖 | 现有状态 | 新增需求 | 优先级 |
|-----|---------|---------|-------|
| ADR-6 注入链 | ✅ antidebug-runtime | Walker payload DLL | P0 |
| Coverage measure | ✅ Route T/U/V 日志 | 解析工具 | P1 |
| 共享内存通信 | ⚠️ 需实现 | 双向通信协议 | P1 |
| 熵计算 | ✅ 已有 | 无 | - |
| 反汇编 | ✅ iced-x86 | 无 | - |
| SEH 帧注册 | ❌ 无 | 目标内 SEH API | P0 |

**不再需要**:
- ❌ 硬件断点 (DR0-DR3)
- ❌ 调试器侧 VEH
- ❌ ReadProcessMemory 探针

---

## 8. LIVE-4 实弹授权申请（修正）

### 8.1 申请概览（修正 F4/F5）

| 字段 | 值 |
|-----|---|
| **申请编号** | LIVE-4-ALPHA-R1-001 |
| **样本来源** | ✅ Manifest 授权 vault 对象 rev2 |
| **身份预检** | ✅ 必须通过 vault identity verification |
| **预算上界** | ✅ Cap = 120 分钟（2小时） |
| **实弹次数** | 3 次迭代 |
| **单次预算** | 40 分钟 |

### 8.2 实验阶段（修正）

#### Phase 1: PoC（10分钟）

**目标**: 验证目标内探针触发 guard 机制

**步骤**:
1. 注入 walker_payload.dll
2. 传递 5 个已知 guard violation 地址
3. 观测 SEH 捕获的 `STATUS_GUARD_PAGE_VIOLATION`
4. 读取熵，验证解密

**成功标准**:
- 5 个地址中 ≥ 3 个触发 guard
- Guard 后熵 < 6.0

**失败应对**:
- ≤ 1 个成功 → 假说失败，止损

---

#### Phase 2: Coverage Exploration（20分钟）

**目标**: Round 1-2 迭代

**步骤**:
1. 加载 coverage_measure.json
2. 生成候选（200-500 地址）
3. Round 1: Cold region sweep
4. Round 2: Boundary refinement
5. 输出覆盖图

**成功标准**:
- 覆盖率 ≥ 40%
- Type C ≥ 20 个页

---

#### Phase 3: Coverage Maximization（20分钟）

**目标**: Round 3 + 饱和检测

**步骤**:
1. Round 3: Hotspot vicinity
2. 监控饱和度
3. 提前终止 or 到达预算

**成功标准**:
- 覆盖率 ≥ 60% 或饱和

---

#### Phase 4: Dump + Smoke（10分钟）

（与原设计相同，调试器侧 RPM dump 已解密区域）

---

### 8.3 风险评估（更新）

| 风险 | 概率 | 影响 | 缓解措施 |
|-----|------|------|---------|
| 假说失败 | 25%（降低） | 高 | Phase 1 快速验证 |
| 保护器敏感 | 15%（降低） | 高 | 目标内访问更隐蔽 |
| 注入失败 | 10%（新增） | 中 | 复用 ADR-6 成熟链 |
| 覆盖率不足 | 35%（增加） | 中 | 预设 60% 接受线 |
| 预算耗尽 | 20%（新增） | 低 | 120min 硬上限 |

---

## 9. 与 WO-1302 协同（修正）

### 9.1 执行顺序（强制约束）

```
Step 1: WO-1302 诊断（如超时）
  ↓
  假说 A (反调试) → 激活 MODE=self (批次 10 自研栈)
  ↓
Step 2: 重新运行
  ↓
  仍超时 → 转 Step 3
  ↓
Step 3: WO-1301A 触碰解密
  ↓
  触碰中超时 → 回到 Step 1 诊断
```

**关键约束**: 不在死进程上执行触碰（WO-1302 条件接受的附加要求）

---

## 10. 修订对照表

| 缺陷 | 原设计 | 修订版 | 状态 |
|-----|--------|-------|------|
| **F1** | DR0-DR3 硬件断点 | 不使用断点 | ✅ 修复 |
| **F2** | 调试器侧 RPM | 目标内 walker | ✅ 修复 |
| **F3** | 调试器进程 VEH | 保护器自有 VEH | ✅ 修复 |
| **F4** | "Route U/V 历史工件" | Manifest 授权 vault rev2 | ✅ 修复 |
| **F5** | "预算无上限" | Cap = 120min | ✅ 修复 |

**保留内容**（60% 复用）:
- ✅ Type A/B/C 三态分类
- ✅ 熵 + 反汇编判据
- ✅ 动态候选扩展
- ✅ 节流止损
- ✅ LIVE-4 分阶段结构
- ✅ 三种结局预案

---

## 11. 总结与审批前确认

### 11.1 关键修正

1. **探针原语**: 从调试器侧 RPM 改为 ADR-6 注入链内的目标上下文读取（F2 致命缺陷修复）
2. **异常处理**: 保护器自有 VEH 处理 guard，我们只观测熵差（F3 修复）
3. **候选筛选**: 使用 coverage_measure 实测数据，不依赖启发式（数据驱动）
4. **身份合规**: Manifest 授权 vault 对象 rev2 + 身份预检（F4 修复）
5. **预算有界**: 120 分钟硬上限（F5 修复）

### 11.2 技术可行性

| 组件 | 技术基础 | 风险 |
|-----|---------|------|
| ADR-6 注入 | ✅ antidebug-runtime 已验证 | 低 |
| 目标内 SEH | ✅ Windows API 标准 | 低 |
| 共享内存 | ✅ CreateFileMapping 成熟 | 低 |
| Coverage measure 解析 | ✅ JSON 格式已定义 | 低 |
| Walker 节流 | ✅ Sleep 实现简单 | 低 |

### 11.3 文档版本

| 版本 | 日期 | 变更 | 作者 |
|-----|------|------|------|
| v0.1 (WO-1301) | 2026-08-22 | 原设计（REJECTED） | 设计组 |
| v1.0 (WO-1301A) | 2026-08-22 | F1-F5 修复，60% 复用 | 设计组 |

---

**提交状态**: 📤 待总指挥批准  
**后续流程**: 批准后 → 实施单拆分 → LIVE-4 签发（与 WO-1302 联合执行）
