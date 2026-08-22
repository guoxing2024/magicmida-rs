# WO-1301A-IMPL: Route α 实施单初稿 — WalkerExecute 导出设计

**工单编号**: WO-1301A-IMPL  
**前置**: WO-1301A CONDITIONALLY APPROVED  
**类型**: 实施设计（代码架构，零实弹）  
**日期**: 2026-08-22  
**状态**: 待总指挥审批

---

## 执行摘要

根据 C1 条件（架构合并：禁止新增第二个自研 DLL），将 `WalkerExecute` 作为 **antidebug-runtime 的新增导出** 实现，复用已验证的 ADR-6 注入链、provenance 框架、attestation 合同。本实施单设计：
1. `WalkerExecute` C ABI 导出接口
2. 目标内探针原语（SEH + read_volatile）
3. 共享内存通信协议
4. antidebug-runtime 模块扩展方案
5. CLI unpacker 接线点

**关键遵守**:
- ✅ **单一 DLL**: antidebug-runtime.dll（不新增 walker_payload.dll）
- ✅ **单一出处**: 复用 ADR-6 加载路径
- ✅ **单一账本**: provenance + attestation 统一记录

---

## 1. WalkerExecute 导出接口设计

### 1.1 C ABI 签名

```rust
// crates/antidebug-runtime/src/exports.rs

/// Walker 执行参数（调试器通过共享内存传递）
#[repr(C)]
pub struct WalkerParams {
    /// 候选地址数组指针（调试器侧地址）
    pub candidate_addrs: *const u64,
    /// 候选地址数量
    pub candidate_count: u32,
    /// 探针选项
    pub options: WalkerOptions,
    /// 共享内存句柄（用于写回结果）
    pub shared_memory_handle: usize,
    /// 共享内存大小
    pub shared_memory_size: u32,
    /// 保留字段（对齐）
    pub _reserved: u32,
}

#[repr(C)]
pub struct WalkerOptions {
    /// 单次探针间隔（毫秒）
    pub probe_interval_ms: u32,
    /// 最大探针次数（止损）
    pub max_probes: u32,
    /// 熵阈值（< 此值认为已解密）
    pub entropy_threshold: f32,
    /// 保留字段
    pub _reserved: [u32; 5],
}

/// Walker 执行结果（通过共享内存返回）
#[repr(C)]
pub struct WalkerResults {
    /// 探针结果数组（与候选地址一一对应）
    pub results: *mut ProbeResult,
    /// 结果数量
    pub result_count: u32,
    /// 统计信息
    pub stats: WalkerStats,
}

#[repr(C)]
pub struct ProbeResult {
    /// 探测的地址
    pub address: u64,
    /// 结果类型
    pub result_type: ProbeResultType,
    /// 读取的数据（16字节）
    pub data: [u8; 16],
    /// 熵值
    pub entropy: f32,
    /// 是否包含有效 x64 指令
    pub has_valid_instructions: bool,
    /// 保留字段
    pub _reserved: [u8; 3],
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResultType {
    /// 成功读取，低熵（已解密）
    SuccessDecrypted = 0,
    /// 成功读取，高熵（仍加密）
    SuccessEncrypted = 1,
    /// Guard page violation（触发后重读）
    GuardPageViolation = 2,
    /// Access violation（非 guard）
    AccessViolation = 3,
    /// 超时或其他错误
    Error = 4,
}

#[repr(C)]
pub struct WalkerStats {
    /// 总探针次数
    pub total_probes: u32,
    /// Type C（guard 触发）次数
    pub guard_violations: u32,
    /// Type A（非 guard AV）次数
    pub access_violations: u32,
    /// 成功解密次数（熵 < 阈值）
    pub decrypted_count: u32,
    /// 执行耗时（毫秒）
    pub elapsed_ms: u32,
}

/// Walker 执行入口（C ABI 导出）
///
/// # Safety
/// - params 必须指向有效的 WalkerParams 结构
/// - shared_memory_handle 必须是有效的内存映射句柄
/// - 调用者负责在调用前冻结目标进程其他线程
#[no_mangle]
pub unsafe extern "C" fn WalkerExecute(params: *const WalkerParams) -> u32 {
    // 1. 参数验证
    if params.is_null() {
        return WALKER_ERROR_INVALID_PARAMS;
    }
    
    let params = &*params;
    
    // 2. 映射共享内存
    let shared_mem = match map_shared_memory(
        params.shared_memory_handle,
        params.shared_memory_size as usize,
    ) {
        Ok(mem) => mem,
        Err(_) => return WALKER_ERROR_SHARED_MEMORY,
    };
    
    // 3. 读取候选地址列表
    let candidates = std::slice::from_raw_parts(
        params.candidate_addrs,
        params.candidate_count as usize,
    );
    
    // 4. 执行 walker 逻辑
    let results = execute_walker_internal(candidates, &params.options);
    
    // 5. 写回结果到共享内存
    match write_results_to_shared_memory(&results, &shared_mem) {
        Ok(_) => WALKER_SUCCESS,
        Err(_) => WALKER_ERROR_WRITE_RESULTS,
    }
}

// 错误码常量
pub const WALKER_SUCCESS: u32 = 0;
pub const WALKER_ERROR_INVALID_PARAMS: u32 = 1;
pub const WALKER_ERROR_SHARED_MEMORY: u32 = 2;
pub const WALKER_ERROR_WRITE_RESULTS: u32 = 3;
pub const WALKER_ERROR_PROBE_FAILED: u32 = 4;
```

### 1.2 导出声明（lib.rs）

```rust
// crates/antidebug-runtime/src/lib.rs

pub use exports::{
    // 现有导出
    MidaAntidebugError, MidaAntidebugGetAttestation, MidaAntidebugInitialize,
    MidaAntidebugShutdown,
    // 新增导出
    WalkerExecute, WalkerParams, WalkerOptions, WalkerResults, ProbeResult,
    ProbeResultType, WalkerStats,
    WALKER_SUCCESS, WALKER_ERROR_INVALID_PARAMS, WALKER_ERROR_SHARED_MEMORY,
    WALKER_ERROR_WRITE_RESULTS, WALKER_ERROR_PROBE_FAILED,
};
```

---

## 2. 目标内探针原语实现

### 2.1 模块结构

```
crates/antidebug-runtime/src/
├── walker/
│   ├── mod.rs          # 模块根，导出 execute_walker_internal
│   ├── probe.rs        # 探针原语（SEH + read_volatile）
│   ├── entropy.rs      # 熵计算
│   ├── disasm.rs       # 反汇编验证
│   └── seh.rs          # SEH 帧封装
```

### 2.2 探针原语（probe.rs）

```rust
// crates/antidebug-runtime/src/walker/probe.rs

use crate::walker::seh::SehFrame;
use crate::walker::entropy::calculate_entropy;
use crate::walker::disasm::is_valid_x64_prologue;
use super::{ProbeResult, ProbeResultType};

/// 目标上下文安全探针
///
/// # Safety
/// - addr 必须在有效地址范围内（调用者验证）
/// - 不处理跨页读取（只读 16 字节）
pub unsafe fn safe_probe_in_target(addr: u64) -> ProbeResult {
    let addr_usize = addr as usize;
    let mut result = ProbeResult {
        address: addr,
        result_type: ProbeResultType::Error,
        data: [0u8; 16],
        entropy: 0.0,
        has_valid_instructions: false,
        _reserved: [0; 3],
    };
    
    // 1. 安装 SEH 帧（捕获 guard / AV）
    let mut guard_triggered = false;
    let _seh_guard = SehFrame::new(|exception_code| {
        match exception_code {
            STATUS_GUARD_PAGE_VIOLATION => {
                // Guard 触发，保护器 VEH 已处理解密
                guard_triggered = true;
                EXCEPTION_CONTINUE_EXECUTION  // 重试读取
            },
            STATUS_ACCESS_VIOLATION => {
                // 真实 AV（加密区或无效地址）
                EXCEPTION_EXECUTE_HANDLER
            },
            _ => EXCEPTION_CONTINUE_SEARCH,
        }
    });
    
    // 2. 执行读取（用户模式指针解引用）
    let read_result = std::panic::catch_unwind(|| {
        let ptr = addr_usize as *const [u8; 16];
        std::ptr::read_volatile(ptr)
    });
    
    // 3. 解析结果
    match read_result {
        Ok(data) => {
            result.data = data;
            result.entropy = calculate_entropy(&data);
            result.has_valid_instructions = is_valid_x64_prologue(&data);
            
            // 根据 guard 标志和熵判定类型
            if guard_triggered {
                result.result_type = ProbeResultType::GuardPageViolation;
            } else if result.entropy < 6.0 && result.has_valid_instructions {
                result.result_type = ProbeResultType::SuccessDecrypted;
            } else {
                result.result_type = ProbeResultType::SuccessEncrypted;
            }
        },
        Err(_) => {
            // Panic 表示 SEH 未恢复的 AV
            result.result_type = ProbeResultType::AccessViolation;
        }
    }
    
    result
}

// Windows 状态码
const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
```

### 2.3 SEH 帧封装（seh.rs）

```rust
// crates/antidebug-runtime/src/walker/seh.rs

use windows::Win32::System::Diagnostics::Debug::*;
use std::ptr;

/// SEH 帧 RAII 封装
///
/// 注意：Rust 的 panic unwinding 与 Windows SEH 是独立机制
/// 本实现使用 SetUnhandledExceptionFilter（全局）或
/// 通过 ntdll!RtlAddVectoredExceptionHandler（推荐）
pub struct SehFrame {
    handler: PVECTORED_EXCEPTION_HANDLER,
}

impl SehFrame {
    /// 安装 VEH（Vectored Exception Handler）
    ///
    /// # Safety
    /// - handler 生命周期必须覆盖整个探针执行
    pub fn new<F>(handler: F) -> Self
    where
        F: Fn(u32) -> i32 + 'static,
    {
        // 将闭包转换为 C 回调
        let handler_ptr = Box::into_raw(Box::new(handler));
        
        unsafe extern "system" fn veh_callback(
            exception_info: *mut EXCEPTION_POINTERS,
        ) -> i32 {
            let exception_record = (*exception_info).ExceptionRecord;
            let exception_code = (*exception_record).ExceptionCode.0;
            
            // 调用用户提供的闭包
            let handler_ptr = HANDLER_PTR.load(std::sync::atomic::Ordering::Relaxed);
            if !handler_ptr.is_null() {
                let handler: &Box<dyn Fn(u32) -> i32> = &*(handler_ptr as *const _);
                handler(exception_code)
            } else {
                EXCEPTION_CONTINUE_SEARCH
            }
        }
        
        // 存储闭包指针到线程局部变量（避免全局竞争）
        HANDLER_PTR.store(handler_ptr as usize, std::sync::atomic::Ordering::Relaxed);
        
        // 注册 VEH（first=1 表示最高优先级）
        let veh_handle = unsafe {
            AddVectoredExceptionHandler(1, Some(veh_callback))
        };
        
        SehFrame {
            handler: veh_handle,
        }
    }
}

impl Drop for SehFrame {
    fn drop(&mut self) {
        // 移除 VEH
        unsafe {
            RemoveVectoredExceptionHandler(self.handler);
        }
        
        // 清理闭包（暂时泄漏，实际需要 TLS 管理）
        // TODO: 使用 thread_local! 管理闭包生命周期
    }
}

// 线程局部存储（简化版，实际需要 TLS）
static HANDLER_PTR: std::sync::atomic::AtomicUsize = 
    std::sync::atomic::AtomicUsize::new(0);
```

### 2.4 熵计算（entropy.rs）

```rust
// crates/antidebug-runtime/src/walker/entropy.rs

/// Shannon 熵（0-8 bits）
pub fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    
    let len = data.len() as f32;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn entropy_of_zeros_is_zero() {
        let data = [0u8; 16];
        assert!(calculate_entropy(&data) < 0.01);
    }
    
    #[test]
    fn entropy_of_random_is_high() {
        let data = [0x4a, 0x8b, 0x2f, 0xc1, 0x93, 0x67, 0x12, 0xef,
                   0xa4, 0x5c, 0xd9, 0x38, 0x76, 0xb2, 0x0e, 0x91];
        assert!(calculate_entropy(&data) > 7.0);
    }
    
    #[test]
    fn entropy_of_x64_code_is_medium() {
        // push rbp; mov rbp, rsp; sub rsp, 0x20
        let data = [0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20,
                   0x48, 0x89, 0x4c, 0x24, 0x08, 0x48, 0x89, 0x54];
        let entropy = calculate_entropy(&data);
        assert!(entropy > 3.0 && entropy < 6.0);
    }
}
```

### 2.5 反汇编验证（disasm.rs）

```rust
// crates/antidebug-runtime/src/walker/disasm.rs

/// x64 函数 prologue 简单验证（无依赖 iced-x86）
pub fn is_valid_x64_prologue(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    
    // 模式 1: push rbp (0x55) + mov rbp, rsp (0x48 0x89 0xe5)
    if data[0] == 0x55 && data.len() >= 4 {
        if data[1] == 0x48 && data[2] == 0x89 && data[3] == 0xe5 {
            return true;
        }
    }
    
    // 模式 2: push r** (0x41 0x5* 系列)
    if data[0] == 0x41 && data.len() >= 2 {
        if (0x50..=0x57).contains(&data[1]) {
            return true;
        }
    }
    
    // 模式 3: sub rsp, imm (0x48 0x83 0xec)
    if data[0] == 0x48 && data.len() >= 3 {
        if data[1] == 0x83 && data[2] == 0xec {
            return true;
        }
    }
    
    // 模式 4: mov rax, ... (0x48 0x8b / 0x48 0x89)
    if data[0] == 0x48 && data.len() >= 2 {
        if data[1] == 0x8b || data[1] == 0x89 {
            return true;
        }
    }
    
    false
}
```

---

## 3. Walker 主逻辑（mod.rs）

```rust
// crates/antidebug-runtime/src/walker/mod.rs

mod probe;
mod entropy;
mod disasm;
mod seh;

use probe::safe_probe_in_target;
use super::{ProbeResult, WalkerOptions, WalkerStats};
use std::time::Instant;

/// Walker 内部执行逻辑
///
/// # Safety
/// - candidates 必须指向有效内存
/// - 调用前已冻结目标其他线程
pub unsafe fn execute_walker_internal(
    candidates: &[u64],
    options: &WalkerOptions,
) -> Vec<ProbeResult> {
    let start = Instant::now();
    let mut results = Vec::with_capacity(candidates.len());
    let mut stats = WalkerStats::default();
    
    for (i, &addr) in candidates.iter().enumerate() {
        // 1. 预算检查
        if i >= options.max_probes as usize {
            break;
        }
        
        // 2. 执行探针
        let probe_result = safe_probe_in_target(addr);
        
        // 3. 统计
        stats.total_probes += 1;
        match probe_result.result_type {
            ProbeResultType::GuardPageViolation => {
                stats.guard_violations += 1;
                // Guard 后需重读验证解密
                if probe_result.entropy < options.entropy_threshold {
                    stats.decrypted_count += 1;
                }
            },
            ProbeResultType::SuccessDecrypted => {
                stats.decrypted_count += 1;
            },
            ProbeResultType::AccessViolation => {
                stats.access_violations += 1;
                
                // 止损检查：连续 10 次非 guard AV
                if consecutive_av_count(&results) >= 10 {
                    break;
                }
            },
            _ => {}
        }
        
        results.push(probe_result);
        
        // 4. 节流
        if i < candidates.len() - 1 {
            std::thread::sleep(std::time::Duration::from_millis(
                options.probe_interval_ms as u64
            ));
        }
    }
    
    stats.elapsed_ms = start.elapsed().as_millis() as u32;
    results
}

/// 检查连续 AV 次数（止损判定）
fn consecutive_av_count(results: &[ProbeResult]) -> usize {
    results.iter()
        .rev()
        .take_while(|r| r.result_type == ProbeResultType::AccessViolation)
        .count()
}

impl Default for WalkerStats {
    fn default() -> Self {
        WalkerStats {
            total_probes: 0,
            guard_violations: 0,
            access_violations: 0,
            decrypted_count: 0,
            elapsed_ms: 0,
        }
    }
}
```

---

## 4. CLI Unpacker 接线点

### 4.1 调用时机

```rust
// crates/cli/src/unpacker/mod.rs

// 在 Route U/V 超时后，WO-1302 诊断完成，决策转 Route α 时调用
if diagnosis.verdict == DiagnosisVerdict::AntiDebugDetection {
    // 可选：先激活 MODE=self
    if let Some(enable_phase23) = diagnosis.recommended_action.enable_phase23() {
        activate_self_mode()?;
    }
}

// 无论诊断结果如何，如果决定执行 Route α
if should_execute_route_alpha(&diagnosis) {
    let coverage = load_coverage_measure("coverage_measure.json")?;
    let candidates = generate_candidates_from_coverage(&coverage)?;
    
    // 调用 walker
    let walker_results = invoke_walker_via_runtime(
        &dbg,
        pid,
        &candidates,
        WalkerOptions {
            probe_interval_ms: 10,
            max_probes: 5000,
            entropy_threshold: 6.0,
            _reserved: [0; 5],
        },
    )?;
    
    // 分析结果
    analyze_walker_results(&walker_results)?;
}
```

### 4.2 Walker 调用实现

```rust
// crates/cli/src/unpacker/walker_invoke.rs (新文件)

use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

/// 通过 antidebug-runtime 的 WalkerExecute 导出执行 walker
pub fn invoke_walker_via_runtime(
    debugger: &dyn DebuggerCore,
    target_pid: u32,
    candidates: &[u64],
    options: WalkerOptions,
) -> Result<Vec<ProbeResult>> {
    let target_handle = debugger.process_handle();
    
    // 1. 创建共享内存
    let shared_mem_size = 1024 * 1024;  // 1MB
    let shared_mem_handle = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_READWRITE,
            0,
            shared_mem_size,
            w!("Local\\MidaWalkerSharedMem"),
        )?
    };
    
    let shared_mem_ptr = unsafe {
        MapViewOfFile(
            shared_mem_handle,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            shared_mem_size as usize,
        )
    };
    
    if shared_mem_ptr.Value.is_null() {
        return Err("MapViewOfFile failed".into());
    }
    
    // 2. 写入候选地址到共享内存
    unsafe {
        let candidates_ptr = shared_mem_ptr.Value as *mut u64;
        std::ptr::copy_nonoverlapping(
            candidates.as_ptr(),
            candidates_ptr,
            candidates.len(),
        );
    }
    
    // 3. 在目标进程中分配参数结构
    let params_size = std::mem::size_of::<WalkerParams>();
    let remote_params = unsafe {
        VirtualAllocEx(
            target_handle,
            None,
            params_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    
    if remote_params.is_null() {
        return Err("VirtualAllocEx(params) failed".into());
    }
    
    // 4. 构造参数（注意：candidate_addrs 指向共享内存偏移）
    let params = WalkerParams {
        candidate_addrs: 0,  // 共享内存起始
        candidate_count: candidates.len() as u32,
        options,
        shared_memory_handle: shared_mem_handle.0 as usize,
        shared_memory_size: shared_mem_size,
        _reserved: 0,
    };
    
    // 5. 写入参数到目标进程
    unsafe {
        WriteProcessMemory(
            target_handle,
            remote_params,
            &params as *const _ as *const c_void,
            params_size,
            None,
        )?;
    }
    
    // 6. 获取 WalkerExecute 导出地址
    let runtime_base = get_runtime_module_base(target_handle, target_pid)?;
    let walker_execute_rva = get_export_rva(runtime_base, "WalkerExecute")?;
    let walker_execute_addr = runtime_base + walker_execute_rva;
    
    // 7. 创建远程线程执行
    let thread = unsafe {
        CreateRemoteThread(
            target_handle,
            None,
            0,
            Some(std::mem::transmute(walker_execute_addr)),
            remote_params,
            0,
            None,
        )?
    };
    
    // 8. 等待完成（120 分钟上限）
    let wait_result = unsafe {
        WaitForSingleObject(thread, 120 * 60 * 1000)
    };
    
    if wait_result != WAIT_OBJECT_0 {
        return Err("Walker timeout (120min exceeded)".into());
    }
    
    // 9. 读取结果从共享内存
    let results = unsafe {
        let results_offset = std::mem::size_of::<u64>() * candidates.len();
        let results_ptr = (shared_mem_ptr.Value as usize + results_offset) as *const ProbeResult;
        std::slice::from_raw_parts(results_ptr, candidates.len()).to_vec()
    };
    
    // 10. 清理
    unsafe {
        UnmapViewOfFile(shared_mem_ptr)?;
        CloseHandle(shared_mem_handle)?;
        VirtualFreeEx(target_handle, remote_params, 0, MEM_RELEASE)?;
        CloseHandle(thread)?;
    }
    
    Ok(results)
}

/// 获取 antidebug-runtime.dll 在目标进程的基址
fn get_runtime_module_base(
    target_handle: HANDLE,
    pid: u32,
) -> Result<usize> {
    // 枚举目标进程模块，查找 "antidebug-runtime.dll"
    // 实现略（使用 EnumProcessModulesEx 或 CreateToolhelp32Snapshot）
    todo!()
}

/// 解析 PE 导出表获取 RVA
fn get_export_rva(module_base: usize, export_name: &str) -> Result<usize> {
    // 读取目标进程内存中的 PE 结构
    // 解析 IMAGE_EXPORT_DIRECTORY
    // 实现略（使用 mida-pe crate）
    todo!()
}
```

---

## 5. Provenance 与 Attestation 集成

### 5.1 Provenance 记录

```rust
// crates/antidebug-runtime/src/provenance.rs

// 新增字段
pub struct Provenance {
    // ... 现有字段
    
    /// Walker 执行记录（可选）
    pub walker_execution: Option<WalkerExecution>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalkerExecution {
    /// 执行时间戳
    pub timestamp: String,
    /// 候选地址数量
    pub candidate_count: u32,
    /// 探针统计
    pub stats: WalkerStats,
    /// 熵阈值
    pub entropy_threshold: f32,
}
```

### 5.2 Attestation 扩展

```rust
// crates/antidebug-runtime/src/attestation.rs

// HookInventory 新增可选字段
pub struct HookInventory {
    // ... 现有字段
    
    /// Walker 执行结果（如有）
    pub walker_results: Option<WalkerAttestationSummary>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalkerAttestationSummary {
    /// 探测总数
    pub total_probes: u32,
    /// Type C（guard）占比
    pub guard_violation_ratio: f32,
    /// 解密成功占比
    pub decryption_ratio: f32,
    /// 止损原因（如有）
    pub stop_reason: Option<String>,
}
```

---

## 6. 测试策略

### 6.1 单元测试

```rust
// crates/antidebug-runtime/tests/walker.rs

#[test]
fn walker_execute_empty_candidates() {
    let candidates = [];
    let options = WalkerOptions::default();
    
    let results = unsafe {
        execute_walker_internal(&candidates, &options)
    };
    
    assert!(results.is_empty());
}

#[test]
fn walker_execute_with_valid_address() {
    // 在测试进程自身地址空间内测试
    let code_addr = walker_execute_empty_candidates as u64;
    let candidates = [code_addr];
    let options = WalkerOptions::default();
    
    let results = unsafe {
        execute_walker_internal(&candidates, &options)
    };
    
    assert_eq!(results.len(), 1);
    assert!(matches!(
        results[0].result_type,
        ProbeResultType::SuccessDecrypted
    ));
}

#[test]
fn walker_execute_with_invalid_address() {
    let candidates = [0xDEADBEEF_u64];
    let options = WalkerOptions::default();
    
    let results = unsafe {
        execute_walker_internal(&candidates, &options)
    };
    
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].result_type,
        ProbeResultType::AccessViolation
    );
}
```

### 6.2 集成测试（LIVE-4 前置）

在 benign host（良性进程）上验证：
1. 注入 antidebug-runtime.dll（已有 b1_benign_host_full.rs 框架）
2. 调用 `WalkerExecute` 导出
3. 验证共享内存通信
4. 验证 provenance + attestation 正确记录

---

## 7. 实施检查清单

| 任务 | 负责模块 | 预计工作量 | 依赖 |
|-----|---------|-----------|------|
| **WalkerExecute 导出** | antidebug-runtime/exports.rs | 4h | 无 |
| **探针原语** | antidebug-runtime/walker/probe.rs | 6h | SEH 封装 |
| **SEH 帧封装** | antidebug-runtime/walker/seh.rs | 8h | Windows VEH API |
| **熵计算** | antidebug-runtime/walker/entropy.rs | 2h | 无 |
| **反汇编验证** | antidebug-runtime/walker/disasm.rs | 2h | 无 |
| **Walker 主逻辑** | antidebug-runtime/walker/mod.rs | 4h | 上述全部 |
| **共享内存通信** | CLI walker_invoke.rs | 6h | Windows API |
| **CLI 接线** | CLI unpacker/mod.rs | 4h | walker_invoke |
| **Provenance 集成** | antidebug-runtime/provenance.rs | 2h | Walker 完成 |
| **Attestation 集成** | antidebug-runtime/attestation.rs | 2h | Walker 完成 |
| **单元测试** | antidebug-runtime/tests/walker.rs | 4h | Walker 完成 |
| **集成测试** | antidebug-runtime/tests/benign_host.rs | 6h | 全部完成 |
| **文档更新** | antidebug-runtime/src/lib.rs | 2h | 全部完成 |
| **总计** | - | **52 小时** | - |

---

## 8. 审批前确认

### 8.1 C1 条件遵守

| 要求 | 实施方案 | 验证 |
|-----|---------|------|
| 单一 DLL | ✅ antidebug-runtime.dll | 不新增 walker_payload.dll |
| 单一出处 | ✅ 复用 ADR-6 注入链 | runtime_loader 现有路径 |
| 单一账本 | ✅ Provenance + Attestation | walker_execution 新字段 |
| 身份核验 | ✅ 继承 runtime 预检 | MidaAntidebugInitialize 已有 |

### 8.2 C2 条件（LIVE-4 授权枚举）

**本实施单使用的注入原语**（需总指挥在 LIVE-4 中显式授权）:
1. `VirtualAllocEx` — 分配远程内存（params + 共享内存映射）
2. `WriteProcessMemory` — 写入 params 结构
3. `CreateRemoteThread` — 执行 WalkerExecute 导出

**载荷范围**: antidebug-runtime.dll 的 `WalkerExecute` 导出，仅此而已

**写入范围**:
- ✅ 允许：params 结构（只读参数）
- ✅ 允许：共享内存（通信通道）
- ❌ 禁止：除 PEB surfaces 外的目标内存写入

### 8.3 技术风险

| 风险 | 概率 | 缓解措施 |
|-----|------|---------|
| SEH 封装复杂度 | 中 | 使用 windows crate VEH API，单元测试验证 |
| 共享内存同步 | 低 | 单线程顺序执行，无竞争 |
| Rust panic vs SEH | 中 | catch_unwind 包裹，文档明确说明 |
| 预算超时 | 低 | 120min 硬上限，WaitForSingleObject 强制 |

---

## 9. 总结

**关键架构决策**:
1. ✅ WalkerExecute 作为 antidebug-runtime 新导出（C1 遵守）
2. ✅ SEH + read_volatile 正确触发保护器 VEH（F2 修复验证）
3. ✅ 共享内存双向通信（候选地址 → 探针结果）
4. ✅ Provenance + Attestation 统一记录（单一账本）

**交付物**:
- 设计文档（本文）
- 代码骨架（walker 模块 + CLI 接线）
- 测试计划（单元 + 集成）

**后续流程**:
1. 总指挥审批本实施单
2. 实施开发（52 小时，~1.5 周）
3. 单元测试 + 集成测试（benign host）
4. 联审通过 → LIVE-4 签发
5. 实弹验证

---

**提交状态**: 📤 待总指挥审批  
**版本**: v1.0  
**日期**: 2026-08-22
