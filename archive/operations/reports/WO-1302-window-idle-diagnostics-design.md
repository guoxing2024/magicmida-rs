# WO-1302: 窗口怠速诊断设计方案

**工单编号**: WO-1302  
**优先级**: P0  
**类型**: 设计文档（docs-only，零实弹零代码）  
**日期**: 2026-08-22  
**状态**: 待总指挥联审

---

## 执行摘要

Route U R1 和 Route V R0 均遭遇 120s 超时但进程未崩溃，主线程似乎陷入等待状态。本方案设计一套多维度诊断体系，通过 **RIP 分布采样、线程等待原因、全窗口枚举** 三大支柱，区分"反调试检测 / 样本行为变化 / 外部阻塞"三种假说，并提供针对性的后续决策路径。

**核心目标**:
- ✅ **非侵入式诊断**：只读观测，不修改目标进程状态
- ✅ **假说判别**：提供定量判据表，避免主观猜测
- ✅ **与 Route α 协同**：超时 → 诊断 → 触碰 → 再诊断 形成闭环

---

## 1. 问题陈述

### 1.1 观测现象

| 案例 | 超时时长 | 进程状态 | 窗口状态 | 已知信息 |
|-----|---------|---------|---------|---------|
| **Route U R1** | 120s | 存活，CPU ~0% | 主窗口未响应 | 环境变量已传播，主 slab 捕获 |
| **Route V R0** | 600s (扩展后) | 存活，CPU ~0% | 未详查 | transform_input_seed 耗时 286s |
| **Route W R1** | 未详述 | 存活 | 未详查 | raw_slab_overlay 失败 |

**共性特征**:
- 进程未崩溃（非反调试触发的自毁）
- CPU 接近 0（非计算密集型循环）
- 调试器可正常附加（非反附加检测）
- 超时发生在特定阶段（非随机）

### 1.2 三假说模型

#### 假说 A: 反调试检测导致怠速

**机制**: 保护器检测到调试器，进入"防御性等待"状态
- **触发条件**: `IsDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort)`, 时序异常检测
- **行为模式**: 
  - 主线程陷入 `Sleep(INFINITE)` 或 `WaitForSingleObject(dummy_event, INFINITE)`
  - RIP 停在时序检测循环（连续 `RDTSC` + 比较）
  - 可能伴随窗口消息处理停止（`GetMessage` 不返回）

#### 假说 B: 样本正常行为变化

**机制**: 调试器导致执行速度放慢，样本进入合法的长等待
- **触发条件**: 等待用户输入、等待网络响应、等待定时器
- **行为模式**:
  - RIP 在正常业务逻辑中（非反调试 API）
  - 线程处于 `Alertable` 或 `UserRequest` 等待
  - 窗口正常枚举，消息泵可能在等待 `WM_*` 事件

#### 假说 C: 外部资源阻塞

**机制**: 依赖的外部资源不可达（文件、注册表、互斥体、网络）
- **触发条件**: 
  - 等待不存在的互斥体（`CreateMutex` 返回 `ERROR_ALREADY_EXISTS` 后 `WaitForSingleObject`）
  - 等待文件 I/O（网络驱动器超时）
  - 等待注册表键（损坏或权限拒绝）
- **行为模式**:
  - RIP 停在 `Nt*` 系统调用返回后的等待循环
  - 线程等待原因 = `Executive` (内核对象)
  - 可通过句柄枚举发现可疑对象

---

## 2. RIP 分布采样设计

### 2.1 采样方法

#### 2.1.1 定时快照法（推荐）

**原理**: 在超时窗口内定时暂停目标进程，读取所有线程的 RIP

**实现**:
```rust
/// RIP 采样器配置
struct RipSamplerConfig {
    /// 采样间隔（毫秒）
    interval_ms: u64,
    /// 总采样时长（秒）
    duration_secs: u64,
    /// 采样的线程选择策略
    thread_filter: ThreadFilter,
}

enum ThreadFilter {
    /// 只采样主线程
    MainOnly,
    /// 所有活跃线程
    AllActive,
    /// CPU 时间 > 阈值的线程
    CpuAbove(f64),  // 百分比
}

/// 单次采样结果
struct RipSnapshot {
    timestamp: SystemTime,
    samples: Vec<ThreadRip>,
}

struct ThreadRip {
    thread_id: u32,
    rip: u64,
    rsp: u64,
    rflags: u64,
    /// 通过 VirtualQueryEx 查询的模块名
    module: Option<String>,
    /// RIP 对应的反汇编指令（前 3 条）
    disasm: Vec<String>,
}

fn sample_rip(
    debugger: &dyn DebuggerCore,
    config: &RipSamplerConfig,
) -> Result<Vec<RipSnapshot>> {
    let start = SystemTime::now();
    let mut snapshots = Vec::new();
    
    loop {
        // 1. 暂停所有线程
        debugger.suspend_all_threads()?;
        
        // 2. 读取 RIP
        let threads = debugger.enumerate_threads()?;
        let mut samples = Vec::new();
        
        for tid in threads {
            if !config.thread_filter.matches(tid) {
                continue;
            }
            
            let ctx = debugger.get_thread_context(tid)?;
            let rip = get_rip(&ctx);
            let rsp = get_rsp(&ctx);
            
            // 查询模块
            let module = query_module_at_address(debugger.process_handle(), rip);
            
            // 反汇编（只读 16 字节，避免跨页）
            let mut code = [0u8; 16];
            let _ = debugger.read_memory(rip as usize, &mut code);
            let disasm = disassemble_x64(&code, rip, 3);
            
            samples.push(ThreadRip {
                thread_id: tid,
                rip,
                rsp,
                rflags: ctx.EFlags as u64,
                module,
                disasm,
            });
        }
        
        snapshots.push(RipSnapshot {
            timestamp: SystemTime::now(),
            samples,
        });
        
        // 3. 恢复线程
        debugger.resume_all_threads()?;
        
        // 4. 检查终止条件
        if start.elapsed()? > Duration::from_secs(config.duration_secs) {
            break;
        }
        
        std::thread::sleep(Duration::from_millis(config.interval_ms));
    }
    
    Ok(snapshots)
}
```

**参数建议**:
- `interval_ms = 500`: 每 0.5 秒采样一次（平衡精度与性能）
- `duration_secs = 30`: 采样 30 秒（覆盖超时窗口的 1/4）
- `thread_filter = MainOnly`: 聚焦主线程（业务逻辑所在）

**预期数据量**: 30s / 0.5s = 60 个快照，每快照 ~1KB，总计 ~60KB

#### 2.1.2 单步统计法（备选，高精度）

**原理**: 启用单步调试，记录每条指令的 RIP

**优点**: 完整执行轨迹，覆盖所有分支  
**缺点**: 
- 极慢（每指令 ~1ms 开销），30 秒只能执行 ~30K 指令
- 严重改变时序，可能触发反调试

**使用场景**: 仅当定时快照法发现 RIP 在小范围跳动，需要精确控制流时使用

### 2.2 分布分析算法

#### 2.2.1 热点识别

**定义**: 出现频率最高的 RIP 地址

```python
def analyze_hotspots(snapshots: List[RipSnapshot]) -> List[Hotspot]:
    rip_counter = Counter()
    
    for snapshot in snapshots:
        for sample in snapshot.samples:
            rip_counter[sample.rip] += 1
    
    # 热点阈值：出现次数 > 总采样的 10%
    threshold = len(snapshots) * 0.1
    hotspots = []
    
    for rip, count in rip_counter.most_common():
        if count < threshold:
            break
        
        hotspots.append(Hotspot(
            address=rip,
            count=count,
            frequency=count / len(snapshots),
            module=query_module(rip),
            disasm=disassemble(rip, 5),
        ))
    
    return hotspots
```

**热点模式识别**:

| 模式 | 热点特征 | 诊断结论 |
|-----|---------|---------|
| **单点热点** | 1 个地址占比 > 80% | 陷入死循环或等待 |
| **双点振荡** | 2 个地址交替出现 | 条件循环（如 `while (condition) { sleep(10); }` |
| **小范围跳动** | 3-5 个相邻地址 | 短函数内循环 |
| **大范围分散** | 无明显热点 | 正常执行，可能只是慢 |

#### 2.2.2 循环检测

**定义**: RIP 序列中的重复模式

```python
def detect_loops(snapshots: List[RipSnapshot]) -> List[Loop]:
    rip_sequence = [s.samples[0].rip for s in snapshots if s.samples]
    
    loops = []
    for pattern_len in range(2, 20):  # 检测 2-20 条指令的循环
        for i in range(len(rip_sequence) - pattern_len * 2):
            pattern = rip_sequence[i:i+pattern_len]
            next_pattern = rip_sequence[i+pattern_len:i+pattern_len*2]
            
            if pattern == next_pattern:
                # 发现循环
                loop_count = 1
                j = i + pattern_len * 2
                while j + pattern_len <= len(rip_sequence):
                    if rip_sequence[j:j+pattern_len] == pattern:
                        loop_count += 1
                        j += pattern_len
                    else:
                        break
                
                loops.append(Loop(
                    start_index=i,
                    pattern=pattern,
                    iterations=loop_count,
                    addresses=pattern,
                ))
    
    return loops
```

**循环类型判别**:

| 类型 | 模式长度 | 迭代次数 | 判定 |
|-----|---------|---------|------|
| **紧密循环** | 2-5 条指令 | > 1000 | 可能是 `while(1) {}`，检查是否包含等待 API |
| **消息泵** | 10-20 条指令 | 适中 | 正常窗口消息处理（`GetMessage` → `DispatchMessage`） |
| **时序检测** | 5-10 条指令，包含 `RDTSC` | > 100 | 反调试时序检测循环 |

#### 2.2.3 基线对比

**目标**: 区分"怠速 120s" vs "正常执行慢"

**方法**: 与成功案例（Route T）的 RIP 分布对比

```python
def compare_with_baseline(
    current: List[RipSnapshot],
    baseline: List[RipSnapshot],
) -> ComparisonResult:
    current_hotspots = analyze_hotspots(current)
    baseline_hotspots = analyze_hotspots(baseline)
    
    # 计算热点地址的交集
    current_addrs = {h.address for h in current_hotspots}
    baseline_addrs = {h.address for h in baseline_hotspots}
    
    overlap = current_addrs & baseline_addrs
    overlap_ratio = len(overlap) / len(current_addrs) if current_addrs else 0
    
    # 计算频率分布的相似度（余弦相似度）
    similarity = cosine_similarity(
        current_frequency_vector,
        baseline_frequency_vector,
    )
    
    return ComparisonResult(
        overlap_ratio=overlap_ratio,
        similarity=similarity,
        verdict=classify_deviation(overlap_ratio, similarity),
    )

def classify_deviation(overlap: float, similarity: float) -> str:
    if similarity > 0.8:
        return "NORMAL_EXECUTION"  # 与基线高度相似
    elif overlap > 0.5:
        return "SIMILAR_BUT_SLOWER"  # 相同代码区域，但频率不同
    else:
        return "ABNORMAL_STATE"  # 完全不同的代码区域（怠速/死循环）
```

### 2.3 反调试 API 特征库

**目的**: 快速识别 RIP 是否在已知的反调试检测代码中

```rust
/// 反调试 API 地址特征
struct AntiDebugSignature {
    name: &'static str,
    /// API 名称或模式
    pattern: ApiPattern,
    /// 调用前后的典型指令序列
    context: Vec<&'static str>,
}

enum ApiPattern {
    /// 精确匹配 API 地址
    ExactApi(&'static str),  // "kernel32!IsDebuggerPresent"
    /// 模糊匹配指令模式
    InstructionPattern(Vec<u8>),  // [0x65, 0x48, 0x8B, ...]  ; gs:[0x60]
}

const ANTIDEBUG_SIGNATURES: &[AntiDebugSignature] = &[
    AntiDebugSignature {
        name: "IsDebuggerPresent",
        pattern: ApiPattern::ExactApi("kernel32!IsDebuggerPresent"),
        context: vec!["call", "test eax, eax", "jz"],
    },
    AntiDebugSignature {
        name: "PEB.BeingDebugged read",
        pattern: ApiPattern::InstructionPattern(vec![
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00  // mov rax, gs:[0x60]
        ]),
        context: vec!["mov al, [rax+2]", "test al, al"],
    },
    AntiDebugSignature {
        name: "NtQueryInformationProcess(ProcessDebugPort)",
        pattern: ApiPattern::ExactApi("ntdll!NtQueryInformationProcess"),
        context: vec!["mov edx, 7", "call"],  // ProcessInformationClass = 7
    },
    AntiDebugSignature {
        name: "RDTSC timing check",
        pattern: ApiPattern::InstructionPattern(vec![0x0F, 0x31]),  // rdtsc
        context: vec!["rdtsc", "sub", "cmp", "ja"],  // delta > threshold
    },
    AntiDebugSignature {
        name: "CheckRemoteDebuggerPresent",
        pattern: ApiPattern::ExactApi("kernel32!CheckRemoteDebuggerPresent"),
        context: vec!["call", "test eax, eax"],
    },
    AntiDebugSignature {
        name: "NtQueryObject(ObjectTypeInformation)",
        pattern: ApiPattern::ExactApi("ntdll!NtQueryObject"),
        context: vec!["mov edx, 2", "call"],  // ObjectInformationClass = 2
    },
];

fn match_signature(rip: u64, code: &[u8]) -> Option<&'static AntiDebugSignature> {
    for sig in ANTIDEBUG_SIGNATURES {
        match &sig.pattern {
            ApiPattern::ExactApi(api_name) => {
                let module = query_module_at_address(rip);
                if module.as_ref().map_or(false, |m| m.contains(api_name)) {
                    return Some(sig);
                }
            },
            ApiPattern::InstructionPattern(pattern) => {
                if code.starts_with(pattern) {
                    return Some(sig);
                }
            },
        }
    }
    None
}
```

**使用**: 在分析热点时，对每个 RIP 进行特征匹配

---

## 3. 线程等待原因诊断

### 3.1 Windows 线程等待状态

#### 3.1.1 等待原因枚举

Windows 内核维护每个线程的等待原因（`KWAIT_REASON`），可通过 `NtQueryInformationThread` 查询：

```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitReason {
    Executive = 0,          // 等待内核对象（Event, Mutex, Semaphore, ...）
    FreePage = 1,           // 等待空闲页
    PageIn = 2,             // 等待页换入
    PoolAllocation = 3,     // 等待池分配
    DelayExecution = 4,     // Sleep() / SleepEx()
    Suspended = 5,          // 挂起状态
    UserRequest = 6,        // 等待用户输入（GetMessage, WaitForSingleObject）
    WrExecutive = 7,        // WaitForSingleObject 等待内核对象
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,  // Alertable sleep
    WrSuspended = 12,
    WrUserRequest = 13,     // Alertable 用户请求
    WrEventPair = 14,
    WrQueue = 15,           // I/O completion port
    WrLpcReceive = 16,      // LPC 等待
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    // ... 更多（Windows 内部）
}

/// 查询线程等待原因
fn query_thread_wait_reason(
    process_handle: HANDLE,
    thread_id: u32,
) -> Result<Option<WaitReason>> {
    let thread_handle = unsafe {
        OpenThread(THREAD_QUERY_INFORMATION, false, thread_id)?
    };
    
    // ThreadInformationClass = ThreadBasicInformation (0)
    let mut tbi = THREAD_BASIC_INFORMATION::default();
    let mut return_length = 0u32;
    
    let status = unsafe {
        NtQueryInformationThread(
            thread_handle,
            0,  // ThreadBasicInformation
            &mut tbi as *mut _ as *mut c_void,
            std::mem::size_of::<THREAD_BASIC_INFORMATION>() as u32,
            &mut return_length,
        )
    };
    
    unsafe { CloseHandle(thread_handle)? };
    
    if status != 0 {
        return Err(format!("NtQueryInformationThread failed: {:#x}", status).into());
    }
    
    // WaitReason 在 THREAD_BASIC_INFORMATION 扩展结构中
    // 需要 SYSTEM_THREAD_INFORMATION（通过 NtQuerySystemInformation 获取）
    query_wait_reason_via_system_info(thread_id)
}

/// 通过 SystemProcessInformation 查询等待原因（更可靠）
fn query_wait_reason_via_system_info(thread_id: u32) -> Result<Option<WaitReason>> {
    // 1. 分配缓冲区（初始 1MB，不够则扩大）
    let mut buffer_size = 1024 * 1024;
    let mut buffer = vec![0u8; buffer_size];
    
    loop {
        let mut return_length = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                5,  // SystemProcessInformation
                buffer.as_mut_ptr() as *mut c_void,
                buffer_size as u32,
                &mut return_length,
            )
        };
        
        if status == 0 {
            break;  // 成功
        } else if status == 0xC0000004 {  // STATUS_INFO_LENGTH_MISMATCH
            buffer_size = return_length as usize;
            buffer.resize(buffer_size, 0);
        } else {
            return Err(format!("NtQuerySystemInformation failed: {:#x}", status).into());
        }
    }
    
    // 2. 解析 SYSTEM_PROCESS_INFORMATION 链表
    let mut offset = 0;
    loop {
        let spi = unsafe {
            &*(buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION)
        };
        
        // 遍历该进程的所有线程
        let threads = unsafe {
            std::slice::from_raw_parts(
                (spi as *const _ as usize + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>()) as *const SYSTEM_THREAD_INFORMATION,
                spi.NumberOfThreads as usize,
            )
        };
        
        for thread in threads {
            if thread.ClientId.UniqueThread as u32 == thread_id {
                return Ok(Some(unsafe { std::mem::transmute(thread.WaitReason) }));
            }
        }
        
        if spi.NextEntryOffset == 0 {
            break;
        }
        offset += spi.NextEntryOffset as usize;
    }
    
    Ok(None)  // 线程未找到
}
```

#### 3.1.2 等待原因解读

| WaitReason | 含义 | 与假说的关联 |
|-----------|------|------------|
| **DelayExecution / WrDelayExecution** | `Sleep()` | 假说 A（反调试）或 B（正常等待） |
| **UserRequest / WrUserRequest** | `GetMessage`, `WaitForSingleObject` | 假说 B（窗口消息泵） |
| **Executive / WrExecutive** | 等待内核对象（Event, Mutex, ...） | 假说 C（外部阻塞） |
| **LpcReceive / LpcReply** | 等待 LPC 通信 | 假说 C（进程间通信阻塞） |
| **Queue** | 等待 I/O 完成端口 | 假说 C（异步 I/O） |
| **Suspended** | 线程被挂起 | 调试器操作或反调试响应 |

### 3.2 等待对象识别

如果 `WaitReason = Executive`，进一步查询线程等待的具体内核对象：

```rust
/// 查询线程等待的内核对象句柄
fn query_wait_objects(thread_handle: HANDLE) -> Result<Vec<HANDLE>> {
    // ThreadInformationClass = ThreadWaitChain (48, Windows 8+)
    let mut wait_chain = [0usize; 16];  // 最多 16 个对象
    let mut return_length = 0u32;
    
    let status = unsafe {
        NtQueryInformationThread(
            thread_handle,
            48,  // ThreadWaitChain
            wait_chain.as_mut_ptr() as *mut c_void,
            std::mem::size_of_val(&wait_chain) as u32,
            &mut return_length,
        )
    };
    
    if status != 0 {
        // ThreadWaitChain 不可用（老系统或权限不足），回退到启发式
        return Ok(Vec::new());
    }
    
    let count = return_length as usize / std::mem::size_of::<usize>();
    Ok(wait_chain[..count].iter().map(|&h| h as HANDLE).collect())
}

/// 查询内核对象的类型和名称
fn query_object_info(handle: HANDLE) -> Result<ObjectInfo> {
    // 1. 查询类型
    let mut type_info = [0u8; 1024];
    let mut return_length = 0u32;
    let status = unsafe {
        NtQueryObject(
            handle,
            1,  // ObjectTypeInformation
            type_info.as_mut_ptr() as *mut c_void,
            type_info.len() as u32,
            &mut return_length,
        )
    };
    
    let type_name = if status == 0 {
        parse_object_type_name(&type_info)
    } else {
        "Unknown".to_string()
    };
    
    // 2. 查询名称
    let mut name_info = [0u8; 4096];
    let status = unsafe {
        NtQueryObject(
            handle,
            1,  // ObjectNameInformation
            name_info.as_mut_ptr() as *mut c_void,
            name_info.len() as u32,
            &mut return_length,
        )
    };
    
    let object_name = if status == 0 {
        parse_object_name(&name_info)
    } else {
        None
    };
    
    Ok(ObjectInfo {
        handle,
        type_name,
        name: object_name,
    })
}
```

**可疑对象模式**:

| 对象类型 | 名称模式 | 判定 |
|---------|---------|------|
| **Mutant (Mutex)** | 包含 "debug" / "olly" / "ida" | 反调试：等待调试器特有互斥体超时 |
| **Event** | 无名称（匿名 Event） | 可能是反调试内部事件 |
| **File** | 网络路径 `\\\\server\\...` | 外部阻塞：网络驱动器超时 |
| **File** | 特殊设备 `\\\\.\\PHYSICALDRIVE0` | 可能是反虚拟机检测 |
| **Event** | 名称 = `Global\\...` | 跨会话对象，可能等待其他进程 |

---

## 4. 全窗口枚举规格

### 4.1 枚举方法

#### 4.1.1 完整枚举（推荐）

**目标**: 获取目标进程创建的所有窗口，不限于类名

```rust
/// 枚举目标进程的所有窗口
fn enumerate_process_windows(target_pid: u32) -> Result<Vec<WindowInfo>> {
    let mut windows = Vec::new();
    
    // EnumWindows 回调
    unsafe {
        EnumWindows(
            Some(enum_windows_callback),
            &mut windows as *mut _ as LPARAM,
        )?;
    }
    
    // 过滤出目标进程的窗口
    windows.retain(|w| w.process_id == target_pid);
    
    Ok(windows)
}

extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let windows = unsafe { &mut *(lparam as *mut Vec<WindowInfo>) };
    
    // 查询窗口所属进程
    let mut pid = 0u32;
    let mut tid = 0u32;
    tid = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    
    // 查询窗口属性
    let class_name = get_window_class_name(hwnd);
    let window_text = get_window_text(hwnd);
    let is_visible = unsafe { IsWindowVisible(hwnd) }.as_bool();
    let parent = unsafe { GetParent(hwnd) };
    
    // 查询窗口位置和大小
    let mut rect = RECT::default();
    let _ = unsafe { GetWindowRect(hwnd, &mut rect) };
    
    windows.push(WindowInfo {
        hwnd: hwnd.0 as usize,
        process_id: pid,
        thread_id: tid,
        class_name,
        window_text,
        is_visible,
        parent_hwnd: if parent.0 != 0 { Some(parent.0 as usize) } else { None },
        rect: (rect.left, rect.top, rect.right, rect.bottom),
    });
    
    true.into()  // 继续枚举
}

fn get_window_class_name(hwnd: HWND) -> String {
    let mut buf = [0u16; 256];
    let len = unsafe { GetClassNameW(hwnd, &mut buf) };
    String::from_utf16_lossy(&buf[..len as usize])
}

fn get_window_text(hwnd: HWND) -> String {
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    if len == 0 {
        return String::new();
    }
    
    let mut buf = vec![0u16; len as usize + 1];
    let len = unsafe { GetWindowTextW(hwnd, &mut buf) };
    String::from_utf16_lossy(&buf[..len as usize])
}
```

**窗口属性收集**:

| 属性 | API | 用途 |
|-----|-----|------|
| **类名** | `GetClassName` | 识别窗口类型（消息框、主窗口、...） |
| **标题** | `GetWindowText` | 读取窗口内容（可能包含错误信息） |
| **可见性** | `IsWindowVisible` | 区分前台窗口 vs 隐藏窗口 |
| **父子关系** | `GetParent` | 构建窗口层级树 |
| **位置大小** | `GetWindowRect` | 检测窗口是否在屏幕外（隐藏技巧） |
| **Z序** | `GetWindow(GW_HWNDPREV/NEXT)` | 判断窗口叠放顺序 |
| **样式** | `GetWindowLong(GWL_STYLE)` | 识别模态对话框（`WS_DISABLED`） |

#### 4.1.2 时序变化追踪

**目标**: 记录窗口在超时窗口内的创建/销毁时间轴

```rust
/// 窗口监控器：定期枚举并记录变化
struct WindowMonitor {
    target_pid: u32,
    snapshots: Vec<WindowSnapshot>,
    interval_ms: u64,
}

struct WindowSnapshot {
    timestamp: SystemTime,
    windows: Vec<WindowInfo>,
}

impl WindowMonitor {
    fn start_monitoring(&mut self, duration_secs: u64) -> Result<()> {
        let start = SystemTime::now();
        
        loop {
            let windows = enumerate_process_windows(self.target_pid)?;
            self.snapshots.push(WindowSnapshot {
                timestamp: SystemTime::now(),
                windows,
            });
            
            if start.elapsed()? > Duration::from_secs(duration_secs) {
                break;
            }
            
            std::thread::sleep(Duration::from_millis(self.interval_ms));
        }
        
        Ok(())
    }
    
    /// 分析窗口变化
    fn analyze_changes(&self) -> WindowChangeReport {
        let mut created = Vec::new();
        let mut destroyed = Vec::new();
        let mut persistent = Vec::new();
        
        for i in 1..self.snapshots.len() {
            let prev = &self.snapshots[i-1].windows;
            let curr = &self.snapshots[i].windows;
            
            let prev_hwnds: HashSet<_> = prev.iter().map(|w| w.hwnd).collect();
            let curr_hwnds: HashSet<_> = curr.iter().map(|w| w.hwnd).collect();
            
            // 新创建的窗口
            for hwnd in curr_hwnds.difference(&prev_hwnds) {
                let window = curr.iter().find(|w| w.hwnd == *hwnd).unwrap();
                created.push((self.snapshots[i].timestamp, window.clone()));
            }
            
            // 被销毁的窗口
            for hwnd in prev_hwnds.difference(&curr_hwnds) {
                let window = prev.iter().find(|w| w.hwnd == *hwnd).unwrap();
                destroyed.push((self.snapshots[i].timestamp, window.clone()));
            }
        }
        
        // 持久窗口（全程存在）
        if let (Some(first), Some(last)) = (self.snapshots.first(), self.snapshots.last()) {
            let first_hwnds: HashSet<_> = first.windows.iter().map(|w| w.hwnd).collect();
            let last_hwnds: HashSet<_> = last.windows.iter().map(|w| w.hwnd).collect();
            
            for hwnd in first_hwnds.intersection(&last_hwnds) {
                let window = last.windows.iter().find(|w| w.hwnd == *hwnd).unwrap();
                persistent.push(window.clone());
            }
        }
        
        WindowChangeReport {
            created,
            destroyed,
            persistent,
        }
    }
}
```

**异常模式**:

| 模式 | 描述 | 判定 |
|-----|------|------|
| **窗口爆炸** | 短时间内创建 > 10 个窗口 | 可能是反调试响应（弹出警告窗口） |
| **窗口冻结** | 全程只有 1 个窗口且不变 | 正常（单窗口应用） |
| **周期性创建销毁** | 同一类名的窗口反复创建/销毁 | 可能是消息泵异常 |
| **隐藏窗口** | `IsWindowVisible = false` 但持续存在 | 可能是后台工作线程的窗口 |

### 4.2 消息泵诊断

**目标**: 判断窗口消息处理是否正常

```rust
/// 向窗口发送测试消息，观察响应
fn test_message_pump(hwnd: HWND) -> MessagePumpStatus {
    // 1. 发送 WM_NULL（无操作消息，不应改变状态）
    let result = unsafe {
        SendMessageTimeoutW(
            hwnd,
            WM_NULL,
            WPARAM(0),
            LPARAM(0),
            SMTO_NORMAL,
            1000,  // 1 秒超时
            None,
        )
    };
    
    if result.is_err() {
        return MessagePumpStatus::NotResponding;
    }
    
    // 2. 检查窗口是否挂起（Hung）
    let is_hung = unsafe { IsHungAppWindow(hwnd) }.as_bool();
    if is_hung {
        return MessagePumpStatus::Hung;
    }
    
    // 3. 查询消息队列状态
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, None) };
    let queue_status = unsafe { GetQueueStatus(QS_ALLINPUT) };
    
    if queue_status == 0 {
        MessagePumpStatus::IdleNoMessages
    } else {
        MessagePumpStatus::Normal
    }
}

enum MessagePumpStatus {
    /// 正常响应
    Normal,
    /// 不响应（SendMessage 超时）
    NotResponding,
    /// Windows 判定为挂起
    Hung,
    /// 空闲（无消息排队）
    IdleNoMessages,
}
```

**诊断结论**:

| 状态 | RIP 位置 | 综合判定 |
|-----|---------|---------|
| **NotResponding** | 在 `GetMessage` | 假说 B：等待消息输入（正常但慢） |
| **NotResponding** | 不在消息泵 | 假说 A：反调试导致主线程挂起 |
| **Hung** | 任意 | Windows 级别判定，进程可能死锁 |
| **IdleNoMessages** | 在 `Sleep` | 假说 B：定时器等待（正常） |

---

## 5. 三假说判据表

### 5.1 判据矩阵

| 观测维度 | 假说 A（反调试） | 假说 B（正常行为） | 假说 C（外部阻塞） |
|---------|----------------|-----------------|-----------------|
| **RIP 热点** | 在反调试 API 或特征循环中 | 在业务逻辑（GetMessage, Sleep） | 在系统调用返回后的等待循环 |
| **RIP 模式** | 单点热点（死循环）或双点振荡 | 消息泵循环（10-20 条指令） | 小范围跳动（等待检查） |
| **RIP 基线对比** | 完全不同（overlap < 0.3） | 相似但频率不同（similarity 0.5-0.8） | 部分重叠（overlap 0.3-0.6） |
| **线程等待原因** | DelayExecution (无限 Sleep) | UserRequest (GetMessage) | Executive (等待内核对象) |
| **等待对象** | 可疑 Mutex（包含 "debug"） | 正常 Event（窗口事件） | 外部资源（File, LPC） |
| **窗口枚举** | 窗口冻结或异常创建 | 窗口正常，消息泵可能慢 | 窗口正常，与等待无关 |
| **消息泵状态** | NotResponding（不在消息泵） | IdleNoMessages（正常等待） | Normal（但线程在其他等待） |
| **CPU 使用率** | ~0%（挂起） | ~0%（空闲等待） | ~0%（I/O 等待） |
| **反调试特征匹配** | 匹配到 ≥ 1 个特征 | 无匹配 | 无匹配 |

### 5.2 决策算法

```python
def diagnose(observations: Observations) -> Diagnosis:
    score_a = 0  # 假说 A
    score_b = 0  # 假说 B
    score_c = 0  # 假说 C
    
    # 1. RIP 分析
    if observations.rip_in_antidebug_signature:
        score_a += 10
    elif observations.rip_in_message_pump:
        score_b += 8
    elif observations.rip_in_syscall_wait:
        score_c += 8
    
    if observations.rip_pattern == "single_hotspot":
        score_a += 5
    elif observations.rip_pattern == "message_pump_loop":
        score_b += 7
    elif observations.rip_pattern == "small_range_jump":
        score_c += 5
    
    if observations.baseline_similarity < 0.3:
        score_a += 3
    elif 0.5 <= observations.baseline_similarity < 0.8:
        score_b += 3
    
    # 2. 线程等待原因
    if observations.wait_reason == "DelayExecution" and observations.wait_infinite:
        score_a += 8
    elif observations.wait_reason == "UserRequest":
        score_b += 7
    elif observations.wait_reason == "Executive":
        score_c += 8
    
    # 3. 等待对象
    if observations.suspicious_mutex:
        score_a += 6
    elif observations.normal_event:
        score_b += 4
    elif observations.external_resource:
        score_c += 7
    
    # 4. 窗口状态
    if observations.window_frozen or observations.window_explosion:
        score_a += 4
    elif observations.message_pump_status == "IdleNoMessages":
        score_b += 5
    
    # 5. 反调试特征
    score_a += observations.antidebug_feature_count * 3
    
    # 决策
    max_score = max(score_a, score_b, score_c)
    confidence = max_score / (score_a + score_b + score_c + 0.01)  # 避免除零
    
    if max_score == score_a:
        verdict = "ANTIDEBUG_DETECTION"
    elif max_score == score_b:
        verdict = "NORMAL_BEHAVIOR_CHANGE"
    else:
        verdict = "EXTERNAL_BLOCKING"
    
    return Diagnosis(
        verdict=verdict,
        confidence=confidence,
        scores={"A": score_a, "B": score_b, "C": score_c},
        evidence=observations,
    )
```

### 5.3 置信度与决策阈值

| 置信度 | 决策 |
|-------|------|
| **> 0.6** | 高置信判定，执行对应后续动作 |
| **0.4 - 0.6** | 中等置信，执行保守动作或多假说并行验证 |
| **< 0.4** | 低置信，需要更多诊断数据或人工分析 |

---

## 6. 诊断流程图

```
                    [超时事件触发]
                           |
                           v
            +-----------------------------+
            | 1. RIP 分布采样（30s）       |
            | - 定时快照 (500ms 间隔)      |
            | - 热点识别                   |
            | - 循环检测                   |
            | - 特征匹配                   |
            +-----------------------------+
                           |
                           v
            +-----------------------------+
            | 2. 线程等待原因查询          |
            | - NtQueryInformationThread   |
            | - 等待对象识别               |
            | - 可疑模式检测               |
            +-----------------------------+
                           |
                           v
            +-----------------------------+
            | 3. 全窗口枚举（30s）         |
            | - EnumWindows                |
            | - 时序变化追踪               |
            | - 消息泵诊断                 |
            +-----------------------------+
                           |
                           v
            +-----------------------------+
            | 4. 三假说判据计算            |
            | - 综合打分                   |
            | - 置信度评估                 |
            +-----------------------------+
                           |
         +-----------------+-----------------+
         |                 |                 |
         v                 v                 v
[假说 A: 反调试]  [假说 B: 正常行为]  [假说 C: 外部阻塞]
     |                 |                 |
     v                 v                 v
[启用 Phase 2-3]  [延长超时 or 接受]  [诊断阻塞源]
   handlers
     |
     v
[重新运行 → Route α]
```

---

## 7. 与 Route α 的协同

### 7.1 协同模式

**场景 1: 超时 → 诊断 → 触碰**

```
1. Route U R1 超时（120s）
2. 启动 WO-1302 诊断
   - RIP 分析：单点热点在 Sleep 循环
   - 线程等待：DelayExecution
   - 窗口状态：冻结，NotResponding
   - 判据结果：假说 A（反调试），置信度 0.75
3. 决策：启用 Phase 2-3 handlers（WO-1006）
4. 重新运行
5. 如仍超时 → 转 Route α 触碰解密
```

**场景 2: 触碰 → 超时 → 诊断**

```
1. Route α Phase 2 触碰中
2. 触碰 200 次后进程超时
3. 启动 WO-1302 诊断
   - RIP 分析：在 NtQueryObject 循环
   - 线程等待：Executive
   - 等待对象：File handle (网络路径)
   - 判据结果：假说 C（外部阻塞），置信度 0.82
4. 决策：非触碰导致，继续 Route α
```

### 7.2 诊断输出到 Route α 的数据接口

```rust
/// 诊断报告（传递给 Route α）
struct DiagnosisReport {
    verdict: Verdict,
    confidence: f64,
    
    /// RIP 热点（供 α 路线触碰策略参考）
    rip_hotspots: Vec<Hotspot>,
    
    /// 反调试特征（供 Phase 2-3 决策）
    antidebug_features: Vec<AntiDebugSignature>,
    
    /// 建议动作
    recommended_action: Action,
}

enum Verdict {
    AntiDebugDetection,
    NormalBehaviorChange,
    ExternalBlocking,
}

enum Action {
    /// 启用 Phase 2-3 handlers
    EnablePhase23,
    /// 延长超时并重试
    ExtendTimeout { new_timeout_secs: u64 },
    /// 转 Route α 触碰
    SwitchToRouteAlpha,
    /// 止损，回到人工分析
    Abort,
}
```

### 7.3 诊断-触碰循环

**迭代策略**:

```
Iteration 1: 基线诊断
  - 无 handlers，无触碰
  - 纯观测超时行为
  - 输出：假说 + 置信度

Iteration 2: Phase 2-3 干预
  - 如假说 A 高置信 → 启用 handlers
  - 重新运行，观测超时是否缓解
  - 如仍超时 → 假说 A 可能错误，或 handlers 不足

Iteration 3: Route α 触碰
  - 启动 Phase 1 PoC（WO-1301 §8.2 Phase 1）
  - 触碰 5 个已知 guard 地址
  - 如成功解密 → 继续 Phase 2-3
  - 如触发非 guard AV → 止损

Iteration 4: 深度诊断
  - 单步执行（RIP 采样升级为单步）
  - CFG 重建（确认控制流完整性）
  - 内存快照对比（检测隐藏修改）
```

---

## 8. LIVE-4 诊断实弹授权申请

### 8.1 申请概览

| 字段 | 值 |
|-----|---|
| **申请编号** | LIVE-4-DIAG-001 |
| **申请人** | WO-1302 设计组 |
| **申请日期** | 2026-08-22 |
| **目标** | 窗口怠速诊断验证 |
| **预期实弹次数** | 2-3 次（与 WO-1301 可合并） |
| **单次预算** | 15 分钟 |
| **样本** | Route U R1 / Route V R0 超时案例 |
| **前置条件** | WO-1302 设计方案已批准 |

### 8.2 实验阶段

#### Phase 1: 基线诊断（无干预）

**目标**: 复现超时并收集诊断数据

**步骤**:
1. 启动目标样本（Route U R1 配置）
2. 同时启动诊断工具：
   - RIP 采样器（30s, 500ms 间隔）
   - 线程等待原因查询（每 5s）
   - 窗口监控器（30s, 1s 间隔）
3. 等待 120s 超时触发
4. 收集所有诊断数据

**成功标准**:
- 超时复现
- 采集到 ≥ 60 个 RIP 快照
- 线程等待原因查询成功
- 窗口枚举 ≥ 30 次

**预期耗时**: 10 分钟（含启动 + 超时 + 数据导出）

---

#### Phase 2: 假说验证（有干预）

**目标**: 根据 Phase 1 判据结果，测试对应干预措施

**分支 A（假说 A 高置信）**:
1. 启用 Phase 2-3 handlers（WO-1006）
2. 重新运行样本
3. 观测超时是否缓解

**分支 B（假说 B 高置信）**:
1. 延长超时至 300s
2. 重新运行
3. 观测是否正常完成

**分支 C（假说 C 高置信）**:
1. 诊断阻塞源（文件/注册表/网络）
2. 移除阻塞（如提供缺失文件）
3. 重新运行

**成功标准**:
- 干预后超时行为改变（缓解或消除）
- 验证假说的预测准确性

**预期耗时**: 10 分钟（每分支）

---

### 8.3 交付物

1. **诊断日志** (JSON)
   - RIP 快照序列
   - 线程等待原因历史
   - 窗口枚举时间轴

2. **三假说评分报告** (Markdown)
   - 判据矩阵填充结果
   - 置信度计算过程
   - 推荐动作

3. **可视化报告** (HTML)
   - RIP 热力图（地址 vs 时间）
   - 窗口时间轴（创建/销毁事件）
   - 等待原因分布图

4. **假说验证结果** (如达到 Phase 2)
   - 干预前后对比
   - 假说准确性评估

---

## 9. 总结与审批前确认

### 9.1 设计方案自查

| 检查项 | 状态 | 备注 |
|-------|------|------|
| ✅ 问题陈述清晰 | 通过 | 1.1-1.2 节 |
| ✅ RIP 采样设计完整 | 通过 | 2.1-2.3 节，含热点/循环/基线 |
| ✅ 线程等待诊断可行 | 通过 | 3.1-3.2 节，API 调用详细 |
| ✅ 窗口枚举规格明确 | 通过 | 4.1-4.2 节，含时序追踪 |
| ✅ 三假说判据表 | 通过 | 5.1-5.3 节，决策算法实现 |
| ✅ 与 Route α 协同 | 通过 | 7.1-7.3 节，闭环设计 |
| ✅ LIVE-4 申请详细 | 通过 | 8.1-8.3 节 |
| ✅ 非侵入式设计 | 通过 | 全文强调只读观测 |

### 9.2 待总指挥决策的关键问题

1. **采样间隔**: 500ms vs 1s？（建议 500ms，精度优先）
2. **诊断时长**: 30s vs 60s？（建议 30s，覆盖超时窗口 1/4）
3. **置信度阈值**: 多少置信度才启动干预？（建议 0.6）
4. **与 WO-1301 合并**: 是否在同一 LIVE-4 会话中同时执行诊断 + 触碰？（建议是，节省时间）

### 9.3 文档版本

| 版本 | 日期 | 变更 | 作者 |
|-----|------|------|------|
| v0.1 | 2026-08-22 | 初稿 | WO-1302 设计组 |
| v1.0 | 待定 | 总指挥批注后定稿 | - |

---

**提交状态**: 📤 待总指挥联审  
**后续流程**: 与 WO-1301 一同批准 → 拆分实施单 → LIVE-4 签发
