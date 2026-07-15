# 容器恢复 Bootstrap 实现

## 概述

扩展了基础的 heap bootstrap 为完整的容器恢复 stub，用于恢复存储在解包进程堆中的 SecurityCookie 编码容器。

## 架构

### .boot Section 布局

```text
+0x000: [Stub Code ~150-200 bytes]
        - 初始化 heap handle
        - 循环处理每个容器
        - 跳转到 OEP
        
+0x0C8: [Container Metadata Array]
        每个容器 40 字节：
        +0x00: u32  data_rva      — .data 中编码三元组的 RVA
        +0x04: u32  heap_size     — 需要分配的大小
        +0x08: u64  cookie        — SecurityCookie
        +0x10: u32  data_offset   — heap 快照在 .boot 中的偏移
        +0x14: u32  _reserved
        +0x18-27: padding
        
+0xXXX: [Heap Snapshot Data]
        每个容器的堆内存快照
```

### Stub 执行流程

```asm
1. 初始化阶段：
   sub rsp, 0x38                ; 栈帧 + 对齐
   call [GetProcessHeap]        ; 获取进程堆句柄
   mov r15, rax                 ; 保存到 r15
   lea r14, [metadata]          ; r14 = 元数据数组基址
   mov r13d, container_count    ; r13 = 容器计数

2. 循环处理每个容器：
.loop:
   mov rcx, r15                 ; hHeap
   xor edx, edx                 ; dwFlags = 0
   mov r8d, [r14+4]             ; dwBytes = heap_size
   call [HeapAlloc]             ; 分配堆内存
   test rax, rax
   jz .skip                     ; 分配失败则跳过
   
   mov r12, rax                 ; 保存分配的指针
   mov rcx, rax                 ; dest
   lea rdx, [rip+base]
   add rdx, [r14+16]            ; source = stub_base + data_offset
   mov r8d, [r14+4]             ; count = heap_size
   call inline_memcpy           ; 复制堆快照数据
   
   mov ecx, [r14]               ; data_rva
   mov rdx, [r14+8]             ; cookie
   mov r8, r12                  ; new_heap_ptr
   mov r9d, [r14+4]             ; heap_size
   call inline_update_triple    ; 更新编码的指针
   
.skip:
   add r14, 40                  ; 下一个元数据条目
   dec r13d
   jnz .loop

3. 跳转到原始入口点：
   add rsp, 0x38
   jmp [original_entry_point]
```

### Helper 函数

#### inline_memcpy
```asm
push rdi, rsi
mov rdi, rcx                    ; dest
mov rsi, rdx                    ; source
mov rcx, r8                     ; count
rep movsb                       ; 快速内存复制
pop rsi, rdi
ret
```

#### inline_update_triple
```asm
; rcx=data_rva, rdx=cookie, r8=new_heap_ptr, r9=size
lea r10, [rip-current_rva]      ; r10 = image_base
add r10, rcx                    ; r10 = image_base + data_rva

; Encode begin pointer
mov rax, r8
xor rax, rdx
mov [r10], rax

; Encode end pointer
lea r8, [r8+r9]
mov rax, r8
xor rax, rdx
mov [r10+8], rax

; Encode capacity pointer (same as end)
mov [r10+16], rax
ret
```

## 集成点

### 1. dump_process.rs
- 在 `dump_process` 函数中调用 `detect_containers` 检测容器
- 将检测到的容器传递给 `install_heap_bootstrap`

### 2. heap_bootstrap.rs
- 修改 `install_heap_bootstrap` 接受 `containers` 参数
- 如果检测到容器，调用 `container_bootstrap::install_container_bootstrap`
- 否则安装简单的 heap bootstrap

### 3. container_bootstrap.rs (新增)
- `install_container_bootstrap`: 创建 .boot section 并安装 stub
- `build_container_stub`: 构建完整的 stub（代码 + 元数据 + 数据）
- `build_stub_code`: 生成 x64 机器码

### 4. output_writer.rs
- 移除静态的容器恢复逻辑
- 容器恢复现在完全由运行时 bootstrap 处理

## 优势

1. **运行时恢复**: 在目标进程启动时动态分配堆内存，避免硬编码地址
2. **完整性**: 保留完整的堆数据快照，确保容器内容完整
3. **可靠性**: 使用 SecurityCookie 编码保护指针，与原始保护机制一致
4. **效率**: 内联的 memcpy 和 update_triple 减少函数调用开销
5. **可扩展**: 支持多个容器，循环处理所有检测到的实例

## 尺寸估计

- 基础代码: ~150 字节
- 每个容器元数据: 40 字节
- 每个容器数据: 变长（实际堆内容大小）
- 总大小: 对齐到 4KB (0x1000)

典型场景：
- 3 个容器，每个 256 字节数据
- 代码: 150 字节
- 元数据: 120 字节  
- 数据: 768 字节
- 总计: ~1038 字节，对齐后 4096 字节

## 测试建议

1. **单元测试**:
   - `metadata_size_is_40_bytes`: 验证元数据结构大小
   - `estimate_reasonable`: 验证代码尺寸估计合理

2. **集成测试**:
   - 使用包含编码容器的样本测试完整流程
   - 验证 stub 正确分配堆内存并更新指针
   - 确认转储的 PE 能够正常启动并访问容器数据

3. **端到端测试**:
   - 使用 Themida/WinLicense 保护的样本
   - 验证解包后的可执行文件行为与原始一致

## 未来改进

1. **错误处理**: 添加更详细的分配失败处理
2. **日志记录**: 在 stub 中添加调试输出（可选编译）
3. **性能优化**: 使用 SIMD 指令加速大块内存复制
4. **压缩**: 对堆快照数据进行压缩以减小 .boot section 大小
