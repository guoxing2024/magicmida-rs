# TLS Bootstrap 持续崩溃诊断
日期：2026-07-16 更新

## 当前状态

程序仍然在TLS callback的memcpy中崩溃：
- 崩溃偏移：0xeda075（rep movsb指令）
- 已修复3个bug，但仍有问题

## 已修复的Bug

1. ✅ 参数类型不匹配
2. ✅ Image base计算（改用movabs）
3. ✅ 部分修复了源地址计算

## 当前问题

### 症状
`rep movsb`指令崩溃（访问违例0xC0000005）

### 源地址计算（最新版本）
```asm
0x31: mov rcx, r12              ; 目标 = HeapAlloc结果
0x34: lea rdx, [rip+0]          ; RDX = 当前VA
0x3B: sub rdx, 0x3B             ; RDX = boot section VA起始
0x3F: add rdx, [r14+0x10]       ; RDX += container_data_offset (0xF0)
```

计算应该得到：`0x140EDA000 + 0xF0 = 0x140EDA0F0`

### 验证结果
- ✅ .boot section有读+执行权限
- ✅ 数据确实在文件的0xF0偏移处（68/72字节非零）
- ✅ VirtualSize足够大（0x1000字节）
- ✅ HeapAlloc成功（否则会跳过memcpy）

## 可能的根本原因

### 假设1：地址计算仍然有误
虽然逻辑看起来正确，但可能：
- `sub rdx, 0x3B`执行后的结果不对
- 或者`[r14+0x10]`读取的值不是0xF0

### 假设2：内存对齐问题
`rep movsb`对地址对齐敏感，虽然理论上不应该崩溃。

### 假设3：TLS callback环境问题
TLS callback执行时，某些系统状态可能异常。

## 建议的下一步

### 方案A：添加调试输出
修改bootstrap代码，在memcpy前添加INT3断点或调试输出：
```asm
; 在0x43处插入
int3  ; 触发调试器
```

### 方案B：简化测试
生成一个**最小化的TLS bootstrap**：
```rust
// 只测试读取.boot section数据，不做memcpy
lea rdx, [rip+0]
sub rdx, offset
; 读取rdx指向的数据到寄存器
mov rax, [rdx+0xF0]
; 然后ret，不执行memcpy
ret
```

### 方案C：使用备选方案
不使用TLS callback，改用传统的entry point bootstrap：
- 修改Entry Point指向bootstrap
- Bootstrap执行完后跳转到真实OEP
- 这样避开TLS callback的复杂性

### 方案D：使用固定地址
不计算.boot section地址，直接使用固定的绝对地址：
```asm
movabs rdx, 0x140EDA0F0  ; 直接加载数据地址
```

## 代码审查检查点

需要验证的地方：
1. `current_offset_in_boot`计算是否正确（第340行）
2. `sub rdx, imm8`的opcode是否正确生成
3. metadata中的`container_data_offset`值是否正确写入

## 时间投入 vs 回报

已经投入大量时间在这个问题上。考虑：
1. 如果方案C（entry point bootstrap）更简单，可能值得尝试
2. 或者先验证其他样本能否用当前代码成功脱壳
3. 这个特定样本可能有特殊的保护机制

## 需要收集的信息

如果继续调试，需要：
1. 用调试器attach到进程，在TLS callback设置断点
2. 检查寄存器RDX、RSI、RDI、RCX的实际值
3. 尝试手工执行`rep movsb`看是否成功
4. 检查内存中.boot section是否完整加载

---

**建议**：考虑使用方案C（entry point bootstrap）作为备选，可能比继续调试TLS callback更高效。
