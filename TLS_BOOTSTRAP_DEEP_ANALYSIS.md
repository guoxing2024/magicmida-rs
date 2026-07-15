# TLS Bootstrap崩溃深度分析
日期：2026-07-16

## 已修复的Bug

### Bug #1: 参数类型不匹配 ✅
**位置**: `tls_bootstrap.rs:94`  
**问题**: 传递`global_vars`而不是`data_snapshot`和`image_base`  
**修复**: 传递`None`和`image_base`

### Bug #2: RIP相对寻址错误 ✅
**位置**: `container_bootstrap.rs:448`  
**问题**: 使用`lea r10, [rip - current_rva]`计算image base  
**修复**: 使用`movabs r10, image_base`直接加载

## 当前状态

程序运行7秒后崩溃，崩溃位置：`0xeda071` (boot section + 0x71)

从日志分析：
- `loop_end=98` (0x62)
- `jmp_over_at=100` (0x64)
- `helpers_end=159` (0x9F)

**0x71在jmp_over和helpers_end之间，说明崩溃在helper函数内部！**

## 代码布局重建

```
0x00-0x62: 主循环代码
0x62:      循环结束
0x64:      jmp short over_helpers  (跳过helper函数)
0x66:      memcpy helper开始
  ...
0xXX:      update_triple helper开始
  ...
0x9F:      helpers结束
0xA0:      over_helpers标签（epilogue）
```

## 崩溃点分析

0x71 - 0x66 (假设memcpy在0x66开始) = 0x0B (11字节进入helper区域)

**memcpy helper代码：**
```asm
0x66: push rdi, rsi            (2 bytes)
0x68: mov rdi, rcx             (3 bytes)
0x6B: mov rsi, rdx             (3 bytes)
0x6E: mov rcx, r8              (3 bytes) = 0x71 ← 崩溃点
```

或者是**update_triple helper**开始位置不对？

## 关键问题

1. **helper函数的相对偏移计算可能有问题**
   - `call memcpy`时计算的偏移量
   - `call update_triple`时计算的偏移量

2. **jmp_over_helpers的偏移计算可能有问题**
   - 如果跳转距离计算错误，可能跳到helpers中间

3. **程序实际执行路径**
   - 可能根本没有跳过helpers，直接执行到里面崩溃

## 下一步调试策略

### 方案A: 添加详细日志
修改`container_bootstrap.rs`，输出每个关键偏移：
- call memcpy的目标偏移
- call update_triple的目标偏移  
- jmp over_helpers的目标偏移
- 每个helper函数的实际起始位置

### 方案B: 反汇编验证
使用工具反汇编`.boot` section，验证：
- helper函数位置是否正确
- call指令目标是否正确
- jmp指令目标是否正确

### 方案C: 简化测试
创建一个**最小化的TLS bootstrap**：
- 移除container恢复逻辑
- 只做一个简单的`nop; ret`
- 验证TLS callback本身能否正常工作

## 代码审查需要检查的地方

1. **`container_bootstrap.rs:407-408`**: memcpy offset patch
2. **`container_bootstrap.rs:430-431`**: update_triple offset patch  
3. **`container_bootstrap.rs:472-473`**: jmp_over_helpers offset patch
4. **helper函数实际生成的位置**

关键是这些offset的计算基准（from和to）是否一致。
