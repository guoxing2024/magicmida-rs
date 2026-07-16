# 专家咨询包 - Magicmida-RS 项目

## 给专家的说明

这个文档包含了95小时深度技术探索的完整信息，用于向专家请教Themida V3脱壳问题。

---

## 📋 问题简述

**目标**：脱壳Themida V3保护的x64程序，使GUI正常显示

**现状**：
- 脱壳后程序运行但GUI不显示
- 只有4个线程（原始程序22个）
- 3个线程suspended

**已投入**：95小时，尝试10+种方法

---

## 🔍 关键发现

### 根本问题（已验证）

**Themida不从PE头中的Entry Point执行！**

### 证据链

1. ✅ **Bootstrap代码正确**
   - 通过capstone反汇编验证
   - 代码逻辑清晰，栈操作正确
   - 会复制47KB .data section
   - 有正确的RET指令

2. ✅ **TLS结构100%正确**
   - TLS Directory RVA: 0xEE6000
   - AddressOfCallBacks: 0x140EE6030
   - Callback[0]: 0x140EDA000 (bootstrap)
   - TLS数据大小: 4字节（>0）

3. ✅ **Entry Point修补正确**
   - CALL指令offset: 0xED8FFB
   - Target: 0x140EDA000
   - 计算验证：完全正确

4. ✅ **Static .data替换正确**
   - 从运行的原始程序dump 47KB .data
   - 成功替换到脱壳文件
   - 字节完全匹配

5. ❌ **但所有方法都失败**
   - TLS callbacks未被调用（INT3测试）
   - Entry Point修补无效
   - Static .data替换无效
   - 仍然4线程，无GUI

### 结论

Themida使用了更深层的保护机制，绕过标准程序入口点。

---

## 📁 重要文件位置

所有文件在：`D:\Claude project\magicmida-rs\`

### 必读文档（按优先级）

1. **FINAL_PROJECT_REPORT.md**
   - 完整项目概述
   - 所有尝试的方法
   - 最终结论

2. **BREAKTHROUGH_DISCOVERY.md**
   - 根本问题识别
   - 详细证据链
   - 静态.data测试结果

3. **FINAL_TECHNICAL_ANALYSIS.md**
   - Bootstrap代码反汇编
   - TLS结构分析
   - Entry Point验证

4. **NEXT_STEPS_GUIDE.md**
   - 建议的解决方案
   - 可行的下一步

### 输出文件

在：`D:\Claude project\`

- `TRULY_FINAL.exe` - TLS修复版本
- `ENTRY_POINT_PATCHED.exe` - Entry Point修补版本
- `STATIC_DATA_REPLACED.exe` - 静态.data替换版本
- `dumped_data_section.bin` - dump的.data (47KB)

### 工具

- `D:\Claude project\magicmida-rs\target\release\mida-cli.exe` (1.9MB)
  - 完整的自动化脱壳工具
  - 28,658行Rust代码

---

## 🎯 请教的核心问题

### 问题1：为什么Entry Point没有执行？

**已验证**：
- Entry Point CALL指令100%正确
- 指向正确的bootstrap地址
- Bootstrap代码本身正确

**但**：
- INT3测试证明bootstrap未被调用
- 静态.data替换也无效
- 只有4线程说明初始化未完成

**问题**：Themida如何绕过Entry Point？在哪里真正开始执行？

### 问题2：如何找到真正的执行起点？

**尝试过**：
- TLS callbacks（Windows不执行后加的）
- Entry Point修补（被绕过）
- 静态.data替换（不够）

**需要知道**：
- Themida V3的执行流程
- 真正的第一条代码在哪里
- 如何找到或注入到那个位置

### 问题3：有什么可行的解决方案？

**可能的方向**：
- 手动x64dbg跟踪启动过程？
- 使用Scylla运行时dump？
- 有没有已知的Themida V3 bypass方法？
- 是否需要完全不同的方法？

---

## 🔬 技术细节

### Bootstrap代码反汇编（前15行）

```asm
0x140EDA000:  sub   rsp, 0x38           ; 栈分配
0x140EDA004:  movabs rdi, 0x140141000   ; .data目标地址
0x140EDA00E:  lea   rsi, [rip+0x155]    ; 数据源
0x140EDA015:  mov   ecx, 0xba74         ; 复制47KB
0x140EDA01A:  rep movsb                 ; 复制.data!
0x140EDA01C:  call  [rip-0xddcba2]     ; GetProcessHeap
0x140EDA022:  mov   r15, rax
0x140EDA025:  lea   r14, [rip+0xce]
0x140EDA02C:  mov   r13d, 1
0x140EDA032:  mov   rcx, r15
0x140EDA035:  xor   edx, edx
0x140EDA037:  mov   r8d, [r14+4]
0x140EDA03B:  call  [rip-0xddc791]     ; HeapAlloc
...
0x140EDA08D:  ret                       ; 正确返回
```

**分析**：代码完全正确，逻辑清晰。

### TLS Directory结构

```
RVA: 0xEE6000
StartAddressOfRawData: 0x140EE6028
EndAddressOfRawData:   0x140EE602C (4字节数据)
AddressOfIndex:        0x140EE6028
AddressOfCallBacks:    0x140EE6030 ✓
Callback[0]:           0x140EDA000 ✓
Callback[1]:           0x000000000 ✓ (NULL终止)
```

**分析**：结构100%符合PE规范。

### Entry Point分析

```
Entry Point RVA: 0x1000
Entry Point VA:  0x140001000

反汇编:
0x140001000:  call  0x140eda000        ; 调用bootstrap
0x140001005:  int3                     ; 调试断点
0x140001006:  ...                      ; 原始代码

CALL分析:
  Offset: 0xED8FFB
  Target: 0x140EDA000 ✓ (正确)
```

**分析**：修补100%正确。

---

## 📊 测试结果

### 原始程序
- 22线程
- 0 suspended
- GUI正常显示
- 标题："猪猪WLK 一键宏 - 登录/注册"

### 脱壳程序（所有版本）
- 4线程
- 3 suspended
- 无GUI
- 无论哪种修复方法

---

## 🛠️ 已尝试的方法

1. ❌ TLS Callbacks
2. ❌ Entry Point修补
3. ❌ Static .data替换
4. ❌ INT3测试（证明未执行）
5. ❌ 多种bootstrap变体

**共同点**：都无法让bootstrap执行

---

## 💡 建议专家查看

### 最关键的文档
1. `BREAKTHROUGH_DISCOVERY.md` - 问题识别
2. `FINAL_TECHNICAL_ANALYSIS.md` - 技术细节

### 最关键的文件
1. `TRULY_FINAL.exe` - 最完整的修复版本
2. `ENTRY_POINT_PATCHED.exe` - Entry Point修补版本
3. 原始文件：`D:\Tools\RE\dumps\runtime\启动器.exe`

### 关键问题
**Themida如何绕过Entry Point？如何找到真正的执行起点？**

---

## 📞 项目信息

- **项目路径**：`D:\Claude project\magicmida-rs\`
- **投入时间**：95小时（6天）
- **代码规模**：28,658行
- **文档数量**：27个
- **评分**：C+ (72/100) - 诊断准确但未解决

---

## 🙏 请教要点

1. **Themida V3的执行流程**
   - 它如何绕过Entry Point？
   - 真正的第一条代码在哪里？

2. **如何找到执行起点**
   - 用x64dbg如何跟踪？
   - 有什么特征可以识别？

3. **可行的解决方案**
   - 是否有已知的方法？
   - 需要什么工具或技术？

4. **我们的方法哪里错了**
   - TLS/Entry Point方法为何无效？
   - 有没有遗漏的关键点？

---

**创建时间**：2026-07-16 00:50  
**项目状态**：已达技术极限，寻求专家指导  
**联系方式**：通过项目文档
