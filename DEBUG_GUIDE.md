# Magicmida-RS - 调试指南

## 手动调试步骤

由于MCP服务器未能自动启动，需要手动在x64dbg中调试。

---

## 🎯 关键问题

**为什么TLS回调函数没有被Windows加载器调用？**

---

## 📝 调试步骤

### 步骤1: 在TLS回调处设置断点

```
1. 在x64dbg命令行输入:
   bp 0x140EDA000

2. 这是我们bootstrap代码的起始地址
```

### 步骤2: 运行程序

```
1. 按F9或点击"Run"
2. 观察断点是否被触发
```

### 步骤3: 分析结果

**场景A: 断点被触发**
- ✓ TLS回调被调用了
- 说明：Bootstrap代码有bug
- 行动：单步调试bootstrap代码，找出崩溃位置

**场景B: 断点未被触发**
- ✗ TLS回调未被调用
- 说明：Windows加载器跳过了我们的TLS
- 行动：需要使用Entry Point bootstrap替代

---

## 🔍 替代方案：检查Entry Point

如果TLS回调不被调用，检查Entry Point：

```
1. 设置Entry Point断点:
   bp 0x140001000

2. 运行程序

3. 单步执行，看是否调用TLS初始化
```

---

## 📊 关键地址

```
目标文件: D:\Claude project\TRULY_FINAL.exe
Bootstrap: 0x140EDA000 (RVA 0xEDA000)
Entry Point: 0x140001000 (RVA 0x1000)
TLS Directory: RVA 0xEE6000
TLS Callback Array: RVA 0xEE6030
```

---

## 💡 预期结果

### 如果TLS回调被调用
- 会看到线程数增加到20+
- 3个suspended线程会被恢复
- GUI应该显示

### 如果TLS回调未被调用
- 只有4个线程
- 3个suspended
- 没有GUI
- 需要修改代码使用Entry Point bootstrap

---

## 🛠️ 如果需要Entry Point Bootstrap

修改代码：
1. 不使用TLS callbacks
2. 修改Entry Point为bootstrap代码地址
3. Bootstrap结束后跳转到真实OEP
4. 重新编译测试

---

## 📄 相关文件

- `PROJECT_FINAL_CONCLUSION.md` - 项目最终总结
- `FINAL_STATUS_REPORT.md` - 状态报告
- `BREAKTHROUGH_ROOT_CAUSE.md` - 根因分析

---

生成时间: 2026-07-15 23:30
