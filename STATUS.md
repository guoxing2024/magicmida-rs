# 方案B实施状态

## 完成情况

### 阶段1: 全局变量快照机制 ✅
- GlobalVarSnapshot结构体
- detect_critical_vars_from_oep() - OEP代码分析
- detect_global_vars() - 运行时捕获
- 模块集成完成

### 阶段2: Bootstrap扩展 ✅
- 修改build_tls_bootstrap_stub接受global_vars参数
- 修改build_container_stub_internal支持全局变量
- 生成全局变量恢复代码（lea/mov指令）
- 编译通过

## 待完成

### 阶段3: 集成到heap_bootstrap (未开始)
需要修改heap_bootstrap.rs调用detect函数并传递global_vars

### 阶段4: 测试 (未开始)
重新脱壳并测试

## 代码变更
- global_vars.rs (新建, 180行)
- container_bootstrap.rs (修改, +60行)
- mod.rs (添加模块声明)
- tls_bootstrap.rs (传递空数组)

## 下一步
1. 修改heap_bootstrap.rs集成检测
2. 测试脱壳
