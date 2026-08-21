# GTO 工作区验证记录 — 2026-08-21（WO-004）

**依据**: WO-C（总指挥验证工作单）+ 本次独立复核  
**状态**: COMPLETE

## 一、测试计数差异解释

| 口径 | 计数 | 说明 |
|---|---|---|
| 边界账本 §7 原基线 | 1885 passed / 0 failed / 2 ignored | **stale** — 旧文档值，与当前树不符 |
| WO-C 报告 | 1271 passed / 0 failed / 2 ignored | **子集统计**（可能为 lib 测试子集，未含全部 integration + doctest） |
| 接手审计复核（vcvars64 MSVC + cargo test --workspace --offline, 2026-08-21） | **2248 passed / 0 failed / 1 ignored / 1 doctest failed（b5_tls_capture.rs:17，既有缺陷）** | 全 workspace 完整运行（总指挥签发口径） |

**差异根源**:
1. **1885→1271**: 账本 §7 陈旧（H4 迭代中测试数变化后未更新）；1271 可能是特定 crate 子集
2. **1271→2256**: 全 workspace 含 mida-acceptance/mida-cli 等所有 crate 的 lib + integration + doctest
3. **唯一失败**: mida-core doctest `b5_tls_capture.rs` line 17 markdown 含 `TEB + 0x58 -> ...` 被当 Rust 代码 — **既有 doctest 缺陷**（ADR7 时代遗留），非 H4/H5 引入

## 二、独立复核数据（2026-08-21）

### 测试
- `cargo test --workspace --offline`（VsDevCmd MSVC 环境，复核日期 2026-08-21）:
  - **2248 passed / 0 failed / 1 ignored / 1 doctest failed（b5_tls_capture.rs:17）**
  - 失败详情: `crates/core/src/b5_tls_capture.rs` line 17-18 doctest: `TEB + 0x58` 无法编译（markdown 箭头注释被解析为代码）
- 关键 crate: mida-pe 985/985；mida-cli 322/322（1 ignored）

### 编译/格式
- cargo build --workspace: PASS（零 warning，P6 门达成）
- cargo fmt --all -- --check: PASS
- git diff --check: PASS
- clippy: 15 warnings（待 WO-005）

### ADR7
- tools/verify_adr7_closeout.ps1: **17/17 PASS, 0 warnings**（frozen, untouched）

## 三、结论
- 测试基线更新为: **"2248 passed / 0 failed / 1 ignored / 1 doctest failed（b5_tls_capture.rs:17，既有缺陷）"**（vcvars64 MSVC + cargo test --workspace --offline，复核日期 2026-08-21）
- 账本 §7 已同步（1271 为 WO-C 子集口径，全量复核为 2248）
- b5_tls_capture doctest 缺陷: 既有（ADR7 遗留），非本任务引入；修复属可选（WO-005 范围外）
