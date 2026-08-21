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
- clippy: 820 warnings（WO-C 口径 15 个已过时；实测 `cargo clippy --workspace --all-targets` 为 820 个，见 §四 附记）

### ADR7
- tools/verify_adr7_closeout.ps1: **17/17 PASS, 0 warnings**（frozen, untouched）

## 三、结论
- 测试基线更新为: **"2248 passed / 0 failed / 1 ignored / 1 doctest failed（b5_tls_capture.rs:17，既有缺陷）"**（vcvars64 MSVC + cargo test --workspace --offline，复核日期 2026-08-21）；WO-103 doctest 修复后 **2257 passed / 0 failed / 2 ignored / 0 doctest fail**
- 账本 §7 已同步（1271 为 WO-C 子集口径，全量复核为 2248）
- b5_tls_capture doctest 缺陷: 既有（ADR7 遗留），非本任务引入；修复属可选（WO-005 范围外）

## 四、附记：WO-103 工作区卫生结果（2026-08-21 执行）

### 1. doctest 修复
- `crates/core/src/b5_tls_capture.rs` L17-18：markdown 缩进代码块改为 ```text 围栏（仅文档，零函数行为改动）
- 结果：`cargo test -p mida-core --doc` 0 failed；全量测试 **2257 passed / 0 failed / 2 ignored / 0 doctest fail**

### 2. clippy 实际规模（与 WO-C 记录不符）
- WO-C 记录"15 warnings（global_vars.rs:17、tls_bootstrap.rs:54-55）"——**已过时**：
  - 这两个位置当前 clippy 下**无任何警告**（此前已加 `#[allow(dead_code)]`）
  - 实测 `cargo clippy --workspace --all-targets` = **820 warnings**（修复前）
- 分布：mida-pe 501（dumper/* 400+，H5 核心）、mida-cli 165、mida-packers-themida 108、mida-core 42 等；~95% 在生产 src

### 3. 已修复（WO-103 授权范围）
- `cargo clippy --workspace --fix`（lib + all-targets）：**~144 处**机械安全修复（52 文件，161+/207-）
- 类型：needless_borrow、collapsible_if、manual_range_contains、manual_is_multiple_of、unnecessary_cast、useless_format、question_mark、unnecessary_mut_passed 等——全部语义等价
- 复验：全量测试 **2257 passed / 0 failed**；CI 双 lane（`cargo check --workspace --tests` 与 `--all-features --tests`，RUSTFLAGS=-D warnings）**0 error 0 warning**

### 4. 剩余 676 个警告（未清零，原因如下）
- **行为敏感类**（需人工重构决策，且多在 H5 未授权区）：result_large_err 79、cloned_ref_to_slice_refs 52、too_many_arguments 90+、manual_saturating_arithmetic 15、manual_c_str_literals 14 等
- **纯格式类**（量大且跨 H5 核心文件）：unusual_byte_groupings（hex 分组）133、doc 格式 ~30
- 处置：不触碰（工单红线：不改函数行为；H5 未授权；且远超"15 个"前提），待总指挥指示

### 5. 残留目录
- `crates/cli/gto_launcher/cccc…c/（snapshot.bin）`：已删除

### 6. 结论
- WO-103 的 doctest、残留目录、CI 双 lane 复验：**完成**
- clippy 清零：**部分完成**（144/820 机械修复；676 剩余需指示——前提"15 个"与现实 820 个不符）
