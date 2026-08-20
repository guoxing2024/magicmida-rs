# GTO Product Recovery — Route Y R0 Declared Size-Reinit Semantics Closure

> 状态：**`RouteY_R0_AuditFixAccepted`**（离线修复完成 + 四轮审计全部闭环，审计放行。未提交、未 live、未 spawn、未 candidate）。
> 交付依据：Route Y R0 离线工单（Y0-1 … Y0-5）+ 四轮审计 Findings（第四轮无阻断项）。HEAD = `9450b3a`，branch = `oreans/two-sample-mainline`。

---

## 1. 根因 → 代码映射

Route X R1 现场运行结果：`raw_slab_overlay` 已通过（X0-A/B 修复生效），但在
`sanitize_ahk_runtime_global` 处暴露了 **X R0 P0-2 的 `content.len` 恒等检查回归**：
该 transform 合法地把 child RVA `0x141bf0` 的内容从 ~`0x8000`（32 KiB）重写为
`0x180`（384 B）的零填充重初始化 slab。X R0 的 `validate_raw_identity_across_transform`
对 `content.len()` 一律要求 before==after，未声明任何合法的 size transition，
于是把这条**声明式、归因明确的 size re-init** 误判为漂移而 reject。

- 错误形态：**对合法的声明式 size transition 使用"恒等"而非"归因校验"** → 过严 reject。
- Y R0 目标：只允许**显式声明、归因到具体 transform、old/new size 精确校验、内容零填充**
  的 size re-init；任何**未声明的** size 漂移仍然 fail-closed。

### 涉及文件

- `crates/pe/src/dumper/raw_slab_coherence.rs` —— 唯一 tracked 修改（+1858 / −190）

---

## 2. 实现（Y0-A .. Y0-C + 审计修复）

### Y0-A：声明式 size-reinit 语义（`DeclaredSizeReinit` + 全校验）

- `DeclaredSizeReinit` 结构 + 表查找 `declared_size_reinit(transform_id, child_rva)`：
  - 唯一已声明项：`transform_id = "sanitize_ahk_runtime_global"`，`child_rva = 0x141bf0`，
    `old_size = 0x8000`（`old_size_tolerance = 0x2000` 容许现场 blob 波动），
    `new_size = 0x180`，`zero_filled = true`。
  - 其它 `(transform_id, child_rva)` → `None`（未声明 size 变化即 fail-closed）。
- `validate_declared_size_reinit`（接受 `&HeapGlobalSnapshot`）与字段级核心
  `validate_declared_size_reinit_fields`（接受 rva/capture_id/live_ptr/content）——
  **同一套字段级校验被 recorder 与 Q0-C overlay 两个消费边界共享**，逐项精确校验：
  1. `after_rva == spec.child_rva`；
  2. `before_len` 在 `old_size ± tolerance` 内；
  3. `after_content.len() == new_size`（精确）；
  4. 若 `zero_filled`，内容必须全零。
  任一不符 → `TransformRunLedgerInvalid`（精确 reason，无前缀掩盖）。

### Y0-B：跨 transform 的 identity 校验 + 声明例外

- `validate_raw_identity_across_transform`：capture_id / extent_kind / capture_path 的
  identity 恒等校验**未删未弱化**；仅 `content.len` 增加声明分支（命中声明表则走
  Y0-A 校验，否则 `undeclared raw identity drift` 拒绝）。

### Y0-B2：recorder 与 Q0-C 对 transition run 表示统一（审计第三轮 P1）

`diff_transform_write_runs` 对 **declared size reinit（shrink）无条件生成一个完整
`[0, new_size)` transition run**，不做稀疏 byte diff。原因是：old prefix 内原本就为 `0x00`
的字节（free-list-polluted heap blob 的常态）不属于 byte diff，会把 sanitize 的 diff 拆成
多个 run，而 Q0-C 强制 transition identity **恰好一个完整 run**。生产端（recorder）与
消费端（Q0-C）现在对 transition 表示完全一致：一个专用完整 run。
- recorder：`is_declared_shrink` → 直接 `changed.push((0, new_size))`，`before_bytes =
  immediate_before[0..new_size]`，`after_bytes = transformed[0..new_size]`；
- 保留 old/new size 声明校验（`validate_raw_identity_across_transform` 在 diff 前执行）；
- Q0-C 继续要求 transition identity 恰好一个完整 run（P1-2 唯一性）。

### Y0-C：ledger / binding / membership 一致性 + Q0-C 消费边界 fail-closed（审计 P1-1 / P1-2 / P1-3 闭环）

- `validate_run_membership`：run→raw child 按 `(capture_id, old_base)` 稳定 identity 唯一匹配；
  **declared reinit 目标 child（rva 命中声明表）的 prior runs 用 raw size、transition run 用
  new size 校验**（P1-3）；未声明 child 的 size 漂移仍 fail-closed。
- **`build_patched_backing_slab_q0c`（审计 P1-1 rev 3 修复）**：declared reinit 子对象在**任何
  size / slab-coverage / binding 处理之前**按完整 capture identity
  `(capture_id, old_base, kind, extent_kind, capture_path)` 唯一解析 raw child，要求**恰好一个**，
  只使用该对象的 `raw.size`，**彻底删除 `max(raw.size)` 与 raw-byte/slab-coherence 选择**。
  即使同 base/kind 存在不同 capture 且与 slab 一致，也不会 fall back 到它——identity 不符即
  fail-closed（`RawCaptureDrift`），绝不消费错误 capture 的字节。
- **`build_patched_backing_slab_q0c`（审计 P1-2 rev 3 修复）**：transition run 的唯一性在
  **identity（transform_id + capture_id + old_base）层面**判定——先收集该身份所有 run，要求
  总数**精确为 1**，再校验唯一 run 的 `child_size == new_size` / `offset == 0` /
  `length == new_size` / bytes / digest。**同身份的坏 run 不再被预过滤后忽略**，歧义即
  `TransformRunLedgerInvalid`。
- **`build_patched_backing_slab_q0c`（审计 P1-3 rev 3 修复）**：transition 的 **before evidence
  是 sanitize 执行前的即时状态**，不是原始 raw prefix。从绑定的 authoritative preimage 开始，
  按 ledger execution order **重放该 child 的所有 prior runs**（每条验证 before == 当前状态 +
  digest 一致），再验证 sanitize run 的 before == 重放后状态、after == transformed 新区，
  且每条 child run 都被消费（transition 之后不得有 orphan run）。
- **`build_patched_backing_slab_q0c`（审计 P1-2 修复）**：declared 的 `0x180` 字节**逐字节登记进
  `resolved_writes`**，与普通写入执行相同的重叠冲突 + last-writer 检查（重叠不同值 →
  `TransformWriteConflict`），登记通过后才应用到 patched slab。空/过时 ledger 无法授权任意字节。

### 审计 P2 修复：生产链测试延伸到 runtime plan + manifest

`route_y_r0_sanitize_full_production_chain_q0c_overlay` 现覆盖：
q0c overlay → **patched slab 的 `0x180` 区域必须精确为全零** → overlay 记录 child_size=0x180
且 transformed digest=sha256(0x00×0x180) → **`build_runtime_rebase_plan` + 校验** →
**`write_bound_transform_manifest` 写临时 manifest 并回读**，断言含
`sanitize_ahk_runtime_global` 条目。已不再只检查 overlay applied / patched 非空。

---

## 3. 门禁核验（隔离 CARGO_TARGET_DIR 复跑）

| 门禁 | 结果 |
|---|---|
| `cargo test -p mida-pe` | **637 passed / 0 failed**（+ pure_parse 7、purity 2、doc 3） |
| `cargo test -p mida-cli --features gto-product-recovery` | **298 / 0 / 1 ignored** |
| `cargo test -p mida-cli`（default） | **296 / 0 / 1 ignored** |
| controller（route_u+af1+v0+w0+waf1+x） | **36 passed / 0 failed** |
| `cargo fmt --all -- --check` | 0 差异 |
| `git diff --check` | 干净 |
| warnings | lib 12（低于基线 13）；**test target 无新增 warning**（上一轮 `unused variable: plan` 已消除）；`declared_size_reinit`/`validate_declared`/`child_rva`/`is_declared_reinit` 均 0 命中 |

### 测试矩阵关键项

- **Y0 定向测试：20 个 `route_y_r0_*`**（原 8 + 第一轮审计 6 + 第二轮审计 4 + 第三轮审计 2）全部 ok：
  - 正向：`sanitize_size_reinit_is_declared_and_allowed`、`sanitize_full_production_chain_q0c_overlay`
  - recorder fail-closed：`undeclared_size_drift`、`wrong_transform`、`wrong_old_size`、
    `wrong_new_size`、`reinit_not_zero_filled`、`wrong_capture_identity`
  - **Q0-C 消费边界 fail-closed（第一轮审计）**：`q0c_empty_ledger`、`q0c_old_size_out_of_tolerance`
    （经真实 `build_patched_backing_slab_q0c` 路径）、`q0c_new_size_wrong`、`q0c_new_bytes_nonzero`、
    `q0c_ledger_child_size_wrong`、`q0c_overlap_different_value`（→ `TransformWriteConflict`）
  - **Q0-C 第二轮审计（P1-1/P1-2/P1-3）**：
    - `q0c_same_base_different_capture_identity_resolves_correctly`（identity 解析选对 capture）
    - `q0c_wrong_capture_raw_bytes_must_not_fall_back_to_slab_matching_child`（不 fall back 到错误 capture）
    - `q0c_extra_same_identity_bad_run_fails_closed`（合法 + 同身份坏 run → 拒绝）
    - `q0c_prior_writer_chain_before_declared_reinit_succeeds`（prior writer 合法链 → 成功）
  - **Q0-C 第三轮审计（recorder/Q0-C 表示统一）**：
    - `q0c_sparse_zero_prefix_succeeds`（old prefix 含多个间隔零字节 → recorder 单完整 run，Q0-C 成功）
    - `q0c_prior_writer_sparse_zero_prefix_succeeds`（prior writer 已零化部分 prefix → recorder 单完整 run，Q0-C 成功）
- **X R0 回归（route_x）**：全部 ok，尤其——
  - `route_x_af1_same_base_size_change_fails_closed ... ok`（未声明漂移仍 fail-closed，Y0-2 核心）
  - `route_x_af1_same_base_capture_id/extent/path_change_fails_closed ... ok`
  - `route_x_r0_participant_set_change_fails_closed ... ok`

---

## 4. 提交边界 / 状态

```
 M crates/pe/src/dumper/raw_slab_coherence.rs      ← 唯一 tracked 修改（Y0）
?? docs/GTO_ROUTE_X_R1_LIVE_RESULT.md              ← untracked，明确排除在 Y0 之外，不提交
?? docs/GTO_ROUTE_Y_R0_OFFLINE_RESULT.md           ← 交付凭据（untracked，等审计）
```
- HEAD `9450b3a`，worktree 无其它改动；`docs/GTO_ROUTE_X_R1_LIVE_RESULT.md`（X R1 live 结果，
  CandidateNotReady + X R0 P0-2 回归）**保持 untracked，绝不进入 Y0 提交**；X R1 结果不得被改写为 pass。
- **交付状态：`RouteY_R0_ReviewRequested`** —— 不提交、不 live、不 spawn、不 candidate。
- 工单约束核对：
  - ✅ Y0-1 声明式 size-transition（仅显式声明的 size reinit，未删除 size 检查 / 未弱化 identity / 未恢复 legacy fallback）
  - ✅ Y0-2 未声明漂移 fail-closed（`route_x_af1_same_base_size_change_fails_closed` 保持绿）
  - ✅ Y0-3 ledger/binding/membership 一致；before/after 证据可重放；无 prefix-diff 掩盖长度变化；
        全局校验保留；最后写者/执行顺序语义不变（declared 现进入统一 resolved_writes 冲突/last-writer 记账）
  - ✅ Y0-4 真实生产链覆盖（identity → coverage → raw-children → seed → apply_recorded_transform →
        sanitize → raw_slab_overlay → runtime rebase plan → manifest），且 patched slab 0x180 零区精确断言
  - ✅ Y0-5 未做 ~273s `transform_input_seed` 热点的任何性能优化

---

## 5. 已知风险 / 说明

- `old_size_tolerance = 0x2000`：对 `sanitize_ahk_runtime_global` 的旧大小允许 ±8 KiB 现场波动
  （live heap blob ~32 KiB 的实际捕获 size 可变化）。new size `0x180` 为精确值。此容差仅作用于
  该单一已声明项；其余一律精确/恒等。审计 P1-1 确认该容差现同时被 recorder 与 Q0-C 强制执行。
- 未新增任何 `MIDA_GTO_*` 旁路或语义修复开关；`MIDA_GTO_NO_BYPASS=1` 约束保持不变。
- 未对 `transform_input_seed`（~273s）做任何性能改动（Y0-5）。
