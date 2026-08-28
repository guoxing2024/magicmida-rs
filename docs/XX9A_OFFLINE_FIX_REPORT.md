# XX-9-A 离线修复单报告（worker-J）

> **执行**: worker-J（XX-9-A → 复检 → XX-9 实弹 5/8）
> **日期**: 2026-08-28
> **基线**: `b85de30`（XX-8-A 问题 1 + 问题 2 已入库）
> **范围**: 修复 XX-8 暴露的「import 表回退」新归因类 —— 185 解析成果被 1 个坏值连坐回退

## 一、修复内容（两个方向，主次明确）

### 主修：门禁策略（方向 2）—— 收益主体

**问题**：`is_complete()==false → use_original` 是「全有或全无」策略。XX-8 现场：
201 slots = 185 Resolved + 1 Unresolved + 15 ZeroTerminator，因 1 个
`module_not_found`（slot 0 的 `0x1b370fa3810`）整体回退到 9-thunk 原始 stub 表。

**修复**：新增 `crates/pe/src/dumper/iat_partial_accept.rs`（分级接受策略）：

1. **严格门禁不动**：`IatRecoveryReport::is_complete()` 语义零改动，仍是
   perfect-prerequisite gate 的唯一权威。
2. **分级接受**：`evaluate_partial_accept()` 对非严格完整的 report 计算决策：
   - resolved 占比 `resolved/(resolved+rejected)` ≥ 95%（`PARTIAL_ACCEPT_MIN_RESOLVED_FRACTION`）;
   - 且 rejected 绝对数 ≤ 4（`PARTIAL_ACCEPT_MAX_REJECTED`）；
   - 结构缺陷（short-read / unaligned / slot 覆盖缺失 / 重复 index/address/rva /
     observed 别名不一致 / 缺 `slot_rva` / 非 resolved slot 缺 `unresolved_reason`）**永不分级**，仍 fatal；
   - `Stale` slot（落在已加载模块但非当前导出）单独分类，不进 rejected 统计；
   - `Unresolved/ShortRead/InvalidModule` 归 rejected。
3. **决策记录始终写出**：`partial_accepted` 恒为 true（对不完整 report），
   阈值不通过时 manifest 也携带完整决策（fraction_ok / rejected_within_budget /
   rejected_slots / stale_slots / accepted_resolved_slots）。
4. **禁止混搭**：分级表仅来自 report 自身的 `Resolved` slots（两轮投票
   `pass2_vote` 已把 rejected slot 排除，`build_import_section_no_iat` 压缩 run +
   module 终止符，loader 不会引用被跳过的 slot）。**绝不**与原始 stub 表合并。

### 辅修：FoundApi 归属校验（方向 1）—— 堵住污染源

**问题**：v3-trace 的 `FoundApi` 校验过粗（只查 `>0x10000` 且不在 image 内），
`0x1b370fa3810` 这类 VM 反混淆错误值被当作 resolved 写入 IAT。

**修复**：`crates/packers/themida/src/trace_imports/mod.rs` 在 `state.traced_api`
接受路径新增 ToolHelp 模块归属校验（复用 XX-3-A 归因枚举）：

- 新增 `crates/packers/themida/src/iat/discovery.rs::loaded_module_ranges(pid)`，
  枚举目标进程全部已加载模块 `(base, end)` 区间；
- `FoundApi` 的地址必须落在任一已加载模块区间内，否则分类
  `Unresolved(vm_non_module_addr)`，在源头就被拒，不再进入 dump 阶段
  `is_complete` 统计的歧义区。

## 二、单测覆盖（7 个新测试）

`crates/pe/src/dumper/iat_partial_accept.rs`：

- `complete_report_is_never_graded` — 严格完整不分级；
- `xx8_shape_is_graded_and_keeps_all_resolved` — XX-8 现场 185/186 形状分级通过；
- `stale_slots_are_classified_but_not_rejected` — Stale 分类不入 rejected；
- `fraction_thresholds_at_95_percent_boundary` — 95% 边界两侧（含 95/100、96/100、94/95、50/50）；
- `structural_short_read_is_fatal_regardless_of_thresholds` — 结构缺陷永不分级；
- `missing_reason_is_structural_fatal_not_stale` — 缺 reason 是 fatal 不是 stale；
- `rejected_slot_does_not_poison_its_neighbors` — rejected slot 不连坐邻槽。

## 三、验收面可见性

- `DumpProcessReport` 新增 `iat_partial_accepted: bool` + `iat_partial_accept: Option<IatPartialAcceptDecision>`；
- CLI `iat_evidence.json` sidecar 新增 `iat_partial_accepted` + `iat_partial_accept`
  （rejected/stale slot 清单 + 各自观测值 + accepted_resolved_slots 明细）；
- acceptance 侧 `OreansIatEvidence` 同步扩字段（`#[serde(default)]` 向后兼容），
  诊断字段不影响 perfect-prerequisite gate 判定。

## 四、红线确认

- ✅ 测试 2753 绿（2746 基线 + 7 新增），0 失败；
- ✅ clippy 349 不涨（修复过程中一度 +1 `manual_is_multiple_of`，已用
  `is_multiple_of` 消除回 349）；
- ✅ 不触碰 v3-trace 已验证语义：`trace_is_at_api` / `trace_one_slot` /
  `iat_trace_handler` / `decision.rs` 的 FoundApi/HitVm/limit 语义零改动；
  仅 `trace_imports` 的 `FoundApi` 结果接受路径新增归属校验（方向 1，隔离在新代码）。

## 五、提交

```text
fix(pe): XX-9-A graded IAT partial-accept gate + FoundApi module ownership validation
```

未 git commit（待总指挥/复核后决定提交时机）。
