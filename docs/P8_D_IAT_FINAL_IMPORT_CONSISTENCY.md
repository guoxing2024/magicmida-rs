# P8-D —— IAT final_imports 一致性 + Lunlun 负例

**状态:** 实现完成（P8-D 阶段）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程。

## 语义澄清

P8-C 修复后，IAT final_imports 的语义明确为：

- **final_imports 只由 resolved thunks 重建**。Unresolved / Stale / ShortRead / InvalidModule
  槽位在最终 PE 里作为 loader terminator 写成 0（`write_iat_to_output` 注释明确
  "Zero entries are written as terminators"），独立 parser 在遇到 0 时终止该 run，**不会**把
  unresolved 槽位误当成 final import。
- 因此 `final_imports.len() == resolved_slots.len()`（一一映射），gate 的
  `validate_final_imports` 契约（数量一致 + 逐 slot module/function/ordinal 一致）成立。

## Lunlun 负例确认

Lunlun（防护严重）的 IAT 捕获为 1548 slots：41 Resolved + 1423 Unresolved + 84 ZeroTerminator。
这些 Unresolved 是**防护导致的真实缺点**，不是 emission bug，应保持为**负例**（gate fail-closed），
producer 不得把它们掩盖成 resolved。

修复（P8-C emission terminator）前，`parse_final_import_identities` 失败导致
`compare_live_report_to_candidate` 根本不执行，Unresolved 只由 gate 单独标记。
修复后，parsed_final 成功，`compare_live_report_to_candidate` 执行，producer sidecar 也会把每个
Unresolved slot 标记为 blocker（`live IAT slot {} status Unresolved`）→
`prerequisite_passes=false`。这与 gate 的 fail-closed 一致，Unresolved 在 producer 与 gate 两侧
都被正确暴露。

## 侧车逐字段一致性（已有 + 新增）

`compare_live_report_to_candidate`（producer 侧）已实现 P8-D 要求的跨字段一致性：
- final/resolved slot 数量一致
- 每个 resolved slot → 恰好一个 final import，module/function/ordinal 逐字段一致
- ZeroTerminator slot 在 candidate 里必须为 0（`ensure_candidate_slot_zero`）
- Unresolved/Stale/ShortRead/InvalidModule 一律 push blocker（fail-closed）

## 新增测试

**mida-pe（P8-D，`import_section.rs`）**
- `unresolved_zero_slots_do_not_produce_final_imports`：模拟 unresolved 槽位写 0，
  `parse_final_import_identities` 只产出 resolved import，unresolved 不产生幻影。

**mida-cli（P8-D，`iat_evidence.rs`）**
- `unresolved_live_slots_fail_closed_and_never_count_as_resolved`：Unresolved slot → sidecar
  blocker 含 "Unresolved"，不被计为 resolved，不伪造 import。
- `resolved_live_slot_maps_one_to_one_to_final_import`：Resolved slot → 恰好一个 final import，
  module/function 一致。

## 端到端 synthetic 证明

P8-C 的 `emission_end_to_end_parse_final_imports_reconstructs_target_set` 已证明
builder → emission → parse 完全一致；P8-D 的 `unresolved_zero_slots_do_not_produce_final_imports`
证明 mixed resolved/unresolved 场景下 unresolved 被正确隔离。合起来覆盖 P8-D 要求的
"synthetic Unresolved+Resolved+ZeroTerminator 混合场景"隔离验证。

## 明确 pin

- Behavior Oracle / isolated replay 10/10 / 最终验收仍不属本批修复。
- 真实 Lunlun 样品的最终重跑验证在 P8-QA（有授权时）；本阶段以 synthetic 逻辑 + 现有 gate 负例
  测试确认 Unresolved 语义。
