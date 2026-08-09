# GTO Product Recovery — Route R R0 Offline Result

**日期：** 2026-08-09
**Route Q 冻结：** `RouteQ_R0_NotReady`
**起点 HEAD：** `7a3671b6c88b9a3265a037fe1b7ab14aa423d218`
**分支：** `oreans/two-sample-mainline`
**工单：** `docs/GTO_ROUTE_R_R0_OFFLINE_WORK_ORDER.md`
**状态：** `RouteR_R0_AuditFix1ReviewRequested`（待审计负责人复审）

> ⚠️ 复审通过前，**不得**报告 `RouteR_R0_Ready` / `RouteR_R1_Ready` / `OfflineRepairReady` / `CandidateReady`。**未 commit**。live = 0，spawn = 0，candidate = 0，cold-start = 0。

---

## 1. Route R R0 实现项与本轮 Audit Fix 1 修复映射

### R0-A — 统一处理全部 captured interior pointers + external fail-closed
- `repair_label_names_after_scrub` 现返回 `Result<(), LabelNameRepairError>`。
- captured alias（label-self interior / other-parent interior / exact base）→ 保留 alias，不创建 snapshot。
- genuinely external `name_ptr`（无 inline fallback）→ `Err(LabelNameRepairError::ExternalNameUnassigned)`，**不复用旧 VA、不创建 synthetic snapshot**。
- `dump_process` 将该错误转为 `PeError::GtoStage { stage: "repair_label_names_after_scrub" }`，在 overlay/manifest/candidate 之前终止。
- 测试：`route_r_r0a_external_name_fails_before_overlay`、`route_r_r0a_other_parent_alias_runtime_fixup`。

### R0-B — 执行型 transform recorder
- 新增 `apply_recorded_transform`（infallible）与 `try_apply_recorded_transform`（fallible）。
- helper 内部完成 before capture → transform 执行 → child-level recording → byte-run recording，生产与 full-pipeline 测试调用同一实现。
- 测试：`route_r_r0b_apply_recorded_transform_records_both_ledgers`、`route_r_r0b_wrong_or_missing_recording_not_constructible`。

### R0-C — 全局 run-ledger shape 验证
- 在任何 byte replay 前，遍历 `run_ledger.runs` 统一验证所有字段；malformed 无关 run 也 fail-closed。
- 测试：`route_r_r0c_valid_plus_zero_length_extra_fails`、`valid_plus_empty_id_extra_fails`、`valid_plus_short_vector_extra_fails`、`offset_length_overflow_fails`。

### R0-D — runtime fixup 真值 + metadata 编码
- `plan.pointers` 断言：inline（mName@+0x28 → label_live+0x30）与 other-parent（→ parent+0x40）的 source/target/classification。
- `encode_plan_metadata` → `BootFixup` 检查：source region/offset、original_value、classification(InCapturedRegion=2)、target region/offset。
- 测试：`route_r_r0d_inline_fixup_survives_metadata_encoding`、`route_r_r0d_other_parent_fixup_survives_metadata_encoding`。

### R0-E — 真实 Container 端到端（保持不退化）
`route_q_af1c_container_end_to_end` 继续通过。

### 文档隔离
- 恢复 `GTO_ROUTE_Q_R0_OFFLINE_RESULT.md` 为 Route Q 历史。
- 新建 `GTO_ROUTE_Q_R0_FINAL_AUDIT.md`（Q 冻结判定）。
- 新建 `GTO_ROUTE_R_R0_OFFLINE_WORK_ORDER.md` / `GTO_ROUTE_R_R0_OFFLINE_RESULT.md`。
- Route R 新增测试以 `route_r_r0*` 命名。

## 2. 测试门禁

| 门禁 | 实测 |
|---|---|
| `cargo fmt --all -- --check` | 0 diff ✓ |
| R0-G / R0-F.1 / R0-F.2 | 27/9/25 ✓ |
| Route R/Q | 通过 ✓ |
| mida-pe | **540/0** ✓ |
| mida-cli gto | 296/0/1 ✓ |
| git diff --check | exit 0 ✓ |
| 3 blocked 警告 | 消失 ✓ |

Route R 新增测试（`route_r_r0*`）：R0-A 2、R0-B 2、R0-C 4、R0-D 2 = 10 个。

## 3. 当前仓库状态
- HEAD：`7a3671b`（未变）
- 工作树含未提交修改（Route Q 底稿 + Route R R0 实现 + Audit Fix 1）。
- 未 commit、未 live、未 spawn、未 candidate、未 cold-start。

## 4. 诚实披露 / 剩余风险
1. 未 commit，待复审。
2. 生产 fail-closed 链由 540/0 单测覆盖，但未经真实 GTO 样本 live 验证。
3. genuinely external label name 目前 fail-closed（不生成 candidate）；真正接入 synthetic allocator 留作独立能力工单。

## 5. 终态
`RouteR_R0_AuditFix1ReviewRequested`。**不是** RouteR_R0_Ready / RouteR_R1_Ready / OfflineRepairReady / CandidateReady。由审计负责人复审通过后，才可 commit 并转入下一判定。
