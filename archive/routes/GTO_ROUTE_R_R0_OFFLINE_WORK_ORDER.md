# GTO Product Recovery — Route R R0 Offline Work Order

**签发日期：** 2026-08-09
**授权：** OFFLINE ONLY
**起点 HEAD：** `7a3671b6c88b9a3265a037fe1b7ab14aa423d218`
**前序终态：** `RouteQ_R0_NotReady`（Route Q 永久冻结）
**目标：** Alias-Safe Transform Provenance Closure

## 授权范围

- 仅离线代码修复 + synthetic/unit tests + 证据整理。
- 无 protected spawn、无 live capture、无 candidate、无 cold-start。
- Route Q 不得重开。

## 强制实现项

### R0-A — 统一处理全部 captured interior pointers
对 `mName`：
1. 指向 label 自身内部：保留 interior pointer（不创建 snapshot）；
2. 指向任意其他 captured parent 内部：保留 parent alias（不创建 snapshot）；
3. 指向 exact captured base：保留 exact pointer；
4. 真正 external 且需复制：本工单**不扩展 allocator**，改为 **fail-closed**（结构化错误 `LabelNameRepairError::ExternalNameUnassigned`），`dump_process` 在 overlay 前终止。
5. 无法归属且无法安全 synthetic：fail-closed，不复用旧 external VA。
禁止在任何 captured range 内创建 SyntheticDerived snapshot。

### R0-B — 原子化 transform recording
新增执行型 helper（`apply_recorded_transform` / `try_apply_recorded_transform`），由 helper 内部完成 before capture、transform 执行、child-level recording、byte-level recording。生产与测试调用同一实现。

### R0-C — 严格验证 run shape（全局）
遍历整个 ledger 统一验证：capture_id 非空 / transform_id 非空 / length>0 / checked_add / end<=child_size / before/after 长度一致 / first bytes 一致 / digests 一致。任何失败返回 `TransformPreimageDrift`，不 panic。malformed 无关 run 也必须 fail-closed。

### R0-D — runtime fixup 真值测试
验证 `plan.pointers` 与 `encode_plan_metadata` 产出的 `BootFixup`：source region/offset、original_value、classification、target region/offset。覆盖 inline（label+0x30）与 other-parent（parent+0x40）两个场景。

### R0-E — 真实 Container 端到端（已在前轮完成，保持不退化）

## 文档要求

- 恢复 `GTO_ROUTE_Q_R0_OFFLINE_RESULT.md` 为 Route Q 历史。
- 新建 `GTO_ROUTE_Q_R0_FINAL_AUDIT.md`（Route Q 冻结判定）。
- 新建 `GTO_ROUTE_R_R0_OFFLINE_WORK_ORDER.md` / `GTO_ROUTE_R_R0_OFFLINE_RESULT.md`。
- Route R 新增测试以 `route_r_r0*` 命名，可与 `route_q_*` 独立 filter。

## 禁止

- commit before re-review；live；candidate；protected spawn；cold-start；Route Q 重开。

## 终态

完成后仅报 `RouteR_R0_AuditFix1ReviewRequested`（复审通过后另定）。
