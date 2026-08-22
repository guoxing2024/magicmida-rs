# AUDIT_SCHEMA_READINESS — Batch 17 readiness matrix 交叉审计（WO-1805）

**工单编号**: WO-1805（Batch 18）
**日期**: 2026-08-23
**审计性质**: 只读源码对照审计；不改 attestation.rs / provenance.rs / runtime_loader.rs / antidebug_controller.rs。
**基线**: e71445d → de12e4c（本审计对照 HEAD = de12e4c 的源码）

## 1. 目的

对照真实代码逐项核实 WO-1705（schema implementation readiness matrix）中的：
- 消费者/构造器行号与影响面；
- v1 fixture 不变性声明；
- 区分设计假设与真实事实；
- 明确 readiness matrix 不是实现证据。

## 2. 构造器锚点核对（attestation.rs / exports.rs）

| WO-1705 声明 | 真实代码（HEAD de12e4c） | 核实 |
|--------------|--------------------------|------|
| exports.rs:133 build_attestation_json | exports.rs L123-145：build_attestation_json(runtime_sha256, ...) 调 RuntimeAttestation::foundation | ✅ 行号一致 |
| exports.rs:148 build_attestation_from_outcomes | exports.rs L148-172：build_attestation_from_outcomes(...) 调 from_surfaces | ✅ 行号一致 |
| attestation.rs:139 foundation | attestation.rs L139-171：foundation(...) 构造 v1 结构（schema = ATTESTATION_SCHEMA） | ✅ 行号一致 |
| attestation.rs:182 from_surfaces | attestation.rs L182-223：from_surfaces(...) 构造 v1 结构 | ✅ 行号一致 |
| RuntimeAttestation v1 结构 deny_unknown_fields | attestation.rs L104-106：#[serde(deny_unknown_fields)] pub struct RuntimeAttestation | ✅ |

结论：WO-1705 §3.1 构造器表全部行号准确；v1 构造器零改动声明成立（本批未触碰）。

## 3. 消费者锚点核对（runtime_loader.rs / antidebug_controller.rs）

| WO-1705 声明 | 真实代码 | 核实 |
|--------------|----------|------|
| runtime_loader.rs:1236 from_canonical_json + PID/module_base/profile_digest 复核 | L1236-1237：RuntimeAttestation::from_canonical_json(&att)；L1238-1242 target_pid 复核；L1244-1248 module_base 复核；L1250-1255 profile_digest 复核 | ✅ 行号一致；PID/module_base/profile_digest 三项复核确认存在 |
| antidebug_controller.rs:593 from_canonical_json | L593-595：RuntimeAttestation::from_canonical_json(&loader.attestation_json)；失败 → RuntimeInitFailed + Failed | ✅ 行号一致 |
| 两个消费点需走 parse_attestation 分派 | 两处均为直接 from_canonical_json（v1 结构）；实现时须切换 | ✅ 属实（设计变更点） |

## 4. v1 fixture 不变性核对（cli/tests/runtime_loader.rs）

| WO-1705 声明 | 真实代码 | 核实 |
|--------------|----------|------|
| runtime_loader.rs:347/429 v1 fixture | L347-368：fake_loader_result() 的 attestation_json（完整 v1 对象，schema = ".../v1"）；L428-440+：incomplete attestation 负例（v1 schema，hooks_installed 缺 AD-PROC-003） | ✅ 行号一致；两 fixture 均为 v1 schema，一个字节未改 |
| runtime_loader.rs:416 "{ not json" 负例 | L416-422：controller_fails_closed_on_bad_attestation（attestation_json = "{ not json" → Failed） | ✅ 行号一致 |
| attestation.rs 测试 40 项 v1 fixture 不变 | tests/attestation.rs（40 passed）全部为 v1 结构序列化/反序列化测试；本批未触碰 | ✅（cargo test de12e4c 40 passed 证实） |

结论：WO-1705 §3.2/§3.3 fixture 不变性声明全部与真实代码一致。

## 5. 设计假设 vs 真实事实（WO-1805 标注）

| 条目 | 类别 | 说明 |
|------|------|------|
| v2 结构（RuntimeAttestationV2/WalkerAttestation/RoundLedger/ProbeSummary/Orphan） | **设计假设** | 不存在于仓库；WO-1503 §2/§3 冻结待实现 |
| TaggedAttestation 判别 + parse_attestation 分派 | **设计假设** | 不存在；两消费点仍直接 v1 解析 |
| json-c14n serializer | **设计假设** | 不存在；v1 用 serde_json::to_string（字段序） |
| 4 个 digest vectors | **真实事实** | WO-1503 §5.3 固定值；总指挥已独立复算一致（AUDIT_BATCH16 §5.1 / AUDIT_BATCH17 §7） |
| runtime_sha256 占位 adr4-foundation-unbound | **真实事实** | exports.rs L237-239 仍为占位；未实现真实 digest 流 |
| v1 deny_unknown_fields 拒绝未知字段 | **真实事实** | attestation.rs L104-106 等；40 项测试含未知字段拒收用例（L217-223） |
| v1 consumer 遇 v2 的行为（SchemaUnsupported） | **设计假设** | 当前 v1 解析器对未知 schema 字符串返回 SchemaMismatch（validate 阶段）；v2 判别路径未实现 |
| walker 相关字段/round 账本 | **设计假设** | 仓库无 walker 代码 |

## 6. readiness matrix 不是实现证据

- WO-1705 矩阵仅登记"实现前检查项"；本审计仅核实其与真实代码的锚点一致性。
- 已实现：v1 结构与解析、deny_unknown_fields、40+ 测试、fixture。
- 未实现：v2 结构、分派、json-c14n、digest 流、walker 容器。
- 因此 readiness matrix 通过 ≠ schema 实现通过；schema 实现仍待独立实现工单 + 总指挥联审。

## 7. 结论

WO-1705 矩阵的行号锚点、影响面、fixture 不变性声明经真实代码对照全部核实一致；
设计假设与真实事实已逐项标注。本审计不改变任何生产代码，不构成 schema 实现证据。

