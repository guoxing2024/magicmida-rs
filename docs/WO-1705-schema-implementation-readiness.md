# WO-1705 — Schema 实现就绪矩阵（v1/v2 split、dispatch、影响面）

**工单编号**: WO-1705（Batch 17）
**优先级**: P1
**性质**: design-only；不得修改 attestation.rs / provenance.rs；不派生产 schema 实现
**日期**: 2026-08-23
**基线**: 07c02db → f05682f
**状态**: 就绪矩阵 — 待总指挥联审

## 0. 目的

把 WO-1503（attestation v2 wire schema 冻结）落为可实施的 Rust 变更清单：
- v1/v2 Rust 类型拆分、serde dispatch、digest preimage 计算路径；
- 现有 deny_unknown_fields 构造器/消费者/fixture 的精确影响面；
- 证据不足、unconfirmed orphan、rollback 语义在实现层的对应检查项；
- 只列实现前检查，不派生产 schema 实现。

## 1. v1/v2 Rust 类型拆分（实现前检查）

### 1.1 目标结构（WO-1503 §2/§3 冻结）

| 类型 | 归属 | deny_unknown_fields | 说明 |
|------|------|--------------------|------|
| RuntimeAttestation（v1） | 保持不动 | 是（既有） | schema = "mida.antidebug-runtime-attestation/v1"；**零字段变更** |
| RuntimeAttestationV2 | 新结构 | 是 | schema = ".../v2"；schema_version: u16 == 2；新增 walker_attestation: Option<WalkerAttestation>、record_digest: String |
| WalkerAttestation | 新结构 | 是 | schema_version==2；target_pid/runtime_module_sha256/walker_export_rva/walker_entry_va/rounds/probe_summary/orphaned_resources/canonical_encoding/record_digest |
| RoundLedger | 新结构 | 是 | round_index ∈ {1,2}；wall_spent_ms <= wall_budget_ms；auto_retry 恒 false；abort_state 封闭集合 |
| ProbeSummary | 新结构 | 是 | type_a+type_b+type_c == candidates_total；av/guard <= total |
| Orphan | 新结构 | 是 | state ∈ {created,timed_out,target_exit_observed,os_reclaimed,completed,unconfirmed}；kind/VA/section 一致性；unconfirmed 不得有 reclaim_note |

### 1.2 枚举校验（实现前检查）

- 封闭集合用 Rust enum + serde(rename_all = "snake_case") + #[serde(deny_unknown_fields)]
  或自写 Deserialize 校验；任一未知值 → 拒收（不默认、不忽略）。
- RoundLedger.round_index 用 u8 + 自校验（1/2），不直接映射 enum（u8 数值语义）。
- Orphan.state 的"completed"含 normal-completion 与 os_reclaimed 两个来源；
  实现须在构造层区分来源（WO-1604 统一命名后的语义保持）。

## 2. serde dispatch（实现前检查）

### 2.1 顶层判别

~~~rust
// 目标（WO-1503 §1.2 伪代码的 Rust 落点）
pub enum TaggedAttestation {
    V1(RuntimeAttestation),
    V2(RuntimeAttestationV2),
}

pub fn parse_attestation(json: &str) -> Result<TaggedAttestation, AttestationError> {
    // 1) serde_json::Value 粗解析取 schema 字段；
    // 2) schema == v1 → RuntimeAttestation::from_canonical_json（既有路径）；
    // 3) schema == v2 → 校验 schema_version == 2（否则 SchemaVersionMismatch），
    //    RuntimeAttestationV2 严格反序列化（deny_unknown_fields）；
    // 4) 其它 → SchemaUnsupported。
}
~~~

- 现有调用点（实现前需同步）：runtime_loader.rs:1236（from_canonical_json + PID/
  module_base/profile_digest 复核）与 antidebug_controller.rs:593。二者必须走
  parse_attestation 分派；v1 行为与现在完全一致。
- v1 consumer 遇 v2 → SchemaUnsupported 显式报错（不部分消费）。

### 2.2 digest preimage（实现前检查）

- json-c14n 独立 serializer（WO-1503 §4）：字节序键、非 ASCII 原样 UTF-8、
  整数/有限 double、bool 字面量、null；与 serde_json::to_string 不混用。
- preimage 排除规则（WO-1503 §5.1a）：只排除"正在计算 digest 的对象"的
  record_digest 字段；嵌套 WalkerAttestation 的 record_digest 是顶层 preimage 的普通字段。
- 验证顺序固定：先 WalkerAttestation.record_digest，再顶层 record_digest。
- 4 个固定 vectors（WO-1503 §5.3）作为 fixture 逐一通过，禁止实现时重定。

## 3. 现有 deny_unknown_fields 构造器/消费者/fixture 影响面（实测登记）

### 3.1 构造器

| 位置 | 类型 | 影响 |
|------|------|------|
| exports.rs:133 build_attestation_json | v1 构造 | 不动；v2 由 walker 路径新增构造入口 |
| exports.rs:148 build_attestation_from_outcomes | v1 构造 | 不动 |
| attestation.rs:139 foundation / :182 from_surfaces | v1 构造 | 不动 |

### 3.2 消费者

| 位置 | 类型 | 影响 |
|------|------|------|
| runtime_loader.rs:1236 from_canonical_json + PID/module_base/profile_digest 复核 | v1 消费者 | 改走 parse_attestation 分派；v1 行为不变 |
| antidebug_controller.rs:593 from_canonical_json | v1 消费者 | 同上 |
| cli/tests/runtime_loader.rs:347/429（attestation_json fixture） | v1 fixture | **一个字节不改**（WO-1503 §8） |
| cli/tests/runtime_loader.rs:416（"{ not json" 反例） | 负例 | 保持 |

### 3.3 fixture 不变性

- attestation.rs 测试（40 项）中全部 v1 JSON fixture 不变；
- 新增 v2 fixture 与 v1 并列（新文件 tests/walker_attestation_v2.rs 或同文件追加）；
- 任何 v1 fixture 变更 = schema 破坏，需总指挥书面批准。

## 4. 证据不足 / unconfirmed orphan / rollback 语义（实现层对应）

| 场景（WO-1503 §6.3/§7） | 实现层检查 |
|-------------------------|-----------|
| walker_attestation = null | V2 结构 Option::None 合法；acceptance 按原 v1 路径消费 |
| v1 consumer 遇 v2 | parse_attestation 返回 SchemaUnsupported，显式报错 |
| record_digest 不符 | 先验嵌套再验顶层；任一失败 → DigestMismatch，拒收全部 walker 字段 |
| timeout → orphan unconfirmed | RoundLedger.orphaned_resources 含 state=unconfirmed 记录；不得声称已回收；fail-closed |
| target_exit_observed → os_reclaimed | 仅当有观察证据（WO-1504）才写 os_reclaimed；否则保持 unconfirmed |
| rollback（runtime/profile digest 不符） | acceptance 拒收整体 attestation，EvidenceInsufficient，不消费任何 walker 字段 |
| round 账本矛盾（abort_state=thread_hung 但 candidates_probed>0 且无 orphan） | 该 round 证据作废 → 整体 EvidenceInsufficient |

## 5. 实现前 checklist（不派发实现）

- [ ] json-c14n 独立 serializer + 4 vectors fixture 通过
- [ ] RuntimeAttestationV2 / WalkerAttestation / RoundLedger / ProbeSummary / Orphan 结构 + 封闭集合校验
- [ ] TaggedAttestation 判别 + parse_attestation 分派；两个现有消费点切换
- [ ] 嵌套/顶层 digest 双层验证（顺序固定）
- [ ] v1 fixture 零变更回归（40 项 attestation 测试 + cli runtime_loader fixture）
- [ ] runtime_sha256 真实 digest 流（WO-1703 v2 通道）接入后 attestation 构造
- [ ] 证据不足/rollback 的 acceptance 测试（§4 每行）

## 6. 状态

| 对象 | 状态 |
|------|------|
| WO-1705 就绪矩阵 | design-only；待联审 |
| attestation.rs / provenance.rs | 未修改 |
| schema 实现 | 未派发（须先过本矩阵 + WO-1701/1702/1703 复审） |

