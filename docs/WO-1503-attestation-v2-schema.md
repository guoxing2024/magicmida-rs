# WO-1503 — Attestation/Provenance v2 wire schema 设计冻结

**工单编号**: WO-1503
**优先级**: P0
**性质**: design-only 冻结文档（纯离线；不改 attestation.rs / provenance.rs）
**日期**: 2026-08-22
**基线**: 786630b（WO-1401-R1 条件接收）
**状态**: 冻结候选 — 待总指挥联审

## 0. 目的与范围

本文件冻结 Walker 阶段所需的 Attestation/Provenance v2 wire schema。它回答 P0-B 审计要求：

1. 完整的 RuntimeAttestationV2 顶层类型与 tagged dispatch 规则；
2. WalkerAttestation / RoundLedger / ProbeSummary / Orphan 的字段、类型、上限、缺省/拒收规则；
3. canonical JSON 算法（json-c14n）与 record_digest 的 preimage 排除规则（无自引用）；
4. 至少 3 个固定 digest vectors；
5. v1 consumer 对 v2 的显式拒收/升级行为，旧 v1 fixture 不变；
6. provenance artifact digest、target PID/image digest/module base/walker RVA/entry VA 的唯一绑定；
7. rollback 与证据不足（timeout/unconfirmed orphan）语义。

**冻结边界**：本文件是 schema 合同。实现（Rust 结构体、serde 派生、反序列化分派）在 Walker
实现工单中执行；本文件不声称已实现。

## 1. 版本分派规则（tagged dispatch）

### 1.1 顶层判别字段

RuntimeAttestationV2 的顶层对象使用显式版本判别：

~~~json
{
  "schema": "mida.antidebug-runtime-attestation/v2",
  "schema_version": 2,
  ...
}
~~~

- schema 固定为 v2 字符串；schema_version 为 u16 数值且 == 2；两者必须一致，不一致即拒收。
- **v1 保持原样**：v1 对象 schema 为 "mida.antidebug-runtime-attestation/v1" 且**没有**
  schema_version 字段（v1 结构体不变，deny_unknown_fields 继续生效）。
- **v1 consumer 遇到 v2 对象**：显式拒收（返回 SchemaUnsupported），绝不静默忽略未知字段；
  这是升级护栏——旧 consumer 看到 v2 必须报错而不是部分消费。
- **v2 consumer 遇到 v1 对象**：按 v1 路径解析并验证（向后兼容读），但 v1 不含 walker 证据，
  walker_attestation 为 None；acceptance 按证据不足处理。

### 1.2 分派算法（伪代码，实现时落为 Rust 枚举 + 分派函数）

~~~text
fn parse_attestation(json) -> Result<TaggedAttestation, Error>
  obj = json_parse(json)
  schema = obj.schema
  match schema:
    "mida.antidebug-runtime-attestation/v1":
        v = parse_v1(obj)   // 原 RuntimeAttestation，deny_unknown_fields
        return TaggedAttestation::V1(v)
    "mida.antidebug-runtime-attestation/v2":
        ver = obj.schema_version
        if ver != 2: return Err(SchemaVersionMismatch)
        v = parse_v2(obj)   // RuntimeAttestationV2，deny_unknown_fields
        return TaggedAttestation::V2(v)
    default:
        return Err(SchemaUnsupported)
~~~

### 1.3 拒收规则（v2 对象）

| 条件 | 行为 |
|------|------|
| schema 与 schema_version 不一致 | 拒收 SchemaVersionMismatch |
| 未知顶层字段 | 拒收（deny_unknown_fields） |
| walker_attestation 为 null | 合法（非 walker 运行），但 round 证据为空 → 证据不足 |
| walker_attestation 存在但 schema_version < 2 | 拒收（v1 不允许携带 walker 容器） |
| record_digest 与重算不符 | 拒收 DigestMismatch |

## 2. RuntimeAttestationV2 顶层类型

~~~text
RuntimeAttestationV2 {
  schema: string = "mida.antidebug-runtime-attestation/v2",
  schema_version: u16 = 2,
  runtime_id: string,            // "mida-antidebug-runtime-x64"
  runtime_version: string,      // CARGO_PKG_VERSION
  architecture: string,         // "x86_64"
  runtime_sha256: string,       // hex lowercase, 64 chars（artifact digest, 见 §6）
  profile_id: string,
  profile_digest: string,
  target_pid: u32,
  module_base: u64,             // 加载基址
  initialized: bool,
  hooks_expected: string[],
  hooks_installed: string[],
  hook_failures: HookFailure[],
  surface_details: SurfaceDetail[],
  telemetry_channel: string,
  cleanup_handler_registered: bool,
  third_party: string,
  source_revision: string,
  toolchain: string,
  walker_attestation: WalkerAttestation | null,  // 仅 v2；null 允许
  record_digest: string,        // 见 §5；排除 record_digest 自身
}
~~~

**与 v1 的差异**：新增 schema_version、walker_attestation、record_digest 三个字段；
其余字段语义与 v1 相同（deny_unknown_fields 封闭）。

## 3. WalkerAttestation / RoundLedger / ProbeSummary / Orphan

### 3.1 WalkerAttestation

~~~text
WalkerAttestation {
  schema_version: u16 = 2,
  target_pid: u32,                // 与顶层 target_pid 必须一致
  target_image_sha256: string,    // 样本身份（vault rev2 digest）
  runtime_module_sha256: string,  // 与顶层 runtime_sha256 必须一致
  walker_export_rva: u64,         // resolve_mida_exports_remote 解析的 WalkerExecute RVA
  walker_entry_va: u64,           // module_base + rva（allowlist 断言值）
  rounds: RoundLedger[],          // 每 round 一份
  probe_summary: ProbeSummary,
  orphaned_resources: Orphan[],
  canonical_encoding: string = "json-c14n",
  record_digest: string,         // 见 §5；排除 record_digest 自身
}
~~~

**绑定关系（唯一）**：target_image_sha256 绑定 vault rev2 样本身份；
runtime_module_sha256 绑定 controller 实际加载的 runtime artifact；
walker_entry_va 必须 == module_base + walker_export_rva（allowlist 断言）。
四者缺一即拒收，且跨字段不一致（如 target_pid 与顶层不符）即拒收。

### 3.2 RoundLedger

~~~text
RoundLedger {
  round_index: u8,               // 1 或 2（封闭集合）
  entry_ts: string,             // RFC3339 UTC
  exit_ts: string,
  wall_budget_ms: u64,          // 60*60*1000
  wall_spent_ms: u64,           // <= wall_budget_ms
  candidates_probed: u32,       // <= 4096
  abort_state: string,          // none | thread_hung | wait_fail | walker_abort |
                                 // budget_exhausted | stop_loss（封闭集合）
  orphaned_resources: Orphan[], // 本 round 产生的悬挂资源
  auto_retry: bool,             // 恒 false
  next_round_authorized: bool,  // round 1 出口是否显式批准 round 2
}
~~~

**缺省/拒收**：round_index 非 1/2 → 拒收；wall_spent_ms > wall_budget_ms → 拒收；
auto_retry != false → 拒收（治理硬规则）；abort_state 非封闭集合 → 拒收。

### 3.3 ProbeSummary

~~~text
ProbeSummary {
  candidates_total: u32,
  type_a_count: u32,
  type_b_count: u32,
  type_c_count: u32,
  av_count: u32,
  guard_count: u32,
  retry_count: u32,
  total_latency_us: u64,
}
~~~

**一致性规则**：type_a + type_b + type_c == candidates_total；
av_count <= candidates_total；guard_count <= candidates_total；不符 → 拒收。

### 3.4 Orphan

~~~text
Orphan {
  kind: string,                  // params_blob | result_section（封闭集合）
  target_pid: u32,
  blob_base_va: u64 | null,     // params blob 时非 null
  section_name: string | null,  // result section 时非 null
  created_ts: string,
  timeout_ts: string | null,
  state: string,                // created | timed_out | target_exit_observed |
                                 // os_reclaimed | completed | unconfirmed（封闭集合）
  reclaim_note: string | null,  // os_reclaimed 时记录观察方式
}
~~~

**缺省/拒收**：state 非封闭集合 → 拒收；kind 与 VA/section 字段不一致 → 拒收；
unconfirmed 状态下不得写 reclaim_note（无证据不可声称回收）。

## 4. Canonical JSON 算法（json-c14n）

record_digest 使用确定性的 canonical JSON 编码（json-c14n）计算。算法：

~~~text
canonicalize(obj) -> bytes:
  1. 对象键按 UTF-8 字节序排序（非字典序，是字节序）。
  2. 字符串：UTF-8 编码，逐字节转义为 JSON 字符串字面量
     （双引号转义、反斜杠转义、控制字符 \u00XX；斜杠不转义；非 ASCII 原样输出 UTF-8 字节）。
  3. 数字：仅允许整数（u64/i64 闭区间）与 IEEE754 有限 double；
     整数按十进制输出（无前导零、无 + 号、-0 规范化）；
     double 按最短往返表示（Rust ryu 语义）；NaN/Infinity 拒收。
  3b. 布尔：true 编码为字面量 true（0x74 0x72 0x75 0x65），
     false 编码为字面量 false（0x66 0x61 0x6C 0x73 0x65）；
     无其它布尔表示（1/0/"true" 均拒收）；布尔与数字互不转换。
  4. 数组：保持顺序，元素递归 canonicalize。
  5. 对象：{k1:v1,k2:v2,...} 键序为字节序，递归。
  6. 空值：null 字面量。
  7. 顶层必须为对象（不允许裸数组/标量）。
  8. Unicode：输入必须已是合法 UTF-8；代理对/非法序列拒收（不替换）。
     空字符串合法。字符串内的 U+0000 合法（转义输出）。
~~~

### 4.1 与 serde_json::to_string 的区别

- serde_json 输出键序 = 结构体字段声明序；json-c14n 输出字节序键序。
- serde_json 输出 \uXXXX 转义（非 ASCII 转义）；json-c14n 非 ASCII 原样 UTF-8。
- 因此 json-c14n **不是** serde_json 默认输出；实现必须提供独立 canonical serializer。
  当前 v1 的 to_canonical_json 使用 serde_json::to_string（字段序），是 v1 合同；
  v2 的 record_digest 必须用 json-c14n，二者不混用。

## 5. record_digest 的 preimage 与自引用排除

### 5.1 定义

- record_digest = sha256_hex(json-c14n(preimage))。
- **preimage = 该记录对象的所有字段，除 record_digest 自身**（顶层与 WalkerAttestation 同理）。
- 因此 preimage 是**有限且可重算**的：去掉 digest 字段后 canonicalize 其余字段。
  不存在自引用循环。

### 5.1a 嵌套 digest 边界（top-level 与 WalkerAttestation）

- **WalkerAttestation.record_digest** 的 preimage = WalkerAttestation 对象自身字段
  （含 rounds/probe_summary/orphaned_resources 等），**排除其 record_digest 字段**。
- **顶层 RuntimeAttestationV2.record_digest** 的 preimage = 顶层对象字段
  （含 walker_attestation 嵌套对象），**排除顶层 record_digest 字段**。
- **walker_attestation 在顶层 preimage 中以其完整形式（含其自身 record_digest）出现**：
  即顶层 digest 覆盖嵌套 digest 值。验证顺序：先验 WalkerAttestation.record_digest（重算其
  preimage），再验顶层 record_digest（重算含嵌套 digest 的 preimage）。两层独立、顺序固定。
- **字段排除规则**：只有"正在计算 digest 的那个对象"的 record_digest 字段被排除；
  嵌套对象的 record_digest 是外层 preimage 的普通字段，不被排除。


### 5.2 计算顺序

1. 构造记录对象（不含 record_digest）。
2. canonicalize 全部字段（不含 record_digest）。
3. sha256(canonical_bytes) → hex lowercase 64 字符。
4. 将 digest 填入 record_digest 字段。
5. 验证时：重新执行 1-3，比较。

### 5.3 固定 digest vectors（fixture，实现必须逐一通过）

#### Vector 1：空对象

~~~json
{}
~~~

canonical bytes: 7b 7d

digest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a

#### Vector 2：标量对象（键序验证）

~~~json
{"b":1,"a":2}
~~~

canonical bytes（hex）: 7b 22 61 22 3a 32 2c 22 62 22 3a 31 7d
（= {"a":2,"b":1}，键按 UTF-8 字节序 a < b）

digest: d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772

#### Vector 3：嵌套对象 + 数组 + 空值 + 转义

~~~json
{"z":null,"a":[1,2],"s":"x\"y","u":"\u4e2d"}
~~~

canonical bytes（hex）: 7b 22 61 22 3a 5b 31 2c 32 5d 2c 22 73 22 3a 22 78 5c 22 79 22 2c
22 75 22 3a 22 e4 b8 ad 22 2c 22 7a 22 3a 6e 75 6c 6c 7d
（= {"a":[1,2],"s":"x\"y","u":"中","z":null}；键字节序 a < s < u < z；
双引号转义保留为 5c 22；非 ASCII "中" 原样 UTF-8 e4 b8 ad；null 字面量）

digest: 154301026b1458e084761c0fba44c2269b5e66f7a4b0e0071ad09e69e97dd244

#### Vector 4：bool 编码验证

~~~json
{"ok":true,"no":false}
~~~

canonical bytes（hex）: 7b 22 6e 6f 22 3a 66 61 6c 73 65 2c 22 6f 6b 22 3a 74 72 75 65 7d
（= {"no":false,"ok":true}；键字节序 "no" < "ok"（0x6e < 0x6f）；true/false 为字面量）

digest: ae8ab1e1b72505d8544a32bf3803333e81528159e214e4198a0271d2f60dc419

> 以上 Vector 1-4 的 digest 均为 **2026-08-23 用 SHA-256（FIPS 180-4）实际计算的固定值**（见
> docs/AUDIT_EVIDENCE_BATCH15_20260823.md 的原始计算记录）；实现工单必须以本文件为权威
> fixture 逐一通过；任何重新计算必须产生相同值，不允许"实现时再定"。

## 6. 唯一绑定关系（provenance / artifact digest / identity）

### 6.1 字段绑定矩阵

| 证据 | 来源 | 绑定校验 |
|------|------|---------|
| target_pid | controller 启动的进程 PID | attestation.target_pid == controller 记录 |
| module_base | loadlib_call 返回值 | attestation.module_base == controller 记录 |
| target_image_sha256 | vault rev2 样本身份 | == controller 预检 digest |
| runtime_module_sha256 | controller 对 runtime DLL 文件字节的 sha256 | == attestation.runtime_sha256 == WalkerAttestation.runtime_module_sha256 |
| walker_export_rva | resolve_mida_exports_remote 解析结果 | == controller 记录的 WalkerExecute RVA |
| walker_entry_va | module_base + rva | == CreateRemoteThread 实际入口地址（allowlist 断言） |

### 6.2 权威来源与时机

- runtime_module_sha256 的**权威来源**：controller 在 load_and_initialize 之前对 runtime
  DLL 文件字节计算 sha256（authority.verify_file 同一文件）。**不写入 MidaInitParams**
  （MidaInitParams 保持不扩展，见 WO-1505 §5.3）：digest 经 target 内独立内存槽（与 params
  blob 同生命周期）下发给 runtime，runtime 读取后回显到 attestation。
- **当前占位值 adr4-foundation-unbound（exports.rs:237-239）不是 digest evidence**：
  它只是字符串占位；实现工单必须改为真实文件哈希，且 v2 顶层与 WalkerAttestation 两处一致。
- controller 校验：attestation.runtime_sha256 == controller 计算的 runtime digest；
  不一致 → 拒收（防换 DLL）。

### 6.3 rollback 语义

- **runtime 回退**：runtime_module_sha256 与 controller 期望不符 → 拒收整个 attestation，
  标记 EvidenceInsufficient，不进入 walker 证据消费。
- **profile 回退**：profile_digest 不符 → 同拒收。
- **round 回退**：某 round 的 ledger 与 probe_summary 矛盾（如 abort_state=thread_hung 但
  candidates_probed > 0 且无 orphan）→ 该 round 证据作废，整体 EvidenceInsufficient。

## 7. 证据不足（EvidenceInsufficient）语义

| 场景 | 判定 | 消费行为 |
|------|------|---------|
| walker 未运行（walker_attestation=null） | 非 walker 运行 | acceptance 按原 v1 路径消费 |
| timeout → orphan 未回收（state=unconfirmed） | 证据不足 | 不得声称"已回收"；记录 orphan 后 fail-closed |
| target exit 观察到但未确认 OS 回收 | target_exit_observed | 可记录 os_reclaimed 仅当有观察证据（§WO-1504） |
| record_digest 校验失败 | 篡改/损坏 | 拒收；不消费任何 walker 字段 |
| v1 consumer 遇 v2 | SchemaUnsupported | 显式报错；不部分消费 |

## 8. 旧 fixture 不变性

- 现有 v1 fixture（attestation.rs 测试中的固定 JSON）**一个字节都不改**。
- 新增 v2 fixture 文件与 v1 并列；任何 v1 fixture 变更 = schema 破坏，需要总指挥书面批准。
- 迁移测试必须覆盖：v1→v2 判别、v2 未知字段拒收、v1 consumer 遇 v2 报错、digest 重算。

## 9. 实现前 checklist

- [ ] json-c14n 独立 serializer（字节序键、非 ASCII 原样、整数/有限 double）
- [ ] 4 个固定 digest vectors 通过（空对象/标量/嵌套+转义/bool）
- [ ] TaggedAttestation 判别 + v1/v2 双解析
- [ ] WalkerAttestation/RoundLedger/ProbeSummary/Orphan 封闭集合校验
- [ ] runtime_sha256 真实文件哈希替换 adr4-foundation-unbound
- [ ] 绑定矩阵全项 controller 校验
- [ ] 旧 v1 fixture 不变回归

## 10. 状态

| 对象 | 状态 |
|-----|------|
| WO-1503 schema 冻结 | design-only；待联审 |
| attestation.rs / provenance.rs | 未修改 |
| 实现派发 | 待 P0-A/P0-B 联审通过 |
