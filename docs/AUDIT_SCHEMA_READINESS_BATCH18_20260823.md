# AUDIT_SCHEMA_READINESS — Batch 18/19 Schema/digest acceptance gate 交叉审计（WO-1904）

**工单编号**: WO-1904（Batch 19）
**日期**: 2026-08-23
**审计性质**: readiness/acceptance 只读审计；未实现 v2 schema，未改消费者。
**基线**: 3e6c50d（审计时 HEAD）

## 1. 目的

以当前真实代码为准更新 v1/v2 构造器/消费者/占位 digest 事实表；逐项检查 v1 fallback、
V2 required、Walker attestation、record digest、EvidenceInsufficient 与 orphan/unconfirmed
门禁在代码中的存在性；给出 readiness/schema implemented/acceptance allowed 三状态矩阵。

## 2. 真实代码事实表（HEAD = 3e6c50d）

### 2.1 exports.rs

| 事实 | 行 | 状态 |
|------|----|------|
| MidaAntidebugInitialize（v1 入口） | L182 | 存在 |
| MidaInitParams（v1 结构） | L89 | 存在 |
| MidaAntidebugInitializeV2 | — | **不存在**（rg 零命中） |
| MidaInitParamsV2 | — | **不存在** |
| runtime_sha256 = "adr4-foundation-unbound" | L239 | 存在（占位，非 digest evidence） |
| out_runtime_sha256 输出回显 | L316-320 | 存在（输出通道；非输入通道） |

### 2.2 runtime_loader.rs

| 事实 | 行 | 状态 |
|------|----|------|
| MidaExports（3 字段：initialize/get_attestation/shutdown） | L533-537 | 存在；**无 initialize_v2/walker_execute** |
| wanted 列表（3 项） | L1451-1455 | 存在；**无 V2/WalkerExecute** |
| resolve_mida_exports_remote 解析 | L1275+ | 存在（3 字段构造） |
| build_init_params_bytes（v1, 0x30） | L1792 | 存在；**无 v2 变体** |
| digest_controller 计算/复核 | — | **不存在** |

### 2.3 attestation.rs / provenance.rs

| 事实 | 行 | 状态 |
|------|----|------|
| RuntimeAttestation v1 + deny_unknown_fields | L104-106 | 存在 |
| ATTESTATION_SCHEMA = ".../v1" | L17 | 存在 |
| schema_version / walker_attestation / record_digest | — | **不存在**（rg 零命中） |
| json-c14n serializer | — | **不存在**（v1 用 serde_json::to_string） |
| Provenance v1（deny_unknown_fields） | provenance.rs L42+ | 存在 |

## 3. 门禁存在性检查（逐项）

| 门禁 | 要求 | 代码中是否存在 | 结论 |
|------|------|--------------|------|
| v1 fallback | 无 digest 需求时走 v1 入口 | 是（唯一入口即 v1） | ✅ 存在（但无"需求判定"逻辑） |
| V2 required | digest 需求时必须走 V2 入口 | **否**（V2 不存在） | ❌ 未实现 |
| Walker attestation 消费 | v2 容器解析 | **否**（无 v2 结构） | ❌ 未实现 |
| record digest 校验 | 双层 digest 验证 | **否**（无 record_digest 字段） | ❌ 未实现 |
| EvidenceInsufficient 路径 | acceptance 拒收 | 部分：attestation parse/validate 失败路径存在（runtime_loader.rs:1236-1255, antidebug_controller.rs:593-604）；但**无 v2/EvidenceInsufficient 专属码** | ⚠️ 部分（v1 路径） |
| orphan/unconfirmed 消费 | walker 悬挂证据门禁 | **否**（无 walker 代码） | ❌ 未实现 |
| digest 绑定拒收（adr4-foundation-unbound） | 未绑定 digest 不得进入可接受证据 | **否**（当前 acceptance 接受占位值） | ❌ 未实现（WO-1902 §5.3d 已冻结合同，待实现） |

## 4. 三状态矩阵（禁止误报）

| 状态 | 定义 | 当前是否达成 | 证据 |
|------|------|-------------|------|
| readiness accepted | 设计合同/矩阵经总指挥联审通过 | ✅（WO-1705/1805 条件接收） | WO-1705 matrix + WO-1805 cross-audit |
| schema implemented | 仓库存在 Rust 类型/函数/测试 | ❌ | rg 零命中：v2 结构、dispatch、c14n、digest 流全部不存在 |
| acceptance allowed | acceptance 可消费 v2 证据并给最终判定 | ❌ | 无 v2 解析/校验代码；占位 digest 仍被接受 |

**规则**：readiness accepted **不**推导 schema implemented **不**推导 acceptance allowed；
任何文档不得用设计字段替代仓库类型、函数或测试证据。

## 5. 与 WO-1902 的绑定核对

- WO-1902（本批）冻结了 MidaInitParamsV2 布局、指针安全、5 项 wanted、fallback 门禁
  （digest 需求 → V2 必选；adr4-foundation-unbound 不得进入可接受证据）；
- 上述均为**设计合同**（docs/ + docs/fixtures/），本批未修改 exports.rs/runtime_loader.rs；
- 本审计确认：这些合同与 attestation v2 schema 字段（runtime_module_sha256 等）绑定方向
  一致（WO-1503 §6.2 已同步 V2 通道表述）；实现仍待独立工单。

## 6. 结论

readiness：✅ 条件接收；schema implemented / acceptance allowed：❌ 均未达成。
本审计不派生产实现；后续 schema 实现工单须以 §4 三状态矩阵的验收条件为准。

