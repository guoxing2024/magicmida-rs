# MIDA-ADR-2 行为规范（clean-room anti-debug behavior specification）

> **工作令：** MIDA-ADR-2 —— 基于 ADR-1 建立 clean-room anti-debug 行为规范与 probe 契约。
> **状态：** 规范设计定稿（文档阶段）。未执行样本、未执行 ScyllaHide、未做 live 差分、未实现任何代码。
> **基线：** `e98a6a61051a734a14cf53ebe9e64e5b1099374b`（ADR-1 提交）。前置：ADR-0（`836c02dd`）+ ADR-1（`e98a6a61`）已提交。
> **配套文档：** [PROBE_CATALOG](MIDA_ADR_2_PROBE_CATALOG.md) · [PROFILE_DRAFT](MIDA_ADR_2_PROFILE_DRAFT.md)

## 1. 目的与范围

本文件把 ADR-1 surface inventory 转成实现 agent 可以直接使用、但不包含第三方实现细节的行为规范。
每个 probe 必须回答：目标是什么、在哪个 phase 发生、输入是什么、正常 no-debugger 状态是什么、当前 debugger 状态是什么、MIDA 应该 observe 还是 emulate、成功/失败如何判断、证据如何记录。

**本任务禁止：** 实现 injector/hook/runtime/controller；执行 protected sample；执行 ScyllaHide；做无/有 ScyllaHide live 差分（live differential 另开独立任务）。

## 2. 必须修正"存在"与"语义"的区别

ADR-1 中部分条目只证明 **API presence**（IAT 中存在 QPC / GetTickCount / SetUnhandledExceptionFilter），
不能直接证明 **anti-debug decision semantics confirmed**。

ADR-2 为每个 surface 增加四个 proof level（互斥，按证据强度从低到高）：

| proof level | 含义 | 可进入 required_hooks 的条件 |
|---|---|---|
| `presence_observed` | 静态可见 API/字节/结构存在（import、字符串、pattern） | 否 |
| `call_site_confirmed` | 有明确调用点（xref / 反汇编 / 动态命中），且确认用于 debugger 相关上下文 | 候选 |
| `runtime_observed` | 运行时观察到调用/行为（live evidence、受控探针） | 候选 |
| `decision_semantics_confirmed` | 确认返回值/分支影响 unpack 结果（anti-debug decision） | **是** |

示例（QueryPerformanceCounter）：

```json
{
  "surface_id": "AD-TIM-002",
  "presence_observed": true,
  "call_site_confirmed": "unknown",
  "runtime_observed": "unknown",
  "decision_semantics_confirmed": false,
  "default_action": "observe-only"
}
```

**硬规则：** 禁止因为"导入了 API"就把它加入 required hooks。
仅有 `presence_observed=true` 的 surface，action 只能是 `observe-only` 或 `defer`。

## 3. 行为规范对象

### 3.1 AntiDebugObservation（`mida.antidebug-observation/v1`）

每个实际观察必须包括：

```json
{
  "schema": "mida.antidebug-observation/v1",
  "sample_id": "origin_macro",
  "surface_id": "AD-PROC-001",
  "phase": "oep_post",
  "source": "static-analysis",
  "input": {},
  "observed": {},
  "confidence": "confirmed",
  "evidence_ref": "iat_evidence slot 92",
  "timestamp": null,
  "notes": ""
}
```

`source` 允许：`static-analysis` / `existing-live-evidence` / `debugger-core` / `mida-runtime` / `scyllahide-oracle` / `public-doc`。
**ADR-2 本身禁止新增 `mida-runtime` 与 `scyllahide-oracle` 的 live 记录**（未实现 runtime、未执行 oracle）。

### 3.2 AntiDebugExpectedState（`mida.antidebug-expected-state/v1`）

每个 sample × surface 必须定义：

```json
{
  "schema": "mida.antidebug-expected-state/v1",
  "sample_id": "origin_macro",
  "surface_id": "AD-PROC-002",
  "phase": "loader",
  "expected_no_debugger": {
    "peb_being_debugged": 0,
    "p_shim_data": 0
  },
  "allowed_variance": [],
  "required": true,
  "reason": "existing live evidence: PEB patched (was 1) in all 66 runs"
}
```

要求：
- **unknown surface 不得写成 required**；
- **没有证据的字段不能填默认值**（缺证据就留空/unknown，不填 0）；
- **expected state 必须有 evidence reference**；
- **allowed_variance 必须明确**（空数组 = 零容忍；禁止写成无限容忍）。

### 3.3 AntiDebugProbeResult（`mida.antidebug-probe-result/v1`）

每个 probe 需要定义：

```json
{
  "schema": "mida.antidebug-probe-result/v1",
  "sample_id": "origin_macro",
  "surface_id": "AD-PROC-002",
  "expected": {},
  "observed": {},
  "match": true,
  "consistency_status": "consistent",
  "decision": "pass",
  "source": "existing-live-evidence",
  "evidence_refs": []
}
```

`decision` 只能是：`pass` / `fail` / `not-run` / `unknown` / `deferred`。
**禁止使用：** `probably-pass` / `best-effort-pass` / `inferred-pass`。

## 4. Fail-closed 规则

以下情况必须 `decision = fail-closed`（profile 级）或 probe 级 `decision = unknown/deferred`，**不能自动 pass**：

| 证据类型 | 能否 pass |
|---|---|
| 只有 IAT presence | 否 |
| 只有字符串命中 | 否 |
| 只有加密 payload byte pattern | 否 |
| 只有历史日志文字 | 否 |
| 只有 ScyllaHide 成功 | 否 |
| 只有 TLS callback 存在 | 否 |

**profile 级 required 只能来自：** confirmed call site / confirmed runtime observation / confirmed decision semantics。

## 5. Differential 规则（只定义格式，不执行）

未来差分必须使用三态：`baseline`（no anti-debug runtime）/ `oracle`（ScyllaHide）/ `candidate`（MIDA-ADR）。
每个结果必须记录：

- baseline artifact hash
- oracle artifact hash
- candidate artifact hash
- runner config digest
- profile digest
- environment digest
- probe results

**约束：** ScyllaHide 结果只能进入 `source=scyllahide-oracle`，不能成为 MIDA runtime 实现来源。
ADR-2 只定义格式，**不执行任何差分**。

## 6. 文档治理

- schema 命名沿用 ADR-0：`mida.antidebug-observation/v1`、`mida.antidebug-expected-state/v1`、`mida.antidebug-probe-result/v1`、`mida.antidebug-profile/v1`。
- 本三份文档为 ADR-2 交付；本文件是总纲，PROBE_CATALOG 是 24 个 surface 的 probe 定义，PROFILE_DRAFT 是两份 per-sample profile。
- 提交信息建议：`docs(antidebug): add ADR-2 behavior spec and probe contract`。