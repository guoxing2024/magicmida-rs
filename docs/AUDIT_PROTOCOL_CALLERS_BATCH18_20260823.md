# AUDIT_PROTOCOL_CALLERS — Batch 18 协议 validated-API caller 审计（WO-1905）

**工单编号**: WO-1905（Batch 19）
**日期**: 2026-08-23
**审计性质**: 纯离线源码审计；未修改 walker_protocol.rs；未实现 Walker runtime。
**基线**: 51c1237（审计时 HEAD）

## 1. 目的

枚举 WalkerParamsV2 / ProbeResultV2 / encode_section / parse_section / validate_section
的全部调用方，证明或否定当前仓库存在绕过 validation 的生产路径，并输出后续实现 gate
所需的最小入口断言。

## 2. 调用方枚举（rg 全仓，HEAD=51c1237）

### 2.1 生产代码（crates/antidebug-runtime/src/）

| 文件 | 行 | 使用方式 |
|------|----|---------|
| src/lib.rs:44 | pub mod walker_protocol; | 模块导出（re-export 面） |
| src/lib.rs:60-64 | pub use walker_protocol::{crc32, derive_session_id, encode_section, is_canonical_user_va, is_canonical_x64, page_span_fits, parse_section, validate_section, IdentityExpectation, MappingIdentityHeaderV2, ProbeResultV2, ProtocolError, ResultSectionHeaderV2, WalkerParamsV2}; | re-export（无调用语义） |

**结论**：src/ 下除 lib.rs 的 re-export 外，**零生产调用**。exports.rs / attestation.rs /
provenance.rs / surfaces.rs / telemetry.rs 均不引用协议 API。

### 2.2 测试代码（crates/antidebug-runtime/tests/）

| 文件 | 使用方式 | 类别 |
|------|---------|------|
| tests/walker_protocol.rs（15 tests） | WalkerParamsV2::new + to_blob_bytes + from_blob_bytes + validate；固定字段/hostile/span fixtures | 测试 |
| tests/walker_protocol_section.rs（27 tests） | MappingIdentityHeaderV2::new + ResultSectionHeaderV2::new + encode_section + parse_section + validate_section + ProbeResultV2::new/set_probe_span | 测试 |

### 2.3 其它 crate（crates/cli、crates/acceptance、crates/core）

rg 结果：validate_section_rebuild_evidence 仅存在于 crates/acceptance/src/oreans_gate.rs:2766
（Oreans 证据重建校验，与 walker_protocol 无关的同名词）；**无任何 walker_protocol API 引用**。

## 3. 绕过 validation 的生产路径判定

### 3.1 结论：不存在生产绕过路径

- 生产 src/ 无任何调用 → 不存在"绕过 validation 的生产路径"；
- 协议 API 目前**未接线**：walkers 运行时、控制器、CLI 均未消费这些函数；
- 因此不能写"runtime 已安全"——正确表述为**"未接线"**（WO-1905 验收门 2）。

### 3.2 测试侧 raw field mutation 登记（有意为之的 hostile 路径，仅测试）

| 测试 | 文件:行 | 方式 | 目的 |
|------|---------|------|------|
| params_fixed_fields_rejected | walker_protocol.rs:228-261 | from_blob_bytes 后 mutate d.magic/version/header_bytes/candidate_off/candidate_stride | 证明 validate 拒收固定字段违规 |
| hostile_counts_rejected | walker_protocol_section.rs:258-289 | validate_section 前 mutate result_count=u32::MAX | 容量规则 |
| header_closed_sets_rejected | walker_protocol_section.rs:294-329 | ResultSectionHeaderV2::new 后 mutate completed_flag/status/stride/results_off | 闭集/对齐规则 |
| encode_invalid_*（12 项） | walker_protocol_section.rs | new + mutate 后 encode_section | 证明 validated constructor 拒收 |
| hostile wire 系列 | walker_protocol_section.rs:337+ | 直接构造字节或 from_blob_bytes/parse_section | 证明 decode panic-free + 拒收 |

上述均为测试内部构造，不构成生产调用面。

## 4. 调用方检查矩阵（probe_span / count / capacity / CRC / reserved-retry）

| 检查项 | 协议强制点（walker_protocol.rs） | 测试覆盖 | 生产调用方 |
|--------|------------------------------|----------|-----------|
| probe_span == 16 | WalkerParamsV2::validate（!=16 → BadProbeSpan）；ProbeResultV2::validate（!=16 → BadProbeSpan）；MIN/MAX/DEFAULT 常量 == 16 | params_probe_span_frozen_rejects_non_16；probe_result_span_frozen_rejects_non_16；hostile wire 两测试 | 无（未接线） |
| candidate_count <= 4096 | from_blob_bytes 前置 CountTooLarge；validate | params_candidate_count_limits；hostile_params_count_max_no_alloc | 无 |
| blob_total_bytes == header+count*stride 且 <= MAX_BLOB_BYTES | from_blob_bytes（len 等长 + 上限） | params_round_trip_valid；truncated 系列 | 无 |
| section capacity（MIN + n*40, n<=4096） | encode_section 入口 + validate_layout + parse_section | hostile_section_bytes_max；encode_exact_section_bytes_round_trip | 无 |
| result_count <= capacity 且 pending 时必须为 0 | encode_section；parse_section；validate_section | section_states_and_payload；InconsistentPendingCount | 无 |
| CRC（header CRC32 + payload CRC32） | validate/validate_common/validate_section | crc32_known_vector；params_crc_mismatch；section_payload_crc_detected | 无 |
| ProbeResult reserved==0 / retry_count<=1 / flags 闭集 / classification 闭集 | ProbeResultV2::validate（encode_section 逐条调用） | encode_invalid_retry_count/reserved/probe_fields；probe_result_span_hostile_wire | 无 |

## 5. 后续实现 gate 的最小入口断言（设计建议，本工单不实现）

1. WalkerExecute 入口（未来实现）**必须**从 WalkerParamsV2::from_blob_bytes + validate 开始，
   任何未 validate 的 blob 不得进入探针循环；
2. 探针结果写入**必须**经 encode_section（validated constructor），禁止手写字节拼装；
3. 控制器读取**必须**经 parse_section + validate_section（含 IdentityExpectation 全回显复核）；
4. probe_span != 16 的 params 在入口即拒收（零探针）。

这些断言将写入 Walker runtime 实现工单的验收条件（另行派发）。

## 6. 可复核性

- 搜索命令：rg -n walker_protocol|WalkerParamsV2|ProbeResultV2|encode_section|parse_section|validate_section crates --glob *.rs
- 结果树：HEAD 51c1237；上述行号均按该树核实；
- 测试范围：cargo test -p mida-antidebug-runtime --offline（116 passed，40+34+15+27）
  于 51c1237 树重跑通过（见 AUDIT_EVIDENCE_BATCH18 §3 新证据文件）。
- 仅测试通过**不**构成生产调用闭环证明；本审计以源码搜索 + 行号为证据。

## 7. 结论

当前仓库：协议层 validated API 已冻结（span=16 等），但**无任何生产调用方**——协议
模块处于"已实现未接线"状态。不存在绕过 validation 的生产路径（因为不存在生产路径）。
Walker runtime 实现派发时必须以 §5 入口断言为验收条件。

