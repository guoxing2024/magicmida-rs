# AUDIT_PROTOCOL_CALLERS — Batch 20 最终树 protocol caller 审计修正（WO-2005）

**工单编号**: WO-2005（Batch 20）
**日期**: 2026-08-23（worker 机时钟；temporal-mismatch 见 AUDIT_EVIDENCE_BATCH19 §6）
**审计性质**: 纯离线源码审计；未修改协议生产代码，未实现 Walker runtime。
**基线**: 最终 HEAD = dd6cae3（Batch 20 生产代码零变更；协议代码自 0e5732f 未变）

## 1. 目的

以最终 HEAD 重做协议 API 调用方搜索，确认生产 caller 仍为零；逐项核对各 API 的生产/测试调用方与 raw mutation；保留未接线不等于已安全的表述；输出 Walker runtime 实现三条硬门。

## 2. 最终树源码搜索（HEAD = dd6cae3，2026-08-23）

### 2.1 搜索命令与结果

~~~text
rg -n encode_section|parse_section|validate_section|WalkerParamsV2|ProbeResultV2 crates/antidebug-runtime/src --glob *.rs -g !walker_protocol.rs
结果：仅 lib.rs:60-64 re-export（零调用语义）

rg -n walker_protocol|WalkerParamsV2|ProbeResultV2 crates/cli crates/acceptance crates/core --glob *.rs
结果：零命中

rg -c WalkerParamsV2|encode_section|parse_section|validate_section crates/antidebug-runtime/tests/walker_protocol.rs crates/antidebug-runtime/tests/walker_protocol_section.rs
结果：walker_protocol.rs 33；walker_protocol_section.rs 88（全部为测试）
~~~

### 2.2 结论

- **生产 caller 仍为零**：src/ 除 lib.rs re-export 外无任何调用；
- cli/acceptance/core 零引用（oreans_gate.rs 的 validate_section_rebuild_evidence 为同名独立函数，与协议无关，Batch 19 已核实）；
- 协议 API 保持**已实现未接线**状态；**未接线 ≠ 已安全**。

## 3. 逐项调用方核对（最终树）

| API | 生产调用 | 测试调用 | raw mutation（仅测试） |
|-----|---------|---------|----------------------|
| WalkerParamsV2::from_blob_bytes | 无 | walker_protocol.rs（round-trip/hostile/span 系列） | hostile wire 构造（CRC 重算后验证 span） |
| WalkerParamsV2::validate | 无 | walker_protocol.rs（固定字段/span/count） | from_blob_bytes 后 mutate 字段 |
| encode_section | 无 | walker_protocol_section.rs（validated constructor 系列） | new + mutate 后 encode（12 项 encode_invalid） |
| parse_section | 无 | walker_protocol_section.rs（round-trip/truncated/hostile） | 字节直接构造 |
| validate_section | 无 | walker_protocol_section.rs（echo/CRC/容量） | mutate 后 validate |

## 4. 协议冻结状态（最终树）

| 项 | 状态（dd6cae3） |
|----|----------------|
| probe_span == 16 | 常量 MIN/MAX/DEFAULT == 16；params+result validate 精确等值；1/15/17/64 拒收测试通过 |
| CRC | header CRC32 + payload CRC32 全覆盖；已知向量测试 |
| capacity | MAX_CANDIDATE_COUNT=4096；section capacity 语义；pending 时 result_count==0 |
| reserved/retry | ProbeResultV2::validate：reserved==0、retry_count<=1；encode 逐条校验 |
| 测试 | 116 passed（40+34+15+27），worker 机 |

## 5. Walker runtime 实现三条硬门（本工单不实现）

1. **validated-entry**：WalkerExecute 入口必须从 WalkerParamsV2::from_blob_bytes + validate 开始；未 validate 的 blob 不得进入探针循环（probe_span != 16 → 入口拒收）；
2. **validated-result**：探针结果写入必须经 encode_section（validated constructor），禁止手写字节拼装或绕过校验的字段注入；
3. **validated-controller-read**：控制器读取必须经 parse_section + validate_section（含 IdentityExpectation 全回显复核 + 双层 CRC）。

## 6. 误计检查

- Batch 19/20 新增 fixture（docs/fixtures/WO-1901/1902/2002）为 C 头文件，非 Rust 生产 caller；
- 本批新增审计文档（AUDIT_*）非代码；均不计入生产调用面；
- 测试绿（116）不构成生产调用闭环证明——本审计以源码搜索 + 行号为证据。

## 7. 结论

最终树（dd6cae3）：协议 validated API 已冻结但未接线；生产 caller 为零；三条硬门（§5）为 Walker runtime 实现验收条件，另行派发实现单时强制执行。
