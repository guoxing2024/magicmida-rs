# AUDIT — Protocol Caller 最终 HEAD 审计（Batch 21 / WO-2105）

**审计运行日期**：2026-08-22（总指挥侧；worker 时间戳 2026-08-23，temporal-mismatch 标记）
**审计基线**：`381507e`（最终 HEAD）
**前版基线**：`dd6cae3`（AUDIT_PROTOCOL_CALLERS_BATCH19.md；旧树，已废弃声明）
**性质**：纯离线源码审计；不修改协议生产代码；不实现 Walker runtime

## 0. 基线差异声明

- 旧审计基线 `dd6cae3` 与最终 HEAD `381507e` 之间仅 `381507e` 一个提交（docs/fixtures）。
- 生产代码（crates/）自 `dd6cae3` 起零修改；本文件以 `381507e` 为唯一最终树基线重做
  全仓搜索，行号均为最终树核对结果。

## 1. 全仓源码搜索（381507e，grep walker_protocol|WalkerParamsV2|ProbeResultV2|
   ResultSectionHeaderV2|MappingIdentityHeaderV2|encode_section|from_blob_bytes）

| 文件 | 命中 | 类别 |
|------|------|------|
| crates/antidebug-runtime/src/lib.rs | L44, L60-64 | **re-export only**（pub use walker_protocol::{...}） |
| crates/antidebug-runtime/src/walker_protocol.rs | 全文件 | 协议实现本体 |
| crates/antidebug-runtime/tests/walker_protocol.rs | 39 处 | 测试 |
| crates/antidebug-runtime/tests/walker_protocol_section.rs | 94 处 | 测试 |
| crates/cli/** | **0** | 无引用 |
| crates/acceptance/** | **0** | 无引用 |
| crates/core/** | **0** | 无引用 |

**结论**：生产 caller 仍为零；仅 lib.rs re-export + 2 个测试文件。

## 2. 生产 API 调用方登记（381507e）

| API | 生产调用方 | 测试调用方 | raw mutation |
|-----|-----------|-----------|-------------|
| WalkerParamsV2 | 0 | walker_protocol.rs tests | 无 unsafe/raw 写 |
| MappingIdentityHeaderV2 | 0 | 同上 | 无 |
| ResultSectionHeaderV2 | 0 | walker_protocol_section.rs tests | 无 |
| ProbeResultV2 | 0 | 同上 | 无 |
| encode_section | 0 | 同上（validated constructor） | 无 |
| from_blob_bytes | 0 | 同上 | 无 |
| parse_section / validate_section | 0 | 同上 | 无 |
| crc32 / derive_session_id / is_canonical_* | 0 | 同上 | 无 |

协议文件内 unsafe/from_raw/as_mut_ptr/transmute 命中：**0**。

## 3. 三条硬门（必须继续存在）

1. **validated-entry**：WalkerExecute 入口只能经 encode_section/from_blob_bytes 等 validated
   构造器进入；任何未经校验的裸解析路径不存在。
2. **validated-result**：controller 读结果 section 必须经 parse_section/validate_section +
   payload_crc32 + completed_flag 校验后才消费（WO-1501/1701 合同）。
3. **validated-controller-read**：远程读取必须走 section 边界校验（result_count/stride/
   results_off 约束），禁止越界就地解析。

## 4. 状态登记（381507e）

| 项 | 值 |
|----|----|
| probe_span | 16（MIN=MAX=DEFAULT=16，冻结） |
| CRC-32 | poly 0xEDB88320，crc32(b"123456789")==0xCBF43926 |
| section capacity | 有界（MAX_BLOB_BYTES / 最大 result_count） |
| reserved/retry | ProbeResultV2::validate 要求 retry_count<=1、_reserved==0 |
| 测试数 | walker_protocol.rs 15 + walker_protocol_section.rs 27 |

## 5. 误计检查

| 潜在误计 | 判定 |
|----------|------|
| docs/fixtures/*.h | 非生产 caller（C 头文件设计 fixture，不链接） |
| docs/WO-*.md 伪代码 | 非生产 caller（design-only） |
| lib.rs re-export | 不是调用（仅符号可见性） |
| 测试全绿 | 不构成生产闭环证明（测试调用 ≠ runtime 集成） |

## 6. 结论

- 协议 API 已实现（116 测试全绿）但**未接线**：生产 caller 为零；"已实现未接线 ≠ runtime 已安全"。
- Walker runtime/CLI：**NOT DISPATCHED**；Windows live test：**NOT AUTHORIZED**；LIVE-4：**NOT AUTHORIZED**。
- 仅测试绿不构成生产闭环；实现工单必须先过三条硬门。

---
（WO-2105 交付，绑定 381507e）