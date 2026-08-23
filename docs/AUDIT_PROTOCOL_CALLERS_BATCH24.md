# AUDIT — Protocol Caller 最终 HEAD 重跑（Batch 25 / WO-2505）

**审计运行日期**：2026-08-23
**审计基线**：`62ed608652c9168913c2cb19671b24455bebeb16`（Batch 24 最终 HEAD）
**前版基线**：`221ef33`（WO-2405，AUDIT_PROTOCOL_CALLERS_BATCH23.md）
**性质**：纯离线源码审计；不修改协议生产代码；不实现 Walker runtime

## 0. 基线关系

- `221ef33..62ed608` 仅 docs/fixtures 提交（a664f92、62ed608），生产代码零修改。
- 本文件以 `62ed608` 为唯一最终树基线重做全仓搜索；WO-2405 的"未接线"结论可复用，
  行号在本树重新核实。

## 1. 全仓源码搜索（62ed608，grep walker_protocol|WalkerParamsV2|ProbeResultV2|
   ResultSectionHeaderV2|MappingIdentityHeaderV2|encode_section|from_blob_bytes）

| 文件 | 命中 | 类别 |
|------|------|------|
| crates/antidebug-runtime/src/lib.rs | L44, L60-64 | **re-export only** |
| crates/antidebug-runtime/src/walker_protocol.rs | 全文件 | 协议实现本体 |
| crates/antidebug-runtime/tests/walker_protocol.rs | 39 处 | 测试 |
| crates/antidebug-runtime/tests/walker_protocol_section.rs | 94 处 | 测试 |
| crates/cli/** | **0** | 无引用 |
| crates/acceptance/** | **0** | 无引用 |
| crates/core/** | **0** | 无引用 |

**结论**：生产 caller 仍为零（与 221ef33 树一致）；仅 lib.rs re-export + 2 测试文件。

## 2. 生产 API 调用方登记（62ed608）

| API | 生产调用方 | 测试调用方 | raw mutation |
|-----|-----------|-----------|-------------|
| WalkerParamsV2 | 0 | walker_protocol.rs tests | 无 unsafe/raw 写 |
| MappingIdentityHeaderV2 | 0 | 同上 | 无 |
| ResultSectionHeaderV2 | 0 | walker_protocol_section.rs tests | 无 |
| ProbeResultV2 | 0 | 同上 | 无 |
| encode_section | 0 | 同上 | 无 |
| from_blob_bytes | 0 | 同上 | 无 |
| parse_section / validate_section | 0 | 同上 | 无 |
| crc32 / derive_session_id / is_canonical_* | 0 | 同上 | 无 |

协议文件 unsafe/from_raw/as_mut_ptr/transmute 命中：**0**。

## 3. 三条硬门（保持）

1. **validated-entry**：入口只能经 encode_section/from_blob_bytes 等 validated 构造器。
2. **validated-result**：controller 读结果必须经 parse_section/validate_section + CRC +
   completed_flag 校验。
3. **validated-controller-read**：远程读取必须走 section 边界校验（count/stride/off）。

## 4. 状态登记（62ed608）

| 项 | 值 |
|----|----|
| probe_span | 16（MIN=MAX=DEFAULT=16 冻结） |
| CRC-32 | poly 0xEDB88320，crc32(b"123456789")==0xCBF43926 |
| reserved/retry | ProbeResultV2::validate 要求 retry<=1、_reserved==0 |
| 测试数 | 15 + 27（+ 40 attestation + 34 lib = 116） |

## 5. 误计检查

| 潜在误计 | 判定 |
|----------|------|
| docs/fixtures/*.h（WO-1901/WO-2102/WO-2301/WO-2401/WO-2501） | 非生产 caller（C 头文件设计 fixture） |
| docs/WO-*.md 伪代码 | 非生产 caller（design-only） |
| lib.rs re-export | 不是调用（仅符号可见性） |
| 测试全绿 | 不构成生产闭环证明 |

## 6. a664f92/62ed608 提交性质

- 两个提交均为 docs/fixtures 变更（+415/-64，7 unique paths），**不改变生产调用面**。
- 协议 API 状态在 62ed608 与 221ef33 完全一致：已实现未接线。

## 7. 结论

- 协议 API 已实现（116 测试全绿）但**未接线**：生产 caller 为零；"已实现未接线 ≠ runtime 已安全"。
- Walker runtime/CLI：**NOT DISPATCHED**；Windows live test：**NOT AUTHORIZED**；
  LIVE-4：**NOT AUTHORIZED**。
- 仅测试绿不构成生产闭环；实现工单必须先过三条硬门。

---
（WO-2505 交付，绑定 62ed608）