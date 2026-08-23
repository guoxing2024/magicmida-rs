# AUDIT — Protocol Caller 最终 HEAD（Batch 26 / WO-2605）

**审计运行日期**：2026-08-23
**审计基线**：`dea085b62a179535ff73194c036d7ea0bfcb70bb`（`dea085b`，Batch 28 最终 HEAD）
**前版基线**：`639eee362d69c1cbb3fc0852438bb6e461d506c9`（Batch 25 最终 HEAD，WO-2605）；`62ed608`（WO-2505）
**前版基线**：`62ed608`（WO-2505，AUDIT_PROTOCOL_CALLERS_BATCH24.md）
**性质**：纯离线源码审计；不修改协议生产代码；不实现 Walker runtime

## 0. 基线关系

- `62ed608..639eee3` 仅 docs/fixtures 提交，生产代码零修改。
- 本文件以 `639eee3` 为唯一最终树基线重做全仓搜索。

## 1. 全仓源码搜索（dea085b，grep walker_protocol|WalkerParamsV2|ProbeResultV2|
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

**结论**：生产 caller 仍为零；仅 lib.rs re-export + 2 测试文件。

## 2. 生产 API 调用方登记（639eee3）

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

## 4. 状态登记（639eee3）

| 项 | 值 |
|----|----|
| probe_span | 16（MIN=MAX=DEFAULT=16 冻结） |
| CRC-32 | poly 0xEDB88320，crc32(b"123456789")==0xCBF43926 |
| reserved/retry | ProbeResultV2::validate 要求 retry<=1、_reserved==0 |
| 测试数 | 15 + 27（+ 40 attestation + 34 lib = 116） |

## 5. 误计检查

| 潜在误计 | 判定 |
|----------|------|
| docs/fixtures/*.h | 非生产 caller（C 头文件设计 fixture） |
| docs/WO-*.md 伪代码 | 非生产 caller（design-only） |
| lib.rs re-export | 不是调用（仅符号可见性） |
| 测试全绿 | 不构成生产闭环证明 |

## 6. 结论

- 协议 API 已实现（116 测试全绿）但**未接线**：生产 caller 为零；"已实现未接线 ≠ runtime 已安全"。
- Batch 25/26 docs/fixtures 不改变生产调用面。
- Walker runtime/CLI：**NOT DISPATCHED**；Windows live test：**NOT AUTHORIZED**；LIVE-4：**NOT AUTHORIZED**。

---
（WO-2605 交付，绑定 639eee3；WO-2705 绑定 928047f；WO-2805 最终头重绑定，绑定 dea085b）