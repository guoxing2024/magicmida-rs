# AUDIT — V2 arithmetic independent hostile audit（Batch 25 / WO-2502）

**审计运行日期**：2026-08-23
**审计基线**：`62ed608`（Batch 24 最终 HEAD；WO-2102 fixture 与 WO-2402 checked-add 均为最终树内容）
**性质**：MSVC ASan 离线独立复核；不得实现 V2 runtime

## 1. 独立复核方法

- 被测对象：docs/fixtures/WO-2102-v2-envelope-fixture.h（最终树版本，checked-add 已就位）
- 测试源：D:\Temp\hostile_test_2202.c（16 用例，SHA-256 7D589D894044346BE30936A44E2ED3AAB4E7B4F3CB30B22BB695A3A62A7ABE64）
- 编译：cl /nologo /std:c11 /W4 /WX /Zi /fsanitize=address /TC
- 运行：hostile_test_2202.exe（ASan 运行时）
- 输出：D:\Temp\hostile_asan_detail.txt（SHA-256 7AFE1FA521B5155D8E832B8004CA175035E1D9EE7930ACFCA52A3DE0E6EC4AC4）

## 2. 逐用例记录（expected / actual / 判定）

| # | 用例 | expected | actual | 判定 |
|---|------|----------|--------|------|
| 1 | valid（完整 envelope） | 0 | 0 | ✅ |
| 2 | hostile profile_id_off=255（审计 ASan 复现） | 10 | 10 | ✅ |
| 3 | hooks > MAX_EXPECTED_HOOKS | 6 | 6 | ✅ |
| 4 | surface entry out-of-blob | 11 | 11 | ✅ |
| 5 | digest_off below 0x48 | 5 | 5 | ✅ |
| 6 | digest_off+65 wrap | 4 | 4 | ✅ |
| 7 | unknown extension tail | 13 | 13 | ✅ |
| 8 | null params | 1 | 1 | ✅ |
| 9 | profile_id no NUL | 10 | 10 | ✅ |
| 10 | base near UINT64_MAX（base+size wrap） | 12 | 12 | ✅ |
| 11 | params_bytes huge (no wrap) | 13 | 13 | ✅ |
| 12 | params_bytes UINT64_MAX（wrap） | 12 | 12 | ✅ |
| 13 | hooks=MAX edge（2048 > blob） | 5 | 5 | ✅ |
| 14 | profile_id_off=UINT64_MAX | 5 | 5 | ✅ |
| 15 | profile_id scan no NUL bounded | 10 | 10 | ✅ |
| 16 | surface string scan bounded | 0 | 0 | ✅ |

**结果**：16/16 ALL PASS，EXIT=0，**零 ASan 报告**。

## 3. checked-add 路径核对（WO-2402 覆盖）

| 位置 | 表达式 | 修复 |
|------|--------|------|
| surface string scan | soff + k | mida_checked_add(soff, k) → overflow 拒收 10 |
| profile_id scan | off + k | mida_checked_add(off, k) → overflow 拒收 10 |
| profile_digest scan | off + k | mida_checked_add(off, k) → overflow 拒收 10 |
| surface base+size | base + params_bytes | mida_checked_add → overflow 拒收 12 |
| surfaces need | hooks*8 | mida_checked_mul → overflow 拒收 4 |
| digest region | digest_off+65 | mida_checked_add → overflow 拒收 4 |

覆盖边界：off/soff 接近 UINT64_MAX（用例 14）、params_bytes 极大（11/12）、
base+size wrap（10）、digest wrap（6）、MAX_EXPECTED_HOOKS 边界（3/13）、
NUL 边界（2/9/15）、strict extension（7）。

## 4. 边界声明

- fixture 外部的 expected_blob_base_va / header_readable 是**离线测试输入**，
  不构成生产 ABI（WO-2202 §5.3f 唯一 trust boundary 方案）。
- ASan PASS 仅证明**纯逻辑 fixture 无已知 hostile 越界**，不构成 V2 runtime
  实现或 Windows 行为证据（exports.rs/runtime_loader.rs 零修改）。

## 5. 结论

- WO-2402 checked-add 路径独立复核通过（16/16 逐用例匹配）。
- 条件接收范围保持：offline fixture only；implementation gate 仍由 placeholder
  digest / V2 未实现阻断。

---
（WO-2502 交付，绑定 62ed608）