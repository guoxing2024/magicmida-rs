# AUDIT — V2 arithmetic final-head audit（Batch 26 / WO-2603）

**审计运行日期**：2026-08-23
**审计基线**：`dea085b62a179535ff73194c036d7ea0bfcb70bb`（`dea085b`，Batch 28 最终 HEAD）
**前版基线**：`639eee362d69c1cbb3fc0852438bb6e461d506c9`（Batch 25 最终 HEAD，WO-2603）；`62ed608`（WO-2503）
**性质**：只读 arithmetic 审计；不实现 V2 runtime

## 1. ASan fixture 结果（条件接收范围）

- 被测对象：docs/fixtures/WO-2102-v2-envelope-fixture.h（最终树）
- 结果：hostile_asan_detail.txt 16/16 ALL PASS EXIT=0（SHA `7AFE1FA5...`）
- **范围**：仅证明纯逻辑 fixture 无已知 hostile 越界；**不构成 V2 runtime 实现**
  （exports.rs/runtime_loader.rs 零修改，无 MidaAntidebugInitializeV2）

## 2. checked-add 代码审查（dea085b 树；自 639eee3 起 crates/ 零修改，事实同源）

| 位置 | 表达式 | checked-add | 拒收码 |
|------|--------|-------------|--------|
| surface string scan | soff + k | ✅ mida_checked_add | 10 |
| profile_id scan | off + k | ✅ mida_checked_add | 10 |
| profile_digest scan | off + k | ✅ mida_checked_add | 10 |
| surface base+size | base + params_bytes | ✅ mida_checked_add | 12 |
| surfaces need | hooks*8 | ✅ mida_checked_mul | 4 |
| digest region | digest_off+65 | ✅ mida_checked_add | 4 |

全部在**任何 blob 读取前**执行（纵深防御顺序正确）。

## 3. off+k overflow 分支覆盖说明

- 回绕分支（ovf → 拒收）在"读取先过边界检查"约束下**不可达**（WO-2502 §6 分析）：
  - off >= params_bytes → 循环前提前拒收（用例 14 覆盖）；
  - off < params_bytes 且 params_bytes 真实分配大小 → off+k 不回绕；
  - params_bytes≈UINT64_MAX → blob 读取先越界，checked-add 拦截先于读取。
- 因此该分支是**防御性编程**，由代码审查保证存在且顺序正确；ASan 无法直接
  覆盖不可达分支（构造覆盖会人为制造越界读取）。

## 4. 边界声明（不得写成 production）

| 项 | 状态 |
|----|------|
| V2 runtime 存在 | **否**（生产零修改） |
| expected_blob_base_va / header_readable | 离线 fixture 输入，**非生产 ABI** |
| 远程 params 读取 | **无**（无 WPM/remote 代码） |
| ASan PASS → runtime PASS | **禁止推导** |

## 5. 结论

- ASan 16/16 + checked-add 审查通过（offline fixture 范围）；
- V2 runtime 未实现，implementation gate 继续由 placeholder digest / V2 缺失阻断。

---
（WO-2603 交付，绑定 639eee3；WO-2703 绑定 928047f；WO-2803 最终头重绑定，绑定 dea085b）