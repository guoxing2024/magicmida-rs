# GTO-H5-RESTORE-AND-BOUNDARY-FIX — 完成报告

## 1. 恢复被原地改写的文件
- 问题：iat_runtime_comparison_evidence.json 被原地追加 correction 块（违反封存政策）
- 修复：恢复原版字节（移除 correction 块）；sha256 = f9347f5a3b1f666163124301713d1accd1a2c7216eca923baae506f6358c4deb —— 与 v3 记录**精确匹配**

## 2. 边界表述修正
- 原："后 816 个都是 .rdata1 元数据"（错误）
- 正：qword 563..1378 越出 IAT 边界（IAT = 562 qword = 0x1190 字节）后，
  - **candidate** 尾部落在 **.rdata**（IAT 0x12c000..0x12d190；.rdata 0x12c000..0x176250）
  - **protected** 尾部落在 **.rdata1**（IAT 0x159f000..0x15a0190；.rdata1 0x159f000..0x15a2f60）
  - 正确表述："越出 IAT 范围"，两侧不同段

## 3. 离线计算结果（保持成立）
- 截断 562 边界：**562 same / 0 diff**；两侧 **546 external VA + 16 zero**
- runtime IAT 在 resolver 入口完全一致 → loader 后 IAT 语义等价 gap 闭合
- 根因保持 PENDING

## 4. 封存
- manifest_v5.json + seal_anchor_v5.json：39 files，self-hash MATCH
- 恢复文件哈希 f934… 复验通过；ADR7 17/17；工作树 clean
