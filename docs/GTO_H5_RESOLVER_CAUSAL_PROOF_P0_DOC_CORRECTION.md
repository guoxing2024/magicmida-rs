# GTO-H5-RESOLVER-CAUSAL-PROOF-1-P0-DOC-CORRECTION — 完成报告

## 一、P0 文档笔误更正（sibling overlay，不碰封存物）
- 错误：`EXPORT=0xE8`（完成报告第 5 行 + audit_correction_overlay.json 第 12 行）
- 正确：`EXPORT=0x108`（独立 PE 计算 pe_field_calculation.json 确认 dd_off=0x108；session 5 实际回填 0x140000108 正确）
- 更正载体：p0_doc_correction.json（sibling correction；原文件冻结）

## 二、结论范围收窄
- 原"DataDirectory 机制被有效否定" → 收窄为：
  (a) 三个 DD 指针值不是崩溃原因（全回填阴性）
  (b) resolver 阶段未直接读取 Import/IAT DD 条目
- **不**扩展到"完整 Import/IAT loader 语义已否定"——loader 后 IAT 语义等价性未建立

## 三、runtime IAT 对比（唯一受控 session）
- 方法：resolver 入口 0x1417223b2 同时 dump candidate/protected 运行时 IAT
- 结果：
  - candidate：871 ext + 270 zero + 237 other（loader 已解析的函数 VA）
  - protected：550 ext + 811 zero + 15 other（大部分未解析的 loader 输入 thunk）
  - 比较：804 same / 574 diff（共 1378）
- 解读：candidate IAT = dump 后 loader 解析状态；protected = resolver 入口时大部分未解析。
  该差异是事实（确认审计"缺 loader 等价证据"），但**不是崩溃因果**（resolver 不读 IAT DD + IAT 回填阴性）。
  根因保持 PENDING。

## 四、封存
- manifest_v3.json + seal_anchor_v3.json：33 files，self-hash MATCH，whole-file anchor 匹配
- ADR7 17/17 PASS；工作树 clean
