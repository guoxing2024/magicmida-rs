# GTO-H5-RESOLVER-CAUSAL-PROOF-1-RUNTIME-IAT-BOUNDARY-CORRECTION — 离线更正

> 总指挥审计（ec9c433 不签收）：runtime IAT 解析边界错误——1378 qword 中仅前 562 属于 IAT（size 0x1190/8=562），后 816 是 .rdata1 元数据。离线更正即可，无需新 session。

## 更正结果
- 截断到 562 边界后：**562 same / 0 diff**
- 两侧均：**546 external VA + 16 zero**（分类完全一致）

## 撤销
- "candidate/protected runtime IAT 语义不同"结论 → **REVOKED**
- 第 19-20 行因果解读（基于虚假差异的"非崩溃触发"框架）→ **REVOKED**
- iat_runtime_comparison_evidence.json 中错误 total/分类 → 已附 correction 块

## 新确立事实
- **runtime IAT 在 resolver 入口 562/562 完全一致** → "loader 后 IAT 语义等价"缺证据的 gap **已闭合**
- IAT 内容差异不是崩溃原因（实际无差异）——与全部回填阴性一致
- 根因保持 PENDING；搜索范围进一步收窄（崩溃与 IAT 内容无关）

## 下一步候选向量
1. r9 来源（0x142934069 处 Themida 元数据读）
2. .rdata1/.rdata2 元数据表在 resolver 入口 byte-diff
3. TLS0 入口前状态 byte-compare

## 封存
- manifest_v4.json + seal_anchor_v4.json：36 files，self-hash MATCH
- ADR7 17/17 PASS；工作树 clean
- GTO-H5-LIVE-AUTHORIZATION-2 继续不签
