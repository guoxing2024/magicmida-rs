# GTO-H5-SEAL-LEDGER-REVOCATION — 账本更正

## 遗留 P0 修复
- 问题：v5 overlay 只说"已恢复"，未明确撤销 v4 有效性，v4 manifest/anchor 仍被纳入链中
- 修复：本 sibling revocation overlay 明确：

| 版本 | 状态 | 说明 |
|---|---|---|
| manifest_v3 | **有效（恢复基线）** | 记录 iat_runtime_comparison_evidence.json = f9347f5a…（原版字节，已恢复匹配） |
| manifest_v4 | **无效 — 不得作为有效证据引用** | 封存时该文件带原地追加的 correction 块（hash 9db809dc…≠f934…）；是违规时刻的历史产物 |
| manifest_v5 | **当前有效** | 恢复后 39 文件封存 |
| manifest_v6 | **当前有效（本次）** | 加入 ledger revocation overlay 后 42 文件封存 |

## 明确规则
1. manifest_v4 / seal_anchor_v4 = 历史上已失效的封存版本，不得作为有效证据
2. v3 已恢复有效，v5/v6 是当前有效封存
3. **不得声称 v2-v5 全部可同时复验**（各版本覆盖不同文件集状态；只有 v6 与恢复一致的 v3 基线代表有效证据状态）

## 封存
- manifest_v6.json + seal_anchor_v6.json：42 files，self-hash MATCH
- iat_runtime_comparison_evidence.json = f9347f5a…（复验通过）
- ADR7 17/17 PASS；工作树 clean
- GTO-H5-LIVE-AUTHORIZATION-2 不签；修码冻结
