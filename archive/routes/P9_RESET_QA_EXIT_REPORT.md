# P9-RESET-QA: Exit Gates & Compliance Proofs

> Work order: P9-RESET (withdraw live, no sample started). QA phase.

## 唯一语义结论

**SEMANTICS_B_PROTECTED_VS_CANDIDATE**

P9 验证 **protected-sample behavior vs candidate unpacked output 的行为保持**，
不是 baseline-revision vs candidate-revision 的 A/B 回归。历史 P7-R2 baseline/
candidate（`858f66e` vs `c8258b3`）是两个代码 revision 解包同一 protected sample
的工具链修复验证，非 P9 验收输入。

## Exit gates

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo test --workspace --locked --offline` | **1053 passed, 0 failed** |
| `RUSTFLAGS="-D warnings" cargo check --workspace --tests --locked` | exit 0, 0 warnings |
| `cargo check -p mida-cli --features gto-product-recovery --locked` | exit 0 |
| `cargo deny --offline check` | advisories/bans/licenses/sources ok |
| `git diff --check` | clean |
| `git show --check` (2 commits) | clean |
| `git status --short` | empty |

## 合同修改

- 仅**文档/离线合同**修正（P9-RESET-B）：P9_PREP_E §2 明确 SEMANTICS_B 且预算无
  baseline-revision 进程；ScyllaHide reference staging 目录 `baseline/` →
  `reference/`（SHA 不变）；seal 文档路径更新。
- 无生产代码修改。审计确认 isolated_replay_ledger / bundle_gate two-bundle
  consumer / behavior_oracle_contract 均为 B 语义（无 baseline-revision 字段）。

## 额外证明

1. 默认测试不访问 D:/MidaVault（acceptance/cli 源码无 Vault 引用）。
2. 0 个真实样品进程（本工单仅文档审计 + 目录重命名，无进程创建）。
3. validation_summary.json blob `cf72b7a` 起始（3e76a67）、最终（58392ec）、工作树一致。
4. P7 roots 未修改（只读访问已批准样品用于复制，未写 P7 root）。
5. 无新增 CLI/env/PATH/verifier 绕过（grep 全零）。
6. acceptance crate 不依赖 producer crate（serde/serde_json/sha2/thiserror）。
7. P9 live 授权**撤回**，本工单未重新申请。

## 最终 live 预算（SEMANTICS_B）

46 sample processes / 22 unpack slots，覆盖 protected reference behavior +
candidate final live unpack + candidate isolated replay。**不含 baseline-revision
进程**。

## 新授权 manifest 需要绑定的完整字段（待审核方签发时）

- candidate revision `169c122a571207a36f1f48020b9c6622bff74640`（baseline NOT_USED）
- candidate mida-cli.exe SHA `7686d2c0...`
- candidate mida-acceptance.exe SHA `8f8bcdc6...`
- verifier 仅 CLI sibling `<cli-dir>/mida-acceptance.exe`
- 两个 protected input identity（origin `1af62999...`/5232656；lunlun `8a0118d0...`/4976144）
- origin runner digest `98458253...`（pure_rebuild=true）
- lunlun runner digest `d838f51e...`（pure_rebuild=false）
- ScyllaHide 三文件 SHA（`211f7b80...`、`d4b20eed...`、`17d51120...`）
- execution root `D:\MidaVault\scratch\p9_live_169c122a_20260806_140803`
- 46/22 进程预算矩阵（protected reference + candidate final/replay）

## Compliance declarations

- 0 live process / 0 slot。
- validation_summary.json 未变。
- P9 live 仍未授权（撤回中）。
- 未声明 perfect/universal/10/10/final acceptance。
