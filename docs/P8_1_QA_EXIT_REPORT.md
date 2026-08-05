# P8.1-QA —— 出口门与合规报告

**状态:** 完成（P8.1-QA）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程、未执行 P9、未申请或消耗 live slot。

## 起始 / 最终 HEAD

- 起始 HEAD：`8a741c7cf9a0942873e7ba8dfcd61dc8db55bba9`（严格匹配工作单要求）
- 最终 HEAD：`a34c3f5be1947ff232ee0e8f2563cebb462ae1fd`

## 5 个独立 commit（未 squash、未重写 P8）

| # | commit | 阶段 |
|---|---|---|
| 1 | `15f866d` | P8.1-A IAT unresolved 分类 + 安全 emission |
| 2 | `b4c3e0f` | P8.1-B 确定性唯一 section emission |
| 3 | `7344343` | P8.1-C 可复现 gate taxonomy harness |
| 4 | `a34c3f5` | P8.1-D 单一 synthetic end-to-end evidence 流水线 |
| 5 | （本 QA 提交） | P8.1-QA 出口门与合规报告 |

## 全部质量门 exit code

| 门 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | exit 0（先 `cargo fmt --all` 统一格式，逻辑不变，再复检通过） |
| `cargo test --workspace --locked --offline` | **940 passed, 0 failed**，exit 0 |
| `cargo check -p mida-cli --features gto-product-recovery --locked` | Finished（无 error），exit 0 |
| `cargo deny --offline check` | advisories ok, bans ok, licenses ok, sources ok，exit 0 |
| `git diff --check` | clean（无空白错误） |
| `git show --check --oneline HEAD` | clean，exit 0 |
| `git status --short` | 见下（QA 提交前仅 fmt 改动 + 新增 QA doc） |

## 合规证明

- **acceptance 不依赖 producer crate**：`crates/acceptance/Cargo.toml` 仅依赖 `serde`/`serde_json`/`sha2`/`thiserror`；P8.1-D 测试在 mida-pe（producer crate）内以 dev-dependency 消费端方式触达 `mida-acceptance`，producer import 从未进入 acceptance crate。
- **默认 workspace tests 不访问 D:/MidaVault**：P8.1 全部测试只用仓库内 synthetic fixture 与内存发射字节；对 "MidaVault" 的引用仅为断言"不访问"的 doc 注释。
- **0 个真实样品进程被创建**：P8.1 代码（`synthetic_evidence_pipeline.rs`、`failure_taxonomy.rs`、`main.rs` 新增命令）无任何样品 process 创建；`main.rs` 唯一的 `std::process::Command` 是既有 `GitWorktreeProbe`（`git status`/`git rev-parse`，非样品）。
- **validation_summary.json 相对起始 HEAD 无变化**：当前 blob `cf72b7a073fd639e23231da6b4a2b4c5768fa077` 与起始 HEAD 完全一致，`git diff HEAD -- validation_summary.json` 为空。
- **P7-R1 / P7.1 / P7-R2 execution root 未修改**：工作区不存在这些 execution root（不在本仓库追踪树内），无法被修改；P7-R2 分类口径仅记录于只读文档 `P8_A_FAILURE_TAXONOMY.md`。
- **未执行 P9**：P8.1 全部为离线工程；文档明确"未执行 P9"。
- **未声明 live/perfect/universal/10/10/final acceptance**：v8 gate 保持 Open；behavior oracle、isolated replay 10/10、最终验收明确 pin 需授权 live run。

## 关键交付回顾

- **1423 unresolved 分类**：P8.1-A 建立 `IatUnresolvedReason`（11 原因 + `pending_live_confirmation`），`unknown` 与 pending 均 fail-closed、绝不静默吞掉；离线无法判定的标记 `pending_live_confirmation`，不伪造根因、不宣称"防护导致"。实际 1423 归属需 live 数据确认（分类 schema/offline 实现/测试已完成）。
- **Resolved→Unresolved→Resolved 测试**：`resolved_unresolved_resolved_sequence_both_reachable` 独立重读最终 PE 证明 A/B 均可达；8 个边界用例（首/中/末/连续/跨模块/name-ordinal 混合/duplicate slot/unknown）全部 fail-closed、无 phantom。
- **section emission 前后独立解析**：P8.1-B `rebuild.rs` 确定性唯一命名，独立重读断言名字唯一、directory 指向、entry section 不变、SizeOfImage=aligned 最大 extent、absent directories canonical；8-byte 截断碰撞/同前缀/>9 重复/空名/已有后缀碰撞测试全部通过。
- **单一 synthetic end-to-end 测试**：`crates/pe/tests/synthetic_evidence_pipeline.rs` 两测试——正例全链路四域 pass + 篡改负例被独立 validator 拒绝。
- **taxonomy harness**：`mida-acceptance classify-gate-report <bundle_gate_report.json>` 输出 input SHA-256 + per-bucket counts + Other 原始文本；synthetic 人工运行输入 hash `9d58552b...` 记录于 `docs/P8_1_C_TAXONOMY_HARNESS.md`；P7-R2 原始报告未提交。

## 明确 pin（非本批，待授权 live run）

- behavior oracle（stimuli/observables/verdict）
- isolated replay 10/10（attempts）
- prerequisite survival/structural evidence artifact_sha256（真实候选绑定）
- 真实候选的 v8 gate 逐字段通过
- 最终 acceptance（需要 live run + 最终授权）
