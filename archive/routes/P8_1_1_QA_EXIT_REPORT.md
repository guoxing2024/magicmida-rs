# P8.1.1-QA —— 出口门与合规报告

**状态:** 完成
**范围:** 纯离线工程。未访问 D:/MidaVault（仅 P8.1.1-A 显式只读读取指定 P7-R2 报告）、未启动任何真实样品、未执行 P9。

## 起始 / 最终 HEAD

- 起始 HEAD：`1faa8752ab412b508e4bad2f2c4546d4d5f4ec90`（严格匹配）
- 最终 HEAD：见 `git log`（P8.1.1-A `50e61d6`，P8.1.1-B `f6eb7ae`，P8.1.1-QA 提交）

## 独立提交

| # | commit | 阶段 |
|---|---|---|
| 1 | `50e61d6` | P8.1.1-A 真实 P7-R2 taxonomy 重放 |
| 2 | `f6eb7ae` | P8.1.1-B 真实 CLI production evidence E2E |
| 3 | （本 QA 提交） | P8.1.1-QA 出口门与合规报告 |

## 全部质量门 exit code

| 门 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | exit 0（先 `cargo fmt --all` 统一格式，逻辑不变，再复检通过） |
| `cargo test --workspace --locked --offline` | **941 passed, 0 failed**，exit 0 |
| `RUSTFLAGS="-D warnings"` 等价检查（acceptance+cli+pe） | Finished，无 warning，exit 0（对应 `.github/workflows/ci.yml` 的 `RUSTFLAGS: -D warnings`） |
| `cargo check -p mida-cli --features gto-product-recovery --locked` | Finished，exit 0 |
| `cargo deny --offline check` | advisories ok, bans ok, licenses ok, sources ok，exit 0 |
| `git diff --check` | clean |
| `git show --check`（50e61d6、f6eb7ae） | clean |
| `git status --short` | 见下（QA 提交前仅 fmt 改动） |

## 额外合规证明

1. **真实 P7-R2 taxonomy 输入 SHA-256 和 337/1504 计数已记录**：`29b7dfb93034989fb32bae88833670ff6fe8304804d90482e0c08768e9568b40`；origin=337、lunlun=1504（见 `docs/P8_1_1_A_P7R2_TAXONOMY_REPLAY.md`）。
2. **Other=0、unclassified=0**（两个 case 均验证）。
3. **新 production E2E 源码存在对 CLI producer 和 atomic assembler 的真实调用**：`write_oep/iat/tls/relocation/section_rebuild_evidence`、`write_bound_transform_manifest`、`build_oreans_pe_evidence`、`assemble_evidence_bundle`（见 `crates/cli/src/unpacker/production_e2e.rs`）。
4. **不再由测试手工构造 `OreansEvidenceBundle` 代替 assembler**：正对照 bundle 完全由 `assemble_evidence_bundle` 原子组装；`assert_not_hand_built` 校验 `manifest_sha256` 密封；源码无 `OreansEvidenceBundle {` 手工构造。
5. **默认 workspace tests 不访问 D:/MidaVault**：P8.1.1-B 测试零 Vault 引用；P8.1.1-A 仅显式只读读取指定 P7-R2 报告（非默认测试）。
6. **0 个真实样品进程被创建**：production E2E 无 process 创建；`main.rs` 的 `std::process::Command` 仅既有 `GitWorktreeProbe`。
7. **validation_summary.json blob 未变化**：当前 `cf72b7a073fd639e23231da6b4a2b4c5768fa077` 与起始 HEAD 一致。
8. **P7 execution roots 未修改**：P8.1.1-A 只在 scratch 写分类输出，不写 P7-R2 root；分类命令只读输入。
9. **未执行 P9**。
10. **未声明 live/perfect/universal/10/10/final acceptance**：v8 gate 保持 Open；行为 oracle/isolated replay/survival 明确 Open；四域 pass 仅为 synthetic 离线证明。

## 备注

- P8.1.1-B 的四个域（OEP/IAT/relocation/section）通过真实 producer 离线证明；TLS 不在四域断言内（#11 只要求上述四域），且 "protected input does not match locked manifest" 是 synthetic 受保护输入固有（锁定身份是真实样品），非结构化域失败。
- 旧 `crates/pe/tests/synthetic_evidence_pipeline.rs` 已删除（被 production E2E 完整替代，不再自称 production/full pipeline）。
