# PROJECT HANDOVER — 2026-08-20 仓库清理与交接

> 本文档记录 2026-08-20 的仓库清理（chore）与当前项目状态，供下一位接手人
> 快速建立上下文。清理本身已提交（见 §4），本文件是交接入口。

## 1. 项目一句话

Windows PE 脱壳研究平台（Rust workspace，10 个 crate）。主目标线：
`gto_launcher`（Themida）；回归闸门：`origin_macro` + `lunlun_software`。
所有样本/产物按 SHA-256 存于仓库外 `D:\MidaVault`（内容寻址 vault），
仓库内只保留源码、确定性 fixture、case manifest（SHA-256 引用）与文档。

## 2. 关键路径速查

| 用途 | 路径 |
|---|---|
| 仓库 | `D:\Claude project\magicmida-rs`（分支 `oreans/two-sample-mainline`） |
| 证据 vault | `D:\MidaVault\lab\evidence\`（adr7b_b4、adr7b_b5 等） |
| 样本身份权威 | `lab/cases/v2/gto_launcher.json`（SHA-256 only） |
| 样本身份解析 | `tools/resolve_gto_source_revision.ps1` |
| 回归闸门案例 | `lab/cases/v2/*.json` |
| CI | `.github/workflows/ci.yml`（fmt + hygiene + check/test --locked + cargo-deny） |
| hygiene 检查 | `tools/verify_workspace_hygiene.ps1` |

## 3. 构建与验证命令

```powershell
cargo check --workspace --tests          # 编译检查
cargo test --workspace --locked          # 全量测试
cargo fmt --all -- --check               # 格式门
powershell -File tools/verify_workspace_hygiene.ps1   # 工件卫生
```

## 4. 2026-08-20 清理内容（已提交）

| 提交 | 内容 |
|---|---|
| `0405595` | docs 历史路线报告（Q–Z、P8/P9、audit/unattended）归档至 `archive/routes/`；README/WORKER_HANDOFF/代码注释引用路径同步更新 |
| `3645d61` | cargo fmt B1/B2/B4 测试源 + `crates/cli/src/unpacker/mod.rs`（纯格式，无行为变化） |

工作区层面（未入库，git 不追踪）：
- 删除根目录调试 dump（cdb/disasm/dumpbin/meta/stub/sym 系列，约 24 MB）；
- 删除 `gto_launcher/`、`crates/cli/gto_launcher/` snapshot.bin 残留；
- 删除 `MidaVaultlabevidenceadr7_a4/`（0 字节空证据）、`.hermes/`、`lab/authority_reviews/`、空目录 `crates/bwhook/`、`crates/cli/src/bin/`；
- 移除 6 个废弃工作树（`.claude/worktrees/*`，约 5.3 GB）并删除对应分支；
- 删除 `.claude/`（settings.local.json 为本机缓存，已被 .gitignore 覆盖）；
- 取消跟踪生成物 `dependency_boundary.json`、`validation_summary.json`（已 ignore）；
- 还原 `crates/core/Cargo.toml` 的 CRLF 伪改动（内容归一化后无 diff）。

### 注意（诚实记录）

- `MidaVaultlabevidenceadr7b_b3B3_RVA_EXACT_LOCATION_REPORT.md` 在清理时
  尝试归档至 vault 失败（vault 写入被拒）后已删除，且该文件从未进入 git，
  无法从历史恢复。其内容为 ADR7-B3 的 RVA 定位报告（fault RVA 0x2edb6），
  **不影响 B4/B5 闭环**（B4 是独立 observer 验证，fault RVA 0x2e806）。
  若需找回：检查 `D:\MidaVault\lab\evidence\adr7b_b3\` 或原始来源。

## 5. ADR7 closeout 状态（截至 2026-08-20，冻结终态）

| 项 | 状态 |
|---|---|
| B4 | **FORMAL PASS**（seal 115 文件 0 mismatch；vault: `adr7b_b4_binding_correction/`） |
| B5 | **FORMAL PASS**（sign-off: `ADR7_B5_FORMAL_SIGNOFF.json`，seal 87 文件 0 mismatch；vault: `adr7b_b5/`） |
| B5 TLS isolation evidence | **COMPLETE**（6/6 target + 6/6 controls） |
| 证据链 | root/final/seal 全部验证通过（B4 115 文件 / B5 87 文件） |

Closeout 资产（`D:\MidaVault\lab\evidence\`）：
- `ADR7_CLOSEOUT_INDEX.json` — 总账本（B4/B5 全部哈希 + sign-off + seal + 依赖关系）
- `ADR7_CLOSEOUT_REPORT.md` — 收口报告（结论 / 已关闭问题 / residual risk / 交接 / 下一阶段）
- `ADR7_FREEZE_FINGERPRINTS_20260820.json` — 四路径冻结指纹
- 验证入口：`pwsh tools/verify_adr7_closeout.ps1`（只读，RESULT: PASS）

Helper 基线（记录于 closeout index）：
- B4（release）：`b1 473E0FC8...` / `b2 49015F84...` / `b4 A47995BB...`
- B5（自有 profile，方案 A 接受）：`b1 58E3EB17...` / `b2 6A1092A6...` / `b4 00BFADCE...`

## 6. 维护规则（防再乱）

1. **样本/证据永远不进 git**：一律入 `D:\MidaVault`，仓库内只留 SHA-256 引用；
2. **轮次报告放 `archive/routes/`**，`docs/` 只放现行文档（VNEXT*/ADR/contract/policy）；
3. **生成物不入库**：`dependency_boundary.json`、`validation_summary.json` 已 ignore，
   `gate_vectors.json` 是 Rust/Python 双端共享测试向量，**必须保留**；
4. 提交前跑 `cargo fmt --all -- --check` + `tools/verify_workspace_hygiene.ps1`；
5. 不要在工作区根目录丢调试 dump；临时文件用完即删；
6. 废弃工作树及时 `git worktree remove` + `git branch -D`。
