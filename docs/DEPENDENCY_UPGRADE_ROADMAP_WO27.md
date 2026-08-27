# WO-27: 依赖升级评估（只调研，不动手）

日期: 2026-08-27
范围: workspace 直接依赖（Cargo.toml [workspace.dependencies]）

## 当前版本 vs 最新（2026-08-27 crates.io 实测）

| 依赖 | 当前 | 最新 | 建议 |
|---|---|---|---|
| windows | 0.58 | **0.62.2** | **有迁移成本**（见下） |
| iced-x86 | 1.21 | 1.21.0 | 无更新，无需动 |
| pelite | 0.10 | 0.10.0 | 无更新，无需动 |
| thiserror | 1.x | **2.0.20** | 低迁移成本（见下） |
| anyhow | 1.x | 1.0.104 | 同 minor，无风险 |
| tracing | 0.1 | 0.1.44 | 同 minor，无风险 |
| tracing-subscriber | 0.3 | 0.3.x | 同 minor，无风险 |
| sha2 | 0.10 | **0.11.0** | 有迁移成本（见下） |
| serde | 1.x | 1.0.229 | 同 minor，无风险 |
| serde_json | 1.x | 1.0.151 | 同 minor，无风险 |

注：cargo-audit 未安装成功（stable toolchain thiserror 编译失败；
rust-toolchain.toml 锁 1.97.1）；RustSEC 在线 API 网络 flaky 未取回。
下方安全评估基于已知公告 + 版本差异分析，建议网络恢复后补跑
`cargo +stable audit` 或 CI cargo-deny（仓库已有 cargo-deny job）。

## 逐项评估

### 1. windows 0.58 → 0.62.2（P2，有迁移成本）
- **API 变化**：0.59 引入 `windows-link`/`windows-result` 重构（Cargo.lock
  已有 0.61.2 windows-targets 过渡），部分 API 签名调整；0.60+ 继续
  micro-version 演进。
- **使用面**：crates/{pe,cli,antidebug,antidebug-runtime,acceptance} 均用
  windows crate（Win32_Foundation/Memory/Threading/LibraryLoader 等大量 feature）。
- **迁移成本**：中等。主要是 `PCWSTR`/`PCSTR` 构造、错误处理
  (`windows-result`)、部分函数签名。需全仓编译 + 测试验证。
- **风险**：0.58 已 EOL（微软 policy），但无已知 RustSEC 公告针对 0.58。
- **建议批次**：独立提交；先在 CI 双跑（0.58 与 0.62 各自全测），
  无回归再切。优先级 P2（安全无紧迫，但长期维护建议升）。

### 2. thiserror 1 → 2.0.20（P2，低成本）
- 2.0 主要变化：`#[error]` 属性微调、MSRV 提升（1.61+）。
- 使用面：各 crate 大量 `#[derive(thiserror::Error)]` + `#[from]`。
- **注意**：WO-24 新增 `Pe(#[from] Box<...>)` —— 2.0 的 `#[from]` 对 Box
  支持不变。
- **建议**：低风险，可随 windows 批次一起或独立。

### 3. sha2 0.10 → 0.11.0（P2，有成本）
- 0.11 属于 RustCrypto 大版本（digest 0.11 系列），API 基本稳定但
  依赖图变化（`crypto-common` 升级）。
- 使用面：`Sha256`/`Digest` trait 调用（raw_slab_coherence、module_identity、
  acceptance 等多处）。
- **建议**：独立批次，改 `use sha2::{Digest, Sha256}` 导入 + 验证。

### 4. 其余（anyhow/tracing/serde/serde_json/tracing-subscriber）
- 全为 minor/patch 级，`cargo update` 直接可升，零迁移成本。
- **建议**：随下次常规维护一起 `cargo update`。

### 5. iced-x86 / pelite
- 无新版，不动。

## 安全（RustSEC）初步结论
- 未取回在线数据库；仓库已有 cargo-deny（advisories）CI job 兜底。
- 已知 rustsec 对 windows 0.58 无高危公告（0.58 仍是广泛使用的过渡版本）。
- **建议**：网络恢复后补跑 `cargo audit`（或确认 CI cargo-deny 绿），
  将结果并入本文件。

## 执行顺序建议（若获批）
1. 批次 A（零成本）：`cargo update` 提升 anyhow/tracing/serde 等 minor。
2. 批次 B（P2）：thiserror 2.0 —— 独立提交 + 全测。
3. 批次 C（P2）：sha2 0.11 —— 独立提交 + 全测。
4. 批次 D（P2）：windows 0.62.2 —— 最大批次，CI 双跑验证。

本 WO-27 只调研，未改任何 Cargo.toml。
