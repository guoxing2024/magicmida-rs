# MagicMida vNext 项目总览报告

> 审计日期：2026-08-29　审计人：小助手（总指挥）
> 依据：工作区源码、Cargo 元数据、CI 配置、质量基线文件、本地复现验证

## 1. 项目性质

Windows PE **脱壳（unpacking）研究平台**：从受保护二进制产出可加载、行为等价的 PE。
当前是 **vNext 重构中的研究基线**，不是 1.0 产品；README 与验收契约均明确不宣称"完美/通用脱壳"。

- **主攻线**：`gto_launcher`（AHK/GTO 族）——已定性为 dump 路线结构性天花板（SecureEngine 类逐页解密），处于"恢复工作开放中"状态。
- **回归门**：`origin_macro` + `lunlun_software`（Oreans/Themida 族）——结构化证据栈的 fail-closed 墙，要求 10/10 隔离复现。

## 2. 技术栈

| 项 | 值 |
|---|---|
| 语言/工具链 | Rust 1.97.1，edition 2021，`x86_64-pc-windows-msvc`（rust-toolchain.toml 锁定） |
| 关键依赖 | iced-x86 1.21（反汇编）、pelite 0.10（PE 解析）、windows 0.58、serde/serde_json、sha2、thiserror、tracing、anyhow |
| 许可证 | GPL-3.0-only，全部 `publish = false` |
| 依赖治理 | cargo-deny：禁 wildcard、禁未知 registry、禁 openssl-sys；syn 2/3 多版本豁免（有注释依据） |
| 依赖规模 | Cargo.lock 80 个包，唯一多版本 = syn（已豁免） |

## 3. 结构（11 个 workspace member）

| crate | 职责 | 规模（src 行数） |
|---|---|---|
| mida-core | 调试器/进程原语、B4/B5 观察器 | ~11.1k |
| mida-pe | PE 解析/重建/导入/TLS/重定位/纯模型（R1） | ~86.9k |
| mida-disasm | iced-x86 封装 | ~0.6k |
| mida-tracer | 单步跟踪引擎 | ~0.8k |
| mida-packers-themida | Oreans/Themida 插件 | ~16.4k |
| mida-packers-ahk-gto | AHK/GTO 插件（恢复路由 opt-in） | ~0.5k |
| mida-cli | CLI 聚合层 | ~48.3k |
| mida-acceptance | 独立静态验收内核（R0B，禁依赖生产 crate） | ~22.2k |
| mida-antidebug | 反调试状态机（ADR-3A） | ~1.2k |
| mida-antidebug-runtime | x64 运行时/导出面（ADR-4） | ~10.4k |
| host_loader | 实验运行时宿主 | lab 下 |

**依赖方向**：acceptance 完全独立（`dependency_boundary.json` pass=true）；
core 为底层，pe/tracer/disasm 依赖 core，packers 依赖底层，cli 聚合全部。

## 4. 质量体系（CI 三层门禁）

1. **windows-quality**：fmt + 工作区卫生（vault 路径、SHA-256 策略）
2. **windows-build-test**：default + all-features 双 lane，`--locked` check/test
3. **windows-clippy**：`--all-targets -D dbg_macro` + `--lib --bins -D unwrap_used/expect_used/manual_let_else` + WO-23 基线单调（349）
4. **cargo-deny**：advisories/licenses/bans

## 5. 本地复现验证结果

| 检查 | 结果 |
|---|---|
| `cargo check --workspace --lib --bins --offline` | ✅ 通过（21.6s） |
| mida-pe / acceptance / themida / antidebug / disasm / tracer 单独 clippy 门禁 | ✅ 通过 |
| **CI clippy 门禁命令（--workspace 全量）** | ❌ **失败：11 个 unwrap error** |
| mida-cli 编译 | ⚠️ 9 个 rustc 警告（unused imports x8 + dead code x1） |

## 6. 核心问题（详见任务单 TASK_BOARD_20260829.md）

- **P1-A【已修复】**：mida-cli 的 `dump.rs` / `iat_observe.rs` / `rebase_fixed.rs` 生产代码原有 11 处 `try_into().unwrap()`，未按项目惯例加 `#![allow]` + 文档注释；CI 的 `-D unwrap_used` 门禁曾在此失败，与 WO-10/12 "fully retired" 声明矛盾。已按惯例修复，门禁 0 error。
- **P1-B【已修复】**：mida-cli 原有 9 个 rustc 警告（unused imports + dead code）未被 CI 拦截（clippy 门禁不覆盖 rustc 警告）。已清理至 0 警告。
- **P2【待执行】**：生产代码 TODO 残留（unpacker/mod.rs x4、process.rs、themida boundaries x2、tls_bootstrap）。
- **P2【待执行】**：`core/src/adr7_b4_observer.rs:8` 裸 `#![allow(clippy::unwrap_used)]` 缺文档化说明（一致性）。
- **P3【待执行】**：`windows_debugger.rs:89` 注释编码乱码（`闁?`）；`pin.log` 显示 PIN 工具 DLL 加载失败（外部工具链不可用）。
- **新观察项**：`production_thunk_call_does_not_leak_thread_handles` 测试在并行运行下 flaky（单独跑通过），需排查并行干扰。
- **环境注意**：工作区有大量未提交改动（XX-11 工作线），`cargo fmt --check` 整体红（200+ 处，多为未提交文件），CI fmt job 当前会失败；修复需与 XX-11 提交协同。本机跑测试需 MSVC 环境（VsDevCmd 被沙箱拦截时，可用手动 PATH/LIB 方案，见记忆）。
- **已确认良好**：unsafe 均有 SAFETY 注释 + RAII；acceptance 边界独立；依赖治理严格；文档体系完备（ADR/GTO/WO 报告）。

## 7. 结论

代码库结构清晰、治理规范、文档完备，工程质量基线高；当前主要风险是**门禁声明与代码现状脱节**（P1-A 会在 CI 上直接红掉），以及 mida-cli 层的警告卫生问题。修复成本低、风险小，建议按任务单 P1 → P2 → P3 顺序处理。
