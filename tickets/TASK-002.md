# TASK-002 — 把在飞的两天成果分批提交并推送

- **优先级**：P0
- **状态**：🔧 执行中（老板 2026-08-29 裁定：**本地提交已授权，推送不做，等老板逐次确认** —— 见 `docs/DECISIONS.md` D-010）
- **岗位**：总指挥亲自执行（涉及 git 历史，不外派）
- **预估**：1 小时
- **前置**：TASK-001 完成（fmt 必须先绿）

## 项目背景

MagicMida vNext 的所有产出都在长期分支 `oreans/two-sample-mainline` 上（`master` 已落后 557 个提交，最后提交 2026-07-16）。
2026-08-28 之后的两天工作 —— 引擎会话绑定修复、三项硬编码清理、两项门禁修复 —— **全部只存在于本机未提交的工作区**：
41 个 modified 文件、约 35 个 untracked 项、1906 行插入 / 329 行删除，其中 3 个是新的生产源文件（共 1259 行）。
这台机器上任何意外都会让这两天归零，而且本地分支还领先 `origin` 14 个未推送提交。

## 你要改的文件

不改代码。只做 git 操作。涉及的改动已按逻辑分好组：

| Commit | 内容 | 文件 |
|---|---|---|
| 0 | **纯格式**：31 个在 HEAD 上就已不合规的文件（`cargo fmt` 顺带修的既有债，与本次功能改动无关） | `crates/packers/themida/` 下 8 个、`crates/pe/` 下 8 个、`crates/antidebug-runtime/` 下 4 个、`crates/cli/` 下 7 个、`crates/acceptance/src/implementation_gate.rs`、`crates/pe/examples/tr_assemble_real.rs` 等，完整清单见 `runs/20260829-TASK-001.md` |
| 1 | T0.7 引擎会话绑定：会话模块表清洗 + sidecar 归档 | `crates/pe/src/dumper/data_reinit.rs`、`dump_process.rs`、`sidecar_consumer.rs`(新)、`types.rs`、`mod.rs`、`output_writer.rs` |
| 2 | T0.8 样品哈希改 manifest 读取 | `crates/cli/src/origin_pure.rs`、`crates/acceptance/src/{oreans_gate,bundle_gate,preflight,lib,main}.rs`、`crates/acceptance/tests/{bundle_gate,oreans_two_sample_gate}.rs`、`crates/cli/src/unpacker/production_e2e.rs` |
| 3 | T0.9 系统目录改 API 查询 | `crates/pe/src/dll_exports.rs`、`crates/pe/src/dumper/dump_process.rs` |
| 4 | T0.10 + T1.1 + T1.2 CLI 示例通用化 / lint 豁免 / 警告清理 | `crates/cli/src/{args,lib,commands}.rs`、`crates/cli/src/unpacker/{dump,iat_observe(新),rebase_fixed(新)}.rs`、`crates/cli/src/runner_preflight/*` |
| 5 | XX-11 工作线其余改动 | `crates/cli/src/unpacker/{generic,generic_gate,loop_state,mod,post_loop}.rs`、`crates/core/src/windows_debugger.rs`、`crates/packers/themida/src/postprocess/mod.rs`、`crates/pe/src/dumper/{header_patch,data_reinit,pure_rebuild_adapter}.rs`、`crates/cli/tests/gate_vectors.rs` |
| 6 | lab/runtime workspace 成员 + 样品 manifest 修订 | `Cargo.toml`、`Cargo.lock`、`lab/runtime/{host_loader,xx21_monitor}/`、`lab/cases/v2/{case-manifest.schema.json,xiongxiong_duokai.json,xiongxiong_core.json}` |
| 7 | 治理文件与文档 | `AGENTS.md`、`docs/{00-START-HERE,PROJECT_STATUS,TICKETS,ARCHITECTURE_MAP,DECISIONS,KNOWN_ISSUES}.md`、`tickets/`、`runs/`、`tools/_enter_msvc_env.cmd`、`tools/_hardcode_scan.py`、`README.md`、`.github/workflows/ci.yml`、`docs/PROJECT_AUDIT_AND_ROADMAP.md`、`docs/VNEXT_ARCHITECTURE.md`、`AUTHORIZATION_XX_20260827.md` |

## 任务目标

`git status --short` 里不再有任何未提交的生产源码；本地与 `origin/oreans/two-sample-mainline` 同步；CI 全绿。

## 具体要求

1. **先确认不该进 Git 的东西没混进来。** 按 `ARTIFACT_POLICY.md`：样品、脱壳产物、dump、日志、二进制一律不进仓库。
   逐个检查这些未跟踪项，确认它们要么被 `.gitignore` 覆盖、要么明确排除：
   `lab/xx21_s4/`、`lab/xx21b_matrix/`、`lab/xx21b_resume/`、`lab/xx21b_run/`、`lab/xx21b_run_ui/`、
   `tools/xx21_monitor_out/`、`tools/xx21_monitor_dump_out/`、`tools/xx21_step1_static_*_out.json`、`.workbuddy-ai/`。
   `tools/verify_workspace_hygiene.ps1` 当前 exit 0，但它只报告未跟踪项、不阻止你 `git add`。
2. **`tools/xx21_msvc_env.cmd` 不要提交**：它写死了 MSVC 版本号 `14.44.35207` 且行尾是 LF（会被 cmd 误解析）。已被 `tools/_enter_msvc_env.cmd` 取代，直接删掉本地文件。
3. **逐个文件 `git add`，不要用 `git add .`**（避免把 vault 产物、日志、临时文件带进去）。
4. 每个 commit 之后跑一次 `cargo check --workspace --tests --offline`，确认该 commit 自身可编译（不留"中间不可编译"的历史）。
5. 全部提交完成后跑一次完整门禁（见验收标准）。
6. **推送不做。** 老板 2026-08-29 裁定：只提交到本地，推送等他逐次确认（`DECISIONS.md` D-010）。提交完成后停在本地状态，把门禁结果报给老板。

## 约束

- 不得改任何代码逻辑（如果发现必须改，停下来单独开工单）。
- 不得 `git add .`、不得 `git commit -a`。
- 不得 `--amend`、不得 `reset --hard`、不得 `push --force`、不得 `clean -f`。
- **不得推送**（老板裁定 D-010：本地提交授权，推送单独把关）。目标分支只有 `oreans/two-sample-mainline`，绝不碰 `master`。
- 不得改 git config。
- 不得 `--no-verify` 跳过 hook。

## 验收标准

1. `git status --short` → 输出里没有任何 `crates/`、`lab/cases/`、`docs/`、`tickets/`、`tools/` 下的 ` M` 或 `??` 生产内容（vault 产物目录仍可保持 untracked，但要在报告里逐个说明为什么不提交）。
2. `cargo fmt --all -- --check` → 退出码 0。
3. 全量测试 → **2801 passed / 0 failed / 2 ignored，EXIT=0**。
4. `cargo clippy --workspace --all-targets --offline -- -D clippy::dbg_macro` → 退出码 0。
5. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 退出码 0。
6. `python tools/_hardcode_scan.py --gate` → `HARD-CODING GATE PASS`。
7. `git log --oneline -8` → 8 个新提交（含 commit 0 纯格式），每个的 message 说清对应哪个原任务 ID。
8. `git status` 显示分支领先 `origin/oreans/two-sample-mainline`，且**没有执行过 push**（`git reflog` 里无 push 记录）。

## 交付格式

写到 `runs/20260829-TASK-002.md`，粘贴上面每条命令的原始输出，以及 `git log --stat -8`。
第 1 条要逐个列出"保持 untracked 的目录 + 不提交的理由"。

## 停止规则

- 任一 commit 之后 `cargo check` 失败 → 停，报告是哪个 commit、缺什么。
- 发现某个未跟踪文件无法判断该不该进 Git → 停，列出来问，**不要猜**。宁可漏提交，不要把样品或产物提进仓库。
- **不要推送。** 提交完成即停，把门禁结果交给老板。
