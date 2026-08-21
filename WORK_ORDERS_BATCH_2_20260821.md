# 工作单批次 2 — 2026-08-21（总指挥签发）

**签发人**: 项目总指挥（接任）
**执行人**: 唯一 worker
**依据**: 2026-08-21 接手审计（fmt PASS；MSVC 全量测试 2248 passed / 0 failed / 1 ignored / 1 doctest failed；基线与账本吻合）

---

## 约束（全部工单适用，违反即作废）

- ❌ 禁止运行真实样本（GTO-H5-LIVE-AUTHORIZATION-2 未签发，修码冻结对生产路径有效）
- ❌ 禁止推送（push）、禁止改写 git 历史、禁止删除任何分支（`codex/gto-route-*` 是治理锚点）
- ❌ 禁止修改 `D:\MidaVault\lab\evidence\` 封存证据、ADR7 验证器、Oreans 两样本门
- ❌ 提交信息不得声称 CLOSED / DELIVERED / FORMAL PASS（除非账本 §8 已有对应 formal acceptance 行）
- ✅ 构建/测试必须走 MSVC 环境：vcvars64.bat 或 `build_with_msvc.bat`（普通 PowerShell 因 link.exe 缺 PATH 会失败——已实证）
- ✅ 每单提交前门禁：`cargo fmt --all -- --check` + `tools/verify_workspace_hygiene.ps1` + 对应测试

---

## WO-101（P0）入库已审计的修正批次

**状态**: READY · **预计**: 1h

1. 将当前工作区改动分两个本地提交入库：
   - 提交 1 `docs(gto): WO-001 audit corrections — honest stage states`：
     `GTO_DELIVERY_FINAL_2026-08-21.md`、`docs/GTO_COLD_START_HEAP_REBASE_1_BOUNDARY.md`、`docs/GTO_AUDIT_CORRECTION_2026-08-21.md`、本文件、`WORK_ORDERS_CORRECTION.md`
   - 提交 2 `docs(gto): WO-002 rdata root cause + WO-004 verification record`：
     `docs/GTO_H5_RDATA_DEFECT_ROOT_CAUSE_INVESTIGATION.md`、`docs/GTO_WORKSPACE_VERIFICATION_2026-08-21.md`、`build_with_msvc.bat`、`test_with_msvc.bat`
2. 同步更新精确测试基线数字：账本 §7 与 `GTO_WORKSPACE_VERIFICATION` 由 "~2256" 改为 **"2248 passed / 0 failed / 1 ignored / 1 doctest failed（b5_tls_capture.rs:17，既有缺陷）"**，注明复核日期与环境（vcvars64 + cargo test --workspace --offline）。
3. bat 文件头部加注释注明为本机辅助脚本（硬编码 VS Professional 路径）。

**验收**: 工作区 clean（除新工单产物）；两个提交存在；无 push。

---

## WO-102（P1）H5 修复路径设计（仅设计，禁止实现）

**状态**: READY · **前置**: 无（WO-002 已完成）· **预计**: 4h

基于 `docs/GTO_H5_RDATA_DEFECT_ROOT_CAUSE_INVESTIGATION.md` 的结论
（节特性忠实复制非缺陷；真正问题 = 节内容为含未解密加密区的运行时快照 +
TLS0 后进入 .boot stub 而非原始入口链），评估
`docs/GTO_H5_LOADER_WALL_ROOT_CAUSE.md` §3 四条候选路径：

(a) 去 .rdata0/.rdata1/.rdata2 EXECUTE 特性；(b) 运行时解密 .rdata 内容；
(c) entry 重定向到原始 Themida 入口链（绕过/修正 .boot stub）；(d) 观察宿主采集受保护程序自身解密行为。

权衡标准：① 是否依赖我们不掌握的 Themida 内部知识；② 能否离线验证；
③ H0 约束符合性（无 bypass/无写入目标/不窃取先前状态）；④ 对 ADR7 与 Oreans 门的影响半径。

**输出**: `docs/GTO_H5_LOADER_FIX_PATH_DESIGN.md`，必含：
推荐路径+理由、拒绝路径+拒绝理由、fail-closed 规则（dumper 无法区分代码 vs 加密数据时的行为）、
需触碰文件清单、离线单元测试方案、"仍需真实授权项"清单、Oreans 门影响评估。

**验收**: 推荐路径有离线验证方案；fail-closed 不依赖猜测；零代码改动。

---

## WO-103（P2）工作区卫生

**状态**: READY（可与 WO-102 并行，分开提交）· **预计**: 2h

1. 修复既有 doctest 缺陷：`crates/core/src/b5_tls_capture.rs:17` 用 ```text 围栏或等价手段使 doctest 可编译；**禁止改动任何函数行为**。验收：`cargo test -p mida-core --doc` 全绿。
2. 清零 15 个 clippy 警告（已知点：`crates/pe/src/dumper/global_vars.rs:17` 未使用字段、`crates/pe/src/dumper/tls_bootstrap.rs:54-55` 未使用常量）。删除前确认字段/常量确无引用（含 `--all-features`）。验收：`cargo clippy --workspace --all-targets` 0 warning，且全量测试仍 2248+/0 fail。
3. 本地复验 CI 双 lane（CI 有 `RUSTFLAGS=-D warnings`）：`cargo check --workspace --tests --offline` 与 `cargo check --workspace --all-features --tests --offline` 均 0 error/warning。
4. 删除调试残留目录 `crates/cli/gto_launcher/cccc…c/`（内含 snapshot.bin）。
5. 更新 `docs/GTO_WORKSPACE_VERIFICATION_2026-08-21.md` 附记本次卫生结果。

---

## 并行轨道（非 worker 任务，记录在案）

- H4-A/B/C 正式签核 PENDING —— 等 owner（行国胜）审阅，worker 不做任何动作；
- H5 解锁需新签 `GTO-H5-LIVE-AUTHORIZATION-2`；在此之前 H5 只进设计不进行码。

---

**执行顺序建议**: WO-101 →（WO-103 ‖ WO-102）
**签发**: 项目总指挥 · 2026-08-21
