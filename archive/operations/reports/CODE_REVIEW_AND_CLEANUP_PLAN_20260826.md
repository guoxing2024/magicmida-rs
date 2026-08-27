# MagicMida vNext 代码评审与净化方案

> **执行记录（2026-08-26）**：批次 0-4 已全部执行完毕，落在 `oreans/two-sample-mainline` 的三个提交中：
> `0cdfa4f`（批次1：已跟踪垃圾+evidence_staging）、`511c7bf`（批次3：文档治理）、`951104a`（批次4：死代码+收敛+lints）。
> 执行后状态：分支 24→7、根目录文件 ~70→16、docs 174→31、evidence_staging(72MB) 已删除、cargo check 全绿且无新增警告。
> 未动项：你的 4 个未提交改动保持原样；5 个有独立提交的 WIP 分支待你裁决；16 个文件的既有 fmt 债务未混入本次提交。
> 注：批次3 实际执行时，8 个**已跟踪**的 WORK_ORDER_* 按 R5 建议归档至 `archive/operations/work-orders/`（比计划中的删除更保守）。

---

> 承接 `../audits/TEAM_AUDIT_REPORT_20260826.md`（安全审计）。本文覆盖：① 未提交改动 PR 式评审 ② 全仓代码质量评审 ③ 净化执行方案。
> 评审团队：R1 架构边界 / R2 死代码坏味 / R3 惯用法错误处理 / R4 测试质量 / R5 文档体系 + Lead（diff 评审、分支分析）。

---

## 一、未提交改动 PR 评审（4 文件，+225/-4）

| 文件 | 结论 |
|---|---|
| `tools/build_gto_live_cli.ps1` | ✅ 质量好。新增 RuntimeAuthorityManifestPath/RuntimeDllPath 必填参数（缺失即 throw，fail-closed）；SHA-256 校验 manifest↔DLL 绑定；构建后验证常量确实注入二进制。小问题：attestation 记录本机绝对路径（延续既有卫生问题）；`ConvertFrom-Json` 无显式 try/catch（靠 $ErrorActionPreference=Stop 兜底，可接受） |
| `tools/gto_live_route_controller.py` | ✅ 质量好。3 个 runtime-authority 变量加入 allowlist 直通白名单，record-only 语义正确（不改变 ok 判定），注释清晰说明 compile-time mirror 性质 |
| `tools/test_gto_live_route_controller.py` | ✅ 质量好。两个新测试含正反用例 + env 泄漏负向测试 + finally 恢复环境。小瑕疵：mkdtemp 未清理 |
| `lab/cases/v2/gto_launcher.json` | ⚠️ **需授权依据**。README 声称此密封清单「untouched、revision 仍在裁定」；本次将 `manifest_revision` 2→3、`protection_family` unknown→`ahk_gto_candidate`。虽然样本 SHA-256 未变、标签措辞诚实（candidate），但按 GTO_SAMPLE_REVISION_POLICY 应有对应的 reviewed manifest revision 工单。**建议：确认授权来源后再提交，或在提交信息中引用授权工单** |

## 二、全仓质量评审汇总

### 2.1 总体评价

工程质量**高于同类项目平均水平**：依赖方向零违规、策略模式落地正确、acceptance 独立验收核名副其实、生产 panic 面极小、2739 个测试断言强度普遍是行为级、pub fn 文档覆盖率抽样 100%。主要债务集中在：**超大单体文件、110 处 dead_code 豁免、安全关键函数零直接测试、文档/工单体系无治理机制**。

### 2.2 架构（R1）

| 严重度 | 发现 | 建议 |
|---|---|---|
| 高 | `raw_slab_coherence.rs` 18990 行单文件（435 fn 中 330 是 test） | 拆核心逻辑（~3k行）与测试/夹具 |
| 高 | `packers/themida/src/lib.rs` re-export 60+ 符号，god-crate 苗头 | 收敛为 ThemidaPlugin + 少数顶层入口 |
| 中 | `cli/src/lib.rs` 10 个 pub mod 全公开（仅为共享实现给 tests/main） | pub(crate) + 薄门面 |
| 中 | `runner_preflight.rs` 246KB 三重职责（producer/verifier/launch gate） | 拆 preflight/{producer,envelope,launch_gate} |
| 中 | `helpers.rs` 混路径安全与通用工具（垃圾桶模块） | 抽出 path_security.rs |

正面：PackerPlugin trait 定义于 core、packer 实现、cli 消费，方向正确无反向依赖；feature 门控双重 fail-closed；acceptance 仅依赖 serde/sha2/thiserror。

### 2.3 死代码（R2）——净化直接输入

**A 级（证据充分可删）**：
- `crates/pe/src/dumper/global_vars.rs` 整模块（196行）— 三处成员 allow(dead_code)，唯一引用是下划线未用参数，注释自证 "not yet used"
- `crates/pe/src/dumper/data_snapshot.rs:60` `capture_data_section` 函数（producer 已死；同文件的 restore 路径仍活，不能删整文件）
- 4 个死 `SCHEMA_VERSION` 常量：oep_evidence.rs:18、tls_evidence.rs:16、section_rebuild_evidence.rs:15、exception_evidence.rs:21
- `crates/pe/src/relocation.rs:21` 私有 `RelocationBlock` 结构体

**B 级（疑似，需逐项确认）**：data_snapshot 的 SkipRegion、antidebug_controller 的 digest_authority（IMP-08 计划相关）、OracleMode.ini_path（ADR-7 占位）、x64_asm 零散 Mem 构造器（不能删整模块）、iat/fix.rs 兼容 shim、iat/boundaries.rs legacy discovery、runner_preflight legacy wrapper 等 9 项。

**坏味模式**：6 个 *_evidence.rs 各自私有定义完全相同的 `ArtifactIdentity` 结构体——应收敛进 evidence_schema.rs（顺带消灭 4 个死常量）。

**重要排除**：MidaAntidebugInitialize(v1)、origin_pure.rs、walker 三件套、x64_asm 主体均确认是活代码，**不是**清理对象。

### 2.4 惯用法与错误处理（R3）

- 生产 panic 面极小：粗扫热点实测绝大多数在 #[cfg(test)] 内；真正生产的只有锁中毒 panic（合理）与不变式断言
- M-1：v1 FFI 路径的 `try_into().unwrap()` 缺 v2 式 OOB 预检（同安全审计 H-1 病灶）
- M-3：pe crate 110 处 `#[allow(dead_code)]` 掩盖真实回归
- M-4：7 处 `let _ = fs::remove_dir_all(...)` 吞错（清理路径，建议 tracing::warn）
- 缺 `[workspace.lints]`：报告给出可直接粘贴的建议配置（unwrap_used/expect_used=warn、print_stdout=deny 等）

### 2.5 测试（R4）

- 规模：~2739 个 #[test] / 59 个测试二进制，CI 双 lane 门禁有效，历史全绿
- 🔴 **安全关键函数零直接测试**：`resolve_output_path`、`sidecar_io::atomic_write`、`ensure_sidecar_is_safe` 全仓测试 0 命中——最敏感的路径保护逻辑没有针对性测试
- 🟠 raw_slab_coherence.rs 单文件 330 测试导致 mida-pe 测试二进制 57.5s 最慢；11 处 thread::sleep 固定等待有 flake 风险
- 11 个无直接测试的生产模块清单见原报告（helpers/sidecar_io/dump 优先）

---

## 三、净化执行方案（分级，待确认后执行）

### 第 0 步【必做前置】：解除 detached HEAD
```
git branch -f oreans/two-sample-mainline HEAD   # 主线快进到当前 HEAD（含47个新提交）
git checkout oreans/two-sample-mainline         # 后续所有净化提交落在主线上
```

### 批次 1【git 可恢复，建议直接执行】—— 已合并分支 + 已跟踪垃圾文件
**删 16 个已合并分支**（保留 two-sample-mainline 作为唯一主线）：
baseline/legacy-recovery-20260722、claude/*×5、codex/gto-product-recovery-route-a、codex/gto-route-{a-candidate-metadata,b,c,d,e,f,g,h}-r1、oreans/impl-phase01/02/03、t0-closeout

**保留评估的 5 个未合并分支**（各有 1-14 个独立提交）：adr7-b4-instrumentation-1(4)、codex/a2-ep-only-optionalheader(3)、codex/b0-a0-a1(2)、codex/imp09-carrier-r5-r2(1)、research/gto-bootwatch-20260728(14)

**git rm 已跟踪垃圾**：
- 根目录：`workspace_full_test.txt`(236KB)、`r5r2_correction_fmt_check.txt`(148KB)、`HANDOFF_PROMPT_H6_LIVE1.md`
- `evidence_staging/` 下被跟踪的 8 个 cargo 输出 txt（106–235KB）
- 根目录已跟踪的旧批次工单：WORK_ORDERS_BATCH_2~13(+_13_REVIEW)、WORK_ORDERS_CORRECTION.md、WORK_ORDERS_IMPLEMENTATION_PHASE_01/02

注：master 分支落后且与 origin/master 分叉，本轮不动（GitHub 默认分支指向它）。

### 批次 2【不可恢复，均为过程产物】—— 未跟踪垃圾直接删除
- 根目录未跟踪工单：WORK_ORDERS_BATCH_14~32、WORK_ORDERS_IMPLEMENTATION_PHASE_01/02、WORK_ORDER_IMP-09-CARRIER-R5-R2*（含 CORRECTION-2/3/4）、WORK_ORDER_IMP-09-CARRIER-R5-R3-*、WORK_ORDER_IMP-09-R5-R3-DISPATCH、WORK_ORDER_IMP-09-DISPATCH-BRIDGE-DESIGN/IMPL、WORK_ORDER_IMP-09-DISPATCH-WIRING、WORK_ORDER_PROTOCOL_RESET、WORK_ORDER_WO-1401-R1
- 输出残留：audit_dispatch_out.txt、r5r2_independent_mida_cli_lib.txt、r5r2_independent_subset.txt、r5r3_test_output.txt
- 本地日志（已被 ignore）：r1_capture.log(344KB)、r3_capture.log(235KB)、fmt_check.log(145KB)
- 编码损坏脚本：t_b2.bat（GBK 乱码，功能与 build_with_msvc.bat 重复）
- 评审中间产物：TEST_QUALITY_REVIEW.md（内容已并入本报告）

### 批次 3【文档治理】—— 按 R5 三级清单
- **A 类删除**：docs/ 下批次审计快照 ~40 个（AUDIT_BATCH15~31、AUDIT_SCHEMA_*、AUDIT_PROTOCOL_CALLERS_*、AUDIT_V2_ARITHMETIC_*、AUDIT_RC1、AUDIT_EVIDENCE_*）、SUPERSEDED.overlay ×3、GTO_H5 过程修正单 ×5
- **B 类归档**至 `archive/operations/{work-orders,reports,audits}/`：GTO_H4/H5/H6_* 实验报告、GTO_COLD_START_* 系列、IMP09_* 设计/报告、WO-10xx~26xx 已完结设计单、PROJECT_HANDOVER、ADR7_B4/B5/CLOSEOUT 等
- **C 类保护名单**（绝不动）：README、ARTIFACT_POLICY + docs/ 下 13 个权威文档 + 被 dd_restore.py 引用的 GTO_H5_STARTUP_ORDER/GTO_R6_A1_DD_RESTORE 两份（留原位否则断引用）
- 新增 `docs/README.md` 权威文档索引；`.gitignore` 增补 `WORK_ORDER*.md`、`HANDOFF_PROMPT*.md` 从源头拦截
- 顺手修死引用：tools/_behavior_bb_gate.py 引用的 `ACCEPTANCE_CONTEACT.md`/`VNEXT_BEHAVIOEAL_PATH.md` 拼写错误

### 批次 4【代码净化】—— R2 A 级死代码 + 配套修复
1. 删 global_vars.rs 整模块 + data_snapshot.rs:60 死函数 + 4×SCHEMA_VERSION + RelocationBlock
2. 收敛 6 处重复 ArtifactIdentity 到 evidence_schema.rs
3. 删 Cargo.toml 陈旧 `exclude=["crates/bwhook"]`
4. 加 `[workspace.lints]`（R3 建议配置）
5. 每步后 `cargo check --workspace --tests --offline` 验证（需 MSVC 环境）

### 批次 5【72MB 大头，二选一】—— evidence_staging/
按 ARTIFACT_POLICY 证据应入金库不入 Git。选项：**(a)** 移动到 `D:\MidaVault\lab\evidence\staging-20260826\` 后清空仓库内目录；**(b)** 确认金库已有副本后直接删除。

### 明确不动的
- crates/ 全部源码主体、tests/、lab/cases/、ci.yml、deny.toml、archive/routes 与 archive/gto-20260730（既有正确归档）、B 级死代码候选（待逐项确认）

---

## 四、预期效果

| 维度 | 现状 | 净化后 |
|---|---|---|
| 本地分支 | 24 个 | 6 个（主线 + 5 个待决 WIP）→ 你裁决后更少 |
| 根目录杂物 | ~70 个文件 | 干净的 Cargo.toml/README/配置 + 少量入口 |
| 仓库体积 | evidence_staging 72MB | 视批次 5 选择，最大减 72MB |
| docs/ | 174 个文件混排 | ~20 个权威文档 + 索引 |
| 死代码豁免 | 156 处 allow(dead_code) | 先消 A 级，B 级逐项裁决 |
