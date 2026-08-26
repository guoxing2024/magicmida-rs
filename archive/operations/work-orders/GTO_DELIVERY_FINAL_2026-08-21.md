# GTO 冷启动堆重定基 — 交付状态报告（修正版）

**项目代号**: GTO-COLD-START-HEAP-REBASE-1  
**修正日期**: 2026-08-21（WO-001 更正 — 本报告取代 7cc10a8 的过度声称版本）  
**总指挥**: 项目总指挥

> ⚠️ 本报告经 WO-001 修正：先前版本（7cc10a8）声称 "H4 CLOSED | H5 BOUNDED" 属于**过度声称**，
> 已撤销。真实状态见下。修正依据：边界账本 §8 实际状态 + 总指挥 WO-B 审计（8 处不一致）。

---

## 执行摘要（修正后）

| 阶段 | 真实状态 |
|---|---|
| H1/H2 | **DONE**（观察/模型/重定基原语，H2 正式签核已完成） |
| H3 | **absorbed into H4**（冷启动墙通过 H4 live runs 跨越；退出条件并入 H4 门） |
| H4-A | **TECHNICAL PASS**（3-layout 证据）— 正式签核 **NOT GRANTED（PENDING）** |
| H4-B | **TECHNICAL PASS**（证据包 PARTIAL）— 正式签核 **NOT GRANTED** |
| H4-C | **TECHNICAL PASS**（3-layout + Seal-2 PASS）— 正式签核 **PENDING** |
| H4-D | **DESIGN + LIVE RUNS COMPLETED**（P6 3/3 布局，观察通道）— **FORMAL PASS 已由 owner 签署（GTO-H4-D-P6-FORMAL-SIGNOFF.json）** |
| H5 | **BLOCKED_AT_LOADER_SMOKE**（9/9 失败；未签核；LIVE-AUTHORIZATION-2 未签发） |
| H6 | pending |

**任何阶段不得声称 "CLOSED" 或 "DELIVERED"** — 除已签署的 H2 与 H4-D formal pass 外，其余签核均未完成。

---

## 一、交付物清单（保留事实部分）

### A. 代码实现

| 模块 | 功能 | 提交 |
|-----|------|------|
| H4-A SMR | 冷启动稳定模块注册表 | 40aa715 |
| H4-B OEP | OEP 入口链证据生成 | 813894c |
| H4-C TLS | TLS 目录证据生成 | 87f38d2 |
| H4-D Exception | 异常/展开/无重定位证据 | ee2f1cb（P6 零警告） |
| IAT 递归界限 | 防止 IAT 扫描循环 | aea53f5 |

### B. 证据档案（vault，不入 git）

| 证据包 | 状态 |
|-------|------|
| H4A_smr / H4A_smr_correction | TECHNICAL PASS（3-layout） |
| H4B_oep_run2 | PARTIAL（attempt_001 raw 不可恢复） |
| H4C_tls | Seal-2 PASS（48/48） |
| H4D_exception_no_reloc + H4D_P6_corrected_final + H4D_P6_validation | P6 3/3 布局；FORMAL PASS 已签署 |
| H5_acceptance_1 / H5_crash_attribution_A / H5_resolver_causal_proof / H5_r9_origin_proof | 诊断证据（NOT ACCEPTANCE EVIDENCE） |
| H2_cross_layout_correction_1 | 已签署（GTO_H2_FORMAL_SIGNOFF.json） |

### C. 测试基线（WO-C 修正）

- **当前工作区**: 1271 passed / 0 failed / 2 ignored（2026-08-21 验证）
- 边界账本 §7 先前声称 1885 — **stale**，已更新（详见 docs/GTO_WORKSPACE_VERIFICATION_2026-08-21.md）
- cargo fmt --all -- --check: PASS
- clippy: 15 warnings（WO-005 待清理）
- ADR7 verifier: 17/17 PASS（frozen, untouched）

---

## 二、技术成就（保留 — 均为已验证事实）

### H4-A/B/C/D 技术验证（3-layout，exit 0）
319 regions / unresolved_required=0；OEP application_oep=true；TLS callbacks 完整 NULL 终止；
Exception 4570 RF / 375 EH-UH / 1510 CHAININFO / 20445 codes / 0 tail defect；no-reloc 六轴保留。

### H5 诊断（诚实状态）
- loader smoke **FAIL 9/9**（0xC0000005）
- Import/IAT DataDirectory 机制 **REFUTED**（正确偏移回填全阴性）
- runtime IAT 562/562 **IDENTICAL**（candidate vs protected）
- r9 最后写入点 **NOT PROVABLE**（加密区 0x142c1d6c3..0x142934069；静态候选全未命中）
- **根因因果链 PENDING** — 机制确认 ≠ 根因确定
- **H5 未签核；H5 不 signing**

---

## 三、验证矩阵（修正）

| 阶段 | Layout A/B/C | 指标 | 签核状态 |
|-----|----------|------|---------|
| H4-A SMR | ✅✅✅ | 319 regions, unresolved=0 | **PENDING** |
| H4-B OEP | ✅✅✅ | application_oep=true | **NOT GRANTED**（PARTIAL） |
| H4-C TLS | ✅✅✅ | callbacks 完整 | **PENDING** |
| H4-D Exception | ✅✅✅ | 4570/375/1510/20445 | **FORMAL PASS 已签** |
| H5 Loader smoke | ❌❌❌ | 9/9 AV | **BLOCKED** |

## 四、已知限制（诚实）

1. **H5 加载器墙未过**：9/9 loader smoke 失败；r9 因果链 PENDING；加密区阻止静态解析
2. **H4-A/B/C 正式签核未完成**（TECHNICAL PASS ≠ FORMAL PASS）
3. **H3 被吸收进 H4**，独立退出条件未单独记录（已在账本标注）
4. 测试基线 1885→1271 差异待 WO-004 完整解释（WO-C 已提供初步数据）

## 五、非声明（binding）

- 不声称 H4 CLOSED / H5 BOUNDED / 项目 DELIVERED
- 不声称任何未签署阶段的 FORMAL PASS
- H5 不 signing；GTO-H5-LIVE-AUTHORIZATION-2 未签发；修码冻结
- 无 bypass；ADR7 frozen；Oreans 门未动
