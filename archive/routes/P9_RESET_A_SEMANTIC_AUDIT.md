# P9-RESET-A: Acceptance Semantics Audit and Decision Record

> Work order: P9-RESET (withdraw live, no sample started). Audit-only.
> No real sample process launched; no live slot consumed; validation_summary.json
> untouched; P7 execution roots untouched.

## 起始状态

- 主 worktree HEAD：`3e76a67e216fad349ee650125746b5cd86598164`
- P9 candidate detached revision：`169c122a571207a36f1f48020b9c6622bff74640`
- 历史 P7 baseline revision：`858f66e`
- validation_summary.json blob：`cf72b7a073fd639e23231da6b4a2b4c5768fa077`（未变）

## 唯一语义结论

> **SEMANTICS_B_PROTECTED_VS_CANDIDATE**

P9 验收的是 **protected sample behavior vs candidate unpacked output 的行为保持**，
**不是** baseline revision vs candidate revision 的真实 A/B 回归。历史 P7-R2 的
`baseline`/`candidate` 是两个**代码 revision**（`858f66e` vs `c8258b3`）解包**同一个
protected sample** 的工具链修复验证，不是 P9 的验收语义。

## 目标语义矩阵

| # | 项目 | 原始要求 | 当前实现 | 是否一致 | 证据 |
|---|---|---|---|---|---|
| 1 | baseline revision 是否验收对象 | **否**（Gate A–G 无 baseline-revision 对照） | 否（授权 manifest `baseline/protected revision = NOT_USED`） | ✅ | OREANS 计划 Gate F/G；P9_LIVE_AUTHORIZATION_MANIFEST |
| 2 | candidate revision 是否验收对象 | 是（作为 unpack 工具链 revision，其正确性由 protected-vs-candidate 证明） | 是（`169c122a`） | ✅ | P9_PREP_E；P9_LIVE_0 |
| 3 | protected sample 角色 | reference behavior input（Gate F） | reference（`protected_input` 身份绑定） | ✅ | oreans_gate.rs `protected_input`；计划 Gate F |
| 4 | P7-R2 baseline/candidate 结果计入 P9 | **否**（历史 live smoke） | 否（`NOT_USED`；仅 taxonomy 回归） | ✅ | P7-R2 报告；P9_PREP_E §2 |
| 5 | P9 replay 是否同一 candidate 10 次 | 是（10 独立 run reproduce reproducible candidate，同 runner config） | 是（ledger 要求 candidate digest 相同、runner_config_digest 相同） | ✅ | 计划 Gate G；P9_PREP_C |
| 6 | behavior oracle 是否 protected 与 candidate 同 stimulus | **是** | 是（`require_identical_stimulus_plan`） | ✅ | 计划 Gate F；P9_PREP_A |
| 7 | final candidate 是否与 baseline 直接比较 | **否**（与 protected reference behavior 比较） | 否 | ✅ | 计划 Gate F；P9_PREP_A |
| 8 | v8 gate candidate identity 语义 | candidate = unpack 输出 artifact，绑定 protected | 是（`OreansArtifactIdentity` protected/candidate） | ✅ | oreans_gate.rs |
| 9 | "A/B" 名称是否准确 | **不准确**（P7 是工具链 revision 对照，非 A/B 验收） | 部分沿用 "baseline/candidate" 命名（P7-R2 上下文） | ⚠️ 措辞 | P7-R2 报告 §2；P9_PREP_E 已是 protected/candidate |
| 10 | 最终 acceptance 必要证据 | 结构化域 + behavior + replay + bundle + verifier | 结构化 OEP/IAT/TLS/reloc/section + behavior oracle + survival/structural + replay 10/10 + two-bundle consumer | ✅ | P9_PREP_A/B/C/D |

## 逐项审计证据

1. **计划文档（唯一权威原始规格）**：Gate F（L216-227）"runs the protected
   input and the unpacked candidate under the same controlled stimulus and
   compares the agreed observable results"；Gate G（L229-244）isolated replay 10
   次、同 runner config。全文**无 baseline-revision vs candidate-revision 验收对照**。
2. **P7-R2 报告**：baseline=worktree @`858f66e`、candidate=worktree @`c8258b3`，
   四组合解包**同一 protected sample**，候选字节一致（origin `f6cc3dcf`、
   lunlun `168dddeb`），仅 IAT slot-0 差异（"预期修复，非回归"）。这是工具链
   revision 修复验证，不是 P9 验收语义。
3. **oreans_gate.rs**：observation 绑定 `protected_input` 与 `candidate`（同一
   `OreansArtifactIdentity` 结构）；无 baseline revision 概念。
4. **P9-Prep A/B/C/D/E**：全部 protected/candidate 措辞，无 baseline 验收语义。
5. **授权 manifest + P9-Live-0**：`baseline/protected revision = NOT_USED`，单一
   candidate revision 绑定；protected 作为 reference，candidate 作为待验证输出。

## 是否修改了合同

**否（本阶段仅审计 + 决策记录）**。语义已一致为 B；P9-RESET-B 将做最小措辞/合同
收口（见下一 commit）。

## 当前 P9 live 状态

- P9 live 授权视为**撤回**，本工单不启动任何样品、不重新申请。
- 0 live process / 0 slot 使用。
- validation_summary.json 未变（blob `cf72b7a`）。
- P7 roots 未修改。
