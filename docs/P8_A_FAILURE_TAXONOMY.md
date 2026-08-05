# P8-A —— v8 gate failure taxonomy 与离线 replay harness

**状态:** 实现完成（P8-A 阶段）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程。

## 目标

把 P7-R2 `bundle_gate_report.json` 中每个 sample 的 `failures: Vec<String>` 稳定分类到九个概念桶，使 producer/gate 契约缺口可跨 revision 追踪，不依赖 failure 文本顺序或措辞。

## 九类桶（`mida_acceptance::failure_taxonomy::TaxonomyBucket`）

| 桶 | label |
|---|---|
| PrerequisiteSurvivalStructural | prerequisite/survival/structural |
| StructuredPe | structured-pe |
| Oep | oep |
| IatUnresolved | iat-unresolved |
| IatFinalImportMapping | iat-final-import-mapping |
| Tls | tls |
| Relocation | relocation |
| SectionRebuild | section-rebuild |
| Behavior | behavior |
| IsolatedReplay | isolated-replay |
| Other（未知 failure，永不静默丢弃） | other |

## P7-R2 真实失败分类结果（只读现场，用临时程序验证，未提交真实数据）

| 桶 | origin_macro (337) | lunlun_software (1504) |
|---|---|---|
| prerequisite/survival/structural | 4 | 4 |
| oep | 9 | 9 |
| iat-unresolved | 0 | 1423 |
| iat-final-import-mapping | 298 | 43 |
| relocation | 4 | 4 |
| section-rebuild | 18 | 17 |
| behavior | 3 | 3 |
| isolated-replay | 1 | 1 |
| other | 0 | 0 |

分类结果与 P7-R2 暴露的工程缺口一致：origin 缺 OEP 字段（9）与 IAT final-import mapping（298，296 resolved 映射 + 2 final imports）；lunlun 缺 IAT unresolved（1423）与 final-import（43）。

## 设计

- `classify(&str) -> TaxonomyBucket`：确定性、顺序无关，一个字符串恒映射到一个桶。
- `summarize(&[String]) -> BTreeMap<TaxonomyBucket, usize>`：计数，BTreeMap 保证顺序稳定。
- 未知 failure 归 `Other` 且计入总数，绝不静默丢弃。
- 纯词法、保守分类：不重派生 gate 决策，只对已产出的 failure 文本分桶。

## 负例覆盖（单元测试）

- 顺序无关：同一组 failure 不同排列 → 相同摘要。
- 重复 failure 计数。
- 未知 failure → Other 且计入总数。
- 空 failure 列表 / 空串 → 空摘要 / Other，不 panic。
- 字段缺失风格（无 token）→ Other。
- relocation 带 "prerequisite failed:" 前缀仍归 relocation（不误入 generic prereq）。

## synthetic / normalized replay fixture

默认测试**只使用仓库内 synthetic fixture**（`failure_taxonomy` 模块的测试内联构造 synthetic failure 字符串），不读取 D:/MidaVault，不包含任何真实 candidate / sample / 原始 sidecar。P7-R2 现场只读用于一次性人工分类验证（临时程序位于 P7-R2 执行根 scratch，未提交，未写入 P7-R2 execution root）。

## 明确 pin

- 本阶段不处理 **behavior oracle**、**isolated replay 10/10**、**最终验收**（它们不属于本批修复，v8 gate 仍可因此保持 open）。
- 本阶段只建立 failure 分类与离线 harness，**不修改任何 producer / gate / PE emission 逻辑**（那些在 P8-B..F）。
