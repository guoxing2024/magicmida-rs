# P8 —— 工程缺口修复 出口报告（P8-QA）

**状态:** 实现完成（P8-A → P8-F → P8-QA）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程。
**HEAD 基线:** `c8258b3`（P7-R2 起始）
**提交:** P8-A `0e65020`、P8-B `e675933`、P8-C `e78a5f5`、P8-D `d2aaab4`、
P8-E `731e2b1`+`1d6f67a`、P8-F `59bfb58`

## 验收命令结果

```
cargo test --workspace --offline
  → EXIT 0，911 个测试全部通过，无 FAILED
```
各 crate：mida-pe 219、mida-cli 152、mida-core 72、mida-packers-themida 121+、
mida-acceptance 56+（lib + 全部集成测试）。

## 交付物（commit → 文档）

| 阶段 | commit | 文档 | 内容 |
|---|---|---|---|
| P8-A | `0e65020` | docs/P8_A_FAILURE_TAXONOMY.md | v8 gate failure 九桶分类器 + 离线 replay harness |
| P8-B | `e675933` | docs/P8_B_OEP_PROVENANCE.md | OEP runtime provenance 传播（修复 unknown 丢 VA） |
| P8-C | `e78a5f5` | docs/P8_C_IAT_FINAL_IMPORT.md | import directory terminator 修复 + Origin 正例 |
| P8-D | `d2aaab4` | docs/P8_D_IAT_FINAL_IMPORT_CONSISTENCY.md | final_imports 一致性 + Lunlun 负例语义 |
| P8-E | `731e2b1`+`1d6f67a` | docs/P8_E_RELOCATION_ASLR.md | DYNAMIC_BASE 保留 + preferred_image_base + canonical blockers |
| P8-F | `59bfb58` | docs/P8_F_SECTION_REBUILD.md | section 生产契约闭环（duplicate/absent/SizeOfImage） |

## 根因修复摘要

| P7-R2 failure 类 | origin | lunlun | 修复阶段 |
|---|---|---|---|
| OEP evidence（source/VA/RVA 丢失） | 9 | 9 | P8-B（av_oep_handler valid-x64-code 分支用 trace 保留 VA） |
| IAT final-import（final_imports 空） | 298 | 43 | P8-C（import directory size 含 terminator） |
| IAT unresolved | 0 | 1423 | P8-D（Lunlun 负例语义，保持 fail-closed） |
| Relocation（DYNAMIC_BASE/image identity/blockers） | 4 | 4 | P8-E（emission + evidence 双侧修复） |
| Section（duplicate/absent/SizeOfImage） | 18 | 17 | P8-F（producer/validator 逐字段一致） |

## 端到端 synthetic 证明

- P8-A：分类器对 P7-R2 真实 failures 100% 归入明确桶（Other=0，临时程序验证，未提交真实数据）。
- P8-B：`sync_plugin_milestones`/`record_oep_provenance` 离线测试证明 runtime OEP provenance
  （source/VA/RVA）正确传播到 post-loop sidecar。
- P8-C：`emission_end_to_end_parse_final_imports_reconstructs_target_set`
  builder → create_import_section → 完整 PE → parse 完全一致。
- P8-D：`unresolved_zero_slots_do_not_produce_final_imports` 证明 mixed 场景下 unresolved 隔离。
- P8-E：`preservation_blockers_are_sorted_and_deduplicated` + `matching_dynamic_base_passes_preservation`。
- P8-F：`duplicate_section_names_fail_closed` + `absent_directories_are_canonical_when_zero`。

## 仍未解决（明确 pin，非本批修复）

| 项 | 说明 |
|---|---|
| behavior oracle | v8 gate 的 behavior 验证（stimuli/observables/NotRun）——P8 工单明确 pin |
| isolated replay 10/10 | 需要 10 次隔离 replay——P8 工单明确 pin |
| process survival | P7-R2 origin 报 process survival 失败——需真实重跑确认环境/样本性质 |
| survival/structural evidence artifact_sha256 | 报 sha256 非 64-hex——需真实重跑验证（修复后 candidate sha256 变化） |

## 出口状态

本批 P8 交付完成 P8-A..F 的全部工程缺口修复。由于**未授权真实样品启动**，下列只能待授权后验证：
- OEP/IAT/Reloc/Section evidence 在真实候选上逐字段通过 v8 gate
- behavior oracle、isolated replay 10/10、最终两样本 gate 通过

工程侧已具备：完整 workspace 911 测试通过 + synthetic 端到端 + producer/validator 逐字段一致。
