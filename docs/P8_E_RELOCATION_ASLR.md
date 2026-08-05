# P8-E —— Relocation/ASLR 证据闭环

**状态:** 实现完成（P8-E 阶段，两个 commit：`731e2b1` DYNAMIC_BASE emission；本 commit evidence 侧）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程。

## P7-R2 暴露的 4 个 relocation failure 与根因

`origin_macro` 与 `lunlun_software` 各有 4 个 relocation failures，逐一分析：

| # | failure | 根因 | 修复 |
|---|---|---|---|
| 1 | `runtime relocation image identity disagrees with PE evidence` | `observe_relocations_runtime` 的 `preferred_image_base` 用了运行时 `pe.image_base`（ASLR 加载基址），而非磁盘 preferred base。gate 要求 `runtime.preferred_image_base == pe_evidence.image_base`（磁盘基址）。 | `preferred_image_base` 参数化，dump_process 从磁盘 PE（`opts.executable_path`）读取磁盘 image_base，无磁盘 PE 时 fallback `pe.image_base`。 |
| 2 | `final relocation DYNAMIC_BASE is not set` | `header_patch` 无条件清除 `DYNAMIC_BASE`；`dump_process` pure-rebuild 设 `prefer_aslr_when_relocs: false`。候选永远丢 ASLR。 | (commit `731e2b1`) `header_patch` 仅对 fixed-base 输入清 DYNAMIC_BASE；`dump_process` 的 `prefer_aslr_when_relocs` 镜像 post-patch DYNAMIC_BASE 位。 |
| 3 | `relocation preservation comparison disagrees with recomputation` | producer `compare_runtime_final` 的 `preservation.blockers` **未排序去重**，而 gate `recompute_relocation_preservation` 排序去重 → 两者逐字段不相等。 | `compare_runtime_final` 返回前对 preservation.blockers 调 `stable_blockers`。 |
| 4 | `relocation blocker lists must be sorted and deduplicated` | 同 #3：producer 的 `preservation.blockers` 未排序去重，gate `stable_blocker_list(&evidence.preservation.blockers)` 返回 false。 | 同 #3。 |

## 数据流与可重算性

```
runtime：observe_relocations_runtime(pe, load_base=ASLR, preferred_base=磁盘基址)
  → RelocationObservationReport{ runtime_image_base, preferred_image_base, targets... }
final：parse_final_candidate(candidate_bytes) 从最终 PE 独立解析
preservation：compare_runtime_final(runtime, final)（blockers 排序去重）
simulation：simulate_aslr(final)
```
- target set / 原值 / 应用值 / normalized：runtime targets 记录 observed + normalized；final 从 candidate 重读；preservation 对比（长度 + block/entry/target_rva/type + normalized）。
- producer 与 gate 独立实现相同逻辑（gate 的 `recompute_relocation_preservation` 独立重算），修复后逐字段一致。

## 测试

- **mida-cli（P8-E，`relocation_evidence.rs`）**
  - `preservation_blockers_are_sorted_and_deduplicated`：多 blocker 场景，验证输出排序去重（canonical blockers）。
  - `matching_dynamic_base_passes_preservation`：runtime 与 final 都设 DYNAMIC_BASE → preservation 通过（验证 emission 修复后的正确行为）。
- mida-pe + mida-cli + mida-acceptance 全部现有测试通过（无回归）。

## 明确 pin

- behavior oracle / isolated replay 10/10 / 最终验收仍不属本批。
- 真实样品的最终重跑验证在 P8-QA（有授权时）；本阶段以 synthetic + 现有 gate 测试确认修复语义。
