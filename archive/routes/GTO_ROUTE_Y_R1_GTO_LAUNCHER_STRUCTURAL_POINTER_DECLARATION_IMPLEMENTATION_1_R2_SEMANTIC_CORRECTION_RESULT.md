# RouteY_R1_GTO_LAUNCHER_STRUCTURAL_POINTER_DECLARATION_IMPLEMENTATION_1_ROUND_2_SEMANTIC_CORRECTION — Final

**Status:** `RouteY_R1_GTO_LAUNCHER_STRUCTURAL_POINTER_DECLARATION_IMPLEMENTATION_1_ReviewRequested` (Round 2, final)
**Authorization:** `..._Round2SemanticCorrectionAuthorized` — this is the SECOND and FINAL implementation round.

## 语义修复（本轮核心）

| 规则 | R1（缺陷） | R2（修复后） |
|---|---|---|
| 值在捕获区域内 | structured_heap_pointer（仅 membership） | **unknown+required**，除非有结构性 provenance |
| 值在模块范围内 | module_relative_candidate（仅 membership） | **unknown+required**，除非有结构性 provenance + 已验证模块范围 |
| 值 ≥ 0x7ff0（threshold） | module_relative_candidate | **unknown+required**（threshold-only，永不进入 module-relative） |
| 排除 | 阈值判定 | 仅带证据排除（UTF-16 形状/tag 编码/非对齐 small） |

**核心规则**：slot 成为 pointer kind 必须同时满足 structural_provenance_present AND target_membership_or_resolver_evidence_present。

## Threshold-only（2,270 唯一槽）

全部 → **unknown + required=true**（`threshold_only_crosswalk.json` 逐项列出 2,270 条），无批量升级。

## 测试

**788/788 通过**（`cargo test -p mida-pe --lib --offline`，raw SHA `685AAEC…`）：771 既有 + 9 R1 + 8 R2。
6 个强制负向测试（in_region/in_module_scalar_collision、threshold_only_high/low、module_range/capture_region_without_provenance）全部断言 kind=unknown、required=true、excluded=false、plan_validation_does_not_gain_false_success=true；2 个正向测试（true_structured_heap_pointer_with_provenance、true_module_relative_candidate_with_provenance）通过。

## Fresh no-bypass reproduce（1 次，允许）

`MIDA_GTO_NO_BYPASS=1` 下 `mida-cli /unpack <4d5770af> --profile=ahk-gto-experimental ...`：

- **pointer_declaration 阶段 fail-closed：3,615 个 duplicate-conflict slot**。
- 含义：R2 语义**正确检测**同一物理 slot 从 slab blob（无 provenance→unknown）与 heap-global 根（有 provenance→pointer kind）扫描出不同 kind → **冲突 → 终止 fail-closed**（工单要求的冲突处理）。R1 静默合并；R2 按指令 fail-closed。这是诚实且安全的结果。

## Validator 语义

`is_unresolved_required` / `validate_runtime_rebase_plan` / `classify_declared_slot` / `DeclaredPointerSlot` 零改动。仅声明来源语义变更。

## 最终冻结时序（严格）

```
final_status (08:28:47) < final_report (08:29:01) < manifest (08:30:02.938)
< sidecar (08:30:03.002) < selfcheck (08:30:03.071) < freeze_after (08:30:03.387)
```
manifest SHA `a889298e…`，selfcheck PASS（21/21），freeze_after 精确排除（非 hash payload）。

## 证据根

`D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_structural_pointer_declaration_implementation_1_r2_semantic_correction_20260814T081214Z\`
（21 载荷 + 4 排除元数据文件）。原实现根与 Audit Correction 1 根均未动。

## 停机

无 production driver / A6 orchestrator / scheduled task / bypass；无 commit/push/git add。本轮为最终轮，之后不再修改 declaration pipeline。
