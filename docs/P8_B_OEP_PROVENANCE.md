# P8-B —— OEP runtime provenance propagation

**状态:** 实现完成（P8-B 阶段）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程。

## 根因（P7-R2 暴露）

P7-R2 `origin_macro` 的 OEP evidence sidecar 为：
```
source: "unknown", va: null, rva: null,
application_oep: false, bootstrap_or_ambiguous: true
```
但运行日志明确显示 OEP 已被 runtime 识别（`OEP found — ... oep=0x7ff7fac713e0`，`Structure gate: EP=0x13e0`）。

**确切断点**：`crates/packers/themida/src/runtime/av_oep_handler.rs` 中 `decide_possible_oep` 的兜底分支
（"OEP looks like valid x64 code — using as-is for non-MSVC compiler"）用
`OepProvenance::unknown(...)` 记录 provenance，**丢弃了已观察的 runtime VA**（`oep_addr`）。
该 VA 来自 `state.oep`（guard AV 的 PossibleOEP fault 地址），字节形态确认为 valid x64 应用序言
（`0x48/0x55/0x53/0x56/0x57` 或 `0x41 0x54-57`），是真实的 application OEP 候选——不是 `.text` 扫描、
不是 PE entry 反推。

`unknown` 构造不含 VA → `source=Unknown`、`va=None` → OEP evidence `application_oep=false`、
`bootstrap_or_ambiguous=true` → v8 gate 的 9 条 OEP failures 全部由此产生。

第二处断点：同函数 `decide_possible_oep` 的 "PossibleOEP without confirming trace" 分支同样用
`unknown` 丢弃已接受为 OEP 的 `address`。

## 修复

1. **valid-x64-code 分支**：`OepProvenance::unknown` → `OepProvenance::trace(va, ...)`，
   保留 runtime VA、`source=Trace`、`application_oep=true`、`bootstrap_or_ambiguous=false`、
   `oep_found_via_scanning=false`。OEP 是 runtime 观察 + 字节形态确认的 application OEP，非扫描。
2. **无确认 trace 分支**：同样改用 `trace(va, ...)` 保留 runtime VA（host 已接受为 OEP），
   使 OEP evidence 保留 source/VA/RVA；gate 仍通过 entry-RVA 匹配、ambiguity 等检查 fail-closed。

**合规**：VA 来自 runtime PossibleOEP 观察，不是从 final PE entry point 或历史 manifest 反向生成，
不违反 P8-B 硬性禁止。`ScanFallback` / storm-fallback / FTraceMSVCOEP bootstrap 分支保持 `unknown` /
`scan_fallback` 语义不变（这些仍是低置信度 / 非 application-OEP，gate 保持 fail-closed）。

## 数据流（修复后）

```
runtime PossibleOEP (guard AV) → decide_possible_oep
  → valid-x64-code / 无确认 trace 分支 → state.provenance (Trace, va=Some)
  → ls.oep_provenance (LoopState)
  → sync_plugin_milestones → plugin_ctx.record_oep_provenance
  → RVA = oep_va_to_rva(runtime_base) 推导
  → run_post_loop_phases(oep_provenance=plugin_ctx.oep_provenance)
  → write_oep_evidence(protected, candidate, oep_provenance)
  → sidecar source=Trace, va/rva 保留
```

## 测试

- **av_oep_handler.rs**（+2）：
  - `valid_x64_code_branch_keeps_runtime_va_and_trace_provenance`
  - `unconfirmed_possible_oep_keeps_runtime_va`
- **plugin.rs（core）**（+3）：
  - `record_oep_provenance_derives_rva_and_keeps_runtime_identity`
  - `record_oep_provenance_scan_fallback_is_preserved_not_overwritten`
  - `record_oep_provenance_requires_runtime_base_for_rva`
- **plugin_host.rs**（+2）：
  - `sync_plugin_milestones_propagates_runtime_oep_provenance`
  - `sync_plugin_milestones_does_not_downgrade_unknown_to_fabricated_rva`
- `LoopState` 增加 `#[derive(Default)]`（字段全部支持默认，供离线状态构造）。

## 攻击负例（P8-B 要求的 fail-closed）

- final PE entry 正确但 runtime provenance 缺失 → OEP evidence `prerequisite_passes=false`、blocker 含 "unknown/RVA missing"（已有 `unknown_and_missing_addresses_fail_closed`）。
- runtime VA/RVA 与 image base 不一致 → `entry_rva_matches_provenance=false`、blocker "does not match"（已有 `final_candidate_entry_is_authoritative_and_mismatch_fails_closed`）。
- bootstrap/ambiguous OEP 不得伪装 application OEP → `bootstrap_ambiguous_fails_closed`。
- provenance 被覆盖/重置 → `sync_plugin_milestones_does_not_downgrade_unknown_to_fabricated_rva` 证明 unknown 不获得伪造 RVA；`record_oep_provenance_scan_fallback_is_preserved_not_overwritten` 证明 scan fallback 不被改写。
- 无 runtime base 时 RVA 不伪造 → `record_oep_provenance_requires_runtime_base_for_rva`。

## 退出状态

本阶段未处理 Behavior Oracle、isolated replay 10/10、最终验收。修复后 OEP evidence 在正常路径保留
source/VA/RVA/application_oep，满足 v8 gate 的 OEP 契约；但完整 v8 gate 仍可因
behavior/prerequisite/10-10 保持 open。
