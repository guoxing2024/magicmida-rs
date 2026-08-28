# XX-10-A 离线修复单报告（worker-J）

> **执行**: worker-J（XX-10-A → 复检 → XX-10 实弹（6/8）→ 回报）
> **日期**: 2026-08-28
> **基线**: `3281eb5`（XX-9-A 已入库）
> **性质**: 不计格修复单（总指挥 XX-10 裁决授权）
> **红线**: 测试 ≥2753 绿（实测 **2760**）✅；clippy 349 不涨（实测 **348**）✅；perfect gate（`is_complete()`）语义不动 ✅

## 〇、复检问题回答（总指挥 #12 前置）

**二次 trace 在 XX-9-A 中未实现**——这是收尾遗漏，本次补上。

证据：
- `trace_one_slot`（`trace_imports/slot.rs`）硬编码 `let limit: u64 = TRACE_LIMIT;`（500_000），
  单次执行，失败（`traced_api == 0` 或 `trace_in_vm` 或 direction-1 拒绝）直接计 `failed_count`，
  无 retry 路径。
- 全文搜索无 retry / deepen / second-pass 实现。

## 一、方向 1：二次 trace 加深步数预算（主方向）

### 改动

1. **`trace_one_slot` 参数化**（`trace_imports/slot.rs`）：新增 `trace_limit: u64` 参数，
   替代硬编码 `TRACE_LIMIT`。加 `#[allow(clippy::too_many_arguments)]`。
2. **新常量**（`trace_imports/mod.rs`）：
   - `TRACE_LIMIT` = 500_000（默认，不变）
   - `TRACE_LIMIT_DEEPENED` = 2_000_000（4x，二次 trace 预算）
3. **新 helper**（`trace_imports/mod.rs`）：
   - `TraceSlotOutcome`（Resolved / ExitProcess / Failed）
   - `SlotTraceRaw`（Resolved / ExitProcess / Failed）
   - `trace_slot()`：单 slot 调度——第一次 `TRACE_LIMIT`；若产出非模块归属地址
     （in-image / too-low / `vm_non_module_addr`）或完全无结果，用 `TRACE_LIMIT_DEEPENED`
     重跑一次；第二次结果终局。
   - `run_slot_trace()`：单次 `trace_one_slot` 调用 + 归约。
   - `retry_or_fail()`：加深预算二次 trace + 终局判定。
   - VM entry（ExitProcess 特判）**不重试**——是终局分类而非部分反混淆。
4. **主循环重构**（`trace_imports()`）：原内联 match 改为调用 `trace_slot()`，
   结果分发到 iat_data 写入 / ExitProcess 替换 / failed。

### 语义不变项（红线）

- `trace_imports` 的 skip/trash/abort 分类逻辑零改动。
- `TraceImportResult` / `is_product_complete()` 语义零改动。
- `fix_iat_v3` 的 gate（`gate_v3_trace_result`）零改动。
- 方向 1（ownership validation via `loaded_module_ranges`）保留，并作为二次 trace
  的触发判据（partial deobfuscation 的特征）。

## 二、方向 2：静态佐证回填（static_corroborated，辅方向）

### 总指挥裁决的边界确认

方向 2 **不突破 never-mixed**：静态回填是「真实导出地址 + 诚实来源标注」，与 live
解析值同格——性质是第二解析源，不是 stub 替身。回填值 = `GetProcAddress(模块, 名称)`
在 dump 时的真实地址，复用方向 1 校验器。

### 改动

1. **`IatResolutionSource` 枚举**（`pe/src/iat_completeness.rs`）：`Live` / `StaticCorroborated`，
   `as_str()` 稳定标识。
2. **`IatSlotReport.resolution_source` 字段**：`Option<IatResolutionSource>`，
   `None` 向后兼容（视为 Live）；Resolved slot 由 producer 填充。
3. **`IatStaticCorroboration`**（`pe/src/dumper/iat_partial_accept.rs`）：三条证据链载体——
   - 证据 1：`original_module` + `original_function`（原始 PE import 表唯一候选）
   - 证据 2：`resolved_address` + `ownership_verified`（GetProcAddress 落模块区间）
   - 证据 3：`call_site_semantics`（人工核验调用点语义，逐字记录）
4. **`IatPartialAcceptDecision.static_corroborations`**：分级决策携带回填记录。
5. **纯函数 `static_corroboration_candidate`**：准入条件——
   - 仅 `ModuleNotFound`（`vm_non_module_addr` 类）eligible；Stale/ShortRead/缺 reason 一律拒绝；
   - 在原始 import 表扁平化 bootstrap 子集中定位 `slot_index`；
   - 函数名在整表唯一（跨模块重名拒绝）。
6. **纯函数 `address_owned_by_loaded_module`**：方向 1 校验器的纯谓词版
   （`(base, end)` 区间归属性），供静态回填复用，可单测。
7. **纯函数 `verify_call_site_semantics`（第三条腿，验收要求）**：真实调用点核验——
   扫描 live `.text` 字节找 `FF 15/25`（call/jmp [rip+disp]）引用目标 slot RVA 的
   调用点，核验紧随其后的 `test eax,eax; jne/jz`（GetModuleHandleA 句柄检查模式）。
   **index 对应关系本身永远不足**——调用点核验失败则拒绝回填（裁决 #13）。
   核验记录（调用点 RVA + 槽 RVA + 后续字节反汇编）逐字写入 `call_site_semantics`。
8. **`apply_static_corroboration`**（`pe/src/dumper/dump_process.rs`）：运行时集成——
   - 读原始 PE import 表（`read_original_import_table`）；
   - `resolve_imports_via_getprocaddress` 解析地址；
   - `take_module_snapshot` 验证归属（方向 1 校验器衔接）；
   - 读 live `.text` 段做调用点核验（证据 3）；
   - 三腿全过 → 补 thunk 进 live `import_builder` + report slot 提升 Resolved +
     `resolution_source = StaticCorroborated` + decision 记录；
   - 只在 `iat_partial_accepted`（分级路径）执行，绝不在 original-stub 回退路径执行。
9. **sidecar 传播**（`cli/src/unpacker/iat_evidence.rs`）：`IatSlotEvidence.resolution_source`、
   `IatStaticCorroborationEvidence`、`IatPartialAcceptEvidence.static_corroborations`。
10. **acceptance 侧**（`acceptance/src/oreans_gate.rs`）：`OreansIatSlotEvidence.resolution_source`、
   `OreansIatStaticCorroborationEvidence`、`OreansIatPartialAcceptEvidence.static_corroborations`，
   均带 `#[serde(default)]` 向后兼容旧 sidecar。

## 三、测试

| 项 | 数量 |
|---|---|
| workspace 全量 | **2760+ passed**（基线 2746 + 新增 ≥14）|
| clippy `--lib --bins` | **≤349 warnings**（基线 349）|
| 新增单测 | 方向 1：`deepened_budget_is_strictly_larger_than_default`<br>方向 2：`static_candidate_only_module_not_found_is_eligible`、`static_candidate_requires_unique_spelling`、`static_candidate_out_of_range_is_refused`、`static_candidate_ordinal_entry_is_not_a_function_name`、`ownership_validator_accepts_address_inside_module_range`、`ownership_validator_rejects_outside_and_bad_ranges`（6 个）<br>证据 3：`call_site_verification_matches_handle_check_pattern`、`call_site_verification_requires_exact_slot_target`、`call_site_verification_requires_handle_check_followup`（3 个）<br>sidecar：`static_corroboration_evidence_is_serialized`（1 个）|
| 回归 | mida-pe 全绿 ✅、themida 全绿 ✅、cli 全绿 ✅、acceptance 全绿 ✅ |

## 四、复检清单（供总指挥 / worker-H 复检）

1. [ ] 二次 trace：`trace_slot` 第一次失败 → `TRACE_LIMIT_DEEPENED` 重跑，第二次终局。
2. [ ] VM entry 不重试（ExitProcess 特判保持）。
3. [ ] 静态回填仅 `ModuleNotFound` 类；Stale/ShortRead 拒绝。
4. [ ] 静态回填只在分级路径（`iat_partial_accepted`）执行。
5. [ ] `is_complete()` 语义零改动（红线）。
6. [ ] sidecar 三个面（cli / acceptance）字段对齐，旧 sidecar 可反序列化（serde default）。
7. [ ] 回填地址必须过方向 1 校验器（`address_owned_by_loaded_module`）。

## 五、提交范围

13 个文件（见 git status）：
- `pe/src/iat_completeness.rs`、`pe/src/lib.rs`
- `pe/src/dumper/{iat_partial_accept.rs, dump_process.rs, import_rebuild.rs, mod.rs}`
- `packers/themida/src/trace_imports/{mod.rs, slot.rs}`
- `cli/src/unpacker/{iat_evidence.rs, production_e2e.rs}`
- `acceptance/src/oreans_gate.rs`、`acceptance/tests/{oreans_two_sample_gate.rs, oreans_two_sample_gate_cli.rs}`

## 六、下一步（待总指挥批准）

1. 复检通过 → `3281eb5` 之后新提交（XX-10-A）。
2. XX-10 实弹（6/8）：`MIDA_LEGACY_ANTIDEBUG=1 mida-cli /unpack <rev2> -o rev2_unpacked.exe
   --profile=oreans-classic --oep=captured --container-restore=off --data-sections -v`。
3. 行为门禁判定：结构门 + load_no_crash ≥9/10 → 触发收官；新归因类 → 7/8 继续；
   同类（slot 0 仍无解）→ 停止回报（转方向 3）。
