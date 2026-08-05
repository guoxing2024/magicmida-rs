# P8.1-D —— 单一 synthetic end-to-end evidence 流水线

**状态:** 实现完成（P8.1-D 阶段）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程、未执行 P9。

## 目标

新增一个单一集成测试，完整执行从 synthetic runtime/replay 事件 → OEP provenance → IAT reconstruction → relocation observation/preservation → section rebuild → 发射 candidate PE → 五个 sidecar + transform manifest + PE evidence → atomic Evidence Bundle v2 → 独立 acceptance bundle validator → v8 gate domain evaluation 的全链路。

## 测试位置

`crates/pe/tests/synthetic_evidence_pipeline.rs`（mida-pe 集成测试）。mida-pe 是 PE 产出发射端，dev-dependency 已有 `mida-acceptance`，因此一个测试 crate 内同时可触达产出发射（`mida_pe::rebuild_pe_image`）与独立消费端（`mida_acceptance::validate_evidence_bundle` / `evaluate_bundle_gate`），**且不把 producer import 放进 acceptance crate**（acceptance 的 Cargo.toml 仅依赖 serde/serde_json/sha2/thiserror，完全不依赖 producer crate）。

## 两个测试

### 1. `synthetic_pipeline_emits_bundle_and_gate_domains_pass`

完整正例流水线：
1. **发射 candidate PE**：`rebuild_pe_image` 用 `.text`（含 entry + reloc target）+ import（IAT）+ `.reloc` + `.tls` 组成 plan，发射出 PE32+ 候选（4 sections、TLS present、basereloc present）。
2. **OEP provenance**：`OreansOepSource::Trace`，`va`/`rva`/`final_entry_rva` 均取自发射 PE 的 `entry_rva`。
3. **IAT reconstruction**：`OreansIatReportEvidence` 带一个 `Resolved` slot（RVA 0x1100）+ 匹配的 `final_imports`，无 unresolved（`unresolved_reason_counts` 为空、pending=0）。
4. **relocation observation/preservation**：runtime/final/ASLR simulation 字段取自发射 PE 的 `relocation_detail`（block_count/entry_count/dynamic_base/observed_types 等）与 `base_reloc` 目录覆盖；`directory_raw_offset` 取 `.reloc` 的 raw offset。
5. **section rebuild**：完整枚举 16 个 data directory、entry_section、overlay 从 raw layout 重算、executable_sections 从 characteristics 重算——与 gate 复算一致。
6. **五个 sidecar + transform manifest + PE evidence**：全部绑定发射 candidate 的 SHA-256/size；PE evidence 由 `build_oreans_pe_evidence` 从发射字节重算。
7. **atomic Evidence Bundle v2**：canonical `members_sha256` + `manifest_sha256` 密封。
8. **独立 bundle validator**：`validate_evidence_bundle` 接受（`valid=true, complete=true`）。
9. **v8 gate domain evaluation**：`evaluate_bundle_gate` 消费两个固定 case 的 bundle。
10. **断言**：OEP / IAT / relocation / section-rebuild 四域 `*_evidence_pass` 全为 true；唯一 open 的 failure 只含 behavior / survival / structural / isolated replay；`prerequisites_pass=false`、`final_behavior_verdict=NotRun`、`isolated_replay.attempts` 为空；gate 整体 `Open`（behavior + replay 不在 bundle 契约内，需 live run 才可能 Close）。

### 2. `tampered_candidate_with_recomputed_hashes_is_rejected`

负例：篡改发射 candidate 的 `.text` 一个字节 → 把除 `iat_evidence` 外所有成员嵌入的 candidate identity 改为篡改值（`iat_evidence` 保持 stale 在原 identity）→ 重算所有 member hash + `members_sha256` + `manifest_sha256`（attack 式）→ 独立 validator 必须拒绝，且原因明确为 `iat_evidence candidate <old> != bundle <new>`；gate 同样拒绝该篡改 bundle。

## 约束遵守

- **测试不通过 import producer 实现到 acceptance crate**：producer 只在 mida-pe（dev-dep 消费端）侧使用；acceptance 库本身不 import 任何 producer crate。
- **不访问 Vault**：测试只操作内存中的发射字节与临时 sidecar，无任何 Vault 路径。
- **不产生真实样品进程**：全程无 process 创建。
- **四域 pass 非伪造**：sidecar 字段全部取自发射 PE 的实际结构（entry/TLS/reloc/section），gate 独立复算通过。

## 明确 pin

- behavior oracle、prerequisite survival/structural、isolated replay 10/10 不在 v2 bundle 契约内，测试明确保持 NotRun/open（它们需要 live run，不属于本离线批）。
- 本阶段不执行任何 live unpack、不申请 live slot、不声明 perfect/universal/10/10/final acceptance。
