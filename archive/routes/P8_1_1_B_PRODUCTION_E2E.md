# P8.1.1-B / P8.1.1.1-B —— 真实 CLI single-production-bundle structured-domain E2E

**状态:** 完成
**范围:** 纯离线工程。未访问 D:/MidaVault、未启动任何真实样品、未执行 P9。

## 目标

替换 P8.1-D 的 synthetic evidence pipeline 测试，使测试**真正经过 CLI 生产证据路径**：不再手工构造 acceptance 的 OEP/IAT/TLS/relocation/section evidence 类型，也不再手工构造 `OreansEvidenceBundle`/`BundleMemberRef`/hash 来代替 atomic assembler。

## 测试位置与 seam

- 测试放在 `crates/cli/src/unpacker/production_e2e.rs`（`#[cfg(test)]` crate 内部测试模块），因为生产 sidecar producer 与 `RunEvidenceContext` 构造器是 `pub(crate)`（严格 test-only seam，符合 P8.1.1-B #1/#9）。
- `write_bound_transform_manifest`（mida-pe 生产 transform manifest writer）是受支持的 **production API**（非仅测试 seam）：它被真实 dump 路径 `dump_process_with_report` / `dump_dotnet_with_source` 使用，也作为生产证据流水线生成 transform-manifest bundle member 的同一 writer。P8.1.1.1-B 为其补全正式 API 契约（参数身份约束 + 原子写语义 + 错误契约）、移除 "solely exposed for tests" 理由，并新增 5 个独立单测。`RunEvidenceContext::new` 仍是 `pub(crate)`（未放宽、未恢复 Clone）。
- **未**新增任何生产 CLI 参数、环境变量后门或公开 attestation 绕过接口（#2）。

## 真实生产函数调用链（#3/#4）

```
emit_candidate_pe (mida_pe::rebuild_pe_image)
  -> write_oep_evidence        (mida-cli unpacker::oep_evidence)
  -> write_iat_evidence        (mida-cli unpacker::iat_evidence)
  -> write_tls_evidence        (mida-cli unpacker::tls_evidence)
  -> write_relocation_evidence (mida-cli unpacker::relocation_evidence)
  -> write_section_rebuild_evidence (mida-cli unpacker::section_rebuild_evidence)
  -> write_bound_transform_manifest (mida_pe::dumper, production manifest)
  -> build_oreans_pe_evidence  (mida-acceptance, production PE evidence)
  -> assemble_evidence_bundle  (mida-cli unpacker::bundle_assembler, atomic assembler)
  -> mida_acceptance::validate_evidence_bundle (independent consumer)
  -> mida_acceptance::evaluate_oreans_two_sample_gate (v8 gate)
```

`identity/tool_revision/runner_config_digest` 全部来自 `RunEvidenceContext::new`（crate-private 受控 context，非 caller-supplied；#7/#8）。

## Claim boundary（P8.1.1.1-B #3）

- **只有 origin bundle 来自真实 atomic assembler**；其 OEP / IAT / relocation / section-rebuild 四结构化域是本测试断言的通过项。
- **lunlun companion 是 synthetic observation**：它只是为满足 raw v8 two-sample gate 固定 case-set（`{origin_macro, lunlun_software}`）而存在，不是独立组装的第二个生产 bundle，其域保持 Open/NotRun 且从不断言。
- **本测试不证明 two-bundle envelope consumer**（`mida.oreans-two-sample-bundle-gate/v1` 需两个 sealed bundle）。two-bundle envelope consumer 的验证**留给 P9** 真实 evidence。

因此本测试被准确命名为 **single-production-bundle structured-domain E2E**，不描述为完整 two-bundle / bundle-gate E2E。

## 两个测试

### 1. `single_production_bundle_structured_domain_e2e_four_domains_pass`（正对照）

真实生产流水线：合成 candidate PE + synthetic replay report → 五个真实 sidecar producer → PE evidence + transform manifest → 真实 atomic assembler → Evidence Bundle v2 → 独立 validator → v8 gate（single production bundle）。

断言：
- `validate_evidence_bundle` → `valid=true, complete=true`（#11a）
- `protected/candidate/case_id/tool_revision/runner_config_digest` 全链一致（与受控 context 绑定；#11b）
- **OEP / IAT / relocation / section-rebuild 四域 pass**（#11c-f）
- behavior / survival / isolated replay 保持 Open/NotRun（不伪造；#11g）
- source guard `assert_not_hand_built`：重读 bundle 校验 `manifest_sha256` 非空且 64 hex（证明由真实 assembler 密封，非手工拼装；#13）

TLS 域不在四域断言内（#11 只要求 OEP/IAT/reloc/section），故 TLS 可保持 Open；"protected input does not match locked manifest" 是 synthetic 受保护输入固有的（锁定的受保护身份是真实样品），非结构化域失败，四域仍独立通过。

### 2. `production_tampered_candidate_rejected_by_independent_validator`（攻击负例）

- 篡改 candidate 字节；
- 诚实重算除 `iat_evidence` 外所有成员 candidate identity + `members_sha256` + `manifest_sha256`（attack 式）；
- 独立 acceptance validator **必须**因 `iat_evidence candidate <old> != bundle <new>` 拒绝（#12）。

P8.1.1.1-B #5 保留此负例；#6 允许攻击负例诚实重算攻击后的 hash（正对照仍禁止手工构造 bundle）。

## 手工拼装禁令（#5/#6）

- 正对照**不**手工构造任何 acceptance evidence 类型：五类 sidecar 全部由真实 producer 写到磁盘，测试只 `serde_json::from_slice` 读取（反序列化生产输出，非构造）。
- 正对照**不**手工构造 `OreansEvidenceBundle`/`BundleMemberRef`/`members_sha256`/`manifest_sha256`：bundle 完全由 `assemble_evidence_bundle` 原子组装；`assert_not_hand_built` 守卫防退化。
- 负例为了证明"篡改+重算 hash 仍被独立 validator 拒绝"，确实重算 hash——这是攻击负例的本质要求（#12），且仍调用 `validate_evidence_bundle` 独立判定。

## 旧测试处置（#14）

`crates/pe/tests/synthetic_evidence_pipeline.rs`（P8.1-D 手工构造 acceptance evidence 类型）已被新的 production E2E 完整替代，**删除**。它不再自称 production/full pipeline。

## 验证

- `cargo test -p mida-cli --lib --offline`：全部通过（含 single-production-bundle structured-domain E2E 正对照 + 攻击负例）。
- `cargo test -p mida-pe --offline`：全部通过（含 `transform_manifest_tests` 5 个独立单测）。
- 默认 tests 不访问 D:/MidaVault、0 真实样品进程、未执行 P9。
