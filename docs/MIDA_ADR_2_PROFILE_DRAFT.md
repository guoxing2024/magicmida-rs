# MIDA-ADR-2 Profile Draft（per-sample profile）

> **工作令：** MIDA-ADR-2 —— 基于 ADR-1 建立 clean-room anti-debug 行为规范与 probe 契约。
> **状态：** 草稿（文档阶段）。未执行样本、未执行 ScyllaHide、未做 live 差分。profile 是 draft，供 ADR-3 controller 接线时使用；required 锁定需动态验证。
> **基线：** `e98a6a61051a734a14cf53ebe9e64e5b1099374b`。
> 配套：[BEHAVIOR_SPEC](MIDA_ADR_2_BEHAVIOR_SPEC.md) · [PROBE_CATALOG](MIDA_ADR_2_PROBE_CATALOG.md)

## 1. 规则

- 每个样本独立 profile；**禁止**用一个共享 profile 覆盖两样本差异。
- unknown surface 不进入 required。
- required 只能来自 confirmed call site / confirmed runtime observation / confirmed decision semantics。
- origin 结论不得复制到 lunlun（lunlun 原程序面不可见 → 保守）。

## 2. origin_macro_profile（`mida.antidebug-profile/v1`）

```json
{
  "schema": "mida.antidebug-profile/v1",
  "profile_id": "oreans_origin_x64_v1",
  "sample_id": "origin_macro",
  "architecture": "x86_64",
  "required_surfaces": [
    "AD-PROC-002",   // PEB.BeingDebugged — decision confirmed (live behavior)
    "AD-PROC-003",   // PEB.pShimData — decision confirmed (live behavior)
    "AD-PROC-001"    // IsDebuggerPresent — REQUIRED CANDIDATE (IAT presence + same detection plane;
                     //   lock-in requires call_site_confirmed or decision_semantics_confirmed at ADR-3)
  ],
  "observe_only_surfaces": [
    "AD-PROC-004", "AD-PROC-005", "AD-THR-001", "AD-THR-003",
    "AD-TIM-001", "AD-TIM-002", "AD-TIM-003", "AD-TIM-004",
    "AD-EXC-001", "AD-EXC-002", "AD-EXC-003",
    "AD-TLS-001", "AD-INT-001", "AD-INT-002", "AD-UI-001"
  ],
  "deferred_surfaces": [
    "AD-PROC-006", "AD-PROC-007", "AD-THR-002", "AD-HEAP-001", "AD-TLS-002", "AD-ENV-001"
  ],
  "unknown_surfaces": [],
  "profile_basis": [
    "docs/MIDA_ADR_1_SURFACE_INVENTORY.md (committed e98a6a61)",
    "docs/MIDA_ADR_2_PROBE_CATALOG.md"
  ],
  "version": 1
}
```

**说明：** origin 的 QPC / GetTickCount / SetUnhandledExceptionFilter **仅凭 IAT presence 不进入 required**（保持 observe-only）。
AD-PROC-001 为 required 候选（保留项），锁定条件见 PROBE_CATALOG §10 注。

## 3. lunlun_software_profile（`mida.antidebug-profile/v1`）

```json
{
  "schema": "mida.antidebug-profile/v1",
  "profile_id": "oreans_lunlun_x64_v1",
  "sample_id": "lunlun_software",
  "architecture": "x86_64",
  "required_surfaces": [
    "AD-PROC-002",   // PEB.BeingDebugged — decision confirmed (live behavior)
    "AD-PROC-003"    // PEB.pShimData — decision confirmed (live behavior)
  ],
  "observe_only_surfaces": [
    "AD-PROC-001", "AD-PROC-004", "AD-PROC-005",
    "AD-THR-001", "AD-THR-003",
    "AD-TIM-001", "AD-TIM-002", "AD-TIM-003", "AD-TIM-004",
    "AD-EXC-001", "AD-EXC-002", "AD-EXC-003",
    "AD-TLS-001", "AD-INT-001", "AD-INT-002", "AD-UI-001"
  ],
  "deferred_surfaces": [
    "AD-PROC-006", "AD-PROC-007", "AD-THR-002", "AD-HEAP-001", "AD-TLS-002", "AD-ENV-001"
  ],
  "unknown_surfaces": [],
  "profile_basis": [
    "docs/MIDA_ADR_1_SURFACE_INVENTORY.md (committed e98a6a61)",
    "docs/MIDA_ADR_2_PROBE_CATALOG.md"
  ],
  "version": 1
}
```

**说明（保守原则）：** lunlun 因 OEP ambiguous、IAT unresolved、原程序 API 面不可见，profile 必须保守：
- PEB behavior：可记录已有 live observation（required）；
- IsDebuggerPresent：unknown → observe-only（**不得复制 origin 的 required**）；
- NtQIP/NtSIT：unknown → observe-only；
- timing semantics：unknown → observe-only；
- TLS callback body：defer。
不能为了"覆盖更多"把 unknown 变成 required。

## 4. 两 profile 差异对照

| 项 | origin_macro | lunlun_software |
|---|---|---|
| profile_id | oreans_origin_x64_v1 | oreans_lunlun_x64_v1 |
| required | 3（含 AD-PROC-001 候选） | 2 |
| observe-only | 15 | 16 |
| deferred | 6 | 6 |
| AD-PROC-001 | required 候选（IAT presence + 同检测面） | observe-only（IAT 未重建） |
| AD-TIM-002/003/004、AD-EXC-001 | observe-only（IAT presence 仅） | defer（无 IAT 证据） |

## 5. 锁定条件（ADR-3 接线时执行，本任务不执行）

- AD-PROC-001（origin）：受控动态验证 IsDebuggerPresent 调用点 → `call_site_confirmed` 或 `decision_semantics_confirmed` 后锁定 required；否则降 observe-only。
- 任何 observe-only → required 升级：必须新增 call-site / runtime / decision 证据并更新本 profile 版本。
- 任何 defer → 激活：必须由独立任务（如 ADR-5 TLS、未来动态探针）提供证据。

## 6. Fail-closed 映射

- profile 级 required 缺失（runtime 未 hook / attestation 不完整）→ `AntiDebugRuntimePartialHooks` → fail-closed（见 EVIDENCE_CONTRACT §4.1）。
- observe-only/defer surface 无证据 → probe decision = `not-run` / `deferred`，**不得**自动 pass。
- 只有 presence / 字符串 / payload pattern / 历史日志 / ScyllaHide 成功 / TLS callback 存在 → 不得 pass（BEHAVIOR_SPEC §4）。

## 7. 文档状态

- 未执行样本；未执行 ScyllaHide；未做 live 差分；未实现代码；未复制第三方内容。
- schema 与 ADR-0 一致（`mida.antidebug-profile/v1`）。
- 待 ADR-1-CLOSEOUT 后随 ADR-2 一起提交（本任务完成后统一 commit）。