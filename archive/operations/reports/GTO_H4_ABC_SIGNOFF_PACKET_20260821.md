# GTO-H4-A/B/C 签核材料包（WO-203）— 供 owner 审阅

**签发**: 项目总指挥（批次 3 WO-203）
**编制**: 唯一 worker · 2026-08-21
**性质**: **只读审阅包** — 不修改任何证据、不改账本既有行、不下结论；签核权在 owner
**前置**: 本包仅汇总既有材料；owner 可仅凭本包完成三阶段签核决策

---

## 0. 使用说明

- 每阶段（A/B/C）一节：设计文档指针、证据 vault 逻辑标识、已知保留项、审阅清单（逐条可勾选）、与账本 §8 行交叉引用。
- 证据路径仅给 **逻辑标识**（evidence_set_id / 目录名），不含绝对路径（工单要求）。
- owner 对每个审阅清单项回答 **PASS / REJECT**（可附意见）。
- 三阶段独立决策：任一阶段 REJECT 不影响其他阶段；H5 不受本包影响（仍 BLOCKED_AT_LOADER_SMOKE）。

---

## 1. H4-A — Stable Module Registry (SMR) stub execution

### 1.1 设计/报告指针
- 设计: docs/GTO_COLD_START_HEAP_REBASE_1_H4A_SMR_DESIGN.md
- 报告: docs/GTO_COLD_START_HEAP_REBASE_1_H4A_REPORT.md
- 账本 §8 行: H4-A SMR (ViaStableBinding stub exec) | TECHNICAL PASS + LIVE EVIDENCE (3 ASLR layouts, exit 0, unresolved_required=0/0/0)

### 1.2 证据 vault 逻辑标识
- evidence_set_id: H4A_smr/（含 H4A_smr/layout_B/；另有更正目录 H4A_smr_correction/）
- 内容: candidate + layout_B + capture_policy + child stdout/stderr + controller_attempt_001/002 + observation-only evidence
- 输入: pinned manifest rev 2 sample (11473d2e…), immutable authorized GTO

### 1.3 已知保留项
- 无已知证据缺失；H4A_smr_correction/ 为审计后更正（非封存修改）。

### 1.4 审阅清单（owner 逐项 PASS/REJECT）

- [ ] 1.4.1 SMR 两阶段 .boot stub 在 3 个 ASLR layout 上执行并 exit 0（报告 §1/§2）
- [ ] 1.4.2 ViaStableBinding resolver 走目标自身 PEB Ldr 链表（无 dump-time 模块状态）
- [ ] 1.4.3 未解析模块 → 无限循环（cookie 保持 0），fail-closed 语义保留
- [ ] 1.4.4 无 blanket module-delta patch、无 gate removal、无 bypass
- [ ] 1.4.5 unresolved_required=0/0/0（3 layouts）
- [ ] 1.4.6 证据目录含完整运行痕迹（controller/child/observation-only）

### 1.5 需 owner 确认的问题
1. SMR 的“无限循环 fail-closed”是否符合签核预期？（而不是静默失败）
2. H4A_smr_correction/ 与 H4A_smr/ 的关系是否需要合并审阅？
3. 是否接受“TECHNICAL PASS + LIVE EVIDENCE”作为 H4-A 正式签核结论？

---

## 2. H4-B — OEP entry-chain evidence

### 2.1 设计/报告指针
- 设计: docs/GTO_COLD_START_HEAP_REBASE_1_H4B_OEP_DESIGN.md
- 报告: docs/GTO_COLD_START_HEAP_REBASE_1_H4B_REPORT.md
- 账本 §8 行: H4-B OEP entry-chain evidence | TECHNICAL PASS; evidence package PARTIAL (attempt_001 raw log unrecoverable); formal seal/sign-off NOT GRANTED — see GTO-H4-LEDGER-CONSISTENCY-1

### 2.2 证据 vault 逻辑标识
- evidence_set_id: H4B_oep_run2/（当前基准；H4B_oep/、H4B_oep_fixed/ 为历史）
- 内容: candidate + layout_B + layout_C + controller_attempt_001/002 + child stdout/stderr
- 基准: baseline 81d44e2 (sha a7054728…)

### 2.3 已知保留项
- attempt_001 raw log unrecoverable（GTO-H4-LEDGER-CONSISTENCY-1 记录）：首次运行的原始日志不可恢复；run2 (81d44e2) 为当前有效证据基准。
- layout_B OEP 来源为 scan_fallback（非 runtime/trace）→ 门拒绝（设计预期，fail-closed 演示）。

### 2.4 审阅清单（owner 逐项 PASS/REJECT）

- [ ] 2.4.1 decode_boot_entry_chain 机器码验证（stub epilogue 签名扫描）
- [ ] 2.4.2 attempt_001: chain_decoded=true, chain_oep_matches=true, prerequisite=true, blocker=null
- [ ] 2.4.3 layout_B: 门拒绝（scan fallback provenance）— fail-closed 语义演示
- [ ] 2.4.4 layout_C: chain_decoded=true, chain_oep_matches=true, prerequisite=true, blocker=null
- [ ] 2.4.5 regions_total=319/319, unresolved_required=0, bootstrap Complete, structure_ep_ok=true
- [ ] 2.4.6 回归: oep_evidence 41/41, mida-pe lib 951/951, ADR7 17/17 PASS

### 2.5 需 owner 确认的问题
1. attempt_001 raw log 不可恢复是否可接受为已知保留项？（若不可接受，需指定补偿证据）
2. layout_B 的 fail-closed 拒绝（scan fallback）是否作为正向证据接受？
3. 是否接受“TECHNICAL PASS + evidence PARTIAL”作为 H4-B 结论？（账本当前为 NOT GRANTED）

---

## 3. H4-C — TLS directory + evidence

### 3.1 设计/报告指针
- 设计: docs/GTO_COLD_START_HEAP_REBASE_1_H4C_TLS_DESIGN.md
- 报告: docs/GTO_COLD_START_HEAP_REBASE_1_H4C_REPORT.md
- 账本 §8 行: H4-C TLS directory+evidence | TECHNICAL PASS + 3-layout evidence PASS; Seal-2 verifier PASS (48/48 size+sha, 0 missing, 0 unexpected, self-hash MATCH); formal sign-off PENDING review disposition

### 3.2 证据 vault 逻辑标识
- evidence_set_id: H4C_tls/（layout_A/B/C + GTO_H4C_EVIDENCE_SEAL.json）
- seal_id: GTO-H4-C-EVIDENCE-SEAL-2（created_utc 2026-08-20T19:42:00Z）
- seal 统计: file_count=48, hash_policy=raw disk SHA-256, manifest_self_hash=c000b900…
- 验证器: tools/gto_h4c_seal/（Seal-2 验证器，移出证据根）

### 3.3 已知保留项
- Seal-1 被 review 拒绝（unexpected file + future timestamp）→ Seal-2 更正（已记录于 seal JSON correction_note）。

### 3.4 审阅清单（owner 逐项 PASS/REJECT）

- [ ] 3.4.1 3 layouts 均 exit 0, sidecar tls_complete=true
- [ ] 3.4.2 TLS 目录捕获与候选验证满足 Acceptance gate #7
- [ ] 3.4.3 Seal-2 验证器 PASS: 48/48 size+sha, 0 missing, 0 unexpected, self-hash MATCH
- [ ] 3.4.4 证据无 in-place 修改（Seal-2 为更正后的新 seal）
- [ ] 3.4.5 ADR7 17/17 PASS（TLS 证据未触碰 Oreans 门）

### 3.5 需 owner 确认的问题
1. Seal-2 的 correction_note（Seal-1 拒绝原因 + 时间戳更正）是否接受？
2. 是否接受“TECHNICAL PASS + 3-layout evidence PASS + Seal-2 verifier PASS”作为 H4-C 正式签核结论？
3. H4-C 签核是否附带任何条件（如 Seal-3 要求）？

---

## 4. 交叉引用与总体说明

| 阶段 | 账本 §8 行 | 证据 set | seal | 签核权 |
|---|---|---|---|---|
| H4-A | SMR TECHNICAL PASS + LIVE EVIDENCE | H4A_smr/ | 无（raw evidence） | owner |
| H4-B | TECHNICAL PASS; evidence PARTIAL; NOT GRANTED | H4B_oep_run2/ | 无（raw evidence） | owner |
| H4-C | TECHNICAL PASS + 3-layout PASS; Seal-2 PASS; PENDING | H4C_tls/ | GTO-H4-C-EVIDENCE-SEAL-2 | owner |

## 5. 红线声明

- 本包未修改任何 vault 证据、未改账本既有行、未下结论。
- H5 状态不变（BLOCKED_AT_LOADER_SMOKE）；本包不授权任何实弹运行。
- owner 的 PASS/REJECT 决定需以签名（或等价权威记录）落账后方生效。
