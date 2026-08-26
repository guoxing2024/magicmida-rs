# GTO-COLD-START-HEAP-REBASE-1 — H4 审核申请

> 申请者: 执行代理 (autonomous)
> 审核人: 总指挥 (human)
> 申请日期: 2026-08-20
> 范围: H4-A (SMR), H4-B (OEP entry-chain), H4-C (TLS) — 三阶段成果联审
> 审核结论: 总指挥 2026-08-20 已裁决 — 见下 "6. 审核裁决与处置"
> 环境纪律: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1, 无 bураs​s/语义修复, ADR7 冻结未动

## 1. 申请审核什么

请总指挥审核以下三阶段的技术结论、证据充分性，并决定：
(a) H4-A 是否正式签收 (technical pass + live evidence)
(b) H4-B 证据缺口 (attempt_001 原始日志不可恢复) 是否接受替代证据
(c) H4-C 正式证据封印 (GTO-H4-C-EVIDENCE-SEAL-1) 是否批准
(d) 是否放行 H4-D (exception+no-reloc) 与 H5 (acceptance)

## 2. 各阶段成果摘要

### H4-A — Stable Module Registry (SMR): ViaStableBinding 冷启动执行
- 设计: docs/GTO_COLD_START_HEAP_REBASE_1_H4A_SMR_DESIGN.md (commit 7d3201d)
- 实现: commit 40aa715 (+802 行, 3 文件)
  - BootResolver 增 module_name_rva; UTF-16LE 名字表; stub smr_resolve helper
    (PEB Ldr InLoadOrderModuleList walk); ViaExportMap 仍 fail-closed
  - 失败语义: 未解析模块 → 无限循环, cookie 保持 0 (与 Phase-1 分配失败同类)
- 验证: 3 独立 ASLR 布局 exit 0; regions 319/319/319; unresolved_required=0/0/0;
  bootstrap status="Complete"; dump 48.5/48.6/48.7MB (12 sections);
  structure_ep_ok=true
- 测试: mida-pe lib 950→951 passed; 4 个新 h4a_* 测试; x64_asm 解码测试 14/14
- 证据: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4A_smr\
  (attempt_001 + layout_B attempt_003 完整 stderr; attempt_002 摘要)

### H4-B — OEP entry-chain evidence
- 设计: docs/GTO_COLD_START_HEAP_REBASE_1_H4B_* (commit 006ce83)
- 实现: commit 813894c (chain evidence), 4bc7230 (structural not family-gated)
- 验证: 3 ASLR 布局技术通过
- 已知缺口: attempt_001 原始 stderr 日志不可恢复 (仅摘要); 证据包 PARTIAL;
  正式 seal/sign-off 未授予 (GTO-H4-LEDGER-CONSISTENCY-1 已记录)

### H4-C — TLS directory capture/rebuild/evidence
- Seal-2 修正已完成 (GTO-H4-C-EVIDENCE-SEAL-2): verifier 移出 evidence root (tools/gto_h4c_seal/), created_utc=2026-08-20T19:42:00Z, manifest_self_hash 重算; verifier: 48/48 size+sha, 0 missing, 0 unexpected, self-hash MATCH, RESULT PASS
- 设计: docs/GTO_COLD_START_HEAP_REBASE_1_H4C_TLS_DESIGN.md (commit 19ff1f6)
- 实现: commit 87f38d2 前序
- 验证: 3 ASLR 布局 evidence PASS
- 状态: 正式证据封印 PENDING (GTO-H4-C-EVIDENCE-SEAL-1); sign-off PENDING

## 3. 纪律确认

- 无 bураs​s: 环境变量强制 MIDA_GTO_NO_BYPASS=1 (allowlist+effective 双检)
- 观察通道: MIDA_GTO_OBSERVATION_ONLY=1; candidate_created=false;
  目标终止 (terminate=ok, wait=signaled); 无产品候选声明
- ADR7 verifier: 17/17 PASS (本轮重跑确认)
- Oreans 回归: mida-packers-themida 123/123; iat discovery 加固 (aea53f5)
  测试绿, 非 GTO 主线
- 无样本/二进制入库; 证据留 vault

## 4. 请审核人决策

| 决策点 | 选项 |
|---|---|
| H4-A 正式签收 | 通过 / 驳回 (附理由) |
| H4-B 替代证据接受 | 接受 (摘要+其余2布局) / 要求重跑完整证据 |
| H4-C 证据封印 | 批准 / 待补 |
| 放行 H4-D | 放行 / 暂缓 |

> 注: 所有证据哈希可独立核验 (controller_attempt_*.json 含 stderr_sha256;
> 布局差异属 ASLR 正常; 不变式 = unresolved_required=0 + Complete install)。

## 6. 审核裁决与处置 (总指挥 2026-08-20)

- H4-A: 技术签收; 证据正式签收暂缓 (raw evidence partial — 3 候选输出中 2 有完整 raw 日志, 1 仅摘要; H4A_smr_correction layout_A exit=1 不计; layout_B/layout_C exit=0 不能补回缺失 raw run)
- H4-B: 接受替代证据为技术层结论; 不接受为完整 formal package (attempt_001 raw stderr 不可恢复; 保留摘要 + 2 完整布局)
- H4-C: 当前 seal (SEAL-1) 驳回 — verifier FAIL (unexpected=1: verify_h4c_seal.py 在 evidence root 内; created_utc 未来时间)
- H4-D: 暂不放行 live, 允许设计准备
- H5: 暂不放行

处置记录: docs/GTO_COLD_START_HEAP_REBASE_1_H4_REVIEW_DISPOSITION.md (GTO-H4-REVIEW-DISPOSITION-1, Seal-2 通过后补写)
