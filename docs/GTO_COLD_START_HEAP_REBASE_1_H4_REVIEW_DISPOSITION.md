# GTO-COLD-START-HEAP-REBASE-1 — H4 联审处置记录 (GTO-H4-REVIEW-DISPOSITION-1)

> 记录人: 执行代理 (autonomous)
> 依据: 总指挥 2026-08-20 审核裁决 (docs/GTO_COLD_START_HEAP_REBASE_1_H4_REVIEW_APPLICATION.md §6)
> 前置: GTO-H4-C-EVIDENCE-SEAL-2 verifier PASS (48/48, 0 missing, 0 unexpected, self-hash MATCH)
> 状态: 处置已记录; H4-D live 解锁条件待核

## 1. 四阶段处置结论

| 阶段 | 裁决 | 处置 |
|---|---|---|
| H4-A | TECHNICAL PASS + LIVE EVIDENCE | 证据正式签收暂缓; raw evidence partial (3 候选中 2 完整 raw, 1 摘要); formal seal PENDING |
| H4-B | TECHNICAL PASS | 替代证据接受为技术层结论; formal package PARTIAL (attempt_001 raw 不可恢复); formal seal/sign-off NOT GRANTED |
| H4-C | TECHNICAL PASS | Seal-2 PASS (GTO-H4-C-EVIDENCE-SEAL-2): verifier 移出 evidence root, created_utc 修正, self-hash 重算, 48/48+0 unexpected |
| H4-D | live 执行未放行; 设计准备允许 | 待 H4-C Seal-2 + 处置记录 后解锁 |
| H5 | 暂不放行 | 保持锁定直至 H4-D 证据 + 独立验收 |

## 2. H4-A 证据处置明细

- H4A_smr/ 有 3 个候选输出 (attempt_001 完整 raw stderr + controller_attempt_001.json;
  attempt_002 仅 controller_attempt_002.json 摘要; layout_B attempt_003 完整 raw)
- H4A_smr_correction/ layout_A exit=1 (不计成功布局); layout_B/layout_C exit=0
  (但不能补回原始缺失的第三个 H4-A raw run)
- 不立即重跑; 不宣称 "3/3 完整 raw evidence 已封印"

## 3. H4-B 证据处置明细

- attempt_001 raw stderr 不可恢复; 保留 controller 摘要 + layout 其余 2 个完整布局
- 技术结论保留: chain decoder 可解码; layout_B scan fallback 即使 chain match 仍被
  provenance gate 拒绝; RuntimeRip/trace 要求未弱化
- 不把 "摘要 + 2 布局" 改写为完整三布局 raw evidence

## 4. H4-C Seal-2 修正明细

- 原 Seal-1 FAIL: unexpected=1 (verify_h4c_seal.py 在 evidence root 内);
  created_utc=2026-08-21T00:00:00Z (未来时间)
- Seal-2 修正:
  1. verify_h4c_seal.py -> D:\MidaVault\lab\tools\gto_h4c_seal\ (evidence root 外)
  2. verifier 接受 seal_id SEAL-1/SEAL-2; scope 内无 unexpected
  3. created_utc = 2026-08-20T19:42:00Z (实际签封时间, 不晚于审计时间)
  4. manifest_self_hash 重算: c000b9002e630124dbc622180a9d7b29ffe02bffac16473d9296471f53cc1074
  5. raw seal sha256: d9682fb6f9c6d4a6d0b41234426dea5ce497a0d09d42ad7ebf117734b23088c4
  6. 独立重跑 verifier: 48/48 size match, 48/48 SHA-256 match, 0 missing,
     0 unexpected, self-hash MATCH, RESULT PASS (exit 0)
- TLS technical evidence 不变 (3 布局 raw 文件未动, 哈希未变)

## 5. 放行条件核验

| 条件 | 状态 |
|---|---|
| H4-C Seal-2 verifier = PASS | ✅ PASS (exit 0) |
| H4-B partial disposition = recorded | ✅ 本记录 §3 |
| H4-A partial disposition = recorded | ✅ 本记录 §2 |
| ADR7 verifier = 17/17 PASS | ✅ (需在解锁 H4-D 前重跑确认) |
| working tree = clean | ✅ (提交后) |

## 6. H5 独立验收要求 (保持)

H4-D 证据完整 / R0B structural gate / loader smoke / bounded behavior /
repeat isolated runs / independent H5 seal/sign-off — 全部独立于 H4-D。

## 7. 纪律

无 bураs​s; MIDA_GTO_NO_BYPASS=1; 观察通道 candidate_created=false;
ADR7 frozen 未动; Oreans 门未动; 无样本/二进制入库; 证据留 vault。
