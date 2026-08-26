# WORK ORDER — GTO-R6-A2: LOADER SMOKE (DIAGNOSTIC)

**签发**: Hermes 总审计，owner 已书面批准执行（2026-08-25）
**性质**: 诊断性 loader smoke — **NOT acceptance evidence**（沿用 H5 crash attribution 先例）
**前置**: A1 PASS（独立复算 15B/4 段 diff，输出 SHA `c4a1a94e…`）

## 1. 目的

检验 startup-order attribution 假设：candidate 崩溃源于 dump 器改写四个
数据目录 RVA。A1 已产出恢复真值的修正版 PE。本单运行它并观察 resolver→entry
路径是否与 protected 参考一致。

## 2. 输入

| 对象 | 路径 |
|---|---|
| 被测 | `D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\R6_A1_dd_restore\layout_A\gto_unpacked.dd_restored.exe`（SHA `c4a1a94e367c0f555243d3408446df0320c04d2262cc039a2fd436a064e01637` — 运行前先验哈希，mismatch 即 STOP） |
| 参考行为 | GTO_H5_STARTUP_ORDER_ATTRIBUTION_REPORT.md §一（TLS0 → … → resolver 0x1417223b2 → 正常返回 → ENTRY 0x1416fb532） |

## 3. 执行协议

- 调试器: cdb（诊断通道），单实例、限时（硬上限 120s）、超时即 kill；
- 断点: TLS0 `0x141728972`、resolver `0x1417223b2`、entry `0x1416fb532`；
  记录每次命中时的 rip/关键寄存器；
- 异常: 首个 second-chance 异常即记录完整现场（exception addr/RVA/section/
  regs/faulting address）后终止——不做乱码游走追跑；
- 环境: 无需 MIDA_GTO_LIVE 授权变量（本单是 owner 直接批准的诊断 smoke，
  非 LIVE-4 注入链验证）；不得注入/修改目标内存，只读观察 + 断点。

## 4. 绿色判据（二值）

- **A2-PASS**: resolver 入口被命中且正常返回（rip 到达 entry `0x1416fb532`
  或其后 20 条指令窗口内），无 second-chance 异常 → 因果假设成立，
  下一步进入 H6 行为验证设计。
- **A2-FAIL**: 任何位置 second-chance 异常或超时 → 完整记录崩点 RVA/section/
  faulting address 与寄存器，假设修正，证据交总审计做根因分析。

PASS 与 FAIL 都是有效科学结果；**禁止**在未达判据时重试超过 2 次
（attempt_001..003 上限），禁止改样本字节来"让它过"。

## 5. 禁止

- 修改 dd_restored.exe 的任何字节；
- 写入/patch 目标进程内存（断点除外，且必须用 cdb 原生 bp 机制）;
- 把本结果写成 acceptance/loader-pass 声明;
- 触碰 Oreans 门、R5 冻结语义。

## 6. 交付物

- vault: `D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\R6_A2_loader_smoke\attempt_NNN\`
  （cdb 全量日志、命中时间线、异常现场 JSON）
- repo: `docs/GTO_R6_A2_LOADER_SMOKE_REPORT.md` — 判定 A2-PASS / A2-FAIL +
  判据对照表 + raw 日志指针
