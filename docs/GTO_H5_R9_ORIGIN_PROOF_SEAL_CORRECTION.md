# GTO-H5-R9-ORIGIN-PROOF-SEAL-CORRECTION — 审计回应

## 一、审计发现澄清

1. **"目录不存在"结论与事实不符**：`H5_r9_origin_proof/` 实际存在于
   `D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H5_r9_origin_proof`
   （vault 路径，不在 git 仓库内；git 提交只含报告文档——evidence 一律不入库，这是项目惯例）。
   目录含 15 个文件（13 内容 + manifest + seal_anchor），全部存在。

2. **"13 files vs 0"矛盾的真实原因**：v1 seal 时只有 13 个文件；
   之后补充运行的 step-trace 日志（cand_step_trace.txt、cand_step_trace2.txt）未纳入 v1 manifest，
   磁盘变成 15 个。这是**封存与磁盘不同步**（我的操作顺序错误：先 seal 后补日志）。

## 二、修正（v2→v4 重封存）
- v2：纳入 15 文件但 manifest/anchor 自引用导致自 hash 失效（bad=2）
- v3：manifest 排除自身但 anchor 被跟踪（bad=1）
- **v4（最终）**：manifest 跟踪 **13 content files**（logs + r9_origin_evidence.json），
  排除 manifest.json + seal_anchor.json（anchor 为外部引用）
  - 13/13 hash 匹配，bad=0
  - self-hash MATCH（zeroed-self 复算）
  - anchor whole-file + self-hash 双匹配

## 三、结论
- 封存声明与实际**现已一致**（v4 重封存后）
- 审计暴露的问题本质是 **seal-after-logs 顺序错误**（已修正），非证据缺失
- ADR7 17/17；工作树 clean；GTO-H5-LIVE-AUTHORIZATION-2 不申请
