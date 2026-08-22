# 工作单批次 8 — GTO 线终局收官(总指挥签发)

**签发人**: 项目总指挥 · 2026-08-22
**前置裁决**: WO-703 ACCEPTED(数据独立验证)。**Round 2 不再授予——LIVE-3 以 used=1/2 终结,
剩余 1 轮刻意保留不花**(理由见下)。owner 选项 B 收官生效。

## 战略裁决理由(binding)

1. 三重证据闭合:LIVE-2 R2(被动等=零解密)+ LIVE-3 R1(真实运行 300s=零新增解密页,
   unreadable=0 排除藏页)+ 结构论证(按页惰性解密 ⇒ 独立重跑必走新路径 ⇒ 必踩密文页);
2. **结论对"窗口为何未现"不变**:无论反调试停滞还是环境阻塞,dump 式天花板结论不受影响;
3. 花掉最后一轮属于好奇心消费,违反 §4.4 ROI 纪律;未花的轮次本身是干净的终局记录;
4. 若未来重启(新工具/新思路),走新治理,不以本账本余轮为据。

---

## WO-801(P0)终局定性报告

产出 `docs/GTO_TERMINAL_CHARACTERIZATION_20260822.md`,综合全弧线:

1. 时间线:r27(26 轮 UI 剥离)→ Route A–H(16 轮恢复)→ H0–H6 冷启动堆重定基 →
   ADR7/B4/B5 证据闭环 → GTO-COLD-START-HEAP-REBASE → LIVE-2/LIVE-3 量化实验;
2. 定量锚点表:密文熵 7.43/7.88/7.90、被动等待零解密、执行 300s 零新增页、
   unreadable=0、覆盖 4.26% 恒定(=磁盘态基线)、60% 经济门差距 14 倍;
3. **终局命题**(分级措辞):suspected-SecureEngine-class 保护 + 执行驱动按页解密 ⇒
   **dump 式完美脱壳结构性不可达;"保护器拥有执行"为 dump 路线终态**
   ——每条断言挂对应证据指针;
4. 结构天花板论证独立成节(交互式脱壳也无法产出可独立运行的二进制,除非破译保护器
   解密算法——超出范围且与 bypass 红线冲突);
5. 已关闭项清单 vs 永久开放项清单;非声明段。

## WO-802(P1)措辞修正落笔(依据 WO-601 清单,现予批准)

按 `GTO_PACKER_ATTRIBUTION_REPORT.md` 的 10 处清单,把 "Themida" 断言改为分级措辞
(`suspected-SecureEngine-class` / 具体版本 `unverified`)。**只改断言强度,不改叙事事实;
WORKER_HANDOFF 历史条目不改写(加编者注即可)。**

## WO-803(P1)账本与交接收口

1. 边界账本:H5 行 → **TERMINAL(dump-route)**,LIVE-3 used=1/2 remaining=1(deliberately unspent);
2. `WORKER_HANDOFF.md` 追加终局条目:全弧线摘要 + 本裁决 + 重启需新治理声明;
3. README "Current status" 段同步(仍不声称 perfect/universal);
4. product 1.0 定义修订提案单列一节(受保护目标:忠实 dump + 已知限制文档化),
   **仅提案,不自行生效**。

---

## 红线

docs-only 全程;ADR7/Oreans 门/vault 封存不动;无实弹;worker 不 push。
两单可并行,统一收口提交。

**签发**: 项目总指挥 · 2026-08-22
