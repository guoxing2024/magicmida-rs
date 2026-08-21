# 工作单批次 4 — H5 实弹重开(总指挥签发,owner 行国胜全权委托)

**签发人**: 项目总指挥 · 2026-08-22
**授权依据**: `docs/GTO_H5_LIVE_AUTHORIZATION_2_20260821.md`(已签发)+
`docs/GTO_H4_ABC_FORMAL_SIGNOFF_20260821.md`(H4-A/B/C 已正式签核落账)
**账本**: `GTO-H5-LIVE-2` cap=2 / used=0 / remaining=2

---

## WO-301(P1)GTO-H5-LIVE-2 Round 1:再基线 + 测量

严格按授权文件 §二 执行,顺序不可调换:

1. 身份预检:`tools/resolve_gto_source_revision.ps1`;mismatch 即停(记
   SampleIdentityMismatch,**不消耗轮次**——预检停不算实弹轮);
2. `MIDA_GTO_NO_BYPASS=1`,no-bypass 采集候选(Immediate timing);
3. 提取候选 manifest 的 `.rdata0/.rdata1/.rdata2` R2 熵观测数据;
4. loader smoke N≥3,如实记录;
5. 报告 `docs/GTO_H5_LIVE2_R1_REPORT.md`:含身份哈希、候选 sha256/size、熵表、
   smoke 结果、与 r27 时代 9/9 崩溃的可比性结论、非声明段。
6. vault 新证据目录 append-only;**报告先于任何 Round 2 动作**。

**验收**: 报告落盘 + 轮次记账(used=1)+ 无红线违反。全败亦是有效交付。

## WO-302(P2,条件工单)PostSelfDecrypt 设计说明

仅当 WO-301 数据支持(密文假设成立)才启动;产出
`docs/GTO_H5_POST_SELF_DECRYPT_DESIGN.md`:有界观察窗设计、完成判据(不许"猜解密完成")、
仅用 core 既有调试原语、对目标零写入清单、离线单测方案、失败模式表。
**本单只出设计,零代码**;实现须另批。

---

## 红线(继承批次 3 全部 + 授权文件 §四)

- ❌ bypass/semantic repair/DRx/VEH/注入/目标写入(核心调试器既有语义除外)
- ❌ 样本入 git;ADR7/Oreans 门/封存证据触碰;为凑预检改 manifest
- ❌ 未签 Round 2 设计前实现 dump_process 观察等待分支
- ✅ push 已由总指挥处理(worker 不执行任何 git push)

**签发**: 项目总指挥 · 2026-08-22
