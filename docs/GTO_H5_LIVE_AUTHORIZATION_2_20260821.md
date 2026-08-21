# GTO-H5-LIVE-AUTHORIZATION-2 — 授权签发(2026-08-22)

**签发权源**: owner 行国胜授权总指挥全权处理(同 H4-A/B/C 委托记录)。
**效力**: 解除 H5 实弹冻结,**仅限本文件条款范围内**的运行。此前所有 "LIVE-AUTHORIZATION-2
未签发" 的表述自本文件起被本授权取代。

## 一、新账本命名空间

- Namespace: **`GTO-H5-LIVE-2`**
- Cap: **2 rounds** · Used: **1** (Round 1 COMPLETE 2026-08-21, see docs/GTO_H5_LIVE2_R1_REPORT.md) · Remaining: 1
- 每轮 = Rust/Python diff + rebuild + 实弹运行 + 报告(沿用 §4.4 口径);docs-only 不消耗轮次。

## 二、Round 1(强制先行):再基线 + 测量

目的:确认 r27 时代诊断在当前样本修订版上仍然成立,并为路径 (d) 提供决策数据。

1. **身份预检(硬门)**:`tools/resolve_gto_source_revision.ps1` 先行;
   `resolved_source.json` 必须 revision_match=true 才可继续;
   mismatch → 记 `SampleIdentityMismatch` 即停,**不得为过预检而更新 manifest**。
2. 环境:`MIDA_GTO_NO_BYPASS=1`;bypass/semantic-repair 变量必须缺席。
3. 采集:no-bypass 候选(Immediate timing,现管线)。
4. **测量(新增,R2 已就绪)**:候选 manifest 中 `.rdata0/.rdata1/.rdata2` 的
   `r2_encrypted_region_observations` 熵数据 —— 判定 dump 时刻这些节是否仍是密文。
5. loader smoke 矩阵 N≥3,如实记录(全败亦是有效结果)。
6. 报告先于 Round 2;vault 新证据目录 append-only。

## 三、Round 2(条件触发):PostSelfDecrypt 实测

仅当 Round 1 数据支持(如:.rdata 在 Immediate 时刻确为高熵密文)才可启动,且需先产出
独立设计说明(有界观察窗、仅用 core 既有调试原语、对目标零写入),报总指挥批准后实施。

## 四、禁止(全程)

- ❌ bypass / semantic repair / DRx / VEH / 注入 / 对目标进程写入(核心调试器既有语义除外)
- ❌ 样本/产物入 git;ADR7、Oreans 两样本门、封存证据触碰
- ❌ 修改 mutable 路径样本本身;manifest 为凑预检而被改
- ❌ 未签 Round 2 设计前实现 dump_process 观察等待分支

## 五、非声明

本授权不声称、也不允许声称:gto perfect unpack、product 1.0、"墙已破"。
每轮报告必须含明确非声明段。

**签署**: 项目总指挥(受托) · 2026-08-22 · 委托权源: 行国胜
