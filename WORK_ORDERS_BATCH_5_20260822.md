# 工作单批次 5 — Round 2 批准与实施(总指挥签发)

**签发人**: 项目总指挥 · 2026-08-22
**审批基础**: 实读 `GTO_H5_LIVE2_R1_REPORT.md`(合格、诚实)+ `GTO_H5_POST_SELF_DECRYPT_DESIGN.md`(合格,附修正案)
**账本**: GTO-H5-LIVE-2 · used=1/2 · **Round 2 = 最后一轮**,消耗后 remaining=0,任何后续需新治理

---

## 总指挥修正案(优先级高于设计原文,实现必须纳入)

### A1:采样清单增加 `.pdata`
设计仅采样 .rdata0/.rdata2。`.pdata` 熵 7.896 异常(R1 §三)必须在同一观察窗内回答:
若窗内 .pdata 熵随 .rdata 同步下降 → 运行时解密的异常数据;若持续高熵 → dump 布局伪影。
成本≈零(同一机制),避免单独开调查工单。**此即对 ".pdata 异常是否专项调查" 的裁决:并入 Round 2,不单开。**

### A2:Round 2 的**首要交付物是熵时间线**,候选产出为次要
设计隐含假设 Themida 做**整体批量解密**(C1 全局熵下降)。真实存在另一种可能:
**惰性/按页解密**(只解密实际执行的页)——若是,C1 永不触发,C3 必然超时。
因此规定:
- 无论 C1/C2/C3 哪个结局,**完整熵时间线(.rdata0/.rdata2/.pdata × 全部采样点)必须落盘证据**;
- 若 C3 超时且熵全程平坦 >7.5:结论必须显式写 "惰性解密假设成立,整体等待策略无效"
  ——这是**有效科学结果**,不是失败;它把下一杠杆指向"执行驱动覆盖后 dump"(连接 Route H 时代 UI-prefer 实验);
- 禁止在时间线不支持时硬造候选。

---

## WO-401(P1)PostSelfDecrypt 实现 + 离线验证(**不含实弹**)

按 WO-302 设计 + 修正案 A1/A2 实现 `dump_process` 的 PostSelfDecrypt 分支:

1. 观察窗:起点=主线程恢复;500ms 周期 RPM 采样 .rdata0/.rdata2/**.pdata** 各 4KB;
   60s 硬上限;全程事件循环推进(不冻结目标);
2. 判据:C1(两节均 <6.5 连续 3 点)/ C2(RIP 稳定入 .text >2s)/ C3(超时 fail-closed 拒绝产出候选);
   时间线无论结局全量落盘(A2);
3. 零写入约束照设计 §2.3 表;T5 静态审计测试必须存在且通过;
4. 离线测试 T1-T6 全绿 + 全量 workspace 测试绿(≥2266/0);
5. **停止点**:实现完成后提交本地 commit,**实弹前把 diff 摘要报总指挥复核**
   (预实弹门,总指挥确认后才发 WO-402 开跑指令)。

## WO-402(P1,**门禁于总指挥对 WO-401 的书面放行**)GTO-H5-LIVE-2 Round 2 实弹

1. 身份预检硬门(同 Round 1;mismatch 即停不耗轮);
2. `MIDA_GTO_NO_BYPASS=1`;PostSelfDecrypt timing 运行采集;
3. 报告 `docs/GTO_H5_LIVE2_R2_REPORT.md`:熵时间线全量、判据触发记录、
   候选(若有)sha256+smoke N≥3、**eager-vs-lazy 显式结论**(A2)、非声明段;
4. 记账 used=2/2,remaining=0;vault append-only。

---

## 红线(授权文件 §四 全文继承)

❌ bypass/semantic repair/DRx/VEH/注入/目标写入(core 既有语义除外:soft bp int3、Suspend/Resume)
❌ 样本入 git;ADR7/Oreans 门/封存证据触碰;未放行先实弹
✅ MSVC 环境;fmt/hygiene/双 lane 三件套;worker 不执行 push

**签发**: 项目总指挥 · 2026-08-22
