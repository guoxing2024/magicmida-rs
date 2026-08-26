# GTO-H6 LIVE-4 授权申请书（草案 v1）

**起草**: Hermes 总审计 2026-08-25
**状态**: DRAFT — 待 owner 签发
**申请类型**: GTO-H6-LIVE-AUTHORIZATION-1（walker 注入链对受保护样本的首轮实弹验证）

---

## 一、申请动机

### 1.1 dump 式路线已证伪（2026-08-25 R6 实验）

- **A1/A2 数据目录还原实验**: 将 candidate 四个被改写的数据目录 RVA 恢复为
  受保护参考真值后 loader smoke 仍然 FAIL——resolver `0x1417223b2` 命中后
  未返回，second-chance AV @ `.rdata0`；且 attempt_001 崩点与原始 candidate
  完全一致（`0x142934089`/读 `0x9fd548`），证明执行路径无差异。
- **结论**: startup-order attribution 的"resolver 读被改写头部"因果链不成立；
  resolver 的解析源不是（仅）PE 头字段。dump 式修复捷径不存在。
- 证据: `docs/GTO_R6_A2_LOADER_SMOKE_REPORT.md` + vault
  `R6_A2_loader_smoke/`（3 attempts cdb raw 日志）。

### 1.2 注入链是唯一活跃路线

IMP-09 walker/V2 runtime 链已具备:
- R5-R2 密封 carrier/事务安装/execute fail-closed 门（C4 封存）；
- R5-R3 生产 section producer/consumer + V2 attestation digest 闭环
  （独立审计 PASS，242 tests / 0 failed，21 个 R5-R3 专项测试）；
- R5-R4 teardown observability 实施中。

## 二、申请范围

| 项 | 内容 |
|---|---|
| 目标 | vault 锚定的 GTO 样本（rev 2, SHA `11473d2e…`）经 preflight 解析后 |
| 动作 | controller 进程向目标进程注入 V2 runtime DLL + walker session 建立 + round-1/round-2 探测执行 + output 消费 |
| 环境 | `MIDA_GTO_NO_BYPASS=1`、观察优先、授权变量单命令窗口 |
| 轮次 | 申请 **2 个 attempt**（与 H5-LIVE-3 账本口径一致） |

## 三、前置条件（签发前必须全部满足）

- [x] R5-R4 teardown PASS 并经独立审计（commit c33401a, 2026-08-25）;
- [x] 全 workspace `cargo test` 绿：**2714 passed / 0 failed**（单线程全量，
      2026-08-25 复验，含 dispatch 桥 T1-T12）;
- [x] target-side dispatch 桥设计文档 + caller graph 经总审计签收
      （docs/IMP09_DISPATCH_BRIDGE_DESIGN_20260825.md，commit a33664b）;
- [x] 生产实现已交付并审计通过（walker_dispatch.rs, commit 9b05abc；
      T1-T12 12/12；LIVE 门保持关闭——两处生产接线恒 None）;
- [x] Oreans 回归门 ADR7 17/17 复验 PASS（2026-08-25 总审计独立重跑）;
- [x] 样本 preflight resolver dry-run MATCH（revision_match=true,
      2026-08-25 只读复验）。

## 四、风险与边界

- 不声称: 本轮即 acceptance / wall broken / 厂商确证;
- 失败轮次照常记账（used/remaining），FAIL 是有效科学结果;
- 崩溃现场按 H5 先例以 DIAGNOSTIC class 记录，不作 acceptance evidence;
- 目标进程崩溃不影响主机; 所有产物入 vault content-addressed 存储。

## 五、签发栏

```
owner 签名/日期: owner (chat 授权) 2026-08-25
生效条件: 第三节前置条件逐项打勾后由 owner 书面放行 —— 已满足（6/6，见 §三）
账本: GTO-H6-LIVE · Round 0 · used=0/2 → **SIGNED, Round 1 开放**
```

> **签署记录**：owner 于 2026-08-25 在 Hermes 会话中书面指示
> "签署 docs/GTO_H6_LIVE_AUTHORIZATION_REQUEST_20260825.md（第五节签发栏）"，
> 视为 §五 生效所需的书面放行。总审计据此可起草 GTO-H6-LIVE-1 执行工单。
> 约束不变：attempt ≤2、FAIL 记账不重试超限、崩现场按 DIAGNOSTIC class 处理。
