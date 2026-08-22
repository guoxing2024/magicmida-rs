# 工作单批次 11 — WO-1005 Oreans 双轨真实接线(总指挥签发)

**签发人**: 项目总指挥 · 2026-08-22
**前置**: 违规 A1-A5 已记录(WORKER_HANDOFF §M);WO-702C 复审 ACCEPTED(cde2c37)
**性质**: 本单是 Phase 4 被拆出的**核心接线**,涉及 Oreans 主流程敏感改动——单独送审。

---

## WO-1005(P1)双轨真实接线:让模式开关真正被生产路径 consult

**现状(诚实基线)**: `config.rs` 的 `AntidebugMode/current_mode()` 全库零调用点;
`lib.rs` 仍无条件走 `inject_scylla_hide`(L44)。

### 任务

1. **接线点**:`themida/lib.rs` 现有 ScyllaHide 注入调用处,按
   `antiantidebug::config::current_mode()` 分支:
   - `Legacy`(默认)→ 原路径**逐字节不变**;
   - `SelfDeveloped` → 激活自研栈(ADR 控制器 + antidebug-runtime surfaces,
     含 AD-PROC-002..005 + handlers/timings 已实现处理器),**不注入 ScyllaHide**;
2. `initialize_mode()` 在进程初始化早期调用一次;`MIDA_ANTIDEBUG_ROLLBACK=1` →
   运行时任何异常回退 legacy(开关语义照 config.rs 既有注释);
3. 证据契约:激活/回退事件写入 runtime-attestation(`mida.antidebug-profile/v1`);
4. 测试:双轨分支单测(mock 层面)+ 默认路径回归(不设环境变量时行为与 main 分支一致);
5. **停止点**:完成后 diff 摘要报预验收;**生产默认翻转与实弹验证不在本单范围**
   (须 owner 单独授权,Oreans 两样本实弹沿用既有授权纪律);
6. 附带整改:`WO-1002-1003-1004-返工报告.md` 从根目录移至 `docs/`(根目录不留文件——第三次提醒)。

### 验收

- [ ] 不设 `MIDA_ANTIDEBUG_MODE` 时:全量测试 ≥2317/0,主流程行为零变化;
- [ ] 设 `self`:分支走到自研栈,attestation 记录生成(mock 验证);
- [ ] 回滚开关测试绿;fmt/hygiene/双 lane 干净;
- [ ] 仅本地提交,**禁止 push**(A1 整改兑现的第一单)。

---

## 红线

继承全部既有约束;本单不改 ScyllaHide 二进制引用的移除时机(那是翻转后的后续清理);
洁净室规则适用。

**签发**: 项目总指挥 · 2026-08-22
