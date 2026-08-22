# 工作单批次 10 — 自研反反调试对等实施(总指挥签发)

**签发人**: 项目总指挥 · 2026-08-22
**批准依据**: WO-901 差距审计(代码抽查属实)+ WO-902 路线图(本批批准生效)
**总原则**: 每阶段独立提交、独立验收;全量测试基线 ≥2280/0 不回归;
洁净室纪律全程;**默认行为零变化直至 Phase 4 显式切换**。

---

## WO-1001(P0)= Phase 1:致命对等(NtGlobalFlag + 堆标志)

按路线图 Phase 1 执行:

1. `antidebug-runtime/surfaces/proc.rs` 新增 **AD-PROC-004**(NtGlobalFlag,x64 偏移 0xBC,
   authority 常量 + 运行时校验)与 **AD-PROC-005**(堆标志 HeapFlags/HeapForceFlags);
2. install/restore/original 三态记录,证据契约 `mida.antidebug-probe-result/v1`;
3. PEB 布局单测 + 标志位模型纯函数测试;
4. 验收:单测绿 + 全量 ≥2280/0 + fmt/lane 干净。

## WO-1002(P1)= Phase 2:CRDP 对抗 + 时序掩盖

按路线图 Phase 2:`handlers.rs` CRDP 分支(伪造返回模型)+ 新 `timings.rs`(固定时钟输入下
确定性);证据契约 `mida.antidebug-observation/v1`;mock/确定性测试。
**注意风险 2**:时序掩盖不得影响观测通道(观测独立于时序补丁——设计已注明,实现须保持)。

## WO-1003(P2)= Phase 3:纵深防御

NtQueryObject(DebugObject 枚举)对抗 + OutputDebugString 对抗 + 驱动名检查;
新 `queries.rs`,复用 kifast syscall 解析模式;分支处理函数单测。

## WO-1004(P1,**门禁于 WO-1001..003 全绿**)Phase 4:Oreans 双轨接线

1. profile 决定 legacy/self;环境开关 `MIDA_ANTIDEBUG_MODE`(默认 **legacy**)、
   回滚开关 `MIDA_ANTIDEBUG_ROLLBACK=1`;
2. 双轨切换单测(profile=legacy → 原路径逐字节不变;profile=self → 自研栈激活);
3. ADR7 verifier 17/17 不回归;ScyllaHide 二进制引用清点归零(代码层);
4. **边界声明**:本单只交付开关与双轨能力,**生产默认翻转(legacy→self)及 Oreans 两样本
   实弹验证须另批授权**(沿用实弹授权纪律);未翻转前 Oreans 主流程行为零变化。

---

## 红线

不做项照路线图 §三(DRx/内核态/bypass 语义/解密算法复现);GTO 终局与账本不动;
vault 封存不动;worker 不 push;每单完成跑 fmt + hygiene + 双 lane 三件套。

**执行顺序**: WO-1001 → WO-1002 →(WO-1003 ‖ 等)→ WO-1004(门禁)。
**签发**: 项目总指挥 · 2026-08-22
