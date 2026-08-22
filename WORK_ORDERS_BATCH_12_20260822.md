# 工作单批次 12 — WO-1006 架构归属裁决与接线(总指挥签发)

**签发人**: 项目总指挥 · 2026-08-22
**依据**: worker 对位图 + 总指挥独立核验(`unpacker/mod.rs:1663` 的
`handle_nt_set_information_thread` 分发确在生产运行——调试器侧拦截模式已被验证)。

---

## 总指挥裁决(Q1-Q3)

### Q1(CRDP / NtQueryObject 归属)→ **调试器侧**

理由:① `unpacker/mod.rs:1663` 的 ThreadHideFromDebugger 拦截证明该分发模式
**已在生产工作**(事件循环集成完毕、经 Oreans 门检验);
② runtime DLL 当前只有**被动 PEB 补丁**能力,新增主动 API 钩子引擎属 L 级新架构,
成本/收益比劣于沿用既有分发点;
③ 直连 syscall 绕过风险对两侧等同,如实记录为已知局限。
**Phase 2-3 实现保留在 themida/handlers.rs——它们不是放错位置,而是待接线的正确位置。**
(修正我此前"迁居 runtime 层"的中间倾向。)

### Q2(时序对抗归属)→ **调试器侧**,附诚实限制

timings.rs 纯函数分类模型已就位;接线方式 = 对 QPC/GTC 系列 API stub 断点拦截,
用 TimingProbeState 归一化增量。**硬限制**:裸 `rdtsc` 指令用户态不可掩——只覆盖 API 级
时序探测,此限制必须写入文档与 attestation。观测通道独立性维持(路线图风险 2)。

### Q3(activate_antidebug 处置)→ **废弃删除**

该函数建立在我的工单错误前提上("lib.rs 现有注入调用处"不存在);Self 臂空壳;
全库零调用者。**删除函数及 lib.rs 导出**;`config.rs`(AntidebugMode/环境解析)保留——
改作下述新分支的策略门,已测试无害。

---

## WO-1006(P1)实施:三分支接入既有分发点 + 模式门控

### 任务

1. 在 `unpacker/mod.rs:1663` 既有分发结构处扩展三个分支(复用同一拦截模式):
   - `handle_check_remote_debugger_present`(伪造 FALSE 输出);
   - `handle_nt_query_object`(返回 STATUS_INVALID_HANDLE);
   - 时序探测归一化(QPC/GTC stub 拦截 + `classify_probe`/`masked_delta`);
2. **门控纪律**:新分支一律由 `current_mode() == SelfDeveloped` 门控
   (`MIDA_ANTIDEBUG_MODE=self` 才激活);默认 Legacy = 现行为零变化
   ——这是"默认零变化"纪律在本单的落点;
3. 删除 `activate_antidebug` 及其 lib.rs 导出(A3/A5 教训:不留无主代码);
4. 单测:三分支处理逻辑(mock)+ 门控矩阵(Legacy 不触发/Self 触发/回滚开关)+
   timings 既有测试不回归;
5. 附带:`docs/WO-1005-completion.md` 未跟踪状态入库或并入 attestation 文档(收尾)。

### 验收

- [ ] 全量测试 ≥2317/0(完整跑通,MSVC 环境);
- [ ] 默认(Legacy)路径行为零变化;
- [ ] 三新分支在 Self 模式下可观测触发(mock 断言);
- [ ] activate_antidebug 及导出移除后无编译警告;
- [ ] fmt/hygiene 干净;仅本地提交,**禁止 push**。

## 明确不做项(继承)

DRx/内核态/裸 rdtsc 掩盖/bypass 语义/生产翻转(须 owner 授权)。

**签发**: 项目总指挥 · 2026-08-22
