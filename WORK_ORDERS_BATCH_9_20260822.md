# 工作单批次 9 — 自研反反调试机制路线(总指挥签发)

**签发人**: 项目总指挥 · 2026-08-22
**owner 决策(已生效,记录在案)**: **弃用外部 ScyllaHide;反反调试一律使用自研机制**
(即 ADR 洁净室栈:`crates/antidebug` + `antidebug-runtime` + ADR-1..6 文档系)。

## 决策的边界与影响(总指挥裁定,随决策生效)

1. **不重开 GTO 终局**:dump 式结构性不可达结论不受本决策影响;自研机制是基础设施能力建设;
2. **Oreans 线可替换**:legacy `antiantidebug` 中 ScyllaHide 注入("mandatory" 标记)是唯一
   外部依赖点——达到对等覆盖后可摘除(供应链清洁 + 许可证干净);
3. **未来线受益**:任何新样本线(含假设性 GTO 重启)以自研隐身层为前提条件;
4. **洁净室纪律不变**:实现遵循 `docs/MIDA_ANTIDEBUG_CLEAN_ROOM_RULES.md` 与
   `MIDA_ANTIDEBUG_EVIDENCE_CONTRACT.md`;不参考 ScyllaHide 源码,只对照其**公开技术清单**
   做覆盖度矩阵(行为级需求,非实现复制)。

---

## WO-901(P0)覆盖度差距审计(离线,代码审查+文档)

产出 `docs/MIDA_ANTIDEBUG_GAP_ANALYSIS_20260822.md`:

1. **现状盘点**:逐一列出 antidebug/antidebug-runtime/surfaces(proc.rs、win32.rs)当前
   **实际实现**的技术项(文件:行号),区分 完整实现 / 骨架 / 仅档案登记未实现 三档;
2. **ScyllaHide 公开技术矩阵对照**:PEB BeingDebugged/NtGlobalFlag/堆标志、
   NtQueryInformationProcess(ProcessDebugPort/DebugObjectHandle/DebugFlags)、
   NtSetInformationThread(ThreadHideFromDebugger)、CheckRemoteDebuggerPresent、
   DRx 寄存器清零、时序攻击(RDTSC/QPC)掩盖、调试器窗口/父进程检查、
   用户模式 syscall 路径(KiFastSystemCall)等——逐项标注 自研已有/缺失;
3. **suspected-SecureEngine-class 需求侧**:结合 WO-601 行为矩阵(TLS 时刻解析器、
   unwind 混淆、调试端口检测致怠速),标注哪些缺口是"对该类保护器致命"的;
4. **结论**:差距表 + 致命缺口 Top-N。

## WO-902(P1)对等路线图设计(docs-only)

产出 `docs/MIDA_ANTIDEBUG_PARITY_ROADMAP.md`:

1. 分阶段计划(建议按"致命缺口优先"),每阶段:技术项、落点模块、证据契约条目
   (对应 MIDA_ANTIDEBUG_EVIDENCE_CONTRACT)、离线验证方案、完成判据;
2. Oreans 线接线方案:替换 mod.rs 的 ScyllaHide pre-injection 为自研栈的切换开关设计
   (双轨期:profile 决定走 legacy 还是自研,回滚开关保留);
3. 明确不做项:DRx 硬件断点对抗(授权红线)、内核态手段(用户态边界)、
   任何 bypass 语义;
4. 工作量分级估算(S/M/L),供后续批次拆单。

---

## 红线

- docs-only 本批次(WO-901 是审查+文档,WO-902 是设计;**零实现**);
- 不触碰 GTO 终局结论与账本;ADR7/Oreans 门/vault 封存不动;
- 洁净室规则全程适用;MSVC 环境;worker 不 push。

**执行顺序**: WO-901 → WO-902。预计合计 5–8h。
**签发**: 项目总指挥 · 2026-08-22
