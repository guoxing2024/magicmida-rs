# 总指挥审计记录 — Batch 13 / WO-1301A-IMPL / WO-1302

日期：2026-08-22
审计基线：`0ef8ad5`（`oreans/two-sample-mainline`）
审计性质：只读审计结论转工单；不授予 LIVE-4，不授权实弹，不改变 vault 样本。

## 1. 项目基线

- 项目是 Windows x64 PE unpacking research workspace，主线为 `gto_launcher`，Oreans 双样本为回归墙。
- `mida-acceptance` 是独立验收内核，禁止依赖生产 unpacker/debugger/plugin；该边界目前由 `dependency_boundary.json` 与测试约束。
- runtime 当前是 `mida-antidebug-runtime` 单 DLL 基础设施，代码真实范围是 C ABI、attestation、telemetry、provenance、PEB surface；当前 `lib.rs` 明确写着尚无 anti-debug hook surface。
- 当前 HEAD 最近提交只有文档交付；WO-1301A-IMPL 尚未落代码，不能把“设计中的代码块/测试样例”报告成实现或验证。
- Git 分支相对 `origin/oreans/two-sample-mainline` ahead 6；工作树未见已跟踪改动，但存在被忽略的构建物、日志、缓存和 `crates/cli/gto_launcher/.../snapshot.bin`。hygiene 实跑结果：FAIL，1811 个 forbidden artifacts、2 个 cache directories。

## 2. 审计结论

### WO-1301A Route alpha revision：CONDITIONALLY ACCEPTED（仅限设计修订）

已修正上一版的 F1/F2/F3/F4/F5 方向，但以下事实仍未被证据证明：

1. 目标内普通读取是否必然经过保护器自己的 VEH 并产生可观测解密效果；文档中的“实验验证”不能以设计文档自证。
2. ADR-6 现有 loader 只证明 `LoadLibraryW` + `MidaAntidebugInitialize` 路径，不等于已证明 WalkerExecute ABI/线程/异常处理兼容。
3. `coverage_measure` 的候选地址语义、页粒度、重复候选去重、跨页读取边界和结果与覆盖率账本的绑定还需要可执行的离线合同。

结论：可作为下一轮实施设计输入；不能批准 LIVE-4。

### WO-1301A-IMPL：REJECTED — 退回协议和实现边界修订

阻断问题：

- **P0-ABI/地址空间错误**：`WalkerParams.candidate_addrs` 是裸指针。调用端把候选数组先写到 controller 进程的 mapping，但参数中的指针仍为 `0`；即使填入 controller 侧指针，目标进程也不能解引用 controller 地址。
- **P0-共享句柄错误**：controller 创建的 `CreateFileMappingW` handle 不能默认在目标进程有效；设计没有 `DuplicateHandle`、目标侧 `OpenFileMappingW` 或目标侧 `MapViewOfFile` 的完整协议。单 DLL 约束下必须明确“句柄如何跨进程获得/验证/关闭”。
- **P0-异常模型错误**：`catch_unwind` 不是 Windows SEH/AV 捕获器；Rust panic 不会把目标内存访问违规自动转换成 `Result`。`EXCEPTION_CONTINUE_EXECUTION` 也不能在没有修正 faulting instruction/context 的情况下无条件重试，否则可死循环/重复异常。
- **P0-VEH/SEH 生命周期与并发未定义**：文档同时把“保护器 VEH”和自定义 `SehFrame` 混在一起，未定义 handler 顺序、线程局部状态、嵌套异常、卸载/清理和目标已有异常链的保留规则。
- **P1-清理不完备**：超时/错误路径没有统一 RAII cleanup；120 分钟等待也不符合上一轮建议的 `2 rounds × 60min` 预算语义，且线程未完成时释放参数/映射会产生悬挂访问。
- **P1-证明链缺失**：`Provenance` / `RuntimeAttestation` 当前均 `deny_unknown_fields` 且 schema v1，直接添加字段会产生 schema/兼容性和构造器全量更新问题；文档没有列出具体迁移、canonical JSON、验收测试和 rollback。
- **P1-交付状态失真**：文档 §9 写“代码骨架 + 测试计划”，仓库却没有 `walker/`、`walker_invoke.rs`、`WalkerExecute` 或 walker 测试文件。必须改成 design-only，不能标记实现完成。
- **P1-模块边界不对齐**：现有 runtime 文档明确当前不提供 hook surface；本工单若扩展导出，必须先定义 API version、feature gate、export allowlist、artifact authority 绑定和默认路径零变化。

因此不派发“直接实现远程线程/注入代码”的工单；先修协议和离线合同。

### WO-1302：CONDITIONALLY ACCEPTED — 设计需修订后才可进入实施

- 三维观测方向（RIP、线程等待原因、EnumWindows）可保留。
- LIVE-4 草稿仍写 `Route U R1 / Route V R0` 历史案例，违反样本身份规则；必须改为 `resolve_gto_source_revision` 通过的 manifest-authorized rev2 vault object。
- “2-3 次”与上一轮硬预算不一致；改成总 cap=2 rounds，每 round 60min，内部阶段预算不得突破总 cap。
- 设计中出现 Phase 2-3 handlers、单步、CFG、内存快照等后续动作，必须从本轮只读诊断实施范围中拆出，避免条件批准被扩大解释。

## 3. 当前门禁基线

- `cargo test --workspace --offline`：未得到测试结果。机器上的 cargo/rustc shim 无法创建/访问 rustup home（os error 183/5），不是代码 PASS。
- `pytest`：未得到测试结果。当前 Python shim 报 `uv trampoline failed` / `No installed Python found`，不是代码 PASS。
- `tools/verify_workspace_hygiene.ps1 -SkipGitDirtyCheck`：FAIL；必须清理/隔离 forbidden artifacts 后再宣称门禁通过。

## 4. 派单 Batch 14

### WO-1401（P0，docs-only，协议修订）

Owner：协议/ABI worker；写入范围仅 `docs/WO-1301A-IMPL-walker-execute-design.md`。

交付：
1. 给出跨进程通信的一个可证明方案：候选地址不得使用 controller 裸指针；明确 inline payload 或 DuplicateHandle + target MapView 的选择。
2. 写出 `repr(C)` 字段、位宽、对齐、版本号、最大长度、整数溢出检查、结果 framing、ownership/cleanup 状态机。
3. 明确样本身份 preflight、runtime artifact authority、export allowlist、默认路径零变化。
4. 把 120min 单次预算改为总 cap=2 rounds × 60min，定义 timeout 后的安全清理和证据状态。
5. 禁止实弹、禁止新增 DLL、禁止提交伪代码式“已验证”结论。

验收：文档中不得出现未绑定的裸指针跨进程方案；附 6 个负例（null、溢出、无效句柄、错误架构、超时、schema 漂移）及预期 fail-closed 结果。

### WO-1402（P0，代码前置，纯离线类型/协议）

Owner：runtime worker；写入范围仅 `crates/antidebug-runtime/src/walker_protocol.rs` 与对应离线测试，不得修改 exports、loader、CLI 注入路径。

交付：
1. 实现纯 Rust 的 versioned wire protocol：候选列表、结果列表、状态码、最大数量/最大字节数、checked size arithmetic。
2. 实现 deterministic encode/decode、拒绝 unknown version、截断、重复/越界 offset、NaN/Inf 参数。
3. 添加不需要 Windows live target 的单元测试；不要实现裸指针解引用、SEH、VEH、远程线程或 WriteProcessMemory。

验收：`cargo test -p mida-antidebug-runtime --offline` 在可用 MSVC 环境通过；协议模块不得新增生产依赖或改变现有 ABI。

### WO-1403（P0，docs-only，WO-1302 修订）

Owner：诊断 worker；写入范围仅 `docs/WO-1302-window-idle-diagnostics-design.md`。

交付：修正 rev2 identity preflight、预算为 2×60min、只读诊断边界；把 Phase 2-3 handlers/单步/CFG/快照列为后续工单，不得混入 LIVE-4；补充观测数据 schema、缺失数据处理、判据的“证据不足”分支。

验收：任何历史 Route U/V 工件只能作为背景，不能作为执行对象；文档不得签发实弹授权。

### WO-1404（P1，验证/工程卫生）

Owner：验证 worker；不修改生产代码。

交付：在不删除/覆盖证据的前提下，给出 out-of-tree `CARGO_TARGET_DIR`、固定 Rust toolchain、可用 Python 解释器和 hygiene 重跑矩阵；列出 1811 forbidden artifacts 的分类和安全隔离动作。任何 move/delete 必须先产出路径、SHA-256、目标 vault 位置和回滚方案。

验收：输出可复现命令和原始 stdout/stderr；禁止把环境阻断写成测试通过。

## 5. 总指挥执行纪律

- 当前状态：WO-1301A-IMPL 不放行；WO-1301A 仅条件接收；WO-1302 退回修订；不签 LIVE-4。
- worker 回报必须附：commit、改动文件、测试命令、原始结果、残余风险、未完成项。
- 只读设计、离线协议、实弹实施三者分离；任何 worker 不得跨越工单边界自行接线。
