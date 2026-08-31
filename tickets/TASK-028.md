# TASK-028 — DEVIRT-CORE Phase 0：VPC 顺序演化验证 + 单 handler CFG 恢复（离线为主）

## 0. 授权令牌（原文回抄到报告第一节）

> `老板 · 2026-08-31 · 原话"作者联系不上，我们自己搞吧。我授权。需要新开会话吗？"`（按全案解释：批准 DEVIRT-CORE 战役（章程 `docs/DEVIRT_CORE_CHARTER.md`）首票 Phase 0 = VPC 顺序演化验证 + 至少 1 个 VM handler 的 CFG 恢复；**离线静态为主，不烧格**（账本 DEVIRT-CORE 0/8 起步）；若需动态验证 VPC 演化（泵下观测），须另票面授权实弹 1 格。）

## 1. 背景（先读 DEVIRT_CORE_CHARTER.md + runs/20260831-TASK-027.md）

- TASK-027 已证：Pushan §5.1 Themida 稳定 VPC 假设成立，5 个候选（r13@0x85daaa 最强 1438 次、r5@0x84d7d1 967 次、r6/r1 存疑），VPC 锚点在手。
- Phase 0 目标：① 验证 VPC **顺序演化**（Pushan §5.1：VPC 指向字节码区且**顺序演化**=递增/递减）——这是 VPC 确证的第二特征，静态可做；② 对至少 1 个 handler 跑通**CFG 恢复**（VPC 敏感 + 无约束符号模拟雏形）——证明工具链闭环。
- 工具基座：`crates/disasm/`（iced-x86 1.21 完整解码，REX/VEX/ModRM 全支持，无新增依赖）+ `crates/pe/`（PE 解析）+ `tools/xx21b_vpc_probe.py`（VPC 候选扫描，已验）。
- 输入工件（只读）：equivalence 41ec52e0（.winlice 明文）、候选 096f3bdf（同源对照）。

## 2. 红线（全程）

- `NO_BYPASS=1`；样品 sha 不匹配即 STOP；样品/产物/VM 语义知识不外发；禁止伪造证据；防火墙只读。
- **不击穿授权**：若还原出的逻辑显示"需注册码"，如实报告——授权框流程是行为等价的一部分。
- 不新增依赖（仅 std + 现有 workspace crates + pefile）；**`crates/` 生产代码不因本战役改动**（本票工具放 `tools/` 或独立 bin，如确需 crate 支持 → 新建 `crates/devirt-core/` 属战役自有，不动既有 11 crate）。
- git 写操作仅限本票新增文件（工具/报告/决策），不触碰既有代码。

## 3. 任务 1：VPC 顺序演化验证（离线静态，主判据）

1. 以 r13@0x85daaa（最强候选）为主验证对象，r5@0x84d7d1 为对照：
   - 收集所有以 r13/r5 为基址的 `[reg+disp]` 读取点（TASK-027 已扫 3682 处，取其子集）；
   - 对每个读取点，用 iced-x86 反汇编上下文，检查是否有**对 r13/r5 的增量/减量操作**（`add/sub/lea` 到自身 + 立即数）出现在读取点附近（同基本块或相邻块）；
   - 若能定位"读取字节码 → 增量 → 再读取"的循环模式 → **顺序演化成立**（VPC 确证）。
2. 输出：演化证据（读取点序列 + 增量指令 + 循环结构）+ 结论判定（成立/不成立/存疑）。

## 4. 任务 2：单 handler CFG 恢复（VPC 敏感 + 无约束符号模拟雏形）

1. 选定目标：VPC 候选 r13 所在代码区（.winlice 明文页）中，取 1 个**短 handler**（≤200 指令，从 VPC 读取→分派→处理→跳转的完整循环片段）。
2. 实现最小模拟器（Python 或 Rust bin）：
   - 值域：具体值 / 符号值 / TOP（路径合并时常量冲突 → TOP，Pushan §5.2）；
   - VPC 敏感：节点 ID = (block_addr, VPC值)，每个 (addr,VPC) 对访问一次；
   - 外部调用（GetAppVersion/Run 调用的非 VM 函数）：函数摘要或符号返回（Pushan §5.2）；
   - 无约束：不做路径约束累积（回避 SMT NP-hard，Pushan §5.3 符号化替代）。
3. 输出：该 handler 的 CFG（节点/边）+ 恢复的语义摘要（如"读字节码第 N 字节 → 按 opcode 分派到 handler X"）。
4. 验收：CFG 恢复后，能解释该 handler 至少 2 个分派目标的含义（对照 .winlice 内其它 handler 入口）。

## 5. 验收标准（逐条对照附命令与原始输出）

1. 输入 sha 双验：equivalence = `41ec52e0...`、候选 = `096f3bdf...`。
2. VPC 顺序演化：r13/r5 至少 1 条完整"读取→增量→再读取"循环链证据（指令级，iced-x86 输出）；两件交叉验证。
3. 单 handler CFG：≥1 个 handler 的 CFG 恢复成功（节点/边表 + 语义摘要），分派目标 ≥2 个被解释。
4. 结论判定明确（演化成立/不成立/存疑）+ 证据链；若成立 → VPC 确证完成，Phase 1 前置通过。
5. 零越界：`crates/` 既有代码零改动（git diff 证明）；无新增依赖；样品只读。
6. 证据入库：`D:/MidaVault/lab/evidence/xx21b_devirt/`（脚本 + 输出 + INDEX.md）。
7. 报告 `runs/<YYYYMMDD>-TASK-028.md`：令牌回抄第一节、结论按 [已验证]/[推断]/[存疑]、"我没做的事/我不确定的事"不许留空。

---
*总指挥拟票 · 2026-08-31 · DEVIRT-CORE Phase 0 · 账本 DEVIRT-CORE 0/8 · 串行纪律 D-014/D-026*
