# DEVIRT-CORE 战役章程 — core.dll .winlice 反虚拟化（按 Pushan 方法学自实现）

## 0. 出生记录

2026-08-31 老板授权"我们自己搞吧"（B 路=联系 Pushan 作者索取 artifact 已关闭——联系不上）。前置门 TASK-027 已通过（D-060：Pushan §5.1 Themida 稳定 VPC 假设在本样本 SUPPORTED，r13/r5 锚点在手）。战役名 **DEVIRT-CORE**，账本独立于 XC-XXI-B（该账冻结 18/4）。

## 1. 目标

按 Pushan（arXiv 2603.18355v1, 2026-03）方法学**自实现最小反虚拟化器**，对 core.dll 的 `.winlice` VM 做语义还原：
1. 恢复被虚拟化函数的完整 CFG（VPC 敏感 + 无约束符号模拟）；
2. 应用语义保持简化（Pushan S1-S4）；
3. 输出 C 伪代码（供 LLM 辅助简化）；
4. **回答 C-10**："VM 状态机在等什么 / 授权逻辑是什么形态"；
5. 产出**语义规格文档** → 交付 B 项目（core-rewrite）作干净重写依据。

## 2. 非目标

- 不击穿授权校验、不生成/推测注册码、不构造假授权服务器（红线不变，NO_BYPASS=1）。
- 不产出"能直接跑通的 core.dll"——快照重建路线已判死（D-054/D-058）；本战役的终点是**语义规格**，不是可运行产物。
- 不还原整个 .winlice（7.37MB 全部）——只还原授权/状态机/更新逻辑相关函数（目标函数 = GetAppVersion/Run 的 VM 化部分）。

## 3. 方法学依据

Pushan 论文全文在 `D:/MidaVault/lab/evidence/xx21b_research/pushan_paper_2603.18355v1.{html,pdf}`；调研综述 `docs/XX21B_DEVIRT_SURVEY_20260831.md`。
核心管线：启发式 VPC 识别（§5.1，已验证 SUPPORTED）→ VPC 敏感 CFG 恢复（§5.2，节点 ID = (addr, VPC)，TOP 值域，函数摘要/符号返回替代外部调用）→ 符号化（§5.3，路径合并符号化非恒定变量，SMT 无约束查常量）→ 简化 S1-S4（§6.1，字节码区只读常量传播、死赋值消除、冗余栈变量、Themida 双跳转专项）→ 反编译（§7，栈指针跟踪增强）。

## 4. 阶段计划与账本

账本：**DEVIRT-CORE 0/8**（预算 8 格起步，老板已授"最大支持"）。

| Phase | 内容 | 验收 | 格 |
|---|---|---|---|
| 0 | 工具链：完整 x64 解码器（REX/VEX/ModRM/SIB，无新依赖）+ VPC 顺序演化跟踪 + 无约束符号模拟器雏形（具体/符号/TOP 值域） | 对 .winlice 至少 1 个 handler 跑通 CFG 恢复 + VPC 演化链证据 | 0-1（纯离线为主） |
| 1 | 目标函数（GetAppVersion/Run 的 VM 化部分）CFG 恢复 + Pushan S1-S4 简化 | **回答 C-10**：状态机等待逻辑的语义还原 | 0-1 |
| 2 | C 伪代码输出 + LLM 辅助简化（论文 8.6 工作流：伪代码→可读 C） | 授权/更新逻辑可读语义 | 0 |
| 3 | 语义规格文档交付 → B 项目（core-rewrite） | 规格文档（含未知/边界声明） | 0 |

实弹格仅用于：动态验证 VPC 演化（泵下观测 r13/r5 随字节码流递增）等非静态不可达的场景；每格按票面授权。

## 5. 红线（全程）

- `NO_BYPASS=1`；样品 sha 不匹配即 STOP；样品/产物/VM 语义知识不外发；禁止伪造证据；防火墙只读。
- **不击穿授权**：还原出的授权逻辑（若为"需注册码"）如实报告，授权框流程是行为等价的一部分。
- 不新增依赖（仅 std + 现有 pefile；x64 解码器自实现）；`crates/` 生产代码不因本战役改动（工具在 `tools/`）。
- 工单制 + 串行派发（D-014/D-026）+ 总指挥独立审计（D-015 口径）+ 停止规则（同一验收标准连续 2 次不通过即停）。

## 6. 工具基座（已有）

- `tools/xx21b_vpc_probe.py`：VPC 候选扫描（TASK-027，已验）。
- `tools/xx21b_session_pointer_census.py` / 三态 harness / 泵：战役外背景，Phase 1 后可能复用（动态验证）。
- 输入工件（只读）：equivalence 41ec52e0（= core_candidate_nep 副本）、候选 096f3bdf、原版 09f3dd34；明文 .winlice = 460 明文页 + 133 字节码页（页级分布已在 TASK-027 证据 JSON）。

## 7. 与 B 项目关系

本战役 Phase 3 规格 → 单向交付 B（core-rewrite，根目录 `D:\Claude project\core-rewrite\`）作干净重写依据；B 的 G-0 权利门槛仍由老板材料开启，本战役不代跑 B 工单。

## 8. 会话与交接（老板问"需要新开会话吗"→ 是）

- **新开会话，根目录不变**（`D:\Claude project\magicmida-rs`）：本战役为月级长战役，当前会话已承载 T021→T027+质证+调研的膨胀上下文；新会话读本文件 + 00-START-HERE + TASK-028 即无缝接手（公司记忆在文件系统）。
- 接手指令见会话结尾消息；首票 TASK-028（Phase 0）已拟好待开。
