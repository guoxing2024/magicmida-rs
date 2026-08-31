# XX-21B core.dll 完美脱壳攻坚调研 — 2026 最新反虚拟化研究综述

- 日期: 2026-08-31 · 总指挥执行（老板授权"研究最新成果，继续攻坚完美脱壳"）
- 红线不变: 不击穿授权校验、不造注册码、不假服务器、样品不外发、不伪造证据
- 账本: 0 格（纯文献调研 + 离线静态）

## 0. 为什么调研这个方向

core.dll 脱壳剩余卡点 C-10 = `.winlice` VM 内部状态机（等待/信号逻辑静态不可达；快照重建判死 D-054）。攻坚 C-10 的唯一技术路径 = **反虚拟化（devirtualization）**：把 VM 字节码语义还原为原始控制流。此前专家（D-054）判断"ROI 极差"，但其依据是**旧方法**（全部依赖执行 trace + DSE）。2026 年 3 月出现了方法学突破，本调研的核心发现即此。

## 1. 核心发现：Pushan（arXiv 2603.18355v1, 2026-03-18, ASU + CISPA）

**"Trace-Free Deobfuscation of Virtualization-Obfuscated Binaries"**（作者：Ashwin Sudhir 等，含 Moritz Schloegel / Yan Shoshitaishvili / Ruoyu Wang）。

### 1.1 为什么它是突破（对比 D-054 专家判断的旧方法）

| 旧方法三大缺陷（论文§1） | 我们的死结 | Pushan 的解法 |
|---|---|---|
| ① 只吃执行 trace → 覆盖不全 | 无注册码 → 授权后状态不可达 → **无 trace 可用** | **trace-free**：静态从二进制恢复完整 CFG |
| ② 依赖动态符号执行（DSE）→ 贵、不可扩展 | 约束累积是 NP-hard | **无约束符号模拟**（constraint-free）：回避路径可满足性 |
| ③ 产出不成形代码 → 反编译器无法处理 | — | 产出**完整 CFG + C 伪代码** |

### 1.2 方法核心（论文§5-7，可直接复现）

1. **启发式 VPC 识别（§5.1）**：VPC（虚拟机程序计数器）定位。**Themida = 稳定位置 VPC**，通过"首次从非常规区段做内存加载"识别（对 Themida 和 Tigress 均有效）——正是我们的 `.winlice`/`.boot` 场景。
2. **VPC 敏感 CFG 恢复（§5.2）**：从混淆代码起点逐指令符号模拟，节点 ID = (block_addr, VPC) 二元组；无约束值域含具体值/符号值/**TOP**（路径合并时常量冲突 → TOP）；外部函数用函数摘要/符号返回替代（VMHunt 可自动划界）。
3. **符号化（§5.3）**：路径合并时符号化非恒定变量（如循环退出守卫），SMT **无约束**检查 opaque predicate 是否为常量；迭代至不动点 → 补全漏掉的边。
4. **语义保持简化（§6.1）**：S1 标准简化（把 VM 字节码区当只读常量传播 → 消除 handler 派发逻辑、死赋值消除、opaque predicate 消除）；S2 冗余栈变量；S3 循环自引用变量；**S4 混淆器专用简化——Themida 把每个条件跳转拆成两个**（先算检查写全局变量、再按全局变量选分支）→ 专项简化。
5. **反编译（§7）**：定制开源 decompiler，**增强栈指针跟踪**（混淆把 rsp 复用作通用值/做 XOR/MBA 运算 → 自行发现真实栈指针寄存器）。

### 1.3 评估数字（§8）

- 1000+ 二进制，覆盖 **VMProtect + Themida** + Tigress（学术）+ CTF。
- 最大样本 huffman（**Themida**）85 万条指令，**10 小时**分析完成；hash（Themida）27 万条 4 小时内。
- 5/5 CTF 挑战恢复的 CFG 与公开 writeup 功能一致、API 轨迹匹配。
- 真实案例：VMProtect 恶意样本 85 分钟反虚拟化 → 476 行 C 伪代码 → 仅凭伪代码交给 Claude 简化成 30 行可重编译 C（与我们的 LLM 工作流同构）。

### 1.4 对我们的意义（对应 C-10）

- **无码死结被绕过**：Pushan 不需要授权后 trace——它静态分析 VM 字节码 + 解释器本身。我们正好有**明文 .winlice**（equivalence/候选件 7.37MB，熵 6.756，含明文 VM 代码段，109 指令/512B）作为输入。
- **Themida 在评估列表**：VPC 稳定、条件跳转二拆等特征与我们观测一致（T026：VM 区 1 线程全速轮询 = 解释器在跑）。
- 输出 = C 伪代码 → 可直接判断"授权/状态机逻辑在等什么"→ 回答 C-10 的"缺 signal 侧"问题（D-054 修正点）。
- 红线兼容：它**还原语义**，不击穿校验；授权框流程仍作为行为等价的一部分保留。

### 1.5 未定项：开源状态

- 论文**无 artifact 链接、无 Code Availability 声明**（仅 License CC BY-NC-SA 4.0）。
- GitHub 通道受限（api.github.com 000、raw.githubusercontent 000、搜索 429）；作者页 asudhir1 无公开仓库；`github.com/asudhir1/Pushan` 404。
- 论文方法描述足够详细（§5-7 + S1-S4 清单 + 附录），**可自实现**；也可联系作者（ASU pwn.engineering）索取。

## 2. 其它调研到的工具（2024-2026 全景）

| 工具/文献 | 年份 | 定位 | 可用性 | 对我们价值 |
|---|---|---|---|---|
| **Pushan** | 2026 | trace-free 反虚拟化 + C 反编译 | 论文可复现，代码未见 | ★★★ 最高 |
| **unlicense**（ergrelet） | 2023-2025 | WinLicense unpacker（运行时 hook + OEP dump + Scylla IAT） | GitHub 仓库页 200（存在） | ★ 专家已判 DLL 支持差、需授权通过 |
| **VMHunt**（CCS'24） | 2024 | 部分虚拟化函数边界识别 + 简化 | arXiv 未取到（网络抖动） | ★★ 可作 Pushan 的前置（边界划界） |
| **VM-Doctor** | 2023 | VPC 识别方法论（Pushan 引用） | — | ★ 方法引用 |
| Rolf Rolles Themida 系列 | 2019- | VM 反混淆 | 公开 | ★ 背景（D-054 已录） |
| Tim Blazytko syntia/msynth | 2019- | 程序综合恢复 handler 语义 | 公开 | ★ 补充 |
| vtil-core | 2020 | VM lifting IR | 公开 | ★ 补充 |
| OASIF（2606.29155） | 2026 | LLM 抗混淆汇编理解（自演进） | 论文 | ★★ LLM 辅助路线（与本项目 LLM 工作流同构，但非核心） |

## 3. 攻坚路线评估

### 路线 A：按 Pushan 论文自实现最小反虚拟化器（推荐主攻）
- **内容**：在项目内实现 VPC 识别 + 无约束符号模拟 + CFG 恢复（§5 部分），先对我们的明文 .winlice 跑通"授权/状态机相关函数"的 CFG 恢复。
- **量级**：GVM-0 同量级（论文 85 万指令 10h；我们 .winlice 7.37MB ≈ 需先测指令规模）。**不是小票，是战役**。
- **前置**：`spec/` 建立 Pushan 方法学笔记（已归档 vault）；可选先做"VPC 识别最小实验"验证我们的 .winlice 里能否定位 VPC（离线零实弹，1 张前置票）。
- **优点**：不依赖外部代码可用性；产出全部可复算；与项目"研究平台"定位一致。
- **缺点**：工程量大；Pushan 本身没有针对 WinLicense 授权状态机的现成输出。

### 路线 B：联系 Pushan 作者索取 artifact（最快验证）
- 邮件 ASU pwn.engineering / asudhir1（论文作者邮箱公开）；或等网络通道恢复后查 ASU 实验室 release。
- **授权要求**：外部沟通需老板点头；且样品不外发红线约束（若索取工具可，样品不出机）。
- **优点**：若能拿到现成工具，直接对 core.dll 跑 → 几小时见分晓。
- **缺点**：作者未必给；可能需等待。

### 路线 C：先做"VPC 识别最小实验"（前置验证，零实弹）
- 用我们明文 .winlice（equivalence/候选件）做**离线静态**：找 VPC 候选寄存器/内存位置（高熵区指针 + 顺序演化特征），验证 Pushan 的 Themida 识别假设在我们样本上成立。
- 这是 A 的探路石，也是给老板的"能力证据"（证明攻坚不是空谈）。

### 路线 D（不推荐）：unlicense 实测
- 专家已判：DLL 支持差 + 需授权自然通过（我们无码）。pass。

## 4. 我的建议

**先 C（VPC 最小实验，离线零实弹，1 张前置票）→ 确认假设成立后 B（联系作者，需老板点头外部沟通）并行 A（自实现战役立项，账本另开）**。
C 的成功标准 = 在我们的明文 .winlice 中定位到符合"高熵区指针 + 顺序演化"的 VPC 候选，并把论文 §5.1 的 Themida 假设落到具体寄存器/内存位置。

## 5. 证据归档

- Pushan 论文全文（HTML + PDF）：`D:/MidaVault/lab/evidence/xx21b_research/pushan_paper_2603.18355v1.{html,pdf}`
- 本报告：`docs/XX21B_DEVIRT_SURVEY_20260831.md`
