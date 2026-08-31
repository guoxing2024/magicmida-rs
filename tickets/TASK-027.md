# TASK-027 — VPC 识别最小实验（Pushan §5.1 Themida 假设验证，离线零实弹）

## 0. 授权令牌（原文回抄到报告第一节）

> `老板 · 2026-08-31 · 原话"授权 C（离线零实弹，1 张前置票，不烧格）"`（按全案解释：批准调研报告 `docs/XX21B_DEVIRT_SURVEY_20260831.md` 路线 C = TASK-027 VPC 识别最小实验——在明文 `.winlice` 中定位 VPC（虚拟机程序计数器）候选，验证 Pushan 论文 §5.1 的 Themida 假设（稳定位置 VPC、首次从非常规区段加载）在本样本成立与否。**离线静态、零实弹、零格**（账本 XC-XXI-B 维持 18/4）。前置亲验由总指挥执行：输入工件 sha 双验（equivalence 41ec52e0 / 候选 096f3bdf）、Pushan 论文全文在 vault `xx21b_research/`。）

## 1. 背景（先读 docs/XX21B_DEVIRT_SURVEY_20260831.md + D-054/D-058）

- core.dll 脱壳剩余卡点 C-10 = `.winlice` VM 内部状态机（静态不可达、快照重建判死）。
- 攻坚路线 = 反虚拟化（Pushan 2026，trace-free，覆盖 Themida）。**前置问题**：论文 §5.1 说 Themida 的 VPC 是**稳定位置**，通过"首次从非常规区段（.winlice）做内存加载"识别。**该假设在我们样本上是否成立，是整条攻坚路的探路石**——不成立则 Pushan 方法对我们不可直接套用，需另想；成立则路线 A（自实现）可立项。
- 我们手里的明文资产：`.winlice` 节（equivalence 41ec52e0 与候选 096f3bdf 的 .winlice 熵同为 6.756，含明文 VM 指令段，前 512B 109 条指令、标准 x64 序言，XX 报告 Step1.1 已证）。

## 2. 红线（全程）

- `NO_BYPASS=1`；样品 sha 不匹配即 STOP；样品不外发；禁止伪造证据；防火墙只读；git 只读；`crates/` 一行未动；**不新增依赖**（仅用 pefile + 标准库，均已在环境）。
- **零实弹**：不起任何进程、不加载 DLL、不触碰宿主——纯文件静态分析。
- 输入工件只读：equivalence（`D:/xiongxiong/core_analysis/core_equivalence.dll` 或 vault `xx3_attempt_3/core_candidate_nep.dll`，sha 41ec52e0 一致）与候选（`lab/xx21b_repro/core_perfect_candidate_r2.dll`，sha 096f3bdf）；对照件只读。

## 3. 任务 1：工具准备（tools/xx21b_vpc_probe.py）

1. pefile 解析输入 PE，提取 `.winlice` 节（raw 偏移/大小/VA）与 `.boot` 节边界。
2. **熵分布图**：按 4KB 页计算 .winlice 熵，标出"明文代码页"（熵 <6.5）与"字节码/数据页"（熵 ≥7.0）分布区间——用于限定扫描范围。
3. **VPC 候选扫描**（限于明文代码页）：
   - `lea reg,[rip+disp32]`（48/4C 8D 05/0D/15/1D/25/2D/35/3D 族）→ 目标 = insn_end + disp32；目标落在 .winlice 内部 → 候选基址（字节码区指针初始化）。
   - `mov reg, imm64`（48 B8+ / 49 B8+ / 4C B8+ 等）→ 立即数落在 .winlice 内部 → 候选基址。
   - `[reg+disp]` 字节码读取模式（`movzx`/`mov` from `[reg+disp]`，reg ∈ 候选集）→ 候选 VPC 使用点。
4. 输出：候选表（文件偏移、指令字节 hex、目标 VA、落区）+ 命中上下文 16B + 统计。
5. 语法自查 + 在 equivalence 与候选两件上各跑一遍（交叉验证：同一 .winlice 应得同一候选集）。

## 4. 任务 2：分析（对照论文 §5.1）

1. 对每个候选基址，评估"VPC 合理性"：是否被 `[reg+disp]` 读取（取字节码）、是否有递增/顺序演化迹象（指令序列内 disp 单调/对同一 reg 多次访问）、是否指向熵 ≥7.0 的字节码页。
2. **结论判定**：
   - **成立**：≥1 个候选满足"指向字节码页 + 被间接读取 + 稳定寄存器" → Themida 稳定 VPC 假设在本样本成立，路线 A 前置通过。
   - **不成立**：无满足候选 → 如实报告假设不成立 + 观察到的模式（Pushan 对 Themida 的假设需修正）。
   - 含混：候选存在但无法定夺 → 标注 [存疑]，列出后续验证手段（如动态观测，属下一票）。
3. 附：.winlice 内 VM 代码区 vs 字节码区的边界估计（熵分布支撑）。

## 5. 验收标准（逐条对照附命令与原始输出）

1. 输入 sha 双验：equivalence = `41ec52e0...`、候选 = `096f3bdf...`（报告内回抄完整 sha256 前 8 + 全串）。
2. 工具产出：熵分布（页级区间）、候选表（含偏移/字节/目标/落区）、使用点统计——全部入证据 JSON。
3. 两件交叉验证：equivalence 与候选的 .winlice 候选集一致（同源证明）。
4. 结论判定明确（成立/不成立/存疑）+ 证据链；若成立，给出 VPC 候选寄存器与基址（VA）。
5. 零越界：无进程创建（报告列出所用命令均为纯文件操作）、crates/ 零改动、git 零写、无新增依赖。
6. 证据先行入库：`D:/MidaVault/lab/evidence/xx21b_vpc/`（脚本副本 + 输出 JSON + INDEX.md 登记 sha）。
7. 报告 `runs/20260831-TASK-027.md`：令牌回抄第一节、结论按 [已验证]/[推断]/[存疑] 标注、"我没做的事/我不确定的事"不许留空。

---
*总指挥拟票 · 2026-08-31 · 老板授权 C（离线零实弹，不烧格）· 串行纪律 D-014/D-026*
