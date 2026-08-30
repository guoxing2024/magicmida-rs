# TASK-024 — C-9 离线静态分析：宿主 exit(0) 调用点与守卫条件解剖（零实弹，不烧格）

> **纪律**：本票**零实弹零格**——禁止执行任何样品（含 host_loader、禁止部署、禁止启动宿主）；只读磁盘文件。若分析需要跑任何东西 → 立即停，上报请示（实弹需另批）。无授权令牌要求（非实弹票）。

## 1. 背景与已知锚点（先读 `runs/20260830-TASK-023.md` 含总指挥审计附注 D-047 + vault `xx21b_c9/` 证据）

TASK-023 诊断结论：宿主 a852880a + 重产候选 096f3bdf 组合，core.dll 的 DllMain（NOP stub）正常返回后 **2.4ms**，宿主侧经 CRT `exit(0)`/`_exit` → ExitProcess(0) 干净退出（决策者 ret = msvcrt+0x3e2c9 = `_exit+0x89`，3/3 逐位一致）。**加载器初始化失败已被 EP 判别位排除**。剩余未知 = LoadLibrary(core) 返回到 exit(0) 之间宿主判定了什么。

已知锚点（全部来自实弹证据，可直接引用）：
- 退出链：`exit(0)`（调用者未知，栈上只有堆 onexit 表）→ msvcrt `_exit+0x89` → ExitProcess（Rcx=0）→ RtlExitUserProcess → NtTerminateProcess ×2。
- 命中时 **Rbp=0x140112058 = 宿主映像 .bss RVA 0x112058**（宿主基址 0x140000000）。
- 宿主已知 init 区：T0.4 记录 RVA 0x21cc0-0x21cd8（`call rax`，ntdll thunk 调用点）；.bss 0x112c10 = ntdll+0x106390 指针槽。
- 三方行为：原版 core（09f3dd34）→ 宿主弹 PigToGoLicenseDialog"授权验证"（class PigToGoLicenseDialog，children=5：授权码 Edit + 确定）；旧候选 094f5401 → 宿主调进候选 VM 代码后撞陈旧指针 AV（**证明宿主加载后会调进 core**）；新候选 096f3bdf → exit(0)。
- 老宿主 36043cb4（vault `D:/MidaVault/lab/worktree_evidence_20260830/lab/xx21b_run/rev2_unpacked.exe`）+ 同样 NOP stub 的候选 = 存活且业务链进消息循环（T0.4 Step1）→ **exit(0) 是新宿主 a852880a 特有行为**。
- 总指挥机制假设（D-048，[推断]）：新宿主早期初始化查询壳状态，NOP stub 不自举 → 查询失败 → exit(0)。本票的任务就是证实或证伪它。

## 2. 任务（全部离线，只读磁盘文件）

### 任务 1：宿主 exit 调用点全列
- 解析 `lab/xx21b_run_pcell2/rev2_unpacked.exe`（a852880a，1,539,072 B）导入表 → 定位 `exit` / `_exit` / `_amsg_exit`（msvcrt）与 `ExitProcess`/`TerminateProcess`（kernel32）的 IAT 槽。
- **注意**：rev2 是重建 PE，导入布局非标准（dump 管线注记 "original PE import table: 12 modules, 12 thunks"，含 .idata/.import 双节）。总指挥快速解析器在此文件上失败过——建议用 MSVC 环境的 `dumpbin /imports`（`tools/_enter_msvc_env.cmd` 包装）或自行处理重建布局；**不许 pip 装新依赖**。
- 扫描 .text 全部 `call/jmp` 到这些 IAT 槽（E8 rel32 / FF 15 rip-rel）→ 调用点全列（RVA + 前后各 32 字节反汇编）。

### 任务 2：钉死引导路径上实际触发的 exit 点 + 守卫条件
- 结合 2.4ms 时序（exit 发生在 core DllMain 返回后立刻）与 T0.4 init 区锚点，确定哪个调用点在引导路径上。
- 反汇编该点上游：**守卫条件是什么**（test/cmp 哪个寄存器/哪个全局、值从哪来——core 导出调用返回值？LoadLibrary 返回值？.bss 状态字？）。交付精确到指令的条件链。

### 任务 3：三方行为自洽解释
- 用找到的条件解释：原版 core → 对话框；094f5401 → AV；096f3bdf → exit(0)。特别回答：094f5401（陈旧指针）为何走到 AV 而 096f3bdf（重锚指针）走到 exit——同一查询点在两种候选上的分叉逻辑。
- 判别"exit(0) 的调用者是宿主代码还是候选代码"：解析**候选 core.dll（096f3bdf，lab/xx21b_run_pcell2/core.dll）的导入表**——若候选也导入 exit 族，候选侧退出可能性不能排除；结合 Rbp=宿主 .bss 与 2.4ms 时序裁定。

### 任务 4：老宿主对照 diff
- 对 vault 老宿主 36043cb4 做同款分析（exit 调用点 + 守卫条件），与 a852880a diff——**新宿主多出（或改变）的检查**若能定位，单独列节。这直接回答"为什么 T0.4 老组合不死"。

### 任务 5：修复方向提案（不实施）
- 基于条件链给出候选侧修复方向（如"最小壳自举 stub"的入口与必需状态）或宿主侧结论；只写方案，不动任何二进制。实施（若需实弹）另立票另批。

## 3. 验收标准（逐条对照附命令与原始输出）

1. 宿主 exit 族调用点全列（RVA + 反汇编片段），导入表解析方法写明（dumpbin 或自研解析的处理方式）。
2. 引导路径 exit 点钉死 + 守卫条件精确到指令 + 条件值来源判定。
3. 三方行为自洽解释（094f5401 AV vs 096f3bdf exit 的分叉逻辑必须有证据支撑，不许硬凑）。
4. 候选 core.dll 导入表结论（候选侧退出可能性排除或确认）。
5. 老宿主对照 diff 结果（可定位则列差异，不可定位则如实说）。
6. 修复方向提案一节 + "我没做的事/我不确定的事"（不许留空）。
7. 零实弹证明：全程未执行任何样品（报告写明）；零越界：crates/ 既有脚本零改动，只读样品文件；git 只读；无新依赖。
8. vault 证据先行：`D:/MidaVault/lab/evidence/xx21b_c9_static/`（反汇编片段 / xref 表 / 结论 JSON + INDEX.md 登记）。

## 4. 报告

写到 `runs/20260831-TASK-024.md`，逐条对照验收标准附原始输出；全部结论按 [已验证]/[推断]/[存疑] 标注。

---
*总指挥拟票 · 2026-08-31 · D-048 · 离线零格 · 老板 2026-08-30"派这张离线票"*
