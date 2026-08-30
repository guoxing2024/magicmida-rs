⛔ 实弹工单——授权令牌见下。未经总指挥在飞批准，本票不得开跑。

# TASK-023 — C-9 根因诊断：宿主 + 重产候选组合引导期 exit 0 的退出调用者定位

## 0. 授权令牌（原文回抄到报告第一节）

> `老板 · 2026-08-30 · 原话"C-9 根因诊断"（按全案解释：批准 D-045 选项 ① = TASK-023 C-9 根因诊断——用调试泵 + int3 退出漏斗断点定位 rev2 宿主（a852880a）+ 重产候选（096f3bdf）组合引导期干净退出 exit 0 的调用者，诊断only不许修复，实弹 1 格（工具验证趟 + 诊断趟含重试，按 T018 先例），账本 XC-XXI-B 14/4 → 15/4；BootTime 存在性硬门以票面为准）· 前置由总指挥亲验（2026-08-30）：HEAD = c787526；BootTime = 2026-08-30 10:05:53.549 连续无重启（候选仍绑定本 boot）；三件 sha 在位（096f3bdf / a852880a / cde9be13）；候选 EP RVA 动态读通（0x1027c0）；fork 基座 tools/xx21b_t05_ui_drive_pcell.py 在`

## 1. 背景（P-10：先读权威记录）

1. C-9 现象（KNOWN_ISSUES §C-9 / runs/20260830-TASK-022.md + 总指挥审计附注 D-045）：rev2 宿主 + 当前 boot 重产候选 → 引导沉降期干净退出 exit 0（3/3 泵 + 3/3 普通启动）；三方对照：原版 core 09f3dd34 → 存活+授权窗口；094f5401 → AV 0xC0000005。隔离加载（host_loader）6/6 正常 → 缺陷特定于**宿主引导路径 × 重产候选**组合。
2. 未知点 = **谁调用了退出**：宿主校验失败分支？候选 VM 数据自检？加载器 DLL 初始化失败路径？候选 .winlice 内存在 VM 32 位旧会话地址高位字立即数（`XOR ECX,0x7FFEEA8F` 类，D-045 定性）——若 VM 用其做地址分类，当前会话地址不匹配可致不同分支（纯假设，本票检验）。
3. 诊断原理：**一切进程退出必经 ntdll!NtTerminateProcess**（干净自退经 kernel32!ExitProcess → ntdll!RtlExitUserProcess → NtTerminateProcess 链；外部强杀直达 NtTerminateProcess；若经直接 syscall 绕过 ntdll 则 0 命中——这本身即有效诊断结论）。在退出漏斗下 int3 断点，命中时抓 [rsp]（返回地址 = 退出决策者）→ 模块归属（宿主映像 / 候选映像 / ntdll 加载器 / 其它）+ 寄存器 + 栈链。**候选 EP 判别位**（首选基址 + EP RVA，disk PE 头动态读）判定候选 DllMain（NOP stub）是否被调用——判定"加载器初始化失败"vs"初始化成功后宿主/VM 决定退出"。

## 2. 红线（全程）

- `NO_BYPASS=1`；样品 sha 不匹配即 STOP；样品不外发；禁止伪造证据。
- **int3 仅限内存驻留**（WriteProcessMemory 写调试目标进程内存，命中后恢复原字节；磁盘文件零改动；部署件 sha 前后双验）。这是标准调试器实践（T015 引擎同族），但**若仪器化改变行为**（退出模式偏离 T022 基线，如出现 AV）→ 如实记录 → STOP。
- 诊断 only：**不许修宿主、不许修候选、不许清洗、不许改任何指针**；修复是另一张票。
- 防火墙只读；git 只读（不 commit/push）；不新增依赖（ctypes/标准库）；`crates/` 一行未动；既有脚本零改动（fork 新文件）。
- **BootTime 存在性硬门**：候选 096f3bdf 的重锚指针绑定本 boot——**开跑前与收尾前各查一次 BootTime，≠ `2026-08-30 10:05:53.549` → 立即 STOP**（重启后候选必失效，现象不可复现）。

## 3. 任务 1：构建 `tools/xx21b_c9_exit_trace.py`（fork pcell harness，保留全部红线机制）

1. **断点动态解析（不许硬编码任何地址）**：
   - ntdll!NtTerminateProcess、ntdll!RtlExitUserProcess —— 导出 RVA 从 `C:\Windows\System32\ntdll.dll` 磁盘导出表解析；kernel32!ExitProcess、kernel32!TerminateProcess —— 从 `C:\Windows\System32\kernel32.dll` 解析；断点 VA = 各自 **LOAD_DLL 事件基址**（泵实时）+ RVA。
   - 候选 EP 断点：EP RVA 从候选 disk PE 头读（AddressOfEntryPoint），VA = 首选基址（disk ImageBase）+ RVA；在候选 LOAD_DLL 事件后布置。
2. **int3 引擎**：WriteProcessMemory 写 `0xCC`（原字节留存）+ FlushInstructionCache；命中（EXCEPTION_BREAKPOINT）→ 法证记录：真地址 = Rip−1、模块归属（enum_modules + MZ 双核）、全寄存器（GetThreadContext 调试句柄，CONTEXT_CONTROL|CONTEXT_INTEGER = 0x100003）、栈链 rsp[0..16] qword 逐个模块归属、命中断点名；恢复原字节 + Rip 回退 1 + TF 单步重布（标准 re-arm）。**re-arm 失败可降级 fire-once 模式**（每断点每趟至多命中 1 次；单次退出链 2-4 调用，fire-once 足够）——用哪种模式如实写报告。
3. **事件流全记录**：T022 泵机制全保留（ndjson 边到边落盘 / 泵健康自证 / EXCEPTION 全记录）；EXIT_PROCESS 后汇总"命中时间线表"。
4. 语法自查 + 单元自测（断点解析器对 System32 导出表解析出 4 个 RVA 且非 0；EP RVA = 0x1027c0 动态读得并打印）。

## 4. 任务 2：验证趟 + 诊断趟（实弹部分，全计本格）

1. **验证趟（工具自检，1 趟）**：host_loader 隔离加载候选（S3 同款，预期存活）+ 本工具断点全布——预期：观测窗内 **0 命中且进程存活**（证明断点不误触发、法证链可用）。若误命中 → 工具缺陷，修工具不烧谜题。
2. **诊断趟（≥3 趟）**：rev2 宿主 a852880a + 候选 096f3bdf + config cde9be13（`lab/xx21b_run_pcell2/` 部署 sha 前后双验），泵 + 断点全布。记录：每命中法证、EP 判别位是否命中、退出码、与 T022 基线（exit 0 / 无 AV / 无窗口）的行为偏离。
3. **判定产出（报告核心表）**：
   - 退出链命中序列（如 ExitProcess → RtlExitUserProcess → NtTerminateProcess）；
   - **退出决策者归属**：最外层命中（第一个）的 [rsp] 返回地址 → 模块 + RVA：`host-image` / `candidate-image` / `ntdll-loader` / `other`；
   - 候选 EP 是否被调用（NOP stub DllMain 是否执行）；
   - 栈链上宿主/候选地址 RVA 明细（供总指挥反汇编定位分支）。
4. **可能的诚实结局**（都是有效诊断，不是失败）：① 0 命中 + exit 0 复现 → 退出经直接 syscall 绕过漏斗 → 如实上报；② 仪器化改变行为 → STOP 如实上报；③ 命中归属 ntdll 加载器路径 → DLL 初始化失败分支 → 上报（连带：哪个 DLL 的初始化、返回值）。

## 5. 验收标准（逐条对照，附命令与原始输出）

1. BootTime 双查记录均 = `2026-08-30 10:05:53.549`（变了即 STOP）。
2. 断点解析零硬编码（grep 证明脚本无 ntdll/kernel32 绝对地址常量；EP RVA 动态读）。
3. 验证趟 1 趟 + 诊断趟 ≥3 趟，逐趟证据（ndjson / 法证 JSON / 命中时间线表 / 泵健康）入册；诊断趟间调用者归属一致性如实报告（一致 / 分歧均报）。
4. 退出决策者归属表 + EP 判别位结果 + 栈链 RVA 明细——**本票的核心交付**。
5. 零越界：仅新增 `tools/xx21b_c9_exit_trace.py`（fork）+ 复用 `lab/xx21b_run_pcell2/` + 新建 vault 证据目录；`crates/` 一行未动；既有脚本零改动。
6. vault 证据先行：`D:/MidaVault/lab/evidence/xx21b_c9/`（INDEX.md 登记 sha）；临时文件逐个按名删除贴证明；报告第一节回抄授权令牌；结论按 [已验证]/[推断]/[存疑] 标注。

## 6. 我没做的事 / 我不确定的事（必填，不许留空）

照实填写。特别要求：re-arm 还是 fire-once 模式及原因；验证趟与诊断趟的行为差异；归属判定的置信度与反例排查（如 [rsp] 指向的模块归属是否有 MZ 复核）。

---
*总指挥拟票 · 2026-08-30 · D-045 选项 ① 落地 · 令牌未经老板亲批原文不得改动 · 串行纪律 D-014/D-026*
