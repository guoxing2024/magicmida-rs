⛔ 实弹工单——授权令牌见下。未经总指挥在飞批准，本票不得开跑。

# TASK-022 — 当前 boot 重产 core 完美候选（D-043 选项 B）+ 同会话 T0.5 三态重跑收官

## 0. 授权令牌（原文回抄到报告第一节）

> `老板 · 2026-08-30 · 原话"当前 boot 重产候选"（按全案解释：批准 D-043 选项 B 全案 = 在当前 boot 会话重产 core 完美候选（活体 dump → 固化 → S1-S4 + 会话指针普查硬门），并同会话完成 T0.5 三态重跑收官；实弹 1 格（生产 dump 含重试尝试 + 重跑多趟，按 T018 5 次/1 格、T0.4 3 次触发/1 格先例），账本 XC-XXI-B 13/4 → 14/4；三态判定语义与 T017/T018/T019/T021 逐字一致；BootTime 硬门与普查硬门以票面为准）· 前置由总指挥亲验（2026-08-30）：HEAD = 1eac91f；BootTime = 2026-08-30 10:05:53.549 连续无重启；宿主 a852880a / 原版 core 09f3dd34 / config cde9be13 在位（vault）；普查器 xx21b_session_pointer_census.py 自校准 PASS（6/6 指标，对已知答案 094f5401）`

## 1. 背景（为什么是本票，P-10：先读历史）

1. T0.4 完美候选（3650ea6c）产自 08-29 的旧会话，携带该会话陈旧绝对指针 → T019 AV → T020/R1 清洗 8 槽（只覆盖已知旧 ntdll 死区间窗口）→ T021 实弹证明**清洗不收敛**：总指挥全域普查（D-043 F3）实测仍余 **~230 个对齐陈旧指针、≥8 个旧会话模块区**（工具化：`tools/xx21b_session_pointer_census.py`，自校准 6/6）。逐族打地鼠不可收敛（D-043 裁定依据）。
2. 老板裁定选项 B：**在当前 boot 重产候选**——新 dump 会话 = 当前会话，产物内会话指针按构造为当前会话值，结构性消灭 C-5 类；随后**同会话**跑 T0.5 三态重跑（FULL 判定证据最干净路径）。
3. **时间硬约束**：产物绑定当前 boot（`2026-08-30 10:05:53.549`）。**开机重启 = 本票全部产物作废 + 宿主 a852880a 同样作废**。开跑前与收尾前各查一次 BootTime，**任何时刻 BootTime ≠ 10:05:53.549 → 立即 STOP 如实上报**（D-022 先例：照实记录，不硬跑）。

## 2. 红线（全程）

- `NO_BYPASS=1`；样品身份 sha 不匹配即 STOP；样品不外发；禁止伪造证据；报告禁止无证据结论（AGENTS.md 措辞纪律）。
- 网络 deny_all：防火墙 BLOCK 规则**只读核实、绝不增删改**（含 `codex_sandbox_offline_block_outbound` 全程序覆盖确认）。
- 样品/产物/dump/日志不进 Git；git 只读（**不 commit / 不 push**）；不新增依赖（仅标准库 + 既有工具）。
- **生产 dump 阶段禁止调试附加宿主**（C-8：调试附加 → 壳不解密 .text）。观测一律外部 ReadProcessMemory / 模块枚举；dump 用 mida-cli 的 /dump-module（RPM 只读路径，不计调试会话）。
- **不许手改任何指针**：普查硬门 FAIL → STOP 上报，不做"顺手清洗"（清洗是另一张票的授权范围）。

## 3. 开工前置（任务 0）：读三份权威报告 + 工具自校准

1. 通读 `docs/XX21_CORE_PERFECT_REPORT_20260829.md`（Step 3 dump 配方权威）与 `docs/XX21B_CORE_PERFECT_REPORT_20260829.md`（Step 2 固化 + Step 3 S1-S4 判据权威）；再读 `runs/20260830-TASK-021.md`（含总指挥审计附注，理解为什么重产）。
2. 普查器自校准（不过 = 工具/环境问题，STOP）：
   `python tools/xx21b_session_pointer_census.py --selftest --image lab/xx21b_run_pcell/core.dll`
   期望：6/6 指标 OK，`SELFTEST PASS`，EXIT=0。
3. 开跑前自查（原始输出全进报告）：HEAD、BootTime（=10:05:53.549）、部署三件 sha、防火墙 BLOCK 只读清单。

## 4. 任务 1：活体 dump（实弹部分①，含重试尝试均计本格）

1. 部署 `lab/xx21b_repro/`：宿主 `rev2_unpacked.exe`（a852880a）+ 原版受保护 `core.dll`（**09f3dd34**，vault 取，sha fail-closed）+ `config.ini`（cde9be13）。
2. `NO_BYPASS=1` 启动宿主（**无调试器**）。记录活体模块表：对宿主进程枚举全部模块（name/base/size）写入 `module_map.json`（格式见普查器 docstring；`boot_time` 字段必填）。**core.dll 的 live base + 尺寸必须在表内**。
3. 等壳解密沉降（T017 口径：宿主窗口出现 / 引导沉降期后），dump 前用 RPM 验证 core .text 已明文（读 Run / GetAppVersion 导出本址 prologue，非加密态；导出 RVA 从内存映像导出表动态解析，不许硬编码）。
4. `mida-cli /dump-module --module=core.dll --keep-runtime-base <pid> <out>`（确切参数以 XX21 报告 §3 为权威）→ 期望 23 节完整映像（≈14.4 MB 量级；.winlice/.boot 节 sha 应与磁盘原版 core.dll 对应节一致——内容寻址对照，XX21 §3.3 同款）。
5. 若 .text 未沉降 / dump 不完整 → 同口径重试（重试全部计入本格，如实记录次数）。

## 5. 任务 2：固化 + S1-S4（离线，0 格——T0.4 §账本先例）

1. 按权威报告固化：keep_runtime_base（新候选首选基址 = 本会话 core 运行时基址，**不会**是 0x7ffe1da10000，属预期，不许"修"）、EP=NOP stub `31 c0 ff c0 c3` DLL 语义、IAT 修复、23 节保留、.winlice 明文不剥离、.boot 加密保留 → `core_perfect_candidate_r2.dll`。
2. S1-S4 全量（判据与 T0.4 Step3 逐字同口径，命令以其报告为权威）：
   - S1 结构 R0B 12/12；S2 `.text` 熵全块 <6.5（2059/2059 同口径）+ .winlice 明文可解码 + .boot 加密保留 + 导出本址明文 prologue；
   - S3 host_loader 独立加载 ×6（隔离加载，不计格），每次首选基址命中、无 AV；
   - S4 GetAppVersion ×10 = `0x1DB4C4C0` 全一致 + 页级零变化。
3. **会话指针普查硬门（本票新增验收，本票存在的意义）**：
   `python tools/xx21b_session_pointer_census.py --image lab/xx21b_repro/core_perfect_candidate_r2.dll --module-map lab/xx21b_repro/module_map.json --out census_r2.json`
   判据：**明文节 8 对齐违规 = 0（硬门）**。未对齐 / .winlice/.boot 加密区命中 → 入 `residual_unpatched` 清单如实上报（不盲改，T020 纪律）。同时记录 own-image 自引用总数（BASE-LOCK 清单）、PE 头 ImageBase、导出 RVA（动态）。硬门 FAIL → STOP 上报，**不许手改指针**。

## 6. 任务 3：同会话 T0.5 三态重跑（实弹部分②，≥2 趟）

1. 唯一授权脚本改动：`tools/xx21b_t05_ui_drive_pcell.py` 的 `CAND_SHA` 常量与打印标签 → 新候选 sha（其余零改动；原死区间标注常量保留不动，历史无害）。
2. 部署 `lab/xx21b_run_pcell2/`：宿主 a852880a + 新候选 + config cde9be13（三 sha fail-closed）。
3. 跑 ≥2 趟：`python tools/xx21b_t05_ui_drive_pcell.py t022_attN lab/xx21b_run_pcell2/t022_attN_evidence.json`。
4. 判定语义与 T017/T018/T019/T021 **逐字一致**，证据源 = 调试泵：
   - **FULL** = Run 线程 RIP 落入 urlmon.dll 模块区间 + 进程存活 + ≥2 趟可复现；
   - **新阻塞** = RIP 卡在新位置（真实样品）→ STOP；
   - **AV** = EXCEPTION 事件或异常退出 → STOP；AV 地址若落在普查 `residual_unpatched` 清单区间 → 标注"残留命中"后 STOP（新候选预期无此情况）；
   - **附加改变行为**（WinLicense 对话框等）→ 如实上报 → STOP；
   - **基址硬门**：脚本动态读新候选 PE 头 ImageBase，实际 ≠ 首选 → `FAIL_CORE_BASE_RELOCATED` 弃判（重定位 = 必败，T021 已实测可命中首选基址）；run_head 明文预检保留。
5. 泵健康自证（事件全消费 / continues / wait_errors / first_breakpoint_seen）逐趟入证据。

## 7. 验收标准（逐条对照，附命令与原始输出）

1. BootTime 硬门：开跑前与收尾前两次记录均 = `2026-08-30 10:05:53.549`；任何变动 → STOP。
2. 新候选三件套：固化产物 sha 登记 + S1-S4 全过（T0.4 同口径）+ 普查硬门 PASS（明文对齐违规 = 0，residual 清单入册）+ module_map.json 与 dump 会话绑定。
3. 三态判定：≥2 趟、逐趟证据（泵事件流 ndjson / evidence JSON / base_agreement / 泵健康）；FULL 需 ≥2 趟可复现；任何 STOP 路径如实上报。
4. 零越界：只动 `tools/xx21b_t05_ui_drive_pcell.py`（仅 CAND_SHA 一处）+ 新建 `lab/xx21b_repro/`、`lab/xx21b_run_pcell2/` + vault 证据目录；`crates/` 一行未动；既有脚本零改动。
5. vault 证据先行：新候选 + module_map + census_r2.json + 全部趟证据 + preflight 自查 → `D:/MidaVault/lab/evidence/xx21b_repro/`（INDEX.md 登记 sha）。
6. 收尾：无残留进程；临时文件逐个按名删除并贴证明；报告第一节回抄授权令牌；全部结论按 [已验证]/[推断]/[存疑] 标注。

## 8. 我没做的事 / 我不确定的事（报告必填，不许留空）

照实填写。特别要求：dump 沉降判定依据、module_map 完整性（模块数与 base/size 来源）、普查 residual 清单逐条定性（真实指针 vs 随机噪声，能定性的定性，不能的写存疑）。

---
*总指挥拟票 · 2026-08-30 · D-043 选项 B 落地 · 令牌未经老板亲批原文不得改动 · 串行纪律 D-014/D-026：本票在飞期间禁止派新单*
