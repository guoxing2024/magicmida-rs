# TASK-006R — TASK-006 复跑：实弹验证缺陷 A 修复（TASK-009）后的重脱壳

- **优先级**：P1
- **状态**：📋 待领取
- **岗位**：developer（实弹执行，单 worker）
- **授权**：老板 2026-08-29 确认消耗 1 格实弹；账本 XC-XXI-B 当前 **2/4**，本次预定 **3/4**
- **前置**：TASK-009 已完成并合入 HEAD（commit `995ff33`）

## 项目背景

1. TASK-006（原单 `tickets/TASK-006.md`，报告 `runs/20260829-TASK-006.md`）实弹验收 BLOCKED：重脱壳候选 `rev2_unpacked_fixed.exe`（sha256 `bb5ee568…`）当前会话启动即 AV（10/10 隔离运行全崩 0xc0000005），core.dll 从未加载。
2. 根因 = **dump 重建缺陷 A（`docs/KNOWN_ISSUES.md` C-4，fail-open）**：IAT 重建不完整（112 resolved / 74 Unresolved ≈ 60% < 95% 阈值）回退 9-thunk stub 表后，未覆盖的槽保留运行时原始指针，`fix_hardcoded_addresses` 把 `.rdata` RVA `0x1137d0` 槽的 `0x7ff6c0dc81d1` 重定位成 `0x1401681d1`（= 自身 .pdata 中间，NX）；`.text` RVA `0xde785` 的 `call [0x1137d0]` 启动期跳进去必崩。管线知情（`iat_evidence_complete=false`、`Unresolved=74`）却照样写出产物并打印 `[GOOD] Candidate written`。
3. TASK-009（commit `995ff33`，+352 行，恰 3 授权文件）已修，**验证级别 = 离线**（单元级缺陷几何 +7 用例 + 判别力探针红→绿）：
   - **兜底清零** `zero_fill_iat_region`（`dump_process.rs`）：`create_import_section` 之前把 IAT span 整段清零，重建 thunk 随后覆写各自槽位；未重建槽 = honest hole（0），不再留运行时指针；
   - **fail-closed 门**（`dump_process.rs` + `iat_partial_accept.rs::unresolvable_slot_rvas` + `iat_gap_retarget.rs::call_sites_targeting_slots`）：全部 in-image 变换之后、写出产物之前，若存在可执行节内直接 `call/jmp [rip+disp]` 指向不可解析槽 → `return Err("TASK-009 fail-closed: …")`，产物不写出、`[GOOD]` 不打印。
4. 本单 = 用 1 格实弹重跑同一路线，验证修复在真实管线上的效果。**结果二分，两个都是合法终态**（见"任务目标"）。

## 你要改的文件

**不改任何生产代码。** 这是执行 + 验证工单。过程中发现需要改引擎代码 → STOP，单独开工单，不要在实弹工单里顺手改。

## 任务目标（一句话可观察的变化）

用含 TASK-009 修复的代码重跑 TASK-006 同一路线重脱壳，得到二选一的实弹结论：

- **路径 A（fail-closed 触发）**：dump 返回 `Err`（消息含 `TASK-009 fail-closed`），无产物文件写出、无 `[GOOD] Candidate written`。→ 结论 = **缺陷 A 的 fail-open 出口已实弹堵死**（管线不再出必崩产物还打 [GOOD]）；T0.5 继续 BLOCKED（重建策略是后续新工单的事）。
- **路径 B（产物写出）**：产物当场存活探针通过 + 缺陷现场字节级复核干净 + S1-S4 全过。→ 结论 = **缺陷 A 修复实弹生效**，T0.5 解锁续跑。

**路径 A 不是失败**——那是门的设计行为（宁可不出产物，也不出必崩产物）。把路径 A 如实报告就是完成了本单。**不许为了走通路径 B 反复重跑刷结果。**

## 具体要求（按顺序，每步落盘证据）

0. **构建核验（先于一切，旧代码不配吃实弹格）**：
   a. `git log --oneline -1` 贴出，HEAD 必须是 `995ff33` 或其后代；
   b. 经 `tools/_enter_msvc_env.cmd` 包装（CRLF `.cmd`、`CARGO_INCREMENTAL=0`）全新构建你要用的 CLI 二进制；
   c. **证明二进制含修复**：对构建产物 exe 做字符串搜索，必须同时命中 `TASK-009 fail-closed` 和 `zero-filled IAT region` 两个串（PowerShell `Select-String` 或 python 皆可，贴原始输出）。搜不到 = 你要跑的是旧二进制 → STOP。
1. **身份核验**：`xiongxiong.exe` + `config.ini` 对照 `lab/cases/v2/xiongxiong_duokai.json` 的 `protected_input`（sha256/size 逐项贴出）。不匹配 = `SampleIdentityMismatch` = STOP。
2. **记录当前会话 ASLR 基线**：ntdll / kernel32 / urlmon 当前基址（这是后续判断"产物是否绑定本会话"的对照物）。
3. **重脱壳**：与 TASK-006 上次同一路线（命令与参数参考 `runs/20260829-TASK-006.md` 里的记录）。**完整保留 stdout/stderr 日志落盘**，并检索以下 TASK-009 证据点（贴命中行 + 上下文）：
   - `TASK-009: zero-filled IAT region`（info 日志，证明清零生效，记下 `zeroed=` 字节数与 `span`）；
   - `TASK-009 fail-closed`（Err，若触发 → 进入路径 A，跳到验收标准第 4 条路径 A 部分）；
   - `[GOOD] Candidate written`（若出现，其后必须紧跟第 4 步存活探针才算数）。
4. **【仅路径 B】P-4 当场存活探针（产物写完立即执行，不许拖）**：跑 1 次新产物；退出码非 0（正常退出）非 259（仍在跑）= **阻塞上报**，不许自行调参重试。
5. **【仅路径 B】缺陷现场字节级复核**（对照物 = `bb5ee568` 的坏值，用 python `struct` 按 PE 偏移读，贴原始字节与换算值）：
   - `.rdata` RVA `0x1137d0` 槽 8 字节：**不得等于** `0x1401681d1`（旧坏值）；预期为 0（honest hole）或合法重建值，写明是哪种；
   - `.text` RVA `0xde785` 起 6 字节（`FF 15 …` 现场是否仍在）与它指向的槽现状；
   - IAT span（RVA `0x1136e0` 起 201 槽）里是否还有任何落在"本会话系统 DLL 区间"的残留指针（对照第 2 步基线）。
6. **【仅路径 B】S1-S4 重新验收**（同原 TASK-006 第 4 步，旧战役结论不适用）：S1 结构 R0B 12/12；S2 `.text` 明文率 x/y blocks（熵<6.5）；S3 load_no_crash **10/10 隔离运行**（贴 10 次各自输出，不许 retry 挑结果）；S4 行为对齐（窗口标题/模块集/`config.ini` 逐字节）。
7. **【仅路径 B】session-clean 扫描模式**（同原第 5 步，不重写）：报告"落在本会话系统 DLL 区间的绝对指针"数量并解读。**跨真实 ASLR 重启存活未验证就如实写"待验证"**——这正是 T0.7 被降级的原因，别重犯。
8. **【仅路径 B】T0.5 续跑**（同原第 6 步）：`tools/xx21b_t05_ui_drive.py` 驱动 UI 事件，目标 `URLDownloadToFileA` 调用点实际触发（`deny_all` 拒绝下载是预期终态）；给出 Run verdict FULL / PARTIAL（带 reason）+ deny_all 落实证据（防火墙记录条数 + ETW 事件数）。
9. **账本记账**：本单消耗格数（预定 1 格，XC-XXI-B 2/4 → 3/4）；实际多消耗必须写明原因。

## 约束与红线

- `NO_BYPASS=1` 全程；样品身份哈希不匹配即 STOP；样品不外发；禁止伪造或推断成证据。
- 网络保持 `deny_all`；下载被拒是预期结果不是失败。
- 隔离环境执行；产出入 vault（`D:/MidaVault/lab/evidence/`），不进 Git（`ARTIFACT_POLICY.md`）。
- 不得改动 `crates/` 下任何文件；不得改 `lab/cases/v2/*.json`；不得提交、不得推送；git 只读。
- **不许为了走通路径 B 而关小 TASK-009 的门、改阈值或绕过 fail-closed**——验收时总指挥会字节级复核产物与日志。
- 同一验收标准连续 2 次不通过 → 停，报告工单本身是否有问题。
- C-5（会话绑定 B：`.bss 0x112c10` 固化本会话 ntdll）**未修且不在本单范围**——修好 A 产物才能在当前会话活，跨重启存活是 B 修好后的事。报告里必须把这条边界写清。

## 验收标准

1. 构建核验三件套原始输出：HEAD 提交号、构建日志尾部、exe 字符串双命中。
2. 身份核验 sha256/size 对照 manifest 的原始输出。
3. 重脱壳完整日志（落盘路径）+ 三个 TASK-009 证据点命中行原文。
4. **路径 A**：Err 消息全文 + 无产物证明（输出目录列表 + 时间戳，证明没有新文件写出）；**路径 B**：存活探针退出码 + 第 5 步缺陷现场三组字节级读数（`0x1137d0` ≠ `0x1401681d1` 是硬断言）。
5. 仅路径 B：S1-S4 逐项原始输出（S3 十次各自输出）、session-clean 扫描结果、T0.5 Run verdict + deny_all 证据。
6. 账本记账行（消耗格数、余额）。
7. 「我不确定的事」一节，**必须明确写出"跨真实 ASLR 重启存活"是否验证过**。

## 交付格式

写到 `runs/<日期>-TASK-006R.md`。每条验收标准逐条对照，附命令与**原始输出**。每条结论标可信度：`[已验证]` / `[推断]` / `[存疑]`。

## 停止规则

- 构建核验搜不到 TASK-009 字符串 → STOP（不许用旧二进制消耗实弹格）。
- 身份不匹配 → STOP。
- 存活探针退出码非 0/259 → 阻塞上报（P-4），不许重试。
- S1-S4 任一 fail → 停下记录原因与阻塞点收口，不刷结果。
- 发现需要改引擎代码才能过 → 停，单独开工单。
