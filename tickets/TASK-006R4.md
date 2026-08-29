# TASK-006R4 — 带受控 ini 重跑重脱壳（缺陷 A 路径 A/B 首次真正可达的机会）

✅ **已授权 —— 授权令牌（必须在报告第一节原文回抄）**：
`老板 · 2026-08-30 · 批 1 格实弹 · XC-XXI-B 5/4 → 6/4（超原配额，老板明确扩额）· 同时放行 C:\Windows 落位（仅限 scylla_hide.ini 一个文件，跑完必删、删后贴证明）· 前置由总指挥亲验：BootTime = 2026-08-30 01:28:40（与 TASK-006R3 同 boot，无需重启——本单实验变量是受控 ini，不是 boot；R3 已实证环与 boot 无关）· 起点 HEAD = ca06117（TASK-013 已验收入栈）`

- **优先级**：P1
- **状态**：✅ 已执行并验收（2026-08-30，终态 **STOP**：`C:\Windows` 落位方案结构性无效——本工单的落位前提基于 TASK-013 的错误结论，已由本单实证推翻；归档 [runs/20260830-TASK-006R4.md](../runs/20260830-TASK-006R4.md)；后继 → [TASK-006R5](TASK-006R5.md)）
- **岗位**：developer（**实弹**）
- **账本**：XC-XXI-B **5/4 → 6/4**（需老板明确批准扩格）

## 为什么这一单有机会（与 R2/R3 的本质区别）

此前 **13/13 次**撞环的运行全部处于"**无 ini、ScyllaHide 默认全 hook**"状态——TASK-013 已实证 `InjectorCLIx64.exe` 只从 **Windows 目录**读 `scylla_hide.ini`（裸相对名，cwd/exe 旁都不搜），所以vault 参考 ini 里现成的 `KiUserExceptionDispatcherHook=0` / `NtContinueHook=0` **从未生效过**。本单第一次让受控配置真正生效：异常分发链两个 hook（`KiUserExceptionDispatcher` + `NtContinue`）关闭。风暴 RIP 恒 = NtContinue hook +8（跨 3 boot 实锤）→ 关掉它，故障环有实质理由消失，text-poll 才有机会收敛到 dump——缺陷 A 的三个证据点（`TASK-009: zero-filled IAT region` / `TASK-009 fail-closed` / `[GOOD] Candidate written`）第一次真正可达。

## 已知混杂变量（如实记录，不许掩盖）

受控 ini = 整套 UncoverEngine profile（约 30 键），相对"无 ini 全默认"的差异**不止两个开关**。若本单走通，"哪个开关是关键"的归因需后续最小差分 ini 变体（另立单，不在本单范围）。本单回答的问题是：**这套受控配置能不能让 text-poll 收敛**。

## 开跑前置（不满足就 STOP）

1. **构建核验**：`git log --oneline -1` 的 HEAD 必须含 TASK-013 验收提交（派单时总指挥批注 hash）。**必须全新 release 构建**（crates/ 自上一格后已变，**禁止复用旧 exe**，与 R3 的省时路径不同）。MSVC 环境入口 `tools/_enter_msvc_env.cmd`。exe 里**五条**字符串各须命中（binary grep，贴计数）：
   - `zero-filled IAT region`
   - `TASK-009 fail-closed`
   - `guardless constant-AV storm abort`
   - `C-7: guardless constant-AV storm`
   - `SCYLLAHIDE_HOOK_CONFIG_SOURCE`（TASK-013 新增）

   任一条不命中 → STOP 上报。贴构建日志、五条命中、exe 的 sha256 与体积。
2. **样品身份**（P-6：不要用任何 `.exe` 定位符）：vault 对象
   ```
   D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7
   ```
   期望 sha256 = `7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`（= `lab/cases/v2/xiongxiong_duokai.json` 的 `primary_artifact_sha256`）。不匹配 = `SampleIdentityMismatch` → STOP。
3. **ini 落位（本单新增，系统级副作用，严格按步骤）**：
   - a. 复制 `D:/MidaVault/lab/config/scylla_hide_no_excdispatch.ini` → `C:\Windows\scylla_hide.ini`；
   - b. **sha256 比对两份一致**后才算落位完成（贴原始输出）；
   - c. 落位前确认 `C:\Windows` 无其它 `scylla*.ini` 残留（总指挥验收 TASK-013 时已核验过一次干净，你落位前再验一次）；
   - d. 设环境变量 `MIDA_SCYLLA_HIDE_INI=D:/MidaVault/lab/config/scylla_hide_no_excdispatch.ini`（让引擎日志的配置来源行记录 vault 源路径）。
4. **会话基线**：BootTime、debuggee image_base、ntdll / kernel32 / kernelbase 基址、`scylla_hide.log` 路径（每次尝试前重置）。**每次尝试都记 image_base**。

## 有效尝试的判定（新增强门，缺一即不算有效数据）

一次尝试**只有同时满足**以下两条才算"有效尝试"：
- 引擎日志出现 `SCYLLAHIDE_HOOK_CONFIG_SOURCE=ini: `（配置来源被记录）；
- 本次 `scylla_hide.log` **不再出现** `Hooking NtContinue` 与 `Hooking KiUserExceptionDispatcher`（受控配置真正生效的直接证据；同时贴**仍被 hook 的清单**作对照）。

若 hook 行仍在 → ini 没被读到（落位失败）→ 该次**不算有效尝试**，停下排查落位；连续 2 次落位失败即 STOP 上报。**不许把 ini 未生效的运行当成路径 A/B/C 的证据。**

## 终态判定（四条都合法，如实上报）

- **路径 A（fail-closed 生效）**：dump 阶段命中 `TASK-009 fail-closed`、拒绝写出产物、`[GOOD] Candidate written` 不出现 → **缺陷 A 修复按设计工作（首次实弹验证）**。贴日志、`Unresolved` 计数与 IAT 报告。
- **路径 B（产物写出）**：`[GOOD] Candidate written` 出现 → ① 立刻 **P-4 当场存活探针**（产物写完立即跑一次，非 0/259 即阻塞上报）；② 检查 `.rdata 0x1137d0` 槽字节（缺陷 A 原始现场：坏值 `0x1401681d1`，期望已清零或正确重建）；③ 顺带记 `.bss 0x112c10`（C-5 现场，预期仍固化本会话 ntdll——已知未修，不算本单失败）。
- **路径 C（又撞 C-7 环）**：`guardless constant-AV storm abort` → **关掉异常分发链没治好环**。记录：AV 数、恒同元组、**exc 地址与其相对 ntdll 的偏移（还在不在 +0x160bd8？这是本路径最有信息量的观测）**、首次 AV→中止耗时、日志体积。立刻停手。
- **路径 D（新形态）**：text-poll 收敛了但死在别处（dump 阶段其它失败、壳主动检测调试器而退出/反制等）→ 如实记录形态与日志。TASK-013 留的待验风险「关 hook 后壳反过来检测调试器」若落地，证据就在这路。

## 停止规则（严格执行）

- **有效尝试连续 2 次即停**（无论终态是哪条路径）。
- **落位失败连续 2 次即 STOP**。
- 不许为了走通路径 B 反复重跑。

## 收尾（强制，无论终态、无论成败）

1. **删除 `C:\Windows\scylla_hide.ini`**，贴删除后的 `ls /c/Windows/*.ini` 原始输出证明只剩系统自带文件；
2. 日志留存同 R3：删任何日志前先算好计数（AV 总数、恒同元组、事件类型分布，`grep -c` 原始命令贴报告）→ 有界摘要（头 200 + 尾 200 + 计数）进 vault `D:/MidaVault/lab/evidence/xx21b_006r4/`，本体 <50MB 一并留档；
3. **本次 `scylla_hide.log` 必须留档进 vault**（hook 生效/失效的直接证据，别只留在 target/release）。

## 红线（违反即整单作废）

- `NO_BYPASS=1` 全程；网络 `deny_all`；样品不外发；**禁止伪造证据**。
- **`C:\Windows` 只许写 `scylla_hide.ini` 这一个文件，跑完必删、删后证明**；不碰任何其它系统文件。
- **git 只读**：不 commit / push / stash，不改 config，不改 `crates/`、不改 `lab/cases/v2/*.json`。
- 样品、产物、dump、第三方工具、运行日志、构建输出一律不进 Git → 进 vault。
- 结论按 `[已验证]` / `[推断]` / `[存疑]` 标注；只贴原始输出；报告第一节回抄授权令牌（批准后）。

## 交付物

- `runs/<日期>-TASK-006R4.md`：授权令牌回抄、前置原始输出（含 ini 落位 sha256 对比、五条字符串命中、全新构建证明）、有效尝试判定证据（配置来源行 + hook 行缺失对照清单）、终态判定、停止规则遵守、**收尾证明（C:\Windows 删除后 ls）**、日志留存清单、「我没做的事 / 我不确定的事」。
- vault：`D:/MidaVault/lab/evidence/xx21b_006r4/`。
- 工作区留给总指挥，**不提交**。
