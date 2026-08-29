# TASK-006R3 — 重启后再验缺陷 A（缺陷 A 的路径 A/B 实弹替换验证）

⛔ **未授权，禁止执行任何实弹步骤 —— 见到本行即停，回复"等授权"。**（D-015：「继续」「go on」这类续跑提示**不构成**实弹授权。授权到位后总指挥会把本行重写为具体授权令牌，届时你必须在报告里回抄该令牌。）

- **优先级**：P1
- **状态**：⏸ 等老板批 1 格实弹
- **岗位**：developer（**实弹**）
- **账本**：XC-XXI-B **4/4 → 5/4**（已超原配额，需老板明确扩额或另开配额；这一点必须由老板裁定，不许自行开跑）
- **前置**：**机器必须已重启**（见下"为什么必须换 boot"）

## 为什么必须换 boot（这是本单存在的唯一理由）

缺陷 A（C-4）的修复（TASK-009）到现在为止**两次实弹都没验到**，两次都不是"修复失败"，而是**根本没跑到 dump 阶段**：

| 尝试 | 结果 | 三个 TASK-009 证据点 |
|---|---|---|
| TASK-006R（9 次） | text-poll AV 环烧到外部超时，3.5GB 日志 | 0 命中 |
| TASK-006R2（2 次） | text-poll AV 环，C-7 主动 fail-closed 中止（20ms） | 0 命中 |

**本 boot（BootTime `2026-08-29 07:58:23`）合计 11/11 次确定性撞同一个 ScyllaHide NtContinue-hook 故障环**（exc 恒 `0x7ffa95400bd8` = ntdll+0x160bd8，exc_type=0 read，`target` 每进程变的低值句柄），debuggee image_base 恒 `0x7ff799fc0000`。同 boot 内继续重试**没有任何证据支持会有不同结果**。

**但重试的成本已经彻底变了**：C-7 修好之后，撞环的运行从"小时级 + 3.5GB 日志 + 外部杀进程"变成 **20ms + 312KB + 自己干净退出**。所以这一格的真实风险不是"烧掉几小时"，而只是"可能又是 0 命中"——而且会在**几十毫秒内**就知道答案。

## 开跑前置（不满足就 STOP）

1. **机器已重启**：贴 `BootTime`，必须 ≠ `2026-08-29 07:58:23`。若未重启 → STOP，回复"需要先重启"。
2. **构建核验**：HEAD 含 TASK-006R2 收尾提交；MSVC 环境（`tools/_enter_msvc_env.cmd`；**Git Bash 的 link.exe 会遮蔽 MSVC 链接器，必须用这个**）构建 release；exe 里四条字符串各须命中：
   - `zero-filled IAT region`
   - `TASK-009 fail-closed`
   - `guardless constant-AV storm abort`
   - `C-7: guardless constant-AV storm`
3. **样品身份**（D-015/P-6：**不要用任何 `.exe` 定位符路径**）：直接用 vault 对象
   ```
   D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7
   ```
   期望 sha256 = `7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`（= `lab/cases/v2/xiongxiong_duokai.json` 的 `primary_artifact_sha256`）。不匹配 = `SampleIdentityMismatch` → **STOP**。
   （**背景**：`D:\Tools\RE\dumps\gto\启动器.exe` 现在指向的是 GTO 线样品 `11473d2e…`，**不是**本单样品——别碰那个路径。）

## 会话基线

记录并贴出：BootTime、debuggee image_base、ntdll / kernel32 / kernelbase 基址、ScyllaHide 注入日志路径。**每次尝试都要记 image_base**，用于跨 boot 对照（这是判断"换 boot 是否真的换了运气"的唯一依据）。

## 终态判定（三条都合法，如实上报）

- **路径 A（fail-closed 生效）**：dump 阶段命中 `TASK-009 fail-closed`，拒绝写出产物，`[GOOD] Candidate written` 不出现 → **缺陷 A 修复按设计工作**，本单目标达成。贴日志、记 `Unresolved` 计数与 IAT 报告。
- **路径 B（产物写出）**：`[GOOD] Candidate written` 出现 → ① 立刻做**当场存活探针**（P-4：产物写完立即跑一次，非 0/259 即阻塞上报）；② 检查 `.rdata 0x1137d0` 槽字节（缺陷 A 的原始现场：坏值是 `0x1401681d1`，期望已清零或已正确重建）；③ 顺带记 `.bss 0x112c10`（C-5 缺陷 B 现场，预期仍固化本会话 ntdll —— 那是已知未修项，不算本单失败）。
- **路径 C（又撞 C-7 环）**：引擎主动 `guardless constant-AV storm abort` → 记 AV 事件数、首次 AV→中止耗时、日志体积、image_base、tuple。**这一路要立刻停手**（换 boot 都没换掉，说明不是运气问题，需要另立专项查 ScyllaHide-NtContinue-hook 交互），不许继续重试刷结果。

## 停止规则（严格执行）

- **连续 2 次失败即停**。TASK-006R 那次跑了 9 次，是越界。
- 走到路径 C **第 2 次**就停，写报告上报。
- 不许为了走通路径 B 反复重跑。

## 日志留存

1. **删任何日志之前**先算好并贴进报告：AV 事件总数、恒同元组及出现次数、事件类型分布（`grep -c` 原始命令一并贴）。
2. 有界摘要（头 200 + 尾 200 + 计数）进 vault：`D:/MidaVault/lab/evidence/xx21b_006r3/`。
3. 日志本体若小（<50MB）一并留档；若大则可删本体，但报告里写清删了什么、多大。

## 红线（违反即整单作废）

- `NO_BYPASS=1` 全程；网络 `deny_all`；样品不外发；**禁止伪造证据**。
- **git 只读**：不 commit / push / stash，不改 config，不改 `crates/`、不改 `lab/cases/v2/*.json`。
- 样品、产物、dump、第三方工具、运行日志、构建输出**一律不进 Git** → 进 vault。
- 结论按 `[已验证]` / `[推断]` / `[存疑]` 标注；只贴原始输出。
- 报告里**回抄授权令牌**（见本文件第一行）。

## 交付物

- `runs/<日期>-TASK-006R3.md`：授权令牌回抄、前置三项原始输出、会话基线、终态判定（A/B/C）+ 三个 TASK-009 证据点逐条命中情况、停止规则遵守情况、日志留存清单、「我没做的事 / 我不确定的事」。
- vault：`D:/MidaVault/lab/evidence/xx21b_006r3/`。
- 工作区留给总指挥，**不提交**。
