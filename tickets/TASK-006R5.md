# TASK-006R5 — 让受控 ini 真正生效（改代码落位）+ 一格实弹重跑

✅ **已授权 —— 授权令牌（必须在报告第一节原文回抄）**：
> `老板 · 2026-08-30 · 原话"批准 TASK-006R5： 授权"（回应总指挥列明的两件批准请求，按全案解释：两件同时批）· ① 授权 crates/ 改动：crates/packers/themida/src/antiantidebug/scyllahide.rs + crates/cli/src/unpacker/helpers.rs 及其测试模块（仅限本单授权文件清单）· ② 批 1 格实弹 · XC-XXI-B 6/4 → 7/4（超原配额，老板明确扩额）· 前置由总指挥亲验：BootTime = 2026-08-30 1:28:40（与 TASK-006R4 同 boot，无需重启）· 起点 HEAD = 5c09e7a（TASK-006R4 已验收入栈；worker 须核验 5c09e7a 为 HEAD 祖先、且 5c09e7a..HEAD 的 diff 仅 docs/tickets 文件）· vault 受控 ini sha256 c88e94c3… 与样品对象 sha256 78009803… 已当场复核在位`

- **优先级**：P1（缺陷 A 实弹验证的硬前置；R4 已实证这是唯一路径）
- **状态**：✅ 已授权（老板 2026-08-30 批准两件：crates/ 改动 + 一格实弹；记 D-021）
- **岗位**：developer（第一段离线改代码，第二段实弹验证）
- **账本**：XC-XXI-B **6/4 → 7/4**（老板 2026-08-30 明确扩额授权）

## 为什么必须改代码（R4 用一格实弹换回的结论）

TASK-013 断言"InjectorCLI 用裸相对名、只搜 Windows 目录"——**这条错了**。R4 反汇编 + 三组受控实验实证（总指挥已独立复验 IAT 槽）：

- InjectorCLI 调 `GetModuleFileNameW`（IAT 槽 `0x6f150`，调用点 `0x14000ce7f`）拿自身 exe 完整路径，再把它作为文件名参数传给 `GetPrivateProfileSectionNamesW`（IAT 槽 `0x6f158`，调用点 `0x14000cf9a`）→ **它读 `<InjectorCLI 所在目录>/scylla_hide.ini`**
- notepad 注入 A/B/C 三实验：exe 同目录有受控 ini → 三个 =0 开关全不 hook（生效）；同目录无、只有 `C:\Windows` 有 → 全默认（不生效）；改 cwd → 无影响
- 引擎 spawn 的是 `target/release/InjectorCLIx64.exe`，那儿没有 ini → **此前 14/14 次实弹全部处于"全默认 hook、异常分发链开启"状态**

而 `ARTIFACT_POLICY.md` 第 11 条明令：活动工作区不得出现名为 `scylla_hide.ini` 的文件（`.gitignore` 不构成例外）。**所以操作员手工落位彻底走不通**——必须改代码。

## 任务目标

### 第一段（离线，改代码）

让引擎在注入前把受控 ini 送到 InjectorCLI 真正会读的位置，且不违反 ARTIFACT_POLICY。**两条路线二选一，报告里说明选择理由**：

- **路线 A（推荐）**：`scyllahide.rs` 在 spawn 前把注入器 + HookLibrary + 受控 ini **复制到工作区外的运行期 staging 目录**（如 `%TEMP%\mida-scyllahide-<pid>\`），spawn 该副本，运行结束后**整目录删除**。工作区永不出现 `scylla_hide.ini`，策略零冲突。
- **路线 B**：只在注入器同目录（`target/release/`）临时落位 ini，用完立即删。**风险**：`target/` 属活动工作区，ARTIFACT_POLICY 第 11 条字面禁止，即使是运行期临时文件也要老板另行放行——**若选此路线必须先 STOP 请示，不许自行判断"临时文件不算"**。

无论哪条路线，**必须做到**：
1. ini 内容来源 = `MIDA_SCYLLA_HIDE_INI` 环境变量或 `OracleMode.ini_path`（TASK-013 已接线，不要另造机制）；
2. 未提供 ini 时行为**与现在完全一致**（不落位、不改 spawn 路径），保证既有路径零回归；
3. **落位后校验 sha256 与源一致**，不一致即 fail-closed 报错（不许静默继续）；
4. 运行结束（含失败/panic 路径）**清理临时物**，并把"实际落位路径 + 校验结果"写进日志（复用 `SCYLLAHIDE_HOOK_CONFIG_SOURCE` 行或紧邻新增一行）；
5. **不改** `.text`-stable 判定、**不改** C-7 风暴检测、**不改** TASK-009 的门。

### 第二段（实弹，1 格）

用第一段的代码 + 受控 ini 重跑重脱壳，回答那个从未被回答的问题：**关掉异常分发链的 hook（KiUserExceptionDispatcher + NtContinue）后，text-poll 能否收敛到 dump 阶段？**

## 授权文件清单（超出即打回）

| 文件 | 允许的改动 |
|---|---|
| `crates/packers/themida/src/antiantidebug/scyllahide.rs` | 落位 / staging 逻辑 + sha256 校验 + 清理 + 日志；消费 `ini_path` |
| `crates/cli/src/unpacker/helpers.rs` | 仅限 staging 目录路径解析辅助（路线 A 需要时） |
| 上述两文件的测试模块 | 新增用例（落位路径解析、校验失败 fail-closed、无 ini 时零行为变化） |

其余一律不动（含 `av_oep_handler.rs`、`av_handler.rs`、`mod.rs` 的 text-poll/C-7 段、`dump_process.rs`、TASK-009 文件、`_clippy_baseline`、`ci.yml`）。**受控 ini 本身不进 Git**（vault：`D:/MidaVault/lab/config/scylla_hide_no_excdispatch.ini`，sha256 `c88e94c38b8edf36f438449dbd0b62f2967affbf1c6229392cabb7b30be46b5c`）。

## 第一段验收标准（离线，全部要真退出码）

1. `git diff --stat` 只含授权文件；无 `#[ignore]` / `.skip` / 既有断言被放宽。
2. `cargo test -p mida-packers-themida --offline` → **真退出码 0**（P-5：先重定向到文件再取 `%ERRORLEVEL%`），新增用例覆盖三条语义（落位成功且校验通过 / 校验失败 fail-closed / 无 ini 时零变化）。
3. `cargo test -p mida-cli --lib --offline` → 真退出码 0，**580 不许掉**。
4. `cargo test -p mida-pe --lib --offline` → 真退出码 0，**1049 不许掉**。
5. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 真退出码 0。
6. `cargo fmt --all -- --check` → 真退出码 0。
7. **判别力证明**：把落位逻辑改成可编译 no-op（如落位后不校验、或落位到错误目录），新增用例必须变红；贴原始失败输出 + 失败断言原文 + 用例名 + **非 0 真退出码**；恢复后贴 `git diff --stat` 证明干净。**编译失败不算红。**
8. **零实弹自证（第一段）**：第一段结束前未启动 debuggee、未注入、未跑 `/unpack`。

## 第二段前置（不满足就 STOP）

1. **全新 release 构建**（禁复用旧 exe），五条字符串各须命中：`zero-filled IAT region` / `TASK-009 fail-closed` / `guardless constant-AV storm abort` / `C-7: guardless constant-AV storm` / `SCYLLAHIDE_HOOK_CONFIG_SOURCE`。贴 sha256 与体积。
2. **样品身份**（P-6：不用 `.exe` 定位符）：vault 对象 `D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`，期望 sha256 同名。不匹配 = `SampleIdentityMismatch` → STOP。
3. **会话基线**：BootTime、debuggee image_base、ntdll / kernel32 / kernelbase 基址。每次尝试都记 image_base。

## 有效尝试强门（R4 教训，缺一即不算有效数据）

一次尝试**同时满足**才算有效：
- 引擎日志出现 `SCYLLAHIDE_HOOK_CONFIG_SOURCE=ini: ` **且**落位校验通过行；
- 本次 `scylla_hide.log` **不出现** `Hooking NtContinue` 与 `Hooking KiUserExceptionDispatcher`（受控生效的直接证据），**同时贴仍被 hook 的清单作对照**（应含 `NtSetInformationThread` 等 =1 的键，证明 ini 是被解析而非被忽略）。

**注意（R4 血的教训）**：`SCYLLAHIDE_HOOK_CONFIG_SOURCE` 行只是引擎对自己输入的记录，**不等于 InjectorCLI 读到了**。两者可能脱节，必须以 `scylla_hide.log` 的 hook 行为准。若 hook 行仍在 → 落位失败 → 该次**不算有效尝试**，停下排查；**连续 2 次落位失败即 STOP**，不许把无效运行当路径证据。

## 终态判定（四条都合法，如实上报）

- **路径 A**：dump 阶段命中 `TASK-009 fail-closed`、拒绝写产物、`[GOOD] Candidate written` 不出现 → **缺陷 A 修复首次实弹验证**。贴日志、`Unresolved` 计数与 IAT 报告。
- **路径 B**：`[GOOD] Candidate written` 出现 → ① 立刻 **P-4 当场存活探针**（非 0/259 即阻塞上报）；② 检查 `.rdata 0x1137d0` 槽字节（缺陷 A 现场，坏值 `0x1401681d1`）；③ 顺带记 `.bss 0x112c10`（C-5 现场，已知未修）。
- **路径 C**：`guardless constant-AV storm abort` → **关掉异常分发链也没治好环**。必记：AV 数、恒同元组、**exc 相对 ntdll 的偏移（还在 +0x160bd8 吗？这是本路径最有信息量的观测）**、首次 AV→中止耗时、日志体积。立刻停手。
- **路径 D**：text-poll 收敛但死在别处（壳改走其它反调试路径检测到调试器等）→ 如实记录形态。这是 TASK-013 留的待验风险落地处。

## 停止规则（严格执行）

- **有效尝试连续 2 次即停**（无论终态）。
- **落位失败连续 2 次即 STOP**。
- 不许为走通路径 B 反复重跑。

## 收尾（强制，无论终态）

1. **清理所有落位/staging 临时物**，贴清理后的目录列表证明（含 `ls target/release/*.ini` 应为空、staging 目录已删）；
2. **本次 `scylla_hide.log` 必须先复制进 vault 再做任何新注入**（P-8：该文件每次注入覆盖，证据窗口只有一次）；
3. 日志留存：删任何日志前先算好计数（AV 总数、恒同元组、事件类型分布，`grep -c` 原始命令贴报告）→ 有界摘要（头 200 + 尾 200 + 计数）进 vault `D:/MidaVault/lab/evidence/xx21b_006r5/`，本体 <50MB 一并留档。

## 红线（违反即整单作废）

- `NO_BYPASS=1` 全程；网络 `deny_all`；样品不外发；**禁止伪造证据**。
- **不写 `C:\Windows`**（R4 已证无效，本单不再碰系统目录）。
- **git 只读**：不 commit / push / stash，不改 config，不改 `lab/cases/v2/*.json`。改 `crates/` 仅限授权清单内文件。
- 不新增依赖、不改 `Cargo.toml` / `Cargo.lock`。
- 不许改既有测试断言迁就自己；不许 `#[ignore]` / `.skip` / 注释用例。
- 临时文件用完**逐个按名删除**。
- 结论按 `[已验证]` / `[推断]` / `[存疑]` 标注；只贴原始输出；报告第一节回抄授权令牌。

## 交付物

- `runs/<日期>-TASK-006R5.md`：授权令牌回抄、第一段八条验收原始输出（含真退出码 + 判别力证明）、第二段前置原始输出、**有效尝试判定证据（配置来源行 + 落位校验行 + hook 行缺失/仍在的对照清单）**、终态判定、停止规则遵守、收尾清理证明、日志留存清单、「我没做的事 / 我不确定的事」。
- vault：`D:/MidaVault/lab/evidence/xx21b_006r5/`。
- 工作区留改动给总指挥，**不提交**。