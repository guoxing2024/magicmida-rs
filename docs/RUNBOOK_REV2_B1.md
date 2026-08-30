# RUNBOOK_REV2_B1 — B1'（XX-11 端点恢复）复现配方

> 建立：2026-08-30（TASK-016 阶段收尾）· 依据：`runs/20260830-TASK-015.md`（2/2 次有效实弹）+ `runs/20260830-TASK-014.md`
> 目标：照做即可复现 B1' 终态（trace 74/74、imports 186、结构门 12/12、load 10/10、S4 字节级对齐、产物 1,539,072 B）。
> **本文件是配方，不是承诺**。每条判据的预期数字来自 T015 实弹日志（`[已验证]`）；跨 boot/跨样品必然有 ASLR 差异，判据只看**计数与日志行**，不看具体地址。

---

## 0. 前置条件（不满足就停，别硬跑）

| 项 | 检查 | 预期 |
|---|---|---|
| 环境 | Git Bash + MSVC（`tools/_enter_msvc_env.cmd`） | 见 AGENTS.md §2 |
| 样品 | `D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7` 存在且 sha256 一致 | `sha256sum <路径>` = 文件名 |
| 受控 ini | `D:/MidaVault/lab/config/scylla_hide_no_excdispatch.ini` 存在 | sha256 = `c88e94c38b8edf36f438449dbd0b62f2967affbf1c6229392cabb7b30be46b5c`（只核在位，T016 起可由 preflight 检查三键） |
| 注入器/钩子 | `target/release/InjectorCLIx64.exe`、`target/release/HookLibraryx64.dll` 在 CLI exe 旁 | 可选；缺则注入 fail 但 debug loop 仍跑（非 B1' 配方） |
| vault 证据 | `D:/MidaVault/lab/evidence/xx21b_t015/`（INDEX 见该目录 `INDEX.md`） | 复算用 |

**红线（零实弹重申）**：debuggee 只能由本 runbook 的 `/unpack` 命令启动；`NO_BYPASS=1` 必须携带；不写 `C:\Windows`；不对外发样品。

---

## 1. 构建（离线，必须先做）

```bash
cd "D:/Claude project/magicmida-rs"
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\ncargo build --release -p mida-cli --offline\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

预期判据：
- `Finished \`release\` profile` + `EXIT=0`。
- 新构建的 `target/release/mida-cli.exe` 五条字符串全 HIT（T015 §5 已验证）：
  `zero-filled IAT region` / `TASK-009 fail-closed` / `guardless constant-AV storm abort` / `C-7: guardless constant-AV storm` / `SCYLLAHIDE_HOOK_CONFIG_SOURCE`
  （`grep -c` 每条 ≥ 1）。

---

## 2. 实弹命令全文（B1' 配方）

```bash
MSYS_NO_PATHCONV=1 NO_BYPASS=1 MIDA_GTO_NO_BYPASS=1 MIDA_LEGACY_ANTIDEBUG=1 \
  MIDA_SCYLLA_HIDE_INI=D:/MidaVault/lab/config/scylla_hide_no_excdispatch.ini CARGO_INCREMENTAL=0 \
  timeout 300 target/release/mida-cli.exe /unpack \
  D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7 \
  --profile=oreans-classic --container-restore=off --oep=captured --data-sections \
  -o lab/xx21b_t015/rev2_unpacked_t015_attemptN.exe > lab/xx21b_t015/attemptN.log 2>&1
```

**环境变量逐项说明**：
| 变量 | 值 | 作用 |
|---|---|---|
| `NO_BYPASS=1` / `MIDA_GTO_NO_BYPASS=1` | 必带 | 红线：禁止 GTO 诊断 bypass 补丁参与产物 |
| `MIDA_LEGACY_ANTIDEBUG=1` | 必带 | 打开 Oreans legacy 注入路径（ScyllaHide 注入 + 经典 debug loop）；不设则 ADR-3B fail-closed 直接拒跑 |
| `MIDA_SCYLLA_HIDE_INI` | 必带 | 受控 ini 绝对路径；注入器 staging 用它关闭异常分发链 |
| `CARGO_INCREMENTAL=0` | 必带 | rustc 1.97.1 ICE 规避（KNOWN_ISSUES E-5） |
| `timeout 300` | 安全网 | 5 分钟硬上限，超时 = 判失败 |

**flag 逐项**：
- `--profile=oreans-classic`：Oreans 经典 dump profile（GTO 专属补丁不激活）
- `--container-restore=off`：不重建容器（B1' 不需要）
- `--oep=captured`：OEP 取冻结时 .text RIP（本样品 = 0x1010；默认值，显式写出防歧义）
- `--data-sections`：dump 阶段重建 `.rdata`/`.data` 节（影响产物节布局，T014 未带、T015 带上后结构门 12/12 与 XX-11 一致）

**产物/日志路径**：`lab/xx21b_t015/`（工作区留档，不提交；vault 证据在 T015 已入 `D:/MidaVault/lab/evidence/xx21b_t015/`）。

---

## 3. 每步预期判据（日志 grep + 预期数字）

| 步骤 | grep 命令 | 预期 | 依据 |
|---|---|---|---|
| ① 受控 ini 记录 | `grep -c SCYLLAHIDE_HOOK_CONFIG_SOURCE attemptN.log` | **2 行**（mod.rs 与 controller 各 1） | T015 强门 ① |
| ② ini staging 校验 | `grep "staging verification passed" attemptN.log` | **1 行** + `sha256=c88e94c3…`（后 4 位 hex 依 ini 演进可变） | T015 强门 ② |
| ③ stale pending 清除 | `grep -c "clearing stale pending" attemptN.log` | **=1**（T015 实测；trace 启动前恰好 1 次） | T015 根因修复触发 |
| ④ trace 解析 | `grep -c "OK IAT\[" attemptN.log` 或 `grep "IAT trace finished"` | **OK IAT[x]=75** / `resolved=74 failed=0 skipped=127 product_complete=true` | T015 §7 |
| ⑤ imports 计数 | `grep "Creating import section" attemptN.log` | **186** thunks | T015 §7 |
| ⑥ 产物写出 | `grep "\[GOOD\]" attemptN.log` | **=1**（`[GOOD] Candidate written`） | T015 终态 B1' |
| ⑦ 结构门 | `structural_attemptN.json` | **12/12**（`verdict: StructuralPassBehaviorPending`） | T015 §7 |
| ⑧ load 存活 | `load_no_crash_attemptN_x10.json` | **10/10**（rate-samples=10, pass_rate=1.0, 0 AV） | T015 §7 |
| ⑨ S4 标记 | 窗口标题 + `config.ini` + `core.dll` | "授权验证"；`[Loader] DllVersion=1.1`（26B）；core.dll 与本样品历史战役逐位一致 | T015 §7 |

**每步日志判据核对顺序**：①→② 必须先行（证明受控 ini 生效），③ 在 trace 启动前，④→⑤ 在 dump 阶段，⑥ 之后 ⑦⑧⑨ 是产物评估。

---

## 4. 终态判定表

| 终态 | 判定条件 | 处置 |
|---|---|---|
| **B1'** | ①②全过 + trace resolved=74/failed=0 + imports 186 + 结构门 12/12 + load 10/10 + S4 对齐 + `[GOOD]`=1 | ✅ 目标达成；2 次即停（T015 已 2/2） |
| **B2** | 结构门 12/12 + load 10/10 但 S4 业务标记不全（如 config.ini/core.dll 缺失） | 行为域未全恢复，报告 + 停止规则 |
| **A'** | ①②全过但 trace failed>0（fail-closed 拒写 `[GOOD]`；日志 `TASK-009 fail-closed`） | 复现未达成；按 T014 定位 |
| **C** | ①②未全过（ini 缺失/键缺失/注入失败）+ AV 风暴环（`guardless constant-AV storm abort` 或外部超时） | 配置问题；先用 T016 preflight 的 ScyllaHide 检查确认三键在位 |
| **D** | 进程起不来 / 网络外联 / 非授权动作 | 立即停，写阻塞报告 |

**"什么会弄坏它"清单（复现失败时的首要嫌疑）**：
1. **无 ini / ini 键缺失**：`MIDA_SCYLLA_HIDE_INI` 未设或指向不含三零键的文件 → 异常分发链默认全 hооk → text-poll 撞 AV 风暴环。**T016 起用 preflight 的 ScyllaHide readiness 检查前置拦截**（`check_scylla_hide_readiness`）。
2. **注入器不在 exe 旁**：`target/release/` 无 `InjectorCLIx64.exe`/`HookLibraryx64.dll` → 注入失败（warn 非致命），无受控 ini 生效 → 同 1。
3. **DR apply 失败（T0.5-R2 宽限窗）**：`arm deferred HW anchor failed: ERROR_NOACCESS` → 12s grace window → 若遗留其它线程 pending 未清 → trace 0/74。**T015 已修**（stale pending 按归属线程 continue）；复发则查 `clearing stale pending` 是否 =1。
4. **workspace 有 `scylla_hide.ini`**：ARTIFACT_POLICY 禁止；注入器 staging 冲突。
5. **`--data-sections` 不带**：产物节布局不同（T014 路径），结构门数字可能对不上（T015 §12 [存疑] 未做逐节 diff）。
6. **NO_BYPASS 未带**：红线违规，产物可能含 GTO 诊断补丁，直接作废。

---

## 5. vault 证据指针

- 本次战役证据：`D:/MidaVault/lab/evidence/xx21b_t015/`（34 件，INDEX.md 有全清单 + sha256）
- XX-11 时代端点证据：`D:/MidaVault/lab/evidence/xiongxiong_duokai/xx11_attempt_20260828-112236/`（`XX11_REPORT.md`、`unpack.stdout.txt`、产物 + sidecar）
- 受控 ini：`D:/MidaVault/lab/config/scylla_hide_no_excdispatch.ini`
- 样品：`D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`

---

## 6. T016 新增：preflight ScyllaHide readiness（离线可跑）

```bash
# 构建后（离线）：
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\ncargo test -p mida-acceptance --lib --offline scylla_hide\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

预期：7 passed / 0 failed，`EXIT=0`。这 7 个用例直接验证 `check_scylla_hide_readiness`（三零键 + 注入器/钩子/ini 三件套在位）。生产接线（把该检查挂进 `run_offline_preflight`）留待后续授权工单（涉及 main.rs 等清单外文件）。

---

## 7. 已知限制（诚实声明）

- 判据数字（75/74/186/12/10）来自 T015 2/2 次实弹，**同一 boot 家族内确定性**；跨 boot ASLR 全变但计数不变（T015 §7 对照表已验证）。
- `--data-sections` 对产物节布局的净效应未做逐节 diff（T015 §12 [存疑]）。
- C-7 阈值 1024 在本配方下不应触发（0 AV）；触发即 = 配置问题（见 §4 终态 C）。
