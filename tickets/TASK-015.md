# TASK-015 — shell trace 线程/时机修复：让 74 个 VM wrapper 槽可解析（恢复 XX-11 端点路径）+ 一格实弹冲 B1'

✅ **已授权 —— 授权令牌（必须在报告第一节原文回抄）**：
> `老板 · 2026-08-30 · 原话"批准"（回应总指挥列明的 TASK-015 范围与两件批准请求，按全案解释：两件同时批）· ① 授权 crates/ 改动：crates/packers/themida/src/trace_imports/mod.rs + slot.rs、crates/pe/src/dumper/iat_partial_accept.rs + iat_gap_retarget.rs + dump_process.rs + import_rebuild.rs + iat_completeness.rs、crates/cli/src/unpacker/iat_evidence.rs、crates/acceptance/src/oreans_gate.rs（仅限 #[serde(default)]/新增可选字段）及其测试模块（仅限本单授权文件清单；fail-closed 门语义零改动为硬约束）· ② 批 1 格实弹 · XC-XXI-B 8/4 → 9/4（超原配额，老板明确扩额）· 前置由总指挥亲验：BootTime（令牌签发时刻）= 2026-08-30 10:05:51（执行时 boot 已变不构成 STOP 事由，照实记录即可——D-022 新规）· 起点 HEAD = 291b239（TASK-014 已验收入栈；worker 须核验 291b239 为 HEAD 祖先、且 291b239..HEAD 的 diff 仅 docs/tickets 文件）· vault 受控 ini sha256 c88e94c3… 与样品对象 sha256 78009803… 已当场复核在位`

- **优先级**：P1（XX-11 端点恢复的最短路径；路径 B 的硬前置）
- **状态**：✅ 已执行并验收（2026-08-30，终态 = 路径 B1'：XX-11 端点恢复——74/74 trace 全解析、186 imports、结构门 12/12、load 10/10、S4 字节级对齐、产物 1,539,072 B ×2；账本 9/4，验收记 D-029）
- **岗位**：developer（第一段离线定位+修复，第二段实弹验证）
- **账本**：XC-XXI-B **8/4 → 9/4**（老板 2026-08-30 明确扩额授权）

## 背景 A：TASK-014 实弹诊断定案 [已验证，vault `xx21b_t014/`]

- 201 槽 = **112 Resolved**（live 直接匹配：msvcrt 76 / kernel32 19 / user32 7 / ntdll 5 / wininet 4 / version 1）+ **74 Unresolved** + 15 ZeroTerminator；192 启动路径站点 → 74 唯一槽，全部 Unresolved。
- 74 个启动路径槽的运行时值**全部是 Themida 段内 VM wrapper 地址**（image_base+0x1681d1 … +0x3203d7；偏移 0x1681d1 与 XX 时代旧产物 `.rdata 0x1137d0` 坏值 `0x1401681d1` 逐位一致——跨 boot 确定性互证）。
- **静态原导入表（9 项）对 VM wrapper 地址结构性 0 命中 → XX-10-A 静态回填 0 覆盖是结构性必然**（不是回归）。
- **shell trace 74 槽全败**（deepened retry 亦败；T014 已 slot-scoped 化，201 槽全遍历可见）：`tracing completed but no API resolved`，无 HitVm 无 FoundApi——单步 trace 在主线程上没有 wrapper 地址的事件。
- **对照：XX-11（08-28）用同族机制把全部 186 imports 解析成功（含 VM 槽）**——报告 vault `xiongxiong_duokai/xx11_attempt_20260828-112236/XX11_REPORT.md`。它当年怎么做到的 = 本单的钥匙。

## 背景 B：两个待验证假设 [不得预设结论]

1. **trace 机制回归**：`18e0349`（XX-11 末笔）→ `291b239` 祖先链上的 8-29 接管日提交（TASK-001…012）之间，trace_imports / dump 路径有约 20 笔改动——XX-11 的 trace 为什么能解 VM 槽、现在为什么不能，`git diff 18e0349..291b239` 里应当有答案（或至少有嫌疑改动清单）。
2. **flag/窗口假设**：XX-10/11 命令带 `--oep=captured --data-sections`，006R 系命令从未带过。`--oep=captured` 改变 OEP 路径与 dump 时机，可能改变 trace 的执行窗口/线程上下文。

## 任务目标

### 第一段（离线）

1. **回归定位（第一优先，只读）**：
   a. `git diff 18e0349..291b239 -- crates/packers/themida crates/pe crates/cli` 逐笔审读，列出影响 shell trace（单步采集、线程选择、trace 窗口、slot 遍历）的改动；
   b. 精读 XX-10/11 报告与 `rev2_unpacked.exe.iat_evidence.json`，还原 XX-11 时代"VM 槽被解出"的完整机制链（谁单步、单步什么地址、何时停止）；
   c. 核对 `--oep=captured` / `--data-sections` 的语义与影响面（args.rs 只读）；
   d. 结论 [已验证]/[推断] 分级，指认主根因（回归 or 机制缺口 or 两者）——此项是第二段通行证。
2. **修复**：让 shell trace 在正确线程/时机单步 VM wrapper 槽。方向不限（trace 窗口提前到壳解析 IAT 的启动段、线程选择/跟随、重触发解析、启动期单步采集等），但**验收级差目标 = 74 槽可解析 → ≥186 imports**；**不许改松 fail-closed 门**；不许动 text-poll/C-7/`data_reinit.rs`。
3. **补 T014 欠账**：slot-scoped 行为改动补**真实行为测试**（"单槽生命周期失败 → 记 failed 且继续遍历余槽"，不得只断言字符串）。
4. **acceptance crate sidecar（如需）**：`crates/acceptance/src/oreans_gate.rs` 仅限给新诊断字段加 `#[serde(default)]`/新增可选字段，使 `OreansIatEvidence` 能携带 192 站点 + 201 槽诊断；其余 acceptance 文件不动。
5. **单元测试 + 判别力证明**：核心修复改可编译 no-op（如 trace 恒返回 failed）→ 新用例必须红（非 0 真退出码）→ 字节级恢复；`--profile=oreans-classic` 全套回归不回退。

### 第二段（实弹，1 格——第一段判别力未过或回归源未定位即 STOP，不烧格）

命令 = T014 命令 + **按第一段结论补齐 flag**（预期含 `--oep=captured --data-sections`，以证据为准）+ `MIDA_SCYLLA_HIDE_INI` staging 照旧。

**强门（沿用，缺一即不算有效尝试）**：`SCYLLAHIDE_HOOK_CONFIG_SOURCE` 双行（ini + staged sha256）+ `staging verification passed` + `scylla_hide.log` 无 NtContinue/KiUser hook 行且 15 个 =1 键在列 + P-8：`scylla_hide.log` 先复制进 vault 再做任何新注入。

**终态判定（都合法，如实上报）**：
- **B1'**：门通过（fail-closed 0 命中）+ `[GOOD] Candidate written` + **P-4 当场存活探针 exit 0** + `iat_evidence_complete=true` → **XX-11 端点恢复**。逐项对照 XX-11：imports 数（186？）、结构门 12/12、load_no_crash ×10、S4 可观测标记（窗口标题/config.ini/core.dll）。贴产物 sha256/大小/探针原始输出。
- **B2**：门通过 + 产物写出 + P-4 失败 → 如实记录 + 对照逐槽诊断（哪些槽仍 unresolved）→ 有价值数据，不算失败也不许报成成功。
- **A'**：门仍触发 → 必记 unresolved 站点/槽数（对照 192/74）、全量清单、逐槽诊断（trace 失败形态有无变化——例如从"无单步事件"变成"有事件但未到 API"）。1 次有效尝试即可记录；确认确定性可跑第 2 次（两次记 1 格），之后立即停。
- **C**：风暴（记 exc 偏移是否 +0x160bd8）／**D**：新形态 → 照实。

**停止规则**：有效尝试连续 2 次即停；A' 未改善不许第 3 次；不许为凑 B 反复重跑。

## 授权文件清单（超出即打回）

| 文件 | 允许的改动 |
|---|---|
| `crates/packers/themida/src/trace_imports/mod.rs`、`slot.rs` | trace 线程/时机/起点修复 |
| `crates/pe/src/dumper/iat_partial_accept.rs`、`iat_gap_retarget.rs`、`dump_process.rs`、`import_rebuild.rs`、`iat_completeness.rs` | 适配与诊断延续 |
| `crates/cli/src/unpacker/iat_evidence.rs` | sidecar 结构化（若 serde default 落地） |
| `crates/acceptance/src/oreans_gate.rs` | **仅限** `#[serde(default)]`/新增可选字段 |
| 上述文件的测试模块 | 新增用例 |

其余一律不动（含 `data_reinit.rs`、`av_oep_handler.rs`、`av_handler.rs`、`mod.rs` 的 text-poll/C-7 段、`args.rs`、`oep/` 模块、`_clippy_baseline`、`ci.yml`、`Cargo.toml`/`Cargo.lock`）。**回归定位是只读工作；若修复需触碰清单外文件（如 `oep/`、`args.rs`）→ STOP 请示，不许自行判断。**

## 第一段验收标准（离线，全部要真退出码）

1. `git diff --stat` 只含授权文件；无 `#[ignore]`/`.skip`/既有断言被放宽。
2. `cargo test -p mida-pe --lib --offline` → 真退出码 0，**1054 不许掉**。
3. `cargo test -p mida-packers-themida --offline` → 真退出码 0，**175 不许掉**（新增 slot-scoped 真实行为测试 ≥1）。
4. `cargo test -p mida-cli --lib --offline` → 真退出码 0，**580 不许掉**。
5. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 真退出码 0；`cargo fmt --all -- --check` → 真退出码 0。
6. **判别力证明**：核心修复改可编译 no-op → 新用例变红（贴原始失败输出 + 用例名 + 非 0 真退出码）→ 字节级恢复（`git diff --stat` 与探针前一致）。**编译失败不算红。**
7. **回归定位报告**（第二段通行证）：`git diff 18e0349..291b239` trace 路径审读结论 + XX-11 机制链还原 + flag 影响面 + 主根因指认（[已验证]/[推断] 分级）。
8. **零实弹自证（第一段）**：未启动 debuggee、未注入、未跑 `/unpack`。

## 第二段前置（不满足就 STOP）

1. **全新 release 构建**（禁复用旧 exe），五条字符串各须命中：`zero-filled IAT region` / `TASK-009 fail-closed` / `guardless constant-AV storm abort` / `C-7: guardless constant-AV storm` / `SCYLLAHIDE_HOOK_CONFIG_SOURCE`。贴 sha256 与体积。
2. **样品身份**（P-6）：vault 对象 `D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`，期望 sha256 同名。不匹配 → STOP。
3. **会话基线**：BootTime、debuggee image_base、ntdll/kernel32/kernelbase 基址，每次尝试记 image_base。BootTime 与签发时刻不同不构成 STOP（D-022 新规），照实记录。

## 红线（违反即整单作废）

- `NO_BYPASS=1` 全程；网络 `deny_all`；样品不外发；**禁止伪造证据**。
- 不写 `C:\Windows`；git 只读（不 commit/push/stash、不改 config、不改 `lab/cases/v2/*.json`）；改 `crates/` 仅限授权清单内文件。
- 不新增依赖、不改 `Cargo.toml`/`Cargo.lock`；不许改既有测试断言迁就自己；不许 `#[ignore]`/`.skip`。
- **不许把 fail-closed 门改松制造"通过"**；**不许动 xx 战役与 xx21b 系列 vault 证据（只读）**。
- 临时文件用完逐个按名删除；结论按 `[已验证]`/`[推断]`/`[存疑]` 标注；只贴原始输出；报告第一节回抄授权令牌。

## 收尾（强制，无论终态）

1. staging/临时物全清，贴清理证明（`ls target/release/*.ini` 空、`%TEMP%\mida-scyllahide-*` 无、evidence 临时副本入 vault 后删除）；
2. 本次 `scylla_hide.log` 先入 vault 再做新注入（P-8）；
3. 日志删除前先算好计数（`grep -c` 原始命令贴报告）→ 有界摘要（头 200+尾 200）+ 本体（<50MB）入 vault `D:/MidaVault/lab/evidence/xx21b_t015/`。

## 交付物

- `runs/<日期>-TASK-015.md`：授权令牌回抄、回归定位报告（第 7 条）、第一段验收原始输出（含判别力）、第二段前置、有效尝试判定证据（强门四件套）、终态判定（B1'/B2/A'/C/D 之一）、**与 XX-11 端点逐项对照表**、停止规则遵守、收尾清理证明、「我没做的事 / 我不确定的事」。
- 工作区留改动给总指挥，**不提交**。
