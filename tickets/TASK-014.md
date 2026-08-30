# TASK-014 — IAT 启动路径回归定位与恢复（XX-11 端点 186/186 已实证存在）+ 一格实弹

✅ **已授权 —— 授权令牌（必须在报告第一节原文回抄）**：
> `老板 · 2026-08-30 · 原话"可以开始"（回应总指挥列明的两件批准请求，按全案解释：两件同时批）· ① 授权 crates/ 改动：crates/pe/src/dumper/iat_partial_accept.rs + iat_gap_retarget.rs + dump_process.rs + import_rebuild.rs、crates/pe/src/iat_completeness.rs、crates/packers/themida/src/trace_imports/mod.rs + slot.rs、crates/cli/src/unpacker/iat_evidence.rs 及其测试模块（仅限本单授权文件清单；fail-closed 门语义零改动为硬约束）· ② 批 1 格实弹 · XC-XXI-B 7/4 → 8/4（超原配额，老板明确扩额）· 前置由总指挥亲验：BootTime（令牌签发时刻）= 2026-08-30 10:05:51（执行时 boot 已变不构成 STOP 事由，照实记录即可——D-022 新规）· 起点 HEAD = be28951（TASK-006R5 已验收入栈；worker 须核验 be28951 为 HEAD 祖先、且 be28951..HEAD 的 diff 仅 docs/tickets 文件）· vault 受控 ini sha256 c88e94c3… 与样品对象 sha256 78009803… 已当场复核在位`

> **修订 v2（2026-08-30，总指挥，记 D-024）**：老板质询后总指挥直读 vault，发现 xx 战役 XX-10/XX-11 报告——**IAT 重建在 08-28 已实证做到 186/186 全解析 + load 10/10**。原工单"扩展回溯"的问题定义作废，改为**回归定位优先**。授权包不变（同 8 文件 + 同 1 格，令牌原文仍有效）；修复若需触碰授权清单外文件 → STOP 请示。

- **优先级**：P1（回归定位 + 恢复 XX-11 已知端点；路径 B 的硬前置）
- **状态**：✅ 已执行并验收（2026-08-30，终态 = 路径 A'：192 站点全列 + 201 槽逐槽诊断采回；74 启动槽 = Themida VM wrapper；账本 8/4，验收记 D-027）
- **岗位**：developer（第一段离线定位+修复，第二段实弹验证）
- **账本**：XC-XXI-B **7/4 → 8/4**（老板 2026-08-30 明确扩额授权）

## 背景 A：xx 战役（2026-08-28）已实证到达的端点 [已验证，vault 直读]

vault：`D:/MidaVault/lab/evidence/xiongxiong_duokai/`（xx1…xx11 全序列 + 产物 + sidecar 证据 + 报告）。

- **XX-10**（09:46，基线 `68109ba` = XX-10-A）：**IAT 186 imports 全解析**（slot 0 二次 trace 深化 2M 步解出 `advapi32!AllocateAndInitializeSid`，`iat_evidence_complete=true`、`is_complete()` 过完美门）、结构门 **12/12**；行为 load_no_crash **0/10 AV**——归因：OEP 误写 0x1020（.text 未完全解密时扫描假阳性）→ 全进程栈错位 8 字节 → wininet `movdqa` SSE AV。
- **XX-11**（11:22，基线 `52d8529` + `18e0349` 双修复：OEP prologue 回溯 + .text poll 双区域特征验证）：**IAT 186/186 全解析（含 wininet 9 函数）+ 结构门 12/12 + load_no_crash 10/10 零 AV + 进程存活 8s+ + S4 业务标记 8/8 对齐**（窗口标题"授权验证"、config.ini `[Loader] DllVersion=1.1`、core.dll 提取）。**这就是"前天跑通"的完整含义。**
- **同一区域坐实**：XX-10 报告 slot 0 现场 VA `0x7ff7f3e236e0` 低 32 位与 R5 honest-holes 的 IAT 区基址 `0x1136e0` 吻合（反推 image base `0x7ff7f3d10000`，64K 对齐合理）[推断，强]。
- **XX-10/11 命令**（与 006R 系的关键差异）：`MIDA_LEGACY_ANTIDEBUG=1 mida-cli /unpack <rev2> -o rev2_unpacked.exe --profile=oreans-classic --oep=captured --container-restore=off --data-sections -v` —— 带 `--oep=captured` 与 `--data-sections`，**006R 系命令从未带这两个 flag**。

## 背景 B：回归窗口 [待第一段验证，不得预设结论]

`18e0349`（XX-11 末笔，08-28）→ `be28951`（R5 基线，08-30）之间约 20+ 笔提交（8-29 接管日 TASK-001…012 等，含 TASK-009 zero-fill/fail-closed 门、TASK-011/012 C-7）。IAT 从 **186/186 退化到 0/201 全零**。两个候选解释（可并存）：
1. **flag 假设**：`--oep=captured` / `--data-sections` 中有 gate IAT 解析路径的开关，006R 系命令缺失 → retrace 根本没跑；
2. **代码回归假设**：接管日某笔改动改变了 dump/IAT 路径的顺序或条件（如 zero-fill 与 retrace 的先后、OEP 扫描路径变化）。

## 任务目标

### 第一段（离线）

1. **回归定位（第一优先）**：
   a. 只读核对 CLI 参数语义（`crates/cli/src/args.rs` 及消费点）：`--oep=captured`/`--data-sections` 是否 gate IAT retrace/解析路径，画出开关链；
   b. `git diff 18e0349..be28951 -- crates/pe crates/packers/themida crates/cli` 逐笔审读，列出影响 dump/IAT 路径的改动 + 机制解释；
   c. 对照 XX-11 的 186 槽证据（vault `xx11_attempt_20260828-112236/rev2_unpacked.exe.iat_evidence.json`）与 R5 的 0/201，指认回归源，**结论按 [已验证]/[推断] 分级**；
   d. 此项为只读工作（git/文档/代码阅读），不要求改代码。
2. **完整清单外发 + 逐槽诊断**（保留）：fail-closed 门触发时外发全部 N 个站点（site rva → slot rva，不再截断 16 个样本）+ 逐槽诊断（运行时原始值、模块归属判定、回溯尝试路径）；诊断字段对照 XX-11 的 186 槽清单设计，便于实弹后直接比对。
3. **修复 = 恢复，不是扩展**：若 flag 缺失 → 第二段命令补 flag + 默认值文档化（代码改动最小化）；若代码回归 → 恢复原路径且**保住** TASK-009/011/012 的新语义。恢复后 186/186 应使门**自然通过**；若门仍触发，如实报数——**不许改松门制造通过**。
4. **单元测试 + 判别力**：合成 thunk 链四型用例（直指/一级间接/shell 内部 stub/不可解析）+ **回归测试**（锁住恢复后的解析路径）+ 完整清单外发用例（≥3 站点断言全量输出）；判别力证明（no-op → 红 exit 101 → 恢复字节级一致）。
5. **不改**：fail-closed 门触发条件与拒绝行为、zero-fill honest-holes 语义、`.text`-stable 判定、C-7 风暴检测。不新增依赖、不改 `Cargo.toml`/`Cargo.lock`。

### 第二段（实弹，1 格——第一段判别力未过或回归源未定位即 STOP，不烧格）

命令 = R5 命令 + **按第一段结论补齐 flag**（预期含 `--oep=captured --data-sections`，以第一段证据为准）+ `MIDA_SCYLLA_HIDE_INI` staging 照旧。

**强门（沿用 R5 四件套）**：CONFIG_SOURCE 双行（ini + staged sha256）+ `staging verification passed` + `scylla_hide.log` 无 NtContinue/KiUser hook 行且 15 个 =1 键在列 + P-8 先入 vault。

**终态判定（都合法，如实上报）**：
- **B1'**：门通过 + `[GOOD] Candidate written` + P-4 当场存活探针 exit 0 + `iat_evidence_complete=true` → **XX-11 端点恢复**。对照 XX-11 全套指标记录：产物 sha256/大小、imports 数（186？）、结构门 12/12、load_no_crash ×10、S4 可观测标记。
- **B2**：门通过 + 产物写出 + P-4 失败 → 如实记录（对照 XX-10 的 wininet/OEP 现象——若复现说明 OEP 路径也有回归）。
- **A'**：门仍触发 → 必记 unresolved 总数（对照 192 与 186/201）、全量站点清单、逐槽诊断。1 次有效尝试即可记录；确认确定性可跑第 2 次（两次记 1 格），之后立即停。
- **C**：风暴（记 exc 偏移是否 +0x160bd8）／**D**：新形态 → 照实。

**停止规则**：有效尝试连续 2 次即停；A' 未改善不许第 3 次；不许为凑 B 反复重跑。

## 授权文件清单（超出即打回）

| 文件 | 允许的改动 |
|---|---|
| `crates/pe/src/dumper/iat_partial_accept.rs` | 回溯/back-fill 路径恢复与扩展 |
| `crates/pe/src/dumper/iat_gap_retarget.rs` | startup-path 扫描的完整站点清单外发（判定逻辑不动） |
| `crates/pe/src/dumper/dump_process.rs` | 门诊断信息外发（门语义零改动） |
| `crates/pe/src/dumper/import_rebuild.rs` | 重建发射适配 |
| `crates/pe/src/iat_completeness.rs` | 完整度记账 |
| `crates/packers/themida/src/trace_imports/mod.rs`、`slot.rs` | shell 侧槽回溯恢复 |
| `crates/cli/src/unpacker/iat_evidence.rs` | 证据记录（对照 XX-11 sidecar 结构） |
| 上述文件的测试模块 | 新增用例 |

其余一律不动（含 `data_reinit.rs`、`av_oep_handler.rs`、`av_handler.rs`、`mod.rs` 的 text-poll/C-7 段、`_clippy_baseline`、`ci.yml`）。**回归定位是只读工作；若修复需触碰清单外文件（如 OEP/oep 模块或 `data_reinit.rs`）→ STOP 请示，不许自行判断。**

## 第一段验收标准（离线，全部要真退出码）

1. `git diff --stat` 只含授权文件；无 `#[ignore]`/`.skip`/既有断言被放宽。
2. `cargo test -p mida-pe --lib --offline` → 真退出码 0，**1049 不许掉**（新增用例 ≥4）。
3. `cargo test -p mida-packers-themida --offline` → 真退出码 0（新用例覆盖回溯/恢复语义）。
4. `cargo test -p mida-cli --lib --offline` → 真退出码 0，**580 不许掉**。
5. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 真退出码 0；`cargo fmt --all -- --check` → 真退出码 0。
6. **判别力证明**：核心修复改成可编译 no-op（如回溯恒返回"不可解析"或清单外发截断回 16 个），新增用例必须变红；贴原始失败输出 + 用例名 + 非 0 真退出码；恢复后 `git diff --stat` 与探针前一致。**编译失败不算红。**
7. **回归定位报告**：flag 开关链 + `git diff 18e0349..be28951` 审读结论 + 回归源指认（[已验证]/[推断] 分级）；此项是第二段的通行证。
8. **零实弹自证（第一段）**：未启动 debuggee、未注入、未跑 `/unpack`。

## 第二段前置（不满足就 STOP）

1. **全新 release 构建**（禁复用旧 exe），五条字符串各须命中：`zero-filled IAT region` / `TASK-009 fail-closed` / `guardless constant-AV storm abort` / `C-7: guardless constant-AV storm` / `SCYLLAHIDE_HOOK_CONFIG_SOURCE`。贴 sha256 与体积。
2. **样品身份**（P-6）：vault 对象 `D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`，期望 sha256 同名。不匹配 → STOP。
3. **会话基线**：BootTime、debuggee image_base、ntdll/kernel32/kernelbase 基址，每次尝试记 image_base。BootTime 与签发时刻不同不构成 STOP（D-022 新规），照实记录。

## 红线（违反即整单作废）

- `NO_BYPASS=1` 全程；网络 `deny_all`；样品不外发；**禁止伪造证据**。
- 不写 `C:\Windows`；git 只读（不 commit/push/stash、不改 config、不改 `lab/cases/v2/*.json`）；改 `crates/` 仅限授权清单内文件。
- 不新增依赖、不改 `Cargo.toml`/`Cargo.lock`；不许改既有测试断言迁就自己；不许 `#[ignore]`/`.skip`。
- **不许把 fail-closed 门改松制造"通过"**；**不许动 XX-10/11 的 vault 证据（只读）**。
- 临时文件用完逐个按名删除；结论按 `[已验证]`/`[推断]`/`[存疑]` 标注；只贴原始输出；报告第一节回抄授权令牌。

## 收尾（强制，无论终态）

1. staging/临时物全清，贴清理证明（`ls target/release/*.ini` 空、`%TEMP%\mida-scyllahide-*` 无）；
2. 本次 `scylla_hide.log` 先入 vault 再做新注入（P-8）；
3. 日志删除前先算好计数（`grep -c` 原始命令贴报告）→ 有界摘要（头 200+尾 200）+ 本体（<50MB）入 vault `D:/MidaVault/lab/evidence/xx21b_t014/`。

## 交付物

- `runs/<日期>-TASK-014.md`：授权令牌回抄、**回归定位报告（第 7 条）**、第一段验收原始输出（含判别力）、第二段前置、有效尝试判定证据（强门四件套）、终态判定（B1'/B2/A'/C/D 之一）、与 XX-11 端点的逐项对照表、停止规则遵守、收尾清理证明、「我没做的事 / 我不确定的事」。
- 工作区留改动给总指挥，**不提交**。
