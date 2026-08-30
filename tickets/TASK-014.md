# TASK-014 — IAT 启动路径重建：192 个启动路径站点可解析 + 一格实弹冲路径 B

⛔ **未授权硬停：本单含①`crates/` 代码改动 与②一格实弹。未获老板批准前不许执行任何步骤——「继续」/「go on」不构成授权（D-015）。批准后总指挥会把本行改写为授权令牌，你必须在报告第一节原文回抄该行。**

- **优先级**：P1（TASK-006R5 实弹指认的最前沿；路径 B 的硬前置）
- **状态**：📋 待授权（等老板批：`crates/` 改动授权 + 一格实弹 7/4 → 8/4）
- **岗位**：developer（第一段离线改代码，第二段实弹验证）
- **账本**：XC-XXI-B **7/4 → 8/4**（需老板明确再扩一格）

## 背景：TASK-006R5 用一格实弹指认的现场 [已验证]

- 2026-08-30 TASK-006R5 终态**路径 A**：受控 ini 经 staging 生效后 **0 次 AV**（对照此前 14/14 次 1024 风暴环）、text-poll 首次收敛到 dump，然后 `TASK-009 fail-closed` 触发：**192 个启动路径 call/jmp 指向 unresolved IAT 槽 → 拒绝写产物**，`[GOOD] Candidate written`=0。有效 2/2 次逐位一致（确定性）。vault：`D:/MidaVault/lab/evidence/xx21b_006r5/`（attempt2/3.log）。
- **honest holes 行**：`iat_rva=0x1136e0 span=1608 zeroed=1608` —— **整个 201 槽 IAT 区全零，XX-10-A 的槽回溯在本样品上 0 槽覆盖**。这不是"差一点"，是回溯对该样品的 shell 结构完全没咬合。
- **完整站点清单不在日志里**：FATAL 行只外发 16 个样本站点（13 个唯一目标槽：`0x113bf8`×3、`0x113710`×2、`0x1138d0`/`0x113cb8`/`0x113cc0`/`0x113bd8`/`0x113c00`/`0x113bd0`/`0x113be8`/`0x113c28`/`0x1137b0`/`0x113798`/`0x113700` 各 1）。修回溯之前必须先能看到全部 192 个。
- **运行时槽值只在 dump 会话内存里**，run 结束即消失——所以"每个槽的原始值 + 模块归属尝试 + 回溯路径"诊断必须**进第一段代码**，靠第二段实弹采回，离线无法补采。

## 任务目标

### 第一段（离线，改代码）

1. **完整清单外发（诊断增强，门判定语义零改动）**：fail-closed 门触发时把**全部** N 个站点（site rva → slot rva）完整写入日志，不再截断为 16 个样本；同时外发 honest-holes 的逐槽清单（201 槽全列，含每个槽的运行时原始值、模块归属判定结果、回溯尝试路径）。
2. **诊断先行**：基于外发数据回答"为什么 XX-10-A 在本样品 0 覆盖"——是回溯深度不够、是 shell 虚拟 API 表形态未识别、还是槽值根本不指向任何已加载模块导出。诊断结论写进报告（`[已验证]`/`[推断]` 分开标）。
3. **修复**：扩展槽回溯 / back-fill 使启动路径站点对应槽可解析。方向不限（回溯深度、静态对照受保护样品结构、shell 内部 stub 识别等），但**目标级差目标 = 192 → 0**；若只能部分解析，如实报数——**不许放宽门来"通过"**。
4. **单元测试**：合成 thunk 链用例（直指导出 / 一级间接 / shell 内部 stub / 不可解析四型），覆盖解析成功与 fail-closed 两路；**完整清单外发**用例（构造 ≥3 站点场景，断言日志含全部站点而非截断样本）。
5. **不改**：fail-closed 门触发条件与拒绝行为、zero-fill honest-holes 语义、`.text`-stable 判定、C-7 风暴检测、TASK-009 门的其余部分。不新增依赖、不改 `Cargo.toml`/`Cargo.lock`。

### 第二段（实弹，1 格——第一段判别力未过或离线证据显示零改善即 STOP，不烧格）

用第一段代码重跑重脱壳，命令与 R5 完全一致（R5 的 staging 代码已在引擎里，`MIDA_SCYLLA_HIDE_INI` 指向 vault 受控 ini 即自动生效）。

**强门（沿用 R5，缺一即不算有效尝试）**：`SCYLLAHIDE_HOOK_CONFIG_SOURCE` 双行（ini + staged sha256 校验）+ `staging verification passed` + 本次 `scylla_hide.log` 不出现 `Hooking NtContinue`/`Hooking KiUserExceptionDispatcher` 且 15 个 =1 键 hook 行在列作对照 + P-8：`scylla_hide.log` 先复制进 vault 再做任何新注入。

**终态判定（都合法，如实上报）**：
- **B1**：门通过（fail-closed 0 命中）+ `[GOOD] Candidate written` + **P-4 当场存活探针 exit 0** → 路径 B 达成。记产物 sha256/大小/探针原始输出。
- **B2**：门通过 + 产物写出 + P-4 探针非 0/259 → 产物不可行。如实记录 + 对照 honest-holes 逐槽清单（哪些槽仍零）→ 这是下一轮的有价值数据，不算失败也不许报成成功。
- **A'**：门仍触发 → 必记 unresolved 总数（对照 192：降了多少）、全量站点清单、逐槽诊断。1 次有效尝试即可记录；如需确认确定性可跑第 2 次，**两次记 1 格**，之后立即停。
- **C**：风暴（记 exc 相对 ntdll 偏移，还在 +0x160bd8 吗）／**D**：新形态（text-poll 收敛但死在别处）→ 照实。

**停止规则**：有效尝试连续 2 次即停；A' 未改善不许第 3 次；不许为凑 B 反复重跑。

## 授权文件清单（超出即打回）

| 文件 | 允许的改动 |
|---|---|
| `crates/pe/src/dumper/iat_partial_accept.rs` | 槽回溯 / back-fill 主体扩展 |
| `crates/pe/src/dumper/iat_gap_retarget.rs` | startup-path 扫描的**完整站点清单外发**（判定逻辑不动） |
| `crates/pe/src/dumper/dump_process.rs` | 门诊断信息外发（**门语义零改动**） |
| `crates/pe/src/dumper/import_rebuild.rs` | 重建发射适配 |
| `crates/pe/src/iat_completeness.rs` | 完整度记账 |
| `crates/packers/themida/src/trace_imports/mod.rs`、`slot.rs` | shell 侧槽回溯扩展 |
| `crates/cli/src/unpacker/iat_evidence.rs` | 证据记录 |
| 上述文件的测试模块 | 新增用例 |

其余一律不动（含 `data_reinit.rs`、`av_oep_handler.rs`、`av_handler.rs`、`mod.rs` 的 text-poll/C-7 段、`_clippy_baseline`、`ci.yml`）。

## 第一段验收标准（离线，全部要真退出码）

1. `git diff --stat` 只含授权文件；无 `#[ignore]`/`.skip`/既有断言被放宽。
2. `cargo test -p mida-pe --lib --offline` → 真退出码 0，**1049 不许掉**（新增用例 ≥4：thunk 四型 + 完整清单外发）。
3. `cargo test -p mida-packers-themida --offline` → 真退出码 0（新用例覆盖回溯语义）。
4. `cargo test -p mida-cli --lib --offline` → 真退出码 0，**580 不许掉**。
5. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 真退出码 0；`cargo fmt --all -- --check` → 真退出码 0。
6. **判别力证明**：把核心修复改成可编译 no-op（如回溯恒返回"不可解析"或清单外发截断回 16 个），新增用例必须变红；贴原始失败输出 + 用例名 + **非 0 真退出码**；恢复后 `git diff --stat` 与探针前一致。**编译失败不算红。**
7. **完整清单外发的离线证明**：单测断言日志含全部站点（非 16 截断）+ 逐槽诊断字段齐全。
8. **零实弹自证（第一段）**：未启动 debuggee、未注入、未跑 `/unpack`。

## 第二段前置（不满足就 STOP）

1. **全新 release 构建**（禁复用旧 exe），五条字符串各须命中：`zero-filled IAT region` / `TASK-009 fail-closed` / `guardless constant-AV storm abort` / `C-7: guardless constant-AV storm` / `SCYLLAHIDE_HOOK_CONFIG_SOURCE`。贴 sha256 与体积。
2. **样品身份**（P-6）：vault 对象 `D:/MidaVault/objects/sha256/78/7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`，期望 sha256 同名。不匹配 = `SampleIdentityMismatch` → STOP。
3. **会话基线**：BootTime、debuggee image_base、ntdll/kernel32/kernelbase 基址，每次尝试记 image_base。**BootTime 规则（D-022 新规）：与授权令牌签发时刻不同不构成 STOP 事由，照实记录即可。**

## 红线（违反即整单作废）

- `NO_BYPASS=1` 全程；网络 `deny_all`；样品不外发；**禁止伪造证据**。
- 不写 `C:\Windows`；git 只读（不 commit/push/stash、不改 config、不改 `lab/cases/v2/*.json`）；改 `crates/` 仅限授权清单内文件。
- 不新增依赖、不改 `Cargo.toml`/`Cargo.lock`；不许改既有测试断言迁就自己；不许 `#[ignore]`/`.skip`。
- **不许把 fail-closed 门改松来制造"通过"**——修的是让槽可解析，不是让门闭嘴。
- 临时文件用完逐个按名删除；结论按 `[已验证]`/`[推断]`/`[存疑]` 标注；只贴原始输出；报告第一节回抄授权令牌。

## 收尾（强制，无论终态）

1. staging/临时物全清，贴清理证明（`ls target/release/*.ini` 空、`%TEMP%\mida-scyllahide-*` 无）；
2. 本次 `scylla_hide.log` 先入 vault 再做新注入（P-8）；
3. 日志删除前先算好计数（`grep -c` 原始命令贴报告）→ 有界摘要（头 200+尾 200）+ 本体（<50MB）入 vault `D:/MidaVault/lab/evidence/xx21b_t014/`。

## 交付物

- `runs/<日期>-TASK-014.md`：授权令牌回抄、第一段八条验收原始输出（含判别力）、诊断结论（为什么 XX-10-A 0 覆盖）、第二段前置、有效尝试判定证据（强门四件套）、终态判定（B1/B2/A'/C/D 之一）、停止规则遵守、收尾清理证明、「我没做的事 / 我不确定的事」。
- 工作区留改动给总指挥，**不提交**。
