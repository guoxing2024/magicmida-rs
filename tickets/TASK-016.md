# TASK-016 — xiongxiong 线阶段收尾：B1' 能力固化 + 硬编码审计清除 + 复现 runbook（纯离线，零实弹）

✅ **已授权 —— 授权令牌（必须在报告第一节原文回抄）**：
> `老板 · 2026-08-30 · 原话"现在你派个单做个阶段收尾，别以后用不能用了。还有要注意通用性，不要有硬编码"（= 批准阶段收尾工单：授权 crates/ 改动仅限本单授权文件清单，行为中性硬编码清除 + preflight 预检；纯离线零实弹，账本不变）· 前置由总指挥亲验：起点 HEAD = 3de2ade（TASK-015 已验收入栈；worker 须核验 3de2ade 为 HEAD 祖先、且 3de2ade..HEAD 的 diff 仅 docs/tickets 文件）· vault 受控 ini sha256 c88e94c3… 与样品对象 sha256 78009803… 已当场复核在位（preflight 检查的目标物）`

- **优先级**：P1（B1' 已达成且老板亲验合格；本单防"以后用不了"）
- **状态**：✅ 已授权（老板 2026-08-30；记 D-030）
- **岗位**：developer（纯离线：审计 + 清除 + 预检 + 文档；**零实弹**）
- **账本**：XC-XXI-B **9/4（不变）**——本单零实弹，不耗格

## 背景：为什么需要这个收尾 [已验证]

B1' 已达成（D-029，老板亲验产物合格），但当前能力有三个"以后用不了"的风险面：

1. **配置依赖在 env 里**：`MIDA_SCYLLA_HIDE_INI` 指向 vault 的 `scylla_hide_no_excdispatch.ini`（sha `c88e94c3…`）。不设它 → 全默认 hook → 撞环；vault 移动/文件丢失 → 静默失效。这一切**没有任何启动前检查**。
2. **隐性知识没进文档**：复现 B1' 需要的命令、flag、每步日志判据（`clearing stale pending`=1、`OK IAT[`=75、imports=186、结构门 12/12…）散落在 runs 报告里，没有一个"照着做就能复现"的 runbook。
3. **硬编码风险**：T014/T015 的快速修复可能把本样品 specifics（RVA `0x1136e0`/`0x1137d0`/`0x1681d1`、201/74/192/16/12s 等魔法数、路径与线程假设）写进了控制流——换一个样品/环境就断。`docs/HARDCODING_AUDIT_20260829.md` 有先例，本单做 T016 增补。

## 任务目标

### 1. 硬编码审计与清除（先审后改，行为中性铁律）

- **审计范围**：B1' 路径授权文件（见清单）逐行审 + **只读审**以下文件（报告发现、不许改）：`cli/src/unpacker/mod.rs`（text-poll/C-7 段：XX-11 双区域 +0x10、prologue 特征字节）、`args.rs`、`oep/`、`dumper/data_reinit.rs`、`windows_debugger.rs`（12s grace window、DR apply 容差）、`av_oep_handler.rs`、`av_handler.rs`。以上文件若发现样品级硬编码，**写进审计报告**，改动需老板另行授权。
- **判据**：任何把"本样品/本 boot/本路径"写死进**控制流**的常量——magic RVA、节尺寸、绝对地址、文件路径、线程 id 假设、魔法数（192/201/74/16/12s/100..5000 等）——三类处置：
  ① **派生化**（首选）：从 PE 结构/运行时状态/配置算出来；
  ② **命名常量**：移到具名 const + 注释说明来源与适用边界；
  ③ **降级为诊断**：只进日志/报告，不参与控制流。
- **行为中性铁律**：清除只能让代码更通用，**不得改变 B1' 行为**——证据 = 全仓测试套件全绿且既有计数不减。若发现必须行为性改动才能修的硬编码 → **STOP 请示**（那属于下一战役，需要实弹再验证）。

### 2. Preflight 能力预检（"以后用不了"要响亮地失败，不要静默撞环）

`crates/acceptance/src/preflight.rs` 新增 ScyllaHide-readiness 检查（+单测）：
- ini 存在、可解析、且 `KiUserExceptionDispatcherHook=0` / `NtContinueHook=0` / `NtCloseHook=0` 三键在列（缺任一 → 明确报"受控 ini 不完整，将撞 AV 风暴环"）；
- InjectorCLIx64.exe / HookLibraryx64.dll 在位；
- 检查结果带明确错误信息（fail-loud）。
**不许**把 ini 的 sha256 写死成常量（ini 内容可能演进）——只查结构，不查内容指纹。

### 3. 复现 runbook

`docs/RUNBOOK_REV2_B1.md`：照着做就能复现 B1' 的完整配方——
- 环境变量（`MIDA_SCYLLA_HIDE_INI` 等）+ 命令全文（含 `--oep=captured --data-sections`）；
- 每步预期判据（日志 grep 命令 + 预期数字：CONFIG_SOURCE 2 行、staging verification passed、clearing stale pending=1、OK IAT[=75、[GOOD]=1、imports=186、结构门 12/12、load 10/10）；
- 终态判定表（B1'/B2/A'/C/D）+ "什么会弄坏它"清单（无 ini/ini 键缺失/DR apply 失败现在有宽限窗处理…）；
- vault 证据指针（`xx21b_t015/`、`xx11_attempt_20260828-112236/`）+ 受控 ini sha `c88e94c3…`。
- **runbook 一致性验证**：worker 须实际执行 runbook 的离线步骤（构建 + preflight + 判据说明核对），贴原始输出证明文档与实际一致；**不执行 `/unpack`**。

### 4. vault 索引

`D:/MidaVault/lab/evidence/xx21b_t015/INDEX.md`：全文件清单 + sha256 + 用途一句话，并在 runbook 链接。vault 是 git 外目录，worker 可写。

### 5. 全量回归快照

`cargo test --workspace --offline` → **真退出码 0**（全仓绿 = 收尾快照），各套件计数入报告（基线：pe 1054 / themida 176 / cli 580 / acceptance lib 256，只增不减）。

## 授权文件清单（超出即打回）

| 文件 | 允许的改动 |
|---|---|
| `crates/packers/themida/src/antiantidebug/scyllahide.rs` | 硬编码派生化/命名常量（行为中性） |
| `crates/packers/themida/src/trace_imports/mod.rs`、`slot.rs` | 同上 |
| `crates/pe/src/dumper/dump_process.rs`、`iat_partial_accept.rs`、`iat_gap_retarget.rs`、`import_rebuild.rs`、`iat_completeness.rs` | 同上 |
| `crates/acceptance/src/preflight.rs` | 新增 readiness 检查 + 测试 |
| 上述文件的测试模块 | 新增用例 |

**报告-only（不许改）**：`cli/src/unpacker/mod.rs`（text-poll/C-7 段）、`args.rs`、`oep/`、`dumper/data_reinit.rs`、`windows_debugger.rs`、`av_oep_handler.rs`、`av_handler.rs`、`Cargo.toml`/`Cargo.lock`、`ci.yml`、`lab/cases/v2/*.json`。修复需触碰清单外文件 → **STOP 请示**。

## 验收标准（离线，全部要真退出码）

1. `git diff --stat` 只含授权文件；无 `#[ignore]`/`.skip`/既有断言被放宽。
2. `cargo test --workspace --offline` → 真退出码 0，各套件计数 ≥ 基线（pe 1054 / themida 176 / cli 580 / acceptance lib 256）。
3. **硬编码审计报告**：逐发现分类（派生化/命名常量/降级诊断/报告-only）+ 修复 diff 对照 + 只读文件的发现清单。新增专属命名常量的，列出常量名与适用边界。
4. **preflight 判别力**：临时移除任一新增检查 → 新用例变红（贴原始失败输出 + 非 0 真退出码）→ 字节级恢复。**编译失败不算红。**
5. **runbook 一致性**：离线步骤（构建 + preflight）实际执行输出 + 与文档判据逐条核对。
6. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 0；`cargo fmt --all -- --check` → 0。
7. **零实弹自证**：全程未启动 debuggee、未注入、未跑 `/unpack`；`tasklist` 无相关进程。
8. `INDEX.md` 存在且 sha256 与实物一致（抽 3 个文件复算）。

## 红线（违反即整单作废）

- **零实弹**：不启动 debuggee、不注入、不跑 `/unpack`、不写 `C:\Windows`。
- git 只读（不 commit/push/stash、不改 config）；不新增依赖、不改 `Cargo.toml`/`Cargo.lock`。
- **行为中性**：清除不得改变 B1' 行为；测试计数只增不减；不许改既有断言迁就自己；不许 `#[ignore]`/`.skip`。
- 不许动 xx 战役与 xx21b 系列 vault 证据（只读；INDEX.md 与新建文档除外）。
- 临时文件逐个按名删除；结论按 `[已验证]`/`[推断]`/`[存疑]` 标注；只贴原始输出；报告第一节回抄授权令牌。

## 交付物

- `runs/<日期>-TASK-016.md`：授权令牌回抄、审计报告（含只读文件发现）、preflight 判别力证明、runbook 一致性输出、全仓回归计数、收尾证明、「我没做的事 / 我不确定的事」。
- `docs/RUNBOOK_REV2_B1.md` + `docs/HARDCODING_AUDIT_20260829.md` 增补段（或独立 `HARDCODING_AUDIT_T016.md`）+ vault `INDEX.md`。
- 工作区留改动给总指挥，**不提交**。
