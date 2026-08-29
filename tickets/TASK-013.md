# TASK-013 — 把 ScyllaHide 的 hook 选择变成可控、可记录的配置（**纯离线，零实弹**）

- **优先级**：P1（缺陷 A 实弹验证的硬前置）
- **状态**：✅ 已完成并验收（2026-08-30；9 条验收总指挥亲验全过，归档 [runs/20260830-TASK-013.md](../runs/20260830-TASK-013.md)）
- **岗位**：developer
- **账本**：**零实弹**（不启动 debuggee、不跑 `/unpack`、不注入）

## 背景：为什么这一单是解锁缺陷 A 的关键

缺陷 A（C-4 / TASK-009 的修复）到现在**三次实弹、跨三个 boot、13/13 次全部没验到**，每次都止步在 dump **之前**的 text-poll 阶段：

| 尝试 | boot | 次数 | 终态 |
|---|---|---|---|
| TASK-006R | `2026-08-29 07:58:23` | 9 | AV 环烧到外部超时（3.5GB 日志） |
| TASK-006R2 | 同上 | 2 | C-7 主动 fail-closed 中止（20ms） |
| TASK-006R3 | `2026-08-30 01:28:40`（**已换 boot**） | 2 | C-7 主动 fail-closed 中止（20ms） |

**换 boot 没换掉故障环**，而且现在因果链是实锤的（总指挥亲验）：

- 两个 boot 的 ASLR 布局完全不同（ntdll `0x7ffa952a0000` → `0x7ff857620000`，debuggee image_base `0x7ff799fc0000` → `0x7ff729430000`），但风暴 RIP **恒等于 ScyllaHide 的 NtContinue hook 地址 + 8**：
  - 旧 boot：`scylla_hide.log` 记 `_NtContinue 00007FFA95400BD0`，风暴 exc = `0x7ffa95400bd8`
  - 新 boot：`scylla_hide.log` 记 `_NtContinue 00007FF857780BD0`，风暴 exc = `0x7ff857780bd8`
  - 两者相对 ntdll 的偏移都是 **+0x160bd8**，都落在 hook 覆盖区（hook 点 +8）
- 这已经不是"相关"，是**同一现象在两套完全不同的地址下复现**。所以：**不是 ASLR 运气，是 ScyllaHide 的 NtContinue hook 与壳的异常分发确定性打架。**

**总指挥这一轮读日志发现的新事实（本单的直接抓手）**：

`target/release/` 下**没有 `scylla_hide.ini`**，本次运行的 `scylla_hide.log` 里也**没有任何读取 ini/config 的痕迹**，而日志显示 `Hooking KiUserExceptionDispatcher` 和 `Hooking NtContinue` **都被应用了**。对照 vault 里的参考 ini（`D:/MidaVault/quarantine/20260722/workspace/magicmida-rs/scylla_hide.ini`）——那份 ini 里 `KiUserExceptionDispatcherHook=0`。

→ **结论**：我们现在是在**无配置**状态下注入 ScyllaHide，它默认把**所有** hook 都装上，包括那个跟壳打架的异常分发链（`KiUserExceptionDispatcher` + `NtContinue`）。而引擎里其实已经留了配置口子：`crates/cli/src/unpacker/antidebug_controller.rs:507` 的 `OracleMode.ini_path: Option<PathBuf>`，但它挂着 `#[allow(dead_code)]` —— **口子留了没接线**。

## 任务目标（三条可观察的变化）

1. **把 `ini_path` 接上线**：注入 ScyllaHide 时，如果配置里给了 ini，就让它真正被 ScyllaHide 读到（ScyllaHide 读的是**与 injector/HookLibrary 同目录**的 `scylla_hide.ini`，所以"接线"的含义是：把指定的 ini 落到注入器工作目录，或按 ScyllaHide 实际的查找规则放置——**先把查找规则查清楚再写代码**，别猜）。
2. **产出一份受控 ini**（放 vault，不进 Git），内容 = 参考 ini 为基线，但**显式关掉异常分发那两项**：`KiUserExceptionDispatcherHook=0`，以及 ScyllaHide 里实际控制 NtContinue hook 的那一项（**参考 ini 里没有 `NtContinueHook` 这个键**，所以你要先从 ScyllaHide 的实现/文档确认 NtContinue 是被哪个开关带着装的——查清楚，查不到就如实写"未找到开关"并上报，**不许瞎猜一个键名写进去**）。
3. **hook 选择要可记录**：注入完成后，把"这次实际生效的 hook 配置来源（ini 路径或"无 ini，全默认"）"写进日志与证据 sidecar，让以后每份实弹报告都能一眼看出当次是哪种 hook 配置——现在这一点完全看不出来，是这次要靠读 ScyllaHide 自己的日志反推的根本原因。

## 你要改的文件（授权清单，超出即打回）

| 文件 | 允许的改动 |
|---|---|
| `crates/cli/src/unpacker/antidebug_controller.rs` | 去掉 `ini_path` 的 `#[allow(dead_code)]`，接上线；加"配置来源"记录 |
| `crates/cli/src/unpacker/helpers.rs` **或** `crates/cli/src/unpacker/session.rs` | **二选一**（挑改动更小的那个），用于 ini 落位/路径解析；在报告里说明为什么选它 |
| `crates/cli/src/unpacker/mod.rs` | 仅限把配置来源传下去 + 记日志；**不许**改 `.text`-stable 判定（`mod.rs:1214-1218`）、不许改 C-7 风暴检测 |

其余一律不动（含 `av_oep_handler.rs`、`av_handler.rs`、`dump_process.rs`、TASK-009/011/012 的文件、`_clippy_baseline`、`ci.yml`）。**ini 本身不进 Git**（ARTIFACT_POLICY）——放 `D:/MidaVault/lab/config/scylla_hide_no_excdispatch.ini`，路径写进报告。

## 验收标准（缺一条即打回）

1. **先诊断后动手**：贴出 ScyllaHide 的 ini 查找规则证据（来源：ScyllaHide 源码/文档/实测 strings，**注明来源**）+ NtContinue hook 由哪个开关控制的证据。若查不到 → **STOP 上报**，不许猜一个键名。
2. `git diff --stat` 只含上表授权文件；无 `#[ignore]`/`.skip`、无既有断言被放宽。
3. `cargo test -p mida-cli --lib --offline` → **真退出码 0**（P-5：`cargo ... | findstr` 之后的 `%ERRORLEVEL%` 是 findstr 的码，**必须先重定向到文件再取码**），且新增用例覆盖：给了 ini → 配置来源被记录为该路径；没给 ini → 记录为"无 ini（ScyllaHide 默认全 hook）"。
4. `cargo test -p mida-pe --lib --offline` → 真退出码 0，**1049 不许掉**。
5. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 真退出码 0。
6. `cargo fmt --all -- --check` → 真退出码 0。
7. **判别力证明**：把"配置来源记录"改成可编译的 no-op（例如恒记为"无 ini"），新增用例必须变红；贴原始失败输出 + 失败断言原文 + 用例名 + **非 0 真退出码**；恢复后贴 `git diff --stat` 证明干净。**编译失败不算红。**
8. **零实弹自证**：明确写出未启动 debuggee、未注入、未跑 `/unpack`。
9. 「我没做的事 / 我不确定的事」——尤其是：**关掉异常分发 hook 之后壳会不会反过来检测到调试器**，这一点本单**验不了**（要实弹），必须如实写成待验风险。

## 红线（违反即整单作废）

- **零实弹**：不启动 debuggee、不注入、不跑 `/unpack`、不碰样品。
- **git 只读**：不 commit / push / stash，不改 git config。
- 不新增依赖、不改 `Cargo.toml` / `Cargo.lock`。
- 不许改既有测试断言来迁就自己；不许 `#[ignore]` / `.skip` / 注释用例。
- ini 不进 Git。
- 临时文件用完**逐个按名删除**。
- 结论按 `[已验证]` / `[推断]` / `[存疑]` 标注；只贴原始输出。

## 交付物

- `runs/<日期>-TASK-013.md`：诊断证据（ini 查找规则 + NtContinue 开关归属）、改动说明、逐条验收原始输出（含真退出码）、判别力证明、ini 的 vault 路径与内容、「我不确定的事」。
- 工作区留改动，**不提交**。

## 这一单之后会发生什么（给你个上下文，不是你的任务）

接完这一单，总指挥会向老板申请下一格实弹（TASK-006R4）：带着"关掉异常分发 hook"的 ini 再跑一次重脱壳，看 text-poll 能不能收敛到 dump 阶段——那才是缺陷 A 的路径 A/B 验证真正有机会到达的时刻。**所以这一单的质量直接决定下一格实弹烧得值不值。**
