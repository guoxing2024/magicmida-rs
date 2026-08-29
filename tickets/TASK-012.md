# TASK-012 — C-7 修复加固：风暴阈值裕量 + 常量拼写 + host 腿补测试

- **优先级**：P1（**下一格实弹之前必做**）
- **状态**：📋 待领取
- **岗位**：developer（**纯离线**，禁实弹）
- **授权**：总指挥 2026-08-29 开单（TASK-011 验收时发现的三个遗留项）
- **账本**：**零实弹**（不启动 debuggee、不跑 `/unpack`、不注入）

## 项目背景

1. TASK-011 已修 C-7（text-poll 阶段无 AV 风暴终止）：guardless 路径按恒同元组 `(exception_addr, target_address, exc_type, thread_id)` 计数，元组变化即清零，达阈值 → `storm_abort` → host 转 `Err` fail-closed。离线验收全过（详见 `runs/20260829-TASK-011.md` 与 `docs/KNOWN_ISSUES.md` C-7）。
2. 总指挥验收时**亲验坐实了实现的正确性**，但发现三个遗留项，**其中第 ① 项会直接威胁下一格实弹**：

   **① 阈值裕量偏薄（主要问题）**
   `GARDLESS_AV_STORM_TUPLE_THRESHOLD = 32` 的选值理由是"与既有 `unrelated_av_storm_threshold`（默认 32）同值"。但两者**后果不同**：既有那个走的是"风暴逃逸 → 回退 Break（软着陆，仍可能出产物）"，而 C-7 这条是**硬 fail-closed（直接 Err，整单中止、无产物）**。后果更重的判据不该沿用后果更轻的阈值。
   实测分布是**双峰**的：健康运行（TASK-006 attempt3 / try1）text-poll 阶段 **0 次 AV**；风暴运行 **20 万 – 322 万次**恒同元组。也就是说 32 这个点距离风暴侧有 4–5 个数量级裕量，距离健康侧只有 32 个事件。而 Themida 大量使用**异常式混淆**，紧循环里出现 >32 次合法恒同 AV 在结构上完全可能——一旦误杀，**白烧一格实弹**（实弹格是本项目除老板时间外最稀缺的资源）。
   把阈值抬到 4 位数，检测能力实质不变（真风暴超阈值仍有 2–3 个数量级裕量），误杀风险却降两个数量级。

   **② 公开常量名拼写错误**
   `GARDLESS_AV_STORM_TUPLE_THRESHOLD` 应为 `GUARDLESS_...`（漏了 U）。这是 `pub const`，已被集成测试 import，属对外名字。

   **③ host 侧那条腿没有自动化测试**
   `av_handler.rs` 里 `storm_abort → Err` 的映射目前**只有代码阅读证据**（TASK-011 的授权清单不含 cli crate 的测试位置，worker 按红线没写）。这是 fail-closed 语义真正生效的地方——引擎侧判对了但 host 侧忘了转 `Err`，缺陷就会静默复活。

## 你要改的文件（授权清单，超出即打回）

| 文件 | 允许的改动 |
|---|---|
| `crates/packers/themida/src/runtime/av_oep_handler.rs` | 改阈值常量的值与名字（含 doc 注释里的选值理由）；如需为 ③ 抽一个纯函数可在此文件加 |
| `crates/packers/themida/tests/av_oep_handler.rs` | 跟随常量改名；**不许放宽任何既有断言** |
| `crates/cli/src/unpacker/av_handler.rs` | 跟随常量改名（若引用）；为 ③ 抽出可测的纯映射函数 + 加 `#[cfg(test)] mod tests`（同 crate 内已有先例：`iat_materialize.rs:98`、`dump.rs:362`） |

其余文件一律不许动（含 `mod.rs`、`dump_process.rs`、TASK-009 的三个文件、`_clippy_baseline`、`ci.yml`）。**特别提醒**：`mod.rs:1214-1218` 的 `.text`-stable 判定继续**零改动**。

## 任务目标（三条可观察的变化）

1. 阈值常量改名为 `GUARDLESS_AV_STORM_TUPLE_THRESHOLD`，取值抬到 **1024**（或你有更好理由的 4 位数值），doc 注释重写选值理由，**必须写清"本判据后果是硬 fail-closed，故不沿用 `unrelated_av_storm_threshold` 的 32"** 以及双峰实测数据（健康 0 / 风暴 20 万–322 万）。
2. `av_handler.rs` 里 `storm_abort → Err` 的映射有一个**直接测试**：给定 `storm_abort = Some((tuple_text, count))` 的 outcome → 得到 `Err` 且错误串含元组与计数；给定 `storm_abort = None` 的 `Break` → 仍得到 `Ok(AvAction::Break)`（不许误伤既有 Break 语义）。
3. 既有 4 个 C-7 用例（两个风暴几何 + 防误杀 + 守卫回归）继续全绿，且**不许**为了迁就新阈值把循环次数写死成魔数——用常量表达（现有用例已经这么写了，保持）。

## 验收标准（缺一条即打回）

1. **改动清单核对**：`git diff --stat` 只含上表 3 个文件；`git diff` 里**没有**既有断言被放宽、没有 `#[ignore]`/`#[cfg(ignore)]`/`.skip`、没有注释掉的用例。
2. `cargo test -p mida-packers-themida --offline` → **真 cargo 退出码 0**（注意：`cargo ... | findstr` 之后的 `%ERRORLEVEL%` 是 findstr 的码，**不是 cargo 的**；必须先重定向到文件再取码，否则报告里的 EXIT=0 无效）；集成测试仍 **16 个**用例全绿。
3. `cargo test -p mida-cli --lib --offline` → 真退出码 0，且输出里能看到 ② 新增的 host 腿用例名。
4. `cargo test -p mida-pe --lib --offline` → 真退出码 0，**1049 不许掉**。
5. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 真退出码 0。
6. `cargo fmt --all -- --check` → 真退出码 0。
7. **判别力证明（host 腿用例）**：把 `av_handler.rs` 的 `storm_abort → Err` 映射临时改成**可编译的 no-op**（例如直接返回 `Ok(AvAction::Break)`），新增用例必须变红；贴原始失败输出 + 失败断言原文 + 用例名；然后恢复，贴 `git diff --stat` 证明恢复干净。**编译失败不算红**（编译错误 ≠ 判别力）。
8. **写清「我没做的事 / 我不确定的事」**，特别是：新阈值仍未经实弹校准。

## 红线（违反即整单作废）

- **零实弹**：不启动任何 debuggee、不跑 `/unpack`、不注入、不碰样品。
- **git 只读**：不 `commit`、不 `push`、不 `stash`、不改 git config。改完把工作区留给总指挥。
- 不新增依赖、不改 `Cargo.toml`/`Cargo.lock`。
- 不许改既有测试断言来让自己过；不许 `#[ignore]`/`.skip`/注释用例。
- 临时文件（`.cmd` 脚本、备份）用完**逐个按名删除**，不许 `rm -rf` 目录。
- 报告里所有结论按 `[已验证]` / `[推断]` / `[存疑]` 标注；**只贴原始输出，不贴"应该没问题"**。

## 交付物

- `runs/20260829-TASK-012.md`：诊断核对 + 改动说明 + 逐条验收原始输出（含真退出码）+ 判别力证明 + 「我不确定的事」。
- 工作区留改动，不提交。
