# TASK-011 — 修 C-7：text-poll 阶段增加 AV 风暴终止（fail-closed）

- **优先级**：P1
- **状态**：📋 待领取
- **岗位**：developer（**纯离线**，禁实弹）
- **授权**：总指挥 2026-08-29 开单（TASK-010 定性 (c) 的主路线建议）
- **账本**：**零实弹**（离线开发 + 单元测试；不启动 debuggee、不跑 `/unpack`）

## 项目背景

1. TASK-006R 用 1 格实弹重跑重脱壳，9/9 全部失败：debuggee 在 text-poll 阶段陷入恒同 AV 环，`.text` 永不 stable，dump 从未到达，产出 3.5GB 级垃圾日志，最后只能外部超时/杀进程。
2. TASK-010 只读调查定性（`runs/20260829-TASK-010.md`，总指挥亲验坐实）：风暴与 debuggee 基址**无因果**（同基址成败并存），两个时段的风暴甚至**不同型**（04:0x = VM 取指环 exc=target=`0x1108e3761a0`；21:1x = ScyllaHide NtContinue-hook 区故障环 exc=ntdll+0x160bd8/target=0x204）。真正把"偶发环"放大成"确定性 0% 收敛"的是**引擎结构缺口 C-7**。
3. **C-7 缺口（代码级已确证，总指挥逐处复核）**：
   - `crates/packers/themida/src/runtime/av_oep_handler.rs:161-168`：`!state.guard_installed` → 无条件 `AvOepAction::Continue` 早返回；
   - 同文件 `:232`：`unrelated_av_streak` 只在 `guard_installed && NotGuarded` 分支递增 → **guardless 阶段永不计数**，既有 `unrelated_av_storm_threshold` / `unrelated_av_null_storm_threshold` 在此阶段完全失效；
   - `crates/cli/src/unpacker/mod.rs:1139-1141`：`text_poll_start` 每个事件重置 → `:1159-1164` 的 30s idle 超时在连续 AV 流下**结构上永不触发**；
   - `.text`-stable 判定（`mod.rs:1214-1218`）依赖壳完成解密 → 壳卡在环里则永不达成。
4. 后果：任何 constant-AV 环都必然烧到外部超时。这个缺口不修，下一次实弹格还会白烧。

## 你要改的文件（授权清单，超出即打回）

| 文件 | 允许的改动 |
|---|---|
| `crates/packers/themida/src/runtime/av_oep_handler.rs` | guardless 分支加恒同 AV 元组风暴检测 + 新增 `AvOepAction` 变体或复用现有中止语义；`AvOepState`/`AvOepInput` 可加字段 |
| `crates/cli/src/unpacker/av_handler.rs` | 消费新 outcome，把风暴中止转成 `Err`（`:92` 已是 `?` 链） |
| `crates/cli/src/unpacker/mod.rs` | 仅限 text-poll 循环消费中止/传阈值；**不许**改 `.text`-stable 判定语义 |

其余文件一律不许动（含 `dump_process.rs`、TASK-009 的三个文件、`_clippy_baseline`、`ci.yml`、任何测试的既有断言）。

## 任务目标（一句话可观察的变化）

text-poll 阶段遇到恒同 AV 环时，引擎在有界事件数内**主动 fail-closed 中止**（返回错误、不 dump、不打 `[GOOD]`、日志有界），而不是无限吞掉直到外部超时。

## 具体要求

1. **先诊断再动手**：把上面 4 处引用逐一在当前代码上核对（贴 file:line + 关键行），确认缺口描述与代码一致。若发现描述有误或根因在别处，**STOP 上报**，不要照着错的描述改。
2. **风暴判据**（保守、可解释）：对 guardless 阶段的 AV 事件按元组 `(exception_addr, target_address, exc_type, thread_id)` 计数；**元组变化即清零**（只抓"恒同"环，不误伤正常多样 AV 流）。阈值取现有 `unrelated_av_storm_threshold` 同源常量或新增独立常量，**不许硬编码魔数在函数体里**——定义为命名常量并写明选值理由。
3. **中止语义 = fail-closed**：超阈值 → 让 `decide_av_oep` 返回可区分的中止结果 → `av_handler.rs` 转 `Err`（错误消息含元组与计数，便于诊断）→ CLI 循环终止、无产物、无 `[GOOD]`。与 TASK-009 的 fail-closed 同族。
4. **不许改 `.text`-stable 的判定标准**（`mod.rs:1214-1218`）：这单只加"环检测中止"，不放宽解密成功的条件。
5. **离线测试（必须含缺陷捕获）**：用现有 `AvOepQuery` mock 模式（该模块已有测试）新增用例：
   a. **guardless 恒同元组达阈值 → 中止**（复现 21:1x 几何：`exception_addr=0x7ffa95400bd8, target=0x204, exc_type` 与 04:0x 几何：`exc=target=0x1108e3761a0, exc_type=8` 各一条）；
   b. **元组变化 → 不中止**（正常多样 AV 流必须继续，防误杀）；
   c. **guard 已装路径行为不变**（回归保护：既有 `unrelated_av_streak` 语义不受影响）。
6. **判别力证明**：临时把风暴检测回退为 no-op（**可编译**的方式，如提前 `return`）→ 新用例必须**变红**（贴原始输出与失败用例名）→ 恢复 → **变绿**；`cmp`/`git diff --stat` 证明恢复干净。

## 约束与红线

- **零实弹**：不启动任何 debuggee、不跑 `/unpack`、不注入。需要实弹才能推进 → STOP 上报。
- 不得改动授权清单外的任何文件；不得改既有测试断言、不得加 `#[ignore]`/`.skip`、不得注释既有用例。
- 不得提交、不得推送；git 只读。
- 不新增依赖。
- 临时文件逐个按名清理（不许通配符删除）。

## 验收标准（每条附命令与原始输出）

1. 诊断核对：4 处引用在当前代码上的 file:line 与关键行。
2. `cargo test -p mida-packers-themida --lib --offline` → **exit 0**，含新增用例（贴新用例名与 passed 计数，说明基线→新计数）。
3. `cargo test -p mida-pe --lib --offline` → **exit 0**（回归：TASK-009 的 1049 不许掉）。
4. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → **exit 0**。
5. `cargo fmt --all -- --check` → **exit 0**。
6. 判别力证明：回退 → 红（失败用例名 + 断言原文）→ 恢复 → 绿 + `git diff --stat` 只含授权文件。
7. 「我不确定的事」一节：必须明确写出**本单未做实弹验证**（真实风暴下的中止效果留待下一次实弹）。

## 交付格式

`runs/<日期>-TASK-011.md`，逐条对照验收标准，附命令与原始输出，结论标 `[已验证]` / `[推断]` / `[存疑]`。

## 停止规则

- 缺口描述与代码不符 → STOP 上报，不照错的改。
- 需要改授权清单外文件才能实现 → STOP，写成新工单建议。
- 同一验收标准连续 2 次不通过 → 停，报告工单本身是否有问题。
- 需要实弹验证 → STOP（本单零实弹）。
