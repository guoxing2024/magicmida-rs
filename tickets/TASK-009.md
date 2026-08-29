# TASK-009 — 修 dump 重建缺陷 A：不得把不可解析的运行时指针固化进只读节

- **优先级**：P1（TASK-006/T0.5 复跑的硬前置；引擎级 bug）
- **状态**：📋 待领取
- **岗位**：developer
- **预估**：4 小时
- **来源**：TASK-006 实弹验收发现（`runs/20260829-TASK-006.md` §四，总指挥字节级复验坐实）

## 项目背景

MagicMida vNext 从受保护的 Windows PE 里 dump 出可加载产物。2026-08-29 TASK-006 实弹验证发现：当前会话重脱壳产物 `rev2_unpacked_fixed.exe`（sha256 `bb5ee568…`，dump 管线自身产出）启动初始化期即 AV（0xc0000005），10/10 隔离运行全崩，core.dll 从未加载。

根因（字节级已验证）：**dump 重建流程把一个不可解析的运行时绝对指针固化进了只读数据节**。

证据链（总指挥已独立复验，你不用重跑实弹）：

1. 产物 `.rdata` 节 RVA `0x1137d0` 槽的固化值 = `0x1401681d1` = 映像基址 0x140000000 + RVA `0x1681d1` —— 落在**自身 `.pdata` 节中间**（.pdata chars=0x40000040，只读不可执行）。
2. `.text` RVA `0xde785` 处指令 `ff 15 45 50 03 00`（`call qword ptr [rip+0x35045]`）→ 即 `call [0x1137d0]` —— 启动初始化期执行流跳进 NX 数据 → AV。
3. 对照：同一次脱壳的**未修复**宿主 `rev2_unpacked.exe`（`698b1172…`）同一槽 = `0x1762f4`（hint/name RVA，小值、loader 可解析语义）→ 该宿主能活。同槽不同语义，证明是重建阶段写入的坏值。
4. **管线自己知情**：`rev2_unpacked_fixed.exe.iat_evidence.json` 记录 `iat_evidence_complete: false`、`Unresolved=74`、`final=9 vs resolved=112`、blocker 字符串写明 "live IAT slot 0/1/2/4/6 status Unresolved; module identity mismat…" —— 但 dump 仍然写出产物并打印 `[GOOD] Candidate written`。

**这是一个 fail-open**：IAT 重建不完整时，管线既没把不可解析槽清零/兜底，也没把产物判为不合格，而是带着会崩的指针照常输出"GOOD"。

## 你要改的文件

- `crates/pe/src/dumper/iat_partial_accept.rs`（882 行：`evaluate_partial_accept`、`static_corroboration_candidate`、`address_owned_by_loaded_module`、`verify_call_site_semantics`）
- `crates/pe/src/dumper/iat_gap_retarget.rs`（415 行：`retarget_iat_gap_call_sites`）
- `crates/pe/src/dumper/dump_process.rs`（调用点：`use super::iat_partial_accept::evaluate_partial_accept` 约 351 行；decision 消费约 388-475 行；`iat_partial_accept` 决策约 951-975 行）

先读这三份材料再动手：`runs/20260829-TASK-006.md` §四（根因）、`lab/xx21b_resume/redump2/rev2_unpacked_fixed.exe.iat_evidence.json`（管线自知的失败证据）、`docs/KNOWN_ISSUES.md` C-4。

## 任务目标（一句话可观察的变化）

dump 管线遇到 IAT 重建不可解析的槽时，产物中**不再出现指向映像自身不可执行节的固化指针**；且管线对该情况的最终判定是**显式失败或显式降级**（带 blocker 的产物不许再打印 `[GOOD] Candidate written`）。

## 具体要求

1. **先诊断后动手**：在现有代码里找到"运行时快照值被原样写进 .rdata 槽"的具体写入路径（0x1137d0 这类槽属于哪条链路：IAT 重建？data_reinit？keep_runtime_base 保指针？），在报告里写清文件:行号级别的因果链。**如果诊断发现根因不在上面三个文件里**，停下来报告实际位置，不要乱改。
2. 修复方向（诊断后二选一或组合，写明理由）：
   - **兜底清零**：不可解析且无法静态佐证的槽，重建时写 0（与 `/session-clean` 对 unmappable 指针的清零语义一致），让加载期重解析；
   - **fail-closed**：当 unresolved 槽属于启动路径（存在直接 call 指向它）且无法兜底时，产物判不合格，dump 以错误退出或输出带 blocker 的降级判定。
3. 修好后必须让 `bb5ee568` 型缺陷**可被离线测试捕获**：加一个单元/集成测试，构造"运行时指针指向映像自身 .pdata"的输入，断言修复后的行为（清零或拒绝），并做判别力证明（临时回退修复 → 测试红 → 恢复 → 绿，贴两段输出）。
4. 不得改变 `/session-clean` 与 `data_reinit.rs` 的既有语义（那是 C-1/B 缺陷的修复路径，另一工单）。
5. 不要求实弹重跑 dump（那是 TASK-006 复跑轮的事，另行授权记账）。

## 约束

- 只改上面三个文件 + `runs/<实际日期>-TASK-009.md`。若诊断结论指向别处，停下报告，不改代码。
- 不新增依赖；不改测试断言（只能新增测试）；不加 `#[ignore]`。
- 不改 `_clippy_baseline`（若你的修复让某 lint 计数下降，报告里说明即可，基线下调由验收人处理）。
- 禁止一切 git 写操作。

## 本机环境（必读）

Git Bash 的 `link.exe` 被 GNU coreutils 抢占，链接必失败——测试走 `tools/_enter_msvc_env.cmd` 包装法（见 `AGENTS.md` §2 或任一已完成工单的 runs 报告）；临时 `.cmd` 必须 CRLF（`sed -i 's/$/\r/'`）。`tools/_enter_msvc_env.cmd` 同时固化 `CARGO_INCREMENTAL=0`（增量编译 ICE，KNOWN_ISSUES E-5）。

## 验收标准（三条命令判生死）

1. `cargo test -p mida-pe --lib --offline` → 全绿 0 failed，且含你新增的缺陷捕获用例（报告里点名函数名与总数变化）。
2. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → exit 0。
3. `cargo fmt --all -- --check` → exit 0。

## 交付格式

写到 `runs/<实际日期>-TASK-009.md`：诊断因果链（文件:行号）→ 修复方案与理由 → 三条验收命令完整原始输出（含退出码）→ 判别力证明（红/绿两段输出 + git diff --stat 证明恢复）→ 「我不确定的事」一节（特别写清：你没做实弹重跑、`bb5ee568` 的实际替换验证仍待 TASK-006 复跑轮）。

## 停止规则

同一条验收标准连续 2 次不通过 → 停下写分析报告。
诊断阶段若发现根因位置与本工单假设不符，或发现"固化"其实发生在更早的观察/快照层（crates/core、tracer），立即停下报告，不要越权改。
