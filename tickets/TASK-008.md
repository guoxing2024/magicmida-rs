# TASK-008 — 清还 clippy 基线漂移（10 个机械修复位点，让 WO-23 门禁回绿）

- **优先级**：P1（推送前必须完成，否则 CI clippy job 必红）
- **状态**：✅ **完成**（2026-08-29，三条验收由总指挥亲自复跑全过；归档 [runs/20260829-TASK-008.md](../runs/20260829-TASK-008.md)）
- **岗位**：developer
- **预估**：1.5 小时

## 项目背景

MagicMida vNext 的 CI 有一道"警告基线"门禁：生产代码 warn 级 clippy lint 计数只许降不许升，基线记在仓库根 `_clippy_baseline`（TOTAL=349，WO-24 于 2026-08-27 在提交 `607276d` 锁定），由 `tools/check_clippy_baseline.ps1` 在 CI 的 `windows-clippy` job 执行。
2026-08-29 总指挥验收 TASK-003 时实测发现：基线锁定后的 28 个提交让实际计数漂到 **354**——5 个 lint 超基线、3 个 lint 不在基线表里，门禁在 HEAD 上已经是红的（exit 1）。新旧两版脚本同环境输出逐字节一致，证明漂移是既有债务，与 TASK-003 的脚本改动无关。
你现在要做的是把 10 个警告位点用最小机械修复清掉，让门禁对真基线回绿。基线政策（`_clippy_baseline` 头部注释）：计数只降不升；修代码把计数降到基线之下时，同 commit 降基线。

## 你要改的文件

以下位点按需修改（全部是 warn 级 lint，不阻塞编译）：

**必清（缺表新 lint / rustc 警告，清到 0）：**

1. `lab/runtime/host_loader/src/main.rs:60` — `clippy::inconsistent_digit_grouping`（数字分组不一致，整理成一致分组）
2. `lab/runtime/xx21_monitor/src/main.rs:181` — `unused_unsafe`（无用 unsafe 块，去掉 `unsafe`）
3. `crates/core/src/windows_debugger.rs:479` — `unused_variables`（未用变量，删掉或 `let _ =`，若是死代码注明）

**必降（超基线，清够差值即可）：**

4. `clippy::let_unit_value` 实际 4 / 基线 2 → 清 2 个：建议 `lab/runtime/xx21_monitor/src/main.rs:136` 和 `:137`（改成 `let _ = ...` 并写一句为什么丢弃返回值；同 lint 另两个位点 `crates/cli/src/unpacker/walker_session.rs:699,701` 达标内可不动）
5. `clippy::unnecessary_cast` 实际 18 / 基线 17 → 清 1 个，任选最机械的。候选位点：`crates/cli/src/unpacker/iat_observe.rs:305`、`crates/cli/src/unpacker/runtime_loader.rs:1375`、`crates/cli/src/unpacker/walker_dispatch.rs:248`、`crates/packers/themida/src/antiantidebug/handlers.rs:351,581,652,705`、`crates/pe/src/dumper/coverage_measure.rs:117`、`crates/pe/src/dumper/dump_process.rs:874,1844,1854,1978,1981`、`crates/pe/src/dumper/heap_global_snapshot.rs:4061,4282,4722`、`crates/pe/src/dumper/wrapper_materialize.rs:525`、`crates/pe/src/dumper/x64_asm.rs:209`
6. `clippy::manual_saturating_arithmetic` 实际 16 / 基线 15 → 清 1 个，任选。候选：`crates/cli/src/unpacker/rebase_fixed.rs:61`、`crates/pe/src/dumper/dump_process.rs:1978,1985,1992,1997,2007`、`crates/pe/src/dumper/heap_global_snapshot.rs:3595`、`crates/pe/src/exception_final.rs:292,295`、`crates/pe/src/exception_observation.rs:415,573,628,631,644,669`、`crates/pe/src/postprocess.rs:757`
7. `clippy::type_complexity` 实际 8 / 基线 7 → 清 1 个，任选（加 type alias 最稳）。候选：`crates/cli/src/unpacker/iat_observe.rs:169`、`crates/cli/src/unpacker/runtime_loader.rs:2309`、`crates/pe/src/dumper/heap_global_snapshot.rs:410,6803`、`crates/pe/src/dumper/raw_slab_coherence.rs:3797,4293`、`crates/pe/src/dumper/remote_modules.rs:195`、`crates/pe/src/dumper/runtime_rebase.rs:2004`
8. `clippy::unnecessary_map_or` 实际 14 / 基线 12 → 清 2 个，任选。候选：`crates/cli/src/unpacker/mod.rs:986,1435`、`crates/cli/src/unpacker/runtime_loader.rs:2073,2113,2154,2725`、`crates/pe/src/dumper/coverage_measure.rs:564,565`、`crates/pe/src/dumper/heap_global_snapshot.rs:1031,6474,6877`、`crates/pe/src/dumper/raw_slab_coherence.rs:3394,5110`、`crates/pe/src/dumper/runtime_rebase.rs:2224`

## 任务目标（一句话可观察的变化）

MSVC 环境下 `tools/check_clippy_baseline.ps1` 对真基线输出 `OK: clippy warn baseline holds (TOTAL baseline=349)` 且 exit 0。

## 具体要求

1. 每个位点只做**最小机械修复**（删无用 cast / 改 `saturating_sub` / 改 `is_some_and` / `let _ =` / 删 unused / 统一数字分组 / 加 type alias），**禁止任何顺手重构、禁止改逻辑**。
2. 若某个位点你判断"修了会改行为"（不是纯 lint 层面的修复），跳过它换一个候选，并在报告里说明。
3. 不要为凑数去动达标内的位点；清够差值就停。
4. 修复后若某 lint 计数降到基线**之下**，把 `_clippy_baseline` 里对应行同批下调（只降不升，TOTAL 同步减）；只降到等于基线则不动基线文件。缺表新 lint 清到 0 后不需要加进基线（不存在 = 0）。

## 约束

- 只动上面列出的文件 + `runs/` 下的报告文件 + （仅当计数低于基线时）`_clippy_baseline`。
- 不得改任何测试文件、不得改 `.github/workflows/ci.yml`、不新增依赖、不改 `tools/check_clippy_baseline.ps1`。
- 禁止一切 git 写操作（不 add、不 commit、不 push）。

## 本机环境（必读）

- Git Bash 的 `PATH` 把 `link.exe` 解析到 GNU coreutils，clippy 链接必失败——验收必须在 `tools/_enter_msvc_env.cmd` 环境下跑：

```bash
cd "D:/Claude project/magicmida-rs"
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\npowershell -NoProfile -ExecutionPolicy Bypass -File tools/check_clippy_baseline.ps1\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

- 临时 `.cmd` 必须 CRLF（`sed -i 's/$/\r/'`），LF 会被 cmd 解析坏。
- 工作区里 `tools/check_clippy_baseline.ps1` 是 TASK-003 第 1 轮修改后的版本：在 MSVC 环境下它的基线比较逻辑正确（总指挥亲测：漂移树 exit 1、镜像基线 exit 0），可以放心当验收器用。TASK-003 第 2 轮返工会继续改它，不影响你——你的验收标准是输出与退出码，不是脚本版本。
- 跑完删掉你自己造的临时脚本，逐个按名字删，不要用通配符。

## 验收标准（三条命令判生死）

1. **门禁回绿**：MSVC 环境跑 `tools/check_clippy_baseline.ps1` → exit 0 + `OK: clippy warn baseline holds (TOTAL baseline=349)`（若降了基线则是更小的 TOTAL）。
2. **测试无回归**：MSVC 环境跑 `cargo test --workspace --offline` → 0 failed（当前基线 2801 passed / 2 ignored）。
3. **格式**：`cargo fmt --all -- --check` → exit 0（本工单会改 .rs，此条是硬要求；开工前先跑一次确认起点是绿的）。

## 交付格式

写到 `runs/<YYYYMMDD>-TASK-008.md`（用你的实际运行日期）：三条验收命令的**完整原始输出**（含退出码）+ 修复位点清单（每个位点一行：文件:行 → 改了什么）+ 若跳过了任何候选位点写明原因 + 末尾必须有「我不确定的事」一节。

## 停止规则

同一条验收标准连续 2 次不通过就停下来报告，不要硬糊。
如果你发现某条 lint 在你修复后计数不降反升（说明你改出了新警告），立即回退那个位点并换一个候选。
