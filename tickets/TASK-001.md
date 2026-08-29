# TASK-001 — 修复 216 处 rustfmt 差异

- **优先级**：P0
- **状态**：📋 待领取
- **岗位**：developer
- **预估**：40 分钟

## 项目背景（3-5 句）

MagicMida vNext 是一个 Windows PE 脱壳研究平台（Rust，221k 行，11 个 crate 的 workspace）。
CI 有四个 job，第一个是 `windows-quality`，它的第一步就是 `cargo fmt --all -- --check`。
过去两天有大量改动没跑过 fmt，导致这一步现在红 216 处 —— **CI 在第一步就死，后面的测试和 clippy 门禁根本不会执行**，等于项目现在没有 CI。
本工单只做格式化，不改任何逻辑。

## 你要改的文件

不要自己找文件。先执行这条命令拿到完整清单：

```bash
cd "D:/Claude project/magicmida-rs"
cargo fmt --all -- --check 2>&1 | grep '^Diff in' | sed 's/ at line.*//' | sort -u
```

然后对整个 workspace 执行 `cargo fmt --all`。已知涉及的文件包括（不完整，以上面命令输出为准）：
`crates/acceptance/src/{bundle_gate.rs,gates/mod.rs,implementation_gate.rs}`、
`crates/antidebug-runtime/src/attestation.rs`、
`crates/antidebug-runtime/tests/{attestation.rs,walker_protocol.rs,walker_protocol_section.rs}`。

## 任务目标（一句话可观察的变化）

`cargo fmt --all -- --check` 从"216 处 diff、退出码 1"变成"无输出、退出码 0"。

## 具体要求

1. 执行 `cargo fmt --all`。
2. **行尾不要动**。仓库 `.gitattributes` 是 `* text=auto eol=lf`，但工作区里有若干 legacy CRLF 文件（例如 `crates/pe/src/dumper/data_reinit.rs`），它们与 HEAD 基线一致。
   如果 `git diff --stat` 出现某个文件"整文件改动"（改动行数 ≈ 文件行数），那就是行尾被改了 —— 用 `git checkout -- <file>` 撤销该文件，再单独 `rustfmt` 它并检查。
3. 格式化后跑一遍全量测试，确认没有任何行为变化。
4. 不要顺手清理 unused import、不要改注释、不要动 `_clippy_baseline`。

## 约束

- 不得改动清单外的文件（`cargo fmt --all` 的作用域就是清单）。
- 不得引入新依赖。
- 不得重构任何无关代码。
- **不得提交、不得推送**（提交由 TASK-002 统一处理）。
- 不得修改任何测试的断言、不得加 `#[ignore]`。

## 本机环境（必读，否则测试必失败）

Git Bash 的 `PATH` 会把 `link.exe` 解析到 Git 的 GNU coreutils，链接必失败；`vcvars64.bat` / `VsDevCmd.bat` 在本沙箱被拦截。
唯一已验证可用的入口是 `tools/_enter_msvc_env.cmd`：

```bash
cd "D:/Claude project/magicmida-rs"
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\ncargo test --workspace --offline\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

`cargo fmt` 不链接，可以直接在 Git Bash 里跑。跑完删掉你自己造的临时脚本，逐个按名字删，不要用通配符。

## 验收标准（一条命令判生死）

1. `cargo fmt --all -- --check` → **退出码 0，无输出**。
2. 全量测试仍为 **2801 passed / 0 failed / 2 ignored，EXIT=0**（上面那条命令的输出）。
3. `git diff --stat` 里**没有**任何文件的改动行数接近其总行数（= 没有行尾被整体改写）。

## 交付格式

写到 `runs/20260829-TASK-001.md`，必须粘贴上面三条命令的**原始输出**（含退出码）。
只写"已完成"不附输出 → 直接打回，不问理由。最后必须有「我不确定的事」一节，不许留空。

## 停止规则

同一条验收标准连续 2 次不通过就停下来，在报告里写清卡在哪、你试过什么，不要继续硬搞。
特别是：如果 fmt 之后测试出现失败，**立刻停**并报告 —— 那说明有比格式更严重的问题。
