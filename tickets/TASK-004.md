# TASK-004 — T0.7 会话绑定修复：补齐可离线验证的闭环

- **优先级**：P1
- **状态**：✅ **完成**（2026-08-29，六条验收由总指挥亲自复跑全过，含独立重做的判别力探针红→绿；归档 [runs/20260829-TASK-004.md](../runs/20260829-TASK-004.md)）。跨 ASLR 重启的实弹验证仍不在本工单内（等老板决策 → TASK-006 路线）
- **岗位**：developer
- **预估**：3 小时
- **前置**：TASK-001（fmt 绿）

## 项目背景

MagicMida vNext 从受保护的 Windows PE 里 dump 出可加载的产物。有一条 `keep_runtime_base` 路线会保留运行时已解析的绝对指针 —— 这在"同一次会话里 dump 完立刻加载"是对的，但系统 DLL 的基址是随每次开机的 ASLR 变化的。
2026-08-29 07:58 机器重启后实锤：产物 `rev2_unpacked.exe` 在 RVA `0x112c10` 固化了旧会话的 ntdll 绝对地址 `0x7ffeeb426390`（当前 ntdll 基址已变成 `0x7ffa952a0000`），启动初始化期 `call rax` 取指即 AV（c0000005），宿主根本没走到加载 core.dll 那一步。

T0.7 已经写了修复代码：`data_reinit.rs` 增加会话模块表命中判定、`dump_process.rs` 把会话模块表归档成 `<output>.session_modules.json` sidecar、`sidecar_consumer.rs` + CLI 的 `/session-clean` 子命令负责用当前会话的模块表重写旧产物。1029 个 pe 单元测试全绿，门禁 0 error。

**但这个工单存在的唯一理由 —— "产物跨 ASLR 重启可加载" —— 一次都没有被验证过。** 原报告自己标了"待验证项"，台账却记成了 ✅ 完成。本次接管已把它降级为半成品。
实弹验证（真实重启 + 真实宿主）受环境限制，已单独挂在阻塞区等老板决策。**本工单只做能离线验证的部分**，把闭环做扎实，让实弹那一步一旦获批就能一次跑通。

## 你要改的文件

| 文件 | 现状 |
|---|---|
| `crates/pe/src/dumper/sidecar_consumer.rs` | 545 行，`load_session_table` / `parse_session_table` / `serialize_session_table` / `cleanup_artifact` / `build_old_table` + 8 个 `#[test]` |
| `crates/pe/src/dumper/dump_process.rs` | `persist_session_modules_sidecar`（约 633 行起）在 3018 行被调用 |
| `crates/pe/src/dumper/data_reinit.rs` | `is_stale_absolute_pointer` + `matches_session_module` + `SessionModuleRange` |
| `crates/cli/src/commands.rs` | `Command::SessionClean` 分派在 124 行，实现约 1328-1405 行 |
| `crates/cli/src/args.rs` | `SessionClean` 定义在 115 行，解析在 167 行、634/657/665 行 |
| `crates/cli/src/lib.rs` | 帮助文本 |

**先读这四份材料再动手**：`docs/ENGINE_SESSION_BINDING_FIX_20260829.md`（T0.7 报告，含"待验证项"一节）、
`docs/HARDCODING_AUDIT_20260829.md` §三 P0、`docs/KNOWN_ISSUES.md` C-1、`docs/TICKETS.md` 阻塞区 T0.5。

## 任务目标（一句话可观察的变化）

`dump → 归档 sidecar → /session-clean 重写 → 静态自检"无残留旧会话指针"` 这条链路有一个**端到端的离线测试**覆盖，并且 `/session-clean` 和 `/rebase-fixed` 在 `mida-cli --help` 里可见。

## 具体要求

1. **端到端离线用例（本工单的主体）**：构造一个合成 PE + 一份"旧会话模块表" + 一份"新会话模块表"（两份表里同名模块的基址不同，模拟重启后 ASLR 变化），走完整链路：
   - 用 `serialize_session_table` 造出与 `persist_session_modules_sidecar` **同一 schema**（`mida.session-modules/v1`）的 sidecar 文件；
   - 调 `cleanup_artifact` 重写；
   - 断言：指向旧会话模块的指针被按"模块名 + 模块内偏移"重定位到新基址；无法映射的被归零；`CleanupStats` 的计数与实际改写字节一致；
   - 断言：重写后的产物里**不再存在**任何落在旧会话模块区间内的绝对指针（这就是"静态自检无残留"）。
   用例放在 `sidecar_consumer.rs` 的测试模块里（与现有 8 个用例同风格）。
2. **schema 一致性用例**：`persist_session_modules_sidecar` 写出的 JSON 必须能被 `parse_session_table` 原样读回（round-trip）。现在写端在 `pe/dumper/dump_process.rs`、读端在 `sidecar_consumer.rs`，两边各自定义结构 —— 加一个用例把它们锁在一起，防止将来一边改字段名另一边不知道。
3. **`--help` 补齐**：`/session-clean` 和 `/rebase-fixed` 已经在 `args.rs` 完整实现（含用法字符串）但 `mida-cli --help` 里看不到。把它们加进 `crates/cli/src/lib.rs` 的 COMMANDS 段，用法与 `args.rs:634`/`args.rs:677` 里已有的字符串保持一致。
   > 先自己确认一遍：`target/release/mida-cli.exe --help | grep -i session` 当前无输出（可能是二进制过期，也可能真的没写帮助）。如果是二进制过期，重新构建后再判断，并在报告里说明。
4. **不要**去改 `is_stale_absolute_pointer` 的判定逻辑。它现在的行为（有会话表就按表判、无表则保留高 ASLR 指针）是 T0.7 的既定设计，改它属于另一个工单。
5. 不要为了让用例好写而放宽任何现有断言。

## 约束

- 只改上面清单里的 6 个文件。
- 不得引入新依赖（`serde_json` 已在依赖里）。
- 不得改 `_clippy_baseline`、不得改 CI 配置。
- 不得重构无关代码；不得动 `data_reinit.rs` 的判定逻辑（只允许为测试增加必要的可见性）。
- 不得提交、不得推送。
- 不得修改或删除现有测试的断言、不得加 `#[ignore]`。

## 本机环境（必读，否则测试必失败）

Git Bash 的 `PATH` 会把 `link.exe` 解析到 Git 的 GNU coreutils，链接必失败；`vcvars64.bat` / `VsDevCmd.bat` 在本沙箱被拦截。
唯一已验证可用的入口是 `tools/_enter_msvc_env.cmd`：

```bash
cd "D:/Claude project/magicmida-rs"
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\ncargo test -p mida-pe --lib --offline\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

跑完删掉你自己造的临时脚本，逐个按名字删，不要用通配符。

## 验收标准

1. `cargo test -p mida-pe --lib --offline` → **全绿，0 failed**，且总数比现在的 1031 多出你新增的用例数（在报告里点名新用例的函数名）。
2. `cargo test -p mida-cli --lib --offline` → 全绿，0 failed。
3. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 退出码 0。
4. `cargo fmt --all -- --check` → 退出码 0。
5. 重新构建后 `target/release/mida-cli.exe --help` 输出里能看到 `/session-clean` 和 `/rebase-fixed`。
6. **端到端用例必须真的会失败**：把 `cleanup_artifact` 里重写指针的那一步临时注释掉，你的新用例必须变红；恢复后变绿。在报告里贴出这两次的输出。
   （这一条是为了证明用例有判别力，不是摆设。改完记得恢复原状，`git diff` 里不许留这个临时改动。）

## 交付格式

写到 `runs/20260829-TASK-004.md`，粘贴上面 6 条的原始输出（含退出码）。
第 6 条要贴"故意改坏 → 变红"和"恢复 → 变绿"两次输出，以及最后的 `git diff --stat` 证明临时改动已恢复。
最后必须有「我不确定的事」一节，特别写清：**你验证了什么、以及跨 ASLR 重启这件事你仍然没有验证**。

## 停止规则

- 同一条验收标准连续 2 次不通过就停下来报告。
- 如果你发现 `persist_session_modules_sidecar` 写出的 schema 和 `parse_session_table` 读的 schema **本来就不一致**（第 2 条会暴露这件事），**停下来先报告**，不要顺手改其中一边 —— 那是一个独立的缺陷，需要单独定级。
- 不要试图自己制造"重启"来做实弹验证。那一步在等老板决策，不属于本工单。
