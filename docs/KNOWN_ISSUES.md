# KNOWN_ISSUES — 历史坑 + 当初为什么那么做

> 最后更新：2026-08-29。新坑往这里加，不要新建文档。
> 每条格式：现象 → 根因 → 当初为什么这么做 → 现在怎么办。

## 环境类

### E-1 Git Bash 里 `cargo test` 必定链接失败 [已验证]

`link: missing operand after '@...linker-arguments'`。Git 的 `C:\Program Files\Git\usr\bin\link.exe`（GNU coreutils 硬链接工具）在 `PATH` 上遮蔽了 MSVC 的 `link.exe`。
`cargo check` / `cargo fmt` 不链接，不受影响。
**怎么办**：用 `tools/_enter_msvc_env.cmd`（本次新增，自动探测 VS 与 SDK 版本）。用法见 `AGENTS.md` §2。

### E-2 `VsDevCmd.bat` / `vcvars64.bat` 在本沙箱被拦截 [已验证]

`vcvars64.bat` 调用返回"系统找不到指定的路径"，`vswhere.exe` 退出码 2。
**当初为什么这么做**：`tools/_enter_msvc_env.ps1` 走 VsDevCmd 是标准做法，在非沙箱环境是对的；它现在不是错的，只是在这台机器上不可用。
**怎么办**：`tools/_enter_msvc_env.ps1`（依赖 VsDevCmd + 写死 Professional 路径）和 `tools/xx21_msvc_env.cmd`（写死 MSVC 版本 `14.44.35207`，且行尾是 LF 导致 cmd 把 `%MSVC_ROOT%` 解析成 `D:` → `D:\bin\Hostx64\x64\link.exe`）都不要再用。统一用 `tools/_enter_msvc_env.cmd`。

### E-3 批处理文件必须是 CRLF 行尾 [已验证]

Git Bash 用 heredoc/`printf` 生成的 `.cmd` 是 LF 行尾，cmd.exe 会错解析变量与块结构（`E-2` 里那个 `D:\bin\...` 就是这么来的）。
**怎么办**：生成后 `sed -i 's/$/\r/'`。

### E-4 批处理里含括号的路径不能出现在 `if (...)` 块内 [已验证]

`%ProgramFiles(x86)%` 展开后的 `(x86)` 会在解析期提前闭合 `if ( ... )` 块，报"此时不应有 \Windows"。
**怎么办**：用 `if defined X goto :ok` 平铺写法，见 `tools/_enter_msvc_env.cmd` 的 SDK 检查段。

### E-5 增量编译会让 rustc 1.97.1 在本工作区 ICE [已验证，已回避未定位]

`cargo test --workspace` 在编译 `mida-disasm` 时报
`error: the compiler unexpectedly panicked. This is a bug`（compiler flags 含 `-C incremental=...`），
`crates/disasm/src/lib.rs`，退出码 101。删掉 `target/debug/incremental` 并设 `CARGO_INCREMENTAL=0` 后一次通过。
**当初为什么没暴露**：之前那次成功的全量测试恰好设了 `CARGO_INCREMENTAL=0`，所以只有在忘记设的那次才撞上。
**怎么办**：`tools/_enter_msvc_env.cmd` 已固化 `CARGO_INCREMENTAL=0`。
**没定位的部分**：不清楚这是"被中断的构建写坏了增量缓存"还是"本工作区 + 1.97.1 的稳定复现"。这是回避，不是修复；将来若需要增量编译的速度，得重新查。

## 门禁类

### G-1 `tools/check_clippy_baseline.ps1` 会把编译失败读成"全绿" [已验证，未修]

脚本第 44-50 行拿到 `$LASTEXITCODE` 后只打印一句 `NOTE: cargo clippy exited $code (deny-level lint present)` 就继续，然后只比较各 lint 的警告计数。
clippy 因任何原因（链接失败、语法错误、环境缺失）没跑起来时，警告计数全为 0，全部 ≤ 基线 → 打印 `OK: clippy warn baseline holds` 并 exit 0。
本次实测复现：无 MSVC 环境下 clippy exit 101、0 条警告，脚本仍然报 OK。
**当初为什么这么做**：clippy 在 deny-level lint 命中时确实会非零退出，而这时仍需要解析警告 —— 意图正确，但没有区分"lint 失败"和"根本没跑起来"。
**怎么办**：TASK-003。区分方式：要求解析到的 target 数 > 0，或检查 JSON 里有无 `compiler-message` 级别的 `error`。

### G-2 `cargo fmt --all -- --check` 曾红 216 处 [已修，归因已纠正]

CI `windows-quality` 是第一个 job，fmt 是第一步 → 红着的时候推任何东西 CI 都会立刻死在第一步。
**已于 2026-08-29 修复**（`cargo fmt --all`，全量测试仍 2801 passed / 0 failed，见 `runs/20260829-TASK-001.md`）。
**归因纠正**：我最初判断"216 处全是两天未提交改动造成的"，这是错的。`cargo fmt --all` 额外改动了 **31 个在 HEAD 上就已不合规**的文件
（`crates/packers/themida/` 8 个、`crates/pe/` 8 个、`crates/antidebug-runtime/` 4 个、`crates/cli/` 7 个等），
也就是 **CI 的 fmt job 在提交的树上本来就是红的**。已单独成一个 `style:` 提交（`d9617f5`），与功能改动分开。
**仍未查证**：这 31 个文件的格式债是哪个提交引入的、CI 实际红了多久 —— 本机无 `gh`，我没看到任何一次真实 CI run 结果。

### G-4 提交时把构建产物 `veh_probe.obj` 带进了仓库 [已验证，已纠正]`lab/runtime/veh_probe/` 里有一个在树内编译的 `.c` 探针，它的 `veh_probe.obj`（11 KB 构建产物）在
`cc8d12a` 里随 `git add -- lab/runtime` 一起进了仓库，违反 `ARTIFACT_POLICY.md`。
**怎么办**：已在 `855fc23` 用 `git rm --cached` 取消跟踪（**没有 `--amend`**，让这个错误留在历史里可见），
并给 `.gitignore` 补上 `*.obj` / `*.lib` / `*.exp`。文件本身留在磁盘上。
**教训**：`git add -- <目录>` 会把目录里所有未被忽略的文件都带上。加目录前先 `git status --short <目录>` 看一遍。

### G-5 `verify_workspace_hygiene.ps1` 在本机永久红，不能当推送前自检 [已验证]

脚本 exit 1、`"status": "FAIL"`：509 forbidden artifacts / 3 cache directories / 138 git-dirty。
**但这不代表 CI 红**。逐个核查过：**509 个全部是未跟踪的本机文件** —— `target/` 418 个、`lab/xx21*` 实弹证据 73 个、
`tools/__pycache__` 14 个，加 `build_release.log`、`pin.log`、`crates/cli/gto_launcher/` 下的 `snapshot.bin`。
仓库里唯一被跟踪的二进制是 `crates/packers/themida/src/oep/fixtures/` 下 8 个 `.bin`，正是政策允许的位置。
CI 是 fresh checkout 且 `CARGO_TARGET_DIR` 指向仓库外，这些都不会存在 → **[推断] CI 上应为绿**。
**坑在哪**：这道门在本机永远红，所以它**无法**用来做推送前的本地自检。我在接管过程中被它误导过两次 ——
第一次把输出管进 `tail` 后读了 `tail` 的退出码，误报"exit 0"；第二次看到 FAIL 又差点误报"CI 红"。
**怎么办**：本地跑它时只看 `counts` 里的 `fixture_manifest_violations` / `oversized_fixtures` / `unmanifested_fixtures` /
`checker_errors`（这四项与本机杂物无关，当前都是 0），忽略 `forbidden_artifacts` / `cache_directories` / `git_dirty`。
读退出码时不要接管道。

### G-6 那 1.3 GB 实弹证据不该躺在仓库工作区里 [已验证，未处理]

`lab/xx21b_resume/`（1.1 GB，115 文件）、`lab/xx21b_run_ui/`（145 MB）、`lab/xx21_s4/`（31 MB）、
`lab/xx21b_run/`（30 MB）、`lab/xx21b_matrix/`（7.3 MB）都是未跟踪的实弹证据。
按 `ARTIFACT_POLICY.md` 它们属于内容寻址 vault（`D:/MidaVault/lab/evidence/`），不属于仓库工作区。
**为什么还在这**：不知道，接管前就在。**没动的原因**：搬移证据是有风险的操作（万一 vault 里没有副本就成了删除），
且不属于任何已批工单。**怎么办**：需要先确认 vault 里已有副本，再决定搬或删。这件事要老板或熟悉 vault 布局的会话来定。

### G-3 `cargo fix` 会误删测试依赖的重导出 [已验证，已绕过]

清理 `runner_preflight/mod.rs` 的 unused imports 时，`cargo fix` 删掉了被 `use super::*` 和 `crate::runner_preflight::X` 引用的 `pub(crate) use` 重导出，造成 46 个 E0425。
**怎么办**：已用 `#[cfg(test)] pub(crate) use` 恢复（launch_gate 11 个 + envelope 2 个）。以后清 unused imports 前先确认测试引用。

## 引擎类

### C-1 `keep_runtime_base` 产物是"会话绑定"的，跨 ASLR 重启即崩 [已验证，修复未实弹验证]

**现象**：机器重启后 `rev2_unpacked.exe` 启动初始化期 AV（c0000005）。RVA `0x112c10` 固化了脱壳当时的 ntdll 绝对地址 `0x7ffeeb426390`，重启后 ntdll 基址变成 `0x7ffa952a0000`；RVA `0x21cc0-0x21cd8` 的 `call rax` 取指即崩。core.dll 从未被加载。
**根因**：`data_reinit.rs` 的 `is_stale_absolute_pointer` 对 `value >= HIGH_ASLR_MODULE_MIN` 直接 `return false`（保留高 ASLR 模块带指针，注释写着 "must survive until rebase"）；而 `keep_runtime_base`（XC-6-A 方案 B）只固定模块自身基址，系统 DLL 基址是随启动 ASLR 变的。
**当初为什么这么做**：`keep_runtime_base` 是为了让运行时已解析的指针在 rebase 前保持有效 —— 在"同一会话内 dump 后立刻加载"的场景是对的，只是把"同会话"这个隐含前提当成了普适前提。
**影响面**：所有 `keep_runtime_base` 产物（`xiongxiong_duokai` rev2、`core_perfect_candidate.dll`）都是会话绑定的，不可移植。
**现状**：T0.7 已加会话模块表清洗 + `.session_modules.json` sidecar 归档，pe 单元测试绿；但"跨 ASLR 重启可加载"这个**唯一目标从未实弹验证**。见 TASK-004。

### C-2 GTO dump 路线已判定为结构性天花板（TERMINAL）[已验证，终态]

被动等待 60s 与真实执行 300s 都产出**零个**新解密页；覆盖率恒定 4.26%（16/376 strips 是磁盘原始数据而非解密产物），距 60% 经济门差 14 倍。
**根因**：疑似 SecureEngine 类保护执行驱动逐页解密 —— 任何独立重跑都必然踩到密文页。
**怎么办**：不要再尝试 dump 路线。已转向 GVM-0 反虚拟化战役（VM 语义还原 → lifter → 整镜像去虚拟化）。

### C-3 GVM Phase 1 有一条自报的必须修正项 [存疑，未复核]

`0x8c000-0x8cfff` 区在 E15_align 和 D_b1 两个 trace 源里 exec 都是 0，与既有"`0x8c4c0` 主译码器有 216K+ trace 实证"的结论直接矛盾。
**注意**：trace 是**基本块入口级**而非指令级（Phase 1 自己修正的方法学），统计时按页起始地址精确匹配会得到误导性的 0 —— N5 修正就是这么来的。这条矛盾大概率是同类统计口径问题，但**未复核前不许当成已解决**。

## 流程类

### P-1 一天一份 `*_2026MMDD.md` 报告的传递方式已经撞过墙 [已验证]

2026-08-26 的提交 `511c7bf` 一次性删掉了 40+ 个 `AUDIT_BATCH*.md` / `AUDIT_EVIDENCE_BATCH*.md`。
**怎么办**：固定六份文件（见 `docs/00-START-HERE.md`），执行产出进 `runs/`，不要再造带日期的新文档。

### P-2 master 分支落后 557 个提交 [已验证]

`master` 最后提交 2026-07-16，`origin/master` 2026-07-09；所有产出都在 `oreans/two-sample-mainline`（本地还领先 origin 14 个未推送提交）。
CI 的 `on.push.branches` 已经把 `oreans/two-sample-mainline` 列为一等分支，所以这不是配置疏漏，是**长期分支事实上变成了主干**。什么时候合回 master 是老板要拍的板。

### P-3 本次接管误删了一个文件 [已验证]

清理我自己造的临时脚本时，把仓库根目录一个我没创建的未跟踪文件 `probe_run_out3.txt`（529 字节，2026-08-29 12:16，疑似上一会话的 probe 输出）一起删了。它未被 Git 跟踪，无法恢复。
**教训**：清理只删自己这次创建的文件，按名字逐个删，不用通配符。
