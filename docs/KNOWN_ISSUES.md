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

### G-1 `tools/check_clippy_baseline.ps1` 会把编译失败读成"全绿" [已验证，**已修（R2）**]

脚本第 44-50 行拿到 `$LASTEXITCODE` 后只打印一句 `NOTE: cargo clippy exited $code (deny-level lint present)` 就继续，然后只比较各 lint 的警告计数。
clippy 因任何原因（链接失败、语法错误、环境缺失）没跑起来时，警告计数全为 0，全部 ≤ 基线 → 打印 `OK: clippy warn baseline holds` 并 exit 0。
本次实测复现：无 MSVC 环境下 clippy exit 101、0 条警告，脚本仍然报 OK。
**当初为什么这么做**：clippy 在 deny-level lint 命中时确实会非零退出，而这时仍需要解析警告 —— 意图正确，但没有区分"lint 失败"和"根本没跑起来"。
**修复史**：R1 用「有无 lint code」分类，堵住了链接失败（code=null）但漏了 E 前缀编译错误（E0308 被"有 code"判成 deny 命中放行，总指挥注入探针实测 exit 0，打回）。R2 改为按 code 三分：无 code → 编译/链接失败；`clippy::` 前缀 → deny 命中放行；其他（`E` 前缀、rustc lint 名）→ 编译失败。**2026-08-29 总指挥亲自复跑四条验收全过**（链接失败 exit 3 / E0308+E0277 注入 exit 3 / 镜像基线 OK exit 0 / deny 注入不误杀 exit 0）。附带修复：warn 计数循环复用 `$code` 变量覆盖 clippy 退出码的隐患（改名 `$lintCode`）。
**残余注意**：与 TASK-008 的基线清还联动——门禁现在是真的，基线数字必须保持真实（见 G-7）。

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

### G-6 那 1.3 GB 实弹证据不该躺在仓库工作区里 [**已处理**，2026-08-30，D-017 授权]

`lab/xx21b_resume/`（1.1 GB，115 文件）、`lab/xx21b_run_ui/`（145 MB）、`lab/xx21_s4/`（31 MB）、
`lab/xx21b_run/`（30 MB）、`lab/xx21b_matrix/`（7.3 MB）、`tools/xx21_monitor*_out/` 都是未跟踪的实弹证据。
按 `ARTIFACT_POLICY.md` 它们属于内容寻址 vault，不属于仓库工作区。

**处理（总指挥执行，老板 D-017 授权动大文件）**：
- **目的地**：`D:/MidaVault/lab/worktree_evidence_20260830/`，**保留原相对路径结构**（`lab/xx21b_resume/...` → `<dest>/lab/xx21b_resume/...`），所以 `runs/`、`docs/` 里既有的旧路径引用（例如 TASK-010 引用的 `lab/xx21b_resume/redump2/*`）都能按同一相对路径在 vault 里找回。
- **做法**：**先拷贝 → 全量 sha256 校验 → 才删源**，不用一步到位的移动。
- **校验**：205 个文件、1,398,827,431 字节，源与目的两份 sha256 清单（含相对路径）`diff` **完全一致**；清单存为 `<dest>/MANIFEST.sha256`，`<dest>/README.txt` 里写了可复算的一行校验命令，并已当场复算通过一次。
- **顺带发现的重复**：`lab/xx21b_006r2/` 的 3 个文件与 `D:/MidaVault/lab/evidence/xx21b_006r2/` 里的**字节完全相同**（sha256 逐一对上），所以直接删掉，未二次归档。
- **结果**：`lab/` 从 1.3 GB 降到 **304 KB**；`git status` 的未跟踪项只剩 `.workbuddy-ai/` 与 3 个小文件（`tools/xx21_msvc_env.cmd`、`tools/xx21_step1_static_out.json` 28 KB、`tools/xx21_step1_static_deep_out.json` 14 KB）——后两个是 TASK-005/010 报告直接引用的静态分析产物，共 42 KB，**故意留在原地**避免打断引用链。
- **注意**：工作区仍有 **2.7 GB 的 `target/`**，那是 Rust 构建缓存（已 gitignore），不是证据、不违反 ARTIFACT_POLICY；删它只会换来一次长时间全量重建，**不建议动**。

### G-7 clippy 基线自 WO-24 锁定后已漂移，HEAD 上 WO-23 门禁是红的 [已验证，**已修（TASK-008）**]

WO-24 于 2026-08-27（提交 `607276d`）锁定 `_clippy_baseline`（TOTAL=349）后，28 个提交（XX-8..XX-11、`exception_final.rs`、rustfmt 全局整理等）让实际 warn 计数漂到 **354**：
5 个 lint 超基线（unnecessary_cast 18/17、manual_saturating_arithmetic 16/15、let_unit_value 4/2、type_complexity 8/7、unnecessary_map_or 14/12），3 个 lint 不在基线表（unused_variables=1、clippy::inconsistent_digit_grouping=1、unused_unsafe=1）。
2026-08-29 总指挥在 TASK-003 验收中实测：新旧两版基线脚本同环境输出**逐字节一致、双双 exit 1**（漂移是既有债务，与 TASK-003 改动无关）；换全新 `CARGO_TARGET_DIR` 复现一致，排除缓存污染。
**修复（TASK-008，2026-08-29）**：10 个机械位点全部最小修复（同型 cast 删除 ×6、`saturating_add`、`is_some_and` ×2、type alias、unit let 绑定清理 ×4、unused 清理 ×2、数字分组统一）；三条验收由总指挥亲自复跑全过（门禁 exit 0 / 全量测试 2801 passed 0 failed / fmt exit 0）。基线同批只降不升（349→337）。
**当初为什么会漂**：基线政策要求"修代码降计数时同 commit 降基线"，但没有反向约束——加代码升计数时没人复查基线，28 个提交就这么滑过去了。
**遗留提醒**：manual_range_contains 9→8、unused_imports 4→0 两行下调是既有向下漂移（非 TASK-008 位点触发），worker 一并下调使门禁自洽；若要基线只记录修复位点可还原这两行（门禁仍绿）。type_complexity 的 `iat_observe.rs:169`/`runtime_loader.rs:2309` 候选因 `&dyn Fn` alias 需生命周期参数（E0373）超出最小机械修复范围被跳过，达标即可，未清的 7 个 continue 存在于基线内。

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

### C-4 dump 重建会把不可解析的运行时指针固化进只读节（缺陷 A，fail-open）[已验证，**TASK-009 已修**（离线级）]

**现象**：当前会话重脱壳产物 `rev2_unpacked_fixed.exe`（`bb5ee568…`）启动初始化期即 AV（10/10 隔离运行 0xc0000005），core.dll 从未加载。
**根因（总指挥字节级复验坐实）**：`.rdata` RVA `0x1137d0` 槽被固化 `0x1401681d1`（= 自身 .pdata 中间，NX）；`.text 0xde785` 的 `call [0x1137d0]` 启动期跳进去。对照同次脱壳的未修复宿主 `698b1172` 同槽是 hint/name RVA（可解析）——重建阶段写入的坏值。
**管线知情却 fail-open**：`iat_evidence.json` 记录 `iat_evidence_complete: false`、`Unresolved=74`、`final=9 vs resolved=112`，但 dump 仍写出产物并打印 `[GOOD] Candidate written`。IAT 重建不完整时既不清零兜底也不判不合格。
**当初为什么会这样**：partial-accept 链路（`iat_partial_accept.rs`）设计上允许部分接受，但没有区分"可安全部分接受"与"启动路径上的必崩指针"。
**修复（TASK-009，2026-08-29 验收通过）**：兜底清零（`zero_fill_iat_region`：IAT span 未重建槽整段清零，honest hole）+ fail-closed 门（`call_sites_targeting_slots`：存在直接 call/jmp 指向不可解析槽 → `Err` 拒绝写出，`[GOOD]` 不再打印）。**修复验证级别 = 离线**（单元级缺陷几何 +7 用例、判别力探针红→绿）；`bb5ee568` 上的实弹替换验证留待 TASK-006 复跑（消耗实弹格，另行授权）。
**注意**：C-5（会话绑定 B）未修，与本项独立——修好 A 产物才能在当前会话活，修好 B 才能跨重启活。
**实弹验证状态：结构性不可达（3 次工单、跨 3 个 boot、13/13 次都没跑到）**。TASK-006R（9/9）、TASK-006R2（2/2）、TASK-006R3（2/2，**已换 boot**）全部在 dump **之前**的 text-poll 阶段结束——首跑烧到外部超时，后两次由 C-7 主动 fail-closed 中止（20ms 级）。三次的 `zero-filled IAT region` / `TASK-009 fail-closed` / `[GOOD] Candidate written` 三个证据点**都是 0 命中**。**这既不证实也不证伪修复**（"没跑到 dump"无法说明 dump 门是否生效）。
**阻塞点已定位到 C-6 的 ScyllaHide NtContinue-hook 故障环**（换 boot 后仍确定性复现，风暴 RIP 恒 = hook 地址 +8）。**继续按原方式开格重跑没有信息增量**——解锁路径是先做 `tickets/TASK-013.md`（离线：把 ScyllaHide 的 hook 选择变成可控可记录，关掉异常分发那条链），再带着受控 ini 申请一格实弹。

### C-5 `keep_runtime_base` 产物 .bss 固化当次会话 ntdll（缺陷 B，C-1 的残留形态）[已验证，未修]

2026-08-29 TASK-006 实测：新旧两个重脱壳宿主的 `.bss 0x112c10` 都固化 `0x7ffa953a6390`（**本**会话 ntdll+0x106390）——与 T0.5 旧宿主固化旧会话 ntdll 同型。当前会话不崩，跨 ASLR 重启必崩。**会话绑定在重脱壳产物中未根除**，`/session-clean` 消费端工具链（T0.7 §7.2 遗留项）是修复路径。注意与 C-4 独立：修好 A 产物才能在当前会话活，修好 B 才能跨重启活。

### C-6 重脱壳 text-poll 阶段 AV 风暴不收敛（TASK-006R 发现，0/9）[已定性 (c)：共因表象 —— TASK-010]

2026-08-29 TASK-006R 实测（21:18-21:56，与 TASK-006 成功路径**同一 boot**、同一样品、同一命令、同一环境变量）：9 次重脱壳尝试全部在 text-poll 阶段陷入 ntdll 内部 AV 风暴（exc 恒 `0x7ffa95400bd8` = ntdll+0x160bd8，单次 20 万–300 万次），`.text` 永不 stable，dump 从未到达——TASK-009 三个证据点全部不可观测，路径 A/B 均未到达。
**TASK-010 定性（2026-08-29，总指挥亲验坐实）：(c) 共因表象，基址与风暴无因果。**
- 基址**不是因**：04:0x 时段同基址 `0x7ff6c0c60000` 下成功（attempt3 03:58 / try1 04:09）与失败（fixed2 04:07，322 万次 AV）并存 —— 三份日志 CreateProcess 行 image_base 逐一相同。
- 基址**不是果**：21:1x 风暴 RIP 在 ntdll hook 区，与 debuggee 基址无算术关系；样品 DllCharacteristics=`0x60`（DYNAMIC_BASE|HIGH_ENTROPY_VA）→ 每进程独立掷点，两值差 3.6GB 属正常范围。
- 21:1x 风暴 = **ScyllaHide NtContinue-hook 区故障环**：dumpbin 确证 ntdll+0x160bd8 磁盘字节为 `F6 04 25 08 03 FE 7F 01` = `test byte ptr [0x7FFE0308],1`（读 KUSER_SHARED_DATA，恒可读，干净字节不可能 AV）→ debuggee 内存该处被改写；`scylla_hide.log` 明示 hook `_NtContinue 0x7FFA95400BD0`，风暴 RIP = hook 点 +8 落在覆盖区；`target=0x204` 是句柄形低值。[微指令级确切字节存疑——原始 3.5GB 日志已清理]
- 04:0x 风暴 = **VM 取指环**（exc=target=`0x1108e3761a0` 未映射空洞，exc_type=8 执行故障）→ **与 21:1x 不同型**。
- 把"偶发环"放大成"确定性 0% 收敛"的是 **C-7 引擎缺口**（见下）。
**影响**：TASK-009 修复的实弹验证仍被阻塞（既未证实也未证伪）；T0.5 继续 BLOCKED。
**待办**：TASK-011（修 C-7，纯离线）。ScyllaHide-NtContinue-hook 交互的微指令级定性需新 trace（实弹），另立专项。**不建议本会话继续烧格重试**——重启只改运气，不改缺口。

**TASK-006R2 追加实测（2026-08-29/30，同一 boot，C-7 已修）**：又是 2/2 次同一几何（exc 恒 `0x7ffa95400bd8`，exc_type=**0** read，`target` 每进程变：0x25a / 0x20e，同首跑的 0x204 一样都是低值句柄），debuggee image_base 恒 `0x7ff799fc0000`。
- **本 boot 合计 11/11 次确定性不收敛**（首跑 9 + 本跑 2），同一 ScyllaHide NtContinue-hook 故障环。C-6 的"共因表象"定性不变，但可以加一句更强的：**在这个 boot 上它不是偶发，是确定性的。**
- **重试的成本模型已经彻底变了**：C-7 修好之后，一次撞环的运行从"小时级 + 3.5GB 日志 + 需要外部杀进程"变成 **20ms + 312KB + 自己干净退出**。所以"重启后重试"从"烧格赌运气"变成了**近乎免费的探测**——TASK-010 当时"不建议靠重启重试当解法"的判断基于旧成本模型，现在应当更新：重启后重试是廉价且合理的下一步，代价不再是格数而是一次重启。
- ScyllaHide-NtContinue-hook 的微指令级根因**仍未定性**（需专项 trace）。绕过它的备选路线（关 ScyllaHide 的 NtContinue hook 单项、换注入时机）尚未评估。

**TASK-006R3 追加实测（2026-08-30，已换 boot，总指挥亲验）：换 boot 没换掉故障环，因果链实锤。**
- 新 boot（`2026-08-30 01:28:40`）的 ASLR 布局完全不同：ntdll `0x7ffa952a0000` → `0x7ff857620000`，debuggee image_base `0x7ff799fc0000` → `0x7ff729430000`。
- 但风暴 RIP **恒等于 ScyllaHide 的 NtContinue hook 地址 + 8**，两个 boot 各自自洽：旧 boot `scylla_hide.log` 记 `_NtContinue 00007FFA95400BD0` / 风暴 exc `0x7ffa95400bd8`；新 boot 记 `_NtContinue 00007FF857780BD0` / 风暴 exc `0x7ff857780bd8`；相对 ntdll 偏移都是 **+0x160bd8**。→ **同一现象在两套完全不同的地址下复现，不再是"相关"而是实锤**：不是 ASLR 运气，是 ScyllaHide 的 NtContinue hook 与壳的异常分发确定性打架。[已验证]
- 每次运行内**恒同元组唯一**（`sort -u` 恰 1 条）× 1024 次，C-7 判据形状再次被证实。
- 累计 **13/13 次跨 3 个 boot** 确定性撞同一故障环（006R 9 + 006R2 2 + 006R3 2）。**"重启后重试"这条路已经走到头了**——TASK-006R2 时我把它列为"近乎免费的探测"，探测做了，结果是阴性，这条路可以关掉了。
- **总指挥读日志发现的抓手（TASK-013 的起点）**：`target/release/` 下**没有 `scylla_hide.ini`**，运行日志里也无任何读 ini/config 的痕迹，而 `scylla_hide.log` 显示 `Hooking KiUserExceptionDispatcher` 与 `Hooking NtContinue` **都装上了**；对照 vault 参考 ini（`D:/MidaVault/quarantine/20260722/workspace/magicmida-rs/scylla_hide.ini`）那里 `KiUserExceptionDispatcherHook=0`。→ **我们是在无配置状态下注入，ScyllaHide 默认把所有 hook 都装上**，包括跟壳打架的异常分发链。引擎里配置口子其实留着（`antidebug_controller.rs:507` 的 `OracleMode.ini_path`，挂着 `#[allow(dead_code)]`），**留了没接线**。[已验证]
- **待办**：~~TASK-013~~ 已完成并验收；~~TASK-006R4~~ **已执行并验收（2026-08-30，终态 STOP：`C:\Windows` 落位方案结构性无效）** → ~~TASK-006R5~~ **已执行并验收（2026-08-30，终态路径 A）：受控 ini 生效后 0 次 AV、text-poll 首次收敛到 dump——C-6 故障环被干预实验定案（配置差异，D-020 证实）；缺陷 A fail-closed 门实弹生效（192 unresolved 槽拒绝产物）。~~新前沿 = IAT 启动路径重建（192 槽）~~ **勘误（D-024/P-10）：IAT 重建能力 08-28 已实证（XX-11 186/186 + load 10/10 + S4 8/8）；当前 0/201 是回归，TASK-014 v2 = 回归定位与恢复。**

**TASK-014 实弹诊断定案（2026-08-30，终态路径 A'，2/2 有效尝试，vault `xx21b_t014/`）[已验证]**：201 槽 = **112 Resolved**（live 直接匹配：msvcrt 76 / kernel32 19 / user32 7 / ntdll 5 / wininet 4 / version 1）+ **74 Unresolved** + 15 ZeroTerminator。74 个启动路径槽的运行时值**全部是 Themida 段内 VM wrapper 地址**（image_base+0x1681d1 … +0x3203d7；偏移 0x1681d1 与 XX 时代旧产物 `.rdata 0x1137d0` 坏值 `0x1401681d1` 逐位一致——跨 boot 确定性互证）。192 启动路径站点 → 74 唯一槽，全部 Unresolved。**XX-10-A 静态原导入表（9 项）对 VM wrapper 地址结构性 0 命中 → 静态回填 0 覆盖是结构性必然，不是回归（修正 D-024 假设②）**。shell trace 74 槽全败（deepened retry 亦败；slot-scoped 化后 201 槽全遍历可见）：主线程在 wrapper 地址无单步事件——**186/186→0/201 的机制层主嫌疑 = shell trace 的执行线程/时机（XX-11 时代能解 VM 槽的机制 = 复现钥匙）**。

**TASK-015 收官定案（2026-08-30，终态路径 B1'，2/2 有效尝试，vault `xx21b_t015/`）[已验证]**：**C-6/IAT 缺口全链闭合**。主根因 = T0.5-R2 的 HW-anchor ERROR_NOACCESS → 12s grace window → debug loop 断在 spurious 线程 ExitThread 且未 continue → post-loop trace `continue_event(trace线程)` 被 TID 校验拒绝 → trace 从未单步（R5 日志 TID mismatch ×3 实证；T014 被 slot-scoped 包装吞成误导文案；XX-11 成功 = frozen-entry 无 pending）。修复 = stale pending 按归属线程 continue 清生命周期再 bootstrap（trace_imports 自 3b5862b/XX-8-A 起结构未变——"回归"在 break 路径不在 trace_imports）。实弹 2/2：**trace resolved=74/74 failed=0、imports 186 整、结构门 12/12、load_no_crash 10/10 ×2、S4 标记字节级对齐（窗口标题"授权验证"/config.ini 26B/core.dll sha 09f3dd34 与 XX-10 vault 一致）、产物 1,539,072 B 与 XX-11 同尺寸**（sha 与 XX-11 不同 = session 级差异，语义端点一致）。**XX-11 端点受治理复现达成。**

**TASK-013 追加（2026-08-30）+ TASK-006R4 勘误（同日实弹实证推翻其中一条）：ini 查找规则的最终定论。**
- ~~`InjectorCLIx64.exe` 用裸相对名读配置、只搜 Windows 目录、放 exe 旁没用~~ —— **这条 TASK-013 结论错误，已由 TASK-006R4 推翻（详见本块末尾"定案版"第 1 条）**。正确结论：InjectorCLI 用 `GetModuleFileNameW` 拿自身 exe 路径，读 **`<exe目录>/scylla_hide.ini`**；放 exe 同目录**有效**，放 `C:\Windows` **无效**。TASK-013 的探针测的是裸相对名的 API 语义（该语义本身正确），但 InjectorCLI 传的是绝对路径，故不适用。**教训（新 P-9）：探针必须打在被测程序的实际调用路径上；只验 API 语义就宣布"程序行为如何"，会把一个正确的 API 结论变成一个错误的程序结论，并据此烧掉一格实弹。**
- `NtContinueHook` 是真实配置键（二进制 wide 字符串命中 + 两份 vault 参考 ini 均含 `NtContinueHook=0`）。**工单前提修正**：我当初写"参考 ini 里没有这个键"是**读漏了**（总指挥亲验 grep：quarantine 版行 35、Magicmida 版行 13），worker 如实纠正——前提错了，修法未受影响。
- 已交付：`ini_path` 接线（去 dead_code）+ 日志行 `SCYLLAHIDE_HOOK_CONFIG_SOURCE=` + walker/failure 两个证据 sidecar 新增 `scylla_hide_config_source` 字段 + 受控 ini `D:/MidaVault/lab/config/scylla_hide_no_excdispatch.ini`（与参考基线逐键一致 42/42，异常分发两开关显式 0）。
- **注意混杂变量（下一格实弹的设计要点）**：受控 ini 相对"全默认 hook"的差异**不止两个开关**，是整套 UncoverEngine profile（约 30 键）。若下一格走通，归因到具体开关需后续最小差分 ini 变体（另立单）。
- ~~受控 ini 生效的唯一路径 = 落位 `C:\Windows\scylla_hide.ini`~~ —— **已被 R4 推翻**。正确路径 = 落到 **InjectorCLI 同目录**（`target/release/`），但 ARTIFACT_POLICY 第 11 条明确禁止活动工作区出现名为 `scylla_hide.ini` 的文件（gitignore 不构成例外）→ **授权内无路径，必须改代码**（见"定案版"第 4 条）。R4 落位的 `C:\Windows\scylla_hide.ini` 已删净（总指挥复核：`ls /c/Windows/*.ini` 只剩 system.ini / win.ini）。
- **熊熊线旁证（2026-08-30 定案版——此前三版归因皆误，本版以 R4 反汇编 + 历史日志双重实证收口）**：
  1. **TASK-013 的"InjectorCLI 只搜 Windows 目录"结论错误**（R4 发现，总指挥反汇编独立证实）：InjectorCLI 实际用 `GetModuleFileNameW` 拿自身 exe 路径、读 **`<exe目录>/scylla_hide.ini`**（IAT 槽 0x6f150=GetModuleFileNameW / 0x6f158=GetPrivateProfileSectionNamesW，调用点 0x14000ce7f / 0x14000cf9a 亲验）；notepad 注入 A/B/C 三实验：exe 同目录有 ini → 受控生效；仅 C:\Windows 有 → 全默认；cwd 无关。TASK-013 的 API 语义探针（裸相对名）测的是 Windows 对相对名的搜索规则，对 InjectorCLI 传入绝对路径的实际行为不适用——**C:\Windows 落位方案结构性无效**。
  2. **15:26 历史 scratch 日志重读（总指挥覆盖前亲读）：那份 ini 当年就生效了**——15 个 `Hooking X` 安装行恰不含 ini 三个 =0 键（NtClose/NtContinue/KiUserExceptionDispatcher），NtQueryObject(=1) 在列；`ApplyNtdllHook -> _NtContinue …` 那行是**地址枚举清单**，不是安装记录。前两版"ini 被无视/全默认 hook"的归因错在读混了这两类行。**该日志已被 R4 探针覆盖（新 P-8），关键行内容已在此存档。**
  3. **xx 线与 006R 线成败的统一解释（撤回 e8bda46 的"ASLR 布局依赖"假说）**：xx 时代实弹跑在 scratch 环境（mida-cli 与 InjectorCLI 同目录，ini 就在旁 → 异常分发链关闭）→ 成功；006R/R2/R3/R4 跑在 target/release（InjectorCLI 旁无 ini → 全默认 hook，异常分发链开启）→ 14/14 撞环。**不是布局运气，是配置差异**——xx11 的成功状态恰好就是"关闭异常分发 hook"（R4 的实验目标）。[xx11 具体使用 scratch 构建为推断——scratch 目录两者共存且时间吻合；ini 生效机制本身为已验证]
  4. **对 R5 的含义**：受控 ini 落到 **InjectorCLI 同目录** = 复现 xx 线成功配置。授权内唯一路径 = 改代码（`scyllahide.rs` spawn 前落位 或 `helpers.rs` 指向工作区外 staging 目录），需老板授权。


### C-7 text-poll 阶段无 AV 风暴终止机制（引擎结构缺口，TASK-010 发现）[**已修 + 实弹验证通过** —— TASK-011 修 / TASK-012 加固 / TASK-006R2 实弹坐实]

**缺口**：guard 未安装（text-poll）阶段，任何恒同 AV 环都被无限吞掉：
- `crates/packers/themida/src/runtime/av_oep_handler.rs:161-168`：`!state.guard_installed` → 无条件 `AvOepAction::Continue` 早返回；
- 同文件 `:232`：风暴计数器 `unrelated_av_streak` 只在 `guard_installed && NotGuarded` 分支递增 → guardless 阶段**永不计数**（既有 `unrelated_av_storm_threshold` / `unrelated_av_null_storm_threshold` 两个阈值在此阶段完全失效）；
- `crates/cli/src/unpacker/mod.rs:1139-1141`：`text_poll_start` 在**每个事件**上重置 → `:1159-1164` 的 30s idle 超时在连续 AV 流下**结构上永不触发**；
- `.text`-stable 判定（`mod.rs:1214-1218`）依赖壳完成解密 → 壳卡在环里则永不达成。
**后果**：任何 constant-AV 环（04:0x 型 VM 取指环、21:1x 型 hook 故障环）都必然 0% 收敛直到外部超时/杀进程，并产出 3.5GB 级垃圾日志。TASK-006R 的 9 次白烧格直接由此造成。
**修复方向（TASK-011）**：guardless 路径对恒同 AV 元组（exception_addr, target, exc_type, thread）计数，超阈值 → 返回 `Err` fail-closed 中止（`av_handler.rs:92` 的 `?` 链现成可用），不 dump、不打 `[GOOD]`、日志有界。纯离线可改、可单元测试，与 TASK-009 的 fail-closed 语义同族。

**已修（离线级，TASK-011，2026-08-29，总指挥亲验）**：
- 实现：`av_oep_handler.rs` guardless 早返回前加恒同元组计数（`guardless_av_tuple` / `guardless_av_tuple_streak`，**元组变化即清零**），达 `GARDLESS_AV_STORM_TUPLE_THRESHOLD=32` → 置 `storm_abort` 并返回 `Break`；`av_handler.rs` 的 `Break` 分支见 `storm_abort` 即转 `Err`（含元组与计数），经调用点 `?` 传播出 `unpack()`，**跳过 `run_post_loop_phases`（dump）与 `[GOOD]`**；`mod.rs` 只加 2 个循环外持久化变量 + 传参。
- 4 个授权文件 **+281/-0（纯新增，0 删除行）**；`.text`-stable 判定（`mod.rs:1214-1218`）与既有断言**零改动**，无 `#[ignore]`/`.skip`。
- 总指挥亲跑（真 cargo 退出码，非管道 grep 码）：themida lib 167 ✅ / 集成 16 ✅（12→16，4 个新用例全绿）/ mida-pe 1049 持平 ✅ / clippy 三 `-D` 0 error ✅ / fmt ✅，5/5 EXIT=0。
- 判别力（总指挥自选回退，与 worker 的 `if false` 不同——改成 streak 永不累加，等价复现"无持久计数"原缺陷）：恰 2 个风暴用例红（exit 101）、防误杀与守卫回归 14 绿 → 字节级恢复（`cmp` 一致）→ 16/16 绿。
- **遗留项（TASK-012 已全部清完，2026-08-29）**：① 阈值 32 对硬 fail-closed 裕量偏薄 → **改为 1024**；② 常量拼写 `GARDLESS` → **`GUARDLESS_AV_STORM_TUPLE_THRESHOLD`**；③ host 侧 `storm_abort → Err` 无自动化测试 → **抽出纯函数 `map_storm_abort` + 2 个单元测试**。

**加固（离线级，TASK-012，2026-08-29，总指挥亲验）**：
- 阈值 **32 → 1024**，doc 注释重写选值理由：本判据后果是**硬 fail-closed**（整单 Err、无产物），不沿用软着陆的 `unrelated_av_storm_threshold=32`（风暴逃逸回退 Break，仍可能出产物）——**后果更重的判据不借用更轻判据的阈值**；实测双峰（健康 0 次 / 风暴 20 万–322 万次）下 1024 对真风暴仍留 2–3 个数量级裕量，误杀窗口比 32 小两个数量级。既有 `unrelated_av_storm_threshold=32` 未动，两阈值从此显式不同。
- host 腿抽出纯函数 `map_storm_abort`（`av_handler.rs`）：`Some((tuple,count))` → `Err`（错误串逐字保留 TASK-011 原文）／`None` → `Ok(AvAction::Break)`；配 2 个单元测试（cli lib 572→**574**）。
- 恰 3 授权文件 **+94/-32**；`mod.rs` 未碰（`.text`-stable 判定继续零改动）；既有断言原文逐字保留，无 `#[ignore]`/`.skip`（cli 那 1 个 ignored 用例是 `plugin_host.rs:710`，来自旧提交 `a2809a6`，本单 diff 里 `ignore` 命中 0）。
- 总指挥亲跑（真退出码）：themida 全量 ✅（集成 16 全绿）/ cli --lib **574** ✅ / mida-pe **1049 持平** ✅ / clippy 三 `-D` 0 error ✅ / fmt ✅。
- 判别力（总指挥自选**两种**回退，均与 worker 的 no-op 不同）：(B) 从 Err 串里去掉 count → 恰 `Err must carry the count` 断言红（exit 101）；(C) 让 `Some` 臂永不命中（`.filter(|_| false)`，可编译）→ `storm abort must fail closed` 红（exit 101）。中途我第一版 (C) patch 触发 E0425 编译错误——**按 P-5 编译失败不算红**，已重做为可编译版本。字节级恢复（`cmp` 一致）→ 2/2 绿。
- **仍是离线级**：1024 未经实弹校准；host 腿测的是抽出的纯映射函数，`handle_access_violation` 全函数 e2e 仍无法离线覆盖（依赖 debugger/ProcessSession）。
- 低优先遗留（下次碰这些文件时顺手，不单独立项）：`guarded_path_unrelated_av_streak_unchanged` 用 `THRESHOLD-1` 作种子，改用 `>= THRESHOLD` 的种子会是更强的"守卫路径下休眠"证明。
- **验证级别 = 离线**：真实 debuggee 风暴下的中止时机、日志有界性、CLI 退出行为**未实弹验证**（下一格实弹应顺带观察：恒同环 ~1024 次事件内触发 `guardless constant-AV storm abort`，无 dump、无 `[GOOD]`、日志非 3.5GB 级）。

**实弹验证通过（TASK-006R2，2026-08-29/30，1 格，总指挥亲验证据）**：2/2 次重脱壳在 text-poll 撞上恒同 AV 环时引擎**主动 fail-closed 中止**，全部预期数字实测坐实：
| 观察点 | 首跑（TASK-006R，C-7 未修） | 本跑（C-7 已修 + 加固） |
|---|---|---|
| 终态 | 9/9 烧到外部超时/杀进程 | 2/2 引擎主动中止 |
| AV 事件数 | 20 万 – 322 万 | **恰 1024**（阈值精确生效，第 1024 个事件上中止，之后 0 个 AV） |
| 首次 AV → 中止 | 从未中止 | **19.6ms / 23.9ms** |
| 日志体积 | 3.5GB / 3.2GB | **~312KB**（首跑的 0.009%） |
| 产物 / `[GOOD]` | 无（烧死） | 无（fail-closed，设计如此） |
| 残留 debuggee | 需外部杀 | 无（验收时全系统复查无残留） |
- 总指挥独立复核（不采信报告表格，直接读 vault 证据）：exe `0c407a97…` 里四条门字符串各命中 1 次；两份日志各 `grep -c AccessViolation` = **1024**；abort 行含完整元组；`[GOOD]` / `zero-filled IAT region` / `TASK-009 fail-closed` 三者各 **0 命中**；时间戳算差 19.6ms / 23.9ms。
- **顺带解决 TASK-011 的一个 [存疑]**：21:1x 几何的 `exc_type` 实测 = **0（read）**，与当初测试里按 `test byte ptr` 读操作结构自洽选的 0 一致——猜对了。
- **元组判据被实弹验证是对的**：`target` 在**不同进程间会变**（首跑 0x204、本跑 attempt1 0x25a / attempt2 0x20e，都是低值句柄），但在**同一次运行内恒定** 1024 次——正好落在"同一运行内恒同即风暴"的判据上，且跨运行的变化不会污染计数（每次运行状态独立）。
- **跨 boot 稳定性（TASK-006R3，2026-08-30）**：换 boot 后再次 2/2 主动中止，AV 恰 1024、19.4/21.5ms、日志 312225/310154 B、无产物、无残留；每次运行内恒同元组 `sort -u` 恰 1 条。**C-7 是这一串修复里唯一已经实弹闭环、且跨 boot 复现过的**。
- 未验证：中止后的清理只确认了"进程无残留"，**未做句柄/内存泄漏检查**；`C-7 FATAL` 与 CLI 最终 `Fatal error:` 之间有恒定 **5.01s** 间隔（疑似固定拆除等待），teardown 路径**无日志**——都不影响 fail-closed 结论，记为观察项。

### C-8 调试附加门控解密：WinLicense 反调试扣住 core.dll `.text` 不解密——附加观测与正常执行结构性互斥 [已验证，2026-08-30 TASK-018，5/5 可复现]

**现象（总指挥亲验字节级对照）**：同一 run_va（core.dll+0x1C120），两种运行方式字节态不同——非附加（T017，3/3）：`4157415641554154555756534881eca8`（明文 prologue）；调试附加（T018，5/5）：`586db5df0b9b0d1ca42f0b4238024a79`（加密态）。附加下宿主引导期弹 **WinLicense 反调试对话框**（class `#32770` title `WinLicense`），Run 线程入口即 AV（0xc0000005 @ run_va）→ 817× 恒同址故障环（core+0x2cc7a6）→ second-chance → 全线程退出 0xC0000005；urlmon 0 命中。
**影响面**：**在 `NO_BYPASS` 红线内，"用调试器观察解密后路径"（RIP 级行为判定）在本样品上结构性不可达**——观察需要附加（P-11：仅附加式上下文可读），附加扣住解密。T017（非附加、明文、GUI 层可达）与 T018（附加、密文、入口 AV）构成对照实验对，证据在 vault `xx21b_t05/` 可复算。
**关联**：与 P-11（环境垫零）叠加 = 本平台三态 RIP 判定的双重结构性障碍。未来路线：非托管环境（外部 GetThreadContext 可用的机器）或壳**进程内自证**（需改样品 = 红线外）。
**规矩**：凡涉本样品/本壳族的"调试器附加观察"工单，派单前先引本条——附加观察解密后路径的尝试不再消耗实弹格。





### C-3 GVM Phase 1 有一条自报的必须修正项 [已验证，已定级 (b) —— TASK-005 复核]

`0x8c000-0x8cfff` 区在 E15_align 和 D_b1 两个 trace 源里 exec 都是 0，与既有"`0x8c4c0` 主译码器有 216K+ trace 实证"的结论直接矛盾。
**注意**：trace 是**基本块入口级**而非指令级（Phase 1 自己修正的方法学），统计时按页起始地址精确匹配会得到误导性的 0 —— N5 修正就是这么来的。这条矛盾大概率是同类统计口径问题，但**未复核前不许当成已解决**。

**最终定级（TASK-005 复核，2026-08-29，两源全量复算）**：**不是统计口径问题，实锤 (b) 静态存在/trace 未激活**。
- 三种口径全为 0：页起始精确匹配 0 / 页区间包含 0 / 基本块入口级（块起始∈页区间）0；块区间覆盖 0x8c4c0 的转移 0；页内 unique 地址 0
- 0x8c4c0 逐址 exec=0；0x8f0bb（静态 `call 0x8c4c0`）exec=0；0x12d8c8 槽 exec=0
- 0x8f099 之后同源相邻 exec 目标 top-1 = 0x8f374（238,672 次），**无一次落入 0x8c4c0** → "0x8f099→0x8c4c0 216K+"不成立
- 0x8c000-0x8cfff 位于两源 .text 最大执行空窗（0x834e0→0x8ef00，46KB）内，且上游 0x8b800-0x8bfff 也无 exec，排除"块内顺序流覆盖页"的可能
- **处置**：ISA_SPEC_V0 的"trace 实证 216K+"标注降级为**静态推断**（静态反汇编/表A/表B 内容仍成立，无执行证据）；不影响调度主链结论（0x8f099→0x8f374→0x9150d 实测转移独立支撑）
- 复算脚本：tools/task005_recheck_8c4c0.py；报告：runs/20260829-TASK-005.md

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

### P-6 红线里的样品定位符 `启动器.exe` 已经指向另一条线的样品了 [已验证，2026-08-30 TASK-006R2 发现，总指挥亲验]

`D:\Tools\RE\dumps\gto\启动器.exe` 现在的字节是 `11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86`（**GTO 线样品**），而 xiongxiong_duokai 的 manifest `protected_input` / `primary_artifact_sha256` 是 `7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`。**两者不是同一个文件。**
红线机制本身工作正常——"定位符不是身份、必须先解析到 vault 对象再比对 manifest"这条规矩正是为此而立，TASK-006R2 的 worker 照做了，直接从 `D:/MidaVault/objects/sha256/78/78009803…` 加载，身份核验 PASS 后才执行（日志 `Input:` 行可复核）。**但我在工单里照抄那个路径当红线示例，本身就是个坑**：下一个 worker 未必这么小心。
**规矩**：① 派单红线里**直接写 vault 对象路径 + 期望 sha256**（`D:/MidaVault/objects/sha256/78/78009803…`），不再引用 `启动器.exe`；② 保留"定位符不是身份"这条原则的表述，但把它作为**通则**而非指向某个具体路径；③ 已有工单里的该路径引用，下次修改这些工单时顺手清掉。

### P-7 证据显示串里混入了西里尔同形字母 `hооk`（U+043E）[已验证，2026-08-30 TASK-013 验收时总指挥发现]

TASK-013 落地代码里 "hook" 一词有 6+ 处写成了西里尔 `о`（U+043E）而非 ASCII `o`（`helpers.rs` 的显示串 `"无 ini（ScyllaHide 默认全 hооk）"` 与注释、`antidebug_controller.rs` 的测试断言与断言消息、报告标题同源）。测试内部自洽所以全绿，**但按 ASCII `hook` 去 grep 日志/sidecar 会漏**（`SCYLLAHIDE_HOOK_CONFIG_SOURCE=` 前缀和 `无 ini` 子串仍可 grep，实际影响面小）。
**规矩**：① 下次任何 worker 获授权碰这三个文件时，顺手把西里尔 о 归一为 ASCII o（含对应测试断言，一处不漏）；② 我以后验收新增用户可见字符串时加一条"纯 ASCII/CJK 检查"。

### P-10 同一样品开新工单/新战役前，必须先挖 vault 里的历史战役证据包 [已验证，2026-08-30 发现]

xx 战役（08-27/28，xx1…xx11 共 11 次实弹）在 `D:/MidaVault/lab/evidence/xiongxiong_duokai/` 留有完整证据包与报告：**XX-11 已端到端跑通**（IAT 186/186 全解析 + 结构门 12/12 + load_no_crash 10/10 零 AV + S4 业务标记 8/8 对齐）。8-29 接管日无人读它 → 006R/R2/R3/R4 四格花在"回到已知位置"；总指挥 08-30 起草 TASK-014 时又没读，把问题定义写成"回溯从未咬合、需扩展"（错，实为回归）——被老板质询"以前能脱壳为什么现在不行"点醒后才直读证据包（D-024）。
**规矩**：① 同一样品开任何新工单，第一步 = 通读 vault 证据目录下该样品全部历史 `*REPORT*`/manifest；② 问题定义里凡出现"从未/没能力/需要新建"字样，必须先有"历史做过没有"的证据；③ 产物类目标必须先对照历史最佳端点（本例 = XX-11 的 186/186 + 10/10 + S4 8/8）。

### P-9 探针打在 API 语义上而不是被测程序的实际调用路径上，烧掉一格实弹 [已验证，2026-08-30 TASK-006R4 实弹实证推翻 TASK-013]

TASK-013 用 P/Invoke 探针验证了"裸相对名传给 `GetPrivateProfileStringW` 只搜 Windows 目录"——**这个 API 结论是对的**。但 InjectorCLI 的实际调用路径是 `GetModuleFileNameW` → 拼出 exe 同目录绝对路径 → 才调 `GetPrivateProfile*`，所以那条 API 语义**对它不适用**。我验收时复验的是导入表（`GetCurrentDirectoryW`/`SearchPathW`/`GetFullPathNameW` 0 命中——这些也都是真的，因为它用的是 `GetModuleFileNameW`，不在我列的名单里），**没有反汇编看文件名参数从哪来**，于是把一个正确的 API 结论当成了程序行为结论批了过去。据此写的 R4 工单要求落位 `C:\Windows` → 结构性无效 → **一格实弹（XC-XXI-B → 6/4）没产出任何有效尝试数据**。责任在我这一侧（验收把关不严），不在 worker。
**规矩**：① 凡"某程序从哪读文件/怎么解析路径"这类结论，验收必须要求**实际调用点证据**（反汇编 / API monitor / 受控 A-B 对照实验），API 文档语义与导入表只能作辅证；② 用"缺失的导入"作反证时，必须先穷举**能达到同一目的的所有 API**（`GetModuleFileNameW`、`GetModuleHandleW`+拼接 等），否则"没导入 X 所以做不到 Y"是伪推理；③ 涉及实弹前置的路径类结论，**先做一次零成本受控 A/B 实验**（R4 worker 的 notepad 三实验即范本，成本几分钟）再烧格。

### P-8 历史 scylla_hide.log 被新一次注入覆盖，证据窗口只有一次 [已验证，2026-08-30 发现]

`scylla_hide.log` 由 ScyllaHide 写在 **InjectorCLI 同目录**且**每次注入覆盖**。scratch 目录里那份 2026-08-28 15:26 的日志（xx 线的关键旁证：证明受控 ini 当年生效——15 条 `Hooking X` 安装行恰不含 ini 中三个 =0 的键）**已在 R4 的探针注入中被覆盖**（现存内容为 08-30 03:56 的 8 行 VA 枚举）。关键行内容已在 C-6 块内存档，但原始文件不可恢复。
**规矩**：① 任何一格实弹的 `scylla_hide.log` **必须在下一次注入前**复制进 vault（R4 worker 做到了：`scylla_hide_livefire_attempt1.log`）；② 离线探针若会触发注入，先备份当前 log 再跑；③ 引用 scylla 日志作证据时，报告里附**当次日志的 vault 副本路径**，不要引用 `target/release/` 或 scratch 里的活文件。

### P-5 报告里的 `EXIT=0` 有可能是 grep/findstr 的退出码，不是 cargo 的 [已验证，2026-08-29 TASK-011 验收时发现]

Windows 批处理里 `cargo test ... 2>&1 | findstr /C:"test result"` 之后取 `%ERRORLEVEL%`，拿到的是**管道最后一个命令（findstr）**的退出码——findstr 找到匹配就返回 0。同理 Bash 下 `cargo ... | grep ...` 的 `$?` 是 grep 的。**这意味着一份 cargo 真的失败（exit 101）的运行，报告里照样能印出 `EXIT=0`。**
本次验收时我自己第一版验收脚本就犯了这个错，改成"先重定向到文件、紧接着取 `%ERRORLEVEL%`、再对文件 grep"后复跑，TASK-011 的 5 条命令确认全是真 0（结论未变，但取证方式此前不成立）。
**规矩**：① 派单模板要求 worker 用"先重定向再取码"的写法；② 我做验收时**一律自己重跑并自己取真码**，不采信报告里的 `EXIT=` 数字；③ 判别力探针的红必须同时给出**非 0 的真退出码**（TASK-011 探针实测 exit 101）。

### P-4 上一 worker 见宿主存活失败仍固化候选、未阻塞上报 [已验证，档案坐实]

2026-08-29 上午的 redump2 worker 在 `lab/xx21b_resume/run_ui_fixed/probe_run_out2.txt` 里**已经看到** `bb5ee568` 宿主 6 秒退出、`alive_final: false`、`core_seen: false`，却没有把"宿主不可用"当阻塞上报，照常固化候选、写 sidecar、继续后续流程——直到 TASK-006 实弹轮 10/10 崩溃才暴露，浪费了一格实弹。
另：`probe_run_out.txt` 记录了一次 `NotADirectoryError` 部署失败（PowerShell `Out-File` 编码问题）也被静默绕过。
**教训（对验收与派单都适用）**：涉及"产物固化/候选晋升"的工单，验收标准必须包含**当场存活探针**（产物写完立即跑一次，非 0/259 即阻塞上报），不能只看 sidecar 与静态结构通过。已在 TASK-009 及后续实弹工单的派单模板中加入此检查项。

### P-11 PI Desktop 托管会话对非附加式观测系统性垫零：GetThreadContext 恒 0、EnumWindows 回调不触发；调试端口路径不受影响 [已验证，2026-08-30 TASK-017 + 总指挥独立探针]

现象（TASK-017 worker 六组探针 + 总指挥两条独立缝复核）：本环境对**任意进程**（notepad/cmd/宿主/自身）的 `GetThreadContext`（kernel32 与 ntdll `NtGetContextThread` 双层）返回成功但 RIP/RSP/RAX 恒 0；`EnumWindows`/`EnumChildWindows` 回调不触发（窗口发现需改走 FindWindowW）；当前线程伪句柄路径直接拒绝（ok=0）。**调试端口附加的进程不受影响**：总指挥用 `DEBUG_ONLY_THIS_PROCESS` 拉起 cmd 实测 CREATE_PROCESS 挂起态读得真实 `Rip=0x22d9f9f8b8`、imageBase 真实非零。
**影响面**：一切"外部观测型"harness（OpenThread+GetThreadContext、EnumWindows 回调）在本环境不可用作判定证据；**解包引擎不受影响**（调试端口路径实测可用，与 T015 同 boot 引擎 trace 74/74 互证）。
**规矩**：① 本机上的判定类工具一律走**调试端口附加**或被测进程**进程内自证**路线；② 外部观测证据（RIP/RSP）在本机不再作为验收判据的必要条件，改用调试端口证据或进程内证据；③ 凡报告以 `GetThreadContext` 外部读取为关键证据的，总指挥验收时按本条复测。
