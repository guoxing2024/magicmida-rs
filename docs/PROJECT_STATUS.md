# PROJECT_STATUS — MagicMida vNext

> 最后更新：2026-08-29（冷启动接管会话，含收尾修正）　更新人：总指挥
> 本文件是项目现状的唯一权威快照。工单台账见 [TICKETS.md](TICKETS.md)。

## 一句话结论

这项目是**活的**（654 次提交，2801 个测试全绿），
本次接管已把最要紧的风险解掉：**两天的在飞成果已分 8 个提交落到本地 git，`cargo fmt` 从红 216 处变为 0。推送按老板裁定停在本地，等他逐次确认。**
下一件最要紧的事需要老板两个裁定：**① TASK-006R2 那一格的授权口径（D-015）；② 是否为 TASK-006R3 扩额**（XC-XXI-B 已 4/4 满配）。**离线侧无待办工单。**
三个 fail-open/无终止缺陷都已在**离线级**修完：缺陷 A（C-4，dump 重建把不可解析运行时指针固化进只读节 → 兜底清零 + fail-closed 门，TASK-009）、C-7（text-poll 阶段无 AV 风暴终止 → 恒同元组计数 + fail-closed 中止，TASK-011）、C-7 加固（阈值 32→1024 + host 腿补测试，TASK-012）。三者的**实弹验证都还没做**，而且只能在同一次重脱壳里一起验：TASK-006R 首跑用掉 1 格但 9/9 陷在 text-poll 风暴里，dump 从未到达（正是 C-7 造成的），所以缺陷 A 的实弹替换验证既未证实也未证伪。

**注意：WO-23 基线门在 HEAD 上是红的**（基线漂移，见 KNOWN_ISSUES G-7 / TASK-008）——推送前必须清还，否则 CI clippy 必红。

## 存活状态 [已验证]

以下是在**最终提交树**上复跑的结果（`tools/_enter_msvc_env.cmd` 环境）：

| 项 | 结果 | 证据 |
|---|---|---|
| release 构建 | ✅ 通过（1m31s） | `target/release/mida-cli.exe` 5.7 MB，`--help` 正常输出 |
| 全量测试 | ✅ **65 个 target / 2801 passed / 0 failed / 2 ignored**，exit 0 | `cargo test --workspace --offline` |
| `cargo fmt --all -- --check` | ✅ exit 0（接管时是红 216 处） | 见 `runs/20260829-TASK-001.md` |
| clippy 门禁 1（`--all-targets -D dbg_macro`） | ✅ exit 0 | — |
| clippy 门禁 2（`--lib --bins -D unwrap_used/expect_used/manual_let_else`） | ✅ exit 0 | — |
| **clippy 门禁 3（WO-23 基线门 `check_clippy_baseline.ps1`）** | ✅ **exit 0（TOTAL=337）** | TASK-008 清还漂移 + TASK-003 R2 修软通过，均于 2026-08-29 验收（总指挥亲测）；详见 KNOWN_ISSUES G-1/G-7 |
| 硬编码门禁 | ✅ `HARD-CODING GATE PASS` | `python tools/_hardcode_scan.py --gate` |
| `cargo check --workspace --tests` | ✅ exit 0 | — |
| 依赖锁定 | ✅ Cargo.lock 81 包，`cargo-deny 0.20.2` 本机可用 | `deny.toml` |
| **`tools/verify_workspace_hygiene.ps1`** | ❌ **本机 exit 1**（509 forbidden artifacts / 3 cache dirs / 138 git-dirty） | 见下方说明 |
| CI 远端红绿 | ❓ 无法查证（本机无 `gh`，从未看到任何一次真实 CI run） | — |

### 关于卫生门禁的 exit 1（我纠正自己的两次误判）[已验证]

- **第一次误判**：接管早期我报"卫生门禁 exit 0"。错的 —— 我把输出管进了 `tail`，`$?` 读的是 `tail` 的退出码。
- **第二次修正**：脚本实际 **exit 1**，`"status": "FAIL"`。
- **但它对 CI 的含义和本机不同**：已逐个核查，**509 个 forbidden artifact 全部是未跟踪的本机文件** ——
  `target/` 418 个、`lab/xx21*` 证据 73 个、`tools/__pycache__` 14 个，加上 `build_release.log`、`pin.log`、
  `crates/cli/gto_launcher/` 下的 `snapshot.bin`（全部 untracked）。
  仓库里**唯一**被跟踪的二进制是 `crates/packers/themida/src/oep/fixtures/` 下 8 个 `.bin`，而它们正是政策明确允许的位置。
  CI 是 fresh checkout 且 `CARGO_TARGET_DIR` 指向仓库外，这些文件都不会存在，`git_dirty` 也会是 0。
- **所以 [推断]：这道门在 CI 上应该是绿的，在本机永久是红的。** 代价是**它不能当作推送前的本地自检**，这一点会误导人（我就被误导了两次）。
  已记入 `KNOWN_ISSUES.md` G-5。

**结论：代码是绿的；仓库已经落地；唯一仍不可信的是"CI 到底红不红"这件事本身 —— 因为没人看过一次真实的 CI run。**

## 家底 [已验证]

- Rust 221k 行 / 269 个 `.rs` 文件：生产 167.5k 行、测试 53.8k 行
- 11 个 workspace member（含 `lab/runtime/` 下 2 个，且**这 2 个成员是未提交状态**加进 `Cargo.toml` 的）
- 2795 个 `#[test]`；`#[ignore]` 仅 1 处；`todo!`/`unimplemented!` 仅 1 处（测试 mock）
- `TODO`/`FIXME`/`HACK` 8 处（cli 4、packers 2、core 1、pe 1）
- 文档：`docs/` 41 个 .md + 根目录 5 个 —— **文档通胀**，无入口、无台账（本次已建）
- 未提交：41 个 modified + ~35 个 untracked（含 3 个新生产源文件共 1259 行）→ **已于 2026-08-29 分 8 个提交落到本地**（未推送）
- 仓库工作区里还躺着 **约 1.3 GB 未跟踪的实弹证据**（`lab/xx21b_resume/` 1.1 GB、`lab/xx21b_run_ui/` 145 MB、`lab/xx21_s4/` 31 MB 等）。按 `ARTIFACT_POLICY.md` 它们应该在 vault 里，不在这里。未处理，列为遗留项。

## 三态分布

**已完成 8 ｜ 半成品 6 ｜ 幻想 0 ｜ 治理缺口 4**

`幻想 0` 是这个项目最值得表扬的地方：README 和验收契约反复自我否定（"`no-gate` 不等于通过"、"structural Accepted 不是完美脱壳的证明"），
文档里没有代码中找不到的功能。这在混乱项目里极罕见。

### 已完成（有实现 + 有调用 + 能验证）

1. **acceptance 独立验收内核（R0B）**：`mida-acceptance` 不依赖任何生产 crate，`dependency_boundary.json` pass=true；253 个 lib 测试。
2. **纯 PE 模型（R1-A..E）**：解析/序列化/`RebuildPlan` 重建/byte-map 适配/`--pure-rebuild` opt-in emit；生产 dump 默认仍走 legacy，pure 是显式选项。
3. **Oreans/Themida 主干链路**：create-process → post-attach 观察循环 → post-loop dump，两样品固定回归门 `origin_macro` + `lunlun_software`。
4. **GTO 家族路由（G0/G1）**：默认构建即识别 GTO 形状并路由到 `ahk_gto`，与 Oreans 共用主干骨架，只有观察策略不同；重型恢复需 `--features gto-product-recovery` + `--profile=ahk-gto-experimental`，未 opt-in 时 fail-closed。
5. **xiongxiong_duokai rev2 战役**（2026-08-28 关闭）：S1 结构 12/12、S2 `.text` 明文 100%、S3 load_no_crash 10/10、S4 行为对齐。
6. **clippy 分阶段门禁（WO-8..WO-25）**：生产代码 `unwrap_used`/`expect_used`/`manual_let_else` 已 deny 且 0 error。
7. **硬编码清理（T0.8/T0.9/T0.10）**：样品哈希改从 `lab/cases/v2/*.json` manifest 读取；系统目录改 `GetSystemDirectoryW`/`GetWindowsDirectoryW`；CLI 示例地址通用化。扫描 `sample_hex 0 / win_path 0`。**代码已核对，但未提交。**
8. **样品身份不可变化（G3-R2/R3）**：可变路径先冻结为内容寻址快照，hash/size 成为 case 身份，封装前后各校验一次，篡改即 fail-closed。

### 半成品（有实现但没接上 / 有结论但没实弹 / 被当成完成）

1. **T0.7 引擎会话绑定根治 —— 离线闭环已补齐（TASK-004，2026-08-29），实弹验证仍未做。**
   `data_reinit.rs` 会话模块表清洗 + `dump_process.rs` 归档 `.session_modules.json` sidecar + `/session-clean` 消费端：现在有端到端离线测试覆盖（e2e 重定位/归零/计数/无残留 + schema round-trip，判别力探针红→绿由总指挥独立复做）；`mida-cli --help` 可见 `/session-clean` 与 `/rebase-fixed`（1042 个 pe 测试全绿）。
   但其存在的**唯一理由**——"产物跨 ASLR 重启可加载"——**仍未实弹验证**。走 TASK-006（重脱壳根治，老板已批 D-011）。
   **worker 自曝的未验证点**：`cleanup_artifact` 用 `section.virtual_address` 直接当 buf 偏移的假定在真实 dump 产物（VA != raw offset 的 .data 节）上未验证——实弹时注意。
2. **`core_perfect_candidate.dll` 的 Run verdict = PARTIAL**：业务链走到 GUI 消息循环即止，`URLDownloadToFileA` 实际调用点从未触发。
3. **T0.5 Run UI 事件驱动补测 = 双重阻塞**：旧宿主 `36043cb4` 跨 ASLR 重启即 AV（BLOCKED_ENV）；新重脱壳候选 `bb5ee568` 当前会话启动即 AV（dump 重建缺陷 A，C-4）。硬前置 = TASK-009 → TASK-006 复跑。**缺陷 A 修复前不消耗实弹格重跑**。
4. **GVM Phase 1（反虚拟化主攻线）**：调度循环已还原、handler 候选 172 个，但 VM 字节码缓冲区 `0x184eb6` 在 dump 中全零未物化、取指核心是运行时动态代码 → "抽字节码→推演→对拍"未闭环，门 1（自洽 ISA 规格书）未过。账本 GVM 0/8。
   **自带一条必须修正项**：`0x8c000-0x8cfff` 两源 trace exec=0，与既有"0x8c4c0 主译码器 216K+ trace 实证"矛盾，尚未归属复核。
5. **GTO preflight lane（G3）**：离线实现完整、测试覆盖，但**从未跑过真实 GTO 样品**。
6. **`production_thunk_call_does_not_leak_thread_handles`**：并行下 flaky，单独跑通过，未定位。本次全量跑 0 failed，未复现。

### 治理缺口（本次接管新发现，不属于代码功能）

1. **`tools/check_clippy_baseline.ps1` 会软通过**：它明确忽略 clippy 的非零退出码（第 49-50 行注释"clippy may exit non-zero on deny-level lints; still parse warnings"），只比较警告计数。
   本次实测：clippy 因缺 MSVC 环境退出 101、产出 0 条警告，脚本仍打印 `OK: clippy warn baseline holds`。
   **编译失败 = 0 警告 = 门禁全绿。** 这是体系里唯一一个会自己放水的门。见 TASK-003。
2. **两个互相打架的 MSVC 环境入口**：`tools/_enter_msvc_env.ps1` 依赖已被沙箱拦截的 `VsDevCmd.bat` 且写死 Professional 路径；`tools/xx21_msvc_env.cmd` 写死 MSVC 版本号 `14.44.35207`（且行尾为 LF，被 cmd 误解析成 `D:\bin\Hostx64\x64\link.exe`）。本次新增经实测可用的 `tools/_enter_msvc_env.cmd`。
3. **master 分支落后 557 个提交**（最后提交 2026-07-16），`origin/master` 落后更多（2026-07-09）。所有产出都在 `oreans/two-sample-mainline`，且本地还领先 origin 14 个未推送提交。
4. **无工单台账、无执行归档、无决策记录**：`docs/TASK_BOARD_20260829.md` 事实上在充当台账，但每天换文件名（`*_20260829.md`），下一个会话找不到入口。本次已改为固定文件。

## 历史断崖 [推断]

没有人员流失型断崖。647 次提交里 634 次是同一个作者（`guoxing2024`）、13 次是 `pi`，提交密度从 2026-07-07 起持续走高（8 月 20-23 日峰值 42/31/41/64），最近三天 12/34/6。
这是**单人 + AI 会话高强度推进**的形状，不是团队解体的形状。真正的风险不是"没人维护"，而是**所有上下文都靠一天一份的 `*_2026MMDD.md` 报告传递**——2026-08-26 一次性删掉了 40+ 个 `AUDIT_BATCH*.md`，说明这个模式已经撞过墙一次。

## 我判断的前三件事（按优先级）

1. ~~P0 — 落地在飞的工作区~~ **已完成**（2026-08-29，8 个本地提交；推送按老板裁定 D-010 停在本地）。
2. ~~P0 — TASK-003：堵住 `check_clippy_baseline.ps1` 的软通过~~ **已完成 R2**（2026-08-29，四条验收由总指挥亲自复跑全过：链接失败 exit 3 / E0308 注入 exit 3 / 镜像基线 exit 0 / deny 不误杀 exit 0；归档 `runs/20260829-TASK-003-R2.md`）。
3. ~~P1 — TASK-008：清还 clippy 基线漂移~~ **已完成**（2026-08-29，10 个机械位点最小修复，基线 349→337 只降不升；三条验收由总指挥亲自复跑全过：门禁 exit 0 / 全量测试 2801 passed 0 failed / fmt exit 0；归档 `runs/20260829-TASK-008.md`）。
4. ~~P1 — TASK-004：T0.7 可离线闭环~~ **已完成**（2026-08-29，六条验收由总指挥亲自复跑全过：pe-lib 1042 passed / cli-lib 572 passed / clippy-deny exit 0 / fmt exit 0 / `--help` 可见 / 判别力探针红→绿；归档 `runs/20260829-TASK-004.md`）。
5. ~~P1 — TASK-009：修 dump 重建缺陷 A（fail-open）~~ **已完成（离线级）**（2026-08-29）。TASK-006 实弹验收发现重脱壳候选 `bb5ee568` 启动即 AV：`.rdata 0x1137d0` 槽被固化 `0x1401681d1`（指向自身 .pdata，NX），启动期 `call [0x1137d0]` 跳进去；管线在 IAT 重建不完整（`Unresolved=74`）时仍打印 `[GOOD] Candidate written`。修复 = 兜底清零 + fail-closed 门（恰 3 授权文件 +352/-0）。归档 `runs/20260829-TASK-009.md`；**实弹替换验证仍未做**（TASK-006R 未到达 dump）。
6. ~~P1 — TASK-011：修 C-7（text-poll 阶段无 AV 风暴终止）~~ **已完成（离线级）**（2026-08-29）。guardless 路径恒同元组计数（元组变化即清零）→ 超阈值 `storm_abort` → host 转 `Err` fail-closed（不 dump、不打 `[GOOD]`、日志有界）。4 授权文件 +281/-0 纯新增，`.text`-stable 判定零改动；5 条验收命令（真 cargo 退出码）与判别力探针由总指挥亲跑/独立重做全过。归档 `runs/20260829-TASK-011.md`。
7. ~~P1 — TASK-012：C-7 修复加固~~ **已完成（离线级）**（2026-08-29）。阈值 `32` 对硬 fail-closed 裕量偏薄（实测双峰：健康 0 次 / 风暴 20 万–322 万次；Themida 异常式混淆的紧循环里 >32 次合法恒同 AV 结构上可能 → 误杀就白烧一格）→ 改为 **1024**，doc 写明"后果更重的判据不借用软着陆判据的阈值"；常量改名 `GUARDLESS_AV_STORM_TUPLE_THRESHOLD`；host 腿抽出纯函数 `map_storm_abort` + 2 个单元测试（cli lib 572→574）。恰 3 授权文件 +94/-32。归档 `runs/20260829-TASK-012.md`。

**等老板批的实弹工作（离线侧已无待办）**：TASK-006R 复跑（需再批 1 格，会到 XC-XXI-B 4/4；一格同时验缺陷 A 修复 + C-7 中止的实弹效果）、TASK-007（GVM 定向 dump 一格，D-012 已批，开跑前须交"写定五项"）。
**TASK-006R 首跑（2026-08-29）：BLOCKED（验证点不可达）**——构建/身份/ASLR 三关 PASS，重脱壳 9/9 次在本会话 text-poll AV 风暴不收敛（debuggee image_base 恒 0x7ff799fc0000 ≠ 上次 0x7ff6c0c60000），dump 从未到达，三个 TASK-009 证据点 0 命中、无产物；路径 A/B 均未到达（非修复失败，是路线阻塞）。**根因已由 TASK-010 定性 (c) 并落到 C-7，修复见 TASK-011/012。** T0.5 继续 BLOCKED。归档 `runs/20260829-TASK-006R.md`。

**TASK-006R2（2026-08-29/30，1 格，终态 = 路径 C）**：**C-7 风暴终止实弹验证通过** —— 2/2 次主动 fail-closed 中止、AV 恰 1024、19.6/23.9ms、日志 ~312KB、无产物无残留（对照首跑 9/9 烧到外部超时、3.5GB 日志）。**缺陷 A 验证点仍不可达**（C-7 中止在 dump 之前，三个证据点 0 命中，非修复失败）。授权口径见 D-015。归档 `runs/20260829-TASK-006R2.md`。

## 下一步

① 老板裁定 D-015 授权口径 + 是否扩额 → ② **重启机器**（本 boot 11/11 确定性撞同一 ScyllaHide NtContinue-hook 环，同 boot 重试无证据支持会不同；但重试成本已降到 20ms/312KB）→ ③ TASK-006R3 验缺陷 A 路径 A/B → ④ T0.5 续跑 → ⑤ TASK-007。
另有两个可另立的专项：ScyllaHide-NtContinue-hook 交互的微指令级定性（需实弹 trace）、C-5 缺陷 B（会话绑定，`/session-clean` 消费端）。
推送时机由老板定；推送前建议补跑 `cargo deny check advisories`（本机离线跑不了）。
