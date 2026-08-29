# PROJECT_STATUS — MagicMida vNext

> 最后更新：2026-08-29（冷启动接管会话）　更新人：总指挥
> 本文件是项目现状的唯一权威快照。工单台账见 [TICKETS.md](TICKETS.md)。

## 一句话结论

这项目是**活的**（647 次提交，最后一次提交 2026-08-28，2801 个测试全绿），
最要紧的一件事是：**过去两天所有"已完成"的成果（41 个改动文件 + 3 个新生产源文件、1906 行插入）全部只存在于本机未提交的工作区，且 `cargo fmt` 红 216 处，CI 第一个 job 就会失败。**

## 存活状态 [已验证]

| 项 | 结果 | 证据 |
|---|---|---|
| release 构建 | ✅ 通过（1m31s） | `build_release.log`，`BUILD_EXIT=0`；`target/release/mida-cli.exe` 5.7 MB，`--help` 正常输出 |
| 全量测试 | ✅ **65 个 target / 2801 passed / 0 failed / 2 ignored**，exit 0 | `cargo test --workspace --offline`（经 `tools/_enter_msvc_env.cmd`） |
| `cargo check --workspace --tests` | ✅ exit 0 | 同上环境 |
| clippy 门禁 1（`--all-targets -D dbg_macro`） | ✅ exit 0 | 同上环境 |
| clippy 门禁 2（`--lib --bins -D unwrap_used/expect_used/manual_let_else`） | ✅ exit 0 | 同上环境 |
| 硬编码门禁 | ✅ `HARD-CODING GATE PASS` | `python tools/_hardcode_scan.py --gate` |
| 工作区卫生门禁 | ✅ exit 0 | `tools/verify_workspace_hygiene.ps1` |
| **`cargo fmt --all -- --check`** | ❌ **失败，216 处 diff** | 见 KNOWN_ISSUES / TICKETS TASK-001 |
| CI 远端红绿 | ❓ 无法查证（本机无 `gh`） | 但 fmt job 是第一个 job → **[推断] 当前必红** |
| 依赖锁定 | ✅ Cargo.lock 81 包，cargo-deny 已配置 | `deny.toml` |

**结论：代码是绿的，仓库是红的。** 问题不在实现质量，在交付纪律。

## 家底 [已验证]

- Rust 221k 行 / 269 个 `.rs` 文件：生产 167.5k 行、测试 53.8k 行
- 11 个 workspace member（含 `lab/runtime/` 下 2 个，且**这 2 个成员是未提交状态**加进 `Cargo.toml` 的）
- 2795 个 `#[test]`；`#[ignore]` 仅 1 处；`todo!`/`unimplemented!` 仅 1 处（测试 mock）
- `TODO`/`FIXME`/`HACK` 8 处（cli 4、packers 2、core 1、pe 1）
- 文档：`docs/` 41 个 .md + 根目录 5 个 —— **文档通胀**，无入口、无台账（本次已建）
- 未提交：41 个 modified + ~35 个 untracked（含 3 个新生产源文件共 1259 行）

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

1. **T0.7 引擎会话绑定根治 —— 记为"✅ 完成"，实际是代码就绪、关键验收未做。**
   `data_reinit.rs` 已加会话模块表清洗 + `dump_process.rs` 归档 `.session_modules.json` sidecar，1029 个 pe 测试绿；
   但其存在的**唯一理由**——"产物跨 ASLR 重启可加载"——**从未实弹验证过**（原文自己写了"跨重启实弹验证受环境限制…标记为待验证项"）。
   → 本次接管把它从"完成"降级为"半成品"。见 TASK-004。
2. **`core_perfect_candidate.dll` 的 Run verdict = PARTIAL**：业务链走到 GUI 消息循环即止，`URLDownloadToFileA` 实际调用点从未触发。
3. **T0.5 Run UI 事件驱动补测 = BLOCKED_ENV**：宿主 `rev2_unpacked.exe` 因固化了旧会话 ntdll 绝对地址，重启后启动期即 AV。这是 T0.7 那个缺陷的实锤现场，也是它必须实弹验证的原因。**待老板决策。**
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

1. **P0 — 落地在飞的工作区（TASK-001 + TASK-002），预估 1.5h。** 理由：现在这台机器上任何意外都会让两天的成果归零，而且 CI 处于必红状态，红着的 CI 等于没有 CI。
2. **P0 — 堵住 `check_clippy_baseline.ps1` 的软通过（TASK-003），预估 0.5h。** 理由：一个会把编译失败读成"全绿"的门，比没有门更危险，因为它会让后面每一次放水都看起来合法。
3. **P1 — 把 T0.7 从"完成"改回"待验证"并补齐可离线验证的部分（TASK-004），预估 3h。** 理由：这是唯一一个"引擎级正确性缺陷"被记成完成的地方，而 T0.5 已经用实锤证明它还没解决。

## 下一步

我建议先做第 1 项。理由：它是唯一一个"不做就可能全丢"的风险，而且做完之后 CI 才能重新变成可信信号，后面所有验收才有依据。
