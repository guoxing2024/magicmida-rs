# TICKETS — 工单台账

> 最后更新：2026-08-29　**本文件是工单的唯一权威列表。**
> 状态：📋 待领取 ｜ 🔧 执行中 ｜ ✅ 完成 ｜ ⏸ 阻塞 ｜ ↩ 已打回
> 「完成」的定义见 [DECISIONS.md](DECISIONS.md) D-009：代码写完 + 门禁绿 **不等于** 完成，工单存在的理由被验证了才算完成。

## 在办

| ID | P | 标题 | 状态 | 负责人 | 一条命令判生死 |
|---|---|---|---|---|---|
| [TASK-001](../tickets/TASK-001.md) | P0 | 修复 216 处 rustfmt 差异，让 CI 第一个 job 能过 | ✅ **完成**（2026-08-29，归档 [runs/20260829-TASK-001.md](../runs/20260829-TASK-001.md)） | 总指挥 | `cargo fmt --all -- --check` exit 0 ✅ |
| [TASK-002](../tickets/TASK-002.md) | P0 | 把在飞的两天成果分批提交（**只本地，不推送**） | ✅ **本地提交完成**（10 个提交，2026-08-29，归档 [runs/20260829-TASK-002.md](../runs/20260829-TASK-002.md)）；⏸ **推送待老板逐次确认**（D-010） | 总指挥 | `git status --short` 无未提交生产源码 ✅ |
| [TASK-003](../tickets/TASK-003.md) | P0 | 堵住 `check_clippy_baseline.ps1` 的软通过 | ✅ **完成 R2**（2026-08-29，归档 [runs/20260829-TASK-003-R2.md](../runs/20260829-TASK-003-R2.md)；四条验收由总指挥亲自复跑全过） | developer | 编译失败时脚本必须 exit≠0 |
| [TASK-004](../tickets/TASK-004.md) | P1 | T0.7 会话绑定修复：补齐可离线验证的闭环 | ✅ **完成**（2026-08-29，归档 [runs/20260829-TASK-004.md](../runs/20260829-TASK-004.md)；六条验收由总指挥亲自复跑全过，含独立重做的判别力探针红→绿） | developer | `cargo test -p mida-pe --lib --offline` 全绿且含新增闭环用例 |
| [TASK-005](../tickets/TASK-005.md) | P1 | GVM Phase 1：`0x8c000` 区归属矛盾复核 | ✅ **完成**（2026-08-29，定级 **(b)**：0x8c4c0 静态存在但 trace 未激活，"216K+ trace 实证"标注错误降级为静态推断；归档 [runs/20260829-TASK-005.md](../runs/20260829-TASK-005.md)；复算数字由总指挥亲跑复现一致） | qa | 复算脚本给出唯一结论并自证口径 |
| [TASK-006](../tickets/TASK-006.md) | P1 | 原版宿主重脱壳，根治会话绑定（解开 T0.5） | ⛔ **BLOCKED**（2026-08-29，归档 [runs/20260829-TASK-006.md](../runs/20260829-TASK-006.md)；重脱壳候选 `bb5ee568` 启动即 AV，根因 = dump 重建缺陷 A + 会话绑定残留 B，四项关键声明总指挥亲验坐实；实弹计 1 格 XC-XXI-B 2/4） | developer | 新宿主 S3 load_no_crash 10/10 隔离运行 |
| [TASK-009](../tickets/TASK-009.md) | P1 | 修 dump 重建缺陷 A：不可解析运行时指针固化进只读节（fail-open） | 📋 待领取（TASK-006/T0.5 复跑的硬前置） | developer | `cargo test -p mida-pe --lib --offline` 全绿含缺陷捕获用例 |
| [TASK-007](../tickets/TASK-007.md) | P1 | GVM Phase 1 定向 dump 实弹（账本 GVM 1/8） | 📋 待领取（开跑前须先交"写定五项"）；授权已批 D-012 | developer | `0x184eb6` 处字节非全零 |
| [TASK-008](../tickets/TASK-008.md) | P1 | 清还 clippy 基线漂移（10 个机械位点，推送前必做） | ✅ **完成**（2026-08-29，归档 [runs/20260829-TASK-008.md](../runs/20260829-TASK-008.md)；三条验收由总指挥亲自复跑全过，基线 349→337 只降不升） | developer | 基线脚本 exit 0 + `TOTAL=337` |

## 老板已裁定（2026-08-29）

| 议题 | 裁定 | 落地 |
|---|---|---|
| 在飞成果如何落地 | **只授权本地提交，推送等老板逐次确认** | D-010；TASK-002 已完成本地提交，停在未推送状态 |
| T0.5 环境阻断怎么解 | **授权新会话对原版宿主重脱壳**（根治），但须等 TASK-004 先把清洗链路验扎实 | D-011；TASK-006 |
| GVM 门 1 过不去怎么办 | **批一格定向 dump 实弹**，账本 GVM 0/8 → 1/8 | D-012；TASK-007 |

## 阻塞（等前置或环境）

| ID | 标题 | 卡在哪 | 解锁条件 |
|---|---|---|---|
| T0.5 | Run UI 事件驱动补测（Run verdict PARTIAL→FULL） | **双候选宿主均不可用**：旧 `rev2_unpacked.exe`（`36043cb4`）跨 ASLR 重启即 AV（BLOCKED_ENV）；新重脱壳候选 `bb5ee568` 当前会话启动即 AV（dump 重建缺陷 A，C-4） | 硬前置 = TASK-009（修缺陷 A）→ TASK-006 复跑（重脱壳 + S1-S4 + 10 次隔离）→ T0.5 续跑。**缺陷 A 修复前不消耗实弹格重跑**（TASK-006 建议已采纳）。重跑脚本 `tools/xx21b_t05_ui_drive.py` 已就绪 |
| GVM 门1 | Phase 1 自洽 ISA 规格书 | VM 字节码缓冲区 `0x184eb6` 在 dump 中全零未物化；取指核心是运行时动态代码（`0x8f099` 间接 call） | ~~建议先做 TASK-005~~ **TASK-005 已完成（定级 (b)：0x8c4c0 静态存在但 trace 未激活，主译码器"trace 实证"标注作废，ISA v1 须按静态推断写证据等级）——dump 目标不受复核推翻，定向 dump 理由仍然成立**。老板已批一格定向 dump（D-012）→ TASK-007（开跑前须先交"写定五项"） |

## 已完成（本次接管前，2026-08-29 及以前）

已核对代码存在、且验收证据完整的项。**注意：以下第 1-6 项的代码改动全部处于未提交状态**，见 TASK-002。

| 原 ID | 标题 | 本次抽查结论 |
|---|---|---|
| T0.8 | 样品哈希改从 manifest 读取（3 处 → 0） | ✅ 已核对：`origin_pure.rs:45-46` 用 `include_str!` 嵌入 `lab/cases/v2/origin_macro.json` 并解析 `protected_input`；`oreans_gate.rs` 锁只留 `case_id`+`manifest_path` |
| T0.9 | 系统目录改 API 查询（3 处 → 0） | ✅ 已核对：`dll_exports.rs:263-290` `system_dll_search_dirs()` 用 `GetSystemDirectoryW`/`GetWindowsDirectoryW`，非 Windows 返回空表 |
| T0.10 | CLI 示例地址通用化 | ✅ 已核对：`mida-cli --help` 实际输出 `0x140000000,0x200 (generic PE32+ image-base example)` |
| T1.1 | 修 mida-cli 生产 unwrap 导致门禁失败（11 处） | ✅ 已复跑：clippy 生产门禁 exit 0 |
| T1.2 | 清理 mida-cli 9 个 rustc 警告 | ✅ 已复跑：`cargo check --workspace --tests` exit 0 |
| T0.1 | 样品线文档同步（core.dll 入线，旧样品作废） | ✅ 已核对 README 与 manifest schema |
| T0.4 | core.dll 完美候选产出化（XC-XXI-B） | ✅ S1-S4 全 PASS，候选 sha256 `3650ea6c…`；但 Run verdict 仍是 PARTIAL（见阻塞区 T0.5） |
| T0.6 | GVM Phase 1 第一批离线测绘 | ✅ 交付了调度循环还原 + 172 个 handler 候选；门 1 未过，自带一条必须复核项 → TASK-005 |

## 降级（原记「完成」，本次接管改判）

| 原 ID | 标题 | 为什么降级 | 去向 |
|---|---|---|---|
| T0.7 | 引擎会话绑定根治（data_reinit 会话系统 DLL 基址表清洗） | 代码就绪、1029 个 pe 测试绿、门禁 0 error —— 但工单存在的**唯一理由**"产物跨 ASLR 重启可加载"从未实弹验证过（原报告自己标了"待验证项"）。按 D-009，这是半成品 | 拆成 TASK-004（可离线验证部分）+ T0.5 阻塞项（实弹部分） |

## 未排期（低优先，别为它中断主线）

| 原 ID | 标题 | 位置 |
|---|---|---|
| T2.1 | 生产代码 8 处 TODO 逐条决议（实现/转跟踪/标记已知限制） | `cli/src/unpacker/mod.rs:2165-2171`、`core/src/process.rs:704`、`packers/themida/src/iat/boundaries.rs:422,474`、`pe/src/dumper/tls_bootstrap.rs:115` |
| T2.2 | 裸 `#![allow(clippy::unwrap_used)]` 补文档注释 | `crates/core/src/adr7_b4_observer.rs:8` |
| T3.1 | 源码注释编码乱码 | `crates/core/src/windows_debugger.rs:89`（`闁?`） |
| T3.2 | `pin.log` 外部工具链告警归档 | 根目录 `pin.log`（Intel PIN 加载失败 C00000D8） |
| — | `production_thunk_call_does_not_leak_thread_handles` 并行下 flaky | 本次全量跑 0 failed，未复现；保持观察 |

## 跟踪规则

1. 工单必须自包含：粘进任何新 AI 会话就能开工，不需要口头补充。粒度 ≤5 个文件、一条命令能判生死。
2. 完成时更新本文件状态 + 在 `runs/<日期>-TASK-xxx.md` 留执行归档（含命令原始输出）。
3. 影响 clippy 基线的改动，同 commit 更新 `_clippy_baseline`（只降不升）。
4. 同一验收标准连续 2 次不通过 → 停止重派，判定工单本身有问题，回到拆解环节重写。
5. 发现改测试降断言 / 注释用例 / 加 `#[ignore]` → 即判失败并记入 `KNOWN_ISSUES.md`。
