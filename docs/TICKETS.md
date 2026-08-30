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
| [TASK-009](../tickets/TASK-009.md) | P1 | 修 dump 重建缺陷 A：不可解析运行时指针固化进只读节（fail-open） | ✅ **完成**（2026-08-29，归档 [runs/20260829-TASK-009.md](../runs/20260829-TASK-009.md)；恰 3 授权文件 +352/-0，三条验收与两个判别力探针由总指挥亲自复跑全过；修复 = 兜底清零 + fail-closed 组合） | developer | `cargo test -p mida-pe --lib --offline` 全绿含缺陷捕获用例 |
| [TASK-006R](../tickets/TASK-006R.md) | P1 | TASK-006 复跑：实弹验证缺陷 A 修复（构建核验→重脱壳→路径 A/B 二分；fail-closed 拒绝出产物也是合法终态） | ⛔ **BLOCKED（执行完毕，验证点不可达）**（2026-08-29，归档 [runs/20260829-TASK-006R.md](../runs/20260829-TASK-006R.md)；构建/身份/ASLR 基线三关 PASS，但重脱壳 9/9 次 text-poll AV 风暴不收敛，dump 从未到达，三个 TASK-009 证据点 0 命中、无产物；路径 A/B 均未到达；实弹计 1 格 XC-XXI-B 2/4→3/4） | developer | 构建核验双字符串命中 + 身份核验 PASS + 重脱壳完整日志（9 次尝试全风暴） |
| [TASK-007](../tickets/TASK-007.md) | P1 | GVM Phase 1 定向 dump 实弹（账本 GVM 1/8） | 📋 待领取（开跑前须先交"写定五项"）；授权已批 D-012 | developer | `0x184eb6` 处字节非全零 |
| [TASK-008](../tickets/TASK-008.md) | P1 | 清还 clippy 基线漂移（10 个机械位点，推送前必做） | ✅ **完成**（2026-08-29，归档 [runs/20260829-TASK-008.md](../runs/20260829-TASK-008.md)；三条验收由总指挥亲自复跑全过，基线 349→337 只降不升） | developer | 基线脚本 exit 0 + `TOTAL=337` |
| [TASK-010](../tickets/TASK-010.md) | P1 | 调查 C-6：重脱壳 text-poll AV 风暴与 debuggee 基址分配差异的因果链（**只读，零实弹**） | ✅ **完成**（2026-08-29，定性 **(c) 共因表象 + 引擎缺口**：基址非因（同基址成败并存）、21:1x 风暴 = ScyllaHide NtContinue-hook 区故障环、04:0x 风暴 = VM 取指环，两型不同；**核心新发现 = text-poll 无风暴终止机制** → C-7；归档 [runs/20260829-TASK-010.md](../runs/20260829-TASK-010.md)；关键声明由总指挥亲验：dumpbin 字节逐一致、scylla_hide.log hook 地址坐实、fixed2 3,220,146 次 AV 元组相符、三份日志同基址成败并存、代码引用 6 处全对） | qa | ntdll+0x160bd8 定性 + 基址漂移机制清单 + 最终定性 (a)-(d) |
| [TASK-011](../tickets/TASK-011.md) | P1 | 修 C-7：text-poll 阶段增加 AV 风暴终止（fail-closed，**纯离线零实弹**） | ✅ **完成**（2026-08-29，归档 [runs/20260829-TASK-011.md](../runs/20260829-TASK-011.md)；4 文件 **+281/-0 纯新增**，`.text`-stable 判定与既有断言零改动；诊断 4 处引用亲验一致；5 条验收命令由总指挥用**真 cargo 退出码**复跑全过（themida lib 167 / 集成 12→16 / mida-pe 1049 持平 / clippy 三 -D 0 error / fmt）；判别力探针由总指挥**自选另一种回退**独立重做（streak 永不累加 → 恰 2 风暴用例红 exit 101、防误杀+守卫回归 14 绿 → 字节级恢复 → 16/16 绿）；**验证级别 = 离线**，实弹中止效果未验） | developer | 恒同 AV 元组超阈值 → `Err` fail-closed，不 dump、不打 `[GOOD]` |
| [TASK-012](../tickets/TASK-012.md) | P1 | C-7 修复加固：风暴阈值裕量（32→**1024**）+ 常量拼写 `GARDLESS`→`GUARDLESS` + host 腿 `storm_abort→Err` 补测试 | ✅ **完成**（2026-08-29，归档 [runs/20260829-TASK-012.md](../runs/20260829-TASK-012.md)；恰 3 授权文件 +94/-32，`mod.rs` 未碰、`.text`-stable 继续零改动；6 条验收由总指挥用**真退出码**复跑全过（themida 集成 16 / cli --lib 572→574 / pe 1049 持平 / clippy 三 -D 0 error / fmt）；判别力由总指挥**自选两种**回退独立重做（去掉 count → `must carry the count` 红；`Some` 臂永不命中 → `must fail closed` 红，均 exit 101）→ 字节级恢复 → 2/2 绿；**仍是离线级**，1024 未经实弹校准） | developer | host 腿映射有直接测试且判别力可证 + 既有 16 用例全绿 |
| [TASK-006R2](../tickets/TASK-006R2.md) | P1 | TASK-006R 二次复跑：一格实弹**同时**验缺陷 A 修复与 C-7 风暴终止 | ✅ **完成（终态 = 路径 C）**（2026-08-29/30，归档 [runs/20260829-TASK-006R2.md](../runs/20260829-TASK-006R2.md)；三关 PASS；**C-7 风暴终止实弹验证通过**：2/2 次主动 fail-closed 中止、AV 恰 **1024**、19.6/23.9ms、日志 ~312KB（首跑 3.5GB 的 0.009%）、无产物无残留；**缺陷 A 验证点仍不可达**（三个证据点 0 命中，非修复失败）；证据由总指挥直读 vault 复核：四条门字符串各命中 1、两份日志 AV 计数各 1024、样品身份 `78009803…` 与 manifest 一致；实弹 3/4 → **4/4**，授权口径见 D-015） | developer | 四条字符串命中 + 身份核验 PASS + 明确终态判定（A/B/C）|
| [TASK-006R3](../tickets/TASK-006R3.md) | P1 | **重启后**再验缺陷 A（路径 A/B）——本 boot 11/11 确定性撞同一 hook 环，必须换 boot | ✅ **完成（终态 = 路径 C）**（2026-08-30，归档 [runs/20260830-TASK-006R3.md](../runs/20260830-TASK-006R3.md)；授权令牌已回抄；**换 boot 没换掉故障环**——新 boot ASLR 全变但风暴 RIP 恒 = ScyllaHide NtContinue hook +8，累计 13/13 跨 3 boot；C-7 再次 2/2 主动中止（AV 恰 1024、20ms、312KB、无产物无残留）；**缺陷 A 三证据点仍 0 命中 → 结构性不可达**；证据由总指挥直读 vault 复核：两份日志 AV 各 1024、恒同元组 `sort -u` 各 1 条、三证据点各 0、hook 地址 +8 算术对上、样品仍走 vault 对象 `78009803…`；实弹 4/4 → **5/4**）| developer | text-poll 收敛到 dump 阶段 + 三个 TASK-009 证据点有命中 |
| [TASK-013](../tickets/TASK-013.md) | P1 | 把 ScyllaHide 的 hook 选择变成可控、可记录的配置（**纯离线零实弹**）——缺陷 A 实弹验证的硬前置 | ✅ **完成**（2026-08-30，归档 [runs/20260830-TASK-013.md](../runs/20260830-TASK-013.md)；恰 3 授权文件 +283/-4，零实弹；9 条验收由总指挥亲验全过：真退出码四连（cli lib 574→**580** / pe **1049** 持平 / clippy 三 -D / fmt 全真 0）+ 判别力总指挥**换接缝**独立复测（纯函数坍缩 → 4 用例红 exit **101** → cmp 字节级恢复 → 6/6 绿）；**核心发现 = InjectorCLI 裸相对名只搜 Windows 目录**（导入表亲验 4 个 cwd/path API 全 0 命中），工单前提"参考 ini 无 NtContinueHook 键"被 worker 如实纠正（两份参考都有 =0，总指挥 grep 复核坐实）；受控 ini 入 vault 逐键一致 42/42；C:\Windows 无残留核验通过） | developer | 给 ini → 配置来源被记录；不给 → 记录为"无 ini 全默认"，且判别力可证 |
| [TASK-006R4](../tickets/TASK-006R4.md) | P1 | 带受控 ini（异常分发 hook 关闭）重跑重脱壳——缺陷 A 路径 A/B **首次真正可达** | ✅ **完成（终态 = STOP，落位方案结构性无效）**（2026-08-30，归档 [runs/20260830-TASK-006R4.md](../runs/20260830-TASK-006R4.md)；授权令牌已回抄；**决定性发现 = TASK-013 的"只搜 Windows 目录"结论错误**：InjectorCLI 用 `GetModuleFileNameW` 读 `<exe目录>/scylla_hide.ini`（总指挥独立反汇编复验：IAT 槽 0x6f150=GetModuleFileNameW / 0x6f158=GetPrivateProfileSectionNamesW 精确对上）+ notepad A/B/C 三实验；attempt1 因 ini 未生效**判无效**（强门生效，未被当成路径证据），未硬跑第 2 次；收尾满分（`C:\Windows` 已删净、vault 5 件、探针环境清零）；**根因在我这侧的验收失误 → 新 P-9**；实弹 5/4 → **6/4**）| developer | 受控 ini 真正生效前提下终态四选一（本单未达成有效尝试，如实 STOP） |
| [TASK-006R5](../tickets/TASK-006R5.md) | P1 | 改代码让受控 ini 真正生效（staging 落位 + sha256 校验 + 清理）+ 一格实弹重跑 | ✅ **完成（终态 = 路径 A）**（2026-08-30，归档 [runs/20260830-TASK-006R5.md](../runs/20260830-TASK-006R5.md)；授权令牌已回抄；**14 次实弹以来首次到达 dump**：受控 ini 经 staging 生效（NtContinue/KiUser hook 行双零 + 15 键对照）、0 次 AV（对照此前 14/14 次 1024 风暴）、text-poll 首次收敛、`TASK-009 fail-closed` 192 unresolved → 拒绝写产物、无产物；有效 2/2 即停（attempt1 因 P-8 证据缺口判无效，未当路径证据）；八条验收由总指挥真退出码复跑全过 + **换缝独立判别力探针**（打断 sha256 原语 → 2 红 exit 101 → 字节级恢复 → 7/7 绿）；实弹 6/4 → **7/4**，验收记 D-022） |
| [TASK-014](../tickets/TASK-014.md) | P1 | **v2**：IAT 启动路径**回归定位与恢复**（08-28 XX-11 已实证 186/186 + load 10/10 + S4 8/8；`18e0349`→`be28951` 窗口内退化到 0/201——先定位 flag/代码回归源再恢复）+ 一格实弹复现 XX-11 端点 | ✅ **完成（终态 = 路径 A'）**（2026-08-30，归档 [runs/20260830-TASK-014.md](../runs/20260830-TASK-014.md)；授权令牌已回抄；第一段八条全过 + 第二段 2/2 有效尝试确定性复现（强门四件套逐趟核对、0 AV、fail-closed 拒绝、192 站点全列 + 201 槽逐槽诊断）；**核心诊断 = 74 个启动路径槽是 Themida VM wrapper 地址**（静态回填结构性 0 命中，修正 D-024 的"回归"定性——静态回填 0 覆盖是结构性必然，真缺口在 shell trace 的执行线程/时机）；验收由总指挥独立复核：门语义零改动亲验、五套件真退出码复跑全 0（pe 1054/themida 175/cli 580/clippy/fmt）、**换缝独立判别力探针**（打断 slot_diagnostics → 2 红 exit 101 → 字节级恢复）、vault 直读 + 跨时代偏移互证（0x1681d1）；账本 7/4 → **8/4**，验收记 D-027） |
| [TASK-015](../tickets/TASK-015.md) | P1 | shell trace 线程/时机修复：74 个 VM wrapper 槽可解析（≥186 imports，恢复 XX-11 端点路径）+ 回归定位（`18e0349..291b239` trace 路径）+ acceptance crate serde default（限窄）+ 一格实弹冲 B1' | ✅ **完成（终态 = 路径 B1'，XX-11 端点恢复）**（2026-08-30，归档 [runs/20260830-TASK-015.md](../runs/20260830-TASK-015.md)；授权令牌已回抄；**主根因定案** = T0.5-R2 grace window 断点遗留其它线程 pending → TID mismatch → trace 从未单步（R5 日志 TID mismatch ×3、T014 被吞 ×0、XX-11 frozen-entry bootstrap 行三日志互证）；修复 = stale pending 按归属线程 continue 清生命周期再 bootstrap；实弹 2/2 有效尝试：**trace resolved=74/74、imports 186 整、结构门 12/12、load_no_crash 10/10 ×2、S4 标记（窗口标题"授权验证"/config.ini 26B/core.dll sha 09f3dd34 与 XX-10 vault 逐位一致）、产物 1,539,072 B 与 XX-11 同尺寸**；验收由总指挥独立复核：六套件真退出码全 0（pe 1054/themida 176/cli 580/acceptance 256/clippy/fmt）、**换缝独立判别力探针**（错 tid continue → 1 红 exit 101 → 字节级恢复）、vault 直读全链条（[GOOD] ×2 经 ANSI 核实、P-8 13:56<14:00、无残留）；账本 8/4 → **9/4**，验收记 D-029） | developer | 第一段八条全绿（回归定位报告 = 第二段通行证 + 判别力 + slot-scoped 真行为测试）；第二段强门（沿用）达成后终态 B1'/B2/A'/C/D 如实上报，B1' 对照 XX-11 端点（186/186 + load 10/10 + S4 8/8） |
| [TASK-016](../tickets/TASK-016.md) | P1 | **阶段收尾**：B1' 能力固化——硬编码审计清除（行为中性，先审后改）+ preflight 能力预检（无 ini 响亮失败）+ 复现 runbook + vault 索引 + 全仓回归快照（**纯离线零实弹**） | ✅ **完成**（2026-08-30，条件通过（D-031）→ R1 补正 → 终验收（D-032）整单入栈；8 标准补正后全 PASS：diff 6 授权文件、四套件真退出码 0 计数 1054/176/580/**263**、preflight readiness 7 用例（未接生产线=已披露限制）、总指挥换缝探针红→恢复、runbook 七判据对 vault 实证逐条一致、INDEX 抽验 6/34 sha 一致、零实弹账本 9/4 不变；审计抓到并经 R1 补正：F1 未申报搜索窗口加宽已逐位还原、F2 GTO-UI 既有锚区已入审计 §九；F3 基线门既有失败留老板裁定） | developer | 八条验收全绿（含硬编码审计报告含只读文件发现、preflight 判别力、runbook 一致性、全仓 workspace 全绿） |
| [TASK-016R1](../tickets/TASK-016R1.md) | P1 | **T016 审计补正（微型）**：F1 行为还原（`GAP_NAME_NEIGHBOR_MAX_DELTA` 64→63，`1..=` 语义逐位还原 pre-T016）+ F2 审计文档增补（GTO-UI 既有锚区清单入 `HARDCODING_AUDIT_T016.md` §九 + 全称命题改限定 + iat_completeness 路径勘误）；**D-030 范围内无新令牌不耗格，纯离线零实弹** | ✅ **完成**（2026-08-30，总指挥终审五条全亲验 PASS：增量仅 2 授权文件、F1 还原逐位核对、pe 1054/acc 263 重跑 0、§九 与审计发现逐项吻合、runs 增补诚实披露 +490；记 D-032，整单随 T016 入栈） | developer | 补正后 pe lib 1054 / acc lib 263 不变 + clippy(-D 三 lint)/fmt 0 + diff 仅 2 文件 + 零实弹自证 |
| [TASK-017](../tickets/TASK-017.md) | P1 | **T0.5 续跑**：熊熊 B1' 产物 Run UI 事件驱动补测（Run verdict PARTIAL→FULL，实弹 1 格 XC-XXI-B 9/4 → 10/4） | 🔶 **执行完毕，终态 = 工具性阻塞**（2026-08-30，记 D-034；实弹 3/3 次有效尝试记 1 格：动态基址适配实弹自证生效（三趟 core_base 各异且都解析成功）、B1' 产物 Run 实调用**到达 GUI 业务层**——PigToGoLicenseDialog"授权验证"出现、GUI 存活响应 3/3、无 AV、IAT 不变；**RIP 证据系统性不可得** = 本环境对非附加式 GetThreadContext 垫零（worker 六组探针 + 总指挥两条独立缝复核；调试端口路径实测可用，出路明确，入 P-11）；三态不可判按停止规则停，审计全 PASS：diff 无钉死残留、vault sha 一致、停止决策正确） | developer | 票面三态判定（因工具性阻塞未出，证据不可得如实上报；判定语义放宽需老板裁定） |



## 老板已裁定（2026-08-29）

| 议题 | 裁定 | 落地 |
|---|---|---|
| 在飞成果如何落地 | **只授权本地提交，推送等老板逐次确认** | D-010；TASK-002 已完成本地提交，停在未推送状态 |
| T0.5 环境阻断怎么解 | **授权新会话对原版宿主重脱壳**（根治），但须等 TASK-004 先把清洗链路验扎实 | D-011；TASK-006 |
| GVM 门 1 过不去怎么办 | **批一格定向 dump 实弹**，账本 GVM 0/8 → 1/8 | D-012；TASK-007 |

## 阻塞（等前置或环境）

| ID | 标题 | 卡在哪 | 解锁条件 |
|---|---|---|---|
| T0.5 | Run UI 事件驱动补测（Run verdict PARTIAL→FULL） | **TASK-017 已执行（2026-08-30，1 格，账本 10/4）**：B1' 产物 Run 实调用**到达 GUI 业务层**（"授权验证"对话框、GUI 存活响应 3/3、无 AV、IAT 不变）——行为面重大进展（旧基线连窗口都出不来）；但 RIP 判定证据不可得（P-11 环境垫零，仅限非附加式观测）。**出路已实测**：调试端口附加路径读得真实 RIP（总指挥 P2 探针）→ 待老板裁定：A' 批 1 格 harness 改调试端口泵重跑三态（推荐） / B 接受非 RIP 证据口径（不推荐） / C 挂起 | 脚本已就绪且动态化完成（D-034）；观测腿需改调试端口泵 |
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
