# DECISIONS — 决策记录

> 最后更新：2026-08-29。一条决策一节，写清"为什么"和"代价"。已被推翻的决策**不删**，标记为「已推翻」并指向新决策。

## D-001 GTO dump 路线判死，转 VM 语义还原（GVM-0）

- **日期**：2026-08-22 判死 / 2026-08-28 裁决转向（老板签署，`docs/GVM-0_RULING_20260828.md`）
- **决策**：`gto_launcher` 不再尝试 dump 路线；改为还原 VM 解释器/handler 语义并重建原生镜像，分三个带门的阶段推进。
- **理由**：LIVE-2（被动等待 60s）与 LIVE-3（真实执行 300s）都产出零个新解密页，覆盖率恒定 4.26%，距经济门差 14 倍。逐页惰性解密意味着任何独立重跑必然踩密文页 —— dump 路线是结构性不可达，不是调参问题。
- **代价与风险**：老板已被明确告知这是三条路里最难的一条（门 1 通过率约 60-70%，全路径 40-50%），周期 2-4 / 3-6 / 4-8 周。Phase 1 的产出（ISA 规格书）无论门是否通过都有价值。
- **约束**：仅限已锚定样品，隔离环境，产出入 vault，全程 `NO_BYPASS=1`。

## D-002 acceptance 内核与生产代码硬隔离

- **决策**：`mida-acceptance` 不得依赖任何生产 crate；R0B 永不输出 `Accepted`，只做静态结构评估。
- **理由**：如果验收内核复用生产代码，生产代码的错误会同时污染判定，"独立验收"就失去意义。
- **代价**：PE 解析等逻辑要在 acceptance 里重写一遍（约 30.9k 行）。由 `dependency_boundary.json` 自动守边界。

## D-003 clippy 门禁分阶段推进 + 警告基线只降不升

- **决策**：CI 不用 `RUSTFLAGS=-D warnings`；改为按批次把单个 lint 提升到 `-D`（phase 0 `dbg_macro` → 1 `unwrap_used` → 2 `expect_used` → 3 `manual_let_else`，均已 ACTIVE），其余 warn 级 lint 用 `_clippy_baseline` 单调计数锁住。
- **理由**：一次性开 `-D warnings` 会在代码清理完成前直接锁死构建。
- **代价**：门禁逻辑变复杂，并且引入了一个会软通过的脚本（见 `KNOWN_ISSUES.md` G-1，待 TASK-003 修）。

## D-004 测试代码里的 `unwrap`/`expect` 不算技术债

- **决策**：clippy 的 `unwrap_used`/`expect_used` 门禁只检查 `--lib --bins`（生产 target），测试 target 永远保持 warn 级。
- **理由**：测试里的断言式 `unwrap` 是惯例写法。已验证 cargo 1.97 不支持 `[workspace.lints.clippy]` 下的 `allow-in-tests`（unused manifest key），且 `cfg_attr(test, allow)` 在 `clippy --all-targets` 下不生效。
- **代价**：测试 target 的 4000+ 条警告永久存在，噪音大。

## D-005 样品身份是内容哈希，不是文件路径

- **决策**：`D:\Tools\RE\dumps\gto\启动器.exe` 这类可变路径只是"定位器"。执行前必须冻结为内容寻址快照，用 hash/size 作为 case 身份，与 `lab/cases/v2/*.json` 里封存的 `protected_input` 比对；不匹配即 `SampleIdentityMismatch` 并停止。
- **理由**：样品会被自动更新或替换。按路径执行等于随机执行一个未知二进制，所有历史证据会静默失效。
- **代价**：每次运行都要多做一次解析与校验；换样品必须走 manifest 修订评审。

## D-006 生产代码不得出现样品哈希/系统路径字面量

- **日期**：2026-08-29（老板指令："不要有硬编码，我们是通用型项目"）
- **决策**：样品哈希改由 `include_str!` 在构建期从 `lab/cases/v2/*.json` 读取；系统目录改 `GetSystemDirectoryW`/`GetWindowsDirectoryW` 派生（不假设系统盘是 `C:`）。manifest 不可解析时 **fail-closed**，不许静默走默认。
- **理由**：验收门的判定基准应当唯一来自 manifest；写死系统盘会让引擎在非 C: 盘系统上失效。
- **代价**：manifest 与代码产生构建期耦合（改 manifest 需重新编译）。
- **落地**：`tools/_hardcode_scan.py --gate` 已进 CI，`sample_hex`/`win_path`/`vault_path` 出现在生产代码即失败。

## D-007 GTO 重型恢复必须显式 opt-in

- **决策**：默认构建即可识别并路由 GTO 形状样品（G0/G1，与 Oreans 共用主干骨架），但真正的恢复阶段需要 `--features gto-product-recovery` + `--profile=ahk-gto-experimental`；未 opt-in 时 fail-closed 报错。
- **理由**：不能让一次普通 unpack 静默变成实验性 GTO 路径。
- **代价**：多一层 feature 组合要维护和测试。

## D-008 固定六份治理文件，禁止再造带日期的新文档

- **日期**：2026-08-29（本次冷启动接管）
- **决策**：只维护 `docs/00-START-HERE.md`、`PROJECT_STATUS.md`、`TICKETS.md`、`ARCHITECTURE_MAP.md`、`DECISIONS.md`、`KNOWN_ISSUES.md` 与 `AGENTS.md`；执行产出进 `runs/<日期>-TASK-xxx.md`；工单进 `tickets/`。
- **理由**：`docs/` 已积到 41 个 `.md`，且 2026-08-26 已经一次性删过 40+ 个 `AUDIT_BATCH*.md` —— 一天一份报告的传递方式撞过墙一次。失忆的 AI 员工需要**固定路径**，不是"最新那份日期文件"。
- **代价**：历史报告与固定文件可能不一致；冲突时以固定文件为准（已写进 `00-START-HERE.md`）。
- **推翻**：`docs/TASK_BOARD_20260829.md` 停止更新，内容并入 `TICKETS.md`。

## D-009 「完成」的定义包含"目标已被验证"，不只是"代码已写完"

- **日期**：2026-08-29（本次冷启动接管）
- **决策**：工单只有在**它存在的理由**被验证之后才能标记完成。单元测试绿 + 门禁绿只是必要条件。若关键验证受环境限制无法执行，状态是「待验证」或「阻塞」，不是「完成」。
- **理由**：T0.7 的目标是"产物跨 ASLR 重启可加载"，交付时单元测试 1029 绿、门禁 0 error，被记为 ✅ 完成 —— 但跨重启这件事一次都没试过，而 T0.5 已经用实锤证明它还没解决。这种记法会让台账整体失真。
- **代价**：完成率数字会变难看。这是应该的。

## D-010 本地提交授权，推送单独把关

- **日期**：2026-08-29（老板裁定）
- **决策**：两天的在飞成果按逻辑分批**提交到本地** `oreans/two-sample-mainline`；**推送不做**，等老板逐次确认。
- **理由**：本地提交消除"机器故障即全丢"的风险，这是不可逆损失；推送是对外动作，老板要自己把关时点。
- **代价**：`origin/oreans/two-sample-mainline` 会持续落后（裁定时已落后 14 个提交，本次提交后缺口更大），CI 在推送前不会对这些改动跑任何验证 —— 门禁只能靠本机复跑，这是明确接受的代价。
- **约束**：不碰 `master`；不 `--amend`、不 `reset --hard`、不 `push --force`。

## D-011 授权对原版宿主重脱壳，根治会话绑定（T0.5 解锁路径）

- **日期**：2026-08-29（老板裁定）
- **决策**：授权在新的启动会话里对原版宿主 `xiongxiong.exe` 重新脱壳，产出与当前 ASLR 会话一致的宿主，从而解开 T0.5 的 `BLOCKED_ENV`。**但必须等 TASK-004 先把 sidecar 清洗链路的离线闭环验扎实**。
- **理由**：另一个选项（接受 Run verdict 长期停在 PARTIAL）等于承认"产物不可移植"这个引擎级缺陷不修。先验清洗链路再重脱壳，是为了避免拿一个未验证的修复去消耗实弹机会。
- **代价**：多一次完整脱壳战役的成本；重脱壳产物是新的候选身份，`xiongxiong_duokai` 的已关闭战役结论（rev2，2026-08-28）**不适用于**新产物，需要重新走 S1-S4。
- **落地**：`tickets/TASK-006.md`，前置 TASK-004。

## D-012 批一格 GVM 定向 dump 实弹（账本 GVM 1/8）

- **日期**：2026-08-29（老板裁定）
- **决策**：批准**一格**实弹定向 dump，目标是把 VM 字节码缓冲区 `0x184eb6` 的真实内容抓出来（它在现有 dump 里全零未物化），用于打通"抽字节码 → 推演 → 与 trace 对拍"，冲 Phase 1 门 1。账本从 GVM 0/8 变为 1/8。
- **理由**：另一个选项（把门 1 降级为"静态 ISA 骨架 + 抽样双证"）会让 Phase 2 的 lifter 建在推断之上 —— 那是把风险往后推，而不是消除。
- **代价**：一格不可回收的实弹机会。因此定向 dump 的触发时机、目标地址、落盘内容必须在开跑前写定，跑完无论成败都记账。
- **约束**：隔离环境，产出入 vault（`D:/MidaVault/lab/evidence/gvm/`），全程 `NO_BYPASS=1`，样品身份哈希不匹配即 STOP。
- **落地**：`tickets/TASK-007.md`。

## D-013 rustfmt 债务不全是在飞改动造成的

- **日期**：2026-08-29（本次接管，纠正我自己前一份报告的归因）
- **决策**：把 rustfmt 修复拆成两个提交 —— 一个只含"HEAD 本来就不合规"的 31 个文件（纯格式），一个含在飞改动自身的格式修复。
- **理由**：实测发现 `cargo fmt --all` 额外改动了 31 个**在 HEAD 上就已经不合规**的文件（`crates/packers/themida/` 下 8 个、`crates/pe/` 下 8 个、`crates/antidebug-runtime/` 下 4 个等）。也就是说 CI 的 fmt job 并不是被这两天的改动搞红的，**它在提交的树上就已经是红的**。我前一份报告把 216 处 diff 全归因于未提交工作，这一点是错的。
- **代价**：多一个提交。收益是将来 `git log` 能分清"格式债"和"功能改动"。

