# 00-START-HERE — 下次开机 30 秒接上

> 最后更新：2026-08-29（冷启动接管会话）

## 你是谁，先读什么

- **AI 员工**（拿到工单来干活）：读 [../AGENTS.md](../AGENTS.md) → 读你的 `tickets/TASK-xxx.md` → 开工。别读别的。
- **总指挥**（新会话接管项目）：读本文件 → [PROJECT_STATUS.md](PROJECT_STATUS.md) → [TICKETS.md](TICKETS.md)，然后抽查代码核对事实。

## 项目一句话

Windows PE 脱壳研究平台（Rust，221k 行，11 个 crate）。把受保护二进制还原成可加载、行为等价的 PE，每条结论都要有可复算证据。
**不是 1.0 产品，禁止宣称"完美/通用脱壳"。**

## 现在在做什么（2026-08-29）

主攻线是 **GVM-0 反虚拟化战役**（`gto_launcher` 的 VM 语义还原 → lifter → 整镜像去虚拟化，账本 GVM 0/8，Phase 1 门 1 未过；老板已批一格定向 dump 实弹 → `tickets/TASK-007.md`）。
`origin_macro` + `lunlun_software` 是必须一直绿的回归门。`xiongxiong_duokai` rev2 战役已于 2026-08-28 关闭。

## 最要紧的一件事

**TASK-009 已完成（2026-08-29，缺陷 A 离线级修复）**：dump 重建 fail-open 已堵——兜底清零（`zero_fill_iat_region`，IAT 未重建槽 honest hole）+ fail-closed 门（存在直接 call 指向不可解析槽 → 拒绝写出，`[GOOD]` 不再打印）。恰 3 授权文件 +352/-0，三条验收与两个判别力探针由总指挥亲自复跑全过（见 `runs/20260829-TASK-009.md`）。**注意：修复验证级别 = 离线**；`bb5ee568` 实弹替换验证留待 TASK-006 复跑。
**TASK-011 已完成（2026-08-29，C-7 离线级修复）**：text-poll 阶段的 AV 风暴终止已装上——guardless 路径按恒同元组 `(exc, target, exc_type, thread)` 计数、元组变化即清零，达阈值 → `storm_abort` → host 转 `Err` fail-closed（不 dump、不打 `[GOOD]`、日志有界）。4 授权文件 **+281/-0 纯新增**，`.text`-stable 判定零改动；5 条验收命令与判别力探针由总指挥亲跑/独立重做全过（见 `runs/20260829-TASK-011.md`）。**验证级别 = 离线**，真实风暴下的中止效果留待下一格实弹顺带观察。
**下一票：TASK-012**（C-7 加固：阈值 32 → 4 位数 + 常量拼写 `GARDLESS`→`GUARDLESS` + host 腿 `storm_abort→Err` 补测试，**纯离线零实弹**）——**必须在下一格实弹之前做完**：32 这个阈值对"硬 fail-closed"来说裕量太薄（健康侧实测 0 次 AV，风暴侧 20 万–322 万次），Themida 异常式混淆的紧循环里出现 >32 次合法恒同 AV 完全可能，误杀就白烧一格。工单 `tickets/TASK-012.md` 已写好待派。

**TASK-010 已完成（只读调查，定性 (c)）**：C-6 的基址差异与 AV 风暴**无因果**（同基址成败并存），两时段风暴不同型（04:0x = VM 取指环；21:1x = ScyllaHide NtContinue-hook 区故障环）；真正的放大器是引擎缺口 **C-7**——text-poll 阶段无风暴终止（guardless 无条件 Continue + `text_poll_start` 每事件重置致 30s idle 结构上永不触发）。见 `runs/20260829-TASK-010.md`。
**TASK-006R 执行结果（2026-08-29）：BLOCKED（验证点不可达）**——构建核验/身份核验/ASLR 基线三关全过，但重脱壳 9/9 次在本会话 text-poll 阶段全部陷入 ntdll 内部 AV 风暴（exc=0x7ffa95400bd8，debuggee image_base 恒为 0x7ff799fc0000 ≠ 上次 0x7ff6c0c60000），`.text` 永不 stable，dump 阶段从未到达：`TASK-009 zero-filled IAT region` / `TASK-009 fail-closed` / `[GOOD] Candidate written` 三个证据点全部 0 命中，无产物。路径 A/B 均未到达（不是修复失败，是路线阻塞）。见 `runs/20260829-TASK-006R.md`。
**TASK-005 已完成（定级 (b)）**：0x8c4c0 静态存在但 trace 未激活，"216K+ trace 实证"标注作废、降级为静态推断；主链 0x8f099→0x8f374→0x9150d 不受影响，TASK-007 的 dump 目标理由仍成立（GVM 仍 0/8）。
**流程新规（P-4）**：产物固化类工单必须含"当场存活探针"——产物写完立即跑一次，非 0/259 即阻塞上报。
（推送按老板裁定停在本地，等他逐次确认；推送前建议补跑 `cargo deny check advisories`。）

工单顺序（**串行派发，同一时间只派一单**——D-014）：TASK-012（C-7 加固，离线）→ 之后才考虑再烧实弹格复跑 TASK-006R → T0.5 → TASK-007。TASK-005/009/010/011 已完成；TASK-006R 已收口（BLOCKED，验证点不可达，实弹 3/4）。

## 30 秒把它跑起来

```bash
cd "D:/Claude project/magicmida-rs"
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\ncargo test --workspace --offline\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

期望：`65 个 target / 2801 passed / 0 failed / 2 ignored`，`EXIT=0`。
**不要**直接在 Git Bash 里 `cargo test`：`link.exe` 会解析到 Git 的 GNU coreutils，链接必失败。`cargo fmt` / `cargo check` 不受影响。
`tools/_enter_msvc_env.cmd` 同时会设 `CARGO_INCREMENTAL=0` —— 增量编译会让 rustc 1.97.1 在 `mida-disasm` 上 ICE（`KNOWN_ISSUES.md` E-5）。

**注意 `tools/verify_workspace_hygiene.ps1` 在本机永远 exit 1**，这是本机杂物（`target/`、1.3 GB 实弹证据、`__pycache__`）导致的，
不代表 CI 红；它不能当推送前自检。判读方式见 `KNOWN_ISSUES.md` G-5。

## 固定的六份文件（只维护这些，禁止新增同类文档）

| 文件 | 作用 |
|---|---|
| [PROJECT_STATUS.md](PROJECT_STATUS.md) | 现状、存活状态、三态清单、前三件事 |
| [TICKETS.md](TICKETS.md) | 工单台账（唯一权威列表） |
| [ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md) | 哪个功能在哪个文件（写工单时先查这里） |
| [DECISIONS.md](DECISIONS.md) | 决策记录，为什么选了这条路 |
| [KNOWN_ISSUES.md](KNOWN_ISSUES.md) | 历史坑 + 当初为什么那么做 |
| [../AGENTS.md](../AGENTS.md) | AI 员工守则 |

`tickets/` 一个工单一个自包含文件；`runs/` 每次执行的产出归档。

## 会话结束前必做

1. 更新 `PROJECT_STATUS.md` + `TICKETS.md`
2. 执行产出归档到 `runs/<YYYYMMDD>-TASK-xxx.md`
3. 新决策进 `DECISIONS.md`，新坑进 `KNOWN_ISSUES.md`
4. 回头看本文件的"现在在做什么"和"最要紧的一件事"还准不准

## 历史文档在哪

`docs/` 下 41 个 `*_2026MMDD.md` 是历史报告，**不是**现状。当它们和上面六份文件冲突时，以上面六份为准。
其中仍有参考价值的：`GVM-0_RULING_20260828.md`（战役裁决）、`ACCEPTANCE_CONTRACT.md`（验收契约）、
`ARTIFACT_POLICY.md`（样品/产物不进 Git 的规则）、`GTO_SAMPLE_REVISION_POLICY.md`（样品身份解析）。
`docs/TASK_BOARD_20260829.md` 是本次台账的前身，内容已并入 `TICKETS.md`，不再更新它。
