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
**TASK-012 已完成（2026-08-29，C-7 加固，离线级）**：风暴阈值 **32 → 1024**（理由：本判据后果是硬 fail-closed，不沿用软着陆的 32；实测双峰健康 0 次 / 风暴 20 万–322 万次，1024 对真风暴仍留 2–3 个数量级裕量，误杀窗口小两个数量级）；常量改名 `GUARDLESS_AV_STORM_TUPLE_THRESHOLD`；host 腿抽出纯函数 `map_storm_abort` + 2 个单元测试（cli lib 572→574）。恰 3 授权文件 +94/-32，`mod.rs` 未碰。见 `runs/20260829-TASK-012.md`。
**TASK-006R2 已执行（2026-08-29/30，1 格，终态 = 路径 C）：C-7 风暴终止实弹验证通过，缺陷 A 验证点仍不可达。**
2/2 次重脱壳在 text-poll 撞上恒同 AV 环时引擎**主动 fail-closed 中止**：AV 事件恰 **1024**（阈值精确生效）、首次 AV→中止 **19.6/23.9ms**、日志 **~312KB**（首跑 3.5GB 的 0.009%）、无产物、无残留进程。对照首跑"9/9 烧到外部超时"，C-7 缺口实弹坐实已堵上。但 C-7 中止发生在 dump **之前**，所以缺陷 A（TASK-009）的三个证据点仍 0 命中——**验证点不可达，不是修复失败**。见 `runs/20260829-TASK-006R2.md`。
**授权口径已裁定（D-015）：老板 2026-08-30 追认** —— XC-XXI-B **4/4** 成立。（起因：那一格是 worker 据「继续」开跑的，而工单和台账都写着"等老板批"。根因在总指挥这边：授权状态写在工单状态字段里，对失忆 worker 不可见。已立规：未授权实弹工单**正文第一行**写 ⛔ 硬拦，「继续」不构成授权。）
**TASK-006R3 已执行（2026-08-30，1 格，终态 = 路径 C）：换 boot 没换掉故障环 —— 缺陷 A 结构性不可达。**
新 boot（`01:28:40`）的 ASLR 全变（ntdll `0x7ffa952a0000`→`0x7ff857620000`、debuggee image_base `0x7ff799fc0000`→`0x7ff729430000`），但风暴 RIP **恒等于 ScyllaHide 的 NtContinue hook 地址 +8**（两 boot 各自自洽，偏移都是 ntdll+0x160bd8）。**同一现象在两套完全不同地址下复现 = 实锤：不是 ASLR 运气，是 ScyllaHide 的 NtContinue hook 与壳的异常分发确定性打架。** 累计 **13/13 次跨 3 个 boot**。C-7 再次 2/2 主动中止（AV 恰 1024、20ms、312KB、无产物无残留），但它在 dump 之前，所以缺陷 A 三个证据点仍 0 命中。见 `runs/20260830-TASK-006R3.md`。
**"重启后重试"这条路已经走到头**：TASK-006R2 时我把它列为"近乎免费的探测"，探测做了，结果阴性，关掉。
**TASK-006R4 已执行并验收（2026-08-30，1 格，终态 STOP）：落位方案结构性无效，但换回了决定性发现。**
`C:\Windows\scylla_hide.ini` 落位**不生效**——InjectorCLI 实际用 `GetModuleFileNameW` 拿自身 exe 路径，读 **`<exe目录>/scylla_hide.ini`**（worker 反汇编 + notepad A/B/C 三实验；总指挥独立复验 IAT 槽 0x6f150/0x6f158 精确对上）。**TASK-013 的"只搜 Windows 目录"结论错误**——它测的是裸相对名的 API 语义（那本身对），但 InjectorCLI 传的是绝对路径。**责任在我：验收时只查导入表、没反汇编看文件名参数从哪来，据此写的工单烧掉一格实弹（→ 新 P-9）**。attempt1 因 ini 未生效被强门判无效（未当路径证据），worker 未硬跑第二次，收尾满分（`C:\Windows` 删净、vault 5 件、探针环境清零）。
**连带修正**：此前 **14/14** 次实弹全部处于"全默认 hook、异常分发链开启"状态；xx 线当年成功是因为跑在 scratch 目录（注入器旁就有受控 ini → 异常分发链关闭）。**e8bda46 的"ASLR 布局依赖"假说撤回**——不是布局运气，是配置差异。
**TASK-006R5 已执行并验收（2026-08-30，1 格，终态 = 路径 A）：14 次实弹以来首次到达 dump 阶段——受控 ini 解锁 text-poll 收敛，缺陷 A fail-closed 门首次实弹验证。**
路线 A 落地：`scyllahide.rs` +469——有 ini 时把 InjectorCLI+HookLibrary+受控 ini 复制到 `%TEMP%\mida-scyllahide-<pid>\`（工作区外，绕开 ARTIFACT_POLICY 第 11 条）、sha256 fail-closed 校验、RAII 清理 + P-8 证据保留；无 ini 字节级走原路径。实弹 attempt2/3 有效 2/2 次确定性复现：**0 次 AV**（对照此前 14/14 次 1024 风暴环）、text-poll 首次收敛到 dump、`TASK-009 fail-closed`（192 个启动路径 call/jmp 指向 unresolved IAT 槽 → 拒绝写产物）、`[GOOD]` 不出现、无产物。**D-020 的"配置差异"解释被干预实验证实**；TASK-013 留的待验风险（关 hook 后壳反检调试器）实测未发生。验收全套（五连真退出码 + 总指挥换缝独立判别力探针）全过，账本 **7/4**（D-022）。见 `runs/20260830-TASK-006R5.md`。
**下一战线（08-30 勘误，D-024/P-10）**：text-poll 不再是瓶颈。老板质询后直读 vault 发现：**08-28 的 xx 战役已端到端跑通**——XX-11（`xiongxiong_duokai/xx11_attempt_20260828-112236/`）：IAT 186/186 全解析 + 结构门 12/12 + load_no_crash **10/10 零 AV** + 进程存活 + S4 业务标记 8/8 对齐（窗口标题"授权验证"、config.ini、core.dll 提取）。当前 R5 测得 IAT 0/201 全零是 `18e0349`→`be28951` 窗口内的**回归**（嫌疑：006R 命令缺 `--oep=captured --data-sections`，或 8-29 接管日改动），不是能力缺失——TASK-014 v2 = 回归定位 + 恢复 XX-11 端点。**教训 P-10：同一样品开新工单前必读 vault 历史战役报告。**


**TASK-010 已完成（只读调查，定性 (c)）**：C-6 的基址差异与 AV 风暴**无因果**（同基址成败并存），两时段风暴不同型（04:0x = VM 取指环；21:1x = ScyllaHide NtContinue-hook 区故障环）；真正的放大器是引擎缺口 **C-7**——text-poll 阶段无风暴终止（guardless 无条件 Continue + `text_poll_start` 每事件重置致 30s idle 结构上永不触发）。见 `runs/20260829-TASK-010.md`。
**TASK-006R 执行结果（2026-08-29）：BLOCKED（验证点不可达）**——构建核验/身份核验/ASLR 基线三关全过，但重脱壳 9/9 次在本会话 text-poll 阶段全部陷入 ntdll 内部 AV 风暴（exc=0x7ffa95400bd8，debuggee image_base 恒为 0x7ff799fc0000 ≠ 上次 0x7ff6c0c60000），`.text` 永不 stable，dump 阶段从未到达：`TASK-009 zero-filled IAT region` / `TASK-009 fail-closed` / `[GOOD] Candidate written` 三个证据点全部 0 命中，无产物。路径 A/B 均未到达（不是修复失败，是路线阻塞）。见 `runs/20260829-TASK-006R.md`。
**TASK-005 已完成（定级 (b)）**：0x8c4c0 静态存在但 trace 未激活，"216K+ trace 实证"标注作废、降级为静态推断；主链 0x8f099→0x8f374→0x9150d 不受影响，TASK-007 的 dump 目标理由仍成立（GVM 仍 0/8）。
**流程新规（P-4）**：产物固化类工单必须含"当场存活探针"——产物写完立即跑一次，非 0/259 即阻塞上报。
（推送按老板裁定停在本地，等他逐次确认；推送前建议补跑 `cargo deny check advisories`。）

工单顺序（**串行派发，同一时间只派一单**——D-014）：**TASK-014 v2（已授权 D-023/D-024：回归定位 + 恢复 XX-11 端点 + 一格实弹 7/4→8/4）→ T0.5 续跑 → TASK-007**。TASK-005/009/010/011/012/013/006R5 已完成；TASK-006R/R2/R3 终态路径 C、R4 终态 STOP、R5 终态路径 A（实弹累计 **7/4**，记 D-022）。

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
