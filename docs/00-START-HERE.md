# 00-START-HERE — 下次开机 30 秒接上

> 最后更新：2026-08-29（冷启动接管会话）

## 你是谁，先读什么

- **AI 员工**（拿到工单来干活）：读 [../AGENTS.md](../AGENTS.md) → 读你的 `tickets/TASK-xxx.md` → 开工。别读别的。
- **总指挥**（新会话接管项目）：读本文件 → [PROJECT_STATUS.md](PROJECT_STATUS.md) → [TICKETS.md](TICKETS.md)，然后抽查代码核对事实。

## 项目一句话

Windows PE 脱壳研究平台（Rust，221k 行，11 个 crate）。把受保护二进制还原成可加载、行为等价的 PE，每条结论都要有可复算证据。
**不是 1.0 产品，禁止宣称"完美/通用脱壳"。**

## 现在在做什么（2026-08-29）

主攻线是 **GVM-0 反虚拟化战役**（`gto_launcher` 的 VM 语义还原 → lifter → 整镜像去虚拟化，账本 GVM 0/8，Phase 1 门 1 未过）。
`origin_macro` + `lunlun_software` 是必须一直绿的回归门。`xiongxiong_duokai` rev2 战役已于 2026-08-28 关闭。

## 最要紧的一件事

**两天的成果全部未提交，且 CI 因 `cargo fmt` 红 216 处处于必红状态。** 先做 `tickets/TASK-001.md` 和 `TASK-002.md`。

## 30 秒把它跑起来

```bash
cd "D:/Claude project/magicmida-rs"
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\ncargo test --workspace --offline\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

期望：`65 个 target / 2801 passed / 0 failed / 2 ignored`，`EXIT=0`。
**不要**直接在 Git Bash 里 `cargo test`：`link.exe` 会解析到 Git 的 GNU coreutils，链接必失败。`cargo fmt` / `cargo check` 不受影响。

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
