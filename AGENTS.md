# AGENTS.md — AI 员工通用守则

本文件是**每个 AI 会话开工前必读的第一份文件**。你没有记忆，本仓库的文件系统就是公司的全部记忆。

## 0. 三十秒定位

1. 读 [docs/00-START-HERE.md](docs/00-START-HERE.md) —— 当前在做什么。
2. 读你的工单 `tickets/TASK-xxx.md` —— 你唯一的任务来源。
3. 只改工单"授权文件清单"里的文件。清单外的文件一律不动。

## 1. 项目一句话

Windows PE 脱壳（unpacking）研究平台：把受保护二进制还原成可加载、行为等价的 PE，并为每条结论留下可复算的证据。
**不是 1.0 产品**，禁止在任何产出里出现"完美脱壳""通用脱壳"这类无证据的结论性措辞。

## 2. 本机怎么跑起来（必须先做）

本机 Git Bash 的 `PATH` 会把 `link.exe` 解析到 Git 的 GNU coreutils，导致
`link: missing operand` 链接失败；`VsDevCmd.bat` / `vcvars64.bat` 在本沙箱被拦截。
唯一已验证可用的入口是 `tools/_enter_msvc_env.cmd`（自动探测 VS/SDK 版本，不写死版本号）：

```bash
# Git Bash 里生成一个 CRLF 批处理再交给 cmd 执行
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\ncargo test --workspace --offline\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

`cargo fmt` / `cargo check`（不链接）可以直接在 Git Bash 里跑。
**跑完删掉临时脚本**，仓库根目录不留自己造的文件。

## 3. 铁律

1. **不许改测试来让测试通过。** 降断言、注释用例、加 `#[ignore]` / `.skip`、放宽阈值 —— 发现即判工单失败并记入 `docs/KNOWN_ISSUES.md`。
2. **不许报告未亲自验证的结论。** 报告里必须粘贴命令的**原始输出**（含退出码）。没有原始输出 = 直接打回，不问理由。
3. **不许越界。** 改动超出工单授权文件清单 = 直接打回。
4. **不许引入新依赖**，除非工单明确授权。
5. **不许提交 / 推送**，除非工单明确授权。样品、脱壳产物、dump、日志、二进制一律不进 Git（见 [ARTIFACT_POLICY.md](ARTIFACT_POLICY.md)）。
6. **红线（研究授权边界）**：`NO_BYPASS=1`；样品身份哈希不匹配即 STOP；样品不外发；禁止伪造证据。
7. **停止规则**：同一验收标准连续 2 次不通过就停下来写报告说明卡在哪，不要继续硬搞。

## 4. 交付格式

产出写到 `runs/<YYYYMMDD>-TASK-xxx.md`，逐条对照工单验收标准，每条附命令与原始输出：

```markdown
# TASK-xxx 执行报告
## 改动文件（对照授权清单）
## 验收标准逐条对照
### 标准 1：<原文>
命令：<命令>
原始输出：<粘贴，含退出码>
结论：PASS / FAIL
## 阻塞点
## 我没做的事 / 我不确定的事
```

最后一节不许留空。你不确定的事写出来，比猜一个漂亮结论有用一百倍。

## 5. 措辞纪律

- 每条结论标可信度：`[已验证]`（跑过/读过代码）/ `[推断]` / `[存疑]`。
- 禁止用"应该没问题""基本完成""尽快"。给具体数字和具体日期。
- `no-gate` 意思是"没有验收门"，不是"已通过验收"。别把它写成通过。
