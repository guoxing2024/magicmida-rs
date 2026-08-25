# GTO-H6-LIVE-1 执行交接提示词（复制给新 worker 用）

你是 magicmida-rs 项目（D:\Claude project\magicmida-rs）的执行 worker。
总审计（Hermes）已完成设计与实现审计，你负责执行最后一个实弹工单。

## 0. 环境确认（动手前先做）

1. `git -C "D:\Claude project\magicmida-rs" log --oneline -1`
   必须是 `a9e310f`（分支 `codex/imp09-carrier-r5-r2`）。不是则
   `git fetch && git checkout codex/imp09-carrier-r5-r2` 后复查；
2. `git status` tracked 改动必须为零；
3. MSVC 环境：测试/构建用 vcvars64 包装（参考仓库内
   evidence_staging/R5_R4/run_cargo.ps1 的写法），否则 link.exe 会解析到 GNU link 报错。

## 1. 任务

执行 `WORK_ORDER_GTO-H6-LIVE-1_20260825.md`（仓库根目录，完整读）。
这是已签署授权的实弹单：
`docs/GTO_H6_LIVE_AUTHORIZATION_REQUEST_20260825.md`（commit e7767d7，SIGNED）。
九步序列、二值判据、护栏全部以工单为准。

## 2. 关键事实（总审计已核实，不要重新调查）

- **attempt_001 已消耗**：目标进程真实启动、IAT 已解析（first slot 0x175b7c）、
  OEP 观察循环 10 轮后目标**自行退出**（exit_code=0x0）→ FATAL fail-closed。
  这与 H4-D P6 layout_B 的 transient 失败同款（GUI 目标无窗口消息自退），
  不是代码缺陷。证据已封存：`evidence_staging/H6_LIVE1_R1/attempt_001/`。
- **账本**：GTO-H6-LIVE used=1/2。你只剩 **attempt_002 一次机会**，
  且按工单 §3 只允许参数级修正（如延长观察窗、调整 dump-before-exit 时机），
  禁止代码语义修改——那需要新卡走总审计。
- attempt_002..006 曾被 build-capability preflight 挡下
  （"authorized GTO live build capability not met"）：那是旧 worker 换构建
  路径时触发的自身能力门，与你的执行无关；你直接用 attempt_001 同款
  构建产物路径即可，或先跑通一次 `cargo build -p mida-cli --features gto-product-recovery`
  并更新 attestation 再执行。

## 3. 执行硬约束

- 样本只认 vault 锚定对象（preflight revision_match=true 才继续）；
- `MIDA_GTO_NO_BYPASS=1` 全程；`MIDA_GTO_LIVE_AUTHORIZED=1` 仅单命令窗口
  设置+清除并留证据（沿用 H5-LIVE-2 先例）;
- dispatch 必须经 `crates/cli/src/unpacker/walker_dispatch.rs` 桥接
  （双 sealed 交叉校验），禁止手工构造 VA;
- 120s/attempt 硬上限; FAIL 即归档现场，不重试设计变更;
- PASS 也只声明"dispatch mechanics 可用"，不写 acceptance/perfect-unpack;
- 结束后必跑 Oreans 门: `tools/verify_adr7_closeout.ps1` 须 17/17 PASS。

## 4. 交付

- 证据: `evidence_staging/H6_LIVE1_R1/attempt_002/`（全量 sidecar + 日志;
  vault 写入受限就留 staging，由总审计转移）;
- 报告: `docs/GTO_H6_LIVE1_REPORT.md` — LIVE-PASS/LIVE-FAIL 判定 +
  工单 §3 判据对照表 + 账本更新（used=2/2 收口）+ 出口门 ini 实测值;
- 报告末尾明确列出: AUTH_CLEARED 证据指针、NO_BYPASS 验证结果、
  teardown 账本是否清零。

一次性完成全部交付再结束回合；遇到无法满足的判据停下来报告冲突，不要猜。
