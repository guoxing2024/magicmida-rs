# TASK-017 — T0.5 续跑：熊熊 B1' 产物 Run UI 事件驱动补测（Run verdict PARTIAL → FULL）

✅ **已授权 —— 授权令牌（必须在报告第一节原文回抄）**：
> `老板 · 2026-08-30 · 原话"先解决1，其他的再等等吧"（按全案解释：批准 T0.5 续跑 = 熊熊 B1' 产物 Run UI 事件驱动实弹 1 格，账本 XC-XXI-B 9/4 → 10/4；TASK-007 / clippy 基线门修复 / §九 GTO-UI 锚区 / 推送 全部暂缓）· 前置由总指挥亲验（2026-08-30）：BootTime = 2026-08-30 10:05:51（与 T015 产物生产同一 boot，C-4/B 跨重启风险当前不适用）；vault 产物 rev2_unpacked_t015_attempt2.exe（a852880a…，1,539,072 B）与 core.dll（09f3dd34…）在位；驱动脚本 tools/xx21b_t05_ui_drive.py 机制就绪但按旧宿主（36043cb4）写死常量，须按本票适配`

- **岗位**：developer（实弹：启动 B1' 产物 + UI 事件驱动；单 worker 连续执行）
- **账本**：XC-XXI-B 9/4 → **10/4**（1 格。本单内多次 UI drive 尝试仍记 1 格——T015 先例"2 次有效尝试 = 1 格"；**若中途判断需要重新 `/unpack` → 停，另立单另批格，本票不许碰脱壳**）

## 背景（为什么现在能跑）

- T0.5 = 熊熊收尾最后一格。当前 verdict = `StructuralPassBehaviorPending`（结构门 12/12、load 10/10、S4 对齐已达成——D-029）；本单验证最后一件：**点击 Run 后 RIP 是否真落 urlmon.dll（URLDownloadToFileA 调用点）** = 事件级行为等价，达成则 Run verdict PARTIAL → FULL。
- 旧双重阻塞均已解除：① 缺陷 A（TASK-009 修复，T015 实弹验证 fail-closed + 产物可加载）；② 旧宿主跨 boot 崩（C-4/B 会话绑定）——**当前 boot（10:05:51）与产物生产同 boot**，风险暂不适用（总指挥已亲验；worker 开跑前须自查一次，见验收 4）。
- 目标宿主换新：旧脚本按 XX-11 时代产物写死（`HOST_SHA=36043cb4…`、core.dll 固定基址 `0x7FFE1DA10000`、宿主基址 `0x140000000`）。本单改用治理产物 **a852880a**（T015 attempt2，load 10/10 ×2、S4 对齐），**基址全部动态解析**（T016 反硬编码纪律沿用，不许再钉死会话地址）。

## 任务

### 1. 脚本适配（`tools/xx21b_t05_ui_drive.py`，允许改动——这是对旧会话假设的清除，不是行为放宽）

- `HOST_SHA` → `a852880aabba215b16a2a96245322ca09d19ff148afaa30ff42b1a8ea438edac`；core.dll 期望 sha（旧 `CAND_SHA=3650ea6c…`）→ `09f3dd344215c6aa608bc6a8e8ae24486e3bf425c3f3541272d065a1d9999144`。
- **core.dll 基址动态化**：删固定 `BASE` 钉死，改为启动后从 `enum_modules()` 动态解析 core.dll 实际基址（解析不到 → fail-loud `FAIL_CORE_NOT_FOUND`）；`RUN_VA` / `URLMON_SLOT_VA` = 动态基址 + 既有 RVA（`0x1C120` / `0x16F300` 保留——它们是 core.dll 结构相对量，core.dll 跨战役逐位一致 09f3dd34，RVA 稳定）。
- **宿主基址动态化**：`rev2_unpacked.exe` 模块项 + MZ 校验动态解析，`RUN_PARAM` 用解析值（保留解析失败 fail-loud）。
- **保留全部红线机制**：`NO_BYPASS=1`、sha256 预核实 fail-closed、网络 deny_all 现状核实（**不改防火墙**）、P-8 证据落盘。
- 适配 diff 逐行进报告；不许顺手改任何其它文件。

### 2. 实弹执行（1 格）

- 部署（全新，`lab/xx21b_run_ui/` 当前不存在）：vault 只读复制 `rev2_unpacked_t015_attempt2.exe`（a852880a）→ `lab/xx21b_run_ui/rev2_unpacked.exe`，`core.dll`（09f3dd34）→ 同目录；sha 双核 fail-closed。
- 执行脚本 UI 驱动；每趟证据（日志/JSON/RIP log/窗口发现/事件序列）落 `lab/xx21b_run_ui/`，**收尾前先整目录拷贝入 vault** `D:/MidaVault/lab/evidence/xx21b_t05/` + `INDEX.md`（P-8：先入 vault 再清理——D-029 备注②教训）。

## 验收标准（每条要真原始输出含退出码）

1. **判定（按脚本既有语义）**：
   - **FULL**：驱动 Run 后 RIP 进入 urlmon.dll（URLDownloadToFileA 调用点）、进程不崩、≥2 次驱动可复现；
   - **新阻塞**：RIP 卡在新位置 → verdict 仍 PARTIAL，卡点证据（RIP/所属模块/事件序列）如实上报 → **STOP**（不烧第 2 格）；
   - **AV**：记录异常地址/模块/上下文 → 上报 → **STOP**。
2. 脚本适配 diff + 判定 + 全部原始输出进报告；结论按 `[已验证]`/`[推断]`/`[存疑]` 标注。
3. **零越界**：只改 `tools/xx21b_t05_ui_drive.py`（+ 新建 `lab/xx21b_run_ui/` 与 vault 证据目录）；生产代码 `crates/` 一行不动；git 只读（不 commit/push）。
4. **BootTime 复核**：开跑前自查 BootTime 仍 = `2026-08-30 10:05:51`；变了 → **STOP 上报勿硬跑**（产物会话绑定 C-4/B 未根治，跨 boot 必崩是已知问题，不是本单要验证的东西）。
5. **防火墙现状核实并记录**（开跑前）；若网络未被拦截 → **STOP 请示**，不许自行改防火墙，不许真联网。
6. 临时文件逐个删除；vault 证据先行；报告第一节回抄授权令牌。

## 红线（违反即整单作废）

`NO_BYPASS=1`；不真联网、不改防火墙；样品/产物不外发、产物只在本机运行；不写 `C:\Windows`；不新增依赖；样品身份哈希不匹配即 STOP；同一验收标准连续 2 次不通过 → 停下写报告。

## 交付物

- `runs/20260830-TASK-017.md`（令牌回抄 + 适配 diff + 判定 + 原始输出 + 「我没做的事 / 我不确定的事」）
- vault `D:/MidaVault/lab/evidence/xx21b_t05/`（全证据 + INDEX.md）
- 工作区留改动给总指挥，**不提交**。
