# TASK-018 — T0.5 续跑（A' 路线）：驱动脚本观测腿改调试端口泵，重跑三态判定

✅ **已授权 —— 授权令牌（必须在报告第一节原文回抄）**：
> `老板 · 2026-08-30 · 原话"A"（按全案解释：批准选项 A' = 批 1 格实弹，把 T0.5 驱动脚本观测腿改调试端口泵并重跑三态判定（FULL / 新阻塞 / AV），账本 XC-XXI-B 10/4 → 11/4；其余事项继续暂缓）· 前置由总指挥亲验（2026-08-30）：BootTime = 2026-08-30 10:05:51（与产物生产同 boot）；总指挥 P2 探针已证调试端口路径读得真实 Rip（D-034 / P-11）；部署物 lab/xx21b_run_ui/（a852880a / 09f3dd34 / config.ini）sha 与 vault 逐位一致；HEAD = e31d5ed`

- **岗位**：developer（实弹：调试端口附加运行 B1' 产物 + UI 事件驱动；单 worker 连续执行）
- **账本**：XC-XXI-B 10/4 → **11/4**（1 格。本单内多次驱动尝试仍记 1 格——T015/T017 先例；**若中途判断需要重新 `/unpack` → 停，另立单另批格**）

## 背景（为什么这条路能成）

- TASK-017（D-034）实证：本环境对**非附加式** GetThreadContext/EnumWindows 系统性垫零（P-11），RIP 证据不可得；但**总指挥 P2 探针实测调试端口路径读得真实 Rip**（`DEBUG_ONLY_THIS_PROCESS` 拉起 cmd，CREATE_PROCESS 挂起态 `Rip=0x22d9f9f8b8`、imageBase 真实）——解包引擎同 boot 当天 trace 74/74 用的是同一条路径，机制可信。
- TASK-017 同时拿到正面证据：B1' 产物 Run 实调用到达 GUI 业务层（PigToGoLicenseDialog"授权验证"、GUI 存活 3/3、无 AV、IAT 不变）。本单把 RIP 证据补上，出三态判定。
- **不改判定语义**：FULL/新阻塞/AV 三态与 TASK-017 票面逐字一致，只是证据来源从"外部 OpenThread 读上下文"换成"调试端口泵"。

## 任务

### 1. 新脚本 `tools/xx21b_t05_ui_drive_dbg.py`（从 TASK-017 版 fork，允许新建此一个文件）

- **宿主创建改调试端口**：`CreateProcessW(..., DEBUG_ONLY_THIS_PROCESS)`（DEBUG_ONLY=0x2）取代普通创建；`pi.hProcess/hThread` 保留。
- **调试泵线程（关键，独立线程持续泵）**：`WaitForDebugEvent` 循环（超时 ~500ms 轮询 `self` 停止标志），**每个事件必须立刻 Continue**——不消费事件 = 调试对象冻结（总指挥 P2b 已实证此坑）。事件处置：
  - `CREATE_PROCESS_DEBUG_EVENT`（3）：记录 hProcess/hThread/imageBase（从 DEBUG_EVENT union 偏移 24/32/40 读）→ 主线程初始 Rip 存证；
  - `CREATE_THREAD_DEBUG_EVENT`（2）：记录 hThread（尤其 `CreateRemoteThread` 注入的 Run 线程——按 tid 匹配 Run 线程）；
  - `EXIT_PROCESS_DEBUG_EVENT`（5）：记录退出码后结束泵；
  - `EXCEPTION_DEBUG_EVENT`（1）：**全部记录**（异常码/地址/首挂起线程 Rip——AV 三态的证据来源）；首个 `EXCEPTION_BREAKPOINT(0x80000003)` → `DBG_CONTINUE`，其余异常 → `DBG_EXCEPTION_NOT_HANDLED`（交还应用 SEH，不吞）；
  - 其余事件（DLL load/unload 等）：记录计数后 `DBG_CONTINUE`。
- **RIP 采样改走调试腿**：对 Run 线程的 hThread（来自 CREATE_THREAD 调试事件，不是 OpenThread）做 GetThreadContext；RIP owner 归属用既有 `enum_modules()`+MZ（ReadProcessMemory/模块枚举本环境**可用**——T017 deploy_check 实证）；`hit_urlmon` 判定 = RIP 落入 urlmon 模块区间。
- **保留 TASK-017 全部机制**：sha256 fail-closed、core.dll/宿主基址动态解析、FindWindowW 窗口发现（EnumWindows 不可用）、GUI 存活观测（IsHungAppWindow/WM_NULL）、`NO_BYPASS=1`、防火墙现状核实（不改）。
- **自证义务（写进每趟证据 JSON）**：调试泵健康计数（事件总数/各类型计数/是否出现"未消费事件导致冻结"——GUI hung>0 或窗口无响应即冻结征兆）；若 GUI 层在调试附加下**不再出现**"授权验证"对话框 → 这是"附加改变行为"的发现，如实上报（本身就有价值），不许硬凑三态。

### 2. 实弹执行（1 格）

- 部署物沿用 `lab/xx21b_run_ui/`（总指挥已核 sha 与 vault 一致；开跑前再自查一次）。
- 执行 ≥2 次驱动（三态判定需 ≥2 次可复现）；每趟证据 JSON + 调试泵日志落 `lab/xx21b_run_ui/`，**收尾前先拷入 vault** `D:/MidaVault/lab/evidence/xx21b_t05/`（并入现有 INDEX.md）。

## 验收标准（每条要真原始输出含退出码）

1. **三态判定（证据源 = 调试端口，语义与 TASK-017 票面逐字一致）**：
   - **FULL**：Run 触发后 RIP 采样落入 urlmon.dll 模块区间、进程存活、≥2 次驱动可复现；
   - **新阻塞**：RIP 稳定卡在新位置（真实采样值）→ verdict 仍 PARTIAL，证据上报 → **STOP**；
   - **AV**：EXCEPTION 调试事件（地址/码）或进程异常退出 → 证据上报 → **STOP**。
2. **调试泵健康自证**：事件全消费（无冻结征兆：GUI hung=0 贯穿）、各类型事件计数入证据。
3. 脚本 diff/全文 + 判定 + 全部原始输出进报告；结论按 `[已验证]`/`[推断]`/`[存疑]` 标注。
4. **零越界**：只新建 `tools/xx21b_t05_ui_drive_dbg.py`（+ 复用 `lab/xx21b_run_ui/` 与 vault 证据目录）；生产代码 `crates/` 一行不动；原 `tools/xx21b_t05_ui_drive.py` 不改；git 只读。
5. **开跑前自查**：BootTime 仍 = `2026-08-30 10:05:51`（变了 → STOP 上报勿硬跑，C-4/B 未根治）；部署物三文件 sha 复核；防火墙 BLOCK 现状核实（未拦截 → STOP 请示，不许真联网）。
6. 临时文件逐个删除；vault 证据先行；报告第一节回抄授权令牌。

## 红线（违反即整单作废）

`NO_BYPASS=1`；不真联网、不改防火墙；样品/产物不外发、产物只在本机运行；不写 `C:\Windows`；不新增依赖；样品身份哈希不匹配即 STOP；同一验收标准连续 2 次不通过 → 停下写报告。

## 交付物

- `runs/20260830-TASK-018.md`（令牌回抄 + 脚本全文/关键 diff + 三态判定 + 调试泵健康自证 + 全部原始输出 + 「我没做的事 / 我不确定的事」）
- vault `D:/MidaVault/lab/evidence/xx21b_t05/`（新证据并入 + INDEX.md 更新）
- 工作区留改动给总指挥，**不提交**。
