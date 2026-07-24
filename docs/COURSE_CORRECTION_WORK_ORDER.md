# 纠偏工作序 — 冲向完美脱壳 1.0

**日期:** 2026-07-24  
**分支:** `baseline/legacy-recovery-20260722`  
**绑定:** [UNATTENDED_DECISIONS_20260724.md](UNATTENDED_DECISIONS_20260724.md)（D1–D8, Q1–Q7）  
**现状真相:** [UNATTENDED_RESIDUAL_20260724.md](UNATTENDED_RESIDUAL_20260724.md) · [AUDIT_PACKAGE_20260724.md](AUDIT_PACKAGE_20260724.md)

---

## 0. 一句话

**B-B / VNEXT-BEH 已关；产品 1.0 未关。**  
下一阶段只打缩短「结构过关 → 稳定可加载 → 可证明行为」距离的工作；  
**停掉**不缩短该距离的配置面扩张。

---

## 1. 当前站位（纠偏前提）

| 已成立 | 未成立 |
|--------|--------|
| R0B 独立结构门 | 单发稳定加载（R-LOAD-FLAKE） |
| 4 案 B-B compose `Accepted`（`load_no_crash_v0` + pin/retry） | 最新 GTO dump 不靠老 pin 过门（R-GTO-LATEST） |
| Origin pure 默认（仅 Origin） | 业务/逻辑等价（R-PURE-LOGIC） |
| GTO 独立 host 代码路径 | GTO 退出 experimental / 产品默认 |
| M1–M4 capture 可配置（plumbing） | 通用产品开箱即用 |

**行为门含金量（诚实）：** 当前 `Accepted` = 结构过 + **进程活着一段时间**。  
**不是** UI / 脚本 / 业务路径等价。纠偏后仍不得把 load survival 说成 1.0。

---

## 2. 立即停止（Do Not）

下列事项 **默认不做**，除非操作员书面改目标为「平台通用化优先于 1.0」：

1. **M5+ capture / policy 扩展**  
   新 preset、新 schema 字段、新 harness 开关、再拆 policy 模块。
2. **再写一层「通用落地」文档而不带 live 证据**  
   residual 更新可以；空转 roadmap 刷新不算进度。
3. **把 pin / 12× retry 当产品修复**  
   门禁可保留 pin 作回归对照；**不得**用「walk 到 r4c」关闭 R-GTO-LATEST。
4. **扩大 pure 默认到非 Origin**（违反 D3）  
   在 Origin 单发稳定之前禁止讨论全局 pure。
5. **假 1.0 / 假「行为闭环」**  
   无新 oracle 证据不得改 claim bar；不得把 M 系列 commit 写成 1.0 进展。
6. **大重构 host / 全量 R2 迁移**  
   除非直接服务 P0/P1 的可证 bugfix。
7. **Dali / 新样品族**  
   范围外；不进本工作序。
8. **push / CI / 远程**（D8）  
   本地 commit 可；远程禁止除非另授。

---

## 3. 工作序（严格串行）

原则：**一次只开一个主战场**；本战场 exit 未过，不启下一场。  
Fix 轮次沿用 Q2：**每战场最多 2 轮**「改代码 → rebuild → 复测」；仍失败则写 residual 停手，不无限磨。

```text
W0 文档对齐（半日级）                    ✅ 2026-07-24
 → W1 Origin 单发加载稳定                 ✅ metric exit（scrub_v2 20/20）
 → W2 GTO 最新 dump 不 pin 过门           ✅ metric exit（clear-regs 3× live 10/10）
 → W3 行为探针升级（有意义的 oracle）     ✅ metric exit（window_class + export_names）
 → W4 宣称门槛复审                        ✅ 2026-07-24 — **产品 1.0 = NO**（默认；无操作员授权）
```

**W1 关闭摘要（2026-07-24）：** 根因 = kernel-canonical object head `0xfc388` + cookie complement 误植 + 过宽 scrub；fix = `data_reinit` kernel/low-4GB + `heap_bootstrap` 邻接 plant。证据：`origin_w1_scrub_v2_rate_20260724-151615`（pass_rate=1.0）。**非 1.0。** 详见 residual W1 节。

**W2 关闭摘要（2026-07-24）：** 根因 = `.boot` multi_fixup 结束后 `r8` 残留 range size（常 `0x8000`），AHK OEP `0x70b0` 把 `r8` 当可选指针 `mov [r8],ecx` → AV@`0x8000`。fix = OEP 跳转前清零易失寄存器。3× 独立 live `w2_clearregs{1,2,3}` 各 N=10 attempt=1 → **1.0**；gate pin 优先序改为 clearregs（不再以 `r4c_gto` 为成功条件）。R-GTO-BOOT 仍 open。**非 1.0。**

**W3 关闭摘要（2026-07-24）：** 最小有意义 oracle 两条（fail-closed，仍走 `mida.behavior-evidence/v0` + `check-with-behavior`）：  
1. Origin `gui_window_class_v0` — 运行时出现 `PigToGoLicenseDialog`（标题「授权验证」观测到但不作门禁）。  
2. GTO `pe_export_names_v0` — 静态导出表面含 `AhkAssign`/`AddScript`/`ahkExec`/`MinHookEnable`（非脚本执行）。  
两侧证据 Pass → compose **Accepted**；负例 Fail。BB 默认门仍可保留 `load_no_crash_v0`；W3 证明行为轴有**超出存活**的可复现信号。**仍非产品 1.0。**

---

### W0 — 文档与证据对齐（先做，低成本）

**目的：** 后人读图不漂；避免按旧 roadmap 开错工。

| 动作 | 完成标准 |
|------|----------|
| 标旧图 | `PROJECT_AUDIT_AND_ROADMAP.md` 文首加 **superseded** 指向 residual + 本文；或补一节「B-B 已关 / 1.0 未关」 |
| 钉证据路径 | residual 中 BB 批次路径与 vault 实盘一致（`summary.json` / compose） |
| 工作区 | 不提交 scratch `tools/_*`（Q6）；本序只 commit 必要代码+证据索引 |

**不做：** 重写整套 vNext 文档。

**Exit:** 审计入口三件套可读且不互相打架：`DECISIONS` · `RESIDUAL` · 本文。

---

### W1 — Origin 单发加载稳定（P0，优先）

**战场 ID:** `R-LOAD-FLAKE`（Origin 侧）  
**为何第一：** pure 默认已绑 Origin（D3/Q3）；Origin 不稳则 1.0 叙事整体不可信。

#### 范围

- 样本：`origin_macro` 保护输入 → 当前默认 pure dump 路径  
- 对照：同 candidate 下 `--no-pure-rebuild`（仅诊断，不改默认）  
- 探针：`load_no_crash_v0`，**强调单发 / 低重试**，不是「12 次里过一次」

#### 度量（必须先量后改）

| 指标 | 建议协议 | 目标（W1 exit） |
|------|----------|-----------------|
| 安静串行通过率 | N≥20，attempt=1，冷却固定，basename 隔离 | ≥ **0.90** |
| 冷启动 / 背靠背 | N≥10 冷；N≥10 短间隔连发 | 记录基线；冷 ≥0.80 为佳 |
| cdb 二次异常 | 失败样本抓 rip / 故障模块 / IAT 邻域 | 同一根因簇可复述，禁止「偶发」收工 |

基线已有线索（residual）：`o+0x39e5c`、`GetCurrentThreadId` 邻域、坏指针 — **从这里打**，不要先改无关 dump 旋钮。

#### 允许改动（白名单）

- dump 写出：reloc / IAT / TLS / exception 与 loader 一致性  
- pure rebuild 边界上 **可证** 导致坏指针的缺陷  
- probe 仅当它 **掩盖** 真失败时再动；默认保持可复现协议

#### 禁止改动

- capture_policy / heap hot-root 表（Origin 非 GTO 主路径）  
- GTO host 大改  
- 全局 pure flip

#### Exit（全部满足才过）

1. 安静 N≥20、attempt=1 通过率 ≥0.90，证据在 vault。  
2. 失败剩余可归类（≤2 个根因簇）并写入 residual。  
3. **不**宣称 1.0；仅关闭或降级 Origin 侧 R-LOAD-FLAKE 叙述。  
4. 若 2 轮 fix 未达标 → **停**，residual 更新，不进入「假稳定」。

#### 失败停手产物

- `docs/UNATTENDED_RESIDUAL_*.md` 增补：协议、通过率、cdb 摘要  
- 本地 commit 工程进展；**无** 1.0 字样

---

### W2 — GTO 最新 independent-host 不 pin 过门（P1）

**战场 ID:** `R-GTO-LATEST`（附带观察 `R-GTO-BOOT`）  
**前置：** W1 exit 或 W1 正式 residual-stop（避免双线并行烧机）。

#### 范围

- 路径：`gto_host` + `--profile=ahk-gto-experimental`  
- **主 candidate：** 当次 live 新鲜 dump（scan60 类 settle），**禁止** 以 `r4c_gto` 作为 W2 成功条件  
- `r4c_gto`：仅作 **回归对照 / 下限**，写在报告「对照」栏

#### 度量

| 指标 | 协议 | 目标（W2 exit） |
|------|------|-----------------|
| 新鲜 dump R0B | 每次 unpack 后 `check-static` | `StructuralPassBehaviorPending` |
| 新鲜 dump 加载 | attempt=1，N≥10 安静 | ≥ **0.70** 起步；冲 **0.90** 再谈「稳」 |
| 多案门压力 | BB 式串行 4 案时 GTO 位 | 新鲜 dump **首 pin Pass**（允许总 attempts≤3，禁止 walk 到旧 tag 算过） |
| `.boot` / snapshot | sidecar + 可选 diff | 记录；**不**要求与 r4c 字节一致 |

#### 允许改动（白名单）

- independent-host settle / IAT 窗 / OEP 观察（已有硬化上的 **可证** 缺口）  
- heap 捕获中导致 **可复现崩溃** 的缺陷（需前后 rate 对比）  
- 非：再加 case-manifest 字段

#### 明确非目标

- 消掉 `.boot` ±28KiB 本身（R-GTO-BOOT 是诚实项，不是 W2 门）  
- 把 GTO 设为 CLI 默认 profile

#### Exit

1. 连续 ≥3 次独立 live（不同 run_id）新鲜 dump：R0B 过 + attempt=1 加载 Pass（或 N 次 rate 达标）。  
2. BB 复跑时 GTO **不**依赖 `r4c_gto` walk。  
3. residual：R-GTO-LATEST 降级或关闭；R-GTO-BOOT 可仍 open。

#### 失败停手

- 2 轮后仍只有 pin 路径绿 → 保持「研究 host 结构绿 / 加载靠 pin」诚实表述；**不**用 M 系列填坑。

---

### W3 — 行为探针升级（P2，真·逼近 1.0）

**战场 ID:** `R-PURE-LOGIC` 的 **第一刀**（不是一次做完 1.0）  
**前置：** W1 达标；W2 至少 residual 诚实（新鲜路径或明确 pin 依赖）。

#### 问题

`load_no_crash_v0` 已榨干作为 1.0 代理的价值。  
再刷 BB 绿 **不再**缩短完美脱壳距离。

#### 本战场交付（最小有意义 oracle）

选 **一条** 可自动判定的产品可观测量（不要并行开一堆）：

| 优先级建议 | 案例 | oracle 形态（例） |
|------------|------|-------------------|
| A | Origin | 固定启动参数 / 文件侧效应 / 可脚本检测的窗口类名或退出码契约 |
| B | GTO | 启动后可探测的稳定特征（导出、子进程、标记文件）— 须可自动化 |

要求：

- 证据 schema 仍走 `mida.behavior-evidence/v0` 族（扩展字段可，但 **fail-closed**）  
- `check-with-behavior` compose 规则不变：结构过 + 证据 Pass 才 `Accepted`  
- **Inconclusive 不得升 Accepted**

#### Exit（W3）

1. ≥1 Oreans 案例 +（若 W2 绿）≥1 GTO 案例：新探针 Pass 可复现。  
2. 文档写清：新探针测的是什么、**不**测什么。  
3. 仍 **不**自动等于产品 1.0；仅把行为轴从 ~25% 推到「有真实信号」。

#### 禁止

- 用 oracle PE 字节全等冒充行为等价  
- 网络 / 完整 E2E 大而全（范围爆炸）

---

### W4 — 宣称门槛复审（仅评审，默认不宣称）

**前置：** W1 exit + W2 exit + W3 至少一侧 oracle 绿。

| 问题 | 通过才可讨论 |
|------|----------------|
| 4 案新鲜路径单发加载是否仍绿？ | 是 |
| 行为是否已超出 load survival？ | 是 |
| pure / GTO experimental 产品策略？ | 书面决定，默认不变 D3 |
| 是否写「产品 1.0」？ | **默认否**；需操作员显式授权，且 Q7 证据重跑 |

**本战场默认产物：** 更新 audit package「距 1.0 清单」——不是发版说明。

#### W4 关闭摘要（2026-07-24）— **产品 1.0 = NO**

| 问题 | 结论 | 证据 |
|------|------|------|
| W1–W3 仍成立？ | **是** | vault `D:\MidaVault\lab\evidence\_beh_gate\w4_review\` |
| Origin load N=5 attempt=1 | **1.0** | `origin_load_rate5.json`（candidate `w1_scrub_v2`） |
| GTO load N=5 attempt=1 | **1.0** | `gto_load_rate5.json`（candidate `w2_clearregs1`） |
| 行为超出 load survival？ | **是** | Origin `gui_window_class_v0` Pass + compose Accepted；GTO `pe_export_names_v0` Pass + compose Accepted |
| 4 案新鲜路径全量单发？ | **本轮未全量重跑** | 仅 Origin+GTO 胜者 pin；lunlun / holdout 仍依 B-B 历史批次，**不**当作 W4 新证 |
| pure / GTO 策略 | **不变** | D3 pure=Origin-only；GTO 仍 `ahk-gto-experimental` |
| **产品 1.0 宣称** | **否** | 无操作员显式授权；R-PURE-LOGIC 未关；无 Q7 四案全量重跑 |

**纠偏阶段状态：** W0–W4 串行关闭。下一阶段 **不是** 自动 1.0，而是：  
- 若冲 1.0：先补 4 案新鲜单发 + 更深 R-PURE-LOGIC，再要操作员授权 + Q7；  
- 若转平台：操作员须显式改目标（§8），禁止借用 1.0 措辞。

#### P1 冲刺（操作员选 1，2026-07-24）— 仍 **非** 1.0

| 步 | 结果 |
|----|------|
| P1-A 4 案 attempt=1 N=10 | **全绿 1.0**（`p1_4case_fresh_20260724-161856`）→ R-4CASE-FRESH **metric closed** |
| P1-B 更深 oracle | Origin **title** 门禁；lunlun/holdout/GTO **exit_code_exact_v0**；4× compose Accepted + 负例 Fail |
| 产品 1.0 | **仍 NO** — 无 Q7 四案全量行为门重写；业务路径未证 |

**下一刀（若继续冲 1.0）：** 业务侧效应（文件/脚本/授权路径）或 GTO 运行时 GUI；然后操作员授权 + Q7 重跑才可讨论 1.0 句子。

#### P2 冲刺（2026-07-24）— 仍 **非** 1.0

| 步 | 结果 |
|----|------|
| Origin 控件文本 | class+title+「授权码」/「确定」Pass + compose Accepted；假控件 Fail |
| GTO 静态字符串 | `pe_string_v0` AutoHotkey+NewClassName Pass + compose Accepted |
| R-GTO-UI 对照 | **protected** NewClassName 登录窗 Pass；**unpacked** 同 oracle Fail（exit 0 无窗） |
| 产品 1.0 | **仍 NO** |

**诚实边界：** Origin 无稳定 registry/file 侧效应可门禁；GTO 运行时 GUI 仍 open（R-GTO-UI）。下一工程刀若冲 GTO 产品行为：查脚本/heap 恢复使 unpacked 到达 `NewClassName`，而非再加静态探针。

#### R-GTO-UI 修复（2026-07-24）— Q2 两轮封顶；**仍非** 1.0

| 轮 | 改动 | 验证 | 结果 |
|----|------|------|------|
| R1 | 强制 capture policy hot root `0x18a898`（Themida `.,\\W` RX 页）；plant 目标节标 `MEM_WRITE` | live `r_gto_ui_r1`：slot 已 capture + section WRITE；window_class `NewClassName` | **Fail**（exit 0 无窗）；load 未回归测本轮 |
| R2 | gscript cap `0x2000→0x10000` + probe 对齐；观察环在 `NewClassName` 出现后 +3s dump | live `r_gto_ui_r2`：UI 于 ~1s 见窗后 dump；gscript size **32768**；load N=5 attempt=1 **1.0** | window_class **仍 Fail**（exit 0） |

**根因进度（证据级，非关闭）：**

1. 旧 dump 丢 title root：`Hot-root ensure skipped: RVA outside fill/.data` @ `0x18a898` — R1 已修。  
2. 冷启动 plant 在 OEP 前生效（cdb：`0x18a898` / `0x149d50` / `0x141bf0` 非零后 `ExitProcess(0)`）。  
3. 脚本对象 live 可读 ≥`0x20000`，旧 cap 8 KiB — R2 抬到 32 KiB 仍不足完整脚本图。  
4. 冷启动仍在 OEP 后立即干净退出，无 `NewClassName` — 更深 AHK 运行时/脚本执行路径，**超出本战场 2 轮**。

**产品 1.0：** **仍 NO**。R-GTO-UI **open**（advanced）。下一刀须新 residual/操作员授权，禁止第 3 轮盲改。

---




## 4. 每战场通用军规

1. **先协议后改码** — rate / N / attempt / 冷却写进证据目录 `run_meta` 或 summary。  
2. **对照固定** — 改动前后同一 CLI 路径、`CARGO_TARGET_DIR`、同 vault 物化哈希。  
3. **Q2 两轮封顶** — 第三轮起必须停写 residual。  
4. **Q6 提交纪律** — 只 commit 本战场必要文件；scratch 探针脚本不进库。  
5. **D8** — 不 push。  
6. **双线禁止** — W1 与 W2 不并行大改；诊断脚本可并行，产品行为变更不可。

---

## 5. 优先级总表

| 序 | 战场 | 主 residual | 对 1.0 | 预估形态 |
|----|------|-------------|--------|----------|
| W0 | 文档对齐 | 文档漂移 | 低 | 半日 |
| W1 | Origin 单发 load | R-LOAD-FLAKE | **高** | 数轮 fix + 量测 |
| W2 | GTO 新鲜 dump | R-GTO-LATEST | **高** | 数轮 fix + 量测 |
| W3 | 有意义行为 oracle | R-PURE-LOGIC（第一刀） | **关键阻塞** | 设计+探针+证据 |
| W4 | 宣称复审 | claim bar | 治理 | 评审 |
| — | M5+ policy | （无） | **近零** | **不做** |
| — | R-GTO-BOOT 字节对齐 | R-GTO-BOOT | 低 | 仅作旁证 |
| — | R-X86 Scylla | R-X86 | 仅 x86 | 有二进制再填 |

---

## 6. 建议的「下一刀」命令骨架（W1 开场）

不代替实现，只固定开场动作：

```powershell
# 0) 重建 CLI
cmd /c tools\_rebuild_cli.cmd

# 1) 确认 Origin pure candidate 存在（或 live 打一发）
# 2) 单发 rate（示例：把 attempt 钉死为 1，N=20，证据进 vault）
python tools\_behavior_probe.py ...  # 以仓库现行 CLI 为准；协议写入 summary

# 3) 失败样本 cdb / 已有 diag 工具，归类根因后再改 pe/cli
```

W1 未出 rate 基线前，**禁止**提交「可能有助于稳定」的盲改。

---

## 7. 与旧计划的关系

| 文档 | 关系 |
|------|------|
| `UNATTENDED_EXECUTION_PLAN.md` | 无人值守 U1–U5 历史；B-B 前后残留表 **部分过时** |
| `PROJECT_AUDIT_AND_ROADMAP.md` | 结构/R 门历史有用；BEH/1.0 状态以 residual + **本文** 为准 |
| `VNEXT_BEHAVIORAL_PATH.md` | 合约仍绑定；B-B 已关不表示 1.0 |
| 本文 | **B-B 之后 → 1.0 之前** 的执行序 |

---

## 8. 操作员可选项（需显式改目标才生效）

若操作员声明 **「平台通用化优先，1.0 降级」**，则：

- 可恢复 M 系列 / 多插件 capture  
- 本工作序 W1–W3 **让路**  
- 宣称条变为「研究平台里程碑」，禁止借用 1.0 措辞  

未声明前，执行者按 **本文 W0→W1** 开工。

---

## 9. 完成定义（本纠偏阶段）

本工作序自身的 “done” **不是** 1.0，而是：

1. 主战场按序推进，未做 Do-Not 清单上的空转；  
2. W1 或正式 residual-stop 有 vault 数字；  
3. 文档三件套（决策 / residual / 本文）与证据一致；  
4. 任何公开句子仍满足：  
   **「VNEXT-BEH 已关 ≠ 完美脱壳 1.0」**。
