# MagicMida vNext — 项目审计与后续规划（Windows 复审）

**审计日期:** 2026-07-23（Windows 复审 + Phase 0 绿测 + Origin/Lunlun live StructuralPass）  
**基线分支:** `baseline/legacy-recovery-20260722`  
**HEAD:** `52c4eee` + 工作区：CONTROL|INTEGER context + Lunlun null-storm/exit 硬化（未提交）  
**工作区:** R1-A..E 已提交；**Origin + Lunlun live unpack + R0B StructuralPass 已固化**；GTO live 仍开放  
**主机:** Windows 11；仓库 `D:\Claude project\magicmida-rs`；vault `D:\MidaVault`  
**环境事实:** VS 2022 Professional MSVC 14.44；`tools/_rebuild_cli.cmd`；
`CARGO_TARGET_DIR=D:\MidaVault\scratch\cargo-target`；
P0 workspace 绿测已固化。样品在 vault，v2 verify 绿。

---

## 0. 复审相对前版的结论增量

| 项 | 2026-07-22（Linux 文档假设） | 2026-07-23（本机 Windows 证据） |
|----|------------------------------|----------------------------------|
| 主机 | Linux agent，无法 live | Windows 11；可物化 vault |
| 四样品 | “未物化” | **7/7 对象 PRESENT，size 全 match** |
| v2 合约 | 文档层 | `verify_manifests.py` → `overall_ok: true`（5 manifests / 7 objects） |
| R0B 测试 | 历史记录 | **本机 `cargo test -p mida-acceptance --offline` 全绿** |
| R1 pe 测试 | 未在本机 | **MSVC 14.44 下 workspace 412 全绿** |
| live unpack | 跳过 | **Origin + Lunlun** live StructuralPass（Lunlun 为 degraded path） |
| R1-E 状态 | handoff “closed” vs roadmap “in progress” | **已对齐：合成 corpus closed；live + default flip 开放** |
| SetThreadContext | 未记录 | **根因：CONTEXT_ALL/XSAVE → Win11 ERROR_NOACCESS；改为 CONTROL\|INTEGER + Suspend 重试** |

---

## 1. 项目定位与最终目标

### 1.1 一句话

**MagicMida vNext** 是 Windows PE 脱壳研究平台：用可复用引擎 + 保护族插件，从受保护二进制产出 **可加载、行为等价** 的 PE；正确性必须来自 **独立证据**，而不是插件自证。

### 1.2 “完美脱壳”在本项目中的可操作定义

仓库明确拒绝把 “Universal / Perfect” 当作当前状态标签。可验收的 “完美” 必须同时满足：

| 维度 | 要求 |
|------|------|
| **结构** | 独立 `mida-acceptance` 静态门通过（R0B: `StructuralPassBehaviorPending`；未来行为引擎后才允许 `Accepted`） |
| **加载** | 目标 OS loader 能加载；EP / IAT / TLS / reloc / exception 一致 |
| **行为** | 与未保护或权威参考行为等价（独立 behavioral engine，非插件自评） |
| **可复现** | 固定 SHA-256 输入；隔离 runner；Oreans 族门禁要求连续 10 次 |
| **可扩展** | ≥2 个生产级保护族插件；用例合约 + vault 分离 |

**当前真相：** 目标是完美脱壳；**现状是 vNext 重构中的研究基线 + 遗留 Themida/Oreans 管线**，不是 1.0 产品。R0B 与 R1 纯 PE 是地基；行为与多族闭环仍远。

### 1.3 交付序列（架构契约 + 复审状态）

```text
R0B  独立 acceptance 静态内核          ✅ 已落地（提交 + 本机测试绿）
R1   纯 PE 模型 + rebuild 管线         ✅ R1-A..E 合成 corpus 关闭（MSVC workspace 绿）
     R1-E 合成 structural corpus      ✅ closed；live smoke 仍开放
     生产 dump 默认 pure              ⬜ 仍 legacy；`--pure-rebuild` opt-in
R2   统一 runtime/event + replay       ⬜ 未开始（debug 仍在 cli/unpacker）
R3   Oreans 插件 + Origin/Lunlun/盲样  ⬜ 遗留逻辑在 cli + packers/themida
R4   第二个独立保护族插件              ⬜ AHK/GTO 仅 experimental profile
1.0  满足 release rule 后才谈          ⬜
```

---

## 2. 仓库结构与职责

```text
crates/
  acceptance/     R0B 独立裁判：字节级 PE 门 + 报告；禁止依赖生产 crate
  core/           调试器/进程原语（Win32）
  pe/             PE 解析/重建；纯模块 vs dumper 适配器（含 pure_rebuild_adapter）
  disasm/         指令解码与扫描
  tracer/         跟踪原语
  packers/themida 遗留 Oreans/Themida 策略（版本/OEP/IAT/反调试/后处理）
  cli/            命令行：unpack / generic-unpack / dump-process / verify
lab/cases/v2/     用例合约（仅 SHA-256 引用外部制品）
docs/             架构与 R0B/R1 契约
tools/            工作区卫生 / 临时探针（勿把探针脚本当产品）
```

**关键边界（不可谈判）：**

1. `mida-acceptance` ↛ `mida-pe` / `mida-core` / packers / cli / tracer / disasm  
2. 纯 PE 模块 ↛ `windows` / `DebuggerCore` / `mida_disasm`  
3. 插件不可绕过 acceptance；legacy oracle **仅比较观察**  
4. 样品 / 脱壳产物 / 日志 / `target` 只在 vault 或 scratch，不进 Git  

**边界证据（复审）：**

- `dependency_boundary.json`：`pass: true`，forbidden 生产 crate 无 violations  
- `pe_purity_boundary.json`：`pass: true`，pure_modules 含 rebuild/byte_map/tls/export/exception  
- `mida-pe` 对 `mida-acceptance` 仅 **dev-dependency**（R1-E 双路径语料），生产 lib 不依赖 acceptance  

---

## 3. 当前能力审计

### 3.1 已具备的能力（证据）

| 能力 | 证据位置 | 成熟度 |
|------|----------|--------|
| 独立静态验收 R0B | `crates/acceptance/*`, `docs/ACCEPTANCE_CONTRACT.md` | **高** — 本机测试全绿；永不 `Accepted` |
| 依赖边界锁 | `dependency_boundary.json` + acceptance 测试 | **高** |
| 纯 PE 模块清单与纯度扫描 | `pe_purity_boundary.json`, `purity_boundary` 测试源 | **高（契约）**；本 shell 未能重链 pe 测 |
| 纯 rebuild / byte-map / pure 适配器 | `rebuild.rs`, `byte_map.rs`, `pure_rebuild_adapter.rs`（`52c4eee`） | **中高**（合成语料；live 默认仍 legacy） |
| Themida 检测、guard、OEP、IAT、trace | `packers/themida`, `cli/unpacker` | **中**（遗留单体；Pascal 对标） |
| 进程 dump + import 重建 + 实验 profile | `pe/dumper/*` | **中**（OreansClassic 默认；AHK/GTO opt-in） |
| Generic dump 门 | `generic_gate` + `gate_vectors.json` | **中**（结构启发式，非 acceptance） |
| 用例 v2 合约 + vault | `lab/cases/v2/*` + `D:\MidaVault\objects\sha256` | **高** — 本机 verifier 全绿 |
| 工件卫生策略 | `ARTIFACT_POLICY.md`, `verify_workspace_hygiene.ps1` | **高** |

### 3.2 脱壳主路径（遗留，仍是“能干活”的路径）

```text
PE 解析 → Themida 检测 → 调试创建进程 → ScyllaHide
  → 调试循环（anti-debug / guard / ACCESS_VIOLATION → OEP）
  → IAT 定位/修复 /（可选）import trace / call-site fix（x86）
  → dump_process（默认 legacy 写出；可选 --pure-rebuild）
  → 后处理（data sections / shrink / anti-dump stub x86）
```

CLI 表面：

- `mida-cli unpack` — Oreans/Themida 主路径  
- `mida-cli generic-unpack` — 无 shrink 的通用 dump + 门  
- `mida-cli dump-process` — 对已运行 PID dump  
- `mida-cli verify` — 与参考比对  
- `mida-acceptance check-static` — 独立结构裁判  

### 3.3 明确缺口（相对“完美脱壳”）

| 缺口 | 影响 | 严重度 |
|------|------|--------|
| **无 behavioral acceptance**（R0B 永不 `Accepted`） | 结构过关 ≠ 能跑 / 行为等价 | **阻塞 1.0** |
| **无统一 runtime/event + replay（R2）** | 调试绑死 Win32 + cli 大循环；难确定性回归 | **阻塞 R3 插件化** |
| **Themida 非 R3 插件契约** | 族策略与引擎未分离；第二族难插 | **高** |
| **默认 dump 仍 legacy**；pure 仅 opt-in | 双路径分叉；维护成本 | **中** |
| **typed import 从 live IAT → pure builder** 未做 | pure 依赖 host extra_data 携带 | **中**（R1-F） |
| **ScyllaHide x86 哈希占位** | x86 注入完整性无效 | **中**（x86 样品） |
| **TLS global_vars 未用于恢复** | 复杂 TLS 样本风险 | **中** |
| **R1-B..E 未提交 / 文档漂移** | ~~已关闭~~（`52c4eee` + 文档对齐） | **已处理** |
| **本机 shell 无 vcvars** | ~~已关闭~~（`tools/_enter_msvc_env.ps1`） | **已处理** |
| **四样品 live 证据包未固化** | Origin+Lunlun+GTO(exp) 已固化；Dali OOS；Lunlun/GTO residual 高 | **低（P1 证据主线基本齐）** |
| **CONTEXT_ALL SetThreadContext** | ~~已关闭~~（core CONTROL\|INTEGER） | **已处理（Origin 首通依赖）** |
| **Dali 明确 out_of_scope** | 四样品中一枚不做完美承诺 | **范围** |

### 3.4 工作区卫生与提交状态（复审）

**已提交：** R0B acceptance、卫生策略、v2 cases、R1-A..E pure rebuild（`52c4eee`）、审计文档。

**不应入库：** `.cargo-target/`、`bash_events/`、`conversations/`、临时 `tools/_*.py`、任何 PE 二进制。

**文档真相句（2026-07-23）：**

`R1-E structural corpus closed; pure dump opt-in; default flip open; live smoke next.`

### 3.5 代码规模与耦合（粗量）

| 区域 | 备注 |
|------|------|
| `cli/unpacker/mod.rs` | 调试主循环 + 策略编排 — **R2/R3 拆分焦点** |
| `pe/dumper/dump_process.rs` | 宿主 dump 编排；接 pure_rebuild_adapter |
| `pe/dumper/*` 实验路径 | GTO heap/container 重量级 |
| `packers/themida` | OEP/IAT/ScyllaHide — 未来 `mida_plugin_oreans` |
| `acceptance` | 相对干净的独立内核 |

---

## 4. 四个样品（+ 对照）审计

制品仅以 SHA-256 存在于 vault；manifest 是唯一合约。**本机已校验对象存在且 size 与 manifest 一致。**

### 4.1 样品清单（vault 复审）

| case_id | 角色 | 保护族 | 引擎路由 | SHA-256（全） | 大小 | 指纹要点 | Oracle | vault |
|---------|------|--------|----------|---------------|------|----------|--------|-------|
| **origin_macro** | regression | oreans_candidate | `mida_plugin_oreans` | `1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7` | 5232656 | PE32+，EP `.boot`，`.winlice`，TLS+reloc | legacy `fe92f992…` **仅比较** | ✅ |
| origin oracle | comparison | — | — | `fe92f992bcf07e630c82ff3a1cfc138a8c2463e3e03f862da171e8781119268f` | 1696768 | 历史 operator 候选 | 非权威 | ✅ |
| **lunlun_software** | development | oreans_candidate | `mida_plugin_oreans` | `8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07` | 4976144 | PE32+，EP `.boot`，`.themida`，TLS+reloc | 无 | ✅ |
| **gto_launcher** | research | ahk_gto_candidate | `future_plugin_ahk_gto` | `4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8` | 8583680 | PE32+，EP `.KI3`，无 reloc，TLS | analysis_ref `dcc411af…` | ✅ |
| gto_ref | analysis_reference | — | — | `dcc411afaafed6bf3fbc52c0c72eddf79f56fc9aea1516b911d49f59c94af379` | 15497216 | 历史工具输出 | 非权威 | ✅ |
| **dali_plugin** | research | packed_managed | **out_of_scope** | `e4f48d5a13589bd7232268d4836f1b7581983536f3310cc066f04d463873165d` | 6129664 | PE32，CLR/`mscoree` | 无 | ✅ |
| plain_pe32 | negative_control | unprotected | generic_static | `5ae16f20b1131e0e030a5f364340fe20d5425be4684bb1b2514ed4ebbb137df3` | 1024 | 合成最小 PE32 | — | ✅ |

**Verifier（本机）：** `manifests_checked: 5`, `objects_checked: 7`, `missing_objects: 0`, `hash_mismatches: 0`, `overall_ok: true`。

### 4.2 每样品目标与风险

#### A. Origin Macro（Oreans 回归主样品）

- **目标：** 遗留 `unpack` + OreansClassic 产出结构门通过；与 legacy oracle **仅观察差异**，不得因 oracle 改 verdict。  
- **路径：** `mida-cli unpack` → `mida-acceptance check-static`（可加 `--oracle`）± `--pure-rebuild`。  
- **风险：** OEP（captured vs crt）；x64 跳过 call-site / anti-dump stub；TLS/cookie；IAT 完整性。  
- **R3 门：** 与 Lunlun + 盲 holdout **连续 10 次** 隔离跑通。

#### B. Lunlun Software（Oreans 开发样品）

- **目标：** 无 oracle 下的独立结构 +（未来）行为门；防 Origin 过拟合。  
- **风险：** 节/版本启发式差异；IAT 边界；shrink 误删。  
- **基线（2026-07-23）：** `live_20260723-163436_p1fix3` → R0B StructuralPass（**degraded**：forced OEP + IAT 41/352 + 无 v3-trace）。

#### C. GTO Launcher（AHK/GTO 研究）

- **目标：** **显式** `--profile=ahk-gto-experimental`；**不**冒充 Oreans 生产。  
- **风险：** heap/container 极重；无 reloc；CRT 敏感。  
- **产品：** R4 候选，非 R3 必过。

#### D. Dali Plugin（托管/CLR）

- **目标：** **范围外**；最多 static + 可选 .NET dump 笔记。  
- **规划：** 保持 `out_of_scope`，不阻塞 native 1.0。

### 4.3 验证协议（Windows + vault；live 需 VS 环境）

```powershell
# 0) 进入 VS x64 开发者环境（必须：link.exe / windows crate 链接）
#    例如 Developer PowerShell for VS 2022，或 vcvars64.bat

# 1) 卫生 + 离线测试
powershell -File tools\verify_workspace_hygiene.ps1
$env:CARGO_TARGET_DIR = 'D:\MidaVault\scratch\cargo-target'
cargo test -p mida-acceptance --offline
cargo test -p mida-pe pure_rebuild --offline
cargo test -p mida-pe r1e_dual_path --offline
cargo test -p mida-pe --test purity_boundary --offline
cargo test -p mida-pe --lib rebuild --offline
cargo test -p mida-pe --lib byte_map --offline

# 2) 合约
python -B lab\cases\verify_manifests.py --objects-root 'D:\MidaVault\objects\sha256'

# 3) 物化到 scratch（禁止写回 repo）
#    从 objects\sha256\<2>\<64> 拷到 D:\MidaVault\scratch\cases\<case_id>\

# 4) Origin（示例；动态执行需 case 授权 + 隔离）
mida-cli unpack <origin> -o <scratch>\origin_u.exe
mida-acceptance check-static <scratch>\origin_u.exe --report <scratch>\origin_r0b.json `
  --oracle <origin_oracle>
# 可选: 同样品 --pure-rebuild 与 legacy 结构对照

# 5) Lunlun / GTO / Dali 按 §4.2；证据只进 vault lab/evidence/
```

**通过判据（当前阶段）：**

- R0B：`StructuralPassBehaviorPending`（exit 0）；永不 `Accepted`  
- Oracle：仅 observations；匹配不升格、不掩盖 Rejected  
- 报告确定性：同一 digest → JSON 确定（无时间戳/主机路径）  
- Oreans 族门（R3）：Origin + Lunlun + holdout × 10  

### 4.4 本机已跑证据摘要

| 检查 | 结果 |
|------|------|
| Vault size/hash vs manifest | **全 match** |
| `verify_manifests.py` | **overall_ok** |
| `unittest lab.cases.test_verify_manifests` | **8 passed** |
| `cargo test -p mida-acceptance --offline` | **全绿**（含 dependency/oracle/static_checks） |
| `cargo test --workspace`（P0） | **412 passed**（MSVC 环境） |
| **Origin live unpack** | **`live_20260723-132326` exit 0；size 13746176；sha256 `0c0923e3…a58efbb`** |
| **Origin R0B candidate** | **`StructuralPassBehaviorPending`，failures=[]**（oracle 仅观察） |
| **Lunlun live unpack** | **`live_20260723-163436_p1fix3` exit 0；size 12980224；sha256 `dd44d9ca…c380`** |
| **Lunlun R0B candidate** | **`StructuralPassBehaviorPending`，failures=[]**（无 oracle；degraded OEP/IAT） |
| **GTO experimental** | **`live_20260723-164707_p1exp` exit 0；size 16445952；sha256 `2bdd7cb2…a6fe`** |
| **GTO R0B candidate** | **`StructuralPassBehaviorPending`，failures=[]**（experimental；cookie/CRT residual） |
| pure-rebuild live compare | **已执行** `live_20260723-165826_p1pure_pure`：R0B 过；file-level vs p1smoke **structural_mismatch**（保留 pure opt-in） |

#### Origin 首通关键路径（vault）

| 项 | 值 |
|----|-----|
| 证据目录 | `D:\MidaVault\lab\evidence\origin_macro\live_20260723-132326\` |
| 诊断（pre-fix） | `phase1_diag_20260723-132013`；失败 run `live_…-130856` / `…-132013` |
| 失败模式 A | virtualized OEP：`SetThreadContext` `ERROR_NOACCESS` |
| 失败模式 B | IAT `trace_one_slot set_thread_context` 同错误（越过 OEP 后） |
| 修复 | `windows_debugger::{get,set}_thread_context` → CONTROL\|INTEGER + Suspend 重试 |
| 成功阶段 | OEP found → IAT 305 slots traced → dump 17 sections → R0B StructuralPass |
| 非目标达成 | **非** Behavioral `Accepted`；**非** 与 oracle 字节一致 |

#### Lunlun StructuralPass 关键路径（vault）

| 项 | 值 |
|----|-----|
| 证据目录 | `D:\MidaVault\lab\evidence\lunlun_software\live_20260723-163436_p1fix3\` |
| 失败/挂死 run | `live_…-161107_p1`（null storm）；`…-162228_p1fix` / `…-162742_p1fix2`（exit 后 v3-trace 挂） |
| 失败模式 A | null-AV `fault=0x0` 被误判 guard hit → 风暴 |
| 失败模式 B | OEP fallback 后 ExitProcess，仍进 IAT v3-trace → 挂死 |
| 修复 | guard 域外 NotGuarded；null-storm≥8 接受 last PossibleOEP；`process_exited` 跳过 v3-trace |
| 成功阶段 | storm escape → forced OEP `0x1401656f4` → skip v3 → dump 14 sec → R0B StructuralPass |
| 质量 residual | IAT rebuild **41/352**；无 v3-trace；虚拟化 OEP；**非** Origin 级恢复 |
| 非目标达成 | **非** Behavioral `Accepted`；**非** 完整 IAT 解密 |

#### GTO experimental 基线（vault；非 Oreans 生产）

| 项 | 值 |
|----|-----|
| 证据目录 | `D:\MidaVault\lab\evidence\gto_launcher\live_20260723-164707_p1exp\` |
| 命令 | `--profile=ahk-gto-experimental --data-sections --no-shrink -v` |
| 成功阶段 | post-attach IAT → OEP 60s timeout → scan OEP → IAT 545/572 → bootstrap `.boot` → R0B StructuralPass |
| WARN residual | SecurityCookie fail-closed；CRT wrapper not patchable；OEP observation timeout |
| 非目标达成 | **非** 默认 profile；**非** R3 Oreans 门；**非** Behavioral `Accepted` |

---

## 5. 架构健康度评分（主观但可辩护）

| 维度 | 分 (1–5) | 说明 |
|------|----------|------|
| 目标清晰度 | 5 | 架构文档与 release rule 明确 |
| 验收独立性 | 5 | R0B 边界与测试强；本机复验绿 |
| 纯 PE 方向 | 4 | R1 实现深，未提交/未默认切换；pe 测本 shell 未链 |
| 运行时抽象 | 2 | 仍是 Win32 调试器直连 + cli 大循环；context 标志已硬化 |
| 插件化 | 2 | themida crate 存在，非 R3 插件契约 |
| 样品工程 | **5** | v2 + vault 绿；Origin/Lunlun/GTO(exp) live 证据 + pure 对照已记 |
| 过程/仓库卫生 | 4 | 硬化已提交；临时 tools 不入库；vault 与 git 分离 |
| 距“完美脱壳” | 2 | 多样品结构候选通过；pure≠legacy；行为与多族未闭环 |

**综合：** 方向正确、R0B/R1 地基扎实；**Origin + Lunlun + GTO(exp) 结构门已过**；pure live R0B 过但 **file-level 与 legacy 不对齐**。主阻塞：**(1) Phase1 收尾卫生（Dali/ScyllaHide）** → **(2) Phase2 pure 对齐（再谈默认 flip）** → **(3) R2 事件引擎** → **(4) R3 Oreans 10×** → **(5) 独立行为验收**。

---

## 6. 后续规划（推荐执行顺序）

原则：**先固化证据与边界，再动运行时，再插件化，最后谈默认路径与 1.0。**  
“完美”按门禁阶梯推进；禁止用历史 oracle 冒充 Accepted。

### Phase 0 — 仓库固化与对齐（0.5–1 天，Windows）

**目标：** 可协作的单一真相源 + 可链测工具链。

1. 在 **VS Developer / vcvars64** shell 中：`cargo test --workspace --offline` 全绿。  
2. 提交 R1-B..E 相关源与测试（排除 `.cargo-target` / conversations / 临时 tools）。  
3. 统一状态句：  
   `R1-E structural corpus closed; pure dump opt-in; default flip open.`  
   同步：`WORKER_HANDOFF` / `VNEXT_R1_ROADMAP` / `README` / 本文件。  
4. 更新 `validation_summary.json` → task `VNEXT-R1-E`。  
5. 可选：清理 `mida-pe` dead_code 警告（tls_bootstrap 等）——不阻塞提交。

**出口：** 干净 tree + 绿测 + 文档一致 + link.exe 可用的 dev 说明。

### Phase 1 — 四样品基线证据包（1–3 天，**必须 Windows + vault**）

**目标：** 可复现失败/成功档案，而非“感觉能脱”。

| 样品 | 动作 | 状态 | 归档（vault only） |
|------|------|------|--------------------|
| Origin | legacy unpack；R0B；oracle 观察 | **✅ `live_20260723-132326` StructuralPass** | candidate SHA、r0b、notes、unpack log |
| Origin pure | 同输入 `--pure-rebuild` 对照 | **✅ R0B 过；file structural_mismatch vs p1smoke** | `live_20260723-165826_p1pure_pure` + compare JSON |
| Lunlun | unpack + R0B（无 oracle） | **✅ `live_20260723-163436_p1fix3` StructuralPass（degraded）** | 同上 + residual 质量说明 |
| GTO | `--profile=ahk-gto-experimental` | **✅ `live_20260723-164707_p1exp` StructuralPass（experimental residual）** | 阶段矩阵 + WARN 点（notes） |
| Dali | static + OOS 笔记 | ⬜ 低优先级 | 一页研究笔记 |

交付模板：`D:\MidaVault\lab\evidence\<case_id>\<run_id>\`

- `candidate.sha256`, `r0b_candidate.json`, `unpack.stdout.txt`, `notes.md`, `run_meta.json`  
- **禁止** exe 进 Git  

**出口（更新）：** Origin + Lunlun + GTO(experimental) 均已 ≥1 次 StructuralPass；Origin ×3 无回归已做。完整质量出口仍可选：Lunlun IAT/OEP 提升、pure-rebuild 对照、Dali OOS 笔记。

### Phase 2 — R1 收口（可选 R1-F，1–2 周）

1. **Live pure vs legacy**（Phase 1 数据）：结构门、节 VA、import/IAT DD。  
2. **Import typed rebuild（R1-F）：** host 解析 IAT → pure `ImportTableBuilder`（纯侧仍无 Win32）。  
3. 仅当 pure ≥ legacy **结构** 且 Origin/Lunlun 不回归 → 再讨论默认 `--pure-rebuild`。  
4. 清理 dumper 内可下沉 pure 的重复序列化。

**非目标：** 行为 Accepted；删 legacy。

### Phase 3 — VNEXT-R2 Runtime / Event Engine（2–4 周）

**目标：** 单一事件泵 + 地址类型 + 双后端。

```text
                    +---------------------+
  packer plugin --> | Runtime Event Engine | <-- PE pure APIs
                    |  wait / ack / BP /   |
                    |  thread lifetime     |
                    +----------+----------+
                     Win32 backend | Replay backend
                                   v
                            确定性回归测试
```

切片建议：

1. 地址新类型：`Va`, `Rva`, `FileOffset`, `PreferredBase`, `RuntimeBase`。  
2. 提升 `debug_event_lifecycle` → 引擎 API；从 `cli/unpacker` 抽离循环。  
3. `DebuggerCore` trait 稳定 + `WindowsDebugger`。  
4. Replay backend：CREATE_PROCESS / EXCEPTION / LOAD_DLL / EXIT 最小集。  
5. CLI 变薄：参数 + 插件选择。

**出口：** 至少一个合成 replay 不触 Win32 跑通 guard→OEP 骨架；live 仍可用。

### Phase 4 — VNEXT-R3 Oreans 插件（3–6 周）

1. `PackerPlugin` trait（identify / observe / advise dump）。  
2. 迁移 `packers/themida`；cli 只调度。  
3. Origin + Lunlun + **盲 holdout**；连续 **10×** `StructuralPassBehaviorPending`。  
4. 修 ScyllaHide x86 真哈希；评估 TLS global_vars。

**出口：** R3 记入 validation_summary；oracle 仍非权威。

### Phase 5 — Behavioral Acceptance

1. 行为证据：受控 loader 探测、API 轨迹摘要、确定性 I/O、禁网。  
2. acceptance **扩展** behavioral 模块，仍禁止依赖 packers。  
3. 契约升版；R0B 静态仍 fail-closed。

**出口：** 证据充分时可 `Accepted`；否则保持 Pending。

### Phase 6 — R4 第二族 + 1.0

1. AHK/GTO → `mida_plugin_ahk_gto`（默认仍 opt-in）。  
2. Dali 保持 OOS / 未来 managed 独立线。  
3. 1.0：R0B–R4 门全绿 + 双插件 + holdout + 10× Oreans。

### 并行工程债

| 项 | 优先级 |
|----|--------|
| 开发 shell 固化 vcvars + `CARGO_TARGET_DIR` 到 vault | **P0**（否则 pe/cli/live 全堵） |
| 提交 R1-B..E + 文档对齐 | **P0** |
| 四样品证据包 | **P0** |
| ScyllaHide x86 哈希 | P1 |
| 缩小 `unpacker/mod.rs`（随 R2） | P1 |
| ExitProcess import stub / IAT writable 检测 | P2 |
| TLS global_vars 使用 | P2 |
| 禁止 docs 刷完成报告堆 | P2 |

---

## 7. 里程碑与成功度量

```text
M0  工作区提交 + 文档对齐 + vcvars 下 workspace offline tests 绿
M1  四样品证据包（vault）— Origin/Lunlun R0B 基线数字
M2  R1-E/F 关闭；pure vs legacy 对照表公开
M3  R2 replay 最小闭环
M4  R3 Oreans 10× Origin+Lunlun+holdout
M5  Behavioral 证据 MVP → 首个 Accepted（若证据充分）
M6  R4 第二族插件 + 1.0 评审
```

**反模式（禁止）：**

- 用 legacy oracle 字节相等当作 Accepted  
- 无 holdout 的 “全绿”  
- 把 Dali/GTO 失败算 Oreans 失败或反之  
- 样品进 Git  
- 插件 crate 依赖 acceptance 或反向  

---

## 8. 建议的近期两周看板（可执行）

### Week 1

- [x] 固定 VS/vcvars 开发入口；`cargo test --workspace --offline` 绿（2026-07-23 复验 412/0）  
- [x] Commit R1-B..E；统一 README / R1 roadmap / handoff 状态句  
- [x] `validation_summary.json` → `VNEXT-R1-E`  
- [x] vault 物化 Origin + Lunlun；live unpack + R0B 证据进 vault（Origin 全路径；Lunlun degraded）  
- [x] Origin ×3 稳定性抽检（`STABILITY_20260723_p1smoke.md`；3/3 StructuralPass）  
- [x] 同样品 `--pure-rebuild` 对照；记 structural mismatches（`live_20260723-165826_p1pure_pure`；**不 flip 默认**）  
- [ ] 确认 ScyllaHide x64 哈希与现场二进制一致  
- [x] 提交 storm/exit + guard 硬化（`eaf8468`；Origin ×3 无回归已验证）  
- [ ] Lunlun OEP/IAT 质量提升后再 smoke（非阻塞结构门；需独立切片+复验）  


### Week 2

- [x] GTO experimental 一次受控跑；只记录不修花（`live_20260723-164707_p1exp`）  
- [ ] Dali 一页 OOS 说明  
- [ ] 起草 `PackerPlugin` + Runtime 接口草图（docs PR）  
- [ ] R2 切片 0：从 `unpacker` 抽出 event loop 状态机接口（行为不变）  

---

## 9. 结论

1. **最终目的**是可证据化的“完美脱壳”（loader-valid + 行为等价 + 可复现 + 多族），不是单一启发式 dump。  
2. **当前最强资产：** 独立 acceptance（R0B，本机已复验）+ 纯 PE rebuild（R1）+ vault 合约 + **Origin/Lunlun live StructuralPass 证据包**。  
3. **当前最强负债：** Lunlun degraded IAT/OEP；pure≠legacy file layout（image_base/winlice）；无行为/replay；单体调试循环。  
4. **四个样品职责：** Origin/Lunlun 扛 Oreans 主线；GTO 未来第二族；Dali 明确范围外。  
5. **下一步唯一正确顺序（验证驱动）：** Phase1 收尾（Dali OOS / ScyllaHide 卫生）→ **有计划的 pure 对齐（Phase2）** → R2 引擎 → R3 Oreans 门禁 → 行为 Accepted → R4。禁止跳过门禁默认 flip pure。  
6. Windows 主机消除了“无法物化样品”的环境借口；**完美脱壳仍取决于证据阶梯，不取决于换了 OS。**

---

## 10. 参考索引

| 文档 | 用途 |
|------|------|
| [VNEXT_ARCHITECTURE.md](VNEXT_ARCHITECTURE.md) | 总架构与交付序列 |
| [ACCEPTANCE_CONTRACT.md](ACCEPTANCE_CONTRACT.md) | R0B 裁决 |
| [VNEXT_R1_ROADMAP.md](VNEXT_R1_ROADMAP.md) / [VNEXT_R1_PE_API.md](VNEXT_R1_PE_API.md) | 纯 PE |
| [../WORKER_HANDOFF.md](../WORKER_HANDOFF.md) | 最近切片交接 |
| [../ARTIFACT_POLICY.md](../ARTIFACT_POLICY.md) | 制品禁入策略 |
| [../lab/cases/v2/](../lab/cases/v2/) | 样品合约 |

_本报告由 OpenHands agent 基于仓库源码、契约、vault 校验与本机可运行测试生成；**不含** live 脱壳成功声明。临时探针 `tools/_vault_size_check.py` / `tools/_write_audit_doc.py` 可删，勿当产品。_
