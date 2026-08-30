# 硬编码审计 T016 增补（B1' 线阶段收尾）

> 审计：2026-08-30　审计人：worker（TASK-016）· 前置：`docs/HARDCODING_AUDIT_20260829.md`（T0.7–T0.10 已清）
> 范围：B1' 路径授权文件逐行审（先审后改，行为中性铁律）；报告-only 文件只读发现清单。
> 扫描工具：`python tools/_hardcode_scan.py`（gate 类别 = win_path/vault_path/sample_hex，生产代码 0 命中，见 §6）。

## 一、结论（先讲重点）

1. **授权文件生产代码无样品级硬编码进入控制流**（该结论**仅覆盖 T014/T015 引入的字面量**，逐处核实见 §4；既有 GTO-UI 样品锚区见新增 §九，处置 = STOP 级留待下一战役）：T014/T015 的快速修复留下的 `0x1136e0`/`0x1137d0`/`0x1681d1`/201/192/74 等魔法数**全部只在测试与注释里**，不参与生产控制流。
2. **本次新增命名常量 5 组**（行为中性，仅把裸字面量提为具名 const + 注释来源与边界）：见 §3。
3. **顺带消除一处重复代码**：`inject_scylla_hide` 非 staging 路径的 38 行哈希校验与 `verify_helper_hashes` 逐字重复 → 复用已存在函数（行为零变化，错误字符串逐字一致）。
4. **报告-only 文件发现 8 处样品级/启发式硬编码**，均**不进控制流修复**（改动需老板另行授权）：见 §5。
5. **preflight 新增 ScyllaHide readiness 检查**（`crates/acceptance/src/preflight.rs`）：ini 存在/可解析/三零键（`KiUserExceptionDispatcherHook=0`/`NtContinueHook=0`/`NtCloseHook=0`）+ 注入器/钩子/ini 三件套在位；**只查结构不查内容指纹**（不写死 ini sha256）。见 §7。

## 二、授权文件逐行审计（先审后改）

授权清单：`scyllahide.rs`、`trace_imports/mod.rs`、`trace_imports/slot.rs`、`dump_process.rs`、`iat_partial_accept.rs`、`iat_gap_retarget.rs`、`import_rebuild.rs`、`iat_completeness.rs`、`preflight.rs`（+各测试模块）。
> **勘误（R1）**：授权清单里的 `iat_completeness.rs` 实际路径为 `crates/pe/src/iat_completeness.rs`（工单误写为 `dumper/` 前缀）；已核对 `201/192` 仅存在于该文件 :281-282 的 doc 注释（诊断说明），原审计结论对该文件仍成立。

### 2.1 审出的魔法字面量分类（生产代码，控制流参与度）

| 位置 | 字面量 | 性质 | 处置 |
|---|---|---|---|
| `trace_imports/mod.rs:160,599,802` | `0x10000`（用户态地址下限） | Windows 用户/内核地址约定（非样品） | **命名常量** `MIN_USER_MODE_ADDRESS` |
| `trace_imports/mod.rs:98`、`slot.rs:286,325` | `EFlags \|= 0x100`（TF 位） | x86 架构位（非样品） | **命名常量** `X86_EFLAGS_TRAP_FLAG` |
| `scyllahide.rs:386,477` | `"mida-scyllahide-{pid}"`/`"mida-scyllahide-evidence-{pid}.log"` | 工程命名（跨 prod/test 重复） | **命名常量** `SCYLLA_STAGING_DIR_PREFIX`/`SCYLLA_STAGING_EVIDENCE_PREFIX` |
| `scyllahide.rs:395-397` | `"InjectorCLIx64.exe"`/`"HookLibraryx64.dll"`/`"scylla_hide.ini"` | 外部工具固定文件名（T013 实证） | **命名常量**（cfg 选择 x64/x86） |
| `scyllahide.rs:180,268` | `"nowait"` | InjectorCLI 参数契约 | **命名常量** `SCYLLA_INJECTOR_NOWAIT_ARG` |
| `iat_gap_retarget.rs:296,318` | `1..64u32` / `i + 24` | 邻域启发式窗口（非样品锚点） | **命名常量** `GAP_NAME_NEIGHBOR_MAX_DELTA`/`GAP_NAME_NEIGHBOR_FUNC_WINDOW` |
| `iat_gap_retarget.rs:352-382` | `0x0A/0x0E`（uType）、`0x0E/0x0C/0x0D/0x02/0x10`（SendMessage imm） | Win32 API 常量（MB_ICON*/WM_*） | **命名常量** `MSGBOX_UTYPE_IMMEDIATES`/`SENDMESSAGE_WM_IMMEDIATES` |
| `dump_process.rs:698,702` | `0x1000` PE 头读取 | PE 规范（头 ≥ 4KiB） | **命名常量** `PE_HEADER_READ_BYTES` |
| `dump_process.rs:1034` | `0x100_000` live .text 读上限 | 启发式上限（防超大） | **命名常量** `LIVE_TEXT_READ_CAP_BYTES` |
| `dump_process.rs:1365,2778` | `0x100000` 巨节日志阈值 | 仅日志不参与控制流 | **命名常量** `HUGE_SECTION_LOG_THRESHOLD` |
| `dump_process.rs:2275` | `0x10000` cmd 表计数上限 | 启发式上限 | **命名常量** `CMD_TABLE_COUNT_MAX` |
| `iat_partial_accept.rs` | 95/100/4 | 已有具名常量（`PARTIAL_ACCEPT_*`） | ✅ 已达标，未动 |
| `iat_completeness.rs` | 201/192 | 仅注释（诊断说明） | ✅ 不参与控制流 |
| `import_rebuild.rs` | — | 无魔法字面量 | ✅ 未动 |

### 2.2 零改动结论（T014/T015 遗留数字）

- `0x1136e0`（IAT 基址）、`0x1137d0`（缺陷槽）、`0x1401681d1`（NX 指针固化）、`0xde785`（call site）：**生产代码仅在注释**（`dump_process.rs:2433,2849,5730` 注释；`iat_partial_accept.rs:75,108` 注释"201 slots on this sample"；`iat_gap_retarget.rs:47,100` 注释）。测试里的这些数字是**回归夹具**（模拟该样品的几何），不是生产控制流。[已验证：逐行 grep 生产段]
- `201`（槽数）/`192`（启动站点）/`74`（Unresolved）/`75`（OK IAT 日志）：只在 `iat_completeness.rs:281-282` 注释 + 测试构造。生产计算全从 `iat.size/ptr_size`、`report.slots.len()`、实际 trace 结果得出。[已验证]

## 三、新增命名常量清单（含适用边界）

| 常量 | 值 | 文件 | 适用边界 |
|---|---|---|---|
| `MIN_USER_MODE_ADDRESS` | `0x1_0000` | `trace_imports/mod.rs` | IAT 槽"已解析系统 API"判定下限；Windows 用户/内核地址约定 |
| `X86_EFLAGS_TRAP_FLAG` | `0x100` | `trace_imports/mod.rs` | TF 位；x86/x64 EFlags 架构定义 |
| `SCYLLA_STAGING_DIR_PREFIX` | `"mida-scyllahide"` | `scyllahide.rs` | 运行期 staging 目录前缀（OS temp 下，pid 键） |
| `SCYLLA_STAGING_EVIDENCE_PREFIX` | `"mida-scyllahide-evidence"` | `scyllahide.rs` | P-8 证据日志前缀（pid 键） |
| `SCYLLA_HIDE_INI_FILE_NAME` | `"scylla_hide.ini"` | `scyllahide.rs` | 注入器读取的 hооk 配置文件名（T013 实证） |
| `SCYLLA_INJECTOR_FILE_NAME`/`SCYLLA_HOOK_FILE_NAME`（cfg 选择） | `InjectorCLIx64.exe`/`HookLibraryx64.dll`（x86 变体） | `scyllahide.rs` | staging 副本文件名；随构建架构选择 |
| `SCYLLA_INJECTOR_NOWAIT_ARG` | `"nowait"` | `scyllahide.rs` | InjectorCLI 参数契约 |
| `GAP_NAME_NEIGHBOR_MAX_DELTA` | `64` | `iat_gap_retarget.rs` | 零槽邻域搜索上界（槽单位） |
| `GAP_NAME_NEIGHBOR_FUNC_WINDOW` | `24` | `iat_gap_retarget.rs` | 原导入表函数窗口（函数数） |
| `MSGBOX_UTYPE_IMMEDIATES` | `[0x0A, 0x0E]` | `iat_gap_retarget.rs` | MessageBoxW uType（MB_ICONWARNING/ERROR） |
| `SENDMESSAGE_WM_IMMEDIATES` | `[0x0E,0x0C,0x0D,0x02,0x10]` | `iat_gap_retarget.rs` | SendMessageW 消息常量（WM_*） |
| `PE_HEADER_READ_BYTES` | `0x1000` | `dump_process.rs` | PE 头读取缓冲（规范） |
| `LIVE_TEXT_READ_CAP_BYTES` | `0x100_000` | `dump_process.rs` | call-site 验证 live .text 读上限 |
| `HUGE_SECTION_LOG_THRESHOLD` | `0x100_000` | `dump_process.rs` | 巨节日志阈值（仅诊断） |
| `CMD_TABLE_COUNT_MAX` | `0x10000` | `dump_process.rs` | AHK cmd 表计数合理性上限 |
| `SCYLLA_HIDE_REQUIRED_ZERO_KEYS` | `["KiUserExceptionDispatcherHook","NtContinueHook","NtCloseHook"]` | `preflight.rs` | readiness 检查三零键（T006R/006R2/006R3 实证） |
| `SCYLLA_HIDE_INI_FILE_NAME` / `SCYLLA_INJECTOR_X64_FILE_NAME` / `SCYLLA_HOOK_X64_FILE_NAME` | 见 §7 | `preflight.rs` | readiness 三件套文件名 |

**行为中性证据**：全部为「同值改名 + 注释」，无一处改变数值、分支或错误字符串；全仓测试计数只增不减（见 §8）。

## 四、修复 diff 对照（要点）

- `scyllahide.rs`：新增 12 个 const；非 staging 路径 38 行重复哈希校验 → `verify_helper_hashes(...)` 单行调用（错误字符串逐字保留）；`"nowait"`×2 → const；staging 文件名/目录前缀 → const；测试同步改 const 引用。
- `trace_imports/mod.rs` + `slot.rs`：`0x10000`×3 → `MIN_USER_MODE_ADDRESS`；`0x100`×3 → `X86_EFLAGS_TRAP_FLAG`（slot.rs 经 `super::` 导入）。
- `iat_gap_retarget.rs`：邻域/窗口/消息常量提为 const；uType 检查改 `contains`。
- `dump_process.rs`：5 处魔法数 → const。
- `preflight.rs`：新增 readiness 模块（7 个单测）。

完整 diff：`git diff HEAD -- <文件>`（工作区留档，未提交）。

## 五、报告-only 文件只读发现清单（不改，改动需老板另行授权）

| 文件 | 发现 | 分级 |
|---|---|---|
| `cli/src/unpacker/mod.rs`（text-poll/C-7 段 1191-1234） | `+0x10` 双区域采样、prologue 特征字节集 `{0x53,0x55,0x56,0x57}`/`41 54..57`/`48 83|81|8B`、classic8 `41 57 41 56 41 55 41 54 55 57 56 53 48 83` | 样品/壳行为启发式（XX-11-B #17）——**进控制流**，改需实弹再验证 |
| `cli/src/unpacker/mod.rs:1515` | `Duration::from_secs(12)` T0.5-R2 grace window | 启发式时序——进控制流 |
| `cli/src/args.rs:416` | `wait_sec = 60u64` | 默认超时——参数化前例（`--wait` 可覆盖？） |
| `cli/src/unpacker/oep_scan.rs` | `WRAPPER_LEN=18`、`CHUNK_OVERLAP=32`、`MAX_WEAK=32`、`0x1000/0x2000` 扫描窗 | 静态 OEP 扫描启发式（已 const，但值源自样品观测） |
| `crates/pe/src/dumper/data_reinit.rs` | 高低位指针带已 const（T0.7 已清）；`0x2b992ddfa232` 等样品值仅在注释 | ✅ 已达标 |
| `crates/core/src/windows_debugger.rs:505` | "skipping thread for HW-BP apply (T0.5-R2 partial tolerance)" | 行为已文档化，无裸魔法数 |
| `crates/cli/src/unpacker/av_handler.rs` | 风暴元组判定逻辑在 av_oep_handler（已 const 1024）；av_handler 无裸样品数 | ✅ 已达标 |
| `crates/packers/themida/src/runtime/av_oep_handler.rs` | `GUARDLESS_AV_STORM_TUPLE_THRESHOLD=1024`（已 const，T012 校准） | ✅ 已达标 |
| `cli/src/unpacker/helpers.rs:451`（测试） | `D:\MidaVault\lab\config\scylla_hide_no_excdispatch.ini` 字面量 | 测试夹具（vault 路径），gate 扫描跳过测试文件 |
| `cli/src/unpacker/antidebug_controller.rs:2033`（测试） | 同上 | 测试夹具 |

**共同点**：以上除测试夹具外均属**壳行为/时序启发式**，不是"本样品路径"锚点；清除需要行为性改动（换样品即变）→ 按工单红线 STOP 请示，属下一战役（需实弹再验证）。

## 六、扫描证据

```
$ python tools/_hardcode_scan.py
（生产代码）sample_hex: 0 · win_path: 0 · vault_path: 0 · high_aslr: 0
long_hex: 22（全部为合法常量：PE 特征/算法常量/签名/通用示例地址，与 T0.10 基线一致）
```
[已验证：工具输出见 runs/20260830-TASK-016.md §验收标准 3]

## 七、preflight ScyllaHide readiness（新增）

`crates/acceptance/src/preflight.rs` 新增（全部 pub，可离线单测）：
- `parse_ini_sections(&str) -> BTreeMap<"section.key", value>`：纯 INI 解析（`[Section]`/`Key=Value`/`;` 注释）
- `check_scylla_hide_ini_content(&str) -> ScyllaHideReadiness`：三零键在列且=0，缺失/非零/多段歧义均 fail-loud
- `check_scylla_hide_helpers(&Path) -> ScyllaHideReadiness`：ini + InjectorCLIx64 + HookLibraryx64 三件套在位
- `check_scylla_hide_readiness(ini, helper_dir) -> ScyllaHideReadiness`：组合入口

**明确不做**：不写死 ini sha256（内容可演进，只查结构）；不把检查接进 `run_offline_preflight`（涉及 main.rs 等清单外文件 → 留待授权）。
**判别力证明**：临时禁用 missing-key 分支 → `scylla_hide_missing_key_fails_loud` 变红（assertion failure, exit 101）→ 字节级恢复 → 7/7 绿。（原始输出见 runs/20260830-TASK-016.md §验收标准 4）

## 八、回归证据（行为中性铁律）

- `cargo test --workspace --offline` → **EXIT=0**；pe 1054 / themida 176 / cli 580 / acceptance lib **263**（256+7 新增）——计数只增不减。[已验证]
- `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 0（无新增告警；既有告警为基线）。
- `cargo fmt --all -- --check` → 0。
- `git diff --stat`：仅授权 6 文件 +487/-66。（R1 勘误：T016 审计时误记 +482，实测 +487/-66）

## 九、既有 GTO-UI 样品锚区（TASK-016R1 审计完整性补正）

> 本单补充 TASK-016 审计遗漏盘点的**既有**（T014/T015 之前已在）GTO-UI 样品锚区——`crates/pe/src/dumper/dump_process.rs`。这些常量/裸字面量全部被 `stage_plan`/`capture_policy`（AhkGto 专属门控，对 B1'/xx21b 路径为死代码）保护，**对 B1' 不可达**；但按 T016 工单判据（任何把"本样品路径"写死进控制流的字面量必须进审计报告），它们属于样品级硬编码进入控制流，本单**不改**：清除需行为性改动（改补丁语义/门控）+ 实弹再验证 → **STOP 级，留待下一战役工单**。

| 位置（dump_process.rs） | 常量/字面量 | 门控方式 | 对 B1' 是否可达 | 处置 |
|---|---|---|---|---|
| :2298-2299（AHK cmd 表计数保持路径） | 裸字面量 `0x147868` / `0x147888` | `capture_policy.is_hot_root(0x147868)` | 不可达 | 既有代码、AhkGto 门控，清除需行为性改动+实弹再验证 → **STOP 级** |
| :2362（同上保持路径） | 裸字面量 `0x147888` | `capture_policy` 分支内 | 不可达 | 同上 → **STOP 级** |
| :3551（WinMain call-site 补丁） | 具名 `SITE_RVA = 0x5c5d` | `stage_plan`（AhkGto 专属） | 不可达 | 同上 → **STOP 级** |
| :3571-3572 | 具名 `CALL_RVA = 0x6757`、`TARGET_RVA = 0x35520`（注释含 0x1b10） | `stage_plan` | 不可达 | 同上 → **STOP 级** |
| :3735-3736 | 具名 `CALL_RVA = 0x63f4`、`TARGET_RVA = 0x364e0` | `stage_plan` | 不可达 | 同上 → **STOP 级** |
| :3652 | 具名 `CHECK_RVA = 0x34dbb` | `stage_plan` | 不可达 | 同上 → **STOP 级** |
| :3675 | 具名 `CLASS_RVA_SITE = 0x34ed4` | `stage_plan` | 不可达 | 同上 → **STOP 级** |
| :3692 | 具名 `CW_CLASS_RVA = 0x34f66` | `stage_plan` | 不可达 | 同上 → **STOP 级** |
| :3719 | 具名 `STYLE_RVA = 0x34f59` | `stage_plan` | 不可达 | 同上 → **STOP 级** |

**共同点**：均为 GTO-UI 样品补丁锚（xx21b 专属 RVA），既有代码、`stage_plan`/`capture_policy` AhkGto 门控、对 B1'/xx21b 死代码；清除必须行为性改动 + 实弹再验证 → **STOP 级，留待下一战役工单**（本单不改任何生产代码）。

**R1 补正范围**：仅上述文档增补；GTO-UI 区生产代码（`dump_process.rs` 等）一行未动。[已验证]
