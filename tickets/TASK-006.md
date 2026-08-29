# TASK-006 — 原版宿主重脱壳，根治会话绑定（解开 T0.5）

- **优先级**：P1
- **状态**：⏸ **前置未完成**（必须等 TASK-004 通过验收才能开跑）
- **岗位**：developer（实弹执行，单 worker 连续执行）
- **授权**：老板 2026-08-29 裁定，见 `docs/DECISIONS.md` D-011
- **账本**：XC-XXI-B 余格（开跑前向总指挥确认当前格数）

## 项目背景

MagicMida vNext 从受保护的 Windows PE 里 dump 出可加载的产物。`keep_runtime_base` 路线会保留运行时已解析的绝对指针 —— 这在"同一次会话里 dump 完立刻加载"是对的，但系统 DLL 的基址随每次开机的 ASLR 变化。

2026-08-29 07:58 机器重启后实锤：已脱壳宿主 `rev2_unpacked.exe` 在 RVA `0x112c10` 固化了旧会话 ntdll 的绝对地址 `0x7ffeeb426390`（当前 ntdll 基址 `0x7ffa952a0000`），启动初始化期 RVA `0x21cc0-0x21cd8` 的 `call rax` 取指即 AV（c0000005）。宿主根本没走到加载 `core.dll` 那一步，所以 T0.5（Run UI 事件驱动补测，要把 Run verdict 从 PARTIAL 升到 FULL）整个被卡死，状态 `BLOCKED_ENV`。

老板已裁定走根治路径：**在当前 ASLR 会话里对原版宿主重新脱壳**，产出一个与当前会话一致的宿主，再继续 T0.5。
另一个选项（接受 Run verdict 长期停在 PARTIAL）已被否决，理由是那等于承认"产物不可移植"这个引擎级缺陷不修。

## 为什么必须等 TASK-004

TASK-004 才是验证"sidecar 会话模块表清洗链路"能不能正确工作的工单。**在清洗链路未验证之前重脱壳，等于拿一格实弹去赌一个未验证的修复。** TASK-004 通过之后再开跑。

## 输入（全部只读，身份必须先核）

| 材料 | 位置 |
|---|---|
| 原版宿主（壳态） | `xiongxiong.exe`，身份见 `lab/cases/v2/xiongxiong_duokai.json` 的 `protected_input` |
| 配套配置 | `config.ini`，`[Loader] DllVersion=1.1` |
| 完美候选 DLL | `core_perfect_candidate.dll`，sha256 `3650ea6c0a88c731d4b613eaa533ab1d48258ce782843a5661ca6c683fd9b64e`（14,435,328 B），vault `xx21b_perfect_output/` |
| 旧战役基线（对照用，**不是**新产物的验收依据） | `docs/XX21B_CORE_PERFECT_REPORT_20260829.md`、`AUTHORIZATION_XX_20260827.md` |
| 缺陷机制 | `docs/KNOWN_ISSUES.md` C-1、`docs/ENGINE_SESSION_BINDING_FIX_20260829.md` |
| T0.5 重跑脚本（已就绪） | `tools/xx21b_t05_ui_drive.py`、`tools/xx21b_t05_ui_drive_resume.py` |

**开跑第一步就是核身份**：把 `xiongxiong.exe` 解析成 vault 对象并与 manifest 的 `protected_input` 比对。不匹配 = `SampleIdentityMismatch` = 立即 STOP，不许继续。

## 你要改的文件

**不改生产代码。** 这是一次执行 + 验证工单。如果过程中发现必须改引擎代码，**停下来单独开工单**。

## 任务目标（一句话可观察的变化）

产出一个新的已脱壳宿主，它在**当前** ASLR 会话里能正常启动并加载 `core_perfect_candidate.dll`，从而让 T0.5 的 Run UI 事件驱动补测能够真正开始跑。

## 具体要求（按顺序，每步落盘证据）

1. **身份核验**：`xiongxiong.exe` 与 `config.ini` 对照 manifest；记录 sha256 + size。不匹配即 STOP。
2. **记录当前会话 ASLR 基线**：跑一次，记下 ntdll / kernel32 / urlmon 等系统 DLL 的当前基址。这是后面判断"产物是否绑定本会话"的对照物。
3. **重脱壳**：走现有 Oreans/WinLicense 主干路线产出新宿主。用 TASK-004 已验证的 sidecar 归档（`<output>.session_modules.json` 必须真的落盘，检查它非空且能被 `parse_session_table` 读回）。
4. **S1-S4 重新验收**（**旧战役结论不适用于新产物**，必须重跑）：
   - S1 结构 R0B 12/12；
   - S2 `.text` 明文可读率（对照旧基线 222/222 blocks 熵<6.5）；
   - S3 load_no_crash 10/10 **隔离运行**（不许 retry 挑结果）；
   - S4 行为对齐（窗口标题 / 模块集 / `config.ini` 逐字节）。
5. **新增一条 S3 维度：跨会话可移植性的可观察证据**。至少做到：用 `/session-clean` 拿新产物 + 第 2 步记录的会话表跑一次扫描模式（不重写），确认报告里"落在本会话系统 DLL 区间的绝对指针"数量与预期一致。
   > 真正的"跨 ASLR 重启存活"需要一次真实重启。如果本次会话内无法重启机器，**明确写成待验证项，不许含糊过去**（这正是 T0.7 被降级的原因，别重犯）。
6. **续跑 T0.5**：新宿主可用后，用 `tools/xx21b_t05_ui_drive.py` 驱动 UI 事件，目标是让 `URLDownloadToFileA` 的调用点**实际触发**（RIP 落入 urlmon.dll 调用点），`deny_all` 拒绝下载是预期终态行为。据此给出 Run verdict：FULL / 仍 PARTIAL（带 reason）。

## 约束与红线

- **红线**：`NO_BYPASS=1` 全程；样品身份哈希不匹配即 STOP；样品不外发；禁止伪造或推断成证据。
- 网络保持 `deny_all`（防火墙阻断 + 记录零出站 + 零 WinINet 事件作为证据）。下载被拒是**预期结果**，不是失败。
- 隔离环境执行；所有产出入 vault（`D:/MidaVault/lab/evidence/`），不进 Git（见 `ARTIFACT_POLICY.md`）。
- 不得改动 `crates/` 下任何文件。
- 不得改 `lab/cases/v2/*.json`（新产物如需入 manifest，走单独的 manifest 修订评审）。
- 不得提交、不得推送。
- **不得用旧战役的 S1-S4 结论替代新产物的验收。** 新产物是新身份。

## 验收标准

1. 身份核验通过（贴出 sha256/size 与 manifest 声明的对照）。
2. 新宿主 S1 = 12/12 PASS。
3. 新宿主 S2 `.text` 明文率有具体数字（x/y blocks，熵阈值写明）。
4. 新宿主 S3 load_no_crash = **10/10 隔离运行**（贴出 10 次各自的输出，不许只贴汇总）。
5. 新宿主 S4 行为对齐结论 + 差异清单（无差异也要写"无差异"并说明比了哪几项）。
6. `<output>.session_modules.json` 存在、非空、可被 `parse_session_table` 读回（贴命令输出）。
7. T0.5 续跑给出明确 Run verdict（FULL 或 PARTIAL + reason），并贴出 `deny_all` 落实证据（防火墙记录条数 + ETW 事件数）。
8. 账本记账：本次消耗几格，写清楚。

## 交付格式

写到 `runs/<日期>-TASK-006.md`。每条验收标准逐条对照，附命令与**原始输出**。
每条结论标可信度：`[已验证]` / `[推断]` / `[存疑]`。
最后必须有「我不确定的事」一节，**并且必须明确写出"跨真实 ASLR 重启存活"这一项是否验证过**。

## 停止规则

- 身份不匹配 → STOP，不许继续。
- S1-S4 任一项 fail → **停下来记录原因与阻塞点收口**，不要反复重跑刷结果。
- 同一验收标准连续 2 次不通过 → 停，报告工单本身是否有问题。
- 发现需要改引擎代码才能过 → 停，单独开工单，不要在实弹工单里顺手改生产代码。
