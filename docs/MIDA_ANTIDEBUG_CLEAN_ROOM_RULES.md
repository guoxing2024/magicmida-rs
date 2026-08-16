# MIDA-ADR Clean-Room 规则与第三方依赖边界

> **工作令：** MIDA-ADR-0 —— 建立自研 anti-debug runtime 的第三方依赖边界与 clean-room 规范。
> **状态：** 定稿（文档阶段）。不执行样本、不实现 hook、不复制 ScyllaHide 源码或二进制。
> **基线：** `4fe2cc350378faf8a1408dadb0caf5c30fd20786`。

## 1. 目的

本文件规定 MIDA-ADR 在“参考第三方 anti-anti-debug 工程（主要是 ScyllaHide）”时的法律与技术边界：
哪些内容只能作为外部 oracle，哪些可以参考公开行为，哪些禁止复制，许可证如何记录，源码/二进制如何隔离。

**一句话规则：ScyllaHide 是实验 reference / oracle，不是代码来源。MIDA-ADR 的实现必须是自研的、独立命名、独立配置、独立 schema 的。**

## 2. 角色分离（clean-room）

| 角色 | 职责 | 可接触什么 |
|---|---|---|
| **行为规范作者（spec author）** | 从目标样本的实际行为建立 anti-debug surface inventory 与期望观察（MIDA-ADR-1/2） | 样本二进制（已授权）、样本运行观察、公开文档/论文 |
| **实现 agent（implementer）** | 按行为规范独立实现 controller / runtime | **只读行为规范与公开 Windows 文档（MSDN/ReactOS/ntinternals 等公开资料）**；不读 ScyllaHide 源码 |
| **oracle 操作者（oracle operator）** | 运行 ScyllaHide 对照实验，产出可观察输入/输出记录 | ScyllaHide 二进制（外部 vault）、注入实验、差分日志 |
| **审计者（auditor）** | 核对 provenance、检查禁止项、验证 attestation 契约 | 全部（只读） |

- 行为规范作者与 oracle 操作者可以接触 ScyllaHide **行为**（黑盒观察），但**不向实现 agent 传递 ScyllaHide 源码/配置/内部实现细节**。
- 实现 agent 的代码 review 必须能确认：实现中无 ScyllaHide 代码片段、无其 hook table/profile/配置格式。

## 3. 第三方 artifact 分类

### 3.1 分类

| 类别 | 定义 | 例子 | 允许用途 |
|---|---|---|---|
| **oracle** | 只提供黑盒行为参考的第三方工具 | ScyllaHide InjectorCLI/HookLibrary（外部 vault 封存） | 差分对照实验（MIDA-ADR-7）、验证 MIDA 行为等价性 |
| **reference 文档** | 公开的行为/接口文档 | MSDN、ReactOS 源码（公开）、ntinternals 文章、Themida 公开 paper | 编写行为规范；**ReactOS 源码只能作为文档引用，不得直接复制代码** |
| **prohibited** | 禁止复制或引入仓库的 | ScyllaHide 源码、hook table、`scylla_hide.ini` 配置格式、第三方 DLL/EXE | 无。不得进入仓库，不得成为实现来源 |
| **permitted-cleanroom** | 允许参考其**公开接口签名**的 | Windows API 头文件签名（NTSTATUS、PROCESSINFOCLASS 常量等公开定义） | 声明 API 签名；签名是事实标准，可独立声明 |

### 3.2 硬性禁止项（与 ARTIFACT_POLICY.md 一致并强化）

1. 仓库内不放置第三方 DLL/EXE（`*.dll` / `*.exe` / PE 内容）——ARTIFACT_POLICY.md 已禁止，MIDA-ADR 同样适用。
2. 不直接复制 ScyllaHide 的 hook table、profile、配置格式或实现代码。
3. 不把“自编译第三方代码”写成“自研”。
4. 不以“ScyllaHide 支持什么”反推目标检查什么；surface inventory 必须来自目标实际行为。
5. 不把 `scylla_hide.ini` 或等价配置格式引入 MIDA-ADR profile 格式。

## 4. ScyllaHide differential oracle 边界

ScyllaHide 只能作为**对照 oracle**，用于回答：

- 目标在“无 debugger 观测”下的**期望观察**是什么（行为规范的事实来源之一）；
- MIDA runtime 的虚拟化结果是否与 reference **行为等价**（不是字节等价）。

**oracle 操作协议：**

1. oracle 二进制只从外部 vault（如 `D:\MidaVault\scratch\...` 封存目录）解析，经 SHA-256 校验后使用；不进入仓库。
2. 每次 oracle 实验记录：三文件 SHA-256（InjectorCLI/HookLibrary/ini）、注入参数、目标进程、时间线、观察输出。
3. oracle 实验的**可观察输入/输出**（调用序列、返回码、时序、异常行为）可以进入行为规范；**内部实现**（hook 实现代码、配置解析逻辑）不得进入。
4. oracle 操作记录与 MIDA runtime 的差分结果写入 evidence（见 EVIDENCE_CONTRACT 的 differential 字段），可被审计。

## 5. 行为规范如何传递给实现 agent

1. 实现 agent 的输入是 **MIDA-ADR-2 行为规范**（`AntiDebugObservation` / `AntiDebugExpectedState` / `AntiDebugProbeResult` 的期望观察表）与公开 Windows 文档。
2. 行为规范中**不引用 ScyllaHide 源码**；引用 oracle 实验时只写“observed: <返回值/时序>”，不写“ScyllaHide does X internally”。
3. 每个 surface 的实现要求附带 **positive control / negative control**（见 EVIDENCE_CONTRACT §5）：实现 agent 必须证明其 hook 在受控探针下行为正确，而不是“看起来没死”。
4. 实现 agent 交付物必须包含 provenance 声明：实现依据（行为规范版本 + 公开文档引用），不含任何 third-party 代码来源声明。

## 6. 何时允许移除 ScyllaHide（MIDA-ADR-8 条件）

仅当**全部**满足：

1. origin_macro x64 通过（MIDA-ADR 差分结果 ≥ reference 证据质量）；
2. lunlun_software x64 通过（同上）；
3. 所有 required hooks 有 attestation（hooks_installed == hooks_expected，hook_failures 为空）；
4. 失败路径 fail closed（runtime 缺失/不完整 → 停止 unpack，不输出成功声明）；
5. 多次 isolated replay 稳定（与既有 isolated-replay 契约一致）；
6. MIDA evidence 独立可验证（证据 schema 完整、可重放、不依赖 ScyllaHide 存在）。

**移除动作本身是独立提交**：删除 ScyllaHide 注入路径（`inject_scylla_hide` 及其调用点、hash 常量），并在文档记录移除依据（引用 MIDA-ADR-7/8 证据）。

## 7. Provenance 字段（runtime provenance schema）

每个 MIDA-ADR artifact（runtime DLL、controller 二进制、profile、attestation、evidence bundle）必须携带：

| 字段 | 说明 |
|---|---|
| `schema` | 固定 `mida.antidebug-provenance/v1` |
| `artifact_id` | 内容寻址标识（SHA-256） |
| `kind` | `runtime-x64` / `runtime-x86` / `controller` / `profile` / `attestation` / `evidence` |
| `sha256` | 文件级 SHA-256（runtime/controller/profile 为文件；attestation/evidence 为规范化 JSON 的 SHA-256） |
| `size_bytes` | 文件大小 |
| `architecture` | `x86_64` / `x86` |
| `toolchain` | 构建工具链标识（如 rustc/msvc 版本） |
| `source_ref` | 源码提交（`4fe2cc35…` 风格；runtime 发布时记录构建 revision） |
| `third_party` | 第三方依赖声明：`none`，或 `{name, role: "oracle"|"reference-doc", license, source_url, sha256}` 列表（ScyllaHide 恒为 oracle） |
| `license` | MIDA-ADR 自有代码许可证（仓库 GPL-3.0-only）；第三方 artifact 许可证**以实际源码和发布物为准**，不臆测 |
| `build_repro` | 构建可复现性说明（`--locked` / 离线 / 环境） |

**规则：** 许可证以实际源码和发布物为准；不得把“自编译第三方代码”标记为自研；`third_party` 字段缺失视为 provenance 不完整，attestation 拒绝（fail-closed）。

## 8. 代码/二进制隔离

- MIDA-ADR 自有代码进 `crates/antidebug*`（独立 crate）；ScyllaHide 相关代码保持现状直到 ADR-8 移除，不混入新 crate。
- 第三方二进制只存在于外部 vault（SHA-256 封存）；仓库内 fixture 例外只允许 `crates/**/fixtures/` 下、≤1 MiB、带 provenance manifest 的确定性测试输入（ARTIFACT_POLICY.md §Binary fixture exception），且不含 PE/MDMP 内容。
- 隔离检查：`tools/verify_workspace_hygiene.ps1` 必须通过；MIDA-ADR 提交不得引入 `*.dll`/`*.exe`/`*.dmp`/`scylla_hide.ini`/PE 内容。

## 9. 审计记录

- 每个 MIDA-ADR 阶段结束产出审计条目：实现依据、oracle 使用记录、禁止项核查结果、hygiene 检查输出。
- 本文件与 EVIDENCE_CONTRACT、ARCHITECTURE 一起构成 MIDA-ADR-0 的交付；三者相对链接，修订须同步版本说明。
