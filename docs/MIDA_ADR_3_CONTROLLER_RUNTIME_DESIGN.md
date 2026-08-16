# MIDA-ADR-3 Controller/Runtime 接线与 fail-closed 生命周期设计

> **工作令：** MIDA-ADR-3 —— 设计 MIDA 自有 anti-debug controller/runtime 接线与 fail-closed 生命周期。
> **状态：** 架构设计定稿（文档阶段）。未实现 injector/hook/DLL；未执行 protected sample；未执行 ScyllaHide；未做 live differential；未新增 `crates/antidebug*`；未修改生产 Rust。
> **基线：** `6f0d22765547c33857f3decb675427f0f317d538`（ADR-2 提交）。前置：ADR-0/1/2 均已提交。
> **配套文档：** [LIFECYCLE_STATE_MACHINE](MIDA_ADR_3_LIFECYCLE_STATE_MACHINE.md) · [INTEGRATION_MAP](MIDA_ADR_3_INTEGRATION_MAP.md)

## 1. 目标

设计一套完全属于 MagicMida 的 runtime 接线方案，使后续实现 agent 可以按图施工：

```text
依赖解析
  -> artifact identity 校验
  -> profile 校验
  -> target launch
  -> runtime load/inject
  -> runtime initialization
  -> hook health check
  -> runtime attestation
  -> controlled probes
  -> ready/proceed
```

任何中间环节失败 → **fail-closed**：不得继续生成成功 candidate。

## 2. Required candidate 语义（profile 修订）

ADR-2 的 `required_surfaces` 需要区分两级，本设计引入：

| 级别 | 含义 | 进入条件 | 升级条件 |
|---|---|---|---|
| `required_candidate` | 有足够初步证据，值得在 controller/runtime 接线时验证；**不表示**已必须安装 hook | call-site presence 或同检测面强证据 | 满足下列之一后升级为 hard_required：`call_site_confirmed` / `runtime_observed` / `decision_semantics_confirmed` |
| `hard_required` | 必须安装 hook；缺失 → `AntiDebugRuntimePartialHooks` | confirmed call site / runtime observation / decision semantics | — |
| `observe_only` | 只记录 observation，不安装 hook | presence 或无证据 | 需新证据 + profile revision |
| `deferred` | 暂不处理 | 无证据/需动态验证 | 独立任务提供证据后激活 |

**升级必须产生：** profile revision、promotion evidence（observation/probe-result 引用）、profile digest 变化、审计记录。

### 2.1 AD-PROC-001（IsDebuggerPresent）当前状态

| 样本 | ADR-2 状态 | ADR-3 状态 | 说明 |
|---|---|---|---|
| origin_macro | required（保留项候选） | **required_candidate** | IAT presence（slot 92）+ 同检测面（PEB.BeingDebugged 已 decision-confirmed）。接线时受控验证 IsDebuggerPresent 调用点 → 满足条件后升级 hard_required；失败则降 observe-only |
| lunlun_software | observe-only | **observe-only** | IAT 未重建；**不得复制 origin 结论**（同 family 不共享 profile） |

**硬规则：** required_candidate 不等于 hard_required。candidate 被误当 hard required 必须在 profile resolver 中被拒绝。

## 3. Controller 组件设计

### 3.1 Dependency Resolver

职责：
- 发现 runtime artifact（`mida-antidebug-runtime-x64.dll` / 未来 x86）；
- 读取外部 vault（`D:\MidaVault\objects\sha256\` 分片路径）；
- 计算 hash/size；验证 architecture（PE machine）；验证 provenance（`mida.antidebug-provenance/v1`）；
- **拒绝 mutable locator**（只接受 immutable vault object 路径）。

禁止：
- 文件缺失时自动 fallback；
- 文件名匹配即信任；
- 只检查存在不检查 hash。

失败 → `DependencyUnavailable` / `DependencyIdentityMismatch` / `ArchitectureMismatch`。

### 3.2 Profile Resolver

职责：按 `sample_id` + `packer_family` + `architecture` 解析 profile（ADR-2 PROFILE_DRAFT 的 `mida.antidebug-profile/v1`），绑定：

- `profile_id`、`profile_digest`（规范化 JSON SHA-256）；
- `required_candidate` / `hard_required` / `observe_only` / `deferred` 四类 surface 列表；
- `profile_basis`（证据引用列表）。

必须拒绝：
- profile 与 sample 不匹配；
- profile 与 architecture 不匹配；
- profile digest 不匹配；
- unknown required surface（required 列表出现 ADR-2 中 unknown 的 surface → 拒绝）；
- candidate 被误当 hard required（结构上分离两个列表）。

失败 → `ProfileMismatch`。

### 3.3 Target Launcher

职责：
- protected input identity（manifest SHA-256/size 校验）；
- 目标 PID 记录；process creation mode（CREATE_SUSPENDED + DEBUG_ONLY_THIS_PROCESS，沿用 `mida_core::process::create_debug_process`）；
- **runtime load timing 决策**（见 §3.4）；
- parent/process identity 绑定（target_pid 与证据绑定）。

需要明确的问题：
- **runtime 是否必须在 TLS callback 前加载**：是（L3 面要求）；TLS callback 由壳运行时填充（ADR-1 证据：origin 3 / lunlun 2），runtime 必须在首次 callback 执行前就绪。当前 pipeline 在 CREATE_PROCESS 事件后注入（进程已冻结），需确认此时间点早于 TLS callback 执行（设计假设：CREATE_SUSPENDED 下 TLS callbacks 在首次 resume 时执行，注入必须在 resume 前完成——见 INTEGRATION_MAP §4 的接线位置）。
- **runtime 是否必须在 OEP 前 ready**：是（OEP 后原程序面执行 anti-debug 检查，如 IsDebuggerPresent）；
- 失败时如何终止目标：`TerminateProcess` + `WaitForSingleObject`（超时后记录 CleanupFailed）；
- 目标终止后如何记录：写 evidence（decision=fail-closed + fail_code）。

### 3.4 Runtime Loader/Injector（设计，不实现）

**分阶段：** x64 first（两个主样本均 PE32+），x86 later（独立验证 ABI/calling convention/PEB layout，见 ADR-0 §5 ADR-6）。

必须明确的接口（实现时决定具体机制）：

| 项 | 设计 |
|---|---|
| 加载方式 | 目标进程内加载自有 DLL（未来实现时选择 CreateRemoteThread + LoadLibrary 或直接映射；ADR-3 只定接口与验收） |
| 初始化入口 | `MidaAntidebugInitialize`（导出函数，返回 NTSTATUS；初始化失败 → `AntiDebugRuntimeInitializationFailed`） |
| 初始化超时 | 有界等待（如 5s），超时 → `AntiDebugRuntimeInitializationFailed` |
| module identity | 加载后从目标进程读取 module_base + 回读模块字节 hash 校验 == runtime_sha256 |
| 通信通道 | telemetry channel（命名事件/共享内存，设计为抽象接口）；`telemetry_channel=ready` 后控制器做一次 ping 往返 |
| 卸载/清理 | cleanup handler 注册（`cleanup_handler_registered=true`）；卸载时验证（`CleanupFailed` 状态存在） |

**禁止在 ADR-3 设计中写死：** ScyllaHide API / ScyllaHide profile / ScyllaHide config / 第三方 hook table。

### 3.5 Hook Health Checker

独立步骤，按序执行（与 ADR-0 EVIDENCE_CONTRACT §5 对齐）：

1. runtime module loaded（目标进程内 module_base 可解析）；
2. runtime hash matches（回读模块字节 hash == runtime_sha256）；
3. profile digest matches（runtime 报告的 profile_digest == controller 选择的）；
4. initialized=true；
5. expected hooks known（来自 profile hard_required + required_candidate）；
6. installed hooks count（runtime 报告）；
7. hook failures（runtime 报告，必须为空）；
8. telemetry channel（ready + ping 往返）；
9. runtime heartbeat（注入后定期确认存活）。

判定：`hooks_installed != hooks_expected` 或 `hook_failures` 非空 → `AntiDebugRuntimePartialHooks` → fail-closed。

### 3.6 Evidence Writer

必须写出：

- `mida.antidebug-runtime-attestation/v1`；
- `mida.antidebug-observation/v1`；
- `mida.antidebug-probe-result/v1`；
- `mida.antidebug-evidence/v1`（bundle）。

每份 evidence 必须绑定：

```text
sample_id
protected_input hash/size
candidate hash/size（若已产生；fail-closed 时可为 null）
profile_id
profile_digest
runtime hash
tool revision
environment digest
```

证据输出目录：外部 vault（`D:\MidaVault\lab\analysis\mida_adr_3_*` 风格），仓库只保留摘要引用。

## 4. Fail-closed 设计要求

以下任一情况必须阻断（decision=fail-closed，fail_code=…）：

| 情况 | fail_code |
|---|---|
| runtime DLL 缺失 / injector 缺失 | `AntiDebugRuntimeUnavailable` |
| hash 不匹配 | `AntiDebugRuntimeIdentityMismatch` |
| architecture 不匹配 | `AntiDebugRuntimeArchitectureMismatch` |
| profile digest 不匹配 | `AntiDebugRuntimeIdentityMismatch`（或 ProfileMismatch） |
| target identity 不匹配 | `AntiDebugRuntimeIdentityMismatch` |
| runtime 初始化失败 | `AntiDebugRuntimeInitializationFailed` |
| hard-required hook 未安装 | `AntiDebugRuntimePartialHooks` |
| telemetry 丢失 | `AntiDebugRuntimeTelemetryLost` |
| probe consistency degraded | `ProbeInconsistent` |
| cleanup 状态未知 | `CleanupFailed` |

**不得输出：** warning-only / continue unpack / candidate success / TLS pass / OEP pass。

## 5. ScyllaHide 边界

- ScyllaHide **不进入** MIDA runtime implementation；
- ScyllaHide **不进入** MIDA profile format；
- ScyllaHide **不进入** MIDA hook table；
- ScyllaHide 只在 ADR-7 differential 中作为 oracle；
- 如未来临时运行 ScyllaHide：必须使用外部 vault artifact、记录 Injector/HookLibrary/ini 三文件 hash、写 `source=scyllahide-oracle`、**不得**将结果直接写入 required profile。

## 6. 未来 crate 边界（ADR-3 只定义 API 边界，不创建）

| crate | 职责 | 关键类型（草案） |
|---|---|---|
| `crates/antidebug` | controller：依赖解析、profile 解析、lifecycle 状态机、failure taxonomy | `DependencyResolver`、`ProfileResolver`、`AntidebugLifecycle`、`FailCode` |
| `crates/antidebug-runtime` | target-side runtime ABI、attestation 协议、hook health 协议 | `MidaAntidebugInitialize` ABI、`AttestationRecord`、`HookHealthReport` |
| `crates/antidebug-evidence` | schema、canonical encoding、hashing、evidence validation | `AttestationV1`、`ObservationV1`、`ProbeResultV1`、`EvidenceBundleV1`、`canonical_json()`、`digest()` |
| `crates/antidebug-fixtures` | synthetic target、benign test process、probe fixtures | 测试用最小可执行目标（符合 ARTIFACT_POLICY fixture 例外） |

依赖方向：`antidebug → antidebug-evidence`；`antidebug-runtime → antidebug-evidence`（编码 attestation）；`antidebug-fixtures` 独立。

## 7. L6 kernel/hypervisor

仍明确 **defer**（ADR-0 §4）：不做 driver/hypervisor；仅当 evidence 证明目标检查内核态面才开独立任务。

## 8. 与 ADR-2 的关系

- profile 语义修订（required_candidate/hard_required）需要同步更新 ADR-2 PROFILE_DRAFT 与 BEHAVIOR_SPEC（见 §2 与报告第 2 项）。
- ADR-2 的 24 surface / proof levels / fail-closed 规则全部沿用，不改变证据 schema（仅新增 expected-state 已在 ADR-0 登记）。