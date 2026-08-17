# MIDA-ADR-4 x64 Runtime Foundation 设计文档

> **工作令：** MIDA-ADR-4 —— 设计并实现自有 x64 anti-debug runtime 基础层：加载、初始化、attestation、telemetry 与 fail-closed 生命周期。
> **状态：** 实现完成 + ADR-4-CORRECTION 修正完成（target identity 绑定、严格 schema、provenance kind、依赖声明、benign host 验证）。
> **基线：** `ed42720428e87d1fbcf10ca091bec2bc31bf388c`（ADR-3B-CORRECTION 提交）。前置：ADR-0/1/2/3/3A/3B 全部完成。
> **修正基线：** `53d4c76d9baca1f6951141f601964b865cf0a3d9`（ADR-4 提交）；ADR-4-CORRECTION 在其上追加。
> **性质：** 自有 runtime 基础层。未实现 anti-debug hook surface（ADR-5+）；未实现 injector；未执行 protected sample；未执行 ScyllaHide。

## 1. 目标与范围

建立完全属于 MIDA 的 Windows x64 runtime 基础设施：

1. 独立的自研 x64 runtime crate（`crates/antidebug-runtime`）；
2. 可被 MIDA controller 识别、验证和初始化（C ABI 导出面）；
3. 明确的 runtime identity、architecture、profile digest、初始化状态、telemetry 状态；
4. 输出符合契约的 runtime attestation（`mida.antidebug-runtime-attestation/v1`）；
5. runtime 不完整/身份/架构/初始化/telemetry 失败时必定 fail-closed；
6. 未实现的 required surface **不得伪装成已安装**（诚实 unsupported inventory）；
7. controller 不能因 runtime "加载成功" 就错误进入 `Proceed`（attestation 校验是独立 gate）。

**明确不做（本任务）：** 完整 anti-debug surface hook、API hook table、远程线程注入器、ScyllaHide 兼容层/配置解析、kernel/hypervisor、x86 runtime、protected sample live 验证。

## 2. Crate 结构与构建目标

```text
crates/antidebug-runtime/
├── Cargo.toml          crate-type = ["cdylib", "rlib"]
├── src/lib.rs          crate 根（架构文档 + 重导出）
├── src/exports.rs      C ABI 导出面（Initialize / GetAttestation / Shutdown）
├── src/attestation.rs  RuntimeAttestation + fail-closed validate()
├── src/telemetry.rs    TelemetryChannel（协议核心，传输无关）
├── src/provenance.rs   Provenance（mida.antidebug-provenance/v1）
└── tests/attestation.rs  25 个测试（FFI/attestation/telemetry/provenance）
```

**构建目标：** `x86_64-pc-windows-msvc` 仅 x64。x86/ARM/kernel/hypervisor 明确不构建。
**cdylib**：DLL 导出面（构建到仓库外 target，禁止入库）。
**rlib**：同一代码供离线测试套件直接调用（不加载 DLL、不注入进程）。

## 3. C ABI 导出接口（稳定、最小）

| 导出 | 签名要点 | 错误码 |
|---|---|---|
| `MidaAntidebugInitialize` | `(params: *const MidaInitParams, out_runtime_sha256, out_attestation_json, out_attestation_written) -> i32` | 0 Ok / 1 AlreadyInitialized / 3 InvalidArgument / 4 BufferTooSmall / 6 Serialization / 7 InternalPanic |
| `MidaAntidebugGetAttestation` | `(out_buf, buf_len, out_written) -> i32` | 0 Ok / 2 NotInitialized / 3 InvalidArgument / 4 BufferTooSmall / 5 AlreadyShutdown / 6 Serialization / 7 InternalPanic |
| `MidaAntidebugShutdown` | `() -> i32` | 0 Ok / 2 NotInitialized / 5 AlreadyShutdown / 7 InternalPanic |

ABI 规则（ADR-4 §2）：

- **C ABI**（`extern "C"`）；
- 输入 buffer 规则：`out_attestation_json` + `out_attestation_len` 由调用方提供；`out_attestation_written` 返回实际写入字节数；
- buffer 太小 → `BufferTooSmall`（不截断）；
- 无效指针/零长度 → `InvalidArgument`；
- 调用线程约束：所有导出必须由初始化线程调用（单线程协议）；
- 生命周期：Initialize → GetAttestation* → Shutdown；
- 无悬空指针：所有输出拷贝进调用方 buffer；
- **panic 不穿过 FFI**：每个导出用 `catch_unwind` 包裹，panic → `InternalPanic`；
- FFI 错误全部结构化（稳定 i32 码，见上表）。

## 4. Runtime Attestation（`mida.antidebug-runtime-attestation/v1`）

```json
{
  "schema": "mida.antidebug-runtime-attestation/v1",
  "runtime_id": "mida-antidebug-runtime-x64",
  "runtime_version": "0.1.0",
  "architecture": "x86_64",
  "runtime_sha256": "...",
  "profile_id": "oreans_origin_x64_v1",
  "profile_digest": "...",
  "target_pid": 1234,
  "module_base": 140694538682368,
  "initialized": true,
  "hooks_expected": ["AD-PROC-001", "AD-PROC-002", "AD-PROC-003"],
  "hooks_installed": [],
  "hook_failures": [{"surface_id": "AD-PROC-001", "reason": "unsupported in ADR-4 foundation ..."}, ...],
  "telemetry_channel": "ready",
  "cleanup_handler_registered": true,
  "third_party": "build-and-serialization-only",
  "source_revision": "...",
  "toolchain": "..."
}
```

**fail-closed validate() 规则**（`AttestationError`）：

| 条件 | 错误 |
|---|---|
| schema != `mida.antidebug-runtime-attestation/v1` | SchemaMismatch |
| architecture != x86_64 | ArchitectureMismatch |
| initialized != true | NotInitialized |
| telemetry_channel != "ready" | TelemetryNotReady |
| cleanup_handler_registered != true | CleanupHandlerMissing |
| profile_digest 为空 | ProfileDigestMissing |
| third_party 为空 | ThirdPartyUndeclared |
| target_pid == 0 | TargetPidMissing |
| module_base == 0 | ModuleBaseZero |
| verify_identity(pid, base) 不匹配 | TargetPidMismatch / ModuleBaseMismatch |
| hooks_installed.len() != hooks_expected.len() | HookInventoryIncomplete |
| hook_failures 非空 | HookFailures |

**关键语义：**

- runtime 只报告，不授权。sample_id/profile_id/profile_digest/target identity 由 controller 选择，runtime 不得修改；
- **target identity 绑定（ADR-4-CORRECTION）**：attestation 携带 `target_pid` + `module_base`，controller 必须用 `verify_identity(expected_pid, expected_module_base)` 交叉校验后才能接受 attestation（防跨进程搬用）；
- **严格 schema（ADR-4-CORRECTION）**：`RuntimeAttestation`/`HookFailure`/`HookInventory` 及 telemetry 全部 `#[serde(deny_unknown_fields)]`——未知字段在解析期即拒绝（ADR-0 契约：字段缺失/类型错误/未知 schema 字段 → 拒绝）；
- `from_canonical_json` 是**传输解析**（不自动 validate），controller 读取 `hooks_installed`/`hook_failures` 后以 `validate()` 做决策 gate——诚实但不完整的 runtime 也能被解析并正确 fail-closed；
- ADR-4 foundation 的 attestation 是**诚实的 unsupported**：`hooks_installed=[]`、`hook_failures` 列出全部 expected surface 为 unsupported。controller 将得到 `AntiDebugRuntimePartialHooks`——这是正确的 fail-closed 结果，不是失败；
- 禁止：空 hooks_expected、虚报 hooks_installed、把 runtime loaded 当 hooks ready、把 candidate 当 hard hook、把 ScyllaHide 结果填进 MIDA attestation。

## 5. Telemetry 通道

ADR-4 实现**协议核心**为进程内通道（`TelemetryChannel`），使完整 fail-closed 矩阵可离线测试。传输（named pipe / shared memory）是 ADR-5 接线关注点；以下语义与传输无关：

| 要求 | 实现 |
|---|---|
| channel identity | `channel_id`（如 `mida-adr4-<pid>`），request/response 必须匹配 |
| bounded timeout | `round_trip_budget`（100ms 有界预算） |
| version/schema | `mida.antidebug-telemetry/v1` |
| request/response correlation | `request_id` 回显 + `validate_response()` |
| monotonic sequence | `accepted_high` 水位线；旧 sequence 拒绝 |
| target PID 绑定 | request 的 `target_pid` 必须 == channel 绑定 PID |
| profile digest 绑定 | request 的 `profile_digest` 必须 == channel 绑定 digest |
| timeout/乱序/PID/digest 不匹配 | 全部 fail-closed（结构化 `TelemetryError`） |
| 静默重试 | 禁止：一次失败即结构化错误，不重试后假设成功 |
| 无界阻塞 | 禁止：`request()` 检查 deadline |

TelemetryMessage 至少报告：`RuntimeInitialized`、`AttestationReady`、`HookInventory{expected,installed,failures}`、`HealthStatus`、`ShutdownStatus`。

## 6. Provenance（`mida.antidebug-provenance/v1`）

```json
{
  "schema": "mida.antidebug-provenance/v1",
  "artifact_id": "mida-antidebug-runtime-x64",
  "kind": "runtime-x64",
  "sha256": "...",
  "size_bytes": 0,
  "architecture": "x86_64",
  "toolchain": "...",
  "source_ref": "...",
  "third_party": "build-and-serialization-only",
  "dependencies": [
    {"name":"serde","version":"1.0.229","license":"MIT OR Apache-2.0","source":"crates.io","role":"serialization","anti_debug":false},
    {"name":"serde_json","version":"1.0.151","license":"MIT OR Apache-2.0","source":"crates.io","role":"serialization","anti_debug":false},
    {"name":"thiserror","version":"1.0.69","license":"MIT OR Apache-2.0","source":"crates.io","role":"error-definition","anti_debug":false}
  ],
  "license": "GPL-3.0-only",
  "build_repro": "--locked offline build; out-of-tree target"
}
```

**third_party 声明语义（ADR-4-CORRECTION）**：本 runtime 链接的 serde/serde_json/thiserror 是第三方 crate，因此**不写 "none"**（"none" 只允许在完全没有外部 crate 时使用）。声明为 `build-and-serialization-only` 并逐项列出依赖（名称/锁定版本/许可证/来源/角色/anti_debug=false）。这些 crate 只参与构建与序列化，不含任何 anti-debug 行为、不注入、不拦截；runtime 的 anti-debug 行为完全来自 `crates/antidebug-runtime` 自有代码。任何未来新增外部 crate 必须同步更新该声明。

## 7. 与 ADR-3B controller 的接线

本任务**未修改** controller（`antidebug_controller.rs` 未动）。ADR-4 runtime 的 attestation 校验是 controller 的独立 gate：

```text
runtime loaded            != Proceed
attestation validate()    != Proceed
hooks complete            == Proceed 前置条件之一
```

当前 foundation attestation 必然 `HookInventoryIncomplete` → controller 保持 `PartialHooks`/`AntiDebugRuntimePartialHooks` fail-closed——正确。ADR-5 实现 surface 后才可能走到 Proceed。

## 8. 测试覆盖

`tests/attestation.rs`（40 tests，全部离线 rlib；ADR-4-CORRECTION 后）：

- **Attestation（19）**：JSON round-trip（含 target identity 字段）、foundation 诚实 unsupported、schema/arch/init/telemetry/cleanup/digest/third-party/hook-failures/missing-fields 拒绝、inventory completeness、target_pid 缺失拒绝、module_base 零拒绝、verify_identity 正常/pid 不匹配/base 不匹配/base 零拒绝、unknown field 拒绝（attestation 与 HookFailure 两级）；
- **Provenance（8）**：round-trip + kind=runtime-x64 + dependencies 声明、third_party 未声明拒绝、kind 缺失/非法拒绝、kind/architecture 不一致拒绝、dependencies 未声明拒绝、dependency anti_debug 拒绝、unknown field 拒绝；
- **Telemetry（13）**：正常 request/response、sequence 单调、PID/digest/channel-id mismatch、out-of-order、duplicate、not-ready、closed、shutdown report、response unknown field 拒绝、repeated start/stop 无资源增长。

**Benign host harness（ADR-4-CORRECTION 补充验收）**：`tests/benign_host.rs`（源码入库；exe 编译在仓库外 `D:\tmp\magicmida-adr4c-target`，不入库）以纯动态加载（LoadLibraryW/GetProcAddress/FreeLibrary）驱动 runtime DLL，执行 5 轮完整生命周期：LoadLibrary → Initialize → GetAttestation×2 → Shutdown → 确认 post-shutdown 返回 AlreadyShutdown → FreeLibrary。每轮记录句柄数：round 0 首载 DLL +4（固定开销），后续轮 0 增长，终值较基线 +4 无持续泄漏。动态加载保证 FreeLibrary 真正卸载模块，每轮重新 Initialize 成功（证明模块级状态随卸载重置）。不加载任何 protected sample，不执行 live differential。

## 9. 验收命令结果

```text
cargo fmt --all -- --check                        ✅
cargo check --workspace --tests --offline        ✅
cargo test -p mida-antidebug-runtime --offline   ✅ (40 passed, ADR-4-CORRECTION)
cargo test -p mida-antidebug --offline           ✅ (27 passed)
cargo test -p mida-cli --offline                ✅ (310+ passed)
cargo test --workspace --offline                ✅
RUSTFLAGS=-D warnings cargo check --workspace --all-features --tests --offline  ✅
git diff --check                                 ✅
benign_host.exe 5-round load/unload cycle        ✅ (BENIGN_HOST_OK, no handle growth)
```

## 10. 审计声明

- 未执行 protected sample；未执行 ScyllaHide；未做差分；
- 未实现 hook surface（ADR-4 foundation 诚实 unsupported）；
- 未修改 `crates/cli/**`（controller 未接线——ADR-5 时接线）；
- 无 DLL/EXE 入库（cdylib 构建产物在 `D:\tmp\magicmida-adr4-target`，仓库外）；
- 未复制 ScyllaHide 任何内容；third_party=none 属实；
- 109 个历史未跟踪文件 + ADR-3A 修正文档未触碰。

**ADR-4-CORRECTION 审计声明：**

- 四个阻塞项全部修复：target identity（target_pid + module_base + verify_identity）、严格 schema（deny_unknown_fields 全覆盖 + 真实断言）、provenance kind（runtime-x64 + 一致性校验）、依赖声明（dependencies 列表 + third_party 语义澄清）；
- benign host 重复 load/unload 验证完成（5 轮，无资源增长，DLL/EXE 不入库）；
- 未执行 protected sample；未执行 ScyllaHide；未做差分；
- 未修改 `crates/cli/**`、`crates/antidebug/**`、`crates/pe/**`、`crates/acceptance/**`、`crates/packers/**`；
- workspace 测试全绿；`RUSTFLAGS=-D warnings` 通过；`git diff --check` 通过。