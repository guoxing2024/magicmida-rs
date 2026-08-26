# MIDA-ADR-6 自有 x64 Runtime Loader 与 Controller 接线

> **工作令：** MIDA-ADR-6 —— 实现自有 x64 runtime loader，并将 controller 接入"暂停启动 -> 加载 -> 初始化 -> attestation -> 决策 -> 首次 resume"生命周期。
> **状态：** 实现完成 + ADR-6-CORRECTION + CORRECTION-2（source_ref 三方一致、完整 provenance validate、全字段交叉绑定）。
> **基线：** `ae1df8eeee4d30f9b48e5103f2ca8c15e529ced6`（ADR-5-CORRECTION）。前置：ADR-0/1/2/3/3A/3B/3B-CORRECTION/4/4-CORRECTION/5/5-CORRECTION 全部封版。
> **性质：** 自有 loader。未执行 protected sample；未执行 ScyllaHide；未做差分。

## 1. 目标与范围

建立完全属于 MIDA 的 runtime loader/controller 接线，使 CLI 在目标首次执行前完成：

```text
CREATE_SUSPENDED
  -> runtime artifact authority verification (SHA-256/size/arch)
  -> target identity verification
  -> load MIDA runtime into target (remote LoadLibraryW)
  -> resolve runtime module base
  -> MidaAntidebugInitialize (thunk, 6-arg, attestation out)
  -> read attestation JSON
  -> verify target_pid/module_base/profile_digest
  -> attestation.validate()
  -> controller decision
  -> only on success: first resume
```

**明确不做：** x86 loader、post-attach runtime load（方案 A：fail-closed）、ScyllaHide、protected sample live、CLI production 之外的行为变更。

## 2. 架构

```text
crates/cli/src/unpacker/
├── runtime_loader.rs      loader：authority 验证 + 远程 LoadLibraryW +
│                          thunk 远程调用 + attestation 读取 + identity 校验
├── antidebug_controller.rs controller：resolve_dependency 真实化 +
│                          loader_result 注入 + 全生命周期驱动
└── mod.rs                 CREATE_PROCESS handler：调用 loader -> 注入结果 ->
                           controller.run() -> Proceed 才首次 resume
```

### 2.1 Loader 机制选择：远程线程 + LoadLibraryW + x64 thunk

**选择原因：**

1. `CreateRemoteThread(kernel32!LoadLibraryW)` 是 Windows 公开、文档化的进程内 DLL 加载方式，x64 下 kernel32 基址跨进程一致（session.rs 已有同假设）；
2. 无需手工 PE 映射（避免 loader stub 的复杂性和安全风险）；
3. 完全自有：无第三方 injector、无 ScyllaHide 代码。

**多参数远程调用**：`CreateRemoteThread` 只能传 1 个参数（lpParameter）。`MidaAntidebugInitialize` 有 6 个参数，因此使用**标准 x64 thunk**（VirtualAllocEx 可执行内存 + 参数块 + 间接调用）：

```asm
mov  r11, rcx          ; r11 = args base（跨调用保持）
mov  rax, [r11]        ; fn_ptr
mov  rcx, [r11+8]      ; arg0
mov  rdx, [r11+16]     ; arg1
mov  r8,  [r11+24]     ; arg2
mov  r9,  [r11+32]     ; arg3
sub  rsp, 0x38         ; shadow space (0x20) + 2 栈参数 + 对齐
mov  r10, [r11+40]     ; arg4 -> [rsp+0x20]
mov  r10, [r11+48]     ; arg5 -> [rsp+0x28]
call rax
add  rsp, 0x38
ret
```

**时序保证：** 目标以 CREATE_SUSPENDED 创建（debug 事件窗口内主线程暂停），loader 在首次 resume 前完成全部远程操作。

**修正记录（benign 验证发现）：** 初版 thunk 使用 `sub rsp, 0x28`，第 5 个栈参数写到 rsp+0x28（超出分配帧），远程线程执行时崩溃（0xC0000005）。修复为 `sub rsp, 0x38` 后 benign host 验证通过（完整 thunk 经 CreateThread 调用 GetCurrentProcessId 返回正确 PID）。

## 3. Runtime Authority

`RuntimeAuthority`（固定审计配置）：

```text
file_name (informational) + sha256 + size_bytes + architecture + source_revision + provenance_schema
```

- 验证流程：canonicalize -> is_file -> size 比对 -> SHA-256 比对 -> arch 比对；
- 禁止信任：文件名、目录"最新 DLL"、调用方传入 hash、仅文件存在；
- 失败映射：sha256/size -> `AntiDebugRuntimeIdentityMismatch`；x64 only -> `AntiDebugRuntimeArchitectureMismatch`；缺失 -> `AntiDebugRuntimeUnavailable`；
- 运行时通过环境变量 `MIDA_RUNTIME_SHA256` / `MIDA_RUNTIME_SIZE` / `MIDA_RUNTIME_DLL` 注入（验收 harness 设置；不接受调用方直接传 hash）。

## 4. Controller 接线

### 4.1 resolve_dependency 真实化

ADR-3B 的"runtime 永远不可用"占位改为：无 authority 配置 -> 保持 fail-closed（DependencyUnavailable）；有 authority -> `verify_file` 真实验证 -> `DependenciesVerified` 或对应失败状态。

### 4.2 loader_result 注入

CREATE_PROCESS handler 执行 loader 后，将 `LoaderResult { module_base, attestation_json, file_identity, target_pid }` 注入 controller。controller 的 `run()` 消费它：

```text
无 loader_result           -> RuntimeLoadFailed（不盲目 Proceed）
target_pid 不匹配          -> TargetIdentityRejected
attestation 解析失败        -> RuntimeInitFailed
attestation.validate() 失败 -> HealthCheckFailed（partial hooks 等）
全部通过                   -> ProfileValidated -> ... -> Proceed
```

### 4.3 Post-attach：方案 A（暂不支持）

post-attach 路径不提供 runtime loader（无 CREATE_PROCESS handler 时机），controller 以 `runtime_authority: None` 保持 fail-closed（`AntiDebugRuntimeUnavailable`），**不绕过** anti-debug 阶段。
## 5. 验证

### 5.1 Synthetic（tests/runtime_loader.rs，14 tests）

| 场景 | 测试 |
|---|---|
| authority 匹配 | authority_matches_ok |
| authority hash 错误 | authority_wrong_hash_fails |
| authority size 错误 | authority_wrong_size_fails |
| authority 文件缺失 | authority_missing_file_fails |
| thunk 字节良构（0x38 帧 + ret） | thunk_code_is_wellformed |
| thunk 参数块序列化 | thunk_args_serialization_roundtrip |
| init params 布局（repr(C) 对齐） | init_params_layout_matches_runtime_repr_c |
| init params 空 surfaces | init_params_empty_surfaces_ok |
| controller + 有效 loader result -> Proceed | controller_proceeds_with_valid_loader_result |
| controller 无 loader result -> fail | controller_fails_closed_without_loader_result |
| target pid mismatch -> fail | controller_fails_closed_on_target_pid_mismatch |
| attestation 解析失败 -> fail | controller_fails_closed_on_bad_attestation |
| attestation 不完整（partial hooks）-> fail | controller_fails_closed_on_incomplete_attestation |
| authority mismatch -> fail（先于 loader） | controller_authority_mismatch_fails_before_loader |

### 5.2 Benign host（5 轮，真实进程）

benign_host_adr6.rs（仓库外 D:/tmp/magicmida-adr6-target）：

```text
ADR-6 benign host: baseline handles=54
thunk selftest: full thunk GetCurrentProcessId = 13644 (expect 13644)
round 0..4: load DLL -> Initialize -> attestation 981B (hooks 002+003, 001 absent)
           -> Shutdown -> FreeLibrary; handles 58 (delta 4, 零增长)
final handles=58 baseline=54 (delta 4)
BENIGN_HOST_ADR6_OK
```

### 5.3 资源计数

| 轮次 | 句柄 | delta |
|---|---|---|
| baseline | 54 | - |
| round 0 | 58 | +4（DLL 首载固定开销） |
| round 1-4 | 58 | 0 |
| final | 58 | +4 总（无泄漏） |
## 6. Evidence 要求

loader/controller 失败生成 mida.antidebug-evidence/v1（record_kind=cli-failure）：decision=fail-closed、fail_code、controller state、target_pid、runtime artifact identity、module base、profile_id/digest、attestation、telemetry sequence、cleanup result、candidate_created=false。

成功时 decision=proceed，但 benign host 的 Proceed 只代表 loader/controller/runtime 链路通过，不代表 protected sample gate 已通过。

## 7. 验收命令结果

```text
cargo fmt --all -- --check                        OK
cargo check --workspace --tests --offline        OK
cargo test -p mida-antidebug-runtime --offline   OK (67)
cargo test -p mida-antidebug --offline           OK
cargo test -p mida-cli --offline                 OK (含 14 loader tests)
cargo test --workspace --offline                 OK
RUSTFLAGS=-D warnings cargo check --workspace --all-features --tests --offline  OK
git diff --check                                 OK
benign_host_adr6.exe 5 轮闭环                    OK (BENIGN_HOST_ADR6_OK)
```

## 8. 审计声明

- 未执行 protected sample；未执行 ScyllaHide；未做差分；
- 未实现禁止项（x86 loader、AD-PROC-001 promotion、post-attach runtime load）；
- 未修改 crates/antidebug/**、crates/pe/**、crates/acceptance/**、crates/packers/**、crates/core/**；
- runtime ABI 未修改（exports.rs 未动；thunk 是 loader 侧机制）；
- 无 DLL/EXE 入库（构建产物在 D:/tmp/magicmida-adr6-target）；
- 历史 109 个未跟踪文件 + ADR-3A 修正文档未触碰；
- loader 自身有 identity（LoaderIdentity）；"远程线程创建成功" != "runtime 初始化成功"（每个 C ABI 调用返回码都检查）。
## 9. ADR-6-CORRECTION：不可变 authority + 真实 PE/provenance 校验

### 9.1 阻塞项一：不可变 authority manifest

原实现从环境变量读取 `MIDA_RUNTIME_SHA256`/`MIDA_RUNTIME_SIZE`——调用方可自选 DLL 并自我授权，违反"禁止信任调用方传入 hash"。

修复：

```text
RuntimeAuthorityManifest（mida.antidebug-runtime-authority/v1）
  schema + kind=runtime-x64 + artifact_id + sha256 + size_bytes
  + architecture + source_ref + provenance_ref

编译时固定：MIDA_RUNTIME_AUTHORITY_DIGEST（manifest 自身 SHA-256）
环境变量只允许：MIDA_RUNTIME_AUTHORITY（manifest 路径）、MIDA_RUNTIME_DLL（runtime 路径）
```

- manifest 加载时校验自身 digest == 编译时固定值（不匹配 -> AuthorityMismatch）；
- 环境变量**不能**提供 expected sha256/size/architecture/source revision；
- 测试 `env_cannot_authorize_arbitrary_runtime` 证明：设置 MIDA_RUNTIME_SHA256 对授权无影响（authority 只认 manifest 路径）。

### 9.2 阻塞项二：真实 PE 架构验证

原实现只返回 authority 字符串。修复为解析实际文件：

```text
MZ（offset 0）-> PE\0\0（e_lfanew）-> COFF Machine == AMD64 (0x8664)
-> Optional Header Magic == PE32+ (0x20B)
```

拒绝：x86/ARM/WOW64/非 PE/截断 PE/PE32——统一 `ArchitectureUnsupported`（controller 映射 `AntiDebugRuntimeArchitectureMismatch`）。

### 9.3 阻塞项三：provenance 实际绑定

`verify_runtime_provenance()` 读取 provenance_ref 指向的 JSON（deny_unknown_fields 严格解析），交叉校验：

```text
provenance.sha256 == runtime 文件 sha256
provenance.size_bytes == runtime 文件 size
provenance.kind == runtime-x64
provenance.architecture == x86_64
provenance.source_ref 非空
provenance.third_party 非空（有效声明）
无 dependency 声明 anti_debug=true
```

任何失败 -> `AuthorityMismatch`（controller 映射 `AntiDebugRuntimeIdentityMismatch`）。

### 9.4 次要：source_revision 使用 Git commit

`MIDA_RUNTIME_SOURCE_REF`（编译时注入的 Git commit）替代 `CARGO_PKG_VERSION` 作为 source_ref；两者分离。

### 9.5 Correction 测试（23 tests）

新增：x86/ARM/非 PE/PE32 拒绝、provenance hash/kind mismatch、provenance 缺失、provenance 通过、env 覆盖拒绝、manifest 缺失。

### 9.6 Correction 验收

```text
workspace tests 全绿；-D warnings 通过；git diff --check 通过
benign host 5 轮重跑：BENIGN_HOST_ADR6_OK（句柄 54->58 零增长）
untracked = 110
```
## 10. ADR-6-CORRECTION-2：三方身份链闭合

### 10.1 source_ref 三方严格一致

```text
MIDA_RUNTIME_SOURCE_REF（编译时注入的 Git commit）
  == manifest.source_ref（load() 时校验，不匹配 -> AuthorityMismatch）
  == provenance.source_ref（verify_runtime_provenance 交叉绑定）

MIDA_RUNTIME_SOURCE_REF 为空 -> AuthorityUnavailable（fail-closed）
```

不再只检查"非空"——compiled/manifest/provenance 三方必须完全相等。

### 10.2 完整 Provenance::validate()

`verify_runtime_provenance()` 在交叉绑定前先调用 ADR-4 已封版的 `prov.validate()`：

```text
kind 合法 + kind/architecture 一致
sha256/size 完整
third_party 声明有效
runtime dependencies 非空（DependenciesUndeclared 拒绝空列表）
dependency name/version 完整
dependency anti_debug=false
```

反序列化成功 != 语义有效——validate() 是必需 gate。

### 10.3 manifest/provenance 全字段交叉绑定

```text
artifact_id / sha256 / size_bytes / kind / architecture / source_ref
全部必须 manifest == provenance，且 sha256/size 同时绑定 runtime 文件
```

### 10.4 返回类型化 Provenance

函数返回 `mida_antidebug_runtime::provenance::Provenance`（已验证类型），不再返回原始 JSON。

### 10.5 CORRECTION-2 测试（30 tests）

新增：provenance artifact_id/source_ref mismatch、empty dependencies 拒绝、dependency name 空/anti_debug=true 拒绝、full chain 通过、arch mismatch、env 不能覆盖 compiled source ref。合法 provenance 使用 ADR-4 登记的 serde/serde_json/thiserror 完整依赖声明（版本与 Cargo.lock 一致）。

### 10.6 CORRECTION-2 验收

```text
workspace tests 全绿；-D warnings 通过；git diff --check 通过
benign host 5 轮回归：BENIGN_HOST_ADR6_OK（句柄 +4 首载零增长）
untracked = 110
```
