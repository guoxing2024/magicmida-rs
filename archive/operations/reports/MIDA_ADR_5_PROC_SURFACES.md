# MIDA-ADR-5 x64 PEB Surface 实现与受控验证

> **工作令：** MIDA-ADR-5 —— 实现自有 x64 runtime 的 hard-required PEB anti-debug surfaces，并完成 synthetic/benign 受控验证。
> **状态：** 实现完成 + ADR-5-CORRECTION（pShimData 偏移 0x2D8 + 真实零化验证）。
> **基线：** `9a7141bbe5e2f83306bdf0a22bb52399e4c7658f`（ADR-4-CORRECTION 提交）。前置：ADR-0/1/2/3/3A/3B/3B-CORRECTION/4/4-CORRECTION 全部封版。
> **性质：** 自有 surface 实现。未接入 CLI production pipeline；未执行 protected sample；未执行 ScyllaHide；未做差分。

## 1. 目标与范围

在 ADR-4 runtime foundation 之上实现两个 hard-required surface：

```text
AD-PROC-002: PEB.BeingDebugged  (offset 0x02, BYTE)
AD-PROC-003: PEB.pShimData     (offset 0x2D8, PVOID; x64 authority layout)
```

完成后 attestation 可诚实报告：

```text
hooks_expected  = [AD-PROC-002, AD-PROC-003]
hooks_installed = [AD-PROC-002, AD-PROC-003]   （全成功时）
hook_failures   = []
```

**明确不做：** AD-PROC-001 promotion、NtQueryInformationProcess / CheckRemoteDebuggerPresent / timing / exception / TLS hook、kernel/hypervisor、x86 runtime、ScyllaHide 兼容实现、CLI production 接线。

## 2. 架构

```text
crates/antidebug-runtime/src/surfaces/
├── mod.rs      surface 模块入口与重导出
├── proc.rs     PebMemory trait + PebView（checked 地址运算）+
│               AD-PROC-002/003 install/restore + SurfaceInstallOutcome
└── win32.rs    Win32PebMemory（真实进程 PEB 视图，gs:[0x60]，零外部依赖）
```

### 2.1 PebMemory trait（可注入内存抽象）

```rust
pub trait PebMemory {
    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, String>;
    fn write_bytes(&self, addr: u64, data: &[u8]) -> Result<(), String>;
    fn is_readable(&self, addr: u64, len: usize) -> bool;
    fn is_writable(&self, addr: u64, len: usize) -> bool;
    fn peb_base(&self, pid: u32) -> Result<u64, String>;
}
```

- **synthetic fixture**（tests/proc_surfaces.rs 的 FakePebMemory）注入内存模拟，离线测试完整 fail-closed 矩阵；
- **benign host**（真实 Windows x64 进程）用 Win32PebMemory，同一份 surface 逻辑。

### 2.2 字段偏移证明（不硬编码）

x64 Windows ABI（公开文档）：BeingDebugged 位于 PEB+0x02（BYTE），pShimData 位于 PEB+0x2D8（PVOID，权威 crates/core/src/process.rs）。每个访问前先 is_readable/is_writable 探测；地址运算全部 checked_add（溢出 -> PebBaseOverflow）。
## 3. Surface 语义

### 3.1 AD-PROC-002（修改型）

1. 校验 target PID / profile digest；
2. 读 BeingDebugged（原始值 observation）；
3. 若非零 -> 清零（写入）；若已零 -> 保持；
4. 记录 original_value / effective_value / restoration_policy = RestoreOriginal；
5. shutdown 时 restore_proc_002 恢复原值；恢复失败 -> RestoreFailed 错误码 + telemetry SurfaceRestore{Failed} + fail-closed。

### 3.2 AD-PROC-003（修改型：零化验证）

ADR-2 probe catalog：pShimData 必须为 0（required）。

1. 校验 target PID / profile digest；
2. 读 pShimData 指针（PEB+0x2D8）；
3. 空值（0）-> 已清洁，installed=true，effective=0；
4. 非空 -> 校验目标可读（is_readable(ptr, 1)），不可读 -> ShimDataInvalid fail-closed；
5. 校验字段可写（is_writable）-> 写入 0；
6. 回读确认 effective_value == 0，否则 -> ShimDataInvalid fail-closed；
7. 记录 original_value / effective_value=0 / restoration_policy = RestoreOriginal；
8. shutdown 时 restore_proc_003 恢复 original_value；恢复失败 -> RestoreFailed + fail-closed。

### 3.3 candidate 分离

AD-PROC-001 保持 required_candidate：本任务不安装、不 promotion；attestation 的 hooks_expected 只含 002/003。若需要记录 AD-PROC-001 仅作为 observation，且不改变 profile revision/digest。## 4. Attestation 扩展

RuntimeAttestation 新增 surface_details: Vec<SurfaceDetail>（每 surface 的完整状态记录：installed/original_value/effective_value/restoration_policy/restore_result/error）；新增 from_surfaces() 构造器（从真实安装结果构建，绝不虚报）；validate() 增加 surface_details 与 hooks_installed/hook_failures 的一致性校验（SurfaceDetailInconsistent）。

deny_unknown_fields 继续生效（ADR-4-CORRECTION 规则不变）。

## 5. Fail-closed 条件

以下任一情况 attestation 不完整（validate 失败，controller 不得 Proceed）：

```text
PEB 地址解析失败           -> PebResolveFailed / PebBaseZero / PebBaseOverflow
PEB 不可读                 -> PebNotReadable
PEB 不可写（需要修改时）    -> PebNotWritable
字段偏移越界               -> PebFieldOutOfRange
pShimData 指针非法         -> ShimDataInvalid
pShimData 写后回读 != 0    -> ShimDataInvalid（write-back verification）
target PID 不一致          -> TargetPidMismatch
profile digest 不一致      -> ProfileDigestMismatch
x86/WOW64 误用             -> WrongPointerSize
恢复失败                   -> RestoreFailed（shutdown 路径）
```## 6. Synthetic 验证（21 tests）

tests/proc_surfaces.rs（27 tests，全离线 rlib；ADR-5-CORRECTION 后）：

| 场景 | 测试 |
|---|---|
| 正常 x64 PEB（BeingDebugged=0） | proc002_normal_clean_peb |
| BeingDebugged=1 -> 清零 | proc002_being_debugged_set_is_zeroed |
| PEB 不可读 | proc002_unreadable_peb_rejected |
| PEB 不可写（需修改时） | proc002_unwritable_peb_rejected_when_modifying |
| target PID mismatch | proc002_target_pid_mismatch_rejected / aggregate_wrong_pid_fails_closed |
| profile digest mismatch | proc002_profile_digest_mismatch_rejected |
| pShimData=0（已清洁） | proc003_null_shim_data_ok |
| pShimData 非零 -> 零化+回读 | proc003_nonzero_shim_is_zeroed |
| 回读失败（写不生效） | proc003_write_back_verification_failure_fails_closed |
| 不可写时零化失败 | proc003_unwritable_peb_fails_closed_when_zeroing |
| 0x2D8 偏移断言（0x08 非 pShimData） | proc003_offset_is_0x2d8_not_0x08 |
| 恢复原指针/已零/失败 | proc003_restore_original_pointer / _zero_original_not_applicable / _failure_reported |
| pShimData 指针越界 | proc003_invalid_shim_pointer_rejected |
| x86 pointer size 拒绝 | wrong_pointer_size_rejected |
| restoration 成功/不适用/失败 | proc002_restore_original / _not_applicable / _failure_reported |
| 聚合全成功 | aggregate_both_installed |
| 聚合部分失败（003 失败） | aggregate_partial_failure_reports_failures |
| 聚合 PEB 不可解析 | aggregate_peb_unresolvable_fails_closed |
| attestation 完整/不完整 | attestation_from_surfaces_full_success_validates / telemetry_sequence_error_still_fails_closed / attestation_candidate_never_in_expected |## 7. Benign x64 host 验证

benign_host_adr5.rs（仓库外 D:/tmp/magicmida-adr5-target，exe/DLL 不入库）：

### Round 1：真实 PEB 状态（ADR-5-CORRECTION 后：003 零化成功）

```text
peb base = 0x149421b000
BeingDebugged before init = 0x0
init ok, attestation 970 bytes
hooks_installed = ["AD-PROC-002", "AD-PROC-003"]
hook_failures = []
surface_details: AD-PROC-003 {original 0x180cf8e0000, effective "0", RestoreOriginal}
BeingDebugged after init = 0x0
BeingDebugged after shutdown = 0x0 (original 0x0)  <- 恢复验证
```

真实进程 pShimData（0x180cf8e0000，apphelp 映射）非零 -> 被零化，effective=0 -> attestation 完整。

### Round 2：预置合法 pShimData（003 零化 + 恢复路径）

```text
hooks_installed = ["AD-PROC-002", "AD-PROC-003"]
hook_failures = []
surface_details: 002 {original 0x00, RestoreOriginal}, 003 {original 0x14944fb4d0, effective "0", RestoreOriginal}
pShimData after round2 install = 0x0 (must be 0)          <- 零化回读确认
pShimData after round2 shutdown = 0x14944fb4d0 (runtime restored its observed original)  <- 恢复执行
handles: base 54 final 58 (delta 4)  <- 无资源增长
BENIGN_HOST_ADR5_OK
```

## 8. 验收命令结果

```text
cargo fmt --all -- --check                        OK
cargo check --workspace --tests --offline        OK
cargo test -p mida-antidebug-runtime --offline   OK (40 attestation + 27 surfaces = 67)
cargo test -p mida-antidebug --offline           OK
cargo test --workspace --offline                OK
RUSTFLAGS=-D warnings cargo check --workspace --all-features --tests --offline  OK
git diff --check                                 OK
benign_host_adr5.exe 两轮闭环                    OK (BENIGN_HOST_ADR5_OK)
```

## 9. 审计声明

- 未执行 protected sample；未执行 ScyllaHide；未做差分；
- 未实现禁止项（AD-PROC-001 promotion / NtQIP / CRDP / timing / exception / TLS / kernel / x86）；
- 未修改 crates/cli/**、crates/antidebug/**、crates/pe/**、crates/acceptance/**、crates/packers/**、crates/core/**；
- 无 DLL/EXE 入库（构建产物在 D:/tmp/magicmida-adr5-target）；
- 历史 109 个未跟踪文件 + ADR-3A 修正文档未触碰；
- provenance third_party 仍为 build-and-serialization-only（无新 crate 依赖；win32.rs 用 core::arch::asm + kernel32 系统导出）。

**ADR-5-CORRECTION 审计声明：**

- pShimData 偏移修正为 0x2D8（对齐 crates/core/src/process.rs 权威 PEB_SHIM_DATA_OFFSET）；0x08 不再作为 pShimData（有专门测试 proc003_offset_is_0x2d8_not_0x08 断言）；
- AD-PROC-003 从 ObserveOnly 改为真实零化：非零 -> 写 0 -> 回读确认 effective==0 -> installed=true；写失败/回读失败/不可写 -> fail-closed；
- original/effective/restoration 全部进入 surface_details evidence；
- shutdown 恢复 original_value（restore_proc_003），恢复失败 -> RestoreFailed + fail-closed；
- benign host 用 0x2D8 布局重跑：round1 真实进程 003 零化成功（original 0x180cf8e0000 -> effective 0），round2 零化+恢复闭环验证通过；
- synthetic 27 tests 覆盖：非零->零、已零、非法指针、写失败、回读失败、恢复失败/成功/不适用、0x2D8 偏移断言。