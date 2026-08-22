# WO-1505 — Loader/ABI 对位清单

**工单编号**: WO-1505
**优先级**: P1
**性质**: 只读审计/设计清单（不得实现）
**日期**: 2026-08-22
**基线**: 786630b（WO-1401-R1 条件接收）
**状态**: 冻结候选 — 待总指挥联审

## 0. 目的

P1-C 审计要求：设计文档 §4 对 loader 的描述存在事实错误（MidaExports 字段、wanted 列表、
runtime 导出数、artifact digest），且"复用"被写成"已支持"。本文件对照**真实代码**逐项对位，
产出 Walker 导出加入 wanted list、返回结构、调用 thunk/ABI、allowlist、artifact digest 绑定的
精确实现变更点，以及实现前 checklist。

## 1. 真实代码基线（已核实，2026-08-22）

### 1.1 runtime_loader.rs

| 位置 | 真实内容 |
|------|---------|
| L302-310 | RemoteWaitOutcome 枚举（Finished/Abandoned/TimedOut/WaitFailed(raw)） |
| L366-374 | classify_wait_status：0→Finished, 0x80→Abandoned, 258→TimedOut, 其他→WaitFailed |
| L473/481 | THUNK_CODE_SIZE=91；THUNK_CODE[91]（6 参 thunk：mov r11,rcx → 装载 6 参 → call rax → ret） |
| L504-513 | ThunkArgs { fn_ptr, arg0..arg5, reserved }（64 字节） |
| L530-537 | **MidaExports { initialize: usize, get_attestation: usize, shutdown: usize }**（3 字段） |
| L595 | remote_call_raw_bounded（有界等待 + drain） |
| L748 | loadlib_call（LoadLibraryW 远程调用，64 位结果槽） |
| L1029 | load_and_initialize（完整 ADR-6 链） |
| L1040 | authority.verify_file（artifact 校验 + architecture == x86_64） |
| L1094 | resolve_mida_exports_remote(target, module_base) |
| L1275 | unsafe fn resolve_mida_exports_remote（PE 导出远程解析） |
| L1451-1455 | **wanted: [&[u8]; 3] = [MidaAntidebugInitialize, MidaAntidebugGetAttestation, MidaAntidebugShutdown]** |
| L1495-1507 | 三导出缺失任一 → ExportResolutionFailed；Ok(MidaExports{...}) |
| L1525 | resolve_exports_from_buffers（纯解析器，测试用） |
| L1792 | build_init_params_bytes（MidaInitParams blob 构造） |

### 1.2 antidebug-runtime/src/exports.rs

| 位置 | 真实内容 |
|------|---------|
| L89 | MidaInitParams 结构（target_pid, module_base, profile_id, profile_digest, expected_surfaces...） |
| L182 | MidaAntidebugInitialize（catch_unwind 包 initialize_inner） |
| L237-239 | runtime_sha256 = "adr4-foundation-unbound"（**占位值，非真实 digest**） |
| L367 | MidaAntidebugGetAttestation |
| L406 | MidaAntidebugShutdown |

## 2. 事实更正（对照 WO-1301A-IMPL 设计文档 §4）

| 设计文档原说法 | 真实情况 | 更正 |
|---------------|---------|------|
| "现含 initialize/shutdown"（§4 L281 附近） | MidaExports 有 3 字段：initialize/get_attestation/shutdown | 设计文档 §4 需改口"三字段" |
| "复用 resolve_mida_exports_remote 即支持 Walker" | wanted 列表固定 3 项；函数签名返回 MidaExports（3 字段） | 需改 wanted 列表 + MidaExports 加字段 + 解析器泛化 |
| "runtime_module_sha256 / artifact digest binding" | runtime_sha256 是占位字符串 | 需真实文件哈希（见 §5） |

## 3. Walker 导出加入的精确变更点

### 3.1 runtime 侧（antidebug-runtime/src/exports.rs）

1. **新增导出** WalkerExecute（C ABI）：
   ~~~rust
   #[no_mangle]
   pub unsafe extern "C" fn WalkerExecute(params_va: usize) -> u32
   ~~~
   位于 exports.rs 现有导出旁（L406 之后），panic 防火墙与 L182 一致（catch_unwind →
   WALKER_ERROR_INTERNAL_PANIC）。
2. **MidaInitParams 不扩展**（params 走 WalkerParamsV2 blob，见 WO-1501）；
   WalkerExecute 的单个 usize 参数 = blob_base_va（target-local）。

### 3.2 loader 侧（runtime_loader.rs）

1. **wanted 列表**（L1451-1455）：[&[u8]; 3] → [&[u8]; 4]，追加 b"WalkerExecute"。
2. **MidaExports**（L530-537）：新增 walker_execute: usize 字段（4 字段）。
3. **解析返回**（L1495-1507）：四导出全解析，任一缺失 → ExportResolutionFailed；
   Ok(MidaExports{ initialize, get_attestation, shutdown, walker_execute })。
4. **resolve_exports_from_buffers**（L1525）：wanted 数组长度参数化（&[&[u8]] 而非固定 3）；
   现有纯解析器逻辑不变，仅 wanted 数量泛化（签名已是 slices，改动最小）。
5. **build_init_params_bytes**（L1792）：不变（Walker 参数独立）。

## 4. 调用 thunk / ABI

### 4.1 现有 thunk 的适配性

- 现有 THUNK_CODE（L481）是 6 参 thunk：ThunkArgs{fn_ptr, arg0..arg5}。
- WalkerExecute 只收 1 参（blob VA）→ 复用 thunk 时 arg0 = blob_base_va，arg1..arg5 = 0；
  或新增 1 参 thunk（可选，最小改动 = 复用 6 参 thunk 传 1 参）。
- 返回：thunk 后接 ret，返回值在 RAX（32 位 u32 状态码），与 GetExitCodeThread 的 32 位
  槽兼容；但结果读取**不依赖** exit code——以 result section 的 completed_flag + walker_status
  为准（WO-1501 §ResultSectionHeaderV2）。

### 4.2 ABI 合同

- 入口地址断言：CreateRemoteThread 的 start 必须 == module_base + WalkerExecute RVA
  （allowlist 强制，防注入任意入口）。
- 参数：lpParameter = blob_base_va（target-local，非 controller 指针）。
- 线程：创建专用探针线程（非复用现有线程），VEH active 归属该线程（WO-1502 §3.3.3）。

## 5. artifact digest 绑定（外部 manifest 权威；无自嵌入循环）

### 5.1 问题与裁决

上一版写"构建时将 runtime DLL 文件字节的 sha256 注入 runtime DLL"——若哈希覆盖最终 DLL
全部字节，把 digest 写进 DLL 会改变被哈希字节，形成**自引用循环**（digest 依赖自身）。

**裁决：外部 manifest / authority 是唯一权威 digest 来源；runtime DLL 不做任何自嵌入。**

### 5.2 数据流（外部权威）

~~~text
1. 构建 runtime DLL（cdylib）→ runtime.dll 文件字节固定。
2. 构建/打包脚本计算 runtime.dll 的 SHA-256 → 写入外部 manifest
   （如 runtime.sha256 或 authority manifest 条目）。
3. controller 加载前：authority.verify_file(runtime_path)（L181）校验文件身份，
   并计算 digest_controller = sha256(runtime.dll 文件字节)。
4. controller 将 digest_controller 通过 **MidaInitParams v2 输入通道**（expected_runtime_sha256_ptr/len，见 5.3）下发 target。
5. runtime 在 initialize 时把收到的 digest 用于 attestation.runtime_sha256 并经
   out_runtime_sha256 回显（不做自算、不读自身文件）。
6. controller 校验：attestation.runtime_sha256 == digest_controller；不一致 → 拒收。
~~~

### 5.3 MidaInitParams 冲突解决（WO-1703 冻结：版本化扩展，真实 ABI 可达）

上一版（Batch 16）的"独立内存槽"方案被审计拒绝（P0-1605-1）：真实
MidaAntidebugInitialize 只有一个 *const MidaInitParams 输入参数，out_runtime_sha256 是
**输出**缓冲（exports.rs:184-185, 316-320），不是输入通道；runtime 没有任何方式知道
"独立 slot"在哪里。**禁止再用"分配一个独立内存槽"代替可调用 ABI。**

**冻结方案：版本化扩展 MidaInitParams（v1 保持字节兼容，v2 新增 digest 输入通道）。**

1. MidaInitParams 拆为 v1（现有 0x30 布局不变）+ v2（v1 字段 + 尾部追加字段）：
   ~~~text
   // MidaInitParams v2 = v1 布局（0x30）+ 追加（总大小 0x48）：
   //   0x30 u64  magic_v2            = 0x4D494441325032 ("MIDA2P2" LE)
   //   0x38 u64  expected_runtime_sha256_ptr  target-local 指针，指向 64 字节
   //                                       hex 字符串 + NUL（controller 写入）
   //   0x40 u64  expected_runtime_sha256_len = 64（固定，hex lowercase）
   //   0x48 结束
   // v1 调用方传 0x30 大小的 blob：magic_v2 区不存在 -> 按 v1 路径（digest 占位）。
   ~~~
2. 判定规则：params blob 大小 >= 0x48 且 magic_v2 == "MIDA2P2" → v2 路径；
   否则 v1 路径（向后兼容，现有 loader 的 build_init_params_bytes 输出 0x30，行为不变）。
3. v2 路径下 runtime 必须：
   - 校验 expected_runtime_sha256_ptr 非空、可读（ReadProcessMemory 之外：target 内
     直接解引用，指向同一 target 进程地址空间——blob 由 controller 经 VirtualAllocEx +
     WriteProcessMemory 写入 target，与 params blob 同生命周期）；
   - 校验 len == 64 且为合法 hex lowercase；否则 InvalidArgument，fail-closed；
   - 用该值构建 attestation 的 runtime_sha256（替换 adr4-foundation-unbound 占位）；
   - 仍经 out_runtime_sha256 输出回显同一值（输出通道语义不变）。
4. loader 侧（runtime_loader.rs）：
   - build_init_params_bytes（L1792）新增 v2 变体 build_init_params_bytes_v2：追加
     magic_v2 + digest 指针 + len；digest 字符串紧随 blob 尾部（remote_blob_base + off）；
   - load_and_initialize（L1029）在步骤 0（authority.verify_file，L1040）之后、步骤 4
     （写 params，L1097）之前计算 digest_controller = sha256(runtime.dll 文件字节)；
     传入 v2 构造器；步骤 4 后校验 out_runtime_sha256 == digest_controller（fail-closed）。
   - 既有 v1 测试 fixture 不变（0x30 路径回归）。
5. 槽的生命周期：digest 字符串随 params blob 一起 VirtualAllocEx + WriteProcessMemory
   （同一分配、同生命周期），与 blob 同回收；DLL 卸载前由 wait-before-free 规则保证
   （远程线程终止后才释放）。权限：PAGE_READWRITE（既有 blob 权限，无新增权限面）。
   完整性：digest 值本身由 controller 计算并写入，runtime 只读不写；attestation 回显
   由 controller 复核（§5.4），任何不一致拒收。
6. target-local 地址语义：digest 指针必须是 target 进程地址空间内的 VA（blob 内相对
   基址），禁止 controller 侧地址；runtime 侧以 raw pointer 解引用（与 profile_id/
   profile_digest 同模式）。
### 5.4 controller 复核（fail-closed）

- authority.verify_file（L181）通过 ≠ digest 绑定通过：verify_file 校验 manifest 身份，
  digest 复核是独立步骤（attestation.runtime_sha256 == digest_controller）。
- 任一不一致 → 拒收 attestation，标记 EvidenceInsufficient（WO-1503 §7），不进入 walker。
- **占位值不得作为 evidence**：adr4-foundation-unbound 只能出现在未实现状态；
  Walker 上线前必须替换为真实 digest 流，否则 acceptance 拒收（fail-closed）。

## 6. 实现前 checklist（全部通过才可派发实现）

- [ ] runtime 新增 WalkerExecute 导出（catch_unwind 防火墙 + walker_inner）
- [ ] loader wanted 4 项 + MidaExports 4 字段 + 解析泛化
- [ ] 入口地址 allowlist 断言（== module_base + rva）
- [ ] thunk 适配（复用 6 参或新增 1 参）
- [ ] runtime_sha256 真实文件哈希（外部 manifest 权威；MidaInitParams v2 通道下发；替换 adr4-foundation-unbound）
- [ ] controller 侧 digest 复核（attestation.runtime_sha256 == digest_controller == out_runtime_sha256 回显）
- [ ] resolve_exports_from_buffers 测试补 4 项 wanted 用例
- [ ] 回归：现有 3 导出解析测试不破坏

## 7. 状态

| 对象 | 状态 |
|-----|------|
| WO-1505 对位清单 | design-only；待联审 |
| runtime_loader.rs / exports.rs | 未修改 |
