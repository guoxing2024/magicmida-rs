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
4. controller 将 digest_controller 通过 **MidaAntidebugInitializeV2 输入通道**（expected_runtime_sha256/len，见 5.3）下发 target。
5. runtime 在 initialize 时把收到的 digest 用于 attestation.runtime_sha256 并经
   out_runtime_sha256 回显（不做自算、不读自身文件）。
6. controller 校验：attestation.runtime_sha256 == digest_controller；不一致 → 拒收。
~~~

### 5.3 MidaInitParams 冲突解决（WO-1803 冻结：独立 versioned entry，安全协商）

上一版（WO-1703）"v1 尾部追加 magic"方案被审计拒绝（P0-1703-1/P0-1703-2）：
- MidaAntidebugInitialize 只有 *const MidaInitParams 参数、**没有 blob length/size 参数**；
  v1 caller 只保证 0x30 字节，runtime 读 offset 0x30 之后的 magic 属于**越界读/UB**；
- 上一版 magic_v2 = 0x4D494441325032 的 little-endian 字节是 32 50 32 41 44 49 4D 00
  （= "2P2ADIM\0"），不是 ASCII "MIDA2P2\0"，endian 标注错误。

**冻结方案：独立 versioned entry point（MidaAntidebugInitializeV2）+ 独立参数结构。**
不修改 MidaAntidebugInitialize 的 ABI；v1 caller 与 v1 blob 完全不变。

1. **新导出（WO-2002 修订：显式 params_bytes + self-relative offsets + 7 参 thunk）**：
   ~~~c
   /* MidaInitParamsV2 — 独立结构；全部引用字段为 **self-relative offsets**
    * （相对 params blob 基址 = entry 的 params 指针），非绝对指针。
    * 理由：runtime 只有 *params，没有 controller 的 VirtualAllocEx 知识；
    * offsets + params_bytes 使"先于解引用验证边界"可执行。 */
   typedef struct MidaInitParamsV2 {
       uint32_t target_pid;                 /* +0x00 */
       uint32_t _pad0;                      /* +0x04 */
       uint64_t module_base;                /* +0x08 */
       uint64_t profile_id_off;             /* +0x10 self-relative */
       uint64_t profile_digest_off;         /* +0x18 self-relative */
       uint64_t expected_hooks;             /* +0x20 */
       uint64_t expected_surfaces_off;      /* +0x28 self-relative（指针数组） */
       uint64_t magic_v2;                   /* +0x30 "MIDA2P2\0" LE */
       uint64_t digest_off;                 /* +0x38 self-relative（64 hex + NUL） */
       uint64_t digest_len;                 /* +0x40 == 64 */
   } MidaInitParamsV2;                      /* size == 0x48 */

   /* V2 entry：params_bytes = controller 实际分配的 blob 总字节数
    * （params blob = 结构 + 全部被引用字符串/数组，见 §5.3e envelope）。
    * runtime 在解引用任何 offset 之前必须验证：
    *   params != NULL && params_bytes >= 0x48 &&
    *   0 <= off && off + need <= params_bytes
    * 7 参签名 → 新增 7 参 thunk 变体（THUNK_CODE_7ARG + ThunkArgs7 9 槽 72B，
    * 实现工单新增，不改现有 6 参 thunk/ThunkArgs）。 */
   __declspec(dllexport) int32_t MidaAntidebugInitializeV2(
       const MidaInitParamsV2* params,      /* arg0 */
       uint64_t params_bytes,               /* arg1  blob 总大小（新增） */
       uint8_t* out_runtime_sha256,         /* arg2 */
       size_t out_runtime_sha256_len,       /* arg3 */
       uint8_t* out_attestation_json,       /* arg4 */
       size_t out_attestation_len,          /* arg5 */
       size_t* out_attestation_written);    /* arg6（栈上第 7 参） */
   ~~~
2. **版本协商（安全，无越界）**：
   - v1 caller：调用 MidaAntidebugInitialize（原符号）→ 只读 0x30 范围内的字段；
     该函数**永不读取 offset 0x30 之后**——不存在 magic 探测。
   - v2 caller：调用 MidaAntidebugInitializeV2 → 结构 size 0x48 由类型系统/编译期保证，
     runtime 在入口校验 params 非空 + 全部 target-local 指针有效后读取全字段。
   - **未知版本**：不存在 v3 调用路径；若未来需 v3，新增 MidaAntidebugInitializeV3 导出
     （版本号入符号名，不依赖结构内 magic 猜测）。任何"用 magic 猜版本"的方式禁用。
   - v1 fallback：loader 无 digest 需求（未启用 walker 绑定）时继续调用 v1 入口，
     runtime_sha256 保持占位（未绑定状态）；有 digest 需求时调用 V2 入口。
3. **magic_v2 endian fixture（WO-1803 修正）**：
   - 目标字节序列（内存布局，little-endian 写入）：4D 49 44 41 32 50 32 00
     （= ASCII "MIDA2P2\0"，8 字节）。
   - 对应的 u64 数值 = 0x00_32_50_32_41_44_49_4D（按 LE 字节序解读：
     最低有效字节在前 → 数值 = 0x003250324144494D）。
   - **decoder 伪代码**：
     ~~~text
     fn read_magic_v2(p: *const u8) -> u64:
         # 读 8 字节 LE
         bytes = [p[0], p[1], ..., p[7]]
         return u64::from_le_bytes(bytes)
         # 校验：read_magic_v2(ptr) == 0x003250324144494D
         # 且 bytes 必须 == [0x4D, 0x49, 0x44, 0x41, 0x32, 0x50, 0x32, 0x00]
     ~~~
   - **endian test vector**：encode("MIDA2P2\0") 的 LE 字节 = 4D 49 44 41 32 50 32 00；
     u64 数值 0x003250324144494D；两个方向都必须在实现单测中断言。
4. v2 路径下 runtime 必须（fail-closed）：
   - 校验 digest_off 非 0 且为 self-relative 边界内（与 profile_id_off 同模式）；
   - 校验 digest_len == 64 且 digest 区域为 64 个 lowercase hex + NUL；否则 InvalidArgument；
   - 用该值构建 attestation 的 runtime_sha256（替换 adr4-foundation-unbound 占位）；
   - 仍经 out_runtime_sha256 输出回显同一值（输出通道语义不变）。
5. loader 侧（runtime_loader.rs）：
   - wanted 列表 += "MidaAntidebugInitializeV2"（与 WalkerExecute 同批）；
     MidaExports 增加 initialize_v2 字段（5 字段）；
   - build_init_params_bytes_v2（新函数）构造 0x48 结构 + 尾部 digest 字符串
     （remote_blob_base + off 指针）；
   - load_and_initialize 在步骤 0（authority.verify_file，L1040）之后计算
     digest_controller = sha256(runtime.dll 文件字节)；walker 绑定场景调用 V2 入口，
     其余场景保持 V1 入口（零行为变化）；步骤 4 后校验 out_runtime_sha256 == digest_controller。
   - 既有 v1 测试 fixture 不变（0x30 路径回归）。
6. 槽的生命周期/权限/完整性：digest 字符串随 params blob 同一 VirtualAllocEx 分配、
   同生命周期、同回收（wait-before-free 铁律）；权限 PAGE_READWRITE（无新增权限面）；
   runtime 只读不写；attestation 回显由 controller 复核（§5.4），不一致拒收。
7. target-local 地址语义：digest 指针必须是 target 进程地址空间内 VA（blob 内相对基址），
   禁止 controller 侧地址；runtime 以 raw pointer 解引用（与 profile_id/profile_digest 同模式）。
   可读性/NUL 校验：读取前先按 len==64 检查目标缓冲区边界（64 hex + NUL = 65 字节，
   分配由 controller 保证）；任何越界/非 hex/非 NUL 结尾 → InvalidArgument，fail-closed。
### 5.3a Layout golden bytes（WO-1902 冻结：C/Rust 双侧 repr(C) 对位）

**MidaInitParams v1（0x30）**——C 与 Rust 侧必须完全一致：

| offset | size | 字段 | C 类型 | Rust 类型 |
|--------|------|------|--------|-----------|
| 0x00 | 4 | target_pid | uint32_t | u32 |
| 0x04 | 4 | _pad0 | — | (padding) |
| 0x08 | 8 | module_base | uint64_t | u64 |
| 0x10 | 8 | profile_id | const char* | *const c_char |
| 0x18 | 8 | profile_digest | const char* | *const c_char |
| 0x20 | 8 | expected_hooks | size_t | usize |
| 0x28 | 8 | expected_surfaces | const char* const* | *const *const c_char |
| 0x30 | — | 结束 | | |

golden bytes（fixture，字段值：target_pid=0x11223344, module_base=0x400000,
profile_id_ptr=0x401000, profile_digest_ptr=0x402000, expected_hooks=2,
expected_surfaces_ptr=0x403000）：

~~~text
00: 44 33 22 11 00 00 00 00     target_pid(LE) + _pad0
08: 00 00 40 00 00 00 00 00     module_base(LE) = 0x400000
10: 00 10 40 00 00 00 00 00     profile_id_ptr(LE) = 0x401000
18: 00 20 40 00 00 00 00 00     profile_digest_ptr(LE) = 0x402000
20: 02 00 00 00 00 00 00 00     expected_hooks(LE) = 2
28: 00 30 40 00 00 00 00 00     expected_surfaces_ptr(LE) = 0x403000
总长 0x30
~~~

**MidaInitParamsV2（0x48）——WO-2102 唯一权威 layout（self-relative offsets，7 字段）**：

> **WO-2102 修订**：删除旧"v1 字段 + 绝对指针（expected_runtime_sha256: const char*）"的
> V2 扩展。V2 是**独立 0x48 结构**，全部引用字段为 self-relative offsets；本表是唯一
> 权威 layout（与 docs/fixtures/WO-2002-v2-envelope-fixture.h 逐字节一致）。
> 旧 WO-1902-initparams-layout-fixture.h 的 V2 绝对指针扩展**已废弃**（v1 部分保留）。

| offset | size | 字段 | C 类型 | Rust 类型 |
|--------|------|------|--------|-----------|
| 0x00 | 4 | target_pid | uint32_t | u32 |
| 0x04 | 4 | _pad0 | — | (padding) |
| 0x08 | 8 | module_base | uint64_t | u64 |
| 0x10 | 8 | profile_id_off | uint64_t（self-relative） | u64 |
| 0x18 | 8 | profile_digest_off | uint64_t（self-relative） | u64 |
| 0x20 | 8 | expected_hooks | uint64_t | u64 |
| 0x28 | 8 | expected_surfaces_off | uint64_t（self-relative） | u64 |
| 0x30 | 8 | magic_v2 | uint64_t | u64 |
| 0x38 | 8 | digest_off | uint64_t（self-relative） | u64 |
| 0x40 | 8 | digest_len | uint64_t（== 64） | u64 |
| 0x48 | — | 结束 | | |

golden bytes（fixture 字段值：target_pid=0x11223344, module_base=0x400000,
profile_id_off=0x48, profile_digest_off=0x68, expected_hooks=2,
expected_surfaces_off=0x78, magic_v2="MIDA2P2\0" LE, digest_off=0x88, digest_len=64）：

~~~text
00: 44 33 22 11 00 00 00 00     target_pid(LE) + _pad0
08: 00 00 40 00 00 00 00 00     module_base(LE) = 0x400000
10: 48 00 00 00 00 00 00 00     profile_id_off(LE) = 0x48
18: 68 00 00 00 00 00 00 00     profile_digest_off(LE) = 0x68
20: 02 00 00 00 00 00 00 00     expected_hooks(LE) = 2
28: 78 00 00 00 00 00 00 00     expected_surfaces_off(LE) = 0x78
30: 4D 49 44 41 32 50 32 00     magic_v2(LE) = "MIDA2P2\0" 字节序 = 0x003250324144494D
38: 88 00 00 00 00 00 00 00     digest_off(LE) = 0x88
40: 40 00 00 00 00 00 00 00     digest_len(LE) = 64
总长 0x48
~~~

**C 侧 static_assert 合同（实现工单必须原样落地）**：

~~~c
_Static_assert(sizeof(MidaInitParamsV2) == 0x48, "v2 size");
_Static_assert(offsetof(MidaInitParamsV2, target_pid) == 0x00, "v2 target_pid");
_Static_assert(offsetof(MidaInitParamsV2, module_base) == 0x08, "v2 module_base");
_Static_assert(offsetof(MidaInitParamsV2, profile_id_off) == 0x10, "v2 profile_id_off");
_Static_assert(offsetof(MidaInitParamsV2, profile_digest_off) == 0x18, "v2 profile_digest_off");
_Static_assert(offsetof(MidaInitParamsV2, expected_hooks) == 0x20, "v2 expected_hooks");
_Static_assert(offsetof(MidaInitParamsV2, expected_surfaces_off) == 0x28, "v2 surfaces_off");
_Static_assert(offsetof(MidaInitParamsV2, magic_v2) == 0x30, "v2 magic");
_Static_assert(offsetof(MidaInitParamsV2, digest_off) == 0x38, "v2 digest_off");
_Static_assert(offsetof(MidaInitParamsV2, digest_len) == 0x40, "v2 digest_len");
~~~

**Rust 侧 static_assert 等价（实现工单必须）**：

~~~rust
const _: () = {
    assert!(std::mem::size_of::<MidaInitParamsV2>() == 0x48);
    assert!(std::mem::offset_of!(MidaInitParamsV2, profile_id_off) == 0x10);
    assert!(std::mem::offset_of!(MidaInitParamsV2, profile_digest_off) == 0x18);
    assert!(std::mem::offset_of!(MidaInitParamsV2, expected_surfaces_off) == 0x28);
    assert!(std::mem::offset_of!(MidaInitParamsV2, magic_v2) == 0x30);
    assert!(std::mem::offset_of!(MidaInitParamsV2, digest_off) == 0x38);
    assert!(std::mem::offset_of!(MidaInitParamsV2, digest_len) == 0x40);
};
~~~

**endian test vector（实现单测）**：encode/decode 双向断言——读 8 字节 LE 于 0x30 得到
0x003250324144494D 且字节 == [4D 49 44 41 32 50 32 00]；写同值再读回一致。

### 5.3b V2 指针安全合同（WO-2002 修订：self-relative offsets + params_bytes）

**target-local 判定（修订）**：V2 结构内全部引用字段改为 **self-relative offsets**
（相对 params 指针；§5.3e），不再使用绝对指针。runtime 判定规则（全部先于解引用）：
- 入口先验证 params != NULL && params_bytes >= 0x48（ShortBlob 拒收）；
- 对每个 off 字段：off == 0 仅当该字段可选且声明为空（digest_off/surfaces_off 允许
  0 的场合按 §5.3f 判定）；off != 0 时 off >= 0x48 && off + need <= params_bytes；
- 目标区域可读性：need 按类型确定（digest = 65 字节、字符串 ≤ 65、数组 = 8×N），
  在边界证明后直接解引用（同一 target 进程 = runtime 自身进程；无 RPM/SEH 依赖）；
- 检查顺序：边界 → NUL/长度/hex 校验 → 内容使用；任何失败 → fail-closed 错误码。

**65-byte digest 可读性**：
- digest_off 指向（self-relative）64 hex 字符 + 1 NUL = 65 字节区域；
- 读取协议：digest_len 字段必须 == 64；从 blob_base + digest_off 起最多读 65 字节，遇 NUL 停止；
  - 读到 64 字节且第 65 字节 != NUL → 拒收（BufferOverrun，fail-closed）；
  - 64 字节内遇 NUL（提前终止）→ 拒收（TruncatedDigest）；
  - 65 字节内有任意非 hex 字符（0-9a-fA-F）→ 拒收（BadHex）；
- **hex 规则**：只接受 lowercase（0-9a-f）；大写拒收（规范化：digest 一律 lowercase）。
- **NUL 位置**：必须恰好在第 65 字节（offset 64）为 0x00；其余位置 NUL → 拒收。

**错误码与 fail-closed 路径**：

| 条件 | 错误 | 路径 |
|------|------|------|
| 指针 == 0 | InvalidArgument | 返回错误码，attestation 不生成 |
| 指针越界（blob 范围外） | InvalidArgument | 同上 |
| len != 64 | InvalidArgument | 同上 |
| 提前 NUL / 超 65 无 NUL | InvalidArgument（Truncated/BufferOverrun） | 同上 |
| 非 lowercase hex | InvalidArgument（BadHex） | 同上 |
| 任一失败 | — | controller 侧：out_runtime_sha256 未写入；attestation.runtime_sha256 保持未绑定；acceptance 拒收（§5.4） |

**cleanup**：V2 params blob（含 digest 字符串）由 controller 的 wait-before-free 铁律管理：
远程线程确认终止后才 VirtualFreeEx；runtime 侧不分配、不释放任何 digest 内存（只读）。

### 5.3c 导出解析闭环（WO-1902 冻结）

**wanted 列表（5 项，全部必选）**：

| # | 导出名 | 用途 |
|---|--------|------|
| 1 | MidaAntidebugInitialize | v1 入口（无 digest 场景 fallback） |
| 2 | MidaAntidebugGetAttestation | 证据读取 |
| 3 | MidaAntidebugShutdown | 清理 |
| 4 | MidaAntidebugInitializeV2 | v2 入口（digest 绑定场景，唯一） |
| 5 | WalkerExecute | walker 探针入口（allowlist 断言对象） |

**MidaExports 五字段**：initialize、get_attestation、shutdown、initialize_v2、walker_execute。

**解析规则（resolve_exports_from_buffers 泛化后）**：
- 任一缺失 → ExportResolutionFailed（fail-closed，不部分放行）；
- **重复导出**（同名多次出现）→ 拒收（AmbiguousExport）；
- **forwarded export**（函数 RVA 落在导出目录内）→ 拒收（ForwardedExportUnsupported，
  沿用既有解析器行为）；
- **out-of-module export**（RVA >= image size 或指向其它模块）→ 拒收；
- **入口 allowlist 证据**：CreateRemoteThread 的 start 必须 == module_base +
  WalkerExecute RVA（解析结果）；controller 记录 module_base、rva、解析出的 VA 三项，
  写入 walker 实现工单的证据要求。

**V2 thunk 七参数对位**（WO-2002：新增 THUNK_CODE_7ARG 变体 + ThunkArgs7 9 槽 72B；
现有 6 参 thunk 不动）：

| thunk 槽 | 值 |
|----------|----|
| fn_ptr | module_base + MidaAntidebugInitializeV2 RVA |
| arg0 | params_v2_blob_va（target-local） |
| arg1 | params_bytes（blob 总大小；controller 已知 VirtualAllocEx 大小） |
| arg2 | out_runtime_sha256_va |
| arg3 | 64（out_runtime_sha256_len） |
| arg4 | out_attestation_json_va |
| arg5 | ATTESTATION_BUFFER_SIZE |
| arg6 | out_attestation_written_va（第 7 参走栈，ABI 规则） |
| reserved | 0 |

**7-arg thunk 完整 ABI（WO-2202 冻结：机器码/栈布局/shadow space/对齐/清理）**：
~~~text
THUNK_CODE_7ARG（60 字节 = 0x3C；WO-2401 修订：栈对齐重算；
经 ml64 + dumpbin 逐字节实测 + 本机 ABI 组合测试（thunk7_final_full.asm /
thunk7_final_test.c，fixture-exact 字节）验证：7 参数完整到达 + callee entry
rsp ≡ 8 mod 16 + call 前 rsp ≡ 0 mod 16；
与现有 6-arg thunk（runtime_loader.rs THUNK_CODE L481-503）风格一致：
mov r11,rcx 用 49 89 CB、间接 call 用 call rax（FF D0）、sub/add rsp 自建帧）：

偏移  字节                    指令
0000: 49 89 CB               mov r11, rcx            ; 保存 ThunkArgs7*
0003: 49 8B 03               mov rax, [r11]          ; fn_ptr -> rax
0006: 49 8B 4B 08            mov rcx, [r11+8]        ; arg0 -> rcx（第 1 参）
000A: 49 8B 53 10            mov rdx, [r11+16]       ; arg1 -> rdx（第 2 参）
000E: 4D 8B 43 18            mov r8,  [r11+24]       ; arg2 -> r8（第 3 参）
0012: 4D 8B 4B 20            mov r9,  [r11+32]       ; arg3 -> r9（第 4 参）
0016: 48 83 EC 38            sub rsp, 0x38           ; 帧 = shadow 32 + 3 outgoing 24 = 56
001A: 4D 8B 53 28            mov r10, [r11+40]       ; arg4 -> r10（暂存）
001E: 4C 89 54 24 20         mov [rsp+0x20], r10     ; arg4 outgoing（第 5 参）
0023: 4D 8B 53 30            mov r10, [r11+48]       ; arg5 -> r10（暂存）
0027: 4C 89 54 24 28         mov [rsp+0x28], r10     ; arg5 outgoing（第 6 参）
002C: 4D 8B 53 38            mov r10, [r11+56]       ; arg6 -> r10（暂存）
0030: 4C 89 54 24 30         mov [rsp+0x30], r10     ; arg6 outgoing（第 7 参）
0035: FF D0                  call rax                ; 间接调用 fn_ptr（与 6-arg thunk 同编码）
0037: 48 83 C4 38            add rsp, 0x38           ; 恢复栈
003B: C3                     ret

总长 = 0x3C = 60 字节（3+3+4+4+4+4+4+4+5+4+5+4+5+2+4+1）

**栈对齐推导（WO-2401，冻结）**：
- thunk 由 caller 的 call 进入 → 入口 rsp ≡ 8 (mod 16)（8 字节返回地址）；
- `sub rsp, 0x38`（0x38 = 56 ≡ 8 mod 16）→ call 前 rsp ≡ 8-8 ≡ 0 (mod 16) ✓
  （Windows x64 要求：call 指令执行前 rsp ≡ 0 mod 16）；
- `call rax` → 被调函数入口 rsp ≡ 8 (mod 16) ✓（ABI 要求）；
- `add rsp, 0x38` → 恢复入口 rsp；`ret` 弹返回地址。
- **旧方案 `sub rsp,0x40`（16 的倍数）错误**：入口 8 mod 16 不变，call 前仍
  8 mod 16，被调函数入口错位（0 mod 16）——违反 ABI，已废弃。

**shadow space 与 outgoing arguments 的区别（WO-2401，冻结）**：
- **shadow space**（rsp+0x00..0x1F，32 字节）：调用方为被调函数预留的
  home 区，被调函数可自由使用（含保存寄存器参数）；**不是参数传递区**。
- **outgoing arguments**（rsp+0x20 起）：第 5 参数起在 call 前由调用方写入
  的栈参数区。thunk 的第 5-7 参写 [rsp+0x20]/[rsp+0x28]/[rsp+0x30]。
- 两者术语不可混用；"home 槽"仅指 shadow space 语义，参数槽是 outgoing。
~~~

**Windows x64 调用约定（7 参跨寄存器/栈，WO-2401 修订冻结）**：
- 第 1-4 参：rcx/rdx/r8/r9（寄存器）；第 5-7 参：**outgoing arguments**
  [rsp+0x20]/[rsp+0x28]/[rsp+0x30]（相对 **sub rsp,0x38 之后的 rsp**）。
- **thunk 自建帧（与现有 6-arg thunk 一致）**：thunk 入口先
  `sub rsp, 0x38`（帧 = 32 字节 shadow space + 3 个 outgoing 槽 24 字节 = 56，
  8 mod 16 → 修正 call 前对齐），call 后 `add rsp, 0x38` 恢复。
  **调用方不需要预分配参数槽**；调用方只需按普通 call 约定执行 call（thunk
  自身帧覆盖 shadow + outgoing）。
- **shadow space**：被调函数可自由使用 rsp+0x00..0x1F（32 字节），
  **不承载参数**；outgoing 参数槽在 shadow 之后：rsp+0x20（arg4/第 5 参）、
  rsp+0x28（arg5/第 6 参）、rsp+0x30（arg6/第 7 参）。
- **栈对齐（WO-2401 推导）**：thunk 入口 rsp ≡ 8 mod 16（caller 压入返回地址）；
  `sub rsp,0x38`（≡ 8 mod 16）→ **call 前 rsp ≡ 0 mod 16**（ABI 要求）；
  `call rax` → 被调 fn 入口 rsp ≡ 8 mod 16 ✓。本机实测（thunk7_final_test.c，
  asm stub 入口首指令记录）：callee entry rsp mod 16 = 8、call 前 rsp mod 16 = 0。
- **callee cleanup**：Windows x64 是 **caller-cleanup**（被调函数不弹栈）；
  thunk 自己 add rsp,0x38 后 ret，返回调用方。
- **volatile 寄存器**：rcx/rdx/r8/r9/r10/r11/rax 均可被被调函数破坏；
  thunk 在 call 前完成全部参数搬运，call 后只 add rsp + ret（不依赖任何 volatile）。
- **fn_ptr 保存**：fn_ptr 在 [r11] 读取到 rax，随后 call rax（FF D0）；
  r11 保存 ThunkArgs7* 贯穿全程（thunk 内不调用其它函数，r11 不被破坏）。

**ThunkArgs7（9 槽 72B，target 内一次性 WPM 写入）**：

| 槽 | 偏移 | 值 |
|----|------|----|
| fn_ptr | 0x00 | module_base + MidaAntidebugInitializeV2 RVA |
| arg0 | 0x08 | params_v2_blob_va |
| arg1 | 0x10 | params_bytes |
| arg2 | 0x18 | out_runtime_sha256_va |
| arg3 | 0x20 | 64 |
| arg4 | 0x28 | out_attestation_json_va |
| arg5 | 0x30 | ATTESTATION_BUFFER_SIZE |
| arg6 | 0x38 | out_attestation_written_va |
| reserved | 0x40 | 0（8 字节，保持 72B 总长） |

- THUNK_CODE_7ARG 与 ThunkArgs7 均为**实现工单新增**；现有 6 参 thunk（THUNK_CODE/
  ThunkArgs 64B）**不改**。
- 寄存器搬运顺序冻结（先 rcx/rdx/r8/r9，再栈槽 40/48/56），避免 r11 被覆盖；
  fn_ptr 保存在 r11（thunk 内不调用其它函数，r11 不会被破坏）。
- 入口断言：CreateRemoteThread start == module_base + MidaAntidebugInitializeV2 RVA
  （allowlist，§4.2）。

### 5.3d fallback 门禁（唯一，WO-1902 冻结）

**digest 需求定义**（可检查的唯一条件）：

> 当且仅当以下任一为真时，本次初始化**要求 digest 绑定**：
> 1. 本次会话启用 Walker 探针（WalkerExecute 将被调用）；或
> 2. 需要生成 v2 attestation（schema_version == 2，含 walker_attestation 容器）；或
> 3. acceptance 配置了 digest-bound 校验（runtime_module_sha256 绑定）。

**门禁规则**：
- digest 需求为真 → **必须**调用 MidaAntidebugInitializeV2；调用 v1 → controller 拒收
  （RuntimeLoadError::DigestBindingRequired），不进入 walker；
- digest 需求为假 → 允许 v1（无绑定路径合法）；
- **adr4-foundation-unbound 不得进入可接受证据**：任何 attestation 中
  runtime_sha256 == "adr4-foundation-unbound" 且 digest 需求为真 → acceptance 拒收
  （EvidenceInsufficient / DigestUnbound）；
- **不存在第三条路径**：不允许"调用 v1 但期望 digest"或"调用 V2 但 len 无效"的混合状态
  （V2 入口任何校验失败即 fail-closed，不降级 v1）。

### 5.3e V2 envelope layout（WO-2002 冻结：blob 自包含，offsets 全部 self-relative）

**envelope = params blob 全部内容**（controller 在 target 内一次性 VirtualAllocEx+WPM）：

| 段 | 相对偏移 | 内容 | 归属 |
|----|---------|------|------|
| 0x00 | 0 | MidaInitParamsV2 结构（0x48） | 固定 |
| 0x48 | 0x48 | profile_id 字符串（NUL 结尾） | 结构内 profile_id_off 指向 |
| — | 0x48+len1+1 | profile_digest 字符串（NUL 结尾） | profile_digest_off 指向 |
| — | … | expected_surfaces 字符串各 + NUL | 字符串区 |
| — | … | expected_surfaces 指针数组（8×N，target-local 绝对地址） | expected_surfaces_off 指向 |
| — | … | digest 字符串（64 hex + NUL = 65 字节） | digest_off 指向 |
| 末 | params_bytes | 结束（blob 总大小 = 结构 + 全部区段） | params_bytes 参数 |

**包含关系证明（runtime 侧，先于解引用）**：
- 对所有 off 字段：off >= 0x48 && off + need <= params_bytes（need 按字段类型：
  字符串 ≤ 65 字节扫描上限、指针数组 = 8×expected_hooks、digest = 65）；
- expected_hooks == 0 时 expected_surfaces_off 可省略（=0 合法，但 off==0 时必须
  与 expected_hooks==0 同时成立，否则拒收）；
- **integer overflow 规则**：所有 off + need 用 checked_add 计算；溢出 → 拒收（fail-closed）；
- **page boundary 规则**：跨页允许（runtime 自身进程可读完整已提交 blob）；
  不适用 probe 的 page-cross 规则（这是本地 params 读取，不是远程探针）；
- **canonical VA 规则**：envelope 内的**绝对地址**（surface 数组条目）必须是
  canonical user VA 且非 0；self-relative offsets 无 VA 语义，只做边界检查。

### 5.3f version negotiation（WO-2102 修订：严格拒绝未知扩展，语义单义）

- **判定顺序（入口，先于任何字段读取）**：
  1. params == NULL || params_bytes < 0x48 → 拒收（ShortBlob）；
  2. 读 params->magic_v2（offset 0x30，8 字节 LE）：
     - == 0x003250324144494D（"MIDA2P2\0"）→ v2 路径；
     - == 0 且 params_bytes >= 0x30 且调用方声称 v2 → 拒收（MissingMagic）；
     - 其它值 → 拒收（UnknownMagic）；
  3. **未知版本/未知扩展：严格拒绝，无兼容尾部**。magic_v2 匹配但
     params_bytes > 0x48 且存在任何超出已声明区段（envelope 表 §5.3e 之外）的
     未知字节 → 拒收（UnknownExtension，fail-closed）。**不存在**"允许未知尾部"
     的宽松语义；v3 必须新增 entry（MidaAntidebugInitializeV3）+ 新 magic +
     新版本化结构，不猜版本、不读未知区。
- **header trust boundary（WO-2202 修订：唯一可执行方案，禁止外部布尔冒充能力）**：
  **唯一方案**：header 可读性是**硬信任边界**——runtime 不自行验证 provenance，
  也不依赖 fixture 的 `expected_blob_base_va`/`header_readable` 外部输入
  （这些仅存在于离线 fixture 以驱动纯逻辑测试，**不进入 7 参 ABI**）。
  具体合同：
  1. **分配同源**：`params` 与 `params_bytes` 均由 controller 从同一次
     `VirtualAllocEx` 提供（params == blob_base_va，params_bytes == 分配大小）；
     该不变式由 controller 的调用序列保证（alloc → WPM 全量写入 → 才创建远程线程
     调 V2 entry），runtime 侧**无法也不尝试**复核分配归属。
  2. **坏指针行为 = 进程终止，而非返回错误码**：若 params 指向未提交/非本进程内存，
     runtime 读取 header 时触发 AV → 该异常沿链传播 → 进程终止。**不捕获、不恢复、
     不返回 HeaderFault**——HeaderFault 错误码**不存在**于 V2 出口（区别于 fixture
     的 14 号拒绝码，后者仅用于离线纯逻辑测试）。
  3. **provenance 的 enforcement 点在 controller**：controller 在 CreateRemoteThread
     前后记录 blob_base_va，并在结果/attestation 消费时复核；runtime 只依赖
     "blob 已由 controller 提交"这一信任前提。
  4. **fixture 定位**：`expected_blob_base_va`/`header_readable` 是 EnvelopeInput
     的纯逻辑测试输入（模拟"已信任的 blob"），用于离线验证边界/拒收逻辑正确性；
     **不得**被实现工单当作 runtime 入口参数或运行时能力。
  5. 所有在边界证明后可读的区域（digest/surfaces/profile 字符串）由 §5.3e 的
     checked 边界证明保护；边界证明失败 → 返回错误码（fixture 4/5/6/10/11/13），
     与 header 自身可读性假设无关。
- **v1 fallback（不变）**：v1 entry（MidaAntidebugInitialize）只读 0x30 内字段，
  永不读取 0x30 之后；digest 需求（WO-1902 §5.3d 三条件）时 V2 必选，
  V2 校验失败**禁止降级 v1**。

### 5.3g 离线拒收矩阵（WO-2002 交付，fixture 逐行断言）

| # | 输入 | 期望 |
|---|------|------|
| 1 | params == NULL | ShortBlob 拒收 |
| 2 | params_bytes < 0x48 | ShortBlob 拒收 |
| 3 | params_bytes == 0x30（v1 blob 传给 V2 entry） | ShortBlob 拒收 |
| 4 | magic_v2 == 0（v1 结构经 V2 传入） | MissingMagic 拒收 |
| 5 | magic_v2 == 0xDEAD | UnknownMagic 拒收 |
| 6 | 完整 V2 envelope（0x48 + 全部区段） | 通过 |
| 7 | params_bytes 溢出（u64::MAX） | Overflow 拒收 |
| 8 | profile_id_off 越界（off + len > params_bytes） | OutOfBounds 拒收 |
| 9 | digest_off 越界 | OutOfBounds 拒收 |
| 10 | digest_len != 64 | InvalidArgument 拒收 |
| 11 | digest 提前 NUL（< 64 字节） | TruncatedDigest 拒收 |
| 12 | digest 无 NUL（第 65 字节非 0） | BufferOverrun 拒收 |
| 13 | digest 含大写 hex（如 "AB"） | BadHex 拒收 |
| 14 | expected_hooks == 0 但 surfaces_off != 0 | InvalidArgument 拒收 |
| 15 | surface 数组条目非 canonical 或为 0 | NonCanonicalVa 拒收 |
| 16 | 未知 magic + params_bytes == 0x48 | UnknownMagic 拒收 |
| 17 | magic 匹配但 params_bytes > 0x48 且存在未声明区段（未知尾部） | UnknownExtension 拒收 |
| 18 | params != controller 记录 blob_base_va（外来指针） | ProvenanceReject 拒收 |
| 19 | header 读取 fault（blob 未提交/被篡改） | HeaderFault 拒收（fail-closed，不恢复） |
| 20 | profile_id_off 指向区域无 NUL（超 65 字节扫描） | TruncatedString 拒收 |
### 5.4 controller 复核（fail-closed）

- authority.verify_file（L181）通过 ≠ digest 绑定通过：verify_file 校验 manifest 身份，
  digest 复核是独立步骤（attestation.runtime_sha256 == digest_controller）。
- 任一不一致 → 拒收 attestation，标记 EvidenceInsufficient（WO-1503 §7），不进入 walker。
- **占位值不得作为 evidence**：adr4-foundation-unbound 只能出现在未实现状态；
  Walker 上线前必须替换为真实 digest 流，否则 acceptance 拒收（fail-closed）。

## 6. 实现前 checklist（全部通过才可派发实现）

- [ ] runtime 新增 WalkerExecute 导出（catch_unwind 防火墙 + walker_inner）
- [ ] loader wanted 5 项（+MidaAntidebugInitializeV2 +WalkerExecute）+ MidaExports 5 字段 + 解析泛化
- [ ] 入口地址 allowlist 断言（== module_base + rva）
- [ ] thunk 适配（复用 6 参或新增 1 参）
- [ ] runtime_sha256 真实文件哈希（外部 manifest 权威；MidaAntidebugInitializeV2 通道下发；替换 adr4-foundation-unbound）
- [ ] controller 侧 digest 复核（attestation.runtime_sha256 == digest_controller == out_runtime_sha256 回显）
- [ ] resolve_exports_from_buffers 测试补 4 项 wanted 用例
- [ ] 回归：现有 3 导出解析测试不破坏
- [ ] 实现后必须新增测试（WO-1902）：v1/v2 golden bytes 双向 encode/decode；endian vector；static_assert（C+Rust）；指针越界/提前 NUL/超长/非 hex 拒收矩阵；5 项 wanted 解析（含缺失/重复/forwarded/out-of-module）；V2 thunk 参数对位；fallback 门禁（digest 需求真假两分支）；未绑定 digest 拒收（adr4-foundation-unbound）

## 7. 状态

| 对象 | 状态 |
|-----|------|
| WO-1505 对位清单 | design-only；待联审 |
| runtime_loader.rs / exports.rs | 未修改 |