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

1. **新导出（设计意图，待实现）**：
   ~~~c
   /* MidaInitParamsV2 — 独立结构，与 v1 无布局依赖 */
   typedef struct MidaInitParamsV2 {
       /* ---- 与 v1 相同的前 0x30 语义字段（独立拷贝，无偏移复用） ---- */
       uint32_t target_pid;
       uint32_t _pad0;
       uint64_t module_base;
       const char* profile_id;        /* target-local */
       const char* profile_digest;    /* target-local */
       uint64_t expected_hooks;
       const char* const* expected_surfaces; /* target-local */
       /* ---- v2 追加字段（0x30 起，总大小 0x48） ---- */
       uint64_t magic_v2;             /* 见下 endian fixture */
       const char* expected_runtime_sha256; /* target-local，64 hex + NUL */
       uint64_t expected_runtime_sha256_len; /* == 64 */
   } MidaInitParamsV2;  /* size == 0x48 */
   __declspec(dllexport) int32_t MidaAntidebugInitializeV2(
       const MidaInitParamsV2* params,     /* 有明确类型，size 由结构定义 */
       uint8_t* out_runtime_sha256, size_t out_runtime_sha256_len,
       uint8_t* out_attestation_json, size_t out_attestation_len,
       size_t* out_attestation_written);
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
   - 校验 expected_runtime_sha256 非空且为 target-local（与 profile_id 同模式）；
   - 校验 expected_runtime_sha256_len == 64 且为合法 hex lowercase；否则 InvalidArgument；
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

**MidaInitParamsV2（0x48）**——v1 字段 + v2 追加：

| offset | size | 字段 | C 类型 | Rust 类型 |
|--------|------|------|--------|-----------|
| 0x00..0x30 | 0x30 | （v1 全部字段，逐字节一致） | 同 v1 | 同 v1 |
| 0x30 | 8 | magic_v2 | uint64_t | u64 |
| 0x38 | 8 | expected_runtime_sha256 | const char* | *const c_char |
| 0x40 | 8 | expected_runtime_sha256_len | uint64_t | u64 |
| 0x48 | — | 结束 | | |

golden bytes（追加段，magic_v2 = "MIDA2P2\0" LE = 0x003250324144494D,
digest_ptr = 0x404000, len = 64）：

~~~text
30: 4D 49 44 41 32 50 32 00     magic_v2(LE) = "MIDA2P2\0" 字节序
38: 00 40 40 00 00 00 00 00     expected_runtime_sha256_ptr(LE) = 0x404000
40: 40 00 00 00 00 00 00 00     expected_runtime_sha256_len(LE) = 64
总长 0x48
~~~

**C 侧 static_assert 合同（实现工单必须原样落地）**：

~~~c
_Static_assert(sizeof(MidaInitParams) == 0x30, "v1 size");
_Static_assert(sizeof(MidaInitParamsV2) == 0x48, "v2 size");
_Static_assert(offsetof(MidaInitParams, target_pid) == 0x00, "v1 target_pid");
_Static_assert(offsetof(MidaInitParams, module_base) == 0x08, "v1 module_base");
_Static_assert(offsetof(MidaInitParamsV2, magic_v2) == 0x30, "v2 magic");
_Static_assert(offsetof(MidaInitParamsV2, expected_runtime_sha256) == 0x38, "v2 digest ptr");
_Static_assert(offsetof(MidaInitParamsV2, expected_runtime_sha256_len) == 0x40, "v2 digest len");
~~~

**Rust 侧 static_assert 等价（实现工单必须）**：

~~~rust
const _: () = {
    assert!(std::mem::size_of::<MidaInitParams>() == 0x30);
    assert!(std::mem::size_of::<MidaInitParamsV2>() == 0x48);
    assert!(std::mem::offset_of!(MidaInitParamsV2, magic_v2) == 0x30);
    assert!(std::mem::offset_of!(MidaInitParamsV2, expected_runtime_sha256) == 0x38);
};
~~~

**endian test vector（实现单测）**：encode/decode 双向断言——读 8 字节 LE 于 0x30 得到
0x003250324144494D 且字节 == [4D 49 44 41 32 50 32 00]；写同值再读回一致。

### 5.3b V2 指针安全合同（WO-1902 冻结）

**target-local 判定**：V2 结构内全部指针（profile_id、profile_digest、expected_surfaces、
expected_runtime_sha256）必须是 target 进程地址空间内的 VA。运行时判定规则：
- 指针值必须落在**本 params blob 分配范围内**（controller 在 target 内 VirtualAllocEx
  分配，blob 基址 + 长度已知）；runtime 在 initialize 时按"blob 范围"检查所有指针，
  不在范围内 → InvalidArgument（fail-closed）。
- 检查顺序：先判指针 == 0 → 拒收；再判指针 < blob_base || 指针 >= blob_base + blob_size
  → 拒收；再判目标区域可读（NUL 扫描 65 字节上限，见下）。
- **不依赖 ReadProcessMemory/SEH**：所有指针指向的字节在本进程地址空间内
  （同一 target 进程 = runtime 自身进程），直接解引用；范围检查在解引用前完成。

**65-byte digest 可读性**：
- expected_runtime_sha256 指向 64 hex 字符 + 1 NUL = 65 字节区域；
- 读取协议：len 字段必须 == 64；从 ptr 起最多读 65 字节，遇 NUL 停止；
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

**V2 thunk 六参数对位**（复用现有 6 参 thunk）：

| thunk 槽 | 值 |
|----------|----|
| fn_ptr | module_base + MidaAntidebugInitializeV2 RVA |
| arg0 | params_v2_blob_va（target-local） |
| arg1 | out_runtime_sha256_va |
| arg2 | 64（out_runtime_sha256_len） |
| arg3 | out_attestation_json_va |
| arg4 | ATTESTATION_BUFFER_SIZE |
| arg5 | out_attestation_written_va |
| reserved | 0 |

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
