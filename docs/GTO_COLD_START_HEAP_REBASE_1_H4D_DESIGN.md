# GTO-COLD-START-HEAP-REBASE-1 — H4-D Design: Exception/Unwind + No-Reloc

> status: DESIGN PREPARATION (GTO-H4-D-DESIGN-1 + CORRECTION-1/2) — no live matrix, no loader smoke, no H5
> authorization: 总指挥 2026-08-20 审核 D1-D4 设计通过; GTO-H4-D-LIVE-AUTHORIZATION-1 NOT granted — live 未解锁
> discipline: 静态审阅 + 设计 + 数据模型 + 负例矩阵; 不伪造 exception/unwind/relocation 数据
> ADR7: FROZEN (17/17 PASS) — 本设计不改动任何 frozen evidence / verifier
> 参照: H4-C 模式 (runtime observation -> candidate reparse -> independent decoder -> fail-closed writer)

## 0. 现状盘点 (静态审阅结论)

已存在的实现 (GTO 主线, 非 ADR7):

| 组件 | 文件 | 状态 |
|---|---|---|
| base relocation runtime observation | crates/pe/src/relocation_observation.rs | 已有: directory_present/relocs_stripped/dynamic_base/runtime+preferred base/blockers fail-closed |
| relocation evidence sidecar | dump_process.rs -> .relocation_evidence.json | 已有 (directory partial/truncated 拒绝逻辑存在) |
| Exception DD 捕获 | dump_process.rs §1b | 已有: saved_exception_rva + exception_directory_lacks_raw + force_pdata_no_shrink |
| .pdata 重建 | dumper/sections.rs create_pdata_section | 已有 (Oreans 回归门要求) |
| TLS 观察模式 | crates/pe/src/tls_observation.rs | 参照对象: report + blockers + is_complete() |

**GAP (H4-D 需要新增)**:
1. 无独立 RUNTIME_FUNCTION/UNWIND_INFO 解码器 (现有检查在 acceptance/oreans_pe_evidence.rs
   是 ADR7 frozen 门, 不可复用为 final truth; dump 侧只捕获 DD 不解析表)
2. exception runtime observation 无 report 类型 (缺 runtime_exception_observation)
3. final decoder 无独立 sidecar (缺 .exception_evidence.json / unwind 结构)
4. no-reloc 六态语义未文档化冻结 (代码有实现, 无 frozen 定义)
5. 负例矩阵未定义

## 1. D1 — Exception Directory / Unwind 设计

### 1.1 Runtime observation (dump 边界, immutable)

新模块: crates/pe/src/exception_observation.rs (仿 tls_observation.rs)

```text
pub enum ExceptionDirectoryStatus {
    Present,          // DD (va,size) 均非零
    Absent,           // DD 元组全零 — 完整负观察
    PartialTuple,     // va/size 一零一非零 — blocker
    SizeOverflow,     // size 超 host usize / 超限 — blocker
}

pub enum RuntimeFunctionStatus {
    Valid,
    OutOfRange,       // Begin/End/UnwindInfoRVA 不在 image 范围 — blocker
    BeginNotLessEnd,  // BeginAddress >= EndAddress — blocker
    UnwindInfoOutOfBounds, // unwind info RVA+size 越界 — blocker
    HandlerOutsideExec,    // handler RVA 不在可执行节 — blocker
    Unaligned,        // RUNTIME_FUNCTION 数组或 unwind info 未 4/8 对齐 — blocker
}

pub struct RuntimeFunctionObservation {
    pub index: u32,
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
    pub status: RuntimeFunctionStatus,
}

pub struct UnwindInfoObservation {
    pub function_index: u32,
    pub version: u8,          // UNWIND_INFO.version (低 3 位)
    pub flags: u8,            // UNWIND_INFO.flags (高 5 位)
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub codes: Vec<UnwindCodeObservation>,
    pub handler_rva: Option<u32>,  // chained/exception handler (UNW_FLAG_EHANDLER|UHANDLER|CHAININFO)
    pub status: UnwindInfoStatus,
}

pub struct UnwindCodeObservation {
    pub code_offset: u8,
    pub unwind_op: u8,
    pub op_info: u8,
    pub slot_status: UnwindCodeStatus,  // Valid | InvalidOp | InvalidVersion
}

pub struct ExceptionObservationReport {
    pub directory_present: bool,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub pe32_plus: bool,
    pub runtime_image_base: u64,
    pub preferred_image_base: u64,
    pub size_of_image: u32,
    pub directory_bytes_read: usize,
    pub function_count: u32,
    pub functions: Vec<RuntimeFunctionObservation>,
    pub unwind_infos: Vec<UnwindInfoObservation>,
    pub sorted_by_begin: bool,          // entries 按 BeginAddress 升序
    pub no_overlap: bool,               // 无非法重叠
    pub handlers_in_executable: bool,   // 所有 handler RVA 在可执行节内
    pub blockers: Vec<String>,
}
```

### 1.2 校验矩阵 (每条都必须 fail-closed)

| # | 校验 | 失败语义 |
|---|---|---|
| E1 | DD (va,size) 元组一致 | 部分元组 -> blocker |
| E2 | directory size 可转 usize 且 <= 64MB 观察上限 | 溢出/超限 -> blocker |
| E3 | size % 12 == 0 (x64 RUNTIME_FUNCTION 12 字节) | 非对齐 -> blocker |
| E4 | 每个 entry: BeginAddress < EndAddress | 违反 -> blocker (该 entry status) |
| E5 | Begin/End/UnwindInfoRVA 均 < SizeOfImage | 越界 -> blocker |
| E6 | 全部 entry 按 BeginAddress 升序 | 乱序 -> blocker |
| E7 | 相邻 entry 无重叠 (prev.End <= cur.Begin) | 重叠 -> blocker |
| E8 | 每个 unwind info: RVA + 展开尺寸 <= SizeOfImage 且不越界 | 越界 -> blocker |
| E9 | unwind info version <= 2 (x64) | 非法版本 -> blocker |
| E10 | flags 仅允许 KNONFLAGS (0x0)/EHANDLER(0x1)/UHANDLER(0x2)/CHAININFO(0x4) 组合 | 非法 flags -> blocker |
| E11 | UNW_FLAG_CHAININFO: chained unwind info RVA 合法且在 image 内 | 非法 -> blocker |
| E12 | UNW_FLAG_EHANDLER/UHANDLER: handler RVA 在可执行节内 | 在不可执行节 -> blocker |
| E13 | count_of_codes * 2 + 4 <= unwind info size (边界) | 越界 -> blocker |
| E14 | 若目录存在但 size==0 (空目录) | 记录为空观察, 非 blocker (同 TLS 语义) |
| E15 | directory 存在但 raw 无 backing (零 raw 节) | 记录 force_pdata 信号 (非 blocker; 重建由 dump 层负责) |

### 1.3 输出模型 (final)

```json
{
  "schema": "mida.gto-h4d-exception/v1",
  "runtime_exception_observation": { ...report as above... },
  "final_exception_observation": {
    "directory_present": true,
    "function_count": 319,
    "functions_preserved": 319,
    "unwind_infos_preserved": 319,
    "handlers_preserved": 12,
    "preservation": "field-by-field copy of decoded table into candidate"
  },
  "preservation": "exception directory + unwind info preserved field-by-field; no re-derivation",
  "blockers": [],
  "prerequisite_passes": {
    "runtime_observation_complete": true,
    "final_decoder_clean": true,
    "directory_preserved": true,
    "relocation_state_consistent": true
  }
}
```

## 2. D2 — No-Reloc 语义冻结

### 2.1 六态定义 (必须可区分)

| 状态 | 判定 | 处置 |
|---|---|---|
| directory absent | DD (va,size) == (0,0) 且 RELOCS_STRIPPED 未设 | 记录 absent; 不合成; 非 blocker (但若 DYNAMIC_BASE 设 -> blocker, 见下) |
| directory present but empty | va!=0, size==0 (或 size < 8 无 block) | 记录 empty; 非 blocker; sidecar 标注 empty |
| RELOCS_STRIPPED | file_header.characteristics & 0x0001 | 记录 stripped; 若与 DD 状态矛盾 -> blocker |
| DYNAMIC_BASE | dll_characteristics & 0x0040 | 记录 dynamic; 若与 runtime base != preferred base 矛盾 -> blocker |
| runtime image base | 实际加载基址 (ASLR) | 记录; 绝不据此推断 reloc 存在 |
| preferred image base | 磁盘 PE image_base | 记录; runtime != preferred 时若无 reloc 且无 stripped -> blocker |

### 2.2 硬规则 (冻结)

1. 不合成假 relocation directory
2. 不凭 ASLR 结果 (runtime != preferred) 推断存在 reloc
3. 不静默清除 RELOCS_STRIPPED
4. runtime/final 状态不一致 -> fail-closed (blocker, 拒写 sidecar)
5. relocation directory 部分存在 (va/size 一零一非零)、越界、截断 -> 拒绝 sidecar
6. 正确语义表述固定为 "no-reloc state observed and preserved"，禁止写成 "relocation PASS"

### 2.3 现状对照

relocation_observation.rs 已实现 1/2/3/5 (partial tuple blocker, size cap, stripped/dynamic 记录);
gap: 4 的一致性 cross-check (runtime vs final 状态比对) 需在 H4-D 中显式接入 final decoder。

## 3. D3 — 独立 Final Decoder

### 3.1 API (frozen)

```rust
// crates/pe/src/exception_final.rs (新模块, 独立于 dump 阶段解析)
pub struct ExceptionFinalDecoder {
    // 输入: candidate 字节 + 其 PE 头 (独立 reparse, 不复用 dump 对象)
}

impl ExceptionFinalDecoder {
    pub fn from_candidate_bytes(bytes: &[u8]) -> Result<Self, String>;
    // 独立解析 candidate: 读 DD 3, 重算 RUNTIME_FUNCTION 表, 独立 unwind walk
    pub fn decode(&self) -> ExceptionFinalReport;
}

pub struct ExceptionFinalReport {
    pub directory_present: bool,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub function_count: u32,
    pub functions: Vec<RuntimeFunctionObservation>,  // 复用同一校验类型
    pub unwind_infos: Vec<UnwindInfoObservation>,
    pub blockers: Vec<String>,
    pub preservation_match: bool,  // 与 runtime observation 逐字段一致
}
```

### 3.2 管线

```text
runtime observation (dump 边界, debugger 读)
  -> candidate byte reparse (final decoder 从 candidate 字节独立解析)
  -> field-by-field preservation 比对 (runtime vs final)
  -> fail-closed evidence writer (.exception_evidence.json)
```

不能复用 dump 阶段已解析的对象作为 final truth — final decoder 必须从
candidate 原始字节重新解析 (仿 H4-C 的独立 reparse 原则)。

## 4. D4 — Negative Test 矩阵 (12+ 负例)

每个负例: prerequisite_passes=false, blocker 非空, 拒绝写入通过门的 sidecar。

| # | 负例 | 构造 | 预期 blocker |
|---|---|---|---|
| N1 | exception directory absent | DD=(0,0), no stripped | 无 (完整负观察) — 仅当 DYNAMIC_BASE 且 runtime!=preferred 才 blocker |
| N2 | directory truncated | size=4 (非 12 倍数) | "size % 12 != 0" |
| N3 | RUNTIME_FUNCTION out of range | begin_rva > SizeOfImage | "begin out of image" |
| N4 | Begin >= End | begin==end | "begin >= end" |
| N5 | unsorted entries | 手动乱序表 | "not sorted by begin" |
| N6 | overlapping entries | prev.end > cur.begin | "overlap" |
| N7 | invalid unwind RVA | unwind_info_rva 越界 | "unwind info out of bounds" |
| N8 | handler outside executable section | handler_rva 指向 .data | "handler not in executable" |
| N9 | RELOCS_STRIPPED mismatch | stripped 位设但 DD 非零 | "stripped flag conflicts with directory" |
| N10 | DYNAMIC_BASE mismatch | dynamic 位设但 runtime != preferred 且无 reloc | "dynamic base without relocation" |
| N11 | preferred/runtime base inconsistency | runtime 记录与 final 重parse 不一致 | "runtime/final base mismatch" |
| N12 | partial relocation directory | va!=0, size==0 | "base relocation tuple partial" (现有已覆盖) |
| N13 | unwind info version invalid | version=7 | "invalid unwind version" |
| N14 | UNW_FLAG_CHAININFO 非法链 | chained rva 越界 | "invalid chained unwind" |
| N15 | count_of_codes 越界 | codes 超出 unwind info 边界 | "unwind codes exceed info size" |

## 5. D5 — 证据结构

```text
D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4D_exception_no_reloc\
├── design_metadata.json          # 本设计文档哈希 + 派单引用 + created_utc
├── schemas/
│   ├── runtime_exception_observation.schema.json
│   ├── final_exception_decoder.schema.json
│   ├── no_reloc_state.schema.json
│   └── exception_evidence.schema.json   # final sidecar schema (正式 JSON Schema draft-07)
├── negative_tests/
│   └── records.jsonl             # 每负例: id, construct, expected_blocker; stage=DESIGN,
│                                 # validation_status=NOT_EXECUTED, pass=null (未跑 live 前禁止称"已验证")
├── build_attestation_reference.json   # 如实记录: H4-D 尚无专用 build attestation;
│                                 # status=PENDING_H4D_BUILD; H4-C 时代引用仅为环境参照, 不冒充
├── layout_A/                     # 占位目录已落盘, 含 layout_status.json
│   ├── layout_status.json        #   {schema, layout, status: "NOT_STARTED"}
│   ├── child.stderr.bin          # live 时写入 (禁止跨布局共享)
│   ├── child.stdout.bin
│   ├── controller_run.json
│   ├── capture_policy.json
│   └── candidate/
└── layout_B/  layout_C/          # 同上, 每布局独立
```

schemas/ 语义 (冻结): 4 个文件均为**正式 JSON Schema (draft-07)** — 含
`$schema`/`$id`/`type`/`properties`/`required`/`additionalProperties`,
可被 jsonschema Draft7Validator 直接执行 (check_schema 通过, 坏样本被拒)。
它们不是"轻量字段描述"。

live 证据规则 (冻结):
- 每布局独立子目录, 禁止共享 child.stderr.bin / child.stdout.bin / controller_run.json
- seal 工具放 evidence root 外 (沿用 H4-C Seal-2 纪律)
- created_utc 用实际签封时间
- layout_A/B/C 在 live 授权前保持 status=NOT_STARTED; 授权后运行才翻转

## 6. D6 — 设计验收门 (完成条件)

| # | 门 | 状态 |
|---|---|---|
| G1 | exception/unwind schema frozen | 本文档 §1 |
| G2 | no-reloc semantics frozen | 本文档 §2 |
| G3 | independent decoder API frozen | 本文档 §3 |
| G4 | fail-closed blockers defined | 本文档 §1.2 (E1-E15) + §2.2 |
| G5 | negative test matrix defined | 本文档 §4 (15 负例) |
| G6 | H4-D live runner path defined | 复用 gto_live_route_controller.py (observation-only 通道) + --attempt-sequence 独立布局 |
| G7 | H4-D seal scope defined | H4D_exception_no_reloc/ 全文件 (工具除外) + design_metadata |
| G8 | ADR7 verifier still 17/17 PASS | 提交前重跑确认 |
| G9 | working tree clean | 提交后确认 |

## 7. 非主张

- 未跑 live matrix; 未做 loader smoke; 未执行 H5
- 未修改 ADR7 frozen evidence; 未改 Oreans 门
- 未提交样本/候选二进制; 未伪造 exception/unwind/relocation 数据
- no-reloc 结论 = "no-reloc state observed and preserved" (不是 "relocation PASS")
