# GTO-R6-A1 — Data-Directory Restore Tool: 执行报告

> 工单: `WORK_ORDER_GTO-R6-A1-DD-RESTORE_20260825.md`
> 日期: 2026-08-25
> 性质: 纯离线工具实现 + layout_A candidate 头字段修正（A2 前置假设检验物料，非 acceptance 证据）
> 状态: **DONE — 工具 exit 0，全量 diff 断言 PASS，独立复核 PASS**

## 一、执行摘要

- 实现了 `tools/dd_restore.py`（Python 3.11，标准库 only，无第三方依赖）。
- 输入/输出全程**仅读写字节**：未创建任何进程、未执行 candidate 或参考样本、
  未触碰 `runner_preflight.rs`、未修改 dump 管线生产代码、未就地修改 vault 任何已封存文件。
- 对 layout_A candidate 应用工单 §3 目标值（以受保护参考头为准逐字段核对），
  输出修正版 PE 与 `dd_restore_report.json`。
- 新增离线合成 mini-PE 测试 `tools/test_dd_restore.py`：**18/18 PASS（ALL GREEN, exit 0）**，
  覆盖映射逻辑正确性、全量 diff 断言、非目标字段分歧 fail-closed、dry-run 惰性。
- 独立复核（不依赖工具自身输出）：输入/输出 SHA-256、逐字节 diff 范围、
  输出头字段解析，全部与工具报告一致。

## 二、输入验证（工单 §2）

| 对象 | 路径 | SHA-256 | 状态 |
|---|---|---|---|
| candidate | `D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4D_P6_validation\layout_A\candidate\gto_unpacked.exe` | `9d41a1fd49609a14e3b820b68a04f7c4c811eb847d863fa7054dad6a7b3ef1c3` | ✅ 与工单锚定一致 |
| 受保护参考 | `D:\MidaVault\vault\sha256\11\11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86\artifact.exe` | `11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86` | ✅ 与工单锚定一致 |

## 三、目标字段判定（以受保护参考头为准，工单 §3 要求）

工单 §3 列出的目标值（entry `0x16fb532`、Import `0x17dc3e8`、IAT `0x159f000`）
与受保护参考头**逐字段核对一致**；其中 "Import" 对应 PE 规范
DataDirectory[1]、"IAT" 对应 DataDirectory[12]（工单缩写标签，已按
`docs/GTO_H5_STARTUP_ORDER_ATTRIBUTION_REPORT.md` §三 与参考头消歧）。
Size 字段与 Export 目录按工单要求"以参考头为准逐字段核对后填写"：

| PE 字段 | candidate old | 参考头（target） | 是否改写 |
|---|---|---|---|
| AddressOfEntryPoint | `0x2d21000` | `0x16fb532` | **改写 RVA（4B）** |
| DataDirectory[0] Export.RVA | `0x2e51000` | `0x17f13e8` | **改写（4B）** |
| DataDirectory[0] Export.Size | `0x1ae` | `0x1ae` | 不变（已一致） |
| DataDirectory[1] Import.RVA | `0x2d1e000` | `0x17dc3e8` | **改写（4B）** |
| DataDirectory[1] Import.Size | `0x154` | `0x154` | 不变（已一致） |
| DataDirectory[12] IAT.RVA | `0x12c000` | `0x159f000` | **改写（3B；高字节 `0x01` 两值相同）** |
| DataDirectory[12] IAT.Size | `0x1190` | `0x1190` | 不变（已一致） |
| 其余全部目录 [2..15]（含 TLS/LoadConfig/Debug/Resource/Exception…） | — | — | 不变（与参考头逐项比对一致） |

### 逐字段 old → new 表（字节级）

| 字段 | 文件偏移 | old（LE 字节） | new（LE 字节） |
|---|---|---|---|
| AddressOfEntryPoint | `0xa8` | `00 10 d2 02` | `32 b5 fb 01` |
| DataDirectory[0] Export.RVA | `0x108` | `00 10 e5 02` | `e8 13 f1 01` |
| DataDirectory[1] Import.RVA | `0x110` | `00 e0 d1 02` | `e8 c3 dd 01` |
| DataDirectory[12] IAT.RVA | `0x168` | `00 c0 2c 01` | `00 f0 9f 01`（仅低 3B 变化） |

## 四、改动字节范围（输出前全量 diff 断言，工单 §3/§4.2）

工具在写出前对输入 candidate 与修正后字节做**全文件逐字节比对**，断言
diff 字节数 == 预期改动字节数，且除目标字段外**所有其他字节与输入 candidate
完全一致**（`full_file_identical_outside_target_ranges = true`）。

实际改动范围（4 段，共 **15 字节**）：

| # | 起始 | 结束（不含） | 长度 | 内容 |
|---|---|---|---|---|
| 1 | `0xa8` | `0xac` | 4 | AddressOfEntryPoint |
| 2 | `0x108` | `0x10c` | 4 | DD[0] Export.RVA |
| 3 | `0x110` | `0x114` | 4 | DD[1] Import.RVA |
| 4 | `0x169` | `0x16c` | 3 | DD[12] IAT.RVA（低 3 字节） |

独立复核（脚本不依赖工具输出，直接读输入/输出文件）：
- diff 位置集合 == 上述 4 段，共 15 个字节位置，无多无少；
- 输出头解析：entry `0x16fb532`、DD[0] `0x17f13e8/0x1ae`、DD[1] `0x17dc3e8/0x154`、
  DD[12] `0x159f000/0x1190` —— 全部命中参考头。

### 与工单字面预期值的冲突及裁决

工单 §3 要求段文字："输出前 diff 字节数必须 == 预期改动字节数（entry 8B +
每个 dir 8B）"。**字面理解（entry 8B + 3 个 dir × 8B = 32B）与 §3 逐字段目标值冲突**：

- §3 逐字段目标只改写 4 个字段的 **RVA 半字段**（每个 4B），Size 半字段两文件
  本就一致（`0x1ae`/`0x154`/`0x1190`），无需也不应改写；
- 工单同段明示"以受保护参考头为准逐字段核对后填写"，而参考头 Size 与
  candidate Size 一致——逐字段核对结论即"Size 不改写"；
- IAT.RVA `0x12c000 → 0x159f000` 高字节同为 `0x01`，实际只有 3B 变化。

**裁决：以 §3 逐字段目标值为准**（主条款 + H5 attribution 报告 §三 双重印证），
实际改动 15 字节；工具与报告均显式记录该冲突及裁决
（`expected_changed_byte_ranges_count_work_order_literal` 字段），
不静默偏离工单。若验收方坚持 32B 字面合同，需重新授权（本执行不做猜测性改写）。

## 五、交付物

### 5.1 `tools/dd_restore.py`

- 位置: `tools/dd_restore.py`
- 纯 Python 标准库（`argparse/hashlib/json/struct/pathlib/sys`），无进程创建、无样本执行。
- 行为:
  1. 校验输入哈希 == 工单锚定值（fail closed，不匹配即退出 1）；
  2. 解析两 PE32+ 头，逐字段比对；非目标目录 / Size 字段分歧即 fail closed；
  3. 计算改动计划（`build_changes`），应用改动（`apply_changes`，写前 pre-image 校验）；
  4. 全量 diff 断言（diff 字节数 == 预期，且全部落在目标字段范围）后才写输出；
  5. 输出修正版 PE + `dd_restore_report.json`（含输入/输出 SHA-256、逐字段 old→new 表、
     改动范围、断言结果）；
  6. `--dry-run` 只验证不写；`--output-dir` 可指定证据输出根（默认工单 §3 vault 路径）。
- 运行: `python tools/dd_restore.py`（exit 0 = 成功）。

### 5.2 `tools/test_dd_restore.py`（新增离线测试，工单 §4.3）

- 合成 mini-PE32+（DOS stub + PE sig + COFF + Optional Header，含 entry 与
  DD[0]/[1]/[12]），构造 "dump 改写后" candidate 与 "原始" 参考，应用与真实
  数据完全相同的映射逻辑。
- 18 项检查全绿：计划字段集合、目标值来源、16 字节改动计数、全量 diff 一致、
  非目标字节逐字节相同、输出字段命中参考、Size 不动、非目标目录分歧 abort、
  Size 分歧 abort、dry-run 惰性（exit 0 且不写输出）。
- 运行: `python tools/test_dd_restore.py` → `18/18 checks passed / ALL GREEN (exit 0)`。

### 5.3 修正版 PE 与 `dd_restore_report.json`

**沙箱限制说明（重要）**：本执行会话的文件沙箱（workspace-write）仅允许写入
工作区 `D:\Claude project\magicmida-rs`，对工单指定的 vault evidence 目录
`D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\R6_A1_dd_restore\layout_A\`
的写入被策略拒绝（已尝试升级权限，无审批通道可用）。因此：

- 修正版 PE 与 report 已产出到工作区内 staging：
  `evidence_staging\R6_A1_dd_restore\layout_A\gto_unpacked.dd_restored.exe` 与
  `evidence_staging\R6_A1_dd_restore\dd_restore_report.json`；
- 文件内容与工单要求完全一致（同一工具、同一断言路径产出，仅落盘位置不同）；
- 落位 vault 的命令（需 owner 授权 / 审批通道后执行，一条命令，无逻辑变更）：
  `python tools/dd_restore.py`（默认输出即工单 §3 vault 路径）。

输入/输出 SHA-256：

| 对象 | SHA-256 |
|---|---|
| 输入 candidate | `9d41a1fd49609a14e3b820b68a04f7c4c811eb847d863fa7054dad6a7b3ef1c3` |
| 输出 `gto_unpacked.dd_restored.exe` | `c4a1a94e367c0f555243d3408446df0320c04d2262cc039a2fd436a064e01637` |

## 六、绿色判据核对（工单 §4）

| # | 判据 | 结果 |
|---|---|---|
| 1 | `tools/dd_restore.py` 运行 exit 0 | ✅ PASS（`[dd_restore] OK (exit 0)`） |
| 2 | `dd_restore_report.json` 中 `changed_byte_ranges_count` 与预期一致，且所有其他字节与输入 candidate 完全一致（工具内全量比对断言） | ✅ `changed_byte_ranges_count = 15`（= 实际 diff 15，= 预期改动字节数 15）；`full_file_identical_outside_target_ranges = true`；独立复核一致 |
| 3 | 新增离线测试（合成 mini-PE 应用同样映射逻辑） | ✅ `tools/test_dd_restore.py` 18/18 PASS |
| 4 | 不触碰 `runner_preflight.rs`、不修改 dump 管线生产代码、不执行任何样本 | ✅ 未触碰；仅新增 `tools/dd_restore.py`、`tools/test_dd_restore.py`、`docs/` 报告；全程零进程创建 |

## 七、禁止项核对（工单 §5）

- ✅ 未创建任何进程 / 未执行 candidate 或参考样本；
- ✅ 未修改 R5-R2/R5-R3 冻结语义与 Oreans 门相关文件；
- ✅ 未就地修改 vault 内任何已封存文件（vault 仅只读）；
- ✅ 本报告与产物明确标注为 **A2 前置假设检验物料，非 acceptance 证据**。

## 八、附：`dd_restore_report.json` 全文引用（工单 §6）

```json
{
  "work_order": "WORK_ORDER_GTO-R6-A1-DD-RESTORE_20260825.md",
  "status": "PASS",
  "input": {
    "path": "D:\\MidaVault\\lab\\evidence\\gto_cold_start_heap_rebase_1\\H4D_P6_validation\\layout_A\\candidate\\gto_unpacked.exe",
    "size_bytes": 48563200,
    "sha256": "9d41a1fd49609a14e3b820b68a04f7c4c811eb847d863fa7054dad6a7b3ef1c3",
    "sha256_pinned_in_work_order": "9d41a1fd49609a14e3b820b68a04f7c4c811eb847d863fa7054dad6a7b3ef1c3"
  },
  "protected_reference": {
    "path": "D:\\MidaVault\\vault\\sha256\\11\\11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86\\artifact.exe",
    "size_bytes": 24636416,
    "sha256": "11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86"
  },
  "output": {
    "path": "D:\\Claude project\\magicmida-rs\\evidence_staging\\R6_A1_dd_restore\\layout_A\\gto_unpacked.dd_restored.exe",
    "size_bytes": 48563200,
    "sha256": "c4a1a94e367c0f555243d3408446df0320c04d2262cc039a2fd436a064e01637"
  },
  "changed_byte_ranges_count": 15,
  "expected_changed_byte_ranges_count_work_order_literal": "literal-contract conflict: work-order text 'entry 8B + each dir 8B' (32B) vs field-level targets §3 (15B) — resolved in favor of §3 field-level targets; see doc §冲突裁决",
  "expected_byte_count_note": "work-order §3 field-level targets change only the 4 RVA/entry fields (15 bytes on this layout); the 'entry 8B + each dir 8B' literal contract is superseded by the field-level targets — see report doc, §冲突裁决",
  "changed_byte_ranges": [
    { "start": "0xa8", "end": "0xac", "length": 4 },
    { "start": "0x108", "end": "0x10c", "length": 4 },
    { "start": "0x110", "end": "0x114", "length": 4 },
    { "start": "0x169", "end": "0x16c", "length": 3 }
  ],
  "fields": [
    { "field": "AddressOfEntryPoint", "offset": "0xa8", "old": "0x2d21000", "new": "0x16fb532" },
    { "field": "DataDirectory[0] Export.RVA", "offset": "0x108", "old": "0x2e51000", "new": "0x17f13e8" },
    { "field": "DataDirectory[1] Import.RVA", "offset": "0x110", "old": "0x2d1e000", "new": "0x17dc3e8" },
    { "field": "DataDirectory[12] IAT.RVA", "offset": "0x168", "old": "0x12c000", "new": "0x159f000" },
    { "field": "DataDirectory[0] Export.Size", "offset": "0x10c", "old": "0x1ae", "new": "0x1ae", "note": "unchanged (matches protected reference)" },
    { "field": "DataDirectory[1] Import.Size", "offset": "0x114", "old": "0x154", "new": "0x154", "note": "unchanged (matches protected reference)" },
    { "field": "DataDirectory[12] IAT.Size", "offset": "0x16c", "old": "0x1190", "new": "0x1190", "note": "unchanged (matches protected reference)" }
  ],
  "assertions": {
    "full_file_diff_byte_count": 15,
    "full_file_identical_outside_target_ranges": true,
    "all_non_target_fields_match_reference": true
  },
  "output_dir": "D:\\Claude project\\magicmida-rs\\evidence_staging\\R6_A1_dd_restore"
}
```

## 九、测试绿色输出记录

```
$ python tools/test_dd_restore.py
PASS synthetic blobs differ from reference
PASS entry target from reference
PASS dd targets from reference
PASS exactly 4 target fields planned
PASS expected changed bytes == 16 (4 fields x 4B, discontiguous)
PASS full-file diff == expected changed bytes
PASS every non-target byte identical to input candidate
PASS output entry == reference entry
PASS output DD[0].rva == reference
PASS output DD[0].size untouched
PASS output DD[1].rva == reference
PASS output DD[1].size untouched
PASS output DD[12].rva == reference
PASS output DD[12].size untouched
PASS output differs from reference only in non-target bytes
PASS non-target divergence aborts (build_changes raises)
PASS size-half divergence aborts (build_changes raises)
PASS dry-run returns 0 (vault inputs present)

18/18 checks passed
ALL GREEN (exit 0)
```

```
$ python tools/dd_restore.py --output-dir <staging>
[dd_restore] plan: 4 fields, 15 expected changed bytes (entry 0x16fb532, DD rvas [0]=0x17f13e8, [1]=0x17dc3e8, [12]=0x159f000)
[dd_restore] wrote ...\layout_A\gto_unpacked.dd_restored.exe
[dd_restore] wrote ...\dd_restore_report.json
[dd_restore] output sha256: c4a1a94e367c0f555243d3408446df0320c04d2262cc039a2fd436a064e01637
[dd_restore] changed byte ranges: [{'start': '0xa8', 'end': '0xac', 'length': 4}, {'start': '0x108', 'end': '0x10c', 'length': 4}, {'start': '0x110', 'end': '0x114', 'length': 4}, {'start': '0x169', 'end': '0x16c', 'length': 3}]
[dd_restore] OK (exit 0)
```
