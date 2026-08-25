# WORK ORDER — GTO-R6-A1: DATA-DIRECTORY RESTORE TOOL (OFFLINE ONLY)

**签发**: Hermes 总审计 (ox-alpha)，经 owner 授权
**日期**: 2026-08-25
**性质**: 纯离线工具实现 + 字节级验证。**禁止任何进程创建/样本执行。**
**工作分支建议**: `codex/gto-r6-a1-dd-restore`

## 1. 背景

GTO-H5-STARTUP-ORDER-ATTRIBUTION-2 已确定 candidate 崩溃机制：dump 器重建了
PE 头数据目录，而 TLS 期 API resolver 读取原始 Import Directory 值。本单在
**不改 dump 管线**的前提下，做一个独立离线修正工具，把四个被改写的目录字段
恢复为运行时真值，产出修正版 candidate 供后续 A2 loader smoke 检验假设。

## 2. 输入（全部只读）

| 对象 | 路径 | SHA-256 |
|---|---|---|
| candidate | `D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4D_P6_validation\layout_A\candidate\gto_unpacked.exe` | `9d41a1fd49609a14e3b820b68a04f7c4c811eb847d863fa7054dad6a7b3ef1c3` |
| 受保护参考 | `D:\MidaVault\vault\sha256\11\11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86\artifact.exe` | `11473d2e…`（vault 锚定） |

## 3. 目标修改（仅 PE 头 Optional Header DataDirectory + AddressOfEntryPoint）

字段写入值（来自 startup order attribution 报告 §三）：

```
AddressOfEntryPoint : 0x16fb532
DataDirectory[0] Import.RVA : 0x17dc3e8
DataDirectory[1] IAT.RVA    : 0x159f000
DataDirectory[0].Size / [1].Size / Export(0) : 以受保护参考头为准逐字段核对后填写
```

**要求**：
- 工具位置：`tools/dd_restore.py`（Python，标准库 only；本机 python 可用）
- 只允许改写上述字段字节；输出前 diff 字节数必须 == 预期改动字节数（entry 8B + 每个 dir 8B），多一个字节即 FAIL
- 修正版输出到 vault evidence：`D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\R6_A1_dd_restore\layout_A\gto_unpacked.dd_restored.exe`
- 同目录产出 `dd_restore_report.json`：输入/输出 SHA-256、逐字段 old→new 表、
  与受保护参考对应头字段的对照表、改动字节计数

## 4. 绿色判据（机器可验）

1. `tools/dd_restore.py` 运行 exit 0；
2. `dd_restore_report.json` 中 `changed_byte_ranges_count` 与预期完全一致，
   且所有其他字节与输入 candidate 完全一致（工具内全量比对断言）;
3. 新增离线测试（Rust 或 Python 均可）验证：对合成 mini-PE 应用同样映射逻辑正确;
4. 不触碰 `runner_preflight.rs`、不修改 dump 管线生产代码、不执行任何样本。

## 5. 禁止

- 创建任何进程 / 执行 candidate 或参考样本（A2 另行授权）;
- 修改 R5-R2/R5-R3 冻结语义与 Oreans 门相关文件;
- 就地修改 vault 内任何已封存文件;
- 把本工具结果写成 acceptance 证据——它只是 A2 的前置假设检验物料。

## 6. 交付物清单

- `tools/dd_restore.py`
- `docs/GTO_R6_A1_DD_RESTORE_REPORT.md`（含 report JSON 全文引用）
- vault 内修正版 PE + `dd_restore_report.json`
- 测试与其绿色输出记录
