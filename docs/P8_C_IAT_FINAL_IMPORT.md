# P8-C —— IAT final-import reconstruction 通用闭环及 Origin 正例

**状态:** 实现完成（P8-C 阶段）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程。

## 根因（P7-R2 暴露）

`origin_macro` 的 IAT evidence sidecar：
```
slot count: 313 = 296 Resolved + 17 ZeroTerminator
final_imports: []
blocker: "final candidate import parser failed:
          PE parse error: import descriptor array is not terminated within directory"
```

即：resolved slots 分类正确（296），但**最终候选 PE 的 import directory 结构不满足独立 parser**，
`final_imports` 无法从最终 PE 重读 → 296 个 resolved slot 无法一对一映射到 final imports
（P7-R2 的 origin 归为 iat-final-import-mapping=298）。

**确切断点**：`crates/pe/src/dumper/import_section.rs` 的 `create_import_section` 设置
import directory 的 size 为 `emitted_descriptor_count() * IMPORT_DESCRIPTOR_SIZE`，
**没有包含 descriptor 数组末尾的全 20 字节零 terminator**。而
`build_import_section_no_iat` 确实在最后一个真实 descriptor 之后附加了全零 terminator。
`parse_final_import_identities` 要求 directory 覆盖该 terminator（否则报
"import descriptor array is not terminated within directory"）。

`import_dir_size = desc_count * 20` 使 `dir_end = section_va + desc_count*20`，
parser 循环 `desc_rva + 20 <= dir_end` 在读完最后一个真实 descriptor 后无法再推进到
terminator（terminator 在 `dir_end` 之外）→ `terminated=false` → fail-closed。

## 修复

`create_import_section` 的 import directory size 增加一个 `IMPORT_DESCRIPTOR_SIZE`（20 字节），
使其覆盖全零 terminator：`(emitted_descriptor_count() + 1) * IMPORT_DESCRIPTOR_SIZE`。

这是**真实 PE emission 路径修复**（不是 sidecar 打补丁）。唯一设置 import directory 的位置就是
`import_section.rs:253`（已 grep 确认），修复后 loader 与独立 parser 对 directory 边界一致。

## 端到端验证（P8-C 要求的 negative→candidate 证明）

新增 `emission_end_to_end_parse_final_imports_reconstructs_target_set`：
```
ImportTableBuilder(4 thunks, 2 modules)
  → create_import_section（写 .import section + import directory）
  → assemble_image（完整 on-disk PE：DOS + serialize_headers + section raw data）
  → write_iat_to_output（写 Hint/Name RVA 到 IAT）
  → parse_final_import_identities(image)
  → reconstructed set == builder target set（module+function 逐项一致，4 slot 无幻影）
```
验证：从 0 → target set → resolved slots → final imports → 从 final PE 重读 final imports **完全一致**。

## 侧车不依赖 runtime

`iat_evidence.rs` 的 `final_imports` 由 `parse_final_import_identities(&candidate_bytes)` 从
**最终候选 PE 字节**独立重读产生（`iat_evidence.rs:99`），不依赖 runtime 内存；runtime 阶段只把
`iat_report`（resolved/terminator slots）和 candidate 落盘。修复 emission 后，该重读从空变为成功，
侧车 `iat_report/resolved → final_imports` 现可重算。

## 测试

- `import_directory_size_covers_null_terminator_descriptor`：import directory size 必须含
  terminator（`(desc_count+1)*20`），且 section data 在 `desc_count*20` 处确有全零 terminator。
- `emission_end_to_end_parse_final_imports_reconstructs_target_set`：完整 emission → parse 闭环。

## 明确 pin

- resolved slot → final import 的**一对一映射验证**是 gate 层职责（P8-QA），本阶段已使
  final_imports 非空、可重读，为映射验证提供正确输入。
- Behavior Oracle / isolated replay 10/10 / 最终验收仍不属本批修复，v8 gate 可保持 open。
