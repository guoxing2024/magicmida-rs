# P8-F —— Section rebuild 生产契约闭环

**状态:** 实现完成（P8-F 阶段）
**范围:** 纯离线工程。未访问 D:/MidaVault、未打开/启动任何真实样品、未创建任何样品进程。

## P7-R2 暴露的 section failures 与根因

`origin_macro` 18 / `lunlun_software` 17 section failures，唯一模式：
1. **duplicate section name '.rdata' / '.data'**：pure rebuild 用 host PE 的原始 section 名
   （`pure_rebuild_adapter.rs` 的 `plan_from_host_dump` 用 `sec.name.clone()`），Themida 受保护样本
   有多个 `.rdata` / `.data` section → rebuild 后保留重名。gate 拒绝 duplicate name。
2. **absent directory 0/4/6/7/8/10/11/13/14/15 has non-canonical coverage**：
   producer 对 rva=0,size=0 的 absent directory 算 `in_image=true`（`0 <= size_of_image`），
   gate 的 recompute 公式同样，但 gate 对 absent directory 要求 in_image=false → 误报。
3. **section_rebuild_evidence_pass disagrees with recomputed result (true/false)** +
   **failed section evidence must include blockers**：producer 的 pass 判定过于宽松
   （不检查 duplicate name、absent directory coverage、SizeOfImage 精确对齐），
   sidecar 报 pass=true，gate 重算 false → 不一致。

## 修复（producer/validator 逐字段一致）

**producer（`section_rebuild_evidence.rs`）**：
- 新增 **duplicate section name** 检查 → blocker。
- 新增 **absent directory non-canonical coverage** 检查（present=false 但
  in_image/raw_backed/security_file_offset 被设置 → blocker）。
- 新增 **SizeOfImage == align_up(max_virtual_end, section_alignment)** 精确检查
  （gate 用 align_up，producer 原来只检查整除）。
- directory 循环对齐 gate：present + size==0 → "zero size"；security(index 4) → file-backed 检查；
  present 非 security → "not in a raw-backed section"。
- **in_image / raw_backed 修复**：absent（rva=0）→ in_image=false / raw_backed=false，
  不再把 absent directory 误标为 in_image。

**gate（`oreans_gate.rs`）**：
- `in_image` recompute 公式加 `directory.rva != 0` 条件，与 producer 一致
  （absent directory → in_image=false，不误报 "not recomputed" / "absent non-canonical"）。

修复后：producer 的 `section_rebuild_evidence_pass` 与 gate 的 `computed_pass` 逐字段一致
（都检查 duplicate、absent coverage、SizeOfImage 对齐、alignment、overlay 等）。

## duplicate section 生产契约

duplicate section name 是 **真实的 emission 问题**（pure rebuild 保留 host 重名 section）。
P8-F 的核心是 producer **如实报告**（blocker），与 gate 一致 fail-closed，不掩盖问题。
这保证"生产契约闭环"：候选的 section 表若违反唯一性契约，producer 与 validator 都拒绝。
（去重 section 名属于 emission 优化，本阶段不修改 section 名以免影响 loader 目录绑定。）

## 测试

- **mida-cli（P8-F，`section_rebuild_evidence.rs`）**
  - `duplicate_section_names_fail_closed`：两个 `.rdata` → producer blocker 含 duplicate name。
  - `absent_directories_are_canonical_when_zero`：全部 absent(rva=0) directory 不误报，
    正常 PE pass。
  - 现有 3 个测试（round-trip、unknown fields、alias）通过。
- mida-pe + mida-cli + mida-acceptance 全部通过（无回归）。

## 明确 pin

- behavior oracle / isolated replay 10/10 / 最终验收仍不属本批。
- 真实样品的最终重跑验证在 P8-QA（有授权时）。duplicate section emission 去重留待后续
  （若需候选通过而非仅如实 fail-closed）。
