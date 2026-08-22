# AUDIT — Evidence 最终 HEAD 重绑定（Batch 21 / WO-2103）

**审计运行日期**：2026-08-22（总指挥侧）
**绑定 HEAD**：`381507e51a5397f5909ee1c9f7f76c849244eb2a`（最终树）
**前版**：evidence_*_2003.txt 绑定 `5cd17a7`（旧树，WO-2003）；现按 WO-2103 重生成
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 重绑定原因

- Batch 20 最终 HEAD 为 `381507e`，而 Batch 20 交付的 evidence_*_2003 绑定 `5cd17a7`；
  之后仍有 `208f1f0`、`dd6cae3`、`381507e` 三个提交，旧证据只能证明旧 code tree。
- WO-2103 要求：以最终 HEAD=`381507e` 重新生成 head/test/check/check_pkg/diffcheck 证据，
  旧 `5cd17a7` 文件保留并显式标注旧树。

## 2. 证据文件清单（绑定 381507e）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2103.txt | 113B | 14330861B84297BB9B7F5B94990FD558F31801EEDCC110AB7F2E19431C788306 | git rev-parse HEAD | 0 |
| D:\Temp\evidence_test_2103.txt | 8770B | A293E13A155BE94D8A6A12440349A2F324701920CFA8507A6E743791FB687F55 | cargo test -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_2103.txt | 394B | A07CD7D3873FC00B141D9B1AC8453E16445ADEA0015114ACC994C813DCA07A63 | cargo check -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_pkg_2103.txt | 2836B | 75BF34ED8C3FCC21C279F1FF2DFEF9034D8AB7D48BF8A142A4A3BEB02852D84F | cargo check -p mida-cli --offline | 0 |
| D:\Temp\evidence_diffcheck_2103.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check f39d1df..381507e | 0 |

**生成时间**：2026-08-23T03:14:49+08:00（worker 机器；temporal-mismatch：相对审计运行日
2026-08-22 为未来日期，不得声称 commander 生成/验证）。

## 3. 每项独立重算说明

1. **head**：`git rev-parse HEAD` = `381507e51a5397f5909ee1c9f7f76c849244eb2a`，
   与提交信息 "docs(gto): WO-2005 protocol caller audit final-tree correction (P1)" 一致。
2. **test**：`cargo test -p mida-antidebug-runtime --offline` 全量输出（116 测试全绿：
   40+34+15+27），末尾 EXIT=0。
3. **check**：`cargo check -p mida-antidebug-runtime --offline`，Finished 无警告，EXIT=0。
4. **check_pkg**：`cargo check -p mida-cli --offline`（含 runtime_loader 依赖链），EXIT=0。
5. **diffcheck**：`git diff --check f39d1df..381507e` 输出仅 "EXIT=0"（无 whitespace 错误），
   文件 8B = "EXIT=0" + 换行。

## 4. 旧树证据保留声明

- `D:\Temp\evidence_head_2003.txt` / `evidence_test_2003.txt` / `evidence_check_2003.txt` /
  `evidence_check_pkg_2003.txt` / `evidence_diffcheck_2003.txt` 仍保留在 D:\Temp，
  显式标注为 **旧树（5cd17a7）证据**，不参与最终树结论。
- 本文件与 evidence_*_2103.txt 是 Batch 20 最终树（381507e）的唯一证据来源。

## 5. 三层分离

| 层 | 状态 |
|----|------|
| worker evidence | 本文件（2026-08-23 生成，哈希/字节/命令/退出码可复核） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断 os error 183；不升级 PASS） |
| Windows/live evidence | **absent**（无实弹；LIVE-4 NOT AUTHORIZED） |

## 6. 验收门自检

| 门 | 结果 |
|----|------|
| manifest 绑定 381507e | ✅ head 证据 = 381507e |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 旧树 diffcheck 不冒充最终树 | ✅ 旧 2003 文件标注旧树，2103 为最终树 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---
（WO-2103 交付，绑定 381507e）
## 7. 提交后绑定补充（Batch 21 交付提交）

- Batch 21 交付提交：`301ac70`（docs(gto): WO-2101 TLS ABI single-source + WO-2102 V2 envelope contract (P0)），
  9 文件 +590/-65。
- 生产代码（crates/）自 `381507e` 起**零修改**（本提交仅 docs/fixtures），
  因此 test/check/diffcheck 证据（绑定 381507e 树）对提交后树仍然有效。
- 提交后 `git diff --check 381507e..301ac70`：EXIT=0（无 whitespace 错误）。
- 提交后 HEAD：`301ac70df8af9ac60937ce8d1ca12f2040158838`。

---
（WO-2103 补充，提交后绑定 301ac70 / 证据树 381507e）