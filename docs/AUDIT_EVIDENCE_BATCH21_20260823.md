# AUDIT — Evidence 最终 HEAD 重绑定（Batch 22 / WO-2203）

**审计运行日期**：2026-08-22（总指挥侧）
**绑定 HEAD**：`cce7e235d9f93c4ce76b323994cabfcd79b15e95`（Batch 21 最终树）
**前版**：evidence_*_2103.txt 绑定 `381507e`（Batch 20 树，WO-2103）；现按 WO-2203 重生成
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定说明（区分两棵树的证据）

- **Batch 20 code tree evidence = 381507e**：`evidence_*_2103.txt`（WO-2103 交付）
  证明 381507e 树的 116 测试/check/diffcheck。
- **Batch 21 final documentation HEAD = cce7e23**：本文件证据（`evidence_*_2203.txt`）
  绑定 cce7e23，并登记 301ac70/cce7e23 两个提交的 diffcheck。
- 生产代码（crates/）自 381507e 起**零修改**；Batch 21 的 9 个 unique paths 全部为
  docs/ 或 docs/fixtures/。

## 2. Batch 21 范围口径修正

- `381507e..cce7e23` 实际 **2 commits、9 unique files**、+601/-65（git diff --name-only 实测）。
- 前版报告"10 文件"是计数口径错误：补充提交 `cce7e23` 修改的是已有
  `AUDIT_EVIDENCE_BATCH20_20260823.md`（第 9 个 unique path），**不产生第 10 个 path**。

## 3. 证据文件清单（绑定 cce7e23）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2203.txt | 113B | B113C1C7B249316A421ABA863F92923E8D30FB87B635193B65F5A87AB48C136E | git rev-parse HEAD | 0 |
| D:\Temp\evidence_test_2203.txt | 9307B | 29E6582885780FBB4376384B26D9C636E1702B0127E37478CCB001772960578F | cargo test -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_2203.txt | 394B | 04B8E2F6223B90A3C34E8C0D2C8A0E84E7CA66D3673D0983DDBA509EF84E9D02 | cargo check -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_pkg_2203.txt | 2836B | 3A45A4828E8FD673347B926311A2CFF212BF19B61CA05033F12301BC531BBAB3 | cargo check -p mida-cli --offline | 0 |
| D:\Temp\evidence_diffcheck_2203.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check 381507e..cce7e23 | 0 |
| D:\Temp\evidence_worktree_2203.txt | 282B | 1CE977658A46B529556E519ACA141279DDEB9CD16A71950D5405E24D2F62756B | git diff --check cce7e23（工作树） | 0 |

**生成时间**：2026-08-23（worker 机器；temporal-mismatch 相对审计日 2026-08-22 为未来日期，
不得声称 commander 生成/验证）。

## 4. 分层登记

| 层 | 状态 |
|----|------|
| worker stdout（cargo test/check/diffcheck） | 本文件证据（可复核 hash） |
| fixture compiler/ASan stdout | hostile_test_2202_stdout.txt（D:\Temp，见 WO-2202） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 5. 验收门自检

| 门 | 结果 |
|----|------|
| manifest 绑定 cce7e23 | ✅ head 证据 = cce7e23 |
| 301ac70/cce7e23 两提交 diffcheck 登记 | ✅ evidence_diffcheck_2203.txt |
| 9 unique paths 口径 | ✅ git 实测 |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---
（WO-2203 交付，绑定 cce7e23）
## 6. 提交后绑定补充（Batch 22 交付提交）

- Batch 22 交付提交：`7b06cb4`（docs(gto): WO-2201 TLS stale-token + WO-2202 hostile
  fixture ASan fix + WO-2203/2204/2205 final-tree audits），8 文件 +396/-46。
- 生产代码（crates/）自 `cce7e23` 起**零修改**（本提交仅 docs/fixtures），
  因此 test/check/diffcheck 证据（绑定 cce7e23 树）对提交后树仍然有效。
- 提交后 HEAD：`7b06cb4440476ddc5329bd78eb2bc97f8054ba5a`。
- 提交后 `git diff --check cce7e23..7b06cb4`：EXIT=0（无 whitespace 错误）。

---
（WO-2203 补充，提交后绑定 7b06cb4 / 证据树 cce7e23）