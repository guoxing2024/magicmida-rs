# AUDIT — Evidence 最终 HEAD 重绑定（Batch 23 / WO-2303）

**审计运行日期**：2026-08-23
**绑定 HEAD**：`ea79518`（Batch 22 最终树）
**前版**：evidence_*_2203.txt 绑定 `cce7e23`（Batch 21 树，WO-2203）；现按 WO-2303 重生成
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定说明（区分三棵树的证据）

- **Batch 21 code tree evidence = cce7e23**：`evidence_*_2203.txt`（WO-2203 交付）。
- **Batch 22 code tree evidence = ea79518**：本文件证据（`evidence_*_2303.txt`），
  并登记 7b06cb4/ea79518 两个提交的 diffcheck。
- 生产代码（crates/）自 cce7e23 起**零修改**；Batch 22 的 8 个 unique paths 全部为
  docs/ 或 docs/fixtures/（git 实测 8）。

## 2. 证据文件清单（绑定 ea79518）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2303.txt | 113B | FFFB58B0054E5BBB80F7CA67F39636A3B06676B612982C02E1C8708A6C9A2B32 | git rev-parse HEAD | 0 |
| D:\Temp\evidence_test_2303.txt | 9308B | FD45F1BE489953EFD690B93CF9EC0A786CA661F1F4F569A497B76059EE3B1B1E | cargo test -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_2303.txt | 394B | FB809311C61F9667957656984150EF78CE72ED7E857AF5EA7BE8E35D911DDE3F | cargo check -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_pkg_2303.txt | 2836B | 1B2F3736B0CF7AE917F81547B6AF93B5B0BA7634BBB1D1CBC73B835CD75B47ED | cargo check -p mida-cli --offline | 0 |
| D:\Temp\evidence_diffcheck_2303.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check cce7e23..ea79518 | 0 |
| D:\Temp\evidence_worktree_2303.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check ea79518（工作树） | 0 |

**生成时间**：2026-08-23（worker 机器）。

## 3. hostile fixture 证据（WO-2302，D:\Temp）

| 文件 | SHA-256 | 说明 |
|------|---------|------|
| hostile_test_2202.c | 1116E13A99F14842BEE09407FA9BB18A942491FDF03DE9C17EE34E18195C08E3 | ASan hostile 测试源（13 用例） |
| hostile_test_2202_stdout.txt | 847D457C2B799001E629B38E3B9EDC1DAD3AD18AA036EEA6F6B4CA78058E0C08 | 13/13 ALL PASS EXIT=0 |
| WO-2102-v2-envelope-fixture.h | 307115674F3DC52753C5373320FD9103822ED018BD0C6F9F5349D85AB7DD0EF2 | 被测 fixture |
| WO-2301-thunk7-fixture.h | 8E33B1ED68D81C1FD602CB5A1D1641602A25D9151B56CA459AFB6699691BA596 | 7-arg thunk fixture |

## 4. 分层登记

| 层 | 状态 |
|----|------|
| worker stdout（cargo test/check/diffcheck） | 本文件证据（可复核 hash） |
| fixture compiler/ASan stdout | hostile_test_2202_stdout.txt |
| thunk 机器码验证 | ml64 + dumpbin（thunk7.obj / verify7.obj，D:\Temp） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 5. 验收门自检

| 门 | 结果 |
|----|------|
| manifest 绑定 ea79518 | ✅ head 证据 = ea79518 |
| 7b06cb4/ea79518 两提交 diffcheck 登记 | ✅ evidence_diffcheck_2303.txt |
| 8 unique paths 口径 | ✅ git 实测 |
| 旧树证据保留并标注 | ✅ evidence_*_2203.txt（cce7e23）保留 |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---
（WO-2303 交付，绑定 ea79518）
## 6. 提交后绑定补充（Batch 23 交付提交）

- Batch 23 交付提交：`0ebfff4`（docs(gto): WO-2301 thunk7 machine-code ABI verified +
  WO-2302 surface arithmetic hardening + WO-2303/2304/2305 final-tree audits），
  6 文件 +376/-28。
- 生产代码（crates/）自 `ea79518` 起**零修改**（本提交仅 docs/fixtures），
  因此 test/check/diffcheck 证据（绑定 ea79518 树）对提交后树仍然有效。
- 提交后 HEAD：`0ebfff403330fce91c69cd9cdcee21a4fb4fa4e3`。
- 提交后 `git diff --check ea79518..0ebfff4`：EXIT=0（无 whitespace 错误）。

---
（WO-2303 补充，提交后绑定 0ebfff4 / 证据树 ea79518）