# AUDIT — Evidence 最终 HEAD 重绑定（Batch 26 / WO-2602）

**审计运行日期**：2026-08-23
**绑定 HEAD**：`639eee362d69c1cbb3fc0852438bb6e461d506c9`（Batch 25 最终树）
**前版**：evidence_*_2503.txt 绑定 `62ed608`（Batch 24 树，WO-2503）；现按 WO-2602 重生成
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定说明（多棵树证据分层）

- **Batch 24 code tree evidence = 62ed608**：`evidence_*_2503.txt`（WO-2503 交付），保留并标注旧树。
- **Batch 25 code tree evidence = 639eee3**：本文件证据（`evidence_*_2602.txt`）。
- 生产代码（crates/）自 62ed608 起**零修改**；Batch 25 的 8 个 unique paths 全部为
  docs/ 或 docs/fixtures/。

## 2. Batch 25 范围（git 实测）

- `62ed608..639eee3`：**5 commits、8 unique paths、+465/-8**（git diff --stat，见
  evidence_stat_2602.txt）。
- commits：2b3e680 → 5d50963 → 12bf21e → 1da43df → 639eee3

## 3. 证据文件清单（绑定 639eee3）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2602.txt | 113B | 2707D48E50938681C3632EF13D9CBD48B7C81FE865D02EE9692F19B9106C9E91 | git rev-parse HEAD | 0 |
| D:\Temp\evidence_test_2602.txt | 9307B | DE77BDA583C0792C49BF274E7DE95A9BE283897562EBC707E280D162015E088E | cargo test -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_2602.txt | 394B | 4B307DCE327530AC680178F6B8A940751CF3F3812C672DB1BBB03E1B69C5B679 | cargo check -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_pkg_2602.txt | 2836B | 2EF4C64994868DC922972C4F9CFAE268F10C22343579BED8936452B8DB7483A3 | cargo check -p mida-cli --offline | 0 |
| D:\Temp\evidence_diffcheck_2602.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check 62ed608..639eee3 | 0 |
| D:\Temp\evidence_worktree_2602.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check 639eee3（工作树） | 0 |
| D:\Temp\evidence_stat_2602.txt | 624B | F7CDEB5865EEED1AB314DDA023D857A68E90D03EE587B98DE83FD54E899EAE91 | git diff --stat 62ed608..639eee3 | 0 |

**生成时间**：2026-08-23（worker 机器）。

## 4. Batch 26 本机/离线测试证据（D:\Temp）

| 文件 | SHA-256 | 说明 |
|------|---------|------|
| thunk7_final_test.c | 1196A360AD1143056BACDE2527B9DABC562224D8B57003FF2895D4225DDF23BE | 三项检查 C 驱动（ThunkArgs7Probe 0x50 + sentinel） |
| thunk7_final_full.asm | 94552912E0C2DBEBCAC87A2C63C6D87EAFFFD8247EBEDF24630D3A2244A72894 | thunk+entry-stub 汇编 |
| thunk7_threecheck_stdout.txt | 5D84C68F7B9ADA3A717BDF47339B0E4C69A63CCE3720DFB8094141511551383F | THREE-CHECK PASS EXIT=0（sentinel 证明） |
| thunk7_final_full.obj | 9D76E5E0D0A66924987DE47CC5995417112BA60076F9AC21951966C8A3629B30 | ml64 产物（.text$mn rawptr=140 rawsize=127） |

**字节闭环**：production 60B SHA `9B6F4A7A138B3C4C5523CEDD047745C96AA83CA01614BEB703E4994DA2E1F017`
（== fixture THUNK7_CODE SHA，call@0x35）；test 64B SHA `01DC2017D8825EFD7E1C3FBE186C2FACF36FB22F2338C493C422E659476E17AE`
（probe@0x35，call@0x39）。

## 5. 分层登记

| 层 | 状态 |
|----|------|
| worker stdout（cargo test/check/diffcheck/stat） | 本文件证据（可复核 hash） |
| 本机 thunk ABI 验证 | thunk7_threecheck 系列（LOCAL，非远程） |
| ASan hostile | hostile_asan_detail.txt（16/16 逐用例） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 6. 验收门自检

| 门 | 结果 |
|----|------|
| manifest 绑定 639eee3 | ✅ head 证据 = 639eee3 |
| 5 commits / 8 unique paths / +465/-8 | ✅ git 实测（evidence_stat_2602.txt） |
| 62ed608..639eee3 与 639eee3 工作树 diffcheck 分开登记 | ✅ 两文件独立 |
| 旧树证据保留并标注 | ✅ evidence_*_2503.txt（62ed608）保留 |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---
（WO-2602 交付，绑定 639eee3）
## 7. 提交后绑定补充（Batch 26 交付提交）

- Batch 26 交付提交：`97d6914`（docs(gto): WO-2601 thunk7 probe layout closure +
  WO-2602/2603/2604/2605 final-head audits + WO-2606 stale-claim scrub），
  7 文件 +393/-8。
- 生产代码（crates/）自 `639eee3` 起**零修改**（本提交仅 docs/fixtures），
  因此 test/check/diffcheck 证据（绑定 639eee3 树）对提交后树仍然有效。
- 提交后 HEAD：`97d6914d53c3743c48576193252484f342231584`。
- 提交后 `git diff --check 639eee3..97d6914`：EXIT=0（无 whitespace 错误）。

---
（WO-2602 补充，提交后绑定 97d6914 / 证据树 639eee3）


---

# WO-2702 补充 — 最终 HEAD 证据重绑定（928047f）

**审计运行日期**：2026-08-23（worker 机器）
**最终绑定 HEAD**：`928047face61cc343137938d5e5610c05a73a8a1`（`928047f`，Batch 26 补充提交后）
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定关系（多棵树分层）

| 树 | 绑定 | 证据文件 | 状态 |
|----|------|---------|------|
| Batch 24 最终树 | `62ed608` | evidence_*_2503.txt | 旧树，保留并标注 |
| Batch 25 最终树 | `639eee3` | evidence_*_2602.txt | 旧树，保留并标注 |
| Batch 26 主交付 | `97d6914` | （上节 WO-2602 补充） | 旧提交，保留并标注 |
| **Batch 27 最终树** | `928047f` | **evidence_*_2702.txt（本文件）** | **当前有效** |

- 生产代码（crates/）自 `62ed608` 起**零修改**；Batch 26 范围（639eee3..928047f）
  7 个 unique paths 全部为 docs/ 或 docs/fixtures/。

## 2. Batch 26 最终范围（git 实测，928047f）

- `639eee3..928047f`：**2 commits、7 unique paths、+405/-8**（git diff --stat，
  见 evidence_stat_2702.txt / evidence_stat_2702_summary.txt）。
- commits：`97d6914`（主交付 7 文件 +393/-8）→ `928047f`（补充 +13/-1）。
- 补充提交净增：+13/-1 = **+12**（WO-2602 post-commit binding supplement）。

## 3. 最终 HEAD 证据文件清单（绑定 928047f）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2702.txt | 42B | 4164FFCB489AA024C6B440CEE155F61DEAA6588C1B359CD003E918B5AC241F49 | git rev-parse HEAD | 0 |
| D:\Temp\evidence_range_2702.txt | 219B | 67FF065DA94298538E72D4190FF1D875BD5BB9405E69CF8861E7EC8597A9F924 | git log 639eee3..928047f | 0 |
| D:\Temp\evidence_stat_2702.txt | 348B | E426689B966E6163B820D7822640B16D6811F1DF7A55F834F436877886859342 | git diff --numstat 639eee3..928047f | 0 |
| D:\Temp\evidence_stat_2702_summary.txt | 552B | 83A1A9695731B8443FE0FBE6AD1AAD37A63F062AFD4A9C0AC869A323F5D78AA9 | git diff --stat 639eee3..928047f | 0 |
| D:\Temp\evidence_names_2702.txt | 314B | 77A8CEECF93F5B2323E8B2B0942C51C492A66D0BBF4FFB8BEE3AA590524BB37E | git diff --name-only 639eee3..928047f | 0 |
| D:\Temp\evidence_diffcheck_2702.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 639eee3..928047f | 0 |
| D:\Temp\evidence_worktree_2702.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 928047f（工作树） | 0 |
| D:\Temp\evidence_supplement_2702.txt | 145B | 54D0F10068397C96055F11CF0892439B7F25639724DA29D0EC55F8C405A24A7A | git show 928047f --numstat | 0 |
| D:\Temp\evidence_exactbyte_2702.txt | 1049B | 43E65528709D40C37E4C04B93C5ED92F76F3F1B94C6351B0B7BDA676607EBA83 | exact-byte 提取证明（WO-2701 公式，prod 60B/test 64B 切片 + SHA） | 0 |
| D:\Temp\evidence_test_2702.txt | 8756B | 9CADAD6C9E053E42610D1548E375751FBD04D505C7502E0C09E4FBE73813FA4C | cargo test -p mida-antidebug-runtime --offline（928047f 树） | 0 |
| D:\Temp\evidence_check_2702.txt | 73B | 3A094CCA6611A3BD9593D2DB21DBB4930947CF2DC732E8991DBE1A08EE0399EC | cargo check -p mida-antidebug-runtime --offline（928047f 树） | 0 |
| D:\Temp\evidence_check_pkg_2702.txt | 588B | DF0A62BABF258C205D01CFD0D6605547CB2FD7422EEB22AD6616AFC57C68B54D | cargo check -p mida-cli --offline（928047f 树） | 0 |

**范围统计实测**：

```
 docs/AUDIT_EVIDENCE_BATCH24_20260823.md          |  11 ++-
 docs/AUDIT_EVIDENCE_BATCH25_20260823.md          |  82 ++++++++++++++++++
 docs/AUDIT_PROTOCOL_CALLERS_BATCH25.md           |  75 +++++++++++++++++
 docs/AUDIT_SCHEMA_ACCEPTANCE_BATCH25_20260823.md |  83 ++++++++++++++++++
 docs/AUDIT_V2_ARITHMETIC_BATCH25_20260823.md     |  51 ++++++++++++
 docs/WO-2601-thunk7-probe-closure_20260823.md    | 102 ++++++++++++++++++++++++
 docs/fixtures/WO-2501-thunk7-runtime-contract.h  |   9 +-
 7 files changed, 405 insertions(+), 8 deletions(-)
```

## 4. WO-2701 全部 source/stdout/obj/hash（绑定 928047f 树）

| 文件 | SHA-256 | 说明 |
|------|---------|------|
| thunk7_final_test.c | 1196A360AD1143056BACDE2527B9DABC562224D8B57003FF2895D4225DDF23BE | 三项检查 C 驱动（ThunkArgs7Probe 0x50 + sentinel） |
| thunk7_final_full.asm | 94552912E0C2DBEBCAC87A2C63C6D87EAFFFD8247EBEDF24630D3A2244A72894 | thunk+entry-stub 汇编 |
| thunk7_threecheck_stdout.txt | 5D84C68F7B9ADA3A717BDF47339B0E4C69A63CCE3720DFB8094141511551383F | THREE-CHECK PASS EXIT=0（sentinel 证明） |
| thunk7_final_full.obj | 9D76E5E0D0A66924987DE47CC5995417112BA60076F9AC21951966C8A3629B30 | ml64 产物（.text$mn rawptr=140 rawsize=127） |

**exact-byte 闭环（WO-2701 修正后公式，evidence_exactbyte_2702.txt 实测）**：
- production = obj[0x00..0x35) || obj[0x39..0x40) = 53B + 7B = **60B**
  SHA `9B6F4A7A138B3C4C5523CEDD047745C96AA83CA01614BEB703E4994DA2E1F017`
  == fixture THUNK7_CODE SHA（PROD == FIXTURE: True）。
- test = obj[0x00..0x40) = **64B**
  SHA `01DC2017D8825EFD7E1C3FBE186C2FACF36FB22F2338C493C422E659476E17AE`
  （probe @0x35..0x38、call @0x39）。

## 5. 分层登记（更新）

| 层 | 状态 |
|----|------|
| worker stdout（cargo test/check/diffcheck/stat） | 本文件证据（可复核 hash） |
| 本机 thunk ABI 验证 | thunk7_threecheck 系列（LOCAL，非远程） |
| ASan hostile | hostile_asan_detail.txt（16/16 逐用例） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 6. 验收门自检（更新）

| 门 | 结果 |
|----|------|
| manifest 绑定 928047f | ✅ head 证据 = 928047face61cc343137938d5e5610c05a73a8a1 |
| 2 commits / 7 unique paths / +405/-8 | ✅ git 实测（evidence_stat_2702.txt） |
| 639eee3..928047f 与 928047f 工作树 diffcheck 分开登记 | ✅ 两文件独立 |
| 旧树证据保留并标注 | ✅ evidence_*_2503.txt（62ed608）、evidence_*_2602.txt（639eee3）、WO-2602 补充（97d6914）均保留 |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---

（WO-2702 交付，绑定 928047f / 证据树 928047f）
