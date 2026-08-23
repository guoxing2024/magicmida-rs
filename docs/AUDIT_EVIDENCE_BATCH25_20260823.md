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
| Batch 27 最终树 | `928047f` | evidence_*_2702.txt | 旧树，保留并标注（WO-2702） |

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


---

# WO-2801 补充 — 最终 HEAD 证据重绑定（dea085b）

**审计运行日期**：2026-08-23（worker 机器）
**最终绑定 HEAD**：`dea085b62a179535ff73194c036d7ea0bfcb70bb`（`dea085b`，Batch 27 交付提交后）
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定关系（多棵树分层，更新）

| 树 | 绑定 | 证据文件 | 状态 |
|----|------|---------|------|
| Batch 24 最终树 | `62ed608` | evidence_*_2503.txt | 旧树，保留并标注 |
| Batch 25 最终树 | `639eee3` | evidence_*_2602.txt | 旧树，保留并标注 |
| Batch 26 主交付 | `97d6914` | （WO-2602 补充） | 旧提交，保留并标注 |
| Batch 26 补充后 | `928047f` | evidence_*_2702.txt | 旧树，保留并标注（WO-2702） |
| Batch 28 最终树 | `dea085b` | evidence_*_2801.txt | 当时有效（WO-2801 交付时）；现为旧树，保留并标注（WO-2901 起当前有效 = 9589fd1） |

- 生产代码（crates/）自 `62ed608` 起**零修改**；Batch 27 范围（928047f..dea085b）
  7 个 unique paths 全部为 docs/ 或 docs/fixtures/。

## 2. Batch 27 最终范围（git 实测，dea085b）

- `928047f..dea085b`：**1 commit、7 unique paths、+191/-40**（git diff --stat，
  见 evidence_stat_2801.txt / evidence_stat_2801_summary.txt）。
- commit：`dea085b`（Batch 27 交付，docs/fixtures only）。
- crates/ diff lines = 0（生产代码零修改）。

## 3. 最终 HEAD 证据文件清单（绑定 dea085b）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2801.txt | 42B | 517748F80A86655E5A7DED42F1BAA4B0F50BF67BF1093CD68104F5A4286B41A7 | git rev-parse HEAD | 0 |
| D:\Temp\evidence_range_2801.txt | 208B | 9B197226085413EB5B2D28D62E1B78C9E936D0D075ADC22C6AD445B4817795EC | git log 928047f..dea085b | 0 |
| D:\Temp\evidence_stat_2801.txt | 339B | 8EC0899B3C1A1BE882E3E1DB45D1985619A47522F835A085D795728D5C332824 | git diff --numstat 928047f..dea085b | 0 |
| D:\Temp\evidence_stat_2801_summary.txt | 513B | 51DE6DF325559E0180F187BE0E59ED1FE21BD985179BF1BD0CAC1792A35B6389 | git diff --stat 928047f..dea085b | 0 |
| D:\Temp\evidence_names_2801.txt | 305B | 36112E48D875BDCB65EA982F09D70101BB7C395595EA31E68F1B83CAFA1B2340 | git diff --name-only 928047f..dea085b | 0 |
| D:\Temp\evidence_diffcheck_2801.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 928047f..dea085b | 0 |
| D:\Temp\evidence_worktree_2801.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check dea085b（工作树） | 0 |
| D:\Temp\evidence_workspace_2801.txt | 1232B | AF5FB3E4258E44541C94EF8BC958249F4AB5519B48D27C6CBFE1461E44245066 | git status --porcelain（commander 未跟踪文件与 tracked tree 区分） | 0 |
| D:\Temp\evidence_test_2801.txt | — | 7F9C854950469E1A077C6AB62E95AC8780F751AA63731AF3E7F490BF81616DFD | cargo test -p mida-antidebug-runtime --offline（dea085b 树） | 0 |
| D:\Temp\evidence_check_2801.txt | — | 77EF1ACE51FE60885FAAB87E6E90DAB26C9CB01755E1B739A33D66FFB8C77E1E | cargo check -p mida-antidebug-runtime --offline（dea085b 树） | 0 |
| D:\Temp\evidence_check_pkg_2801.txt | — | 913E578BF70C96F16C5585042E95C9581B92E8E4FFAC5D44419C8C3A24DDF07D | cargo check -p mida-cli --offline（dea085b 树） | 0 |

**范围统计实测**：

```
 docs/AUDIT_EVIDENCE_BATCH24_20260823.md          |  45 +++++-----
 docs/AUDIT_EVIDENCE_BATCH25_20260823.md          | 102 ++++++++++++++++++++++-
 docs/AUDIT_PROTOCOL_CALLERS_BATCH25.md           |   7 +-
 docs/AUDIT_SCHEMA_ACCEPTANCE_BATCH25_20260823.md |   7 +-
 docs/AUDIT_V2_ARITHMETIC_BATCH25_20260823.md     |   7 +-
 docs/WO-2601-thunk7-probe-closure_20260823.md    |  36 ++++++--
 docs/fixtures/WO-2301-thunk7-fixture.h           |  27 +++++-
 7 files changed, 191 insertions(+), 40 deletions(-)
```

## 4. workspace 状态说明

- tracked tree：dea085b 干净（git diff --check dea085b EXIT=0）。
- untracked：commander 审计文件（WORK_ORDERS_BATCH_*.md、docs/AUDIT_BATCH*.md）
  保持未跟踪状态，属 commander 工作区，不纳入本次证据树。

## 5. WO-2802 全部 source/stdout/obj/hash（绑定 dea085b 树）

| 文件 | SHA-256 | 说明 |
|------|---------|------|
| thunk7_final_test.c | 1196A360AD1143056BACDE2527B9DABC562224D8B57003FF2895D4225DDF23BE | 三项检查 C 驱动（ThunkArgs7Probe 0x50 + sentinel） |
| thunk7_final_full.asm | 94552912E0C2DBEBCAC87A2C63C6D87EAFFFD8247EBEDF24630D3A2244A72894 | thunk+entry-stub 汇编 |
| thunk7_threecheck_stdout.txt | 5D84C68F7B9ADA3A717BDF47339B0E4C69A63CCE3720DFB8094141511551383F | THREE-CHECK PASS EXIT=0（sentinel 证明） |
| thunk7_final_full.obj | 9D76E5E0D0A66924987DE47CC5995417112BA60076F9AC21951966C8A3629B30 | ml64 产物（.text$mn rawptr=140 rawsize=127） |

**exact-byte 闭环（WO-2802 修正后，evidence_exactbyte_2702.txt 实测）**：
- production = obj[0x00..0x35) || obj[0x39..0x40) = 53B + 7B = **60B**
  （非连续 production slices，非前 60B 连续字节）
  SHA `9B6F4A7A138B3C4C5523CEDD047745C96AA83CA01614BEB703E4994DA2E1F017`
  == fixture THUNK7_CODE SHA（PROD == FIXTURE: True）。
- test = obj[0x00..0x40) = **64B**
  SHA `01DC2017D8825EFD7E1C3FBE186C2FACF36FB22F2338C493C422E659476E17AE`
  （probe @0x35..0x38、call @0x39）。

**双流偏移分离**：

| 指令 | production（60B） | test（64B） |
|------|-------------------|-------------|
| call rax | 0x35（FF D0） | 0x39（FF D0） |
| add rsp,0x38 | 0x37 | 0x3B |
| ret | 0x3B | 0x3F |
| probe（49 89 63 48） | —（不包含） | 0x35..0x38 |

## 6. 分层登记（更新）

| 层 | 状态 |
|----|------|
| worker stdout（cargo test/check/diffcheck/stat） | 本文件证据（可复核 hash） |
| 本机 thunk ABI 验证 | thunk7_threecheck 系列（LOCAL，非远程） |
| ASan hostile | hostile_asan_detail.txt（16/16 逐用例） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 7. 验收门自检（更新）

| 门 | 结果 |
|----|------|
| manifest 绑定 dea085b | ✅ head 证据 = dea085b62a179535ff73194c036d7ea0bfcb70bb |
| 1 commit / 7 unique paths / +191/-40 | ✅ git 实测（evidence_stat_2801.txt） |
| 928047f..dea085b 与 dea085b 工作树 diffcheck 分开登记 | ✅ 两文件独立 |
| 旧树证据保留并标注 | ✅ 62ed608/639eee3/97d6914/928047f 全部保留并标注旧树 |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---

（WO-2801 交付，绑定 dea085b / 证据树 dea085b）


---

# WO-2901 补充 — 最终 HEAD 证据重绑定（9589fd1）

**审计运行日期**：2026-08-23（worker 机器）
**最终绑定 HEAD**：`9589fd13f8e45e7612b212335bcae4c0b1ede23e`（`9589fd1`，Batch 28 交付提交后）
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定关系（多棵树分层，更新）

| 树 | 绑定 | 证据文件 | 状态 |
|----|------|---------|------|
| Batch 24 最终树 | `62ed608` | evidence_*_2503.txt | 旧树，保留并标注 |
| Batch 25 最终树 | `639eee3` | evidence_*_2602.txt | 旧树，保留并标注 |
| Batch 26 主交付 | `97d6914` | （WO-2602 补充） | 旧提交，保留并标注 |
| Batch 26 补充后 | `928047f` | evidence_*_2702.txt | 旧树，保留并标注（WO-2702） |
| Batch 27 交付后 | `dea085b` | evidence_*_2801.txt | 旧树，保留并标注（WO-2801） |
| Batch 29 最终树 | `9589fd1` | evidence_*_2901.txt | 当时有效（WO-2901 交付时）；现为旧树 + 旧 dirty-workspace 证据，保留并标注（WO-3001 起当前有效 = ecd77ae） |

- 生产代码（crates/）自 `62ed608` 起**零修改**；Batch 28 范围（dea085b..9589fd1）
  6 个 unique paths 全部为 docs/ 或 docs/fixtures/。

## 2. Batch 28 最终范围（git 实测，9589fd1）

- `dea085b..9589fd1`：**1 commit、6 unique paths、+154/-19**（git diff --stat，
  见 evidence_stat_2901.txt / evidence_stat_2901_summary.txt）。
- commit：`9589fd1`（Batch 28 交付，docs/fixtures only）。
- crates/ diff lines = 0（生产代码零修改）。

## 3. 最终 HEAD 证据文件清单（绑定 9589fd1）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2901.txt | 42B | 60869B138D5512E4B1E93CBD2A7A60F35B496564272E5F520A831AA486527EC4 | git rev-parse HEAD | 0 |
| D:\Temp\evidence_range_2901.txt | 194B | 60C977A964025957FACC3F201F6261FEE51F231414F986CA30DE5134460DBC8E | git log dea085b..9589fd1 | 0 |
| D:\Temp\evidence_stat_2901.txt | 291B | 39594581A208245AC10E2CDEDC1DAD34732C9EB97B13E20F17F44DB127DE0EDB | git diff --numstat dea085b..9589fd1 | 0 |
| D:\Temp\evidence_stat_2901_summary.txt | 439B | 29B276099EB801B05049499BBA8785B13FB3794B4FAA20EF7801AF7C33B1C1E7 | git diff --stat dea085b..9589fd1 | 0 |
| D:\Temp\evidence_names_2901.txt | 264B | CB5A96292CE9B542DE5E2671431AA5E8D101271301E0D80E8782EEEBA246BA52 | git diff --name-only dea085b..9589fd1 | 0 |
| D:\Temp\evidence_diffcheck_2901.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check dea085b..9589fd1 | 0 |
| D:\Temp\evidence_worktree_2901.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 9589fd1（工作树） | 0 |
| D:\Temp\evidence_workspace_2901.txt | 1304B | A1BFE4F06F9DD83590A05335012A22037026CFD93DF54A4608F1F6062294E83A | git status --porcelain（commander 未跟踪文件区分） | 0 |
| D:\Temp\evidence_test_2901.txt | — | 71CE67BD6DCB10FAFA664DCDBAF01A08A78C6B5E22C9763DBE549A9C34AC60F6 | cargo test -p mida-antidebug-runtime --offline（9589fd1 树） | 0 |
| D:\Temp\evidence_check_2901.txt | — | 77EF1ACE51FE60885FAAB87E6E90DAB26C9CB01755E1B739A33D66FFB8C77E1E | cargo check -p mida-antidebug-runtime --offline（9589fd1 树） | 0 |
| D:\Temp\evidence_check_pkg_2901.txt | — | AE145AFFC375E82CA5F2C514ED1A820778E79A087B081816E3B5593D03C2EA9B | cargo check -p mida-cli --offline（9589fd1 树） | 0 |

**范围统计实测**：

```
 docs/AUDIT_EVIDENCE_BATCH25_20260823.md          | 118 ++++++++++++++++++++++-
 docs/AUDIT_PROTOCOL_CALLERS_BATCH25.md           |   6 +-
 docs/AUDIT_SCHEMA_ACCEPTANCE_BATCH25_20260823.md |   6 +-
 docs/AUDIT_V2_ARITHMETIC_BATCH25_20260823.md     |   6 +-
 docs/WO-2601-thunk7-probe-closure_20260823.md    |  32 ++++--
 docs/fixtures/WO-2301-thunk7-fixture.h           |   5 +-
 6 files changed, 154 insertions(+), 19 deletions(-)
```

## 4. workspace 状态说明

- tracked tree：9589fd1 干净（git diff --check 9589fd1 EXIT=0）。
- untracked：commander 审计文件（WORK_ORDERS_BATCH_*.md、docs/AUDIT_BATCH*.md）
  保持未跟踪状态，属 commander 工作区，不纳入本次证据树。

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
| manifest 绑定 9589fd1 | ✅ head 证据 = 9589fd13f8e45e7612b212335bcae4c0b1ede23e |
| 1 commit / 6 unique paths / +154/-19 | ✅ git 实测（evidence_stat_2901.txt） |
| dea085b..9589fd1 与 9589fd1 工作树 diffcheck 分开登记 | ✅ 两文件独立 |
| 旧树证据保留并标注 | ✅ 62ed608/639eee3/97d6914/928047f/dea085b 全部保留并标注旧树 |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---

（WO-2901 交付，绑定 9589fd1 / 证据树 9589fd1）


---

# WO-3001 补充 — 最终 HEAD 证据重绑定（ecd77ae）

**审计运行日期**：2026-08-23（worker 机器，14:00-14:02 生成）
**最终绑定 HEAD**：`ecd77aee1990f23f3044f293afe7446464ac2deb`（`ecd77ae`，Batch 29 交付提交后）
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定关系（多棵树分层，更新）

| 树 | 绑定 | 证据文件 | 状态 |
|----|------|---------|------|
| Batch 24 最终树 | `62ed608` | evidence_*_2503.txt | 旧树，保留并标注 |
| Batch 25 最终树 | `639eee3` | evidence_*_2602.txt | 旧树，保留并标注 |
| Batch 26 主交付 | `97d6914` | （WO-2602 补充） | 旧提交，保留并标注 |
| Batch 26 补充后 | `928047f` | evidence_*_2702.txt | 旧树，保留并标注（WO-2702） |
| Batch 27 交付后 | `dea085b` | evidence_*_2801.txt | 旧树，保留并标注（WO-2801） |
| Batch 28 交付后 | `9589fd1` | evidence_*_2901.txt | **旧树 + 旧 dirty-workspace 证据**（WO-2901 生成时工作树含未提交 tracked 修改，见 evidence_workspace_2901.txt 首行 "M docs/WO-2601..."；仅作历史记录，不作为 ecd77ae 树 manifest） |
| Batch 30 最终树 | `ecd77ae` | evidence_*_3001.txt | 当时有效（WO-3001 交付时）；现为旧树，保留并标注（WO-3101 起当前有效 = 9d7010e） |

- 生产代码（crates/）自 `62ed608` 起**零修改**；Batch 29 范围（9589fd1..ecd77ae）
  5 个 unique paths 全部为 docs/ 或 docs/fixtures/。

## 2. Batch 29 最终范围（git 实测，ecd77ae 干净树）

- `9589fd1..ecd77ae`：**1 commit、5 unique paths、+103/-14**（git diff --stat，
  见 evidence_stat_3001.txt / evidence_stat_3001_summary.txt）。
- commit：`ecd77ae`（Batch 29 交付，docs/fixtures only）。
- crates/ diff lines = 0（生产代码零修改）。
- **tracked workspace clean 确认**：git status --porcelain 中 tracked 修改数 = 0
  （evidence_workspace_3001.txt，仅 commander untracked 文件）。

## 3. 最终 HEAD 证据文件清单（绑定 ecd77ae，干净树生成）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_3001.txt | 42B | 82E19C9C9DE2420A603C121ADBFB9AAA7AB7D76F88600677CAAFA37E3EACCA3B | git rev-parse HEAD | 0 |
| D:\Temp\evidence_range_3001.txt | 203B | 8561D49195E6A42332B8D4CC8B02CB07CC7F133EC9F82A8766C5E7C9EFCAB206 | git log 9589fd1..ecd77ae | 0 |
| D:\Temp\evidence_stat_3001.txt | 245B | BA6AB0F07D559516C0FD755A01EFDE68E810DD9CE405A88972F474ECA37EEBA3 | git diff --numstat 9589fd1..ecd77ae | 0 |
| D:\Temp\evidence_stat_3001_summary.txt | 372B | 01B30E58F2662D84E8B638910895BC6270F4162BBCD2BA641B955655A7A7D622 | git diff --stat 9589fd1..ecd77ae | 0 |
| D:\Temp\evidence_names_3001.txt | 224B | 29CE7921417EE31110EA73677D00E7A33BEA33451F4ABD7DD021D230BC8E0DC4 | git diff --name-only 9589fd1..ecd77ae | 0 |
| D:\Temp\evidence_diffcheck_3001.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 9589fd1..ecd77ae | 0 |
| D:\Temp\evidence_worktree_3001.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check ecd77ae（工作树） | 0 |
| D:\Temp\evidence_workspace_3001.txt | 1326B | 6EC308930D304A3DAD0205102E3816E2A7C5E943085703EA3BF23DDAB655E753 | git status --porcelain（tracked 修改数 = 0，仅 commander untracked） | 0 |

**范围统计实测**：

```
 docs/AUDIT_EVIDENCE_BATCH25_20260823.md          |  91 +++++++++++++++++++++++-
 docs/AUDIT_PROTOCOL_CALLERS_BATCH25.md           |   6 +-
 docs/AUDIT_SCHEMA_ACCEPTANCE_BATCH25_20260823.md |   6 +-
 docs/AUDIT_V2_ARITHMETIC_BATCH25_20260823.md     |   6 +-
 docs/WO-2601-thunk7-probe-closure_20260823.md    |   8 +--
 5 files changed, 103 insertions(+), 14 deletions(-)
```

## 4. WO-3002 workspace 全量测试证据（绑定 ecd77ae，真实原始 stdout）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_workspace_test_3001.txt | 200672B | 1A810D003380F7CAB243DA7A636D7DD49EA88DD84AF832C9541A3EFAECB04E5C | cargo test --workspace --offline（原始 stdout，2026-08-23 13:58:39 → 14:00:07，HEAD=ecd77ae） | 0 |
| D:\Temp\evidence_workspace_check_3001.txt | 514B | 4B83B9B0A86B2838F9F60909007C4FB21F48F0A3B2104CF37213E738FC459ED3 | cargo check --workspace --offline（2026-08-23 13:59:24，HEAD=ecd77ae） | 0 |

**workspace test 结果汇总（56 个 test result 行，全部 ok）**：
- 各套件 0 failed：含 243/322/1008 passed 大套件（1008 passed 用时 9.31s）
- 真实运行时长：13:58:39 → 14:00:07（88 秒）
- FAILED 行数：0

**package test/check 单独登记（分层）**：

| 文件 | SHA-256 | 命令 | 退出码 |
|------|---------|------|--------|
| D:\Temp\evidence_pkg_test_3001.txt | 7C9A19182C510E40B782AA2D763D0E2641000CA6C83B937866A49E2F06924945 | cargo test -p mida-antidebug-runtime --offline（2026-08-23 14:01:49，HEAD=ecd77ae） | 0 |
| D:\Temp\evidence_pkg_check_3001.txt | DAB4E4707B2E6FDBDEAD361B4487BE475974A047EDEA846DD92BAC44F319F872 | cargo check -p mida-antidebug-runtime --offline（2026-08-23 14:01:49） | 0 |

**pkg test 结果**：116 通过（40+34+15+27）0 failed。

**threecheck source/stdout/obj/hash 登记（local-only）**：

| 文件 | SHA-256 | 说明 |
|------|---------|------|
| thunk7_final_test.c | 1196A360AD1143056BACDE2527B9DABC562224D8B57003FF2895D4225DDF23BE | 三项检查 C 驱动 |
| thunk7_final_full.asm | 94552912E0C2DBEBCAC87A2C63C6D87EAFFFD8247EBEDF24630D3A2244A72894 | thunk+entry-stub 汇编 |
| thunk7_threecheck_stdout.txt | 5D84C68F7B9ADA3A717BDF47339B0E4C69A63CCE3720DFB8094141511551383F | THREE-CHECK PASS EXIT=0（sentinel 证明，local-only） |
| thunk7_final_full.obj | 9D76E5E0D0A66924987DE47CC5995417112BA60076F9AC21951966C8A3629B30 | ml64 产物（.text$mn rawptr=140 rawsize=127） |

## 5. 分层登记（更新）

| 层 | 状态 |
|----|------|
| worker stdout（workspace test/check/pkg test/check/diffcheck/stat） | 本文件证据（可复核 hash，真实原始 stdout） |
| 本机 thunk ABI 验证 | thunk7_threecheck 系列（LOCAL，非远程） |
| ASan hostile | hostile_asan_detail.txt（16/16 逐用例） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 6. 验收门自检（更新）

| 门 | 结果 |
|----|------|
| manifest 绑定 ecd77ae | ✅ head 证据 = ecd77aee1990f23f3044f293afe7446464ac2deb |
| 1 commit / 5 unique paths / +103/-14 | ✅ git 实测（evidence_stat_3001.txt） |
| tracked workspace clean | ✅ tracked 修改数 = 0（evidence_workspace_3001.txt） |
| workspace 全量测试原始证据 | ✅ evidence_workspace_test_3001.txt（200672B，56 行 test result 全 ok，88s 真实运行） |
| package test 与 workspace test 分层 | ✅ 两文件独立登记 |
| 旧树证据保留并标注（含 2901 dirty） | ✅ 62ed608/639eee3/97d6914/928047f/dea085b/9589fd1 全部保留；9589fd1 标注旧树 + 旧 dirty 证据 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---

（WO-3001 + WO-3002 交付，绑定 ecd77ae / 证据树 ecd77ae）


---

# WO-3001 post-commit 补充 — 最终 HEAD 证据重绑定（1e0ebeb）

**审计运行日期**：2026-08-23（worker 机器，14:03）
**最终绑定 HEAD**：`1e0ebeb9b174692035124f3729d7755c47113b26`（`1e0ebeb`，Batch 30 交付提交后）
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定关系（多棵树分层，更新）

| 树 | 绑定 | 证据文件 | 状态 |
|----|------|---------|------|
| ...（历史树同 WO-3001 章节） | | | |
| Batch 29 交付后 | `ecd77ae` | evidence_*_3001.txt | 旧树，保留并标注（WO-3001） |
| Batch 30 最终树 | `1e0ebeb` | evidence_*_3001b.txt | 当时有效（WO-3001b 交付时）；现为旧树，保留并标注（WO-3101 起当前有效 = 9d7010e） |

- 生产代码（crates/）自 `62ed608` 起**零修改**；Batch 30 范围（ecd77ae..1e0ebeb）
  5 个 unique paths 全部为 docs/ 或 docs/fixtures/。

## 2. Batch 30 最终范围（git 实测，1e0ebeb 干净树）

- `ecd77ae..1e0ebeb`：**1 commit、5 unique paths、+125/-12**（git diff --stat，
  见 evidence_stat_3001b.txt / evidence_stat_3001b_summary.txt）。
- commit：`1e0ebeb`（Batch 30 交付，docs/fixtures only）。
- crates/ diff lines = 0（生产代码零修改）。
- **tracked workspace clean 确认**：git status --porcelain 中 tracked 修改数 = 0
  （evidence_workspace_3001b.txt，仅 commander untracked 文件）。

## 3. 最终 HEAD 证据文件清单（绑定 1e0ebeb，干净树生成）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_3001b.txt | 42B | 3B8C65741A0403F99042E7883A77DC42163805021588E58583CBF3F232ED0F2D | git rev-parse HEAD | 0 |
| D:\Temp\evidence_range_3001b.txt | 204B | 9CE0AACDB53E2BB7E03096A0BE2828B3374AB9B257DBFD9CBCFC6CB848F1BAED | git log ecd77ae..1e0ebeb | 0 |
| D:\Temp\evidence_stat_3001b.txt | 246B | A69A3F91812F22C31BC556AE9792F45A32082F9B04C8A300670EB8613B37ED1A | git diff --numstat ecd77ae..1e0ebeb | 0 |
| D:\Temp\evidence_stat_3001b_summary.txt | 375B | C9359F008A6F678898E1EBAAEBF3CA75BA1F093C2E5A8D569250B8C919E8223A | git diff --stat ecd77ae..1e0ebeb | 0 |
| D:\Temp\evidence_names_3001b.txt | 224B | 29CE7921417EE31110EA73677D00E7A33BEA33451F4ABD7DD021D230BC8E0DC4 | git diff --name-only ecd77ae..1e0ebeb | 0 |
| D:\Temp\evidence_diffcheck_3001b.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check ecd77ae..1e0ebeb | 0 |
| D:\Temp\evidence_worktree_3001b.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 1e0ebeb（工作树） | 0 |
| D:\Temp\evidence_workspace_3001b.txt | 1326B | 6EC308930D304A3DAD0205102E3816E2A7C5E943085703EA3BF23DDAB655E753 | git status --porcelain（tracked 修改数 = 0） | 0 |

**范围统计实测**：

```
 docs/AUDIT_EVIDENCE_BATCH25_20260823.md          | 115 ++++++++++++++++++++++-
 docs/AUDIT_PROTOCOL_CALLERS_BATCH25.md           |   6 +-
 docs/AUDIT_SCHEMA_ACCEPTANCE_BATCH25_20260823.md |   6 +-
 docs/AUDIT_V2_ARITHMETIC_BATCH25_20260823.md     |   6 +-
 docs/WO-2601-thunk7-probe-closure_20260823.md    |   4 +-
 5 files changed, 125 insertions(+), 12 deletions(-)
```

## 4. workspace 全量测试证据（绑定 1e0ebeb 树，ecd77ae 树生成、1e0ebeb 仅 docs/fixtures 变更）

- `evidence_workspace_test_3001.txt`（200672B，SHA `1A810D003380F7CAB243DA7A636D7DD49EA88DD84AF832C9541A3EFAECB04E5C`）：
  cargo test --workspace --offline 原始 stdout，2026-08-23 13:58:39 → 14:00:07，HEAD=ecd77ae，EXIT=0。
  **crates/ 自 62ed608 起零修改**，1e0ebeb 仅 docs/fixtures，测试结论对 1e0ebeb 树仍然成立。
- `evidence_workspace_check_3001.txt`（514B，SHA `4B83B9B0A86B2838F9F60909007C4FB21F48F0A3B2104CF37213E738FC459ED3`）：
  cargo check --workspace --offline，2026-08-23 13:59:24，HEAD=ecd77ae，EXIT=0。
- package test/check（evidence_pkg_test_3001.txt / evidence_pkg_check_3001.txt）同 WO-3001 章节登记。

## 5. 验收门自检（更新）

| 门 | 结果 |
|----|------|
| manifest 绑定 1e0ebeb | ✅ head 证据 = 1e0ebeb9b174692035124f3729d7755c47113b26 |
| 1 commit / 5 unique paths / +125/-12 | ✅ git 实测（evidence_stat_3001b.txt） |
| tracked workspace clean | ✅ tracked 修改数 = 0 |
| workspace 全量测试原始证据 | ✅ evidence_workspace_test_3001.txt（真实 stdout） |
| 旧树证据保留并标注 | ✅ 62ed608/639eee3/97d6914/928047f/dea085b/9589fd1/ecd77ae 全部保留并标注旧树 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---

（WO-3001 post-commit 补充，绑定 1e0ebeb / 证据树 1e0ebeb）


---

# WO-3101 补充 — 最终 HEAD 证据重绑定（9d7010e）

**审计运行日期**：2026-08-23（worker 机器，14:22-14:24 生成）
**最终绑定 HEAD**：`9d7010e8112541167447e2aaaea109e63100cb7f`（`9d7010e`，Batch 30 最终 HEAD = post-commit binding supplement）
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定关系（多棵树分层，更新）

| 树 | 绑定 | 证据文件 | 状态 |
|----|------|---------|------|
| ...（历史树同 WO-3001/3001b 章节） | | | |
| Batch 30 主交付 | `1e0ebeb` | evidence_*_3001b.txt | 旧树，保留并标注（WO-3001 post-commit） |
| **Batch 31 最终树** | `9d7010e` | **evidence_*_3101.txt（本文件）** | **当前有效（干净树生成）** |

- 生产代码（crates/）自 `62ed608` 起**零修改**；Batch 30 完整范围（ecd77ae..9d7010e）
  = 2 commits、5 unique paths、+202/-12，全部 docs/fixtures。

## 2. Batch 30 最终范围（git 实测，9d7010e 干净树）

- `ecd77ae..1e0ebeb`：1 commit、5 paths、+125/-12（Batch 30 主交付）。
- `1e0ebeb..9d7010e`：1 commit、1 path、+77/-0（post-commit binding supplement）。
- **累计**：`ecd77ae..9d7010e` = **2 commits、5 unique paths、+202/-12**。
- crates/ diff lines = 0（生产代码零修改）。
- **tracked workspace clean 确认**：git status --porcelain 中 tracked 修改数 = 0
  （evidence_workspace_3101.txt，仅 commander untracked 文件）。

## 3. 最终 HEAD 证据文件清单（绑定 9d7010e，干净树生成）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_3101.txt | 42B | 8ACA0376C248C9FCB38F44A21A8A5E0EE8ABF5500DD18741D9AE8C736876A09C | git rev-parse HEAD | 0 |
| D:\Temp\evidence_range_3101.txt | 69B | 5F6AEBC6B330B527C17299CFD3132AD19397C285E3861C53D83687C244C5A9F9 | git log 1e0ebeb..9d7010e | 0 |
| D:\Temp\evidence_stat_3101.txt | 46B | 5AA10D4AFC711186B8F811F47DE51A2C8C8526F1E1B08BE652772B2E222265F5 | git diff --numstat 1e0ebeb..9d7010e | 0 |
| D:\Temp\evidence_stat_3101_summary.txt | 116B | 94A693AA809FA6FAC64363406B5161DBFB64F41A9C0EED87BC6EDF35C3CE5CB2 | git diff --stat 1e0ebeb..9d7010e | 0 |
| D:\Temp\evidence_names_3101.txt | 41B | DE98E2FD61B59498CE2E15C4FA49C27CB455E252B870A9C570607E93200B944B | git diff --name-only 1e0ebeb..9d7010e | 0 |
| D:\Temp\evidence_diffcheck_3101.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 1e0ebeb..9d7010e | 0 |
| D:\Temp\evidence_worktree_3101.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 9d7010e（工作树） | 0 |
| D:\Temp\evidence_workspace_3101.txt | 1326B | 6EC308930D304A3DAD0205102E3816E2A7C5E943085703EA3BF23DDAB655E753 | git status --porcelain（tracked 修改数 = 0） | 0 |

**范围统计实测（1e0ebeb..9d7010e）**：

```
 docs/AUDIT_EVIDENCE_BATCH25_20260823.md | 77 +++++++++++++++++++++++++++++++++
 1 file changed, 77 insertions(+)
```

**累计（ecd77ae..9d7010e）**：

```
 docs/AUDIT_EVIDENCE_BATCH25_20260823.md          | 192 ++++++++++++++++++++++-
 docs/AUDIT_PROTOCOL_CALLERS_BATCH25.md           |   6 +-
 docs/AUDIT_SCHEMA_ACCEPTANCE_BATCH25_20260823.md |   6 +-
 docs/AUDIT_V2_ARITHMETIC_BATCH25_20260823.md     |   6 +-
 docs/WO-2601-thunk7-probe-closure_20260823.md    |   4 +-
 5 files changed, 202 insertions(+), 12 deletions(-)
```

## 4. WO-3102 workspace 全量测试证据（9d7010e 树补跑，真实原始 stdout）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_workspace_test_3101.txt | 200846B | 216C146D80EC30A921322DCE6B9C6440C0CBAB35E59D1262D21338C25A822C3A | cargo test --workspace --offline（原始 stdout，2026-08-23 14:22:41 → 14:24:22，HEAD=9d7010e） | 0 |
| D:\Temp\evidence_workspace_check_3101.txt | 673B | A903AB28A53EB549609FFDE485E007DD001E0E2304148A983EB57E18F3BEEF7A | cargo check --workspace --offline（2026-08-23 14:22:42，HEAD=9d7010e） | 0 |

**workspace test 结果汇总（56 个 test result 行，全部 ok）**：
- 各套件 0 failed：含 243/322/1008 passed 大套件（1008 passed 用时 9.33s）
- 真实运行时长：14:22:41 → 14:24:22（101 秒）
- FAILED 行数：0
- **warning 口径（如实保留，非 zero warnings）**：
  - mida-packers-themida：field `thread_id` is never read（1 warning）
  - mida-antidebug-runtime（proc_surfaces test）：unused_mut ×2（2 warnings）
  - mida-cli（lib）：unused variable `dump_timing`（1 warning）
  - 结论口径：**tests passed; existing warnings present**

**carry-forward 关系说明**：
- `evidence_workspace_test_3001.txt`（ecd77ae 树，200672B，SHA `1A810D00...`）为**旧树证据**，保留并标注。
- 本次 `evidence_workspace_test_3101.txt`（9d7010e 树，200846B，SHA `216C146D...`）为**当前树补跑**，9d7010e 仅 docs/fixtures 变更（crates/ 零修改），两树测试结论一致（0 failed）。

**package test/check 分层（9d7010e 树）**：

| 文件 | SHA-256 | 命令 | 退出码 |
|------|---------|------|--------|
| evidence_pkg_test_3001.txt | 7C9A19182C510E40B782AA2D763D0E2641000CA6C83B937866A49E2F06924945 | cargo test -p mida-antidebug-runtime --offline（ecd77ae 树，116 通过 0 failed） | 0 |
| evidence_pkg_check_3001.txt | DAB4E4707B2E6FDBDEAD361B4487BE475974A047EDEA846DD92BAC44F319F872 | cargo check -p mida-antidebug-runtime --offline | 0 |

**threecheck source/stdout/obj/hash（local-only）**：同 WO-3001 章节登记（1196A360/94552912/5D84C68F/9D76E5E0）。

## 5. 分层登记（更新）

| 层 | 状态 |
|----|------|
| worker stdout（workspace test/check 9d7010e 树 + pkg test/check） | 本文件证据（可复核 hash，真实原始 stdout） |
| 本机 thunk ABI 验证 | thunk7_threecheck 系列（LOCAL，非远程） |
| ASan hostile | hostile_asan_detail.txt（16/16 逐用例） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 6. 验收门自检（更新）

| 门 | 结果 |
|----|------|
| manifest 绑定 9d7010e | ✅ head 证据 = 9d7010e8112541167447e2aaaea109e63100cb7f |
| 2 commits / 5 unique paths / +202/-12（累计） | ✅ git 实测（evidence_stat_3101.txt + 3001 系列） |
| tracked workspace clean | ✅ tracked 修改数 = 0 |
| workspace 全量测试原始证据（9d7010e 树补跑） | ✅ evidence_workspace_test_3101.txt（200846B，56 行 test result 全 ok，101s 真实运行） |
| carry-forward 关系明确 | ✅ ecd77ae 旧 stdout 标注旧树；9d7010e 补跑为当前树 |
| warning 口径如实 | ✅ tests passed; existing warnings present（非 zero warnings） |
| 旧树证据保留并标注 | ✅ 62ed608/639eee3/97d6914/928047f/dea085b/9589fd1/ecd77ae/1e0ebeb 全部保留并标注旧树 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---

（WO-3101 + WO-3102 交付，绑定 9d7010e / 证据树 9d7010e）


---

# WO-3101 post-commit 补充 — 最终 HEAD 证据重绑定（ea1ca8d）

**审计运行日期**：2026-08-23（worker 机器，14:26）
**最终绑定 HEAD**：`ea1ca8dcd15229e111cdbb1739b66e1992205eee`（`ea1ca8d`，Batch 31 交付提交后）
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定关系（更新）

| 树 | 绑定 | 证据文件 | 状态 |
|----|------|---------|------|
| ...（历史树同 WO-3101 章节） | | | |
| Batch 31 主交付 | `9d7010e` | evidence_*_3101.txt | 旧树，保留并标注（WO-3101） |
| **Batch 31 最终树** | `ea1ca8d` | **evidence_*_3101b.txt（本文件）** | **当前有效（干净树生成）** |

## 2. Batch 31 最终范围（git 实测，ea1ca8d 干净树）

- `9d7010e..ea1ca8d`：**1 commit、5 unique paths、+130/-13**（git diff --stat，
  见 evidence_stat_3101b.txt / evidence_stat_3101b_summary.txt）。
- crates/ diff lines = 0（生产代码零修改）。
- **tracked workspace clean 确认**：tracked 修改数 = 0（evidence_workspace_3101b.txt）。

## 3. 最终 HEAD 证据文件清单（绑定 ea1ca8d，干净树生成）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_3101b.txt | 42B | ADAB6A57722443CF5739C27BADD3ED71252F54A2F214AEF3CA1454F016F79E50 | git rev-parse HEAD | 0 |
| D:\Temp\evidence_range_3101b.txt | 210B | B5D552AE82700392FA9E3B8503097018E1D5728DBCC98C510D7B8A8942DAE20F | git log 9d7010e..ea1ca8d | 0 |
| D:\Temp\evidence_stat_3101b.txt | 246B | 5CDDD2C12112F6072216785EEE28EAFC510ACE6BF7C4289C5B452FE8D41247B1 | git diff --numstat 9d7010e..ea1ca8d | 0 |
| D:\Temp\evidence_stat_3101b_summary.txt | 375B | E114E25121AC462EFA899CC7B48E1AFF579CE581FCDE8ECB4C2E3BF8E6D0DB44 | git diff --stat 9d7010e..ea1ca8d | 0 |
| D:\Temp\evidence_names_3101b.txt | 224B | 29CE7921417EE31110EA73677D00E7A33BEA33451F4ABD7DD021D230BC8E0DC4 | git diff --name-only 9d7010e..ea1ca8d | 0 |
| D:\Temp\evidence_diffcheck_3101b.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check 9d7010e..ea1ca8d | 0 |
| D:\Temp\evidence_worktree_3101b.txt | 0B | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check ea1ca8d（工作树） | 0 |
| D:\Temp\evidence_workspace_3101b.txt | 1398B | EEBABDE879EA102B2020249A961188869C19021BC25290BD6D252F9F6C49FFB6 | git status --porcelain（tracked 修改数 = 0） | 0 |

**范围统计实测**：

```
 docs/AUDIT_EVIDENCE_BATCH25_20260823.md          | 121 ++++++++++++++++++++++-
 docs/AUDIT_PROTOCOL_CALLERS_BATCH25.md           |   6 +-
 docs/AUDIT_SCHEMA_ACCEPTANCE_BATCH25_20260823.md |   6 +-
 docs/AUDIT_V2_ARITHMETIC_BATCH25_20260823.md     |   6 +-
 docs/WO-2601-thunk7-probe-closure_20260823.md    |   4 +-
 5 files changed, 130 insertions(+), 13 deletions(-)
```

## 4. workspace 全量测试证据（carry-forward 关系）

- `evidence_workspace_test_3101.txt`（200846B，SHA `216C146D80EC30A921322DCE6B9C6440C0CBAB35E59D1262D21338C25A822C3A`）：
  cargo test --workspace --offline 原始 stdout，2026-08-23 14:22:41 → 14:24:22，**执行树 = 9d7010e**，EXIT=0。
  **carry-forward 说明**：9d7010e..ea1ca8d 仅 docs/fixtures 变更（crates/ 零修改），
  测试结论对 ea1ca8d 树继续成立（56 个 test result 行全部 ok、0 failed）。
- `evidence_workspace_check_3101.txt`（673B，SHA `A903AB28...`）：cargo check --workspace --offline，执行树 9d7010e，EXIT=0。
- **warning 口径（如实保留）**：mida-packers-themida thread_id、antidebug-runtime proc_surfaces unused_mut ×2、
  mida-cli dump_timing——结论：**tests passed; existing warnings present**（非 zero warnings）。

## 5. 验收门自检（更新）

| 门 | 结果 |
|----|------|
| manifest 绑定 ea1ca8d | ✅ head 证据 = ea1ca8dcd15229e111cdbb1739b66e1992205eee |
| 1 commit / 5 unique paths / +130/-13 | ✅ git 实测（evidence_stat_3101b.txt） |
| tracked workspace clean | ✅ tracked 修改数 = 0 |
| workspace 全量测试 carry-forward 明确 | ✅ 执行树 9d7010e，9d7010e..ea1ca8d docs-only，结论 carry-forward |
| warning 口径如实 | ✅ tests passed; existing warnings present |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---

（WO-3101 post-commit 补充，绑定 ea1ca8d / 证据树 ea1ca8d）
