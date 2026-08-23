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