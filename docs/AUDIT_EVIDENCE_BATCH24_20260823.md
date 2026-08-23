# AUDIT — Evidence 最终 HEAD 重绑定（Batch 25 / WO-2503）

**审计运行日期**：2026-08-23
**绑定 HEAD**：`62ed608`（Batch 24 最终树）
**前版**：evidence_*_2403.txt 绑定 `221ef33`（Batch 23 树，WO-2403）；现按 WO-2503 重生成
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定说明（多棵树证据分层）

- **Batch 23 code tree evidence = 221ef33**：`evidence_*_2403.txt`（WO-2403 交付）。
- **Batch 24 code tree evidence = 62ed608**：本文件证据（`evidence_*_2503.txt`），
  并登记 a664f92/62ed608 两个提交的 diffcheck。
- 生产代码（crates/）自 221ef33 起**零修改**；Batch 24 的 7 个 unique paths 全部为
  docs/ 或 docs/fixtures/。

## 2. Batch 24 统计更正（WO-2503 要求）

- 交付报告曾写 `+416/-65`；**git 实测为 `+415/-64`**（git diff --stat 221ef33..62ed608，
  原始命令输出：7 files changed, 415 insertions(+), 64 deletions(-)）。
- 更正：Batch 24 = **2 commits、7 unique paths、+415/-64**。

## 3. 证据文件清单（绑定 62ed608）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2503.txt | 113B | F9E89F5C14F1B15012BAB3E5D4EF8E074BAF925F1C0A8F27B1142D41D74648D1 | git rev-parse HEAD | 0 |
| D:\Temp\evidence_test_2503.txt | 9307B | 43BAEB1539B383E616341008FD9906DAF2A5D8B93762253FB3FB322416D74C33 | cargo test -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_2503.txt | 394B | F24683A72E72103E29051DA64E37BBBFBC172D71976307918957BE0EEA88D93B | cargo check -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_pkg_2503.txt | 2836B | C76E79B3BD27252FF8FD2888910B2AAC2BE37A7193872D5A5B4E850027A11804 | cargo check -p mida-cli --offline | 0 |
| D:\Temp\evidence_diffcheck_2503.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check 221ef33..62ed608 | 0 |
| D:\Temp\evidence_worktree_2503.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check 62ed608（工作树） | 0 |

**生成时间**：2026-08-23（worker 机器）。

## 4. Batch 25 本机/离线测试证据（D:\Temp）

| 文件 | SHA-256 | 说明 |
|------|---------|------|
| thunk7_v2_test.c | F77DFDD63E5B4481F42B85D95C157B7ECAA6B2792C917F77A2BCD08E780E8358 | 组合测试 C 驱动 |
| thunk7_v2.asm | 9F950B6CF9E4A47E3FEFFA6B3B2099FEF9B8CD2074536F912E5C7FBB8A9ED349 | thunk+entry-stub 汇编 |
| thunk7_v2_stdout.txt | DC6D1485BB0E86FE722126A5A3DDB4469702D02B07A9FF7B46284532754475AD | THUNK7 COMBINED PASS EXIT=0 |
| thunk7_v2.obj | C0B2E32A40C086EF46F1EDB16DC5FC8CF27E4782EE354803347D2AAFBEDBB0D4 | ml64 产物 |
| hostile_asan_detail.txt | 7AFE1FA521B5155D8E832B8004CA175035E1D9EE7930ACFCA52A3DE0E6EC4AC4 | ASan 16/16 逐用例 EXIT=0 |


| thunk7_final_test.c | 7ECFB5593A0781016C887F91516C3E6D71E7233A151247CE4ACD9A851CE896CC | 最终测试 C 驱动（fixture-exact 65B） |
| thunk7_final_full.asm | 94552912E0C2DBEBCAC87A2C63C6D87EAFFFD8247EBEDF24630D3A2244A72894 | 最终 thunk+entry-stub 汇编 |
| thunk7_final_stdout.txt | 34629AAE017FD563F3ABF7B20A05C76B7BEC8F0796D8F8569A211E38944BCE71 | THUNK7 FINAL PASS EXIT=0 |
| thunk7_final_full.obj | BE1042DA3AA6947F539503E6655B90126E57292F1B7F3D97359DE6070C171A20 | ml64 产物（49 89 CB 逐指令确认） |


**obj 原始字节验证（自检追加）**：从 thunk7_final_full.obj 的 .text$mn section
（COFF rawptr=140, rawsize=127）直接提取前 60 字节：
`49 89 CB 49 8B 03 49 8B 4B 08 49 8B 53 10 4D 8B 43 18 4D 8B 4B 20`
`48 83 EC 38 4D 8B 53 28 4C 89 54 24 20 4D 8B 53 30 4C 89 54 24 28`
`4D 8B 53 38 4C 89 54 24 30 49 89 63 48 FF D0 48 ...`
= WO-2301 fixture THUNK7_CODE（60B）+ probe（49 89 63 48 @0x35）扩展，
**fixture 字节表 = obj 实际字节 = 测试执行字节，三者完全一致**。

**自检修正（Batch 25 追加）**：thunk7_v2 系列使用 ml64 自由编码（4C 8B D9）而非 fixture
冻结的 49 89 CB——虽语义等价但违反"机器码与文字一致"原则；本批以 thunk7_final 系列
（fixture-exact 字节）为唯一验证来源。
**更正说明**：Batch 24 的 thunk7_abi_stdout.txt（ABI ROUND-TRIP FAIL）与
thunk7_rsp_stdout.txt（错误 opcode 4D 89 63 48）**作废**，本批以 thunk7_v2 系列为准
（entry 对齐由 asm stub 入口首指令记录，opcode 49 89 63 48 经 ml64 反汇编确认）。

## 5. 分层登记

| 层 | 状态 |
|----|------|
| worker stdout（cargo test/check/diffcheck） | 本文件证据（可复核 hash） |
| 本机 thunk ABI 验证 | thunk7_v2 系列（LOCAL，非远程） |
| ASan hostile | hostile_asan_detail.txt（逐用例） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 6. 验收门自检

| 门 | 结果 |
|----|------|
| manifest 绑定 62ed608 | ✅ head 证据 = 62ed608 |
| a664f92/62ed608 两提交 diffcheck 登记 | ✅ evidence_diffcheck_2503.txt |
| 7 unique paths / +415/-64 口径 | ✅ git 实测并更正 |
| 旧树证据保留并标注 | ✅ evidence_*_2403.txt（221ef33）保留；作废文件已标注 |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---
（WO-2503 交付，绑定 62ed608）
## 7. 提交后绑定补充（Batch 25 交付提交）

- Batch 25 交付提交：`2b3e680`（docs(gto): WO-2501 thunk7 local runtime three-check
  PASS + WO-2502 arithmetic independent audit + WO-2503/2504/2505 final-tree audits），
  6 文件 +403。
- 生产代码（crates/）自 `62ed608` 起**零修改**（本提交仅 docs/fixtures），
  因此 test/check/diffcheck 证据（绑定 62ed608 树）对提交后树仍然有效。
- 提交后 HEAD：`2b3e680d3144994cf777725ccf075286955b0859`。
- 提交后 `git diff --check 62ed608..2b3e680`：EXIT=0（无 whitespace 错误）。

---
（WO-2503 补充，提交后绑定 2b3e680 / 证据树 62ed608）