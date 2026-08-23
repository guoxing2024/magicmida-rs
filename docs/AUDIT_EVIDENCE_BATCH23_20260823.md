# AUDIT — Evidence 最终 HEAD 重绑定（Batch 24 / WO-2403）

**审计运行日期**：2026-08-23
**绑定 HEAD**：`221ef33`（Batch 23 最终树）
**前版**：evidence_*_2303.txt 绑定 `ea79518`（Batch 22 树，WO-2303）；现按 WO-2403 重生成
**性质**：只读证据审计；不修改生产代码；不宣称 commander PASS

## 1. 绑定说明（区分多棵树证据）

- **Batch 22 code tree evidence = ea79518**：`evidence_*_2303.txt`（WO-2303 交付）。
- **Batch 23 code tree evidence = 221ef33**：本文件证据（`evidence_*_2403.txt`），
  并登记 0ebfff4/221ef33 两个提交的 diffcheck。
- 生产代码（crates/）自 ea79518 起**零修改**；Batch 23 的 6 个 unique paths 全部为
  docs/ 或 docs/fixtures/（git 实测 6）。

## 2. 证据文件清单（绑定 221ef33）

| 文件 | 大小 | SHA-256 | 命令 | 退出码 |
|------|------|---------|------|--------|
| D:\Temp\evidence_head_2403.txt | 113B | 51195D625B6AA89F66E93240DBDE4EF1F6E56CE40790A60BDF10C5205C8F495C | git rev-parse HEAD | 0 |
| D:\Temp\evidence_test_2403.txt | 9307B | A913544500F1DC6B403F25E8CC314D9CED9D78BF8C9E405B2A38EF705B5685A1 | cargo test -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_2403.txt | 394B | B109ABDCB9424A55C9B1AF387A74FEF61AFBF43C89415CB69F8B06FB4635AE5D | cargo check -p mida-antidebug-runtime --offline | 0 |
| D:\Temp\evidence_check_pkg_2403.txt | 2836B | FA33AFC9846210D6F4A00F887DA5BEFD2363B409C113F32F61570B8F2DDB7468 | cargo check -p mida-cli --offline | 0 |
| D:\Temp\evidence_diffcheck_2403.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check ea79518..221ef33 | 0 |
| D:\Temp\evidence_worktree_2403.txt | 8B | CC258D839E50D5E0CF220528399D5C29A6BCC5C3A9EE2616A915627E0363D91D | git diff --check 221ef33（工作树） | 0 |

**生成时间**：2026-08-23（worker 机器）。

## 3. Batch 24 离线测试证据（D:\Temp）

| 文件 | SHA-256 | 说明 |
|------|---------|------|
| hostile_test_2202.c | 7D589D894044346BE30936A44E2ED3AAB4E7B4F3CB30B22BB695A3A62A7ABE64 | ASan hostile 16 用例 |
| hostile_test_2202_stdout.txt | 7AFE1FA521B5155D8E832B8004CA175035E1D9EE7930ACFCA52A3DE0E6EC4AC4 | 16/16 ALL PASS EXIT=0 |
| WO-2102-v2-envelope-fixture.h | 1C95C23FB6248523C9090FD6137FC24FDCFC7880EFD8253DC3B4CD38150E30EE | 被测 fixture |
| thunk7_abi_stdout.txt | A30CA1674CC3E66F79DB6380D8F08B5DE3F3E78D49346A19FE8B58EDB5AA0867 | 7 参数回传 PASS（本机 ABI） |
| thunk7_rsp_stdout.txt | B21F05FCD0F7B60A7334C29E3D03DEB20146917C9782D7E73ED8BC4374F2EA91 | call 前 rsp mod 16 = 0 PASS |
| WO-2301-thunk7-fixture.h | 19C24E51F2ABE300A389BD298DE6E6652DAC12366EB728CB80DE3536682A0BC1 | thunk7 机器码 fixture |
| WO-2401-thunk7-stack-fixture.h | 0CDD39F40E495F9A0A076CF17989E78A207CF1BCCE978B476767D3DBEC921FD5 | 栈布局 fixture |

## 4. 分层登记

| 层 | 状态 |
|----|------|
| worker stdout（cargo test/check/diffcheck） | 本文件证据（可复核 hash） |
| fixture compiler/ASan stdout | hostile_test_2202_stdout.txt |
| thunk 机器码 + 本机 ABI 验证 | ml64/dumpbin + thunk7_abi/rsp_test（LOCAL，非远程） |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim 阻断；不升级 PASS） |
| Windows/live evidence | **absent**（LIVE-4 NOT AUTHORIZED） |

## 5. 验收门自检

| 门 | 结果 |
|----|------|
| manifest 绑定 221ef33 | ✅ head 证据 = 221ef33 |
| 0ebfff4/221ef33 两提交 diffcheck 登记 | ✅ evidence_diffcheck_2403.txt |
| 6 unique paths 口径 | ✅ git 实测 |
| 旧树证据保留并标注 | ✅ evidence_*_2303.txt（ea79518）保留 |
| 时间/退出码/哈希可复核 | ✅ 上表完整 |
| 不宣称 commander PASS | ✅ BLOCKED 保持 |

---
（WO-2403 交付，绑定 221ef33）
## 6. 提交后绑定补充（Batch 24 交付提交）

- Batch 24 交付提交：`a664f92`（docs(gto): WO-2401 thunk stack ABI realigned +
  WO-2402 offset-wrap hardening + WO-2403/2404/2405 final-tree audits），
  7 文件 +403/-64。
- 生产代码（crates/）自 `221ef33` 起**零修改**（本提交仅 docs/fixtures），
  因此 test/check/diffcheck 证据（绑定 221ef33 树）对提交后树仍然有效。
- 提交后 HEAD：`a664f9247dca935023e77f598560715a3ea8f898`。
- 提交后 `git diff --check 221ef33..a664f92`：EXIT=0（无 whitespace 错误）。

---
（WO-2403 补充，提交后绑定 a664f92 / 证据树 221ef33）