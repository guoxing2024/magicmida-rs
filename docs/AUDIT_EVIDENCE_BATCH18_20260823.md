# AUDIT_EVIDENCE — Batch 18/19 证据树绑定重打包（WO-1903）

**工单编号**: WO-1903（Batch 19）
**日期**: 2026-08-23
**审计性质**: 只读证据审计；不修改生产代码；不宣称 commander PASS。
**基线**: 51c1237 → 3e6c50d

## 1. 目的

修正 Batch 18 证据绑定歧义（AUDIT_BATCH18 §2.2/WO-1804 裁决）：明确区分被测 code tree
与文档最终 HEAD；所有"最终 HEAD"措辞必须由 hash manifest 支持。

## 2. 树区分（核心修正）

| 树 | commit | 含义 |
|----|--------|------|
| 被测 code tree | de12e4c | Batch 18 生产代码证据（WO-1801 协议 + WO-1802/1803 文档）绑定树 |
| 文档最终 HEAD | 51c1237（Batch 18 末）/ 3e6c50d（Batch 19 进行中） | 文档提交不改变被测代码；旧 evidence_*_1804.txt **不能**写为最终 HEAD 证据 |

Batch 18/19 的生产代码变更：仅 0e5732f（walker_protocol.rs + 2 测试文件）；
其余全部为文档/审计/fixture 提交。因此：
- evidence_*_1804.txt 证明 **de12e4c code tree**（协议行为）；
- 文档后续提交（1a10327, 51c1237, 570e764, 3e6c50d 等）不自动重写旧 stdout 绑定。

## 3. Batch 18 证据文件（绑定 de12e4c code tree）

| 文件（绝对路径） | 字节数 | SHA-256 | 命令 | 退出码 | 生成时间 | 绑定 code tree |
|------------------|--------|---------|------|--------|----------|----------------|
| D:Tempevidence_head_1804.txt | 121 | 582098D1C3A93A12EEDE27F518C590DA5338974C9EE0D055F603644FF44FDB20 | git log -1 --format="%H %s" | 0 | 2026-08-23 02:20 前后 | de12e4c |
| D:Tempevidence_test_1804.txt | 8654 | 0EECB1321E66E51E23D3695CC30C41DA9FF2375448461B5682D14963426C05D9 | cargo test -p mida-antidebug-runtime --offline | 0 | 2026-08-23 | de12e4c |
| D:Tempevidence_check_1804.txt | 690 | 6F0308CAFEC0787C35CA7EC7E6AE17194E0062803BB0E52482EEE0F411572E39 | cargo check --workspace --offline | 0 | 2026-08-23 | de12e4c |
| D:Tempevidence_check_pkg_1804.txt | 175 | DFE3798657EC9DA743188B1465AEE1793FD35080AA962E71EB4C900B1B7BAB19 | cargo check -p mida-antidebug-runtime --offline | 0 | 2026-08-23 | de12e4c |

**不得**把这些文件称为 51c1237 或任何后续 HEAD 的证据。

## 4. Batch 19 重跑证据（绑定 3e6c50d，当前进行中 HEAD）

> 协议代码自 de12e4c 未变（0e5732f 是 Batch 18 内唯一代码提交）；重跑目的：在 Batch 19
> 当前树（3e6c50d）上建立 fresh manifest，消除"旧 hash 对应旧树"的一切歧义。

| 文件（绝对路径） | 字节数 | SHA-256 | 命令 | 退出码 | 生成时间 | 绑定 code tree |
|------------------|--------|---------|------|--------|----------|----------------|
| D:Tempevidence_head_1903.txt | 136 | CB724B45DB0471B1EE737017C973A05C7CEC8E0824F2475B5D909F2B5E3BA223 | git log -1 --format="%H %s" | 0 | 2026-08-23 02:37:14 | 3e6c50d |
| D:Tempevidence_test_1903.txt | 8654 | B317AB91D47313011CF5206BDD10741CAA31B896461DA5E5F00D4EA1E47DCA55 | cargo test -p mida-antidebug-runtime --offline | 0 | 2026-08-23 02:37:15 | 3e6c50d |
| D:Tempevidence_check_1903.txt | 514 | AE145AFFC375E82CA5F2C514ED1A820778E79A087B081816E3B5593D03C2EA9B | cargo check --workspace --offline | 0 | 2026-08-23 02:37:15 | 3e6c50d |
| D:Tempevidence_check_pkg_1903.txt | 73 | DAB4E4707B2E6FDBDEAD361B4487BE475974A047EDEA846DD92BAC44F319F872 | cargo check -p mida-antidebug-runtime --offline | 0 | 2026-08-23 02:37:16 | 3e6c50d |
| D:Tempevidence_diffcheck_1903.txt | 0 | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | git diff --check | 0 | 2026-08-23 02:37:16 | 3e6c50d |

（evidence_diffcheck_1903.txt 为空文件 = git diff --check 无输出，exit 0。）

## 5. 测试结果对照（3e6c50d）

~~~text
cargo test -p mida-antidebug-runtime --offline (exit 0)
test result: ok. 40 passed (attestation.rs)
test result: ok. 34 passed (proc_surfaces.rs)
test result: ok. 15 passed (walker_protocol.rs)
test result: ok. 27 passed (walker_protocol_section.rs)
总计 116 passed; 0 failed
~~~

warnings：test 2× unused_mut（proc_surfaces 既有）；workspace check 1× dump_timing（mida-cli 既有）；
package check 0。本批新增代码零 warning。

## 6. 三层证据分离（保留）

| 层 | 状态 |
|----|------|
| worker evidence | 全部登记（§3/§4 hash manifest）；worker 机 cargo 1.97.1 |
| commander independent verification | **BLOCKED**（总指挥机 rustup shim：os error 183）；不得填 PASS |
| Windows/live evidence | 不存在；design-only 合同，V10 待实现后 + LIVE-4 独立审批 |

## 7. 工作树范围声明

- 本文件（及全部 Batch 19 交付）只修改 docs/ 下文档与 docs/fixtures/ 下离线 fixture；
- 生产代码（walker_protocol.rs 等）未在 Batch 19 修改；
- git diff --check（evidence_diffcheck_1903.txt）exit 0，无 whitespace 错误；
- 文档提交不会自动重写旧 stdout 绑定：旧证据文件 hash 与生成树一一对应，
  任何重跑必须生成新文件并登记新 hash（本文件 §4 即范例）。

## 8. 结论

证据树绑定已校正：旧 evidence_*_1804.txt 明确标注 de12e4c code tree；
新 evidence_*_1903.txt 绑定 3e6c50d；三层分离保持；commander 独立验证保持 BLOCKED。
