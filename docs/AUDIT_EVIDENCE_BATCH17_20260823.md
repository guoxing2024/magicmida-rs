# AUDIT_EVIDENCE — Batch 18 最终绑定审计（WO-1804）

**工单编号**: WO-1804（Batch 18）
**日期**: 2026-08-23
**审计性质**: 只读证据审计；不改生产代码。
**基线**: e71445d → de12e4c

## 1. 目的

对 Batch 17 审计（AUDIT_BATCH17_20260823.md §2）指出的证据绑定缺陷逐项修正：
1. 当前 evidence_test_1704.txt / evidence_check_1704.txt / evidence_check_pkg_1704.txt 的
   hash/size/time/tree 绑定；
2. 明确测试实际绑定 fa7db57 还是最终 e71445d；
3. warnings 与 exit code 逐项对照；
4. worker evidence、commander independent verification、Windows/live evidence 三层分离。

## 2. 历史证据文件绑定（Batch 17 生成，07c02db→fa7db57 期间）

> 这三个文件是 WO-1701 协议测试的证据，生成时 HEAD = fa7db57（WO-1701 commit 完成时）。
> 之后 Batch 17 的 4 个文档 commit（451cb4c/f05682f/d07e0d5/e71445d）不涉及协议代码，
> 因此该证据**只证明 WO-1701 的协议行为**（fa7db57 树），不证明文档变更后的任何行为。

| 文件 | 字节数 | SHA-256 | 生成时间 | 命令 | 退出码 | 绑定 HEAD |
|------|--------|---------|---------|------|--------|----------|
| D:Tempevidence_test_1704.txt | 8544 | DC95D9F37A92FDF03A3492EF6EACD2CC5E58730DB02D129A81B6D1D631DB2E58 | 2026-08-23 01:57:49 | cargo test -p mida-antidebug-runtime --offline | 0 | fa7db57 |
| D:Tempevidence_check_1704.txt | 690 | 49AD313FE3C1C71DC08A3CA3A7A4003604C86276AA845084F7040BE9EB374BAE | 2026-08-23 01:57:51 | cargo check --workspace --offline | 0 | fa7db57 |
| D:Tempevidence_check_pkg_1704.txt | 73 | 78B375D6908AEB462EF5471EE8844057B14AD6CF7E7BE3553697FB7C0CDF3AD6 | 2026-08-23 01:57:51 | cargo check -p mida-antidebug-runtime --offline | 0 | fa7db57 |

> 注意：AUDIT_EVIDENCE_BATCH16 中该三文件的生成时间标注为 2026-08-23（无时分），
> 本表以 2026-08-23 01:57 的 LastWriteTime 为准（与 Batch 16 审计时读取的 01:32 不同：
> 文件在 2026-08-23 01:57 被重新生成过，内容与 Batch 16 记录一致——hash 相同证明内容未变）。

## 3. 最终绑定：Batch 18 全量回归（HEAD = de12e4c）

为消除"证据绑定旧 HEAD"的歧义，Batch 18 结束时在**最终 HEAD（de12e4c）**重新执行
全量回归并生成新的证据文件：

| 文件 | 字节数 | SHA-256 | 生成时间 | 命令 | 退出码 | 绑定 HEAD |
|------|--------|---------|---------|------|--------|----------|
| D:Tempevidence_head_1804.txt | 121 | 582098D1C3A93A12EEDE27F518C590DA5338974C9EE0D055F603644FF44FDB20 | 2026-08-23 | git log -1 --format="%H %s" | 0 | de12e4c |
| D:Tempevidence_test_1804.txt | 8654 | 0EECB1321E66E51E23D3695CC30C41DA9FF2375448461B5682D14963426C05D9 | 2026-08-23 | cargo test -p mida-antidebug-runtime --offline | 0 | de12e4c |
| D:Tempevidence_check_1804.txt | 690 | 6F0308CAFEC0787C35CA7EC7E6AE17194E0062803BB0E52482EEE0F411572E39 | 2026-08-23 | cargo check --workspace --offline | 0 | de12e4c |
| D:Tempevidence_check_pkg_1804.txt | 175 | DFE3798657EC9DA743188B1465AEE1793FD35080AA962E71EB4C900B1B7BAB19 | 2026-08-23 | cargo check -p mida-antidebug-runtime --offline | 0 | de12e4c |

## 4. warnings 与 exit code 逐项对照（de12e4c）

| 命令 | 退出码 | test results | warnings |
|------|--------|-------------|----------|
| cargo test -p mida-antidebug-runtime --offline | 0 | 40 (attestation) + 34 (proc_surfaces) + 15 (walker_protocol) + 27 (walker_protocol_section) = **116 passed, 0 failed** | 2× unused_mut（proc_surfaces 测试，既有；本批未触碰） |
| cargo check -p mida-antidebug-runtime --offline | 0 | Finished dev profile | 0 |
| cargo check --workspace --offline | 0 | Finished dev profile | 1× unused variable dump_timing（mida-cli lib，既有） |

本批（Batch 18）新增代码零 warning：walker_protocol.rs 及两个测试文件的变更无任何警告。

## 5. 三层证据分离

| 层 | 内容 | 状态 |
|----|------|------|
| worker evidence | §2/§3 全部命令的原始输出（D:Temp 文件 + 本表 hash） | 全部登记；worker 机 cargo 1.97.1 执行 |
| commander independent verification | 总指挥机重跑 §2/§3 命令并比对退出码/hash | **BLOCKED**：总指挥机 rustup shim 阻断（could not create home directory .rustup, os error 183）；设置 CARGO_TARGET_DIR 或修复 rustup home 后可复核 |
| Windows/live evidence | VEH/SEH/探针/实弹行为 | **不存在**；全部设计合同为 design-only，V10 待实现后 + LIVE-4 独立审批 |

**结论**：本文件所有测试结果均为 worker evidence；不构成总指挥独立 PASS，更不构成
Windows 行为 PASS。

## 6. 复核方法

- hash 复核：Get-FileHash <file> -Algorithm SHA256 必须等于上表值；
- tree 绑定：git log -1 在 de12e4c；任何 commit 变更后需重跑 §3 命令并更新 hash；
- 外部文件独立于 git：本文件修改不改变 D:Temp 文件内容。

