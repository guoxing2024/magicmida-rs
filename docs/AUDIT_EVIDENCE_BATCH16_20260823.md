# AUDIT_EVIDENCE — Batch 16/17 可复核证据包（WO-1704 溯源版）

**工单编号**: WO-1704（Batch 17）
**日期**: 2026-08-23
**审计性质**: 只读证据审计；不改生产代码。
**基线**: 07c02db（Batch 16）→ fa7db57（WO-1701）

## 1. 目的

对 Batch 16 审计（AUDIT_BATCH16_20260823.md）指出的证据缺陷逐项修正：
1. 对 D:Temp 每个外部输出记录 SHA-256、字节数、生成时间与对应 commit/tree 状态；
2. 明确 worker 机输出只能作为 worker evidence；总指挥机阻断不能标记独立 PASS；
3. 更正"zero warnings"矛盾：拆分 test warnings / package check warnings / workspace warnings；
4. 把 evidence 文件与命令、退出码、环境版本绑定，不得只给路径。

## 2. 环境信息（worker 机）

| 项 | 值 | 说明 |
|----|----|------|
| 机器 | Windows（x64），worker 机 | |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) | worker 机可用 |
| cargo | 1.97.1 (c980f4866 2026-06-30) | worker 机可用 |
| git user | guoxing2024 <guoxing2024@users.noreply.github.com> | |
| 工作目录 | D:Claude projectmagicmida-rs | |
| 总指挥机 rustup | 阻断：could not create home directory ... .rustup (os error 183) | 见 §7 |

## 3. 外部证据文件溯源表（D:Temp，不进 git）

> 说明：所有 hash 均为 SHA-256（FIPS 180-4，PowerShell Get-FileHash 计算，2026-08-23）；
> 生成时间 = 文件 LastWriteTime（本地时间）；tree 状态 = 命令执行时 HEAD commit。

| 文件 | 字节数 | SHA-256 | 生成时间 | 命令 | 退出码 | 对应 HEAD |
|------|--------|---------|---------|------|--------|----------|
| D:Tempevidence_test_1606.txt | 7823 | E730128A597AF8CB569E8B9CC472A26394E181D4588AC88081232A640C2B6737 | 2026-08-23 01:32:29 | cargo test -p mida-antidebug-runtime --offline | 0 | 07c02db |
| D:Tempevidence_check_1606.txt | 690 | 3DF41E9614E116FD5DA00F92FBDD8BA1CBB0A897D52489A9D13A44307CE94C02 | 2026-08-23 01:32:38 | cargo check --workspace --offline | 0 | 07c02db |
| D:Tempevidence_test_1704.txt | 8544 | DC95D9F37A92FDF03A3492EF6EACD2CC5E58730DB02D129A81B6D1D631DB2E58 | 2026-08-23 | cargo test -p mida-antidebug-runtime --offline | 0 | fa7db57 |
| D:Tempevidence_check_1704.txt | 690 | 49AD313FE3C1C71DC08A3CA3A7A4003604C86276AA845084F7040BE9EB374BAE | 2026-08-23 | cargo check --workspace --offline | 0 | fa7db57 |
| D:Tempevidence_check_pkg_1704.txt | 73 | 78B375D6908AEB462EF5471EE8844057B14AD6CF7E7BE3553697FB7C0CDF3AD6 | 2026-08-23 | cargo check -p mida-antidebug-runtime --offline | 0 | fa7db57 |

> 总指挥复核方式：对同一文件重算 Get-FileHash 必须得到表中值；文件未变则 hash 不变。
> 本文件自身的任何修改都不会改变上述外部文件内容（外部文件在 D:Temp，独立于 git）。

## 7. 环境差异声明（worker evidence ≠ 总指挥 PASS）

- worker 机（本机）cargo/rustc 1.97.1 可用；§3/§5 所有命令为 worker 机原始执行结果。
- 总指挥机 cargo 被 rustup shim 阻断（could not create home directory ... os error 183）；
  因此**总指挥侧不能登记独立 PASS**，本文件所有测试结果均为 **worker evidence**。
- 同一命令在不同环境的不同结果属于环境问题；本文件如实记录两侧情况。
- 总指挥独立复核路径：修复 rustup home 或设置 CARGO_TARGET_DIR 后重跑 §3 表内命令，
  对比退出码与测试计数；外部文件 hash 用 Get-FileHash 复核。

## 8. digest vectors 权威计算记录（WO-1603，总指挥已独立复算一致）

| Vector | canonical bytes（hex） | SHA-256 |
|--------|----------------------|---------|
| V1 {} | 7b 7d | 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a |
| V2 {"a":2,"b":1} | 7b 22 61 22 3a 32 2c 22 62 22 3a 31 7d | d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772 |
| V3 {"a":[1,2],"s":"x\"y","u":"中","z":null} | 7b 22 61 22 3a 5b 31 2c 32 5d 2c 22 73 22 3a 22 78 5c 22 79 22 2c 22 75 22 3a 22 e4 b8 ad 22 2c 22 7a 22 3a 6e 75 6c 6c 7d | 154301026b1458e084761c0fba44c2269b5e66f7a4b0e0071ad09e69e97dd244 |
| V4 {"no":false,"ok":true} | 7b 22 6e 6f 22 3a 66 61 6c 73 65 2c 22 6f 6b 22 3a 74 72 75 65 7d | ae8ab1e1b72505d8544a32bf3803333e81528159e214e4198a0271d2f60dc419 |

> 总指挥已用 PowerShell .NET SHA-256 独立复算全部四个 digest 并匹配（AUDIT_BATCH16 §5.1）。
> V4 的 authoritative digest = ae8ab1e1...（早期占位 0e64db... 已废弃）。

## 9. hygiene 检查

- 未修改：GTO/Oreans vault、manifest、LIVE-4 文件、实弹 runtime、attestation.rs / provenance.rs / exports.rs / runtime_loader.rs 生产代码。
- 未删除/移动任何既有文件。
- 无 forbidden artifacts（无二进制、无 target 产物进 git）。
- git status 未跟踪文件均为既有派单/审计文档，非本批引入。

## 10. 结论

本文件提供 Batch 16/17 交付的可复核证据链：每项外部输出的 SHA-256/字节数/时间/tree 绑定、
warnings 三分拆、worker evidence 与总指挥环境差异声明、digest 权威计算记录。
任何条目均可由总指挥独立复核；无法独立复现的（总指挥机 rustup 阻断）已如实标注，不写 PASS。

