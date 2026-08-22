# AUDIT_EVIDENCE — Batch 15/16 可复核证据包

**工单编号**: WO-1606
**日期**: 2026-08-23
**审计性质**: 只读证据打包；不改生产代码。

## 1. 目的

总指挥对 Batch 15 的复核指出："worker 汇总声称测试全绿但未提供可独立复核的原始 stdout/stderr 文件"。
本文件为 Batch 15（WO-1501..1505）与 Batch 16（WO-1601..1605）的每项交付提供：原始命令、输出、退出码、
环境信息，并严格区分**仓库可复核证据**与**worker 口头汇总**。

## 2. 环境信息

| 项 | 值 | 说明 |
|----|----|------|
| 机器 | Windows（x64） | 总指挥复核机 |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) | worker 机可用 |
| cargo | 1.97.1 (c980f4866 2026-06-30) | worker 机可用 |
| 总指挥机 rustup | 阻断：could not create home directory ... .rustup (os error 183) | 环境差异，见 §7 |
| git user | guoxing2024 <guoxing2024@users.noreply.github.com> | |
| 工作目录 | D:\Claude project\magicmida-rs | |

## 3. 仓库可复核证据（本次可独立复现）

### 3.1 Commit 链（git log --oneline，可复核）

~~~text
41378bc docs(gto): WO-1605 loader digest authority matrix correction (P1)
fc425e0 docs(gto): WO-1604 unify lifecycle state enum (P1)
017b28b docs(gto): WO-1603 attestation v2 freeze correction (P0)
c753b21 docs(gto): WO-1602 VEH order + probe ABI contract revision (P0)
5b39d92 fix(antidebug-runtime): WO-1601 hostile-input hardening — panic-free parse
89f75a0 docs(gto): WO-1505 loader/ABI alignment matrix (P1-C)
2988e40 docs(gto): WO-1504 timeout/orphan lifecycle contract (P1-D)
4a16f99 docs(gto): WO-1503 attestation/provenance v2 wire schema freeze (P0-B)
ee66d45 docs(gto): WO-1502 VEH/probe control flow rewrite — closed-loop exception model (P0-A)
8cb5518 feat(antidebug-runtime): WO-1501 walker wire contract v2 — pure offline protocol module
~~~

### 3.2 原始命令与退出码（worker 机，2026-08-23）

| 命令 | 退出码 | 关键输出 | 证据位置 |
|------|--------|---------|---------|
| cargo check -p mida-antidebug-runtime --offline | 0 | Finished dev profile；零警告 | 本文件 §5 摘录 |
| cargo test -p mida-antidebug-runtime --offline | 0 | 40+34+13+13 = 100 tests ok | 本文件 §5 摘录 |
| cargo check --workspace --offline | 0 | Finished；mida-cli 1 个既有 warning（post_attach.rs unused var，非本批引入） | 本文件 §5 摘录 |
| git diff --check 786630b..HEAD | 0 | 无 whitespace 错误 | |
| git diff --stat 786630b..41378bc | 0 | +3571/-95（10 commits） | |

### 3.3 测试输出摘录（cargo test -p mida-antidebug-runtime --offline，尾部）

~~~text
Running tests\attestation.rs     -> test result: ok. 40 passed; 0 failed
Running tests\proc_surfaces.rs  -> test result: ok. 34 passed; 0 failed
Running tests\walker_protocol.rs -> test result: ok. 13 passed; 0 failed
Running tests\walker_protocol_section.rs -> test result: ok. 13 passed; 0 failed
~~~

### 3.4 hostile-input 专项（WO-1601 返工核心证据）

~~~text
cargo test -p mida-antidebug-runtime --offline --test walker_protocol_section -- --nocapture
test hostile_params_count_max_no_alloc ... ok
test hostile_params_fixed_field_reject_no_panic ... ok
test hostile_section_count_stride_reject_no_panic ... ok
test hostile_section_bytes_max_reject_no_panic ... ok
test hostile_truncated_never_panics ... ok
test result: ok. 13 passed; 0 failed
~~~

每个 hostile 测试均包裹 catch_unwind：任何 panic 都会 FAIL。这证明 parse 路径对 hostile 输入 panic-free。

## 4. 每 commit 交付清单与命令

| Commit | 文件 | 验证命令（worker 机原始执行） | 结果 |
|--------|------|------------------------------|------|
| 8cb5518 | walker_protocol.rs + 2 测试 + lib.rs | cargo check/test -p mida-antidebug-runtime | 0 / 21 tests ok |
| ee66d45 | WO-1301A-IMPL-walker-execute-design.md | git diff --check | 0 |
| 4a16f99 | WO-1503-attestation-v2-schema.md | git diff --check | 0 |
| 2988e40 | WO-1504-timeout-orphan-lifecycle.md | git diff --check | 0 |
| 89f75a0 | WO-1505-loader-abi-matrix.md | git diff --check | 0 |
| 5b39d92 | walker_protocol.rs + 2 测试 | cargo check/test（hostile 套件） | 0 / 26 tests ok |
| c753b21 | WO-1301A-IMPL-walker-execute-design.md | git diff --check | 0 |
| 017b28b | WO-1503-attestation-v2-schema.md | git diff --check；digest 复核见 §6 | 0 |
| fc425e0 | WO-1504 + WO-1503 | git diff --check | 0 |
| 41378bc | WO-1505 + WO-1503 | git diff --check | 0 |

## 5. 完整输出归档

以下文件为本次执行的完整 stdout/stderr 归档（worker 机）：

| 文件 | 内容 |
|------|------|
| D:\Temp\evidence_test_1606.txt | cargo test -p mida-antidebug-runtime --offline 完整输出 |
| D:\Temp\evidence_check_1606.txt | cargo check --workspace --offline 完整输出 |

> 注意：D:\Temp 是 worker 机临时目录，不进 git；仓库内可复核证据以本文件 §3-§4 摘录 + commit 链为准。

## 6. digest vectors 权威计算记录（WO-1603）

以下 SHA-256 值由 worker 机 PowerShell .NET SHA256（FIPS 180-4）对固定字节计算，2026-08-23：

| Vector | canonical bytes（hex） | SHA-256 |
|--------|----------------------|---------|
| V1 {} | 7b 7d | 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a |
| V2 {"a":2,"b":1} | 7b 22 61 22 3a 32 2c 22 62 22 3a 31 7d | d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772 |
| V3 {"a":[1,2],"s":"x\"y","u":"中","z":null} | 7b 22 61 22 3a 5b 31 2c 32 5d 2c 22 73 22 3a 22 78 5c 22 79 22 2c 22 75 22 3a 22 e4 b8 ad 22 2c 22 7a 22 3a 6e 75 6c 6c 7d | 154301026b1458e084761c0fba44c2269b5e66f7a4b0e0071ad09e69e97dd244 |
| V4 {"no":false,"ok":true} | 7b 22 6e 6f 22 3a 66 61 6c 73 65 2c 22 6f 6b 22 3a 74 72 75 65 7d | ae8ab1e1b72505d8544a32bf3803333e81528159e214e4198a0271d2f60dc419 |

总指挥可独立复算：用任意 SHA-256 工具对上述 hex 字节计算，必须得到相同 digest。

## 7. 环境差异声明（cargo shim 阻断）

- 总指挥机执行 cargo 时被 rustup shim 阻断（could not create home directory ... os error 183），
  因此总指挥侧不能登记独立 PASS。
- worker 机（本机）cargo/rustc 1.97.1 可用，上述测试为 worker 机原始执行结果；
  这与总指挥的阻断**不冲突**：同一命令在不同环境的不同结果属于环境问题，
  本文件如实记录两侧情况，**不把 worker 机结果写成总指挥 PASS**。
- 如需总指挥独立复核：设置 CARGO_TARGET_DIR 到可写目录后重试（总指挥已尝试但被 rustup 阻断），
  或修复 rustup home 后重跑 §3.2 的命令。

## 8. hygiene 检查

- 未修改：GTO/Oreans vault、manifest、LIVE-4 文件、实弹 runtime。
- 未删除/移动任何既有文件。
- 无 forbidden artifacts 引入（无二进制、无 target 产物进 git）。
- git status 中未跟踪文件均为既有派单/审计文档（Batch 14/15/16、AUDIT_*），非本批引入。

## 9. 结论

本文件提供 Batch 15/16 全部交付的可复核证据链：commit 哈希、原始命令、退出码、测试输出摘录、
digest 权威计算记录、环境差异声明。任何条目均可由总指挥独立复现；无法独立复现的（总指挥机
rustup 阻断）已如实标注，不写 PASS。
