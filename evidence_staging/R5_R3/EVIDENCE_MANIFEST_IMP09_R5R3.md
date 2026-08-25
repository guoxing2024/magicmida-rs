# IMP-09-CARRIER-R5-R3 — Raw Evidence Manifest（§0.2 从简口径）

工单: WORK_ORDER_IMP-09-CARRIER-R5-R3-SECTION-PRODUCER_20260825.md
执行派发: WORK_ORDER_IMP-09-R5-R3-DISPATCH_20260825.md
分支: codex/imp09-carrier-r5-r2
基线 HEAD: affb992f2b30b2c9f8243c72296456b5515f6e86
执行日期: 2026-08-25
状态声明: offline_mock=true / live_authorized=false / protected_sample=NOT_AUTHORIZED

## 1. 源文件 SHA-256（工作区最终态）

| 文件 | SHA-256 | 行数 |
|---|---|---|
| crates/antidebug-runtime/src/walker_protocol.rs | ea590622ad4594dc8dc385538a2e0a4d5bb204eb3e8bcf5bf2b9dfeb95757ce5 | 1756 |
| crates/antidebug-runtime/src/walker_producer.rs | 9b257a14b0e0ed416d727d3dc1ac202084f5484554d92ce3b09f840839ba9ccb | 717 |
| crates/antidebug-runtime/src/walker_consumer.rs | 91ab4c934f3b9cd632e0a816eb348735f678c7552a5729a3a6fe9bf8428352e4 | 745 |
| crates/antidebug-runtime/src/walker_control.rs | 513febc1594a59d710b28be596d0d0b77670df7f712256399daa15d8400894b4 | 1460 |
| crates/antidebug-runtime/src/lib.rs | 715a3eabcd5526bcd6c7fc4fbff916791051244d0db8a376e904d85e8da375fe | 85 |
| crates/cli/src/unpacker/antidebug_controller.rs | d237b6ed933ca034945c9f03373511112755976b6b532b23c4bd89258170ab73 | 2940 |
| docs/IMP09_CARRIER_R5_R3_SECTION_PRODUCER_DESIGN_20260825.md | 1054716b4cb4078cfc43c49d59462aa95ad40e8ad685df3374a58376be6d4752 | 143 |
| evidence_staging/R5_R3/REPORT_IMP09_R5R3_20260825.md | 139bcf6c0d427a3ac7cd0e3ebc6c3d16aa30254c95d59e8debf6a5ef68e11d51 | 187 |

## 2. 原始测试输出 / 退出码（分开记录）

| 文件 | 内容 | 退出码 |
|---|---|---|
| baseline_cargo_test.txt | 基线 cargo test --workspace（改动前） | 101（3 个既有环境失败） |
| cargo_test_workspace_final2.txt | cargo test --workspace（改动后最终态） | 101（同 3 个既有环境失败） |
| cargo_fmt_check.txt | cargo fmt --all -- --check（格式化前，全仓既有 diff） | 1 |
| cargo_fmt_check_final.txt | cargo fmt --all -- --check（最终态） | 1（NOT_PASS，全仓层面） |

### cargo fmt -- --check（工单 §4.6 诚实口径）

- workspace 层面：NOT_PASS（退出码 1，169 处 diff）。
- 全部 169 处 diff 均位于非本单文件（acceptance/themida/runtime_loader/
  exports/attestation/mod.rs 等）；经 git show HEAD:file + rustfmt 验证：
  这些文件在基线 HEAD affb992f2b30b2c9f8243c72296456b5515f6e86 处即为
  fmt-dirty（工作区从来不是 fmt-clean）。
- 本单 6 个触及文件全部 fmt-clean（rustfmt --edition 2021
  --config skip_children=true --check 退出码 0）：
  lib.rs / walker_control.rs / walker_protocol.rs / walker_producer.rs /
  walker_consumer.rs / antidebug_controller.rs。
- 为遵守工单"精确文件清单"，格式化只对触及文件执行；未改动非本单文件
  （曾误格式化后已全部 git checkout 还原；git status 仅 4 个 M + 2 个 ??）。

### 测试统计（最终态 final2）

- workspace 总计：1235 passed; 3 failed（基线 1210 passed; 3 failed；
  新增 25 个测试全部通过）。
- runtime（mida-antidebug-runtime）：
  - lib unittests：87 passed（含本单 producer 10 + consumer 10 + driver 闭环 1）
  - tests/attestation.rs：68 passed
  - tests/proc_surfaces.rs：34 passed
  - tests/walker_protocol.rs：26 passed
  - tests/walker_protocol_section.rs：27 passed
  - 合计 242 全部通过，0 失败
- cli（mida-cli --lib）：507 passed; 3 failed; 1 ignored
  （基线 504 passed；+3 为本单 R5-R3 CLI 消费门测试）。
  - 3 个失败均为既有环境性失败（与基线一致，非本单引入）：
    - runner_preflight::tests::resolver_extended_path_prefix_cannot_bypass_sibling_boundary
    - runner_preflight::tests::resolver_rejects_symlink_into_subdirectory_escape
    - runner_preflight::tests::resolver_rejects_symlinked_sibling_escape
    （沙箱无符号链接创建特权，硬链接回退导致 canonical path 与 sibling 相同；
    runner_preflight.rs 属禁止修改清单，未改动。）
- 其余 workspace crate 全部 ok。

### 新增测试（本单，25 个全部通过）

- runtime lib：producer 10（walker_producer::tests）+ consumer 10
  （walker_consumer::tests）+ driver 闭环 1
  （walker_control::tests::production_consumer_v2_digest_closure_passes）
- cli lib：R5-R3 消费门 3（imp09_r5r3_*）

## 3. 出口门

```ini
R5_R3_PRODUCTION_PRODUCER = PROVEN
R5_R3_ROUND1_DONE = PROVEN
R5_R3_ROUND2_DONE = PROVEN
R5_R3_CONSUMER = PROVEN
R5_R3_NEGATIVE_GATES = ALL_PASS
R5_R3_ROLLBACK = PROVEN
R5_R2_GATES_UNCHANGED = true
R5_R4_TEARDOWN = NOT_IMPLEMENTED
LIVE_AUTHORIZED = false
PROTECTED_SAMPLE = NOT_AUTHORIZED
```

## 4. 环境说明

- MSVC 链接器路径问题由 evidence_staging/R5_R3/run_cargo.ps1 解决
  （vcvars64 + 剥离 Git usr/bin 的 link.exe 遮蔽）。
- fmt：全仓层面 NOT_PASS 为基线既有状态（基线 HEAD 即 fmt-dirty），
  非本单引入；本单 6 个触及文件全部 fmt-clean。
