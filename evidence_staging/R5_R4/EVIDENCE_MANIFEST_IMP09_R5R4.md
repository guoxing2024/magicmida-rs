# IMP-09-CARRIER-R5-R4 — Raw Evidence Manifest（§0.2 从简口径）

工单: WORK_ORDER_IMP-09-CARRIER-R5-R4-TEARDOWN_20260825.md
分支: codex/imp09-carrier-r5-r2
基线 HEAD: 4c8661f04bfdcc0ca14d3499aeb5b0d825a89c10（R5-R3 audited PASS 242/0）
执行日期: 2026-08-25
状态声明: offline_mock=true / live_authorized=false / protected_sample=NOT_AUTHORIZED

## 1. 源文件 SHA-256（工作区最终态）

| 文件 | SHA-256 | 行数 |
|---|---|---|
| crates/cli/src/unpacker/walker_teardown.rs（新建） | 45aada4178f2cf4e8f2d5b043964bde16d28e90b78a154e2e6b4cc4326f75c1f | 805 |
| crates/cli/src/unpacker/antidebug_controller.rs | 95851b84afaa08fc4a3decd82fade6ab244da4ac20a338f10932b89f7c9e736a | 3165 |
| crates/cli/src/unpacker/mod.rs | 8b621adb56e1868a254bb3bed2e260079e0b085a3dc0ef0fbfa489bb0523622d | 2185 |
| docs/IMP09_CARRIER_R5_R4_TEARDOWN_DESIGN_20260825.md | c83ce782b532b536d7bc0f15af468e0031d09a5eae753963f1375eb395350189 | 162 |
| evidence_staging/R5_R4/REPORT_IMP09_R5R4_20260825.md | b652acd9df1da220fb89c3c350c6f840271db26f0290d3670c776efccfa60ce1 | 154 |
| evidence_staging/R5_R4/run_cargo.ps1 | 70ec341c678aa1db5d06dbc4697824899e64c4af3edea9cd8a91bb6947a27416 | 34 |

## 2. 原始测试输出 / 退出码（分开记录）

| 文件 | 内容 | 退出码 |
|---|---|---|
| cargo_test_r5r4.txt（55ff256f…） | cargo test -p mida-cli --lib imp09_r5r4（本单 17 个测试） | 0 |
| cargo_test_cli_lib.txt（1684ce6a…） | cargo test -p mida-cli --lib -- --test-threads=1（全量） | 101（3 个既有环境失败） |
| cargo_test_runtime.txt（abd82f55…） | cargo test -p mida-antidebug-runtime | 0 |
| cargo_fmt_check.txt（401a19cb…） | cargo fmt --all -- --check | 1（全仓既有 diff） |

### 测试统计

- 本单新增 17 个测试全部通过（walker_teardown 模块 12 + controller 5）。
- mida-cli --lib 全量（--test-threads=1）：524 passed; 3 failed; 1 ignored。
  3 个失败均为既有环境性失败（与基线一致，非本单引入）：
  - runner_preflight::tests::resolver_extended_path_prefix_cannot_bypass_sibling_boundary
  - runner_preflight::tests::resolver_rejects_symlink_into_subdirectory_escape
  - runner_preflight::tests::resolver_rejects_symlinked_sibling_escape
  （沙箱无符号链接创建特权；runner_preflight.rs 属禁止修改清单，未改动。）
- mida-antidebug-runtime：全部通过（lib 87 + tests 68/34/26/27 = 242，0 失败）。
- walker_session 43 个测试在 --test-threads=1 下全部通过（并行运行时的
  13 个失败为 walker 运行时单例进程全局互斥的既有测试间干扰，非本单引入；
  该现象在基线即存在，R5-R2/R5-R3 证据已记录同样模式）。

### cargo fmt -- --check（诚实口径）

- workspace 层面：NOT_PASS（退出码 1，既有 169 处 diff，全部位于非本单
  文件，基线 HEAD 即 fmt-dirty）。
- 本单 3 个触及文件全部 fmt-clean（rustfmt --edition 2021
  --config skip_children=true --check 退出码 0）：
  walker_teardown.rs / antidebug_controller.rs / mod.rs。

## 3. 出口门

```ini
R5_R4_TEARDOWN = PROVEN
R5_R4_EVENT_LEDGER = PROVEN
R5_R4_IDEMPOTENCY = PROVEN
R5_R4_ABORT_PATH = PROVEN
R5_R4_NO_LEAK = PROVEN
R5_R3_GATES_UNCHANGED = true
LIVE_AUTHORIZED = false
```

## 4. 环境说明

- MSVC 链接器路径问题由 evidence_staging/R5_R4/run_cargo.ps1 解决
  （vcvars64 + 剥离 Git usr/bin 的 link.exe 遮蔽）。
- fmt：全仓层面 NOT_PASS 为基线既有状态，非本单引入；本单 3 个触及文件
  全部 fmt-clean。
