# GTO Product Recovery — Route W R0 Build Capability Attestation and Preflight Evidence Preservation

**日期：** 2026-08-10
**授权：** Route W R0（OFFLINE ONLY，0 live / 0 spawn / 0 candidate）
**起点提交：** `ffa72eac245cc9432f7241913f3470eb5fdb0660`（Route V R0 AF1）
**分支：** `oreans/two-sample-mainline`

> 本文档是 **离线 work order**。Route W R0 是离线 harness 加固，非 live run。

---

## 1. 背景

Route V R1 single live run 被 **`RouteV_R1_InvalidatedByBuildConfig`** 无效化：唯一 armed
attempt 与 protected spawn 已消耗（`spawned=true`，pid=24776），但 mida-cli 二进制被
**默认 feature（无 `gto-product-recovery`）** 构建，其自身 GTO 门禁在 process creation 前
FATAL：
```
GTO route disabled in default build; rebuild with --features gto-product-recovery
```
受保护 sample 从未被 GTO 管线处理，无 capture / normalize / overlay / candidate，未发射任何
stage telemetry。Route U R1 的 ~110s 静默窗口**仍未被定位**。根因是构建时遗漏了
`--features gto-product-recovery`（Route U R1 的 `_build_u_r1_cli.cmd` 用了，V R1 没沿用）。

同时暴露第二个 harness 缺口：第一次 preflight rejection（attempt 1）的 evidence 被 attempt 2
覆盖，未单独保存（`controller_run.json` 只保留最新 attempt；`route_ledger.json` /
`preflight.json` / `resolved_source.json` 缺失）。

W0 的目标：把"正确 feature 构建"从人工记忆变成 **binary capability + attestation +
controller hard gate**，同时修掉 attempt evidence 覆盖。

## 2. 工单范围（W0-A .. W0-F）

### W0-A：唯一授权构建入口

新增 `tools/build_gto_live_cli.ps1`，固定执行：
```
cargo build -p mida-cli --features gto-product-recovery --offline
```
operator 不得手工拼 cargo 参数。脚本记录：cargo command / package / features / profile /
target dir / rustc version / cargo version / HEAD / binary path / binary size / binary sha256。

### W0-B：二进制自身 capability 查询

为 `mida-cli` 增加不接触 sample 的 `--build-capabilities-json`：
```json
{ "schema_version": "mida.build-capabilities/v1",
  "gto_product_recovery": true,   // 依 cfg!(feature=gto-product-recovery)
  "profile": "debug", "package": "mida-cli" }
```
default build 诚实返回 `gto_product_recovery:false`。禁止读取 sample / 启动 debuggee /
创建 candidate / 访问网络。用与生产 GTO 门禁**完全相同**的 `cfg!` 检查，保证查询与运行时
门禁不背离。

### W0-C：build attestation

构建完成后生成 `gto_cli_build_attestation.json`，含 baseline_commit / binary_path /
binary_sha256 / binary_size / cargo_package / cargo_profile / requested_features /
capability_probe_output / gto_product_recovery / created_utc。attestation 的 binary hash
与即将传给 controller 的 binary 独立重算一致。

### W0-D：controller spawn 前 capability 门禁

Controller 增加 `--build-attestation=<path>`（可选）。当提供时，在 Popen 前验证：
attestation 存在 / binary path == argv[0] / sha256 匹配 / size 匹配 / baseline == authorized
HEAD / requested_features 含 gto-product-recovery / capability true。任一失败 →
`build_capability_preflight_error`，`spawned=false`，`pid=null`，**exit 7**。
精确原因：`build_attestation_arg_missing` / `build_attestation_file_missing` /
`build_binary_path_mismatch` / `build_binary_digest_mismatch` / `build_binary_size_mismatch` /
`build_baseline_mismatch` / `gto_feature_not_requested` / `gto_capability_false`。
Exit 6 保留给 env/capture-policy；build capability 用独立 exit 7。
**未提供 `--build-attestation` 时，build gate 不生效（兼容 U/V 既有调用）。**

### W0-E：preflight evidence 不得覆盖

每次 controller invocation 写入独立 `controller_attempt_NNN.json`（NNN 单调递增，auto-derive
自 evidence 目录现有文件），以及最新指针 `controller_run.json`。历史 attempt 文件不得覆盖或
删除。每个 attempt 记录 attempt_sequence / armed / spawned / pid / exit_code /
environment_preflight / capture_policy_preflight / build_capability_preflight /
started_utc / finished_utc。armed attempt 与 preflight rejection 可独立计数。

### W0-F：离线测试

Rust（CLI）：
```
build_capabilities_json_is_valid_schema     # JSON 结构合法
build_capabilities_gto_flag_matches_cfg     # gto_product_recovery == cfg!(feature)
```
Python（controller）：
```
route_w_r0_default_build_reports_gto_false      # （Rust 断言机制 + 实际二进制探针）
route_w_r0_feature_build_reports_gto_true
route_w_r0_build_script_requests_gto_feature
route_w_r0_build_attestation_matches_binary
route_w_r0_missing_attestation_fails_before_popen
route_w_r0_digest_mismatch_fails_before_popen
route_w_r0_feature_false_fails_before_popen
route_w_r0_valid_attestation_reaches_mock_popen
route_w_r0_build_preflight_returns_exit_seven
route_w_r0_preflight_attempts_are_not_overwritten
route_w_r0_attempt_sequence_is_monotonic
```
使用 mock Popen / 临时无害 binary。不得启动 protected sample。

## 3. 验收门槛

- `cargo fmt --all -- --check` = 0
- `cargo test -p mida-pe` ≥ 599/0
- `cargo test -p mida-cli`（feature）：≥ 296/0/1，新 capability 测试通过
- `python tools/test_gto_live_route_controller.py`：U/V 不退化 + W0 全通过
- default build capability = false；feature build capability = true
- build-feature 缺失在 Popen 前 exit 7
- 所有 controller attempts evidence 永不覆盖
- `git diff --check` = 0

## 4. 提交边界

包含：
```
crates/cli/src/args.rs
crates/cli/src/commands.rs
crates/cli/src/lib.rs
tools/gto_live_route_controller.py
tools/test_gto_live_route_controller.py
tools/build_gto_live_cli.ps1        (新增)
docs/GTO_ROUTE_W_R0_OFFLINE_WORK_ORDER.md
docs/GTO_ROUTE_W_R0_OFFLINE_RESULT.md
```
排除：Route T coherence code、Route V stage timing code、slab/transform/overlay/planner 语义、
acceptance、TrustToken、vault、resolver、capture policy、protected sample。
必须排除：`docs/GTO_ROUTE_V_R1_LIVE_RESULT.md`（独立报告，除非授权边界改变）。
