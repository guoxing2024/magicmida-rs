# GTO Product Recovery — Route W R0 Build Capability Attestation and Preflight Evidence Preservation

**日期：** 2026-08-10
**授权：** Route W R0（OFFLINE ONLY，0 live / 0 spawn / 0 candidate）
**起点提交：** `ffa72eac245cc9432f7241913f3470eb5fdb0660`（Route V R0 AF1）
**分支：** `oreans/two-sample-mainline`
**终态：** **`RouteW_R0_AuditFix1ReviewRequested`**

> 本文档是 **离线结果**。Route W R0 是离线 harness 加固，非 live run，未生成 candidate。
> 2026-08-10：AF1 审计 `RouteW_R0_NotReady`（P0：build gate 是 opt-in，operator 忘了传
> `--build-attestation` 仍可 Popen）。已修复（WAF1-A..E：build gate 改为强制，
> 删除 legacy bypass）。

---

## 1. 背景

Route V R1 因 **构建缺少 `gto-product-recovery` feature** 被无效化
（`RouteV_R1_InvalidatedByBuildConfig`）：armed attempt + protected spawn 已消耗，但
mida-cli 自身 GTO 门禁在 process creation 前 FATAL，受保护 sample 从未被 GTO 管线处理。
同时第一次 preflight rejection 的 evidence 被后续 attempt 覆盖，未单独保存。

W0 把"正确 feature 构建"从人工记忆变成 **binary capability + attestation + controller hard
gate**，并修掉 attempt evidence 覆盖。

## 2. 实现（W0-A .. W0-F）

### W0-A：唯一授权构建入口（`tools/build_gto_live_cli.ps1`，新增）

固定执行 `cargo build -p mida-cli --features gto-product-recovery --offline`，并记录 cargo
command / package / features / profile / target dir / rustc version / cargo version / HEAD /
binary path / size / sha256。operator 不得手工拼参数。构建后自动探测 capability 并生成
attestation；若 `gto_product_recovery` 为 false 则硬性失败。

### W0-B：二进制 capability 查询（`crates/cli/src/`）

`mida-cli --build-capabilities-json` 输出：
```json
{
  "schema_version": "mida.build-capabilities/v1",
  "gto_product_recovery": true,
  "profile": "debug",
  "package": "mida-cli"
}
```
- 用与生产 GTO 门禁**完全一致**的 `cfg!(feature = "gto-product-recovery")`（复用
  `plugin_host::gto_route_capability` 的检查），查询与运行时门禁不背离。
- 纯查询：不读取 sample / 不启动 debuggee / 不创建 candidate / 不访问网络。
- 实测：default build → `false`；feature build → `true`。
- 新增 `Command::BuildCapabilities`，在 `run()` 中于 logging 初始化前处理。

### W0-C：build attestation

`tools/build_gto_live_cli.ps1` 生成 `gto_cli_build_attestation.json`，含 baseline_commit /
binary_path / binary_sha256 / binary_size / cargo_package / cargo_profile /
requested_features / capability_probe_output / gto_product_recovery / created_utc。
- 实测 attestation 的 sha256 / size 与 binary 独立重算一致。
- 修掉 PowerShell `Set-Content -Encoding UTF8` 写 BOM 的问题：改 `-Encoding ascii`
  （无 BOM），并让 controller 以 `utf-8-sig` 读取（双保险）。

### W0-D：controller spawn 前 capability 门禁

Controller 新增 `--build-attestation=<path>` 与 `--authorized-head=<head>`。Popen 前验证
attestation / path / sha256 / size / baseline / features / capability；任一失败 →
`build_capability_preflight_error`，`spawned=false`，`pid=null`，**exit 7**。
精确原因覆盖（含 `build_binary_digest_mismatch` / `gto_capability_false` /
`gto_feature_not_requested` / `build_baseline_mismatch` / `build_attestation_arg_missing` /
`authorized_head_arg_missing`）。

#### W0-D AF1（WAF1-A/B/C）：build gate 强制，非 opt-in

原实现 `--build-attestation` 未传时返回 `ok=true`（legacy bypass），operator 忘传参数仍可
Popen —— 这正是 W0 要堵死的事故。AF1 改为**强制**：
- `attestation_path is None` → `ok=false`，`failure_reason=build_attestation_arg_missing`，
  Popen=0，spawned=false，pid=null，exit 7；
- `authorized_head` 缺失 → `ok=false`，`failure_reason=authorized_head_arg_missing`，
  exit 7，Popen=0；
- attestation 的 baseline 必须与 `authorized_head` **精确匹配**（空 baseline 或不等 →
  `build_baseline_mismatch`）；
- 删除 `build_attestation_required=False` 的 legacy bypass；U/V 的历史无-attestation 行为
  不再作为新 controller 的继续绕过口（U/V 需构造合法 attestation 才能到达 env/policy gate）。
- 实测：真实 attestation + 真实 mida-cli 二进制 → build gate `ok=true`，随后 policy 门禁
  （未给 `--capture-policy`）exit 6 —— 门禁链正确（build → env → policy）。

### W0-E：preflight evidence 不得覆盖

每次 invocation 写入单调 `controller_attempt_NNN.json`（auto-derive 自现有文件 +1）+ 最新
指针 `controller_run.json`。历史 attempt 文件永不覆盖/删除。
- 实测：两次失败 attempt 分别写入 `controller_attempt_001/002.json`；第三次 attempt=3 后
  auto-derive=4。

### W0-F：离线测试

Rust（`crates/cli/src/lib.rs`）：
```
build_capabilities_json_is_valid_schema      ✓  schema_version/package/字段齐全
build_capabilities_gto_flag_matches_cfg      ✓  gto_product_recovery == cfg!(feature)
```
Python（`tools/test_gto_live_route_controller.py`，+9）：
```
route_w_r0_build_script_requests_gto_feature   ✓  ps1 请求 --features gto-product-recovery
route_w_r0_build_attestation_matches_binary    ✓  sha/size 匹配
route_w_r0_missing_attestation_fails_before_popen ✓  build_attestation_file_missing，未 Popen
route_w_r0_digest_mismatch_fails_before_popen  ✓  build_binary_digest_mismatch，未 Popen
route_w_r0_feature_false_fails_before_popen    ✓  gto_capability_false，未 Popen
route_w_r0_valid_attestation_reaches_mock_popen ✓  合法 attestation 达 mock Popen
route_w_r0_build_preflight_returns_exit_seven  ✓  rc=7，spawned=false
route_w_r0_preflight_attempts_are_not_overwritten ✓ 001/002 均保留
route_w_r0_attempt_sequence_is_monotonic       ✓  attempt=3 后 auto-derive=4
```
（W0-F 的 default/feature build 能力报告由 Rust `build_capabilities_gto_flag_matches_cfg`
分别在 default（false）与 feature（true）构建下断言，且用真实二进制探针复核。）

#### W0-AF1（WAF1-D/E）测试（+6）

```
route_w_af1_missing_attestation_arg_fails_before_popen  ✓  build_attestation_arg_missing，Popen=0
route_w_af1_missing_authorized_head_fails_before_popen  ✓  authorized_head_arg_missing，Popen=0
route_w_af1_missing_both_fails_before_popen             ✓  build_attestation_arg_missing，Popen=0
route_w_af1_wrong_head_fails_before_popen               ✓  build_baseline_mismatch，Popen=0
route_w_af1_valid_attestation_and_head_reaches_mock_popen ✓ 合法 att+head 达 mock Popen=1
route_w_af1_attempt_auto_sequence_is_real               ✓  main() 两次调用 → 001/002，run=002，001 不变
```
删除原先“未传 attestation 仍允许 Popen”的 legacy-bypass 测试语义。

## 3. 验收结论

| 门禁 | 实测 |
|---|---|
| `cargo fmt --all -- --check` | **0** ✓ |
| `cargo test -p mida-pe` | **599/0** ✓ |
| `cargo test -p mida-cli`（feature） | **298/0/1** ✓（296 基线 + 2 新 capability） |
| `cargo test -p mida-cli`（default） | **296/0/1** ✓（gto=false，capability 测试通过） |
| `python tools/test_gto_live_route_controller.py` | **34/0** ✓（19 U/V + 9 W0 + 6 WAF1） |
| default build capability | **false** ✓ |
| feature build capability | **true** ✓ |
| build-feature 缺失 → Popen 前 exit 7 | ✓ |
| attempts evidence 永不覆盖 | ✓ |
| `git diff --check` | **0** ✓ |

## 4. 提交边界核验

W0 commit 仅含允许文件：
```
crates/cli/src/args.rs / commands.rs / lib.rs
tools/gto_live_route_controller.py
tools/test_gto_live_route_controller.py
tools/build_gto_live_cli.ps1        (新增)
docs/GTO_ROUTE_W_R0_OFFLINE_WORK_ORDER.md / OFFLINE_RESULT.md
```
Cargo.toml / Cargo.lock **未改动**。排除 Route T/V 语义代码、acceptance、vault、resolver、
protected sample。`docs/GTO_ROUTE_V_R1_LIVE_RESULT.md` 保持 untracked（独立报告，未夹带进 W0）。

## 5. 已知风险 / 说明

- `--build-attestation` 与 `--authorized-head` **均为强制**（WAF1）：两者缺失都会在 Popen 前
  exit 7 拒绝，operator 无法靠忘传参数绕过 capability/baseline 绑定。W R1 授权时必须两者都传。
- attestation 的 `binary_path` 必须与 controller argv[0] 精确一致（路径规范化后比较）。
- 真实 build gate 验证（真实 attestation + 真实二进制）在 W R1 live run 时是强制的；本次
  离线已用真实二进制探针验证 `ok=true`。

**终态：`RouteW_R0_AuditFix1ReviewRequested`**。待 Route W R1 授权：新 live budget，用
canonical 构建（attestation + authorized-head 强制）跑 600s 单次 live run，定位 Route U R1 的
~110s 静默窗口，并完整演练 Route T coherence 链。
