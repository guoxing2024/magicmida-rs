# GTO Product Recovery — Route U R0 Live Harness Environment Propagation and Armed-Run Preflight Closure

**日期：** 2026-08-10
**授权：** Route U R0（OFFLINE ONLY，0 live / 0 spawn / 0 candidate / 0 cold-start）
**起点提交：** `2abaabdda795375c68a8c86f900338b47f5738b9`
**分支：** `oreans/two-sample-mainline`

> 本文档是 **离线 work order**。Route U R0 是离线 harness 修复，非 live run。

---

## 1. 背景

Route T R1 单次 live run 被无效化（`RouteT_R1 = InvalidatedByControllerConfig`）：

- controller `environment_allowlist = [SystemRoot, WINDIR, PATH, TEMP, TMP, COMSPEC]` 不含
  `MIDA_GTO_NO_BYPASS`；
- 未传 `--set-env MIDA_GTO_NO_BYPASS=1`；
- 子进程 `no_bypass=false` → 权威 raw-capture / coverage / overlay 路径（`capture_slab_normalize`
  / `capture_identity_bind` / `capture_coverage_bind` / `transform_input_seed` /
  `raw_slab_overlay`）全部被条件跳过；
- `candidate_slab_count=0` 反映 `all_slabs`（因 no_bypass 跳过而为空），**不是** Route T R0
  coverage 失败。

结论：Route T R0 代码未被 live 验证，但**不得据此判坏**。Route T 冻结，Route T R2 拒绝。
本工单修复 live harness 的环境传播与 spawn 前门禁，为将来真实演练 Route T R0 铺路。

## 2. 工单范围（U0-A .. U0-E）

### U0-A：环境传播闭环

修复 `tools/gto_live_route_controller.py`，使 `MIDA_GTO_NO_BYPASS=1` 在
controller → CLI child → dump process 中**显式传播**：
- 新增 `GTO_ENV_NO_BYPASS` / `GTO_ENV_BYPASS` / `GTO_ENV_SEMANTIC_REPAIR` 常量与
  `GTO_ENV_CONTRACT_VALUE = "1"`；
- 新增 `validate_authorized_env(env, allowlist)`，验证 child env 的 authorized 契约；
- 不依赖父进程隐式继承，不依赖 operator shell 环境。

### U0-B：armed-run 前置拒绝

在 protected spawn 之前新增硬门禁：
- allowlist 不含 `MIDA_GTO_NO_BYPASS`，或
- effective env 未明确设置 `MIDA_GTO_NO_BYPASS=1`，或
- bypass / semantic-repair 变量存在，或
- `--capture-policy=` 文件不存在

→ 在 spawn 前失败，`stage=live_environment_preflight`，`protected_spawn=0`，`spawned=false`。

### U0-C：effective environment 证据

controller 记录非敏感 effective-env 证据到 `controller_run.json`：
```
effective_env_contract:
  allowlist_carries_no_bypass
  no_bypass_present / no_bypass_value / no_bypass_expected / no_bypass_verified
  bypass_present / bypass_absent
  semantic_repair_present / semantic_repair_absent
  ok
capture_policy_preflight:
  capture_policy_arg_present / capture_policy_path / capture_policy_exists / ok
```

### U0-D：离线测试

新增 `tools/test_gto_live_route_controller.py`，至少：
```
route_u_r0_no_bypass_missing_fails_before_spawn
route_u_r0_no_bypass_propagates_to_child
route_u_r0_bypass_vars_absent
route_u_r0_semantic_repair_absent
route_u_r0_effective_env_matches_authorized_contract
route_u_r0_capture_policy_missing_fails_before_spawn
route_u_r0_argv_and_env_contract_is_armed_only_after_preflight
```
关键：环境错误不消耗 protected spawn；环境错误不启动第二次 controller。

### U0-E：文档与 commit 边界

U0 commit 只包含：
- `tools/gto_live_route_controller.py`（env 传播 + preflight 门禁）；
- `tools/test_gto_live_route_controller.py`（离线测试）；
- 本 work order + result 文档。

不得修改：
- acceptance / TrustToken / vault / resolver / protected sample；
- Route T R0 已提交代码（`2abaabd` 中的 6 个 Rust 文件）。

`docs/GTO_ROUTE_T_R1_LIVE_RESULT.md` 保持 untracked，**不混入** U0 commit。

## 3. 边界

OFFLINE ONLY：0 live / 0 spawn / 0 candidate / 0 cold-start / 0 rerun。Route U R1 需另行独立授权。
