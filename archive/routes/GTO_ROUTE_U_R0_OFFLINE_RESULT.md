# GTO Product Recovery — Route U R0 Live Harness Environment Propagation and Armed-Run Preflight Closure

**日期：** 2026-08-10
**授权：** Route U R0（OFFLINE ONLY，0 live / 0 spawn / 0 candidate / 0 cold-start）
**起点提交：** `2abaabdda795375c68a8c86f900338b47f5738b9`
**分支：** `oreans/two-sample-mainline`
**终态：** **`RouteU_R0_AuditFix1ReviewRequested`**

> 本文档是 **离线结果**。Route U R0 是离线 harness 修复，非 live run，未生成 candidate。
> 2026-08-10：AF1 审计 `RouteU_R0_NotReady`（3 缺口：Popen 边界未自动测试、`--capture-policy`
> 参数缺失仍放行、未断言 exit 6），已全部补齐（UAF1-A..E）。

---

## 1. 背景

Route T R1 因 harness 配置错误无效化：`MIDA_GTO_NO_BYPASS=1` 未传入子进程，
权威 raw-capture / coverage / overlay 路径全部被 `no_bypass=false` 跳过。
Route T R0 代码未被 live 验证，但不得据此判坏。本工单修复环境传播与 spawn 前门禁。

## 2. 实现（U0-A .. U0-E）

### U0-A：环境传播闭环（`tools/gto_live_route_controller.py`）

新增 authorized 环境契约：
- `GTO_ENV_NO_BYPASS = "MIDA_GTO_NO_BYPASS"` / `GTO_ENV_BYPASS = "MIDA_GTO_BYPASS"` /
  `GTO_ENV_SEMANTIC_REPAIR = "MIDA_GTO_SEMANTIC_REPAIR"` / `GTO_ENV_CONTRACT_VALUE = "1"`；
- `validate_authorized_env(env, allowlist)`：验证 child env 满足契约
  （allowlist 携带 `MIDA_GTO_NO_BYPASS` 且 effective env 显式 `=1`，且 bypass /
  semantic-repair 变量缺席）。

### U0-B：armed-run 前置拒绝

`run_child` 在 `Popen` **之前**执行 env 契约 + capture-policy 校验：
- 任一违反（allowlist 缺 `MIDA_GTO_NO_BYPASS` / effective env 非 `=1` / bypass 或
  semantic-repair 存在 / `--capture-policy=` 文件不存在）→
  `live_environment_preflight_error` 记录，`spawned=false`，`pid=None`，
  **不 spawn**，controller 返回 exit 6（独特 preflight 码）；
- `protected_spawn` 保持 0，不消耗 route attempt。

### U0-C：effective environment 证据

`controller_run.json` 记录：
```
effective_env_contract:
  allowlist_carries_no_bypass / no_bypass_present / no_bypass_value /
  no_bypass_expected / no_bypass_verified / bypass_present / bypass_absent /
  semantic_repair_present / semantic_repair_absent / ok
capture_policy_preflight:
  capture_policy_arg_present / capture_policy_path / capture_policy_exists / ok
live_environment_preflight_error
spawned
```

### U0-D：离线测试（`tools/test_gto_live_route_controller.py`）

14/14 通过（原 U0 9 项不退化 + AF1 5 项）：
```
route_u_r0_no_bypass_missing_fails_before_spawn                 ✓
route_u_af1_no_bypass_reaches_popen_env                          ✓  (mock Popen 边界)
route_u_r0_no_bypass_propagates_to_child                         ✓
route_u_r0_bypass_vars_absent                                    ✓
route_u_r0_bypass_present_fails                                  ✓
route_u_r0_semantic_repair_absent                                ✓
route_u_r0_semantic_repair_present_fails                         ✓
route_u_r0_effective_env_matches_authorized_contract             ✓
route_u_af1_capture_policy_arg_missing_fails_before_spawn        ✓
route_u_af1_capture_policy_file_missing_fails_before_spawn       ✓
route_u_r0_argv_and_env_contract_is_armed_only_after_preflight   ✓
route_u_af1_all_preflight_rejections_return_exit_six             ✓
route_u_af1_capture_policy_reasons_distinct                      ✓
route_u_af1_no_popen_call_on_preflight_failure                   ✓
```

### UAF1-A..E 修复

- **UAF1-A**：mock `Popen` 边界测试——monkeypatch `ctrl.subprocess.Popen` 用 `FakePopen`
  捕获 env/argv/cwd，调用真实 `run_child`，断言 Popen 调用一次、`env[MIDA_GTO_NO_BYPASS]=="1"`、
  `MIDA_GTO_BYPASS`/`MIDA_GTO_SEMANTIC_REPAIR` 缺席、`spawned=true`、contract ok。
- **UAF1-B/C**：`--capture-policy` 参数**完全缺失** → fail-closed
  （`capture_policy_arg_missing`）；参数存在但文件缺失 → fail-closed（`capture_policy_file_missing`）。
  两者均 `spawned=false`、`pid=None`、`Popen 调用=0`、controller exit 6。
- **UAF1-D**：所有 preflight rejection 强制断言 `rc==6`、`spawned=false`、`pid=None`、
  `exit_code=None`、`live_environment_preflight_error` 存在；成功契约断言 Popen env
  `MIDA_GTO_NO_BYPASS=1` + bypass/semantic 缺席。

手动验证（零真实进程，mock Popen）：
- 缺 `MIDA_GTO_NO_BYPASS=1` → `spawned=false`，exit 6；
- 正确 `--set-env MIDA_GTO_NO_BYPASS=1` + 有效 capture_policy → `spawned=true`，
  Popen env 含 `MIDA_GTO_NO_BYPASS=1`。

### U0-E：文档与 commit 边界

改动文件（U0 授权边界内）：
```
tools/gto_live_route_controller.py
tools/test_gto_live_route_controller.py
docs/GTO_ROUTE_U_R0_OFFLINE_WORK_ORDER.md
docs/GTO_ROUTE_U_R0_OFFLINE_RESULT.md
```
未修改：acceptance / TrustToken / vault / resolver / protected sample / Route T R0 已提交 Rust 代码。
`docs/GTO_ROUTE_T_R1_LIVE_RESULT.md` 保持 untracked（不混入 U0 commit）。

## 3. 核验

| 项 | 结果 |
|---|---|
| controller Python 语法 | 通过 |
| `route_u_r0+af1` 测试 | **14/14**（原 9 不退化 + AF1 5） |
| Route T R0 已提交 Rust 代码 | 未修改 |
| `cargo fmt` / `git diff --check`（Rust） | 通过（无 Rust 改动） |
| HEAD | `2abaabd` 不变 |
| protected sample spawn | 0（mock Popen，零真实进程） |

## 4. 边界

OFFLINE ONLY：0 live / 0 spawn / 0 candidate / 0 cold-start / 0 rerun。
Route U R1 未授权。commit 待审计复审通过后执行。

**下一步：** 请审计负责人复审 Route U R0 Audit Fix 1。通过后 commit；Route U R1（单次
live truth run）需另行独立授权，且首要验证 child effective env `MIDA_GTO_NO_BYPASS=1`。
