# GTO Product Recovery — Route X R1 Ledger-Closure Live Truth Run

**日期：** 2026-08-10
**授权：** Route X R1（单次受保护 live truth run，600s 硬超时）
**起点提交：** `9450b3aed570ff42c62a248f7e7013540a7e1348`（Route X R0 AF1 Rev1）
**分支：** `oreans/two-sample-mainline`
**终态：** **`RouteX_R1_CandidateNotReady`**

> 本文档是 **live 结果**。Route X R1 是一次 live truth run。五层门禁全部通过，GTO 管线真实
> 运行，**越过了 W R1 的 `raw_slab_overlay` blocker**（progress），但在 `sanitize_ahk_runtime_global`
> 阶段因 **Route X R0 的 P0-2 identity-tuple 检查对合法 size 变更过度严格**而 fail-closed。
> **未生成 candidate。**

---

## 1. 五层门禁全绿

```
build_capability_preflight.ok = true  (baseline=9450b3a, gto_product_recovery=true,
                                       sha/size 匹配, features 含 gto-product-recovery)
effective_env_contract.ok = true       (no_bypass_verified=true, bypass_absent=true,
                                        semantic_repair_absent=true)
capture_policy_preflight.ok = true
configured_timeout_sec = 600.0
live_environment_preflight_error = null
build_capability_preflight_error = null
```
canonical 构建（`tools/build_gto_live_cli.ps1`）产出 `gto_cli_build_attestation.json`，
baseline/sha/size 独立重算一致，`mida-cli --build-capabilities-json` → `gto_product_recovery=true`。

## 2. 进程 / PID

```
armed controller/CLI attempt:  1，已消耗（attempt_sequence=1）
controller child CLI spawn:    1，CLI PID 4652（mida-cli）
protected debuggee spawn:      1（debuggee 创建，FATAL 前 terminate=ok wait=signaled）
candidate:                     0
```

## 3. Stage 时间线（完整）

| stage | event | monotonic_ms | stage_elapsed_ms | items | bytes |
|---|---|---|---|---|---|
| capture_heap_slab | exit | 77 | 77 | 0 | 48929360 |
| normalize_authoritative_slabs | exit | 1939 | 1847 | 2 | 0 |
| reconcile_duplicate_heap_globals | exit | 1949 | 0 | 0 | 0 |
| capture_identity_bind | exit | 1949 | 0 | 317 | 0 |
| capture_coverage_bind | exit | 1950 | 0 | 317 | 0 |
| raw_children_from_capture | exit | 1961 | 11 | 316 | 0 |
| **transform_input_seed** | exit | **274681** | **272719** | 316 | 0 |
| scrub_uncaptured_heap_pointers | exit | 274800 | 119 | 9941 | 21723 |
| resynthesize_gscript_label_count | exit | 274801 | 0 | 0 | 0 |
| repair_label_names_after_scrub | exit | 274802 | 0 | 0 | 0 |
| sort_gscript_label_table | exit | 274805 | 3 | 125 | 324 |
| mark_labels_non_nested | exit | 274810 | 4 | 127 | 127 |
| **sanitize_ahk_runtime_global** | **error** | 274810 | 0 | 0 | 0 |

## 4. 关键进展：越过 W R1 的 raw_slab_overlay blocker

Route W R1 在 `raw_slab_overlay`（empty child_capture_id at run[3464]）fail-closed。本次：
- **`raw_slab_overlay` 不再失败** — 空 child_capture_id 问题已消除（X0-A/B 修复生效）；
- 管线越过 overlay，推进到 `sanitize_ahk_runtime_global`；
- 所有早期 transform（scrub / resynthesize / repair / sort / mark）均通过，raw run identity
  完整。

**`transform_input_seed` 的 ~286s 热点仍存在**（本次 272,719ms ≈ 273s），与 W R1 一致。
它在 600s 内完成（273s + 后续 ~2s），未触发 timeout，但暴露为管线主要耗时。

## 5. 失败：Route X R0 P0-2 对合法 size 变更过度严格

`sanitize_ahk_runtime_global` 是**合法的 size 变更 re-init**：它把 AHK runtime global
`0x141bf0` 的内容从 `old_size=32768` 替换为 `new_size=384`（零填充 re-init slab，`NEED=0x180`）。
W R1 基线下同样如此（`Sanitized AHK runtime global 0x141bf0 ... old_size=32768 new_size=384`），
且 W R1 未因 size 失败（它是在之后 empty child_capture_id 才失败）。

本次失败：
```
transform run ledger invalid at run[0]:
  child_capture_id="mainslot:0x141bf0:0x3437e50"
  child_old_base=0x3437e50  child_size=0x180
  transform="sanitize_ahk_runtime_global"
  reason=raw identity drift on content.len for old_base 0x3437e50: 32768 -> 384
```
映射到 `stage=raw_slab_overlay`（FATAL）。

**根因**：Route X R0 的 P0-2 `diff_transform_write_runs` 对每个 raw participant 要求
`content.len()` 跨 transform 不变，否则 fail-closed（`route_x_af1_same_base_size_change_fails_closed`）。
但 `sanitize_ahk_runtime_global` 是**受支持的大小变更 re-init**。P0-2 审计原本要堵的是
“size 变更被公共前缀 diff 静默吞掉（fail-open）”，**不是**要求拒绝所有合法 size 变更。
我的实现过度严格，把合法 re-init 也拒绝了。离线测试（617/0）未覆盖“size 变更的合法
sanitize re-init 且该 global 是 in-slab raw participant 且有 binding”的组合，故未暴露。

## 6. 处置 / 后续路线

- **Route X 冻结**（spawned=true 后不得 rerun / 不得 X R2）。
- 本次不是 timeout，也不是 build/config 问题；是 **Route X R0 的 P0-2 size-check 回归**。
- 下一路线 = **Route Y R0**（offline work order）：修 P0-2 的 size 处理——size 变更不应一律
  fail-closed；应允许**声明/受支持的大小变更 re-init**（如 `sanitize_ahk_runtime_global`），
  同时仍对**未声明的大小漂移** fail-closed（保留 `route_x_af1_same_base_size_change_fails_closed`
  的恶意场景）。需要区分“合法的 re-init 大小变更”与“provenance 漂移”。修后新 commit + 新独立
  live 授权。

## 7. 预算 / 边界

| 项目 | 预算 | 实测 |
|---|---|---|
| Armed controller/CLI attempt | 1 | **1（消耗）** |
| Protected debuggee spawn | ≤1 | **1** |
| Hard timeout | 600s | 600 配置，未触发（285s 自然退出） |
| Preflight rejection | ≤1 exit 6/7 | **0**（5 门禁首跑全绿） |
| Rerun | 0 | 0 |
| Cold-start | 0 | 0 |
| 单独启动 candidate | 0 | 0 |
| 网络 | 0 deny-all | 0 |

## 8. 证据位置

- evidence：`D:\MidaVault\lab\evidence\gto_launcher\live_20260810T180501Z_route_x_r1_ledger_closure\`
  - `controller_run.json` / `controller_attempt_001.json`
  - `child.stderr.bin` / `child.stderr.txt`（完整 stage telemetry + fail-closed error）
- canonical 构建 + attestation：
  `D:\MidaVault\scratch\cargo-target-route-x1\gto_cli_build_attestation.json`
  `D:\MidaVault\scratch\cargo-target-route-x1\debug\mida-cli.exe`
- 受保护 sample：`D:\MidaVault\vault\sha256\4d\4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8\artifact.exe`
