# GTO-H6-LIVE-1 — 执行报告（终版，attempt_002 实弹）

**签发依据**: WORK_ORDER_GTO-H6-LIVE-1-R2_20260826.md（基于 GTO-H6-LIVE-AUTHORIZATION-1，commit e7767d7，owner 已签署）
**取代**: 上一版 NOT_EXECUTED 冲突报告（commit ba6ab40 归档）
**执行**: 唯一 worker · 2026-08-26
**基线 HEAD**: c8acd77（WIRING-2 sealed exports carrier channel，audited PROVEN；R2 工单在 fccf032 提交，实弹基线按工单 §1 为 c8acd77）
**构建**: cargo build -p mida-cli --features gto-product-recovery（SHA 9df90ecfa28710dbce50f8c2c4740a572694a9e8d859d16cc87534f4ca9d9031 锚定入 build attestation）
**账本**: GTO-H6-LIVE · used=2/2（**已收口**；后续任何实弹需新授权书）
**状态**: **LIVE-FAIL — STRUCTURAL_PRECONDITION_MISSING（child 实弹运行 828ms 后在 runtime 注入前置 fail-closed，dispatch 未发生）**

---

## 1. 结论（一句话）

**attempt_002 已实弹消耗（spawned=true, exit_code=1）**：gate 正确打开（NO_BYPASS=1 + LIVE_DISPATCH=1 同窗口）、preflight 全过（build attestation / capture policy / env contract / revision_match）、vault 样本正确创建进程（PID 1360）；但 post-attach runtime loader 在 pre-resume 前 fail-closed——**profile carrier 缺失（unpack argv 无 --preflight-dir → evidence_ctx=None → profile_identity=None）**，随后 **runtime DLL 不可达（MIDA_RUNTIME_AUTHORITY_DIGEST 编译时为空 + MIDA_RUNTIME_AUTHORITY/MIDA_RUNTIME_DLL env 未提供）**。步④ runtime 注入未完成 → LoaderResult 未产生 → 步④断言（walker_exports().is_some()）不可评估 → 步⑥ dispatch **未发生**（桥从未构造）。按原工单 §3 "任何步失败 → LIVE-FAIL + DIAGNOSTIC 归档"，判定 **LIVE-FAIL**。

## 2. 执行事实链（全部已核实，非猜测）

| # | 事实 | 证据位 |
|---|---|---|
| 1 | preflight 步①: resolve_gto_source_revision revision_match=true（authorized_vault 模式，vault 对象验证通过，SHA 11473d2e…） | `attempt_002/resolved_source.json` |
| 2 | 构建认证: mida-cli --features gto-product-recovery 构建成功，SHA 锚定 build attestation（baseline_commit=c8acd77），controller W0-D 校验 ok | `evidence_staging/H6_LIVE1_R1/gto_cli_build_attestation.json` + `attempt_002/controller_run.json` build_capability_preflight.ok=true |
| 3 | 授权窗口: MIDA_GTO_NO_BYPASS=1 且 MIDA_GTO_LIVE_DISPATCH=1 同一 driver 进程设置，child 通过 allowlist 获得（effective_env_contract.ok=true, no_bypass_verified=true）；MIDA_GTO_OBSERVATION_ONLY **未设置**（正确，非观察模式） | `attempt_002/controller_run.json` effective_env_contract + auth_window.json |
| 4 | AUTH_CLEARED: 两变量在 child 退出后立即从 driver 进程清除（no_bypass_after=<unset>, live_dispatch_after=<unset>），双清除证据落盘 | `attempt_002/auth_window.json` |
| 5 | 样本正确创建（PID 1360, image_base 0x140000000, .text section → text_is_plain_for_attach=true → post-attach 路径） | `attempt_002/child.stderr.txt` |
| 6 | **fail-closed 点 1**: post-attach runtime loader (pre-resume) failed: verified profile carrier unavailable: no attested profile identity | 同上 |
| 7 | **fail-closed 点 2**: anti-debug controller failure: DependencyUnavailable (AntiDebugRuntimeUnavailable): mida-antidebug-runtime-x64.dll not found | 同上 |
| 8 | 目标终止干净（terminate_and_wait: ownership=OwnedPostAttach, terminate=ok, wait=signaled），无残留进程 | 同上 |
| 9 | dispatch 步⑥: **未发生**（loader 未完成 → LoaderResult 未产生 → post-attach 构造点无法取到 walker_exports → 桥未构造 → execute gate 未达） | `attempt_002/child.stderr.txt`（无任何 dispatch 日志） |
| 10 | 120s 上限未触碰（elapsed=828ms），无超时 kill | `attempt_002/controller_run.json` timed_out=false |

## 3. 工单 §3 判据对照表（二值）

| 判据 | 要求 | 实际 | 判定 |
|---|---|---|---|
| LIVE-PASS | 步⑥ raw status==0 且 步⑦ 两轮 DONE + digest MATCH 且 步⑧ Released+账本空 | 步⑥ 未达（dispatch 未发生），无 raw status | **NOT MET** |
| LIVE-FAIL | 任何步失败/崩溃/超时 → DIAGNOSTIC 归档 + used+1 | child exit=1 fail-closed（步④ runtime 注入前置缺失），已归档 | **DECLARED — LIVE-FAIL** |
| 账本收口 | used=2/2，后续需新授权书 | used=2/2 **已收口** | **CLOSED** |

> 说明：本 FAIL 是**结构性前置缺失**（工单 argv 未含 --preflight-dir；runtime 编译时 digest 未注入构建；runtime env 未进 allowlist），不是 dispatch 机制失败（T1-T18 离线全绿已证明桥与通道正确）。按工单 §3 "FAIL 不自动重试设计变更；attempt_002 仅允许总审计分析后的参数级修正"——**本次不重试**，交总审计决策。

## 4. 账本与轮次

- GTO-H6-LIVE: used=1/2（attempt_001 观察模式退出）→ attempt_002 实弹消耗第 2 格 → **used=2/2 收口**。
- **后续任何实弹（含参数级修正后的 attempt_003）需新授权书**（R2 工单 §3）。
- attempt_002 账本消耗成立（child 实际 spawn 并运行了 828ms，非 preflight 拒绝——preflight 全过才 spawn）。

## 5. 出口门 ini（实测值）

```ini
LIVE_VERDICT = LIVE-FAIL
VERDICT_CLASS = STRUCTURAL_PRECONDITION_MISSING
LEDGER_USED = 2/2             ; CLOSED - further live shots require a new authorization
AUTH_CLEARED = true           ; both MIDA_GTO_NO_BYPASS and MIDA_GTO_LIVE_DISPATCH set+cleared in single window, dual clear records in auth_window.json
NO_BYPASS_HONORED = true      ; MIDA_GTO_NO_BYPASS=1 verified in effective_env_contract; no bypass/semantic-repair vars
GATE_OPEN_VERIFIED = true     ; live_dispatch_gate() inputs both = "1" in child env (no_bypass=1, live_dispatch=1)
DISPATCH_REACHED = false      ; step 6 not reached - loader fail-closed pre-resume
STEP4_ASSERT = NOT_EVALUATABLE; no LoaderResult produced (loader failed before exports resolution)
TEARDOWN_CLEAN = true         ; target terminated cleanly (terminate=ok, wait=signaled); no session established
OREANS_GATE_RECHECK = 17/17   ; tools/verify_adr7_closeout.ps1 PASS (17 checks, 0 warnings)
```

## 6. 交付物清单（evidence_staging/H6_LIVE1_R1/attempt_002/ 全量）

- `resolved_source.json` — preflight 步①（revision_match=true）
- `auth_window.json` — 授权窗口设置 + 双变量 AUTH_CLEARED 证据
- `env_snapshot.json` — 现场 env 快照（child effective env + 缺失前置清单）
- `child.stderr.bin/.txt` — 权威 stderr raw（含两个 FATAL fail-closed 点）
- `child.stdout.bin/.txt` — stdout raw
- `controller_run.json` + `controller_attempt_002.json` — controller 生命周期（preflight 全过、spawned=true、exit=1、elapsed=828ms、timed_out=false）
- `capture_policy.json` — capture policy（与 attempt_001 相同）
- `attempt_002_diagnostic.json` — DIAGNOSTIC 归档（判定、根因、证据索引）
- `candidate/` — 空（loader 未完成，无候选产物，fail-closed 正确）

## 7. AUTH_CLEARED / NO_BYPASS / teardown 证据指针

- **AUTH_CLEARED**: `attempt_002/auth_window.json` — no_bypass=1 + live_dispatch=1 于 19:08:02.724Z 设置，19:08:03.617Z 清除；两变量 after 均 `<unset>`（双清除记录）。禁止入全局/profile 环境已满足（变量仅存在于 driver 子进程 env，bash 外层未泄漏——`echo $MIDA_GTO_LIVE_DISPATCH` 为空）。
- **NO_BYPASS 验证**: `controller_run.json` effective_env_contract: no_bypass_present=true, no_bypass_value="1", no_bypass_verified=true, bypass_absent=true, semantic_repair_absent=true（ok=true）。
- **teardown**: 无 session 建立（loader fail-closed），无分配需释放；目标进程由 mida-cli 自身 terminate_and_wait 干净终止（terminate=ok, wait=signaled, summary=OwnedPostAttach）→ TEARDOWN_CLEAN=true。

## 8. 冲突消除所需（供总审计决策，需新授权书）

1. **unpack argv 增加 `--preflight-dir=<dir>`**：先运行 `/offline-preflight` 生成 GTO case（gto_launcher）的 envelope + Ready 报告（含 snapshot capture、verifier 独立校验），使 `evidence_ctx.profile_identity()` 有值（loader 步④前置 1）。
2. **构建时注入 `MIDA_RUNTIME_AUTHORITY_DIGEST` + `MIDA_RUNTIME_SOURCE_REF`**：用 vault 中 adr7b_b4/b5 权威 manifest 的 SHA-256 与 source_ref（7e65cf65…）编译进 mida-cli（build_gto_live_cli.ps1 需扩展或在构建命令前设 env），并重新锚定 build attestation（loader 步④前置 2）。
3. **child allowlist 增加 `MIDA_RUNTIME_AUTHORITY` + `MIDA_RUNTIME_DLL`**：指向 vault 权威 manifest 与 runtime DLL（D:/MidaVault/lab/evidence/adr7b_b4_binding_correction/runtime/mida_antidebug_runtime.dll）（loader 步④前置 3）。
4. 以上均为**参数/准备级修正**（无代码语义修改），但按 R2 工单 §3 需**新授权书**后方可执行 attempt_003。
