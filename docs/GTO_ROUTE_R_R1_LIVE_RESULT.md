# GTO Product Recovery — Route R R1 Probe-Scoped Coherence End-to-End Live Truth Run

**日期：** 2026-08-09
**授权：** Route R R1（单次受保护 live truth run）
**起点提交：** `39602dba889891b66e5e5e9098b1169ab00444bc`
**分支：** `oreans/two-sample-mainline`
**终态：** **`RouteR_R1_CandidateNotReady`**（已接受）

> 本文档是 **live 结果**。Route R R1 是 live truth run，不是 offline 修复。

---

## 1. 终态结论

本次唯一受保护 live run 在 **`raw_slab_overlay`** 阶段 **fail-closed**，**未生成 candidate**。

```
terminal_status:  RouteR_R1_CandidateNotReady
failure_stage:    raw_slab_overlay
failure_reason:   TransformPreimageDrift
child=0x9a4d40  size=0x710  slab_offset=0x1d40
C=0x50 S=0x50 T=0x50
transform=[scrub_uncaptured_heap_pointers]
```

## 2. 根因（经审计重分类，最终归属）

> ⚠️ **原报告中的 `ScrubWriteRunShapeIncompatible` 归因已被审计推翻。**

**实际根因链：**

```
DanglingEdgeCaptureIdentityMissing
→ EmptyTransformPreimageBindingCaptureId
→ ExactBindingRejected
```

1. **dangling-edge snapshot 生产代码创建了空 identity**
   `heap_global_snapshot.rs` 的 dangling-edge 构造使用：
   ```
   extent_kind: CaptureExtentKind::default(),   // = ProbeWindow
   extent_evidence: CaptureExtentEvidence::default(),  // capture_id="", path=MainSlot
   ```
   尽管代码已有 `CapturePath::DanglingEdge` 变体，生产构造却没有使用它。

2. **空 identity 被带入 raw child 和 binding**
   `raw_children_from_capture` 复制 `capture_id`，seeding 生成 `binding.capture_id = raw.capture_id`。所以 child `0x9a4d40` 的 binding capture ID 仍为空。

3. **Q0-C exact binding 拒绝空 capture ID**
   `raw_slab_coherence.rs` exact filter：`!b.capture_id.is_empty()`。空 ID → exact binding 数量为 0 → 立即返回 `TransformPreimageDrift`（`child_byte_offset=0`）。**此检查发生在全局 run-ledger validator 之前。**

4. **`C=S=T=0x50` 印证 binding 失败**
   三个字节完全相等，说明这不是 transform write byte 冲突，而是 byte replay 前的身份/binding 失败。`transform=["scrub_uncaptured_heap_pointers"]` 只说明该 child 被 scrub 改过某些位置，不证明 malformed run 属于 byte 0，也不证明 validator 拒绝了该 run。

## 3. 认可的 live 结论

- Route P 的 `child 0x8aa5f8 +0x28` 阻断已消失；
- overlay 已处理并越过该较低地址 child，随后才到达 `0x9a4d40`；
- captured-alias 修复真实生效；
- synthetic class/title identity 仍正确（class=0x10020, title=0x10000）；
- candidate 未生成；
- 单次 attempt、单次 protected spawn、零 rerun、零 cold-start；
- PID 1500 与 CLI PID 28356 均已结束；
- candidate 目录为空；
- firewall 已清理；
- 没有虚报 `ScriptRecovered` / `UiRecovered` / `OepReached`。

## 4. 预算执行

| 预算项 | 上限 | 使用 |
|---|---|---|
| route attempt | 1 | 1 |
| protected spawn | 1 | 1（debuggee PID 1500, terminated cleanly） |
| rerun / cold-start | 0 | 0 |
| candidate | 1（natural） | 0 |

CLI PID 28356, exit 1, process tree `exited_naturally`。

## 5. 证据

工作区：`D:\MidaVault\lab\evidence\gto_launcher\live_20260809T165952Z_route_r_r1_probe_scoped_coherence\`
- `preflight.json` / `resolved_source.json` / `controller_run.json`
- `child.stdout.txt` / `child.stderr.txt`
- `route_ledger.json`（终态 `RouteR_R1_CandidateNotReady`）
- `GTO_PRODUCT_RECOVERY_ROUTE_R_R1_REPORT.md`

## 6. 边界（已遵守）

- 未 rerun、未冷启动、未手工修补 candidate、未伪造 acceptance。
- 仓库代码未改动：HEAD `39602db`，tracked files unchanged。
- 当前 worktree 有一个 untracked 报告文档（本文件），非 clean 但代码未修改。

## 7. 结论

`RouteR_R1_CandidateNotReady`，**已接受**。Route R **冻结**。根因已重分类。下一步进入 **Route S R0**（Capture-Identity Closure and Precise Overlay Diagnostics，offline only）。
