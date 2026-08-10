# GTO Product Recovery — Route S R0 Audit Fix 1 Result

**日期：** 2026-08-09
**Route S R0 基线：** `3ef0e85`（Route R1 docs 闭锁）
**分支：** `oreans/two-sample-mainline`
**授权：** OFFLINE ONLY
**状态：** `RouteS_R0_AuditFix1ReviewRequested`（待审计负责人复审）

> ⚠️ Route S R1 **DENIED**。live 预算 0。未 commit。

---

## 1. 前轮 4 个阻断与本轮修复映射

### P1-1 — `S0EProductionScrubNotExercised`
**阻断**：S0-E scrub 测试用手工 `g[0].content[0x40..0x48].fill(0)`，非真实 scrub。

**修复**：测试改用**真实 `scrub_uncaptured_heap_pointers`**，构造一个指向 child 捕获范围外的外部指针 qword 于 +0x40，经 `apply_recorded_transform` 执行真实 scrub，再 overlay。run 归因到实际变化字节（offset 0x43, len 1，因 0x40000000 LE=[0,0,0,0x40,0,0,0,0] 仅 byte 0x43 变），capture_id 匹配，overlay 自然完成。

### P1-2 — `S0BExplicitExtentPathInvariantNotEnforced`
**阻断**：identity gate 只查 capture_id 非空，未验证 path↔extent 矩阵。

**修复**：`validate_raw_coherence_capture_identities` 强制矩阵：
- `DanglingEdge` → `ProbeWindow` + capture_id 前缀 `dangling_edge:`
- `MainSlot` → `ObservedAllocation`|`ProbeWindow`
- `GscriptChildLink`/`GscriptFirstHop` → `ProbeWindow`|`InteriorSubview`
- `StringBufferChild` → `ProbeWindow`
- `ImageInline`/`Synthetic` → 禁止
- capture_id 前缀 ↔ path 一致性（`dangling_edge:` id 必须 DanglingEdge path，`mainslot:` id 必须 MainSlot path）

**负向测试（6）**：DanglingEdge+MainSlot、DanglingEdge+non-ProbeWindow、Synthetic path、same-id+same-base+不同 size/path/extent。

### P1-3 — `S0BDuplicateIdentitySameBaseNotRejected`
**阻断**：`prior_base != live_ptr` 允许同 base 重复 snapshot。

**修复**：same-base 重复仅当完整 tuple `(base, size, extent, path)` 完全一致才允许；任何差异即 fail。

### P1-4 — `WorkspaceHermesArtifactUnclosed`
**阻断**：`.hermes/` untracked 使 worktree 非 clean。

**修复**：`.hermes/` 加入 `.gitignore`（最小 diff，无 CRLF 噪音）。worktree 现仅含 3 代码文件 + `.gitignore` + S0 结果文档。

## 2. 测试门禁（AF1 后）

| 门禁 | 实测 |
|---|---|
| fmt --check | 0 ✓ |
| R0-G / F.1 / F.2 | 27/9/25 ✓ |
| mida-pe | **556/0**（was 550; +6 identity）✓ |
| mida-cli gto | 296/0/1 ✓ |
| git diff --check | exit 0 ✓ |
| S0-E 合计 | 15/15 ✓ |

## 3. 当前仓库状态
- HEAD：`3ef0e85`（未变）
- 修改：`.gitignore` + `dump_process.rs` + `heap_global_snapshot.rs` + `raw_slab_coherence.rs`
- 新文档：`docs/GTO_ROUTE_S_R0_OFFLINE_RESULT.md`
- **未 commit**。未 live、未 spawn、未 candidate、未 cold-start。

## 4. 终态
`RouteS_R0_AuditFix1ReviewRequested`。Route S R1 **DENIED**。由审计负责人复审通过后，才可 commit 并转入下一判定。
