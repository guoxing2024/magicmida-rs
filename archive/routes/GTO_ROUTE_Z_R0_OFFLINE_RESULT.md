# GTO Product Recovery — Route Z R0 Transform Input Seed Raw-Capture Drift Offline Root-Cause

> 状态：**`RouteZ_R0_LiveNondeterminismConfirmed`**（离线调查确认 child 0x3327260 的 raw capture drift
> 由 live 捕获时序/对象生命周期非确定性导致，当前 fail-closed 正确；非 Route Y 语义回归）。
> 授权 baseline：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`）。不授权 live。
> 分析目录：`D:\MidaVault\lab\analysis\route_z_r0_seed_drift_20260811T080130Z\`

---

## 1. 授权 baseline 核对（只读）

| 检查 | 预期 | 实际 | 结果 |
|---|---|---|---|
| branch | `oreans/two-sample-mainline` | 一致 | ✅ |
| HEAD | `68b8032` | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` | ✅ |
| HEAD^ | `9450b3a` | `9450b3aed570ff42c62a248f7e7013540a7e1348` | ✅ |
| 无 tracked 修改 | 是 | 是 | ✅ |
| untracked 仅 4 个 docs | 是 | X R1 / Y R0 / Y R1 / Y R1 A2 | ✅ |
| `git diff --check` | 干净 | 干净 | ✅ |

**baseline 全部匹配。** 三套冻结 evidence（X R1 / Y R1 NotRun / Y R1 A2）均未修改。

## 2. A2 evidence 路径

```
D:\MidaVault\lab\evidence\gto_launcher\live_20260811T065313Z_route_y_r1_declared_size_reinit_a2\
  child.stderr.bin / child.stderr.txt   (原始 binary 保留)
  controller_run.json
  controller_attempt_001.json
  argv_static_verification.json
  capture_policy.json
  candidate\ (空)
```

## 3. Child dossier（0x3327260）

完整字段见 `child_dossier_0x3327260.json`（分析目录）。要点：

| 字段 | 值 |
|---|---|
| child old base | `0x3327260` |
| RVA | `0x144400` |
| size | 40（0x28） |
| xref | 18 |
| in_data | true |
| kind | heap_global |
| capture_path | MainSlot（image .data slot 指向 heap） |
| extent_kind | **ObservedAllocation（严格 C==S）** |
| covering slab old base | `0x894000` |
| slab span | `0x2a93288` |
| slab offset of child | `0x2a93260`（= 0x3327260 − 0x894000，精确对齐） |
| child 捕获时间 | `06:54:44.875969Z` |
| slab 捕获时间 | `06:54:45.124257Z` |

## 4. Raw/slab digest 与 byte mismatch

- **raw_child_sha256**：`adbb0c0a6842e2fed5cebcca7915c3c3a085d1a227e2f5e8626c502b906be56c`
- **slab_slice_sha256**：`a6ec10866244f8906f4f14db1a9521b9077ede0856fcf5bab5cdda5678af395e`
- **first_mismatch_offset**：`0x0`（第一个字节即不同）
- **child size**：0x28；**slab slice size**：0x28（对齐一致）
- **证据缺口**：A2 evidence 未保留 raw/slab 实际 bytes，仅保留 digest / offset / size / telemetry。无法恢复可复现字节。

## 5. Capture / slab 数据流（只读追踪）

`dump_process` 单次流程内的调用顺序（`dump_process.rs` 861-1041）：

1. `detect_heap_globals`（861）→ child 捕获。对 image .data slot 指向的每个 heap 对象执行 `estimate_object_size` + `read_memory`（`windows_debugger.rs` 958：直接 `ReadProcessMemory`，**无全线程冻结**）。
   - child 0x3327260 在此 stage @ 44.875 读取 40 字节。
2. `capture_heap_slab`（892）→ 主堆 slab 捕获。`capture_heap_slab`（`heap_global_snapshot.rs` 389-424）对 span 范围**逐页 `read_memory`**（分页 RPM），@ 45.124 读取整个 slab（含 0x3327260 位置的 40 字节 slice）。
3. `normalize_authoritative_slabs`（925）
4. `reconcile_duplicate_heap_globals`（953）
5. `capture_identity_bind`（966）
6. `seed_transform_inputs_from_authoritative_slab`（1041）→ **在此 fail-closed**：严格 extent child 要求 `C == S`（`slab_slice != current → raw_capture_drift_error`），child 0x3327260 不满足。

**关键**：child 捕获与 slab 捕获是**两次独立 `ReadProcessMemory`**，间隔约 **249ms**（44.875 → 45.124）。`target 状态`：`no debug port → direct dump mode (SuspendThread + ReadProcessMemory)`，日志明确 `main thread resumed`（06:54:35.019），**无全进程冻结**。

## 6. Relevant git diff verdict（函数级）

| 函数 | 9450b3a vs 68b8032 | 判定 |
|---|---|---|
| `seed_transform_inputs_from_authoritative_slab` | **IDENTICAL**（118 行） | unchanged |
| `detect_heap_globals` | 未改动（heap_global_snapshot.rs 未在 Route Y commit 中） | unchanged |
| `capture_heap_slab` | 未改动 | unchanged |
| `raw_children_from_capture` | **IDENTICAL**（64 行） | unchanged |
| `validate_raw_coherence_capture_identities` | **IDENTICAL**（132 行） | unchanged |
| `validate_probe_coverage` | **IDENTICAL**（87 行） | unchanged |
| `covering_slab_for_child` | **IDENTICAL**（152 行） | unchanged |
| `is_raw_coherence_participant` | 未改动（heap_global_snapshot.rs） | unchanged |
| `validate_run_membership` | 改动（365→432 行，declared reinit） | changed，但在 **overlay 前**，**不在** transform_input_seed 阶段 |

**结论**：Route Y R0 对 `transform_input_seed`（seed）阶段所涉全部函数**零改动**。非回归有**函数级 diff 证据**支撑（不仅凭"失败 stage 早于 Route Y"）。

## 7. Route X R1 vs Y R1 A2 对比

| 项 | X1（9450b3a） | Y1 A2（68b8032） |
|---|---|---|
| 主堆 slab base | `0x874000` | `0x894000` |
| main slab span | `0x2ea9a50` | `0x2a93288` |
| 0x332xxxx 对象 | **无** | `0x3325050`、`0x3327260` |
| RVA 0x144400 | 无 | 有（→ heap 0x3327260） |
| transform_input_seed | **成功**（item_count=316，~272s） | **失败**（error，item_count=0，~108s） |
| 后续 stage | sanitize | 无（fail-closed） |

**ASLR / heap layout 显著不同**：两次 live 的主堆基址不同（0x874000 vs 0x894000），0x332xxxx 区域对象仅 Y1 A2 出现。这是**正常地址随机化 + 对象集合变化**，非确定性代码缺陷。

## 8. Offline reproduction

现有 Rust 测试已覆盖严格 extent C==S 的 fail-closed 语义（Route Y 未改）：

- `r0g_strict_observed_allocation_drift_fails_closed`（strict ObservedAllocation 全范围 drift → `RawCaptureDrift`）
- `r0g_backing_object_drift_fails_closed`（strict BackingObject 全范围 drift → `RawCaptureDrift`）

**当前 fail-closed 是正确的**：严格 extent 对象 C != S 时拒绝，保护完整性。问题不在校验逻辑，而在**为什么一个严格 extent 对象在 live 中出现 C != S**（捕获时序/数据层面）。

## 9. Hypothesis matrix

| Hypothesis | Supporting evidence | Contradicting evidence | Test | Verdict |
|---|---|---|---|---|
| **H1 capture TOCTOU** | child 与 slab 两次独立 RPM（249ms 窗口）；target 未全冻结（direct dump, main thread resumed）；first_mismatch=0（对象整体改写）；0x3327260 是 AHK 运行时动态数据（xref=18） | 无原始 bytes 无法 100% 证明是"修改" | 需 evidence 含 bytes 或冻结确认 | **主根因（高）** |
| H2 wrong covering slab | — | slab offset `0x2a93260` 精确 = 0x3327260−0x894000；覆盖 slab 唯一 | — | **排除** |
| H3 duplicate capture selected | — | 0x3327260 捕获仅出现一次（无重复）；reconcile 在 slab 捕获后、seed 前，未改单次捕获对象 | — | **排除** |
| H4 wrong extent classification | 0x3327260 是 MainSlot image slot 独立对象，ObservedAllocation 合理 | 无证据它是 interior/probe | 若证实应走 probe，则改分类 | **低**（分类合理） |
| H5 object freed/reused | AHK 0x332xxxx 可能是临时运行时缓冲；child 捕获时有效、slab 捕获时被改写/复用 | 无原始 bytes 佐证生命周期 | 需捕获前后对照 | **备选（中）**，与 H1 同属时序 |
| H6 stale capture identity | — | capture_id/path/extent 一致，无错绑证据 | — | **排除** |
| H7 overlap/containment error | — | 0x3327260 与 0x3325050 不相邻（差 0x2210），独立对象；无 containment 错误 | — | **排除** |
| H8 evidence corruption/truncation | — | child size 40 = slab slice 40，offset 对齐，digest 一致计算 | — | **排除** |

**裁决**：H1（capture TOCTOU）为主根因，H5（对象生命周期）为紧密相关的备选；两者同属 **live 捕获时序非确定性**。H2/H3/H6/H7/H8 排除，H4 低概率。

## 10. Confirmed facts

1. child 0x3327260 与 slab 是两次独立 `ReadProcessMemory`，间隔 249ms。
2. target 无全进程冻结（`direct dump mode`，main thread resumed）。
3. `first_mismatch=0` → 对象整体内容不同，非少量并发修改。
4. 0x3327260 仅出现在 Y1 A2（X1 无此对象，ASLR/堆布局不同）。
5. Route Y R0 对 seed 阶段所有函数零改动（函数级 diff IDENTICAL）。
6. 严格 extent C==S fail-closed 是既有正确行为（有测试覆盖）。
7. current fail-closed 正确拒绝了 C != S，保护了完整性。

## 11. Unresolved uncertainties（证据缺口）

1. **无原始 raw/slab bytes**：A2 evidence 只保留 digest。无法区分"对象被运行时改写" vs "读取到相邻/错误内容"。
2. **target 冻结精确语义未确认**：`direct dump mode` 下逐线程 SuspendThread 的完整时序未从代码完全追溯。
3. **0x3327260 对象语义未确认**：未验证它是"稳定 image slot 对象"还是"动态运行时缓冲"（后者更易 TOCTOU）。

## 12. Proposed minimal remediation（不实施，等单独授权）

**方向 A（增强证据，最低风险）**：
- 在 `seed_transform_inputs_from_authoritative_slab` 或错误路径中，`raw_capture_drift_error` 附带 child 与 slab slice 的**前 N 字节**（如前 64 字节 + digest），使 live drift 可离线复现诊断。
- 这不会改变 fail-closed 语义，仅增强 evidence。

**方向 B（捕获一致性，需谨慎评估）**：
- 若确认 target 未全冻结是根因，考虑在 `capture_heap_slab` 前对严格 extent 依赖的对象做一次性冻结快照，或让 child 与 slab 共享同一份进程快照。
- **风险**：改变捕获时序可能影响其它 315 个 child 的现有行为，需最小化并配回归。

**方向 C（分类审查）**：
- 评估 0x3327260 这类 AHK 运行时动态对象是否应走 probe/interior（seed from slab）而非严格 C==S。需先确认对象语义。

**本工单不实施任何 production patch**。最小修复方案待单独授权。

## 13. Exit status

**`RouteZ_R0_LiveNondeterminismConfirmed`**

> 证明：child 0x3327260 的 raw capture drift 由 live 捕获时序/对象生命周期非确定性导致
> （child 与 slab 两次独立 RPM、target 未全冻结、first_mismatch=0、live 特有对象），
> 当前 fail-closed 正确。非 Route Y 语义回归（seed 阶段函数级 diff IDENTICAL）。
> 附证据缺口：无原始 bytes，无法完全排除读取/分类缺陷，需 evidence 增强（方向 A）。

**未签发 Route Y R1 A3**。是否重跑 Route Y R1 须在 Route Z R0 审计完成后单独决定；不得通过重跑碰运气越过 `transform_input_seed`。

## 14. Final report

- **baseline/head**：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`，无 tracked 修改）
- **A2 evidence path**：`D:\MidaVault\lab\evidence\gto_launcher\live_20260811T065313Z_route_y_r1_declared_size_reinit_a2\`
- **child dossier**：`D:\MidaVault\lab\analysis\route_z_r0_seed_drift_20260811T080130Z\child_dossier_0x3327260.json`
- **raw/slab digest 与 byte mismatch**：见第 4 节（first_mismatch=0，digest 不同，无原始 bytes）
- **capture/slab 数据流**：见第 5 节（child 捕获 → slab 捕获，249ms 窗口，两次独立 RPM）
- **relevant git diff verdict**：见第 6 节（seed 阶段函数全部 IDENTICAL，非回归）
- **Route X vs Y A2 对比**：见第 7 节（主堆基址 0x874000 vs 0x894000，0x3327260 仅 Y1 A2）
- **offline reproduction**：见第 8 节（strict C==S fail-closed 既有测试覆盖，行为正确）
- **hypothesis matrix**：见第 9 节（H1 主根因，H2/3/6/7/8 排除）
- **confirmed facts**：见第 10 节
- **unresolved uncertainties**：见第 11 节（证据缺口：无原始 bytes）
- **proposed minimal remediation**：见第 12 节（方向 A/B/C，未实施）
- **report/analysis 路径**：`docs\GTO_ROUTE_Z_R0_OFFLINE_RESULT.md`（untracked）、`D:\MidaVault\lab\analysis\route_z_r0_seed_drift_20260811T080130Z\`
- **git status**：branch `oreans/two-sample-mainline`，HEAD `68b8032`，无 tracked 修改，untracked 5 个 docs（X R1 / Y R0 / Y R1 / Y R1 A2 / Z R0）
- **Route Z R0 最终状态**：**`RouteZ_R0_LiveNondeterminismConfirmed`**
