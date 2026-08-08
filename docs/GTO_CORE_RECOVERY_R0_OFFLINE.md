# GTO Core Recovery R0 — Heap/Runtime Rebase 与 Cold-Start Bootstrap 离线闭环

**Branch:** `oreans/two-sample-mainline`
**Base:** `ab83221`
**Status:** 离线核心恢复工单完成（非 GTO Product 1.0）

---

## 1. 当前真实恢复数据流（Recon）

### 1.1 GTO observation 何时决定 dump

- `crates/cli/src/unpacker/gto_host.rs::observe_gto`（观察策略）：
  - OEP 由 `.text` scan / `find_real_oep_by_scanning` 决定（`gto_host.rs:470`）。
  - UI class `NewClassName` 出现后 settle（3s / no-bypass 5s）再 dump（`gto_host.rs:39-42,362-380`）。
  - no-bypass 走 IAT+9s 或 max_wait 的 last-resort alive dump。
- observation 产物 `GtoObservation { oep_addr, frozen_rip, iat_override }` 交回共享 `run_post_loop_phases` 做 dump。

### 1.2 live memory 进入 EarlySectionSnapshot / container / heap snapshot

- `crates/pe/src/dumper/dump_process.rs::dump_process_with_report`：
  - `early_section_snapshots`（`dump_process.rs:957` 经 `apply_early_section_overlays`）覆盖 `.data` 到 pre-CRT 基线。
  - `detect_containers`（`dump_process.rs:844`）读 live heap 的 SecurityCookie 容器。
  - `detect_heap_globals`（`dump_process.rs:856`）capture 图像根对象 + graph children。
  - `capture_heap_slab`（`dump_process.rs:900`，仅 no-bypass）capture 覆盖所有 heap-global span 的连续 slab。

### 1.3 哪些 snapshot 被写入输出 PE

- 容器 / heap-global / slab 的 bytes 被嵌入 `.boot` stub（`container_bootstrap.rs::build_container_stub_internal`）。
- 早期 overlay 覆盖 `.data` 到 pre-CRT 基线。

### 1.4 哪些旧 VA 被 patch

- `.data` 内 encoded container triples 由 runtime stub 用新 heap 地址重新 encode（`output_writer.rs:96-120` 先零化，bootstrap 运行时重建）。
- heap-global slot 由 stub plant `GetProcessHeap` 或新对象地址。
- phase-2 multi_fixup 把 captured region 内指向旧 heap 的 qword 重映射（`container_bootstrap.rs` phase 2）。

### 1.5 哪些旧 VA 没有 patch

- 指向原进程私有 allocation / 未被 capture 的 heap 地址（可能残留 → cold-start AV）。
- 指向已捕获 old heap 但未被 multi_fixup 精确命中的 interior pointer。
- **本工单新增：`RuntimeRebasePlan` 在写盘前离线验证，未解析 required pointer → fail-closed（不写 candidate）。**

### 1.6 bootstrap 何时运行

- `install_heap_bootstrap`（`dump_process.rs:1108`）→ `PostCrt` → `install_post_crt_container_restore` 在 `__security_init_cookie` 之后、CRT body 之前（`container_bootstrap.rs:109`）。PE EP 保持 CRT wrapper；CRT wrapper 的 `jmp` 被改写为 `.boot` stub。
- TLS callback 路径 `install_tls_callback_bootstrap`（`tls_bootstrap.rs:75`）是 **dead code**（`#[allow(dead_code)]`，pending P2），当前**未启用**。

### 1.7 bootstrap 如何分配 heap

- stub 先 `GetProcessHeap` → r15；对每个 container/global 调 `HeapAlloc`，失败 `jz .skip`（记录 new_begin=0）。
- heap slab 走 `VirtualAlloc(old_base)` 尝试原位保留，失败 fallback HeapAlloc（`container_bootstrap.rs` phase 1c）。

### 1.8 snapshot 内部指针如何从 old VA 映射到 new VA

- runtime stub phase 2 `multi_fixup`：仅 exact-base（`V == old`）命中才重映射（`container_bootstrap.rs` p21h 注释），避免误改整数字段。
- 本工单的 `RuntimeRebasePlan` 提供 offline 确定性映射（interior pointer 支持 + Ambiguous fail-closed），供写盘前验证。

### 1.9 image globals 如何获得新对象地址

- heap-global image-inline 对象：stub 把 bytes memcpy 回 image+rva，并记录 fixup `old→image_base+rva`。
- 非 inline slot：stub plant 新对象地址到 image slot。

### 1.10 bootstrap 完成后如何转移到真实 OEP

- stub 清 volatile regs（`emit_clear_volatile_regs`）→ `jmp original_entry_point`（真实 OEP，`.text` scan 得到的 app OEP，或 no-bypass 的 Themida VM entry）。

### 1.11 只有实现但没有实际调用的函数

- `tls_bootstrap::install_tls_callback_bootstrap` / `build_tls_directory` / `container_bootstrap::build_tls_bootstrap_stub` — dead（P2 TLS gate）。
- `data_snapshot::capture_data_section` / `build_data_restore_code` — dead（legacy）。
- `container_snapshot::restore_containers` — dead（被 runtime stub 取代）。

### 1.12 AhkGtoExperimental 实际启用的恢复阶段

- `DumpProfile::AhkGtoExperimental` 的 `capabilities()` 开启：capture_containers、capture_heap_graph、install_heap_bootstrap、materialize_wrappers、patch_wrapper_calls（`types.rs:109`）。默认 `container_restore=PostCrt`。
- OreansClassic 全部关闭（`types.rs:101`）。

---

## 2. RuntimeRebasePlan 数据结构

`crates/pe/src/dumper/runtime_rebase.rs`（新模块）：

- `PointerClassification`：Null / InImage / InCapturedRegion / ExternalModule / SmallIntegerOrTag / Unmapped / Ambiguous。
- `RebaseRegion { id, old_base, size, alignment, bytes, required, kind, image_inline_rva }`。
- `RebasePointer { source_region, source_offset, original_value, classification, target_region, target_offset }`。
- `RuntimeRebasePlan { regions, pointers, old_image_base, new_image_base, plan_complete, plan_digest }`。
- 确定性：region 按 `(old_base,size)` 排序，pointer 按 `(source_region, source_offset)` 排序；`canonical_bytes()` + sha256 → `plan_digest`。

### 不变量

1. old range 用 checked arithmetic。
2. region 不重叠，重叠 fail-closed。
3. 同一 old VA 映射唯一 target（`classify_value` 多命中 → Ambiguous）。
4. 排序确定性（无 HashMap 迭代序）。
5. pointer 宽度绑定 x64（8 字节），绝不猜测任意 8 字节是指针。
6. 只有显式声明的 pointer slot 才可 patch。
7. required pointer unresolved → 整个 recovery 失败。
8. optional/opaque 保持原字节但记录未解释状态。
9. patch 前校验 `source_offset + width` 不越界。
10. patch 后无指向已捕获 old heap/private range 的 required pointer。

---

## 3. 两阶段 heap/container 重建

- **Phase 1（分配）**：`build_runtime_rebase_plan` 为所有 required region 记录新 allocation target（image-inline → 新 image RVA；否则新 heap 分配）。任一 required allocation 失败 → fail-closed，不跳 OEP。
- **Phase 2（复制与 patch）**：复制 snapshot bytes；遍历显式 pointer ledger：
  - `InCapturedRegion`：`new_value = target_new_base + target_offset`。
  - `InImage`：绑定到 rebuilt image base + RVA。
  - `ExternalModule`：仅稳定地址 / IAT resolver 重建。
  - `Unmapped/Ambiguous required`：失败。
  - 完成后设置 completion cookie，最后才进入真实 OEP。
- 循环对象图（A→B、B→A、self、多 root、interior、NULL、tagged）先建完整 allocation map，再统一 patch —— 不按递归复制顺序决定地址。

---

## 4. Bootstrap 执行顺序（现状 + 契约）

当前启用顺序（AhkGtoExperimental + PostCrt）：
1. PE EP = MSVC CRT wrapper → `__security_init_cookie`。
2. CRT wrapper `jmp` → `.boot` stub。
3. `.boot`：GetProcessHeap → Phase1 HeapAlloc+memcpy（容器 / globals / slab）→ Phase2 multi_fixup → clear volatiles → cookie mirror → `jmp` 真实 OEP。

验证项（`validate_bootstrap_contract`）：
- bootstrap RVA 位于可执行 section。
- TLS RVA 在 image 内。
- original OEP 合法（非 0、在 image 内）。
- region count 合法（1..=65535）。
- `.boot`/`.tls` 的 VirtualSize 未远超 SizeOfRawData。

TLS callback 路径**未接线**（P2），不声称已启用。

---

## 5. Fail-closed 条件

- `build_runtime_rebase_plan` 返回 Err：old-range overflow / region overlap / ambiguous target / 指针宽度不匹配。
- `validate_runtime_rebase_plan` 返回 Err：required region 无 target / InCapturedRegion 缺 target mapping / target 越界 / slot 越界 / target alignment 错误。
- `plan_and_validate_for_dump`：`recovery_status != Complete`（即 unresolved_required > 0）→ 返回 Err。
- `dump_process` 集成点：plan 校验 Err → `PeError::Parse` → 不写 candidate（不出看似成功的 dump）。

---

## 6. Synthetic offline tests（mida-pe）

`runtime_rebase.rs::tests`（24 项）覆盖工单第六节 1–24：
单 region 无指针 / A→B / A→B→A / self / interior / 多 root 同目标 / NULL / image RVA / external / unmapped fail-closed / ambiguous fail-closed / optional opaque 不 patch / old region 重叠拒绝 / target 重叠拒绝 / old+size overflow 拒绝 / slot 越界拒绝 / required allocation 失败不跳 OEP / 确定性重复构建 / post-patch 扫描无旧指针 / 无 required old-range pointer / 确定性 digest / Oreans 不启用 / AhkGto 启用 / 无 plan fail-closed。

`snapshot_manifest.rs::tests::rebase_summary_renders_status_complete`：诊断 summary 侧写。

---

## 7. 诊断输出（RuntimeRebaseSummary）

- regions_total / regions_required / bytes_captured / pointer_slots_total / intra_region_pointers / image_pointers / external_pointers / null_or_tagged / unresolved_required / unresolved_optional / image_roots_patched / bootstrap_kind / bootstrap_rva / original_oep_rva / completion_cookie_rva / deterministic_plan_digest / recovery_status。
- 状态仅 Complete / Incomplete / Rejected。仅 `unresolved_required==0` 且 bootstrap contract 完整 → Complete。
- 写入 `{stem}.dump_snapshot.json` 的 `runtime_rebase` 块（仅 AhkGtoExperimental；不涉 acceptance）。

---

## 8. 修改文件

- `crates/pe/src/dumper/runtime_rebase.rs`（新增，核心 plan/validate/summary + 24 测试）。
- `crates/pe/src/dumper/mod.rs`（模块声明 + 公开导出）。
- `crates/pe/src/dumper/dump_process.rs`（AhkGtoExperimental 集成：写盘前 plan 校验 fail-closed + summary 侧写）。
- `crates/pe/src/dumper/snapshot_manifest.rs`（manifest 增加 runtime_rebase 诊断块 + 测试）。

未改：`crates/acceptance/*`、`gto_host.rs`、`bwhook`、`behavior_oracle_contract.rs`、`report.rs`、TrustToken/schema/签名消费。

---

## 9. 完成定义核对

- 离线 heap/runtime rebasing 有确定性实现（RuntimeRebasePlan + digest）。
- bootstrap 有明确两阶段恢复与执行顺序（Phase1 分配 / Phase2 复制+patch，离线契约）。
- required unresolved pointer fail-closed（dump 不写 candidate）。
- AhkGtoExperimental recovery 不再只是复制 heap bytes（写盘前计划校验 + 证据）。
- 已具备下一轮受控 live route 验证 cold-start AV 的技术基础（plan digest + 诊断侧写 + fail-closed 契约）。
- Oreans 回归保持绿色（workspace 全部测试 0 failed）。

**本工单完成 ≠ GTO Product 1.0。UI/script engine 恢复未在 live 验证，明确为否。**
