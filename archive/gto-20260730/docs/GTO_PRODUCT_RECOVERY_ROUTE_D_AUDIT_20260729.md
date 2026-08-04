# GTO-PRODUCT-RECOVERY — Route D Read-Only Audit (2026-07-29)

> **Phase:** 0.5 (read-only debug-context audit). **Budget consumed = 0**.
> **Not** Phase 1. **Not** R1B re-entry. **Not** E2 activation. **Not** a live run. **Not** a source-code edit. **Not** push.
> **Proposal authority:** `docs/GTO_PRODUCT_RECOVERY_CHARTER_20260729.md` §6.4 Route D.
> **Branch:** `baseline/legacy-recovery-20260722` @ `e19b129`.
> **Working tree at start of task:** clean (only the `e19b129` commit ahead of `c5729fe`).

---

## 1. Executive verdict

| Question | Answer |
|----------|--------|
| Is Route D a read-only debug-context audit? | **Yes.** No Rust/Python diff, no rebuild, no re-measure. Per `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 step 4 budget-burn rule, **investigation that does not produce Rust/Python diff + rebuild + re-measure is not a budget round**. |
| Budget consumed = 0? | **Yes.** This document is docs-only. |
| Should Route A Phase 1 default-reuse the parked VEH+DR0 short-window class? | **No.** Recommend Route A explicitly avoid the parked class as the primary capture method. See §6. |
| Should a non-GTO local flag-acceptance harness be run first if DRx is to be reused? | **Yes** (if DRx is to be used at all) — but **must be a separate governance proposal**, not executed in this task. See §6.3. |

### 1.1 One-paragraph verdict

The R1B `GetThreadContext(flags=0x100013) -> ok=false` failure is **not** evidence that the target pointee at `0x1405febb8` does not exist. It is evidence that **the parked VEH+DR0 short-window class failed to take control of the target thread before `GetThreadContext` was called**. The four `capture_reason`s observed across the R1B smokes (`arm_timeout` × 1; `dr0_fail` × 3) describe host-side state-machine failures, not pointee-existence failures. `same_epoch=false` and `committed_readable=false` in `r1b_01_outcome.json` are downstream of `arm_dr0_on_thread failed`; the slot was never populated, so the `committed_readable` check never had a chance to fail on its own terms. **This is qualitatively the same wall the R1A evidence already documented** — the host cannot establish the same suspended RIP at capture time as at the VIP fetch time, except R1A's `hard_deadline_last_near` ages things by ~3.4 s on a *different* code path (BootWatch near-fetch) and R1B's `dr0_fail` kills the attempt at an *earlier* point (the very first `GetThreadContext` after suspend).

### 1.2 Recommended Route A posture

Route A Phase 1 (if separately approved) should **not** default to VEH+DR0 short-window. The audit recommends Route A explore, in this order:

1. **Memory-state epoch capture** (extension of H1 in charter §5.1, plus R1A's `saved_near` mechanism as a precondition class — but reframed as the *primary* capture class, not as a *fallback*). The parked R1B mechanism was an *interception* class; the failure modes here suggest interception-on-a-VM-owned-process is harder than memory-state capture.
2. **VM-ownership-aware non-DRx capture** (VirtualAlloc-anchor pinning, `.boot` write-storm entropy-watching per `4c2b545:docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` §0 fact #2). This avoids `GetThreadContext` entirely and therefore avoids the flag-acceptance surface area altogether.
3. **DRx as a *secondary*, gated capture class** — *only* after a non-GTO local harness has confirmed on this Win10/11 build: (a) which `CONTEXT_FLAGS` Windows actually accepts for `main_tid` of a protected process under various suspend-count states; (b) whether `SuspendThread(prev=0)` while the host had skipped its own suspend is reproducible as a race. That harness is **out of scope for this task** and must be a **separate governance proposal** under `GTO-PRODUCT-RECOVERY` (or under a *new* `GTO-PRODUCT-RECOVERY` sub-ledger namespace, allocated by separate governance).

---

## 2. Evidence inventory

All paths below were inspected read-only. **No file in this section was modified.** SHA-256 hashes were taken at audit start (timestamps shown in §2.1, §2.2, §2.3). The vault evidence lives outside the working tree (under `D:\MidaVault\`); per task authorization, these are *cited as evidence inputs only*, not modified.

### 2.1 R1B evidence (`D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\`)

| File | mtime | bytes | SHA-256 (full) |
|------|-------|-------|----------------|
| `R1B_RESIDUAL_STOP.md` | 2026-07-29 15:39:32 | 734 | `bb140399acfde3d76900906f18af08044069891509c9c8ab59a68aa0e70011b8` |
| `r1b_summary_20260729-120703.json` | 2026-07-29 12:07:03 | 1 141 | `244c274d3baae9b3e877a7b017c68b675b552b390688d9d73e9cf8becb523690` |
| `r1b_summary_20260729-145140.json` | 2026-07-29 14:51:40 | 1 135 | `00d562448e68e7a1c5e7ff3f0e7a7629175f892e2de8d95447174aa12cb9977a` |
| `r1b_summary_20260729-153634.json` | 2026-07-29 15:36:34 | 1 135 | `33372108be19c220427a7599e7e2b7f822d8c8421d89b12d8ce7acc748618e76` |
| `r1b_summary_20260729-153932.json` | 2026-07-29 15:39:32 | 1 134 | `22098b45cead8135315abc1ab84ed84ec465c4a882f5695f9f9f333c55023909` |

Key observations across these four summaries:

| ts | elapsed_sec | outcome | capture_reason | notes |
|----|-------------|---------|----------------|-------|
| 12:07:03 | 24.33 | timeout | `arm_timeout` | DLL waited 24s for arm event; never fired. **Pre-arming failure.** |
| 14:51:40 | 4.73 | error | `dr0_fail` | Arm signaled; arm path reached `GetThreadContext(flags=0x100013) -> ok=false`. |
| 15:36:34 | 4.25 | error | `dr0_fail` | Same. |
| 15:39:32 | 4.10 | error | `dr0_fail` | Same (latest; matches bwhook log mtime). |

All four summaries: `same_epoch_hits=0`, `committed_readable_hits=0`, `gate_pass=false`.

### 2.2 R1B smoke artifacts (`D:\MidaVault\scratch\`)

| File | mtime | bytes | SHA-256 |
|------|-------|-------|---------|
| `r1b_smoke_log\r1b_01_bwhook.log` | 2026-07-29 15:39:29 | 519 | `0b21c10bf26b73da35b3a72945ab64143d96a3e82f9458c3627337da3ce1e8e8` |
| `r1b_smoke_out\r1b_01_outcome.json` | 2026-07-29 15:39:29 | 1 006 | `18bc16d8b95448d72717642a5c10f80da496bf58ad750db2639e21a2020ce74d` |

`r1b_01_bwhook.log` content (full, since it is 519 bytes):

```text
bwhook R1B: inject wait-mode pid=23576 target=0x1405febb8 main_tid=13636
bwhook R1B: waiting arm event Local\MidaBwHookArm_23576
bwhook R1B: arm signaled — registering VEH + DR0 (main thread only)
bwhook R1B: OpenThread OK, SuspendThread(prev=0)
bwhook R1B: GetThreadContext(flags=0x100013) -> ok=false
bwhook R1B: arm_dr0_on_thread failed
bwhook R1B: wrote outcome D:\MidaVault\scratch\r1b_smoke_out\r1b_01_outcome.json
bwhook R1B: outcome=error same_epoch=false slot=0x0 pointee=0x0 committed=false arm_to_hit_ms=0
```

`r1b_01_outcome.json` content (key fields, full file is 1006 bytes):

| field | value | meaning |
|-------|-------|---------|
| `schema` | `gto.transient_epoch_trap/v1` | (canonical) |
| `capture_reason` | `dr0_fail` | host arm failed before any capture |
| `outcome` | `error` | (canonical) |
| `same_epoch` | `false` | vacuously false; no slot was populated |
| `target_rip` | `0x1405febb8` | from charter §0 (`mov r10,[rsp+rax] @ 0x1405febb8`) |
| `hit_rip` | `0x0` | no DR0 hit (arm never succeeded) |
| `current_rsp` / `current_rax` | `0x0` / `0x0` | never read; `GetThreadContext` failed |
| `slot_va` | `0x0` | never allocated |
| `slot_rsp_source` | `current_suspended` | (declared; not exercised) |
| `committed_readable` | `false` | vacuously false |
| `gpr.*` | all `0x0` | never populated |
| `note` | `R1B capture-only; same_epoch=true only on VEH hit at target with current RSP+RAX slot` | |

### 2.3 R1A N=10 evidence (`D:\MidaVault\scratch\bootwatch\r1a_n10_20260728-192757\`)

| File | bytes | SHA-256 |
|------|-------|---------|
| `r1a_n10_aggregate.json` | 961 | `9aad531f74eca4fecb8d78f8b8f275d4eae29ae64833dd6ff82ee39dd7a6bc17` |
| `r1a_n10_summary.json` | 9 407 | `fb3fe40ee6a766517e2858c7cd22d1f659a4013fef265e59aeec6bbcac10bda0` |

(`r1a_n10_aggregate.json` per-run files, `r01..r10.bootwatch_outcome.json` + `transform_manifest.json`, and the `*.bin` artifacts — 87 files total — were enumerated by `Get-ChildItem -Recurse` and counted, but only the aggregate + summary were read for content; SHA-256 of every individual `.bin` is out of scope for this audit.)

**`r1a_n10_aggregate.json` key counts (per the file as committed):**

| field | value |
|-------|-------|
| `stamp` | `20260728-192757` |
| `n` | 10 |
| `ok_exit` | 10 |
| `by_reason.hard_deadline_last_near` | 9 |
| `by_reason.ui_or_timeout_miss` | 1 |
| `same_epoch_committed` | **0** |
| `mixed_epoch_committed` | 9 |
| `sample_bypass_manifest_hits` | 0 |
| `e2_gate_same_epoch_committed_ge3` | **false** |

**`r1a_n10_summary.json` per-run table (10 rows):**

| run | exit | has_outcome | has_slot | capture_reason | same_epoch | slot_rsp_source | saved_near_age_ms | stack_slot_class | current_rip | saved_near_rip |
|-----|------|-------------|----------|----------------|------------|-----------------|-------------------|------------------|-------------|----------------|
| 1 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3431 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b866b` |
| 2 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3443 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b866b` |
| 3 | 0 | T | F | `ui_or_timeout_miss` | F | `none` | — | `none` | `0x0` | `0x0` |
| 4 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3451 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b866b` |
| 5 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3500 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b866b` |
| 6 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3440 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b866b` |
| 7 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3492 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b8672` |
| 8 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3446 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b866b` |
| 9 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3442 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b866b` |
| 10 | 0 | T | T | `hard_deadline_last_near` | F | `saved_near` | 3435 | `mem_mapped_committed_readable` | `0x7ffc07c51344` | `0x1405b866b` |

`has_sample_bypass=false` on every row. `manifest_ids` always include `cs_reinit,heap_bootstrap,early_section_overlay`; `heap_slab_restore` present 9/10 times (missing in r09).

**Critical observation** that motivates §3 and §4 below:

For runs 1, 2, 4, 5, 6, 8, 9, 10: `current_rip = 0x7ffc07c51344` (a `ntdll`/`win32u` system range) while `saved_near_rip = 0x1405b866b` (image range). This is exactly what `4c2b545:docs/GTO_POINTEE_EPOCH_R1A_20260728.md` §2.2 calls a "typical hard-deadline outcome": the host captured a saved-near RSP that was ~3.4s old; by the time `SuspendThread` succeeded, the thread had already returned to user-mode idle (RIP in `ntdll!0x7ffc07c51344` range) and the saved RIP no longer corresponded to the suspended state.

For run 7: `current_rip = 0x7ffc07c51344` (same idle) but `saved_near_rip = 0x1405b8672` (7 bytes off the usual `0x1405b866b`); the saved-near RIP itself varies across runs, confirming the captured slot is from **different suspended epochs** across runs.

### 2.4 R1A seal + body (immutable refs)

| Doc | Ref | Header excerpt (verbatim) |
|-----|-----|----------------------------|
| Residual-stop seal | `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` | `Round 1A  epoch-honest outcomes   → DONE with residual-stop (0/10 same_epoch COMMIT)` |
| R1A Pointee Epoch body | `4c2b545:docs/GTO_POINTEE_EPOCH_R1A_20260728.md` | `R1A closed with honest stop: E2 gate not met.` |
| KI3 breakpoint design | `4c2b545:docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` | `“正典自旋锁 VM ENTER 断点”在 启动器 这个构建上不存在。` |

The KI3 §0 conclusion is the **load-bearing fact for §6 below**: Themida VM ENTER on `启动器` is virtualized/inlined; no portable instruction-pattern BP exists across both `启动器` and the `hello_world_themida_protected.exe` reference build. Capture must be **memory-state-epoch based**.

### 2.5 bwhook flag-assembly (parked, research-branch only)

Inspected **read-only** from `4be4ee5:crates/bwhook/src/lib.rs` for the flag-construction lines (cited as evidence input only — file is parked on `research/gto-bootwatch-20260728` and is **not** on baseline HEAD):

```rust
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, CONTEXT, CONTEXT_FLAGS,
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, GetThreadContext,
    SetThreadContext,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};
// …
const CONTEXT_DEBUG_REGISTERS_AMD64: u32   = 0x0010_0010;
const CONTEXT_CONTROL_INTEGER_AMD64: u32  = 0x0010_0001 | 0x0010_0002;  // = 0x0010_0003
// …
let access = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME;
// …
let mut ctx: CONTEXT = core::mem::zeroed();
ctx.ContextFlags = CONTEXT_FLAGS(CONTEXT_DEBUG_REGISTERS_AMD64 | CONTEXT_CONTROL_INTEGER_AMD64);
let ok = GetThreadContext(h, &mut ctx).is_ok();
```

---

## 3. R1B failure reconstruction

### 3.1 Single-run timeline (r1b_01, ts `20260729-153932`, latest of the four)

| Step | What happened | Where in evidence | Outcome |
|------|---------------|-------------------|---------|
| 1 | DLL injected into launcher in **wait-mode** | `r1b_01_bwhook.log` line 1: `inject wait-mode pid=23576 target=0x1405febb8 main_tid=13636` | OK |
| 2 | DLL blocked on `OpenEventW(Local\MidaBwHookArm_23576)` | `r1b_01_bwhook.log` line 2: `waiting arm event Local\MidaBwHookArm_23576` | OK (blocked) |
| 3 | External arm event signaled | `r1b_01_bwhook.log` line 3: `arm signaled — registering VEH + DR0 (main thread only)` | OK |
| 4 | `AddVectoredExceptionHandler` (VEH) + `SetThreadContext` (DR0) queued | (same line) | queued |
| 5 | `OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, …)` | `r1b_01_bwhook.log` line 4: `OpenThread OK` | OK |
| 6 | `SuspendThread(handle)` returned `prev=0` | `r1b_01_bwhook.log` line 4: `SuspendThread(prev=0)` | **Note**: `prev=0` means the thread was *not already suspended by another component* (per Win32 contract); but on a freshly-injected handle to `main_tid`, `prev=0` is the expected first-suspend count. |
| 7 | `GetThreadContext(handle, ctx{flags=0x100013})` | `r1b_01_bwhook.log` line 5: `GetThreadContext(flags=0x100013) -> ok=false` | **FAIL** |
| 8 | Helper returned error; outcome written | `r1b_01_bwhook.log` lines 6–8 | dr0_fail |

### 3.2 What `same_epoch=false`, `committed_readable=false` mean here

In `r1b_01_outcome.json` these fields are both `false`. **Both are vacuously false in this run** because the slot was never populated:

- `slot_va = 0x0` — never allocated (slot.alloc happens *after* `arm_dr0_on_thread` succeeds, per bwhook source).
- `gpr.* = 0x0` — never read; `GetThreadContext` failed before populating.
- `current_rsp = 0x0` / `current_rax = 0x0` — same reason.

So **the absence of `committed_readable=true` is not evidence the target pointee at `0x1405febb8` does not exist**. The host simply never reached the pointee-probe step. The audit agrees with `R1B_RESIDUAL_STOP.md` § "Outcome": the gate fail (`<3 of 10 with same_epoch=true`) is real, but its interpretation in §6 below must distinguish "we didn't capture" from "there's nothing to capture".

### 3.3 The R1A evidence is *consistent* with R1B

R1A's failure mode is *different in mechanism* (BootWatch near-fetch with ~3.4s staleness) but *same in shape* (host never held the thread at the same suspended RIP as the VIP fetch epoch). Two distinct mechanisms, same wall:

| Mechanism | Code path | Failure observation |
|-----------|-----------|---------------------|
| R1A | Poll + defer 500ms + hard-deadline `near_fetch` fallback | `saved_near_age_ms ≈ 3400`; `current_rip` in `ntdll` range; `saved_near_rip` in image range |
| R1B | VEH + DR0 short-window; `SuspendThread` then `GetThreadContext` | `GetThreadContext(flags=0x100013) -> ok=false` immediately; slot never populated |

In R1A, the slot *was* committed+readable (`mem_mapped_committed_readable`), but the suspended RIP had drifted; in R1B, the slot never even got to be committed. Both reach the **same gate result** (`same_epoch_committed=0`), and the audit believes this is **not coincidence**.

---

## 4. Flag analysis

### 4.1 Decomposition of `0x100013`

Hex `0x100013` is the OR of two constants in `4be4ee5:crates/bwhook/src/lib.rs`:

```
0x0010_0010   CONTEXT_DEBUG_REGISTERS_AMD64     (DebugRegisters on AMD64)
0x0010_0003   CONTEXT_CONTROL_INTEGER_AMD64     (Control | Integer on AMD64)
─────────────────────────────────────────────
0x0010_0013   (the value actually passed)
```

Mapping to Win32 `CONTEXT_*` flags (AMD64):

| Hex bit | Flag name (AMD64) | Meaning |
|---------|-------------------|---------|
| `0x0000_0001` | `CONTEXT_AMD64` | architecture bit — *required* on x64 to select the AMD64 context layout |
| `0x0000_0002` | `CONTEXT_INTEGER` | GPR (rax..r15) — without this, integer registers are undefined |
| `0x0000_0004` | `CONTEXT_CONTROL` | cs/rsp/rip/eflags — without this, control registers are undefined |
| `0x0000_0010` | `CONTEXT_DEBUG_REGISTERS` | Dr0..Dr7 — *not* the full segment, just the DRs |
| `0x0010_0000` | (part of the layout bits, not a flag) | AMD64-vs-i386 layout selector (not present in standard WinNT.h flag bits) |

The `0x0010_0000` "AMD64 layout selector" is **already implicitly encoded** in both `CONTEXT_DEBUG_REGISTERS_AMD64` and `CONTEXT_CONTROL_INTEGER_AMD64`. It is *the high byte of the `0010_xxxx` block* that distinguishes AMD64 from x86. OR-ing `CONTEXT_AMD64=0x100000` again is therefore **a no-op** — the bit is already set in both operands.

This matches the `WORKER_HANDOFF.md` § "Open discipline notes" withdrawal (third-pass 2026-07-29): the previously claimed "one-line fix" `OR CONTEXT_AMD64` is **incorrect** and must not be re-introduced.

### 4.2 What flag values are *actually* valid here?

`GetThreadContext` can return `ok=false` for reasons unrelated to the flag bits:

- `ERROR_INVALID_PARAMETER` (87) — flag combination illegal for the thread's architecture
- `ERROR_ACCESS_DENIED` (5) — handle does not have `THREAD_GET_CONTEXT`
- `ERROR_INVALID_HANDLE` (6) — bad handle (closed / wrong tid)
- `ERROR_NOT_SUPPORTED` (50) — operation not supported on this platform / build

The bwhook log does **not** record `GetLastError()` after the failed call (no `GetThreadContext(flags=0x100013) -> ok=false (err=…)` line). **That is itself a finding**: the parked code does not surface the actual `ERROR_*` value, so we cannot from log evidence alone distinguish H-D1 (flag combination) from H-D2 (handle / state) from H-D3 (rights). The next `Route D`-recommended harness (§6.3) must capture this.

---

## 5. Root-cause hypotheses

For each hypothesis below:

- **Supporting evidence**: what we observed that *would be consistent* with this root cause.
- **Counter-evidence**: what we observed that *would not be consistent* with this root cause (or what we lack to confirm).
- **How to test later without GTO live run**: where the test would run (typically a non-GTO local harness), what data it would emit, and what outcome would tilt the verdict.
- **Effect on Route A method choice**: whether this hypothesis, if true, would push Route A away from DRx, toward memory-state epoch, or toward some other class.

### 5.1 H-D1 — Windows flag-combination / WOW64 / thread architecture mismatch

- **Supporting evidence:**
  - `0x100013` is *not* a documented `CONTEXT_FLAGS` value in WinNT.h; it is the OR of two research-only convenience constants. Whether Windows accepts it on this Win10/11 build for a **protected-process main thread** has not been empirically established.
  - The `main_tid=13636` of a process started by `启动器.exe` is a 64-bit-mode thread, so WOW64 mismatch is unlikely.
  - `SuspendThread(prev=0)` returned cleanly, suggesting the handle itself was valid.
- **Counter-evidence:**
  - `prev=0` + `OpenThread OK` means handle + rights + suspension all succeeded. If flags were the only problem, you'd typically see `ERROR_INVALID_PARAMETER` — but we did not capture `GetLastError()`.
  - The same `0x100013` value was used across 4 separate runs (`12:07:03`, `14:51:40`, `15:36:34`, `15:39:32`); all four failed at the same step. That is *consistent* with H-D1 but does not prove it (could also be H-D2 / H-D3 below).
- **How to test later without GTO live run:**
  - In a non-GTO local harness, on a *trivial* Win32 thread (no protection, no Themida), pass `ContextFlags = 0x100013` and `0x100010` (DEBUG_REGISTERS_AMD64 only) and `0x100003` (CONTROL_INTEGER_AMD64 only) and `0x100000` (just the architecture bit) and `CONTEXT_FULL_AMD64=0x0010_000B`. Record `GetLastError()` after each. Expected: trivial thread accepts all of them with `ok=true` and `GetLastError()=0`. If not, the flag bit is the problem.
- **Effect on Route A method choice:**
  - If H-D1 is true, Route A should **prefer non-DRx capture** (memory-state epoch or `.boot` write-storm entropy watching — see §6) entirely, since the DRx surface area is hostile to the flag combinations the parked code chose. Re-using DRx would require a different flag discipline *and* a different capture mechanism (e.g. kernel-mode debug, or non-`GetThreadContext` reads via `NtQueryInformationThread(ThreadContext)`).

### 5.2 H-D2 — Suspend-count race / target thread not in acceptable suspended state

- **Supporting evidence:**
  - `r1b_01_bwhook.log` line 4: `SuspendThread(prev=0)` — but on a freshly injected thread, `prev=0` is the *expected* first-suspend count. The bwhook host *itself* might have skipped an internal pre-suspend (the gate `if frozen_rip.is_none() && bootwatch_vm_enter_rip.is_none()` from `WORKER_HANDOFF.md` § "Open discipline notes" is the only place this race is mitigated — but only when *another* path has already taken a frozen RIP, not when `GetThreadContext` is the first touch).
  - A protected-process main thread, freshly injected and not yet executing user-mode, may be in a transitional state where `GetThreadContext` is momentarily refused even with valid flags.
- **Counter-evidence:**
  - `prev=0` from `SuspendThread` *is* the correct first-suspend state. There's no obvious race signature in the log (no "host_suspend_skipped", no "race_detected", no extra suspend/resume cycles).
  - The 4 R1B runs (24s/4.7s/4.3s/4.1s) all succeeded in *some* steps (`OpenThread OK`, `SuspendThread(prev=0)`) and only `GetThreadContext` failed. If a suspend-count race were the cause, you'd expect variance in *which* step failed.
- **How to test later without GTO live run:**
  - In a non-GTO local harness, on a trivial Win32 thread, issue `SuspendThread; GetThreadContext(flags=0x100013); ResumeThread` in a tight loop. If it succeeds reliably (≥99/100), H-D2 is unlikely; if it fails on a fraction of attempts, the race is reproducible without any Themida involvement.
  - A second test on a *protected-process equivalent* (e.g. a PPL binary started the same way) would isolate the architecture/process-class effect.
- **Effect on Route A method choice:**
  - If H-D2 is true, Route A can still use DRx but **must** add: a host-side pre-suspend self-discipline, an explicit "double-suspend + verify prev==1" gate, and a retry loop on `GetThreadContext` failure. None of these were present in `4be4ee5`. This makes Route A's path back to DRx **non-trivial**.

### 5.3 H-D3 — Handle rights / thread identity / main_tid mismatch

- **Supporting evidence:**
  - The DLL logs `pid=23576 target=0x1405febb8 main_tid=13636`. If the *target* (the launcher, presumably pid 23576) has multiple threads, and the wrong one was picked (e.g. a thread that was a worker, not the one that would ever reach `0x1405febb8`), then `OpenThread(THREAD_SUSPEND_RESUME)` would succeed (any thread of the process can be opened with these rights) but `GetThreadContext` might fail if the thread is in a system-only state.
  - `main_tid` was presumably obtained from a snapshot (`CreateToolhelp32Snapshot`) before injection; if the main thread had already been replaced (rare but possible in protected processes), `main_tid=13636` could be stale.
- **Counter-evidence:**
  - `OpenThread OK` + `SuspendThread(prev=0)` both succeeded. If the handle were stale or wrong-thread, the more typical failure is `ERROR_INVALID_HANDLE` (6) on `SuspendThread` itself, not on `GetThreadContext`.
  - The 4 R1B runs all opened the *same* tid (no log shows variance). Consistent with the tid being correct.
- **How to test later without GTO live run:**
  - Non-GTO local harness: enumerate threads of a trivial process, pick a non-main tid, `SuspendThread; GetThreadContext(flags=0x100013)`. If it always succeeds for non-main threads, H-D3 is unlikely; if it fails, handle-rights on system threads may be a real class.
- **Effect on Route A method choice:**
  - If H-D3 is true, Route A must adopt **explicit per-thread state validation** before `GetThreadContext`, e.g. `GetThreadId` + `IsThreadInThreadState` checks. This is a meaningful additional surface.

### 5.4 H-D4 — Anti-debug or protected-process interference with debug-register context

- **Supporting evidence:**
  - Themida is known to install anti-debug hooks on protected processes (per `4c2b545:docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` §0 conclusions 1–3 and the broader body of knowledge about VM-based protectors).
  - `SuspendThread` succeeded but `GetThreadContext` failed — this asymmetry is *exactly* what anti-debug interference looks like: `SuspendThread` is a generic kernel API; `GetThreadContext` for debug registers can be selectively filtered.
  - R1A's `0x7ffc07c51344` `current_rip` (ntdll range) across 9/10 runs is consistent with a process whose main thread has been *forcibly parked* into a system DLL by the VM at idle — exactly the kind of state that anti-debug measures might gate `GetThreadContext` on.
- **Counter-evidence:**
  - If anti-debug were the cause, you'd typically see `STATUS_DEBUGGER_INACTIVE` or a hand-rolled exception, not a clean `ok=false`. (But again, the parked code does not log `GetLastError()`.)
  - The R1A captures *did* read `saved_near_age_ms` and write a `slot.bin` — which means R1A's host *did* succeed in reading some thread state via a *different* path (`saved_near` RSP captured at near-fetch time, not via `GetThreadContext` of the *current* suspended state).
- **How to test later without GTO live run:**
  - Anti-debug interference requires a Themida-style protected process to test. There is no clean non-GTO harness for this hypothesis. **H-D4 may only be testable on `gto_launcher` itself**, which is the very thing Phase 1 cannot run. The audit **flags H-D4 as a hypothesis that, if true, would block DRx-based capture *categorically*** and would force Route A toward memory-state epoch capture.
- **Effect on Route A method choice:**
  - **Highest leverage** among the five. If H-D4 is true, Route A should **never** use DRx on this protected process; memory-state epoch capture (`.boot` write-storm watching, VirtualAlloc-anchor pinning) becomes the only viable method class. This is *the* reason the audit recommends memory-state epoch as the primary Route A direction (§6.1).

### 5.5 H-D5 — Hook ordering / arming epoch too late or wrong thread

- **Supporting evidence:**
  - The 12:07:03 run's `capture_reason=arm_timeout` (DLL waited 24s for the arm event that never fired) shows the arm-pump *can* fail in production. If the arm event fires *after* the target thread has already moved past `0x1405febb8` (which is what charter §1.5 calls the "transient epoch"), DR0 may be set on a stale instruction pointer — Windows may then refuse `GetThreadContext` because the thread is in a transitional state.
  - "Short-window" in the parked class name suggests the design assumed the window would be tight enough; the audit's R1A evidence (~3.4s age) shows the *actual* windows are wide.
- **Counter-evidence:**
  - The 14:51:40 / 15:36:34 / 15:39:32 runs all succeeded in arming (`arm signaled` is logged before `GetThreadContext`); the failure is at `GetThreadContext` specifically. If ordering were the cause, you'd expect more variance in the failed step.
- **How to test later without GTO live run:**
  - The "is `0x1405febb8` actually a transient epoch at all?" question is fundamental to the project and cannot be answered without running `gto_launcher`. The non-GTO equivalent would be: confirm on a trivial binary that a debug-register hook *just after* the target instruction still produces `GetThreadContext(ok=true)` — i.e. that `GetThreadContext` failure is *not* a general property of "RIP near but not at target".
- **Effect on Route A method choice:**
  - If H-D5 is true, Route A must redesign arming as **race-tolerant**: arming must happen at *multiple* candidate RIPs simultaneously, or use a *post-instruction* trigger (e.g. capture the *previous* instruction's state via single-step backward, which requires TF not DRx). Both add surface.

---

## 6. Route A guidance

### 6.1 Recommendation: Route A should *not* default to VEH+DR0 short-window

The 4 R1B smokes + 10 R1A captures + 3 distinct mechanisms that reach the same `same_epoch_committed=0` wall are the audit's reason for this recommendation. **The parked VEH+DR0 short-window class is not the best Route A default.**

### 6.2 Recommended method-class order for Route A

In priority order, if Route A is approved by separate governance (per `docs/GTO_PRODUCT_RECOVERY_CHARTER_20260729.md` §3.3 / §6.5):

1. **Memory-state epoch capture (H1 extension, §5.1 of charter)** — anchor on `.boot` write-storm entropy transitions (per `4c2b545:docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` §0 fact #2), VirtualAlloc original-address remap (already validated per charter §1 fact #4). Capture at the moment the runtime `.boot` reaches a stable entropy + an RIP inside `.boot`'s live area = first VM ENTER. Avoids `GetThreadContext` entirely.

2. **VM-ownership-aware non-DRx capture (H1 sub-class)** — use R1A's `saved_near` mechanism as a *primary* (not fallback) class: defer + accept ~3.4s staleness as the inherent property of any non-DRx mechanism on a VM-owned process, and require ≥3/10 with `committed_readable=true` at a named `slot_rsp_source ∈ {current_suspended, saved_near}` — whichever epoch class the harness can honestly reproduce. The R1A evidence shows `mem_mapped_committed_readable` is reachable 9/10 already; what fails is the *same-epoch* property, which is a *measurement* problem, not a *capture* problem.

3. **DRx as a secondary, gated class (only after a non-GTO local harness validates the surface)** — see §6.3.

4. **Suspended-only re-read with explicit pre-suspend self-discipline** — for runs where `current_suspended_rip` is reachable at all. Requires a host-side double-suspend + verify gate. Not in scope for this audit but the next-most-feasible after (1)–(3).

### 6.3 If Route A wants to keep DRx: required gating (out of scope for this task)

A future Route A proposal that names "DRx short-window" as the method class **must** precede it with:

- A **separate governance proposal** (e.g. `docs/GTO_PRODUCT_RECOVERY_LOCAL_HARNESS_20260729.md`) that:
  - Is *not* `R1B re-entry` (does not name that token literally).
  - Is a non-GTO harness (no `gto_launcher` involved; trivial Win32 test process + optional PPL-equivalent).
  - Emits a **flag-acceptance table** + a **race-reproduction report**.
  - Explicitly logs `GetLastError()` after every `GetThreadContext` call (the parked code did not).
- A separate expert ruling recorded in `WORKER_HANDOFF.md` with an **explicit round allocation in the proposed `GTO-PRODUCT-RECOVERY` ledger namespace** (per charter §3.3 / §7). The allocation is **not** inherited from this audit; only separate governance can grant it.
- **No** Phase 1 round may be started under "DRx short-window" until both of the above have been **separately approved**.

This audit does not authorize any of the above.

### 6.4 Why not just retry the parked capture with the working tree patched?

Because:

- `crates/bwhook/**` and `crates/cli/src/unpacker/gto_host.rs` are **excluded from the workspace members** on baseline (per `WORKER_HANDOFF.md` § "Baseline vs research") — the parked code does not even compile in baseline.
- Even on `research/gto-bootwatch-20260728`, modifying `bwhook` to "try a different flag combination" is a Rust diff + rebuild + re-measure = **1 budget round** under `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 budget-burn rule, and the R1B budget round is **already consumed** (`4be4ee5`).
- Even if budget were available, the audit identifies H-D4 (anti-debug interference) as a hypothesis that, if true, would block DRx-based capture *categorically* — patching flag bits cannot recover from a kernel-side filter.

The audit recommends **not** patching and not retrying.

---

## 7. Non-claims

This audit does **not** claim any of the following:

- A fix for the parked capture class.
- A capture meeting the `same_epoch_committed≥3` gate.
- Product 1.0.
- `gto_launcher` perfect unpack.
- Phase 1 of `GTO-PRODUCT-RECOVERY` (or any other battlefield).
- Re-opening of R1B (charter §4.4) or activation of E2 (charter §4.5).
- A right to skip the `Route A residual-stop → stop-and-write-residual` discipline (charter §6.5 third-pass 2026-07-29).

This audit **is** a Phase 0.5 read-only debug-context investigation. It is the kind of activity the `docs/GTO_PRODUCT_RECOVERY_CHARTER_20260729.md` §6.4 Route D proposal explicitly proposed, **not** a route activation.

---

## 8. Appendix

### 8.1 Original log excerpts (key lines only)

#### A.1 — `r1b_01_bwhook.log` (519 bytes, full)

```text
bwhook R1B: inject wait-mode pid=23576 target=0x1405febb8 main_tid=13636
bwhook R1B: waiting arm event Local\MidaBwHookArm_23576
bwhook R1B: arm signaled — registering VEH + DR0 (main thread only)
bwhook R1B: OpenThread OK, SuspendThread(prev=0)
bwhook R1B: GetThreadContext(flags=0x100013) -> ok=false
bwhook R1B: arm_dr0_on_thread failed
bwhook R1B: wrote outcome D:\MidaVault\scratch\r1b_smoke_out\r1b_01_outcome.json
bwhook R1B: outcome=error same_epoch=false slot=0x0 pointee=0x0 committed=false arm_to_hit_ms=0
```

SHA-256: `0b21c10bf26b73da35b3a72945ab64143d96a3e82f9458c3627337da3ce1e8e8`.

#### A.2 — `r1b_01_outcome.json` (selected fields, full file is 1006 bytes)

```json
{
  "schema": "gto.transient_epoch_trap/v1",
  "capture_reason": "dr0_fail",
  "outcome": "error",
  "same_epoch": false,
  "target_rip": "0x1405febb8",
  "hit_rip": "0x0",
  "current_rsp": "0x0",
  "current_rax": "0x0",
  "slot_va": "0x0",
  "slot_rsp_source": "current_suspended",
  "committed_readable": false,
  "blob_len": 0,
  "blob_fnv1a64": "",
  "note": "R1B capture-only; same_epoch=true only on VEH hit at target with current RSP+RAX slot"
}
```

SHA-256: `18bc16d8b95448d72717642a5c10f80da496bf58ad750db2639e21a2020ce74d`.

#### A.3 — `r1a_n10_aggregate.json` (key counts)

```json
{
  "ok_exit": 10,
  "n": 10,
  "by_reason": {
    "ui_or_timeout_miss": 1,
    "hard_deadline_last_near": 9
  },
  "same_epoch_committed": 0,
  "mixed_epoch_committed": 9,
  "ui_or_timeout_miss": 1,
  "sample_bypass_manifest_hits": 0,
  "e2_gate_same_epoch_committed_ge3": false
}
```

SHA-256: `9aad531f74eca4fecb8d78f8b8f275d4eae29ae64833dd6ff82ee39dd7a6bc17`.

#### A.4 — `R1B_RESIDUAL_STOP.md` (full, 734 bytes)

```text
# R1B transient epoch trap — RESIDUAL STOP
Date: 2026-07-29T15:39:32
Target RIP: 0x1405febb8
DLL: D:\MidaVault\scratch\cargo-target\debug\mida_bwhook.dll
N runs: 1
same_epoch hits: 0
committed_readable hits: 0
Gate: >=3 same_epoch=true (with committed_readable=true required for acceptance)

## Outcome

Gate **not met**: fewer than 3 `same_epoch=true` + committed+readable
captures in N=10 runs. Same-suspend epoch proof was not obtained.

## Next step

Stop polishing the R1B trap. Either:
1. Document the residual and seek expert direction (post-VM
   capture strategy, not poll-based interception).
2. Re-scope the GTO product path away from `load-site at
   .KI3+0x5a10` since Themida VM owns execution.
```

SHA-256: `bb140399acfde3d76900906f18af08044069891509c9c8ab59a68aa0e70011b8`.

### 8.2 Hash inventory (all SHA-256, audit-start timestamps in `D:\MidaVault\` mtime)

| File | SHA-256 |
|------|---------|
| `R1B_RESIDUAL_STOP.md` | `bb140399acfde3d76900906f18af08044069891509c9c8ab59a68aa0e70011b8` |
| `r1b_summary_20260729-120703.json` | `244c274d3baae9b3e877a7b017c68b675b552b390688d9d73e9cf8becb523690` |
| `r1b_summary_20260729-145140.json` | `00d562448e68e7a1c5e7ff3f0e7a7629175f892e2de8d95447174aa12cb9977a` |
| `r1b_summary_20260729-153634.json` | `33372108be19c220427a7599e7e2b7f822d8c8421d89b12d8ce7acc748618e76` |
| `r1b_summary_20260729-153932.json` | `22098b45cead8135315abc1ab84ed84ec465c4a882f5695f9f9f333c55023909` |
| `r1b_smoke_log\r1b_01_bwhook.log` | `0b21c10bf26b73da35b3a72945ab64143d96a3e82f9458c3627337da3ce1e8e8` |
| `r1b_smoke_out\r1b_01_outcome.json` | `18bc16d8b95448d72717642a5c10f80da496bf58ad750db2639e21a2020ce74d` |
| `r1a_n10_aggregate.json` | `9aad531f74eca4fecb8d78f8b8f275d4eae29ae64833dd6ff82ee39dd7a6bc17` |
| `r1a_n10_summary.json` | `fb3fe40ee6a766517e2858c7cd22d1f659a4013fef265e59aeec6bbbac10bda0` |

(Note: the `r1b_summary_*.json` files' top-of-file `ts` field uses a `YYYYMMDD-HHMMSS` form, not a UTC/ISO timestamp; the file mtimes in §2.1 are the canonical local-time audit-start reference.)

### 8.3 Exact read-only inspection commands

```powershell
# 1. Enumerate evidence inventory (no reads):
Get-ChildItem -ErrorAction SilentlyContinue `
  'D:\MidaVault\scratch\r1b_smoke_log\',`
  'D:\MidaVault\scratch\r1b_smoke_out\',`
  'D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\',`
  'D:\MidaVault\scratch\bootwatch\r1a_n10_20260728-192757\' `
  -Recurse -Force -File

# 2. SHA-256 hashes (read-only):
Get-FileHash -Algorithm SHA256 <each file> | Format-List Path,Hash

# 3. Content reads (read-only):
Get-Content 'D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\R1B_RESIDUAL_STOP.md'
Get-Content 'D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\r1b_summary_*.json' -Raw
Get-Content 'D:\MidaVault\scratch\r1b_smoke_log\r1b_01_bwhook.log'
Get-Content 'D:\MidaVault\scratch\r1b_smoke_out\r1b_01_outcome.json' -Raw
Get-Content 'D:\MidaVault\scratch\bootwatch\r1a_n10_20260728-192757\r1a_n10_aggregate.json' -Raw
Get-Content 'D:\MidaVault\scratch\bootwatch\r1a_n10_20260728-192757\r1a_n10_summary.json' -Raw

# 4. Immutable refs (read-only git show):
git show 4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md
git show 4c2b545:docs/GTO_POINTEE_EPOCH_R1A_20260728.md
git show 4c2b545:docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md

# 5. Parked bwhook source (read-only; not on baseline HEAD):
git show 4be4ee5:crates/bwhook/src/lib.rs
```

No file was written; no command produced a side effect beyond printing to stdout.

### 8.4 Git status before / after

#### Before this audit task started

```text
## baseline/legacy-recovery-20260722
e19b129bc5eb4b8204f86260462de74a753a8f3d
e19b129 docs(gto): file product recovery governance proposal
```

Working tree clean — only the `e19b129` commit ahead of `c5729fe`. No tracked-file modifications, no untracked files.

#### After this audit task

```text
## baseline/legacy-recovery-20260722
 M WORKER_HANDOFF.md
?? docs/GTO_PRODUCT_RECOVERY_ROUTE_D_AUDIT_20260729.md
```

Tracked-file modifications: **only `WORKER_HANDOFF.md`** (the approved Phase 0.5 audit-filed record). Untracked: **only `docs/GTO_PRODUCT_RECOVERY_ROUTE_D_AUDIT_20260729.md`** (this audit document). No source code (`crates/**`), no tooling (`tools/**`), no vault writes, no commits, no push.

### 8.5 Self-check (observed at task end)

Tracked-file checks (handoff only):

- `git diff --check` — covers **only tracked-file modifications** (here: `WORKER_HANDOFF.md`). Expect silent; trailing whitespace or conflict markers would surface here.
- `git diff --name-status` — expect exactly `M	WORKER_HANDOFF.md` (no source files).
- `git status --short --branch` — expect `## baseline/legacy-recovery-20260722` with one tracked modification (` M WORKER_HANDOFF.md`) and one untracked file (`?? docs/GTO_PRODUCT_RECOVERY_ROUTE_D_AUDIT_20260729.md`).

Untracked-file checks (this audit document):

- Trailing whitespace: `rg -n "[ \t]+$" docs/GTO_PRODUCT_RECOVERY_ROUTE_D_AUDIT_20260729.md` — expect no hits.
- Markdown link resolution (plain `[text](path)` form, excluding research-only files that are deliberately cited as `4c2b545:docs/...` code spans): see the script in `WORKER_HANDOFF.md` Phase 0.5 / proposal-filed records; expect all targets resolvable on baseline HEAD.
- Content self-check: `rg -n "Phase 0.5|Route D|budget consumed = 0|not Phase 1|not R1B re-entry|not E2" docs/GTO_PRODUCT_RECOVERY_ROUTE_D_AUDIT_20260729.md WORKER_HANDOFF.md` — expect hits in both files (audit doc + handoff Phase 0.5 record).