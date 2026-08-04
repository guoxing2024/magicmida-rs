# GTO Product Recovery — read-only governance proposal (2026-07-29)

> **Type:** governance proposal (docs-only). **Not** a re-entry authorization. **Not** a charter amendment. **Not** a code-change mandate.
> **Branch:** `baseline/legacy-recovery-20260722` @ `c5729fe`
> **Binding goal:** [`docs/PROJECT_GOAL_20260725.md`](PROJECT_GOAL_20260725.md) — `gto_launcher` perfect unpack
> **Discipline:** read-only audit of existing docs / git history / vault evidence only; **zero** code change, **zero** live run, **zero** budget consumption

---

## 0. One-sentence proposal

**Propose** opening a **new** battlefield `GTO-PRODUCT-RECOVERY` whose *Phase 0* is a strictly read-only product-recovery audit (no code, no rebuild, no re-measure) of all evidence ever collected on `gto_launcher`, propose a ranked set of routes that — *if* this proposal is approved by separate governance — would draw budget from a **separate ledger namespace** independent of the frozen `GTO-POINTEE-EPOCH` ledger. **This document does not open the battlefield, does not allocate budget, and does not authorize any code change.** A **separate governance ruling** (charter amendment or new expert order recorded in `WORKER_HANDOFF.md`) is the only thing that could open Phase 1; bare "continue" / "proceed" / handoff-passing-C-1 do not satisfy that bar.

> **Scope reminder.** Every phrase in this charter — "battlefield", "ledger", "rounds", "route" — refers to a **proposal** until separate governance lands. Reading this document as authorization to act is a category error; nothing here is self-executing.

---

## 1. Background (binding facts)

### 1.1 Status of the binding goal samples

| Sample | Status (binding) | Source |
|--------|------------------|--------|
| `origin_macro` (时光一键宏.exe) | **Perfect unpack complete** (1/2 samples) — Phase C reconfirmed 2026-07-29 | [`WORKER_HANDOFF.md`](../WORKER_HANDOFF.md) § "Phase C re-run"; [`docs/PROJECT_GOAL_20260725.md`](PROJECT_GOAL_20260725.md) § "时光一键宏.exe" |
| `gto_launcher` (启动器.exe) | **far / blocked** — "Themida VM owns execution (r27 r5); not residual polish" | [`WORKER_HANDOFF.md`](../WORKER_HANDOFF.md) § "gto_launcher — OPEN (the remaining sample)" |

### 1.2 Status of the frozen battlefield

`GTO-POINTEE-EPOCH` was opened on 2026-07-28 against `gto_launcher`, then **residual-stopped** after R1A. The seal is binding:

| Item | Status | Source |
|------|--------|--------|
| `GTO-POINTEE-EPOCH` | **Residual-stop after R1A** | [`docs/GTO_RESEARCH_CHARTER_20260728.md`](GTO_RESEARCH_CHARTER_20260728.md) §0, §10; `4c2b545:docs/GTO_POINTEE_EPOCH_R1A_20260728.md` §0 (research branch only — immutable ref) |
| R1A same-epoch gate | **0/10** committed+readable at `same_epoch=true` | seal §0 |
| R1B capture trench | **FROZEN** (rejected §6 E 2026-07-29) | [`WORKER_HANDOFF.md`](../WORKER_HANDOFF.md) § "Expert ruling on §6 E battlefield" |
| E2 minimal restore | **Dormant** (§4.5 dormant 2026-07-29 amendment) | charter §4.5 |
| §6 E battlefield | **NOT opened** (expert ruling 2026-07-29 second pass) | handoff § "Expert ruling" |

### 1.3 Budget ledger (binding, workspace-auditable, 2026-07-29 expert-verified)

From `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 step 4 ledger, **immutable** for `GTO-POINTEE-EPOCH`:

| Round | Commit / pin | Class | Code change | Status |
|-------|--------------|-------|-------------|--------|
| R1A | `6b2a6eb` (`gto_host.rs` +301 lines; outcome JSON + N=10 batch) | instrument (host observability) | yes — host only | **closed 2026-07-28** (consumed 1) |
| R1B | `4be4ee5` (bwhook + gto_host + runner +1342 lines; 4× live smoke at `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\`) | capture (VEH+DR0 short-window) | yes — bwhook + gto_host + tools | **closed 2026-07-29** (consumed 1) |
| E2 | **forbidden** in current charter | restore | — | **0 remaining** |

**Arithmetic:** used = R1A(1) + R1B(1) + E2(0) = **2**; cap = **2**; remaining = **0**.

### 1.4 Prior pre-charter peel series (R-GTO-UI r1 → r25b)

Independent of `GTO-POINTEE-EPOCH`, the `R-GTO-UI` peel series under `baseline/legacy-recovery-20260722` ran **multiple successive 2-round authorizations** (soft-cap r9/r10, then r11/r11b, r12/r12b, … through r25/r25b). All stopped on **window oracle Fail**. Deepest progress in that series:

- **r23b** (2026-07-25): RegisterClass **succeeds**; product-related class `ZhuChuangKou` appeared but not `NewClassName`; **STOP** ([`docs/UNATTENDED_RESIDUAL_20260724.md`](UNATTENDED_RESIDUAL_20260724.md) "R-GTO-UI class plant + RegisterClass lea (post r22b, 2 rounds)").
- **r25b** (2026-07-25): `0x34ed4` retarget to `NewClassName` was a **regression** (cdb `AFTER_34DB0 eax=0`); **STOP** (`UNATTENDED_RESIDUAL_20260724.md` "R-GTO-UI msg pump + real class lea (post r24b, 2 rounds)" — section truncated at file read; classified STOP per pattern).

`R-GTO-UI` peel-series rounds **predate** the `GTO-POINTEE-EPOCH` framing; they live in `docs/UNATTENDED_RESIDUAL_20260724.md` and the ledger is closed (all rounds stopped). **None** of these r1–r25b rounds are part of the `GTO-POINTEE-EPOCH` budget ledger; they share the goal sample but not the budget.

### 1.5 Why this proposal exists

1. `gto_launcher` is the **only remaining sample** blocking product 1.0.
2. `GTO-POINTEE-EPOCH` is **budget-exhausted** (§1.3) and **residual-stopped** (§1.2).
3. Existing evidence (charter §1, residual r1–r25b, KI3 §12.6) already suggests **multiple non-overlapping hypotheses** for the gap; no single current battlefield was chartered to compare them.
4. The project discipline (1 battlefield, ≤2 rounds, residual-stop) is **correctly closed** on `GTO-POINTEE-EPOCH`; trying to squeeze another route through it would (a) re-litigate the budget question and (b) violate the §4.4 budget-burn rule.

This proposal opens a **separate** battlefield with a **separate** budget, governed by a **separate** ledger, on a **separate** authorization bar.

---

## 2. Proposed battlefield name — `GTO-PRODUCT-RECOVERY`

**Proposed ID:** `GTO-PRODUCT-RECOVERY`.

### 2.1 What it is

- A **read-only audit** of all existing evidence on `gto_launcher`, ending in a **ranked route proposal**.
- A **proposed future battlefield** that — *if* approved by separate governance — would carry **its own proposed ledger namespace**, its own authorization bar, and its own residual.
- Anchored to the **same binding goal** as `GTO-POINTEE-EPOCH` ([`docs/PROJECT_GOAL_20260725.md`](PROJECT_GOAL_20260725.md) — `gto_launcher` perfect unpack), but **not a continuation** of the frozen battlefield.

### 2.2 What it is **not**

- **Not** `GTO-POINTEE-EPOCH` resumed. The name change is deliberate; reusing the old ID would conflate ledgers.
- **Not** a re-entry under `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4. §4.4 step 1 requires the operator to name `R1B re-entry` literally; this proposal does not.
- **Not** an E2 implementation under §4.5. §4.5 is dormant; this proposal does not propose restore.
- **Not** a new round of the `R-GTO-UI` peel series (r1–r25b). That series is closed.
- **Not** a silent `sample_bypass` expansion. [`docs/TRANSFORM_TAXONOMY_V1.md`](TRANSFORM_TAXONOMY_V1.md) `sample_bypass` blocks product `Accepted`; this charter inherits the rule.

### 2.3 Why a rename (not a new round on the old ID)

| Concern | Mitigation by rename |
|---------|----------------------|
| Budget bleed across battlefields | New ID ⇒ **proposed** `GTO-PRODUCT-RECOVERY` ledger namespace (see §7); **only separate governance** can allocate rounds into it — this proposal does not |
| Operator instruction confusion (e.g. "continue" re-read as `R1B re-entry`) | A **separate ID** merely avoids overloading old trigger language; it does **not** bypass, weaken, reopen, or otherwise affect `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4. The §4.4 bar still applies to anything that names `R1B re-entry` literally. |
| Mixing peel-series R-GTO-UI rounds with charter-budget R1A/R1B | Separate ID avoids double-counting in either ledger |
| Silent restoration of E2 under a new label | Charter §4.5 dormant protocol gates E2 globally; renaming does not bypass, weaken, or reopen it. See §8.4. |

---

## 3. Battlefield goal

### 3.1 End-state (same as `GTO-POINTEE-EPOCH` §4.2 — inherited, not redefined)

`gto_launcher` perfect unpack per [`docs/PROJECT_GOAL_20260725.md`](PROJECT_GOAL_20260725.md) § "完美脱壳的可操作定义":

1. Structure R0B `StructuralPassBehaviorPending`.
2. Load 10× isolated attempt=1, no pin walk.
3. Behavior: real product UI path (`NewClassName` window / AHK script engine load+execute) — not forced class, not skipped `MessageBoxW`, not skipped `LoadFile`, not `sample_bypass`.
4. Reproducible with current CLI on the merge-reviewed research → baseline path.
5. Zero `sample_bypass` patches in the candidate.

### 3.2 Phase-0 scope (this document; docs-only)

Phase 0 = **read-only audit + ranked route proposal**. Specifically:

- Re-read (no new writes) the evidence listed in §4.
- Produce the **hypothesis matrix** in §5.
- Produce the **ranked route proposal** in §6.
- Produce the **budget request** in §7.
- **Do not** modify any code, rebuild any artifact, run any live measurement, or extend any current battlefield's ledger.

### 3.3 Phase-1 scope (NOT opened by this document)

Phase 1 = a bounded implementation round on the operator-approved top-ranked route, with:

- ≤2 fix rounds (`改代码 → rebuild → 复测`), per [`docs/COURSE_CORRECTION_WORK_ORDER.md`](COURSE_CORRECTION_WORK_ORDER.md) §3.
- Independent ledger namespace `GTO-PRODUCT-RECOVERY` (proposed R1, R2) under a **proposed** budget (see §7). **The round count is not allocated by this proposal; only separate governance can allocate it.** This proposal does not itself authorize any Phase 1 round.
- All current battlefield protections inherited: `MIDA_GTO_NO_BYPASS=1`, no `MIDA_GTO_BYPASS`, no `MIDA_GTO_SEMANTIC_REPAIR` unless explicitly authorized, no `sample_bypass`, no push.

**Phase 1 requires separate governance:** a charter amendment to *this* document **or** a new expert ruling recorded in `WORKER_HANDOFF.md`, with both (a) operator naming `GTO-PRODUCT-RECOVERY Phase 1 on Route X` and (b) explicit ledger allocation. **No bare "continue" / "proceed" satisfies Phase 1 authorization.**

---

## 4. Read-only audit scope

### 4.1 In-scope evidence (re-read, no new writes)

| Artifact | Path / ref | Why |
|----------|-----------|-----|
| Binding goal | [`docs/PROJECT_GOAL_20260725.md`](PROJECT_GOAL_20260725.md) | Defines "perfect unpack" for the remaining sample |
| Course correction work order | [`docs/COURSE_CORRECTION_WORK_ORDER.md`](COURSE_CORRECTION_WORK_ORDER.md) | Defines the ≤2-round budget rule (Q2) and §4.4 budget-burn semantics |
| Operational handoff | [`WORKER_HANDOFF.md`](../WORKER_HANDOFF.md) | Records current E2-frozen / E-rejected / Phase C-reconfirmed / budget-exhausted state |
| R1A residual-stop seal | `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` (research branch only — **immutable ref**) | Authoritative Phase E status; **0/10 same_epoch** is the binding gate |
| R1A residual body | `4c2b545:docs/GTO_POINTEE_EPOCH_R1A_20260728.md` (research branch only — **immutable ref**) | Per-round evidence + `same_epoch=0/10` root cause (`hard_deadline_last_near` age ≈ 3.4 s) |
| GTO research charter | [`docs/GTO_RESEARCH_CHARTER_20260728.md`](GTO_RESEARCH_CHARTER_20260728.md) | §4.4 re-entry bar, §4.5 dormant E2, §6 round template |
| R-GTO-UI peel-series residual | [`docs/UNATTENDED_RESIDUAL_20260724.md`](UNATTENDED_RESIDUAL_20260724.md) | r1 → r25b diagnosis (each 2-round authorization); deepest progress r23b (`ZhuChuangKou` class reached, not `NewClassName`) |
| KI3 breakpoint design | `4c2b545:docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` (research branch only — **immutable ref**) | Three foundational facts: (i) `.KI3` never decrypted on disk; (ii) `.boot` is the live VM byte-code container; (iii) no portable spinlock VM-ENTER BP exists — capture is memory-state-epoch based |
| Audit package & self-correction | [`docs/AUDIT_PACKAGE_20260724.md`](AUDIT_PACKAGE_20260724.md); [`docs/AUDIT_SELF_CORRECTION_20260727.md`](AUDIT_SELF_CORRECTION_20260727.md) | Lab-self-correction history (esp. §22–27 referenced by charter §2.3) |
| Phase A audit report | [`docs/PHASE_A_AUDIT_REPORT_20260728.md`](PHASE_A_AUDIT_REPORT_20260728.md) | Pre-Phase-A audit snapshot |
| Transform taxonomy | [`docs/TRANSFORM_TAXONOMY_V1.md`](TRANSFORM_TAXONOMY_V1.md) | `sample_bypass` definition; blocks product `Accepted` |

### 4.2 Out-of-scope operations (this document does not perform)

| Operation | Why excluded |
|-----------|-------------|
| Modify `crates/bwhook/**` | Research-branch-only, R1B surface; this battlefield must not touch R1B code |
| Modify `crates/cli/src/unpacker/gto_host.rs` | Same — that file is the R1A/R1B code locus on research branch; freeze holds |
| Modify `tools/_r1b_transient_epoch_trap.py` | Per task standing order; same reasoning |
| Run live GTO unpack / R1B / E2 / restore | Forbidden under current charter §4.5 dormant |
| Use `sample_bypass` | Forbidden by [`docs/TRANSFORM_TAXONOMY_V1.md`](TRANSFORM_TAXONOMY_V1.md) |
| Push / remote | Per D8 / charter §3.7 |
| Treat bare "continue" as Phase 1 authorization | This document does not auto-start Phase 1; explicit governance required |

### 4.3 Git history items referenced (read-only)

For auditability of the budget ledger, the following commits are cited but **not** modified:

- `c5729fe` — baseline HEAD (P0 freeze + dormant E2 gate) — current HEAD.
- `6b2a6eb` — R1A host instrumentation (consumed 1 round, closed 2026-07-28).
- `4be4ee5` — R1B bwhook + gto_host + runner on `research/gto-bootwatch-20260728` (consumed 1 round, closed 2026-07-29).
- `4c2b545` — R1A seal pin (binding N=3 to immutable timestamped path) on `research/gto-bootwatch-20260728`.
- `7c86595`, `6211e6c`, `4288b5f`, `4ede9cc`, `dcf9ab6`, `9507e1f`, `010a401`, `a546c09`, `c59dc06`, `b164431`, `7bd046a`, `2d3e505`, `06320a1`, `a7ad655`, `1137958`, `0cfc105`, `bc69ae0`, `0a0fde5`, `a08c548`, `cfaede5`, `52d104b`, `289c6e6`, `80b5e67`, `2e2bd2f` — peel-series history (R-GTO-UI r1 → r25b) under `docs/UNATTENDED_RESIDUAL_20260724.md`.

---

## 5. Hypothesis matrix

Each row states a hypothesis for **why** `gto_launcher` cannot yet reach `NewClassName` window + AHK script execute, given all known evidence. "Gap" = what is not yet observed/confirmed. "Next read-only verification" = the cheapest re-read or cross-reference that strengthens or weakens the hypothesis without code change.

### 5.1 H1 — Themida VM ownership / dispatcher state

| Field | Content |
|-------|---------|
| Hypothesis | The protected process never executes native `.text@0x5a10`; Themida VM owns control via `.boot`/`.KI3` engine. The current dump architecture (static decode `.text` → jump to plaintext OEP) hits a structural ceiling; the OEP captured (`0x70b0` per residual r11/r11b) is a WindowProc, not a program entry ([`docs/UNATTENDED_RESIDUAL_20260724.md`](UNATTENDED_RESIDUAL_20260724.md) "R-GTO-UI step-1 read-only root-cause diagnosis"). |
| Existing evidence | (a) KI3 §0: `.KI3` is encrypted source store; `.boot` is the live VM byte-code container. (b) Charter §1: protected process never executes `.text`. (c) `WORKER_HANDOFF.md` gto_launcher Round 0: heap-rebasing wall; `0x846898` uncaptured gap. (d) R-GTO-UI r1 → r25b peel: peeling only relocates AV sites. |
| Gap | No capture method has yet produced a **named same-epoch load/VIP pointee** at `same_epoch=true` for `gto_launcher`. R1A ledger `same_epoch_committed = 0/10`. R1B's VEH+DR0 short-window capture (commit `4be4ee5`) is parked without a ≥3-of-10 same_epoch proof. |
| Next read-only verification | Re-read the R1A outcome JSONs (`r1a_n10_20260728-192757`) + the R1B smoke JSONs under `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\` (vault only). Cross-reference `capture_reason` distribution against `current_suspended_rip` to confirm the failure mode is *poll-induced mixed-age* rather than *region-never-committed*. **No new live runs.** |
| Viable as new battlefield? | **Yes**, but only with a method class that the operator names (per charter §4.4 step 1 + 2). The current R1B capture class (VEH+DR0) is the parked baseline; a new sub-class would need expert authorization under the **proposed `GTO-PRODUCT-RECOVERY` ledger namespace**, allocated by **separate governance** — not authorized by this proposal. |

### 5.2 H2 — AHK runtime object / script engine path

| Field | Content |
|-------|---------|
| Hypothesis | Even with a captured epoch pointee, AHK's runtime objects (`g_script`, label table, VarList, dispatch table, `0x147868` cmd table, `0x141bf0` global, `0xb9360` path allocator, `0x145db0` CS) are partially reconstructed in the dump; WinMain dereferences objects whose state is not preserved (heap-replay incompleteness L2 wall per r5/r6). |
| Existing evidence | (a) R-GTO-UI r5: CS @ `0x145db0` zeroed in dump; re-init to `LockCount=-1` resolves CS AV (validated byte-patch experiment). (b) R-GTO-UI r7 (CODE SHIPPED): CS re-init + gscript cap raise; CS AV cleared, next layer = exception-object g_script source. (c) R-GTO-UI r8: AHK call-obfuscation cookie (`0x1454b8`) needs `*(0x14ca60)` live, blocked by anti-debug + init-AV deadlock. (d) r11 → r25b peel: label table count + mName + sort; reached `CALL_C13D0 rax=1` (r21b) then `CALL_34DB0 eax=1` (r22b/r23b) but never `NewClassName`. (e) Deepest: r23b created `ZhuChuangKou` class, not `NewClassName`; r25b retarget to `NewClassName` regressed to `eax=0`. |
| Gap | The runtime-object surface has been individually probed (CS, gscript, cmd table, label count, mName, sort, path allocator) but no combination in any single round 2-fix reached `NewClassName`. The interdependence graph is **partially mapped, not closed**. |
| Next read-only verification | Cross-reference the r1 → r25b residuals for **which** runtime object was the most recent blocker per round; produce a directed graph (object → blocker → revealed next blocker). Static analysis only. **No new live runs.** |
| Viable as new battlefield? | **Yes**, but as a bounded **iterative capture-completeness** effort (re-init + per-object hot-root addition + label-name exact-graph), explicitly NOT the cookie/anti-tamper RE that r8 misclassified. Per r6 verdict: "tractable engineering, not research" — but multi-round, not 2-round. |

### 5.3 H3 — Loader / runtime initialization ordering

| Field | Content |
|-------|---------|
| Hypothesis | The captured `0x70b0` (WindowProc per r11 diagnosis) plus the W2 `emit_clear_volatile_regs` (which clobbers rcx/rdx/r8/r9) plus the boot-stub heap replay **compose incompatibly** with a fresh `mainCRTStartup`. Direction 1 (OEP re-capture) AV'd at `_initterm`; direction 1b (post-`_initterm` WinMain EP) AV'd at `_initterm` helpers (bad module-name string global) and at WinMain (stale CS `OwningThread`). The stub's heap replay does not match the CRT init order the unpacked binary actually needs. |
| Existing evidence | (a) `docs/UNATTENDED_RESIDUAL_20260724.md` "R-GTO-UI step-1": `0x70b0` = WindowProc (msg-dispatch). (b) "R-GTO-UI round 3 (direction 1)": OEP re-capture to `mainCRTStartup @ 0xd92d4` → AV. (c) "R-GTO-UI round 4 (direction 1b)": post-`_initterm` EP `@0xd9268` → AV at `GetModuleHandleA` (NULL module-name string) and at `RtlEnterCriticalSection` (stale CS state). (d) "R-GTO-UI round 5": CS re-init technique validated; revealed anti-tamper layer. (e) r7 (CODE SHIPPED): CS re-init on the default EP path is harmless. |
| Gap | No tested combination of (a) different OEP + (b) different stub-replay surface + (c) re-init policy has reached the post-init CRT helper layer cleanly. Init-ordering is half-mapped. |
| Next read-only verification | Static trace of `__scrt_common_main_seh` (RVA `0xd9160`) → `mainCRTStartup` (`0xd92d4`) → WinMain call site (`0xd9268`) → WinMain (`0xd97ac`) → product path (`0x5a10` → `0x63f4` → `0x65d1` → `0x34db0` → `RegisterClassExW` → `CreateWindowExW`), with each step annotated by what stub replay currently provides vs what the live CRT init would provide. **Static analysis only.** |
| Viable as new battlefield? | **Yes**, but framed as **stub-redesign** (skip heap replay OR replay-and-set-EP-to-post-init), explicitly beyond OEP-detection. Per r4 verdict: "stub-redesign is beyond 'OEP re-capture'." |

### 5.4 H4 — Import / bootstrap mismatch

| Field | Content |
|-------|---------|
| Hypothesis | The unpacked binary's IAT + `.boot` payload + gscript pointer slots are inconsistent: IAT span capped to `0x11e0` (572 slots), 98% rebuilt, but `.text` calls into interior IAT zeros (19 sites in r9; 12 patched in r10) leave gaps; cookie mirror (`0x141020 → 0x1454b8`) was added in r9 to bridge AHK's call-obfuscation skip path. Some IAT symbols WinMain references remain unresolved or zero in the dump. |
| Existing evidence | (a) R-GTO-UI r9 (CODE SHIPPED): IAT gap retarget (`iat_gap_retarget.rs`) + cookie mirror. (b) r10 live: `interior_zeros=19, sites_patched=12`. (c) `load_no_crash_v0` green in r10. (d) `docs/UNATTENDED_RESIDUAL_20260724.md` "GTO independent-host progress 2026-07-24": external-only IAT resolve; `wrapper_call_patch 0/0`; never-freeze on packer sections. |
| Gap | Which **specific** IAT symbols still AV after r10 was not enumerated; the residual records "AV at later site" but does not list a symbol-level gap audit. |
| Next read-only verification | Cross-reference r10's `iat_gap_retarget` log + r9/r10 `interior_zeros` / `sites_patched` / `mapped_gaps` against WinMain's static IAT calls (extract from `.text` call sites with modrm `[rip+disp32]` referencing the IAT FirstThunk). Static-only; no live calls. |
| Viable as new battlefield? | **Marginal.** Most of the easy IAT gap was already closed in r9/r10. A fresh round would target residual interior zeros, which is closer to "polish" than "wall". **Not recommended as top-ranked route** unless H1/H2/H3 audit shows IAT gaps are still load-blocking. |

### 5.5 H5 — Debug-context / hardware breakpoint incompatibility

| Field | Content |
|-------|---------|
| Hypothesis | The R1B capture class (VEH+DR0) hit `GetThreadContext` failures that earlier handoff drafts mis-attributed to a missing `CONTEXT_AMD64` bit (the high `0x100000` is already inside `CONTEXT_DEBUG_REGISTERS_AMD64 (0x100010)` and `CONTEXT_CONTROL_INTEGER_AMD64 (0x100003)`). The actual root cause of `GetThreadContext` Err is **not established** — candidates: (i) flag combination behavior on Win10/11 build; (ii) suspend-count / handle race (`SuspendThread(prev=0)` observed while BootWatch had already frozen RIP); (iii) thread-state precondition not met at DLL arming time. |
| Existing evidence | (a) `WORKER_HANDOFF.md` § "Open discipline notes" — explicit withdrawal of the CONTEXT_FLAGS one-line fix claim. (b) `bwhook` parked on research branch (`4be4ee5`). (c) SuspendThread race logged `D:\MidaVault\scratch\r1b_smoke_log\` (vault only). |
| Gap | No empirical `GetThreadContext` reproduction under controlled flags; no enumeration of which Win10/11 build properties govern the flag-acceptance; no race-condition hypothesis verified. |
| Next read-only verification | Cross-reference `r1b_smoke_log` against the `bwhook` source for `GetThreadContext` flag assembly. Static-only: trace which flag values are actually passed; check whether the value Windows accepted (per `Set/GetLastError`) is logged; check whether the race-handling `if frozen_rip.is_none() && bootwatch_vm_enter_rip.is_none()` gate (per handoff § Open discipline notes) is positioned correctly. **No live attach.** |
| Viable as new battlefield? | **Marginal as a standalone battlefield.** This is a **debug-context root-cause investigation** that should be a precondition to any future R1B-class re-entry (under the **proposed `GTO-PRODUCT-RECOVERY` ledger namespace**, only **if** separate governance allocates it). As H1's sub-class, it could be ranked separately (see Route D in §6). |

### 5.6 H6 — Independent-PE feasibility vs goal write-down

| Field | Content |
|-------|---------|
| Hypothesis | The binding goal [`docs/PROJECT_GOAL_20260725.md`](PROJECT_GOAL_20260725.md) requires an *independent* PE — no `sample_bypass`, real product UI, AHK script engine load/execute. If no route H1–H5 can be completed within a bounded number of fix rounds, the **honest** outcome is a **goal write-down** (per charter §4.2: "expert may authorize scope write-down (document 'independent-PE perfect unpack not achievable for this VM-mode build')"). |
| Existing evidence | (a) Charter §4.2: write-down is an explicit, allowed outcome. (b) Charter §4.1: research exit ≠ product exit. (c) `WORKER_HANDOFF.md` § "Takeover status": **product 1.0 still NO**. (d) r1 → r25b peel: every 2-round authorization closed without `NewClassName`; deepest class seen = `ZhuChuangKou` (r23b). |
| Gap | No aggregated feasibility review across all 6 hypotheses has been documented in one place; each prior round's residual is incremental. |
| Next read-only verification | **This proposal is the verification artifact.** Reading §5.1–§5.5 + §6 produces the feasibility review. **No new live runs.** |
| Viable as a battlefield? | **Not as a code battlefield** — a write-down is a *governance* artifact, not a fix round. But this battlefield's **Phase 0 output (§6 ranked routes + §7 budget request)** is the natural place for the feasibility recommendation to be expressed, then routed to operator for §4.2 scope write-down if no route survives ranking. |

---

## 6. Ranked route proposal (Phase 1 candidates; **NOT opened** by this document)

Routes are ordered by **expected evidence-density per fix round**, not by expected success rate. Lower-ranked routes may still be the right choice if higher-ranked ones are already closed under a different ledger.

### 6.1 Route A — VM ownership recovery (extends H1)

- **Idea:** Re-attempt same-epoch capture under a **named new method class** (operator-named; not VEH+DR0 if that class is already exhausted under `GTO-POINTEE-EPOCH`'s parked R1B). Concretely, candidate sub-classes that the proposal must NOT pre-commit to (operator chooses):
  - Memory-state-epoch capture (KI3 §0 recommendation): VirtualAlloc anchor → `.boot` write-storm entropy stable → first execution into `.boot` = VM ENTER.
  - Earlier VM ENTER capture (before the dispatch fetch where R1A's hard-deadline mixed-age was observed).
  - External soft-BP / non-poll technique (charter §5 allowed), with a non-product linear-path bar (i.e. the soft-BP must bind a VIP epoch without locking the linear path used in r1–r26 hot-root onion peels).
- **Cost:** ≤2 fix rounds (`改代码 → rebuild → 复测`).
- **Surface allowed:** a **new** capture code locus (e.g. `crates/cli/src/unpacker/gto_host.rs` *on a new branch* — must NOT mutate the parked R1B version), plus a new runner script (NOT `tools/_r1b_transient_epoch_trap.py`, which is the parked R1B runner). Workspace policy: keep new code off baseline until expert merge review (charter §9).
- **Evidence bar (per charter §4.4 step 4 analog):** ≥3 of N=10 with `same_epoch=true && committed_readable=true`. If fewer, residual-stop per §4.3.
- **Risk:** repeats R1B's 1-round budget consumption; if the sub-class is the same as parked R1B, the result is no new evidence.
- **Score:** medium — the parked R1B implies this route is the **highest-information** if the operator names a genuinely new sub-class, but the lowest if the operator re-uses VEH+DR0.

### 6.2 Route B — AHK runtime / script-object recovery (extends H2)

- **Idea:** Iterative capture-completeness effort: CS re-init at known CS RVAs (r5/r7 technique, validated) + per-object hot-root addition to `DumpCapturePolicy` + label-name exact-graph completion + path allocator cold-init fix. The r1 → r25b peel series mapped the blocker graph; this route would commit to closing it within a fresh 2-round budget.
- **Cost:** ≤2 fix rounds. Per r6 verdict, "unlikely within 2 rounds — peeling the onion." The proposal notes this; the route would need an explicit **iterative-capture** budget (not the standard 2-round cap) if the operator wants a fair shot.
- **Surface allowed:** `crates/pe/src/dumper/heap_global_snapshot.rs`, `crates/pe/src/dumper/capture_policy.rs`, `crates/pe/src/dumper/container_bootstrap.rs` (NOT `gto_host.rs` on research branch — that's frozen). New code goes on a **new branch** derived from baseline.
- **Evidence bar:** `window_class NewClassName` Pass under `MIDA_GTO_NO_BYPASS=1`, `MIDA_GTO_BYPASS` absent, no `MIDA_GTO_SEMANTIC_REPAIR`, N=3 attempt=1 (per P1-A precedent for `gto_launcher` in `UNATTENDED_RESIDUAL_20260724.md` "P1-A"). Compose `Accepted` requires behavior oracle beyond `load_no_crash_v0` (W3 minimum).
- **Risk:** r25b already showed register-class-name (label name) and post-MB paths regress under isolated edits. Two rounds is tight.
- **Score:** low-medium — the peel-series evidence is exhaustive enough that another 2-round attempt on the same code surface is **diminishing-returns**. Recommended only if the operator authorizes an iterative-capture budget.

### 6.3 Route C — Loader equivalence / acceptance-contract review (extends H3)

- **Idea:** **Stub redesign** (charter §4.2 implied; r4 verdict named this as beyond OEP-detection): either (a) skip heap replay and rely on real ctors + fully-fixed-up `.data`/`.rdata`, or (b) replay heap AND set EP to post-`_initterm` point (the `call WinMain` site inside `__scrt_common_main`, i.e. `0xd9268`), not `mainCRTStartup`. This is **not** a new OEP-detection attempt; it's a re-architecture of the transfer stub.
- **Cost:** ≤2 fix rounds. Per r4 verdict: "stub-redesign is beyond 'OEP re-capture'." Likely needs more; the route would explicitly request a stub-redesign sub-budget if approved.
- **Surface allowed:** `crates/pe/src/dumper/container_bootstrap.rs`, `crates/pe/src/dumper/heap_bootstrap.rs`, `crates/pe/src/dumper/tls_bootstrap.rs` (read-only per current freeze; Phase 1 would need explicit un-freeze).
- **Evidence bar:** `load_no_crash_v0` N=3 attempt=1 must not regress from baseline `1.0` (r10 baseline); `window_class NewClassName` oracle must reach Pass without `sample_bypass`. Phase C smoke (`p1_4case_fresh_20260724-161856`) must remain green after any shared `mida-pe` change (charter §3.8).
- **Risk:** high — direction 1 / 1b in r3/r4 both AV'd; the heuristic variants are speculative. Two rounds is tight even with a redesign.
- **Score:** low — already attempted twice (r3, r4) with no green outcome; committing more rounds on this surface without a new heuristic (e.g. init-order-aware replay) repeats the pattern.

### 6.4 Route D — Debug-context root-cause tooling (extends H5)

- **Idea:** **No code change to `gto_host` / `bwhook` / `_r1b_transient_epoch_trap`.** Only investigation: which `GetThreadContext` flag combinations are actually accepted on the Win10/11 build under which suspend-count state; whether the race `SuspendThread(prev=0)` while host had skipped its own suspend is reproducible. Output: a **flag-acceptance table** + a **race-reproduction report**. This is investigation, not a fix round; per charter §4.4 step 4 budget-burn rule, **investigation that does not produce Rust/Python diff + rebuild + re-measure is NOT a budget round**.
- **Cost:** 0 fix rounds (docs-only). May inform Route A's choice of sub-class.
- **Surface allowed:** none (read-only). Vault files: `D:\MidaVault\scratch\r1b_smoke_log\`.
- **Evidence bar:** the flag-acceptance table is itself the deliverable.
- **Risk:** near-zero; this is investigation only.
- **Score:** **highest as a precondition**, lowest as a stand-alone. Recommended as **Phase 0.5** (still docs-only, still no code change) before Route A or B commits any fix round.

### 6.5 Recommended order — **non-automatic**

> ⚠️ **Non-automatic fallback (third-pass 2026-07-29).** Nothing in §6.5 self-executes. Each numbered step requires its own operator name + governance artifact recorded in `WORKER_HANDOFF.md`. Steps 2–4 each require a **separate governance ruling** that explicitly allocates rounds in the `GTO-PRODUCT-RECOVERY` ledger namespace; nothing here is pre-authorized.

If Phase 1 is approved by separate governance (§3.3), the proposal recommends:

1. **Phase 0.5 = Route D** (docs-only flag-acceptance + race report). 0 fix rounds. Approval is **separate governance**; this proposal does not preempt it.
2. **Phase 1 = Route A** on a **named new sub-class** (operator-chosen; not VEH+DR0). ≤2 fix rounds, on a **separate ledger namespace**. Approval is **separate governance**; this proposal does not preempt it.
3. **If Route A residual-stops, STOP.** Write residual per the analog of `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.3 (failure stop). Do **not** auto-fall-back to Route B, do **not** auto-reallocate rounds, do **not** silently re-label. **Route B (or any other route) does not auto-start** — starting it requires a **new** governance ruling recorded in `WORKER_HANDOFF.md` that:
   - explicitly names `GTO-PRODUCT-RECOVERY Phase 1 on Route B`, and
   - **explicitly allocates** rounds in the `GTO-PRODUCT-RECOVERY` ledger namespace (the allocation is **not** inherited from this proposal).
4. **If a separately-approved Route B residual-stops, STOP again.** Write residual. Route to operator for **goal write-down** per charter §4.2 — that write-down is also a governance artifact, not code.

Routes C and the un-iterative form of Route B are **not recommended** as top-2 because their evidence density (r3/r4/r25b) shows already-attempted classes without green. The "non-automatic" qualifier on §6.5 also applies to Route C as a candidate Route A successor.

---

## 7. Budget request

### 7.1 Phase 0 (this document)

| Item | Value |
|------|-------|
| Fix rounds consumed | **0** |
| Code change | **none** |
| Live runs | **none** |
| Vault writes | **none** |
| Push | **none** |

### 7.2 Phase 0.5 (Route D, docs-only) — *if separately approved*

| Item | Value |
|------|-------|
| Fix rounds consumed | **0** (docs-only; not a budget round per charter §4.4 budget-burn rule) |
| Code change | **none** |
| Live runs | **none** (vault log re-read only) |
| Vault writes | **none** |

### 7.3 Phase 1 (Route A — or operator-selected top route) — *if separately approved*

| Item | Value |
|------|-------|
| Fix rounds budgeted | **≤2** (`改代码 → rebuild → 复测`), per [`docs/COURSE_CORRECTION_WORK_ORDER.md`](COURSE_CORRECTION_WORK_ORDER.md) §3 |
| Per-round definition | code diff → rebuild → re-measure; **any** Rust/Python edit that affects capture is a fix round regardless of label (per charter §4.4 budget-burn rule) |
| New ledger | **GTO-PRODUCT-RECOVERY R1, R2** — separate from `GTO-POINTEE-EPOCH` ledger |
| Ledger independence | this battlefield's rounds **do not** count against the `GTO-POINTEE-EPOCH` `used=2/cap=2/remaining=0` ledger; that ledger is closed (charter §4.5 dormant) and can only be re-opened by **separate** governance (charter amendment or new expert ruling) |
| Ledger inheritance | any prior `GTO-POINTEE-EPOCH` work (R1A `6b2a6eb`, R1B `4be4ee5`) **stays consumed** and is **not** re-counted under this new battlefield |
| Anti-revival protection | the new ledger **cannot** be used to re-litigate R1A's `same_epoch=0/10` or R1B's parked capture class; those are historical facts and may only be cited as evidence inputs to Route A's method-class choice |

### 7.4 Budget independence — explicit non-bleed rule

This proposal does **not** request any expansion of the `GTO-POINTEE-EPOCH` budget. It does **not** request that the parked R1B capture class be re-opened under any name. It does **not** request that E2 (§4.5 dormant) be activated. A literal `R1B re-entry` instruction in the operator message does **not** satisfy Phase 1 authorization for this battlefield; only `GTO-PRODUCT-RECOVERY Phase 1 on Route X` (with X named) satisfies it, and even then requires separate governance recorded in `WORKER_HANDOFF.md`.

---

## 8. Explicit prohibitions (binding)

These are not aspirational; they are required by prior binding artifacts and re-stated here for this battlefield's scope.

1. **No restore of R1B blobs** (the `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\` N=4 smoke data, the `r1a_n10_20260728-192757\` outcome JSONs, and the parked bwhook code) under any path on any new branch. The blobs are evidence inputs only; restoring them as a runtime artifact is forbidden.
2. **No post-VM restore** as a Phase 1 goal. Restore from a captured pointee is `GTO-POINTEE-EPOCH` E2 (§4.5 dormant); it is forbidden in this battlefield until §4.5 is activated by separate governance. Phase 1 routes in this charter are **capture-side**, not restore-side.
3. **No UI-patch fake-green** (no `sample_bypass`, no forced `NewClassName`, no skipped `MessageBoxW`, no skipped `LoadFile`, no `MIDA_GTO_BYPASS=1`). [`docs/TRANSFORM_TAXONOMY_V1.md`](TRANSFORM_TAXONOMY_V1.md) `sample_bypass` blocks product `Accepted`.
4. **No silent bleed into `GTO-POINTEE-EPOCH` ledger.** No commit under this battlefield may modify `crates/bwhook/**`, `crates/cli/src/unpacker/gto_host.rs` (research-branch version), or `tools/_r1b_transient_epoch_trap.py`. No commit under this battlefield may re-introduce VEH+DR0 short-window capture as a new artifact under a renamed file unless the operator names the sub-class under §4.4 step 1 + 2 of the prior charter (which requires its own separate governance).
5. **No push / remote.** Per D8 and charter §3.7. Local commits on a new branch derived from `baseline/legacy-recovery-20260722` are allowed; push requires separate authorization.
6. **No "continue" re-read.** A bare "continue" / "proceed" / handoff-passing-C-1 instruction does **not** authorize Phase 1 of this battlefield. The operator must name `GTO-PRODUCT-RECOVERY Phase 1 on Route X` literally, and a new expert ruling (or charter amendment) must be recorded in `WORKER_HANDOFF.md` with the new ledger allocation.
7. **No Phase 1 self-start.** This document does not start Phase 1. Phase 1 requires separate governance; this document is the proposal artifact that such governance would reference.

---

## 9. Relationship to prior artifacts

| Artifact | Relationship |
|----------|-------------|
| [`docs/PROJECT_GOAL_20260725.md`](PROJECT_GOAL_20260725.md) | Inherits binding goal for `gto_launcher`; does not modify |
| [`docs/COURSE_CORRECTION_WORK_ORDER.md`](COURSE_CORRECTION_WORK_ORDER.md) | Inherits Q2 ≤2 rounds + Q6 commit discipline + D8 no-push; does not modify |
| [`docs/GTO_RESEARCH_CHARTER_20260728.md`](GTO_RESEARCH_CHARTER_20260728.md) | **Not** modified by this proposal. `GTO-POINTEE-EPOCH` remains residual-stopped; §4.4 + §4.5 unchanged. |
| `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` (immutable ref) | Cited as evidence; not modified |
| `4c2b545:docs/GTO_POINTEE_EPOCH_R1A_20260728.md` (immutable ref) | Cited as evidence; not modified |
| `4c2b545:docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` (immutable ref) | Cited as evidence; not modified |
| [`docs/UNATTENDED_RESIDUAL_20260724.md`](UNATTENDED_RESIDUAL_20260724.md) | Cited as evidence (R-GTO-UI peel-series residuals r1 → r25b); not modified |
| [`WORKER_HANDOFF.md`](../WORKER_HANDOFF.md) | This proposal notes a sync-up entry should be added ("proposal filed, not authorization") — see §10 |
| [`docs/TRANSFORM_TAXONOMY_V1.md`](TRANSFORM_TAXONOMY_V1.md) | `sample_bypass` rule inherited as binding |
| [`docs/AUDIT_PACKAGE_20260724.md`](AUDIT_PACKAGE_20260724.md), [`docs/AUDIT_SELF_CORRECTION_20260727.md`](AUDIT_SELF_CORRECTION_20260727.md) | Cited as evidence; not modified |

---

## 10. Operator stop state

```text
FILED — read-only proposal; Phase 1 NOT authorized
Budget consumed by this filing: 0 (docs-only, not a budget round per charter §4.4 budget-burn rule)
GTO-POINTEE-EPOCH ledger: UNCHANGED (used=2 / cap=2 / remaining=0; E2 dormant)
R-GTO-UI peel-series: UNCHANGED (closed r1 → r25b)
Push: NONE
Live runs: NONE
Next action requires: operator names `GTO-PRODUCT-RECOVERY Phase 1 on Route X`
                     + new expert ruling OR charter amendment recorded in WORKER_HANDOFF.md
```

**Non-claim:** filing this proposal does **not** authorize any code change, live run, push, ledger expansion, or Phase 1 start. It only registers the proposal artifact and the sync-up entry in `WORKER_HANDOFF.md`.

---

*Read-only governance proposal. Not a re-entry authorization. Not a charter amendment. Not a code-change mandate. Not product 1.0.*