# GTO Research Charter — GTO-POINTEE-EPOCH

> **Status:** **Residual-stop after R1A** — re-entry only per §4.4 (amended 2026-07-29, second-pass 2026-07-29).  
> **Source of truth for status (immutable):** `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §0. Baseline HEAD does not contain the seal file (it lives on `research/gto-bootwatch-20260728`); the `4c2b545:...` form is the only path resolvable from baseline. Earlier "Open" header is superseded by R1A seal; this charter's §10 is the live status reference but does not overrule R1A seal when in conflict.  
> **Branch:** `research/gto-bootwatch-20260728` (default worktree for code)  
> **Binding goal:** `docs/PROJECT_GOAL_20260725.md` — `gto_launcher` perfect unpack  
> **Product 1.0:** still **NO** until this charter's product exit is met **without** `sample_bypass`  
> **Discipline:** one battlefield · ≤2 fix rounds then residual-stop · evidence-driven · no fake UI green

---

## 0. One-sentence mission

Capture a **committed, readable pointee** at the real load epoch of  
`mov r10,[rsp+rax] @ 0x1405febb8` (or an equivalent proven VIP epoch), restore the  
minimum state needed for free-run past the next transfer, and only then reassess  
UI / AHK script reality — **without** r26b-class sample bypass patches.

---

## 1. Why this battlefield (hard wall, not polish)

Established facts (r27 r4–r5 + KI3 §12.6 + self-corr §22–27):

1. Dump **correctly decrypts** `.text` (e.g. WinMain prologue at `0x5a10` plaintext).
2. Protected process **never executes** those `.text` RVAs — Themida VM owns control  
   (EP / interpreter in `.boot` / `.,\W` / `.KI3` engine).
3. Candidate stub → `.text@0x5a10` runs the **wrong native path** (machine-ID MessageBox).
4. Heap slab + VirtualAlloc original-address remap: **necessary, not sufficient**.
5. DISPATCH-freeze pointee capture: slot often **MEM_FREE** / wrong epoch  
   (`GTO-POINTEE-CAPTURE-1` negative close — do not fake regions from dead dumps).
6. VEH/DR0 in-process capture: **anti-tamper kills** (`0xDEADC0DE` class).
7. External soft-BP: can execute 10⁵–10⁶ VIP fetches but locks **non-product** linear path.
8. Five r26b bypasses can fake `NewClassName` window oracle — **diagnostic only**;  
   taxonomy `sample_bypass` **blocks** product `Accepted`.

**Implication:** static dump + “jump to plaintext OEP” architecture has hit a ceiling.  
This charter is **post-VM state capture / epoch-correct restart**, not another hot-root peel.

---

## 2. Scope

### 2.1 In scope

| ID | Work |
|----|------|
| E0 | Baseline on research branch: reproduce DISPATCH freeze + slot MEM_FREE (or document delta) |
| E1 | **GTO-POINTEE-EPOCH** — capture at load instruction time / later VIP when region is committed+readable |
| E2 | Minimal pointee restore into restart stub / sidecar; free-run past next transfer |
| E3 | If E2 holds: reassess GTO-UI-1 (real class name / script path) **without** bypass |

### 2.2 Explicitly out of scope (this charter)

- Full Themida devirtualizer / universal VM lifter
- Product Ed25519 / CI signing (Phase F; separate)
- Expanding `sample_bypass` allowlist or default `MIDA_GTO_BYPASS=1`
- Mixing BootWatch mega-diff into baseline Set A without expert merge review
- Adding `crates/bwhook` to workspace `members`
- Lunlun / Xiongxiong / Dali as 1.0 gates
- Claiming product `Accepted` from `load_no_crash_v0` or export/window oracles alone

### 2.3 Code / doc home

| Asset | Location |
|-------|----------|
| Host residual | `crates/cli/src/unpacker/gto_host.rs` (research branch) |
| Region / inject APIs | `crates/core/src/windows_debugger.rs` (`MemoryRegionInfo`, `query_region_full`, …) |
| soft-BP analysis host | `tools/softbp_host.py` |
| RE bible | `docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` §12.6 |
| Self-corr stuck labels | `docs/AUDIT_SELF_CORRECTION_20260727.md` §22–27 |
| bwhook (research-only) | `crates/bwhook/**` — **exclude** from root members |
| Vault evidence | `D:\MidaVault\scratch\bootwatch\` and case evidence under vault only |

Baseline (`baseline/legacy-recovery-20260722`) remains the **P0 / origin-safe** line.  
Default implementation commits for this charter go on **`research/gto-bootwatch-20260728`**.

---

## 3. Non-negotiable gates

1. **`sample_bypass` never product-Accepts** (`docs/TRANSFORM_TAXONOMY_V1.md`).
2. **`MIDA_GTO_BYPASS` default OFF**; bypass dumps = diagnostic.
3. **Dumper never self-signs**; unsigned managed → Pending on product CLI posture.
4. **One battlefield**; max **2** rounds of code→rebuild→measure; then residual-stop.
5. **No debug-port assumptions** that contradict proven anti-tamper (prefer post-attach / external host patterns already validated).
6. **No fake pointees** from free/dead VAs (`GTO-POINTEE-CAPTURE-1`).
7. **No push/remote** unless separately authorized.
8. Origin perfect-unpack invariants (three-band scrub, EP OptionalHeader+16) must not regress if shared dump code is touched — re-run Phase C smoke after any `mida-pe` dumper change.

---

## 4. Success / exit criteria

### 4.1 Research exit (charter complete as research)

All of:

1. Documented capture method with vault evidence (JSON sidecars + logs) showing  
   committed+readable pointee at a **named** epoch (RIP/VIP + timing).
2. Free-run advances past the previously blocking transfer **≥2/3** independent runs  
   (or honest residual explaining irreducible wall).
3. Residual doc updated: what was proven / disproven / next wall.
4. Language remains research — **not** product 1.0.

### 4.2 Product-facing exit (only path to gto perfect-unpack claim)

All of (`PROJECT_GOAL_20260725`):

1. **No** r26b / `sample_bypass` patches in candidate.
2. Structure R0B `StructuralPassBehaviorPending`.
3. Load 10× isolated attempt=1.
4. Real product UI path (not forced class / skipped MessageBox / skipped LoadFile).
5. AHK script engine load/execute reality (not oracle-only).
6. Reproducible with current CLI on research→reviewed merge path.
7. Product Accept only under current contract (registered probe + managed + taxonomy + authenticity policy) — **not** this charter’s default deliverable.

If product exit is judged unachievable after residual-stop: expert may authorize  
**scope write-down** (document “independent-PE perfect unpack not achievable for this  
VM-mode build”) — **not** silent claim inflation.

### 4.3 Failure stop (mandatory)

After 2 fix rounds without E1/E2 measurable advance:

- Write/update residual (prefer `docs/UNATTENDED_RESIDUAL_20260724.md` appendix or  
  new `docs/GTO_POINTEE_EPOCH_RESIDUAL_YYYYMMDD.md`).
- Stop coding loops; do not open parallel GTO peels.
- Leave research branch tip green enough to rebuild; no half-merged baseline pollution.

---

### 4.4 R1B re-entry procedure (2026-07-29 amendment)

> ⚠️ **Logical correction (2026-07-29):** earlier draft made §4.4 contingent on
> §4.1–§4.3 being satisfied. That is **wrong** — §4.1 is the *research exit*
> (charter complete), §4.3 is the *failure stop* (residual without path). Neither
> is a prerequisite for re-entering R1B capture; neither alone proves R1B has a
> route forward. Re-entry is a **separate, operator-named** process. The correct
> sequence is:

**Sequence (mandatory, in order):**

1. **Operator names `R1B re-entry`.** A bare "continue" / "proceed" / handoff
   passing C-1 / "execute charter Round 0" does **not** satisfy this step.
   "R1B re-entry" must appear literally in the operator instruction, and must
   name the **method class** (e.g. "DR0 short-window capture at 0x1405febb8",
   "soft-BP VIP linear", "BootWatch earlier VM ENTER", etc.).
2. **Expert grants explicit authorization** for that method class with the
   evidence requirements named in step 3. The 2026-07-28 charter "open" is not
   such an authorization for R1B — R1A seal §0 froze the battlefield before any
   R1B method was reviewed. Expert may delegate review to a named reviewer,
   but the delegation must be recorded in `WORKER_HANDOFF.md` for audit.
3. **Capture under authorized method produces N=10 outcomes**, all under the
   same env contract (`MIDA_GTO_NO_BYPASS=1`, `MIDA_GTO_BYPASS` /
   `MIDA_GTO_SEMANTIC_REPAIR` absent, BootWatch / softbp env per §7). Each
   outcome's JSON sidecar must carry `same_epoch`, `committed_readable`,
   `at_fetch` / `near_fetch` / equivalent timing, and `rsp_source`. Aggregate
   written under `D:\MidaVault\scratch\r1b_n10_<ts>\r1b_n10_aggregate.json`
   plus pointer `D:\MidaVault\scratch\r1b_n10_latest.json`.
4. **≥3 of 10 with `same_epoch=true && committed_readable=true`.** If fewer than
   3 — **stop**, write residual per §4.3, do **not** propose E2. Per-battlefield
   fix budget is **≤2 rounds total** per `docs/COURSE_CORRECTION_WORK_ORDER.md`
   §3 (字面定义 `改代码 → rebuild → 复测`). Budget is **retrospective**: a round
   that has already produced Rust/Python diff, rebuild, and re-measure is
   consumed **whether the result passed, failed, was a miss, or was later
   retracted** — outcome does not refund budget.

   **Budget ledger (workspace-auditable, 2026-07-29 expert-verified):**

   | Round | Commit / pin | Class | Code change | Status |
   |-------|--------------|-------|-------------|--------|
   | R1A | `6b2a6eb` (`gto_host.rs` +301 lines; outcome JSON + N=10 batch) | instrument (host observability) | yes — host only | **closed 2026-07-28** (consumed 1) |
   | R1B | `4be4ee5` (bwhook + gto_host + runner +1342 lines; 4× live smoke in `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\`) | capture (VEH+DR0 short-window) | yes — bwhook + gto_host + tools | **closed 2026-07-29** (consumed 1) |
   | E2 | **forbidden** in current charter | restore | — | **0 remaining** |

   **Arithmetic:** used = R1A(1) + R1B(1) + E2(0) = **2**; cap = 2; remaining
   = **0**. Budget **exhausted** — see §4.5 dormant note.

   **Budget-burn rule (also explicit):** *Any* operator-authorized round that
   produces or modifies Rust/Python code, rebuilds, and re-measures is **1
   budget round** regardless of whether the change is "instrument", "capture",
   "restore", "free-run" or "validation". Pure analysis of existing logs/JSON
   (no code change, no rebuild, no re-measure) is **not** a round. Drafting a
   proposal document without code change is **not** a round.

   **Operator pre-declaration policy (rejected on 2026-07-29 second-pass):**
   earlier draft proposed that the operator pre-declare R1B as "measurement-
   only (0 rounds)" or "code-changing (1 round)" to pin the ledger. That
   proposal was **withdrawn**: pre-declaration expresses **intent only**, not
   the ledger; the ledger is determined by the **actual** Rust/Python diff +
   clean tree + rebuild + re-measure, **audited at commit time**. The audit
   trio is:
   1. **Pin commit** — the operator names the commit hash that introduces the
      round's code change (or, for uncommitted work, the diff hunks).
   2. **Confirm clean tree** before measurement — no uncommitted hunks that
      would muddy attribution.
   3. **Diff is the budget truth** — re-running or rebuilding existing code
      with no source change is **measurement**, not a fix round; **any**
      Rust/Python edit that affects capture is a fix round regardless of
      label.

5. **In the current charter (remaining = 0), E2 cannot be proposed, drafted,
   or implemented.** Any operator instruction carrying the literal `R1B re-
   entry` token — or `E2 implementation` — is **not authorization to act**;
   see §4.5 for the dormant protocol and the only governance path that can
   re-open budget.

**No one-line fix without empirical root cause.** Any candidate patch that
claims to fix a captured failure mode (e.g. a `CONTEXT_FLAGS` value) must first
reproduce the failure under controlled flags and show the actual `ERROR_*`
Windows returned, plus the flag value Windows actually accepted. Hypothesized
no-op patches (OR-ing a bit the value already contains) are **not** counted
against the per-battlefield ≤2 fix budget until root cause is empirically
confirmed.

### 4.5 E2 protocol gate — DORMANT (2026-07-29 amendment)

> ⚠️ **Logical scope (2026-07-29):** E2 is the **research-restore** gate —
> verifying a minimal captured-pointee restart lets free-run advance past the
> previously blocking transfer. E2 is **not** a product-facing exit (§4.2 is).
> Passing E2 does **not** claim product `Accepted`; it merely establishes the
> research artifact has a reproducible same-epoch restore.

> ⚠️ **DORMANT NOTICE (2026-07-29 expert ruling):** the §4.4 step 4 budget
> ledger records used=2 / remaining=0. **This protocol is dormant in the
> current charter** — it is **not** an active implementation gate. **No E2
> proposal, draft, or implementation may be written** under the current
> budget, regardless of whether the operator names `E2 implementation`
> literally. An `R1B re-entry` or `E2 implementation` instruction is **not**
> itself authorization to act and is **not** a mechanism that expands budget.
> The only path to re-open budget is **separate governance** — a charter
> amendment or a new expert ruling that explicitly allocates additional
> rounds, evidenced in `WORKER_HANDOFF.md`. Until such a ruling lands, the
> §4.4 step 5 "stop" applies; §4.3 is the live status.

**E2 evidence bar (recorded for future activation, NOT active today):**

1. R1B captured batch must have passed §4.4 step 4 (≥3 of 10 with
   `same_epoch=true && committed_readable=true`) under authorized method.
2. Budget ledger must show **≥1 round remaining** for E2 specifically.
3. Operator must name `E2 implementation` literally plus chosen restore path
   class.
4. Expert grants explicit authorization; delegation recorded in handoff.
5. Restore prototype produces N=5 independent runs under no-bypass env. Each
   outcome JSON sidecar must carry `restore_path_class`,
   `pre_restore_rip`/`post_restore_rip`/`post_restore_rsp`,
   `free_run_past_next_transfer`, `crash_class`, `rsp_source`,
   `bypass_used=false` (strict: any `bypass_used=true` disqualifies the
   batch).
6. ≥3 of 5 with `free_run_past_next_transfer=true && bypass_used=false`.
   If fewer — stop, write residual per §4.3.
7. E2 implementation **must** also consume exactly 1 budget round; it is
   **never** "free" — once activated, §4.4 step 4 ledger must be updated
   *before* code is written.

**E2 ≠ product (scope reminder):** R0B check-static, `load_no_crash_v0`,
managed-manifest / registered-probe, AHK real-script-execution, bilateral
dialog, reproducibility-without-bypass — all under §4.2, **not** §4.5.

**Activation gate:** budget must be expanded by separate governance first;
the dormant protocol itself does not bootstrap.

---

## 5. Method constraints (recommended approach)

**Do:**

- Prefer **memory-state / epoch** capture over instruction-pattern VM ENTER myths  
  (启动器 has no portable spinlock ENTER vs hello_world).
- Treat `.KI3` as encrypted **source store**; runtime focus `.boot` / RWX residue.
- Reuse validated assets: slab capture, VirtualAlloc original-address remap,  
  BootWatch early freeze, RBP/R9 restart policy where already proven.
- Measure first (E0) before code (E1).

**Do not:**

- Re-open r1–r26 hot-root onion peels as primary strategy.
- Treat soft-BP linear VIP++ as product progress.
- Restore RBP=0 free-run that reintroduces SOI cliff without new evidence.
- Commit diagnostic bypasses as default dump behavior.

---

## 6. Round budget (template)

| Round | Intent | Max code surface | Exit measure |
|-------|--------|------------------|--------------|
| 0 | Reproduce epoch problem | logs/scripts only preferred | MEM_FREE or committed? N≥3 |
| 1 | Capture at later/load epoch | gto_host + core query APIs | readable pointee sidecar |
| 2 | Minimal restore + free-run | restart stub / policy | past next transfer ≥2/3 |

If Round 0 already shows a new wall class → residual-stop without burning Round 1–2 on dead ends.

---

## 7. Verification commands (research host)

```powershell
. .\tools\_enter_msvc_env.ps1
$env:CARGO_TARGET_DIR = 'D:\MidaVault\scratch\cargo-target'

# Work on research branch
git checkout research/gto-bootwatch-20260728

cargo build -p mida-cli --offline
# Then operator-authorized BootWatch / softbp recipes under vault scratch
# (exact env flags documented in KI3 §12.6 — do not invent product defaults)
```

After any shared `mida-pe` dumper edit, also:

```powershell
git checkout baseline/legacy-recovery-20260722   # or merge-test worktree
python tools\_origin_live_unpack.py
# R0B StructuralPassBehaviorPending on fresh candidate
```

---

## 8. Reporting language (required)

| Allowed | Forbidden |
|---------|-----------|
| “research advance / residual” | “perfect unpack complete” (gto) |
| “pointee epoch captured (evidence path)” | “product Accepted” via load survival |
| “free-run past transfer N/M” | “UI fixed” with bypass still on |
| “Blocked — wall = …” | silent re-label of historical B-B Accepted |

---

## 9. Relationship to product baseline

| Line | Role |
|------|------|
| `baseline/legacy-recovery-20260722` | P0 fail-closed, origin perfect-unpack protection, lab summary honesty |
| `research/gto-bootwatch-20260728` | This charter’s default implementation branch |
| Merge research → baseline | Only after expert review; no bypass-default; origin smoke green |

---

## 10. Authorization record

| Item | Value |
|------|-------|
| Opened | 2026-07-28 (operator request: process Set C + open GTO research charter) |
| Frozen | 2026-07-28 — R1A residual-stop (`4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §0) |
| Re-entry barrier | §4.4 (amended 2026-07-29, third-pass 2026-07-29) — operator must **name `R1B re-entry`**; **"execute charter Round 0" alone is not admissible** under Residual-stop. **Budget exhausted**: ledger records `R1A=1` (consumed, `6b2a6eb`) + `R1B=1` (consumed, `4be4ee5` + 4× smoke under `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\`) + `E2=0 remaining` = **used=2 / cap=2 / remaining=0**. E2 (§4.5) is **dormant**: no proposal, draft, or implementation permitted under current budget; only **separate governance** (charter amendment or new expert ruling) can re-open budget — `R1B re-entry` / `E2 implementation` instructions do **not** themselves expand budget. Per-battlefield ≤2 budget lives at `docs/COURSE_CORRECTION_WORK_ORDER.md` §3. |
| Battlefield ID | `GTO-POINTEE-EPOCH` |
| Auto-start grind | **No** — and **never auto**, even post-authorization: any R1B capture or charter Round 0 requires §4.4 step 1 (operator names R1B re-entry) **and** step 2 (expert grants authorization). Charter **status was downgraded to Residual-stop on 2026-07-28 by R1A seal**, not by this document. |
| Closes | Research exit §4.1 / product exit §4.2 / residual-stop §4.3 / expert revoke |

---

*Does not claim gto perfect unpack or product 1.0.*
