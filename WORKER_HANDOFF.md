# WORKER_HANDOFF — operational takeover 2026-07-29 (1 of 2 samples)

## Goal (binding): docs/PROJECT_GOAL_20260725.md

Perfect unpack of exactly two samples.

| sample | status |
|--------|--------|
| 时光一键宏.exe (origin_macro) | **✅ PERFECT UNPACK COMPLETE** (protected; Phase C reconfirmed 2026-07-29) |
| 启动器.exe (gto_launcher) | ❌ far / **Blocked** — Themida VM owns execution (r27 r5); not residual polish |

## Takeover status (2026-07-29)

| Phase | Status | Evidence |
|-------|--------|----------|
| **B** Set A P0 ship | **Done** | commit `7c86595` on `baseline/legacy-recovery-20260722` |
| **C** Origin non-regression | **Done (2026-07-29 re-run)** | live unpack EP=`0x13e0`; R0B `StructuralPassBehaviorPending`; 1× smoke `all_ok`; artifact-bound manifest sha256 `ae1e6344…` |
| **D** Park Set B | **Done** | branch `research/gto-bootwatch-20260728` @ `4be4ee5` (BootWatch/R1B bwhook/KI3) |
| **Set C** lab honesty | **Done** | superseded `validation_summary` + BA3/BB contract adaptation |
| **E** GTO research | **REJECTED 2026-07-29** — §6 E **not opened**; R1B trench **FROZEN**; **budget exhausted (used=2/cap=2/remaining=0)** | `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §0 (status); charter `§4.4` (third-pass 2026-07-29) + §4.5 dormant (2026-07-29) define re-entry + E2 protocol; **operator must name `R1B re-entry`** — "continue" / "proceed" / passing C-1 do **not** satisfy §4.4; **R1B already consumed 1 round** (`4be4ee5` + 4× smoke in `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\`) — re-entry alone does **not** expand budget; only separate governance (charter amendment / new expert ruling) can re-open |
| Product 1.0 | **NO** | gto perfect unpack not achieved; **§0.1 binding unchanged** |

### Phase C re-run (2026-07-29) evidence pointers

- Live dump: `D:\MidaVault\lab\evidence\origin_macro\live_20260729-165727\origin_unpacked.exe` (18 sections, 13,769,216 bytes, sha256 `ae1e6344…`)
- Bound manifest written (0 transforms): sha256 `ae1e6344683dfc193932faf96b06b3bba45a59af6ee8f8d403928eeef09cc7cc`  (== live dump sha256)
- Smoke batch: `D:\MidaVault\lab\evidence\_repeat\batch_20260729-165829_phase_c_origin_reg\summary.json` — `all_ok=True` (artifact sha256 `aa99fa05…`)
- R0B report: `D:\MidaVault\scratch\phase_c_origin_r0b.json` — 12 gates pass, 0 failures, 0 warnings (artifact sha256 `ae1e6344…`)
- **Distinction (corrected 2026-07-29 per expert review):** the smoke artifact (`aa99fa05…`) and the R0B/manifest-bound artifact (`ae1e6344…`) are **two independent runs** of the unpacker, not one artifact running through a unified "all-gates" pipeline. Each individually satisfies its own contract; "Origin non-regression" is the conjunction of these two independent observations, **not** "the same artifact is green across both pipelines." Future evidence descriptions must keep them separate.
- Offline gates re-verified on `baseline/legacy-recovery-20260722` (after Set B park):
  - `cargo test -p mida-pe --lib` → **175/175 ok**
  - `cargo test -p mida-packers-themida --lib` → **121/121 ok**
  - `cargo test -p mida-acceptance --lib` → **25/25 ok**
  - `cargo check -p mida-cli` → **ok** (1 warning: `mut` unused in `gto_host.rs:120`)
  - `cargo build -p mida-cli` → **ok** (CLI matches current baseline source)

### Expert ruling on §6 E battlefield (2026-07-29)

**§6 E field = REJECTED / NOT OPENED** (expert ruling 2026-07-29, second pass). C-1 (operational takeover) accepted; E battlefield not opened; R1B capture trench remains FROZEN. Re-entry bar = `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 (2026-07-29 amendment) + immutable seal at `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §4. No code change to bwhook / gto_host / `_r1b_transient_epoch_trap.py` authorized by this handoff. **Operator must name `R1B re-entry`; "continue" / "proceed" do not satisfy §4.4.**

### Baseline vs research

- **baseline** = P0 fail-closed + origin-safe path only (no BootWatch mega-diff in tree)
- **research/gto-bootwatch-20260728** = GTO host residual + R1B capture harness (`crates/bwhook` + `tools/_r1b_transient_epoch_trap.py`); `crates/bwhook` remains workspace-`exclude`
- Set C committed: `validation_summary.json` status=superseded; BB writer no longer re-certifies product Accepted via load_no_crash
- GTO charter: `docs/GTO_RESEARCH_CHARTER_20260728.md` — current status **Residual-stop after R1A** (per §0); re-entry only per charter §4.4 / seal `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §4. **"execute charter Round 0" alone is not admissible** under Residual-stop — operator must name **R1B re-entry** and produce evidence per §4.4.

### Open discipline notes (2026-07-29 — corrected 2026-07-29 per expert review)

- **WITHDRAWN — prior claim about CONTEXT_FLAGS fix was wrong.** Earlier draft described "OR in `CONTEXT_AMD64`" as a one-line fix for `GetThreadContext` returning `ERROR_INVALID_PARAMETER`. That claim is **incorrect**: `0x100013` already encodes the architecture bit (the high `0x100000` is set inside both `CONTEXT_DEBUG_REGISTERS_AMD64 (0x100010)` and `CONTEXT_CONTROL_INTEGER_AMD64 (0x100003)`). OR-ing `CONTEXT_AMD64` again is a no-op and does not fix anything. The actual root cause of the `GetThreadContext` Err in the R1B smoke is **not established** — candidates remain: (i) non-standard flag combination behavior on this Win10/11 build; (ii) suspend-count / handle race (earlier session observed `SuspendThread(prev=0)` while host had skipped its own suspend); (iii) thread-state precondition not actually met at the moment of DLL arming. **No "one-line fix" is to be trusted or committed without empirical `ERROR_INVALID_PARAMETER` reproduction under controlled flags, and without showing the flag value Windows actually accepted.**
- bwhook diagnostic log path: `D:\MidaVault\scratch\r1b_smoke_log\` (vault only, not committed)
- Race note observed earlier in this session: `SuspendThread(prev=0)` showed up while BootWatch had already frozen the RIP — handled by host's `if frozen_rip.is_none() && bootwatch_vm_enter_rip.is_none()` gate, but worth a hygiene pass if R1B is reopened.
- **R1B trench remains FROZEN** per expert 2026-07-29 ruling (third pass, 2026-07-29); re-entry bar = charter §4.4 + §4.5 dormant (third-pass 2026-07-29) + immutable seal `4c2b545:docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` §4. Per-round fix budget = ≤2 (per `docs/COURSE_CORRECTION_WORK_ORDER.md` §3 — workspace-auditable). **Budget exhausted, ledger 2026-07-29:** R1A = 1 round consumed (host instrument, closed 2026-07-28, see `4c2b545:docs/GTO_POINTEE_EPOCH_R1A_20260728.md` §1); **R1B = 1 round already consumed** (commit `4be4ee5` on `research/gto-bootwatch-20260728` — bwhook + gto_host + runner +1342 lines + 4× live smoke at `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\`); E2 = **0 remaining**, **forbidden** under current charter. **used=2 / cap=2 / remaining=0.** The earlier "operator pre-declaration" policy was withdrawn on third-pass: declaration expresses intent only; the ledger is determined by actual Rust/Python diff + clean tree + rebuild + re-measure. **Only separate governance** (charter amendment or new expert ruling recorded here) can re-open budget — `R1B re-entry` / `E2 implementation` instructions do **not** themselves expand budget.

## GTO-PRODUCT-RECOVERY proposal filed (2026-07-29) — NOT a re-entry authorization

**Proposal artifact:** [`docs/GTO_PRODUCT_RECOVERY_CHARTER_20260729.md`](docs/GTO_PRODUCT_RECOVERY_CHARTER_20260729.md) (new file on this baseline; both files resolve from repo root).

**Status (proposal only, no action authorized):**

- This is a **read-only governance proposal** — a docs-only artifact that **proposes** opening a **new** battlefield `GTO-PRODUCT-RECOVERY` with a **proposed** ledger namespace. It does **not** open the battlefield; it does **not** allocate budget; it does **not** authorize any code change.
- The use of a separate ID is for bookkeeping clarity; it does **not** bypass, weaken, or reopen `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 or §4.5. The §4.4 re-entry bar still applies to anything that names `R1B re-entry` literally; §4.5 (E2) remains dormant.
- **Phase 0 of the proposal consumed 0 fix rounds** (docs-only; not a budget round per `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 budget-burn rule).
- **`GTO-POINTEE-EPOCH` ledger is UNCHANGED** (used=2 / cap=2 / remaining=0). The proposal explicitly does **not** request expansion of that ledger, does **not** re-open parked R1B (`4be4ee5`), does **not** activate dormant E2 (§4.5).
- **`R-GTO-UI` peel-series ledger is UNCHANGED** (closed r1 → r25b; deepest progress r23b `ZhuChuangKou` class).
- **No code change.** No live runs. No push.

**Next action requires (separately from this filing):**

1. Operator names `GTO-PRODUCT-RECOVERY Phase 1 on Route X` literally (per the proposal's §3.3 + §8.6 authorization bar). Bare "continue" / "proceed" / handoff-passing-C-1 do **not** satisfy this.
2. **New expert ruling OR charter amendment** recorded in this handoff that **explicitly allocates** rounds in the `GTO-PRODUCT-RECOVERY` ledger namespace (the allocation is **not** inherited from the proposal; only separate governance can grant it).
3. The expert ruling must **explicitly state** the chosen Route X and its evidence bar (charter §6.4 / §6.1 / §6.2 / §6.3 as appropriate).

**Non-automatic fallback note (third-pass 2026-07-29):** the proposal's §6.5 step 3 ("if Route A residual-stops → Route B") is **not** an automatic fallback. After any Route A residual-stop, the worker must **stop and write residual** per the analog of `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.3. Route B requires its **own** governance ruling (operator-named, with explicit round allocation) and does **not** auto-start from the proposal's recommendation alone.

**What this entry is NOT:** this is a "proposal filed" record, **not** an authorization to act. No code change, no live GTO unpack / R1B / E2 / restore, no `sample_bypass`, no push. `WORKER_HANDOFF.md` is not the governance artifact for Phase 1 of this proposal; the new expert ruling or charter amendment (recorded in `WORKER_HANDOFF.md` when it lands) would be.

**Anti-revival cross-check (2026-07-29):**

- `crates/bwhook/**` — **unchanged** by this filing.
- `crates/cli/src/unpacker/gto_host.rs` (research branch) — **unchanged** by this filing.
- `tools/_r1b_transient_epoch_trap.py` — **unchanged** by this filing.
- Vault evidence under `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\` and `D:\MidaVault\scratch\bootwatch\r1a_n10_20260728-192757\` — **unrestored**; cited as evidence inputs only.

## Phase 0.5 Route D audit filed (2026-07-29) — read-only, no budget consumed

**Audit artifact:** `docs/GTO_PRODUCT_RECOVERY_ROUTE_D_AUDIT_20260729.md` (new docs-only audit file; filed for expert review).

**Status (read-only audit only, no action authorized):**

- This is a **Phase 0.5 read-only debug-context audit** under `docs/GTO_PRODUCT_RECOVERY_CHARTER_20260729.md` §6.4 Route D. **Not** Phase 1. **Not** R1B re-entry. **Not** E2 activation. **Not** a live run. **Not** a source-code edit. **Not** push.
- **Budget consumed = 0** (docs-only; no Rust/Python diff, no rebuild, no re-measure; per `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 step 4 budget-burn rule, **investigation that does not produce Rust/Python diff + rebuild + re-measure is not a budget round**).
- **`GTO-POINTEE-EPOCH` ledger is UNCHANGED** (used=2 / cap=2 / remaining=0).
- **`GTO-PRODUCT-RECOVERY` ledger namespace is UNCHANGED** (Phase 0.5 = 0 rounds; Phase 1 still requires separate governance per charter §3.3 + §6.5 third-pass 2026-07-29).
- **No code change.** No live runs. No push. No vault writes.

**Audit verdict (read-only finding only):**

- R1B `GetThreadContext(flags=0x100013) -> ok=false` is **not** evidence the target pointee at `0x1405febb8` does not exist; it is host-state-machine failure (3 of 4 runs: `capture_reason=dr0_fail`; 1 of 4 runs: `arm_timeout`).
- `0x100013` already encodes `CONTEXT_AMD64=0x100000`; OR-ing `CONTEXT_AMD64` is a no-op. **The "one-line fix" withdrawal from earlier this session is reaffirmed — do not re-introduce.**
- R1A `same_epoch_committed=0` and R1B `same_epoch_hits=0` reach the **same gate** via **different mechanisms** — both describe the host's inability to hold the target thread at the same suspended RIP as the VIP fetch epoch.
- **Route A should not default to VEH+DR0 short-window.** Recommended Route A method-class order (if separately approved by Phase 1 governance): memory-state epoch capture → VM-ownership-aware non-DRx → DRx as secondary + gated by a separate local-harness proposal.

**Anti-revival cross-check (2026-07-29):**

- `crates/bwhook/**` — **unchanged** by this filing.
- `crates/cli/src/unpacker/gto_host.rs` (research branch) — **unchanged** by this filing.
- `tools/_r1b_transient_epoch_trap.py` — **unchanged** by this filing.
- Vault evidence under `D:\MidaVault\lab\evidence\_r1b_transient_epoch_trap\` and `D:\MidaVault\scratch\bootwatch\r1a_n10_20260728-192757\` — **unmodified** (only SHA-256 hashes recorded for audit).
- No new untracked vault evidence written.

**Next action requires (separately from this filing):**

- Expert review of the audit document.
- Operator names `GTO-PRODUCT-RECOVERY Phase 1 on Route X` literally (per `docs/GTO_PRODUCT_RECOVERY_CHARTER_20260729.md` §3.3 + §8.6) **and** a new expert ruling OR charter amendment recorded in this handoff that explicitly allocates rounds in the `GTO-PRODUCT-RECOVERY` ledger namespace. **This Phase 0.5 audit does not allocate any rounds; it only informs method-class choice.**
- If DRx is to be used at all: a separate governance proposal (e.g. `docs/GTO_PRODUCT_RECOVERY_LOCAL_HARNESS_20260729.md`) for a non-GTO local flag-acceptance harness is required first; **out of scope for this audit**.

## GTO-PRODUCT-RECOVERY Phase 1 Route A R1 — COMMITTED (2026-07-29/30)

**Status (sealed):** expert accepted R1 for commit. Commit `55976c9d3f1fda65166c317f9ef4242daab5cac5` on `codex/gto-product-recovery-route-a` from baseline `1ca2fde`.

- Machine pre-report `aggregate.json` (R1 vault): `stability_score=1.0`; items 1–7 true; **`item_8_report=false` by design**; **`evidence_bar_pass=false`**.
- Final R1 pass = expert acceptance after report review (strength-corrected: expand not proven; protect=32=`PAGE_EXECUTE_READ`; protection_transition supporting-weak only).
- **Ledger after R1 commit:** Route A used=1 / cap=2 / remaining=1 (before R2).
- Report: `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_20260729.md`. Plan: `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_PLAN_20260729.md`.
- Vault (READ-ONLY): `D:\MidaVault\scratch\product_recovery_route_a_r1_n3_20260729-155500\`.
- **No push** of R1 commit required by that authorization; local seal only unless separately ordered.

## GTO-PRODUCT-RECOVERY Phase 1 Route A R2 — ACCEPTED / CLOSEOUT-READY (2026-07-30)

**Status (per `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R2_20260730.md`):**

- **R2 PASS accepted by expert review (2026-07-30).** Status = **accepted / closeout-ready**.
- Machine pre-report `aggregate.json` (vault, unchanged): **N=5/5**, **reproduction_count=5**, identity **independent_count=5**; items 1–7 true; **`item_8_report=false` by design**; **`evidence_bar_pass=false`**. Human report layer accepted as item 8; machine aggregate is **not** rewritten to flip those flags.
- **Ledger:** `GTO-PRODUCT-RECOVERY Route A` — **used=2 / cap=2 / remaining=0**. **No R3.**
- **`GTO-POINTEE-EPOCH` UNCHANGED** (used=2/cap=2/remaining=0, FROZEN). **R1B FROZEN. E2 dormant.**
- **No DRx / VEH / injection / bypass / sample_bypass / WriteProcessMemory / R1B restore / E2.**

**R2 round artifacts (closeout commit on `codex/gto-product-recovery-route-a` from R1 seal `55976c9`; no push):**

- Modified: `crates/cli/src/bin/mida_gto_product_recovery_observer.rs` (candidate_regions lifetime + multi-page fingerprint + neighborhood; honest bindings; round/drx/veh/injection flags).
- Modified: `tools/_mtr_acq_route_a_observer.py` (N=5 default, `--round`).
- Modified: `tools/_mtr_acq_route_a_aggregate.py` (family clustering + R2 evidence bar).
- New: `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R2_20260730.md` (includes expert acceptance block).
- Modified: `WORKER_HANDOFF.md` (this section).

**R2 evidence (vault only, READ-ONLY input):**

- Out root: `D:\MidaVault\scratch\product_recovery_route_a_r2_n5_20260730-012013\`
- 5 × `outcomes.json` + `aggregate.json` + `orchestrator_summary.json`
- Target sha256 `4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8`
- Observer sha256 `1217a5913d5ddde6a1ae1d23c3a0ec0a1be0b5e765581f473f080f94ba014a6d`

**Stable candidate family (5/5):**

- `family_key = sz0x120000|fp1891a1ae5a1e8f8f`
- size `0x127000` (1208320) exact 5/5; protect=`32` (`PAGE_EXECUTE_READ`) 5/5; MEM_PRIVATE + MEM_COMMIT; not image-backed
- identical `checksum_4k` + `checksum_multi_page` 5/5; lifetime ticks 263–320; first_seen ≈ 11–12
- identity dims all true: size, checksum, lifetime, neighborhood, protection (**independent_count=5**)
- JSON name `vm_codegen_region_expand` retained; **expansion NOT proven**; **not necessarily RWX**
- `vm_protection_transition` supporting-weak only; **not** primary pass anchor
- `.boot` **not** module-visible; **no `.boot` binding claimed**

**Anti-revival cross-check (2026-07-30):**

- `crates/bwhook/**` — unchanged
- `crates/cli/src/unpacker/gto_host.rs` — unchanged
- `tools/_r1b_transient_epoch_trap.py` — unchanged
- seal docs — unchanged
- vault lab evidence — unmodified
- No `MIDA_GTO_BYPASS` / `MIDA_GTO_SEMANTIC_REPAIR`
- No push. **No R3.**

**Closeout / next action:**

- R2 closeout commit authorized (five R2 files only). **No push.**
- Cap exhausted (remaining=0): **No R3.** Optional next step only via **new governance** (e.g. candidate dump **metadata** only — not restore/E2/R1B/UI/bypass).
- **`GTO-POINTEE-EPOCH` remains FROZEN.** Non-claims retained (not product 1.0; not gto perfect unpack; not R1B; not E2; not DRx; not bypass; expand not proven; not necessarily RWX).

## GTO-PRODUCT-RECOVERY Route A Candidate Metadata Pack M0 — COMMITTED

- Based on R2 accepted commit: `2c8ebeabbcd6da55ec2359300241d5aff3c461b8`
- Branch: `codex/gto-route-a-candidate-metadata`
- Class: metadata-only evidence packaging
- Fix rounds consumed: **0**
- Live measurement: **none**
- Target execution: **none**
- Route A R3: **not opened**
- Selected family: `sz0x120000|fp1891a1ae5a1e8f8f` (size `0x127000`, protect=32 `PAGE_EXECUTE_READ`, 5/5, identity dims=5)
- Vault input (READ-ONLY): evidence set id `product_recovery_route_a_r2_n5_20260730-012013` (no vault rewrite; aggregate `item_8_report=false` retained)
- Output:
  - `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_CANDIDATE_METADATA_20260730.json`
  - `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_CANDIDATE_METADATA_20260730.md`
  - `tools/_mtr_route_a_candidate_metadata.py`
- Non-claims retained (not product 1.0; not gto perfect unpack; not R1B; not E2; not DRx/VEH/injection; not bypass; expand not proven; not necessarily RWX; no `.boot` module-visible binding).
- Next-governance recommendation: accept M0 as deterministic R2 primary-anchor descriptor; any successor is a **separate** route-selection ruling (e.g. Route B); **do not reopen Route A R3**.
- Local commit on branch `codex/gto-route-a-candidate-metadata` (parent `2c8ebeabbcd6da55ec2359300241d5aff3c461b8`; subject `gto: add route a candidate metadata pack`; four allowed files only). Record tip via `git rev-parse codex/gto-route-a-candidate-metadata`. **No push.**

## origin_macro — DONE (evidence)

- Structure R0B StructuralPassBehaviorPending
- Load 10× isolated 10/10
- .text entropy 6.045 (plaintext), x64 prologues present
- Product strings (授权验证/授权码) GBK plaintext in .rdata
- Modifiable: patched 1 byte @0xfe5c5 → R0B still Pass + load still Pass + business_dialog still Pass (no integrity lock)
- Behavior: license rejection path bilateral N=3 Pass, status message identical
- Zero bypass patches
- Reproducible: current CLI fresh dump → all green

valid-code acceptance path not tested (no valid license) — that is a licensing-layer concern, NOT an unpacking-layer concern. Unpack goal met.

## gto_launcher — OPEN (the remaining sample)

5 r26b bypass patches in candidate:
- 0x5c5d MessageBoxW skip
- 0x63f4 LoadFile skip (script not actually loaded!)
- 0x34f66 CreateWindowEx → forced NewClassName
- 0x34f59 WS_VISIBLE forced
- 0x6757 msg-loop AV skip

"Perfect unpack" for gto requires: revert ALL 5 patches + product code naturally runs to UI + AHK script engine loads/executes. This is the r1–r26 unsolved heap/script resume root cause.

product 1.0 = NO until gto perfect-unpacks.

## gto_launcher Round 0 (r27 no-bypass) — root cause: heap rebasing wall

- Reverted all 5 r26b bypass patches via `MIDA_GTO_NO_BYPASS=1`; re-dumped.
- Protected input naturally shows NewClassName login window (no MB, no crash).
- No-bypass candidate: shows #32770 MessageBox (machine-ID E4847ED08866458F8DD35F94B37001C0) then AV 0xc0000005.
- Crash: rip=0x1406110a0 (Themida `.,\W` section), `mov edi,[rax]`, rax=0x846898 (stale heap ptr).
- 0x846898 = 0x830000 (captured heap handle) + 0x16898; falls in an uncaptured 0x318-byte gap before the object at 0x846bb0.
- 0x846898 has 0 static hits → computed at runtime from stale heap base. This is heap-rebasing incompleteness, same wall r1-r26 peeled for 26 rounds.
- Round 1 (capture the gap) would just move crash to next stale ptr. STOP per discipline; needs heap-rebase research, not another peel.

gto_launcher perfect-unpack = NOT achieved. product 1.0 = NO.

## GTO-PRODUCT-RECOVERY Route B B0 Work Order (2026-07-30)

**Base:** ec559ca
**Branch:** codex/gto-route-a-candidate-metadata

## Goal

Docs/governance-only work order for GTO-PRODUCT-RECOVERY Route B R1 (AHK runtime / script-object recovery).

## Scope

- Docs/governance only.
- No code.
- No cargo.
- No live measurement.
- No target execution.
- No vault write.
- No push.
- Do not start R1.
- Do not touch Route A / R1B / E2 / DRx / VEH / injection / bypass.

## Fresh ledger

- Namespace: `GTO-PRODUCT-RECOVERY Route B`
- Cap: 2 rounds
- Used: 0
- Remaining: 2

## Allowed future implementation surfaces (charter)

- `crates/pe/src/dumper/heap_global_snapshot.rs`
- `crates/pe/src/dumper/capture_policy.rs`
- `crates/pe/src/dumper/container_bootstrap.rs`

**Explicitly forbidden (no implementation or reference in this work order):**
- `crates/cli/src/unpacker/gto_host.rs`
- `crates/bwhook/**`
- `_r1b_transient_epoch_trap.py`
- Route A observer
- DRx / VEH / injection / bypass

## R1 objective

- CS re-init at known CS RVAs
- per-object hot-root addition to DumpCapturePolicy
- label-name exact-graph completion
- path allocator cold-init fix

## R1 evidence bar

- build/check passes
- deterministic output artifact/manifest generated
- compare against prior r23b/r25b blocker graph
- no bypass / semantic repair
- report written before any final pass

## B0 consumption

B0 consumes **0** fix rounds. Implementation has **not started**.

## GTO-PRODUCT-RECOVERY Next Route Ruling N0 — Route A closed (2026-07-30)

## Governance status

- **Route A evidence:** R2 accepted; M0 accepted.
- **Route A budget status:** cap exhausted, no further Route A round authorized.
- **Hygiene residual:** carried as local/pre-existing, non-blocking for governance.
- **Implementation has not started.**

## Route comparison (brief)

- **Route B**: recommended next route.
- **revised Route D / audit-only**: not selected.
- **goal write-down**: pending.

## Recommendation

Exactly one next route: **Route B**.

## Fresh separate ledger

- Namespace: `GTO-PRODUCT-RECOVERY Route B`
- Rounds cap: **2**

## GTO-PRODUCT-RECOVERY Route B Residual-Stop Seal (2026-07-30)

**Base:** 406e3a0
**Branch:** codex/gto-route-b-r1

## Audit correction

- R1 commit `41025f0` was no-op/comment-only; consumed 1 Route B round.
- R2 commit `406e3a0` was also no-op: `0x147868` (cmd/dispatch table) already existed in `ahk_gto_default()` hot_root_rvas before R2; R2 only moved/recommented it.
- R2 report claim “added 0x147868 / real functional change” is **superseded** by this expert audit.
- WORKER_HANDOFF.md was not included in R2 commit despite worker summary.
- Final Route B ledger: `used=2 / cap=2 / remaining=0`.
- Final Route B status: **RESIDUAL-STOP**.
- No Route B R3.
- Next governance options only: goal write-down, new route proposal with fresh explicit governance, or archive as evidence package.

## Non-claims

- Not product 1.0.

## GTO-PRODUCT-RECOVERY Goal Write-Down Gate G0 (2026-07-30)

**Base:** f53d249
**Branch:** codex/gto-route-b-r1

## Final ledger summary

- **Route A**: used=2/cap=2/remaining=0, accepted evidence only, no R3.
- **Route B**: used=2/cap=2/remaining=0, residual-stop, no R3.

## Evidence summary

- Route A found stable VM-owned primary-anchor candidate (`sz0x120000|fp1891a1ae5a1e8f8f`) but not product restore.
- Route B failed due to no-op R1/R2; no functional recovery achieved.

## Next governance choices

1. **goal write-down**: accept current outcome as VM-ownership characterization, not product 1.0.
2. **new route proposal**: requires fresh named Route C/D/etc with new evidence bar and cap.
3. **archive package**: package reports/commits for review.

## Recommendation

Exactly one: **goal write-down** first.

No implementation rounds allocated.

## GTO-PRODUCT-RECOVERY Goal Write-Down Gate G1 (2026-07-30)

**Base:** 6533ea9
**Branch:** codex/gto-route-b-r1

## Accepted outcome

- VM-ownership characterization + stable Route A primary-anchor metadata accepted as evidence only.
- Explicitly **not** product 1.0 / not perfect unpack / not restore.
- Route A exhausted and accepted as evidence.
- Route B exhausted and residual-stopped.
- Product-recovery implementation paused pending new explicit governance.

## Non-claims

- Not R1B / E2 / DRx / VEH / injection / bypass / sample_bypass.
- No Route A/B R3.

## P0 reopen product-perfect route proposal

P0 proposes a new Route C for gto_launcher perfect unpack / product 1.0. No implementation rounds consumed yet.

## A1 archive manifest completeness patch

A1 only completes archive index; no new governance or implementation.
- Not gto perfect unpack.
- Not R1B / E2 / DRx / VEH / injection / bypass / sample_bypass.
- Route B complete; no further Route B rounds authorized.
- Explicitly separate from Route A (no inheritance, no reopening of Route A).

## Non-claims

This ruling does not:
- Claim R2+R3 completed.
- Open Route A R3.
- Authorize any code, live measurement, target execution, vault write, push, R1B, E2, DRx, VEH, injection, bypass, or sample_bypass.
- Claim product 1.0 or gto perfect unpack.

Next governance step requires operator naming the route and new expert ruling/charter amendment allocating the 2 rounds in the Route B ledger.

## GTO-PRODUCT-RECOVERY Route C RESIDUAL-STOP SEAL (2026-07-30)

**Branch:** codex/gto-route-c-r1
**Base:** 843c10d
**Ledger:** used=2 / cap=2 / remaining=0 (final Route C round; no R3)

### Current tail status
- Route A exhausted (evidence only)
- Route B residual-stop (no-op prior rounds)
- P0 accepted
- Route C R1 test-only residual (do not claim pass)
- Route C R2 production patch invalid (bogus stub plant block + placeholder test); R2 report pass claim superseded by expert audit
- Final Route C status: **RESIDUAL-STOP**
- Product 1.0 / gto perfect unpack still not achieved

### Changed files
- crates/pe/src/dumper/container_bootstrap.rs (rollback of invalid R2 stub plant block)
- crates/pe/src/dumper/heap_global_snapshot.rs (rollback of bogus placeholder test)
- docs/GTO_PRODUCT_RECOVERY_ROUTE_C_RESIDUAL_STOP_20260730.md (new)
- WORKER_HANDOFF.md (updated tail + R1 correction)

### Actual change
Rollback of invalid R2 production stub patch (missing store opcode, unproven condition, placeholder test). R1 was test-only residual; sanitize_ahk_runtime_global() already wired in real capture/scrub path. No new product-recovery round.

### Validation
- `cargo fmt --all -- --check` (clean)
- `cargo check -p mida-pe --offline` (passes)
- `cargo test -p mida-pe --offline` (passes)
- `git diff --check` (clean)
- `git status --short --branch`

### Product-perfect evidence
None (bootstrap/cold-start fix rolled back as invalid; full gto_launcher perfect unpack / product 1.0 still not achieved).

### Ledger
used=2 / cap=2 / remaining=0 (final Route C round; no R3)

### Non-claims
- Not product 1.0 / not gto perfect unpack / not full cold-start correctness.
- No DRx / VEH / injection / bypass / semantic repair / R1B / E2 / push.
- No changes to forbidden files or Route A/B observers/scripts.
- No Route C R3.

## GTO-PRODUCT-RECOVERY Route D P0 Proposal (2026-07-30)

**Proposal artifact:** `docs/GTO_PRODUCT_RECOVERY_ROUTE_D_P0_20260730.md` (new file on this baseline).

**Status (proposal only, no action authorized):**
- This is a **read-only governance proposal** — a docs-only artifact that **proposes** opening a **new** battlefield `GTO-PRODUCT-RECOVERY Route D` with a **proposed** ledger namespace. It does **not** open the battlefield; it does **not** allocate budget; it does **not** authorize any code change.
- The use of a separate ID is for bookkeeping clarity; it does **not** bypass, weaken, or reopen previous Route C ledger.
- **Phase 0 of the proposal consumed 0 fix rounds** (docs-only; not a budget round per `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 budget-burn rule).
- **`GTO-POINTEE-EPOCH` UNCHANGED** (used=2/cap=2/remaining=0, FROZEN). **R1B FROZEN. E2 dormant. Route C exhausted.**
- **`R-GTO-UI` peel-series ledger is UNCHANGED** (closed r1 → r25b; deepest progress r23b `ZhuChuangKou` class).
- **No code change.** No live runs. No push.

**Next action requires (separately from this filing):**

1. Operator names `GTO-PRODUCT-RECOVERY Phase 1 on Route D` literally (per the proposal's §3.3 + §8.6 authorization bar). Bare "continue" / "proceed" / handoff-passing-C-1 do **not** satisfy this.
2. **New expert ruling OR charter amendment** recorded in this handoff that **explicitly allocates** rounds in the `GTO-PRODUCT-RECOVERY Route D` ledger namespace (the allocation is **not** inherited from the proposal; only separate governance can grant it).
3. The expert ruling must **explicitly state** the chosen Route D and its evidence bar (charter §6.4 / §6.1 / §6.2 / §6.3 as appropriate).

**Anti-revival cross-check (2026-07-30):**
- `crates/bwhook/**` — **unchanged**.
- `crates/cli/src/unpacker/gto_host.rs` — **unchanged**.
- `tools/_r1b_transient_epoch_trap.py` — **unchanged**.
- Vault evidence under previous routes — **unmodified**.
- No new untracked vault evidence written.
