# GTO-PRODUCT-RECOVERY Phase 1 — Route A R1 evidence report (2026-07-29)

> **Status:** **R1 evidence filed — expert pre-review pending / conditional technical pass candidate.**
> Final R1 pass is **not** machine-declared; it can only be written as **expert acceptance after report review**.
> **Authorization:** expert ruling 2026-07-29 (`GTO-PRODUCT-RECOVERY Phase 1 on Route A`).
> **Plan doc:** `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_PLAN_20260729.md`.
> **Branch:** `codex/gto-product-recovery-route-a` (from `baseline/legacy-recovery-20260722 @ 1ca2fde`).
> **Ledger:** `GTO-PRODUCT-RECOVERY Route A` — separate from `GTO-POINTEE-EPOCH` (frozen, used=2/cap=2/remaining=0).
> **Budget burn:** R1 = **1 round consumed** (Rust+Python diff + rebuild + re-measure; per `docs/GTO_RESEARCH_CHARTER_20260728.md` §4.4 step 4 budget-burn rule). R2 = 0; **remaining = 1 of cap=2**.
> **Hard scope confirmed:** non-DRx memory-state epoch capture only. No `gto_host.rs` research-branch version touched. No `bwhook/**`. No `_r1b_transient_epoch_trap.py`. No VEH+DR0 short-window. No `sample_bypass`. No push. No commit yet.

---

## 0. One-sentence R1 result

Three independent external-observer runs (`N=3`, no DRx, no VEH, no in-process hook, `MIDA_GTO_NO_BYPASS=1`) against a single canonical `gto_protected.exe` (sha256 `4d5770af…037c8`) observed **two named memory-state epochs in 3/3 runs** — `vm_codegen_region_expand` (JSON name retained; evidence supports a **stable MEM_PRIVATE executable RX/RWX-class >1 MiB region candidate**, not proven expansion and not necessarily RWX) and `vm_protection_transition` (**supporting weak observation only** — transition struct lacks state/type/size, so MEM_PRIVATE committed binding is not proven). Machine pre-report aggregate reports `stability_score = 1.0` with items 1–7 true and **item_8_report=false by design**; **final R1 pass is expert acceptance after report review**, not a machine `evidence_bar_pass=true`.

---

## 1. Evidence bar checklist (plan §3) — machine vs expert layers

### 1.1 Machine pre-report output (`aggregate.json`)

`aggregate.json` is **pre-report machine output**. The aggregator hard-codes `item_8_report = False` and fills it only after a human report exists; therefore:

- `evidence_bar.item_8_report = false` **by design** at orchestrator/aggregator time
- `evidence_bar_pass = false` in the vault `aggregate.json` (do **not** restate as true)
- Machine items 1–7 evaluate the measurement layer only

| # | Item | Machine result (pre-report) |
|---|------|-----------------------------|
| 1 | N≥3 | **true** — 3/3 runs present, 0 failures |
| 2 | ≥2/3 runs observe same named epoch | **true** — 2 named epochs in 3/3 runs each |
| 3 | `.boot`/VM-owned/allocation binding | **true** (string non-empty only) — see §2 for strength downgrade |
| 4 | `bypass_used=false` | **true** — all 3 sidecars; env `MIDA_GTO_NO_BYPASS=1` set, `MIDA_GTO_BYPASS`/`MIDA_GTO_SEMANTIC_REPAIR` absent |
| 5 | no `sample_bypass` | **true** — taxonomic; observer never sets bypass env |
| 6 | no DRx | **true** — `rsp_source = "external-observer"` ×3; only `ReadProcessMemory` + `VirtualQueryEx` |
| 7 | JSON sidecars | **true** — 3 sidecars + 1 aggregate at vault out_root |
| 8 | report | **false by design** — this document is the report layer |

Machine output: `evidence_bar_pass = false` (expected; item 8 not filled by aggregator).

### 1.2 Expert-layer status (this report)

This filing supplies item 8 (the report). Expert review must still judge:

- whether the **primary** named-epoch evidence is strong enough under plan §3.1 (see §2.1 downgrade)
- whether the **supporting** `vm_protection_transition` observation may be counted at all (see §2.2)
- whether the measurement + this report together constitute R1 pass

**Final R1 pass can only be written as: expert acceptance after report review.**
This document does **not** declare machine `evidence_bar_pass=true`, and does **not** self-declare final R1 PASS.

**Current worker status:** **R1 evidence filed — expert pre-review pending / conditional technical pass candidate.**

---

## 2. Named epochs observed — strength-corrected

### 2.1 `vm_codegen_region_expand` (3/3 runs) — primary candidate, name retained with downgrade

- **JSON name retained:** `vm_codegen_region_expand` (as emitted by the observer / sidecars / aggregate).
- **Code reality (downgrade):** the observer did **not** track per-base growth across ticks. The name is a heuristic label for regions that match a size/protect/type filter; it does **not** prove expansion.
- **What the evidence actually supports:** a **stable MEM_PRIVATE executable private region > 1 MiB (RX/RWX-class)** region candidate, repeatedly present across the observation window.
- **What is NOT proven:** expansion; and **not necessarily RWX**.
- **Protect values in run samples:** `protect = 32` = `PAGE_EXECUTE_READ` (`0x20`), **not** `PAGE_EXECUTE_READWRITE` (`0x40` / RWX). All three runs' large (>1 MiB) VM-owned samples show `protect=32`.
- **Type/state in samples:** `type = 131072` (`MEM_PRIVATE` / `0x20000`); `state = 4096` (`MEM_COMMIT` / `0x1000`).
- **Corrected evidence-binding language (report layer):** `executable private region >1 MiB (RX/RWX-class)` — **not** “MEM_PRIVATE RWX region > 1 MiB”.
  - Note: the **sidecar JSON** still carries the original string `"MEM_PRIVATE RWX region > 1 MiB (codegen candidate)"` as emitted by the observer at measurement time. That string is **historical machine output** and is **overclaimed** relative to `protect=32`. This report corrects the interpretation; vault evidence is left unmodified (per expert audit scope: no vault rewrite).
- **Sample base/size (per run):**
  - run 1: base=`0x3571000`, size=`0x127000` (1.2 MiB), count=311 ticks observed, protect=32 (`PAGE_EXECUTE_READ`)
  - run 2: base=`0x3521000`, size=`0x127000` (1.2 MiB), count=305 ticks observed, protect=32
  - run 3: base=`0x3601000`, size=`0x127000` (1.2 MiB), count=296 ticks observed, protect=32
- **Stability of presence:** 3/3 runs; `count` per run ranges 296–311 (CV ≈ 2.5%); base address varies by ≤0xE0000 within the heap-style allocator region (typical `VirtualAlloc` rebase drift).
- **Role in R1:** this is the **primary** conditional pass anchor candidate (stable executable private >1 MiB region), subject to expert acceptance of the downgraded claim.

### 2.2 `vm_protection_transition` (3/3 runs) — supporting weak observation only

- **JSON name retained:** `vm_protection_transition`.
- **Downgrade:** **supporting weak observation**. **Not** an R1 primary pass anchor.
- **Struct limitation:** each transition record carries only `base`, `from_protect`, `to_protect`, `tick`, `region_was_boot_named`. It **lacks** `state`, `type`, and `size`.
- **Consequence:** the sidecar `evidence_binding` string `"MEM_PRIVATE committed region protection change"` is **not proven** by the transition struct. MEM_PRIVATE / committed attributes are **not** attached to the transition event itself.
- **Named-observation sample_size:** `0` on all three runs for this name (no size captured on the named epoch).
- **Per-run counts (presence only):**
  - run 1: count=13 transitions, sample base=`0x140141000` (protect pairs include e.g. 8→4)
  - run 2: count=13 transitions, sample base=`0x7ffd3f322000` (pairs include 8→4 and 32→64)
  - run 3: count=11 transitions, sample base=`0x140001000` (pairs include 32→64, 2→8, 32→128)
- **Role in R1:** may be cited as a **secondary / supporting** signal that protect flips occurred during the window; **must not** be used alone, and **must not** be treated as proven allocation-transition / MEM_PRIVATE-committed binding.

### 2.3 Notable absences (not failed — just absent)

- `boot_region_candidates=0` in all 3 runs. The `.boot` section name is **not** visible at module level — Themida keeps the byte-code container in a non-PE-image private region with no module-level name. Consistent with literature; **not a defect**.
- `boot_section_first_committed`, `vm_owned_region_write_storm`, `vm_codegen_region_split`, `vm_allocation_anchor`: not observed within the 30 s observation window. Acceptable under plan §3.1 if a stable named epoch is otherwise accepted; the primary candidate here is the downgraded `vm_codegen_region_expand` presence signal.

---

## 3. Run records (N=3)

| run | pid | tick_count | observed_regions (latest snap) | vm_owned | protection_transitions | failure_class | binary_sha256 (target) | manifest_sha256 | sidecar_sha256 |
|-----|----:|-----------:|-------------------------------:|---------:|------------------------:|---------------|------------------------|-----------------|----------------|
| 1 | 14340 | 323 | 218 601 | 311 | 13 | none | `4d5770af…037c8` | `ed8c843f…f1c787` | `4148c949…827ec401` |
| 2 | 14768 | 314 | 214 417 | 306 | 13 | none | `4d5770af…037c8` | `9972f9b1…9726367` | `79aeaa17…2442b857` |
| 3 | 13308 | 305 | 207 299 | 297 | 11 | none | `4d5770af…037c8` | `1e49534d…2f3af01` | `f59feb2a…12616950c` |

All 3 runs: `route = "GTO-PRODUCT-RECOVERY/RouteA"`, `method_class = "memory-state-epoch external observer"`, `bypass_used = false`, `semantic_repair_used = false`, `target_sample = "gto_launcher"`, `rsp_source = "external-observer"`, `source_commit = 1ca2fdefd5014ce9f043d6aab84c434542d9ca6b`, `observation_window_ms = 30000`, `poll_period_ms = 50`, `failure_class = "none"`.

Target sample is **the same physical binary across all 3 runs** (`sha256 = 4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8`), located at `D:\MidaVault\lab\evidence\gto_launcher\r27_nobypass_round0_20260725\gto_protected.exe` — the canonical `gto_protected.exe` (size 8 583 680 bytes).

---

## 4. Per-run measurement items (from sidecars / aggregate)

| Item | run 1 | run 2 | run 3 |
|------|-------|-------|-------|
| `route = "GTO-PRODUCT-RECOVERY/RouteA"` | ✓ | ✓ | ✓ |
| `method_class = "memory-state-epoch external observer"` | ✓ | ✓ | ✓ |
| `bypass_used = false` | ✓ | ✓ | ✓ |
| `semantic_repair_used = false` | ✓ | ✓ | ✓ |
| `target_sample = "gto_launcher"` | ✓ | ✓ | ✓ |
| `target_image_path` matches canonical | ✓ | ✓ | ✓ |
| `target_image_sha256 = 4d5770af…037c8` | ✓ | ✓ | ✓ |
| `rsp_source = "external-observer"` (no DRx) | ✓ | ✓ | ✓ |
| `named_observations[]` non-empty | ✓ (2) | ✓ (2) | ✓ (2) |
| `evidence_binding` strings non-empty | ✓ (overclaimed wording; see §2) | ✓ | ✓ |
| `observed_regions[]` non-empty | ✓ (218 601) | ✓ (214 417) | ✓ (207 299) |
| `vm_owned_region_candidates[]` non-empty | ✓ (311; protect=32 on large samples) | ✓ (306) | ✓ (297) |
| `failure_class = "none"` | ✓ | ✓ | ✓ |
| `source_commit` matches baseline head | ✓ | ✓ | ✓ |

---

## 5. Files produced (R1 round) — uncommitted working tree

### 5.1 New files (untracked)

| Path | Notes |
|------|-------|
| `crates/cli/src/bin/mida_gto_product_recovery_observer.rs` | ~600+ lines; observation-only |
| `tools/_mtr_acq_route_a_observer.py` | N=3 orchestrator |
| `tools/_mtr_acq_route_a_aggregate.py` | aggregator; item_8 starts false |
| `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_PLAN_20260729.md` | plan (0 budget) |
| `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_20260729.md` | this file |

### 5.2 Modified files (tracked, unstaged)

| Path | Edit |
|------|------|
| `crates/cli/Cargo.toml` | +1 [[bin]] entry; +1 `[dependencies]` line for `serde` |
| `WORKER_HANDOFF.md` | R1 audit-filed section (this round) |

### 5.3 NOT touched (per authorization §四)

- `crates/bwhook/**` — unchanged
- `crates/cli/src/unpacker/gto_host.rs` (research-branch version) — unchanged
- `tools/_r1b_transient_epoch_trap.py` — unchanged
- `docs/GTO_R1A_RESIDUAL_STOP_SEAL_20260728.md` — unchanged
- Vault evidence files — unmodified

### 5.4 Evidence-side artifacts (vault, READ-ONLY references, not committed)

- `D:\MidaVault\scratch\product_recovery_route_a_r1_n3_20260729-155500\` (root of N=3 evidence)
  - `aggregate.json` — **pre-report machine output**; `evidence_bar_pass=false`; `item_8_report=false` by design; `stability_score=1.0`
  - `orchestrator_summary.json`
  - `run_1/outcomes.json`, `run_1/observer.log`, `run_1/observer.stdout.log`
  - `run_2/...`, `run_3/...` (mirror)

Vault evidence is **not** part of any repo commit; it is the input/observation record for this report and is referenced by SHA-256. **Not rewritten** under this expert-audit docs pass.

### 5.5 Anti-revival cross-check (2026-07-29, post-R1; reaffirmed docs-only audit)

- `crates/bwhook/**` — unchanged.
- `tools/_r1b_transient_epoch_trap.py` — unchanged.
- `crates/cli/src/unpacker/gto_host.rs` (research-branch version) — unchanged. New observer under `crates/cli/src/bin/`.
- No `MIDA_GTO_BYPASS=1` or `MIDA_GTO_SEMANTIC_REPAIR` ever set.
- No `git push`.
- No `git commit` of R1 artifacts yet.

---

## 6. Commands run (R1 round)

| Command | Result |
|---------|--------|
| `git checkout -b codex/gto-product-recovery-route-a 1ca2fde` | new branch from baseline |
| `cargo check -p mida-cli --offline` (initial) | ok, 0 errors, 8 pre-existing warnings |
| `cargo test -p mida-pe --lib --offline` | 175/175 pass (regression guard; R1 does not touch shared dumper) |
| `cargo test -p mida-packers-themida --lib --offline` | 121/121 pass |
| `cargo build -p mida-cli --bin mida_gto_product_recovery_observer --offline` (via vcvars64-sourced cmd.exe) | ok |
| Smoke run (5 s) — first build | `VirtualQueryEx` returned 0 on every call → root cause: missing `PROCESS_QUERY_INFORMATION` |
| Smoke run (5 s) — after access-rights fix | 247 ticks; observed_regions captured |
| Diagnostic rebuild + 3 s smoke | confirmed `VirtualQueryEx` returns 48 bytes per call; `OpenProcess(PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION)` required |
| Diagnostic code removed + final rebuild | 1.56 s |
| `python tools/_mtr_acq_route_a_observer.py --n 3 --observation-window-ms 30000 --poll-period-ms 50` | N=3 runs, sidecars written; aggregator emits `stability_score=1.0`, **`evidence_bar_pass=false`** (item_8 false by design) |

Note: `cargo test -p mida-acceptance --lib --offline` was **not** run in this R1 round — pre-existing MSVC linker unavailability in this shell context. R1 does **not** modify acceptance logic.

---

## 7. Exact env vars

| Var | Value | Notes |
|-----|-------|-------|
| `MIDA_GTO_NO_BYPASS` | `1` | Default-deny bypass; set by orchestrator before launching the observer. |
| `MIDA_GTO_BYPASS` | absent | Per plan §4.1 + §七. |
| `MIDA_GTO_SEMANTIC_REPAIR` | absent | Per plan §4.1 + §七. |
| `PATH` | inherited | Includes `C:\Program Files\Git\usr\bin` (GNU `link.exe` shadows MSVC linker if `vcvars64.bat` is not sourced). |
| Other env | inherited | No additional GTO-related vars set. |

The observer spawns the protected target with `CreateProcessW(... CREATE_SUSPENDED)` then `ResumeThread` and immediately begins polling. The protected target inherits the orchestrator's env (so `MIDA_GTO_NO_BYPASS=1` is also set on the target side).

---

## 8. Pass notation (corrected)

Plan §3.1 machine conjuncts (items 1–7) are measurement-layer true in the vault aggregate. Item 8 is the report layer.

```
Machine pre-report: evidence_bar_pass = false   # item_8_report=false by design
Report layer:       this document filed
Final R1 pass:      expert acceptance after report review ONLY
```

Do **not** write:

- `aggregate evidence_bar_pass=true`
- “all 8 evidence-bar items satisfied” as a machine fact
- self-declared final “R1 PASS” without expert acceptance

**Current status string:** **R1 evidence filed — expert pre-review pending / conditional technical pass candidate.**

Primary conditional anchor (if expert accepts the downgrade): stable **executable private region >1 MiB (RX/RWX-class)** under the retained JSON name `vm_codegen_region_expand` (presence, not proven expansion; protect=32 = `PAGE_EXECUTE_READ`).

`vm_protection_transition` is **supporting weak observation only** and is **not** the primary pass anchor.

---

## 9. R2 entry conditions (per plan §六)

R2 entry is permitted **only if**:

1. R1 has been **expert-accepted** after report review (not merely machine items 1–7).
2. R2 goal is **derived from R1 evidence** (the accepted named-epoch observation must inform R2's hypothesis — including any strength downgrades recorded here).
3. New expert ruling OR charter amendment recorded in `WORKER_HANDOFF.md` **explicitly** allocates R2 rounds in the `GTO-PRODUCT-RECOVERY Route A` ledger namespace. R2 = 1 round, cap = 2 total. The ledger has R1 = 1 round consumed, so **R2 = 1 round remaining** if/when authorized.

Per plan §六, R2's target is:

- N≥5 runs, ≥3/5 reproduce R1 named epoch
- At least one produced candidate dump reaches R0B `StructuralPassBehaviorPending` OR explicitly state Route A is pre-dump evidence only
- Origin Phase C non-regression if shared dumper touched
- Write `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R2_20260729.md` + update `WORKER_HANDOFF.md`

**This report does NOT request R2 authorization.** R2 is gated on a separate expert ruling per the proposal's §3.3 + §6.5 third-pass 2026-07-29 rule.

---

## 10. Self-discipline check

- Anti-revival: `crates/bwhook/**` unchanged.
- Anti-revival: `tools/_r1b_transient_epoch_trap.py` unchanged.
- Anti-revival: `crates/cli/src/unpacker/gto_host.rs` (research version) unchanged. New observer lives under `crates/cli/src/bin/`.
- Anti-rename: new observer binary is `mida_gto_product_recovery_observer` (no `_r1b_` / `_r1a_` / `_gto_host_` substring).
- Anti-default: env default `MIDA_GTO_NO_BYPASS=1`; bypass absent.
- Anti-push: no `git push`.
- Anti-commit-premature: **no commit of R1 artifacts yet**; uncommitted working tree awaiting expert review (plan §九).
- Anti-VEH: no VEH API usage in observer.
- Anti-DRx: no `GetThreadContext` debug-register fetch; no `SetThreadContext`; no `NtContinue` injection.
- Anti-overclaim (this audit pass): RWX → executable RX/RWX-class; expand not proven; protection_transition weak; aggregate `evidence_bar_pass` left false.

---

## 11. Commit status (actual)

**No commit has been made for the R1 round.** Working tree on `codex/gto-product-recovery-route-a` is **dirty / uncommitted**, awaiting expert pre-review per plan §九 + authorization §九 (“R1 完成后不自动 commit; 先给专家验收; 专家通过后才 commit”).

- HEAD remains `1ca2fdefd5014ce9f043d6aab84c434542d9ca6b` (baseline head; branch created from it, no R1 commits).
- **No push.**
- **No staged index** claimed; files are modified/untracked in the working tree only.
- Earlier draft language that said “committed locally” / “workspace staged” was **incorrect** and is withdrawn by this audit pass.

---

## 12. Reporting shell (actual uncommitted state)

Expected / observed shape after this docs-only audit (exact lines may vary slightly with whitespace-only noise):

```
git status --short --branch
## codex/gto-product-recovery-route-a
 M WORKER_HANDOFF.md
 M crates/cli/Cargo.toml
?? crates/cli/src/bin/
?? docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_20260729.md
?? docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_PLAN_20260729.md
?? tools/_mtr_acq_route_a_aggregate.py
?? tools/_mtr_acq_route_a_observer.py

git rev-parse HEAD
1ca2fdefd5014ce9f043d6aab84c434542d9ca6b

git diff --stat
# covers TRACKED files only (WORKER_HANDOFF.md + crates/cli/Cargo.toml)

git diff --name-status
# M  WORKER_HANDOFF.md
# M  crates/cli/Cargo.toml

git ls-files --others --exclude-standard
# crates/cli/src/bin/mida_gto_product_recovery_observer.rs
# docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_20260729.md
# docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_PLAN_20260729.md
# tools/_mtr_acq_route_a_aggregate.py
# tools/_mtr_acq_route_a_observer.py

git diff --check
# (run at audit time; no newly introduced whitespace errors expected on docs)
```

**Note:** `git diff --stat` / `git diff --name-status` show **tracked** changes only. The five untracked R1 artifacts require `git status` and/or `git ls-files --others --exclude-standard`. Together these are the **7 change paths** of the R1 round (2 modified + 5 untracked; `crates/cli/src/bin/` is the directory containing the new observer `.rs`).

Exact SHA-256s of produced artifacts (working tree + vault evidence):

- target binary (`gto_protected.exe`): `4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8`
- observer binary (`target/debug/mida_gto_product_recovery_observer.exe` at R1 time): `67f6158e30bd88c061ca8a6876f33e2c8e35301440c43b65a47d795ac08a258c`
- sidecar sha256s: see §3 table
- `aggregate.json`: at `D:\MidaVault\scratch\product_recovery_route_a_r1_n3_20260729-155500\aggregate.json` — **`evidence_bar_pass=false`**, `item_8_report=false` by design, `stability_score=1.0`

**Budget burn:** R1 = 1 round consumed; R2 = 0; cap = 2; **remaining = 1**.

**Expert-audit docs-only correction (this pass):** no Rust/Python change; no re-measure; no vault rewrite; no commit; no push.
