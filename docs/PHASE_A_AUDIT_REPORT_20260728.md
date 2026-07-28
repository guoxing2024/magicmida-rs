# Phase A Audit Report — Freeze / Offline Gate / Commit Boundaries

> **Generated:** 2026-07-28 (local session, OpenHands agent)  
> **Audience:** expert audit  
> **Status:** Phase A complete for *offline* scope. Product unpack still **Blocked**.  
> **Discipline:** evidence-driven · one battlefield · no fake 1.0 · freeze features until P0 done

---

## 0. Executive verdict

| Question | Answer |
|----------|--------|
| Can agent take over? | **Yes** — repo, MSVC, vault, offline gates, and residual docs are operable. |
| Is working tree shippable as one commit? | **No** — mixed P0 safety + research GTO/BootWatch + lab tooling. |
| Offline P0 gates green? | **Yes** after one HEAD regression fix (see §3). |
| Product goal complete? | **No.** `origin_macro` perfect-unpack remains historical win; `gto_launcher` still far. |
| Fake Accepted risk? | Prior fail-closed work is present and offline-tested; **do not** re-label historical `validation_summary` as current product success. |

**Binding goal unchanged** (`docs/PROJECT_GOAL_20260725.md`): perfect unpack for exactly two samples. GTO is not product-complete.

---

## 1. Freeze snapshot

| Item | Value |
|------|-------|
| Branch | `baseline/legacy-recovery-20260722` |
| HEAD | `6211e6c` — *fix: IAT forward margin + 64-bit scrub range + .themida raw retention* |
| Dirty modified | **31** files (`git diff --name-only`) |
| Dirty untracked | `envelope.rs`, `crates/bwhook/`, audit/GTO docs, tools (`softbp_host.py`, `_idalib_mcp_fixed.py`), transient `nul` (cleaned this session) |
| Diff magnitude | **+7014 / −2453** (stat) |
| Commits this session | **none** (freeze only; no push/PR) |
| `CARGO_TARGET_DIR` | `D:\MidaVault\scratch\cargo-target` |
| Toolchain | rustc/cargo **1.96.1**; MSVC **14.44** HostX64\x64 (`tools/_enter_msvc_env.ps1`) |

### 1.1 Modified inventory (by layer)

**Workspace / policy**

- `Cargo.toml`, `Cargo.lock` — `exclude = ["crates/bwhook"]` + `default-members` pin product crates
- `validation_summary.json` — narrative / gate summary drift (do **not** treat as product certificate)

**P0 / product-adjacent (candidate commit set A)**

- `crates/pe/src/dumper/dump_process.rs` — EP OptionalHeader+16, alias/hardlink refusal, managed manifest path, .NET OEP, short-read fail-closed
- `crates/pe/src/dumper/container_bootstrap.rs` — stub arity 24 alignment
- `crates/pe/src/dumper/data_reinit.rs` — **this session** three-band scrub fix (HEAD regression)
- `crates/pe/src/dumper/mod.rs`, `crates/pe/src/lib.rs`, `crates/pe/Cargo.toml`
- `crates/acceptance/**` + `crates/acceptance/src/envelope.rs` (untracked) — fail-closed Accepted, taxonomy, signed bundle path
- `crates/packers/themida/src/iat/{boundaries,fix}.rs`, `trace_imports/mod.rs`, `guard.rs` — product_complete / FTMGuard / within_image
- `crates/cli/src/unpacker/{helpers,mod,plugin_host,iat_trace,av_handler}.rs` — output alias, IAT product gate wiring
- `crates/core/src/{process,lib}.rs` — stub unique path / small surface
- `docs/ACCEPTANCE_CONTRACT.md`, `docs/TRANSFORM_TAXONOMY_V1.md` (untracked), `docs/AUDIT_SELF_CORRECTION_20260727.md` (untracked)

**Research / residual (candidate set B — do not mix into P0 ship commit)**

- `crates/cli/src/unpacker/gto_host.rs` — **largest** dirty file (~+3.3k lines class); BootWatch / GTO experimental
- `crates/core/src/windows_debugger.rs` — debugger surface expansion
- `tools/softbp_host.py`, `tools/_idalib_mcp_fixed.py`, BA3/BB tool churn
- `crates/bwhook/` — research-only, excluded from workspace members
- `docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` — GTO analysis, not product gate

---

## 2. Offline verification (this session, MSVC 14.44)

All runs used `--offline` and `CARGO_TARGET_DIR=D:\MidaVault\scratch\cargo-target`.

| Gate | Result | Notes |
|------|--------|-------|
| `cargo test -p mida-pe --lib address_of_entry_point` | **1/1 ok** | EP not section table |
| `cargo test -p mida-pe --lib tls_process_attach` | **1/1 ok** | stub 24-arg |
| `cargo test -p mida-pe --lib data_offset_uses_dword` | **1/1 ok** | stub 24-arg |
| `cargo test -p mida-pe --lib` | **175/175 ok** | after scrub fix; was **174 pass + 1 fail** on HEAD tree |
| `cargo test -p mida-packers-themida --lib within_image` | **2/2 ok** | |
| `cargo test -p mida-packers-themida --lib gate` (+ cookie) | **4/4 ok** | product_complete gates |
| `cargo test -p mida-packers-themida --lib` | **121/121 ok** | |
| `cargo test -p mida-acceptance --lib` | **25/25 ok** | includes fail-closed / taxonomy / envelope tests |
| `cargo check -p mida-cli --offline` | **ok** | |
| `cargo check -p mida-pe --offline` | **ok** | |

**Not run this Phase A (explicitly out of freeze scope):** live unpack of vault samples, full workspace `--all-targets`, Clippy, Windows CI, GTO free-run.

Logs under `D:\MidaVault\scratch\phase_a_*.out` / `phase_a_summary_*.json`.

---

## 3. Session code fix (only functional change this Phase A)

### 3.1 Defect (pre-existing on HEAD `6211e6c`)

`is_stale_absolute_pointer` was widened to full user range **and** alignment was removed. That contradicts:

1. File comment: *do not scrub ASLR image VAs (`0x7ff7…`) — Origin W1*
2. Unit test `clears_origin_kernel_garbage_object_head` asserting  
   `!is_stale_absolute_pointer(0x0000_7ff7_2537_1200, …)`

**Observed failure before fix:**

```text
mida-pe lib: 174 passed; 1 failed
assertion failed: !is_stale_absolute_pointer(0x0000_7ff7_2537_1200, image_base, image_end)
at crates/pe/src/dumper/data_reinit.rs:401
```

`git diff` on this file was empty **before** the fix → failure was on committed HEAD logic, not dirty-tree noise.

### 3.2 Fix (three-band scrub)

In `crates/pe/src/dumper/data_reinit.rs`:

| Band | Range | Policy |
|------|-------|--------|
| Image | `[image_base, image_end)` | never scrub |
| Kernel canonical | `>= 0xffff_8000_0000_0000`, `!= u64::MAX` | scrub (unaligned OK) |
| Low heap | `MIN_USER .. 0xffff_ffff` | scrub **only if 8-byte aligned** |
| Mid-user | `>4GB` and `< HIGH_ASLR_MODULE_MIN` | scrub (unaligned OK; Themida `0x2b99…` class) |
| High ASLR module | `>= 0x7ff0_0000_0000` | **preserve** until rebase |

Test extended with mid-user unaligned positive case `0x2b992ddfa232`.

### 3.3 Intent preserved from `6211e6c`

- Still clears mid-user unaligned Themida heap garbage (original commit motive).
- Restores Origin W1 safety for high module VAs.
- Restores low-4GB alignment filter for packed constants / cookie fragments.

---

## 4. Claimed P0 items — independent confirmation

Mapped from `docs/AUDIT_SELF_CORRECTION_20260727.md` against tree + tests:

| ID | Claim | Evidence this session | Status |
|----|-------|----------------------|--------|
| P0-1 EP | OptionalHeader+16, not section table | `address_of_entry_point_file_offset` = `e_lfanew+24+16`; golden test poisons sect0+16 `0xDEADBEEF`; test **pass** | **Confirmed in dirty tree + green** |
| P0-2 stub arity | tests 24 params | `container_bootstrap` tests call 24 args; TLS/dword tests **pass** | **Confirmed** |
| P0-3 Accepted fake-green | fail-closed parse/compose | acceptance lib **25/25**; prior self-corr docs list dedicated reject tests | **Offline green** (no product sample re-label) |
| P1-IAT complete | product_complete strict | themida gate tests **pass**; semantics still “not full resolve proof” | **Gate compiles + unit green**; live corpus not re-run |
| P1-FTMGuard | re-arm active guard | `guard.rs` dirty; themida lib green | **Compile/unit only** |
| P1-GTO bypass default OFF | opt-in only | claimed in self-corr + dump_process dirty; **not** product path | **Policy intent present**; bypass still research |
| P1-output alias | refuse clobber | helpers/process/dumper dirty | **Code present**; no live hardlink trial this phase |
| P1-bwhook | out of product | root `exclude` + untracked crate | **Confirmed excluded** |

---

## 5. Commitable boundaries (recommended split)

### Set A — “P0 offline safety / fail-closed” (allowed after expert OK)

Focus: PE dump correctness, acceptance contract, Themida IAT product gate, CLI non-GTO safety, taxonomy/envelope **verification** side, docs that define contract.

Suggested paths (review before commit):

```text
Cargo.toml
Cargo.lock
crates/pe/**
crates/acceptance/**
crates/packers/themida/src/guard.rs
crates/packers/themida/src/iat/**
crates/packers/themida/src/trace_imports/**
crates/cli/src/unpacker/helpers.rs
crates/cli/src/unpacker/mod.rs
crates/cli/src/unpacker/plugin_host.rs
crates/cli/src/unpacker/iat_trace.rs
crates/cli/src/unpacker/av_handler.rs
crates/core/src/process.rs
crates/core/src/lib.rs
docs/ACCEPTANCE_CONTRACT.md
docs/TRANSFORM_TAXONOMY_V1.md
docs/AUDIT_SELF_CORRECTION_20260727.md
docs/PHASE_A_AUDIT_REPORT_20260728.md
```

**Include this session’s** `data_reinit.rs` scrub fix in Set A — it repairs HEAD.

### Set B — “GTO / BootWatch research residual” (hold)

```text
crates/cli/src/unpacker/gto_host.rs
crates/core/src/windows_debugger.rs   # if only consumed by BootWatch
tools/softbp_host.py
tools/_idalib_mcp_fixed.py
docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md
crates/bwhook/**                      # never product members
```

### Set C — “lab / summary churn” (hold or separate)

```text
tools/_behavior_ba3_smoke.py
tools/_behavior_bb_gate.py
validation_summary.json               # rewrite only with honest Blocked / superseded wording
```

### Explicit non-goals until Set A lands + expert ack

- No new GTO free-run grind
- No product `Accepted` for gto_launcher
- No merge of bwhook into workspace members
- No single mega-commit of +7k lines

---

## 6. Goal scoreboard (honest)

| Sample | Goal | State |
|--------|------|-------|
| `origin_macro` | Perfect unpack | **Historical complete** (do not regress via scrub/EP) |
| `gto_launcher` | Perfect unpack | **Far** — Themida VM / pointee epoch / UI path research; residual bypass ≠ product |

Phase A does **not** advance gto_launcher product score. It freezes and validates offline foundations.

---

## 7. Risks / residual for expert

1. **Dirty tree entanglement** — Set A and Set B share some modules (`dump_process`, core). Expert should review `git diff` hunks, not only file list.
2. **`gto_host.rs` size** — high review cost; keep off P0 merge.
3. **HEAD scrub regression** — proves `6211e6c` was under-tested on full pe lib; Set A must include scrub band fix before further scrub experiments.
4. **Envelope trust model** — signed Accept path is lab/HMAC constrained; Ed25519 product path still incomplete (self-corr §18–21). Do not market as production attestation.
5. **Live vault samples** — not re-executed in Phase A; offline green ≠ live perfect unpack.
6. **Terminal hygiene** — PowerShell+cargo sometimes hung on interactive hosts; prefer `Start-Process` redirect to `D:\MidaVault\scratch\`.

---

## 8. Recommended next phase (after expert ack)

**Phase B (P0 ship slice only):**

1. Expert reviews Set A diff boundaries.
2. Agent stages **only** Set A (or expert-trimmed subset), runs offline gates again, single focused commit message (no GTO claims).
3. Re-run origin smoke if vault sample available (load_no_crash / prior perfect path) — **one battlefield**.
4. Leave Set B parked; gto_launcher work only after P0 commit lands and expert opens that battlefield.

---

## 9. Takeover capability statement

| Capability | Ready? |
|------------|--------|
| Read/navigate monorepo + vault layout | Yes |
| MSVC + cargo offline test/check | Yes (after `_enter_msvc_env.ps1`) |
| Diagnose PE/IAT/acceptance regressions | Yes |
| Live GTO unpack / UI equivalence | Research only; not product-ready |
| Unattended mega-merge of dirty tree | **Refused** under project discipline |

**Conclusion:** Agent can operate and gate this project. Phase A freeze + offline green is established. Product remains **Blocked** on gto_launcher; origin_macro remains the only completed binding sample.

---

*This report was produced by an AI agent (OpenHands) for expert audit. It does not claim perfect unpack or product Accepted.*
