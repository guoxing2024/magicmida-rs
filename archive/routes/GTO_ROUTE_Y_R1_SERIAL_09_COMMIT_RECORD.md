# GTO Route Y R1 — MIDA-SERIAL-09 Local Commit Record

## 1. Record date

2026-08-15

## 2. Repository

- branch: `oreans/two-sample-mainline`
- base HEAD: `9419ce9c40fd0874b97ac4c4459167d345ac8091`
- final HEAD: `dfbf5913b49d5e1122b8e7ccd1da842c6914c52a`
- local-only: the four commits exist only in the local repository
- remote/upstream: **not configured** (`git remote -v` empty; branch has no upstream)
- push: **not executed**

## 3. Commit chain

Four local commits, applied in this exact order (strictly linear, each commit is the parent of the next):

| # | SHA-256 (full) | Message | Files | Boundary |
|---|---|---|---|---|
| 1 | `8c7de4a63ce58b78a7db140d7f8e13aee70a84f9` | `test(cli): add extended-path and subdirectory symlink escape regression tests` | `crates/cli/src/runner_preflight.rs` | standalone |
| 2 | `b5aba7c183f0bb18c0b4683a13228d59e7459994` | `fix(pe): checked region/slot arithmetic and fallible structural pointer declaration` | `crates/pe/src/dumper/runtime_rebase.rs` | standalone |
| 3 | `2313947877a15672d1ff5fd986b1cac0d5bf0937` | `feat(pe): gscript label-table capture path with atomic raw-coherence identity and manifest serialization` | `crates/pe/src/dumper/heap_global_snapshot.rs`, `crates/pe/src/dumper/raw_slab_coherence.rs`, `crates/pe/src/dumper/snapshot_manifest.rs` | **atomic** (must not be split) |
| 4 | `dfbf5913b49d5e1122b8e7ccd1da842c6914c52a` | `fix(pe): wire heap-window trim and fallible pointer declaration into dump pipeline` | `crates/pe/src/dumper/dump_process.rs` | wired last |

Order dependency: commit 3 (B+E+F) is atomic because the `GscriptLabelTableEntry` enum variant addition breaks raw-slab `CapturePath` match exhaustiveness and manifest serialization simultaneously; commit 4 (D) depends on commits 2 (C) and 3 (B+E+F).

## 4. Verification

- `cargo test --workspace --offline`: **1885 passed / 0 failed / 2 ignored**
- `cargo fmt --all -- --check`: **PASS**
- `git diff --check`: **PASS**
- `git diff --name-only` (tracked working tree): **empty**
- `git diff --cached --name-only` (staged): **empty**
- Per-layer gates: runner_preflight 53 passed; runtime_rebase p2_4 3 passed; raw_slab_coherence 292 passed (+ 3 targeted heap tests); workspace full suite 1885 passed.

## 5. Scope exclusions

- docs/ and lab/ existing audit evidence: **unchanged** (untracked evidence preserved as-is)
- push: **not executed**
- launcher / target execution: **none**
- observer / controller / network / firewall: **none**
- hook / injection / debugger: **none**
- dynamic behavior verification: **not performed**

## 6. Governance state

- `dynamic_authorized = false`
- governance: `RouteY_R1_GTO_LAUNCHER_REV2_DynamicAuthorizationSuspended`
- approved scope remains only: `RouteY_R1_GTO_LAUNCHER_REV2_RUNTIME_MODULE_IDENTITY_RECAPTURE_2` (module identity recapture)
- local commit closure does **not** equal dynamic authorization; `ReadyForSeparateDynamicWorkOrder` (authority review 4) is issuance eligibility only
- offline test pass (1885) grants no launcher/target/observer/controller/network/firewall/hook/injection/debugger permission

## 7. Deferred P1 (not resolved)

- `DumpCapturePolicy` (`capture_policy.rs`) `hot_root_rvas`/`large_table_rvas` remain **bare-RVA policies unbound to module/capture identity** — fixed RVAs can silently apply to non-target captures (POLICY_UNBOUND_SAMPLE_COUPLING, MIDA-SERIAL-07)
- `sanitize_ahk_runtime_global` still contains the `0x141bf0` sample-specific special case; no static generic predicate exists — MIDA-SERIAL-06 blocked as `BLOCKED_BY_MISSING_GENERIC_PREDICATE`
- This P1 is a **pre-existing HEAD architecture coupling**; the four commits did **not** add, move, or widen any sample RVA production dependency (0x141bf0 production references unchanged: capture_policy.rs untouched; raw_slab production references are the 3 pre-existing HEAD ones; all other 0x141bf0 occurrences are test-module constructs)
- The P1 is **deferred, not resolved** — moving fixed RVAs into a new config item must not be claimed as generalization; future work must go through an identity-bound policy / transform evidence-chain independent work order

## 8. Evidence provenance

- This document records the current state reported by MIDA-SERIAL-09 (commit closure).
- Historical authority reviews (REVIEW_1/2/3/4, static baseline, forensic reconciliation, etc.) are **not rewritten**; their recorded HEAD snapshots are preserved as immutable history.
- This document is **not** a dynamic-execution authorization and **not** a new authority approval.
- Corroborating mutable handoff entry: `WORKER_HANDOFF.md` section `### MIDA-SERIAL-09 Local Commit Closure — 2026-08-15` (appended 2026-08-15).