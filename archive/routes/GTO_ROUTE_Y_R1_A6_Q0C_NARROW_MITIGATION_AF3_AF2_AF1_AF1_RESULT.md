# Route Y R1 A6 — Q0-C Narrow Mitigation AF3 AF2 AF1 AF1 — RESULT
## (Identity-First Pre-Resolution and Exact Error-Contract Closure)

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF3_AF2_AF1_AF1_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged — no commit)

This is the **AF3 AF2 AF1 AF1** work order, issued by the AF3 AF2 AF1 audit rejection
(`RouteY_R1_A6_Q0C_AF3_AF2_AF1_ParentIdentityAccepted`,
`..._SeedingIdentityAccepted`, `..._ParentUnificationAccepted`,
`..._BindingConsistencyAccepted`, `..._Q0COrderingNeedsAF1`). The audit accepted the four
core closures (parent 12-field consumption, seeding full-identity unique resolution, parent
field unification, binding typed consistency) but blocked on one remaining gap:

> `build_patched_backing_slab_q0c` ran `validate_run_ledger_shape` /
> `validate_run_membership` / binding consistency **before** the raw full-identity
> resolution inside the child loop, so an identity error could surface as
> `TransformRunLedgerInvalid` / `BindingIdentityInconsistent` instead of the required
> `RawChildMissing`.

AF3 AF2 AF1 AF1 closes this with a dedicated **identity pre-resolution phase** that runs
first, plus a shared identity resolver and an exact typed error contract. No live, no
protected sample, no controller, no spawn, no candidate, no cold-start/promote, no Route Z
R1, no Supervisor Production Integration, no commit. All pre-existing
AF1/AF2/AF3/AF3-AF1/AF3-AF2/AF3-AF2-AF1 tests are preserved.

---

## 1. P1-1 — Q0-C identity pre-resolution plan

`build_patched_backing_slab_q0c` now has an **identity pre-resolution phase** that runs
immediately after the transformed children are collected and sorted, and **before**
`validate_run_ledger_shape`, `validate_run_membership`, binding validation, slab coverage,
size, bytes, digest, ledger replay, and overlay.

For every non-`SyntheticDerived` transformed child:

1. build `FullCaptureIdentity` (from the transformed snapshot);
2. detect whether it is a legal `DeclaredSizeReinit` (via `transform_ids` + `rva`);
3. normal child → require exact structural equality of the raw identity;
4. `DeclaredSizeReinit` → ignore only `size`; every other field must match exactly;
5. require **exactly one** raw child;
6. 0 or >1 → `RawChildMissing`;
7. never first-match, never `sort+next`, never slab-bytes identity selection, never
   capture-id wildcard.

The result is saved as a typed plan:

```rust
struct ResolvedQ0cChild {
    transformed_index: usize, // index into `transformed`
    raw_index: usize,         // index into `raw_capture.children` (unique full-identity match)
    declared_reinit: bool,
}
```

The child loop **consumes** this plan (`identity_plan.iter().find(|r| r.transformed_index == tc_idx)`)
and reads the raw child by `raw_index`; it never re-looks up a raw child by partial identity.

---

## 2. P1-2 — unified identity resolver

A single shared predicate is used by **both** seeding and Q0-C, so the two can never drift:

```rust
fn raw_identity_matches_transformed(
    raw: &RawChild,
    transformed: &FullCaptureIdentity,
    declared_reinit: bool,
) -> bool
```

- `declared_reinit == false` → exact structural equality;
- `declared_reinit == true` → `identity_matches_ignore_size` (every field except `size`).

Call sites:
- **Seeding**: `find_raw_child` filters via `raw_identity_matches_transformed(child, identity, false)`.
- **Q0-C pre-resolution**: `raw_identity_matches_transformed(c, &tc.identity, declared_reinit)`.

`DeclaredSizeReinit` continues to ignore **only** `size` — never source evidence.

---

## 3. P1-3 — subsequent fail-closed gates preserved (order moved, not weakened)

After identity pre-resolution succeeds, every existing gate still runs in order and is **not**
weakened:

- `validate_run_ledger_shape` (malformed ledger / duplicate run);
- `validate_run_membership` (orphan run, duplicate raw child, wrong capture id);
- all-binding `validate_identity_consistency` (orphan / contradictory binding);
- binding identity == raw identity == transformed identity (overlay exact-match);
- slab unique coverage (`covering_slab_for_child`);
- raw `C == slab S`;
- digest self-consistency;
- run replay / last-writer;
- `resolved_writes` conflict;
- Q0-C last-writer prohibition.

Only the ordering changed; no gate was removed or relaxed.

---

## 4. P1-4 — exact typed error contract

The priority is now locked:

| condition | exact error |
|---|---|
| raw full-identity 0 / >1 matches | `RawChildMissing` |
| (only after identity unique success) malformed/mismatched ledger | `TransformRunLedgerInvalid` |
| (only after identity unique success) contradictory binding representation | `BindingIdentityInconsistent` |
| (only after identity unique success) slab coverage failure | `RawChildOutsideSlab` / `ProbeCoverageMissing` |
| (only after identity unique success) raw byte drift | `RawCaptureDrift` |

No `A || B` weak assertion is used to mask the stage. The previously weak
`q0c_duplicate_full_identity_fails_closed` (which accepted
`RawChildMissing || TransformRunLedgerInvalid`) was **rewritten** to
`q0c_duplicate_full_identity_is_exact_raw_child_missing` asserting exactly `RawChildMissing`.

---

## 5. The mandatory AF3 AF2 AF1 AF1 tests

All 9 present and green:

| # | Test | Proves |
|---|------|--------|
| 1 | `q0c_wrong_identity_precedes_binding_identity_inconsistent` | wrong identity + contradictory binding → exactly `RawChildMissing` |
| 2 | `q0c_wrong_identity_precedes_run_membership_invalid` | wrong identity + invalid membership → exactly `RawChildMissing` |
| 3 | `q0c_duplicate_full_identity_is_exact_raw_child_missing` | duplicate full identity → exactly `RawChildMissing` (weak assertion removed) |
| 4 | `q0c_declared_reinit_source_drift_precedes_binding_and_ledger` | declared reinit, valid size change, source drift + defective binding/ledger → exactly `RawChildMissing` |
| 5 | `q0c_exact_identity_then_binding_inconsistency_is_reported` | exact identity + contradictory binding → `BindingIdentityInconsistent` |
| 6 | `q0c_exact_identity_then_membership_error_is_reported` | exact identity + orphaned run → `TransformRunLedgerInvalid` |
| 7 | `q0c_orphan_inconsistent_binding_still_fails_closed` | orphan + contradictory binding still fails at binding-consistency gate |
| 8 | `q0c_identity_failure_does_not_touch_slab` | wrong identity + empty slab → `RawChildMissing` (slab not first adjudicator) |
| 9 | `q0c_identity_plan_uses_same_raw_for_binding_and_overlay` | plan resolves ONE raw child that both binding and overlay consume (no later partial lookup) |

---

## 6. Static gate

```
git grep -n "if raws.len() == 1" -- crates/pe/src/dumper/raw_slab_coherence.rs
crates/pe/src/dumper/raw_slab_coherence.rs:3238:        let raw = if raws.len() == 1 {
```

The **only** hit (line 3238) is inside the **legacy** `build_patched_backing_slab`
(fn starts at line 3067), which is a **test-only** function: it has no non-test callers, and
production `crates/pe/src/dumper/dump_process.rs:1546` calls
`build_patched_backing_slab_q0c`. The production Q0-C path contains **no**
`if raws.len() == 1` shortcut.

---

## 7. P2 — report honesty

The following are stated factually, not over-claimed:

- `TransformPreimageBinding` is a **dual representation + typed consistency validation**,
  not a physical single identity owner: it still stores both the legacy field tuple and
  `identity`, but `new(...)` derives the legacy tuple from `identity` and
  `validate_identity_consistency()` (called at the Q0-C entry) fails closed with
  `BindingIdentityInconsistent` on any overlap mismatch.
- `build_patched_backing_slab` retains a `if raws.len() == 1` shortcut; it is the
  legacy/test-only function, not the production Q0-C path.
- Production `dump_process.rs` calls only `build_patched_backing_slab_q0c`.
- Gate results are reported as worker evidence and are **not** presented as independently
  audited verification.

---

## 8. Gates (all green)

| Gate | Command | Result |
|------|---------|--------|
| fmt | `cargo fmt --all -- --check` | clean |
| mida-pe offline | `cargo test -p mida-pe --offline` (via `af3_pe_full.cmd`) | **751 passed / 0 failed** (743 prior + 8 net new; one renamed) |
| mida-cli features | `cargo test -p mida-cli --features gto-product-recovery` (via `af3_cli_gates.cmd`) | exit 0 |
| mida-cli offline | `cargo test -p mida-cli --offline` (via `af3_cli_gates.cmd`) | exit 0 |
| python controller | `python tools/test_gto_live_route_controller.py` | **36 passed / 0 failed** |
| whitespace | `git diff --check` | clean |

### Preserved matrix
All AF1/AF2/AF3/AF3-AF1/AF3-AF2/AF3-AF2-AF1 tests remain green (751 total). The label-table
canonical qword `00 00 00 01 00 00 00 00` (`B+0x23 == 1`), child-link/legitimate-containment
success, all fail-closed negatives, declared-reinit (`RVA 0x141bf0, old 0x8000, new 0x180,
zero-filled`), and Route X fail-closed are unchanged.

---

## 9. Production diff

- `crates/pe/src/dumper/raw_slab_coherence.rs` — identity pre-resolution phase
  (`ResolvedQ0cChild`, `identity_plan`), shared `raw_identity_matches_transformed` resolver
  (used by seeding `find_raw_child` + Q0-C pre-resolution), child-loop consumes the plan
  (no partial re-lookup), the 9 new identity-first tests, the duplicate test rewritten to
  exact `RawChildMissing`.
- `crates/pe/src/dumper/heap_global_snapshot.rs` — carries the P1-1 parent-identity
  consumption from the accepted AF3 AF2 AF1 round (unchanged this round).
- `crates/pe/src/dumper/snapshot_manifest.rs` — carries the AF3 AF2 binding-identity
  literals from the accepted round (unchanged this round).

**No `Cargo.toml` / `Cargo.lock` / source changes outside the three files above.**

---

## 10. Git live boundary

```
HEAD = f386b49af8f547a16f3d107dc6e80c02ea6e4403   (unchanged, no commit)

tracked modified:
- crates/pe/src/dumper/heap_global_snapshot.rs
- crates/pe/src/dumper/raw_slab_coherence.rs
- crates/pe/src/dumper/snapshot_manifest.rs

untracked source = 0
git diff --check: PASS
```

Docs remain untracked; A6 frozen evidence untouched.

---

## 11. Constraints honored

- **No commit**; HEAD unchanged.
- **No live**, no protected sample, **no controller**, **no spawn**, **no candidate**, **no
  cold-start/promote**, **no Route Z R1**, **no Supervisor Production Integration**, **no
  second protected live**.
- Q0-C, `resolved_writes`, last-writer, binding, run-membership, slab-slice, digest, and
  strict identity are **not weakened**.
- The Q0-C production path has **no** single-candidate shortcut; the only `if raws.len() == 1`
  is in the legacy test-only `build_patched_backing_slab`.
- **Stop here.** Await independent audit. No Supervisor Production Integration; no second
  protected live; no commit.
