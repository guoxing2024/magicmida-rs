# Route Y R1 A6 — Q0-C Narrow Mitigation AF3 AF2 AF1 AF1 AF1 — RESULT
## (UnknownSynthetic Precedence, Declared-Reinit Qualification, and Plan-Consumption Evidence Closure)

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF3_AF2_AF1_AF1_AF1_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged — no commit)

This is the **AF3 AF2 AF1 AF1 AF1** work order, issued by the AF3 AF2 AF1 AF1 audit rejection
(`RouteY_R1_A6_Q0C_AF3_AF2_AF1_AF1_RawIdentityPlanAccepted`,
`..._SharedResolverAccepted`, `..._OrdinaryErrorOrderingAccepted`,
`..._NeedsAF1`). The audit accepted the ordinary-child identity pre-resolution, the shared
resolver, and the ordinary error ordering, but blocked on two edge cases plus a test-evidence
gap:

- **P1-1** — `UnknownSynthetic` was grouped with `SyntheticDerived` in the same skip branch,
  so it could pass through ledger/binding gates and surface the wrong error before the
  child-loop `RawChildMissing`;
- **P1-2** — `declared_reinit` was inferred only from `transform_ids + rva` (declaration-table
  hit), letting the identity comparison ignore `size` before the declaration itself was
  qualified (old-size tolerance, new-size exact, zero-fill);
- **P2** — the "plan same raw for binding and overlay" test used identical bytes for the exact
  and distractor raw children, so it could not prove which raw the overlay consumed.

All three are closed. No live, no protected sample, no controller, no spawn, no candidate, no
cold-start/promote, no Route Z R1, no Supervisor Production Integration, no commit. All
pre-existing AF1/AF2/AF3/AF3-AF1/AF3-AF2/AF3-AF2-AF1/AF3-AF2-AF1-AF1 tests are preserved.

---

## 1. P1-1 — UnknownSynthetic precedence at pre-resolution

The pre-resolution phase now treats `UnknownSynthetic` and `SyntheticDerived` as **distinct**:

- `SyntheticDerived { .. }` → legal bypass with no raw preimage; skipped here, preserved for
  the synthetic overlay/provenance path;
- `UnknownSynthetic` → **fails closed IMMEDIATELY** as `RawChildMissing`, **before**
  `validate_run_ledger_shape`, `validate_run_membership`, binding consistency, slab, bytes,
  digest, replay, or overlay.

`UnknownSynthetic` is never converted to `SyntheticDerived`, never given a raw fallback, and
never silently ignored. The static gate confirms the two are no longer combined in one skip
branch.

---

## 2. P1-2 — declared-reinit qualification (two-stage plan)

The identity pre-resolution is now **two-stage**:

- **Stage A — candidate declaration identification**: exactly one transform id + rva hit must
  select the declaration (`declared_size_reinit`). A hit uses identity-ignore-size lookup;
  otherwise exact lookup. Either way **exactly one** raw candidate is required (0 or >1 →
  `RawChildMissing`).
- **Stage B — declaration qualification**: before any later gate, call
  `validate_declared_size_reinit_fields` with the raw child's old size, the transformed RVA /
  capture id / live base / bytes, proving: raw old size within tolerance, transformed new size
  exact, zero-fill, child RVA exact, capture id / live base. An invalid declaration returns
  `TransformRunLedgerInvalid` (reason names the failing declaration field) — **before** any
  ledger-shape / membership / binding / slab / byte decision.

The plan stores the **verified** spec:

```rust
enum ResolvedQ0cMode {
    Ordinary,
    DeclaredSizeReinit { spec: &'static DeclaredSizeReinit },
}
```

The child loop consumes `plan.mode`'s spec (`plan_spec`) and does **not** re-select via
`filter_map(...).next()`; the only `filter_map(...declared_size_reinit)` in the file is in the
pre-resolution Stage A.

### Locked error precedence (P1-2)

1. no unique raw identity (0 or >1) → `RawChildMissing`;
2. unique identity but invalid declaration → `TransformRunLedgerInvalid` (reason names the
   field);
3. identity + declaration valid → then any ledger / binding / slab / byte error.

---

## 3. P2 — strengthened plan-consumption evidence

`q0c_identity_plan_uses_same_raw_for_binding_and_overlay` was rewritten so the exact and
distractor raw children have **distinct bytes/digests**:

- exact raw: probe=0x100, capture_id `gscript_label:0x8e9da8`, bytes `0xAA` → digest A;
- distractor raw: probe=0x200, capture_id `...:dup`, bytes `0x55` → digest B;

The test asserts the **binding's** `raw_child_digest == digest A` (and `!= digest B`) and the
**overlay ledger's** `raw_child_digest == digest A` (and `!= digest B`), plus the patched byte
comes from the plan-selected raw. A future implementation that lets the overlay partial-lookup
the distractor would now fail the digest assertions.

---

## 4. The mandatory AF3 AF2 AF1 AF1 AF1 tests

All 11 present and green:

| # | Test | Proves |
|---|------|--------|
| 1 | `q0c_unknown_synthetic_is_exact_raw_child_missing` | UnknownSynthetic → exactly `RawChildMissing` at pre-resolution |
| 2 | `q0c_unknown_synthetic_precedes_binding_inconsistency` | UnknownSynthetic precedes contradictory-binding error |
| 3 | `q0c_unknown_synthetic_precedes_ledger_invalid` | UnknownSynthetic precedes malformed/orphan ledger error |
| 4 | `q0c_synthetic_derived_still_bypasses_raw_identity` | SyntheticDerived remains a legal bypass (not rejected) |
| 5 | `q0c_declared_wrong_old_size_precedes_binding_and_ledger` | declared wrong old size → `TransformRunLedgerInvalid`, old-size reason |
| 6 | `q0c_declared_wrong_new_size_precedes_binding_and_ledger` | declared wrong new size → `TransformRunLedgerInvalid`, new-size reason |
| 7 | `q0c_declared_nonzero_bytes_precede_binding_and_ledger` | declared nonzero content → `TransformRunLedgerInvalid`, zero-fill reason |
| 8 | `q0c_declared_identity_missing_precedes_declaration_validation` | source identity missing → `RawChildMissing` (before declaration) |
| 9 | `q0c_valid_declared_transition_then_binding_error_is_visible` | valid transition then contradictory binding → `BindingIdentityInconsistent` |
| 10 | `q0c_valid_declared_transition_then_ledger_error_is_visible` | valid transition then orphan run → `TransformRunLedgerInvalid` (ledger reason) |
| 11 | `q0c_declared_plan_spec_is_consumed_without_relookup` | valid declared transition overlays via the plan spec (no relookup) |

Plus the rewritten **P2 test 9** (`q0c_identity_plan_uses_same_raw_for_binding_and_overlay`)
with distinct digest evidence.

---

## 5. Static gates

```
git grep -n "UnknownSynthetic | RegionProvenance::SyntheticDerived" -- crates/pe/src/dumper/raw_slab_coherence.rs
→ (no matches)

git grep -n "filter_map.*declared_size_reinit" -- crates/pe/src/dumper/raw_slab_coherence.rs
→ crates/pe/src/dumper/raw_slab_coherence.rs:3725   (pre-resolution Stage A — candidate identification)
```

The only `filter_map(...declared_size_reinit)` is the pre-resolution Stage A; the Q0-C child
loop consumes `plan_spec` from the plan (lines 3844, 4183) and never re-selects a declaration
by transform-id first-match. `UnknownSynthetic` and `SyntheticDerived` are no longer combined
in one skip branch.

---

## 6. Honest report scope

- **Worker-executed gates** (this round): `cargo fmt --all -- --check`, `cargo test -p mida-pe
  --offline`, `python tools/test_gto_live_route_controller.py`, `git diff --check`, and the two
  static gates above.
- **Not independently re-run by an auditor this round**: `cargo test -p mida-cli
  --features gto-product-recovery` and `cargo test -p mida-cli --offline` were executed by the
  worker; exit codes are reported as worker evidence, not as independent verification.
- **Production Q0-C**: `build_patched_backing_slab_q0c` (called by `dump_process.rs:1546`).
- **Legacy/test-only**: `build_patched_backing_slab` retains the `if raws.len() == 1`
  shortcut; it is not production.
- `SyntheticDerived` is a legal bypass; `UnknownSynthetic` must fail closed immediately.

---

## 7. Gates

| Gate | Command | Result |
|------|---------|--------|
| fmt | `cargo fmt --all -- --check` | clean |
| mida-pe offline | `cargo test -p mida-pe --offline` (via `af3_pe_full.cmd`) | **762 passed / 0 failed** (751 prior + 11 new) |
| mida-cli features | `cargo test -p mida-cli --features gto-product-recovery` | exit 0 (worker) |
| mida-cli offline | `cargo test -p mida-cli --offline` | exit 0 (worker) |
| python controller | `python tools/test_gto_live_route_controller.py` | **36 passed / 0 failed** |
| whitespace | `git diff --check` | clean |
| static gate 1 | `git grep UnknownSynthetic \| RegionProvenance::SyntheticDerived` | no matches |
| static gate 2 | `git grep filter_map.*declared_size_reinit` | only pre-resolution Stage A |

### Preserved matrix
All AF1/AF2/AF3/AF3-AF1/AF3-AF2/AF3-AF2-AF1/AF3-AF2-AF1-AF1 tests remain green (762 total).
The label-table canonical qword `00 00 00 01 00 00 00 00` (`B+0x23 == 1`), child-link /
legitimate-containment success, all fail-closed negatives, declared-reinit (`RVA 0x141bf0,
old 0x8000 ± 0x2000, new 0x180, zero-filled`), and Route X fail-closed are unchanged.

---

## 8. Production diff

- `crates/pe/src/dumper/raw_slab_coherence.rs` — split `UnknownSynthetic` (immediate
  `RawChildMissing`) from `SyntheticDerived` (legal skip) in the pre-resolution; two-stage
  declared-reinit qualification (`ResolvedQ0cMode` with the verified spec); child loop consumes
  `plan_spec` (no relookup); the 11 new tests; the strengthened plan-consumption test.
- `crates/pe/src/dumper/heap_global_snapshot.rs`, `snapshot_manifest.rs` — carry the accepted
  prior rounds (unchanged this round).

**No `Cargo.toml` / `Cargo.lock` / source changes outside the three files above.**

---

## 9. Git live boundary

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

## 10. Constraints honored

- **No commit**; HEAD unchanged.
- **No live**, no protected sample, **no controller**, **no spawn**, **no candidate**, **no
  cold-start/promote**, **no Route Z R1**, **no Supervisor Production Integration**, **no
  second protected live**.
- Q0-C, `resolved_writes`, last-writer, binding, run-membership, slab-slice, digest, and strict
  identity are **not weakened**.
- `UnknownSynthetic` is not converted to `SyntheticDerived`, gets no raw fallback, and is not
  silently ignored.
- The child loop consumes the plan-qualified declaration spec; it never re-selects via
  transform-id first-match.
- **Stop here.** Await independent audit. No Supervisor Production Integration; no second
  protected live; no commit.
