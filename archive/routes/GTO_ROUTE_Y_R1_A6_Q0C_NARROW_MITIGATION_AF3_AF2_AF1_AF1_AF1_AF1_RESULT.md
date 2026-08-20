# GTO ROUTE Y R1 A6 — Q0-C Narrow Mitigation
## Work Order: AF3 AF2 AF1 AF1 AF1 AF1 — Unique Declared-Reinit Declaration Resolution and First-Match Elimination

**Target state:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF3_AF2_AF1_AF1_AF1_AF1_ReviewRequested`
**Baseline:** HEAD = `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (unchanged, no commit/push)
**Status:** COMPLETE — STOPPED, awaiting independent audit.

---

## 1. Audit finding being fixed (P1)

The prior pre-resolution selected a declared-reinit spec with **first-match** semantics:

```rust
let spec = tc
    .transform_ids
    .iter()
    .filter_map(|tid| declared_size_reinit(tid, tc.rva))
    .next();
```

This violates the "unique declaration" fail-closed requirement: a duplicated transform ID that hits the same declaration, or a future same-RVA declaration with multiple records, would silently pick the first instead of failing closed.

---

## 2. What was implemented

### Task 1 — Unique declaration resolver (shared, pure)

New shared functions in `crates/pe/src/dumper/raw_slab_coherence.rs`:

- `collect_declared_reinit_hits(transform_ids, child_rva) -> (usize, Vec<String>)`
  — counts EVERY hit and collects the matching transform IDs, sorted. Duplicate transform IDs that hit the same declaration are each counted as distinct evidence; they are **not** deduplicated and never collapse to "one unique declaration".
- `resolve_declared_size_reinit_spec(transform_ids, child_rva, child_capture_id, child_old_base, child_size) -> Result<Option<&'static DeclaredSizeReinit>, OverlayError>`
  - **0 hits** → `Ok(None)` (ordinary child, exact-identity lookup)
  - **exactly 1 hit** → `Ok(Some(spec))`
  - **> 1 hits** → `Err(OverlayError::TransformRunLedgerInvalid)` with a **typed, machine-parseable** reason:
    ```
    ambiguous declared size reinit: child rva {rva:#x} matched {n} transform id(s) [{ids}]
    ```
    containing the child RVA, every matching transform ID, the exact match count, and the `ambiguous declared size reinit` marker.
  - The identity context (`child_capture_id` / `child_old_base` / `child_size`) is carried only so the typed error is fully populated; the ambiguity decision depends solely on `transform_ids` + `child_rva`.
  - **No `.next()`** anywhere in the resolver or counting core.
  - **No sort-and-first-match**, **no dedup-to-hide-evidence**.

This reuses the existing `OverlayError::TransformRunLedgerInvalid` variant — the `PeError` conversion and report schema are unchanged (no new error variant, no schema degradation).

### Task 2 — Locked exact error ordering (pre-resolution)

The Q0-C pre-resolution loop now runs three stages per non-SyntheticDerived child, in this locked order:

1. **Declaration candidate resolution** (via `resolve_declared_size_reinit_spec`):
   - ambiguity → `TransformRunLedgerInvalid` (reason: `ambiguous declared size reinit` + match count)
   - reported BEFORE any raw-identity decision; never coerced to Ordinary, never silent-fallback.
2. **Raw full-identity resolution**:
   - 0 or >1 raw matches → `RawChildMissing`
   - only reached after the declaration candidate is unique (or ordinary).
3. **Declaration field qualification** (`validate_declared_size_reinit_fields`):
   - old size / new size / zero-fill / RVA / capture id invalid → `TransformRunLedgerInvalid` (reason names the field).
   - only reached after identity is unique.

Then, only after identity + declaration both succeed, ledger / binding / slab / byte / digest / replay / overlay errors are surfaced.

Preserved precedence at the top of the loop:
- `SyntheticDerived` → legal skip (no raw preimage; synthetic overlay path).
- `UnknownSynthetic` → immediate `RawChildMissing`, still the FIRST decision, before ledger/membership/binding.

### Task 3 — First-match static evidence eliminated

- `git grep -n "filter_map.*declared_size_reinit"` → **no match** in Q0-C code (exit 1). The only textual occurrence is inside a doc-comment describing the replacement, not code.
- Zero `.next()` calls in the production resolver / counting core.
- The child loop continues to consume `plan_spec` from `plan_entry.mode` (no re-selection via `transform_ids`).

### Task 4 — Six mandatory tests (all present and passing)

| # | Test | Locked behavior |
|---|------|-----------------|
| 1 | `q0c_duplicate_declared_reinit_spec_is_exact_ledger_invalid` | Two identical declared IDs, correct raw identity → EXACTLY `TransformRunLedgerInvalid`; reason contains `ambiguous declared size reinit` and `matched 2 transform id(s)`. |
| 2 | `q0c_duplicate_declared_spec_precedes_binding_and_ledger` | Declaration ambiguity + contradictory binding + orphan ledger run → EXACTLY `TransformRunLedgerInvalid` (ambiguity wins, not binding/ledger). |
| 3 | `q0c_declaration_unique_then_wrong_identity_is_raw_child_missing` | Unique declaration candidate + wrong raw full identity → EXACTLY `RawChildMissing`. |
| 4 | `q0c_declaration_unique_then_invalid_fields_is_ledger_invalid` | Unique declaration + unique identity + wrong new size → `TransformRunLedgerInvalid`, reason names the field. |
| 5 | `q0c_ordinary_no_declaration_hit_uses_exact_identity` | No declaration hit, size differs (identity otherwise identical) → `RawChildMissing`, proving ordinary mode does NOT ignore size. |
| 6 | `q0c_declaration_resolver_has_no_first_match` | Pure/static test on `collect_declared_reinit_hits` + `resolve_declared_size_reinit_spec`: 0 hits → None/count 0; 1 hit → Some/count 1; duplicate identical ID → count 2 (not deduplicated) and resolver fails closed (not first-match); reason records ambiguity + count. |

### Task 5 — Existing protections preserved (not weakened/deleted)

- `FullCaptureIdentity` 12 fields intact; `containing_parent_old_base`/`containing_parent_size` anchors unchanged.
- Source-evidence raw freeze intact (`RawChild` full identity; `raw_identity_matches_transformed`).
- Parent 12-field scrub consumption unchanged.
- `BindingIdentityInconsistent` / binding identity consistency unchanged.
- `identity_plan` `raw_index` (exact, single-match) unchanged.
- `UnknownSynthetic` precedence (first decision) preserved.
- `SyntheticDerived` legal bypass preserved.
- Declared old-size tolerance (0x8000 ± 0x2000), exact new size 0x180, zero-fill, RVA 0x141bf0 unchanged.
- raw C == slab S, unique slab coverage, digest, run-ledger shape/membership, `resolved_writes` conflict, last-writer prohibition, Route X/Route Y R0 fail-closed — all unchanged.

---

## 3. Gates (worker evidence — NOT independent audit)

All gates were run via native PowerShell `cmd.exe //c` (never Git Bash for controller/gate invocations) inside the MSVC `vcvars64.bat` developer environment (the Git `usr/bin/link.exe` shadows MSVC's linker in PATH; `vcvars64` fixes PATH/LIB/INCLUDE).

| Gate | Result |
|------|--------|
| `cargo fmt --all -- --check` | **clean** (exit 0) |
| `cargo test -p mida-pe --offline` | **768 passed / 0 failed** (unit) + 7 (pure_parse_serialize) + 2 (purity_boundary) + 3 (doctest, 1 ignored) — total 780 passed / 0 failed |
| `cargo test -p mida-cli --features gto-product-recovery` | **343 passed / 0 failed** (1 ignored) |
| `cargo test -p mida-cli --offline` | **341 passed / 0 failed** (1 ignored) |
| `python tools/test_gto_live_route_controller.py` | **36 passed / 0 failed / 36 total** (exit 0) |
| `git diff --check` | **clean** (exit 0; only benign CRLF notices) |

### Static gates (Task 3)
- `git grep -n "filter_map.*declared_size_reinit"` → no match in Q0-C code (PASS).
- `.next()` count in the production resolver/counting core = 0 (PASS).

---

## 4. Honesty notes

- **Worker gates ≠ independent audit.** All pass/fail above are worker-run evidence; they do not substitute for the independent audit.
- **Production Q0-C path:** `build_patched_backing_slab_q0c` — the only path that consumes `resolve_declared_size_reinit_spec` (line 3792) and the plan `ResolvedQ0cChild`/`ResolvedQ0cMode`. This is the Q0-C overlay boundary.
- **Legacy / test-only `build_patched_backing_slab`** (non-Q0C) is unchanged and does not use the new resolver; it remains distinct from the production Q0-C path.
- **`SyntheticDerived`** remains a legal bypass (no raw preimage, synthetic overlay); **`UnknownSynthetic`** remains an immediate fail-closed `RawChildMissing`, first decision.
- **Declaration ambiguity** error contract is the existing `TransformRunLedgerInvalid` with a machine-parseable `ambiguous declared size reinit` reason carrying RVA + matching IDs + count; no new error variant, no schema degradation.
- **No live / no spawn / no candidate / no cold-start / no promote / no Route Z R1 / no Supervisor Production Integration / no second protected live / no commit / no push.**

---

## 5. Work-tree boundary

- HEAD = `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (unchanged)
- tracked modified = 3 (the allowed set): `heap_global_snapshot.rs`, `raw_slab_coherence.rs`, `snapshot_manifest.rs`
- untracked source = 0; untracked docs = 35 (all `docs/GTO_ROUTE_Y_R1_A6_*`, incl. this report)
- `git diff --check` = PASS

**Report path:** `docs/GTO_ROUTE_Y_R1_A6_Q0C_NARROW_MITIGATION_AF3_AF2_AF1_AF1_AF1_AF1_RESULT.md` (untracked)

---

## 6. Completion

All five tasks implemented; all gates green (worker); all 6 mandatory tests present and passing; both static gates satisfied. Per the work order: **stop and await independent audit. Do not issue a second protected live; do not commit; do not enter Supervisor Production Integration.**
