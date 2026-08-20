# Route Y R1 A6 — Q0-C Narrow Mitigation AF3 AF2 AF1 — RESULT
## (No-Shortcut Full-Identity Resolution, Parent Identity Consumption, and Identity-Owner Unification)

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF3_AF2_AF1_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged — no commit)

This is the **AF3 AF2 AF1** work order, issued by the AF3 AF2 audit rejection
(`RouteY_R1_A6_Q0C_AF3_AF2_FullIdentityCoreAccepted` →
`RouteY_R1_A6_Q0C_NarrowMitigation_AF3_AF2_NeedsAF1`). The audit accepted the AF3 AF2
`FullCaptureIdentity` core (raw→binding→Q0-C identity chain), but blocked the overall AF3
on three residual gaps that AF3 AF2 AF1 closes:

- **P1-1** — parent identity (方案A): `CurrentScrubIdentity` did not carry / compare the
  parent source evidence, so `matches_parent` consumed only the old 6 fields;
- **P1-2** — production seeding (`find_raw_child`) still resolved by partial identity +
  raw bytes and took the sort-then-first candidate;
- **P1-3** — Q0-C still had a single-candidate shortcut (`if raws.len() == 1 { raws[0] }`)
  that skipped full-identity verification before slab/byte/binding stages;
- **P1-4** — `RawChild.source_parent_old_base` remained a second, un-unified parent field;
- **P2** — `TransformPreimageBinding` still carried two identity sources (legacy tuple +
  `identity`).

All five are closed. No live, no protected sample, no controller, no spawn, no candidate, no
cold-start/promote, no Route Z R1, no Supervisor Production Integration, no commit. All
pre-existing AF1 / AF2R1 / AF3 / AF3-AF1 / AF3-AF2 tests are preserved.

---

## 1. P1-1 — parent identity 方案A: full source-evidence consumption

`CurrentScrubIdentity` now carries and compares the **full** parent identity (12 fields):

```rust
pub(crate) struct CurrentScrubIdentity {
    kind, capture_id, extent_kind, capture_path, old_base, size,
    source_root_rva, source_slot_offset, probe_requested_size,
    was_interior, containing_parent_old_base, containing_parent_size,
}
```

- `CurrentScrubIdentity::heap_global(g)` populates every field from the live snapshot's
  `extent_evidence` — never a truncated 6-field projection.
- `matches_parent(&parent: &CaptureIdentity)` compares **all 12** fields; a single source-
  evidence / containing-parent difference denies authorization.
- `CaptureIdentity` gained `containing_parent_old_base` / `containing_parent_size` and its
  `from_heap_global` fills them, so the recorded parent identity is complete too.
- Container identity uses fixed defaults (`None`/`0`/`false`) and `matches_parent` requires
  `kind == HeapGlobal`, so a container never matches a heap-global parent.

### Parent per-field consumption matrix (P1-1)

| parent field | compared in `matches_parent` | denied + actually scrubbed |
|---|---|---|
| kind | ✓ | ✓ (container vs heap-global) |
| capture_id | ✓ | ✓ |
| extent_kind | ✓ | ✓ |
| capture_path | ✓ | ✓ |
| old_base | ✓ | ✓ |
| size | ✓ | ✓ |
| source_root_rva | ✓ | ✓ (new test 1) |
| source_slot_offset | ✓ | ✓ (new test 2) |
| probe_requested_size | ✓ | ✓ (new test 3) |
| was_interior | ✓ | ✓ (new test 4) |
| containing_parent_old_base | ✓ | ✓ (new test 5) |
| containing_parent_size | ✓ | ✓ (new test 6) |

Each of the 6 new tests builds a protection whose parent carries full source evidence, flips
**one** field on the current scrub identity, asserts `protection_authorizes_qword` is false,
**and** runs `scrub_buffer_external_ptrs` asserting the dangling qword is actually zeroed
(not merely `matches_parent` false).

---

## 2. P1-2 — seeding uses full-identity unique resolution

`find_raw_child` was rewritten to accept `&FullCaptureIdentity` and resolve by **complete
structural identity**:

- filter: `FullCaptureIdentity::from_raw_child(child) == identity`;
- require **exactly one** match: `[single] => Ok`, `[]` / `>1` → `RawChildMissing`;
- no `sort_by_key(...).next()`, no raw-bytes identity selection, no slab-based selection;
- an empty `capture_id` is **not** a wildcard (compared structurally).

Both production call sites in `seed_transform_inputs_from_authoritative_slab` now pass the
transformed snapshot's full identity (`from_heap_global(global)` / `from_container(container)`),
so raw-child resolution precedes any byte/digest comparison.

New tests 7–11: `seed_same_bytes_different_source_identity_selects_exact`,
`seed_same_bytes_duplicate_full_identity_fails_closed`,
`seed_single_candidate_wrong_source_identity_fails_closed`,
`seed_empty_capture_id_is_not_wildcard`,
`seed_identity_resolution_precedes_byte_drift`.

---

## 3. P1-3 — Q0-C removes the single-candidate shortcut

`build_patched_backing_slab_q0c` now resolves the raw child by **full identity first**,
for both normal and declared-reinit children:

```rust
// Before slab coverage, child_size, raw bytes, digest, or binding:
let full_matches: Vec<&&RawChild> = raws.iter()
    .filter(|r| { let ri = FullCaptureIdentity::from_raw_child(r);
        if declared_reinit { /* every field EXCEPT size */ }
        else { &ri == child_identity } })
    .collect();
let raw = match full_matches.as_slice() {
    [single] => *single,
    _ => return Err(OverlayError::RawChildMissing { .. }),
};
```

- For a **declared** size reinit, size is ignored (the raw child's old size is used) but
  every other field must match exactly — the raw old size is taken only after the unique
  full-identity match.
- For a **normal** child, the full identity (including size) must equal the transformed
  identity exactly.
- Identity resolution now runs **before** `covering_slab_for_child`, child-size coverage,
  raw-byte reads, digests, and the binding check. A wrong source identity therefore
  surfaces as `RawChildMissing`, never as `RawCaptureDrift` / `RawChildOutsideSlab` /
  `ProbeCoverageMissing`.

New tests 12–16: `q0c_single_raw_wrong_source_identity_is_raw_child_missing`,
`q0c_single_raw_wrong_identity_precedes_slab_failure`,
`q0c_single_raw_wrong_identity_precedes_byte_drift`,
`q0c_duplicate_full_identity_fails_closed`,
`q0c_declared_reinit_single_raw_source_drift_fails_before_size_handling`.

---

## 4. P1-4 — unified parent semantics (方案A)

`RawChild.source_parent_old_base` is **deleted**. The only parent anchor is
`containing_parent_old_base` (+ `containing_parent_size`), which `FullCaptureIdentity`
carries and every stage compares. The production constructor
(`raw_children_from_capture`) no longer copies `containing_parent_old_base` into a second
field; the two can never diverge because the second field no longer exists.

New test 17 `source_parent_and_containing_parent_cannot_diverge` is the compile-layer proof:
`RawChild` has no `source_parent_old_base`, and `FullCaptureIdentity::from_raw_child`
round-trips the single `containing_parent_*` anchor from the production raw child.

---

## 5. P2 — binding single identity owner

`TransformPreimageBinding` now exposes a single constructor `TransformPreimageBinding::new(identity, slab_evidence…)` that derives the legacy field tuple **from** `identity`, plus
`validate_identity_consistency()` which verifies every overlapping legacy field
(`child_kind`, `capture_id`, `child_old_base`, `child_size`, `extent_kind`) equals `identity`.
`build_patched_backing_slab_q0c` calls `validate_identity_consistency()` on **every** binding
before any binding is resolved or overlaid; a contradictory binding fails closed with the
new typed error `OverlayError::BindingIdentityInconsistent`. Production seeding uses the
constructor, so a seeded binding cannot be constructed self-inconsistent.

New test 18 `binding_legacy_fields_cannot_diverge_from_full_identity` flips each legacy field
and asserts the Q0-C entry rejects with `BindingIdentityInconsistent`.

---

## 6. The 18 mandatory AF3 AF2 AF1 tests

All 18 present and green:

| # | Test | Proves |
|---|------|--------|
| 1 | `parent_source_root_rva_mismatch_not_protected` | parent source_root_rva flip denied + actually scrubbed |
| 2 | `parent_source_slot_offset_mismatch_not_protected` | parent source_slot_offset flip denied + scrubbed |
| 3 | `parent_probe_requested_size_mismatch_not_protected` | parent probe flip denied + scrubbed |
| 4 | `parent_was_interior_mismatch_not_protected` | parent was_interior flip denied + scrubbed |
| 5 | `parent_containing_parent_base_mismatch_not_protected` | parent containing base flip denied + scrubbed |
| 6 | `parent_containing_parent_size_mismatch_not_protected` | parent containing size flip denied + scrubbed |
| 7 | `seed_same_bytes_different_source_identity_selects_exact` | seeding selects exact full identity, not first-match |
| 8 | `seed_same_bytes_duplicate_full_identity_fails_closed` | duplicate full identity fails closed |
| 9 | `seed_single_candidate_wrong_source_identity_fails_closed` | single wrong-source candidate fails closed |
| 10 | `seed_empty_capture_id_is_not_wildcard` | empty capture_id is not a wildcard |
| 11 | `seed_identity_resolution_precedes_byte_drift` | identity error precedes byte drift |
| 12 | `q0c_single_raw_wrong_source_identity_is_raw_child_missing` | single wrong source → RawChildMissing |
| 13 | `q0c_single_raw_wrong_identity_precedes_slab_failure` | identity precedes slab failure |
| 14 | `q0c_single_raw_wrong_identity_precedes_byte_drift` | identity precedes byte drift |
| 15 | `q0c_duplicate_full_identity_fails_closed` | duplicate full identity fails closed at Q0-C |
| 16 | `q0c_declared_reinit_single_raw_source_drift_fails_before_size_handling` | declared-reinit source drift fails before size handling |
| 17 | `source_parent_and_containing_parent_cannot_diverge` | `source_parent_old_base` removed (compile proof) |
| 18 | `binding_legacy_fields_cannot_diverge_from_full_identity` | contradictory binding fails at Q0-C entry |

---

## 7. Gates (all green)

| Gate | Command | Result |
|------|---------|--------|
| fmt | `cargo fmt --all -- --check` | clean |
| mida-pe offline | `cargo test -p mida-pe --offline` (via `af3_pe_full.cmd`) | **743 passed / 0 failed** (725 prior + 18 new) |
| mida-cli features | `cargo test -p mida-cli --features gto-product-recovery` (via `af3_cli_gates.cmd`) | exit 0 |
| mida-cli offline | `cargo test -p mida-cli --offline` (via `af3_cli_gates.cmd`) | exit 0 |
| python controller | `python tools/test_gto_live_route_controller.py` | **36 passed / 0 failed** |
| whitespace | `git diff --check` | clean |

### Preserved matrix
All AF1 / AF2R1 / AF3 / AF3-AF1 / AF3-AF2 tests remain green (743 total). The label-table
canonical qword `00 00 00 01 00 00 00 00` (`B+0x23 == 1`), child-link/legitimate-containment
success, all fail-closed negatives, declared-reinit (`RVA 0x141bf0, old 0x8000, new 0x180,
zero-filled`), and Route X fail-closed are unchanged.

---

## 8. Production diff

- `crates/pe/src/dumper/heap_global_snapshot.rs` — `CurrentScrubIdentity` full identity
  (12 fields), `matches_parent` 12-field compare, `CaptureIdentity` containing-parent fields,
  `CaptureIdentity::from_heap_global` completeness.
- `crates/pe/src/dumper/raw_slab_coherence.rs` — `find_raw_child` full-identity unique
  resolution, Q0-C no-shortcut full-identity resolution (normal + declared), removal of
  `RawChild.source_parent_old_base`, `TransformPreimageBinding::new` + `validate_identity_consistency`,
  new `OverlayError::BindingIdentityInconsistent`, seeding uses the constructor, the 18 tests.
- `crates/pe/src/dumper/snapshot_manifest.rs` — unchanged this round (carries the AF3 AF2
  binding-identity literals from the prior accepted round).

**No `Cargo.toml` / `Cargo.lock` / source changes outside the three files above.**

---

## 9. Git live boundary

```
HEAD = f386b49af8f547a16f3d107dc6e80c02ea6e4403   (unchanged, no commit)

tracked modified:
- crates/pe/src/dumper/heap_global_snapshot.rs
- crates/pe/src/dumper/raw_slab_coherence.rs
- crates/pe/src/dumper/snapshot_manifest.rs

git diff --check: PASS
```

Docs remain untracked; A6 frozen evidence untouched.

---

## 10. Constraints honored

- **No commit**; HEAD unchanged.
- **No live**, no protected sample, **no controller**, **no spawn**, **no candidate**, **no
  cold-start/promote**, **no Route Z R1**, **no Supervisor Production Integration**, **no
  second protected live**.
- Q0-C, `resolved_writes`, last-writer, binding, run-membership, slab-slice, digest, and
  strict identity are **not weakened**.
- Source-evidence fields were **not removed** to satisfy the work order (only the genuinely
  duplicate `source_parent_old_base` was unified into `containing_parent_old_base`).
- No first-match or raw-byte fallback remains in the production seeding or Q0-C resolution.
- **Stop here.** No Supervisor Production Integration; no second protected live; no commit.
