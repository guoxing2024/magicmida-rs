# Route X R0 Offline Work Order

**Title:** Raw-Coherence Participant-Set and Transform Ledger Identity Closure
**Status:** RouteX_R0_Authorized
**Date:** 2026-08-10
**Baseline:** 4491b5b44bf73f44f458a72b7af8cb0de8e5a628 on oreans/two-sample-mainline
**Execution class:** OFFLINE ONLY
**Live budget:** 0 route attempts / 0 protected spawns / 0 candidates / 0 reruns / 0 cold-starts

## 1. Binding decision

Route W is frozen at RouteW_R1_CandidateNotReady. Its one armed attempt was valid and may not be rerun or renamed as a pass. Route X is a new route letter. This order authorizes only Route X R0 offline implementation, tests, documentation, and one reviewed commit. It does not authorize Route X R1.

The untracked historical report docs/GTO_ROUTE_W_R1_LIVE_RESULT.md is frozen evidence and must not be silently edited, deleted, or included in the Route X R0 commit. It may be archived outside the repository with hash/path evidence, or remain untracked.

## 2. Authoritative W R1 facts

The W R1 production failure is:

- stage: raw_slab_overlay
- error: TransformRunLedgerInvalid
- run index: 3464
- transform: scrub_uncaptured_heap_pointers
- child old base: 0x140149d50
- child size: 0x1950
- child offset: 0x28c
- write length: 0x2
- defect: child_capture_id is empty

The object is not speculative: live evidence identifies it as the gscript image-inline body at RVA 0x149d50, live VA 0x140149d50, size 6480 (0x1950).

Source inspection establishes the participant-set split:

1. The image-inline constructor sets is_image_inline=true and uses default CaptureExtentEvidence, leaving capture_id empty.
2. validate_raw_coherence_capture_identities explicitly skips image-inline snapshots.
3. raw_children_from_capture explicitly skips image-inline snapshots.
4. scrub_uncaptured_heap_pointers mutates every heap-global snapshot, including image-inline snapshots.
5. diff_transform_write_runs diffs every zipped before/after heap-global pair and copies a.extent_evidence.capture_id into the raw-overlay run ledger without applying the raw-coherence participant predicate.

Therefore the root cause is a production participant-set invariant violation: an object excluded from raw identity binding and raw-child capture still enters the raw-overlay transform write-run ledger.

## 3. Required implementation

### X0-A — One canonical raw-coherence participant predicate (P0)

Introduce one production predicate/helper defining whether a HeapGlobalSnapshot participates in raw capture, authoritative seeding, raw-overlay transform provenance, and overlay reconciliation.

At minimum it must consistently exclude:

- is_heap_handle snapshots;
- is_image_inline snapshots;
- empty snapshots;
- RegionProvenance::SyntheticDerived snapshots.

Use the same predicate in all relevant production paths, including identity validation, raw-child construction, transform-input seeding/binding, transform write-run recording, and pre-overlay membership validation. No copied ad-hoc condition sets are accepted. Container participation remains explicit and unchanged.

### X0-B — Raw-ledger recording by participant identity, not positional zip (P0)

The raw-overlay write-run ledger must be constructed only from canonical raw-coherence participants.

Do not merely add an is_image_inline special-case at run 3464. Recording must:

- match before/after participants by stable child identity, not only vector position;
- reject duplicate or ambiguous participant identities;
- reject participant-set changes across one transform unless the change is an explicitly supported synthetic/non-raw operation;
- preserve transform execution order and overlapping-writer replay order;
- retain existing byte/run digests and before/after byte evidence.

A non-raw snapshot may still be mutated by an existing transform if that is current business behavior, but it must not be represented as a raw-slab overlay child. Existing child-level transform evidence for such a mutation must not be silently destroyed.

### X0-C — Image-inline semantic decision is fixed (P0)

For Route X R0, gscript image-inline is an image-backed, non-raw-coherence participant. Do not:

- invent a fake capture_id such as unknown;
- reclassify it as a heap slab child merely to satisfy the validator;
- seed it from an unrelated authoritative heap slab;
- disable or weaken the global run-ledger validator.

The exact W R1 image-inline scrub write may remain part of non-raw or child-level transform evidence, but it must not enter TransformRunLedger, whose consumer is raw slab overlay.

### X0-D — Pre-overlay participant and binding closure (P0)

Before byte replay, validate that every raw transform write run resolves to exactly one raw child and that the child belongs to the canonical participant set. Preserve existing malformed-run fail-closed checks.

Add a precise diagnostic for participant or binding mismatch; do not misreport it as byte drift or synthesize child offset or bytes. The diagnostic must identify run index, transform id, base, size, capture id, and mismatch reason.

### X0-E — Controller stage evidence parser closure (P1)

Fix tools/gto_live_route_controller.py::_sample_last_stage() so Rust tracing output with ANSI escapes and quoted fields is parsed correctly. W R1 uses fields of the form stage="raw_slab_overlay" event="error".

Required behavior:

- strip or ignore ANSI escape sequences before field parsing;
- accept quoted and unquoted field values;
- preserve best-effort recording-only semantics;
- parse the final W-style line as raw_slab_overlay / error;
- never use parser failure or silence as an early-kill condition.

This is an evidence defect, not permission to alter pipeline semantics or timeout policy.

### X0-F — Exact regression and invariant tests (P0/P1)

Add, at minimum, tests proving:

1. route_x_r0_exact_140149d50_geometry: image-inline RVA/base/size geometry reproduces the W R1 class and does not create a raw write run.
2. route_x_r0_image_inline_is_non_raw_participant: identity gate, raw-child capture, seeding, and ledger recording agree.
3. route_x_r0_scrub_raw_runs_never_have_empty_capture_id: real scrub_uncaptured_heap_pointers through the production recorder.
4. route_x_r0_identity_gate_and_run_ledger_share_participant_set.
5. route_x_r0_non_raw_mutation_keeps_child_level_evidence.
6. route_x_r0_malformed_empty_raw_id_still_fails_closed: a genuinely raw malformed run remains rejected.
7. route_x_r0_participant_set_change_fails_closed.
8. route_x_r0_full_pipeline_reaches_overlay_past_w_run_3464: production-order offline pipeline completes overlay for the exact mixed raw plus image-inline case.
9. route_x_r0_stage_parser_handles_ansi_quoted_fields.
10. route_x_r0_stage_parser_reports_raw_slab_overlay_error.

Tests must call the production predicate, production transform recorder, real scrub transform, and production overlay validator. Hand-constructed ledgers alone are insufficient for the positive closure test.

## 4. Mandatory gates

Run and report exact commands and counts:

- cargo fmt --all -- --check: exit 0;
- cargo test -p mida-pe --offline: no regression from 599/0 baseline plus X tests;
- cargo test -p mida-cli --features gto-product-recovery --offline: no regression from 298/0/1 baseline;
- cargo test -p mida-cli --offline: no regression from 296/0/1 baseline;
- controller tests: no regression from 34/0 plus X parser tests;
- git diff --check: exit 0;
- no new compiler warnings attributable to Route X.

Also report targeted counts for every route_x_r0 test.

## 5. Authorized write set

Expected authorized files:

- crates/pe/src/dumper/heap_global_snapshot.rs
- crates/pe/src/dumper/raw_slab_coherence.rs
- crates/pe/src/dumper/dump_process.rs
- crates/pe/src/dumper/snapshot_manifest.rs only if required evidence schema changes
- tools/gto_live_route_controller.py
- tools/test_gto_live_route_controller.py
- docs/GTO_ROUTE_X_R0_OFFLINE_WORK_ORDER.md
- docs/GTO_ROUTE_X_R0_OFFLINE_RESULT.md

Any additional file requires explicit justification in the delivery report and separate audit approval before commit.

## 6. Forbidden actions

During Route X R0:

- no protected sample execution;
- no live controller invocation;
- no process spawn against the protected debuggee;
- no candidate generation or manual candidate patching;
- no W R1 rerun, W R2, or reuse of W authorization;
- no weakening or removal of fail-closed identity, binding, digest, replay-chain, or overlay checks;
- no changes to acceptance, TrustToken, vault, resolver, firewall, or protected sample artifacts;
- no unrelated optimization of the 286-second transform_input_seed stage. Performance work is a separate route unless it remains a live blocker after correctness closure.

## 7. Delivery state and commit rule

The implementer may initially report only RouteX_R0_ReviewRequested.

The report must include:

- root-cause-to-code mapping;
- changed files and diff stat;
- participant-set definition and all production call sites using it;
- exact W geometry test evidence;
- all gate counts;
- git status --short and git diff --check;
- explicit statement of 0 live / 0 spawn / 0 candidate / 0 rerun / 0 cold-start;
- explicit confirmation that the W R1 report was excluded.

Commit is denied until audit acceptance. After acceptance, one Route X R0 commit may be authorized. Even after that commit, Route X R1 remains denied until a separate written single-run authorization.
