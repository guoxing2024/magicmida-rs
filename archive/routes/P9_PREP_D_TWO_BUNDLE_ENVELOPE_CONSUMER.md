# P9-Prep-D: Two-Bundle Envelope Consumer

> Batch: P9-Prep Final Acceptance Harness Closure (offline; no live authorization)
> Start HEAD: `1caae82d3c51575244c967d120d271ff7b9ad25e`
> Offline only. No real sample launched. No P9 live executed.

## Scope

Closes the two-bundle consumer boundary explicitly left open by P8.1.1.1-B.
The production two-bundle envelope consumer (`evaluate_bundle_gate`) now has an
injectable locked-manifest core so it can be exercised hermetically, and the
test suite assembles **two genuinely independent production bundles** and feeds
them to the real consumer.

## Two genuinely independent production bundles

`crates/cli/src/unpacker/production_e2e.rs` (`two_independent_production_bundles_envelope_consumer_e2e`):
`build_run_for("origin_macro")` and `build_run_for("lunlun_software")` each
assemble a fully independent bundle through the real production chain:
five sidecar producers → transform manifest → PE evidence → atomic
`assemble_evidence_bundle` (a distinct `RunEvidenceContext` per case) →
independent `validate_evidence_bundle`. Each bundle is a separate Run with its
own temp dir, candidate, sidecars, and sealed hashes. There is no clone of one
bundle relabeled for the other.

## Consumer (keyed by case_id)

`evaluate_bundle_gate` / `evaluate_bundle_gate_with_manifest` (acceptance
`bundle_gate.rs`) is the real production two-bundle envelope consumer. It:

- validates every envelope via `validate_evidence_bundle` (fail-closed);
- resolves the locked manifest by `case_id` (keyed mapping, not array position);
- checks `protected_input` against the locked manifest;
- re-parses every sidecar into the gate's structured types;
- evaluates the v8 two-sample gate.

## Hermetic locked-manifest seam (P9-Prep-D #8)

The existing `evaluate_bundle_gate` hard-codes `locked_manifest` (real sample
SHAs). Because a hermetic test cannot produce a bundle whose `protected_input`
matches a real Vault sample, `evaluate_bundle_gate_with_manifest` is a pure core
that takes a locked-manifest **provider** (test-fixture dependency injection).
`evaluate_bundle_gate` is the production wrapper that injects the real
`locked_manifest`. The injected provider returns a manifest whose
`protected_input` matches the synthetic bundles. This is never a production
bypass — no CLI flag, env var, hidden parameter, or verifier-path override was
added.

## Claim boundary

This is a **two-independent-production-assembled-synthetic-bundles**
envelope-consumer E2E. It is **not** a live double-sample result, and it does
**not** prove real behavior equivalence or a real 10/10. Those remain pinned for
the authorized live run (P9).

## Attack tests (acceptance `tests/bundle_gate.rs`, 8 new)

Covers: synthetic-provider acceptance; missing case via provider; duplicate case;
bundle swap (relabeled case_ids); bundle hash drift (member byte tampered without
re-seal → InvalidBundle); runner-config digest drift (bundle-level; structural
validity retained — binding lives in the P9-Prep-A/C contracts); one side unknown
bundle schema; one side partial (missing member); honest-recompute inner identity
attack (sidecar candidate swapped + all outer hashes recomputed → validator
rejects). Plus mida-cli positive/negative (missing case, case-order-swap keyed,
protected-digest mismatch).

Result: `cargo test -p mida-acceptance --test bundle_gate` → 16 passed
(8 new two-bundle consumer); `cargo test -p mida-cli --lib production_e2e`
→ 6 passed (4 two-bundle). Full acceptance lib+integration 331 passed;
mida-cli lib 158 passed. 0 warnings.
