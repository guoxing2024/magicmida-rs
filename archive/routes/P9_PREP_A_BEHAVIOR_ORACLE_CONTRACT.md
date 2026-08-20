# P9-Prep-A: Behavior Oracle Contract

> Batch: P9-Prep Final Acceptance Harness Closure (offline; no live authorization)
> Start HEAD: `1caae82d3c51575244c967d120d271ff7b9ad25e`
> Offline only. No real sample launched. No P9 live executed.

## Scope

Establishes a strict, independently verifiable, fail-closed case-bound behavior
oracle **contract** (`crates/acceptance/src/behavior_oracle_contract.rs`). This
is the **verifier side**: it never runs a probe, never opens a sample, and never
imports a producer crate.

## Contract (`mida.oreans-behavior-oracle-contract/v1`)

Fixed schema version + `deny_unknown_fields`. The evidence binds all of:

- `case_id` (must be exactly `origin_macro` or `lunlun_software`)
- `protected_input` identity, `candidate` identity
- `tool_revision`
- `runner_config_digest` (exactly 64 lowercase hex)
- `cli_identity`, `verifier_identity` (sha256 + version)
- `stimulus_plan` (content-hash identity), `execution` (execution_id +
  `emitted_at` + completion marker `done`)
- `reason` (non-empty)

Fail-closed rules enforced:

1. `stimuli` and `observables` are non-empty; every `id` is unique and every
   `value` non-empty.
2. An observable's verdict is **not** caller-supplied. The verifier recomputes it
   from the recorded `observed` value + a deterministic comparator (`Matching`,
   `NonEmpty`, `ExitCodeZero`, `MarkerPresent`). There is no `verdict` field on an
   observable or on the document.
3. The final verdict is recomputed here: every observable must be `Pass`; any
   `Missing`/`NotRun`/`Unknown`/`Malformed`/`Timeout`/`Partial`/`Mismatch` fails
   the contract. `reason` must be non-empty.
4. Protected and candidate must run the **same** canonical stimulus plan
   (`require_identical_stimulus_plan` / `stimulus_plan.sha256` registry). A plan
   referenced by evidence must be registered in the `StimulusPlanRegistry`.
5. Equivalence manufacture is rejected: a server/icon patch, forced visibility,
   skipped product code, semantic bypass, case-specific success override, or a
   sample-hash-based pass override is a hard error (no such field exists in the
   schema; a manufacture marker in `reason` is rejected).
6. Producer and verifier keep independent serde types and independent
   canonical/digest implementations; the verifier does not depend on any producer
   crate.

`verify_contract_bound` additionally binds the evidence to a caller-supplied
trusted `ExpectedBinding` (case_id, candidate, protected, tool_revision,
runner_config_digest) so identity-swap / digest-drift / revision-drift evidence
is rejected.

## Per-case stimulus/observable definitions — P9-live BLOCKER

The contract types and verifier are fully implemented offline, but the
case-specific **business** stimuli/observables **cannot be derived offline** and
are therefore recorded as a **P9-live blocker** (`BLOCKER_CASE_BUSINESS_DEFINITION`):

- `origin_macro` locked manifest exposes only a `legacy_oracle_candidate`
  (`use=regression_comparison_only`, `authority=historical_operator_report`) — a
  byte-comparison oracle, not a business behavior definition.
- `lunlun_software` locked manifest declares `oracle: none` — no business behavior
  definition at all.
- `docs/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md` lists "define the behavior
  oracle (specify protected-vs-unpacked stimuli and observables for each fixed
  sample)" as an outstanding item.
- `docs/VNEXT_BEHAVIORAL_PATH.md` defers the live behavioral gate.

To close: a named operator must define the business semantics per case (the
success/failure UI path, license-path markers, or product I/O the unpacked
candidate must reproduce under the same canonical stimulus plan), and/or a
controlled reconnaissance run under an authorized live budget must observe which
deterministic observables are in scope. This is **not** fabricated offline.
`offline_test_plan_origin` / `offline_test_plan_lunlun` register **contract-shaped
placeholder plans only** for hermetic offline testing; they are explicitly not a
claim about real product behavior.

## Attack tests (31 total)

Covers: empty stimuli; empty observables; duplicate id; empty id/value;
protected/candidate identity swap; candidate identity drift; runner-config digest
drift; tool revision drift; stimulus-plan drift/unregistered; candidate vs
protected using different plans; case-id drift; Missing/Timeout/Malformed/Partial/
Mismatch observable; caller-cannot-pass-a-verdict (no verdict field in schema);
single-failure-cannot-forge-overall-pass; partial/stale completion marker; unknown
schema; unknown field; empty reason; equivalence-manufacture marker; no sample-hash
pass-override path; honest-recompute candidate-hash identity attack.

Result: `cargo test -p mida-acceptance --lib behavior_oracle_contract --offline`
→ **31 passed, 0 failed**.
