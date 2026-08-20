# P9-RESET-B: Minimal Contract / Document Correction (SEMANTICS_B)

> Decision: **SEMANTICS_B_PROTECTED_VS_CANDIDATE** (from P9-RESET-A).
> Minimal offline contract/document correction only. No sample started, no slot
> consumed, validation_summary.json untouched, P7 roots untouched.

## Scope

Per P9-RESET-B §5 (conclusion B), collapse all "baseline A/B" wording into
protected-vs-candidate, and confirm the budget/ledger/consumer carry no
baseline-revision semantics.

## 1. P9 does not validate a historical baseline revision

- The P9 gate accepts a **candidate** (unpacked output) bound to a **protected
  input** (reference) per observation. There is no baseline-revision acceptance
  object.
- The historical P7-R2 `baseline` (worktree @ `858f66e`) and `candidate`
  (worktree @ `c8258b3`) are two **code-revision** toolchains unpacking the
  SAME protected sample to verify a fix (IAT slot-0). They are not P9 inputs.

## 2. P7-R2 baseline results are historical regression material only

- `docs/P9_PREP_E_LIVE_EXECUTION_BUDGET_PLAN.md` §2 now states P9 semantics are
  SEMANTICS_B, that the P7-R2 baseline is not a live input, is never auto-counted
  into a new 10/10, and the 46/22 budget contains **no baseline-revision process**.

## 3. Uniform naming

- "protected sample" = reference behavior (and the unpack input).
- "candidate" = the live unpacked output (final candidate + each replay attempt's
  reproducible candidate).
- "10/10" = candidate isolated replay (10 same-config reproducible runs).
- "behavior" = protected vs candidate under the **same** canonical stimulus plan.
- Historical P7-R2 toolchain-revision comparison is described only as a
  regression cross-check, never as an acceptance side.

## 4. No misleading baseline/candidate titles

- The ScyllaHide reference staging directory was renamed from
  `<root>\scyllahide\baseline\` to `<root>\scyllahide\reference\` (the candidate
  staging remains `<root>\scyllahide\candidate\`), so the protected-reference side
  is not confused with a toolchain baseline. File SHAs unchanged by the rename.
- `docs/P9_LIVE_0_REVISION_SCYLLAHIDE_SEAL.md` updated to the new canonical paths.
- `docs/P9_LIVE_AUTHORIZATION_MANIFEST.md` already states
  `baseline/protected revision = NOT_USED`.

## 5. Restated semantics

- protected sample = reference behavior.
- candidate = live unpack output.
- 10/10 = candidate isolated replay.
- behavior = protected vs candidate under the same stimulus plan.

## 6. Budget confirmation

The 46-sample-process / 22-unpack-slot budget covers:
- protected reference behavior (1/case),
- candidate final live unpack (1/case),
- candidate behavior (1/case),
- candidate isolated replay 10 (10 protected unpack + 10 candidate behavior per
  case).
It contains **no baseline-revision process**. Confirmed in `P9_PREP_E` §2.

## 7. Ledger / consumer baseline semantics

- `isolated_replay_ledger.rs` (P9-Prep-C): binds candidate digest, runner config,
  CLI/verifier/tool identities; no baseline-revision field. Consistent with B.
- `bundle_gate.rs` two-bundle consumer (P9-Prep-D): two bundles are
  origin_macro + lunlun_software (protected-vs-candidate per case); no
  baseline-side bundle. Consistent with B.
- `behavior_oracle_contract.rs` (P9-Prep-A): protected vs candidate under the
  same stimulus plan. Consistent with B.
- No minimal code change was required; the wording was already B-consistent.
  Only the ScyllaHide staging directory name and the P9-Prep-E baseline section
  were corrected (document/offline contract only).

## Compliance

- 0 live process / 0 slot.
- validation_summary.json unchanged (blob `cf72b7a`).
- P7 roots untouched.
- No CLI flag / env / PATH / verifier bypass added.
