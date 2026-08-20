# P9-Prep-B: Survival / Structural First-Class Evidence

> Batch: P9-Prep Final Acceptance Harness Closure (offline; no live authorization)
> Start HEAD: `1caae82d3c51575244c967d120d271ff7b9ad25e`
> Offline only. No real sample launched. No P9 live executed.

## Scope

Survival and structural evidence are made **first-class, case-bound,
independently verifiable artifacts** in
`crates/acceptance/src/survival_structural_evidence.rs`. The gate's
`survival` / `structural` bool must be **derived** from one of these artifacts by
this verifier — a caller cannot set it directly (there is no bool field in the
schema).

## `OreansEvidenceRef.artifact_sha256` semantic audit (pinned)

The existing gate contract
(`crates/acceptance/src/oreans_gate.rs::OreansEvidenceRef::validate_for_candidate`)
requires `artifact_sha256 == candidate.sha256`. That is the reference pointing at
the **candidate artifact** the prerequisite evidence is bound to — it is NOT the
hash of the evidence JSON document. That existing contract is **preserved
unchanged**. Because an evidence document needs its own integrity hash, this
module adds a **separately named** `artifact_self_sha256` field: the sealed hash
of the document itself (computed over the canonical document **excluding** that
field, to avoid self-reference). The two fields are independent and both
verified; a producer that mistakes the evidence report hash for the candidate
hash fails the sealed self-hash check. Documented as
`ARTIFACT_SHA256_SEMANTIC_PIN`.

## Survival evidence (`mida.oreans-survival-evidence/v1`)

Records: `case_id` + both identities, `process` (creation observation, PID,
start/end time, observation window), `exit` (exit code / signal / timeout /
forced-termination), `survival_verdict`, runner/tool/verifier identities,
`tool_revision`, `candidate_digest` (must equal `candidate.sha256`), completion
marker, non-empty `reason`, and the sealed `artifact_self_sha256`. Survival Pass
is derived as a clean observed exit within the window; it is independent of
behavior equivalence.

## Structural evidence (`mida.oreans-structural-evidence/v1`)

Records: `case_id`, candidate identity, `bundle_validation` (valid + complete +
`members_sha256` + `manifest_sha256` + reasons — from the independent bundle
validator), per-domain results (OEP / IAT / TLS+reloc / section) each with a
verdict and non-empty reason, runner/tool/verifier identities, `tool_revision`,
completion marker, non-empty `reason`, and the sealed `artifact_self_sha256`.
The structural bool is derived from the bundle validator + every domain passing;
it is never derived from file existence.

## Verification

`verify_survival_evidence` / `verify_structural_evidence` take an
`ExpectedEvidenceBinding` (trusted runner/tool/verifier identities + optional
sealed bundle hashes), so identity swap, chain-identity drift, bundle-hash drift
are rejected. Both verify the sealed `artifact_self_sha256`.

## Attack tests (21 total)

Covers: empty producer/summary/reason; wrong candidate SHA; evidence report hash
mistaken for candidate hash; stale/tampered artifact (self-hash mismatch);
identity swap; runner-digest drift; structural bundle-hash drift; structural
bundle invalid/incomplete; survival timeout / forced termination; structural any
domain Open/Fail; empty structural domains; unknown schema; unknown field; no
caller bool field; honest-recompute self-hash identity attack. Also documents
that survival Pass does not imply behavior Pass.

Result: `cargo test -p mida-acceptance --lib survival_structural_evidence
--offline` → **21 passed, 0 failed**; full acceptance lib suite 129 passed.
