# P6.3 Launch Attestation Closure

Status: implemented (P6.3 + P6.3.1 on `oreans/two-sample-mainline`).

Scope: offline engineering hardening only. No real sample was opened or
started; `validation_summary.json` remains `open`.

## Problem

P6.2's launch boundary trusted a `ready` status in `preflight.json` plus
digest equality. The P6.3 review showed four closure gaps:

1. **Detached config identity** — the envelope was built from a frozen
   policy, not the configuration the run would actually apply; in
   particular the Origin Macro pure-rebuild default (operator decision D3)
   was outside the config identity, so an envelope staged as
   `pure_rebuild=false` could silently authorize a run that resolved to
   `true`.
2. **Hand-written authorization** — a fabricated `{"status":"ready"}`
   report with a matching digest chain passed the gate; input/output/CLI/
   config identities were never re-checked at launch.
3. **Envelope overwrite** — an existing stale/tampered envelope was
   silently replaced by the next staging run.
4. **No production evidence chain** — `assemble_evidence_bundle` accepted a
   caller-supplied digest and had no production call site.

## Design

### P6.3-A actual run config binding (`crates/cli/src/run_spec.rs`)

`runner_config_from_unpack_args` builds the canonical runner config from the
parsed `/unpack` arguments: profile (features entry), OEP policy, container
restore, shrink, data sections, the RESOLVED pure-rebuild value (Origin D3
default included), capture-policy digest (SHA-256 of the policy file bytes),
debugger backend, timeout/isolation, tool revision and CLI binary SHA-256.
`frozen_run_policy(input)` is the P7 fixed-mode expectation with the Origin
default resolved per input; `policy_matches` fails closed on any divergence.

### P6.3-B launch attestation (`crates/cli/src/runner_preflight.rs`)

`attest_ready_before_launch` re-verifies the FULL run context before any
sample process can be created:

- envelope `$schema` + `schema_version` strictly validated;
- actual run-config digest == envelope digest;
- current CLI binary SHA-256 == envelope pinned identity;
- current input identity matches EXACTLY ONE preflight case identity
  (cross-case / third-input reuse refused);
- the independent acceptance verifier is RE-RUN against the recorded
  runner context with the current input/output for the target case — a
  hand-written `ready` JSON is not an authorization credential;
- the fresh report must be ready with exactly {origin_macro,
  lunlun_software}, every case identity_ok;
- target-case input identity unchanged since the staged report;
- current output canonical path == staged candidate (hard links and
  canonical aliases are refused);
- the output must not alias the protected input.

On success it returns the single-use `RunEvidenceContext` (case id, tool
revision, envelope digest, canonical input/output, CLI identity).

### P6.3-C envelope fail-closed reuse

`envelope_reuse_policy` allows first creation only when the file is absent;
an existing envelope must parse strictly and match the would-be envelope
field-by-field (`$schema`, schema version, full config JSON, digest, CLI
identity, tool revision). Any failure is a hard error and the original
bytes are preserved — there is no `Err(_) => write(...)` fallback.

### P6.3-D production evidence chain

```text
launch attestation -> RunEvidenceContext -> sidecar producers
-> atomic bundle assembler -> v8 gate consumer
```

`assemble_evidence_bundle` derives `case_id`, `tool_revision` and
`runner_config_digest` exclusively from the attested context. `complete_run_evidence`
is the production driver: it collects the seven members exactly as the
producers name them (five structured sidecars + dumper transform manifest +
PE evidence via the acceptance binary), fails closed on any missing member,
and writes the bundle atomically. The unpack pipeline calls it after a
successful gated run, so the bundle digest always equals the launch
attestation digest.

### P6.3.1 seal + verifier binding

- `RunEvidenceContext` is sealed: not `Clone`, every field private (getters
  only), no public constructor (crate-private `new`, reachable only from
  the attestation and crate unit tests). `complete_run_evidence` and
  `assemble_evidence_bundle` take it BY VALUE, so one attestation
  authorizes exactly one bundle — a second use is a compile error.
- The launch attestation emits a stable, filter-independent gate line
  (`launch attestation: Ready (...)`), so the positive control does not
  depend on the log filter.

### P6.3.2 verifier trust root

- The production CLI has NO verifier override. `--acceptance-bin` (all
  forms) is forbidden and fails closed on both `/unpack` and
  `/offline-preflight`; the environment is never read; there is no PATH
  fallback.
- The only verifier source is the exact sibling `mida-acceptance.exe` of
  the running `mida-cli` (`resolve_acceptance_bin_from_cli`). The resolver
  returns `Result` and hard-fails when the sibling is missing, is not a
  regular file, or does not canonicalize to exactly `cli_dir/mida-acceptance.exe`.
- The envelope is `mida.runner-config-envelope/v3` and binds the verifier's
  controlled relative source (`<cli-dir>/mida-acceptance.exe`), its
  canonical path, AND its SHA-256. Staging, launch re-attestation,
  PE-evidence and bundle completion all re-resolve the sibling and validate
  path identity AND hash — reporting no unchecked path drift.
- The trust root is the deployment unit: whoever controls the `mida-cli`
  install controls its sibling verifier (replacing the sibling is equivalent
  to replacing the CLI itself — host trust, not a CLI interface bypass).
- Tests inject a verifier by copying `mida-cli` into a temp dir and placing
  the verifier as its `mida-acceptance.exe` sibling — never a flag or
  environment override.
- Tests fail closed on a stale sibling `mida-acceptance` binary (it must be
  newer than the acceptance sources); the `cargo test --workspace` gate
  rebuilds it fresh (hermetic).

## Attack tests (`crates/cli/tests/launch_attestation.rs`, 20 tests)

1. hand-written `ready` is never an authorization (verifier re-run
   NotReady blocks);
2. a Ready report staged for one input cannot launch a different input
   (cross-case reuse refused);
3. a Ready report cannot launch a garbage/third input;
4. an input modified after preflight is refused;
5. an output path changed after preflight is refused;
6. outputs aliasing the protected input (same canonical path, hard link)
   are refused;
7. `--no-shrink` divergence is refused;
8. every other policy divergence (`--data-sections`, `--oep`,
   `--container-restore`, `--profile`, `--pure-rebuild`,
   `--capture-policy`) is refused item by item;
9. a binary A preflight cannot authorize a binary B launch;
10. a malformed existing envelope is never overwritten (bytes preserved);
11. a stale/different envelope is never reused (bytes preserved);
12. `$schema` drift is rejected by both the runner and the acceptance
    verifier;
13. the envelope binds the exact CLI-sibling verifier (source token +
    canonical path + SHA) and the unique resolver returns it;
14. the one-time authorization is compile-enforced (no Clone, no public
    constructor, by-value ownership consume);
15. a verifier different from the envelope-pinned identity is refused at
    launch;
16. `--acceptance-bin` is forbidden in the production CLI (all forms), so a
    stub cannot be directed at staging/launch through the interface (the
    same-stub Ready path that existed in P6.3.1 is closed);
17. positive control: a genuinely re-verified Ready report passes the
    attestation and the pipeline continues past it (stable Ready output,
    passes under `RUST_LOG=warn`).

Negative tests use the real `mida-acceptance` binary; the pass-path tests
use the deterministic `mida-verifier-stub`
(`crates/cli/tests/bin/verifier_stub.rs`, a test-support bin that mirrors
the acceptance CLI surface). The assembler unit tests
(`bundle_assembler::tests`) live in the crate so they can construct a
sealed `RunEvidenceContext` and exercise the by-value ownership consume.

## Remaining boundaries

- The attestation re-runs the verifier process; the report file is trusted
  only as the verifier's output (locally recomputed identities and the
  digest chain are the authority).
- The verifier trust root is the deployment unit: the sibling
  `mida-acceptance.exe` beside `mida-cli`. Substituting the sibling is host
  trust (equivalent to replacing the CLI), not a CLI interface bypass — the
  interface (no `--acceptance-bin`, no env, no PATH) cannot direct the
  resolver to any other binary.
- The `v8` two-sample gate consumer (observations from live runs) is
  outside this change: the bundle digest equality with the attestation is
  enforced, but a live P7 smoke is still gated by operator authorization.
- No real sample was opened or started; P7 is NOT authorized.
- The AHK/GTO product-recovery route does not participate in the Oreans
  evidence-bundle chain (its attested context stays unused).
- No claim of live, perfect, universal, or 10/10 behavior is made.

# P6.3.3 Case-Bound Runner Config Closure

Status: implemented on `oreans/two-sample-mainline`.

Scope: pure offline engineering closure. No real sample process was created;
the P7 one-time live-smoke quota remains 0/4.

## Design conflict discovered during P7-0 preflight

The pre-P6.3.3 `/offline-preflight` built a single `mida.runner-config-envelope/v3`
from `frozen_runner_config()`, which hardcodes `pure_rebuild=false`. At actual
`/unpack` parse time the Origin Macro D3 default (`origin_pure::resolve_pure_rebuild`)
resolves `pure_rebuild=true` for the verified origin_macro input. A single
top-level `runner_config_digest` therefore could not honestly authorize both
origin_macro (`pure_rebuild=true`) and lunlun_software (`pure_rebuild=false`).
The launch attestation's `bind_actual_config_to_envelope` digest-equality check
would block the Origin launch (actual digest `true` vs envelope digest `false`).

That P7-0 v3 preflight directory is preserved and marked `SUPERSEDED.md`
(config-model-conflict). It does not constitute a failed live run; the live-slot
usage stays 0/4.

## Resolution: case-bound envelope v4

- `mida.runner-config-envelope/v4` removes the ambiguous top-level
  `runner_config`/`runner_config_digest` and replaces them with
  `case_configs: [CaseRunnerConfigEnvelope]` — exactly the two fixed cases,
  each carrying `case_id`, `protected_input` identity (locked manifest
  artifact), full `RunnerConfig`, and its own `runner_config_digest`.
- A sealed `case_set_digest` covers every case config and its case/input
  binding (`case=id\nprotected_input=sha|size\nrunner_config_digest=...`),
  so any single-case tamper breaks the whole-envelope seal.
- Staging (`run_offline_preflight_command`) builds one config per REAL case
  input from `frozen_run_policy(case.input)` — the Origin D3 default resolves
  `pure_rebuild=true` only for the verified origin_macro input, never by the
  `case_id` string.
- The acceptance verifier independently reparses the v4 envelope, recomputes
  EACH case's digest and the case-set digest, validates the
  case_id ↔ protected identity ↔ config-digest binding, and fails the whole
  preflight on any single-case drift. A v3 single-config envelope is rejected
  (no silent upgrade).
- The launch attestation first matches the current protected input to EXACTLY
  ONE case, then compares the actual config digest against ONLY that case's
  digest; `policy_matches(actual, frozen_run_policy(input))` still runs. The
  selected case's digest flows into the `RunEvidenceContext` and the bundle.
- The preflight report is `mida.preflight-report/v3`: each case entry carries
  its own `runner_config_digest`, and the top-level digest is the envelope's
  case-set digest; the report and envelope cross-validate every case.

## P6.3.3 attack tests

Positive (case-bound digest binding, hermetic unit tests in
`runner_preflight::tests`):

- Origin config `pure_rebuild=true` and Lunlun `pure_rebuild=false` in one
  envelope, distinct per-case digests, independently recomputable.
- `select_case_config` picks the unique case by input identity (0 or 2+ matches
  refused).
- `bind_actual_config_to_envelope` compares only the selected case's digest:
  Origin actual vs Lunlun digest is rejected, and vice versa.
- `case_set_digest` re-seals and rejects missing/duplicate/extra cases.

Negative (integration, real acceptance binary + launch):

- swapping the two per-case configs (stale per-case digest, re-sealed outer
  hash) is rejected by the verifier;
- forcing Origin `pure_rebuild=false` / Lunlun `pure_rebuild=true` is rejected
  at launch (actual digest no longer matches the tampered case digest) before
  process creation;
- a v3 single-config envelope is rejected by the acceptance verifier;
- `launch_attestation` (20 tests) and `preflight_boundary` (12 tests) cover the
  case-bound selection, per-case digest drift, hand-written-Ready, and
  before-process-creation blocking.

## Boundaries after P6.3.3

- No real sample process was created; P7 is NOT authorized.
- `validation_summary.json` remains `open`.
- No claim of live, perfect, universal, or 10/10 behavior is made.
