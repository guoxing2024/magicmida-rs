//! Runner-side offline-preflight closure (P6.2): the production binding of
//! the independent runner-config digest producer to the launch boundary.
//!
//! Roles:
//!
//! - **Producer (this module, `mida-cli` production)**: builds
//!   [`mida_core::runner_config::RunnerConfig`] from the actual run policy,
//!   computes the digest with `mida_core::runner_config::runner_config_digest`,
//!   and atomically emits the `mida.runner-config-envelope/v4` envelope
//!   (case-bound: one full config JSON + producer digest per case, plus CLI
//!   binary SHA-256, tool revision, verifier identity, and a sealed
//!   `case_set_digest` over every case config and its case/input binding).
//! - **Verifier (`mida-acceptance` binary)**: reparses the envelope JSON
//!   with its own dependency-free `RunnerConfig`, recomputes the digest with
//!   its own canonical implementation, and produces `preflight.json`.
//! - **Launch boundary (this module)**: [`run_offline_preflight`] drives the
//!   verifier and [`require_ready_before_launch`] refuses to proceed unless
//!   the consumed report is `ready`, the report digest equals the
//!   producer-computed digest, and the CLI identity matches. The unpack
//!   pipeline calls [`require_ready_before_launch`] before any sample
//!   process is created.
//!
//! Digest chain proven by `tests/preflight_boundary.rs`:
//!
//! ```text
//! runner-emitted digest
//! == acceptance-recomputed digest (report.runner_config_digest)
//! == envelope digest
//! == envelope_runner_config_digest() used for sidecar/bundle requests
//! ```
//!
//! P6.3: the envelope binds the ACTUAL run configuration (built by
//! `crate::run_spec` from the parsed `/unpack` arguments, including the
//! Origin Macro pure-rebuild default).
//!
//! P6.3.3: the envelope is case-bound. `/offline-preflight` builds one
//! per-case `RunnerConfig` from `frozen_run_policy(case.input)` — the Origin
//! Macro D3 default resolves `pure_rebuild=true` for origin_macro and
//! `false` for lunlun_software — so a single envelope can honestly
//! authorize both cases. The launch boundary ([`attest_ready_before_launch`])
//! first matches the current protected input to EXACTLY ONE case, then
//! compares the actual config digest against ONLY that case's
//! `runner_config_digest`; the selected digest flows into the evidence
//! context and bundle. A v3 single-config envelope fails closed (no silent
//! upgrade).
//!
//! ## Verifier TOCTOU — RESIDUAL (P2)
//!
//! The verifier identity is re-resolved + re-hashed at each spawn site
//! immediately before `Command::new` and bound to the envelope-pinned SHA-256
//! (see [`VerifierIdentity`]). This narrows but does NOT eliminate the
//! time-of-check/time-of-use window: a handle-based launch (open with
//! no-write/no-delete sharing across the spawn) is not implemented on this
//! platform. This is documented as a residual risk, not a full fix; the
//! sibling-only resolver is the trust boundary.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};

use crate::unpacker::sidecar_io::atomic_write;

/// Schema id of the runner-config envelope.
///
/// v3 (P6.3.2): binds the verifier PATH identity (canonical CLI sibling
/// path + controlled relative marker) together with `verifier_sha256`, so
/// staging, launch re-attestation, PE-evidence and bundle completion all
/// validate path AND hash.
///
/// v4 (P6.3.3): binds configuration PER CASE. The top-level single
/// `runner_config`/`runner_config_digest` is removed (it could not authorize
/// both Origin `pure_rebuild=true` and Lunlun `pure_rebuild=false`); it is
/// replaced by a `case_configs` collection (exactly the two fixed cases)
/// and a sealed `case_set_digest` over every case config + case/input
/// binding. v3 envelopes no longer parse (fail-closed, no silent upgrade).
pub const RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION: &str = "mida.runner-config-envelope/v4";
/// Filename of the envelope inside the preflight output dir.
pub const RUNNER_CONFIG_ENVELOPE_FILENAME: &str = "runner-config-envelope.json";
/// Filename of the preflight report inside the preflight output dir.
pub const PREFLIGHT_REPORT_FILENAME: &str = "preflight.json";
/// Emitted `$schema` reference of the envelope.
pub const RUNNER_CONFIG_ENVELOPE_SCHEMA_REF: &str = "./runner-config-envelope.schema.json";
/// The controlled relative identity of the verifier: always the CLI sibling.
pub const VERIFIER_SOURCE_TOKEN: &str = "<cli-dir>/mida-acceptance.exe";

/// Fixed policy of the two-sample Oreans runner (frozen for P7).
///
/// The values mirror the CLI defaults the unpack pipeline applies for the
/// Oreans path; the envelope binds the run to exactly this policy, and the
/// acceptance verifier independently recomputes the digest. The P7
/// fixed-mode comparison (including the Origin Macro pure-rebuild default
/// for a given input) lives in `crate::run_spec`.
mod envelope;
mod launch_gate;
mod producer;

pub use envelope::{
    bind_actual_config_to_envelope, frozen_runner_config, select_case_config,
    CaseRunnerConfigEnvelope, RunnerConfigEnvelope,
};
pub use launch_gate::{
    attest_ready_before_launch, canonicalize_loose, complete_run_evidence, current_tool_revision,
    envelope_case_runner_config_digest, file_identity, sha256_file,
    verify_verifier_identity_bindings, LaunchAttestationContext, RunEvidenceContext,
    VerifiedProfileIdentity, VerifiedTargetIdentity,
};
pub use producer::{
    envelope_reuse_policy, read_gate_report, require_ready_before_launch, resolve_acceptance_bin,
    resolve_acceptance_bin_from_cli, resolve_verifier_identity, resolve_verifier_identity_checked,
    run_offline_preflight, EnvelopeReuse, FileIdentityGate, PreflightCaseGate, PreflightReportGate,
    VerifierIdentity,
};

// pub(crate) re-exports: internal cross-module / test-seam symbols keep the
// `crate::runner_preflight::X` spelling working (WO-19 split; not part of the
// public surface).
pub(crate) use envelope::{canonical_case_entry, case_set_digest};
pub(crate) use launch_gate::verify_gto_sealed_root_matches;
pub(crate) use launch_gate::{
    enforce_gto_snapshot_path_binding, is_64_hex, is_64_lower_hex, pe_evidence_command_for_family,
    protected_input_for_evidence, rerun_verifier, sha256_hex, sidecar_path,
    verify_bundle_verifier_identity, verify_verifier_identity,
};
pub(crate) use launch_gate::{profile_for_case, snapshot_root_of_snapshot};
pub(crate) use producer::{
    check_chain_ready, maybe_record_verifier_spawn, maybe_test_launch_stop,
    note_sample_launch_attempted, verified_verifier_for_spawn,
};
#[cfg(test)]
pub(crate) use producer::{
    test_sample_launch_attempted_any, test_snapshot_root_recorder, test_verifier_override,
    test_verifier_recorder, DispatchTestGuard, TEST_LAUNCH_STOP_MESSAGE, TEST_LAUNCH_STOP_TOKEN,
};

/// Schema id of the preflight report the gate consumes.
///
/// v3 (P6.3.3): each case entry carries its own `runner_config_digest`, so
/// the report can cross-validate every case's config against the v4
/// envelope. v2 reports (single top-level digest) no longer parse.
pub const PREFLIGHT_REPORT_SCHEMA_VERSION: &str = "mida.preflight-report/v3";

/// The two fixed Oreans cases; the Oreans fixed regression lane accepts
/// exactly this set (no cross-case reuse).
pub const FIXED_CASE_IDS: [&str; 2] = ["origin_macro", "lunlun_software"];

/// The independent GTO generic/no-gate lane case. It is NOT part of the Oreans
/// fixed regression gate; it carries `family_id = ahk_gto` and a `no-gate`
/// acceptance state, and produces generic `mida.unpack-*` evidence.
pub const GTO_CASE_ID: &str = "gto_launcher";

#[cfg(test)]
#[path = "runner_preflight_tests.rs"]
mod runner_preflight_tests;
