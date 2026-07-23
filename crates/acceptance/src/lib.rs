//! # mida-acceptance
//!
//! Independent acceptance kernel for MagicMida vNext (R0B + B-A2 compose).
//!
//! Default path judges candidate PE files by **static structure only**.
//! Optional `check_with_behavior` composes **pre-recorded** behavioral
//! evidence (produced outside this crate). It must not depend on
//! `mida-core`, `mida-pe`, `mida-tracer`, `mida-packers-*`, or `mida-cli`.
//! It does not call Win32, launch processes, or run packer heuristics.
//!
//! See `docs/ACCEPTANCE_CONTRACT.md` and `docs/VNEXT_BEHAVIORAL_PATH.md`.

pub mod behavior;
pub mod check;
pub mod gates;
pub mod identity;
pub mod oracle;
pub mod pe;
pub mod report;
pub mod verdict;

#[cfg(test)]
#[allow(dead_code)]
mod test_support;

pub use behavior::{
    compose_with_behavior, BehaviorEvidence, BehaviorEvidenceError, BehaviorVerdict,
    BEHAVIOR_EVIDENCE_SCHEMA_VERSION,
};
pub use check::{check_static, check_static_verdict, check_with_behavior, CheckStaticOptions};
pub use identity::{sha256_hex, ArtifactIdentity, ROLE_CANDIDATE, ROLE_LEGACY_ORACLE};
pub use oracle::{observe_oracle, OracleObservation};
pub use report::{
    AcceptanceReport, FailureRecord, GateResult, GateStatus, ResidualRisk, WarningRecord,
    REPORT_SCHEMA_VERSION,
};
pub use verdict::Verdict;
