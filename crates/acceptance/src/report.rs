//! Deterministic acceptance JSON report.
//!
//! v2 adds the machine-consumable product-trust fields `trust_tier` and
//! `product_acceptable` (P1/P2). v1 reports lacked these and must be rejected
//! by machine consumers that gate on product acceptance.

use serde::{Deserialize, Serialize};

use crate::identity::ArtifactIdentity;
use crate::oracle::OracleObservation;
use crate::verdict::Verdict;

pub const REPORT_SCHEMA_VERSION: &str = "mida.acceptance-report/v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Stable gate identifier (ordering key).
    pub id: String,
    pub status: GateStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureRecord {
    pub gate_id: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarningRecord {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualRisk {
    pub id: String,
    pub message: String,
}

/// Product trust tier of an acceptance verdict (P1 Lab/Product isolation).
///
/// Machine consumers MUST read `trust_tier` + `product_acceptable` rather than
/// treating any `Accepted` verdict as a product acceptance:
///
/// - `Product` — a verified signature envelope with a non-caller-controlled
///   trust root backed the run. Only this tier may report `product_acceptable`.
/// - `Lab` — an explicitly-flagged lab-only Accept (e.g. `--allow-hmac-lab`,
///   `check_with_behavior_managed_lab`). Diagnostic only, never product.
/// - `Unsigned` — no verified envelope (managed-but-unsigned or unmanaged).
///   Never product-acceptable; capped below `Accepted` where possible.
/// - `Rejected` — the run failed; not acceptable at any tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    Product,
    Lab,
    Unsigned,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceReport {
    pub schema_version: String,
    pub artifact: ArtifactIdentity,
    pub verdict: Verdict,
    /// Product trust tier (P1). `product_acceptable` is derived from this.
    pub trust_tier: TrustTier,
    /// `true` only when `trust_tier == Product` AND `verdict == Accepted`. A
    /// lab/unsigned `Accepted` reports `product_acceptable == false` so a
    /// machine consumer cannot mistake it for a product acceptance.
    pub product_acceptable: bool,
    /// Gates in fixed evaluation order.
    pub gates: Vec<GateResult>,
    pub failures: Vec<FailureRecord>,
    pub warnings: Vec<WarningRecord>,
    pub residual_risks: Vec<ResidualRisk>,
    pub oracle_observations: Vec<OracleObservation>,
}

impl AcceptanceReport {
    pub fn new(artifact: ArtifactIdentity) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            artifact,
            verdict: Verdict::Rejected,
            trust_tier: TrustTier::Rejected,
            product_acceptable: false,
            gates: Vec::new(),
            failures: Vec::new(),
            warnings: Vec::new(),
            residual_risks: Vec::new(),
            oracle_observations: Vec::new(),
        }
    }

    /// Recompute `product_acceptable` from the current `trust_tier` and
    /// `verdict`. Call after changing either.
    pub fn refresh_product_acceptable(&mut self) {
        self.product_acceptable =
            self.trust_tier == TrustTier::Product && self.verdict == Verdict::Accepted;
    }

    /// Serialize to deterministic JSON (compact, stable field order from serde).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        // Compact form without trailing newline for byte stability of the body;
        // callers may append a single trailing newline for file output.
        serde_json::to_string(self)
    }

    /// Finalize verdict from failures. Never emits `Accepted` in R0B.
    pub fn finalize_r0b(&mut self) {
        if self.failures.is_empty() {
            self.verdict = Verdict::StructuralPassBehaviorPending;
        } else {
            self.verdict = Verdict::Rejected;
        }
        // Hard contract: Accepted is unreachable.
        debug_assert_ne!(self.verdict, Verdict::Accepted);
    }
}
