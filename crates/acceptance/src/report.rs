//! Deterministic acceptance JSON report.

use serde::{Deserialize, Serialize};

use crate::identity::ArtifactIdentity;
use crate::oracle::OracleObservation;
use crate::verdict::Verdict;

pub const REPORT_SCHEMA_VERSION: &str = "mida.acceptance-report/v1";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceReport {
    pub schema_version: String,
    pub artifact: ArtifactIdentity,
    pub verdict: Verdict,
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
            gates: Vec::new(),
            failures: Vec::new(),
            warnings: Vec::new(),
            residual_risks: Vec::new(),
            oracle_observations: Vec::new(),
        }
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
