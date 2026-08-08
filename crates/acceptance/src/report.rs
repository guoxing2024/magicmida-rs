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

/// Strict product-gating report parse/validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("report JSON is not valid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("report schema_version '{0}' is not the required {REPORT_SCHEMA_VERSION}")]
    SchemaVersion(String),
    #[error("report is missing the required v2 field '{0}'")]
    MissingField(&'static str),
    #[error("report declares an unknown field: {0}")]
    UnknownField(String),
    #[error("report trust fields are inconsistent: {0}")]
    Inconsistent(String),
}

/// Strict, field-locked projection of an [`AcceptanceReport`]. This is the
/// ONLY shape a product consumer deserializes: `deny_unknown_fields` rejects
/// any report carrying a field this product pipeline does not know about, so
/// an attacker cannot smuggle a forged trust field under an unknown key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductReportStrict {
    schema_version: String,
    artifact: ArtifactIdentity,
    verdict: Verdict,
    trust_tier: TrustTier,
    product_acceptable: bool,
    gates: Vec<GateResult>,
    failures: Vec<FailureRecord>,
    warnings: Vec<WarningRecord>,
    residual_risks: Vec<ResidualRisk>,
    oracle_observations: Vec<OracleObservation>,
}

/// STRICT product-gating parser for machine consumers.
///
/// Unlike a raw `serde_json::from_str::<AcceptanceReport>()`, this parser:
/// - rejects any report whose `schema_version` is not exactly
///   [`REPORT_SCHEMA_VERSION`] (v2) — a v1 report is rejected even if it has
///   been padded with the v2 trust fields, because the declared schema is v1;
/// - rejects unknown fields (`deny_unknown_fields`) and missing required v2
///   fields (`trust_tier`, `product_acceptable`);
/// - rejects trust-field inconsistency, i.e. any state that would let a
///   consumer misread a non-product report as product-acceptable:
///     * `product_acceptable == true` requires `trust_tier == Product` AND
///       `verdict == Accepted`;
///     * `trust_tier == Product` requires `verdict == Accepted` for
///       `product_acceptable`, and the reverse must not claim product without a
///       Product tier.
///
/// Product consumers MUST call this instead of deserializing `AcceptanceReport`
/// directly, so that the product-gating semantics are enforced centrally.
pub fn parse_product_report(bytes: &[u8]) -> Result<AcceptanceReport, ReportError> {
    let strict: ProductReportStrict = serde_json::from_slice(bytes)?;

    if strict.schema_version != REPORT_SCHEMA_VERSION {
        return Err(ReportError::SchemaVersion(strict.schema_version));
    }

    // Product gating invariants.
    let is_accepted = strict.verdict == Verdict::Accepted;
    let is_product_tier = strict.trust_tier == TrustTier::Product;
    if strict.product_acceptable && !(is_product_tier && is_accepted) {
        return Err(ReportError::Inconsistent(
            "product_acceptable=true requires trust_tier=Product AND verdict=Accepted".to_string(),
        ));
    }
    if is_product_tier && is_accepted && !strict.product_acceptable {
        return Err(ReportError::Inconsistent(
            "trust_tier=Product + verdict=Accepted must set product_acceptable=true".to_string(),
        ));
    }

    Ok(AcceptanceReport {
        schema_version: strict.schema_version,
        artifact: strict.artifact,
        verdict: strict.verdict,
        trust_tier: strict.trust_tier,
        product_acceptable: strict.product_acceptable,
        gates: strict.gates,
        failures: strict.failures,
        warnings: strict.warnings,
        residual_risks: strict.residual_risks,
        oracle_observations: strict.oracle_observations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> ArtifactIdentity {
        ArtifactIdentity {
            sha256: "aa".repeat(32),
            size_bytes: 1024,
            role: "candidate".to_string(),
            expected_sha256: None,
        }
    }

    fn base_report() -> AcceptanceReport {
        let mut r = AcceptanceReport::new(artifact());
        r.verdict = Verdict::Accepted;
        r.trust_tier = TrustTier::Product;
        r.product_acceptable = true;
        r
    }

    /// A v1 report JSON: same shape as v2 but declares schema v1 and lacks the
    /// v2 trust fields (as a real v1 producer emitted).
    fn v1_report_json() -> String {
        let r = base_report();
        // Build the same fields but drop trust_tier/product_acceptable and use v1.
        let mut v = serde_json::to_value(&r).unwrap();
        v["schema_version"] = serde_json::Value::String("mida.acceptance-report/v1".into());
        let obj = v.as_object_mut().unwrap();
        obj.remove("trust_tier");
        obj.remove("product_acceptable");
        serde_json::to_string(&v).unwrap()
    }

    #[test]
    fn valid_v2_product_report_parses() {
        let r = base_report();
        let bytes = r.to_json().unwrap();
        let parsed = parse_product_report(bytes.as_bytes()).unwrap();
        assert!(parsed.product_acceptable);
        assert_eq!(parsed.trust_tier, TrustTier::Product);
        assert_eq!(parsed.verdict, Verdict::Accepted);
    }

    #[test]
    fn v1_report_rejected() {
        let bytes = v1_report_json();
        let err = parse_product_report(bytes.as_bytes()).unwrap_err();
        // A real v1 report lacks the v2 trust fields, so it is rejected either
        // by the strict field lock (Json) or — if padded — by the schema check.
        assert!(
            matches!(err, ReportError::Json(_) | ReportError::SchemaVersion(_)),
            "v1 report must be rejected, got {err:?}"
        );
    }

    /// v1 report even when PADDED with the v2 trust fields must be rejected,
    /// because the declared schema_version is v1.
    #[test]
    fn v1_report_padded_with_v2_fields_still_rejected() {
        let r = base_report();
        let mut v = serde_json::to_value(&r).unwrap();
        v["schema_version"] = serde_json::Value::String("mida.acceptance-report/v1".into());
        // keep trust_tier/product_acceptable (v2 fields) but schema is still v1.
        let bytes = serde_json::to_vec(&v).unwrap();
        let err = parse_product_report(&bytes).unwrap_err();
        assert!(matches!(err, ReportError::SchemaVersion(_)));
    }

    #[test]
    fn unknown_schema_version_rejected() {
        let r = base_report();
        let mut v = serde_json::to_value(&r).unwrap();
        v["schema_version"] = serde_json::Value::String("mida.acceptance-report/v99".into());
        let bytes = serde_json::to_vec(&v).unwrap();
        let err = parse_product_report(&bytes).unwrap_err();
        assert!(matches!(err, ReportError::SchemaVersion(_)));
    }

    #[test]
    fn missing_trust_field_rejected() {
        let r = base_report();
        let mut v = serde_json::to_value(&r).unwrap();
        v.as_object_mut().unwrap().remove("trust_tier");
        let bytes = serde_json::to_vec(&v).unwrap();
        let err = parse_product_report(&bytes).unwrap_err();
        // Missing required v2 field → serde error (unknown_field/missing_field).
        assert!(matches!(err, ReportError::Json(_)));
    }

    #[test]
    fn missing_product_acceptable_rejected() {
        let r = base_report();
        let mut v = serde_json::to_value(&r).unwrap();
        v.as_object_mut().unwrap().remove("product_acceptable");
        let bytes = serde_json::to_vec(&v).unwrap();
        let err = parse_product_report(&bytes).unwrap_err();
        assert!(matches!(err, ReportError::Json(_)));
    }

    #[test]
    fn unknown_field_rejected() {
        let r = base_report();
        let mut v = serde_json::to_value(&r).unwrap();
        v.as_object_mut().unwrap().insert(
            "trust_tier_backdoor".to_string(),
            serde_json::Value::String("Product".into()),
        );
        let bytes = serde_json::to_vec(&v).unwrap();
        let err = parse_product_report(&bytes).unwrap_err();
        assert!(matches!(err, ReportError::Json(_)));
    }

    /// product_acceptable=true but trust_tier=Lab → inconsistent → rejected.
    #[test]
    fn product_acceptable_true_with_lab_tier_rejected() {
        let mut r = base_report();
        r.trust_tier = TrustTier::Lab;
        r.refresh_product_acceptable(); // would set product_acceptable=false
                                        // Force the inconsistent state directly.
        r.product_acceptable = true;
        let bytes = r.to_json().unwrap();
        let err = parse_product_report(bytes.as_bytes()).unwrap_err();
        assert!(matches!(err, ReportError::Inconsistent(_)));
    }

    /// product_acceptable=true but verdict!=Accepted → inconsistent → rejected.
    #[test]
    fn product_acceptable_true_with_non_accepted_verdict_rejected() {
        let mut r = base_report();
        r.verdict = Verdict::StructuralPassBehaviorPending;
        r.product_acceptable = true; // force inconsistent
        let bytes = r.to_json().unwrap();
        let err = parse_product_report(bytes.as_bytes()).unwrap_err();
        assert!(matches!(err, ReportError::Inconsistent(_)));
    }

    /// trust_tier=Product + verdict=Accepted must set product_acceptable=true.
    #[test]
    fn product_tier_accepted_must_set_product_acceptable() {
        let mut r = base_report();
        r.product_acceptable = false; // force inconsistent
        let bytes = r.to_json().unwrap();
        let err = parse_product_report(bytes.as_bytes()).unwrap_err();
        assert!(matches!(err, ReportError::Inconsistent(_)));
    }

    /// A lab Accept (tier=Lab, product_acceptable=false) parses but is NOT
    /// product-acceptable — this is the honest lab result a consumer must gate on.
    #[test]
    fn lab_accept_parses_but_is_not_product_acceptable() {
        let mut r = AcceptanceReport::new(artifact());
        r.verdict = Verdict::Accepted;
        r.trust_tier = TrustTier::Lab;
        r.product_acceptable = false;
        let bytes = r.to_json().unwrap();
        let parsed = parse_product_report(bytes.as_bytes()).unwrap();
        assert!(!parsed.product_acceptable);
        assert_eq!(parsed.trust_tier, TrustTier::Lab);
    }
}
