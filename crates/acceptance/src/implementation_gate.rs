//! Implementation gate (IMP-04): readiness / implemented / acceptance-allowed
//! three-state evaluation for the v2 + Walker implementation phase.
//!
//! Pure offline. Evaluates only declared facts about the deliverable tree
//! (what exists, what is placeholder, what is wired) and returns a
//! fail-closed verdict. Never upgrades local/offline evidence into a
//! production/Windows PASS.

use serde::{Deserialize, Serialize};

/// Implementation gate schema id.
pub const IMPLEMENTATION_GATE_SCHEMA: &str = "mida.acceptance/implementation-gate/v1";

/// The placeholder digest value that blocks implementation acceptance
/// (exports.rs:239 "adr4-foundation-unbound").
pub const PLACEHOLDER_DIGEST: &str = "adr4-foundation-unbound";

/// Three-state implementation gate status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplGateStatus {
    /// Design/readiness accepted (schemas, fixtures, contracts in place).
    Ready,
    /// Implementation present and wired.
    Implemented,
    /// Acceptance may be granted (all gates clear).
    AcceptanceAllowed,
}

impl ImplGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ImplGateStatus::Ready => "ready",
            ImplGateStatus::Implemented => "implemented",
            ImplGateStatus::AcceptanceAllowed => "acceptance_allowed",
        }
    }
}

/// Facts about the deliverable tree evaluated by the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationFacts {
    /// exports.rs digest value ("" if not present).
    pub digest_value: String,
    /// Whether MidaAntidebugInitializeV2 exists in the runtime exports.
    pub has_initialize_v2: bool,
    /// Whether the production 7-arg thunk is wired into the loader.
    pub has_production_thunk_wired: bool,
    /// Whether a production Walker protocol caller exists.
    pub has_walker_caller: bool,
    /// Whether a V2 attestation/digest consumer exists.
    pub has_v2_consumer: bool,
    /// Whether Walker runtime/CLI is dispatched.
    pub walker_dispatched: bool,
    /// Whether LIVE-4 (or any live/Windows runtime) authorization exists.
    /// NEVER true in this phase; a true value without evidence is a lie.
    pub live_authorized: bool,
    /// Whether the Windows runtime path has been verified with real
    /// evidence (WPM/CRT/SEH/VEH observations). False in this phase.
    pub windows_runtime_verified: bool,
    /// Whether evidence is sufficient for acceptance (per-layer sufficiency
    /// check). False without live evidence.
    pub evidence_sufficient: bool,
}

/// Implementation gate verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationGateVerdict {
    pub schema: String,
    pub readiness: ImplGateStatus,
    pub implemented: ImplGateStatus,
    pub acceptance_allowed: ImplGateStatus,
    /// Fail-closed implementation gate result.
    pub gate: ImplGateResult,
    /// Human-readable reasons for the current status.
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplGateResult {
    Pass,
    Hold,
    Fail,
}

/// Evaluate the implementation gate from declared facts.
///
/// Rules (fail-closed):
/// - readiness = Ready when the v1 foundation + protocol contracts exist
///   (always true in this phase: the frozen tree carries them).
/// - implemented = Implemented ONLY when: digest is not the placeholder,
///   initialize_v2 exists, production thunk wired, walker caller exists,
///   v2 consumer exists. Otherwise NOT implemented.
/// - acceptance_allowed = Allowed ONLY when implemented AND walker
///   dispatched AND no LIVE-4-style authorization is outstanding.
/// - gate: Pass iff all three states are at their accepted value.
pub fn evaluate_implementation_gate(facts: &ImplementationFacts) -> ImplementationGateVerdict {
    let mut reasons = Vec::new();

    // readiness
    let readiness = ImplGateStatus::Ready;
    reasons.push(
        "readiness=ready: v1 foundation + v2 protocol contracts present in frozen tree".to_string(),
    );

    // implemented
    let mut implemented_ok = true;
    if facts.digest_value == PLACEHOLDER_DIGEST || facts.digest_value.is_empty() {
        implemented_ok = false;
        reasons.push(format!(
            "implemented=NOT: digest is placeholder or empty (got {:?})",
            facts.digest_value
        ));
    }
    if !facts.has_initialize_v2 {
        implemented_ok = false;
        reasons.push("implemented=NOT: MidaAntidebugInitializeV2 missing".to_string());
    }
    if !facts.has_production_thunk_wired {
        implemented_ok = false;
        reasons.push("implemented=NOT: production 7-arg thunk not wired".to_string());
    }
    if !facts.has_walker_caller {
        implemented_ok = false;
        reasons.push("implemented=NOT: Walker protocol production caller missing".to_string());
    }
    if !facts.has_v2_consumer {
        implemented_ok = false;
        reasons.push("implemented=NOT: V2 attestation/digest consumer missing".to_string());
    }
    let implemented = if implemented_ok {
        ImplGateStatus::Implemented
    } else {
        ImplGateStatus::Ready // readiness only
    };

    // acceptance allowed — HARD GATES (RC-2):
    // walker_dispatched alone can NEVER grant acceptance. All three of
    // live_authorized, windows_runtime_verified and evidence_sufficient
    // must be true, and each requires its own evidence layer (LIVE-4).
    let mut allowed_ok = implemented_ok;
    if !facts.walker_dispatched {
        allowed_ok = false;
        reasons.push("acceptance_allowed=NOT: Walker runtime/CLI not dispatched".to_string());
    }
    if !facts.live_authorized {
        allowed_ok = false;
        reasons.push(
            "acceptance_allowed=NOT: live authorization missing (LIVE-4 NOT AUTHORIZED)"
                .to_string(),
        );
    }
    if !facts.windows_runtime_verified {
        allowed_ok = false;
        reasons.push(
            "acceptance_allowed=NOT: windows runtime not verified (no live evidence)".to_string(),
        );
    }
    if !facts.evidence_sufficient {
        allowed_ok = false;
        reasons.push("acceptance_allowed=NOT: evidence insufficient for acceptance".to_string());
    }
    let acceptance_allowed = if allowed_ok {
        ImplGateStatus::AcceptanceAllowed
    } else {
        ImplGateStatus::Ready
    };

    let gate = if implemented_ok && allowed_ok {
        ImplGateResult::Pass
    } else if implemented_ok {
        ImplGateResult::Hold
    } else {
        ImplGateResult::Fail
    };

    ImplementationGateVerdict {
        schema: IMPLEMENTATION_GATE_SCHEMA.to_string(),
        readiness,
        implemented,
        acceptance_allowed,
        gate,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_tree_facts() -> ImplementationFacts {
        // Facts as of the frozen deliverable tree (914e73e): production
        // v2/Walker not implemented.
        ImplementationFacts {
            digest_value: PLACEHOLDER_DIGEST.to_string(),
            has_initialize_v2: false,
            has_production_thunk_wired: false,
            has_walker_caller: false,
            has_v2_consumer: false,
            walker_dispatched: false,
            live_authorized: false,
            windows_runtime_verified: false,
            evidence_sufficient: false,
        }
    }

    #[test]
    fn current_tree_is_ready_not_implemented_not_allowed() {
        let v = evaluate_implementation_gate(&current_tree_facts());
        assert_eq!(v.readiness, ImplGateStatus::Ready);
        assert_eq!(v.implemented, ImplGateStatus::Ready); // NOT implemented
        assert_eq!(v.acceptance_allowed, ImplGateStatus::Ready); // NOT allowed
        assert_eq!(v.gate, ImplGateResult::Fail);
        assert_eq!(v.schema, IMPLEMENTATION_GATE_SCHEMA);
    }

    #[test]
    fn placeholder_digest_blocks_implementation() {
        let mut f = current_tree_facts();
        // everything implemented EXCEPT digest still placeholder
        f.has_initialize_v2 = true;
        f.has_production_thunk_wired = true;
        f.has_walker_caller = true;
        f.has_v2_consumer = true;
        f.walker_dispatched = true;
        let v = evaluate_implementation_gate(&f);
        assert_eq!(v.implemented, ImplGateStatus::Ready);
        assert_eq!(v.gate, ImplGateResult::Fail);
        assert!(v.reasons.iter().any(|r| r.contains("placeholder")));
    }

    #[test]
    fn missing_walker_caller_blocks_implementation() {
        let mut f = current_tree_facts();
        f.digest_value = "a".repeat(64);
        f.has_initialize_v2 = true;
        f.has_production_thunk_wired = true;
        f.has_v2_consumer = true;
        // has_walker_caller stays false
        f.walker_dispatched = true;
        let v = evaluate_implementation_gate(&f);
        assert_eq!(v.implemented, ImplGateStatus::Ready);
        assert_eq!(v.gate, ImplGateResult::Fail);
        assert!(v
            .reasons
            .iter()
            .any(|r| r.contains("Walker protocol production caller")));
    }

    #[test]
    fn not_dispatched_blocks_acceptance() {
        let mut f = current_tree_facts();
        f.digest_value = "a".repeat(64);
        f.has_initialize_v2 = true;
        f.has_production_thunk_wired = true;
        f.has_walker_caller = true;
        f.has_v2_consumer = true;
        // walker_dispatched stays false
        let v = evaluate_implementation_gate(&f);
        assert_eq!(v.implemented, ImplGateStatus::Implemented);
        assert_eq!(v.acceptance_allowed, ImplGateStatus::Ready);
        assert_eq!(v.gate, ImplGateResult::Hold);
    }

    #[test]
    fn fully_implemented_without_live_authorization_is_hold() {
        // Even fully implemented + dispatched, WITHOUT live authorization
        // the gate must NOT pass (RC-2 hard gate: no LIVE-4 -> no acceptance).
        let f = ImplementationFacts {
            digest_value: "a".repeat(64),
            has_initialize_v2: true,
            has_production_thunk_wired: true,
            has_walker_caller: true,
            has_v2_consumer: true,
            walker_dispatched: true,
            live_authorized: false,
            windows_runtime_verified: false,
            evidence_sufficient: false,
        };
        let v = evaluate_implementation_gate(&f);
        assert_eq!(v.implemented, ImplGateStatus::Implemented);
        assert_eq!(v.acceptance_allowed, ImplGateStatus::Ready); // NOT Allowed
        assert_eq!(v.gate, ImplGateResult::Hold);
    }

    #[test]
    fn acceptance_requires_all_hard_gates() {
        let mut f = ImplementationFacts {
            digest_value: "a".repeat(64),
            has_initialize_v2: true,
            has_production_thunk_wired: true,
            has_walker_caller: true,
            has_v2_consumer: true,
            walker_dispatched: true,
            live_authorized: true,
            windows_runtime_verified: false,
            evidence_sufficient: false,
        };
        // windows_runtime_verified=false -> NOT allowed
        let v = evaluate_implementation_gate(&f);
        assert_eq!(v.acceptance_allowed, ImplGateStatus::Ready);
        assert_eq!(v.gate, ImplGateResult::Hold);

        f.windows_runtime_verified = true;
        // evidence_sufficient=false -> NOT allowed
        let v2 = evaluate_implementation_gate(&f);
        assert_eq!(v2.acceptance_allowed, ImplGateStatus::Ready);
        assert_eq!(v2.gate, ImplGateResult::Hold);

        f.evidence_sufficient = true;
        let v3 = evaluate_implementation_gate(&f);
        assert_eq!(v3.acceptance_allowed, ImplGateStatus::AcceptanceAllowed);
        assert_eq!(v3.gate, ImplGateResult::Pass);
    }

    #[test]
    fn walker_dispatched_alone_cannot_pass() {
        let f = ImplementationFacts {
            digest_value: "a".repeat(64),
            has_initialize_v2: true,
            has_production_thunk_wired: true,
            has_walker_caller: true,
            has_v2_consumer: true,
            walker_dispatched: true,
            live_authorized: false,
            windows_runtime_verified: false,
            evidence_sufficient: false,
        };
        let v = evaluate_implementation_gate(&f);
        assert_ne!(v.gate, ImplGateResult::Pass);
        assert!(v.reasons.iter().any(|r| r.contains("live authorization")));
    }

    #[test]
    fn verdict_roundtrips_json() {
        let v = evaluate_implementation_gate(&current_tree_facts());
        let json = serde_json::to_string(&v).unwrap();
        let back: ImplementationGateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}
