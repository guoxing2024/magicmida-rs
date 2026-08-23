//! Runtime attestation ("mida.antidebug-runtime-attestation/v1").
//!
//! The runtime **reports**; the controller **authorizes**. This module
//! defines the record shape, the fail-closed validation rules, the
//! target-identity binding, and the canonical JSON encoding used for
//! the attestation handshake.
//!
//! Target-identity binding (ADR-4-CORRECTION, blocker 1): the attestation
//! carries target_pid and module_base so it cannot be taken from one
//! process and presented for another. The controller MUST cross-check
//! both via [RuntimeAttestation::verify_identity] before treating the
//! attestation as valid for the current run.

use serde::{Deserialize, Serialize};

/// Attestation schema (ADR-0 evidence contract).
pub const ATTESTATION_SCHEMA: &str = "mida.antidebug-runtime-attestation/v1";

/// Architecture string for the x64 runtime.
pub const ARCH_X86_64: &str = "x86_64";

/// Runtime identity (static build-time identity of this crate).
pub const RUNTIME_ID: &str = "mida-antidebug-runtime-x64";
pub const RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Hook inventory: what the profile requires vs what is actually installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookInventory {
    /// Surface ids the profile requires (hard_required + candidates).
    pub hooks_expected: Vec<String>,
    /// Surface ids actually installed by this runtime.
    pub hooks_installed: Vec<String>,
    /// Surface ids that failed to install (with reason).
    pub hook_failures: Vec<HookFailure>,
}

impl HookInventory {
    /// An honest "no hooks implemented yet" inventory (ADR-4).
    /// Every expected surface is reported as unsupported, never as
    /// silently installed.
    pub fn unsupported(expected: &[String]) -> Self {
        Self {
            hooks_expected: expected.to_vec(),
            hooks_installed: Vec::new(),
            hook_failures: expected
                .iter()
                .map(|s| HookFailure {
                    surface_id: s.clone(),
                    reason: "unsupported in ADR-4 foundation (hook surface ships in ADR-5)"
                        .to_string(),
                })
                .collect(),
        }
    }

    /// Fail-closed check: incomplete inventory is a failure.
    pub fn is_complete(&self) -> bool {
        self.hooks_installed.len() == self.hooks_expected.len() && self.hook_failures.is_empty()
    }
}

/// A hook installation failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookFailure {
    pub surface_id: String,
    pub reason: String,
}
/// Per-surface installation detail (ADR-5): full state record for each
/// hard-required surface, including original/effective values and the
/// restoration policy. Mirrors surfaces::SurfaceInstallOutcome in
/// serialized form so the attestation is self-contained and auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceDetail {
    pub surface_id: String,
    pub installed: bool,
    /// Raw value observed before any modification.
    pub original_value: Option<String>,
    /// Value in effect after install.
    pub effective_value: Option<String>,
    pub restoration_policy: String,
    pub restore_result: String,
    pub error: Option<String>,
}

/// Runtime telemetry channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    Uninitialized,
    Initialized,
    AttestationReady,
    Shutdown,
}

/// The runtime attestation record ("mida.antidebug-runtime-attestation/v1").
///
/// Unknown JSON fields are rejected at parse time
/// (#[serde(deny_unknown_fields)]) so a schema drift can never be
/// silently tolerated (ADR-0 evidence contract: missing field, wrong type
/// and unknown schema field are all rejected).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAttestation {
    pub schema: String,
    pub runtime_id: String,
    pub runtime_version: String,
    pub architecture: String,
    /// SHA-256 of the runtime artifact (hex, lowercase).
    pub runtime_sha256: String,
    pub profile_id: String,
    pub profile_digest: String,
    /// Target process id this runtime instance is bound to (target identity
    /// binding; must equal the launched target PID - ADR-4-CORRECTION).
    pub target_pid: u32,
    /// Base address of the loaded runtime module inside the target process
    /// (non-zero; controller must be able to resolve it - ADR-4-CORRECTION).
    pub module_base: u64,
    pub initialized: bool,
    pub hooks_expected: Vec<String>,
    pub hooks_installed: Vec<String>,
    pub hook_failures: Vec<HookFailure>,
    /// Per-surface detail records (ADR-5).
    pub surface_details: Vec<SurfaceDetail>,
    pub telemetry_channel: String,
    pub cleanup_handler_registered: bool,
    /// Provenance declaration of the runtime artifact
    /// (mida.antidebug-provenance/v1 kind summary; full record separate).
    pub third_party: String,
    pub source_revision: String,
    pub toolchain: String,
}

impl RuntimeAttestation {
    /// Build the ADR-4 foundation attestation: initialized, telemetry ready,
    /// but NO hooks installed (honest unsupported inventory).
    pub fn foundation(
        runtime_sha256: String,
        profile_id: String,
        profile_digest: String,
        target_pid: u32,
        module_base: u64,
        expected_surfaces: &[String],
        source_revision: String,
        toolchain: String,
    ) -> Self {
        let inventory = HookInventory::unsupported(expected_surfaces);
        Self {
            schema: ATTESTATION_SCHEMA.to_string(),
            runtime_id: RUNTIME_ID.to_string(),
            runtime_version: RUNTIME_VERSION.to_string(),
            architecture: ARCH_X86_64.to_string(),
            runtime_sha256,
            profile_id,
            profile_digest,
            target_pid,
            module_base,
            initialized: true,
            hooks_expected: inventory.hooks_expected,
            hooks_installed: inventory.hooks_installed,
            hook_failures: inventory.hook_failures,
            surface_details: Vec::new(),
            telemetry_channel: "ready".to_string(),
            cleanup_handler_registered: true,
            third_party: "build-and-serialization-only".to_string(),
            source_revision,
            toolchain,
        }
    }

    /// Build the ADR-5 attestation from actual surface installation results.
    ///
    /// Fail-closed contract:
    /// - every successful surface is listed in hooks_installed (never a
    ///   failed surface);
    /// - every failed surface is listed in hook_failures (never hidden);
    /// - hooks_installed must equal the expected set or the attestation
    ///   will not validate;
    /// - AD-PROC-001 is never installed here (candidate separation).
    pub fn from_surfaces(
        runtime_sha256: String,
        profile_id: String,
        profile_digest: String,
        target_pid: u32,
        module_base: u64,
        expected_surfaces: &[String],
        installed: &[String],
        failures: &[(String, String)],
        surface_details: Vec<SurfaceDetail>,
        source_revision: String,
        toolchain: String,
    ) -> Self {
        let hook_failures: Vec<HookFailure> = failures
            .iter()
            .map(|(id, reason)| HookFailure {
                surface_id: id.clone(),
                reason: reason.clone(),
            })
            .collect();
        Self {
            schema: ATTESTATION_SCHEMA.to_string(),
            runtime_id: RUNTIME_ID.to_string(),
            runtime_version: RUNTIME_VERSION.to_string(),
            architecture: ARCH_X86_64.to_string(),
            runtime_sha256,
            profile_id,
            profile_digest,
            target_pid,
            module_base,
            initialized: true,
            hooks_expected: expected_surfaces.to_vec(),
            hooks_installed: installed.to_vec(),
            hook_failures,
            surface_details,
            telemetry_channel: "ready".to_string(),
            cleanup_handler_registered: true,
            third_party: "build-and-serialization-only".to_string(),
            source_revision,
            toolchain,
        }
    }

    /// Canonical JSON encoding (used for the FFI handshake).
    pub fn to_canonical_json(&self) -> Result<String, AttestationError> {
        serde_json::to_string(self).map_err(|e| AttestationError::Serialization(e.to_string()))
    }

    /// Parse from canonical JSON (transport: does NOT validate).
    ///
    /// Validation is the controller decision gate ([Self::validate]);
    /// parsing must succeed even for an honest-but-incomplete runtime so the
    /// controller can read hooks_installed/hook_failures and fail closed
    /// with the correct code. Unknown fields are rejected at parse time
    /// (deny_unknown_fields), which is a transport-level fail-closed rule.
    pub fn from_canonical_json(s: &str) -> Result<Self, AttestationError> {
        serde_json::from_str(s).map_err(|e| AttestationError::Deserialization(e.to_string()))
    }

    /// Target-identity cross-check (controller side).
    ///
    /// The controller must call this before accepting the attestation:
    /// - expected_pid = PID of the process the controller launched;
    /// - expected_module_base = module base the controller resolved for
    ///   the runtime module inside that process.
    ///
    /// Any mismatch is fail-closed ([AttestationError::TargetPidMismatch] /
    /// [AttestationError::ModuleBaseMismatch]).
    pub fn verify_identity(
        &self,
        expected_pid: u32,
        expected_module_base: u64,
    ) -> Result<(), AttestationError> {
        if self.target_pid != expected_pid {
            return Err(AttestationError::TargetPidMismatch {
                expected: expected_pid,
                got: self.target_pid,
            });
        }
        if self.module_base == 0 {
            return Err(AttestationError::ModuleBaseZero);
        }
        if self.module_base != expected_module_base {
            return Err(AttestationError::ModuleBaseMismatch {
                expected: expected_module_base,
                got: self.module_base,
            });
        }
        Ok(())
    }

    /// Fail-closed validation against the ADR-0 evidence contract rules.
    ///
    /// Rules:
    /// - schema must match;
    /// - architecture must be x86_64;
    /// - initialized must be true;
    /// - telemetry_channel must be "ready";
    /// - hook inventory must be complete (installed == expected, no failures);
    /// - profile digest must be non-empty (controller cross-checks the value);
    /// - cleanup handler must be registered;
    /// - third_party must be declared (non-empty);
    /// - target_pid must be non-zero and module_base must be non-zero
    ///   (target identity binding; exact match is verified by
    ///   [Self::verify_identity]);
    /// - unknown/missing fields are rejected by serde (no defaulting).
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.schema != ATTESTATION_SCHEMA {
            return Err(AttestationError::SchemaMismatch(self.schema.clone()));
        }
        if self.architecture != ARCH_X86_64 {
            return Err(AttestationError::ArchitectureMismatch(
                self.architecture.clone(),
            ));
        }
        if !self.initialized {
            return Err(AttestationError::NotInitialized);
        }
        if self.telemetry_channel != "ready" {
            return Err(AttestationError::TelemetryNotReady(
                self.telemetry_channel.clone(),
            ));
        }
        if !self.cleanup_handler_registered {
            return Err(AttestationError::CleanupHandlerMissing);
        }
        if self.profile_digest.is_empty() {
            return Err(AttestationError::ProfileDigestMissing);
        }
        if self.third_party.is_empty() {
            return Err(AttestationError::ThirdPartyUndeclared);
        }
        if self.target_pid == 0 {
            return Err(AttestationError::TargetPidMissing);
        }
        if self.module_base == 0 {
            return Err(AttestationError::ModuleBaseZero);
        }
        if self.hooks_installed.len() != self.hooks_expected.len() {
            return Err(AttestationError::HookInventoryIncomplete {
                expected: self.hooks_expected.len(),
                installed: self.hooks_installed.len(),
            });
        }
        if !self.hook_failures.is_empty() {
            return Err(AttestationError::HookFailures(self.hook_failures.clone()));
        }
        // surface_details consistency (ADR-5): every installed hook must have
        // a matching installed surface detail, and every detail must agree
        // with the installed list. A detail marked installed=false with a
        // surface in hooks_installed is a contradiction -> fail-closed.
        for detail in &self.surface_details {
            let in_installed = self.hooks_installed.contains(&detail.surface_id);
            let in_failures = self
                .hook_failures
                .iter()
                .any(|f| f.surface_id == detail.surface_id);
            if detail.installed && (in_failures || !in_installed) {
                return Err(AttestationError::SurfaceDetailInconsistent(
                    detail.surface_id.clone(),
                ));
            }
            if !detail.installed && (in_installed || !in_failures) {
                return Err(AttestationError::SurfaceDetailInconsistent(
                    detail.surface_id.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// Attestation errors (all fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("schema mismatch: {0}")]
    SchemaMismatch(String),
    #[error("architecture mismatch: {0}")]
    ArchitectureMismatch(String),
    #[error("runtime not initialized")]
    NotInitialized,
    #[error("telemetry channel not ready: {0}")]
    TelemetryNotReady(String),
    #[error("cleanup handler not registered")]
    CleanupHandlerMissing,
    #[error("profile digest missing")]
    ProfileDigestMissing,
    #[error("third_party provenance undeclared")]
    ThirdPartyUndeclared,
    #[error("target pid missing (zero)")]
    TargetPidMissing,
    #[error("target pid mismatch: expected {expected}, got {got}")]
    TargetPidMismatch { expected: u32, got: u32 },
    #[error("module base is zero")]
    ModuleBaseZero,
    #[error("module base mismatch: expected {expected:#x}, got {got:#x}")]
    ModuleBaseMismatch { expected: u64, got: u64 },
    #[error("hook inventory incomplete: expected {expected}, installed {installed}")]
    HookInventoryIncomplete { expected: usize, installed: usize },
    #[error("hook failures present: {0:?}")]
    HookFailures(Vec<HookFailure>),
    #[error("surface detail inconsistent: {0}")]
    SurfaceDetailInconsistent(String),
    #[error("session id missing")]
    SessionIdMissing,
    #[error("record digest missing")]
    RecordDigestMissing,
    #[error("record digest mismatch: expected {expected}, got {got}")]
    RecordDigestMismatch { expected: String, got: String },
    #[error("round sequence gap: expected {expected}, got {got}")]
    RoundSeqGap { expected: u64, got: u64 },
    #[error("attestation counts inconsistent (rounds>0 but pages==0)")]
    CountsInconsistent,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),
}


// ============================================================================
// Walker attestation v2 (IMP-01, Protocol Reset phase)
// ============================================================================
//
// Pure-local, offline implementation phase types. These records describe a
// walker session's probe rounds for controller-side audit. They do NOT
// execute anything: no process memory is probed here; the probe results are
// supplied by the caller (the future Walker runtime) and merely shaped,
// validated and digest-anchored.
//
// Schema ids:
//   - "mida.antidebug-runtime-attestation/walker-v2"   (WalkerAttestation)
//   - "mida.antidebug-runtime-attestation/round-v2"    (RoundLedger)
//
// Digest anchor (record_digest): canonical JSON (sorted keys, no
// insignificant whitespace) of the *ledger* fields only, then sha256.
// The digest excludes session-level fields that are bound by the envelope,
// so a ledger can be re-anchored into a different envelope without changing
// its digest preimage.

/// Walker attestation schema id (v2).
pub const WALKER_ATTESTATION_SCHEMA: &str = "mida.antidebug-runtime-attestation/walker-v2";

/// Round ledger schema id (v2).
pub const ROUND_LEDGER_SCHEMA: &str = "mida.antidebug-runtime-attestation/round-v2";

/// Canonical JSON: sorted object keys, no insignificant whitespace.
///
/// serde_json preserves insertion order for structs; to guarantee the
/// canonical form used by digest preimages we re-serialize through a
/// BTreeMap-backed representation. For structs whose field order is
/// stable (Rust structs), serde_json output is already canonical for the
/// same binary; the BTreeMap pass guards against future field-order drift.
pub fn json_c14n(value: &serde_json::Value) -> Result<String, AttestationError> {
    fn sort(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<String> = map.keys().cloned().collect();
                keys.sort();
                for k in keys {
                    if let Some(val) = map.get(&k) {
                        sorted.insert(k, sort(val.clone()));
                    }
                }
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.into_iter().map(sort).collect())
            }
            other => other,
        }
    }
    let sorted = sort(value.clone());
    serde_json::to_string(&sorted)
        .map_err(|e| AttestationError::Serialization(e.to_string()))
}

/// SHA-256 hex (lowercase) helper shared by v2 digest anchoring.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in out {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

/// One probe round's result summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSummary {
    /// Monotonic round sequence within the session.
    pub round_seq: u64,
    /// Probe span in bytes (frozen contract: 16).
    pub span: u64,
    /// Number of pages covered by this round.
    pub page_count: u64,
    /// Guard pages touched (decrypt-triggered) in this round.
    pub guard_pages_touched: u64,
    /// Number of ProbeResultV2 records accepted into the section.
    pub accepted: u64,
    /// Number of records rejected by validation.
    pub rejected: u64,
    /// Round digest (sha256 hex of canonical ledger preimage for this round).
    pub round_digest: String,
}

/// An orphaned probe result: accepted into a section whose identity could
/// not be confirmed (no matching round ledger entry at audit time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Orphan {
    /// The mapping identity the orphan claims.
    pub identity_va: u64,
    /// The section header bytes digest (sha256 hex) that referenced it.
    pub section_digest: String,
    /// Why the orphan could not be confirmed (controller-side classification).
    pub reason: String,
}

/// Round ledger: the controller-side audit record for one walker session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundLedger {
    pub schema: String,
    /// Walker session id (derived, matches walker_protocol session id).
    pub session_id: String,
    /// Envelope profile id (from the params blob).
    pub profile_id: String,
    /// Rounds in execution order.
    pub rounds: Vec<ProbeSummary>,
    /// Orphans observed by the controller.
    pub orphans: Vec<Orphan>,
    /// Ledger digest over the canonical JSON of rounds+orphans (record_digest
    /// preimage; session fields excluded so the ledger can be re-anchored).
    pub record_digest: String,
}

impl RoundLedger {
    pub fn new(session_id: impl Into<String>, profile_id: impl Into<String>) -> Self {
        Self {
            schema: ROUND_LEDGER_SCHEMA.to_string(),
            session_id: session_id.into(),
            profile_id: profile_id.into(),
            rounds: Vec::new(),
            orphans: Vec::new(),
            record_digest: String::new(),
        }
    }

    /// Append a round summary and re-anchor the digest.
    pub fn push_round(&mut self, round: ProbeSummary) {
        self.rounds.push(round);
        self.record_digest = self.compute_digest();
    }

    /// Append an orphan and re-anchor the digest.
    pub fn push_orphan(&mut self, orphan: Orphan) {
        self.orphans.push(orphan);
        self.record_digest = self.compute_digest();
    }

    /// record_digest preimage: canonical JSON of {rounds, orphans} only.
    pub fn digest_preimage(&self) -> Result<String, AttestationError> {
        let value = serde_json::json!({
            "rounds": self.rounds,
            "orphans": self.orphans,
        });
        json_c14n(&value)
    }

    /// Compute the record digest (sha256 of the canonical preimage).
    pub fn compute_digest(&self) -> String {
        match self.digest_preimage() {
            Ok(pre) => sha256_hex(pre.as_bytes()),
            Err(_) => String::new(), // fail-closed: empty digest never validates
        }
    }

    /// Fail-closed validation.
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.schema != ROUND_LEDGER_SCHEMA {
            return Err(AttestationError::SchemaMismatch(self.schema.clone()));
        }
        if self.session_id.is_empty() {
            return Err(AttestationError::SessionIdMissing);
        }
        if self.record_digest.is_empty() {
            return Err(AttestationError::RecordDigestMissing);
        }
        // digest must match a recomputation over the current rounds+orphans.
        let recomputed = self.compute_digest();
        if recomputed != self.record_digest {
            return Err(AttestationError::RecordDigestMismatch {
                expected: recomputed,
                got: self.record_digest.clone(),
            });
        }
        // round_seq must be strictly increasing and gap-free.
        let mut last: Option<u64> = None;
        for r in &self.rounds {
            match last {
                None => last = Some(r.round_seq),
                Some(prev) => {
                    if r.round_seq != prev + 1 {
                        return Err(AttestationError::RoundSeqGap {
                            expected: prev + 1,
                            got: r.round_seq,
                        });
                    }
                    last = Some(r.round_seq);
                }
            }
        }
        Ok(())
    }

    /// Canonical JSON (transport).
    pub fn to_canonical_json(&self) -> Result<String, AttestationError> {
        serde_json::to_string(self).map_err(|e| AttestationError::Serialization(e.to_string()))
    }

    /// Parse from canonical JSON (transport: does NOT validate; call
    /// [Self::validate] on the controller side).
    pub fn from_canonical_json(s: &str) -> Result<Self, AttestationError> {
        serde_json::from_str(s).map_err(|e| AttestationError::Deserialization(e.to_string()))
    }
}

/// Walker session attestation (v2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalkerAttestation {
    pub schema: String,
    /// Walker session id (derived via walker_protocol::derive_session_id).
    pub session_id: String,
    /// Envelope profile id.
    pub profile_id: String,
    /// Profile digest from the envelope (controller cross-checks).
    pub profile_digest: String,
    /// Target pid the walker session is bound to.
    pub target_pid: u32,
    /// Number of completed probe rounds.
    pub round_count: u64,
    /// Total pages probed across all rounds.
    pub total_pages_probed: u64,
    /// Total guard pages touched.
    pub total_guard_pages_touched: u64,
    /// Ledger digest (anchors the full RoundLedger record).
    pub ledger_digest: String,
    /// Runtime artifact sha256 (same value as v1 runtime_sha256).
    pub runtime_sha256: String,
}

impl WalkerAttestation {
    pub fn new(
        session_id: impl Into<String>,
        profile_id: impl Into<String>,
        profile_digest: impl Into<String>,
        target_pid: u32,
        runtime_sha256: impl Into<String>,
    ) -> Self {
        Self {
            schema: WALKER_ATTESTATION_SCHEMA.to_string(),
            session_id: session_id.into(),
            profile_id: profile_id.into(),
            profile_digest: profile_digest.into(),
            target_pid,
            round_count: 0,
            total_pages_probed: 0,
            total_guard_pages_touched: 0,
            ledger_digest: String::new(),
            runtime_sha256: runtime_sha256.into(),
        }
    }

    /// Anchor to a ledger: copy counts and bind ledger_digest.
    pub fn anchor_ledger(&mut self, ledger: &RoundLedger) {
        self.round_count = ledger.rounds.len() as u64;
        self.total_pages_probed = ledger.rounds.iter().map(|r| r.page_count).sum();
        self.total_guard_pages_touched = ledger.rounds.iter().map(|r| r.guard_pages_touched).sum();
        self.ledger_digest = ledger.record_digest.clone();
    }

    /// Fail-closed validation.
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.schema != WALKER_ATTESTATION_SCHEMA {
            return Err(AttestationError::SchemaMismatch(self.schema.clone()));
        }
        if self.session_id.is_empty() {
            return Err(AttestationError::SessionIdMissing);
        }
        if self.profile_digest.is_empty() {
            return Err(AttestationError::ProfileDigestMissing);
        }
        if self.ledger_digest.is_empty() {
            return Err(AttestationError::RecordDigestMissing);
        }
        if self.target_pid == 0 {
            return Err(AttestationError::TargetPidMissing);
        }
        // counts must be consistent with a ledger that has rounds.
        if self.round_count > 0 && self.total_pages_probed == 0 {
            return Err(AttestationError::CountsInconsistent);
        }
        Ok(())
    }

    /// Canonical JSON (transport).
    pub fn to_canonical_json(&self) -> Result<String, AttestationError> {
        serde_json::to_string(self).map_err(|e| AttestationError::Serialization(e.to_string()))
    }

    /// Parse from canonical JSON (transport: does NOT validate; call
    /// [Self::validate] on the controller side).
    pub fn from_canonical_json(s: &str) -> Result<Self, AttestationError> {
        serde_json::from_str(s).map_err(|e| AttestationError::Deserialization(e.to_string()))
    }
}
