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
    #[error("attestation counts inconsistent (rounds>0 but pages==0)")]
    CountsInconsistent,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),
    // --- v2 (WO-1503) ---
    #[error("schema version mismatch: got {got}")]
    SchemaVersionMismatch { got: u16 },
    #[error("schema version missing")]
    SchemaVersionMissing,
    #[error("schema missing")]
    SchemaMissing,
    #[error("unsupported schema: {0}")]
    SchemaUnsupported(String),
    #[error("canonical encoding invalid: {0}")]
    CanonicalEncodingInvalid(String),
    #[error("canonical top-level value is not an object")]
    CanonicalTopLevelNotObject,
    #[error("canonical non-finite number")]
    CanonicalNonFinite,
    #[error("canonical number error")]
    CanonicalNumber,
    #[error("canonical UTF-8 error")]
    CanonicalUtf8,
    #[error("round index invalid: {0}")]
    RoundIndexInvalid(u8),
    #[error("wall budget exceeded: spent {spent}, budget {budget}")]
    WallBudgetExceeded { spent: u64, budget: u64 },
    #[error("auto_retry must be false (governance hard rule)")]
    AutoRetryForbidden,
    #[error("candidates probed limit: got {got}, max 4096")]
    CandidatesProbedLimit { got: u32 },
    #[error("timestamp missing/empty")]
    TimestampMissing,
    #[error("orphan kind/VA/section inconsistent")]
    OrphanKindVaInconsistent,
    #[error("orphan reclaim_note in unconfirmed state")]
    OrphanReclaimNoteUnconfirmed,
    #[error("probe summary type sum mismatch: sum {sum}, total {total}")]
    ProbeSummaryTypeSumMismatch { sum: u32, total: u32 },
    #[error("probe summary count exceeds: {field} {got} > total {total}")]
    ProbeSummaryCountExceeds { field: &'static str, got: u32, total: u32 },
    #[error("counts overflow (checked add)")]
    CountsOverflow,
    #[error("walker pid mismatch: expected {expected}, got {got}")]
    WalkerPidMismatch { expected: u32, got: u32 },
    #[error("walker runtime digest mismatch with top-level runtime_sha256")]
    WalkerRuntimeDigestMismatch,
    #[error("target image digest missing")]
    TargetImageDigestMissing,
    #[error("walker export rva missing (zero)")]
    WalkerExportRvaMissing,
    #[error("walker entry va missing (zero)")]
    WalkerEntryVaMissing,
    #[error("round sequence gap: expected {expected}, got {got}")]
    RoundSeqGap { expected: u8, got: u8 },
    #[error("walker entry va overflow (module_base + rva)")]
    WalkerEntryOverflow,
    #[error("walker entry va mismatch: expected {expected:#x}, got {got:#x}")]
    WalkerEntryMismatch { expected: u64, got: u64 },
}


// ============================================================================
// Attestation v2 (WO-1503 frozen contract, IMP-01-R1)
// ============================================================================
//
// WO-1503 §1-§5 implemented field-exact. Pure offline: nothing here probes
// a process; record shaping, tagged dispatch, canonical JSON and digest
// anchoring only.
//
// Tagged dispatch (WO-1503 §1):
//   parse_attestation(json) -> TaggedAttestation::V1 | V2 | Err
//   v1 consumer on v2 -> SchemaUnsupported (never partial consume)
//   v2 consumer on v1 -> parse as v1, walker_attestation = None

/// v2 top-level schema id.
pub const ATTESTATION_SCHEMA_V2: &str = "mida.antidebug-runtime-attestation/v2";
/// v2 schema version discriminator.
pub const ATTESTATION_SCHEMA_VERSION_V2: u16 = 2;
/// Walker canonical encoding tag.
pub const WALKER_CANONICAL_ENCODING: &str = "json-c14n";

// ---------------------------------------------------------------------------
// json-c14n (WO-1503 §4): independent canonical serializer.
// ---------------------------------------------------------------------------

/// Canonicalize a parsed JSON value to the frozen json-c14n byte form.
///
/// Rules (WO-1503 §4):
///   1. object keys sorted by UTF-8 byte order;
///   2. strings: UTF-8 passthrough, escape only " \ and control chars;
///      non-ASCII output as raw UTF-8 bytes;
///   3. numbers: integers only (u64/i64) and finite doubles; -0 normalized;
///      NaN/Infinity rejected;
///   4. bool literals true/false; no numeric/string coercion;
///   5. arrays preserve order;
///   6. null literal;
///   7. top-level MUST be an object;
///   8. input must be valid UTF-8 (serde_json guarantees this on parse).
pub fn json_c14n_bytes(v: &serde_json::Value) -> Result<Vec<u8>, AttestationError> {
    fn write_string(out: &mut Vec<u8>, s: &str) {
        out.push(b'"');
        for &b in s.as_bytes() {
            match b {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                0x00..=0x1F => {
                    out.extend_from_slice(format!("\\u{:04x}", b).as_bytes());
                }
                _ => out.push(b),
            }
        }
        out.push(b'"');
    }

    fn write_number(out: &mut Vec<u8>, n: &serde_json::Number) -> Result<(), AttestationError> {
        if let Some(i) = n.as_i64() {
            out.extend_from_slice(i.to_string().as_bytes());
            return Ok(());
        }
        if let Some(u) = n.as_u64() {
            out.extend_from_slice(u.to_string().as_bytes());
            return Ok(());
        }
        if let Some(f) = n.as_f64() {
            if !f.is_finite() {
                return Err(AttestationError::CanonicalNonFinite);
            }
            // -0.0 normalizes to 0
            if f == 0.0 {
                out.push(b'0');
                return Ok(());
            }
            out.extend_from_slice(format!("{}", f).as_bytes());
            return Ok(());
        }
        Err(AttestationError::CanonicalNumber)
    }

    fn rec(out: &mut Vec<u8>, v: &serde_json::Value) -> Result<(), AttestationError> {
        match v {
            serde_json::Value::Null => out.extend_from_slice(b"null"),
            serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
            serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
            serde_json::Value::Number(n) => write_number(out, n)?,
            serde_json::Value::String(s) => write_string(out, s),
            serde_json::Value::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    rec(out, item)?;
                }
                out.push(b']');
            }
            serde_json::Value::Object(map) => {
                out.push(b'{');
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    write_string(out, k);
                    out.push(b':');
                    rec(out, &map[*k])?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }

    // Top-level must be an object (WO-1503 §4.7).
    if !v.is_object() {
        return Err(AttestationError::CanonicalTopLevelNotObject);
    }
    let mut out = Vec::new();
    rec(&mut out, v)?;
    Ok(out)
}

/// Canonical JSON string form (digest preimage input).
pub fn json_c14n(v: &serde_json::Value) -> Result<String, AttestationError> {
    let bytes = json_c14n_bytes(v)?;
    String::from_utf8(bytes).map_err(|_| AttestationError::CanonicalUtf8)
}

/// Fixed digest vectors (WO-1503 §5.3) — authoritative fixtures.
pub const C14N_VECTOR_1_HEX: &str = "7b7d";
pub const C14N_VECTOR_1_DIGEST: &str = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
pub const C14N_VECTOR_2_HEX: &str = "7b2261223a322c2262223a317d";
pub const C14N_VECTOR_2_DIGEST: &str = "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772";
pub const C14N_VECTOR_3_HEX: &str = "7b2261223a5b312c325d2c2273223a22785c2279222c2275223a22e4b8ad222c227a223a6e756c6c7d";
pub const C14N_VECTOR_3_DIGEST: &str = "154301026b1458e084761c0fba44c2269b5e66f7a4b0e0071ad09e69e97dd244";
pub const C14N_VECTOR_4_HEX: &str = "7b226e6f223a66616c73652c226f6b223a747275657d";
pub const C14N_VECTOR_4_DIGEST: &str = "ae8ab1e1b72505d8544a32bf3803333e81528159e214e4198a0271d2f60dc419";

/// SHA-256 hex (lowercase).
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

// ---------------------------------------------------------------------------
// Orphan (WO-1503 §3.4)
// ---------------------------------------------------------------------------

/// Orphan kind closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanKind {
    ParamsBlob,
    ResultSection,
}

/// Orphan state closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanState {
    Created,
    TimedOut,
    TargetExitObserved,
    OsReclaimed,
    Completed,
    Unconfirmed,
}

/// Orphan record (WO-1503 §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Orphan {
    pub kind: OrphanKind,
    pub target_pid: u32,
    pub blob_base_va: Option<u64>,
    pub section_name: Option<String>,
    pub created_ts: String,
    pub timeout_ts: Option<String>,
    pub state: OrphanState,
    pub reclaim_note: Option<String>,
}

impl Orphan {
    /// Fail-closed validation (WO-1503 §3.4):
    /// - kind/VA/section consistency: params_blob requires blob_base_va,
    ///   result_section requires section_name;
    /// - unconfirmed state must NOT carry a reclaim_note (no evidence, no claim).
    pub fn validate(&self) -> Result<(), AttestationError> {
        match self.kind {
            OrphanKind::ParamsBlob => {
                if self.blob_base_va.is_none() {
                    return Err(AttestationError::OrphanKindVaInconsistent);
                }
                if self.section_name.is_some() {
                    return Err(AttestationError::OrphanKindVaInconsistent);
                }
            }
            OrphanKind::ResultSection => {
                if self.section_name.is_none() {
                    return Err(AttestationError::OrphanKindVaInconsistent);
                }
                if self.blob_base_va.is_some() {
                    return Err(AttestationError::OrphanKindVaInconsistent);
                }
            }
        }
        if self.created_ts.is_empty() {
            return Err(AttestationError::TimestampMissing);
        }
        if self.state == OrphanState::Unconfirmed && self.reclaim_note.is_some() {
            return Err(AttestationError::OrphanReclaimNoteUnconfirmed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProbeSummary (WO-1503 §3.3)
// ---------------------------------------------------------------------------

/// Probe summary counts (WO-1503 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSummary {
    pub candidates_total: u32,
    pub type_a_count: u32,
    pub type_b_count: u32,
    pub type_c_count: u32,
    pub av_count: u32,
    pub guard_count: u32,
    pub retry_count: u32,
    pub total_latency_us: u64,
}

impl ProbeSummary {
    /// Consistency rules (WO-1503 §3.3):
    /// type_a + type_b + type_c == candidates_total;
    /// av_count <= candidates_total; guard_count <= candidates_total.
    pub fn validate(&self) -> Result<(), AttestationError> {
        let sum = self
            .type_a_count
            .checked_add(self.type_b_count)
            .and_then(|v| v.checked_add(self.type_c_count))
            .ok_or(AttestationError::CountsOverflow)?;
        if sum != self.candidates_total {
            return Err(AttestationError::ProbeSummaryTypeSumMismatch {
                sum,
                total: self.candidates_total,
            });
        }
        if self.av_count > self.candidates_total {
            return Err(AttestationError::ProbeSummaryCountExceeds {
                field: "av_count",
                got: self.av_count,
                total: self.candidates_total,
            });
        }
        if self.guard_count > self.candidates_total {
            return Err(AttestationError::ProbeSummaryCountExceeds {
                field: "guard_count",
                got: self.guard_count,
                total: self.candidates_total,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RoundLedger (WO-1503 §3.2)
// ---------------------------------------------------------------------------

/// Round abort state closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortState {
    None,
    ThreadHung,
    WaitFail,
    WalkerAbort,
    BudgetExhausted,
    StopLoss,
}

/// Round ledger (WO-1503 §3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundLedger {
    /// 1 or 2 (closed set).
    pub round_index: u8,
    /// RFC3339 UTC.
    pub entry_ts: String,
    pub exit_ts: String,
    pub wall_budget_ms: u64,
    pub wall_spent_ms: u64,
    pub candidates_probed: u32,
    pub abort_state: AbortState,
    pub orphaned_resources: Vec<Orphan>,
    /// Governance hard rule: always false.
    pub auto_retry: bool,
    /// Round 1 exit explicitly authorizes round 2.
    pub next_round_authorized: bool,
}

impl RoundLedger {
    pub fn new(round_index: u8) -> Result<Self, AttestationError> {
        if round_index != 1 && round_index != 2 {
            return Err(AttestationError::RoundIndexInvalid(round_index));
        }
        Ok(Self {
            round_index,
            entry_ts: String::new(),
            exit_ts: String::new(),
            wall_budget_ms: 0,
            wall_spent_ms: 0,
            candidates_probed: 0,
            abort_state: AbortState::None,
            orphaned_resources: Vec::new(),
            auto_retry: false,
            next_round_authorized: false,
        })
    }

    /// Fail-closed validation (WO-1503 §3.2):
    /// round_index ∈ {1,2}; wall_spent <= wall_budget; auto_retry == false;
    /// abort_state closed (enum); orphans each valid; timestamps non-empty.
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.round_index != 1 && self.round_index != 2 {
            return Err(AttestationError::RoundIndexInvalid(self.round_index));
        }
        if self.entry_ts.is_empty() || self.exit_ts.is_empty() {
            return Err(AttestationError::TimestampMissing);
        }
        if self.wall_spent_ms > self.wall_budget_ms {
            return Err(AttestationError::WallBudgetExceeded {
                spent: self.wall_spent_ms,
                budget: self.wall_budget_ms,
            });
        }
        if self.auto_retry {
            return Err(AttestationError::AutoRetryForbidden);
        }
        if self.candidates_probed > 4096 {
            return Err(AttestationError::CandidatesProbedLimit {
                got: self.candidates_probed,
            });
        }
        for o in &self.orphaned_resources {
            o.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WalkerAttestation (WO-1503 §3.1)
// ---------------------------------------------------------------------------

/// Walker session attestation (WO-1503 §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalkerAttestation {
    pub schema_version: u16,
    /// Must equal top-level target_pid.
    pub target_pid: u32,
    /// Sample identity (vault rev2 digest).
    pub target_image_sha256: String,
    /// Must equal top-level runtime_sha256.
    pub runtime_module_sha256: String,
    /// WalkerExecute export RVA.
    pub walker_export_rva: u64,
    /// module_base + rva (allowlist assertion value).
    pub walker_entry_va: u64,
    pub rounds: Vec<RoundLedger>,
    pub probe_summary: ProbeSummary,
    pub orphaned_resources: Vec<Orphan>,
    /// "json-c14n".
    pub canonical_encoding: String,
    /// sha256 of json-c14n preimage of this object minus record_digest.
    pub record_digest: String,
}

impl WalkerAttestation {
    pub fn new(
        target_pid: u32,
        target_image_sha256: impl Into<String>,
        runtime_module_sha256: impl Into<String>,
        walker_export_rva: u64,
        walker_entry_va: u64,
        probe_summary: ProbeSummary,
    ) -> Self {
        Self {
            schema_version: ATTESTATION_SCHEMA_VERSION_V2,
            target_pid,
            target_image_sha256: target_image_sha256.into(),
            runtime_module_sha256: runtime_module_sha256.into(),
            walker_export_rva,
            walker_entry_va,
            rounds: Vec::new(),
            probe_summary,
            orphaned_resources: Vec::new(),
            canonical_encoding: WALKER_CANONICAL_ENCODING.to_string(),
            record_digest: String::new(),
        }
    }

    /// record_digest preimage: this object minus record_digest field.
    pub fn digest_preimage(&self) -> Result<Vec<u8>, AttestationError> {
        let mut v = serde_json::to_value(self)
            .map_err(|e| AttestationError::Serialization(e.to_string()))?;
        if let Some(obj) = v.as_object_mut() {
            obj.remove("record_digest");
        }
        json_c14n_bytes(&v)
    }

    pub fn compute_digest(&self) -> String {
        match self.digest_preimage() {
            Ok(bytes) => sha256_hex(&bytes),
            Err(_) => String::new(),
        }
    }

    /// Verify the frozen binding matrix (WO-1503 §6.1) plus digest.
    pub fn validate(
        &self,
        top_level_pid: u32,
        top_level_runtime_sha256: &str,
        top_level_module_base: u64,
    ) -> Result<(), AttestationError> {
        if self.schema_version != ATTESTATION_SCHEMA_VERSION_V2 {
            return Err(AttestationError::SchemaVersionMismatch {
                got: self.schema_version,
            });
        }
        if self.canonical_encoding != WALKER_CANONICAL_ENCODING {
            return Err(AttestationError::CanonicalEncodingInvalid(
                self.canonical_encoding.clone(),
            ));
        }
        if self.target_pid != top_level_pid {
            return Err(AttestationError::WalkerPidMismatch {
                expected: top_level_pid,
                got: self.target_pid,
            });
        }
        if self.runtime_module_sha256 != top_level_runtime_sha256 {
            return Err(AttestationError::WalkerRuntimeDigestMismatch);
        }
        if self.target_image_sha256.is_empty() {
            return Err(AttestationError::TargetImageDigestMissing);
        }
        if self.walker_export_rva == 0 {
            return Err(AttestationError::WalkerExportRvaMissing);
        }
        if self.walker_entry_va == 0 {
            return Err(AttestationError::WalkerEntryVaMissing);
        }
        if self.walker_export_rva == 0 {
            return Err(AttestationError::WalkerExportRvaMissing);
        }
        // WO-1503 §6.1 binding: walker_entry_va == module_base + walker_export_rva.
        // Overflow must fail closed; any mismatch is rejected.
        let expected_entry = top_level_module_base
            .checked_add(self.walker_export_rva)
            .ok_or(AttestationError::WalkerEntryOverflow)?;
        if expected_entry != self.walker_entry_va {
            return Err(AttestationError::WalkerEntryMismatch {
                expected: expected_entry,
                got: self.walker_entry_va,
            });
        }
        if self.record_digest.is_empty() {
            return Err(AttestationError::RecordDigestMissing);
        }
        let recomputed = self.compute_digest();
        if recomputed != self.record_digest {
            return Err(AttestationError::RecordDigestMismatch {
                expected: recomputed,
                got: self.record_digest.clone(),
            });
        }
        self.probe_summary.validate()?;
        // round_index sequence must be 1 then 2 (no skip, no repeat)
        let mut expected_next: u8 = 1;
        for r in &self.rounds {
            r.validate()?;
            if r.round_index != expected_next {
                return Err(AttestationError::RoundSeqGap {
                    expected: expected_next,
                    got: r.round_index,
                });
            }
            expected_next = expected_next
                .checked_add(1)
                .ok_or(AttestationError::CountsOverflow)?;
        }
        for o in &self.orphaned_resources {
            o.validate()?;
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, AttestationError> {
        serde_json::to_string(self).map_err(|e| AttestationError::Serialization(e.to_string()))
    }

    pub fn from_canonical_json(s: &str) -> Result<Self, AttestationError> {
        serde_json::from_str(s).map_err(|e| AttestationError::Deserialization(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// RuntimeAttestationV2 (WO-1503 §2)
// ---------------------------------------------------------------------------

/// v2 top-level attestation (WO-1503 §2): v1 fields + schema_version +
/// walker_attestation + record_digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAttestationV2 {
    pub schema: String,
    pub schema_version: u16,
    pub runtime_id: String,
    pub runtime_version: String,
    pub architecture: String,
    pub runtime_sha256: String,
    pub profile_id: String,
    pub profile_digest: String,
    pub target_pid: u32,
    pub module_base: u64,
    pub initialized: bool,
    pub hooks_expected: Vec<String>,
    pub hooks_installed: Vec<String>,
    pub hook_failures: Vec<HookFailure>,
    pub surface_details: Vec<SurfaceDetail>,
    pub telemetry_channel: String,
    pub cleanup_handler_registered: bool,
    pub third_party: String,
    pub source_revision: String,
    pub toolchain: String,
    pub walker_attestation: Option<WalkerAttestation>,
    pub record_digest: String,
}

impl RuntimeAttestationV2 {
    /// record_digest preimage: this object minus record_digest field.
    pub fn digest_preimage(&self) -> Result<Vec<u8>, AttestationError> {
        let mut v = serde_json::to_value(self)
            .map_err(|e| AttestationError::Serialization(e.to_string()))?;
        if let Some(obj) = v.as_object_mut() {
            obj.remove("record_digest");
        }
        json_c14n_bytes(&v)
    }

    pub fn compute_digest(&self) -> String {
        match self.digest_preimage() {
            Ok(bytes) => sha256_hex(&bytes),
            Err(_) => String::new(),
        }
    }

    /// Fail-closed validation (WO-1503 §1.3, §2, §5.1a):
    /// - schema/schema_version consistency;
    /// - record_digest matches recomputation (nested walker digest verified first);
    /// - walker binding matrix via WalkerAttestation::validate.
    pub fn validate(&self) -> Result<(), AttestationError> {
        if self.schema != ATTESTATION_SCHEMA_V2 {
            return Err(AttestationError::SchemaMismatch(self.schema.clone()));
        }
        if self.schema_version != ATTESTATION_SCHEMA_VERSION_V2 {
            return Err(AttestationError::SchemaVersionMismatch {
                got: self.schema_version,
            });
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
        if self.target_pid == 0 {
            return Err(AttestationError::TargetPidMissing);
        }
        if self.module_base == 0 {
            return Err(AttestationError::ModuleBaseZero);
        }
        if self.record_digest.is_empty() {
            return Err(AttestationError::RecordDigestMissing);
        }
        // Nested walker digest verified BEFORE top-level digest (WO-1503 §5.1a).
        if let Some(w) = &self.walker_attestation {
            w.validate(self.target_pid, &self.runtime_sha256, self.module_base)?;
        }
        let recomputed = self.compute_digest();
        if recomputed != self.record_digest {
            return Err(AttestationError::RecordDigestMismatch {
                expected: recomputed,
                got: self.record_digest.clone(),
            });
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String, AttestationError> {
        serde_json::to_string(self).map_err(|e| AttestationError::Serialization(e.to_string()))
    }

    pub fn from_canonical_json(s: &str) -> Result<Self, AttestationError> {
        serde_json::from_str(s).map_err(|e| AttestationError::Deserialization(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tagged dispatch (WO-1503 §1)
// ---------------------------------------------------------------------------

/// Tagged attestation: v1 or v2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaggedAttestation {
    V1(RuntimeAttestation),
    V2(RuntimeAttestationV2),
}

/// Parse + dispatch on the schema discriminator (WO-1503 §1.2).
///
/// - v1 consumer on v2 input: this parser understands both; the *caller*
///   decides which variant it accepts. A v1-only consumer calling
///   RuntimeAttestation::from_canonical_json on v2 JSON still gets
///   Deserialization (unknown fields) — the upgrade guardrail.
/// - schema_version != 2 on a v2 schema -> SchemaVersionMismatch.
/// - unknown schema -> SchemaUnsupported.
pub fn parse_attestation(json: &str) -> Result<TaggedAttestation, AttestationError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| AttestationError::Deserialization(e.to_string()))?;
    let schema = value
        .get("schema")
        .and_then(|v| v.as_str())
        .ok_or(AttestationError::SchemaMissing)?;
    match schema {
        ATTESTATION_SCHEMA => {
            let v1: RuntimeAttestation = serde_json::from_value(value)
                .map_err(|e| AttestationError::Deserialization(e.to_string()))?;
            Ok(TaggedAttestation::V1(v1))
        }
        ATTESTATION_SCHEMA_V2 => {
            let ver = value
                .get("schema_version")
                .and_then(|v| v.as_u64())
                .ok_or(AttestationError::SchemaVersionMissing)? as u16;
            if ver != ATTESTATION_SCHEMA_VERSION_V2 {
                return Err(AttestationError::SchemaVersionMismatch { got: ver });
            }
            let v2: RuntimeAttestationV2 = serde_json::from_value(value)
                .map_err(|e| AttestationError::Deserialization(e.to_string()))?;
            Ok(TaggedAttestation::V2(v2))
        }
        _ => Err(AttestationError::SchemaUnsupported(schema.to_string())),
    }
}
