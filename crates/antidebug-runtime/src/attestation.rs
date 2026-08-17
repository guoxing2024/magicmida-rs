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
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),
}
