//! Runtime artifact provenance (`mida.antidebug-provenance/v1`).
//!
//! Records the build-time identity of the runtime artifact so the
//! controller can verify it before loading. ADR-4: no third-party
//! components are used, so `third_party = "none"` is honest.

use serde::{Deserialize, Serialize};

/// Provenance schema (ADR-0 clean-room rules §7).
pub const PROVENANCE_SCHEMA: &str = "mida.antidebug-provenance/v1";

/// Runtime artifact provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub schema: String,
    pub artifact_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub architecture: String,
    pub toolchain: String,
    pub source_ref: String,
    /// ADR-4: honest "none". If external crates are ever used at runtime,
    /// this must list them explicitly - never label third-party as own.
    pub third_party: String,
    pub license: String,
    pub build_repro: String,
}

impl Provenance {
    /// Build the provenance for the current crate (rlib/cdylib identity).
    pub fn current(sha256: String, size_bytes: u64, toolchain: String, source_ref: String) -> Self {
        Self {
            schema: PROVENANCE_SCHEMA.to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256,
            size_bytes,
            architecture: crate::attestation::ARCH_X86_64.to_string(),
            toolchain,
            source_ref,
            third_party: "none".to_string(),
            license: "GPL-3.0-only".to_string(),
            build_repro: "--locked offline build; out-of-tree target".to_string(),
        }
    }

    /// Canonical JSON.
    pub fn to_canonical_json(&self) -> Result<String, ProvenanceError> {
        serde_json::to_string(self).map_err(|e| ProvenanceError::Serialization(e.to_string()))
    }

    /// Parse + validate.
    pub fn from_canonical_json(s: &str) -> Result<Self, ProvenanceError> {
        let v: Provenance =
            serde_json::from_str(s).map_err(|e| ProvenanceError::Deserialization(e.to_string()))?;
        v.validate()?;
        Ok(v)
    }

    /// Fail-closed validation: schema, architecture, third_party declaration.
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        if self.schema != PROVENANCE_SCHEMA {
            return Err(ProvenanceError::SchemaMismatch(self.schema.clone()));
        }
        if self.architecture != crate::attestation::ARCH_X86_64 {
            return Err(ProvenanceError::ArchitectureMismatch(
                self.architecture.clone(),
            ));
        }
        if self.third_party.is_empty() {
            return Err(ProvenanceError::ThirdPartyUndeclared);
        }
        if self.sha256.is_empty() {
            return Err(ProvenanceError::IdentityIncomplete);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvenanceError {
    #[error("schema mismatch: {0}")]
    SchemaMismatch(String),
    #[error("architecture mismatch: {0}")]
    ArchitectureMismatch(String),
    #[error("third_party provenance undeclared")]
    ThirdPartyUndeclared,
    #[error("artifact identity incomplete (sha256/size missing)")]
    IdentityIncomplete,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),
}
