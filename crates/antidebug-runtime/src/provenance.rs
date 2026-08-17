//! Runtime artifact provenance ("mida.antidebug-provenance/v1").
//!
//! Records the build-time identity of the runtime artifact so the
//! controller can verify it before loading. Per clean-room rules the
//! record must carry kind, artifact identity, toolchain, source ref,
//! third-party declaration, license and build reproducibility.
//!
//! third_party semantics (ADR-4-CORRECTION, blocker 4): this runtime
//! links third-party crates (serde/serde_json/thiserror) as build- and
//! serialization-only dependencies. "none" would be false: those crates
//! ARE third-party. The declaration therefore uses the literal
//! "build-and-serialization-only" and lists every dependency with its
//! exact locked version, license and registry source so it is auditable.
//! No third-party anti-debug runtime, injector or hook implementation is
//! used, and none of the listed crates contribute anti-debug behavior.

use serde::{Deserialize, Serialize};

/// Provenance schema (ADR-0 clean-room rules §7).
pub const PROVENANCE_SCHEMA: &str = "mida.antidebug-provenance/v1";

/// Allowed provenance kinds (clean-room rules §7 table).
pub const KIND_RUNTIME_X64: &str = "runtime-x64";
pub const KIND_RUNTIME_X86: &str = "runtime-x86";
pub const KIND_CONTROLLER: &str = "controller";
pub const KIND_PROFILE: &str = "profile";
pub const KIND_ATTESTATION: &str = "attestation";
pub const KIND_EVIDENCE: &str = "evidence";

/// Allowed kinds for this record type.
pub const ALLOWED_KINDS: &[&str] = &[
    KIND_RUNTIME_X64,
    KIND_RUNTIME_X86,
    KIND_CONTROLLER,
    KIND_PROFILE,
    KIND_ATTESTATION,
    KIND_EVIDENCE,
];

/// Single third-party dependency declaration (auditable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyDecl {
    /// Crate name as declared in Cargo.toml.
    pub name: String,
    /// Exact version from Cargo.lock.
    pub version: String,
    /// SPDX license of the crate (from its published metadata).
    pub license: String,
    /// Crate registry source.
    pub source: String,
    /// Role in this artifact: build / serialization / other.
    pub role: String,
    /// Whether the crate participates in anti-debug behavior (must be false
    /// for every entry; enforced by validate()).
    pub anti_debug: bool,
}

impl DependencyDecl {
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        license: impl Into<String>,
        source: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            license: license.into(),
            source: source.into(),
            role: role.into(),
            anti_debug: false,
        }
    }
}

/// Runtime artifact provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub schema: String,
    /// Content-addressed artifact identity (SHA-256 of the artifact bytes).
    pub artifact_id: String,
    /// Artifact kind: runtime-x64 / runtime-x86 / controller / profile /
    /// attestation / evidence.
    pub kind: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub architecture: String,
    pub toolchain: String,
    pub source_ref: String,
    /// Third-party dependency declaration. Literal "none" only when NO
    /// external crates are linked; this runtime declares
    /// "build-and-serialization-only" and lists every dependency in
    /// `dependencies` (ADR-4-CORRECTION).
    pub third_party: String,
    /// Auditable dependency list (locked versions from Cargo.lock).
    pub dependencies: Vec<DependencyDecl>,
    pub license: String,
    pub build_repro: String,
}

impl Provenance {
    /// Build the provenance for the current crate (rlib/cdylib identity).
    pub fn current(sha256: String, size_bytes: u64, toolchain: String, source_ref: String) -> Self {
        Self {
            schema: PROVENANCE_SCHEMA.to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            kind: KIND_RUNTIME_X64.to_string(),
            sha256,
            size_bytes,
            architecture: crate::attestation::ARCH_X86_64.to_string(),
            toolchain,
            source_ref,
            third_party: "build-and-serialization-only".to_string(),
            dependencies: default_dependencies(),
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

    /// Fail-closed validation: schema, kind, architecture, third_party
    /// declaration and dependency audit.
    pub fn validate(&self) -> Result<(), ProvenanceError> {
        if self.schema != PROVENANCE_SCHEMA {
            return Err(ProvenanceError::SchemaMismatch(self.schema.clone()));
        }
        if !ALLOWED_KINDS.contains(&self.kind.as_str()) {
            return Err(ProvenanceError::KindInvalid(self.kind.clone()));
        }
        // kind/architecture consistency: an x64 runtime can only declare
        // runtime-x64 (clean-room rules §7). Checked BEFORE the bare
        // architecture check so a kind/arch mismatch reports the precise
        // error instead of a generic ArchitectureMismatch.
        if self.kind == KIND_RUNTIME_X64 && self.architecture != "x86_64" {
            return Err(ProvenanceError::KindArchitectureMismatch {
                kind: self.kind.clone(),
                architecture: self.architecture.clone(),
            });
        }
        if self.kind == KIND_RUNTIME_X86 && self.architecture != "x86" {
            return Err(ProvenanceError::KindArchitectureMismatch {
                kind: self.kind.clone(),
                architecture: self.architecture.clone(),
            });
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
        if self.kind == KIND_RUNTIME_X64 || self.kind == KIND_RUNTIME_X86 {
            // A runtime artifact that links third-party crates MUST list them.
            if self.dependencies.is_empty() {
                return Err(ProvenanceError::DependenciesUndeclared);
            }
            for d in &self.dependencies {
                if d.name.is_empty() || d.version.is_empty() {
                    return Err(ProvenanceError::DependencyIncomplete(d.name.clone()));
                }
                if d.anti_debug {
                    return Err(ProvenanceError::DependencyAntiDebug(d.name.clone()));
                }
            }
        }
        Ok(())
    }
}

/// The locked third-party build/serialization dependencies of this crate
/// (ADR-4-CORRECTION). Versions are the exact Cargo.lock entries; kept in
/// sync by the build verification step. These crates are build- and
/// serialization-only: they never participate in anti-debug behavior.
pub fn default_dependencies() -> Vec<DependencyDecl> {
    vec![
        DependencyDecl::new(
            "serde",
            "1.0.229",
            "MIT OR Apache-2.0",
            "crates.io",
            "serialization",
        ),
        DependencyDecl::new(
            "serde_json",
            "1.0.151",
            "MIT OR Apache-2.0",
            "crates.io",
            "serialization",
        ),
        DependencyDecl::new(
            "thiserror",
            "1.0.69",
            "MIT OR Apache-2.0",
            "crates.io",
            "error-definition",
        ),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvenanceError {
    #[error("schema mismatch: {0}")]
    SchemaMismatch(String),
    #[error("architecture mismatch: {0}")]
    ArchitectureMismatch(String),
    #[error("kind invalid: {0}")]
    KindInvalid(String),
    #[error("kind/architecture mismatch: kind {kind}, architecture {architecture}")]
    KindArchitectureMismatch { kind: String, architecture: String },
    #[error("third_party provenance undeclared")]
    ThirdPartyUndeclared,
    #[error("artifact identity incomplete (sha256/size missing)")]
    IdentityIncomplete,
    #[error("runtime artifact links third-party crates but dependencies are undeclared")]
    DependenciesUndeclared,
    #[error("dependency declaration incomplete: {0}")]
    DependencyIncomplete(String),
    #[error("dependency declared as anti-debug: {0}")]
    DependencyAntiDebug(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),
}
