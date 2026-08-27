//! Per-sample profile model, validation, and promotion (ADR-2/ADR-3).
//!
//! Production `.expect()`s are invariants (WO-12): `serde_json::to_string`
//! on a plain-data profile struct cannot fail. Test-block expects are
//! ordinary assertions (WO-14).
#![allow(clippy::expect_used)]
//!
//! Profiles are pure data with deterministic validation. A profile binds:
//!
//! - `sample_id` / `profile_id` / `architecture` / `profile_digest`;
//! - four surface classes: `hard_required`, `required_candidate`,
//!   `observe_only`, `deferred`.
//!
//! Promotion (`required_candidate` -> `hard_required`) is only allowed with
//! sufficient proof level (`call_site_confirmed` / `runtime_observed` /
//! `decision_semantics_confirmed`) and must produce a new revision, a new
//! digest, promotion evidence, and an audit record. Validation failure
//! downgrades the candidate to `observe_only` - never silently keeps it
//! hard-required.

use serde::{Deserialize, Serialize};

/// Known sample ids (ADR-1 cases).
pub const SAMPLE_ORIGIN: &str = "origin_macro";
pub const SAMPLE_LUNLUN: &str = "lunlun_software";

/// Architecture string used in profiles.
pub const ARCH_X86_64: &str = "x86_64";

/// Surface classification within a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceClass {
    HardRequired,
    RequiredCandidate,
    ObserveOnly,
    Deferred,
}

impl SurfaceClass {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SurfaceClass::HardRequired => "hard_required",
            SurfaceClass::RequiredCandidate => "required_candidate",
            SurfaceClass::ObserveOnly => "observe_only",
            SurfaceClass::Deferred => "deferred",
        }
    }
}

/// A single surface entry inside a profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SurfaceSpec {
    pub surface_id: String,
    pub class: SurfaceClass,
    /// Evidence basis for this classification (free-form refs).
    #[serde(default)]
    pub basis: Vec<String>,
}

/// An anti-debug profile (`mida.antidebug-profile/v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub schema: String,
    pub profile_id: String,
    pub sample_id: String,
    pub architecture: String,
    pub surfaces: Vec<SurfaceSpec>,
    pub profile_basis: Vec<String>,
    pub version: u32,
}

impl Profile {
    /// Surface class lookup (first match wins; duplicates are a validation error).
    pub fn class_of(&self, surface_id: &str) -> Option<SurfaceClass> {
        self.surfaces
            .iter()
            .find(|s| s.surface_id == surface_id)
            .map(|s| s.class)
    }

    /// All surface ids in this profile.
    pub fn surface_ids(&self) -> impl Iterator<Item = &str> {
        self.surfaces.iter().map(|s| s.surface_id.as_str())
    }

    /// Surfaces of a given class.
    pub fn surfaces_of(&self, class: SurfaceClass) -> Vec<&SurfaceSpec> {
        self.surfaces.iter().filter(|s| s.class == class).collect()
    }

    /// Canonical JSON encoding (used for digest).
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).expect("profile serialization is infallible")
    }

    /// Deterministic profile digest.
    ///
    /// Pure Rust, no external crypto dependency: FNV-1a 64-bit placeholder
    /// until `sha2` is allowed (ADR-3A keeps deps minimal). Deterministic
    /// for a given canonical JSON.
    pub fn profile_digest(&self) -> String {
        let s = self.canonical_json();
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in s.bytes() {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("{hash:016x}")
    }
}

/// Profile validation errors (all fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("empty profile")]
    EmptyProfile,
    #[error("profile schema mismatch: {0}")]
    SchemaMismatch(String),
    #[error("sample_id mismatch: expected {expected}, got {got}")]
    SampleMismatch { expected: String, got: String },
    #[error("architecture mismatch: expected {expected}, got {got}")]
    ArchitectureMismatch { expected: String, got: String },
    #[error("profile digest mismatch: expected {expected}, got {got}")]
    DigestMismatch { expected: String, got: String },
    #[error("duplicate surface_id: {0}")]
    DuplicateSurface(String),
    #[error("surface {0} appears in more than one class")]
    ConflictingClass(String),
    #[error("unknown surface {0} classified as hard_required")]
    UnknownSurfaceInHardRequired(String),
    #[error("required_candidate {0} serialized as hard_required (candidate misuse)")]
    CandidateMisusedAsHard(String),
}

/// Proof levels allowed for promotion (ADR-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofLevel {
    PresenceObserved,
    CallSiteConfirmed,
    RuntimeObserved,
    DecisionSemanticsConfirmed,
}

/// Promotion errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PromoteError {
    #[error("surface {0} is not a required_candidate")]
    NotACandidate(String),
    #[error("surface {0} not found in profile")]
    UnknownSurface(String),
    #[error("promotion evidence is required")]
    MissingEvidence,
    #[error("proof level {0:?} is insufficient; need call_site_confirmed, runtime_observed or decision_semantics_confirmed")]
    InsufficientProof(ProofLevel),
}

/// The result of a successful promotion: a new profile revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileRevision {
    pub profile: Profile,
    pub previous_version: u32,
    pub promotion_evidence: Vec<String>,
    pub audit_record: String,
}

impl ProfileRevision {
    pub fn new_profile_digest(&self) -> String {
        self.profile.profile_digest()
    }
}

/// Validate a profile against a sample + architecture + expected digest.
/// Fail-closed: any inconsistency is an error.
pub fn validate_profile(
    profile: &Profile,
    sample_id: &str,
    architecture: &str,
    expected_digest: &str,
) -> Result<(), ProfileError> {
    if profile.surfaces.is_empty() {
        return Err(ProfileError::EmptyProfile);
    }
    if profile.schema != "mida.antidebug-profile/v1" {
        return Err(ProfileError::SchemaMismatch(profile.schema.clone()));
    }
    if profile.sample_id != sample_id {
        return Err(ProfileError::SampleMismatch {
            expected: sample_id.to_string(),
            got: profile.sample_id.clone(),
        });
    }
    if profile.architecture != architecture {
        return Err(ProfileError::ArchitectureMismatch {
            expected: architecture.to_string(),
            got: profile.architecture.clone(),
        });
    }
    let digest = profile.profile_digest();
    if digest != expected_digest {
        return Err(ProfileError::DigestMismatch {
            expected: expected_digest.to_string(),
            got: digest,
        });
    }

    // duplicate surface ids
    let mut seen: Vec<&str> = Vec::new();
    for s in &profile.surfaces {
        if seen.contains(&s.surface_id.as_str()) {
            return Err(ProfileError::DuplicateSurface(s.surface_id.clone()));
        }
        seen.push(s.surface_id.as_str());
    }
    Ok(())
}

/// Reject unknown surfaces classified as hard_required.
/// `known_surfaces` is the ADR-1 surface id registry (24 entries).
pub fn validate_hard_required(
    profile: &Profile,
    known_surfaces: &[&str],
) -> Result<(), ProfileError> {
    for s in &profile.surfaces {
        if s.class == SurfaceClass::HardRequired && !known_surfaces.contains(&s.surface_id.as_str())
        {
            return Err(ProfileError::UnknownSurfaceInHardRequired(
                s.surface_id.clone(),
            ));
        }
    }
    Ok(())
}

/// Reject a required_candidate that was (mis)serialized as hard_required.
/// `candidates` is the authoritative candidate list for this sample.
pub fn reject_candidate_as_hard(
    profile: &Profile,
    candidates: &[&str],
) -> Result<(), ProfileError> {
    for s in &profile.surfaces {
        if s.class == SurfaceClass::HardRequired && candidates.contains(&s.surface_id.as_str()) {
            return Err(ProfileError::CandidateMisusedAsHard(s.surface_id.clone()));
        }
    }
    Ok(())
}

/// Promote a `required_candidate` to `hard_required`.
///
/// Allowed proof levels: `CallSiteConfirmed`, `RuntimeObserved`,
/// `DecisionSemanticsConfirmed`. Promotion bumps the profile version,
/// changes the digest, records promotion evidence and an audit record.
/// A validation failure downgrades the candidate to `observe_only`
/// (never keeps it hard-required without proof).
pub fn promote_candidate(
    profile: &Profile,
    surface_id: &str,
    proof_level: ProofLevel,
    promotion_evidence: Vec<String>,
) -> Result<ProfileRevision, PromoteError> {
    if promotion_evidence.is_empty() {
        return Err(PromoteError::MissingEvidence);
    }
    match proof_level {
        ProofLevel::PresenceObserved => {
            return Err(PromoteError::InsufficientProof(proof_level));
        }
        ProofLevel::CallSiteConfirmed
        | ProofLevel::RuntimeObserved
        | ProofLevel::DecisionSemanticsConfirmed => {}
    }

    let idx = profile
        .surfaces
        .iter()
        .position(|s| s.surface_id == surface_id)
        .ok_or_else(|| PromoteError::UnknownSurface(surface_id.to_string()))?;
    let spec = &profile.surfaces[idx];
    if spec.class != SurfaceClass::RequiredCandidate {
        return Err(PromoteError::NotACandidate(surface_id.to_string()));
    }

    let mut new_profile = profile.clone();
    let new_spec = SurfaceSpec {
        surface_id: spec.surface_id.clone(),
        class: SurfaceClass::HardRequired,
        basis: {
            let mut b = spec.basis.clone();
            b.extend(promotion_evidence.iter().cloned());
            b
        },
    };
    new_profile.surfaces[idx] = new_spec;
    new_profile.version = profile.version + 1;

    let audit = format!(
        "promote {} {} -> {} (v{} -> v{}): {}",
        surface_id,
        SurfaceClass::RequiredCandidate.as_str(),
        SurfaceClass::HardRequired.as_str(),
        profile.version,
        new_profile.version,
        promotion_evidence.join("; ")
    );

    Ok(ProfileRevision {
        profile: new_profile,
        previous_version: profile.version,
        promotion_evidence,
        audit_record: audit,
    })
}

/// Downgrade a candidate to observe-only (validation failure path).
pub fn demote_candidate_to_observe_only(
    profile: &Profile,
    surface_id: &str,
) -> Result<ProfileRevision, PromoteError> {
    let idx = profile
        .surfaces
        .iter()
        .position(|s| s.surface_id == surface_id)
        .ok_or_else(|| PromoteError::UnknownSurface(surface_id.to_string()))?;
    let spec = &profile.surfaces[idx];
    if spec.class != SurfaceClass::RequiredCandidate {
        return Err(PromoteError::NotACandidate(surface_id.to_string()));
    }
    let mut new_profile = profile.clone();
    let new_spec = SurfaceSpec {
        surface_id: spec.surface_id.clone(),
        class: SurfaceClass::ObserveOnly,
        basis: {
            let mut b = spec.basis.clone();
            b.push("demoted: validation failed at ADR-3A wiring".to_string());
            b
        },
    };
    new_profile.surfaces[idx] = new_spec;
    new_profile.version = profile.version + 1;
    let new_version = new_profile.version;
    Ok(ProfileRevision {
        profile: new_profile,
        previous_version: profile.version,
        promotion_evidence: vec!["demotion".to_string()],
        audit_record: format!(
            "demote {surface_id} candidate -> observe_only (v{} -> v{})",
            profile.version, new_version
        ),
    })
}

/// Build the origin_macro profile (ADR-2 PROFILE_DRAFT).
pub fn origin_profile() -> Profile {
    Profile {
        schema: "mida.antidebug-profile/v1".to_string(),
        profile_id: "oreans_origin_x64_v1".to_string(),
        sample_id: SAMPLE_ORIGIN.to_string(),
        architecture: ARCH_X86_64.to_string(),
        surfaces: vec![
            SurfaceSpec {
                surface_id: "AD-PROC-001".into(),
                class: SurfaceClass::RequiredCandidate,
                basis: vec!["iat_evidence slot 92".into()],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-002".into(),
                class: SurfaceClass::HardRequired,
                basis: vec!["live logs PEB patched".into()],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-003".into(),
                class: SurfaceClass::HardRequired,
                basis: vec!["live logs pShimData cleared".into()],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-004".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-005".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-006".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-007".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-THR-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-THR-002".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-THR-003".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-HEAP-001".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TIM-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TIM-002".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TIM-003".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TIM-004".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-EXC-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-EXC-002".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-EXC-003".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TLS-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TLS-002".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-INT-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-INT-002".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-UI-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-ENV-001".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
        ],
        profile_basis: vec![
            "docs/MIDA_ADR_1_SURFACE_INVENTORY.md".into(),
            "docs/MIDA_ADR_2_PROBE_CATALOG.md".into(),
        ],
        version: 1,
    }
}

/// Build the lunlun_software profile (ADR-2 PROFILE_DRAFT).
pub fn lunlun_profile() -> Profile {
    Profile {
        schema: "mida.antidebug-profile/v1".to_string(),
        profile_id: "oreans_lunlun_x64_v1".to_string(),
        sample_id: SAMPLE_LUNLUN.to_string(),
        architecture: ARCH_X86_64.to_string(),
        surfaces: vec![
            SurfaceSpec {
                surface_id: "AD-PROC-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec!["IAT not rebuilt".into()],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-002".into(),
                class: SurfaceClass::HardRequired,
                basis: vec!["live logs PEB patched".into()],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-003".into(),
                class: SurfaceClass::HardRequired,
                basis: vec!["live logs pShimData cleared".into()],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-004".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-005".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-006".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-PROC-007".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-THR-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-THR-002".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-THR-003".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-HEAP-001".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TIM-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TIM-002".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TIM-003".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TIM-004".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-EXC-001".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-EXC-002".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-EXC-003".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TLS-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-TLS-002".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-INT-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-INT-002".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-UI-001".into(),
                class: SurfaceClass::ObserveOnly,
                basis: vec![],
            },
            SurfaceSpec {
                surface_id: "AD-ENV-001".into(),
                class: SurfaceClass::Deferred,
                basis: vec![],
            },
        ],
        profile_basis: vec![
            "docs/MIDA_ADR_1_SURFACE_INVENTORY.md".into(),
            "docs/MIDA_ADR_2_PROBE_CATALOG.md".into(),
        ],
        version: 1,
    }
}

/// The 24 surface ids from ADR-1 Matrix A (canonical registry).
pub const KNOWN_SURFACES: [&str; 24] = [
    "AD-PROC-001",
    "AD-PROC-002",
    "AD-PROC-003",
    "AD-PROC-004",
    "AD-PROC-005",
    "AD-PROC-006",
    "AD-PROC-007",
    "AD-THR-001",
    "AD-THR-002",
    "AD-THR-003",
    "AD-HEAP-001",
    "AD-TIM-001",
    "AD-TIM-002",
    "AD-TIM-003",
    "AD-TIM-004",
    "AD-EXC-001",
    "AD-EXC-002",
    "AD-EXC-003",
    "AD-TLS-001",
    "AD-TLS-002",
    "AD-INT-001",
    "AD-INT-002",
    "AD-UI-001",
    "AD-ENV-001",
];
