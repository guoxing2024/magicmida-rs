//! Family-aware evidence-schema dispatch (producer side).
//!
//! G2-R2: the shared sidecar producers and the PE-evidence producer must emit
//! family-appropriate member schemas. Oreans-family runs keep the legacy
//! `mida.oreans-*-evidence/v1` schemas; generic-family runs (currently
//! `ahk_gto`) emit the family-agnostic `mida.unpack-*-evidence/v1` schemas.
//! This module is the SINGLE dispatch point for a member schema given a packer
//! family — producers never scatter `if ahk_gto` checks across files.
//!
//! Fail-closed: an unknown family yields an error, so a producer can never
//! silently fall back to the Oreans schema for a family that does not belong
//! to it.

use mida_core::runner_config::packer_family;

/// Which evidence member's schema is being resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceMemberKind {
    Oep,
    Iat,
    Tls,
    Relocation,
    Exception,
    SectionRebuild,
    /// PE evidence is produced via the acceptance binary; the CLI-side dispatch
    /// keeps the variant so the family->schema table is complete (the
    /// acceptance `unpack-pe-evidence` command resolves the same id).
    #[allow(dead_code)]
    Pe,
}

/// The generic, family-agnostic member schema ids.
pub mod unpack {
    pub const OEP: &str = "mida.unpack-oep-evidence/v1";
    pub const IAT: &str = "mida.unpack-iat-evidence/v1";
    pub const TLS: &str = "mida.unpack-tls-evidence/v1";
    pub const RELOCATION: &str = "mida.unpack-relocation-evidence/v1";
    pub const EXCEPTION: &str = "mida.unpack-exception-evidence/v1";
    pub const SECTION_REBUILD: &str = "mida.unpack-section-rebuild-evidence/v1";
    pub const PE: &str = "mida.unpack-pe-evidence/v1";
}

/// The legacy Oreans member schema ids.
pub mod oreans {
    pub const OEP: &str = "mida.oreans-oep-evidence/v1";
    pub const IAT: &str = "mida.oreans-iat-evidence/v1";
    pub const TLS: &str = "mida.oreans-tls-evidence/v1";
    pub const RELOCATION: &str = "mida.oreans-relocation-evidence/v1";
    pub const EXCEPTION: &str = "mida.oreans-exception-evidence/v1";
    pub const SECTION_REBUILD: &str = "mida.oreans-section-rebuild-evidence/v1";
    pub const PE: &str = "mida.oreans-pe-evidence/v1";
}

/// The single family->member-schema dispatch. Oreans family resolves to the
/// legacy `mida.oreans-*` ids; any REGISTERED generic family resolves to the
/// `mida.unpack-*` ids. An unknown family fails closed (`Err`) — a producer
/// must never silently fall back to the Oreans schema.
pub fn member_schema_for_family(
    family: &str,
    kind: EvidenceMemberKind,
) -> Result<&'static str, String> {
    if packer_family::is_oreans_family(family) {
        return Ok(oreans_schema(kind));
    }
    if packer_family::is_generic_family(family) {
        return Ok(unpack_schema(kind));
    }
    Err(format!(
        "unknown packer family {family:?}; cannot choose a member evidence schema (fail-closed)"
    ))
}

fn oreans_schema(kind: EvidenceMemberKind) -> &'static str {
    match kind {
        EvidenceMemberKind::Oep => oreans::OEP,
        EvidenceMemberKind::Iat => oreans::IAT,
        EvidenceMemberKind::Tls => oreans::TLS,
        EvidenceMemberKind::Relocation => oreans::RELOCATION,
        EvidenceMemberKind::Exception => oreans::EXCEPTION,
        EvidenceMemberKind::SectionRebuild => oreans::SECTION_REBUILD,
        EvidenceMemberKind::Pe => oreans::PE,
    }
}

fn unpack_schema(kind: EvidenceMemberKind) -> &'static str {
    match kind {
        EvidenceMemberKind::Oep => unpack::OEP,
        EvidenceMemberKind::Iat => unpack::IAT,
        EvidenceMemberKind::Tls => unpack::TLS,
        EvidenceMemberKind::Relocation => unpack::RELOCATION,
        EvidenceMemberKind::Exception => unpack::EXCEPTION,
        EvidenceMemberKind::SectionRebuild => unpack::SECTION_REBUILD,
        EvidenceMemberKind::Pe => unpack::PE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oreans_family_resolves_oreans_member_schemas() {
        use mida_core::runner_config::packer_family;
        assert_eq!(
            member_schema_for_family(packer_family::OREANS, EvidenceMemberKind::Iat).unwrap(),
            "mida.oreans-iat-evidence/v1"
        );
        assert_eq!(
            member_schema_for_family(packer_family::OREANS, EvidenceMemberKind::Pe).unwrap(),
            "mida.oreans-pe-evidence/v1"
        );
        assert_eq!(
            member_schema_for_family(packer_family::OREANS, EvidenceMemberKind::Oep).unwrap(),
            "mida.oreans-oep-evidence/v1"
        );
    }

    #[test]
    fn generic_family_resolves_unpack_member_schemas() {
        use mida_core::runner_config::packer_family;
        assert_eq!(
            member_schema_for_family(packer_family::AHK_GTO, EvidenceMemberKind::Iat).unwrap(),
            "mida.unpack-iat-evidence/v1"
        );
        assert_eq!(
            member_schema_for_family(packer_family::AHK_GTO, EvidenceMemberKind::Pe).unwrap(),
            "mida.unpack-pe-evidence/v1"
        );
        assert_eq!(
            member_schema_for_family(packer_family::AHK_GTO, EvidenceMemberKind::SectionRebuild)
                .unwrap(),
            "mida.unpack-section-rebuild-evidence/v1"
        );
    }

    #[test]
    fn unknown_family_fails_closed() {
        assert!(member_schema_for_family("bogus", EvidenceMemberKind::Iat).is_err());
        assert!(member_schema_for_family("", EvidenceMemberKind::Pe).is_err());
    }

    /// A2: the family-aware dispatch stays in lockstep with the generic bundle
    /// assembler's `EXPECTED_MEMBER_SCHEMAS` — the two producer-side schema
    /// tables must never drift. (The acceptance consumer's
    /// `REQUIRED_UNPACK_MEMBERS` is independently locked by its own test; the
    /// consumer never depends on this crate.)
    #[test]
    fn dispatch_matches_generic_assembler_member_schemas() {
        use crate::unpacker::generic_bundle_assembler::EXPECTED_MEMBER_SCHEMAS;
        use mida_core::runner_config::packer_family;
        let member_kind = |name: &str| match name {
            "oep_evidence" => Some(EvidenceMemberKind::Oep),
            "iat_evidence" => Some(EvidenceMemberKind::Iat),
            "tls_evidence" => Some(EvidenceMemberKind::Tls),
            "relocation_evidence" => Some(EvidenceMemberKind::Relocation),
            "exception_evidence" => Some(EvidenceMemberKind::Exception),
            "section_rebuild_evidence" => Some(EvidenceMemberKind::SectionRebuild),
            "pe_evidence" => Some(EvidenceMemberKind::Pe),
            "transform_manifest" => None, // shared, versioned; not in the dispatch enum
            _ => panic!("unexpected member name {name:?}"),
        };
        for (name, expected_schema) in EXPECTED_MEMBER_SCHEMAS {
            match member_kind(name) {
                None => assert_eq!(expected_schema, "mida.transform-manifest/v0"),
                Some(kind) => {
                    let generic = member_schema_for_family(packer_family::AHK_GTO, kind).unwrap();
                    assert_eq!(
                        generic, expected_schema,
                        "dispatch generic schema for {name} drifts from generic_bundle_assembler"
                    );
                    let oreans = member_schema_for_family(packer_family::OREANS, kind).unwrap();
                    assert!(
                        oreans.starts_with("mida.oreans-"),
                        "Oreans schema for {name} must be mida.oreans-*: {oreans}"
                    );
                }
            }
        }
    }
}
