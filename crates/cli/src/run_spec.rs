//! Actual run-config binding (P6.3-A): the runner-config envelope must bind
//! the configuration the unpack pipeline will really apply, not a detached
//! frozen copy.
//!
//! - [`runner_config_from_unpack_args`] builds the canonical
//!   [`mida_core::runner_config::RunnerConfig`] from the *parsed* `/unpack`
//!   arguments (profile, OEP policy, container restore, shrink, data
//!   sections, pure rebuild, capture-policy digest, backend, timeout,
//!   isolation, tool revision, CLI binary SHA-256). The Origin Macro
//!   pure-rebuild default (operator decision D3) is resolved into the config
//!   *before* the digest is computed, so the digest is an honest identity of
//!   what the run will do — an envelope that says `pure_rebuild=false` can
//!   never match a run that silently resolved to `true`.
//! - [`runner_config_from_unpack_args_family`] additionally binds the packer
//!   family. The legacy family-less API ([`runner_config_from_unpack_args`])
//!   is preserved as an Oreans-compat wrapper (family defaults to Oreans).
//! - [`frozen_runner_config`] is the P7 fixed-mode default policy for the
//!   Oreans family; [`frozen_runner_config_for_family`] builds the fixed-mode
//!   policy for an explicit family (GTO uses the generic contract). The
//!   staging command emits the envelope from exactly this policy unless the
//!   operator binds explicit run-config flags.
//! - [`frozen_run_policy`] resolves the fixed-mode expectation for a given
//!   protected input (Origin Macro → `pure_rebuild=true`, others → `false`),
//!   so the fixed-mode comparison includes the D3 default behavior.
//! - [`policy_matches`] compares two policies field-by-field (ignoring only
//!   the runtime-filled `tool_revision` / `cli_binary_sha256`). The launch
//!   boundary applies it fail-closed: any parameter differing from the
//!   fixed-mode expectation blocks the launch.

use std::path::Path;

use mida_core::runner_config::{packer_family, RunnerConfig};
use mida_pe::{ContainerRestoreMode, DumpProfile, OepPolicy};

/// Enabled feature set of this CLI build (canonical order is applied at
/// digest time).
pub fn current_features() -> Vec<String> {
    let mut features = vec!["default".to_string()];
    if cfg!(feature = "gto-product-recovery") {
        features.push("gto-product-recovery".to_string());
    }
    features
}

/// Map the parsed `--oep` policy to its canonical identity string.
pub fn oep_policy_id(policy: OepPolicy) -> String {
    match policy {
        OepPolicy::Crt => "crt".to_string(),
        OepPolicy::Captured => "captured".to_string(),
        OepPolicy::Fixed(rva) => format!("fixed:0x{rva:x}"),
    }
}

/// Map the parsed `--container-restore` mode to its canonical identity string.
pub fn container_restore_id(mode: ContainerRestoreMode) -> String {
    match mode {
        ContainerRestoreMode::Off => "off".to_string(),
        ContainerRestoreMode::PostCrt => "post-crt".to_string(),
        ContainerRestoreMode::PreCrt => "tls-pre".to_string(),
    }
}

/// Map the parsed `--profile` to its canonical identity string. The profile
/// is part of the feature identity (`features` list entry).
pub fn profile_id(profile: DumpProfile) -> String {
    match profile {
        DumpProfile::OreansClassic => "oreans-classic".to_string(),
        DumpProfile::AhkGtoExperimental => "ahk-gto-experimental".to_string(),
    }
}

/// Full feature identity: build features + dump profile.
pub fn feature_identity(profile: DumpProfile) -> Vec<String> {
    let mut features = current_features();
    features.push(profile_id(profile));
    features
}

/// Full feature identity for an explicit family: build features + profile +
/// family feature marker. GTO configs carry `family=ahk-gto` (and vice versa),
/// so a GTO run and an Oreans run never share a feature identity even when the
/// dump profile happens to align.
pub fn feature_identity_for_family(profile: DumpProfile, family: &str) -> Vec<String> {
    let mut features = feature_identity(profile);
    features.push(format!("family={family}"));
    features
}

/// The evidence-bundle schema id for a packer family. Oreans routes to the
/// legacy `mida.oreans-evidence-bundle/v2`; GTO routes to the generic
/// `mida.unpack-evidence-bundle/v1`. Unknown families fail closed (empty).
pub fn evidence_bundle_schema_for_family(family: &str) -> String {
    match family {
        packer_family::OREANS => "mida.oreans-evidence-bundle/v2".to_string(),
        packer_family::AHK_GTO => "mida.unpack-evidence-bundle/v1".to_string(),
        _ => String::new(),
    }
}

/// The gate-schema id for a packer family. Oreans keeps the v8 two-sample gate;
/// GTO has no gate consumer yet (its products are not accepted).
pub fn gate_schema_for_family(family: &str) -> String {
    match family {
        packer_family::OREANS => "mida.oreans-two-sample-gate/v8".to_string(),
        packer_family::AHK_GTO => "mida.unpack-gate/none".to_string(),
        _ => String::new(),
    }
}

/// Build the canonical runner config from the *actual* parsed `/unpack`
/// arguments and an explicit packer family.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn runner_config_from_unpack_args_family(
    family: &str,
    oep_policy: OepPolicy,
    container_restore: ContainerRestoreMode,
    profile: DumpProfile,
    shrink: bool,
    data_sections: bool,
    pure_rebuild: bool,
    capture_policy_digest: &str,
    tool_revision: &str,
    cli_binary_sha256: &str,
) -> RunnerConfig {
    use mida_core::runner_config::IsolationConfig;
    RunnerConfig {
        packer_family: family.to_string(),
        tool_revision: tool_revision.to_string(),
        cli_binary_sha256: cli_binary_sha256.to_string(),
        features: feature_identity_for_family(profile, family),
        debugger_backend: "windows_debug_api".to_string(),
        oep_policy: oep_policy_id(oep_policy),
        container_restore: container_restore_id(container_restore),
        shrink,
        data_sections,
        pure_rebuild,
        capture_policy_digest: capture_policy_digest.to_lowercase(),
        iat_fix_strategy: "v3-trace".to_string(),
        timeout_secs: 120,
        isolation: IsolationConfig {
            workspace_policy: "isolated-temp".to_string(),
            process_tree_policy: "single-process".to_string(),
            network_policy: "blocked".to_string(),
        },
        attempt_numbering: "continuous-1-based".to_string(),
        evidence_bundle_schema: evidence_bundle_schema_for_family(family),
        gate_schema: gate_schema_for_family(family),
        env_allowlist: vec!["CARGO_TARGET_DIR".to_string()],
    }
}

/// Build the canonical runner config from the *actual* parsed `/unpack`
/// arguments. `pure_rebuild` must already be the resolved value (CLI flags +
/// Origin Macro D3 default); `capture_policy_digest` is the SHA-256 of the
/// capture-policy file bytes (empty when no policy is loaded);
/// `tool_revision` / `cli_binary_sha256` are the runtime pinning inputs.
///
/// Oreans-compat wrapper: this family-less API binds the Oreans family (the
/// legacy contract), matching the pre-family behavior exactly. GTO runs use
/// [`runner_config_from_unpack_args_family`].
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn runner_config_from_unpack_args(
    oep_policy: OepPolicy,
    container_restore: ContainerRestoreMode,
    profile: DumpProfile,
    shrink: bool,
    data_sections: bool,
    pure_rebuild: bool,
    capture_policy_digest: &str,
    tool_revision: &str,
    cli_binary_sha256: &str,
) -> RunnerConfig {
    runner_config_from_unpack_args_family(
        packer_family::OREANS,
        oep_policy,
        container_restore,
        profile,
        shrink,
        data_sections,
        pure_rebuild,
        capture_policy_digest,
        tool_revision,
        cli_binary_sha256,
    )
}

/// The P7 fixed-mode default policy of the two-sample Oreans runner.
///
/// The staging command emits the envelope from exactly this policy unless
/// explicit run-config flags are bound; the launch boundary compares the
/// actual policy against [`frozen_run_policy`] and fails closed on any
/// divergence.
#[must_use]
pub fn frozen_runner_config() -> RunnerConfig {
    frozen_runner_config_for_family(packer_family::OREANS)
}

/// The fixed-mode default policy for an explicit packer family. GTO and
/// Oreans carry distinct `packer_family`, feature, and evidence-schema
/// identities, so their frozen policies — and their runner digests — never
/// collide.
#[must_use]
pub fn frozen_runner_config_for_family(family: &str) -> RunnerConfig {
    use mida_core::runner_config::IsolationConfig;
    RunnerConfig {
        packer_family: family.to_string(),
        tool_revision: String::new(),     // filled at emission time
        cli_binary_sha256: String::new(), // filled at emission time
        features: feature_identity_for_family(DumpProfile::OreansClassic, family),
        debugger_backend: "windows_debug_api".to_string(),
        oep_policy: "captured".to_string(),
        container_restore: "off".to_string(),
        shrink: true,
        data_sections: false,
        pure_rebuild: false,
        capture_policy_digest: String::new(),
        iat_fix_strategy: "v3-trace".to_string(),
        timeout_secs: 120,
        isolation: IsolationConfig {
            workspace_policy: "isolated-temp".to_string(),
            process_tree_policy: "single-process".to_string(),
            network_policy: "blocked".to_string(),
        },
        attempt_numbering: "continuous-1-based".to_string(),
        evidence_bundle_schema: evidence_bundle_schema_for_family(family),
        gate_schema: gate_schema_for_family(family),
        env_allowlist: vec!["CARGO_TARGET_DIR".to_string()],
    }
}

/// The fixed-mode expectation for one protected input under the Oreans family:
/// the frozen policy with the Origin Macro pure-rebuild default (D3) resolved
/// for `input`. This is what the launch boundary compares the actual policy
/// against — the Origin default is part of the configuration identity, so an
/// envelope staged for `pure_rebuild=false` can never authorize a run that
/// silently resolves to `true` (and vice versa).
#[must_use]
pub fn frozen_run_policy(input: &Path) -> RunnerConfig {
    let mut policy = frozen_runner_config();
    let (pure, _) = crate::origin_pure::resolve_pure_rebuild(input, false, false);
    policy.pure_rebuild = pure;
    policy
}

/// Family-aware fixed-mode expectation: the frozen policy for `family` with the
/// Origin Macro pure-rebuild default resolved for `input`.
#[must_use]
pub fn frozen_run_policy_for_family(input: &Path, family: &str) -> RunnerConfig {
    let mut policy = frozen_runner_config_for_family(family);
    let (pure, _) = crate::origin_pure::resolve_pure_rebuild(input, false, false);
    policy.pure_rebuild = pure;
    policy
}

/// Field-by-field policy comparison (P7 fixed mode). Compares every field
/// except the runtime-filled `tool_revision` / `cli_binary_sha256`. Returns
/// the first divergence reason, or `None` when the policies match.
pub fn policy_matches(actual: &RunnerConfig, expected: &RunnerConfig) -> Option<String> {
    if actual.packer_family != expected.packer_family {
        return Some(format!(
            "packer_family {:?} != fixed-mode {:?}",
            actual.packer_family, expected.packer_family
        ));
    }
    if actual.features != expected.features {
        return Some(format!(
            "features {:?} != fixed-mode {:?}",
            actual.features, expected.features
        ));
    }
    if actual.debugger_backend != expected.debugger_backend {
        return Some(format!(
            "debugger_backend {:?} != fixed-mode {:?}",
            actual.debugger_backend, expected.debugger_backend
        ));
    }
    if actual.oep_policy != expected.oep_policy {
        return Some(format!(
            "oep_policy {:?} != fixed-mode {:?}",
            actual.oep_policy, expected.oep_policy
        ));
    }
    if actual.container_restore != expected.container_restore {
        return Some(format!(
            "container_restore {:?} != fixed-mode {:?}",
            actual.container_restore, expected.container_restore
        ));
    }
    if actual.shrink != expected.shrink {
        return Some(format!(
            "shrink {} != fixed-mode {}",
            actual.shrink, expected.shrink
        ));
    }
    if actual.data_sections != expected.data_sections {
        return Some(format!(
            "data_sections {} != fixed-mode {}",
            actual.data_sections, expected.data_sections
        ));
    }
    if actual.pure_rebuild != expected.pure_rebuild {
        return Some(format!(
            "pure_rebuild {} != fixed-mode {} (includes the Origin Macro D3 default)",
            actual.pure_rebuild, expected.pure_rebuild
        ));
    }
    if actual.capture_policy_digest != expected.capture_policy_digest {
        return Some(format!(
            "capture_policy_digest {} != fixed-mode {}",
            actual.capture_policy_digest, expected.capture_policy_digest
        ));
    }
    if actual.iat_fix_strategy != expected.iat_fix_strategy {
        return Some(format!(
            "iat_fix_strategy {:?} != fixed-mode {:?}",
            actual.iat_fix_strategy, expected.iat_fix_strategy
        ));
    }
    if actual.timeout_secs != expected.timeout_secs {
        return Some(format!(
            "timeout_secs {} != fixed-mode {}",
            actual.timeout_secs, expected.timeout_secs
        ));
    }
    if actual.isolation != expected.isolation {
        return Some(format!(
            "isolation {:?} != fixed-mode {:?}",
            actual.isolation, expected.isolation
        ));
    }
    if actual.attempt_numbering != expected.attempt_numbering {
        return Some(format!(
            "attempt_numbering {:?} != fixed-mode {:?}",
            actual.attempt_numbering, expected.attempt_numbering
        ));
    }
    if actual.evidence_bundle_schema != expected.evidence_bundle_schema {
        return Some(format!(
            "evidence_bundle_schema {:?} != fixed-mode {:?}",
            actual.evidence_bundle_schema, expected.evidence_bundle_schema
        ));
    }
    if actual.gate_schema != expected.gate_schema {
        return Some(format!(
            "gate_schema {:?} != fixed-mode {:?}",
            actual.gate_schema, expected.gate_schema
        ));
    }
    if actual.env_allowlist != expected.env_allowlist {
        return Some(format!(
            "env_allowlist {:?} != fixed-mode {:?}",
            actual.env_allowlist, expected.env_allowlist
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> RunnerConfig {
        runner_config_from_unpack_args(
            OepPolicy::Captured,
            ContainerRestoreMode::Off,
            DumpProfile::OreansClassic,
            true,
            false,
            false,
            "",
            "oreans/two-sample-mainline@test",
            &"a".repeat(64),
        )
    }

    #[test]
    fn actual_config_identity_covers_every_resolved_parameter() {
        let base = sample_policy();
        let d0 = mida_core::runner_config::runner_config_digest(&base);

        let mut cases = Vec::new();
        let mut c = base.clone();
        c.oep_policy = "crt".to_string();
        cases.push((
            "oep_policy",
            d0.clone(),
            mida_core::runner_config::runner_config_digest(&c),
        ));
        let mut c = base.clone();
        c.container_restore = "post-crt".to_string();
        cases.push((
            "container_restore",
            d0.clone(),
            mida_core::runner_config::runner_config_digest(&c),
        ));
        let mut c = base.clone();
        c.shrink = false;
        cases.push((
            "shrink",
            d0.clone(),
            mida_core::runner_config::runner_config_digest(&c),
        ));
        let mut c = base.clone();
        c.data_sections = true;
        cases.push((
            "data_sections",
            d0.clone(),
            mida_core::runner_config::runner_config_digest(&c),
        ));
        let mut c = base.clone();
        c.pure_rebuild = true;
        cases.push((
            "pure_rebuild",
            d0.clone(),
            mida_core::runner_config::runner_config_digest(&c),
        ));
        let mut c = base.clone();
        c.capture_policy_digest = "f".repeat(64);
        cases.push((
            "capture_policy_digest",
            d0.clone(),
            mida_core::runner_config::runner_config_digest(&c),
        ));
        let mut c = base.clone();
        c.features = vec!["default".to_string(), "gto-product-recovery".to_string()];
        cases.push((
            "features",
            d0.clone(),
            mida_core::runner_config::runner_config_digest(&c),
        ));

        for (label, before, after) in cases {
            assert_ne!(before, after, "{label} must change the config identity");
        }
    }

    #[test]
    fn origin_pure_default_is_part_of_the_config_identity() {
        // The resolved pure-rebuild value (which carries the Origin Macro D3
        // default) must change the digest: an envelope staged as
        // pure_rebuild=false can never bind a run that resolves to true.
        let legacy = runner_config_from_unpack_args(
            OepPolicy::Captured,
            ContainerRestoreMode::Off,
            DumpProfile::OreansClassic,
            true,
            false,
            false,
            "",
            "rev",
            &"a".repeat(64),
        );
        let pure = runner_config_from_unpack_args(
            OepPolicy::Captured,
            ContainerRestoreMode::Off,
            DumpProfile::OreansClassic,
            true,
            false,
            true,
            "",
            "rev",
            &"a".repeat(64),
        );
        assert_ne!(
            mida_core::runner_config::runner_config_digest(&legacy),
            mida_core::runner_config::runner_config_digest(&pure)
        );
    }

    #[test]
    fn fixed_mode_policy_includes_origin_default() {
        // Non-Origin input: legacy default.
        let p = frozen_run_policy(Path::new("does-not-exist.bin"));
        assert!(!p.pure_rebuild);
        assert!(policy_matches(&frozen_runner_config(), &p).is_none());
        // The frozen default itself matches a legacy-resolved policy.
        assert!(policy_matches(&sample_policy(), &frozen_run_policy(Path::new("x.bin"))).is_none());
    }

    #[test]
    fn policy_matches_rejects_every_divergent_field() {
        let expected = frozen_run_policy(Path::new("x.bin"));
        let mut c = sample_policy();
        c.shrink = false;
        assert!(policy_matches(&c, &expected).unwrap().contains("shrink"));
        let mut c = sample_policy();
        c.data_sections = true;
        assert!(policy_matches(&c, &expected)
            .unwrap()
            .contains("data_sections"));
        let mut c = sample_policy();
        c.oep_policy = "crt".to_string();
        assert!(policy_matches(&c, &expected)
            .unwrap()
            .contains("oep_policy"));
        let mut c = sample_policy();
        c.container_restore = "post-crt".to_string();
        assert!(policy_matches(&c, &expected)
            .unwrap()
            .contains("container_restore"));
        let mut c = sample_policy();
        c.pure_rebuild = true;
        assert!(policy_matches(&c, &expected)
            .unwrap()
            .contains("pure_rebuild"));
        let mut c = sample_policy();
        c.capture_policy_digest = "f".repeat(64);
        assert!(policy_matches(&c, &expected)
            .unwrap()
            .contains("capture_policy_digest"));
        let mut c = sample_policy();
        c.features = vec!["gto-product-recovery".to_string()];
        assert!(policy_matches(&c, &expected).unwrap().contains("features"));
        let mut c = sample_policy();
        c.timeout_secs = 60;
        assert!(policy_matches(&c, &expected)
            .unwrap()
            .contains("timeout_secs"));
    }

    #[test]
    fn runtime_pinning_fields_are_ignored_by_policy_matches() {
        let mut a = sample_policy();
        let mut b = sample_policy();
        a.tool_revision = "rev-a".to_string();
        b.tool_revision = "rev-b".to_string();
        a.cli_binary_sha256 = "a".repeat(64);
        b.cli_binary_sha256 = "b".repeat(64);
        assert!(policy_matches(&a, &b).is_none());
    }

    #[test]
    fn oep_and_profile_ids_are_canonical() {
        assert_eq!(oep_policy_id(OepPolicy::Captured), "captured");
        assert_eq!(oep_policy_id(OepPolicy::Crt), "crt");
        assert_eq!(oep_policy_id(OepPolicy::Fixed(0x13e0)), "fixed:0x13e0");
        assert_eq!(container_restore_id(ContainerRestoreMode::Off), "off");
        assert_eq!(
            container_restore_id(ContainerRestoreMode::PostCrt),
            "post-crt"
        );
        assert_eq!(
            container_restore_id(ContainerRestoreMode::PreCrt),
            "tls-pre"
        );
        assert_eq!(profile_id(DumpProfile::OreansClassic), "oreans-classic");
        assert_eq!(
            profile_id(DumpProfile::AhkGtoExperimental),
            "ahk-gto-experimental"
        );
    }

    /// G2: the family is part of the config identity. GTO and Oreans must have
    /// distinguishable features, frozen policies, and runner digests.
    #[test]
    fn gto_and_oreans_policies_and_digests_differ() {
        let oreans = runner_config_from_unpack_args(
            OepPolicy::Captured,
            ContainerRestoreMode::Off,
            DumpProfile::AhkGtoExperimental,
            true,
            false,
            false,
            "",
            "rev",
            &"a".repeat(64),
        );
        let gto = runner_config_from_unpack_args_family(
            packer_family::AHK_GTO,
            OepPolicy::Captured,
            ContainerRestoreMode::Off,
            DumpProfile::AhkGtoExperimental,
            true,
            false,
            false,
            "",
            "rev",
            &"a".repeat(64),
        );
        assert_eq!(oreans.packer_family, packer_family::OREANS);
        assert_eq!(gto.packer_family, packer_family::AHK_GTO);
        // Feature identity differs because family is a feature marker.
        assert_ne!(oreans.features, gto.features);
        assert!(oreans.features.iter().any(|f| f == "family=oreans_themida"));
        assert!(gto.features.iter().any(|f| f == "family=ahk_gto"));
        // Evidence/gate schema differ (Oreans keeps v2/v8; GTO is generic).
        assert_eq!(
            oreans.evidence_bundle_schema,
            "mida.oreans-evidence-bundle/v2"
        );
        assert_eq!(gto.evidence_bundle_schema, "mida.unpack-evidence-bundle/v1");
        assert_eq!(oreans.gate_schema, "mida.oreans-two-sample-gate/v8");
        // Digests differ.
        assert_ne!(
            mida_core::runner_config::runner_config_digest(&oreans),
            mida_core::runner_config::runner_config_digest(&gto)
        );
    }

    /// G2: the frozen fixed-mode policies (and their digests) differ by family.
    #[test]
    fn frozen_policies_differ_by_family() {
        let oreans = frozen_runner_config_for_family(packer_family::OREANS);
        let gto = frozen_runner_config_for_family(packer_family::AHK_GTO);
        assert_eq!(oreans.packer_family, packer_family::OREANS);
        assert_eq!(gto.packer_family, packer_family::AHK_GTO);
        assert_ne!(
            mida_core::runner_config::runner_config_digest(&oreans),
            mida_core::runner_config::runner_config_digest(&gto)
        );
        assert_eq!(
            frozen_runner_config().packer_family,
            packer_family::OREANS,
            "the no-arg frozen builder remains the Oreans wrapper"
        );
        // policy_matches treats family as binding (fail-closed on cross-family).
        let mut gto2 = oreans.clone();
        gto2.packer_family = packer_family::AHK_GTO.to_string();
        assert!(
            policy_matches(&gto2, &oreans)
                .unwrap()
                .contains("packer_family"),
            "a GTO policy must never match the Oreans frozen policy"
        );
    }

    /// G2: schema resolution for unknown families fails closed.
    #[test]
    fn unknown_family_fails_closed_on_schema_resolution() {
        assert_eq!(evidence_bundle_schema_for_family("bogus"), "");
        assert_eq!(gate_schema_for_family("bogus"), "");
    }
}
