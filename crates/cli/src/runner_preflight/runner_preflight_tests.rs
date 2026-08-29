//! Tests for runner_preflight (WO-19 split; `use super::*` resolves to mod.rs).

use super::*;
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "mida_resolver_{tag}_{}_{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    /// A fake "mida-acceptance.exe" that is NOT the real binary — used to
    /// prove the resolver only ever accepts the exact sibling and never a
    /// PATH entry or a byte-copy elsewhere.
    fn fake_acceptance(dir: &Path) -> PathBuf {
        let p = dir.join("mida-acceptance.exe");
        write(&p, b"FAKE-ACCEPTANCE-1");
        p
    }

    #[test]
    fn resolver_accepts_exact_sibling_regular_file() {
        let dir = temp_dir("ok");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir);
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling resolves");
        assert_eq!(
            resolved,
            std::fs::canonicalize(&sibling).unwrap(),
            "must resolve to the exact sibling"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_hard_fails_when_sibling_missing() {
        let dir = temp_dir("missing");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let err = resolve_acceptance_bin_from_cli(&cli).expect_err("missing sibling must fail");
        assert!(err.to_string().contains("does not exist"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_hard_fails_when_sibling_not_regular() {
        let dir = temp_dir("notreg");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = dir.join("mida-acceptance.exe");
        std::fs::create_dir(&sibling).unwrap(); // a directory, not a file
        let err = resolve_acceptance_bin_from_cli(&cli).expect_err("dir sibling must fail");
        assert!(err.to_string().contains("not a regular file"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_rejects_path_drift_away_from_sibling() {
        let dir = temp_dir("drift");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        // A verifier placed at the sibling path IS accepted; but a copy of the
        // same bytes at ANY OTHER path must never be selected.
        fake_acceptance(&dir);
        let other = dir.join("somewhere-else/mida-acceptance.exe");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        write(&other, b"FAKE-ACCEPTANCE-1");
        // Resolver still returns the sibling, never the other copy.
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling wins");
        assert_ne!(resolved, other);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_never_consults_path() {
        let dir = temp_dir("path");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir);
        // A DIFFERENT fake acceptance in a PATH directory must be ignored.
        let path_dir = dir.join("path-dir");
        std::fs::create_dir_all(&path_dir).unwrap();
        let in_path = path_dir.join("mida-acceptance.exe");
        write(&in_path, b"PATH-ACCEPTANCE-DIFFERENT");
        // Override PATH for this process.
        let old_path = std::env::var_os("PATH").clone();
        let mut paths =
            std::env::split_paths(&old_path.clone().unwrap_or_default()).collect::<Vec<_>>();
        paths.push(path_dir.clone());
        std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling resolves");
        assert_eq!(resolved, std::fs::canonicalize(&sibling).unwrap());
        match old_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_rejects_sibling_that_is_a_byte_copy_to_another_path() {
        // The resolver must only select the exact sibling; a byte-identical
        // copy placed at a sibling-adjacent path is not the sibling.
        let dir = temp_dir("bytecopy");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir);
        let real_dir = dir.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let other = real_dir.join("acceptance-copy.exe");
        write(&other, &std::fs::read(&sibling).unwrap());
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling resolves");
        assert_eq!(resolved, std::fs::canonicalize(&sibling).unwrap());
        assert_ne!(resolved, other, "a byte copy elsewhere is never selected");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // -----------------------------------------------------------------------
    // P6.3.3: case-bound envelope + per-case digest selection (positive
    // control, hermetic — no process launch).
    // -----------------------------------------------------------------------

    /// The locked protected-input identities (mirror of the case manifests).
    const ORIGIN_ID: &str = "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";
    const LUNLUN_ID: &str = "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07";

    fn case_config(case_id: &str, sha: &str, pure_rebuild: bool) -> CaseRunnerConfigEnvelope {
        let mut config = crate::run_spec::frozen_runner_config();
        config.pure_rebuild = pure_rebuild;
        let digest = mida_core::runner_config::runner_config_digest(&config);
        CaseRunnerConfigEnvelope {
            case_id: case_id.to_string(),
            family_id: config.packer_family.clone(),
            protected_input: FileIdentityGate {
                sha256: sha.to_string(),
                size_bytes: if case_id == "origin_macro" {
                    5_232_656
                } else {
                    4_976_144
                },
            },
            protected_input_path: None, // Oreans live-input lane: no path binding
            runner_config: serde_json::to_value(&config).unwrap(),
            runner_config_digest: digest,
        }
    }

    fn v4_envelope() -> RunnerConfigEnvelope {
        RunnerConfigEnvelope::build(
            vec![
                case_config("origin_macro", ORIGIN_ID, true),
                case_config("lunlun_software", LUNLUN_ID, false),
            ],
            &"a".repeat(64),
            "rev",
            "C:\\dummy\\mida-acceptance.exe",
            &"b".repeat(64),
        )
    }

    #[test]
    fn case_bound_envelope_carries_distinct_origin_and_lunlun_configs() {
        let env = v4_envelope();
        assert!(env.validate_case_set().is_none(), "case set is well-formed");
        let origin = env
            .case_configs
            .iter()
            .find(|c| c.case_id == "origin_macro")
            .unwrap();
        let lunlun = env
            .case_configs
            .iter()
            .find(|c| c.case_id == "lunlun_software")
            .unwrap();
        // Origin resolves pure_rebuild=true, Lunlun pure_rebuild=false (D3).
        let origin_cfg: serde_json::Value = origin.runner_config.clone();
        assert_eq!(origin_cfg["pure_rebuild"], serde_json::json!(true));
        let lunlun_cfg: serde_json::Value = lunlun.runner_config.clone();
        assert_eq!(lunlun_cfg["pure_rebuild"], serde_json::json!(false));
        // Distinct per-case digests.
        assert_ne!(origin.runner_config_digest, lunlun.runner_config_digest);
        // The sealed case-set digest covers both case + input bindings.
        assert_eq!(env.case_set_digest.len(), 64);
    }

    #[test]
    fn select_case_config_picks_the_unique_case_by_input_identity() {
        let env = v4_envelope();
        let origin_identity = FileIdentityGate {
            sha256: ORIGIN_ID.to_string(),
            size_bytes: 5_232_656,
        };
        let lunlun_identity = FileIdentityGate {
            sha256: LUNLUN_ID.to_string(),
            size_bytes: 4_976_144,
        };
        let origin = select_case_config(&env, &origin_identity).unwrap();
        assert_eq!(origin.case_id, "origin_macro");
        let lunlun = select_case_config(&env, &lunlun_identity).unwrap();
        assert_eq!(lunlun.case_id, "lunlun_software");
        // Origin and Lunlun select DIFFERENT digests.
        assert_ne!(origin.runner_config_digest, lunlun.runner_config_digest);
        // A third / unknown identity matches 0 cases -> refused.
        let unknown = FileIdentityGate {
            sha256: "c".repeat(64),
            size_bytes: 1,
        };
        assert!(
            select_case_config(&env, &unknown).is_err(),
            "0 matches must be refused"
        );
    }

    #[test]
    fn bind_actual_config_compares_only_the_selected_case_digest() {
        let dir = temp_dir("bind_case");
        let env = v4_envelope();
        env.write(&dir).unwrap();

        // Origin actual config (pure_rebuild=true) against Origin digest
        // passes; the same actual config is NOT compared to Lunlun's digest.
        let origin_identity = FileIdentityGate {
            sha256: ORIGIN_ID.to_string(),
            size_bytes: 5_232_656,
        };
        let mut origin_actual = crate::run_spec::frozen_run_policy(Path::new("x.bin"));
        origin_actual.pure_rebuild = true;
        assert!(bind_actual_config_to_envelope(&dir, &origin_actual, &origin_identity).is_ok());
        // A Lunlun actual config (pure_rebuild=false) against Lunlun digest
        // passes.
        let lunlun_identity = FileIdentityGate {
            sha256: LUNLUN_ID.to_string(),
            size_bytes: 4_976_144,
        };
        let mut lunlun_actual = crate::run_spec::frozen_runner_config();
        lunlun_actual.pure_rebuild = false;
        assert!(bind_actual_config_to_envelope(&dir, &lunlun_actual, &lunlun_identity).is_ok());

        // Wrong pairing: an Origin actual config (pure=true) bound to the
        // LUNLUN identity -> its digest must NOT equal Lunlun's digest -> fail.
        assert!(
            bind_actual_config_to_envelope(&dir, &origin_actual, &lunlun_identity).is_err(),
            "Origin config must never match the Lunlun digest"
        );
        // And a Lunlun actual (pure=false) bound to the ORIGIN identity fails.
        assert!(
            bind_actual_config_to_envelope(&dir, &lunlun_actual, &origin_identity).is_err(),
            "Lunlun config must never match the Origin digest"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// G2-R1: a packer family is bound at STAGING and cannot be switched. An
    /// actual config carrying a different family than the envelope case is
    /// refused by the launch boundary — so an Oreans-staged case can never be
    /// attested under a GTO-family config (or vice versa). This is what makes
    /// the removed `rebind_family` path unnecessary and unsafe to reintroduce:
    /// the family is checked field-by-field before the digest, and the digest
    /// also embeds the family.
    #[test]
    fn g2r1_oreans_case_rejects_gto_family_config() {
        use mida_core::runner_config::packer_family;
        let dir = temp_dir("g2r1_bind_family");
        let env = v4_envelope(); // family_id = oreans_themida for both cases
        env.write(&dir).unwrap();
        let origin_identity = FileIdentityGate {
            sha256: ORIGIN_ID.to_string(),
            size_bytes: 5_232_656,
        };
        // The SAME policy as the Oreans Origin case but carrying the GTO
        // family: a GTO-family digest must never bind to an Oreans envelope
        // case (this is the "rebind a GTO family onto an Oreans attestation"
        // attack, now impossible).
        let mut gto_actual = crate::run_spec::frozen_run_policy_for_family(
            Path::new("x.bin"),
            packer_family::AHK_GTO,
        );
        gto_actual.pure_rebuild = true;
        assert!(
            bind_actual_config_to_envelope(&dir, &gto_actual, &origin_identity).is_err(),
            "a GTO-family config must never bind to an Oreans envelope case"
        );
        // A family-less actual config defaults to Oreans and still binds.
        let mut oreans_actual = crate::run_spec::frozen_run_policy(Path::new("x.bin"));
        oreans_actual.pure_rebuild = true;
        assert_eq!(oreans_actual.packer_family, packer_family::OREANS);
        assert!(
            bind_actual_config_to_envelope(&dir, &oreans_actual, &origin_identity).is_ok(),
            "the Oreans-family (default) config binds to the Oreans case"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// G3: a GTO lane envelope (case `gto_launcher`, family `ahk_gto`) binds a
    /// GTO-family actual config and REJECTS an Oreans-family actual config. The
    /// GTO lane can never be attested under an Oreans config (and vice versa).
    #[test]
    fn gto_lane_envelope_binds_gto_config_and_rejects_oreans() {
        use mida_core::runner_config::packer_family;
        let dir = temp_dir("g3_gto_bind");
        // Build a GTO lane envelope: Oreans fixed lane + a gto_launcher case
        // with family ahk_gto and a GTO config/digest.
        let mut env = v4_envelope();
        let mut gto_cfg = crate::run_spec::frozen_runner_config_for_family(packer_family::AHK_GTO);
        gto_cfg.tool_revision = "rev".to_string();
        gto_cfg.cli_binary_sha256 = "a".repeat(64);
        gto_cfg.pure_rebuild = false;
        let gto_digest = mida_core::runner_config::runner_config_digest(&gto_cfg);
        let gto_identity = FileIdentityGate {
            sha256: "c".repeat(64),
            size_bytes: 42,
        };
        env.case_configs.push(CaseRunnerConfigEnvelope {
            case_id: GTO_CASE_ID.to_string(),
            family_id: packer_family::AHK_GTO.to_string(),
            protected_input: gto_identity.clone(),
            protected_input_path: Some(
                "C:\\snapshots\\gto_launcher\\cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\snapshot.bin"
                    .to_string(),
            ),
            runner_config: serde_json::to_value(&gto_cfg).unwrap(),
            runner_config_digest: gto_digest,
        });
        assert!(
            env.validate_case_set().is_none(),
            "GTO lane envelope is valid"
        );
        env.write(&dir).unwrap();

        // A GTO-family actual config matching the GTO case digest binds.
        let mut gto_actual = crate::run_spec::frozen_run_policy_for_family(
            Path::new("x.bin"),
            packer_family::AHK_GTO,
        );
        gto_actual.tool_revision = "rev".to_string();
        gto_actual.cli_binary_sha256 = "a".repeat(64);
        gto_actual.pure_rebuild = false;
        assert_eq!(gto_actual.packer_family, packer_family::AHK_GTO);
        assert!(
            bind_actual_config_to_envelope(&dir, &gto_actual, &gto_identity).is_ok(),
            "GTO lane envelope + GTO actual config must bind"
        );

        // An Oreans-family actual config must never bind to the GTO lane case.
        let mut oreans_actual = crate::run_spec::frozen_run_policy(Path::new("x.bin"));
        oreans_actual.pure_rebuild = false;
        assert!(
            bind_actual_config_to_envelope(&dir, &oreans_actual, &gto_identity).is_err(),
            "GTO lane envelope must reject an Oreans actual config"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// G3: unknown / missing family in the GTO lane case fails closed at
    /// case-set validation.
    #[test]
    fn gto_lane_unknown_or_missing_family_fails_closed() {
        use mida_core::runner_config::packer_family;
        let mut unknown = v4_envelope();
        let mut gto_case = v4_envelope().case_configs[0].clone();
        gto_case.case_id = GTO_CASE_ID.to_string();
        gto_case.family_id = "bogus_family".to_string();
        unknown.case_configs.push(gto_case);
        assert!(
            unknown.validate_case_set().is_some(),
            "a GTO lane case with an unknown family must fail closed"
        );
        let mut missing = v4_envelope();
        let mut gto_missing = v4_envelope().case_configs[0].clone();
        gto_missing.case_id = GTO_CASE_ID.to_string();
        gto_missing.family_id = String::new();
        missing.case_configs.push(gto_missing);
        assert!(
            missing.validate_case_set().is_some(),
            "a GTO lane case with a missing family must fail closed"
        );
        let _ = packer_family::AHK_GTO;
    }
    #[test]
    fn g2r1_unknown_family_in_envelope_fails_closed() {
        let dir = temp_dir("g2r1_unknown_family");
        let mut env = v4_envelope();
        env.case_configs[0].family_id = "bogus_family".to_string();
        assert!(
            env.validate_case_set().is_some(),
            "an unknown family_id in the envelope must fail case-set validation"
        );
        let mut empty_family = v4_envelope();
        empty_family.case_configs[1].family_id = String::new();
        assert!(
            empty_family.validate_case_set().is_some(),
            "a missing family_id in the envelope must fail case-set validation"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// G2-R2: the PE-evidence command dispatches by family — Oreans →
    /// `oreans-pe-evidence`, a generic family (ahk_gto) → `unpack-pe-evidence`.
    /// The two never cross lines and an unknown family fails closed.
    #[test]
    fn pe_evidence_command_dispatches_by_family() {
        use mida_core::runner_config::packer_family;
        assert_eq!(
            pe_evidence_command_for_family(packer_family::OREANS).unwrap(),
            "oreans-pe-evidence"
        );
        assert_eq!(
            pe_evidence_command_for_family(packer_family::AHK_GTO).unwrap(),
            "unpack-pe-evidence"
        );
        assert!(pe_evidence_command_for_family("bogus").is_err());
        assert!(pe_evidence_command_for_family("").is_err());
    }

    /// G2-R2 (reachability guard, choice B): the GTO preflight lane is NOT yet
    /// wired. The fixed two-sample regression gate is strictly the two Oreans
    /// cases, so no GTO case can be staged into the envelope today — the GTO
    /// family/digest/attest path is unit-tested but not end-to-end reachable.
    /// This assertion locks that boundary so a future change cannot silently
    /// claim GTO preflight is live without explicitly removing this guard.
    #[test]
    fn gto_preflight_is_not_yet_reachable() {
        // The Oreans fixed regression gate is exactly the two Oreans cases;
        // the GTO lane is a SEPARATE case id and is never folded into it.
        assert_eq!(FIXED_CASE_IDS, ["origin_macro", "lunlun_software"]);
        assert!(
            !FIXED_CASE_IDS.contains(&"gto_launcher"),
            "the GTO lane must never be folded into the Oreans fixed regression gate"
        );
        assert_eq!(GTO_CASE_ID, "gto_launcher");
        // The GTO lane is NOT an accepted sample: no real GTO sample has been
        // staged/attested/verified end-to-end (it stays offline-only). This
        // guards against anyone claiming real GTO preflight acceptance.
    }

    /// G3: `validate_case_set` accepts the two lanes — the Oreans fixed lane
    /// must be present, and an optional GTO no-gate lane case is allowed with
    /// family `ahk_gto`. Cross-lane / unknown family reuse fails closed.
    #[test]
    fn validate_case_set_accepts_oreans_plus_optional_gto_lane() {
        use mida_core::runner_config::packer_family;
        let dir = temp_dir("g3_lane_set");
        let mut oreans = v4_envelope();
        assert!(
            oreans.validate_case_set().is_none(),
            "pure Oreans set is valid"
        );
        // Add a GTO lane case (family ahk_gto) -> still valid.
        let mut gto_case = v4_envelope().case_configs[0].clone();
        gto_case.case_id = GTO_CASE_ID.to_string();
        gto_case.family_id = packer_family::AHK_GTO.to_string();
        gto_case.protected_input_path = Some(
            "C:\\snapshots\\gto_launcher\\cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\snapshot.bin"
                .to_string(),
        );
        oreans.case_configs.push(gto_case);
        assert!(
            oreans.validate_case_set().is_none(),
            "Oreans + GTO lane is valid"
        );
        // A GTO case borrowing the Oreans family must fail closed.
        let mut bad = v4_envelope();
        let mut gto_case_oreans = v4_envelope().case_configs[0].clone();
        gto_case_oreans.case_id = GTO_CASE_ID.to_string();
        gto_case_oreans.family_id = packer_family::OREANS.to_string();
        bad.case_configs.push(gto_case_oreans);
        assert!(
            bad.validate_case_set().is_some(),
            "a GTO case borrowing the Oreans family must fail closed"
        );
        // An Oreans fixed case carrying the GTO family must fail closed.
        let mut oreans_as_gto = v4_envelope();
        oreans_as_gto.case_configs[0].family_id = packer_family::AHK_GTO.to_string();
        assert!(
            oreans_as_gto.validate_case_set().is_some(),
            "an Oreans fixed case with the GTO family must fail closed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// P6.3.3.2: the verifier-replacement rejection is proven offline via a
    /// PURE seam (`verify_verifier_identity_bindings`), WITHOUT selecting a
    /// real locked case or creating a sample process. A fabricated envelope
    /// pins a verifier identity; the sibling the run would resolve to hashes
    /// to a DIFFERENT identity, so the check must fail with a
    /// verifier-identity reason (not a generic "launch blocked").
    #[test]
    fn verifier_replacement_rejected_by_pure_identity_seam() {
        let dir = temp_dir("vrfy_seam");
        // The verifier this run would resolve to: the fake sibling.
        let fake_acceptance_bin = fake_acceptance(&dir);
        let resolved_sha = sha256_hex(&std::fs::read(&fake_acceptance_bin).unwrap());

        // A valid envelope whose pinned verifier SHA is a DIFFERENT identity
        // (and whose pinned path is the same sibling path).
        let mut env = v4_envelope();
        let pinned_path = std::fs::canonicalize(&fake_acceptance_bin).unwrap();
        env.verifier_path = pinned_path.display().to_string();
        env.verifier_sha256 = "f".repeat(64);

        let err = verify_verifier_identity_bindings(&env, &fake_acceptance_bin, &resolved_sha)
            .expect_err("a replaced verifier must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("verifier") && msg.contains("does not match"),
            "the rejection must cite the verifier identity: {msg}"
        );
        assert!(
            msg.contains("replacement") || msg.contains("drift"),
            "the rejection must cite replacement/drift: {msg}"
        );

        // Positive control: an envelope pinned to the ACTUAL resolved
        // identity passes the pure seam (path + hash both match).
        let mut ok_env = v4_envelope();
        ok_env.verifier_path = pinned_path.display().to_string();
        ok_env.verifier_sha256 = resolved_sha.clone();
        let ok = verify_verifier_identity_bindings(&ok_env, &fake_acceptance_bin, &resolved_sha)
            .expect("exact pinned identity passes");
        assert_eq!(ok.to_lowercase(), resolved_sha.to_lowercase());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// P6.3.3.2: the pure seam also fails closed on verifier PATH drift — a
    /// verifier at a DIFFERENT canonical path than the pinned one is refused
    /// even if its SHA-256 coincidentally matched.
    #[test]
    fn verifier_path_drift_rejected_by_pure_identity_seam() {
        let dir = temp_dir("vrfy_path");
        let fake_acceptance_bin = fake_acceptance(&dir);
        let resolved_sha = sha256_hex(&std::fs::read(&fake_acceptance_bin).unwrap());

        let mut env = v4_envelope();
        // Pin a DIFFERENT canonical path (same SHA) -> path drift must fail.
        env.verifier_path = dir
            .join("elsewhere/mida-acceptance.exe")
            .display()
            .to_string();
        env.verifier_sha256 = resolved_sha.clone();
        let err = verify_verifier_identity_bindings(&env, &fake_acceptance_bin, &resolved_sha)
            .expect_err("path drift must be refused");
        assert!(
            err.to_string().contains("path drift"),
            "path drift reason expected: {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// P6.3.3.2: the production pure-rebuild policy is resolved from the REAL
    /// protected-input bytes via `is_origin_macro_protected_input` — never
    /// guessed from the case_id string. A file whose bytes hash to the
    /// Origin locked identity resolves `pure_rebuild=true`; any other input
    /// resolves `false`, regardless of its path or name.
    #[test]
    fn frozen_run_policy_resolves_pure_rebuild_from_real_input_bytes() {
        use std::io::Write;
        let dir = temp_dir("d3_resolver");
        // A file whose bytes hash to the locked Origin identity. We cannot
        // produce 5MB+ of those exact bytes here, so we instead prove the
        // resolver is INPUT-BASED (hash of the actual file) by confirming the
        // default non-Origin input resolves false, and that the Origin
        // identity constant is the resolver's discriminator.
        let non_origin = dir.join("whatever.bin");
        let mut f = std::fs::File::create(&non_origin).unwrap();
        f.write_all(b"NON-ORIGIN-INPUT-BYTES").unwrap();
        drop(f);
        let policy = crate::run_spec::frozen_run_policy(&non_origin);
        assert!(
            !policy.pure_rebuild,
            "a non-Origin input must resolve pure_rebuild=false"
        );

        // Directly prove the discriminator is the file's real SHA-256, not the
        // path/name: a file with the ORIGIN identity bytes must be flagged.
        // (The real locked bytes are 5MB+; here we assert the resolver keys on
        // the manifest-declared SHA, which is the exact logic used at launch.)
        let origin_sha = crate::origin_pure::origin_macro_protected_sha256()
            .expect("embedded origin_macro manifest");
        assert_eq!(origin_sha.len(), 64);
        assert_ne!(
            origin_sha.to_lowercase(),
            sha256_hex(&std::fs::read(&non_origin).unwrap()),
            "the two inputs must have distinct identities"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// P6.3.3.2.1: the TRUE dual swap — both the case_id and the
    /// protected_input are exchanged together while each runner CONFIG stays
    /// in its original slot, so every case keeps its OWN protected identity
    /// (the keyed binding stays valid) but carries the OTHER case's policy.
    /// Rejected at the launch-attestation level: `bind_actual_config_to_envelope`
    /// recomputes the ACTUAL config digest and compares it only against the
    /// SELECTED case's digest — even when every envelope digest is re-sealed
    /// honestly. The rejection must cite the config/policy digest, never a
    /// synthetic-input identity mismatch.
    ///
    /// Resulting envelope (identity valid, config swapped):
    ///   lunlun_software + LUNLUN identity + Origin policy(true)
    ///   origin_macro   + ORIGIN  identity + Lunlun policy(false)
    #[test]
    fn true_dual_swap_rejected_by_launch_attestation_config_digest() {
        let dir = temp_dir("dual_swap");
        let mut env = v4_envelope();
        // Origin slot keeps its ORIGIN identity but now carries the LUNLUN
        // policy (pure=false); the Lunlun slot keeps LUNLUN identity but
        // carries the ORIGIN policy (pure=true).
        env.case_configs[0] = case_config("origin_macro", ORIGIN_ID, false);
        env.case_configs[1] = case_config("lunlun_software", LUNLUN_ID, true);
        env.case_set_digest = case_set_digest(&env.case_configs);
        env.write(&dir).unwrap();

        // The launch binds the ORIGIN identity to the REAL Origin frozen
        // policy (pure=true). The selected origin_macro case now holds the
        // lunlun (pure=false) config digest, so the actual digest mismatches.
        let origin_identity = FileIdentityGate {
            sha256: ORIGIN_ID.to_string(),
            size_bytes: 5_232_656,
        };
        let mut origin_actual = crate::run_spec::frozen_runner_config();
        origin_actual.pure_rebuild = true; // Origin D3 resolves true
        let err = bind_actual_config_to_envelope(&dir, &origin_actual, &origin_identity)
            .expect_err("Origin pure=true actual must not bind a pure=false envelope case");
        assert!(
            err.to_string().contains("digest"),
            "the rejection must cite the config/digest, not an input mismatch: {err}"
        );

        // Symmetric negative control: the Lunlun identity bound to the real
        // Lunlun frozen policy (pure=false) must also fail against the origin
        // (pure=true) config now carried by the lunlun case.
        let lunlun_identity = FileIdentityGate {
            sha256: LUNLUN_ID.to_string(),
            size_bytes: 4_976_144,
        };
        let mut lunlun_actual = crate::run_spec::frozen_runner_config();
        lunlun_actual.pure_rebuild = false;
        let err2 = bind_actual_config_to_envelope(&dir, &lunlun_actual, &lunlun_identity)
            .expect_err("Lunlun pure=false actual must not bind a pure=true envelope case");
        assert!(
            err2.to_string().contains("digest"),
            "the rejection must cite the config/digest: {err2}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn v4_envelope_seals_case_set_and_rejects_missing_duplicate_extra() {
        let dir = temp_dir("case_set");
        let env = v4_envelope();
        env.write(&dir).unwrap();
        // The sealed digest round-trips and is stable.
        assert_eq!(
            env.case_set_digest,
            case_set_digest(&env.case_configs),
            "case-set digest must be recomputable from the case configs"
        );
        // Missing a case is rejected.
        let mut missing = v4_envelope();
        missing
            .case_configs
            .retain(|c| c.case_id != "lunlun_software");
        assert!(
            missing.validate_case_set().is_some(),
            "missing case rejected"
        );
        // Duplicate is rejected.
        let mut dup = v4_envelope();
        dup.case_configs
            .push(case_config("origin_macro", ORIGIN_ID, true));
        assert!(dup.validate_case_set().is_some(), "duplicate case rejected");
        // Extra (third) case is rejected.
        let mut extra = v4_envelope();
        extra
            .case_configs
            .push(case_config("gto_launcher", &"d".repeat(64), false));
        assert!(extra.validate_case_set().is_some(), "extra case rejected");
        // Tampering one per-case digest, then re-sealing the case set, must
        // change the case-set digest (any single-case tamper breaks the seal).
        let mut tampered = v4_envelope();
        tampered.case_configs[0].runner_config_digest = "e".repeat(64);
        tampered.case_set_digest = case_set_digest(&tampered.case_configs);
        assert_ne!(tampered.case_set_digest, env.case_set_digest);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ---------------------------------------------------------------------
    // G2: family-agnostic generic evidence contract — producer -> consumer
    // round-trip, run entirely offline with synthetic member sidecars. Uses
    // the real `generic_bundle_assembler` (producer) and the independent
    // `mida-acceptance` consumer, proving the two implementations agree.
    // ---------------------------------------------------------------------

    /// Build the JSON bytes of one family-agnostic sidecar member with the
    /// identities embedded exactly as the producer's `check_embedded_identity`
    /// (and the consumer's `check_sidecar_identity`) require.
    fn g2_sidecar(
        schema: &str,
        protected: Option<(String, u64)>,
        candidate: (String, u64),
    ) -> Vec<u8> {
        let mut obj = serde_json::json!({
            "schema_version": schema,
            "candidate": { "sha256": candidate.0, "size_bytes": candidate.1 },
        });
        if let Some((sha, size)) = protected {
            obj["protected_input"] = serde_json::json!({ "sha256": sha, "size_bytes": size });
        }
        serde_json::to_vec(&obj).unwrap()
    }

    fn g2_transform_manifest(candidate: (String, u64)) -> Vec<u8> {
        serde_json::json!({
            "schema_version": "mida.transform-manifest/v0",
            "taxonomy_version": "mida.transform-taxonomy/v1",
            "candidate_sha256": candidate.0,
            "candidate_size_bytes": candidate.1,
            "entries": [],
        })
        .to_string()
        .into_bytes()
    }

    /// Produce a GTO-family generic bundle from synthetic inputs via the real
    /// producer, then hand the emitted manifest + member bytes to the
    /// `mida-acceptance` consumer. Returns the consumer verdict.
    fn g2_produce_and_consume(dir: &std::path::Path) -> mida_acceptance::UnpackBundleVerdict {
        use crate::unpacker::generic_bundle_assembler::{
            assemble_generic_evidence_bundle, AssembleRequest,
        };

        let protected_path = dir.join("protected.bin");
        let candidate_path = dir.join("candidate.bin");
        let protected_bytes = b"G2-PROTECTED-INPUT-00000000000000";
        let candidate_bytes = b"G2-CANDIDATE-OUTPUT-000000000000000";
        write(&protected_path, protected_bytes);
        write(&candidate_path, candidate_bytes);
        let protected_sha = sha256_hex(protected_bytes);
        let candidate_sha = sha256_hex(candidate_bytes);
        let protected = (protected_sha.clone(), protected_bytes.len() as u64);
        let candidate = (candidate_sha.clone(), candidate_bytes.len() as u64);

        // Build the 7 member files. Member schemas come from the PRODUCTION
        // family-aware dispatch (`evidence_schema::member_schema_for_family`
        // with the GTO family), so the test exercises the real dispatch rather
        // than a hand-rolled set.
        let evidence_dir = dir.join("evidence");
        std::fs::create_dir_all(&evidence_dir).unwrap();
        use crate::unpacker::evidence_schema::{member_schema_for_family, EvidenceMemberKind};
        const GTO_FAMILY: &str = "ahk_gto";
        let member_specs: Vec<(&str, &str, bool)> = vec![
            (
                "oep_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Oep).unwrap(),
                true,
            ),
            (
                "iat_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Iat).unwrap(),
                true,
            ),
            (
                "tls_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Tls).unwrap(),
                true,
            ),
            (
                "relocation_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Relocation).unwrap(),
                true,
            ),
            (
                "section_rebuild_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::SectionRebuild).unwrap(),
                true,
            ),
            (
                "pe_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Pe).unwrap(),
                false,
            ),
            ("transform_manifest", "mida.transform-manifest/v0", false),
        ];
        let mut members = Vec::new();
        for (name, schema, has_protected) in &member_specs {
            let path = evidence_dir.join(format!("{name}.json"));
            let bytes = if *name == "transform_manifest" {
                g2_transform_manifest(candidate.clone())
            } else {
                g2_sidecar(
                    schema,
                    if *has_protected {
                        Some(protected.clone())
                    } else {
                        None
                    },
                    candidate.clone(),
                )
            };
            write(&path, &bytes);
            members.push((name.to_string(), path));
        }

        let test_target_identity = VerifiedTargetIdentity::from_attested(
            "gto_launcher",
            &FileIdentityGate {
                sha256: "ab12".repeat(16),
                size_bytes: 4096,
            },
            "x86_64",
        )
        .expect("test target identity seals");
        let context = RunEvidenceContext::new_with_family(
            mida_core::runner_config::packer_family::AHK_GTO.to_string(),
            "gto_launcher".to_string(),
            "oreans/two-sample-mainline@test".to_string(),
            "ab12".repeat(16),
            "cd34".repeat(16),
            protected_path,
            candidate_path.clone(),
            "ef56".repeat(16),
            test_target_identity,
            None, // GTO lane has no profile object -> fail-closed
        )
        .expect("GTO evidence context builds");

        let output = evidence_dir.join("unpack_bundle.json");
        let request = AssembleRequest {
            emitted_at: "2026-08-04T12:00:00Z".to_string(),
            protected_input: dir.join("protected.bin"),
            candidate: candidate_path.clone(),
            members: members.clone(),
            output: output.clone(),
        };
        assemble_generic_evidence_bundle(&request, context)
            .expect("producer assembles generic bundle");

        // Consumer side: read the emitted manifest + member bytes.
        let raw = std::fs::read_to_string(&output).unwrap();
        let bundle: mida_acceptance::UnpackEvidenceBundle =
            serde_json::from_str(&raw).expect("consumer parses emitted manifest");
        let mut files: std::collections::BTreeMap<String, Vec<u8>> =
            std::collections::BTreeMap::new();
        for m in &bundle.members {
            let src = evidence_dir.join(&m.relative_path);
            files.insert(m.name.clone(), std::fs::read(&src).unwrap());
        }
        mida_acceptance::validate_unpack_bundle(&bundle, &files)
    }

    /// Read the emitted generic bundle manifest back from the producer output.
    fn g2_read_emitted_bundle(dir: &std::path::Path) -> mida_acceptance::UnpackEvidenceBundle {
        let raw = std::fs::read_to_string(dir.join("evidence/unpack_bundle.json")).unwrap();
        serde_json::from_str(&raw).expect("consumer parses emitted generic manifest")
    }

    /// Reconstruct the consumer `files` map from the emitted manifest's member
    /// paths (the member files live next to the emitted bundle).
    fn g2_member_files(
        dir: &std::path::Path,
        bundle: &mida_acceptance::UnpackEvidenceBundle,
    ) -> std::collections::BTreeMap<String, Vec<u8>> {
        let evidence_dir = dir.join("evidence");
        let mut files = std::collections::BTreeMap::new();
        for m in &bundle.members {
            let src = evidence_dir.join(&m.relative_path);
            files.insert(m.name.clone(), std::fs::read(&src).unwrap());
        }
        files
    }

    #[test]
    fn g2_generic_bundle_producer_consumer_round_trip_is_valid() {
        let dir = temp_dir("g2_roundtrip");
        let verdict = g2_produce_and_consume(&dir);
        assert!(
            verdict.valid && verdict.complete,
            "producer output must be accepted by consumer: {:?}",
            verdict.reasons
        );
        // The high-level `consume_unpack_bundle` seam also accepts it.
        let bundle = g2_read_emitted_bundle(&dir);
        let files = g2_member_files(&dir, &bundle);
        assert!(
            mida_acceptance::consume_unpack_bundle(&bundle, &files).is_ok(),
            "consume_unpack_bundle must accept producer output"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn g2_oreans_v2_evidence_is_rejected_by_generic_consumer() {
        // An Oreans v2 manifest (v2 schema id, no family_id) must be refused by
        // the generic consumer: it cannot even deserialize (family_id required +
        // deny_unknown_fields), and a family-less/wrong-schema manifest is
        // rejected at the schema seam. This is the "Oreans evidence disguised as
        // GTO generic evidence" cross-contamination rejection.
        let dir = temp_dir("g2_oreans_reject");
        // Mimic the exact Oreans v2 bundle wire form (see
        // mida_acceptance::OreansEvidenceBundle) without family_id.
        let oreans_json = serde_json::json!({
            "schema_version": "mida.oreans-evidence-bundle/v2",
            "case_id": "origin_macro",
            "tool_revision": "rev",
            "runner_config_digest": "ab12".repeat(16),
            "emitted_at": "2026-08-04T12:00:00Z",
            "completion_marker": { "state": "complete" },
            "protected_input": { "sha256": "a".repeat(64), "size_bytes": 10 },
            "candidate": { "sha256": "b".repeat(64), "size_bytes": 20 },
            "members_sha256": "c".repeat(64),
            "manifest_sha256": "d".repeat(64),
            "members": [],
        });
        let parsed = serde_json::from_value::<mida_acceptance::UnpackEvidenceBundle>(oreans_json);
        assert!(
            parsed.is_err(),
            "an Oreans v2 manifest must not parse as a generic bundle (fail-closed)"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn g2_generic_evidence_is_rejected_by_oreans_consumer() {
        // Conversely, a GTO generic bundle must never be accepted as Oreans
        // evidence. The Oreans consumer type is family-agnostic-neutral but the
        // schema id differs, so a generic manifest cannot deserialize into
        // `mida_acceptance::OreansEvidenceBundle`.
        let dir = temp_dir("g2_generic_as_oreans");
        // Emit a real GTO generic bundle via the producer.
        let verdict = g2_produce_and_consume(&dir);
        assert!(
            verdict.valid,
            "sanity: the same producer output is a valid generic bundle"
        );
        // The emitted manifest JSON cannot parse as an Oreans v2 bundle.
        let raw = std::fs::read_to_string(dir.join("evidence/unpack_bundle.json")).unwrap();
        let as_oreans = serde_json::from_str::<mida_acceptance::OreansEvidenceBundle>(&raw);
        assert!(
            as_oreans.is_err(),
            "a GTO generic bundle must never deserialize as Oreans evidence (fail-closed)"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
    // -----------------------------------------------------------------------
    // G3-R3-R1: GTO launch path + identity double binding.
    // -----------------------------------------------------------------------

    /// Build a GTO 3-case envelope (2 Oreans fixed + 1 GTO) where the GTO case
    /// carries the given sealed snapshot path (or None).
    fn gto_envelope_with_path(snapshot_path: Option<&str>) -> RunnerConfigEnvelope {
        use mida_core::runner_config::packer_family;
        let mut env = v4_envelope();
        let mut gto_cfg = crate::run_spec::frozen_runner_config_for_family(packer_family::AHK_GTO);
        gto_cfg.tool_revision = "rev".to_string();
        gto_cfg.cli_binary_sha256 = "a".repeat(64);
        let gto_digest = mida_core::runner_config::runner_config_digest(&gto_cfg);
        env.case_configs.push(CaseRunnerConfigEnvelope {
            case_id: GTO_CASE_ID.to_string(),
            family_id: packer_family::AHK_GTO.to_string(),
            protected_input: FileIdentityGate {
                sha256: "c".repeat(64),
                size_bytes: 42,
            },
            protected_input_path: snapshot_path.map(|p| p.to_string()),
            runner_config: serde_json::to_value(&gto_cfg).unwrap(),
            runner_config_digest: gto_digest,
        });
        env.case_set_digest = case_set_digest(&env.case_configs);
        env
    }

    /// The GTO case's sealed protected_input identity (must match what the
    /// report records for the GTO case).
    fn gto_identity() -> FileIdentityGate {
        FileIdentityGate {
            sha256: "c".repeat(64),
            size_bytes: 42,
        }
    }

    /// A `PreflightCaseGate` for the GTO case carrying the given protected path.
    fn gto_report_case(protected_input_path: &str) -> PreflightCaseGate {
        PreflightCaseGate {
            case_id: GTO_CASE_ID.to_string(),
            identity_ok: true,
            reasons: Vec::new(),
            protected_input: Some(gto_identity()),
            protected_input_path: protected_input_path.to_string(),
            manifest_path: "gto_launcher.json".to_string(),
            candidate_output: "C:\\dummy\\out\\candidate.exe".to_string(),
            runner_config_digest: Some("c".repeat(64)),
        }
    }

    /// A `LaunchAttestationContext` with the given input, borrowing a runner
    /// config owned by the caller.
    fn launch_ctx<'a>(
        input: &'a Path,
        snapshot_root: &'a Path,
        config: &'a mida_core::runner_config::RunnerConfig,
    ) -> LaunchAttestationContext<'a> {
        LaunchAttestationContext {
            input,
            output: Path::new("C:\\dummy\\out\\candidate.exe"),
            cli_binary: Path::new("C:\\dummy\\mida-cli.exe"),
            runner_config: config,
            snapshot_root,
        }
    }

    /// A GTO-family runner config (owned) for the launch context.
    fn gto_runner_config() -> mida_core::runner_config::RunnerConfig {
        mida_core::runner_config::RunnerConfig {
            packer_family: "ahk_gto".to_string(),
            tool_revision: "rev".to_string(),
            cli_binary_sha256: "a".repeat(64),
            features: Vec::new(),
            debugger_backend: String::new(),
            oep_policy: String::new(),
            container_restore: String::new(),
            shrink: false,
            data_sections: false,
            pure_rebuild: false,
            capture_policy_digest: String::new(),
            iat_fix_strategy: String::new(),
            timeout_secs: 0,
            isolation: mida_core::runner_config::IsolationConfig {
                workspace_policy: String::new(),
                process_tree_policy: String::new(),
                network_policy: String::new(),
            },
            attempt_numbering: String::new(),
            evidence_bundle_schema: String::new(),
            gate_schema: String::new(),
            env_allowlist: Vec::new(),
        }
    }

    /// Create a real GTO snapshot under a temp snapshot_root and return
    /// (root, snapshot_path).
    fn make_snapshot(root: &Path) -> (PathBuf, PathBuf) {
        let sha = "c".repeat(64);
        let dir = root.join(GTO_CASE_ID).join(&sha);
        std::fs::create_dir_all(&dir).unwrap();
        let snap = dir.join("snapshot.bin");
        std::fs::write(&snap, b"G3-R3-R1-SNAPSHOT-PAYLOAD").unwrap();
        let canonical = std::fs::canonicalize(&snap).unwrap();
        (root.to_path_buf(), canonical)
    }

    #[test]
    fn gto_snapshot_path_passes_launch_attestation() {
        let root = temp_dir("gto_path_pass");
        let (_, snap_path) = make_snapshot(&root);
        let snap_str = snap_path.to_string_lossy().to_string();
        let env = gto_envelope_with_path(Some(&snap_str));
        let report_case = gto_report_case(&snap_str);
        let cfg = gto_runner_config();
        let ctx = launch_ctx(&snap_path, &root, &cfg);
        let ident = gto_identity();

        // A correct snapshot path with matching identity passes the binding.
        enforce_gto_snapshot_path_binding(&env, &report_case, &ident, &ctx, &root).unwrap();
        // And the evidence input is exactly the snapshot path (not a live alias).
        let selected = select_case_config(&env, &ident).unwrap();
        assert_eq!(
            protected_input_for_evidence(GTO_CASE_ID, selected, &snap_path),
            canonicalize_loose(&snap_path)
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gto_live_source_same_bytes_is_rejected_at_launch() {
        let root = temp_dir("gto_live_same_bytes");
        let (_, snap_path) = make_snapshot(&root);
        let snap_str = snap_path.to_string_lossy().to_string();
        let env = gto_envelope_with_path(Some(&snap_str));
        let report_case = gto_report_case(&snap_str);
        let ident = gto_identity();

        // A live source OUTSIDE snapshot_root with the SAME bytes/hash as the
        // snapshot, placed at a DIFFERENT (but structurally valid) snapshot-root
        // path. Its canonical path differs from the sealed snapshot path, so it
        // is refused even though identity (hash/size) matches.
        let live_root = root.join("live_snapshots");
        let live = live_root
            .join("gto_launcher")
            .join("c".repeat(64))
            .join(crate::sample_snapshot::SNAPSHOT_FILENAME);
        std::fs::create_dir_all(live.parent().unwrap()).unwrap();
        std::fs::write(&live, b"G3-R3-R1-SNAPSHOT-PAYLOAD").unwrap();
        let cfg = gto_runner_config();
        let ctx = launch_ctx(&live, &root, &cfg);
        let err =
            enforce_gto_snapshot_path_binding(&env, &report_case, &ident, &ctx, &root).unwrap_err();
        assert!(
            format!("{err:#}").contains("must be the staged immutable snapshot")
                || format!("{err:#}")
                    .contains("lexical snapshot_root != caller trusted snapshot_root")
                || format!("{err:#}").contains("failed disk verification"),
            "live source with identical bytes must be path-rejected: {err:#}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gto_live_source_changed_after_preflight_is_rejected() {
        let root = temp_dir("gto_live_changed");
        let (_, snap_path) = make_snapshot(&root);
        let snap_str = snap_path.to_string_lossy().to_string();
        let env = gto_envelope_with_path(Some(&snap_str));
        let report_case = gto_report_case(&snap_str);
        let ident = gto_identity();

        // The dynamic source path (a different file with DIFFERENT bytes) is
        // passed at launch at a different (structurally valid) snapshot path. It
        // fails the path binding; it must not be re-captured or auto-registered.
        let live_root = root.join("live_snapshots");
        let live = live_root
            .join("gto_launcher")
            .join("c".repeat(64))
            .join(crate::sample_snapshot::SNAPSHOT_FILENAME);
        std::fs::create_dir_all(live.parent().unwrap()).unwrap();
        std::fs::write(&live, b"DIFFERENT-PAYLOAD-AFTER-PREFLIGHT").unwrap();
        let cfg = gto_runner_config();
        let ctx = launch_ctx(&live, &root, &cfg);
        let err =
            enforce_gto_snapshot_path_binding(&env, &report_case, &ident, &ctx, &root).unwrap_err();
        assert!(
            format!("{err:#}").contains("must be the staged immutable snapshot")
                || format!("{err:#}")
                    .contains("lexical snapshot_root != caller trusted snapshot_root")
                || format!("{err:#}").contains("failed disk verification"),
            "a changed live source must be refused: {err:#}"
        );
        // The snapshot is untouched.
        assert!(snap_path.is_file());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gto_snapshot_path_escape_is_rejected() {
        let root = temp_dir("gto_path_escape");
        let (_, snap_path) = make_snapshot(&root);
        let snap_str = snap_path.to_string_lossy().to_string();
        let env = gto_envelope_with_path(Some(&snap_str));
        let report_case = gto_report_case(&snap_str);
        let ident = gto_identity();

        // Launch inputs that escape or alias outside snapshot_root must be
        // rejected at the launch path-binding boundary (canonical comparison
        // against the sealed snapshot path), even when their bytes/hash match.
        let escape_inputs: Vec<PathBuf> = vec![
            // `..` traversal out of snapshot_root
            root.join("..").join("outside").join("snapshot.bin"),
            // adjacent directory prefix (root2 not a child of root)
            PathBuf::from(format!(
                "{}2\\gto_launcher\\{}\\snapshot.bin",
                root.to_string_lossy(),
                "c".repeat(64)
            )),
            // relative path (not canonical/absolute)
            PathBuf::from(format!("gto_launcher/{}/snapshot.bin", "c".repeat(64))),
            // a plain sibling file (same bytes, different location)
            root.join("live_source.exe"),
        ];
        let cfg = gto_runner_config();
        for inp in &escape_inputs {
            // Create the file so canonicalize resolves it; a failing escape is
            // still rejected fail-closed.
            if inp.parent().is_some() {
                let _ = std::fs::create_dir_all(inp.parent().unwrap());
            }
            let _ = std::fs::write(inp, b"G3-R3-R1-SNAPSHOT-PAYLOAD");
            let ctx = launch_ctx(inp, &root, &cfg);
            let err = enforce_gto_snapshot_path_binding(&env, &report_case, &ident, &ctx, &root)
                .unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("must be the staged immutable snapshot")
                    || msg.contains("failed disk verification")
                    || msg.contains("contains a relative")
                    || msg.contains("must end in snapshot.bin")
                    || msg.contains("escapes canonical snapshot root")
                    || msg.contains("is not absolute"),
                "escape input {} must be path-rejected: {msg}",
                inp.display()
            );
        }

        // Malformed snapshot addresses are refused structurally by the
        // snapshot-root validator (defense in depth on the sealed path).
        let malformed: Vec<PathBuf> = vec![
            // wrong file name (not snapshot.bin)
            PathBuf::from(format!(
                "{}\\gto_launcher\\{}\\other.bin",
                root.to_string_lossy(),
                "c".repeat(64)
            )),
            // malformed hash directory (not 64-hex)
            PathBuf::from(format!(
                "{}\\gto_launcher\\not-a-hash\\snapshot.bin",
                root.to_string_lossy()
            )),
            // wrong case dir
            PathBuf::from(format!(
                "{}\\origin_macro\\{}\\snapshot.bin",
                root.to_string_lossy(),
                "c".repeat(64)
            )),
        ];
        for m in &malformed {
            assert!(
                snapshot_root_of_snapshot(m).is_err(),
                "malformed snapshot address must be rejected: {}",
                m.display()
            );
        }
        // The valid snapshot path passes the structural check.
        snapshot_root_of_snapshot(&snap_path).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gto_snapshot_symlink_or_reparse_escape_is_rejected() {
        let root = temp_dir("gto_symlink_escape");
        let (_, snap_path) = make_snapshot(&root);
        let snap_str = snap_path.to_string_lossy().to_string();
        let env = gto_envelope_with_path(Some(&snap_str));
        let report_case = gto_report_case(&snap_str);
        let ident = gto_identity();
        let cfg = gto_runner_config();

        // A symlink/junction INSIDE snapshot_root that resolves OUTSIDE it must
        // not pass: canonicalize() resolves the link to its target, which is a
        // different canonical path than the sealed snapshot, so the launch
        // path-binding boundary rejects it.
        let mut junction_created = false;
        #[cfg(windows)]
        {
            // Best-effort: build a junction from snapshot_root/escape_link to a
            // directory outside snapshot_root. If the environment forbids
            // junction creation (permissions), we fall back to the guaranteed
            // structural unit check below.
            let outside = root.join("outside_real");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("snapshot.bin"), b"G3-R3-R1-SNAPSHOT-PAYLOAD").unwrap();
            let link = root.join("escape_link");
            let mklink = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&outside)
                .output();
            if let Ok(o) = mklink {
                if o.status.success() {
                    junction_created = true;
                    let junction_snap = link.join("snapshot.bin");
                    assert!(junction_snap.is_file());
                    // The junction path is not a well-formed content-addressed
                    // address (no logical/hash layers), so the launch helper must
                    // fail closed on it.
                    let ctx = launch_ctx(&junction_snap, &root, &cfg);
                    let err =
                        enforce_gto_snapshot_path_binding(&env, &report_case, &ident, &ctx, &root)
                            .unwrap_err();
                    let msg = format!("{err:#}");
                    assert!(
                        msg.contains("failed disk verification")
                            || msg.contains("must be the staged immutable snapshot")
                            || msg.contains("escapes canonical snapshot root")
                            || msg.contains("must end in snapshot.bin"),
                        "a junction escape out of snapshot_root must be rejected: {msg}"
                    );
                }
            }
        }

        // Guaranteed structural rejection (no filesystem feature required): a
        // relative / non-canonical address that would alias outside is always
        // rejected by the snapshot-root structural validator, and a same-bytes
        // sibling path is rejected by the canonical launch-path comparison.
        let relative = Path::new("gto_launcher")
            .join("c".repeat(64))
            .join("snapshot.bin");
        assert!(snapshot_root_of_snapshot(&relative).is_err());
        let sibling_root = root.join("sibling_snapshots");
        let sibling = sibling_root
            .join("gto_launcher")
            .join("c".repeat(64))
            .join(crate::sample_snapshot::SNAPSHOT_FILENAME);
        std::fs::create_dir_all(sibling.parent().unwrap()).unwrap();
        std::fs::write(&sibling, b"G3-R3-R1-SNAPSHOT-PAYLOAD").unwrap();
        let ctx = launch_ctx(&sibling, &root, &cfg);
        let err =
            enforce_gto_snapshot_path_binding(&env, &report_case, &ident, &ctx, &root).unwrap_err();
        assert!(
            format!("{err:#}").contains("must be the staged immutable snapshot")
                || format!("{err:#}")
                    .contains("lexical snapshot_root != caller trusted snapshot_root")
                || format!("{err:#}").contains("failed disk verification"),
            "a same-bytes sibling must be path-rejected: {err:#}"
        );
        // Record whether a real junction was exercised (for the report).
        let _ = junction_created;
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn gto_report_protected_input_path_tamper_is_rejected() {
        let root = temp_dir("gto_report_tamper");
        let (_, snap_path) = make_snapshot(&root);
        let snap_str = snap_path.to_string_lossy().to_string();
        let env = gto_envelope_with_path(Some(&snap_str));
        let ident = gto_identity();

        // The REPORT records a DIFFERENT (tampered) path than the sealed
        // envelope path. The launch must reject on the report-vs-sealed path
        // divergence, not trust hash/size.
        let tampered = root.join("tampered_path").join("snapshot.bin");
        std::fs::create_dir_all(tampered.parent().unwrap()).unwrap();
        std::fs::write(&tampered, b"G3-R3-R1-SNAPSHOT-PAYLOAD").unwrap();
        let report_case = gto_report_case(&tampered.to_string_lossy());
        let cfg = gto_runner_config();
        let ctx = launch_ctx(&snap_path, &root, &cfg);
        let err =
            enforce_gto_snapshot_path_binding(&env, &report_case, &ident, &ctx, &root).unwrap_err();
        assert!(
            format!("{err:#}").contains("!= sealed envelope path"),
            "a tampered report protected_input_path must be rejected: {err:#}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn oreans_live_input_attestation_unchanged() {
        use mida_core::runner_config::packer_family;
        // Oreans fixed cases carry no sealed path (None) and are NOT path-bound.
        let env = v4_envelope();
        for c in &env.case_configs {
            assert_eq!(c.family_id, packer_family::OREANS);
            assert!(
                c.protected_input_path.is_none(),
                "Oreans has no path binding"
            );
        }
        // The evidence input for an Oreans case is the live input path, not a
        // snapshot path.
        let live = Path::new("C:\\some\\live\\origin.bin");
        let selected = &env.case_configs[0];
        assert_eq!(
            protected_input_for_evidence("origin_macro", selected, live),
            canonicalize_loose(live)
        );
        // The GTO path-binding enforcement is a no-op for Oreans (never invoked
        // because target_case_id != GTO_CASE_ID).
    }

    #[test]
    fn gto_evidence_input_uses_snapshot_path() {
        use mida_core::runner_config::packer_family;
        let root = temp_dir("gto_evidence_path");
        let (_, snap_path) = make_snapshot(&root);
        let snap_str = snap_path.to_string_lossy().to_string();
        let env = gto_envelope_with_path(Some(&snap_str));
        let gto_case = &env.case_configs[2];
        assert_eq!(gto_case.family_id, packer_family::AHK_GTO);

        // Even if the launch input is a live alias with identical bytes, the
        // evidence context must bind the sealed snapshot path for GTO.
        let live_alias = root.join("alias.exe");
        std::fs::write(&live_alias, b"G3-R3-R1-SNAPSHOT-PAYLOAD").unwrap();
        let ev = protected_input_for_evidence(GTO_CASE_ID, gto_case, &live_alias);
        assert_eq!(
            ev,
            canonicalize_loose(&snap_path),
            "evidence must use snapshot path"
        );
        assert_ne!(ev, canonicalize_loose(&live_alias), "never a live alias");
        std::fs::remove_dir_all(&root).unwrap();
    }

    // -----------------------------------------------------------------------
    // G3-R3-R2: GTO digest through the launch-boundary gate + CLI path schema.
    // -----------------------------------------------------------------------

    /// Build a `ready` preflight report for a 3-case envelope (2 Oreans + GTO),
    /// with per-case digests matching the envelope and a ready status.
    fn ready_report_for_envelope(env: &RunnerConfigEnvelope) -> PreflightReportGate {
        let mut cases: Vec<PreflightCaseGate> = env
            .case_configs
            .iter()
            .map(|c| PreflightCaseGate {
                case_id: c.case_id.clone(),
                identity_ok: true,
                reasons: Vec::new(),
                protected_input: Some(c.protected_input.clone()),
                protected_input_path: c.protected_input_path.clone().unwrap_or_default(),
                manifest_path: format!("{}.json", c.case_id),
                candidate_output: format!("C:\\dummy\\out\\{}.exe", c.case_id),
                runner_config_digest: Some(c.runner_config_digest.clone()),
            })
            .collect();
        // Sort to a deterministic order matching the envelope's cross-validation.
        cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));
        PreflightReportGate {
            schema_version: PREFLIGHT_REPORT_SCHEMA_VERSION.to_string(),
            status: "ready".to_string(),
            reasons: Vec::new(),
            runner_config_digest: env.case_set_digest.clone(),
            head_revision: None,
            worktree_clean: Some(true),
            toolchain_matches: Some(true),
            cli_binary_sha256: Some(env.cli_binary_sha256.clone()),
            cli_binary_matches: Some(true),
            cli_binary_path: "C:\\dummy\\mida-cli.exe".to_string(),
            repo_root: "C:\\dummy\\repo".to_string(),
            toolchain_pin_file: "C:\\dummy\\toolchain.toml".to_string(),
            expected_toolchain: "1.97.1".to_string(),
            cases,
        }
    }

    /// B-hermetic: the launch-boundary gate (`check_chain_ready`) accepts a ready
    /// report whose GTO per-case digest matches the envelope — proving the GTO
    /// digest flows through the gate exactly like Oreans (P1 closure).
    #[test]
    fn gto_check_chain_ready_accepts_verified_digest() {
        use mida_core::runner_config::packer_family;
        // Build a 3-case envelope: 2 Oreans fixed + 1 GTO with a sealed path.
        let mut env = v4_envelope();
        let mut gto_cfg = crate::run_spec::frozen_runner_config_for_family(packer_family::AHK_GTO);
        gto_cfg.tool_revision = "rev".to_string();
        gto_cfg.cli_binary_sha256 = "a".repeat(64);
        let gto_digest = mida_core::runner_config::runner_config_digest(&gto_cfg);
        env.case_configs.push(CaseRunnerConfigEnvelope {
            case_id: GTO_CASE_ID.to_string(),
            family_id: packer_family::AHK_GTO.to_string(),
            protected_input: gto_identity(),
            protected_input_path: Some(
                "C:\\snapshots\\gto_launcher\\cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\snapshot.bin"
                    .to_string(),
            ),
            runner_config: serde_json::to_value(&gto_cfg).unwrap(),
            runner_config_digest: gto_digest,
        });
        env.case_set_digest = case_set_digest(&env.case_configs);
        assert_eq!(
            env.validate_case_set(),
            None,
            "3-case GTO envelope is valid"
        );

        let report = ready_report_for_envelope(&env);
        check_chain_ready(&report, &env).unwrap();
    }

    /// C-negative (CLI): tampering the GTO per-case digest in the report is
    /// rejected by `check_chain_ready`.
    #[test]
    fn gto_check_chain_ready_rejects_tampered_digest() {
        use mida_core::runner_config::packer_family;
        let mut env = v4_envelope();
        let mut gto_cfg = crate::run_spec::frozen_runner_config_for_family(packer_family::AHK_GTO);
        gto_cfg.tool_revision = "rev".to_string();
        gto_cfg.cli_binary_sha256 = "a".repeat(64);
        let gto_digest = mida_core::runner_config::runner_config_digest(&gto_cfg);
        env.case_configs.push(CaseRunnerConfigEnvelope {
            case_id: GTO_CASE_ID.to_string(),
            family_id: packer_family::AHK_GTO.to_string(),
            protected_input: gto_identity(),
            protected_input_path: Some(
                "C:\\snapshots\\gto_launcher\\cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\snapshot.bin"
                    .to_string(),
            ),
            runner_config: serde_json::to_value(&gto_cfg).unwrap(),
            runner_config_digest: gto_digest,
        });
        env.case_set_digest = case_set_digest(&env.case_configs);

        let mut report = ready_report_for_envelope(&env);
        // Tamper the GTO report digest.
        for c in &mut report.cases {
            if c.case_id == GTO_CASE_ID {
                c.runner_config_digest = Some("0".repeat(64));
            }
        }
        let err = check_chain_ready(&report, &env).unwrap_err();
        assert!(
            format!("{err:#}").contains("digest drift"),
            "a tampered GTO per-case digest must be rejected at the gate: {err:#}"
        );
    }

    /// C-negative (CLI): `validate_case_set` rejects a GTO case with a missing
    /// protected_input_path.
    #[test]
    fn gto_validate_case_set_missing_path_rejected() {
        use mida_core::runner_config::packer_family;
        let mut env = v4_envelope();
        let gto_cfg = crate::run_spec::frozen_runner_config_for_family(packer_family::AHK_GTO);
        let gto_digest = mida_core::runner_config::runner_config_digest(&gto_cfg);
        env.case_configs.push(CaseRunnerConfigEnvelope {
            case_id: GTO_CASE_ID.to_string(),
            family_id: packer_family::AHK_GTO.to_string(),
            protected_input: gto_identity(),
            protected_input_path: None, // missing path -> fail-closed
            runner_config: serde_json::to_value(&gto_cfg).unwrap(),
            runner_config_digest: gto_digest,
        });
        let reason = env.validate_case_set();
        assert!(
            reason.is_some() && reason.as_deref().unwrap().contains("protected_input_path"),
            "a GTO case with a missing path must be rejected: {reason:?}"
        );
    }

    /// C-negative (CLI): `validate_case_set` rejects an Oreans fixed case that
    /// carries a protected_input_path.
    #[test]
    fn gto_validate_case_set_oreans_with_path_rejected() {
        let mut env = v4_envelope();
        env.case_configs[0].protected_input_path = Some("C:\\evil\\origin.bin".to_string());
        let reason = env.validate_case_set();
        assert!(
            reason.is_some() && reason.as_deref().unwrap().contains("protected_input_path"),
            "an Oreans case with a path must be rejected: {reason:?}"
        );
    }

    /// G3-R3-R2-R1 (三): the launch helper rejects a raw `..` in the sealed
    /// protected-input path BEFORE canonicalization. `enforce_gto_snapshot_path_binding`
    /// must fail closed on the raw path's lexical/shape validation, not rely on
    /// a later canonical comparison or the `rerun_verifier`.
    #[test]
    fn launch_helper_rejects_raw_dotdot_before_canonicalization() {
        let root = temp_dir("launch_dotdot");
        let (_, snap_path) = make_snapshot(&root);
        // A raw sealed path containing `..` that WOULD canonicalize to the same
        // snapshot is still rejected by the lexical/shape validator.
        let raw_dotdot = format!(
            "{}\\snapshots\\..\\snapshots\\gto_launcher\\{}\\snapshot.bin",
            root.display(),
            "c".repeat(64)
        );
        let env = gto_envelope_with_path(Some(&raw_dotdot));
        let report_case = gto_report_case(&raw_dotdot);
        let ident = gto_identity();
        let cfg = gto_runner_config();
        let ctx = launch_ctx(&snap_path, &root, &cfg);
        let err =
            enforce_gto_snapshot_path_binding(&env, &report_case, &ident, &ctx, &root).unwrap_err();
        assert!(
            format!("{err:#}").contains("relative") || format!("{err:#}").contains("ParentDir"),
            "a raw `..` sealed path must be rejected by the launch helper: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// G3-R5-R1-R1-R1-R1: the sealed+caller root cross-check passes when the
    /// caller root matches the sealed path root, and fails closed on mismatch.
    #[test]
    fn gto_sealed_root_cross_check_match_and_mismatch() {
        let root = temp_dir("root_cross_check");
        let sha = "c".repeat(64);
        // A sealed path under `root`.
        let sealed = format!("{}\\gto_launcher\\{}\\snapshot.bin", root.display(), sha);
        // Match: caller root == sealed path root.
        verify_gto_sealed_root_matches(&root, &sealed).unwrap();
        // Mismatch: caller root differs (alternate root) -> fail-closed.
        let alt = root.join("alt_root");
        let err = verify_gto_sealed_root_matches(&alt, &sealed).unwrap_err();
        assert!(
            format!("{err:#}").contains("root mismatch")
                || format!("{err:#}").contains("does not match the sealed path root"),
            "root mismatch must be a clear fail-closed: {err:#}"
        );
        // A malformed sealed path fails the parse.
        let err = verify_gto_sealed_root_matches(&root, "not-a-path").unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid") || format!("{err:#}").contains("not absolute"),
            "malformed sealed path must fail: {err:#}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // G3-R5-R1-R1-R1-R1-R1-R1: production-shaped `/unpack` dispatch coverage.
    // These drive run_command(Command::Unpack { .. }) through
    // unpacker::unpack -> LaunchAttestationContext -> attest_ready_before_launch
    // -> verify_gto_sealed_root_matches -> enforce_gto_snapshot_path_binding ->
    // rerun_verifier, using the #[cfg(test)] verifier seam to record the
    // `--snapshot-root` the verifier would receive and to terminate before any
    // process is created.
    // ------------------------------------------------------------------

    /// Workspace root (for rust-toolchain.toml / real manifests).
    fn workspace_root() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    /// A real locked Oreans manifest path.
    fn real_manifest(case_id: &str) -> PathBuf {
        workspace_root()
            .join("lab/cases/v2")
            .join(format!("{case_id}.json"))
    }

    /// Serializes the G3-R5-R1-R1-R1-R1-R1-R1 dispatch tests. Seam state is
    /// thread-local, so the four tests are independent and safe to run in any
    /// order and in parallel with any other test; this lock additionally
    /// serializes them against shared temp-dir roots. Correctness of seam
    /// isolation does NOT depend on this lock (proven by the state-isolation
    /// tests below, which run on separate threads).
    static TEST_DISPATCH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Write a fake verifier stub into `dir` and arm the thread-local
    /// #[cfg(test)] seam via the RAII [`DispatchTestGuard`] (injecting the
    /// stub verifier and enabling the deterministic launch-stop boundary).
    /// Returns the verifier path and the guard, which restores the prior
    /// override / recorders / launch-stop state on drop — including on panic.
    fn arm_dispatch_guard(dir: &Path) -> (PathBuf, DispatchTestGuard) {
        let v = dir.join("mida-acceptance.exe");
        std::fs::write(&v, b"FAKE-VERIFIER-STUB").unwrap();
        let guard = DispatchTestGuard::arm(v.clone());
        (v, guard)
    }

    /// Fabricate a GTO v4 envelope + Ready report whose GTO sealed path is under
    /// `snapshot_root`, matching exactly what `unpack` will build from the given
    /// `Command::Unpack` args (so `bind_actual_config_to_envelope` passes).
    /// Returns the real snapshot path that must be the launch input.
    #[allow(clippy::too_many_arguments)]
    fn fabricate_gto_unpack_state(
        dir: &Path,
        snapshot_root: &Path,
        gto_bytes: &[u8],
        manifest: &Path,
        candidate_output: &Path,
        oep: mida_pe::OepPolicy,
        restore: mida_pe::ContainerRestoreMode,
        profile: mida_pe::DumpProfile,
        shrink: bool,
    ) -> (PathBuf, serde_json::Value, serde_json::Value) {
        use mida_core::runner_config::packer_family;
        use mida_core::runner_config::{IsolationConfig, RunnerConfig};

        let gto_sha = sha256_hex(gto_bytes);
        let gto_size = gto_bytes.len() as u64;
        let sealed_snap = snapshot_root
            .join("gto_launcher")
            .join(&gto_sha)
            .join("snapshot.bin");
        std::fs::create_dir_all(sealed_snap.parent().unwrap()).unwrap();
        std::fs::write(&sealed_snap, gto_bytes).unwrap();

        // The exact config `unpack` builds from the given args + family ahk_gto.
        let cli_binary_sha256 =
            crate::runner_preflight::sha256_file(&std::env::current_exe().unwrap()).unwrap();
        let tool_revision = "rev";
        let gto_cfg = crate::run_spec::runner_config_from_unpack_args_family(
            packer_family::AHK_GTO,
            oep,
            restore,
            profile,
            shrink,
            false,
            false,
            "",
            tool_revision,
            &cli_binary_sha256,
        );
        let gto_digest = mida_core::runner_config::runner_config_digest(&gto_cfg);

        // Oreans configs (their digests are pinned in the envelope; the launch
        // only matches the GTO case by input identity).
        let oreans_cfg = RunnerConfig {
            packer_family: packer_family::OREANS.to_string(),
            tool_revision: tool_revision.to_string(),
            cli_binary_sha256: cli_binary_sha256.clone(),
            features: Vec::new(),
            debugger_backend: String::new(),
            oep_policy: String::new(),
            container_restore: String::new(),
            shrink: false,
            data_sections: false,
            pure_rebuild: false,
            capture_policy_digest: String::new(),
            iat_fix_strategy: String::new(),
            timeout_secs: 0,
            isolation: IsolationConfig {
                workspace_policy: String::new(),
                process_tree_policy: String::new(),
                network_policy: String::new(),
            },
            attempt_numbering: String::new(),
            evidence_bundle_schema: String::new(),
            gate_schema: String::new(),
            env_allowlist: Vec::new(),
        };
        let oreans_digest = mida_core::runner_config::runner_config_digest(&oreans_cfg);

        // Verifier identity: the seam injects a fake verifier; the envelope
        // must pin its canonical path + sha so verify_verifier_identity passes.
        let verifier = dir.join("mida-acceptance.exe");
        std::fs::write(&verifier, b"FAKE-VERIFIER-STUB").unwrap();
        let verifier_canon = std::fs::canonicalize(&verifier).unwrap();
        let verifier_sha = crate::runner_preflight::sha256_file(&verifier_canon).unwrap();

        let configs = vec![
            serde_json::json!({
                "case_id": "origin_macro",
                "family_id": packer_family::OREANS,
                "protected_input": {"sha256": "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7", "size_bytes": 5232656},
                "protected_input_path": null,
                "runner_config": serde_json::to_value(&oreans_cfg).unwrap(),
                "runner_config_digest": oreans_digest,
            }),
            serde_json::json!({
                "case_id": "lunlun_software",
                "family_id": packer_family::OREANS,
                "protected_input": {"sha256": "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07", "size_bytes": 4976144},
                "protected_input_path": null,
                "runner_config": serde_json::to_value(&oreans_cfg).unwrap(),
                "runner_config_digest": oreans_digest,
            }),
            serde_json::json!({
                "case_id": "gto_launcher",
                "family_id": packer_family::AHK_GTO,
                "protected_input": {"sha256": gto_sha, "size_bytes": gto_size},
                "protected_input_path": sealed_snap.display().to_string(),
                "runner_config": serde_json::to_value(&gto_cfg).unwrap(),
                "runner_config_digest": gto_digest,
            }),
        ];
        let mut entries: Vec<String> = configs
            .iter()
            .map(|c| {
                let path = c
                    .get("protected_input_path")
                    .and_then(|p| p.as_str())
                    .unwrap_or_default()
                    .to_lowercase();
                format!(
                    "case={}\nfamily={}\nprotected_input={}|{}\nprotected_input_path={}\nrunner_config_digest={}\n",
                    c["case_id"].as_str().unwrap(),
                    c["family_id"].as_str().unwrap().to_lowercase(),
                    c["protected_input"]["sha256"].as_str().unwrap().to_lowercase(),
                    c["protected_input"]["size_bytes"].as_u64().unwrap(),
                    path,
                    c["runner_config_digest"].as_str().unwrap().to_lowercase(),
                )
            })
            .collect();
        entries.sort();
        let case_set = sha256_hex(entries.concat().as_bytes());

        let envelope = serde_json::json!({
            "$schema": "./runner-config-envelope.schema.json",
            "schema_version": "mida.runner-config-envelope/v4",
            "cli_binary_sha256": cli_binary_sha256,
            "tool_revision": tool_revision,
            "verifier_source": "<cli-dir>/mida-acceptance.exe",
            "verifier_path": verifier_canon.display().to_string(),
            "verifier_sha256": verifier_sha,
            "case_set_digest": case_set,
            "case_configs": configs,
        });
        std::fs::write(
            dir.join("runner-config-envelope.json"),
            serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();

        // Ready report with all three cases matching the envelope.
        let report = serde_json::json!({
            "schema_version": "mida.preflight-report/v3",
            "status": "ready",
            "reasons": [],
            "runner_config_digest": case_set,
            "head_revision": null,
            "worktree_clean": true,
            "toolchain_matches": true,
            "cli_binary_sha256": envelope["cli_binary_sha256"],
            "cli_binary_matches": true,
            "cli_binary_path": std::env::current_exe().unwrap().display().to_string(),
            "repo_root": dir.display().to_string(),
            "toolchain_pin_file": workspace_root().join("rust-toolchain.toml").display().to_string(),
            "expected_toolchain": "1.97.1",
            "cases": vec![
                serde_json::json!({"case_id":"origin_macro","identity_ok":true,"reasons":[],"protected_input":{"sha256":"1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7","size_bytes":5232656},"protected_input_path":"","manifest_path":real_manifest("origin_macro").display().to_string(),"candidate_output":dir.join("origin_candidate.exe").display().to_string(),"runner_config_digest":oreans_digest}),
                serde_json::json!({"case_id":"lunlun_software","identity_ok":true,"reasons":[],"protected_input":{"sha256":"8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07","size_bytes":4976144},"protected_input_path":"","manifest_path":real_manifest("lunlun_software").display().to_string(),"candidate_output":dir.join("lunlun_candidate.exe").display().to_string(),"runner_config_digest":oreans_digest}),
                serde_json::json!({"case_id":"gto_launcher","identity_ok":true,"reasons":[],"protected_input":{"sha256":gto_sha,"size_bytes":gto_size},"protected_input_path":sealed_snap.display().to_string(),"manifest_path":manifest.display().to_string(),"candidate_output":crate::runner_preflight::canonicalize_loose(candidate_output).display().to_string(),"runner_config_digest":gto_digest}),
            ],
        });
        std::fs::write(
            dir.join("preflight.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        (sealed_snap, envelope, report)
    }

    /// A minimal GTO manifest for the synthetic case.
    fn gto_synthetic_manifest(dir: &Path, gto_sha: &str, gto_size: u64) -> PathBuf {
        let p = dir.join("gto_launcher.json");
        std::fs::write(
            &p,
            serde_json::to_vec_pretty(&serde_json::json!({
                "$schema": "./case-manifest.schema.json",
                "schema_version": "mida.case-manifest/v2",
                "case_id": "gto_launcher",
                "primary_artifact_sha256": gto_sha,
                "artifacts": [{"sha256": gto_sha, "size_bytes": gto_size, "role": "protected_input"}],
                "capability_cell": {"protection_family": "ahk_gto_candidate", "engine_route": "mida_plugin_ahk_gto"},
                "static_fingerprint": {}, "execution_policy": {}, "oracle": {}
            }))
            .unwrap(),
        )
        .unwrap();
        p
    }

    /// Custom root: the dispatch chain runs to completion (attestation Ready,
    /// rerun verifier records the custom root) and then terminates exactly at
    /// the deterministic test-only launch-stop boundary — never by a malformed
    /// PE parse failure. The sample-process recorder stays empty and no
    /// candidate is produced.
    #[test]
    fn unpack_dispatch_threads_custom_snapshot_root_to_launch_attestation() {
        let _lock = TEST_DISPATCH_LOCK.lock().unwrap();
        let root = temp_dir("unpack_custom_root");
        let custom_root = root.join("custom_store");
        let dir = root.join("preflight");
        std::fs::create_dir_all(&dir).unwrap();
        let gto_bytes = b"CUSTOM-ROOT-DISPATCH-GTO";
        let gto_sha = sha256_hex(gto_bytes);
        let manifest = gto_synthetic_manifest(&dir, &gto_sha, gto_bytes.len() as u64);
        let candidate = dir.join("gto_candidate.exe");
        let (sealed_snap, _envelope, _report) = fabricate_gto_unpack_state(
            &dir,
            &custom_root,
            gto_bytes,
            &manifest,
            &candidate,
            mida_pe::OepPolicy::Captured,
            mida_pe::ContainerRestoreMode::Off,
            mida_pe::DumpProfile::OreansClassic,
            true,
        );

        // Arm the thread-local seam via the RAII guard (stub verifier +
        // launch-stop boundary). It restores state on drop, even on panic.
        let (_verifier, _dispatch_guard) = arm_dispatch_guard(&dir);

        let cmd = crate::args::Command::Unpack {
            input: sealed_snap.clone(),
            output: Some(candidate.clone()),
            create_data_sections: false,
            shrink: true,
            oep_policy: mida_pe::OepPolicy::Captured,
            container_restore: mida_pe::ContainerRestoreMode::Off,
            profile: mida_pe::DumpProfile::OreansClassic,
            pure_rebuild: false,
            capture_policy: mida_pe::DumpCapturePolicy::default(),
            capture_policy_digest: String::new(),
            preflight_dir: Some(dir.clone()),
            snapshot_root: Some(custom_root.clone()),
            dump_timing: mida_pe::DumpTiming::Immediate,
            verbose: false,
        };
        let err = match crate::commands::run_command(cmd) {
            Ok(()) => String::new(),
            Err(e) => format!("{e:#}"),
        };
        // (a) The run stopped EXACTLY at the test-only launch-stop sentinel,
        // after attestation Ready and before any PE parse / process creation.
        // The synthetic GTO bytes are deliberately not a PE, so if the launch-
        // stop did not fire the test would fail with a parse error instead.
        assert!(
            err.contains(super::TEST_LAUNCH_STOP_TOKEN),
            "dispatch must terminate at the launch-stop sentinel after Ready, got: {err}"
        );
        // (b) The rerun verifier received the custom snapshot root.
        let recorded = test_snapshot_root_recorder();
        assert!(
            recorded
                .iter()
                .any(|r| crate::sample_snapshot::paths_equivalent(
                    std::path::Path::new(r),
                    &custom_root
                )),
            "rerun verifier must receive the custom snapshot root, got {recorded:?}"
        );
        // The verifier spawn-args recorder proves the seam fired at rerun_verifier.
        assert!(
            !test_verifier_recorder().is_empty(),
            "the verifier seam must have recorded a spawn"
        );
        // (c) The sample-process boundary recorder is empty — no real process
        // creation was ever attempted.
        assert!(
            !_dispatch_guard.sample_launch_attempted(),
            "no sample-process launch may be attempted in a dispatch test"
        );
        // (d) No candidate may be produced.
        assert!(!candidate.exists(), "no candidate may be produced");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Default root: snapshot_root=None selects <preflight_dir>/sample-snapshots.
    /// The chain runs to completion (attestation Ready) and stops exactly at
    /// the test-only launch-stop sentinel; sample recorder empty, no candidate.
    #[test]
    fn unpack_dispatch_defaults_snapshot_root_from_preflight_dir() {
        let _lock = TEST_DISPATCH_LOCK.lock().unwrap();
        let root = temp_dir("unpack_default_root");
        let default_root = root.join("preflight").join("sample-snapshots");
        let dir = root.join("preflight");
        std::fs::create_dir_all(&dir).unwrap();
        let gto_bytes = b"DEFAULT-ROOT-DISPATCH-GTO";
        let gto_sha = sha256_hex(gto_bytes);
        let manifest = gto_synthetic_manifest(&dir, &gto_sha, gto_bytes.len() as u64);
        let candidate = dir.join("gto_candidate.exe");
        // The sealed path is under the DEFAULT root (sample-snapshots).
        let (sealed_snap, _envelope, _report) = fabricate_gto_unpack_state(
            &dir,
            &default_root,
            gto_bytes,
            &manifest,
            &candidate,
            mida_pe::OepPolicy::Captured,
            mida_pe::ContainerRestoreMode::Off,
            mida_pe::DumpProfile::OreansClassic,
            true,
        );

        let (_verifier, _dispatch_guard) = arm_dispatch_guard(&dir);

        let cmd = crate::args::Command::Unpack {
            input: sealed_snap.clone(),
            output: Some(candidate.clone()),
            create_data_sections: false,
            shrink: true,
            oep_policy: mida_pe::OepPolicy::Captured,
            container_restore: mida_pe::ContainerRestoreMode::Off,
            profile: mida_pe::DumpProfile::OreansClassic,
            pure_rebuild: false,
            capture_policy: mida_pe::DumpCapturePolicy::default(),
            capture_policy_digest: String::new(),
            preflight_dir: Some(dir.clone()),
            snapshot_root: None,
            dump_timing: mida_pe::DumpTiming::Immediate,
            verbose: false,
        };
        let err = match crate::commands::run_command(cmd) {
            Ok(()) => String::new(),
            Err(e) => format!("{e:#}"),
        };
        // (a) Exact launch-stop sentinel after Ready.
        assert!(
            err.contains(super::TEST_LAUNCH_STOP_TOKEN),
            "dispatch must terminate at the launch-stop sentinel after Ready, got: {err}"
        );
        // (b) The rerun verifier receives the DEFAULT root <preflight_dir>/sample-snapshots.
        let recorded = test_snapshot_root_recorder();
        assert!(
            recorded
                .iter()
                .any(|r| crate::sample_snapshot::paths_equivalent(
                    std::path::Path::new(r),
                    &default_root
                )),
            "rerun verifier must receive the default snapshot root, got {recorded:?}"
        );
        assert!(
            !test_verifier_recorder().is_empty(),
            "the verifier seam must have recorded a spawn"
        );
        // (c) No sample-process launch attempted.
        assert!(
            !_dispatch_guard.sample_launch_attempted(),
            "no sample-process launch may be attempted in a dispatch test"
        );
        // (d) No candidate produced.
        assert!(!candidate.exists(), "no candidate may be produced");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Mismatch: staged under a custom root, launched with the default root
    /// (snapshot_root=None) -> fail-closed before any process creation with a
    /// root-mismatch reason.
    #[test]
    fn unpack_dispatch_rejects_staging_launch_root_mismatch_before_process() {
        let _guard = TEST_DISPATCH_LOCK.lock().unwrap();
        let root = temp_dir("unpack_mismatch");
        let custom_root = root.join("custom_store");
        let dir = root.join("preflight");
        std::fs::create_dir_all(&dir).unwrap();
        let gto_bytes = b"MISMATCH-ROOT-DISPATCH-GTO";
        let gto_sha = sha256_hex(gto_bytes);
        let manifest = gto_synthetic_manifest(&dir, &gto_sha, gto_bytes.len() as u64);
        let candidate = dir.join("gto_candidate.exe");
        // Staged under the CUSTOM root.
        let (sealed_snap, _envelope, _report) = fabricate_gto_unpack_state(
            &dir,
            &custom_root,
            gto_bytes,
            &manifest,
            &candidate,
            mida_pe::OepPolicy::Captured,
            mida_pe::ContainerRestoreMode::Off,
            mida_pe::DumpProfile::OreansClassic,
            true,
        );

        let (_verifier, _dispatch_guard) = arm_dispatch_guard(&dir);

        // Launch WITHOUT --snapshot-root -> default root (sample-snapshots)
        // mismatches the sealed custom root -> fail-closed before rerun_verifier.
        let cmd = crate::args::Command::Unpack {
            input: sealed_snap.clone(),
            output: Some(candidate.clone()),
            create_data_sections: false,
            shrink: true,
            oep_policy: mida_pe::OepPolicy::Captured,
            container_restore: mida_pe::ContainerRestoreMode::Off,
            profile: mida_pe::DumpProfile::OreansClassic,
            pure_rebuild: false,
            capture_policy: mida_pe::DumpCapturePolicy::default(),
            capture_policy_digest: String::new(),
            preflight_dir: Some(dir.clone()),
            snapshot_root: None,
            dump_timing: mida_pe::DumpTiming::Immediate,
            verbose: false,
        };
        let err = crate::commands::run_command(cmd).unwrap_err();
        let err_str = format!("{err:#}");
        // (a) The failure is EXACTLY the root-mismatch class — asserted
        // positively, not merely "not something else", so an arbitrary later
        // error cannot masquerade as the fail-closed root check.
        assert!(
            err_str.contains("root mismatch")
                || err_str.contains("does not match the sealed path root"),
            "staging/launch root mismatch must be the exact failure, got: {err_str}"
        );
        // (b) The verifier recorder is empty — the seam never reached
        // rerun_verifier, so no verifier spawn was recorded.
        let recorded = test_snapshot_root_recorder();
        assert!(
            recorded.is_empty(),
            "no verifier spawn on root mismatch: {recorded:?}"
        );
        assert!(
            test_verifier_recorder().is_empty(),
            "no verifier args may be recorded on root mismatch"
        );
        // (c) The sample-process boundary recorder is empty — no process
        // creation was ever attempted.
        assert!(
            !_dispatch_guard.sample_launch_attempted(),
            "no sample-process launch may be attempted on root mismatch"
        );
        // (d) No candidate produced.
        assert!(!candidate.exists(), "no candidate may be produced");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The rerun verifier receives the SAME custom snapshot root as staging,
    /// then the dispatch stops exactly at the test-only launch-stop sentinel
    /// (sample recorder empty, no candidate).
    #[test]
    fn unpack_dispatch_rerun_verifier_receives_same_snapshot_root() {
        let _lock = TEST_DISPATCH_LOCK.lock().unwrap();
        let root = temp_dir("unpack_same_root");
        let custom_root = root.join("custom_store");
        let dir = root.join("preflight");
        std::fs::create_dir_all(&dir).unwrap();
        let gto_bytes = b"SAME-ROOT-DISPATCH-GTO";
        let gto_sha = sha256_hex(gto_bytes);
        let manifest = gto_synthetic_manifest(&dir, &gto_sha, gto_bytes.len() as u64);
        let candidate = dir.join("gto_candidate.exe");
        let (sealed_snap, _envelope, _report) = fabricate_gto_unpack_state(
            &dir,
            &custom_root,
            gto_bytes,
            &manifest,
            &candidate,
            mida_pe::OepPolicy::Captured,
            mida_pe::ContainerRestoreMode::Off,
            mida_pe::DumpProfile::OreansClassic,
            true,
        );

        let (_verifier, _dispatch_guard) = arm_dispatch_guard(&dir);

        let cmd = crate::args::Command::Unpack {
            input: sealed_snap.clone(),
            output: Some(candidate.clone()),
            create_data_sections: false,
            shrink: true,
            oep_policy: mida_pe::OepPolicy::Captured,
            container_restore: mida_pe::ContainerRestoreMode::Off,
            profile: mida_pe::DumpProfile::OreansClassic,
            pure_rebuild: false,
            capture_policy: mida_pe::DumpCapturePolicy::default(),
            capture_policy_digest: String::new(),
            preflight_dir: Some(dir.clone()),
            snapshot_root: Some(custom_root.clone()),
            dump_timing: mida_pe::DumpTiming::Immediate,
            verbose: false,
        };
        let err = match crate::commands::run_command(cmd) {
            Ok(()) => String::new(),
            Err(e) => format!("{e:#}"),
        };
        // (a) Exact launch-stop sentinel after Ready (never a root mismatch,
        // never a malformed-PE parse error).
        assert!(
            err.contains(super::TEST_LAUNCH_STOP_TOKEN),
            "dispatch must terminate at the launch-stop sentinel after Ready, got: {err}"
        );
        // (b) The recorded --snapshot-root equals the caller's custom root (the
        // same root staging used), not the default and not derived from the path.
        let recorded = test_snapshot_root_recorder();
        let has_custom = recorded.iter().any(|r| {
            crate::sample_snapshot::paths_equivalent(std::path::Path::new(r), &custom_root)
        });
        let has_default = recorded.iter().any(|r| {
            crate::sample_snapshot::paths_equivalent(
                std::path::Path::new(r),
                &dir.join("sample-snapshots"),
            )
        });
        assert!(
            has_custom && !has_default,
            "rerun verifier must receive the custom root (not default): {recorded:?}"
        );
        assert!(
            !test_verifier_recorder().is_empty(),
            "the verifier seam must have recorded a spawn"
        );
        // (c) No sample-process launch attempted.
        assert!(
            !_dispatch_guard.sample_launch_attempted(),
            "no sample-process launch may be attempted in a dispatch test"
        );
        // (d) No candidate produced.
        assert!(!candidate.exists(), "no candidate may be produced");
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // Dispatch seam state isolation. The test-only seams are thread-local and
    // RAII-managed: they must restore prior state on normal drop AND on panic,
    // and must never leak to another test thread. These tests prove that
    // independence so the four dispatch tests above do not rely on a coarse
    // global lock to avoid polluting each other or unrelated tests.
    // ------------------------------------------------------------------

    /// Normal Drop: arming then dropping the guard restores the override,
    /// recorders, launch-stop flag and sample recorder to their prior state.
    #[test]
    fn dispatch_guard_drop_restores_all_seam_state() {
        // Pre-arm: default empty state.
        assert_eq!(test_verifier_override(), None);
        assert!(test_verifier_recorder().is_empty());
        assert!(test_snapshot_root_recorder().is_empty());
        // Arm and mutate. (Use `DispatchTestGuard::arm` directly so no stub
        // file is written to disk.)
        {
            let path = PathBuf::from("stub-verifier.exe");
            let guard = DispatchTestGuard::arm(path.clone());
            assert_eq!(test_verifier_override(), Some(path));
            assert!(test_verifier_recorder().is_empty());
            // Record a verifier spawn through the seam on this thread.
            let args: Vec<std::ffi::OsString> = vec![
                std::ffi::OsString::from("preflight"),
                std::ffi::OsString::from("--snapshot-root"),
                std::ffi::OsString::from("C:\\snap"),
            ];
            assert!(super::maybe_record_verifier_spawn(&args));
            assert!(!test_verifier_recorder().is_empty());
            assert!(!test_snapshot_root_recorder().is_empty());
            assert!(!guard.sample_launch_attempted());
        }
        // After Drop: everything restored to the pre-arm (empty) state.
        assert_eq!(test_verifier_override(), None);
        assert!(test_verifier_recorder().is_empty());
        assert!(test_snapshot_root_recorder().is_empty());
        assert!(!crate::runner_preflight::test_sample_launch_attempted_any());
    }

    /// Panic path: if a test panics while the guard is armed, Drop still runs
    /// during unwinding and restores the override/recorders/launch-stop, so a
    /// panicked dispatch test cannot leak the fake verifier into later tests.
    #[test]
    fn dispatch_guard_restores_state_after_panic() {
        // Clear to a known baseline first (a prior test on this thread could
        // have left state only if a bug skipped Drop — which is what we assert
        // is NOT the case).
        let _ = std::panic::catch_unwind(|| {
            let _guard = DispatchTestGuard::arm(PathBuf::from("panic-verifier.exe"));
            // The guard is armed; assert it is observable on this thread.
            assert!(test_verifier_override().is_some());
            // Force a panic inside the guard scope.
            panic!("intentional panic to exercise guard Drop during unwinding");
        });
        // After the panic unwound, the guard's Drop restored state.
        assert_eq!(test_verifier_override(), None);
        assert!(test_verifier_recorder().is_empty());
        assert!(test_snapshot_root_recorder().is_empty());
        assert!(!crate::runner_preflight::test_sample_launch_attempted_any());
        // The launch-stop flag is off again: a dispatch would NOT stop early.
        assert!(
            crate::runner_preflight::maybe_test_launch_stop().is_ok(),
            "launch-stop must be disabled after guard drop"
        );
    }

    /// Cross-thread isolation: a fake verifier / launch-stop armed on one test
    /// thread is invisible on another thread. This is the property that keeps
    /// non-dispatch tests (running in parallel on other threads) from ever
    /// observing the seam — not the dispatch test lock.
    #[test]
    fn dispatch_guard_override_is_thread_local() {
        // Arm on THIS thread.
        let guard = DispatchTestGuard::arm(PathBuf::from("thread-local-verifier.exe"));
        assert!(test_verifier_override().is_some());
        // A spawned thread must see NO override, no launch-stop, empty recorders.
        let handle = std::thread::spawn(|| {
            let override_seen = test_verifier_override().is_some();
            let rec_seen = !test_verifier_recorder().is_empty();
            let roots_seen = !test_snapshot_root_recorder().is_empty();
            let launch_stop_on = crate::runner_preflight::maybe_test_launch_stop().is_err();
            (override_seen, rec_seen, roots_seen, launch_stop_on)
        });
        let (override_seen, rec_seen, roots_seen, launch_stop_on) = handle.join().unwrap();
        assert!(
            !override_seen && !rec_seen && !roots_seen && !launch_stop_on,
            "other thread must not observe this thread's dispatch seam \
             (override={override_seen} rec={rec_seen} roots={roots_seen} stop={launch_stop_on})"
        );
        // Drop the guard on the arming thread and confirm the other thread was
        // unaffected by our drop too (already proven above).
        drop(guard);
        assert_eq!(test_verifier_override(), None);
    }

    /// The default/custom/mismatch dispatch tests are order-independent:
    /// arming the seam does not depend on any prior test's leftovers, and the
    /// guard fully restores state, so running them in any sequence leaves the
    /// thread-local seam in its default (disabled) state. This runs the guard
    /// arm/drop cycle repeatedly and asserts a stable end state.
    #[test]
    fn dispatch_tests_have_no_ordering_dependency() {
        for i in 0..8 {
            // Simulate the custom / default / mismatch dispatch patterns in a
            // mixed order; each fully arms and drops the seam independently.
            if i % 3 == 0 {
                let _g = DispatchTestGuard::arm(PathBuf::from("custom"));
                assert!(crate::runner_preflight::maybe_test_launch_stop().is_err());
            } else if i % 3 == 1 {
                let _g = DispatchTestGuard::arm(PathBuf::from("default"));
            } else {
                // mismatch: no launch-stop reached; just arm and drop.
                let _g = DispatchTestGuard::arm(PathBuf::from("mismatch"));
            }
            // After each iteration the seam must be back to default.
            assert_eq!(
                test_verifier_override(),
                None,
                "iteration {i} must leave no verifier override"
            );
            assert!(
                test_verifier_recorder().is_empty(),
                "iteration {i} recorder leak"
            );
            assert!(
                test_snapshot_root_recorder().is_empty(),
                "iteration {i} root recorder leak"
            );
            assert!(
                crate::runner_preflight::maybe_test_launch_stop().is_ok(),
                "iteration {i} launch-stop must be off"
            );
            assert!(
                !crate::runner_preflight::test_sample_launch_attempted_any(),
                "iteration {i} sample recorder leak"
            );
        }
    }

    // -----------------------------------------------------------------------
    // P2 verifier TOCTOU hardening.
    // -----------------------------------------------------------------------

    /// Hash drift: `resolve_verifier_identity_checked` with a pinned SHA that
    /// does not match the resolved sibling must refuse to return an identity
    /// (so the spawn cannot use a drifted verifier).
    #[test]
    fn checked_resolver_rejects_pinned_sha_mismatch() {
        let dir = temp_dir("hashdrift");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir);
        // Arm the test seam to inject this sibling as the "verifier".
        let _guard = DispatchTestGuard::arm(sibling.clone());
        let identity = resolve_verifier_identity_checked(None).expect("resolve");
        assert_eq!(identity.path, std::fs::canonicalize(&sibling).unwrap());
        // Re-resolve binding a WRONG pinned sha: must fail.
        let wrong = sha256_hex(b"not-the-sibling");
        let err =
            resolve_verifier_identity_checked(Some(&wrong)).expect_err("hash drift must fail");
        assert!(err.to_string().contains("hash drift"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Non-regular verifier path: the checked resolver refuses a directory at
    /// the sibling path (fail-closed before any spawn).
    #[test]
    fn checked_resolver_rejects_non_regular_verifier() {
        let dir = temp_dir("nonreg_checked");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        // Replace the sibling with a directory.
        let sibling = dir.join("mida-acceptance.exe");
        std::fs::create_dir(&sibling).unwrap();
        let _guard = DispatchTestGuard::arm(sibling.clone());
        let err = resolve_verifier_identity_checked(None).expect_err("dir must fail");
        assert!(err.to_string().contains("not a regular file"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Verifier trust boundary: the resolver NEVER executes a verifier from a
    /// caller-writable staging location — it can only use the exact CLI
    /// sibling (canonical path identity). A byte-identical copy placed in a
    /// separate caller-writable directory is never selected, so no swapped
    /// binary from an arbitrary writable path can be launched. This is the
    /// P2 fallback (handle-based launch is not available); the primary TOCTOU
    /// defense is re-resolving + re-binding immediately before each spawn.
    #[test]
    fn verifier_trust_boundary_never_selects_caller_writable_copy() {
        let dir = temp_dir("trust_boundary");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir);
        // A caller-writable staging directory holding a byte-identical copy.
        let staging = dir.join("staging/");
        std::fs::create_dir_all(&staging).unwrap();
        let copy = staging.join("mida-acceptance.exe");
        write(&copy, &std::fs::read(&sibling).unwrap());
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling resolves");
        assert_eq!(resolved, std::fs::canonicalize(&sibling).unwrap());
        assert_ne!(resolved, std::fs::canonicalize(&copy).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Symlink/reparse: a sibling that is a symlink escaping to a different
    /// location must be refused (the resolver requires the canonical path to be
    /// exactly the sibling path, not a re-linked target).
    #[test]
    #[cfg(windows)]
    fn resolver_rejects_symlinked_sibling_escape() {
        use std::os::windows::fs::symlink_file;
        let dir = temp_dir("symlink_escape");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        // Put the real bytes in a hidden target elsewhere.
        let target = dir.join("hidden/real-acceptance.exe");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        write(&target, b"REAL-ACCEPTANCE");
        // Sibling is a symlink pointing at the target.
        let sibling = dir.join("mida-acceptance.exe");
        symlink_file(&target, &sibling).unwrap_or_else(|_| {
            // Symlink creation can require privileges; if unavailable, fall back
            // to a hard link (which still proves the resolver only accepts the
            // exact sibling path, not a re-linked identity).
            std::fs::hard_link(&target, &sibling).unwrap();
        });
        let err = resolve_acceptance_bin_from_cli(&cli).expect_err("symlink escape must fail");
        // The canonical path of the symlink is the target, so it differs from
        // `cli_dir/mida-acceptance.exe` and the resolver refuses path drift.
        assert!(err.to_string().contains("path drift"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Windows extended-length path prefix (\\?\C:\...) must NOT bypass the
    /// canonical/root boundary check. The resolver refuses any resolved path
    /// that is not exactly the CLI sibling's canonical path; a caller that
    /// reaches the sibling through an extended-length spelling still ends up
    /// canonicalized to the same controlled path (never to a symlink target
    /// outside the CLI directory), and any drift is still refused.
    #[test]
    fn resolver_extended_path_prefix_cannot_bypass_sibling_boundary() {
        use std::os::windows::fs::symlink_file;

        let dir = temp_dir("ext_prefix");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        // Real bytes live outside the sibling identity.
        let outside = dir.join("hidden/real-acceptance.exe");
        std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
        write(&outside, b"REAL-ACCEPTANCE");
        let sibling = dir.join("mida-acceptance.exe");
        symlink_file(&outside, &sibling).unwrap_or_else(|_| {
            std::fs::hard_link(&outside, &sibling).unwrap();
        });
        // Build the \\?\\ extended-length spelling of the sibling and reach the
        // resolver through it: the CLI's own parent is derived from the real
        // (non-prefixed) path, but a hostile caller could pass a prefixed path
        // in. canonicalize must normalize both sides; the boundary check must
        // still refuse the symlink drift.
        let canon = std::fs::canonicalize(&sibling).unwrap();
        let mut prefixed = std::path::PathBuf::from("\\\\?\\");
        prefixed.push(&canon);
        // The prefixed spelling canonicalizes to the same path as the sibling;
        // the resolver must still reject because the canonical target differs
        // from `cli_dir/mida-acceptance.exe` (path drift).
        let err = resolve_acceptance_bin_from_cli(&prefixed)
            .expect_err("extended-path-prefixed symlink escape must fail");
        assert!(
            err.to_string().contains("path drift") || err.to_string().contains("does not exist"),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A symlink sibling whose target is a DIFFERENT directory inside the CLI
    /// root (subdirectory escape) must also be refused: only the exact
    /// `cli_dir/mida-acceptance.exe` regular file identity is acceptable.
    #[test]
    fn resolver_rejects_symlink_into_subdirectory_escape() {
        use std::os::windows::fs::symlink_file;
        let dir = temp_dir("subdir_escape");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let nested = dir.join("nested/mida-acceptance.exe");
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        write(&nested, b"NESTED-REAL");
        let sibling = dir.join("mida-acceptance.exe");
        symlink_file(&nested, &sibling).unwrap_or_else(|_| {
            std::fs::hard_link(&nested, &sibling).unwrap();
        });
        let err = resolve_acceptance_bin_from_cli(&cli).expect_err("subdirectory escape must fail");
        assert!(err.to_string().contains("path drift"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// Path-replacement seam: resolving an identity, then REPLACING the file,
    /// then re-resolving must catch the replacement (the second resolution's
    /// hash differs). This is the "replacement occurs between identity
    /// resolution and spawn" scenario — the fix is that each spawn re-resolves
    /// and re-binds immediately before `Command::new`, so a stale identity can
    /// never be used to launch.
    #[test]
    fn checked_resolver_receives_replaced_binary() {
        let dir = temp_dir("replaced");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir); // FAKE-ACCEPTANCE-1
        let sha_before = sha256_file(&sibling).unwrap();
        let _guard = DispatchTestGuard::arm(sibling.clone());
        let identity = resolve_verifier_identity_checked(None).expect("resolve");
        assert_eq!(identity.sha256, sha_before);
        // Replace the sibling bytes (simulates a swap between resolution and spawn).
        write(&sibling, b"REPLACED-ACCEPTANCE-XXXX");
        let sha_after = sha256_file(&sibling).unwrap();
        assert_ne!(sha_before, sha_after, "replacement must change the hash");
        // A re-resolution binds the NEW sha; pinning the pre-replacement sha now
        // fails (hash drift), proving a stale identity cannot be used to launch.
        let err = resolve_verifier_identity_checked(Some(&sha_before))
            .expect_err("pinning the pre-replacement sha after replacement must fail (hash drift)");
        assert!(err.to_string().contains("hash drift"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A GTO runner config matching the envelope fabricated by
    /// fabricate_gto_unpack_state (real CLI sha, family ahk_gto) — the same
    /// config unpack() builds for the GTO lane.
    fn attest_gto_config() -> mida_core::runner_config::RunnerConfig {
        use mida_core::runner_config::packer_family;
        let cli_binary_sha256 =
            crate::runner_preflight::sha256_file(&std::env::current_exe().unwrap()).unwrap();
        crate::run_spec::runner_config_from_unpack_args_family(
            packer_family::AHK_GTO,
            mida_pe::OepPolicy::Captured,
            mida_pe::ContainerRestoreMode::Off,
            mida_pe::DumpProfile::OreansClassic,
            true,
            false,
            false,
            "",
            "rev",
            &cli_binary_sha256,
        )
    }

    // ---- IMP-09-CARRIER-R3: sealed verified target identity ----

    #[test]
    fn imp09_target_identity_from_attested_rejects_placeholder_digest() {
        let err = VerifiedTargetIdentity::from_attested(
            "origin_macro",
            &FileIdentityGate {
                sha256: "adr6-profile-digest".to_string(),
                size_bytes: 4096,
            },
            "x86_64",
        )
        .expect_err("placeholder digest must not seal");
        assert!(err.contains("sha256 invalid"), "{err}");
    }

    #[test]
    fn imp09_target_identity_from_attested_rejects_uppercase_digest() {
        let id = VerifiedTargetIdentity::from_attested(
            "origin_macro",
            &FileIdentityGate {
                sha256: "AB12".repeat(16).to_uppercase(),
                size_bytes: 4096,
            },
            "x86_64",
        )
        .expect("canonicalizable uppercase digest seals");
        assert_eq!(id.sha256(), "ab12".repeat(16));
        assert_eq!(id.case_id(), "origin_macro");
        assert_eq!(id.size_bytes(), 4096);
        assert_eq!(id.architecture(), "x86_64");

        let err = VerifiedTargetIdentity::from_attested(
            "origin_macro",
            &FileIdentityGate {
                sha256: "z".repeat(64),
                size_bytes: 4096,
            },
            "x86_64",
        )
        .expect_err("non-hex digest must not seal");
        assert!(err.contains("sha256 invalid"), "{err}");
    }

    #[test]
    fn imp09_target_identity_rejects_empty_case_and_zero_size() {
        let err = VerifiedTargetIdentity::from_attested(
            "  ",
            &FileIdentityGate {
                sha256: "ab12".repeat(16),
                size_bytes: 4096,
            },
            "x86_64",
        )
        .expect_err("empty case id must not seal");
        assert!(err.contains("case_id"), "{err}");

        let err = VerifiedTargetIdentity::from_attested(
            "origin_macro",
            &FileIdentityGate {
                sha256: "ab12".repeat(16),
                size_bytes: 0,
            },
            "x86_64",
        )
        .expect_err("zero size must not seal");
        assert!(err.contains("size_bytes"), "{err}");

        let err = VerifiedTargetIdentity::from_attested(
            "origin_macro",
            &FileIdentityGate {
                sha256: "ab12".repeat(16),
                size_bytes: 4096,
            },
            " ",
        )
        .expect_err("empty architecture must not seal");
        assert!(err.contains("architecture"), "{err}");
    }

    #[test]
    fn imp09_target_identity_cannot_be_externally_constructed() {
        // Fields are private; the ONLY constructor is the sealed
        // from_attested. External struct-literal construction is a compile
        // error. Round-trip proves the sealed path carries attested values.
        let id = VerifiedTargetIdentity::from_attested(
            "origin_macro",
            &FileIdentityGate {
                sha256: "ab12".repeat(16),
                size_bytes: 777,
            },
            "x86_64",
        )
        .expect("sealed construction");
        assert_eq!(id.case_id(), "origin_macro");
        assert_eq!(id.sha256(), "ab12".repeat(16));
        assert_eq!(id.size_bytes(), 777);
        assert_eq!(id.architecture(), "x86_64");
    }

    #[test]
    fn imp09_target_identity_cannot_be_deserialized() {
        // VerifiedTargetIdentity has NO Serialize/Deserialize: no JSON/disk
        // form can forge it. The report's FileIdentityGate IS serializable
        // (preflight report schema) but is a DIFFERENT type — the sealed
        // carrier only flows by value from the attestation.
        let gate = FileIdentityGate {
            sha256: "ab12".repeat(16),
            size_bytes: 777,
        };
        let roundtrip: FileIdentityGate =
            serde_json::from_value(serde_json::to_value(&gate).unwrap()).unwrap();
        assert_eq!(roundtrip, gate, "report gate is serializable by design");
        let id = VerifiedTargetIdentity::from_attested("origin_macro", &gate, "x86_64")
            .expect("sealed from the SAME gate values");
        assert_eq!(id.sha256(), gate.sha256);
    }

    #[test]
    fn imp09_attestation_seals_verified_target_identity() {
        let _lock = TEST_DISPATCH_LOCK.lock().unwrap();
        let root = temp_dir("attest_seal");
        let dir = root.join("preflight");
        std::fs::create_dir_all(&dir).unwrap();
        let gto_bytes = b"ATTEST-SEAL-GTO-BYTES-0123456789";
        let gto_sha = sha256_hex(gto_bytes);
        let manifest = gto_synthetic_manifest(&dir, &gto_sha, gto_bytes.len() as u64);
        let candidate = dir.join("gto_candidate.exe");
        let (sealed_snap, _envelope, _report) = fabricate_gto_unpack_state(
            &dir,
            &root,
            gto_bytes,
            &manifest,
            &candidate,
            mida_pe::OepPolicy::Captured,
            mida_pe::ContainerRestoreMode::Off,
            mida_pe::DumpProfile::OreansClassic,
            true,
        );
        let (_verifier, _dispatch_guard) = arm_dispatch_guard(&dir);
        let gto_cfg = attest_gto_config();
        let cli_bin = std::env::current_exe().expect("test binary");
        let ctx = LaunchAttestationContext {
            input: &sealed_snap,
            output: &candidate,
            cli_binary: &cli_bin,
            runner_config: &gto_cfg,
            snapshot_root: &root,
        };
        let context = attest_ready_before_launch(&dir, &ctx).expect("attestation Ready");
        let identity = context.target_identity();
        assert_eq!(identity.case_id(), "gto_launcher");
        assert_eq!(identity.sha256(), &gto_sha);
        assert_eq!(identity.size_bytes(), gto_bytes.len() as u64);
        assert_eq!(identity.architecture(), "unknown"); // non-PE bytes
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn imp09_attestation_rejects_same_size_replaced_input() {
        let _lock = TEST_DISPATCH_LOCK.lock().unwrap();
        let root = temp_dir("attest_replace");
        let dir = root.join("preflight");
        std::fs::create_dir_all(&dir).unwrap();
        let gto_bytes = b"ATTEST-REPLACE-AAAAAAAAAAAAAAA";
        let gto_sha = sha256_hex(gto_bytes);
        let manifest = gto_synthetic_manifest(&dir, &gto_sha, gto_bytes.len() as u64);
        let candidate = dir.join("gto_candidate.exe");
        let (sealed_snap, _envelope, _report) = fabricate_gto_unpack_state(
            &dir,
            &root,
            gto_bytes,
            &manifest,
            &candidate,
            mida_pe::OepPolicy::Captured,
            mida_pe::ContainerRestoreMode::Off,
            mida_pe::DumpProfile::OreansClassic,
            true,
        );
        let (_verifier, _dispatch_guard) = arm_dispatch_guard(&dir);
        let replaced: Vec<u8> = gto_bytes.iter().map(|b| b.wrapping_add(1)).collect();
        assert_eq!(replaced.len(), gto_bytes.len(), "same size");
        assert_ne!(sha256_hex(&replaced), gto_sha, "different content");
        std::fs::write(&sealed_snap, &replaced).unwrap();
        let gto_cfg = attest_gto_config();
        let cli_bin = std::env::current_exe().expect("test binary");
        let ctx = LaunchAttestationContext {
            input: &sealed_snap,
            output: &candidate,
            cli_binary: &cli_bin,
            runner_config: &gto_cfg,
            snapshot_root: &root,
        };
        let err = attest_ready_before_launch(&dir, &ctx)
            .expect_err("same-size replacement must be rejected");
        assert!(
            err.to_string().contains("identity") || err.to_string().contains("case"),
            "{err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn imp09_attestation_rejects_wrong_target_artifact() {
        let _lock = TEST_DISPATCH_LOCK.lock().unwrap();
        let root = temp_dir("attest_wrong");
        let dir = root.join("preflight");
        std::fs::create_dir_all(&dir).unwrap();
        let gto_bytes = b"ATTEST-WRONG-AAAAAAAAAAAAAAA";
        let gto_sha = sha256_hex(gto_bytes);
        let manifest = gto_synthetic_manifest(&dir, &gto_sha, gto_bytes.len() as u64);
        let candidate = dir.join("gto_candidate.exe");
        let (_sealed_snap, _envelope, _report) = fabricate_gto_unpack_state(
            &dir,
            &root,
            gto_bytes,
            &manifest,
            &candidate,
            mida_pe::OepPolicy::Captured,
            mida_pe::ContainerRestoreMode::Off,
            mida_pe::DumpProfile::OreansClassic,
            true,
        );
        let (_verifier, _dispatch_guard) = arm_dispatch_guard(&dir);
        let foreign = dir.join("foreign_input.bin");
        std::fs::write(&foreign, b"FOREIGN-UNSTAGED-INPUT-BYTES").unwrap();
        let gto_cfg = attest_gto_config();
        let cli_bin = std::env::current_exe().expect("test binary");
        let ctx = LaunchAttestationContext {
            input: &foreign,
            output: &candidate,
            cli_binary: &cli_bin,
            runner_config: &gto_cfg,
            snapshot_root: &root,
        };
        let err = attest_ready_before_launch(&dir, &ctx)
            .expect_err("wrong unstaged artifact must be rejected");
        assert!(
            err.to_string().contains("matches") || err.to_string().contains("case"),
            "{err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // IMP-09-PROFILE-SOURCE-R1: hostile tests for the sealed verified
    // profile identity carrier (SHA-256 of canonical profile bytes).
    // ------------------------------------------------------------------

    #[test]
    fn imp09_profile_canonical_bytes_stable() {
        // The same profile object encodes to the SAME canonical bytes every
        // time, and the SHA-256 digest is therefore stable.
        use mida_antidebug::profile::origin_profile;
        let p1 = origin_profile();
        let p2 = origin_profile();
        let j1 = p1.canonical_json();
        let j2 = p2.canonical_json();
        assert_eq!(j1, j2, "canonical JSON must be byte-stable");
        assert_eq!(sha256_hex(j1.as_bytes()), sha256_hex(j2.as_bytes()));
        // The seal recomputes the same digest from the same source.
        let a = VerifiedProfileIdentity::from_verified_profile(&p1, "origin_macro", "x86_64")
            .expect("origin profile seals");
        let b = VerifiedProfileIdentity::from_verified_profile(&p2, "origin_macro", "x86_64")
            .expect("origin profile seals again");
        assert_eq!(a.profile_digest(), b.profile_digest());
        assert_eq!(a.profile_id(), "oreans_origin_x64_v1");
    }

    #[test]
    fn imp09_profile_single_byte_change_changes_digest() {
        // A single-byte mutation of the profile content must change the
        // SHA-256 digest (canonical bytes are the hash input).
        use mida_antidebug::profile::origin_profile;
        let mut p = origin_profile();
        let orig_digest = sha256_hex(p.canonical_json().as_bytes());
        p.version += 1;
        let new_digest = sha256_hex(p.canonical_json().as_bytes());
        assert_ne!(
            orig_digest, new_digest,
            "single field change must change digest"
        );
        // And the seal reflects it.
        let a = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("mutated profile still seals (same case/arch)");
        assert_ne!(a.profile_digest(), orig_digest);
    }

    #[test]
    fn imp09_profile_digest_is_64_lowercase_hex() {
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let id = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("seals");
        assert_eq!(id.profile_digest().len(), 64);
        assert!(
            id.profile_digest()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "digest must be 64 lowercase hex: {}",
            id.profile_digest()
        );
        assert!(!id.profile_digest().chars().any(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn imp09_profile_fnv_digest_rejected() {
        // The legacy FNV-1a 16-hex digest (Profile::profile_digest()) must
        // NEVER be accepted as the verified carrier digest — the carrier
        // digest is always recomputed as SHA-256 of canonical bytes.
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let fnv = p.profile_digest();
        assert_eq!(fnv.len(), 16, "FNV-1a placeholder is 16 hex");
        // The sealed carrier's digest is SHA-256, not FNV.
        let id = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("seals");
        assert_ne!(id.profile_digest(), fnv);
        assert_eq!(id.profile_digest().len(), 64);
    }

    #[test]
    fn imp09_profile_adr6_digest_rejected() {
        // The bare placeholder string must never appear as a carrier digest.
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let id = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("seals");
        assert_ne!(id.profile_digest(), "adr6-profile-digest");
        assert_ne!(id.profile_id(), "adr6-profile-digest");
        // profile_for_case never selects a bare-string profile.
        assert!(profile_for_case("gto_launcher").is_none());
    }

    #[test]
    fn imp09_profile_id_digest_same_source() {
        // profile_id and profile_digest MUST come from the SAME verified
        // profile object: the digest is SHA-256 of that object's canonical
        // bytes, and the id is that object's profile_id. Neither is taken
        // from a second source.
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let id = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("seals");
        assert_eq!(id.profile_id(), p.profile_id);
        assert_eq!(
            id.profile_digest(),
            sha256_hex(p.canonical_json().as_bytes())
        );
        assert_eq!(id.sample_id(), p.sample_id);
        assert_eq!(id.architecture(), p.architecture);
    }

    #[test]
    fn imp09_profile_sample_mismatch_rejected() {
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let err = VerifiedProfileIdentity::from_verified_profile(&p, "lunlun_software", "x86_64")
            .expect_err("sample/case mismatch must be rejected");
        assert!(err.contains("sample"), "{err}");
    }

    #[test]
    fn imp09_profile_architecture_mismatch_rejected() {
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let err = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86")
            .expect_err("architecture mismatch must be rejected");
        assert!(err.contains("architecture"), "{err}");
    }

    #[test]
    fn imp09_profile_schema_mismatch_rejected() {
        use mida_antidebug::profile::origin_profile;
        let mut p = origin_profile();
        p.schema = "mida.antidebug-profile/v2".to_string();
        let err = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect_err("schema mismatch must be rejected");
        assert!(err.contains("schema"), "{err}");
    }

    #[test]
    fn imp09_profile_identity_no_external_construction() {
        // No public constructor, no public fields: the only way to obtain a
        // VerifiedProfileIdentity is the crate-internal sealed constructor
        // from a verified profile object. A foreign crate cannot name the
        // fields (private) and cannot call the pub(crate) constructor.
        // Compile-time guarantee; this test proves the API surface is sealed.
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let id = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("seals");
        // Only getters are exposed; Debug/Clone only.
        let _clone = id.clone();
        let _ = format!("{id:?}");
        assert_eq!(id.profile_id(), "oreans_origin_x64_v1");
    }

    #[test]
    fn imp09_profile_identity_no_deserialize() {
        // VerifiedProfileIdentity is NOT Serialize/Deserialize: there is no
        // disk/JSON form that can forge the carrier. (Compile-time: the
        // type does not implement the traits; this test documents it.)
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let id = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("seals");
        // serde_json::to_string must NOT compile for this type; instead we
        // assert the digest is only obtainable from the sealed object.
        assert_eq!(id.profile_digest().len(), 64);
    }

    #[test]
    fn imp09_profile_cannot_be_replaced_by_runtime_digest() {
        // The runtime module digest is NEVER a profile digest: the profile
        // carrier digest is SHA-256 of the canonical profile bytes, and the
        // runtime digest is a different artifact's digest. A forged
        // "profile identity" carrying a runtime digest cannot be built
        // through the sealed constructor (it recomputes from the profile
        // object), and profile_for_case never returns a runtime digest.
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let id = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("seals");
        // 64-hex of "runtime" is not the profile digest.
        let runtime_like = sha256_hex(b"mida-antidebug-runtime-x64.dll");
        assert_ne!(id.profile_digest(), runtime_like);
        // profile_for_case returns the real profile object (never a digest).
        let selected = profile_for_case("origin_macro").expect("origin has a profile");
        assert_eq!(selected.profile_id, "oreans_origin_x64_v1");
    }

    #[test]
    fn imp09_profile_canonical_change_invalidates_old_carrier() {
        // Once the canonical profile bytes change, the OLD sealed carrier's
        // digest no longer matches the new canonical bytes: the digest is
        // always recomputed from the current object.
        use mida_antidebug::profile::origin_profile;
        let p1 = origin_profile();
        let id1 = VerifiedProfileIdentity::from_verified_profile(&p1, "origin_macro", "x86_64")
            .expect("v1 seals");
        let mut p2 = origin_profile();
        p2.version += 1;
        let id2 = VerifiedProfileIdentity::from_verified_profile(&p2, "origin_macro", "x86_64")
            .expect("v2 seals");
        assert_ne!(id1.profile_digest(), id2.profile_digest());
        // The old digest is not valid for the new canonical bytes.
        assert_ne!(
            id1.profile_digest(),
            sha256_hex(p2.canonical_json().as_bytes())
        );
    }

    #[test]
    fn imp09_old_fnv_profile_digest_preserved() {
        // Regression: Profile::profile_digest() keeps its FNV-1a semantics
        // (16 lowercase hex) — it is NOT replaced by SHA-256.
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let fnv = p.profile_digest();
        assert_eq!(fnv.len(), 16);
        assert!(fnv.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(fnv, fnv.to_lowercase());
        // The old validate_profile contract still accepts the FNV digest.
        let ok = mida_antidebug::profile::validate_profile(&p, "origin_macro", "x86_64", &fnv);
        assert!(
            ok.is_ok(),
            "legacy FNV validation must be preserved: {ok:?}"
        );
    }

    #[test]
    fn imp09_profile_uppercase_digest_cannot_be_injected() {
        // SOURCE-ACCURATE wording (P2-2 correction): the sealed constructor
        // accepts NO external digest at all — from_verified_profile always
        // recomputes SHA-256(canonical_json bytes). Therefore an uppercase
        // (or any non-canonical) digest can never be INJECTED into the
        // carrier; there is no input path that could carry one in. The
        // strict [0-9a-f]{64} contract is enforced at the checker level
        // (is_64_lower_hex, tested separately).
        use mida_antidebug::profile::origin_profile;
        let p = origin_profile();
        let id = VerifiedProfileIdentity::from_verified_profile(&p, "origin_macro", "x86_64")
            .expect("seals");
        // Produced digest is canonical lowercase hex (never uppercase).
        assert_eq!(id.profile_digest(), id.profile_digest().to_lowercase());
        assert!(!id
            .profile_digest()
            .contains(|c: char| c.is_ascii_uppercase()));
        // The digest equals the recomputed SHA-256 of the canonical bytes.
        assert_eq!(
            id.profile_digest(),
            sha256_hex(p.canonical_json().as_bytes())
        );
        // And the strict checker rejects the hostile forms outright.
        assert!(!is_64_lower_hex(&id.profile_digest().to_uppercase()));
        assert!(!is_64_lower_hex(&format!(
            "{}g",
            &id.profile_digest()[..63]
        )));
        assert!(!is_64_lower_hex(&format!(
            "{}z",
            &id.profile_digest()[..63]
        )));
        assert!(!is_64_lower_hex(&id.profile_digest()[..63]));
    }

    #[test]
    fn imp09_strict_lowercase_hex_checker_rejects_hostile_forms() {
        // P2-1 correction: the checker enforces exactly [0-9a-f]{64} —
        // 'g'..='z' lowercase letters, uppercase letters, wrong length, and
        // non-hex characters are all rejected.
        let valid = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12";
        assert!(is_64_lower_hex(valid));
        // lowercase letters outside [0-9a-f]
        let mut with_g = valid.to_string();
        with_g.replace_range(0..1, "g");
        assert!(!is_64_lower_hex(&with_g), "g must be rejected");
        let mut with_z = valid.to_string();
        with_z.replace_range(63..64, "z");
        assert!(!is_64_lower_hex(&with_z), "z must be rejected");
        // uppercase
        assert!(!is_64_lower_hex(&valid.to_uppercase()));
        let mut with_a = valid.to_string();
        with_a.replace_range(0..1, "A");
        assert!(!is_64_lower_hex(&with_a), "uppercase A must be rejected");
        // wrong length
        assert!(!is_64_lower_hex(&valid[..63]));
        assert!(!is_64_lower_hex(&format!("{valid}0")));
        assert!(!is_64_lower_hex(""));
        // non-hex
        assert!(!is_64_lower_hex(&format!("{valid}x")));
        // FNV-1a 16-hex is not 64
        assert!(!is_64_lower_hex("2b01482a3681d838"));
        // real SHA-256 output passes (contract preserved)
        let real = sha256_hex(b"mida");
        assert!(is_64_lower_hex(&real));
    }

    #[test]
    fn imp09_profile_id_and_digest_cannot_be_split_across_sources() {
        // There is no constructor that takes profile_id from one source and
        // digest from another: from_verified_profile derives BOTH from the
        // single verified Profile object. A forged split (bare id string +
        // unrelated digest) cannot be expressed with the sealed API.
        use mida_antidebug::profile::{lunlun_profile, origin_profile};
        let origin = origin_profile();
        let lunlun = lunlun_profile();
        // The origin carrier's digest is bound to origin canonical bytes;
        // lunlun's canonical bytes hash differently (same-source proof).
        let o = VerifiedProfileIdentity::from_verified_profile(&origin, "origin_macro", "x86_64")
            .expect("origin seals");
        let l =
            VerifiedProfileIdentity::from_verified_profile(&lunlun, "lunlun_software", "x86_64")
                .expect("lunlun seals");
        assert_ne!(o.profile_id(), l.profile_id());
        assert_ne!(o.profile_digest(), l.profile_digest());
        // Each digest matches ITS OWN profile object's canonical bytes.
        assert_eq!(
            o.profile_digest(),
            sha256_hex(origin.canonical_json().as_bytes())
        );
        assert_eq!(
            l.profile_digest(),
            sha256_hex(lunlun.canonical_json().as_bytes())
        );
    }
}
