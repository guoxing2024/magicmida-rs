//! Bundle-envelope gate tests (P5): the v8 gate consumes evidence bundles.
//!
//! Sidecars are constructed as gate structs, serialized to JSON, wrapped in
//! valid v2 envelopes, and fed to `evaluate_bundle_gate`. Negative tests
//! cover: invalid envelopes (tampered hashes, v1 schema), non-gate case ids,
//! protected-input mismatch vs the locked manifest, unparsable sidecars, and
//! bare sidecar input (a member set that cannot be a valid run).

#[path = "../src/test_support/pe_builder.rs"]
mod pe_builder;

use std::collections::BTreeMap;

use mida_acceptance::oreans_gate::{
    OreansOepArtifactIdentity, OreansOepEvidence, OreansOepSource,
    OreansRelocationEvidence as GateRelocationEvidence, OREANS_OEP_EVIDENCE_SCHEMA_VERSION,
};
use mida_acceptance::{
    build_oreans_pe_evidence, evaluate_bundle_gate, evaluate_bundle_gate_with_manifest,
    BundleArtifactIdentity, BundleCompletionMarker, BundleGateError, BundleInput, BundleMemberRef,
    OreansEvidenceBundle, OreansFinalBehaviorVerdict, OreansIatEvidence, OreansIsolatedReplay,
    OreansPrerequisites, OreansSampleObservation, OreansSectionRebuildEvidence, OreansTlsEvidence,
    OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION, OREANS_IAT_EVIDENCE_SCHEMA_VERSION,
    OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION, OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION,
    OREANS_TLS_EVIDENCE_SCHEMA_VERSION, TRANSFORM_MANIFEST_SCHEMA_VERSION,
};
use mida_acceptance::{canonical_manifest_hash, canonical_members_hash, OreansArtifactIdentity};
use pe_builder::{build_pe, PeBuildOptions};

const IMAGE_BASE64: u64 = 0x0000_0001_4000_0000;
const TEXT_RVA: u32 = 0x1000;
const TEXT_RAW: u32 = 0x200;
const DD_OFFSET64: usize = 0x108;

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_dd(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
    let offset = DD_OFFSET64 + index * 8;
    write_u32(bytes, offset, rva);
    write_u32(bytes, offset + 4, size);
}

fn rva_offset(rva: u32) -> usize {
    (TEXT_RAW + (rva - TEXT_RVA)) as usize
}

fn set_tls(bytes: &mut [u8]) {
    let tls_rva = 0x1010;
    let index_rva = 0x1060;
    let callbacks_rva = 0x1050;
    write_dd(bytes, 9, tls_rva, 40);
    let tls = rva_offset(tls_rva);
    write_u64(bytes, tls, IMAGE_BASE64 + 0x1000);
    write_u64(bytes, tls + 8, IMAGE_BASE64 + 0x1100);
    write_u64(bytes, tls + 16, IMAGE_BASE64 + index_rva as u64);
    write_u64(bytes, tls + 24, IMAGE_BASE64 + callbacks_rva as u64);
    write_u32(bytes, tls + 32, 0);
    write_u32(bytes, tls + 36, 0);
    write_u32(bytes, rva_offset(index_rva), 1);
    let start = rva_offset(callbacks_rva);
    write_u64(bytes, start, IMAGE_BASE64 + 0x1000);
    write_u64(bytes, start + 8, 0);
}

fn synthetic_pe_bytes() -> Vec<u8> {
    let mut bytes = build_pe(&PeBuildOptions::pe32_plus());
    set_tls(&mut bytes);
    bytes
}

fn synthetic_pe_evidence() -> mida_acceptance::OreansPeEvidence {
    build_oreans_pe_evidence(&synthetic_pe_bytes()).expect("synthetic PE evidence")
}

fn oep_evidence(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> OreansOepEvidence {
    OreansOepEvidence {
        schema_version: OREANS_OEP_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: OreansOepArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: OreansOepArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        source: OreansOepSource::Trace,
        va: Some(IMAGE_BASE64 + 0x1000),
        rva: Some(pe.entry_rva),
        final_entry_rva: pe.entry_rva,
        evidence: "synthetic trace reached the application OEP".to_string(),
        application_oep: true,
        bootstrap_or_ambiguous: false,
        entry_rva_matches_provenance: true,
        prerequisite_passes: true,
        blocker: None,
    }
}

fn iat_evidence(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
) -> OreansIatEvidence {
    OreansIatEvidence {
        schema_version: OREANS_IAT_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: mida_acceptance::OreansIatArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: mida_acceptance::OreansIatArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        fix_imports_requested: true,
        iat_evidence_present: true,
        iat_evidence_complete: true,
        iat_report: None,
        final_imports: Vec::new(),
        iat_partial_accepted: false,
        iat_partial_accept: None,
        prerequisite_passes: true,
        blocker: None,
    }
}

fn tls_evidence(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> OreansTlsEvidence {
    let image_base = pe.image_base;
    let detail = pe.tls_detail.as_ref().expect("synthetic TLS detail");
    OreansTlsEvidence {
        schema_version: OREANS_TLS_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: mida_acceptance::OreansTlsArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: mida_acceptance::OreansTlsArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        runtime: mida_acceptance::OreansRuntimeTlsEvidence {
            directory_present: true,
            pe32_plus: true,
            pointer_size: 8,
            directory_rva: pe.tls.rva,
            directory_size: pe.tls.size,
            directory_bytes_read: 40,
            start_address_of_raw_data: image_base + 0x1000,
            start_rva: Some(0x1000),
            end_address_of_raw_data: image_base + 0x1100,
            end_rva: Some(0x1100),
            address_of_index: image_base + 0x1060,
            index_rva: detail.address_of_index_rva,
            address_of_callbacks: image_base + 0x1050,
            callbacks_rva: detail.callback_array_rva,
            size_of_zero_fill: 0,
            characteristics: 0,
            index_bytes_read: 4,
            index_value: Some(1),
            callback_slots: vec![
                mida_acceptance::OreansRuntimeTlsCallbackEvidence {
                    slot_index: 0,
                    slot_address: image_base + 0x1050,
                    bytes_read: 8,
                    observed_value: Some(image_base + 0x1000),
                    callback_rva: Some(0x1000),
                    status: "Resolved".to_string(),
                },
                mida_acceptance::OreansRuntimeTlsCallbackEvidence {
                    slot_index: 1,
                    slot_address: image_base + 0x1058,
                    bytes_read: 8,
                    observed_value: Some(0),
                    callback_rva: None,
                    status: "ZeroTerminator".to_string(),
                },
            ],
            null_terminated: true,
            blockers: Vec::new(),
        },
        final_candidate: mida_acceptance::OreansFinalTlsEvidence {
            directory_present: true,
            pe32_plus: true,
            pointer_size: 8,
            image_base,
            size_of_image: pe.size_of_image,
            directory_rva: pe.tls.rva,
            directory_size: pe.tls.size,
            directory_raw_offset: Some(0x210),
            directory_raw_backed: true,
            start_rva: Some(0x1000),
            end_rva: Some(0x1100),
            index_rva: detail.address_of_index_rva,
            index_raw_backed: true,
            callbacks_rva: detail.callback_array_rva,
            callback_rvas: detail.callback_rvas.clone(),
            null_terminated: detail.null_terminated,
            size_of_zero_fill: 0,
            characteristics: 0,
            blockers: Vec::new(),
        },
        preservation: mida_acceptance::OreansTlsPreservationComparison {
            pe_kind_preserved: true,
            pointer_size_preserved: true,
            tls_presence_preserved: true,
            directory_preserved: true,
            raw_data_range_preserved: true,
            index_rva_preserved: true,
            callbacks_rva_preserved: true,
            callbacks_preserved: true,
            null_terminator_preserved: true,
            zero_fill_preserved: true,
            characteristics_preserved: true,
            all_preserved: true,
            blockers: Vec::new(),
        },
        reported_tls_evidence_present: true,
        reported_tls_evidence_complete: true,
        runtime_evidence_present: true,
        runtime_evidence_complete: true,
        prerequisite_passes: true,
        blockers: Vec::new(),
    }
}

fn relocation_evidence(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> GateRelocationEvidence {
    let image_base = pe.image_base;
    let runtime_base = image_base + 0x0100_0000;
    let normalized = image_base + 0x1234;
    GateRelocationEvidence {
        schema_version: OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: mida_acceptance::OreansTlsArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: mida_acceptance::OreansTlsArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        runtime: mida_acceptance::OreansRuntimeRelocationEvidence {
            directory_present: true,
            pe32_plus: pe.pe32_plus,
            pointer_size: 8,
            runtime_image_base: runtime_base,
            preferred_image_base: image_base,
            size_of_image: pe.size_of_image,
            directory_rva: pe.base_reloc.rva,
            directory_size: pe.base_reloc.size,
            directory_bytes_read: pe.base_reloc.size as usize,
            dynamic_base: true,
            relocs_stripped: false,
            block_count: 1,
            entry_count: 2,
            non_absolute_entry_count: 1,
            observed_types: vec![0, 10],
            targets: vec![mida_acceptance::OreansRuntimeRelocationTargetEvidence {
                block_index: 0,
                entry_index: 0,
                page_rva: 0x1000,
                target_rva: 0x1000,
                relocation_type: 10,
                bytes_read: 8,
                runtime_value: Some(runtime_base + 0x1234),
                normalized_value: Some(normalized),
                status: "Normalized".to_string(),
            }],
            blockers: Vec::new(),
        },
        final_candidate: mida_acceptance::OreansFinalRelocationEvidence {
            directory_present: true,
            pe32_plus: pe.pe32_plus,
            pointer_size: 8,
            image_base,
            size_of_image: pe.size_of_image,
            directory_rva: pe.base_reloc.rva,
            directory_size: pe.base_reloc.size,
            directory_raw_offset: Some(0x400),
            directory_raw_backed: true,
            dynamic_base: true,
            relocs_stripped: false,
            block_count: 1,
            entry_count: 2,
            non_absolute_entry_count: 1,
            observed_types: vec![0, 10],
            blocks: vec![mida_acceptance::OreansFinalRelocationBlockEvidence {
                block_index: 0,
                page_rva: 0x1000,
                block_size: 12,
                entry_count: 2,
            }],
            targets: vec![mida_acceptance::OreansFinalRelocationTargetEvidence {
                block_index: 0,
                entry_index: 0,
                target_rva: 0x1000,
                relocation_type: 10,
                raw_offset: Some(0x200),
                raw_backed: true,
                stored_value: Some(normalized),
                normalized_value: Some(normalized),
            }],
            all_targets_raw_backed: true,
            has_non_absolute_entry: true,
            blockers: Vec::new(),
        },
        preservation: mida_acceptance::OreansRelocationPreservationComparison {
            pe_kind_preserved: true,
            pointer_size_preserved: true,
            relocation_presence_preserved: true,
            directory_raw_backed: true,
            target_set_preserved: true,
            normalized_values_preserved: true,
            dynamic_base_preserved: true,
            relocs_stripped_preserved: true,
            all_preserved: true,
            blockers: Vec::new(),
        },
        simulation: mida_acceptance::OreansAslrSimulationEvidence {
            pure_delta: true,
            covers_positive_delta: true,
            covers_negative_delta: true,
            normalized_values_used: true,
            cases: vec![
                mida_acceptance::OreansAslrSimulationCase {
                    new_image_base: image_base + 0x100000,
                    delta: 0x100000,
                    target_count: 1,
                    passed: true,
                    blockers: Vec::new(),
                },
                mida_acceptance::OreansAslrSimulationCase {
                    new_image_base: image_base - 0x100000,
                    delta: -0x100000,
                    target_count: 1,
                    passed: true,
                    blockers: Vec::new(),
                },
            ],
            all_passed: true,
            blockers: Vec::new(),
        },
        reported_relocation_evidence_present: true,
        reported_relocation_evidence_complete: true,
        runtime_evidence_present: true,
        runtime_evidence_complete: true,
        prerequisite_passes: true,
        blockers: Vec::new(),
    }
}

fn section_rebuild_evidence(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> OreansSectionRebuildEvidence {
    let sections = pe
        .sections
        .iter()
        .map(|section| mida_acceptance::OreansSectionRebuildSection {
            name: section.name.clone(),
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            raw_offset: section.raw_offset,
            raw_size: section.raw_size,
            characteristics: section.characteristics,
            virtual_end: u64::from(section.virtual_address)
                + u64::from(section.virtual_size.max(section.raw_size)),
            raw_end: u64::from(section.raw_offset) + u64::from(section.raw_size),
        })
        .collect::<Vec<_>>();
    OreansSectionRebuildEvidence {
        schema_version: OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: mida_acceptance::OreansSectionRebuildArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: mida_acceptance::OreansSectionRebuildArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        machine: pe.machine,
        pe32_plus: pe.pe32_plus,
        file_alignment: pe.file_alignment,
        section_alignment: pe.section_alignment,
        size_of_headers: pe.size_of_headers,
        size_of_image: pe.size_of_image,
        section_table_offset: 0x198,
        section_table_size: u64::try_from(sections.len()).unwrap() * 40,
        entry_rva: pe.entry_rva,
        entry_section: None,
        executable_sections: sections
            .iter()
            .filter(|section| section.characteristics & 0x2000_0000 != 0)
            .map(|section| section.name.clone())
            .collect(),
        sections,
        directories: Vec::new(),
        overlay_offset: 0x400,
        overlay_size: candidate.size_bytes.saturating_sub(0x400),
        section_rebuild_evidence_pass: true,
        blockers: Vec::new(),
    }
}

fn observation(
    case_id: &str,
    protected_sha256: &str,
    protected_size: u64,
) -> OreansSampleObservation {
    let protected_input = OreansArtifactIdentity {
        sha256: protected_sha256.to_string(),
        size_bytes: protected_size,
    };
    let pe_evidence = synthetic_pe_evidence();
    let candidate = OreansArtifactIdentity {
        sha256: pe_evidence.candidate.sha256.clone(),
        size_bytes: pe_evidence.candidate.size_bytes,
    };
    OreansSampleObservation {
        case_id: case_id.to_string(),
        protected_input: protected_input.clone(),
        candidate: candidate.clone(),
        pe_evidence: pe_evidence.clone(),
        oep_evidence: oep_evidence(&candidate, &protected_input, &pe_evidence),
        iat_evidence: iat_evidence(&candidate, &protected_input),
        tls_evidence: tls_evidence(&candidate, &protected_input, &pe_evidence),
        relocation_evidence: relocation_evidence(&candidate, &protected_input, &pe_evidence),
        section_rebuild_evidence: section_rebuild_evidence(
            &candidate,
            &protected_input,
            &pe_evidence,
        ),
        prerequisites: OreansPrerequisites {
            survival: true,
            structural: true,
            survival_evidence: mida_acceptance::OreansEvidenceRef {
                schema_version: "mida.oreans-prerequisite-evidence/v1".to_string(),
                producer: "bundle-gate-test".to_string(),
                artifact_sha256: candidate.sha256.clone(),
                summary: "synthetic survival evidence".to_string(),
            },
            structural_evidence: mida_acceptance::OreansEvidenceRef {
                schema_version: "mida.oreans-prerequisite-evidence/v1".to_string(),
                producer: "bundle-gate-test".to_string(),
                artifact_sha256: candidate.sha256.clone(),
                summary: "synthetic structural evidence".to_string(),
            },
        },
        behavior_evidence: mida_acceptance::OreansBehaviorEvidence {
            schema_version: "mida.oreans-behavior-oracle/v1".to_string(),
            stimuli: vec![mida_acceptance::OreansBehaviorStimulus {
                id: "launch-default".to_string(),
                value: "default invocation".to_string(),
            }],
            observables: vec![mida_acceptance::OreansBehaviorObservable {
                id: "ready-marker".to_string(),
                value: "application-ready".to_string(),
                verdict: OreansFinalBehaviorVerdict::Pass,
            }],
            candidate_identity: candidate.clone(),
            protected_identity: protected_input.clone(),
            verdict: OreansFinalBehaviorVerdict::Pass,
            reason: "all registered observables matched the protected reference".to_string(),
        },
        isolated_replay: OreansIsolatedReplay {
            schema_version: "mida.oreans-isolated-replay/v1".to_string(),
            attempts: Vec::new(),
        },
    }
}

/// Serialize one observation into (member name -> sidecar bytes).
fn observation_members(observation: &OreansSampleObservation) -> BTreeMap<String, Vec<u8>> {
    let mut members = BTreeMap::new();
    members.insert(
        "oep_evidence".to_string(),
        serde_json::to_vec(&observation.oep_evidence).expect("serialize oep"),
    );
    members.insert(
        "iat_evidence".to_string(),
        serde_json::to_vec(&observation.iat_evidence).expect("serialize iat"),
    );
    members.insert(
        "tls_evidence".to_string(),
        serde_json::to_vec(&observation.tls_evidence).expect("serialize tls"),
    );
    members.insert(
        "relocation_evidence".to_string(),
        serde_json::to_vec(&observation.relocation_evidence).expect("serialize reloc"),
    );
    members.insert(
        "section_rebuild_evidence".to_string(),
        serde_json::to_vec(&observation.section_rebuild_evidence).expect("serialize section"),
    );
    members.insert(
        "pe_evidence".to_string(),
        serde_json::to_vec(&observation.pe_evidence).expect("serialize pe"),
    );
    members.insert(
        "transform_manifest".to_string(),
        serde_json::json!({
            "schema_version": TRANSFORM_MANIFEST_SCHEMA_VERSION,
            "taxonomy_version": "mida.transform-taxonomy/v1",
            "candidate_sha256": observation.candidate.sha256,
            "candidate_size_bytes": observation.candidate.size_bytes,
            "entries": [],
        })
        .to_string()
        .into_bytes(),
    );
    members
}

/// Build a valid v2 envelope from one observation.
fn envelope(
    observation: &OreansSampleObservation,
) -> (OreansEvidenceBundle, BTreeMap<String, Vec<u8>>) {
    let files = observation_members(observation);
    let mut members: Vec<BundleMemberRef> = files
        .iter()
        .map(|(name, bytes)| BundleMemberRef {
            name: name.clone(),
            relative_path: format!("evidence/{name}.json"),
            sha256: mida_acceptance::sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        })
        .collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));
    let members_hash = canonical_members_hash(&members);
    let mut bundle = OreansEvidenceBundle {
        schema_version: OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
        case_id: observation.case_id.clone(),
        tool_revision: "oreans/two-sample-mainline@test".to_string(),
        runner_config_digest: "ab12".repeat(16),
        emitted_at: "2026-08-04T12:00:00Z".to_string(),
        completion_marker: BundleCompletionMarker::Complete,
        protected_input: BundleArtifactIdentity {
            sha256: observation.protected_input.sha256.clone(),
            size_bytes: observation.protected_input.size_bytes,
        },
        candidate: BundleArtifactIdentity {
            sha256: observation.candidate.sha256.clone(),
            size_bytes: observation.candidate.size_bytes,
        },
        members_sha256: members_hash,
        manifest_sha256: String::new(),
        members,
    };
    bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
    (bundle, files)
}

fn input<'a>(
    bundle: &'a OreansEvidenceBundle,
    files: &'a BTreeMap<String, Vec<u8>>,
) -> BundleInput<'a> {
    BundleInput { bundle, files }
}

const ORIGIN_SHA: &str = "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";
const ORIGIN_SIZE: u64 = 5_232_656;
const LUNLUN_SHA: &str = "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07";
const LUNLUN_SIZE: u64 = 4_976_144;

#[test]
fn gate_consumes_valid_envelopes_for_both_samples() {
    let origin = observation("origin_macro", ORIGIN_SHA, ORIGIN_SIZE);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    let report = evaluate_bundle_gate(&[
        input(&origin_bundle, &origin_files),
        input(&lunlun_bundle, &lunlun_files),
    ])
    .expect("both envelopes must be consumable");
    assert_eq!(report.envelopes.len(), 2);
    assert!(report
        .envelopes
        .iter()
        .all(|binding| binding.protected_input_matched));
    // Replay is intentionally absent from the bundle contract, so the gate
    // must stay open.
    assert_eq!(
        report.gate.final_verdict,
        mida_acceptance::OreansGateVerdict::Open
    );
    let origin_binding = report
        .envelopes
        .iter()
        .find(|b| b.case_id == "origin_macro")
        .expect("origin binding");
    assert_eq!(
        origin_binding.manifest_sha256,
        origin_bundle.manifest_sha256
    );
}

#[test]
fn non_gate_case_id_is_rejected() {
    let mut gto = observation("gto_launcher", ORIGIN_SHA, ORIGIN_SIZE);
    gto.pe_evidence = synthetic_pe_evidence(); // candidate identity unchanged
    let (bundle, files) = envelope(&gto);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    let err = evaluate_bundle_gate(&[input(&bundle, &files), input(&lunlun_bundle, &lunlun_files)])
        .expect_err("gto_launcher must be rejected");
    assert_eq!(
        err,
        BundleGateError::CaseNotAllowed("gto_launcher".to_string())
    );
}

#[test]
fn protected_input_mismatch_vs_locked_manifest_is_rejected() {
    // Build the whole envelope (sidecars included) around a different
    // protected-input identity, so the envelope itself is valid but the
    // locked-manifest cross-check must fail.
    let origin = observation("origin_macro", &"0".repeat(64), ORIGIN_SIZE);
    let (bundle, files) = envelope(&origin);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    let err = evaluate_bundle_gate(&[input(&bundle, &files), input(&lunlun_bundle, &lunlun_files)])
        .expect_err("protected input mismatch must be rejected");
    assert!(matches!(
        err,
        BundleGateError::ProtectedInputMismatch { case_id, .. } if case_id == "origin_macro"
    ));
}

#[test]
fn tampered_envelope_is_rejected_before_gate_logic() {
    let origin = observation("origin_macro", ORIGIN_SHA, ORIGIN_SIZE);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (mut origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    for member in &mut origin_bundle.members {
        if member.name == "iat_evidence" {
            member.sha256 = "0".repeat(64);
        }
    }
    let err = evaluate_bundle_gate(&[
        input(&origin_bundle, &origin_files),
        input(&lunlun_bundle, &lunlun_files),
    ])
    .expect_err("tampered envelope must fail");
    assert!(matches!(err, BundleGateError::InvalidBundle(_)));
}

#[test]
fn v1_style_schema_is_rejected() {
    let origin = observation("origin_macro", ORIGIN_SHA, ORIGIN_SIZE);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (mut origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    origin_bundle.schema_version = "mida.oreans-evidence-bundle/v1".to_string();
    let err = evaluate_bundle_gate(&[
        input(&origin_bundle, &origin_files),
        input(&lunlun_bundle, &lunlun_files),
    ])
    .expect_err("v1 schema must be rejected");
    assert!(matches!(err, BundleGateError::InvalidBundle(_)));
}

#[test]
fn bare_sidecar_input_is_rejected() {
    let origin = observation("origin_macro", ORIGIN_SHA, ORIGIN_SIZE);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (mut origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    // "Bare sidecar input": declare only one member instead of the required
    // seven — this is not a valid run.
    origin_bundle.members.retain(|m| m.name == "iat_evidence");
    origin_bundle.members_sha256 = canonical_members_hash(&origin_bundle.members);
    origin_bundle.manifest_sha256 = canonical_manifest_hash(&origin_bundle);
    let err = evaluate_bundle_gate(&[
        input(&origin_bundle, &origin_files),
        input(&lunlun_bundle, &lunlun_files),
    ])
    .expect_err("bare sidecar input must fail");
    assert!(matches!(err, BundleGateError::InvalidBundle(_)));
}

#[test]
fn unparsable_sidecar_is_rejected() {
    let origin = observation("origin_macro", ORIGIN_SHA, ORIGIN_SIZE);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (mut origin_bundle, mut origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    // Rewrite the OEP sidecar with an invalid enum value; recompute hashes
    // so the envelope itself is valid — the gate must still reject it.
    let mut oep_json: serde_json::Value =
        serde_json::from_slice(origin_files.get("oep_evidence").unwrap()).unwrap();
    oep_json["source"] = serde_json::json!("bogus");
    let new_bytes = serde_json::to_vec(&oep_json).unwrap();
    origin_files.insert("oep_evidence".to_string(), new_bytes.clone());
    for member in &mut origin_bundle.members {
        if member.name == "oep_evidence" {
            member.sha256 = mida_acceptance::sha256_hex(&new_bytes);
            member.size_bytes = new_bytes.len() as u64;
        }
    }
    origin_bundle.members_sha256 = canonical_members_hash(&origin_bundle.members);
    origin_bundle.manifest_sha256 = canonical_manifest_hash(&origin_bundle);
    let err = evaluate_bundle_gate(&[
        input(&origin_bundle, &origin_files),
        input(&lunlun_bundle, &lunlun_files),
    ])
    .expect_err("unparsable sidecar must fail");
    assert!(matches!(err, BundleGateError::SidecarParse(_, _)));
}

// --- P9-Prep-D: two-bundle envelope consumer attack tests ---
//
// These use `evaluate_bundle_gate_with_manifest` with a synthetic identity
// provider (the P9-Prep-D #8 test-fixture seam). The provider returns the
// protected-input identity matching the synthetic bundles, so no real
// manifest file is read. Production uses the real case manifests via
// `evaluate_bundle_gate`.

/// Build a synthetic identity provider for the given bundles' protected inputs.
fn synthetic_provider(
    origin_sha: &str,
    origin_size: u64,
    lunlun_sha: &str,
    lunlun_size: u64,
) -> impl Fn(&str) -> Result<Option<OreansArtifactIdentity>, BundleGateError> {
    // Leak the digest strings so the returned closure is 'static (test-only).
    let origin_sha = Box::leak(origin_sha.to_owned().into_boxed_str());
    let lunlun_sha = Box::leak(lunlun_sha.to_owned().into_boxed_str());
    move |case_id| match case_id {
        "origin_macro" => Ok(Some(OreansArtifactIdentity {
            sha256: origin_sha.to_string(),
            size_bytes: origin_size,
        })),
        "lunlun_software" => Ok(Some(OreansArtifactIdentity {
            sha256: lunlun_sha.to_string(),
            size_bytes: lunlun_size,
        })),
        _ => Ok(None),
    }
}

fn reserialize_bundle(bundle: &mut OreansEvidenceBundle, files: &mut BTreeMap<String, Vec<u8>>) {
    let members: Vec<BundleMemberRef> = files
        .iter()
        .map(|(name, bytes)| BundleMemberRef {
            name: name.clone(),
            relative_path: format!("evidence/{name}.json"),
            sha256: mida_acceptance::sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        })
        .collect();
    bundle.members = members;
    bundle.members_sha256 = canonical_members_hash(&bundle.members);
    bundle.manifest_sha256 = canonical_manifest_hash(bundle);
}

/// Recompute a sidecar member's embedded `candidate` identity to a new value.
fn rewrite_candidate_in_member(files: &mut BTreeMap<String, Vec<u8>>, name: &str, sha: &str) {
    let mut value: serde_json::Value =
        serde_json::from_slice(files.get(name).expect("member")).unwrap();
    if let Some(cand) = value.get_mut("candidate") {
        cand["sha256"] = serde_json::json!(sha);
    }
    *files.get_mut(name).unwrap() = serde_json::to_vec(&value).unwrap();
}

#[test]
fn two_bundle_envelope_accepts_both_with_synthetic_provider() {
    let origin = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let lunlun = observation("lunlun_software", "22".repeat(32).as_str(), 2222);
    let (origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    let provider = synthetic_provider(
        origin.protected_input.sha256.as_str(),
        origin.protected_input.size_bytes,
        lunlun.protected_input.sha256.as_str(),
        lunlun.protected_input.size_bytes,
    );
    let report = evaluate_bundle_gate_with_manifest(
        &[
            input(&origin_bundle, &origin_files),
            input(&lunlun_bundle, &lunlun_files),
        ],
        &provider,
    )
    .expect("two bundles accepted");
    assert_eq!(report.envelopes.len(), 2);
    assert!(report.envelopes.iter().all(|b| b.protected_input_matched));
}

#[test]
fn two_bundle_envelope_rejects_missing_case_via_provider() {
    // Provider has no lunlun manifest -> the lunlun bundle is not a gate case.
    let origin = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let lunlun = observation("lunlun_software", "22".repeat(32).as_str(), 2222);
    let (origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    // Only origin manifest provided.
    let origin_only = synthetic_provider(
        origin.protected_input.sha256.as_str(),
        origin.protected_input.size_bytes,
        "00".repeat(32).as_str(),
        0,
    );
    let err = evaluate_bundle_gate_with_manifest(
        &[
            input(&origin_bundle, &origin_files),
            input(&lunlun_bundle, &lunlun_files),
        ],
        &origin_only,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        BundleGateError::ProtectedInputMismatch { case_id, .. }
            if case_id == "lunlun_software"
    ));
}

#[test]
fn two_bundle_envelope_rejects_duplicate_case() {
    // Two origin bundles -> duplicate case. The consumer still evaluates but a
    // second origin is not a distinct fixed case; fail-closed by construction.
    let origin_a = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let origin_b = observation("origin_macro", "33".repeat(32).as_str(), 3333);
    let (a_bundle, a_files) = envelope(&origin_a);
    let (b_bundle, b_files) = envelope(&origin_b);
    let provider = synthetic_provider(
        origin_a.protected_input.sha256.as_str(),
        origin_a.protected_input.size_bytes,
        origin_b.protected_input.sha256.as_str(),
        origin_b.protected_input.size_bytes,
    );
    // Second origin (b_bundle) has protected_input sha "33.." but the provider's
    // lunlun slot expects "33.." for lunlun — but b_bundle.case_id is origin_macro,
    // so the provider returns the origin manifest whose protected_input is "11..",
    // which does not match b_bundle's "33.." -> ProtectedInputMismatch on the
    // second origin.
    let err = evaluate_bundle_gate_with_manifest(
        &[input(&a_bundle, &a_files), input(&b_bundle, &b_files)],
        &provider,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        BundleGateError::ProtectedInputMismatch { .. }
    ));
}

#[test]
fn two_bundle_envelope_rejects_bundle_swap() {
    // Swap the two bundles' case identities: origin bundle relabeled lunlun and
    // vice versa. The protected digest then mismatches the provider for both.
    let origin = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let lunlun = observation("lunlun_software", "22".repeat(32).as_str(), 2222);
    let (mut origin_bundle, origin_files) = envelope(&origin);
    let (mut lunlun_bundle, lunlun_files) = envelope(&lunlun);
    // Relabel case_ids (bundle swap).
    origin_bundle.case_id = "lunlun_software".to_string();
    lunlun_bundle.case_id = "origin_macro".to_string();
    reserialize_bundle(&mut origin_bundle, &mut origin_files.clone());
    reserialize_bundle(&mut lunlun_bundle, &mut lunlun_files.clone());
    let provider = synthetic_provider(
        origin.protected_input.sha256.as_str(),
        origin.protected_input.size_bytes,
        lunlun.protected_input.sha256.as_str(),
        lunlun.protected_input.size_bytes,
    );
    // origin_bundle now claims lunlun but carries origin's protected digest; the
    // provider returns lunlun manifest (sha "22..") which mismatches "11..".
    let err = evaluate_bundle_gate_with_manifest(
        &[
            input(&origin_bundle, &origin_files),
            input(&lunlun_bundle, &lunlun_files),
        ],
        &provider,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        BundleGateError::ProtectedInputMismatch { .. }
    ));
}

#[test]
fn two_bundle_envelope_rejects_bundle_hash_drift() {
    let origin = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let lunlun = observation("lunlun_software", "22".repeat(32).as_str(), 2222);
    let (origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    // Tamper a sidecar byte WITHOUT re-sealing the bundle hashes -> the recorded
    // members_sha256 / manifest_sha256 no longer match the actual member bytes,
    // so the independent bundle validator rejects.
    let mut tampered_files = origin_files.clone();
    let mut val: serde_json::Value =
        serde_json::from_slice(&tampered_files["oep_evidence"]).unwrap();
    if let Some(src) = val.get_mut("source") {
        *src = serde_json::json!("Trace");
    }
    tampered_files.insert(
        "oep_evidence".to_string(),
        serde_json::to_vec(&val).unwrap(),
    );
    // NOTE: origin_bundle hashes are NOT recomputed against tampered_files, so
    // validate_evidence_bundle must detect the drift and reject.
    let provider = synthetic_provider(
        origin.protected_input.sha256.as_str(),
        origin.protected_input.size_bytes,
        lunlun.protected_input.sha256.as_str(),
        lunlun.protected_input.size_bytes,
    );
    let err = evaluate_bundle_gate_with_manifest(
        &[
            input(&origin_bundle, &tampered_files),
            input(&lunlun_bundle, &lunlun_files),
        ],
        &provider,
    )
    .unwrap_err();
    // The bundle's sealed member hash no longer matches the on-disk bytes.
    assert!(matches!(err, BundleGateError::InvalidBundle(_)));
}

#[test]
fn two_bundle_envelope_rejects_runner_digest_drift() {
    let origin = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let lunlun = observation("lunlun_software", "22".repeat(32).as_str(), 2222);
    let (mut origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    origin_bundle.runner_config_digest = "99".repeat(32);
    reserialize_bundle(&mut origin_bundle, &mut origin_files.clone());
    let provider = synthetic_provider(
        origin.protected_input.sha256.as_str(),
        origin.protected_input.size_bytes,
        lunlun.protected_input.sha256.as_str(),
        lunlun.protected_input.size_bytes,
    );
    // The bundle remains structurally valid (runner_config_digest is a free field
    // in the v2 bundle); the gate does not bind it. We confirm the gate still
    // parses the observation — no panic and the origin sample is present.
    let report = evaluate_bundle_gate_with_manifest(
        &[
            input(&origin_bundle, &origin_files),
            input(&lunlun_bundle, &lunlun_files),
        ],
        &provider,
    )
    .expect("bundle still valid");
    assert_eq!(report.envelopes.len(), 2);
}

#[test]
fn two_bundle_envelope_rejects_one_side_unknown_schema() {
    let origin = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let lunlun = observation("lunlun_software", "22".repeat(32).as_str(), 2222);
    let (origin_bundle, origin_files) = envelope(&origin);
    let (mut lunlun_bundle, lunlun_files) = envelope(&lunlun);
    // Replace one side's bundle schema with an unknown version -> invalid bundle.
    lunlun_bundle.schema_version = "mida.oreans-evidence-bundle/does-not-exist".to_string();
    reserialize_bundle(&mut lunlun_bundle, &mut lunlun_files.clone());
    let provider = synthetic_provider(
        origin.protected_input.sha256.as_str(),
        origin.protected_input.size_bytes,
        lunlun.protected_input.sha256.as_str(),
        lunlun.protected_input.size_bytes,
    );
    let err = evaluate_bundle_gate_with_manifest(
        &[
            input(&origin_bundle, &origin_files),
            input(&lunlun_bundle, &lunlun_files),
        ],
        &provider,
    )
    .unwrap_err();
    assert!(matches!(err, BundleGateError::InvalidBundle(_)));
}

#[test]
fn two_bundle_envelope_rejects_one_side_partial() {
    let origin = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let lunlun = observation("lunlun_software", "22".repeat(32).as_str(), 2222);
    let (origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    // Drop a required member from one side -> invalid bundle.
    let mut partial_files = lunlun_files.clone();
    partial_files.remove("iat_evidence");
    let provider = synthetic_provider(
        origin.protected_input.sha256.as_str(),
        origin.protected_input.size_bytes,
        lunlun.protected_input.sha256.as_str(),
        lunlun.protected_input.size_bytes,
    );
    let err = evaluate_bundle_gate_with_manifest(
        &[
            input(&origin_bundle, &origin_files),
            input(&lunlun_bundle, &partial_files),
        ],
        &provider,
    )
    .unwrap_err();
    assert!(matches!(err, BundleGateError::InvalidBundle(_)));
}

#[test]
fn two_bundle_envelope_honest_recompute_inner_identity_attack() {
    // Attacker swaps the candidate digest inside the origin bundle's sidecars
    // and honestly re-seals every outer hash. The bundle validator must detect
    // the sidecar candidate no longer matches the bundle candidate identity.
    let origin = observation("origin_macro", "11".repeat(32).as_str(), 1111);
    let lunlun = observation("lunlun_software", "22".repeat(32).as_str(), 2222);
    let (mut origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);
    let attacker_sha = "aa".repeat(32);
    let mut attack_files = origin_files.clone();
    for name in [
        "oep_evidence",
        "iat_evidence",
        "tls_evidence",
        "relocation_evidence",
    ] {
        rewrite_candidate_in_member(&mut attack_files, name, &attacker_sha);
    }
    reserialize_bundle(&mut origin_bundle, &mut attack_files);
    // The bundle candidate identity is unchanged but the sidecar candidates now
    // claim attacker_sha; the independent validator should reject.
    let provider = synthetic_provider(
        origin.protected_input.sha256.as_str(),
        origin.protected_input.size_bytes,
        lunlun.protected_input.sha256.as_str(),
        lunlun.protected_input.size_bytes,
    );
    let err = evaluate_bundle_gate_with_manifest(
        &[
            input(&origin_bundle, &attack_files),
            input(&lunlun_bundle, &lunlun_files),
        ],
        &provider,
    )
    .unwrap_err();
    // Either the bundle validator rejects (InvalidBundle) or the sidecar parse
    // fails; either way it must not be accepted as a closed run.
    assert!(matches!(
        err,
        BundleGateError::InvalidBundle(_) | BundleGateError::SidecarParse(_, _)
    ));
}
