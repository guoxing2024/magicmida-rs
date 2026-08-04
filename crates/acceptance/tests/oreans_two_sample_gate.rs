//! Offline contract tests for the fixed two-sample Oreans perfect-unpack gate.
//!
//! These tests use only synthetic evidence records. No sample executable is
//! opened, launched, unpacked, or otherwise touched.

#[path = "../src/test_support/pe_builder.rs"]
mod pe_builder;

use mida_acceptance::{
    build_oreans_pe_evidence, evaluate_oreans_two_sample_gate, OreansArtifactIdentity,
    OreansAslrSimulationCase, OreansAslrSimulationEvidence, OreansBehaviorEvidence,
    OreansBehaviorObservable, OreansBehaviorStimulus, OreansEvidenceRef,
    OreansFinalBehaviorVerdict, OreansFinalImportEvidence, OreansFinalRelocationBlockEvidence,
    OreansFinalRelocationEvidence, OreansFinalRelocationTargetEvidence, OreansGateError,
    OreansGateRelocationEvidence, OreansGateVerdict, OreansIatEvidence, OreansIatReportEvidence,
    OreansIatSlotEvidence, OreansIsolatedReplay, OreansPrerequisites,
    OreansRelocationPreservationComparison, OreansReplayAttempt, OreansRuntimeRelocationEvidence,
    OreansRuntimeRelocationTargetEvidence, OreansRuntimeTlsCallbackEvidence,
    OreansRuntimeTlsEvidence, OreansSampleObservation, OreansTlsArtifactIdentity,
    OreansTlsEvidence, OreansTlsPreservationComparison, OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION,
    OREANS_ISOLATED_REPLAY_SCHEMA_VERSION, OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
    OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION, OREANS_SAMPLE_MANIFESTS,
};

use mida_acceptance::oreans_gate::{
    OreansOepArtifactIdentity, OreansOepEvidence, OreansOepSource,
    OreansSectionRebuildArtifactIdentity, OreansSectionRebuildDirectory,
    OreansSectionRebuildEvidence, OreansSectionRebuildSection, OREANS_OEP_EVIDENCE_SCHEMA_VERSION,
    OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION,
};

fn evidence(summary: &str, candidate_sha256: &str) -> OreansEvidenceRef {
    OreansEvidenceRef {
        schema_version: OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION.to_string(),
        producer: "oreans-two-sample-gate-synthetic-test".to_string(),
        artifact_sha256: candidate_sha256.to_string(),
        summary: summary.to_string(),
    }
}

fn prerequisites(pass: bool, candidate_sha256: &str) -> OreansPrerequisites {
    OreansPrerequisites {
        survival: pass,
        structural: pass,
        survival_evidence: evidence("synthetic survival evidence", candidate_sha256),
        structural_evidence: evidence("synthetic structural evidence", candidate_sha256),
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
        .map(|section| OreansSectionRebuildSection {
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
    let names = [
        "export",
        "import",
        "resource",
        "exception",
        "security",
        "base_reloc",
        "debug",
        "architecture",
        "global_ptr",
        "tls",
        "load_config",
        "bound_import",
        "iat",
        "delay_import",
        "com_descriptor",
        "reserved",
    ];
    let directories = (0..16)
        .map(|index| {
            let coverage = match index {
                3 if pe.exception.present => &pe.exception,
                5 => &pe.base_reloc,
                9 => &pe.tls,
                _ => &mida_acceptance::OreansPeDirectoryCoverage {
                    rva: 0,
                    size: 0,
                    present: false,
                    raw_backed: false,
                    in_image: false,
                },
            };
            OreansSectionRebuildDirectory {
                index,
                name: names[index as usize].to_string(),
                rva: coverage.rva,
                size: coverage.size,
                present: coverage.present,
                in_image: coverage.in_image,
                raw_backed: coverage.raw_backed,
                security_file_offset: false,
            }
        })
        .collect();
    let entry_section = sections.iter().find(|section| {
        u64::from(pe.entry_rva) >= u64::from(section.virtual_address)
            && u64::from(pe.entry_rva) < section.virtual_end
    });
    let overlay_offset = sections
        .iter()
        .map(|section| section.raw_end)
        .max()
        .unwrap_or(u64::from(pe.size_of_headers));
    OreansSectionRebuildEvidence {
        schema_version: OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: OreansSectionRebuildArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: OreansSectionRebuildArtifactIdentity {
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
        entry_section: entry_section.map(|section| section.name.clone()),
        executable_sections: sections
            .iter()
            .filter(|section| section.characteristics & 0x2000_0000 != 0)
            .map(|section| section.name.clone())
            .collect(),
        sections,
        directories,
        overlay_offset,
        overlay_size: candidate.size_bytes.saturating_sub(overlay_offset),
        section_rebuild_evidence_pass: true,
        blockers: Vec::new(),
    }
}

const IMAGE_BASE64: u64 = 0x0000_0001_4000_0000;
const TEXT_RVA: u32 = 0x1000;
const TEXT_RAW: u32 = 0x200;
const DD_OFFSET64: usize = 0x108;
const RELOC_RAW: usize = 0x400;

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn rva_offset(rva: u32) -> usize {
    (TEXT_RAW + (rva - TEXT_RVA)) as usize
}

fn write_directory(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
    let offset = DD_OFFSET64 + index * 8;
    write_u32(bytes, offset, rva);
    write_u32(bytes, offset + 4, size);
}

fn set_tls(bytes: &mut [u8]) {
    let tls_rva = 0x1010;
    let index_rva = 0x1060;
    let callbacks_rva = 0x1050;
    write_directory(bytes, 9, tls_rva, 40);
    let tls = rva_offset(tls_rva);
    write_u64(bytes, tls, IMAGE_BASE64 + 0x1000);
    write_u64(bytes, tls + 8, IMAGE_BASE64 + 0x1100);
    write_u64(bytes, tls + 16, IMAGE_BASE64 + index_rva as u64);
    write_u64(bytes, tls + 24, IMAGE_BASE64 + callbacks_rva as u64);
    write_u32(bytes, tls + 32, 0);
    write_u32(bytes, tls + 36, 0);
    write_u32(bytes, rva_offset(index_rva), 1);
    write_u64(bytes, rva_offset(callbacks_rva), IMAGE_BASE64 + 0x1000);
    write_u64(bytes, rva_offset(callbacks_rva) + 8, 0);
}

fn synthetic_pe_evidence() -> mida_acceptance::OreansPeEvidence {
    let mut bytes = pe_builder::build_pe(&pe_builder::PeBuildOptions {
        include_reloc: true,
        dll_characteristics: 0x0040,
        ..pe_builder::PeBuildOptions::pe32_plus()
    });
    set_tls(&mut bytes);
    write_u16(&mut bytes, RELOC_RAW + 8, 0xA000);
    build_oreans_pe_evidence(&bytes).expect("synthetic PE evidence")
}

fn candidate_from_pe(pe_evidence: &mida_acceptance::OreansPeEvidence) -> OreansArtifactIdentity {
    OreansArtifactIdentity {
        sha256: pe_evidence.candidate.sha256.clone(),
        size_bytes: pe_evidence.candidate.size_bytes,
    }
}

fn iat_evidence(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
) -> OreansIatEvidence {
    OreansIatEvidence {
        schema_version: "mida.oreans-iat-evidence/v1".to_string(),
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
        iat_report: Some(OreansIatReportEvidence {
            requested_bytes: 16,
            bytes_read: 16,
            slot_size: 8,
            slots: vec![
                OreansIatSlotEvidence {
                    slot_index: 0,
                    slot_address: 0x1800,
                    slot_rva: Some(0x1100),
                    observed_value: Some(0x7000),
                    rebuilt_value: Some(0x7000),
                    slot_value: Some(0x7000),
                    status: "Resolved".to_string(),
                    module_name: Some("KERNEL32.DLL".to_string()),
                    function_name: Some("ExitProcess".to_string()),
                    ordinal: None,
                },
                OreansIatSlotEvidence {
                    slot_index: 1,
                    slot_address: 0x1808,
                    slot_rva: Some(0x1108),
                    observed_value: Some(0),
                    rebuilt_value: None,
                    slot_value: Some(0),
                    status: "ZeroTerminator".to_string(),
                    module_name: None,
                    function_name: None,
                    ordinal: None,
                },
            ],
        }),
        final_imports: vec![OreansFinalImportEvidence {
            slot_rva: 0x1100,
            module_name: "kernel32.dll".to_string(),
            function_name: Some("ExitProcess".to_string()),
            ordinal: None,
        }],
        prerequisite_passes: true,
        blocker: None,
    }
}

fn tls_evidence(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> OreansTlsEvidence {
    let detail = pe.tls_detail.as_ref().expect("synthetic TLS detail");
    let image_base = pe.image_base;
    let runtime = OreansRuntimeTlsEvidence {
        directory_present: true,
        pe32_plus: pe.pe32_plus,
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
            OreansRuntimeTlsCallbackEvidence {
                slot_index: 0,
                slot_address: image_base + 0x1050,
                bytes_read: 8,
                observed_value: Some(image_base + 0x1000),
                callback_rva: Some(0x1000),
                status: "Resolved".to_string(),
            },
            OreansRuntimeTlsCallbackEvidence {
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
    };
    let final_candidate = mida_acceptance::OreansFinalTlsEvidence {
        directory_present: true,
        pe32_plus: pe.pe32_plus,
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
    };
    OreansTlsEvidence {
        schema_version: "mida.oreans-tls-evidence/v1".to_string(),
        protected_input: OreansTlsArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: OreansTlsArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        preservation: OreansTlsPreservationComparison {
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
        runtime,
        final_candidate,
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
) -> OreansGateRelocationEvidence {
    let image_base = pe.image_base;
    let runtime_base = image_base + 0x0100_0000;
    let normalized = image_base + 0x1234;
    let runtime = OreansRuntimeRelocationEvidence {
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
        targets: vec![OreansRuntimeRelocationTargetEvidence {
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
    };
    let final_candidate = OreansFinalRelocationEvidence {
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
        blocks: vec![OreansFinalRelocationBlockEvidence {
            block_index: 0,
            page_rva: 0x1000,
            block_size: 12,
            entry_count: 2,
        }],
        targets: vec![OreansFinalRelocationTargetEvidence {
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
    };
    let simulation = OreansAslrSimulationEvidence {
        pure_delta: true,
        covers_positive_delta: true,
        covers_negative_delta: true,
        normalized_values_used: true,
        cases: vec![
            OreansAslrSimulationCase {
                new_image_base: image_base + 0x100000,
                delta: 0x100000,
                target_count: 1,
                passed: true,
                blockers: Vec::new(),
            },
            OreansAslrSimulationCase {
                new_image_base: image_base - 0x100000,
                delta: -0x100000,
                target_count: 1,
                passed: true,
                blockers: Vec::new(),
            },
        ],
        all_passed: true,
        blockers: Vec::new(),
    };
    OreansGateRelocationEvidence {
        schema_version: OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: OreansTlsArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: OreansTlsArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        runtime,
        final_candidate,
        preservation: OreansRelocationPreservationComparison {
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
        simulation,
        reported_relocation_evidence_present: true,
        reported_relocation_evidence_complete: true,
        runtime_evidence_present: true,
        runtime_evidence_complete: true,
        prerequisite_passes: true,
        blockers: Vec::new(),
    }
}

fn oep_evidence(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
    pe_evidence: &mida_acceptance::OreansPeEvidence,
) -> OreansOepEvidence {
    OreansOepEvidence {
        schema_version: OREANS_OEP_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: OreansOepArtifactIdentity {
            path: "protected/origin_macro.exe".to_string(),
            sha256: protected_input.sha256.clone(),
            size_bytes: protected_input.size_bytes,
        },
        candidate: OreansOepArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        source: OreansOepSource::RuntimeRip,
        va: Some(0x0000_0001_4000_1000),
        rva: Some(pe_evidence.entry_rva),
        final_entry_rva: pe_evidence.entry_rva,
        evidence: "synthetic runtime RIP reached the application OEP".to_string(),
        application_oep: true,
        bootstrap_or_ambiguous: false,
        entry_rva_matches_provenance: true,
        prerequisite_passes: true,
        blocker: None,
    }
}

fn behavior(
    candidate: &OreansArtifactIdentity,
    protected_input: &OreansArtifactIdentity,
) -> OreansBehaviorEvidence {
    OreansBehaviorEvidence {
        schema_version: OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION.to_string(),
        stimuli: vec![OreansBehaviorStimulus {
            id: "launch-default".to_string(),
            value: "default invocation".to_string(),
        }],
        observables: vec![OreansBehaviorObservable {
            id: "ready-marker".to_string(),
            value: "application-ready".to_string(),
            verdict: OreansFinalBehaviorVerdict::Pass,
        }],
        candidate_identity: candidate.clone(),
        protected_identity: protected_input.clone(),
        verdict: OreansFinalBehaviorVerdict::Pass,
        reason: "all registered observables matched the protected reference".to_string(),
    }
}

fn replay(candidate: &OreansArtifactIdentity) -> OreansIsolatedReplay {
    OreansIsolatedReplay {
        schema_version: OREANS_ISOLATED_REPLAY_SCHEMA_VERSION.to_string(),
        attempts: (1..=10)
            .map(|attempt_index| OreansReplayAttempt {
                attempt_index,
                candidate_sha256: candidate.sha256.clone(),
                exit_code: Some(0),
                signal: None,
                observable_verdict: OreansFinalBehaviorVerdict::Pass,
                timestamp: format!("2026-08-01T12:00:{attempt_index:02}Z"),
                runner_config_digest: "cd".repeat(32),
                retry_picked: false,
            })
            .collect(),
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
    let candidate = candidate_from_pe(&pe_evidence);
    OreansSampleObservation {
        case_id: case_id.to_string(),
        protected_input: protected_input.clone(),
        candidate: candidate.clone(),
        oep_evidence: oep_evidence(&candidate, &protected_input, &pe_evidence),
        iat_evidence: iat_evidence(&candidate, &protected_input),
        tls_evidence: tls_evidence(&candidate, &protected_input, &pe_evidence),
        relocation_evidence: relocation_evidence(&candidate, &protected_input, &pe_evidence),
        pe_evidence: pe_evidence.clone(),
        section_rebuild_evidence: section_rebuild_evidence(
            &candidate,
            &protected_input,
            &pe_evidence,
        ),
        prerequisites: prerequisites(true, &candidate.sha256),
        behavior_evidence: behavior(&candidate, &protected_input),
        isolated_replay: replay(&candidate),
    }
}

fn both_passing() -> [OreansSampleObservation; 2] {
    [
        observation(
            "origin_macro",
            "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7",
            5_232_656,
        ),
        observation(
            "lunlun_software",
            "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07",
            4_976_144,
        ),
    ]
}

#[test]
fn locked_values_match_repository_case_manifests() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for lock in OREANS_SAMPLE_MANIFESTS {
        let path = root.join(lock.manifest_path);
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read case manifest JSON"))
                .expect("parse case manifest JSON");
        assert_eq!(json["case_id"], lock.case_id);
        assert_eq!(json["primary_artifact_sha256"], lock.protected_input_sha256);
        assert_eq!(json["artifacts"][0]["sha256"], lock.protected_input_sha256);
        assert_eq!(
            json["artifacts"][0]["size_bytes"],
            lock.protected_input_size_bytes
        );
    }
}

fn assert_origin_pe_failure(
    mutate: impl FnOnce(&mut mida_acceptance::OreansPeEvidence),
    expected_failure: &str,
) {
    let mut cases = both_passing();
    mutate(&mut cases[0].pe_evidence);
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    assert_eq!(report.final_verdict, OreansGateVerdict::Open, "{report:#?}");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.prerequisites_pass);
    assert!(!origin.passed);
    assert!(
        origin
            .failures
            .iter()
            .any(|failure| failure.contains(expected_failure)),
        "failures: {:?}",
        origin.failures
    );
}

#[test]
fn structured_pe_evidence_is_required_and_serialized_in_v7_reports() {
    let cases = both_passing();
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    assert_eq!(report.schema_version, "mida.oreans-two-sample-gate/v8");
    assert!(
        report.samples.iter().all(|sample| sample.passed),
        "{report:#?}"
    );
    let json = serde_json::to_value(&report).expect("serializable report");
    assert!(json["samples"][0]["pe_evidence"].is_object());
    assert!(json["samples"][0]["oep_evidence"].is_object());
    assert!(json["samples"][0]["oep_evidence_pass"].as_bool().unwrap());
    assert!(json["samples"][0]["tls_evidence"].is_object());
    assert!(json["samples"][0]["tls_evidence_pass"].as_bool().unwrap());
    assert!(json["samples"][0]["relocation_evidence"].is_object());
    assert!(json["samples"][0]["relocation_evidence_pass"]
        .as_bool()
        .unwrap());

    let mut observation_json = serde_json::to_value(&cases[0]).expect("serialize observation");
    observation_json
        .as_object_mut()
        .expect("observation object")
        .remove("pe_evidence");
    assert!(serde_json::from_value::<OreansSampleObservation>(observation_json).is_err());
}

#[test]
fn structured_oep_evidence_is_required_and_legacy_fields_are_rejected() {
    let cases = both_passing();
    let mut missing = serde_json::to_value(&cases[0]).expect("serialize observation");
    missing
        .as_object_mut()
        .expect("observation object")
        .remove("oep_evidence");
    assert!(serde_json::from_value::<OreansSampleObservation>(missing).is_err());

    let mut legacy = serde_json::to_value(&cases[0]).expect("serialize observation");
    legacy["prerequisites"]["oep_recovered"] = serde_json::Value::Bool(true);
    legacy["prerequisites"]["oep_evidence"] = serde_json::json!({
        "schema_version": OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
        "producer": "legacy",
        "artifact_sha256": cases[0].candidate.sha256,
        "summary": "legacy OEP ref"
    });
    assert!(serde_json::from_value::<OreansSampleObservation>(legacy).is_err());
}

fn assert_oep_failure(mutate: impl FnOnce(&mut OreansOepEvidence), expected_failure: &str) {
    let mut cases = both_passing();
    mutate(&mut cases[0].oep_evidence);
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.oep_evidence_pass, "{report:#?}");
    assert!(!origin.prerequisites_pass, "{report:#?}");
    assert!(!origin.passed, "{report:#?}");
    assert!(
        origin
            .failures
            .iter()
            .any(|failure| failure.contains("structured OEP evidence")
                && failure.contains(expected_failure)),
        "failures: {:?}",
        origin.failures
    );
}

#[test]
fn structured_oep_source_and_addresses_fail_closed() {
    assert_oep_failure(
        |evidence| evidence.source = OreansOepSource::ScanFallback,
        "source",
    );
    assert_oep_failure(
        |evidence| evidence.source = OreansOepSource::Unknown,
        "source",
    );
    assert_oep_failure(|evidence| evidence.va = None, "VA is missing");
    assert_oep_failure(|evidence| evidence.rva = None, "RVA is missing");
    assert_oep_failure(
        |evidence| evidence.rva = Some(evidence.final_entry_rva + 1),
        "RVA does not match final_entry_rva",
    );
    assert_oep_failure(
        |evidence| evidence.final_entry_rva += 1,
        "structured PE AddressOfEntryPoint",
    );
}

#[test]
fn structured_oep_identity_flags_and_contract_fail_closed() {
    assert_oep_failure(
        |evidence| evidence.schema_version = "wrong-schema".to_string(),
        "schema_version",
    );
    assert_oep_failure(
        |evidence| evidence.protected_input.path.clear(),
        "path is empty",
    );
    assert_oep_failure(|evidence| evidence.candidate.path.clear(), "path is empty");
    assert_oep_failure(
        |evidence| evidence.protected_input.size_bytes += 1,
        "protected_input SHA-256/size",
    );
    assert_oep_failure(
        |evidence| evidence.candidate.sha256 = "ef".repeat(32),
        "candidate SHA-256/size",
    );
    assert_oep_failure(|evidence| evidence.evidence.clear(), "evidence is empty");
    assert_oep_failure(
        |evidence| evidence.application_oep = false,
        "application_oep",
    );
    assert_oep_failure(
        |evidence| evidence.bootstrap_or_ambiguous = true,
        "bootstrap_or_ambiguous",
    );
    assert_oep_failure(
        |evidence| evidence.entry_rva_matches_provenance = false,
        "entry_rva_matches_provenance",
    );
    assert_oep_failure(
        |evidence| evidence.prerequisite_passes = false,
        "prerequisite_passes",
    );
    assert_oep_failure(
        |evidence| evidence.blocker = Some("blocked".to_string()),
        "blocker",
    );
}

#[test]
fn structured_pe_schema_and_valid_flag_are_fail_closed() {
    assert_origin_pe_failure(
        |evidence| evidence.schema_version = "wrong-schema".to_string(),
        "structured PE evidence schema_version",
    );
    assert_origin_pe_failure(
        |evidence| evidence.valid = false,
        "structured PE evidence valid=false",
    );
}

#[test]
fn structured_pe_candidate_identity_must_match_observation() {
    assert_origin_pe_failure(
        |evidence| evidence.candidate.sha256 = "ef".repeat(32),
        "structured PE evidence candidate SHA-256",
    );
    assert_origin_pe_failure(
        |evidence| evidence.candidate.size_bytes += 1,
        "structured PE evidence candidate size",
    );
}

#[test]
fn structured_pe_tls_coverage_and_detail_are_fail_closed() {
    assert_origin_pe_failure(
        |evidence| evidence.tls.present = false,
        "TLS coverage is absent",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence.exception.present = false;
            evidence.exception.rva = 0x1000;
            evidence.exception.size = 12;
        },
        "exception absent coverage is not canonical",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence.tls.present = true;
            evidence.tls.rva = 0;
            evidence.tls.size = 40;
            evidence.tls.in_image = true;
            evidence.tls.raw_backed = true;
        },
        "TLS coverage has zero RVA",
    );
    assert_origin_pe_failure(
        |evidence| evidence.tls_detail = None,
        "TLS detail is missing",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence
                .tls_detail
                .as_mut()
                .expect("synthetic TLS detail")
                .null_terminated = false;
        },
        "TLS callbacks are not null-terminated",
    );
    assert_origin_pe_failure(
        |evidence| {
            let text_virtual_address = evidence
                .sections
                .first()
                .expect("synthetic .text section")
                .virtual_address;
            let text_raw_size = evidence
                .sections
                .first()
                .expect("synthetic .text section")
                .raw_size;
            let next_section_virtual_address = evidence
                .sections
                .iter()
                .skip(1)
                .map(|section| section.virtual_address)
                .min()
                .unwrap_or(evidence.size_of_image);
            let desired_virtual_size = text_raw_size
                .checked_add(0x100)
                .expect("synthetic .text virtual size");
            let text_virtual_end = text_virtual_address
                .checked_add(desired_virtual_size)
                .expect("synthetic .text virtual end");
            assert!(desired_virtual_size > text_raw_size);
            assert!(text_virtual_end <= evidence.size_of_image);
            assert!(text_virtual_end <= next_section_virtual_address);
            evidence.sections[0].virtual_size = desired_virtual_size;

            let address_of_index_rva = text_virtual_address
                .checked_add(text_raw_size)
                .expect("synthetic TLS AddressOfIndex RVA");
            let address_of_index_end = address_of_index_rva
                .checked_add(4)
                .expect("synthetic TLS AddressOfIndex end");
            assert!(address_of_index_rva >= text_virtual_address + text_raw_size);
            assert!(address_of_index_end > text_virtual_address + text_raw_size);
            assert!(address_of_index_end <= text_virtual_end);
            evidence
                .tls_detail
                .as_mut()
                .expect("synthetic TLS detail")
                .address_of_index_rva = Some(address_of_index_rva);
        },
        "TLS AddressOfIndex is not raw-backed",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence
                .tls_detail
                .as_mut()
                .expect("synthetic TLS detail")
                .callback_array_rva = Some(0x11f8);
        },
        "TLS callback array is not raw-backed through its NULL terminator",
    );
}

#[test]
fn structured_pe_relocations_require_coverage_and_semantics() {
    assert_origin_pe_failure(
        |evidence| evidence.base_reloc.present = false,
        "base relocation coverage is absent",
    );
    assert_origin_pe_failure(
        |evidence| evidence.relocation_detail = None,
        "relocation detail is missing",
    );
    assert_origin_pe_failure(
        |evidence| {
            let detail = evidence
                .relocation_detail
                .as_mut()
                .expect("synthetic relocation detail");
            detail.relocs_stripped = true;
            evidence.coff_characteristics |= 0x0001;
        },
        "relocation relocs_stripped=true",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence
                .relocation_detail
                .as_mut()
                .expect("synthetic relocation detail")
                .non_absolute_entry_count = 0;
        },
        "non_absolute_entry_count is zero",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence
                .relocation_detail
                .as_mut()
                .expect("synthetic relocation detail")
                .dynamic_base = false;
        },
        "dynamic_base disagrees",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence
                .relocation_detail
                .as_mut()
                .expect("synthetic relocation detail")
                .observed_types = vec![0];
        },
        "require observed type 10",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence
                .relocation_detail
                .as_mut()
                .expect("synthetic relocation detail")
                .observed_types = vec![0, 10, 3];
        },
        "observed type 3 is invalid",
    );
}

#[test]
fn structured_pe_section_raw_ranges_must_not_overlap() {
    assert_origin_pe_failure(
        |evidence| {
            let text_raw_offset = evidence.sections[0].raw_offset;
            evidence.sections[1].raw_offset = text_raw_offset + 0x100;
        },
        "overlapping raw ranges",
    );
}

fn valid_exception(evidence: &mut mida_acceptance::OreansPeEvidence) {
    evidence.exception.present = true;
    evidence.exception.rva = 0x2000;
    evidence.exception.size = 12;
    evidence.exception.in_image = true;
    evidence.exception.raw_backed = true;
    evidence.exception_detail = Some(mida_acceptance::OreansExceptionEvidence {
        runtime_function_count: 1,
        runtime_functions: vec![mida_acceptance::OreansRuntimeFunctionEvidence {
            begin_rva: 0x1000,
            end_rva: 0x1004,
            unwind_rva: 0x1008,
        }],
        ranges_raw_backed: true,
        unwind_rvas_raw_backed: true,
    });
}

#[test]
fn structured_pe_entry_sections_and_exception_detail_are_fail_closed() {
    assert_origin_pe_failure(
        |evidence| evidence.entry_rva = 0x2000,
        "entry_rva is not inside an executable section",
    );
    assert_origin_pe_failure(
        |evidence| evidence.sections[0].virtual_address = 0x3000,
        "section '.text' exceeds size_of_image",
    );
    assert_origin_pe_failure(
        |evidence| {
            evidence.exception.present = true;
            evidence.exception.rva = 0x1000;
            evidence.exception.size = 12;
            evidence.exception.in_image = true;
            evidence.exception.raw_backed = true;
        },
        "exception detail is missing",
    );
    assert_origin_pe_failure(
        |evidence| {
            valid_exception(evidence);
            evidence.exception.size = 24;
        },
        "exception coverage size does not equal",
    );
    assert_origin_pe_failure(
        |evidence| {
            valid_exception(evidence);
            evidence
                .exception_detail
                .as_mut()
                .expect("synthetic exception detail")
                .runtime_function_count = 2;
        },
        "exception count does not match",
    );
    assert_origin_pe_failure(
        |evidence| {
            valid_exception(evidence);
            let function = &mut evidence
                .exception_detail
                .as_mut()
                .expect("synthetic exception detail")
                .runtime_functions[0];
            function.begin_rva = 0x2000;
            function.end_rva = 0x2004;
        },
        "exception runtime function 0 is not executable",
    );
    assert_origin_pe_failure(
        |evidence| {
            valid_exception(evidence);
            evidence
                .exception_detail
                .as_mut()
                .expect("synthetic exception detail")
                .runtime_functions[0]
                .unwind_rva = 0x11ff;
        },
        "exception runtime function 0 unwind RVA is not raw-backed",
    );
}

#[test]
fn both_fixed_samples_are_required_for_closed_gate() {
    let report = evaluate_oreans_two_sample_gate(&both_passing()).expect("valid case set");
    assert_eq!(
        report.final_verdict,
        OreansGateVerdict::Closed,
        "{report:#?}"
    );
    assert_eq!(report.required_cases, ["origin_macro", "lunlun_software"]);
    assert!(report.samples.iter().all(|sample| sample.passed));

    let json = serde_json::to_value(&report).expect("serializable report");
    assert!(json["samples"][0]["behavior_evidence"]["stimuli"].is_array());
    assert!(json["samples"][0]["behavior_evidence"]["observables"].is_array());
    assert!(json["samples"][0]["behavior_evidence"]["candidate_identity"].is_object());
    assert!(json["samples"][0]["behavior_evidence"]["protected_identity"].is_object());
    assert!(json["samples"][0]["behavior_evidence"]["verdict"].is_string());
    assert!(json["samples"][0]["behavior_evidence"]["reason"].is_string());
    assert_eq!(
        json["samples"][0]["isolated_replay"]["attempts"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
}

#[test]
fn survival_and_structure_are_prerequisites_not_final_behavior() {
    let mut cases = both_passing();
    cases[0].prerequisites.structural = false;

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    assert_eq!(report.final_verdict, OreansGateVerdict::Open);
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.prerequisites_pass);
    assert_eq!(
        origin.final_behavior_verdict,
        OreansFinalBehaviorVerdict::Pass
    );
    assert!(!origin.passed);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("structural PE acceptance")));
}

#[test]
fn final_behavior_failure_keeps_gate_open_even_when_prerequisites_pass() {
    let mut cases = both_passing();
    cases[1].behavior_evidence.verdict = OreansFinalBehaviorVerdict::Fail;

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let lunlun = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "lunlun_software")
        .unwrap();
    assert!(lunlun.prerequisites_pass);
    assert_eq!(
        lunlun.final_behavior_verdict,
        OreansFinalBehaviorVerdict::Fail
    );
    assert!(!lunlun.passed);
}

#[test]
fn manifest_sha256_and_size_are_fail_closed() {
    let mut cases = both_passing();
    cases[0].protected_input.size_bytes += 1;
    cases[1].protected_input.sha256 = "cd".repeat(32);

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    assert_eq!(report.final_verdict, OreansGateVerdict::Open);
    assert!(report.samples.iter().all(|sample| !sample.passed));
    assert!(report.samples.iter().all(|sample| !sample.manifest.matched));
}

#[test]
fn gto_holdout_and_shiguang_cannot_satisfy_the_gate() {
    for case_id in ["gto_launcher", "xiongxiong_duokai", "shiguang"] {
        let err = evaluate_oreans_two_sample_gate(&[
            observation(case_id, "aa".repeat(32).as_str(), 1),
            observation(
                "origin_macro",
                "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7",
                5_232_656,
            ),
        ])
        .expect_err("non-gate case must be rejected");
        assert_eq!(err, OreansGateError::CaseNotAllowed(case_id.to_string()));
    }
}

#[test]
fn missing_or_duplicate_required_case_is_not_a_partial_pass() {
    let cases = both_passing();
    assert_eq!(
        evaluate_oreans_two_sample_gate(&cases[..1]).expect_err("missing case"),
        OreansGateError::MissingCase("lunlun_software".to_string())
    );
    assert_eq!(
        evaluate_oreans_two_sample_gate(&[cases[0].clone(), cases[0].clone()])
            .expect_err("duplicate case"),
        OreansGateError::DuplicateCase("origin_macro".to_string())
    );
}

#[test]
fn behavior_candidate_mismatch_keeps_gate_open() {
    let mut cases = both_passing();
    cases[0].behavior_evidence.candidate_identity.sha256 = "ef".repeat(32);

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.passed);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("behavior candidate identity")));
}

#[test]
fn nine_of_ten_replay_attempts_cannot_pass() {
    let mut cases = both_passing();
    cases[0].isolated_replay.attempts.pop();

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.isolated_replay_pass);
    assert!(!origin.prerequisites_pass);
    assert!(!origin.passed);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("exactly 10 required")));
}

#[test]
fn ten_replay_attempts_must_be_contiguous_and_ordered() {
    let mut cases = both_passing();
    cases[0].isolated_replay.attempts.swap(4, 5);

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.isolated_replay_pass);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("attempt_index")));
}

#[test]
fn runner_config_digest_must_match_across_all_ten_replay_attempts() {
    let mut cases = both_passing();
    cases[0].isolated_replay.attempts[6].runner_config_digest = "ef".repeat(32);

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.isolated_replay_pass);
    assert!(!origin.prerequisites_pass);
    assert!(origin.failures.iter().any(|failure| {
        failure.contains("runner_config_digest")
            || failure.contains("config")
            || failure.contains("mismatch")
    }));
}

#[test]
fn retry_picked_is_illegal_even_when_all_ten_attempts_pass() {
    let mut cases = both_passing();
    cases[0].isolated_replay.attempts[9].retry_picked = true;

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.isolated_replay_pass);
    assert!(!origin.passed);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("retry_picked")));
}

#[test]
fn observables_inconclusive_cannot_be_upgraded_to_behavior_pass() {
    let mut cases = both_passing();
    cases[0].behavior_evidence.observables[0].verdict = OreansFinalBehaviorVerdict::Inconclusive;

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.passed);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("observable 'ready-marker'")));
}

#[test]
fn replay_failure_exit_signal_and_observable_verdict_keep_gate_open() {
    let mut cases = both_passing();
    cases[0].isolated_replay.attempts[0].exit_code = Some(1);
    cases[0].isolated_replay.attempts[1].signal = Some("SIGTERM".to_string());
    cases[0].isolated_replay.attempts[2].observable_verdict = OreansFinalBehaviorVerdict::Fail;

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.isolated_replay_pass);
    assert!(!origin.passed);
}

#[test]
fn malformed_candidate_identity_cannot_pass() {
    let mut cases = both_passing();
    cases[0].candidate.sha256 = "not-a-digest".to_string();
    cases[0].candidate.size_bytes = 0;

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.passed);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("candidate SHA-256/size")));
}

#[test]
fn legacy_tls_relocation_fields_are_rejected() {
    let cases = both_passing();
    let mut legacy = serde_json::to_value(&cases[0]).expect("serialize observation");
    legacy["prerequisites"]["tls_relocations_valid"] = serde_json::Value::Bool(true);
    legacy["prerequisites"]["tls_relocation_evidence"] = serde_json::json!({
        "schema_version": OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
        "producer": "legacy",
        "artifact_sha256": cases[0].candidate.sha256,
        "summary": "legacy TLS ref"
    });
    assert!(serde_json::from_value::<OreansSampleObservation>(legacy).is_err());
}

#[test]
fn section_rebuild_structured_evidence_cannot_be_replaced_by_generic_ref() {
    let mut cases = both_passing();
    cases[0]
        .section_rebuild_evidence
        .section_rebuild_evidence_pass = false;

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.prerequisites_pass);
    assert!(!origin.passed);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("section rebuild") && failure.contains("evidence")));
}

#[test]
fn section_rebuild_unknown_fields_and_layout_mismatches_fail_closed() {
    let cases = both_passing();
    let mut json = serde_json::to_value(&cases[0]).expect("serialize observation");
    json["section_rebuild_evidence"]["unknown"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<OreansSampleObservation>(json).is_err());

    let mut mutations: Vec<fn(&mut OreansSampleObservation)> = vec![
        |case| {
            case.section_rebuild_evidence.sections[1].raw_offset = 0x200;
            case.section_rebuild_evidence.sections[1].raw_end = 0x400;
        },
        |case| {
            case.section_rebuild_evidence.sections[1].raw_end = case.candidate.size_bytes + 1;
        },
        |case| {
            case.section_rebuild_evidence.directories[9].raw_backed = false;
        },
        |case| {
            case.section_rebuild_evidence.sections[0].characteristics &= !0x2000_0000;
        },
        |case| {
            case.section_rebuild_evidence.size_of_image -=
                case.section_rebuild_evidence.section_alignment;
        },
        |case| {
            case.section_rebuild_evidence.size_of_headers +=
                case.section_rebuild_evidence.file_alignment;
        },
        |case| {
            case.section_rebuild_evidence.file_alignment =
                case.section_rebuild_evidence.section_alignment * 2;
        },
        |case| {
            case.section_rebuild_evidence.sections[0].raw_size += 1;
        },
    ];
    for mutate in mutations.drain(..) {
        let mut mutated = cases.clone();
        mutate(&mut mutated[0]);
        let report = evaluate_oreans_two_sample_gate(&mutated).expect("valid case set");
        let sample = report
            .samples
            .iter()
            .find(|sample| sample.case_id == "origin_macro")
            .expect("origin sample");
        assert!(!sample.section_rebuild_evidence_pass);
        assert!(!sample.passed);
    }
}

#[test]
fn section_rebuild_raw_size_alignment_is_required() {
    let mut cases = both_passing();
    cases[0].section_rebuild_evidence.sections[0].raw_size += 1;
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .expect("origin sample");
    assert!(!origin.section_rebuild_evidence_pass);
    assert!(origin
        .failures
        .iter()
        .any(|failure| failure.contains("raw pointer/size")));
}

#[test]
fn structured_oep_identity_must_match_candidate() {
    let mut cases = both_passing();
    cases[0].oep_evidence.candidate.sha256 = "ef".repeat(32);

    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.prerequisites_pass);
    assert!(!origin.passed);
    assert!(origin.failures.iter().any(|failure| {
        failure.contains("structured OEP evidence") && failure.contains("candidate SHA-256/size")
    }));
}

#[test]
fn structured_iat_evidence_is_required_and_serialized_in_v7_reports() {
    let cases = both_passing();
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    assert_eq!(report.schema_version, "mida.oreans-two-sample-gate/v8");
    assert!(report.samples.iter().all(|sample| sample.passed));
    assert!(report.samples.iter().all(|sample| sample.iat_evidence_pass));
    let json = serde_json::to_value(&report).expect("serialize report");
    assert!(json["samples"][0]["iat_evidence"].is_object());
    assert_eq!(json["samples"][0]["iat_evidence_pass"], true);

    let mut missing = serde_json::to_value(&cases[0]).expect("serialize observation");
    missing.as_object_mut().unwrap().remove("iat_evidence");
    assert!(serde_json::from_value::<OreansSampleObservation>(missing).is_err());

    let mut legacy = serde_json::to_value(&cases[0]).expect("serialize observation");
    legacy["prerequisites"]["iat_complete"] = serde_json::Value::Bool(true);
    legacy["prerequisites"]["iat_evidence"] = serde_json::json!({
        "schema_version": OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
        "producer": "legacy",
        "artifact_sha256": cases[0].candidate.sha256,
        "summary": "legacy IAT ref"
    });
    assert!(serde_json::from_value::<OreansSampleObservation>(legacy).is_err());
}

fn assert_iat_failure(mutate: impl FnOnce(&mut OreansIatEvidence), expected: &str) {
    let mut cases = both_passing();
    mutate(&mut cases[0].iat_evidence);
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.iat_evidence_pass, "{report:#?}");
    assert!(!origin.prerequisites_pass, "{report:#?}");
    assert!(!origin.passed, "{report:#?}");
    assert!(
        origin.failures.iter().any(|failure| {
            failure.contains("structured IAT evidence") && failure.contains(expected)
        }),
        "failures: {:?}",
        origin.failures
    );
}

#[test]
fn structured_iat_identity_and_request_contract_fail_closed() {
    assert_iat_failure(
        |e| e.schema_version = "wrong-schema".to_string(),
        "schema_version",
    );
    assert_iat_failure(|e| e.protected_input.path.clear(), "path is empty");
    assert_iat_failure(|e| e.candidate.sha256 = "ef".repeat(32), "SHA-256/size");
    assert_iat_failure(|e| e.fix_imports_requested = false, "fix_imports_requested");
    assert_iat_failure(|e| e.iat_evidence_present = false, "present");
    assert_iat_failure(|e| e.iat_evidence_complete = false, "complete");
    assert_iat_failure(|e| e.prerequisite_passes = false, "diagnostic");
    assert_iat_failure(
        |e| e.blocker = Some("incorrect self-certification".to_string()),
        "blocker",
    );
}

#[test]
fn structured_iat_report_fail_closed_categories() {
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slot_size = 4,
        "slot_size",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().bytes_read = 8,
        "short-read",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().requested_bytes = 12,
        "aligned",
    );
    assert_iat_failure(
        |e| {
            e.iat_report.as_mut().unwrap().slots.pop();
        },
        "coverage",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[1].slot_index = 0,
        "duplicate slot_index",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[1].slot_address = 0x1800,
        "duplicate slot_address",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[1].slot_rva = Some(0x1100),
        "duplicate slot_rva",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[1].slot_rva = Some(0x1110),
        "continuous",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[0].slot_value = Some(0xdead),
        "observed_value",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[0].status = "Stale".to_string(),
        "Stale",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[0].status = "Unresolved".to_string(),
        "Unresolved",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[0].status = "ShortRead".to_string(),
        "ShortRead",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[0].status = "InvalidModule".to_string(),
        "InvalidModule",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[0].function_name = None,
        "identity metadata",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[1].observed_value = Some(1),
        "ZeroTerminator",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[0].status = "Unknown".to_string(),
        "unknown",
    );
    assert_iat_failure(
        |e| e.iat_report.as_mut().unwrap().slots[0].status = "ZeroTerminator".to_string(),
        "no resolved",
    );
    assert_iat_failure(|e| e.iat_report = None, "iat_report missing");
}

#[test]
fn final_import_identity_is_strict_and_ordinal_zero_is_supported() {
    assert_iat_failure(|e| e.final_imports.clear(), "final imports are empty");
    assert_iat_failure(
        |e| e.final_imports[0].module_name = "Kernel32.DLL".to_string(),
        "lowercase ASCII",
    );
    assert_iat_failure(
        |e| e.final_imports[0].function_name = Some("exitprocess".to_string()),
        "function mismatch",
    );
    assert_iat_failure(
        |e| {
            e.final_imports[0].ordinal = Some(0);
            e.iat_report.as_mut().unwrap().slots[0].ordinal = Some(0);
        },
        "exactly one",
    );

    let mut cases = both_passing();
    cases[0].iat_evidence.final_imports[0].function_name = None;
    cases[0].iat_evidence.final_imports[0].ordinal = Some(0);
    cases[0].iat_evidence.iat_report.as_mut().unwrap().slots[0].function_name = None;
    cases[0].iat_evidence.iat_report.as_mut().unwrap().slots[0].ordinal = Some(0);
    let report = evaluate_oreans_two_sample_gate(&cases).expect("ordinal zero is valid");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(origin.iat_evidence_pass, "{report:#?}");
    assert!(origin.passed, "{report:#?}");
}

fn assert_tls_failure(mutate: impl FnOnce(&mut OreansTlsEvidence), expected: &str) {
    let mut cases = both_passing();
    mutate(&mut cases[0].tls_evidence);
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.tls_evidence_pass, "{report:#?}");
    assert!(!origin.prerequisites_pass, "{report:#?}");
    assert!(!origin.passed, "{report:#?}");
    assert!(
        origin.failures.iter().any(|failure| {
            failure.contains("structured TLS evidence") && failure.contains(expected)
        }),
        "failures: {:?}",
        origin.failures
    );
}

#[test]
fn structured_tls_evidence_is_first_class_and_strict() {
    let cases = both_passing();
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    assert_eq!(report.schema_version, "mida.oreans-two-sample-gate/v8");
    assert!(report.samples.iter().all(|sample| sample.tls_evidence_pass));
    let json = serde_json::to_value(&report).expect("serialize report");
    assert!(json["samples"][0]["tls_evidence"].is_object());
    assert_eq!(json["samples"][0]["tls_evidence_pass"], true);

    let mut missing = serde_json::to_value(&cases[0]).expect("serialize observation");
    missing.as_object_mut().unwrap().remove("tls_evidence");
    assert!(serde_json::from_value::<OreansSampleObservation>(missing).is_err());

    let mut unknown = serde_json::to_value(&cases[0]).expect("serialize observation");
    unknown["tls_evidence"]["unknown"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<OreansSampleObservation>(unknown).is_err());
}

fn assert_relocation_failure(
    mutate: impl FnOnce(&mut OreansGateRelocationEvidence),
    expected: &str,
) {
    let mut cases = both_passing();
    mutate(&mut cases[0].relocation_evidence);
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    let origin = report
        .samples
        .iter()
        .find(|sample| sample.case_id == "origin_macro")
        .unwrap();
    assert!(!origin.relocation_evidence_pass, "{report:#?}");
    assert!(!origin.prerequisites_pass, "{report:#?}");
    assert!(
        origin.failures.iter().any(|failure| {
            failure.contains("structured relocation evidence") && failure.contains(expected)
        }),
        "failures: {:?}",
        origin.failures
    );
}

#[test]
fn structured_relocation_evidence_is_first_class_and_strict() {
    let cases = both_passing();
    let report = evaluate_oreans_two_sample_gate(&cases).expect("valid case set");
    assert!(report
        .samples
        .iter()
        .all(|sample| sample.relocation_evidence_pass));
    let json = serde_json::to_value(&report).expect("serialize report");
    assert!(json["samples"][0]["relocation_evidence"].is_object());
    assert_eq!(json["samples"][0]["relocation_evidence_pass"], true);

    let mut missing = serde_json::to_value(&cases[0]).expect("serialize observation");
    missing
        .as_object_mut()
        .unwrap()
        .remove("relocation_evidence");
    assert!(serde_json::from_value::<OreansSampleObservation>(missing).is_err());

    assert_relocation_failure(
        |e| e.final_candidate.targets[0].raw_backed = false,
        "raw-backed",
    );
    assert_relocation_failure(
        |e| e.runtime.targets[0].normalized_value = e.runtime.targets[0].runtime_value,
        "de-relocated",
    );
    assert_relocation_failure(
        |e| e.final_candidate.targets[0].entry_index = e.final_candidate.blocks[0].entry_count,
        "block/entry index",
    );
    assert_relocation_failure(
        |e| e.simulation.covers_negative_delta = false,
        "positive and negative",
    );
}

#[test]
fn structured_tls_identity_and_diagnostics_fail_closed() {
    assert_tls_failure(
        |e| e.schema_version = "wrong-schema".to_string(),
        "schema_version",
    );
    assert_tls_failure(
        |e| e.protected_input.sha256 = "ef".repeat(32),
        "SHA-256/size",
    );
    assert_tls_failure(|e| e.candidate.size_bytes += 1, "SHA-256/size");
    assert_tls_failure(
        |e| e.reported_tls_evidence_present = false,
        "reported_tls_evidence_present",
    );
    assert_tls_failure(
        |e| e.reported_tls_evidence_complete = false,
        "reported_tls_evidence_complete",
    );
    assert_tls_failure(
        |e| e.runtime_evidence_present = false,
        "runtime_evidence_present",
    );
    assert_tls_failure(
        |e| e.runtime_evidence_complete = false,
        "runtime_evidence_complete",
    );
    assert_tls_failure(|e| e.runtime.directory_present = false, "absent");
    assert_tls_failure(|e| e.runtime.pointer_size = 2, "pointer_size");
    assert_tls_failure(|e| e.runtime.callback_slots[0].slot_index = 1, "continuous");
    assert_tls_failure(
        |e| e.runtime.callback_slots[0].status = "ShortRead".to_string(),
        "invalid",
    );
    assert_tls_failure(
        |e| e.runtime.callback_slots[0].callback_rva = None,
        "incomplete",
    );
    assert_tls_failure(|e| e.runtime.callback_slots[1].slot_index = 0, "continuous");
    assert_tls_failure(
        |e| e.runtime.callback_slots[1].observed_value = Some(1),
        "zero terminator",
    );
    assert_tls_failure(|e| e.runtime.null_terminated = false, "null_terminated");
    assert_tls_failure(
        |e| e.runtime.blockers = vec!["runtime blocker".to_string()],
        "blockers",
    );
    assert_tls_failure(|e| e.runtime.blockers = vec!["".to_string()], "blockers");
}

#[test]
fn structured_tls_final_and_preservation_fields_are_recomputed() {
    assert_tls_failure(
        |e| e.final_candidate.directory_rva += 1,
        "structured PE evidence",
    );
    assert_tls_failure(
        |e| e.final_candidate.index_rva = Some(0x1061),
        "structured PE TLS detail",
    );
    assert_tls_failure(
        |e| e.final_candidate.callback_rvas[0] += 1,
        "structured PE TLS detail",
    );
    assert_tls_failure(
        |e| {
            e.final_candidate.start_rva = Some(0x1200);
            e.final_candidate.end_rva = Some(0x1300);
        },
        "not raw-backed",
    );
    assert_tls_failure(|e| e.final_candidate.size_of_zero_fill = 1, "preservation");
    assert_tls_failure(|e| e.final_candidate.characteristics = 1, "preservation");
    assert_tls_failure(
        |e| e.final_candidate.blockers = vec!["final blocker".to_string()],
        "final TLS evidence",
    );
    assert_tls_failure(|e| e.preservation.all_preserved = false, "preservation");
    assert_tls_failure(
        |e| e.preservation.blockers = vec!["fake blocker".to_string()],
        "preservation",
    );
    assert_tls_failure(|e| e.prerequisite_passes = false, "diagnostic");
    assert_tls_failure(
        |e| {
            e.final_candidate.directory_rva += 1;
            e.blockers.clear();
        },
        "failed TLS evidence must include a blocker",
    );
    assert_tls_failure(
        |e| e.blockers = vec!["z".to_string(), "a".to_string()],
        "sorted",
    );
}
