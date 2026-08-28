//! Offline CLI tests use only synthetic observations and PE bytes.
//! No sample executable is opened, launched, unpacked, or otherwise touched.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "../src/test_support/pe_builder.rs"]
mod pe_builder;

use mida_acceptance::{
    build_oreans_pe_evidence, OreansArtifactIdentity, OreansAslrSimulationCase,
    OreansAslrSimulationEvidence, OreansBehaviorEvidence, OreansBehaviorObservable,
    OreansBehaviorStimulus, OreansEvidenceRef, OreansFinalBehaviorVerdict,
    OreansFinalImportEvidence, OreansFinalRelocationBlockEvidence, OreansFinalRelocationEvidence,
    OreansFinalRelocationTargetEvidence, OreansGateRelocationEvidence, OreansIatEvidence,
    OreansIatReportEvidence, OreansIatSlotEvidence, OreansIsolatedReplay, OreansPrerequisites,
    OreansRelocationPreservationComparison, OreansReplayAttempt, OreansRuntimeRelocationEvidence,
    OreansRuntimeRelocationTargetEvidence, OreansRuntimeTlsCallbackEvidence,
    OreansRuntimeTlsEvidence, OreansSampleObservation, OreansTlsArtifactIdentity,
    OreansTlsEvidence, OreansTlsPreservationComparison, OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION,
    OREANS_ISOLATED_REPLAY_SCHEMA_VERSION, OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
    OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION,
};

use mida_acceptance::oreans_gate::{
    OreansOepArtifactIdentity, OreansOepEvidence, OreansOepSource,
    OreansSectionRebuildArtifactIdentity, OreansSectionRebuildDirectory,
    OreansSectionRebuildEvidence, OreansSectionRebuildSection, OREANS_OEP_EVIDENCE_SCHEMA_VERSION,
    OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION, OREANS_TWO_SAMPLE_OBSERVATIONS_SCHEMA_VERSION,
};

const BUNDLE_SCHEMA: &str = OREANS_TWO_SAMPLE_OBSERVATIONS_SCHEMA_VERSION;
const IMAGE_BASE64: u64 = 0x0000_0001_4000_0000;
const TEXT_RVA: u32 = 0x1000;
const TEXT_RAW: u32 = 0x200;
const DD_OFFSET64: usize = 0x108;
const RELOC_RAW: usize = 0x400;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mida-oreans-two-sample-gate-cli-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mida-acceptance"))
        .args(args)
        .output()
        .expect("spawn mida-acceptance")
}

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

fn evidence(summary: &str, candidate_sha256: &str) -> OreansEvidenceRef {
    OreansEvidenceRef {
        schema_version: OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION.to_string(),
        producer: "oreans-two-sample-gate-cli-test".to_string(),
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
            unresolved_reason_counts: mida_acceptance::OreansIatReasonCounts {
                by_reason: std::collections::BTreeMap::new(),
                pending_live_confirmation: 0,
            },
            slots: vec![
                OreansIatSlotEvidence {
                    slot_index: 0,
                    slot_address: 0x1800,
                    slot_rva: Some(0x1100),
                    observed_value: Some(0x7000),
                    rebuilt_value: Some(0x7000),
                    slot_value: Some(0x7000),
                    status: "Resolved".to_string(),
                    unresolved_reason: None,
                    module_name: Some("KERNEL32.DLL".to_string()),
                    function_name: Some("ExitProcess".to_string()),
                    ordinal: None,
                    resolution_source: Some("live".to_string()),
                },
                OreansIatSlotEvidence {
                    slot_index: 1,
                    slot_address: 0x1808,
                    slot_rva: Some(0x1108),
                    observed_value: Some(0),
                    rebuilt_value: None,
                    slot_value: Some(0),
                    status: "ZeroTerminator".to_string(),
                    unresolved_reason: None,
                    module_name: None,
                    function_name: None,
                    ordinal: None,
                    resolution_source: None,
                },
            ],
        }),
        final_imports: vec![OreansFinalImportEvidence {
            slot_rva: 0x1100,
            module_name: "kernel32.dll".to_string(),
            function_name: Some("ExitProcess".to_string()),
            ordinal: None,
        }],
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
    let detail = pe.tls_detail.as_ref().expect("synthetic TLS detail");
    let image_base = pe.image_base;
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
        runtime: OreansRuntimeTlsEvidence {
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
    OreansGateRelocationEvidence {
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
        runtime: OreansRuntimeRelocationEvidence {
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
        },
        final_candidate: OreansFinalRelocationEvidence {
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
        },
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
        simulation: OreansAslrSimulationEvidence {
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
        },
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
        va: Some(0x0000_0001_4000_1000),
        rva: Some(pe_evidence.entry_rva),
        final_entry_rva: pe_evidence.entry_rva,
        evidence: "synthetic trace reached the application OEP".to_string(),
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
    let absent = mida_acceptance::OreansPeDirectoryCoverage {
        rva: 0,
        size: 0,
        present: false,
        raw_backed: false,
        in_image: false,
    };
    let directories = (0..16)
        .map(|index| {
            let coverage = match index {
                3 if pe.exception.present => &pe.exception,
                5 => &pe.base_reloc,
                9 => &pe.tls,
                _ => &absent,
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
        prerequisites: prerequisites(true, &candidate.sha256),
        behavior_evidence: behavior(&candidate, &protected_input),
        isolated_replay: replay(&candidate),
    }
}

fn both_passing() -> Vec<OreansSampleObservation> {
    vec![
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

fn bundle(observations: &[OreansSampleObservation]) -> String {
    serde_json::json!({
        "schema_version": BUNDLE_SCHEMA,
        "observations": observations,
    })
    .to_string()
}

fn write_bundle(dir: &TestDir, name: &str, observations: &[OreansSampleObservation]) -> PathBuf {
    let path = dir.path().join(name);
    fs::write(&path, bundle(observations)).expect("write observations bundle");
    path
}

#[test]
fn bundle_schema_is_strict_and_unknown_fields_are_rejected() {
    let dir = TestDir::new();
    let path = dir.path().join("unknown.json");
    fs::write(
        &path,
        r#"{"schema_version":"mida.oreans-two-sample-observations/v2","observations":[],"extra":true}"#,
    )
    .expect("write unknown-field bundle");
    let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid Oreans observations bundle JSON"),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let wrong_schema = dir.path().join("wrong-schema.json");
    fs::write(
        &wrong_schema,
        r#"{"schema_version":"wrong/v1","observations":[]}"#,
    )
    .expect("write wrong-schema bundle");
    let output = run(&["oreans-two-sample-gate", wrong_schema.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("schema_version"));
}

#[test]
fn legacy_v1_observations_bundle_is_rejected() {
    let dir = TestDir::new();
    let path = write_bundle(&dir, "legacy-v1.json", &both_passing());
    let mut json: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read bundle")).expect("parse bundle");
    json["schema_version"] =
        serde_json::Value::String("mida.oreans-two-sample-observations/v2".to_string());
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json).expect("serialize legacy bundle"),
    )
    .expect("write legacy bundle");
    let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("schema_version"));
}

#[test]
fn missing_fixed_sample_is_semantic_exit_two() {
    let dir = TestDir::new();
    let cases = both_passing();
    let path = write_bundle(&dir, "missing.json", &cases[..1]);
    let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing required"));
}

#[test]
fn gto_and_holdout_cases_are_rejected_as_non_gate_inputs() {
    let dir = TestDir::new();
    for case_id in ["gto_launcher", "holdout"] {
        let mut cases = both_passing();
        cases[0].case_id = case_id.to_string();
        let path = write_bundle(&dir, &format!("{case_id}.json"), &cases);
        let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(2), "case={case_id} {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot form a report"),
            "case={case_id} stderr: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn two_passing_observations_emit_v8_closed_report_and_exit_zero() {
    let dir = TestDir::new();
    let cases = both_passing();
    let path = write_bundle(&dir, "passing.json", &cases);
    let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 report");
    assert!(stdout.starts_with("{\n"), "expected pretty JSON: {stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse gate report");
    assert_eq!(value["schema_version"], "mida.oreans-two-sample-gate/v8");
    assert_eq!(value["gate_id"], "oreans_two_sample_perfect_unpack");
    assert_eq!(value["final_verdict"], "closed");
    assert_eq!(value["samples"].as_array().unwrap().len(), 2);
}

#[test]
fn cli_rejects_legacy_v5_v7_and_generic_tls_relocation_fields() {
    let dir = TestDir::new();
    let path = write_bundle(&dir, "legacy.json", &both_passing());
    let mut json: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read bundle")).expect("parse bundle");
    json["schema_version"] =
        serde_json::Value::String("mida.oreans-two-sample-observations/v5".to_string());
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json).expect("serialize legacy schema"),
    )
    .expect("write legacy schema");
    let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("schema_version"));

    json["schema_version"] =
        serde_json::Value::String("mida.oreans-two-sample-gate/v7".to_string());
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json).expect("serialize old gate schema"),
    )
    .expect("write old gate schema");
    let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("schema_version"));

    json["schema_version"] = serde_json::Value::String(BUNDLE_SCHEMA.to_string());
    json["observations"][0]["prerequisites"]["tls_relocations_valid"] =
        serde_json::Value::Bool(true);
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json).expect("serialize old field"),
    )
    .expect("write old field");
    let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));
}

#[test]
fn false_prerequisite_emits_open_report_and_exit_two() {
    let dir = TestDir::new();
    let mut cases = both_passing();
    cases[0].prerequisites.survival = false;
    let path = write_bundle(&dir, "open.json", &cases);
    let output = run(&["oreans-two-sample-gate", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse open report");
    assert_eq!(value["final_verdict"], "open");
}

#[test]
fn report_same_path_is_rejected_without_modifying_input() {
    let dir = TestDir::new();
    let cases = both_passing();
    let path = write_bundle(&dir, "same.json", &cases);
    let original = fs::read(&path).expect("read original bundle");
    let output = run(&[
        "oreans-two-sample-gate",
        path.to_str().unwrap(),
        "--report",
        path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("aliases") && stderr.contains("observations bundle"));
    assert_eq!(fs::read(&path).expect("input preserved"), original);
}

#[test]
fn report_hard_link_alias_is_rejected_without_modifying_input() {
    let dir = TestDir::new();
    let cases = both_passing();
    let path = write_bundle(&dir, "input.json", &cases);
    let original = fs::read(&path).expect("read original bundle");
    let alias = dir.path().join("report-alias.json");
    fs::hard_link(&path, &alias).expect("create hard-link alias");
    let output = run(&[
        "oreans-two-sample-gate",
        path.to_str().unwrap(),
        "--report",
        alias.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("aliases") && stderr.contains("observations bundle"));
    assert_eq!(fs::read(&path).expect("input preserved"), original);
}
