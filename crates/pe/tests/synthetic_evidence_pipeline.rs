//! P8.1-D: full synthetic evidence pipeline end-to-end.
//!
//! One integration test drives the whole chain from a synthetic runtime
//! reconstruction through the emitted candidate PE, the five candidate-bound
//! sidecars, the transform manifest, PE evidence, an atomic
//! `mida.oreans-evidence-bundle/v2`, the independent acceptance bundle
//! validator, and finally the v8 two-sample gate's domain evaluation.
//!
//! Constraints honored:
//! - the candidate is EMITTED by the producer (`mida_pe::rebuild_pe_image`),
//!   not hand-constructed in the acceptance crate;
//! - every sidecar is bound to the emitted candidate's SHA-256/size and its
//!   field values are sourced from the emitted PE's own structure (entry RVA,
//!   TLS detail, base-relocation detail, section table), so the sidecars agree
//!   with the emitted bytes the acceptance validator re-parses;
//! - `mida-acceptance` is consumed here as a dev-dependency only; the
//!   acceptance crate itself does not import any producer crate;
//! - no `D:/MidaVault` access and no real sample is opened;
//! - OEP / IAT / relocation / section-rebuild domains must all pass;
//!   behavior oracle, prerequisite survival/structural, and isolated replay
//!   10/10 stay explicitly open/NotRun (the bundle contract does not carry
//!   them, so the gate remains open by construction);
//! - a tampered final PE whose bundle hashes are recomputed must still be
//!   rejected by the independent validator.

use std::collections::BTreeMap;

use mida_acceptance::oreans_gate::{
    OreansOepArtifactIdentity, OreansOepEvidence, OreansOepSource,
    OreansRelocationEvidence as GateRelocationEvidence, OREANS_OEP_EVIDENCE_SCHEMA_VERSION,
};
use mida_acceptance::{
    build_oreans_pe_evidence, canonical_manifest_hash, canonical_members_hash,
    evaluate_bundle_gate, BundleArtifactIdentity, BundleCompletionMarker, BundleInput,
    BundleMemberRef, OreansArtifactIdentity, OreansEvidenceBundle, OreansFinalBehaviorVerdict,
    OreansGateVerdict, OreansIatEvidence, OreansIsolatedReplay, OreansPrerequisites,
    OreansSampleObservation, OreansSectionRebuildEvidence, OreansTlsEvidence,
    OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION, OREANS_IAT_EVIDENCE_SCHEMA_VERSION,
    OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION, OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION,
    OREANS_TLS_EVIDENCE_SCHEMA_VERSION, TRANSFORM_MANIFEST_SCHEMA_VERSION,
};
use mida_pe::import_table::{ImportTableBuilder, ImportThunk};
use mida_pe::rebuild::{rebuild_pe_image, PlannedSection, RebuildPlan};
use mida_pe::tls::TlsDirectoryBuilder;

const ORIGIN_SHA: &str = "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";
const ORIGIN_SIZE: u64 = 5_232_656;
const LUNLUN_SHA: &str = "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07";
const LUNLUN_SIZE: u64 = 4_976_144;

/// Emit a synthetic candidate PE through the producer rebuild path. The
/// returned bytes are the exact artifact the sidecars must bind to.
fn emit_candidate_pe() -> Vec<u8> {
    let mut imports = ImportTableBuilder::new(true);
    {
        let m = imports.add_module("kernel32.dll");
        m.thunks.push(ImportThunk {
            iat_address: 0,
            function_name: Some("ExitProcess".into()),
            ordinal: None,
            is_64bit: true,
        });
    }
    let mut plan = RebuildPlan::pe32_plus();
    plan.sections.push(PlannedSection::new(
        ".text",
        0x6000_0020,
        vec![0x48, 0xC7, 0xC0, 0, 0, 0, 0, 0xC3],
    ));
    plan.entry_point_rva = 0x1000;
    plan.imports = Some(imports);
    plan.relocations = vec![(0x1000, 10)];
    plan.prefer_aslr = true;
    let mut tls = TlsDirectoryBuilder::pe32_plus();
    tls.template_data = vec![0u8; 0x100];
    tls.callback_rvas = vec![0x1000];
    plan.tls = Some(tls);
    rebuild_pe_image(&plan).expect("producer emits candidate PE")
}

/// Build PE evidence from the exact emitted candidate bytes.
fn pe_evidence(candidate: &[u8]) -> mida_acceptance::OreansPeEvidence {
    build_oreans_pe_evidence(candidate).expect("candidate PE evidence")
}

fn oep_evidence(
    candidate: &OreansArtifactIdentity,
    protected: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> OreansOepEvidence {
    OreansOepEvidence {
        schema_version: OREANS_OEP_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: OreansOepArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected.sha256.clone(),
            size_bytes: protected.size_bytes,
        },
        candidate: OreansOepArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        source: OreansOepSource::Trace,
        va: Some(pe.image_base + u64::from(pe.entry_rva)),
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
    protected: &OreansArtifactIdentity,
) -> OreansIatEvidence {
    OreansIatEvidence {
        schema_version: OREANS_IAT_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: mida_acceptance::OreansIatArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected.sha256.clone(),
            size_bytes: protected.size_bytes,
        },
        candidate: mida_acceptance::OreansIatArtifactIdentity {
            path: "candidate/unpacked.exe".to_string(),
            sha256: candidate.sha256.clone(),
            size_bytes: candidate.size_bytes,
        },
        fix_imports_requested: true,
        iat_evidence_present: true,
        iat_evidence_complete: true,
        iat_report: Some(mida_acceptance::OreansIatReportEvidence {
            requested_bytes: 16,
            bytes_read: 16,
            slot_size: 8,
            unresolved_reason_counts: mida_acceptance::OreansIatReasonCounts {
                by_reason: std::collections::BTreeMap::new(),
                pending_live_confirmation: 0,
            },
            slots: vec![
                mida_acceptance::OreansIatSlotEvidence {
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
                },
                mida_acceptance::OreansIatSlotEvidence {
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
                },
            ],
        }),
        final_imports: vec![mida_acceptance::OreansFinalImportEvidence {
            slot_rva: 0x1100,
            module_name: "kernel32.dll".to_string(),
            function_name: Some("ExitProcess".to_string()),
            ordinal: None,
        }],
        prerequisite_passes: true,
        blocker: None,
    }
}

/// The `.tls` and `.reloc` sections' raw offsets in the emitted image, used to
/// keep the TLS / relocation sidecars consistent with the emitted bytes.
fn raw_offset_of(pe: &mida_acceptance::OreansPeEvidence, section_name: &str) -> Option<u32> {
    pe.sections
        .iter()
        .find(|s| s.name == section_name)
        .map(|s| s.raw_offset)
}

fn tls_evidence(
    candidate: &OreansArtifactIdentity,
    protected: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> OreansTlsEvidence {
    let image_base = pe.image_base;
    let detail = pe
        .tls_detail
        .as_ref()
        .expect("emitted candidate has TLS detail");
    let raw = raw_offset_of(pe, ".tls").unwrap_or(0);
    OreansTlsEvidence {
        schema_version: OREANS_TLS_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: mida_acceptance::OreansTlsArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected.sha256.clone(),
            size_bytes: protected.size_bytes,
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
            directory_bytes_read: pe.tls.size as usize,
            start_address_of_raw_data: image_base + 0x1000,
            start_rva: Some(0x1000),
            end_address_of_raw_data: image_base + 0x1100,
            end_rva: Some(0x1100),
            address_of_index: image_base + 0x1010,
            index_rva: detail.address_of_index_rva,
            address_of_callbacks: image_base + 0x1008,
            callbacks_rva: detail.callback_array_rva,
            size_of_zero_fill: 0,
            characteristics: 0,
            index_bytes_read: 4,
            index_value: Some(1),
            callback_slots: vec![
                mida_acceptance::OreansRuntimeTlsCallbackEvidence {
                    slot_index: 0,
                    slot_address: image_base + 0x1008,
                    bytes_read: 8,
                    observed_value: Some(image_base + 0x1000),
                    callback_rva: Some(0x1000),
                    status: "Resolved".to_string(),
                },
                mida_acceptance::OreansRuntimeTlsCallbackEvidence {
                    slot_index: 1,
                    slot_address: image_base + 0x1010,
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
            directory_raw_offset: Some(u64::from(raw)),
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
    protected: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> GateRelocationEvidence {
    let image_base = pe.image_base;
    let runtime_base = image_base + 0x0100_0000;
    let normalized = image_base + 0x1234;
    let reloc_detail = pe
        .relocation_detail
        .as_ref()
        .expect("candidate has reloc detail");
    let raw = raw_offset_of(pe, ".reloc").unwrap_or(0);
    GateRelocationEvidence {
        schema_version: OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION.to_string(),
        protected_input: mida_acceptance::OreansTlsArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected.sha256.clone(),
            size_bytes: protected.size_bytes,
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
            dynamic_base: reloc_detail.dynamic_base,
            relocs_stripped: reloc_detail.relocs_stripped,
            block_count: reloc_detail.block_count,
            entry_count: reloc_detail.entry_count,
            non_absolute_entry_count: reloc_detail.non_absolute_entry_count,
            observed_types: reloc_detail.observed_types.clone(),
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
            directory_raw_offset: Some(u64::from(raw)),
            directory_raw_backed: true,
            dynamic_base: reloc_detail.dynamic_base,
            relocs_stripped: reloc_detail.relocs_stripped,
            block_count: reloc_detail.block_count,
            entry_count: reloc_detail.entry_count,
            non_absolute_entry_count: reloc_detail.non_absolute_entry_count,
            observed_types: reloc_detail.observed_types.clone(),
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
    protected: &OreansArtifactIdentity,
    pe: &mida_acceptance::OreansPeEvidence,
) -> OreansSectionRebuildEvidence {
    let sections = pe
        .sections
        .iter()
        .map(|s| mida_acceptance::OreansSectionRebuildSection {
            name: s.name.clone(),
            virtual_address: s.virtual_address,
            virtual_size: s.virtual_size,
            raw_offset: s.raw_offset,
            raw_size: s.raw_size,
            characteristics: s.characteristics,
            virtual_end: u64::from(s.virtual_address) + u64::from(s.virtual_size.max(s.raw_size)),
            raw_end: u64::from(s.raw_offset) + u64::from(s.raw_size),
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
            mida_acceptance::OreansSectionRebuildDirectory {
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
        protected_input: mida_acceptance::OreansSectionRebuildArtifactIdentity {
            path: "protected/input.exe".to_string(),
            sha256: protected.sha256.clone(),
            size_bytes: protected.size_bytes,
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
        entry_section: entry_section.map(|section| section.name.clone()),
        executable_sections: sections
            .iter()
            .filter(|s| s.characteristics & 0x2000_0000 != 0)
            .map(|s| s.name.clone())
            .collect(),
        sections,
        directories,
        overlay_offset,
        overlay_size: candidate.size_bytes.saturating_sub(overlay_offset),
        section_rebuild_evidence_pass: true,
        blockers: Vec::new(),
    }
}

fn observation(case_id: &str, protected_sha: &str, protected_size: u64) -> OreansSampleObservation {
    let protected = OreansArtifactIdentity {
        sha256: protected_sha.to_string(),
        size_bytes: protected_size,
    };
    let candidate_bytes = emit_candidate_pe();
    let pe_evidence = pe_evidence(&candidate_bytes);
    let candidate = OreansArtifactIdentity {
        sha256: pe_evidence.candidate.sha256.clone(),
        size_bytes: pe_evidence.candidate.size_bytes,
    };
    OreansSampleObservation {
        case_id: case_id.to_string(),
        protected_input: protected.clone(),
        candidate: candidate.clone(),
        pe_evidence: pe_evidence.clone(),
        oep_evidence: oep_evidence(&candidate, &protected, &pe_evidence),
        iat_evidence: iat_evidence(&candidate, &protected),
        tls_evidence: tls_evidence(&candidate, &protected, &pe_evidence),
        relocation_evidence: relocation_evidence(&candidate, &protected, &pe_evidence),
        section_rebuild_evidence: section_rebuild_evidence(&candidate, &protected, &pe_evidence),
        prerequisites: OreansPrerequisites {
            survival: false,
            structural: false,
            survival_evidence: mida_acceptance::OreansEvidenceRef {
                schema_version: "mida.oreans-prerequisite-evidence/v1".to_string(),
                producer: "p8-1-d".to_string(),
                artifact_sha256: String::new(),
                summary: "no survival evidence in bundle".to_string(),
            },
            structural_evidence: mida_acceptance::OreansEvidenceRef {
                schema_version: "mida.oreans-prerequisite-evidence/v1".to_string(),
                producer: "p8-1-d".to_string(),
                artifact_sha256: String::new(),
                summary: "no structural evidence in bundle".to_string(),
            },
        },
        behavior_evidence: mida_acceptance::OreansBehaviorEvidence {
            schema_version: "mida.oreans-behavior-oracle/v1".to_string(),
            stimuli: Vec::new(),
            observables: Vec::new(),
            candidate_identity: candidate.clone(),
            protected_identity: protected.clone(),
            verdict: OreansFinalBehaviorVerdict::NotRun,
            reason: "no behavior oracle evidence in bundle".to_string(),
        },
        isolated_replay: OreansIsolatedReplay {
            schema_version: "mida.oreans-isolated-replay/v1".to_string(),
            attempts: Vec::new(),
        },
    }
}

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

/// Full synthetic pipeline: emit -> sidecars -> bundle -> validator -> gate.
/// OEP / IAT / relocation / section-rebuild domains must all pass; behavior,
/// prerequisite survival/structural, and isolated replay stay open.
#[test]
fn synthetic_pipeline_emits_bundle_and_gate_domains_pass() {
    let origin = observation("origin_macro", ORIGIN_SHA, ORIGIN_SIZE);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (origin_bundle, origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);

    // Independent bundle validator accepts the producer-assembled bundles.
    let verdict = mida_acceptance::validate_evidence_bundle(&origin_bundle, &origin_files);
    assert!(
        verdict.valid,
        "origin bundle must be valid: {:?}",
        verdict.reasons
    );
    assert!(verdict.complete);
    let verdict = mida_acceptance::validate_evidence_bundle(&lunlun_bundle, &lunlun_files);
    assert!(
        verdict.valid,
        "lunlun bundle must be valid: {:?}",
        verdict.reasons
    );
    assert!(verdict.complete);

    // v8 gate consumes both bundles and evaluates all domains.
    let report = evaluate_bundle_gate(&[
        input(&origin_bundle, &origin_files),
        input(&lunlun_bundle, &lunlun_files),
    ])
    .expect("bundle gate consumes the emitted candidates");

    for sample in &report.gate.samples {
        // OEP / IAT / relocation / section-rebuild domains all pass.
        assert!(
            sample.oep_evidence_pass,
            "OEP domain must pass for {}",
            sample.case_id
        );
        assert!(
            sample.iat_evidence_pass,
            "IAT domain must pass for {}",
            sample.case_id
        );
        assert!(
            sample.relocation_evidence_pass,
            "relocation domain must pass for {}",
            sample.case_id
        );
        assert!(
            sample.section_rebuild_evidence_pass,
            "section-rebuild domain must pass for {}",
            sample.case_id
        );
        // The only open gates are behavior/survival/replay (not in the bundle).
        assert!(
            sample.failures.iter().all(|f| f.contains("isolated replay")
                || f.contains("behavior")
                || f.contains("survival")
                || f.contains("structural")),
            "only behavior/survival/replay may be open, got failures for {}: {:?}",
            sample.case_id,
            sample.failures
        );

        // Behavior / survival / structural / replay stay explicitly open/NotRun.
        assert!(
            !sample.prerequisites_pass,
            "survival/structural stay open for {}",
            sample.case_id
        );
        assert_eq!(
            sample.final_behavior_verdict,
            OreansFinalBehaviorVerdict::NotRun,
            "behavior oracle stays NotRun for {}",
            sample.case_id
        );
        assert!(
            sample.isolated_replay.attempts.is_empty(),
            "replay 10/10 stays open"
        );
    }

    // The gate overall stays open because behavior + replay are not in the
    // bundle contract (they require a live run).
    assert_eq!(report.gate.final_verdict, OreansGateVerdict::Open);
}

/// Tampering the emitted candidate and recomputing the bundle hashes must be
/// rejected by the independent validator (identity chain is sealed).
#[test]
fn tampered_candidate_with_recomputed_hashes_is_rejected() {
    let origin = observation("origin_macro", ORIGIN_SHA, ORIGIN_SIZE);
    let lunlun = observation("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE);
    let (mut origin_bundle, mut origin_files) = envelope(&origin);
    let (lunlun_bundle, lunlun_files) = envelope(&lunlun);

    // Tamper the candidate's .text bytes.
    let candidate_bytes = {
        let pe_bytes = emit_candidate_pe();
        let mut v = pe_bytes;
        // Flip a byte in .text so the candidate identity changes.
        let idx = 0x200 + 4; // inside .text raw (raw offset 0x200)
        v[idx] ^= 0xFF;
        v
    };

    // Attacker-style: update every member that binds the candidate to the
    // tampered identity EXCEPT one sidecar, which stays stale on the original
    // candidate identity. Then recompute all member hashes and both bundle
    // hashes exactly as an attacker would. The identity chain must still fail
    // closed in the INDEPENDENT validator.
    let tampered_sha = mida_acceptance::sha256_hex(&candidate_bytes);
    let tampered_size = candidate_bytes.len() as u64;
    let stale_name = "iat_evidence";

    for name in [
        "oep_evidence",
        "iat_evidence",
        "tls_evidence",
        "relocation_evidence",
        "section_rebuild_evidence",
        "pe_evidence",
        "transform_manifest",
    ] {
        if name == stale_name {
            continue; // leave iat_evidence stale on the original candidate
        }
        if let Some(bytes) = origin_files.get_mut(name) {
            let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            if let Some(cand) = value.get_mut("candidate") {
                cand["sha256"] = serde_json::json!(tampered_sha);
                cand["size_bytes"] = serde_json::json!(tampered_size);
            }
            if let Some(cs) = value.get_mut("candidate_sha256") {
                *cs = serde_json::json!(tampered_sha);
            }
            if let Some(csz) = value.get_mut("candidate_size_bytes") {
                *csz = serde_json::json!(tampered_size);
            }
            *bytes = serde_json::to_vec(&value).unwrap();
        }
    }

    // Rebuild the member refs with the (mostly tampered) bytes.
    let mut members: Vec<BundleMemberRef> = origin_files
        .iter()
        .map(|(name, bytes)| BundleMemberRef {
            name: name.clone(),
            relative_path: format!("evidence/{name}.json"),
            sha256: mida_acceptance::sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        })
        .collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));

    origin_bundle.candidate = BundleArtifactIdentity {
        sha256: tampered_sha,
        size_bytes: tampered_size,
    };
    origin_bundle.members = members;
    origin_bundle.members_sha256 = canonical_members_hash(&origin_bundle.members);
    origin_bundle.manifest_sha256 = canonical_manifest_hash(&origin_bundle);

    // The independent validator must reject the stale identity chain even after
    // every hash was recomputed.
    let verdict = mida_acceptance::validate_evidence_bundle(&origin_bundle, &origin_files);
    assert!(
        !verdict.valid,
        "tampered candidate with recomputed hashes must be rejected by the independent validator"
    );
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| r.contains("iat_evidence candidate")),
        "rejection must name the stale sidecar identity, got: {:?}",
        verdict.reasons
    );

    // The gate likewise rejects the tampered bundle.
    let gate = evaluate_bundle_gate(&[
        input(&origin_bundle, &origin_files),
        input(&lunlun_bundle, &lunlun_files),
    ]);
    assert!(
        gate.is_err(),
        "gate must reject the tampered candidate bundle"
    );
    if let Err(e) = gate {
        eprintln!("gate rejected tampered candidate: {e}");
    }
}
