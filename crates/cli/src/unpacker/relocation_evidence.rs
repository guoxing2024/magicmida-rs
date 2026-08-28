//! Candidate-bound relocation and ASLR evidence.

//! Production `.unwrap()`s are invariants: read_u16/read_u32 follow explicit
//! boundary breaks, `i64::try_from(0x100000)` on a constant, and
//! `file_name()` on a constructed temp path (WO-10). Test unwraps are
//! ordinary assertions.
#![allow(clippy::unwrap_used)]
//!
//! Runtime facts come only from the immutable dump report. Final facts are
//! independently rebuilt from the candidate bytes re-read from disk.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use mida_pe::{PeHeader, RelocationObservationReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RELOC_DIRECTORY_INDEX: usize = 5;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;

use super::evidence_schema::ArtifactIdentity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeRelocationTargetEvidence {
    pub block_index: u32,
    pub entry_index: u32,
    pub page_rva: u32,
    pub target_rva: u32,
    pub relocation_type: u8,
    pub bytes_read: usize,
    pub runtime_value: Option<u64>,
    pub normalized_value: Option<u64>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeRelocationEvidence {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub runtime_image_base: u64,
    pub preferred_image_base: u64,
    pub size_of_image: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_bytes_read: usize,
    pub dynamic_base: bool,
    pub relocs_stripped: bool,
    pub block_count: u32,
    pub entry_count: u32,
    pub non_absolute_entry_count: u32,
    pub observed_types: Vec<u8>,
    pub targets: Vec<RuntimeRelocationTargetEvidence>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalRelocationBlockEvidence {
    pub block_index: u32,
    pub page_rva: u32,
    pub block_size: u32,
    pub entry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalRelocationTargetEvidence {
    pub block_index: u32,
    pub entry_index: u32,
    pub target_rva: u32,
    pub relocation_type: u8,
    pub raw_offset: Option<u64>,
    pub raw_backed: bool,
    pub stored_value: Option<u64>,
    pub normalized_value: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalRelocationEvidence {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub image_base: u64,
    pub size_of_image: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_raw_offset: Option<u64>,
    pub directory_raw_backed: bool,
    pub dynamic_base: bool,
    pub relocs_stripped: bool,
    pub block_count: u32,
    pub entry_count: u32,
    pub non_absolute_entry_count: u32,
    pub observed_types: Vec<u8>,
    pub blocks: Vec<FinalRelocationBlockEvidence>,
    pub targets: Vec<FinalRelocationTargetEvidence>,
    pub all_targets_raw_backed: bool,
    pub has_non_absolute_entry: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelocationPreservationComparison {
    pub pe_kind_preserved: bool,
    pub pointer_size_preserved: bool,
    pub relocation_presence_preserved: bool,
    pub directory_raw_backed: bool,
    pub target_set_preserved: bool,
    pub normalized_values_preserved: bool,
    pub dynamic_base_preserved: bool,
    pub relocs_stripped_preserved: bool,
    pub all_preserved: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AslrSimulationCase {
    pub new_image_base: u64,
    pub delta: i64,
    pub target_count: u32,
    pub passed: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AslrSimulationEvidence {
    pub pure_delta: bool,
    pub covers_positive_delta: bool,
    pub covers_negative_delta: bool,
    pub normalized_values_used: bool,
    pub cases: Vec<AslrSimulationCase>,
    pub all_passed: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RelocationEvidenceSidecar {
    pub schema_version: String,
    pub protected_input: ArtifactIdentity,
    pub candidate: ArtifactIdentity,
    pub runtime: RuntimeRelocationEvidence,
    pub final_candidate: FinalRelocationEvidence,
    pub preservation: RelocationPreservationComparison,
    pub simulation: AslrSimulationEvidence,
    pub reported_relocation_evidence_present: bool,
    pub reported_relocation_evidence_complete: bool,
    pub runtime_evidence_present: bool,
    pub runtime_evidence_complete: bool,
    pub prerequisite_passes: bool,
    pub blockers: Vec<String>,
}

pub(crate) fn write_relocation_evidence(
    protected_input: &Path,
    candidate: &Path,
    report: &mida_pe::DumpProcessReport,
    family: &str,
) -> anyhow::Result<PathBuf> {
    let sidecar = sidecar_path(candidate)?;
    let value = build_relocation_evidence(protected_input, candidate, report, family)?;
    ensure_sidecar_is_safe(&sidecar, protected_input, candidate)?;
    let json =
        serde_json::to_vec_pretty(&value).context("serialize relocation evidence sidecar")?;
    atomic_write(&sidecar, &json)?;
    Ok(sidecar)
}

pub(crate) fn build_relocation_evidence(
    protected_input: &Path,
    candidate: &Path,
    report: &mida_pe::DumpProcessReport,
    family: &str,
) -> anyhow::Result<RelocationEvidenceSidecar> {
    let schema_version = super::evidence_schema::member_schema_for_family(
        family,
        super::evidence_schema::EvidenceMemberKind::Relocation,
    )
    .map_err(anyhow::Error::msg)?
    .to_string();
    if same_file(protected_input, candidate)? {
        return Err(anyhow!("protected input and candidate are the same file"));
    }
    let (_, protected_identity) = read_artifact(protected_input)
        .with_context(|| format!("read protected input: {}", protected_input.display()))?;
    let (candidate_bytes, candidate_identity) = read_artifact(candidate)
        .with_context(|| format!("read candidate: {}", candidate.display()))?;

    let runtime = runtime_to_evidence(&report.relocation_report);
    let final_candidate = parse_final_candidate(&candidate_bytes)?;
    let preservation = compare_runtime_final(&report.relocation_report, &final_candidate);
    let simulation = simulate_aslr(&final_candidate);
    let mut blockers = Vec::new();
    if report.relocation_evidence_present != report.relocation_report.directory_present {
        blockers.push("relocation_evidence_present disagrees with relocation_report".to_string());
    }
    if report.relocation_evidence_complete != report.relocation_report.is_complete() {
        blockers.push("relocation_evidence_complete disagrees with relocation_report".to_string());
    }
    if report.output_size != candidate_bytes.len() {
        blockers.push(format!(
            "dump report output_size {} disagrees with candidate disk size {}",
            report.output_size,
            candidate_bytes.len()
        ));
    }
    blockers.extend(
        runtime
            .blockers
            .iter()
            .map(|item| format!("runtime: {item}")),
    );
    blockers.extend(
        final_candidate
            .blockers
            .iter()
            .map(|item| format!("final: {item}")),
    );
    blockers.extend(
        preservation
            .blockers
            .iter()
            .map(|item| format!("preservation: {item}")),
    );
    blockers.extend(
        simulation
            .blockers
            .iter()
            .map(|item| format!("simulation: {item}")),
    );
    stable_blockers(&mut blockers);
    let prerequisite_passes = blockers.is_empty()
        && preservation.all_preserved
        && simulation.all_passed
        && final_candidate.directory_raw_backed
        && final_candidate.all_targets_raw_backed
        && final_candidate.has_non_absolute_entry;

    Ok(RelocationEvidenceSidecar {
        schema_version: schema_version.clone(),
        protected_input: protected_identity,
        candidate: candidate_identity,
        runtime: runtime.clone(),
        final_candidate: final_candidate.clone(),
        preservation: preservation.clone(),
        simulation: simulation.clone(),
        reported_relocation_evidence_present: report.relocation_evidence_present,
        reported_relocation_evidence_complete: report.relocation_evidence_complete,
        runtime_evidence_present: runtime.directory_present,
        runtime_evidence_complete: runtime.blockers.is_empty(),
        prerequisite_passes,
        blockers,
    })
}

fn runtime_to_evidence(report: &RelocationObservationReport) -> RuntimeRelocationEvidence {
    RuntimeRelocationEvidence {
        directory_present: report.directory_present,
        pe32_plus: report.pe32_plus,
        pointer_size: report.pointer_size,
        runtime_image_base: report.runtime_image_base,
        preferred_image_base: report.preferred_image_base,
        size_of_image: report.size_of_image,
        directory_rva: report.directory_rva,
        directory_size: report.directory_size,
        directory_bytes_read: report.directory_bytes_read,
        dynamic_base: report.dynamic_base,
        relocs_stripped: report.relocs_stripped,
        block_count: report.block_count,
        entry_count: report.entry_count,
        non_absolute_entry_count: report.non_absolute_entry_count,
        observed_types: report.observed_types.clone(),
        targets: report
            .targets
            .iter()
            .map(|target| RuntimeRelocationTargetEvidence {
                block_index: target.block_index,
                entry_index: target.entry_index,
                page_rva: target.page_rva,
                target_rva: target.target_rva,
                relocation_type: target.relocation_type,
                bytes_read: target.bytes_read,
                runtime_value: target.runtime_value,
                normalized_value: target.normalized_value,
                status: target.status.to_string(),
            })
            .collect(),
        blockers: report.blockers.clone(),
    }
}

fn parse_final_candidate(bytes: &[u8]) -> anyhow::Result<FinalRelocationEvidence> {
    let pe = PeHeader::from_bytes(bytes).map_err(|error| anyhow!("parse candidate PE: {error}"))?;
    let directory = pe.nt_headers.optional_header.data_directory[RELOC_DIRECTORY_INDEX];
    let directory_present = directory.virtual_address != 0 || directory.size != 0;
    let mut evidence = FinalRelocationEvidence {
        directory_present,
        pe32_plus: pe.is_64bit,
        pointer_size: if pe.is_64bit { 8 } else { 4 },
        image_base: pe.image_base,
        size_of_image: pe.size_of_image(),
        directory_rva: directory.virtual_address,
        directory_size: directory.size,
        directory_raw_offset: None,
        directory_raw_backed: false,
        dynamic_base: (pe.nt_headers.optional_header.dll_characteristics
            & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
            != 0,
        relocs_stripped: (pe.nt_headers.file_header.characteristics & IMAGE_FILE_RELOCS_STRIPPED)
            != 0,
        block_count: 0,
        entry_count: 0,
        non_absolute_entry_count: 0,
        observed_types: Vec::new(),
        blocks: Vec::new(),
        targets: Vec::new(),
        all_targets_raw_backed: true,
        has_non_absolute_entry: false,
        blockers: Vec::new(),
    };
    if !directory_present {
        evidence
            .blockers
            .push("base relocation directory is absent".to_string());
        return Ok(evidence);
    }
    if (directory.virtual_address == 0) != (directory.size == 0) {
        evidence
            .blockers
            .push("base relocation data-directory tuple is partial".to_string());
        return Ok(evidence);
    }
    if directory.size < 8 {
        evidence
            .blockers
            .push("base relocation directory is shorter than one block header".to_string());
        return Ok(evidence);
    }
    let Some(directory_offset) = raw_span(&pe, bytes, directory.virtual_address, directory.size)
    else {
        evidence
            .blockers
            .push("base relocation directory is not fully raw-backed".to_string());
        return Ok(evidence);
    };
    evidence.directory_raw_offset = Some(directory_offset as u64);
    evidence.directory_raw_backed = true;
    let directory_end = directory_offset
        .checked_add(directory.size as usize)
        .ok_or_else(|| anyhow!("base relocation directory offset overflow"))?;
    let directory_bytes = bytes
        .get(directory_offset..directory_end)
        .ok_or_else(|| anyhow!("base relocation directory exceeds candidate bytes"))?;
    let relocation_type = if pe.is_64bit { 10u8 } else { 3u8 };
    let width = evidence.pointer_size as u32;
    let mut cursor = 0usize;
    while cursor < directory_bytes.len() {
        let remaining = directory_bytes.len() - cursor;
        if remaining < 8 {
            evidence
                .blockers
                .push("base relocation directory has a partial block header".to_string());
            break;
        }
        let page_rva = read_u32(directory_bytes, cursor).unwrap();
        let block_size = read_u32(directory_bytes, cursor + 4).unwrap();
        if block_size < 8 || !block_size.is_multiple_of(2) || block_size as usize > remaining {
            evidence
                .blockers
                .push(format!("invalid base relocation block size {block_size}"));
            break;
        }
        if page_rva >= evidence.size_of_image || !page_rva.is_multiple_of(0x1000) {
            evidence
                .blockers
                .push(format!("invalid base relocation page RVA {page_rva:#x}"));
            break;
        }
        let block_index = evidence.block_count;
        let block_entry_count = (block_size - 8) / 2;
        evidence.block_count += 1;
        evidence.entry_count = evidence.entry_count.saturating_add(block_entry_count);
        evidence.blocks.push(FinalRelocationBlockEvidence {
            block_index,
            page_rva,
            block_size,
            entry_count: block_entry_count,
        });
        let block_rva = directory.virtual_address.checked_add(cursor as u32);
        if block_rva
            .and_then(|block_rva| raw_span(&pe, bytes, block_rva, block_size))
            .is_none()
        {
            evidence
                .blockers
                .push(format!("relocation block {block_index} is not raw-backed"));
        }
        for entry_index in 0..block_entry_count {
            let word_offset = cursor + 8 + entry_index as usize * 2;
            let word = read_u16(directory_bytes, word_offset).unwrap();
            let kind = (word >> 12) as u8;
            if !evidence.observed_types.contains(&kind) {
                evidence.observed_types.push(kind);
            }
            if kind == 0 {
                continue;
            }
            evidence.has_non_absolute_entry = true;
            evidence.non_absolute_entry_count = evidence.non_absolute_entry_count.saturating_add(1);
            let Some(target_rva) = page_rva.checked_add(u32::from(word & 0x0fff)) else {
                evidence
                    .blockers
                    .push("relocation target RVA overflow".to_string());
                continue;
            };
            let raw_offset = raw_span(&pe, bytes, target_rva, width).map(|value| value as u64);
            let raw_backed = raw_offset.is_some();
            if !raw_backed {
                evidence.all_targets_raw_backed = false;
                evidence.blockers.push(format!(
                    "relocation target {target_rva:#x} is not raw-backed"
                ));
            }
            let stored_value = raw_offset.and_then(|offset| {
                let offset = usize::try_from(offset).ok()?;
                if pe.is_64bit {
                    read_u64(bytes, offset)
                } else {
                    read_u32(bytes, offset).map(u64::from)
                }
            });
            let normalized_value = stored_value.filter(|value| {
                value
                    .checked_sub(evidence.image_base)
                    .is_some_and(|delta| delta < u64::from(evidence.size_of_image))
            });
            if kind != relocation_type {
                evidence.blockers.push(format!(
                    "relocation type {kind} is invalid for this architecture"
                ));
            }
            if normalized_value.is_none() {
                evidence.blockers.push(format!(
                    "relocation target {target_rva:#x} value is not a normalized image VA"
                ));
            }
            evidence.targets.push(FinalRelocationTargetEvidence {
                block_index,
                entry_index,
                target_rva,
                relocation_type: kind,
                raw_offset,
                raw_backed,
                stored_value,
                normalized_value,
            });
        }
        cursor += block_size as usize;
    }
    evidence.observed_types.sort_unstable();
    evidence.observed_types.dedup();
    stable_blockers(&mut evidence.blockers);
    if evidence.non_absolute_entry_count == 0 {
        evidence
            .blockers
            .push("base relocation directory has no non-ABSOLUTE entry".to_string());
    }
    Ok(evidence)
}

fn compare_runtime_final(
    runtime: &RelocationObservationReport,
    final_candidate: &FinalRelocationEvidence,
) -> RelocationPreservationComparison {
    let mut blockers = Vec::new();
    let pe_kind_preserved = runtime.pe32_plus == final_candidate.pe32_plus;
    let pointer_size_preserved = runtime.pointer_size == final_candidate.pointer_size;
    let relocation_presence_preserved =
        runtime.directory_present && final_candidate.directory_present;
    let directory_raw_backed = final_candidate.directory_raw_backed;
    let dynamic_base_preserved = runtime.dynamic_base == final_candidate.dynamic_base;
    let relocs_stripped_preserved = runtime.relocs_stripped == final_candidate.relocs_stripped;
    let target_set_preserved = runtime.targets.len() == final_candidate.targets.len()
        && runtime
            .targets
            .iter()
            .zip(&final_candidate.targets)
            .all(|(left, right)| {
                left.block_index == right.block_index
                    && left.entry_index == right.entry_index
                    && left.target_rva == right.target_rva
                    && left.relocation_type == right.relocation_type
            });
    let normalized_values_preserved = runtime.targets.len() == final_candidate.targets.len()
        && runtime
            .targets
            .iter()
            .zip(&final_candidate.targets)
            .all(|(left, right)| {
                left.normalized_value.is_some() && left.normalized_value == right.normalized_value
            });
    for (name, passed) in [
        ("PE kind", pe_kind_preserved),
        ("pointer size", pointer_size_preserved),
        ("relocation presence", relocation_presence_preserved),
        ("directory raw backing", directory_raw_backed),
        ("relocation target set", target_set_preserved),
        ("normalized relocation values", normalized_values_preserved),
        ("DYNAMIC_BASE", dynamic_base_preserved),
        ("RELOCS_STRIPPED", relocs_stripped_preserved),
        (
            "all final relocation targets raw-backed",
            final_candidate.all_targets_raw_backed,
        ),
    ] {
        if !passed {
            blockers.push(format!("{name} was not preserved"));
        }
    }
    // P8-E: the gate recomputes preservation independently and requires the
    // blocker lists to be sorted and deduplicated. Sort here so the sidecar's
    // preservation matches the gate's recomputation field-for-field.
    stable_blockers(&mut blockers);
    let all_preserved = blockers.is_empty();
    RelocationPreservationComparison {
        pe_kind_preserved,
        pointer_size_preserved,
        relocation_presence_preserved,
        directory_raw_backed,
        target_set_preserved,
        normalized_values_preserved,
        dynamic_base_preserved,
        relocs_stripped_preserved,
        all_preserved,
        blockers,
    }
}

fn simulate_aslr(final_candidate: &FinalRelocationEvidence) -> AslrSimulationEvidence {
    let mut blockers = Vec::new();
    let preferred = final_candidate.image_base;
    let delta = 0x100000u64;
    let mut cases = Vec::new();
    let mut new_bases = Vec::new();
    if let Some(base) = preferred.checked_add(delta) {
        new_bases.push((base, i64::try_from(delta).unwrap()));
    } else {
        blockers.push("positive ASLR base overflows".to_string());
    }
    if let Some(base) = preferred.checked_sub(delta) {
        new_bases.push((base, -i64::try_from(delta).unwrap()));
    } else {
        blockers.push("negative ASLR base underflows".to_string());
    }
    for (new_base, signed_delta) in new_bases {
        let mut case_blockers = Vec::new();
        if new_base == preferred {
            case_blockers.push("simulated base is not different from preferred base".to_string());
        }
        if !final_candidate.pe32_plus
            && new_base
                .checked_add(u64::from(final_candidate.size_of_image))
                .is_none()
        {
            case_blockers.push("PE32 simulated image range overflows".to_string());
        }
        for target in &final_candidate.targets {
            let Some(normalized) = target.normalized_value else {
                case_blockers.push(format!(
                    "target {:#x} lacks normalized value",
                    target.target_rva
                ));
                continue;
            };
            let simulated = if signed_delta >= 0 {
                normalized.checked_add(signed_delta as u64)
            } else {
                normalized.checked_sub(signed_delta.unsigned_abs())
            };
            let Some(simulated) = simulated else {
                case_blockers.push(format!(
                    "target {:#x} delta arithmetic overflow",
                    target.target_rva
                ));
                continue;
            };
            if !final_candidate.pe32_plus && simulated > u64::from(u32::MAX) {
                case_blockers.push(format!(
                    "target {:#x} exceeds PE32 value width",
                    target.target_rva
                ));
                continue;
            }
            let de_relocated = if signed_delta >= 0 {
                simulated.checked_sub(signed_delta as u64)
            } else {
                simulated.checked_add(signed_delta.unsigned_abs())
            };
            if de_relocated != Some(normalized) {
                case_blockers.push(format!(
                    "target {:#x} failed pure delta round-trip",
                    target.target_rva
                ));
            }
        }
        cases.push(AslrSimulationCase {
            new_image_base: new_base,
            delta: signed_delta,
            target_count: final_candidate.targets.len() as u32,
            passed: case_blockers.is_empty(),
            blockers: case_blockers,
        });
    }
    let covers_positive_delta = cases.iter().any(|case| case.delta > 0);
    let covers_negative_delta = cases.iter().any(|case| case.delta < 0);
    let normalized_values_used = !final_candidate.targets.is_empty()
        && final_candidate
            .targets
            .iter()
            .all(|target| target.normalized_value.is_some());
    let all_passed = cases.len() >= 2
        && covers_positive_delta
        && covers_negative_delta
        && normalized_values_used
        && cases.iter().all(|case| case.passed);
    if !covers_positive_delta {
        blockers.push("ASLR simulation lacks a positive delta".to_string());
    }
    if !covers_negative_delta {
        blockers.push("ASLR simulation lacks a negative delta".to_string());
    }
    if !normalized_values_used {
        blockers.push("ASLR simulation did not use normalized values".to_string());
    }
    AslrSimulationEvidence {
        pure_delta: true,
        covers_positive_delta,
        covers_negative_delta,
        normalized_values_used,
        cases,
        all_passed,
        blockers,
    }
}

fn raw_span(pe: &PeHeader, bytes: &[u8], rva: u32, size: u32) -> Option<usize> {
    let end = rva.checked_add(size)?;
    if end <= pe.nt_headers.optional_header.size_of_headers {
        let end = usize::try_from(end).ok()?;
        return (end <= bytes.len()).then_some(rva as usize);
    }
    pe.sections.iter().find_map(|section| {
        let raw_end = section.virtual_address.checked_add(section.raw_size)?;
        if rva < section.virtual_address || end > raw_end || section.raw_size == 0 {
            return None;
        }
        let offset = section
            .raw_offset
            .checked_add(rva - section.virtual_address)? as usize;
        let end = offset.checked_add(size as usize)?;
        (end <= bytes.len()).then_some(offset)
    })
}

fn read_artifact(path: &Path) -> anyhow::Result<(Vec<u8>, ArtifactIdentity)> {
    let bytes = fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    let size_bytes = bytes.len() as u64;
    let sha256 = format!("{:064x}", Sha256::digest(&bytes));
    Ok((
        bytes,
        ArtifactIdentity {
            path: path.to_string_lossy().into_owned(),
            sha256,
            size_bytes,
        },
    ))
}

fn sidecar_path(candidate: &Path) -> anyhow::Result<PathBuf> {
    let name = candidate
        .file_name()
        .ok_or_else(|| anyhow!("candidate path has no file name"))?;
    let mut sidecar = name.to_os_string();
    sidecar.push(".relocation_evidence.json");
    Ok(candidate.with_file_name(sidecar))
}

fn ensure_sidecar_is_safe(
    sidecar: &Path,
    protected_input: &Path,
    candidate: &Path,
) -> anyhow::Result<()> {
    if sidecar.exists() && (same_file(sidecar, protected_input)? || same_file(sidecar, candidate)?)
    {
        return Err(anyhow!("relocation sidecar aliases a source artifact"));
    }
    if sidecar.is_dir() {
        return Err(anyhow!("relocation sidecar destination is a directory"));
    }
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> anyhow::Result<bool> {
    if fs::canonicalize(left).ok() == fs::canonicalize(right).ok() {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        #[derive(Default)]
        struct FileTime {
            low: u32,
            high: u32,
        }
        #[repr(C)]
        #[derive(Default)]
        struct Info {
            attributes: u32,
            creation: FileTime,
            access: FileTime,
            write: FileTime,
            volume: u32,
            size_high: u32,
            size_low: u32,
            links: u32,
            index_high: u32,
            index_low: u32,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetFileInformationByHandle(handle: *mut std::ffi::c_void, info: *mut Info) -> i32;
        }
        let identity = |path: &Path| -> anyhow::Result<(u32, u64)> {
            let file = OpenOptions::new().read(true).share_mode(0x7).open(path)?;
            let mut info = Info::default();
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
                return Err(anyhow!("GetFileInformationByHandle failed"));
            }
            Ok((
                info.volume,
                (u64::from(info.index_high) << 32) | u64::from(info.index_low),
            ))
        };
        Ok(identity(left)? == identity(right)?)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let left_meta = fs::metadata(left)?;
        let right_meta = fs::metadata(right)?;
        return Ok((left_meta.dev(), left_meta.ino()) == (right_meta.dev(), right_meta.ino()));
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(false)
    }
}

fn atomic_write(destination: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("sidecar has no parent"))?;
    fs::create_dir_all(parent)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(
        ".{}.tmp-{}-{stamp}",
        destination.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    let result = file
        .write_all(contents)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all());
    drop(file);
    result?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let temp_w: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
        let dest_w: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        let ok = unsafe { MoveFileExW(temp_w.as_ptr(), dest_w.as_ptr(), 0x1 | 0x8) };
        if ok == 0 {
            let _ = fs::remove_file(&temp);
            return Err(anyhow!(io::Error::last_os_error()));
        }
    }
    #[cfg(not(windows))]
    {
        if let Err(error) = fs::rename(&temp, destination) {
            let _ = fs::remove_file(&temp);
            return Err(error.into());
        }
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}
fn stable_blockers(blockers: &mut Vec<String>) {
    blockers.sort();
    blockers.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_pe::RelocationObservationReport;

    fn final_evidence(dynamic_base: bool, relocs_stripped: bool) -> FinalRelocationEvidence {
        FinalRelocationEvidence {
            directory_present: true,
            pe32_plus: true,
            pointer_size: 8,
            image_base: 0x14000_0000,
            size_of_image: 0x1000,
            directory_rva: 0x1000,
            directory_size: 0x200,
            directory_raw_offset: Some(0x200),
            directory_raw_backed: true,
            dynamic_base,
            relocs_stripped,
            block_count: 1,
            entry_count: 1,
            non_absolute_entry_count: 1,
            observed_types: vec![10],
            blocks: Vec::new(),
            targets: Vec::new(),
            all_targets_raw_backed: true,
            has_non_absolute_entry: true,
            blockers: Vec::new(),
        }
    }

    #[test]
    fn preservation_blockers_are_sorted_and_deduplicated() {
        // P8-E: the gate recomputes preservation independently and requires
        // sorted+deduped blocker lists. The producer must match field-for-field
        // so 'preservation comparison disagrees with recomputation' does not
        // fire merely because the sidecar order differed.
        let runtime = RelocationObservationReport {
            dynamic_base: true,
            relocs_stripped: false,
            pe32_plus: true,
            pointer_size: 8,
            ..Default::default()
        };
        // Final differs on DYNAMIC_BASE, relocs_stripped, and target set
        // (empty vs empty is equal, so force a mismatch via block/entry counts
        // that feed target_set by length — both empty keeps length equal, so
        // use non-empty target counts through a longer target list instead).
        let mut final_candidate = final_evidence(false, true);
        // target_set_preserved compares target lists by length+fields; keep
        // both empty but force failure via pe_kind/pointer mismatch to get a
        // multi-item blocker set.
        final_candidate.pe32_plus = false;
        final_candidate.pointer_size = 4;

        let preserved = compare_runtime_final(&runtime, &final_candidate);
        // More than one blocker: pe_kind, pointer size, DYNAMIC_BASE, RELOCS_STRIPPED.
        assert!(
            preserved.blockers.len() >= 3,
            "expected multiple preservation blockers, got {:?}",
            preserved.blockers
        );
        // Sorted and deduplicated (stable_blockers contract).
        let mut sorted = preserved.blockers.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            preserved.blockers, sorted,
            "blockers must be sorted+deduped"
        );
    }

    #[test]
    fn matching_dynamic_base_passes_preservation() {
        // P8-E: with the emission fix the final candidate keeps DYNAMIC_BASE
        // when the runtime observed it, so DYNAMIC_BASE preservation passes.
        let runtime = RelocationObservationReport {
            dynamic_base: true,
            relocs_stripped: false,
            pe32_plus: true,
            pointer_size: 8,
            ..Default::default()
        };
        let final_candidate = final_evidence(true, false);
        let preserved = compare_runtime_final(&runtime, &final_candidate);
        assert!(
            preserved.dynamic_base_preserved,
            "DYNAMIC_BASE must be preserved when both sides set it"
        );
        assert!(
            preserved.relocs_stripped_preserved,
            "RELOCS_STRIPPED must be preserved when both agree"
        );
        // With empty target lists on both sides, target set is trivially equal.
        assert!(preserved.target_set_preserved);
    }

    /// A minimal legal PE64 that `parse_final_candidate` can parse. The exact
    /// section/directory layout is not important for the schema-dispatch test;
    /// the sidecar is returned (possibly with blockers) once the PE parses.
    fn minimal_pe64() -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0..2].copy_from_slice(b"MZ");
        buf[60..64].copy_from_slice(&0x40u32.to_le_bytes());
        let nt = 0x40usize;
        buf[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let fh = nt + 4;
        buf[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[fh + 2..fh + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[fh + 16..fh + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        let oh = nt + 24;
        buf[oh..oh + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        buf[oh + 16..oh + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[oh + 24..oh + 32].copy_from_slice(&0x1400_0000_0u64.to_le_bytes());
        buf[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[oh + 56..oh + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[oh + 60..oh + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let sh = nt + 24 + 0xF0;
        buf[sh..sh + 5].copy_from_slice(b".text");
        buf[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        buf
    }

    fn write_reloc_pair(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let protected = dir.join("protected.exe");
        let candidate = dir.join("candidate.exe");
        std::fs::write(&protected, b"protected-input").expect("protected");
        std::fs::write(&candidate, minimal_pe64()).expect("candidate");
        (protected, candidate)
    }

    fn absent_tls_report() -> mida_pe::TlsObservationReport {
        mida_pe::TlsObservationReport {
            directory_present: false,
            pe32_plus: false,
            pointer_size: 4,
            directory_rva: 0,
            directory_size: 0,
            directory_bytes_read: 0,
            start_address_of_raw_data: 0,
            start_rva: None,
            end_address_of_raw_data: 0,
            end_rva: None,
            address_of_index: 0,
            index_rva: None,
            address_of_callbacks: 0,
            callbacks_rva: None,
            size_of_zero_fill: 0,
            characteristics: 0,
            index_bytes_read: 0,
            index_value: None,
            callback_slots: Vec::new(),
            null_terminated: false,
            blockers: Vec::new(),
        }
    }

    fn reloc_report(output_size: usize) -> mida_pe::DumpProcessReport {
        mida_pe::DumpProcessReport {
            fix_imports_requested: false,
            iat_evidence_present: false,
            iat_evidence_complete: true,
            iat_report: None,
            iat_partial_accepted: false,
            iat_partial_accept: None,
            tls_evidence_present: false,
            tls_evidence_complete: true,
            tls_report: absent_tls_report(),
            relocation_evidence_present: false,
            relocation_evidence_complete: true,
            relocation_report: mida_pe::RelocationObservationReport::default(),
            exception_evidence_present: false,
            exception_evidence_complete: true,
            exception_report: mida_pe::ExceptionObservationReport {
                directory_present: false,
                directory_rva: 0,
                directory_size: 0,
                pe32_plus: true,
                runtime_image_base: 0,
                preferred_image_base: 0,
                size_of_image: 0,
                directory_bytes_read: 0,
                function_count: 0,
                functions: Vec::new(),
                unwind_infos: Vec::new(),
                sorted_by_begin: true,
                no_overlap: true,
                handlers_in_executable: true,
                blockers: Vec::new(),
            },
            output_size,
        }
    }

    /// A1: the REAL relocation producer dispatches its member schema by family —
    /// `mida.oreans-relocation-evidence/v1` for Oreans, `mida.unpack-relocation-evidence/v1`
    /// for a generic family (ahk_gto), and fails closed on an unknown family.
    #[test]
    fn relocation_sidecar_schema_dispatches_by_family() {
        let dir = std::env::temp_dir().join(format!("mida-reloc-family-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (protected, candidate) = write_reloc_pair(&dir);
        let report = reloc_report(minimal_pe64().len());

        let oreans =
            build_relocation_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert_eq!(oreans.schema_version, "mida.oreans-relocation-evidence/v1");

        let gto = build_relocation_evidence(&protected, &candidate, &report, "ahk_gto").unwrap();
        assert_eq!(gto.schema_version, "mida.unpack-relocation-evidence/v1");

        assert!(build_relocation_evidence(&protected, &candidate, &report, "bogus").is_err());
        assert!(build_relocation_evidence(&protected, &candidate, &report, "").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A1: the REAL relocation producer's `write_relocation_evidence` emits a
    /// disk sidecar whose JSON schema is the generic `mida.unpack-relocation-evidence/v1`
    /// for the GTO family — never the Oreans schema.
    #[test]
    fn relocation_write_gto_sidecar_has_generic_schema() {
        let dir = std::env::temp_dir().join(format!("mida-reloc-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (protected, candidate) = write_reloc_pair(&dir);
        let report = reloc_report(minimal_pe64().len());

        let path = write_relocation_evidence(&protected, &candidate, &report, "ahk_gto").unwrap();
        let json = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value["schema_version"],
            "mida.unpack-relocation-evidence/v1"
        );
        assert!(!json.contains("mida.oreans-relocation-evidence"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
