//! Candidate-bound Oreans TLS evidence.
//!
//! This module binds the immutable runtime TLS observation captured before
//! dump mutation to the exact final candidate bytes re-read from disk.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use mida_pe::{PeHeader, TlsCallbackStatus, TlsObservationReport, MAX_TLS_CALLBACK_SLOTS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const SCHEMA_VERSION: &str = "mida.oreans-tls-evidence/v1";
const TLS_DIRECTORY_INDEX: usize = 9;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeTlsCallbackEvidence {
    pub slot_index: usize,
    pub slot_address: u64,
    pub bytes_read: usize,
    pub observed_value: Option<u64>,
    pub callback_rva: Option<u32>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeTlsEvidence {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_bytes_read: usize,
    pub start_address_of_raw_data: u64,
    pub start_rva: Option<u32>,
    pub end_address_of_raw_data: u64,
    pub end_rva: Option<u32>,
    pub address_of_index: u64,
    pub index_rva: Option<u32>,
    pub address_of_callbacks: u64,
    pub callbacks_rva: Option<u32>,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub index_bytes_read: usize,
    pub index_value: Option<u32>,
    pub callback_slots: Vec<RuntimeTlsCallbackEvidence>,
    pub null_terminated: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalTlsEvidence {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub image_base: u64,
    pub size_of_image: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_raw_offset: Option<u64>,
    pub directory_raw_backed: bool,
    pub start_rva: Option<u32>,
    pub end_rva: Option<u32>,
    pub index_rva: Option<u32>,
    pub index_raw_backed: bool,
    pub callbacks_rva: Option<u32>,
    pub callback_rvas: Vec<u32>,
    pub null_terminated: bool,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsPreservationComparison {
    pub pe_kind_preserved: bool,
    pub pointer_size_preserved: bool,
    pub tls_presence_preserved: bool,
    pub directory_preserved: bool,
    pub raw_data_range_preserved: bool,
    pub index_rva_preserved: bool,
    pub callbacks_rva_preserved: bool,
    pub callbacks_preserved: bool,
    pub null_terminator_preserved: bool,
    pub zero_fill_preserved: bool,
    pub characteristics_preserved: bool,
    pub all_preserved: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsEvidenceSidecar {
    pub schema_version: String,
    pub protected_input: ArtifactIdentity,
    pub candidate: ArtifactIdentity,
    pub runtime: RuntimeTlsEvidence,
    pub final_candidate: FinalTlsEvidence,
    pub preservation: TlsPreservationComparison,
    pub reported_tls_evidence_present: bool,
    pub reported_tls_evidence_complete: bool,
    pub runtime_evidence_present: bool,
    pub runtime_evidence_complete: bool,
    pub prerequisite_passes: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
}

pub(crate) fn write_tls_evidence(
    protected_input: &Path,
    candidate: &Path,
    report: &mida_pe::DumpProcessReport,
) -> anyhow::Result<PathBuf> {
    let sidecar = sidecar_path(candidate)?;
    let value = build_tls_evidence(protected_input, candidate, report)?;
    ensure_sidecar_is_safe(&sidecar, protected_input, candidate)?;
    let json = serde_json::to_vec_pretty(&value).context("serialize TLS evidence sidecar")?;
    atomic_write(&sidecar, &json)?;
    Ok(sidecar)
}

pub(crate) fn build_tls_evidence(
    protected_input: &Path,
    candidate: &Path,
    report: &mida_pe::DumpProcessReport,
) -> anyhow::Result<TlsEvidenceSidecar> {
    if same_file(protected_input, candidate)? {
        return Err(anyhow!("protected input and candidate are the same file"));
    }
    let (_, protected_identity) = read_artifact(protected_input).with_context(|| {
        format!(
            "read protected input for TLS evidence: {}",
            protected_input.display()
        )
    })?;
    let (candidate_bytes, candidate_identity) = read_artifact(candidate)
        .with_context(|| format!("read candidate for TLS evidence: {}", candidate.display()))?;

    let runtime = runtime_to_evidence(&report.tls_report);
    let actual_present = report.tls_report.directory_present;
    let actual_complete = report.tls_report.is_complete();
    let final_candidate = parse_final_candidate(&candidate_bytes)?;
    let preservation = compare_runtime_final(&report.tls_report, &final_candidate);

    let mut blockers = Vec::new();
    if report.tls_evidence_present != actual_present {
        blockers.push("tls_evidence_present disagrees with tls_report presence".to_string());
    }
    if report.tls_evidence_complete != actual_complete {
        blockers.push("tls_evidence_complete disagrees with tls_report blockers".to_string());
    }
    if report.output_size != candidate_bytes.len() {
        blockers.push(format!(
            "dump report output_size {} disagrees with candidate disk size {}",
            report.output_size,
            candidate_bytes.len()
        ));
    }
    blockers.extend(
        report
            .tls_report
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
    stable_blockers(&mut blockers);

    Ok(TlsEvidenceSidecar {
        schema_version: SCHEMA_VERSION.to_string(),
        protected_input: protected_identity,
        candidate: candidate_identity,
        runtime,
        final_candidate,
        preservation: preservation.clone(),
        reported_tls_evidence_present: report.tls_evidence_present,
        reported_tls_evidence_complete: report.tls_evidence_complete,
        runtime_evidence_present: actual_present,
        runtime_evidence_complete: actual_complete,
        prerequisite_passes: blockers.is_empty() && preservation.all_preserved,
        blockers,
    })
}

fn runtime_to_evidence(report: &TlsObservationReport) -> RuntimeTlsEvidence {
    RuntimeTlsEvidence {
        directory_present: report.directory_present,
        pe32_plus: report.pe32_plus,
        pointer_size: report.pointer_size,
        directory_rva: report.directory_rva,
        directory_size: report.directory_size,
        directory_bytes_read: report.directory_bytes_read,
        start_address_of_raw_data: report.start_address_of_raw_data,
        start_rva: report.start_rva,
        end_address_of_raw_data: report.end_address_of_raw_data,
        end_rva: report.end_rva,
        address_of_index: report.address_of_index,
        index_rva: report.index_rva,
        address_of_callbacks: report.address_of_callbacks,
        callbacks_rva: report.callbacks_rva,
        size_of_zero_fill: report.size_of_zero_fill,
        characteristics: report.characteristics,
        index_bytes_read: report.index_bytes_read,
        index_value: report.index_value,
        callback_slots: report
            .callback_slots
            .iter()
            .map(|slot| RuntimeTlsCallbackEvidence {
                slot_index: slot.slot_index,
                slot_address: slot.slot_address,
                bytes_read: slot.bytes_read,
                observed_value: slot.observed_value,
                callback_rva: slot.callback_rva,
                status: tls_callback_status_name(slot.status).to_string(),
            })
            .collect(),
        null_terminated: report.null_terminated,
        blockers: report.blockers.clone(),
    }
}

fn tls_callback_status_name(status: TlsCallbackStatus) -> &'static str {
    match status {
        TlsCallbackStatus::Resolved => "Resolved",
        TlsCallbackStatus::ZeroTerminator => "ZeroTerminator",
        TlsCallbackStatus::ShortRead => "ShortRead",
        TlsCallbackStatus::InvalidAddress => "InvalidAddress",
        TlsCallbackStatus::NonExecutable => "NonExecutable",
        TlsCallbackStatus::InvalidByteCount => "InvalidByteCount",
        TlsCallbackStatus::ReadError => "ReadError",
    }
}

fn parse_final_candidate(bytes: &[u8]) -> anyhow::Result<FinalTlsEvidence> {
    let pe = PeHeader::from_bytes(bytes)
        .map_err(|error| anyhow!("parse final candidate PE: {error}"))?;
    let pointer_size = if pe.is_64bit { 8 } else { 4 };
    let directory = pe.nt_headers.optional_header.data_directory[TLS_DIRECTORY_INDEX];
    let directory_present = directory.virtual_address != 0 || directory.size != 0;
    let mut evidence = FinalTlsEvidence {
        directory_present,
        pe32_plus: pe.is_64bit,
        pointer_size,
        image_base: pe.image_base,
        size_of_image: pe.size_of_image(),
        directory_rva: directory.virtual_address,
        directory_size: directory.size,
        directory_raw_offset: None,
        directory_raw_backed: false,
        start_rva: None,
        end_rva: None,
        index_rva: None,
        index_raw_backed: false,
        callbacks_rva: None,
        callback_rvas: Vec::new(),
        null_terminated: false,
        size_of_zero_fill: 0,
        characteristics: 0,
        blockers: Vec::new(),
    };
    if !directory_present {
        evidence.null_terminated = true;
        return Ok(evidence);
    }
    if (directory.virtual_address == 0) != (directory.size == 0) {
        evidence
            .blockers
            .push("TLS data-directory is a partial (RVA,size) tuple".to_string());
        return Ok(evidence);
    }
    let directory_size = if pe.is_64bit { 40usize } else { 24usize };
    let Ok(directory_size_u) = usize::try_from(directory.size) else {
        evidence
            .blockers
            .push("TLS data-directory size does not fit host usize".to_string());
        return Ok(evidence);
    };
    if directory_size_u < directory_size {
        evidence.blockers.push(format!(
            "TLS data-directory size {} is smaller than {}",
            directory.size, directory_size
        ));
        return Ok(evidence);
    }
    if !rva_range_in_image(
        directory.virtual_address,
        directory.size,
        pe.size_of_image(),
    ) {
        evidence
            .blockers
            .push("TLS data-directory range is outside SizeOfImage".to_string());
    }
    let Some(directory_offset) = raw_span(&pe, bytes, directory.virtual_address, directory.size)
    else {
        evidence
            .blockers
            .push("TLS data-directory is not exactly raw-backed".to_string());
        return Ok(evidence);
    };
    evidence.directory_raw_offset = Some(directory_offset as u64);
    evidence.directory_raw_backed = true;

    let Some(directory_end) = directory_offset.checked_add(directory_size) else {
        evidence
            .blockers
            .push("TLS directory offset arithmetic overflow".to_string());
        return Ok(evidence);
    };
    let Some(dir) = bytes.get(directory_offset..directory_end) else {
        evidence
            .blockers
            .push("TLS directory bytes are truncated".to_string());
        return Ok(evidence);
    };
    let fields = (|| {
        if pe.is_64bit {
            Some((
                read_u64(dir, 0)?,
                read_u64(dir, 8)?,
                read_u64(dir, 16)?,
                read_u64(dir, 24)?,
                read_u32(dir, 32)?,
                read_u32(dir, 36)?,
            ))
        } else {
            Some((
                u64::from(read_u32(dir, 0)?),
                u64::from(read_u32(dir, 4)?),
                u64::from(read_u32(dir, 8)?),
                u64::from(read_u32(dir, 12)?),
                read_u32(dir, 16)?,
                read_u32(dir, 20)?,
            ))
        }
    })();
    let Some((start_va, end_va, index_va, callbacks_va, zero_fill, characteristics)) = fields
    else {
        evidence
            .blockers
            .push("TLS directory field bytes are truncated".to_string());
        return Ok(evidence);
    };
    evidence.size_of_zero_fill = zero_fill;
    evidence.characteristics = characteristics;

    evidence.start_rva = checked_va_to_rva(
        start_va,
        pe.image_base,
        pe.size_of_image(),
        "StartAddressOfRawData",
        &mut evidence.blockers,
    );
    evidence.end_rva = checked_va_to_rva_end(
        end_va,
        pe.image_base,
        pe.size_of_image(),
        "EndAddressOfRawData",
        &mut evidence.blockers,
    );
    if (start_va == 0) != (end_va == 0) {
        evidence.blockers.push(
            "TLS raw-data start/end addresses must be both zero or both non-zero".to_string(),
        );
    }
    if let (Some(start), Some(end)) = (evidence.start_rva, evidence.end_rva) {
        if start > end {
            evidence
                .blockers
                .push("TLS raw-data range is reversed".to_string());
        } else if start < end && raw_span(&pe, bytes, start, end - start).is_none() {
            evidence
                .blockers
                .push("TLS raw-data range is not raw-backed".to_string());
        }
    }

    if index_va == 0 {
        evidence
            .blockers
            .push("TLS AddressOfIndex is zero".to_string());
    } else if let Some(index_rva) = checked_va_to_rva(
        index_va,
        pe.image_base,
        pe.size_of_image(),
        "AddressOfIndex",
        &mut evidence.blockers,
    ) {
        evidence.index_rva = Some(index_rva);
        evidence.index_raw_backed = raw_span(&pe, bytes, index_rva, 4).is_some();
        if !evidence.index_raw_backed {
            evidence
                .blockers
                .push("TLS AddressOfIndex is not exactly 4-byte raw-backed".to_string());
        }
    }

    if callbacks_va == 0 {
        evidence.null_terminated = true;
        stable_blockers(&mut evidence.blockers);
        return Ok(evidence);
    }
    let Some(callbacks_rva) = checked_va_to_rva(
        callbacks_va,
        pe.image_base,
        pe.size_of_image(),
        "AddressOfCallbacks",
        &mut evidence.blockers,
    ) else {
        stable_blockers(&mut evidence.blockers);
        return Ok(evidence);
    };
    evidence.callbacks_rva = Some(callbacks_rva);

    for slot_index in 0..MAX_TLS_CALLBACK_SLOTS {
        let Some(slot_delta) = slot_index.checked_mul(pointer_size) else {
            evidence
                .blockers
                .push("TLS callback slot offset overflow".to_string());
            break;
        };
        let Ok(slot_delta_u32) = u32::try_from(slot_delta) else {
            evidence
                .blockers
                .push("TLS callback slot offset does not fit in RVA".to_string());
            break;
        };
        let Some(slot_rva) = callbacks_rva.checked_add(slot_delta_u32) else {
            evidence
                .blockers
                .push("TLS callback slot RVA overflow".to_string());
            break;
        };
        let Some(slot_offset) = raw_span(&pe, bytes, slot_rva, pointer_size as u32) else {
            evidence.blockers.push(format!(
                "TLS callback slot {slot_index} is not exactly {pointer_size}-byte raw-backed"
            ));
            break;
        };
        let Some(callback_va) = (if pe.is_64bit {
            read_u64(bytes, slot_offset)
        } else {
            read_u32(bytes, slot_offset).map(u64::from)
        }) else {
            evidence.blockers.push(format!(
                "TLS callback slot {slot_index} bytes are truncated"
            ));
            break;
        };
        if callback_va == 0 {
            evidence.null_terminated = true;
            break;
        }
        let Some(callback_rva) = checked_va_to_rva(
            callback_va,
            pe.image_base,
            pe.size_of_image(),
            "TLS callback",
            &mut evidence.blockers,
        ) else {
            continue;
        };
        let executable = pe.sections.iter().any(|section| {
            let Some(end) = section.virtual_address.checked_add(section.virtual_size) else {
                return false;
            };
            section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                && section.virtual_address <= callback_rva
                && callback_rva < end
        });
        if !executable {
            evidence.blockers.push(format!(
                "TLS callback RVA {callback_rva:#x} is not in an executable section"
            ));
        }
        if raw_span(&pe, bytes, callback_rva, 1).is_none() {
            evidence.blockers.push(format!(
                "TLS callback RVA {callback_rva:#x} has no raw-backed code byte"
            ));
        }
        evidence.callback_rvas.push(callback_rva);
    }
    if !evidence.null_terminated {
        evidence.blockers.push(format!(
            "TLS callback array is not NULL-terminated within {MAX_TLS_CALLBACK_SLOTS} slots"
        ));
    }
    stable_blockers(&mut evidence.blockers);
    Ok(evidence)
}

fn checked_va_to_rva(
    va: u64,
    image_base: u64,
    size_of_image: u32,
    label: &str,
    blockers: &mut Vec<String>,
) -> Option<u32> {
    if va == 0 {
        return None;
    }
    let Some(delta) = va.checked_sub(image_base) else {
        blockers.push(format!("TLS {label} VA {va:#x} is below image base"));
        return None;
    };
    let Ok(rva) = u32::try_from(delta) else {
        blockers.push(format!("TLS {label} VA {va:#x} does not fit in RVA"));
        return None;
    };
    if rva >= size_of_image {
        blockers.push(format!("TLS {label} RVA {rva:#x} is outside SizeOfImage"));
        return None;
    }
    Some(rva)
}

fn checked_va_to_rva_end(
    va: u64,
    image_base: u64,
    size_of_image: u32,
    label: &str,
    blockers: &mut Vec<String>,
) -> Option<u32> {
    if va == 0 {
        return None;
    }
    let Some(delta) = va.checked_sub(image_base) else {
        blockers.push(format!("TLS {label} VA {va:#x} is below image base"));
        return None;
    };
    let Ok(rva) = u32::try_from(delta) else {
        blockers.push(format!("TLS {label} VA {va:#x} does not fit in RVA"));
        return None;
    };
    if rva > size_of_image {
        blockers.push(format!("TLS {label} RVA {rva:#x} is outside SizeOfImage"));
        return None;
    }
    Some(rva)
}

fn rva_range_in_image(rva: u32, size: u32, image_size: u32) -> bool {
    rva.checked_add(size).is_some_and(|end| end <= image_size)
}

// Exact file-backed RVA range. It intentionally does not use
// PeHeader::rva_to_offset because virtual-size semantics accept virtual-only tails.
fn raw_span(pe: &PeHeader, bytes: &[u8], rva: u32, size: u32) -> Option<usize> {
    let size_usize = usize::try_from(size).ok()?;
    let end_rva = rva.checked_add(size)?;
    let headers = pe.nt_headers.optional_header.size_of_headers;
    if end_rva <= headers {
        let offset = usize::try_from(rva).ok()?;
        let end = offset.checked_add(size_usize)?;
        return (end <= bytes.len()).then_some(offset);
    }

    for section in &pe.sections {
        let Some(virt_end) = section.virtual_address.checked_add(section.virtual_size) else {
            continue;
        };
        if section.virtual_address > rva || end_rva > virt_end {
            continue;
        }
        let Some(delta) = rva.checked_sub(section.virtual_address) else {
            continue;
        };
        let Some(delta_end) = delta.checked_add(size) else {
            continue;
        };
        if delta_end > section.raw_size {
            continue;
        }
        let Some(raw_offset) = section.raw_offset.checked_add(delta) else {
            continue;
        };
        let Ok(offset) = usize::try_from(raw_offset) else {
            continue;
        };
        let Some(end) = offset.checked_add(size_usize) else {
            continue;
        };
        if end <= bytes.len() {
            return Some(offset);
        }
    }
    None
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let chunk = bytes.get(offset..end)?;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let chunk = bytes.get(offset..end)?;
    Some(u64::from_le_bytes(chunk.try_into().ok()?))
}

fn compare_runtime_final(
    runtime: &TlsObservationReport,
    final_candidate: &FinalTlsEvidence,
) -> TlsPreservationComparison {
    let runtime_callbacks: Vec<u32> = runtime
        .callback_slots
        .iter()
        .filter_map(|slot| slot.callback_rva)
        .collect();
    let both_absent = !runtime.directory_present && !final_candidate.directory_present;
    let pe_kind_preserved = runtime.pe32_plus == final_candidate.pe32_plus;
    let pointer_size_preserved = runtime.pointer_size == final_candidate.pointer_size;
    let tls_presence_preserved = runtime.directory_present == final_candidate.directory_present;
    let directory_preserved = both_absent
        || (runtime.directory_rva == final_candidate.directory_rva
            && runtime.directory_size == final_candidate.directory_size
            && final_candidate.directory_raw_backed);
    let raw_data_range_preserved = both_absent
        || (runtime.start_rva == final_candidate.start_rva
            && runtime.end_rva == final_candidate.end_rva);
    let index_rva_preserved = both_absent
        || (runtime.index_rva == final_candidate.index_rva && final_candidate.index_raw_backed);
    let callbacks_rva_preserved =
        both_absent || runtime.callbacks_rva == final_candidate.callbacks_rva;
    let callbacks_preserved = both_absent || runtime_callbacks == final_candidate.callback_rvas;
    let null_terminator_preserved =
        both_absent || runtime.null_terminated == final_candidate.null_terminated;
    let zero_fill_preserved =
        both_absent || runtime.size_of_zero_fill == final_candidate.size_of_zero_fill;
    let characteristics_preserved =
        both_absent || runtime.characteristics == final_candidate.characteristics;
    let mut blockers = Vec::new();
    for (ok, label) in [
        (pe_kind_preserved, "PE kind mismatch"),
        (pointer_size_preserved, "pointer size mismatch"),
        (tls_presence_preserved, "TLS directory presence mismatch"),
        (
            directory_preserved,
            "TLS directory RVA/size or raw backing mismatch",
        ),
        (raw_data_range_preserved, "TLS raw-data RVA range mismatch"),
        (index_rva_preserved, "TLS index RVA or raw backing mismatch"),
        (callbacks_rva_preserved, "TLS callbacks RVA mismatch"),
        (callbacks_preserved, "TLS callback RVA list/order mismatch"),
        (
            null_terminator_preserved,
            "TLS callback NULL terminator mismatch",
        ),
        (zero_fill_preserved, "TLS SizeOfZeroFill mismatch"),
        (characteristics_preserved, "TLS Characteristics mismatch"),
    ] {
        if !ok {
            blockers.push(label.to_string());
        }
    }
    stable_blockers(&mut blockers);
    let all_preserved = blockers.is_empty();
    TlsPreservationComparison {
        pe_kind_preserved,
        pointer_size_preserved,
        tls_presence_preserved,
        directory_preserved,
        raw_data_range_preserved,
        index_rva_preserved,
        callbacks_rva_preserved,
        callbacks_preserved,
        null_terminator_preserved,
        zero_fill_preserved,
        characteristics_preserved,
        all_preserved,
        blockers,
    }
}

fn stable_blockers(blockers: &mut Vec<String>) {
    blockers.sort();
    blockers.dedup();
}

fn read_artifact(path: &Path) -> anyhow::Result<(Vec<u8>, ArtifactIdentity)> {
    let bytes = fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let size_bytes = u64::try_from(bytes.len()).context("artifact size does not fit u64")?;
    Ok((
        bytes,
        ArtifactIdentity {
            path: path.to_string_lossy().into_owned(),
            sha256: format!("{:064x}", hasher.finalize()),
            size_bytes,
        },
    ))
}

fn sidecar_path(candidate: &Path) -> anyhow::Result<PathBuf> {
    let file_name = candidate
        .file_name()
        .ok_or_else(|| anyhow!("candidate path has no file name"))?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(".tls_evidence.json");
    Ok(candidate.with_file_name(sidecar_name))
}

fn ensure_sidecar_is_safe(
    sidecar: &Path,
    protected_input: &Path,
    candidate: &Path,
) -> anyhow::Result<()> {
    if sidecar.exists() && (same_file(sidecar, protected_input)? || same_file(sidecar, candidate)?)
    {
        return Err(anyhow!(
            "TLS sidecar aliases a source artifact: {}",
            sidecar.display()
        ));
    }
    if sidecar.is_dir() {
        return Err(anyhow!(
            "TLS sidecar destination is a directory: {}",
            sidecar.display()
        ));
    }
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> anyhow::Result<bool> {
    if fs::canonicalize(left).ok() == fs::canonicalize(right).ok() {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        return Ok(windows_file_identity(left)? == windows_file_identity(right)?);
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

#[cfg(windows)]
fn windows_file_identity(path: &Path) -> anyhow::Result<FileIdentity> {
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
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        #[link_name = "GetFileInformationByHandle"]
        fn get_file_information_by_handle_tls(
            file: *mut std::ffi::c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(0x7)
        .open(path)
        .with_context(|| format!("open file identity {}", path.display()))?;
    let mut info = ByHandleFileInformation::default();
    let ok = unsafe { get_file_information_by_handle_tls(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(anyhow!(
            "read file identity {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(FileIdentity {
        volume_serial: info.volume_serial_number,
        file_index: (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
    })
}

fn atomic_write(destination: &Path, contents: &[u8]) -> anyhow::Result<()> {
    if destination.is_dir() {
        return Err(anyhow!("TLS sidecar destination is a directory"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("TLS sidecar destination has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create TLS sidecar directory {}", parent.display()))?;
    let temp = create_temp_file(
        parent,
        destination.file_name().unwrap_or_default(),
        contents,
    )?;
    if let Err(error) = atomic_replace(&temp, destination) {
        let _ = fs::remove_file(&temp);
        return Err(error)
            .with_context(|| format!("atomically replace TLS sidecar {}", destination.display()));
    }
    Ok(())
}

fn create_temp_file(
    parent: &Path,
    destination_name: &std::ffi::OsStr,
    contents: &[u8],
) -> anyhow::Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..32u32 {
        let name = format!(
            ".{}.tmp-{}-{}",
            destination_name.to_string_lossy(),
            std::process::id(),
            now.saturating_add(u128::from(attempt))
        );
        let path = parent.join(name);
        let mut file = match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create temporary TLS sidecar {}", path.display()))
            }
        };
        let result = file
            .write_all(contents)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = result {
            let _ = fs::remove_file(&path);
            return Err(error)
                .with_context(|| format!("sync temporary TLS sidecar {}", path.display()));
        }
        return Ok(path);
    }
    Err(anyhow!("unable to allocate unique temporary TLS sidecar"))
}

#[cfg(windows)]
fn atomic_replace(temp: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let temp_w: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_w: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let ok = unsafe {
        MoveFileExW(
            temp_w.as_ptr(),
            destination_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn atomic_replace(temp: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temp, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_pe::{TlsCallbackObservation, TlsCallbackStatus};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDirGuard(PathBuf);

    impl std::ops::Deref for TempDirGuard {
        type Target = Path;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(label: &str) -> TempDirGuard {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("mida-tls-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        TempDirGuard(path)
    }

    #[derive(Clone)]
    struct ImageSpec {
        pe32_plus: bool,
        tls: bool,
        directory_rva: u32,
        directory_size: u32,
        section_virtual_size: u32,
        section_raw_size: u32,
        size_of_image: u32,
        section_exec: bool,
        start_rva: u32,
        end_rva: u32,
        index_rva: u32,
        callbacks_rva: u32,
        callback_rvas: Vec<u32>,
        null_terminated: bool,
        zero_fill: u32,
        characteristics: u32,
    }

    impl Default for ImageSpec {
        fn default() -> Self {
            Self {
                pe32_plus: true,
                tls: true,
                directory_rva: 0x1100,
                directory_size: 40,
                section_virtual_size: 0x1000,
                section_raw_size: 0x1000,
                size_of_image: 0x2000,
                section_exec: true,
                start_rva: 0x1600,
                end_rva: 0x2000,
                index_rva: 0x1200,
                callbacks_rva: 0x1300,
                callback_rvas: vec![0x1500],
                null_terminated: true,
                zero_fill: 0x20,
                characteristics: 0x4000_0000,
            }
        }
    }

    fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf.get_mut(offset..offset + 2)
            .unwrap()
            .copy_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf.get_mut(offset..offset + 4)
            .unwrap()
            .copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf.get_mut(offset..offset + 8)
            .unwrap()
            .copy_from_slice(&value.to_le_bytes());
    }
    fn rva_offset(spec: &ImageSpec, rva: u32) -> Option<usize> {
        let delta = rva.checked_sub(0x1000)?;
        (delta < spec.section_raw_size).then_some(0x200 + delta as usize)
    }
    fn put_ptr(buf: &mut [u8], offset: usize, value: u64, pe32_plus: bool) {
        if pe32_plus {
            put_u64(buf, offset, value);
        } else {
            put_u32(buf, offset, value as u32);
        }
    }

    fn candidate(spec: &ImageSpec) -> Vec<u8> {
        let nt = 0x40usize;
        let optional_size = if spec.pe32_plus { 0xf0usize } else { 0xe0usize };
        let file_len = 0x200usize + spec.section_raw_size as usize;
        let mut buf = vec![0u8; file_len.max(0x400)];
        buf[0..2].copy_from_slice(b"MZ");
        put_u32(&mut buf, 0x3c, nt as u32);
        buf[nt..nt + 4].copy_from_slice(b"PE\0\0");
        put_u16(
            &mut buf,
            nt + 4,
            if spec.pe32_plus { 0x8664 } else { 0x14c },
        );
        put_u16(&mut buf, nt + 6, 1);
        put_u16(&mut buf, nt + 20, optional_size as u16);
        put_u16(&mut buf, nt + 22, 0x22);
        let oh = nt + 24;
        put_u16(&mut buf, oh, if spec.pe32_plus { 0x20b } else { 0x10b });
        put_u32(&mut buf, oh + 16, 0x1500);
        if spec.pe32_plus {
            put_u64(&mut buf, oh + 24, 0x1400_0000_0);
        } else {
            put_u32(&mut buf, oh + 28, 0x400000);
        }
        put_u32(&mut buf, oh + 32, 0x1000);
        put_u32(&mut buf, oh + 36, 0x200);
        put_u32(&mut buf, oh + 56, spec.size_of_image);
        put_u32(&mut buf, oh + 60, 0x200);
        put_u32(&mut buf, oh + if spec.pe32_plus { 108 } else { 92 }, 16);
        let data_dir = oh + if spec.pe32_plus { 112 } else { 96 } + TLS_DIRECTORY_INDEX * 8;
        if spec.tls || spec.directory_rva != 0 || spec.directory_size != 0 {
            put_u32(&mut buf, data_dir, spec.directory_rva);
            put_u32(&mut buf, data_dir + 4, spec.directory_size);
        }
        let sh = nt + 24 + optional_size;
        buf[sh..sh + 5].copy_from_slice(b".text");
        put_u32(&mut buf, sh + 8, spec.section_virtual_size);
        put_u32(&mut buf, sh + 12, 0x1000);
        put_u32(&mut buf, sh + 16, spec.section_raw_size);
        put_u32(&mut buf, sh + 20, 0x200);
        put_u32(
            &mut buf,
            sh + 36,
            if spec.section_exec {
                0x6000_0020
            } else {
                0x4000_0040
            },
        );
        let image_base = if spec.pe32_plus {
            0x1400_0000_0
        } else {
            0x400000
        };
        if spec.tls && spec.directory_size >= if spec.pe32_plus { 40 } else { 24 } {
            if let Some(offset) = rva_offset(spec, spec.directory_rva) {
                let values = [
                    image_base + u64::from(spec.start_rva),
                    image_base + u64::from(spec.end_rva),
                    image_base + u64::from(spec.index_rva),
                    if spec.callbacks_rva == 0 {
                        0
                    } else {
                        image_base + u64::from(spec.callbacks_rva)
                    },
                ];
                for (index, value) in values.into_iter().enumerate() {
                    put_ptr(
                        &mut buf,
                        offset + index * if spec.pe32_plus { 8 } else { 4 },
                        value,
                        spec.pe32_plus,
                    );
                }
                let tail = offset + if spec.pe32_plus { 32 } else { 16 };
                put_u32(&mut buf, tail, spec.zero_fill);
                put_u32(&mut buf, tail + 4, spec.characteristics);
            }
            if let Some(offset) = rva_offset(spec, spec.index_rva) {
                put_u32(&mut buf, offset, 0);
            }
            if spec.callbacks_rva != 0 {
                for (slot, callback_rva) in spec.callback_rvas.iter().copied().enumerate() {
                    if let Some(offset) = rva_offset(
                        spec,
                        spec.callbacks_rva + (slot as u32) * (if spec.pe32_plus { 8 } else { 4 }),
                    ) {
                        put_ptr(
                            &mut buf,
                            offset,
                            image_base + u64::from(callback_rva),
                            spec.pe32_plus,
                        );
                    }
                    if let Some(offset) = rva_offset(spec, callback_rva) {
                        buf[offset] = 0xc3;
                    }
                }
                if spec.null_terminated {
                    let slot = spec.callback_rvas.len() as u32;
                    if let Some(offset) = rva_offset(
                        spec,
                        spec.callbacks_rva + slot * (if spec.pe32_plus { 8 } else { 4 }),
                    ) {
                        put_ptr(&mut buf, offset, 0, spec.pe32_plus);
                    }
                }
            }
        }
        buf
    }

    fn absent_report(pe32_plus: bool, output_size: usize) -> mida_pe::DumpProcessReport {
        mida_pe::DumpProcessReport {
            fix_imports_requested: false,
            iat_evidence_present: false,
            iat_evidence_complete: true,
            iat_report: None,
            tls_evidence_present: false,
            tls_evidence_complete: true,
            tls_report: mida_pe::TlsObservationReport {
                directory_present: false,
                pe32_plus,
                pointer_size: if pe32_plus { 8 } else { 4 },
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
            },
            relocation_evidence_present: false,
            relocation_evidence_complete: true,
            relocation_report: mida_pe::RelocationObservationReport::default(),
            output_size,
        }
    }

    fn runtime_report(spec: &ImageSpec, output_size: usize) -> mida_pe::DumpProcessReport {
        let image_base = if spec.pe32_plus {
            0x1400_0000_0
        } else {
            0x400000
        };
        let pointer_size = if spec.pe32_plus { 8 } else { 4 };
        let mut callback_slots = spec
            .callback_rvas
            .iter()
            .enumerate()
            .map(|(slot_index, callback_rva)| TlsCallbackObservation {
                slot_index,
                slot_address: image_base
                    + u64::from(spec.callbacks_rva)
                    + (slot_index * pointer_size) as u64,
                bytes_read: pointer_size,
                observed_value: Some(image_base + u64::from(*callback_rva)),
                callback_rva: Some(*callback_rva),
                status: TlsCallbackStatus::Resolved,
            })
            .collect::<Vec<_>>();
        if spec.null_terminated {
            callback_slots.push(TlsCallbackObservation {
                slot_index: spec.callback_rvas.len(),
                slot_address: image_base
                    + u64::from(spec.callbacks_rva)
                    + (spec.callback_rvas.len() * pointer_size) as u64,
                bytes_read: pointer_size,
                observed_value: Some(0),
                callback_rva: None,
                status: TlsCallbackStatus::ZeroTerminator,
            });
        }
        mida_pe::DumpProcessReport {
            fix_imports_requested: false,
            iat_evidence_present: false,
            iat_evidence_complete: true,
            iat_report: None,
            tls_evidence_present: true,
            tls_evidence_complete: true,
            tls_report: mida_pe::TlsObservationReport {
                directory_present: true,
                pe32_plus: spec.pe32_plus,
                pointer_size,
                directory_rva: spec.directory_rva,
                directory_size: spec.directory_size,
                directory_bytes_read: spec.directory_size as usize,
                start_address_of_raw_data: image_base + u64::from(spec.start_rva),
                start_rva: Some(spec.start_rva),
                end_address_of_raw_data: image_base + u64::from(spec.end_rva),
                end_rva: Some(spec.end_rva),
                address_of_index: image_base + u64::from(spec.index_rva),
                index_rva: Some(spec.index_rva),
                address_of_callbacks: if spec.callbacks_rva == 0 {
                    0
                } else {
                    image_base + u64::from(spec.callbacks_rva)
                },
                callbacks_rva: (spec.callbacks_rva != 0).then_some(spec.callbacks_rva),
                size_of_zero_fill: spec.zero_fill,
                characteristics: spec.characteristics,
                index_bytes_read: 4,
                index_value: Some(7),
                callback_slots,
                null_terminated: spec.null_terminated,
                blockers: Vec::new(),
            },
            relocation_evidence_present: false,
            relocation_evidence_complete: true,
            relocation_report: mida_pe::RelocationObservationReport::default(),
            output_size,
        }
    }

    fn write_pair(dir: &Path, candidate_bytes: &[u8]) -> (PathBuf, PathBuf) {
        let protected = dir.join("protected.exe");
        let candidate = dir.join("candidate.exe");
        fs::write(&protected, b"protected-input").unwrap();
        fs::write(&candidate, candidate_bytes).unwrap();
        (protected, candidate)
    }

    fn good_pair(
        label: &str,
        spec: &ImageSpec,
    ) -> (TempDirGuard, PathBuf, PathBuf, mida_pe::DumpProcessReport) {
        let dir = temp_dir(label);
        let bytes = candidate(spec);
        let (protected, candidate_path) = write_pair(&dir, &bytes);
        let report = runtime_report(spec, bytes.len());
        (dir, protected, candidate_path, report)
    }

    #[test]
    fn pe32_plus_happy_preservation_and_end_at_size_of_image() {
        let spec = ImageSpec::default();
        let (_dir, protected, candidate_path, report) = good_pair("pe64", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar.prerequisite_passes, "{:?}", sidecar.blockers);
        assert_eq!(sidecar.final_candidate.end_rva, Some(spec.size_of_image));
        assert_eq!(sidecar.runtime.index_value, Some(7));
        assert!(sidecar.preservation.all_preserved);
    }

    #[test]
    fn pe32_happy_preservation() {
        let mut spec = ImageSpec::default();
        spec.pe32_plus = false;
        spec.directory_size = 24;
        let (_dir, protected, candidate_path, report) = good_pair("pe32", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar.prerequisite_passes, "{:?}", sidecar.blockers);
        assert_eq!(sidecar.final_candidate.pointer_size, 4);
    }

    #[test]
    fn runtime_absent_is_complete_negative_observation() {
        let mut spec = ImageSpec::default();
        spec.tls = false;
        spec.directory_rva = 0;
        spec.directory_size = 0;
        let (_dir, protected, candidate_path, report) = {
            let dir = temp_dir("absent");
            let bytes = candidate(&spec);
            let (protected, candidate_path) = write_pair(&dir, &bytes);
            (
                dir,
                protected,
                candidate_path,
                absent_report(true, bytes.len()),
            )
        };
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar.prerequisite_passes, "{:?}", sidecar.blockers);
        assert!(!sidecar.runtime_evidence_present);
        assert!(!sidecar.final_candidate.directory_present);
        assert!(sidecar.preservation.tls_presence_preserved);
    }

    #[test]
    fn diagnostic_bool_mismatch_blocks() {
        let spec = ImageSpec::default();
        let (_dir, protected, candidate_path, mut report) = good_pair("diagnostic", &spec);
        report.tls_evidence_present = false;
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(!sidecar.prerequisite_passes);
        assert!(sidecar
            .blockers
            .iter()
            .any(|b| b.contains("present disagrees")));
    }

    #[test]
    fn candidate_identity_is_recomputed_from_disk_and_output_size_is_checked() {
        let spec = ImageSpec::default();
        let (_dir, protected, candidate_path, mut report) = good_pair("identity", &spec);
        let bytes = fs::read(&candidate_path).unwrap();
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        assert_eq!(
            sidecar.candidate.sha256,
            format!("{:064x}", hasher.finalize())
        );
        assert_eq!(sidecar.candidate.size_bytes, bytes.len() as u64);
        report.output_size += 1;
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar.blockers.iter().any(|b| b.contains("output_size")));
    }

    #[test]
    fn partial_directory_tuple_is_blocked() {
        let mut spec = ImageSpec::default();
        spec.directory_size = 0;
        let (_dir, protected, candidate_path, report) = good_pair("partial-dd", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .final_candidate
            .blockers
            .iter()
            .any(|b| b.contains("partial")));
    }

    #[test]
    fn truncated_and_not_raw_backed_directory_are_blocked() {
        let spec = ImageSpec::default();
        let (_dir, protected, candidate_path, report) = good_pair("truncated", &spec);
        let mut bytes = fs::read(&candidate_path).unwrap();
        let directory_offset = rva_offset(&spec, spec.directory_rva).unwrap();
        bytes.truncate(directory_offset + 39);
        fs::write(&candidate_path, &bytes).unwrap();
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(
            sidecar
                .final_candidate
                .blockers
                .iter()
                .any(|b| b.contains("raw-backed")),
            "{:?}",
            sidecar.final_candidate.blockers
        );

        let mut spec = ImageSpec::default();
        spec.directory_rva = 0x1f00;
        spec.directory_size = 0x200;
        spec.section_virtual_size = 0x2000;
        spec.section_raw_size = 0x1000;
        spec.size_of_image = 0x3000;
        let (_dir, protected, candidate_path, report) = good_pair("unbacked-dd", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .final_candidate
            .blockers
            .iter()
            .any(|b| b.contains("raw-backed")));
    }

    #[test]
    fn index_and_callback_array_unmapped_are_blocked() {
        let mut spec = ImageSpec::default();
        spec.index_rva = 0x3000;
        let (_dir, protected, candidate_path, report) = good_pair("index-unmapped", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .final_candidate
            .blockers
            .iter()
            .any(|b| b.contains("AddressOfIndex")));

        let mut spec = ImageSpec::default();
        spec.section_virtual_size = 0x3000;
        spec.size_of_image = 0x4000;
        spec.callbacks_rva = 0x3000;
        let (_dir, protected, candidate_path, report) = good_pair("callbacks-unmapped", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .final_candidate
            .blockers
            .iter()
            .any(|b| b.contains("callback slot")));
    }

    #[test]
    fn unterminated_callback_array_is_blocked() {
        let mut spec = ImageSpec::default();
        spec.section_virtual_size = 0x9000;
        spec.section_raw_size = 0x9000;
        spec.size_of_image = 0xa000;
        spec.callbacks_rva = 0x1800;
        spec.callback_rvas = (0..MAX_TLS_CALLBACK_SLOTS)
            .map(|i| 0x3000 + i as u32)
            .collect();
        spec.null_terminated = false;
        let (_dir, protected, candidate_path, report) = good_pair("unterminated", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .final_candidate
            .blockers
            .iter()
            .any(|b| b.contains("NULL-terminated")));
    }

    #[test]
    fn non_executable_callback_is_blocked() {
        let mut spec = ImageSpec::default();
        spec.section_exec = false;
        let (_dir, protected, candidate_path, report) = good_pair("non-exec", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .final_candidate
            .blockers
            .iter()
            .any(|b| b.contains("executable")));
    }

    #[test]
    fn callback_and_index_rva_mismatches_are_blocked() {
        let spec = ImageSpec::default();
        let (_dir, protected, candidate_path, mut report) = good_pair("mismatch", &spec);
        report.tls_report.callback_slots[0].callback_rva = Some(0x1510);
        report.tls_report.index_rva = Some(0x1210);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .blockers
            .iter()
            .any(|b| b.contains("callback RVA list")));
        assert!(sidecar.blockers.iter().any(|b| b.contains("index RVA")));
    }

    #[test]
    fn zero_fill_and_characteristics_mismatch_are_blocked() {
        let spec = ImageSpec::default();
        let (_dir, protected, candidate_path, mut report) = good_pair("fields", &spec);
        report.tls_report.size_of_zero_fill += 1;
        report.tls_report.characteristics ^= 1;
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .blockers
            .iter()
            .any(|b| b.contains("SizeOfZeroFill")));
        assert!(sidecar
            .blockers
            .iter()
            .any(|b| b.contains("Characteristics")));
    }

    #[test]
    fn virtual_only_tail_is_not_raw_backed() {
        let mut spec = ImageSpec::default();
        spec.section_raw_size = 0x800;
        spec.start_rva = 0x1800;
        spec.end_rva = 0x1900;
        let (_dir, protected, candidate_path, report) = good_pair("virtual-tail", &spec);
        let sidecar = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        assert!(sidecar
            .final_candidate
            .blockers
            .iter()
            .any(|b| b.contains("raw-backed")));
    }

    #[test]
    fn same_path_and_hard_link_are_rejected() {
        let spec = ImageSpec::default();
        let dir = temp_dir("identity-reject");
        let bytes = candidate(&spec);
        let (_protected, candidate_path) = write_pair(&dir, &bytes);
        let report = runtime_report(&spec, bytes.len());
        assert!(build_tls_evidence(&candidate_path, &candidate_path, &report).is_err());
        let hardlink = dir.join("candidate-hardlink.exe");
        fs::hard_link(&candidate_path, &hardlink).unwrap();
        assert!(build_tls_evidence(&candidate_path, &hardlink, &report).is_err());
    }

    #[test]
    fn atomic_overwrite_and_directory_destination_errors_propagate() {
        let spec = ImageSpec::default();
        let (_dir, protected, candidate_path, report) = good_pair("atomic", &spec);
        let written_sidecar_path = sidecar_path(&candidate_path).unwrap();
        fs::write(&written_sidecar_path, b"stale").unwrap();
        let written = write_tls_evidence(&protected, &candidate_path, &report).unwrap();
        let parsed: TlsEvidenceSidecar =
            serde_json::from_slice(&fs::read(&written).unwrap()).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert!(!fs::read_dir(written.parent().unwrap())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")));

        let dir = temp_dir("directory-destination");
        let (protected, candidate_path) = write_pair(&dir, &candidate(&spec));
        let destination = sidecar_path(&candidate_path).unwrap();
        fs::create_dir(&destination).unwrap();
        let report = runtime_report(&spec, fs::metadata(&candidate_path).unwrap().len() as usize);
        assert!(write_tls_evidence(&protected, &candidate_path, &report).is_err());
    }

    #[test]
    fn schema_roundtrip_and_unknown_field_rejection() {
        let spec = ImageSpec::default();
        let (_dir, protected, candidate_path, report) = good_pair("schema", &spec);
        let value = build_tls_evidence(&protected, &candidate_path, &report).unwrap();
        let json = serde_json::to_string(&value).unwrap();
        let decoded: TlsEvidenceSidecar = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, value);
        let mut object: serde_json::Value = serde_json::from_str(&json).unwrap();
        object
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), serde_json::Value::Null);
        assert!(serde_json::from_value::<TlsEvidenceSidecar>(object).is_err());
    }
}
