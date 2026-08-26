//! Candidate-bound exception-directory evidence (GTO-H4-D).
//!
//! Binds the immutable runtime exception observation captured before dump
//! mutation to the exact final candidate bytes re-read from disk via the
//! independent final decoder (`ExceptionFinalDecoder`). Fail-closed: any
//! blocker prevents writing a passing sidecar.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use mida_pe::{
    ExceptionFinalDecoder, ExceptionFinalReport, ExceptionObservationReport,
    ExceptionPreservationComparison,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::evidence_schema::ArtifactIdentity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeFunctionEvidence {
    pub index: u32,
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnwindCodeEvidence {
    pub code_offset: u8,
    pub unwind_op: u8,
    pub op_info: u8,
    pub slot_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChainInfoEvidence {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnwindInfoEvidence {
    pub function_index: u32,
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub codes: Vec<UnwindCodeEvidence>,
    pub handler_rva: Option<u32>,
    pub chain: Option<ChainInfoEvidence>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeExceptionEvidence {
    pub directory_present: bool,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub pe32_plus: bool,
    pub runtime_image_base: u64,
    pub preferred_image_base: u64,
    pub size_of_image: u32,
    pub directory_bytes_read: usize,
    pub function_count: u32,
    pub functions: Vec<RuntimeFunctionEvidence>,
    pub unwind_infos: Vec<UnwindInfoEvidence>,
    pub sorted_by_begin: bool,
    pub no_overlap: bool,
    pub handlers_in_executable: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalExceptionEvidence {
    pub directory_present: bool,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub pe32_plus: bool,
    pub image_base: u64,
    pub size_of_image: u32,
    pub directory_raw_offset: Option<u64>,
    pub directory_raw_backed: bool,
    pub function_count: u32,
    pub functions: Vec<RuntimeFunctionEvidence>,
    pub unwind_infos: Vec<UnwindInfoEvidence>,
    pub sorted_by_begin: bool,
    pub no_overlap: bool,
    pub handlers_in_executable: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExceptionPreservationEvidence {
    pub all_preserved: bool,
    pub directory_present_preserved: bool,
    pub directory_rva_preserved: bool,
    pub directory_size_preserved: bool,
    pub function_count_preserved: bool,
    pub functions_preserved: bool,
    pub unwind_infos_preserved: bool,
    pub blockers: Vec<String>,
}

/// D2 no-reloc state (frozen semantics).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NoRelocStateEvidence {
    pub directory_absent: bool,
    pub directory_present_but_empty: bool,
    pub relocs_stripped: bool,
    pub dynamic_base: bool,
    pub runtime_image_base: u64,
    pub preferred_image_base: u64,
    pub state_text: String,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExceptionEvidenceSidecar {
    pub schema_version: String,
    pub protected_input: ArtifactIdentity,
    pub candidate: ArtifactIdentity,
    pub runtime: RuntimeExceptionEvidence,
    pub final_candidate: FinalExceptionEvidence,
    pub preservation: ExceptionPreservationEvidence,
    pub no_reloc_state: NoRelocStateEvidence,
    pub reported_exception_evidence_present: bool,
    pub reported_exception_evidence_complete: bool,
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

fn runtime_to_evidence(report: &ExceptionObservationReport) -> RuntimeExceptionEvidence {
    RuntimeExceptionEvidence {
        directory_present: report.directory_present,
        directory_rva: report.directory_rva,
        directory_size: report.directory_size,
        pe32_plus: report.pe32_plus,
        runtime_image_base: report.runtime_image_base,
        preferred_image_base: report.preferred_image_base,
        size_of_image: report.size_of_image,
        directory_bytes_read: report.directory_bytes_read,
        function_count: report.function_count,
        functions: report
            .functions
            .iter()
            .map(|f| RuntimeFunctionEvidence {
                index: f.index,
                begin_rva: f.begin_rva,
                end_rva: f.end_rva,
                unwind_info_rva: f.unwind_info_rva,
                status: f.status.to_string(),
            })
            .collect(),
        unwind_infos: report.unwind_infos.iter().map(unwind_to_evidence).collect(),
        sorted_by_begin: report.sorted_by_begin,
        no_overlap: report.no_overlap,
        handlers_in_executable: report.handlers_in_executable,
        blockers: report.blockers.clone(),
    }
}

fn unwind_to_evidence(u: &mida_pe::UnwindInfoObservation) -> UnwindInfoEvidence {
    UnwindInfoEvidence {
        function_index: u.function_index,
        version: u.version,
        flags: u.flags,
        size_of_prolog: u.size_of_prolog,
        count_of_codes: u.count_of_codes,
        frame_register: u.frame_register,
        frame_offset: u.frame_offset,
        codes: u
            .codes
            .iter()
            .map(|c| UnwindCodeEvidence {
                code_offset: c.code_offset,
                unwind_op: c.unwind_op,
                op_info: c.op_info,
                slot_status: c.slot_status.to_string(),
            })
            .collect(),
        handler_rva: u.handler_rva,
        chain: u.chain.as_ref().map(|c| ChainInfoEvidence {
            begin_address: c.begin_address,
            end_address: c.end_address,
            unwind_info_address: c.unwind_info_address,
            status: c.status.to_string(),
        }),
        status: u.status.to_string(),
    }
}

fn final_to_evidence(report: &ExceptionFinalReport) -> FinalExceptionEvidence {
    FinalExceptionEvidence {
        directory_present: report.directory_present,
        directory_rva: report.directory_rva,
        directory_size: report.directory_size,
        pe32_plus: report.pe32_plus,
        image_base: report.image_base,
        size_of_image: report.size_of_image,
        directory_raw_offset: report.directory_raw_offset,
        directory_raw_backed: report.directory_raw_backed,
        function_count: report.function_count,
        functions: report
            .functions
            .iter()
            .map(|f| RuntimeFunctionEvidence {
                index: f.index,
                begin_rva: f.begin_rva,
                end_rva: f.end_rva,
                unwind_info_rva: f.unwind_info_rva,
                status: f.status.to_string(),
            })
            .collect(),
        unwind_infos: report.unwind_infos.iter().map(unwind_to_evidence).collect(),
        sorted_by_begin: report.sorted_by_begin,
        no_overlap: report.no_overlap,
        handlers_in_executable: report.handlers_in_executable,
        blockers: report.blockers.clone(),
    }
}

fn preservation_to_evidence(p: &ExceptionPreservationComparison) -> ExceptionPreservationEvidence {
    ExceptionPreservationEvidence {
        all_preserved: p.all_preserved,
        directory_present_preserved: p.directory_present_preserved,
        directory_rva_preserved: p.directory_rva_preserved,
        directory_size_preserved: p.directory_size_preserved,
        function_count_preserved: p.function_count_preserved,
        functions_preserved: p.functions_preserved,
        unwind_infos_preserved: p.unwind_infos_preserved,
        blockers: p.blockers.clone(),
    }
}

/// D2: no-reloc state observation with frozen wording — "no-reloc state
/// observed and preserved" is the only acceptable positive text; "relocation
/// PASS" is never emitted.
fn no_reloc_state(
    reloc: &mida_pe::relocation_observation::RelocationObservationReport,
    final_reloc: &NoRelocFinalState,
) -> NoRelocStateEvidence {
    // N1 semantics: directory absent is the negative observation on the
    // directory axis alone; RELOCS_STRIPPED is a separate axis recorded
    // independently (they must not be conflated).
    let directory_absent = !reloc.directory_present;
    let present_but_empty = reloc.directory_present && reloc.directory_size == 0;
    let mut blockers = Vec::new();
    // N9: stripped flag conflicts with directory.
    if reloc.relocs_stripped && reloc.directory_present {
        blockers.push("stripped flag conflicts with directory".to_string());
    }
    // N10: DYNAMIC_BASE set but runtime != preferred and no relocation.
    if reloc.dynamic_base
        && reloc.runtime_image_base != reloc.preferred_image_base
        && !reloc.directory_present
        && !reloc.relocs_stripped
    {
        blockers.push("dynamic base without relocation".to_string());
    }
    // D2.2-4: runtime/final consistency (GTO-H4-D: the final axis is
    // re-parsed from the candidate PE, not the dump object).
    if final_reloc.image_base_changed {
        blockers.push("runtime/final base mismatch".to_string());
    }
    // D2 no-reloc preservation: a stripped+absent candidate MUST keep the
    // stripped flag and absent directory. Clearing either is fabrication.
    if reloc.relocs_stripped != final_reloc.relocs_stripped {
        blockers.push("runtime/final RELOCS_STRIPPED mismatch".to_string());
    }
    if reloc.directory_present != !final_reloc.directory_absent {
        blockers.push("runtime/final base-reloc directory mismatch".to_string());
    }
    // D2.2-4 (empty-directory axis): a runtime "present but empty" directory
    // must match the final candidate's "present but empty" fact. The final
    // side re-parses the on-disk candidate, so a fabricated/cleared empty
    // directory (or a size flipped to non-zero) fails closed here.
    if present_but_empty != final_reloc.directory_present_but_empty {
        blockers.push("runtime/final empty base-reloc directory mismatch".to_string());
    }
    if reloc.dynamic_base != final_reloc.dynamic_base {
        blockers.push("runtime/final DYNAMIC_BASE mismatch".to_string());
    }
    if reloc.runtime_image_base != final_reloc.runtime_image_base
        || reloc.preferred_image_base != final_reloc.preferred_image_base
    {
        blockers.push("runtime/final image base metadata mismatch".to_string());
    }
    let state_text = if blockers.is_empty() {
        if directory_absent {
            "no-reloc state observed and preserved (directory absent)".to_string()
        } else if present_but_empty {
            "no-reloc state observed and preserved (directory present but empty)".to_string()
        } else {
            "no-reloc state observed and preserved".to_string()
        }
    } else {
        "no-reloc state NOT preserved (fail-closed)".to_string()
    };
    NoRelocStateEvidence {
        directory_absent,
        directory_present_but_empty: present_but_empty,
        relocs_stripped: reloc.relocs_stripped,
        dynamic_base: reloc.dynamic_base,
        runtime_image_base: reloc.runtime_image_base,
        preferred_image_base: reloc.preferred_image_base,
        state_text,
        blockers,
    }
}

/// Final relocation facts re-parsed from the candidate's own PE header
/// (GTO-H4-D: never trust the dump object; the D2.2-4 cross-check must use
/// the on-disk candidate). `image_base_changed` alone is insufficient — a
/// no-reloc candidate keeps RELOCS_STRIPPED and an absent directory even
/// when its image base equals the runtime base.
pub(crate) struct NoRelocFinalState {
    pub image_base_changed: bool,
    pub directory_absent: bool,
    pub directory_present_but_empty: bool,
    pub relocs_stripped: bool,
    pub dynamic_base: bool,
    pub runtime_image_base: u64,
    pub preferred_image_base: u64,
}

pub(crate) fn write_exception_evidence(
    protected_input: &Path,
    candidate: &Path,
    report: &mida_pe::DumpProcessReport,
    family: &str,
    final_reloc: &NoRelocFinalState,
) -> anyhow::Result<PathBuf> {
    let sidecar = sidecar_path(candidate)?;
    let value = build_exception_evidence(protected_input, candidate, report, family, final_reloc)?;
    if !value.prerequisite_passes {
        let reason = value.blockers.join("; ");
        return Err(anyhow!(
            "refusing to write exception evidence sidecar: {reason}"
        ));
    }
    ensure_sidecar_is_safe(&sidecar, protected_input, candidate)?;
    let json = serde_json::to_vec_pretty(&value).context("serialize exception evidence sidecar")?;
    atomic_write(&sidecar, &json)?;
    Ok(sidecar)
}

pub(crate) fn build_exception_evidence(
    protected_input: &Path,
    candidate: &Path,
    report: &mida_pe::DumpProcessReport,
    family: &str,
    final_reloc: &NoRelocFinalState,
) -> anyhow::Result<ExceptionEvidenceSidecar> {
    let schema_version = super::evidence_schema::member_schema_for_family(
        family,
        super::evidence_schema::EvidenceMemberKind::Exception,
    )
    .map_err(anyhow::Error::msg)?
    .to_string();
    if same_file(protected_input, candidate)? {
        return Err(anyhow!("protected input and candidate are the same file"));
    }
    let (_, protected_identity) = read_artifact(protected_input).with_context(|| {
        format!(
            "read protected input for exception evidence: {}",
            protected_input.display()
        )
    })?;
    let (candidate_bytes, candidate_identity) = read_artifact(candidate).with_context(|| {
        format!(
            "read candidate for exception evidence: {}",
            candidate.display()
        )
    })?;

    let runtime = runtime_to_evidence(&report.exception_report);
    let actual_present = report.exception_report.directory_present;
    let actual_complete = report.exception_report.is_complete();

    // Independent final decode (L4): fresh reparse from candidate bytes.
    let decoder = ExceptionFinalDecoder::from_candidate_bytes(&candidate_bytes)
        .map_err(|e| anyhow!("final exception decode: {e}"))?;
    let final_report = decoder.decode();
    let final_candidate = final_to_evidence(&final_report);
    let preservation = preservation_to_evidence(&mida_pe::compare_runtime_final(
        &report.exception_report,
        &final_report,
    ));
    let nrs = no_reloc_state(&report.relocation_report, final_reloc);

    let mut blockers = Vec::new();
    if report.exception_evidence_present != actual_present {
        blockers.push(
            "exception_evidence_present disagrees with exception_report presence".to_string(),
        );
    }
    if report.exception_evidence_complete != actual_complete {
        blockers.push(
            "exception_evidence_complete disagrees with exception_report blockers".to_string(),
        );
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
            .exception_report
            .blockers
            .iter()
            .map(|item| format!("runtime: {item}")),
    );
    blockers.extend(
        final_report
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
    blockers.extend(nrs.blockers.iter().map(|item| format!("no-reloc: {item}")));
    stable_blockers(&mut blockers);
    let all_preserved = preservation.all_preserved;

    Ok(ExceptionEvidenceSidecar {
        schema_version,
        protected_input: protected_identity,
        candidate: candidate_identity,
        runtime,
        final_candidate,
        preservation,
        no_reloc_state: nrs,
        reported_exception_evidence_present: report.exception_evidence_present,
        reported_exception_evidence_complete: report.exception_evidence_complete,
        runtime_evidence_present: actual_present,
        runtime_evidence_complete: actual_complete,
        prerequisite_passes: blockers.is_empty() && all_preserved,
        blockers,
    })
}

fn stable_blockers(blockers: &mut Vec<String>) {
    blockers.sort();
    blockers.dedup();
}

fn sidecar_path(candidate: &Path) -> anyhow::Result<PathBuf> {
    let file_name = candidate
        .file_name()
        .ok_or_else(|| anyhow!("candidate path has no file name"))?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(".exception_evidence.json");
    Ok(candidate.with_file_name(sidecar_name))
}

fn read_artifact(path: &Path) -> anyhow::Result<(Vec<u8>, ArtifactIdentity)> {
    let bytes = fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = format!("{:x}", hasher.finalize());
    let identity = ArtifactIdentity {
        path: path.to_string_lossy().into_owned(),
        sha256: digest,
        size_bytes: bytes.len() as u64,
    };
    Ok((bytes, identity))
}

fn same_file(left: &Path, right: &Path) -> anyhow::Result<bool> {
    if fs::canonicalize(left).ok() == fs::canonicalize(right).ok() {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        Ok(windows_file_identity(left)? == windows_file_identity(right)?)
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
        return Err(anyhow!("exception sidecar destination is a directory"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("exception sidecar destination has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create exception sidecar directory {}", parent.display()))?;
    let temp = create_temp_file(
        parent,
        destination.file_name().unwrap_or_default(),
        contents,
    )?;
    if let Err(error) = atomic_replace(&temp, destination) {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| {
            format!(
                "atomically replace exception sidecar {}",
                destination.display()
            )
        });
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
                return Err(error).with_context(|| {
                    format!("create temporary exception sidecar {}", path.display())
                })
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
                .with_context(|| format!("write temporary exception sidecar {}", path.display()));
        }
        return Ok(path);
    }
    Err(anyhow!(
        "could not create a unique temporary file in {}",
        parent.display()
    ))
}

fn atomic_replace(source: &Path, destination: &Path) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        let result = std::fs::rename(source, destination);
        match result {
            Ok(()) => Ok(()),
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists
                    || error.kind() == io::ErrorKind::PermissionDenied =>
            {
                fs::remove_file(destination).with_context(|| {
                    format!("remove stale exception sidecar {}", destination.display())
                })?;
                fs::rename(source, destination)
                    .with_context(|| format!("replace exception sidecar {}", destination.display()))
            }
            Err(error) => Err(error)
                .with_context(|| format!("replace exception sidecar {}", destination.display())),
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, destination)
            .with_context(|| format!("replace exception sidecar {}", destination.display()))
    }
}

fn ensure_sidecar_is_safe(
    sidecar: &Path,
    protected_input: &Path,
    candidate: &Path,
) -> anyhow::Result<()> {
    if sidecar.exists() && (same_file(sidecar, protected_input)? || same_file(sidecar, candidate)?)
    {
        return Err(anyhow!(
            "exception sidecar aliases a source artifact: {}",
            sidecar.display()
        ));
    }
    if sidecar.is_dir() {
        return Err(anyhow!(
            "exception sidecar destination is a directory: {}",
            sidecar.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_reloc_absent_state_uses_frozen_wording() {
        let _runtime = ExceptionObservationReport {
            directory_present: false,
            directory_rva: 0,
            directory_size: 0,
            pe32_plus: true,
            runtime_image_base: 0x7ff600000000,
            preferred_image_base: 0x140000000,
            size_of_image: 0x1000,
            directory_bytes_read: 0,
            function_count: 0,
            functions: Vec::new(),
            unwind_infos: Vec::new(),
            sorted_by_begin: true,
            no_overlap: true,
            handlers_in_executable: true,
            blockers: Vec::new(),
        };
        let reloc = mida_pe::relocation_observation::RelocationObservationReport {
            directory_present: false,
            pe32_plus: true,
            pointer_size: 8,
            runtime_image_base: 0x7ff600000000,
            preferred_image_base: 0x140000000,
            size_of_image: 0x1000,
            directory_rva: 0,
            directory_size: 0,
            directory_bytes_read: 0,
            dynamic_base: false,
            relocs_stripped: true,
            block_count: 0,
            entry_count: 0,
            non_absolute_entry_count: 0,
            observed_types: Vec::new(),
            targets: Vec::new(),
            blockers: Vec::new(),
        };
        let final_reloc = NoRelocFinalState {
            image_base_changed: false,
            directory_absent: true,
            directory_present_but_empty: false,
            relocs_stripped: reloc.relocs_stripped,
            dynamic_base: reloc.dynamic_base,
            runtime_image_base: reloc.runtime_image_base,
            preferred_image_base: reloc.preferred_image_base,
        };
        let nrs = no_reloc_state(&reloc, &final_reloc);
        assert_eq!(
            nrs.state_text,
            "no-reloc state observed and preserved (directory absent)"
        );
        assert!(nrs.blockers.is_empty());
        assert!(
            !nrs.state_text.contains("PASS"),
            "never emit relocation PASS"
        );
    }

    #[test]
    fn empty_directory_mismatch_fails_closed() {
        // Runtime observed "directory present but empty"; the final candidate
        // claims the directory is absent (fabricated/cleared). The D2.2-4
        // empty-directory axis must fail closed.
        let reloc = mida_pe::relocation_observation::RelocationObservationReport {
            directory_present: true,
            pe32_plus: true,
            pointer_size: 8,
            runtime_image_base: 0x7ff600000000,
            preferred_image_base: 0x140000000,
            size_of_image: 0x1000,
            directory_rva: 0x2000,
            directory_size: 0,
            directory_bytes_read: 0,
            dynamic_base: false,
            relocs_stripped: false,
            block_count: 0,
            entry_count: 0,
            non_absolute_entry_count: 0,
            observed_types: Vec::new(),
            targets: Vec::new(),
            blockers: Vec::new(),
        };
        let final_reloc = NoRelocFinalState {
            image_base_changed: false,
            directory_absent: true, // final says absent; runtime says present-but-empty
            directory_present_but_empty: false,
            relocs_stripped: reloc.relocs_stripped,
            dynamic_base: reloc.dynamic_base,
            runtime_image_base: reloc.runtime_image_base,
            preferred_image_base: reloc.preferred_image_base,
        };
        let nrs = no_reloc_state(&reloc, &final_reloc);
        assert!(
            nrs.blockers
                .iter()
                .any(|b| b.contains("empty base-reloc directory mismatch")),
            "empty-directory axis must fail closed: {:?}",
            nrs.blockers
        );
        assert!(
            nrs.state_text.contains("NOT preserved"),
            "state text must be fail-closed wording"
        );
    }

    #[test]
    fn dynamic_base_without_relocation_is_blocker() {
        let _runtime = ExceptionObservationReport {
            directory_present: false,
            directory_rva: 0,
            directory_size: 0,
            pe32_plus: true,
            runtime_image_base: 0x7ff600000000,
            preferred_image_base: 0x140000000,
            size_of_image: 0x1000,
            directory_bytes_read: 0,
            function_count: 0,
            functions: Vec::new(),
            unwind_infos: Vec::new(),
            sorted_by_begin: true,
            no_overlap: true,
            handlers_in_executable: true,
            blockers: Vec::new(),
        };
        let reloc = mida_pe::relocation_observation::RelocationObservationReport {
            directory_present: false,
            pe32_plus: true,
            pointer_size: 8,
            runtime_image_base: 0x7ff600000000,
            preferred_image_base: 0x140000000,
            size_of_image: 0x1000,
            directory_rva: 0,
            directory_size: 0,
            directory_bytes_read: 0,
            dynamic_base: true,
            relocs_stripped: false,
            block_count: 0,
            entry_count: 0,
            non_absolute_entry_count: 0,
            observed_types: Vec::new(),
            targets: Vec::new(),
            blockers: Vec::new(),
        };
        let final_reloc = NoRelocFinalState {
            image_base_changed: false,
            directory_absent: true,
            directory_present_but_empty: false,
            relocs_stripped: reloc.relocs_stripped,
            dynamic_base: reloc.dynamic_base,
            runtime_image_base: reloc.runtime_image_base,
            preferred_image_base: reloc.preferred_image_base,
        };
        let nrs = no_reloc_state(&reloc, &final_reloc);
        assert!(!nrs.blockers.is_empty());
        assert!(nrs.blockers.iter().any(|b| b.contains("dynamic base")));
    }
}
