//! Candidate-bound Oreans IAT evidence.
//!
//! This module binds immutable live IAT observations to the exact protected
//! input and the exact final candidate bytes serialized on disk. It is
//! diagnostic evidence only; acceptance remains in the separate gate.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use mida_pe::{
    parse_final_import_identities, FinalImportIdentity, IatRecoveryReport, IatSlotReport,
    IatSlotStatus, PeHeader,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IatSlotEvidence {
    pub slot_index: usize,
    pub slot_address: u64,
    pub slot_rva: Option<u32>,
    pub observed_value: Option<u64>,
    pub rebuilt_value: Option<u64>,
    pub slot_value: Option<u64>,
    pub status: String,
    /// Deterministic root-cause reason for a non-resolved slot, when known.
    /// Absent on resolved/zero-terminator slots; `None` on a non-resolved slot
    /// means pending live confirmation.
    pub unresolved_reason: Option<String>,
    pub module_name: Option<String>,
    pub function_name: Option<String>,
    pub ordinal: Option<u16>,
}

/// Stable per-reason counts over a recovery report's non-resolved slots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IatReasonCounts {
    /// Map from unresolved reason to count.  Keys are the stable `as_str()`
    /// identifiers.  The `unknown` reason, if present, is never folded away.
    pub by_reason: BTreeMap<String, usize>,
    /// Non-resolved slots whose reason could not be established without a live
    /// run.  These are never fabricated or counted as `unknown`.
    pub pending_live_confirmation: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalImportEvidence {
    pub slot_rva: u32,
    pub module_name: String,
    pub function_name: Option<String>,
    pub ordinal: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IatReportEvidence {
    pub requested_bytes: usize,
    pub bytes_read: usize,
    pub slot_size: usize,
    pub slots: Vec<IatSlotEvidence>,
    /// Stable per-reason counts over the non-resolved slots.
    pub unresolved_reason_counts: IatReasonCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IatEvidenceSidecar {
    pub schema_version: String,
    pub protected_input: ArtifactIdentity,
    pub candidate: ArtifactIdentity,
    pub fix_imports_requested: bool,
    pub iat_evidence_present: bool,
    pub iat_evidence_complete: bool,
    pub iat_report: Option<IatReportEvidence>,
    pub final_imports: Vec<FinalImportEvidence>,
    pub prerequisite_passes: bool,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
}

pub(crate) fn build_iat_evidence(
    protected_input: &Path,
    candidate: &Path,
    report: &mida_pe::DumpProcessReport,
    family: &str,
) -> anyhow::Result<IatEvidenceSidecar> {
    let schema_version = super::evidence_schema::member_schema_for_family(
        family,
        super::evidence_schema::EvidenceMemberKind::Iat,
    )
    .map_err(anyhow::Error::msg)?
    .to_string();
    let (_, protected_identity) = read_artifact(protected_input).with_context(|| {
        format!(
            "read protected input for IAT evidence: {}",
            protected_input.display()
        )
    })?;
    let (candidate_bytes, candidate_identity) = read_artifact(candidate)
        .with_context(|| format!("read candidate for IAT evidence: {}", candidate.display()))?;

    let parsed_final = parse_final_import_identities(&candidate_bytes);
    let final_imports = parsed_final
        .as_ref()
        .map(|items| items.iter().map(final_import_to_evidence).collect())
        .unwrap_or_default();
    let actual_present = report.iat_report.is_some();
    let actual_complete = report
        .iat_report
        .as_ref()
        .is_some_and(IatRecoveryReport::is_complete);
    let report_evidence = report.iat_report.as_ref().map(iat_report_to_evidence);

    let mut blockers = Vec::new();
    if !report.fix_imports_requested {
        blockers.push("fix_imports_requested=false".to_string());
    }
    if report.iat_evidence_present != actual_present {
        blockers.push("iat_evidence_present disagrees with iat_report presence".to_string());
    }
    if report.iat_evidence_complete != actual_complete {
        blockers.push("iat_evidence_complete disagrees with structured report".to_string());
    }
    let Some(iat_report) = report.iat_report.as_ref() else {
        blockers.push("iat_report missing".to_string());
        return Ok(IatEvidenceSidecar {
            schema_version: schema_version.clone(),
            protected_input: protected_identity,
            candidate: candidate_identity,
            fix_imports_requested: report.fix_imports_requested,
            iat_evidence_present: actual_present,
            iat_evidence_complete: actual_complete,
            iat_report: report_evidence,
            final_imports,
            prerequisite_passes: false,
            blocker: Some(blockers.join("; ")),
        });
    };
    if !actual_complete {
        blockers.push(format!(
            "live IAT report incomplete: {}",
            iat_report.failure_summary()
        ));
    }
    if let Err(error) = &parsed_final {
        blockers.push(format!("final candidate import parser failed: {error}"));
    }

    if parsed_final.is_ok() {
        compare_live_report_to_candidate(
            iat_report,
            &candidate_bytes,
            &parsed_final,
            &mut blockers,
        );
    }

    let prerequisite_passes = blockers.is_empty();
    Ok(IatEvidenceSidecar {
        schema_version: schema_version.clone(),
        protected_input: protected_identity,
        candidate: candidate_identity,
        fix_imports_requested: report.fix_imports_requested,
        iat_evidence_present: actual_present,
        iat_evidence_complete: actual_complete,
        iat_report: report_evidence,
        final_imports,
        prerequisite_passes,
        blocker: (!prerequisite_passes).then(|| blockers.join("; ")),
    })
}

pub(crate) fn write_iat_evidence(
    protected_input: &Path,
    candidate: &Path,
    report: &mida_pe::DumpProcessReport,
    family: &str,
) -> anyhow::Result<PathBuf> {
    let sidecar = sidecar_path(candidate)?;
    let sidecar_value = build_iat_evidence(protected_input, candidate, report, family)?;
    ensure_sidecar_is_safe(&sidecar, protected_input, candidate)?;
    let mut json =
        serde_json::to_vec_pretty(&sidecar_value).context("serialize IAT evidence sidecar")?;
    json.push(b'\n');
    atomic_write(&sidecar, &json)?;
    Ok(sidecar)
}

fn compare_live_report_to_candidate(
    report: &IatRecoveryReport,
    candidate_bytes: &[u8],
    parsed_final: &Result<Vec<FinalImportIdentity>, mida_pe::PeError>,
    blockers: &mut Vec<String>,
) {
    let Ok(final_imports) = parsed_final else {
        return;
    };
    let mut final_by_rva = BTreeMap::new();
    for item in final_imports {
        if final_by_rva.insert(item.slot_rva, item).is_some() {
            blockers.push(format!("duplicate final slot RVA {:#x}", item.slot_rva));
        }
    }
    let resolved: Vec<&IatSlotReport> = report
        .slots
        .iter()
        .filter(|slot| slot.status == IatSlotStatus::Resolved)
        .collect();
    if final_by_rva.len() != resolved.len() {
        blockers.push(format!(
            "final/resolved slot count mismatch: final={}, resolved={}",
            final_by_rva.len(),
            resolved.len()
        ));
    }
    for slot in &report.slots {
        if slot.slot_value != slot.observed_value {
            blockers.push(format!(
                "observed alias mismatch at slot {}",
                slot.slot_index
            ));
        }
        match slot.status {
            IatSlotStatus::Resolved => {
                let Some(slot_rva) = slot.slot_rva else {
                    blockers.push(format!(
                        "resolved slot {} missing slot_rva",
                        slot.slot_index
                    ));
                    continue;
                };
                let Some(final_item) = final_by_rva.get(&slot_rva) else {
                    blockers.push(format!("missing final import slot RVA {slot_rva:#x}"));
                    continue;
                };
                let live_module = slot
                    .module_name
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if live_module.is_empty() || live_module != final_item.module_name {
                    blockers.push(format!(
                        "module identity mismatch at slot RVA {slot_rva:#x}"
                    ));
                }
                let live_name = slot.function_name.as_deref();
                let live_ordinal = slot.ordinal;
                if live_name.is_some() == live_ordinal.is_some() {
                    blockers.push(format!(
                        "live identity is not exactly-one at slot RVA {slot_rva:#x}"
                    ));
                }
                if live_name != final_item.function_name.as_deref()
                    || live_ordinal != final_item.ordinal
                {
                    blockers.push(format!(
                        "function/ordinal identity mismatch at slot RVA {slot_rva:#x}"
                    ));
                }
            }
            IatSlotStatus::ZeroTerminator => {
                let Some(slot_rva) = slot.slot_rva else {
                    blockers.push(format!(
                        "zero terminator slot {} missing slot_rva",
                        slot.slot_index
                    ));
                    continue;
                };
                if let Err(error) =
                    ensure_candidate_slot_zero(candidate_bytes, slot_rva, report.slot_size)
                {
                    blockers.push(format!("zero terminator slot {slot_rva:#x}: {error}"));
                }
            }
            IatSlotStatus::Stale
            | IatSlotStatus::Unresolved
            | IatSlotStatus::ShortRead
            | IatSlotStatus::InvalidModule => {
                blockers.push(format!(
                    "live IAT slot {} status {:?}",
                    slot.slot_index, slot.status
                ));
            }
        }
    }
    for item in final_imports {
        if !resolved
            .iter()
            .any(|slot| slot.slot_rva == Some(item.slot_rva))
        {
            blockers.push(format!("extra final import slot RVA {:#x}", item.slot_rva));
        }
    }
}

fn ensure_candidate_slot_zero(bytes: &[u8], slot_rva: u32, slot_size: usize) -> anyhow::Result<()> {
    if slot_size == 0 {
        return Err(anyhow!("slot bytes out of bounds"));
    }
    let slot_size_u32 =
        u32::try_from(slot_size).map_err(|_| anyhow!("slot size does not fit in an RVA"))?;
    let slot_end_rva = slot_rva
        .checked_add(slot_size_u32)
        .ok_or_else(|| anyhow!("slot RVA overflow"))?;
    let pe = PeHeader::from_bytes(bytes).map_err(|error| anyhow!("parse candidate: {error}"))?;

    // `rva_to_offset` intentionally follows the section's virtual range. That
    // is not sufficient here: an RVA in virtual padding can still translate to
    // an in-bounds file offset even though no serialized raw bytes back it.
    let section = pe
        .sections
        .iter()
        .find(|section| {
            let Some(raw_end_rva) = section.virtual_address.checked_add(section.raw_size) else {
                return false;
            };
            section.virtual_address <= slot_rva && slot_end_rva <= raw_end_rva
        })
        .ok_or_else(|| anyhow!("slot RVA is outside a serialized raw section"))?;

    let raw_end = section
        .raw_offset
        .checked_add(section.raw_size)
        .ok_or_else(|| anyhow!("section raw range overflow"))? as usize;
    if raw_end > bytes.len() {
        return Err(anyhow!("section raw bytes out of bounds"));
    }
    let offset = section
        .raw_offset
        .checked_add(slot_rva - section.virtual_address)
        .ok_or_else(|| anyhow!("slot offset overflow"))? as usize;
    let end = offset
        .checked_add(slot_size)
        .ok_or_else(|| anyhow!("slot offset overflow"))?;
    if offset < section.raw_offset as usize || end > raw_end || end > bytes.len() {
        return Err(anyhow!("slot bytes out of serialized raw section bounds"));
    }
    if bytes[offset..end].iter().any(|byte| *byte != 0) {
        return Err(anyhow!("candidate slot bytes are not zero"));
    }
    Ok(())
}

fn iat_report_to_evidence(report: &IatRecoveryReport) -> IatReportEvidence {
    let mut slots: Vec<_> = report.slots.iter().map(slot_to_evidence).collect();
    slots.sort_by_key(|slot| (slot.slot_rva.unwrap_or(u32::MAX), slot.slot_index));
    IatReportEvidence {
        requested_bytes: report.requested_bytes,
        bytes_read: report.bytes_read,
        slot_size: report.slot_size,
        unresolved_reason_counts: reason_counts(report),
        slots,
    }
}

fn reason_counts(report: &IatRecoveryReport) -> IatReasonCounts {
    let mut by_reason = BTreeMap::new();
    let mut pending_live_confirmation = 0usize;
    for slot in &report.slots {
        if matches!(
            slot.status,
            IatSlotStatus::Resolved | IatSlotStatus::ZeroTerminator
        ) {
            continue;
        }
        match slot.unresolved_reason {
            Some(reason) => {
                *by_reason.entry(reason.as_str().to_string()).or_insert(0) += 1;
            }
            None => pending_live_confirmation += 1,
        }
    }
    IatReasonCounts {
        by_reason,
        pending_live_confirmation,
    }
}

fn slot_to_evidence(slot: &IatSlotReport) -> IatSlotEvidence {
    IatSlotEvidence {
        slot_index: slot.slot_index,
        slot_address: slot.slot_address,
        slot_rva: slot.slot_rva,
        observed_value: slot.observed_value,
        rebuilt_value: slot.rebuilt_value,
        slot_value: slot.slot_value,
        status: status_name(slot.status).to_string(),
        unresolved_reason: slot.unresolved_reason.map(|r| r.as_str().to_string()),
        module_name: slot.module_name.clone(),
        function_name: slot.function_name.clone(),
        ordinal: slot.ordinal,
    }
}

fn final_import_to_evidence(item: &FinalImportIdentity) -> FinalImportEvidence {
    FinalImportEvidence {
        slot_rva: item.slot_rva,
        module_name: item.module_name.clone(),
        function_name: item.function_name.clone(),
        ordinal: item.ordinal,
    }
}

fn status_name(status: IatSlotStatus) -> &'static str {
    match status {
        IatSlotStatus::Resolved => "Resolved",
        IatSlotStatus::Stale => "Stale",
        IatSlotStatus::Unresolved => "Unresolved",
        IatSlotStatus::ShortRead => "ShortRead",
        IatSlotStatus::InvalidModule => "InvalidModule",
        IatSlotStatus::ZeroTerminator => "ZeroTerminator",
    }
}

fn read_artifact(path: &Path) -> anyhow::Result<(Vec<u8>, ArtifactIdentity)> {
    let bytes = fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = format!("{:064x}", hasher.finalize());
    let size_bytes = bytes.len() as u64;
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
    let file_name = candidate
        .file_name()
        .ok_or_else(|| anyhow!("candidate path has no file name"))?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(".iat_evidence.json");
    Ok(candidate.with_file_name(sidecar_name))
}

fn ensure_sidecar_is_safe(
    sidecar: &Path,
    protected_input: &Path,
    candidate: &Path,
) -> anyhow::Result<()> {
    for source in [protected_input, candidate] {
        if sidecar.exists() && same_file(sidecar, source)? {
            return Err(anyhow!(
                "refusing to replace sidecar {} because it aliases {}",
                sidecar.display(),
                source.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn same_file(left: &Path, right: &Path) -> anyhow::Result<bool> {
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
    use std::fs::OpenOptions;
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
        fn get_file_information_by_handle_iat(
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
    let ok = unsafe { get_file_information_by_handle_iat(file.as_raw_handle(), &mut info) };
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
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("sidecar destination has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create sidecar directory {}", parent.display()))?;
    let temp = create_temp_file(
        parent,
        destination.file_name().unwrap_or_default(),
        contents,
    )?;
    if let Err(error) = atomic_replace(&temp, destination) {
        let _ = fs::remove_file(&temp);
        return Err(error)
            .with_context(|| format!("atomically replace sidecar {}", destination.display()));
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
                    .with_context(|| format!("create temporary sidecar {}", path.display()))
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
                .with_context(|| format!("sync temporary sidecar {}", path.display()));
        }
        return Ok(path);
    }
    Err(anyhow!("unable to allocate unique temporary sidecar"))
}

#[cfg(unix)]
fn atomic_replace(temp: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temp, destination)
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
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
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

#[cfg(not(any(unix, windows)))]
fn atomic_replace(temp: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temp, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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
            std::env::temp_dir().join(format!("mida-iat-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        TempDirGuard(path)
    }

    fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn rva_off(rva: u32) -> usize {
        0x200 + (rva - 0x1000) as usize
    }

    fn minimal_candidate(two_slots: bool, ordinal: bool, function: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x1200];
        buf[0..2].copy_from_slice(b"MZ");
        put_u32(&mut buf, 60, 0x40);
        let nt = 0x40usize;
        buf[nt..nt + 4].copy_from_slice(b"PE\0\0");
        put_u32(&mut buf, nt + 4, 0x0000_8664);
        buf[nt + 6..nt + 8].copy_from_slice(&1u16.to_le_bytes());
        buf[nt + 20..nt + 22].copy_from_slice(&0xf0u16.to_le_bytes());
        buf[nt + 22..nt + 24].copy_from_slice(&0x22u16.to_le_bytes());
        let oh = nt + 24;
        buf[oh..oh + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        put_u32(&mut buf, oh + 16, 0x1000);
        put_u64(&mut buf, oh + 24, 0x1400_0000_0);
        put_u32(&mut buf, oh + 32, 0x1000);
        put_u32(&mut buf, oh + 36, 0x200);
        put_u32(&mut buf, oh + 56, 0x2000);
        put_u32(&mut buf, oh + 60, 0x200);
        put_u32(&mut buf, oh + 108, 16);
        put_u32(&mut buf, oh + 112 + 8, 0x1100);
        put_u32(&mut buf, oh + 112 + 12, if two_slots { 0x28 } else { 0x28 });
        let sh = nt + 24 + 0xf0;
        buf[sh..sh + 6].copy_from_slice(b".idata");
        put_u32(&mut buf, sh + 8, 0x1000);
        put_u32(&mut buf, sh + 12, 0x1000);
        put_u32(&mut buf, sh + 16, 0x1000);
        put_u32(&mut buf, sh + 20, 0x200);
        put_u32(&mut buf, sh + 36, 0xc000_0040);

        let desc = rva_off(0x1100);
        put_u32(&mut buf, desc, 0x1140);
        put_u32(&mut buf, desc + 12, 0x1180);
        put_u32(&mut buf, desc + 16, 0x1150);
        let lookup = rva_off(0x1140);
        let iat = rva_off(0x1150);
        let value = if ordinal {
            0x8000_0000_0000_0000u64
        } else {
            0x1190
        };
        put_u64(&mut buf, lookup, value);
        put_u64(&mut buf, iat, value);
        if two_slots {
            put_u64(
                &mut buf,
                lookup + 8,
                if ordinal {
                    0x8000_0000_0000_0000
                } else {
                    0x1190
                },
            );
            put_u64(
                &mut buf,
                iat + 8,
                if ordinal {
                    0x8000_0000_0000_0000
                } else {
                    0x1190
                },
            );
        }
        buf[rva_off(0x1180)..rva_off(0x1180) + 13].copy_from_slice(b"KERNEL32.dll\0");
        put_u32(&mut buf, rva_off(0x1190), 0);
        buf[rva_off(0x1192)..rva_off(0x1192) + function.len()].copy_from_slice(function);
        buf
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

    fn report_for(count: usize, ordinal: bool, function: &str) -> mida_pe::DumpProcessReport {
        let mut slots = Vec::new();
        for index in 0..count {
            slots.push(IatSlotReport {
                slot_index: index,
                slot_address: 0x1400_0000 + 0x1150 + (index as u64 * 8),
                slot_rva: Some(0x1150 + (index as u32 * 8)),
                observed_value: Some(0x7fff_0000_1000 + index as u64),
                rebuilt_value: Some(0x7fff_0000_1000 + index as u64),
                slot_value: Some(0x7fff_0000_1000 + index as u64),
                status: IatSlotStatus::Resolved,
                unresolved_reason: None,
                module_name: Some("KERNEL32.DLL".into()),
                function_name: (!ordinal).then(|| function.to_string()),
                ordinal: ordinal.then_some(0),
            });
        }
        slots.push(IatSlotReport {
            slot_index: count,
            slot_address: 0x1400_0000 + 0x1150 + (count as u64 * 8),
            slot_rva: Some(0x1150 + (count as u32 * 8)),
            observed_value: Some(0),
            rebuilt_value: None,
            slot_value: Some(0),
            status: IatSlotStatus::ZeroTerminator,
            unresolved_reason: None,
            module_name: None,
            function_name: None,
            ordinal: None,
        });
        let requested_bytes = (count + 1) * 8;
        mida_pe::DumpProcessReport {
            fix_imports_requested: true,
            iat_evidence_present: true,
            iat_evidence_complete: true,
            iat_report: Some(IatRecoveryReport {
                requested_bytes,
                bytes_read: requested_bytes,
                slot_size: 8,
                slots,
            }),
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
            output_size: 0,
        }
    }

    fn write_pair(dir: &Path, candidate_bytes: &[u8]) -> (PathBuf, PathBuf) {
        let protected = dir.join("protected.exe");
        let candidate = dir.join("candidate.exe");
        fs::write(&protected, b"protected-input").unwrap();
        fs::write(&candidate, candidate_bytes).unwrap();
        (protected, candidate)
    }

    #[test]
    fn happy_path_preserves_structured_report_and_function_case() {
        let dir = temp_dir("happy");
        let bytes = minimal_candidate(false, false, b"ExitProcess\0");
        let (protected, candidate) = write_pair(&dir, &bytes);
        let report = report_for(1, false, "ExitProcess");
        let sidecar =
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert!(sidecar.prerequisite_passes, "{:?}", sidecar.blocker);
        let evidence = sidecar.iat_report.unwrap();
        assert_eq!(evidence.requested_bytes, 16);
        assert_eq!(evidence.bytes_read, 16);
        assert_eq!(evidence.slot_size, 8);
        assert_eq!(evidence.slots.len(), 2);
        assert_eq!(sidecar.final_imports[0].module_name, "kernel32.dll");
        assert_eq!(
            sidecar.final_imports[0].function_name.as_deref(),
            Some("ExitProcess")
        );
        assert_eq!(
            sidecar.protected_input.size_bytes,
            b"protected-input".len() as u64
        );
    }

    #[test]
    fn module_case_normalizes_but_function_case_is_exact() {
        let dir = temp_dir("case");
        let (protected, candidate) =
            write_pair(&dir, &minimal_candidate(false, false, b"ExitProcess\0"));
        let mut report = report_for(1, false, "ExitProcess");
        report.iat_report.as_mut().unwrap().slots[0].module_name = Some("kernel32.dll".into());
        assert!(
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida")
                .unwrap()
                .prerequisite_passes
        );
        report.iat_report.as_mut().unwrap().slots[0].function_name = Some("exitprocess".into());
        assert!(
            !build_iat_evidence(&protected, &candidate, &report, "oreans_themida")
                .unwrap()
                .prerequisite_passes
        );
    }

    #[test]
    fn ordinal_zero_is_first_class() {
        let dir = temp_dir("ordinal0");
        let (protected, candidate) = write_pair(&dir, &minimal_candidate(false, true, b"Unused\0"));
        let report = report_for(1, true, "Unused");
        let sidecar =
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert!(sidecar.prerequisite_passes, "{:?}", sidecar.blocker);
        assert_eq!(sidecar.final_imports[0].ordinal, Some(0));
    }

    #[test]
    fn zero_terminator_must_be_inside_serialized_raw_section() {
        let mut virtual_padding = minimal_candidate(false, false, b"ExitProcess\0");
        let section_header = 0x40 + 24 + 0xf0;
        // The section remains 0x1000 bytes on disk but has a larger virtual
        // extent. A virtual-padding RVA must not be accepted as raw bytes.
        put_u32(&mut virtual_padding, section_header + 8, 0x2000);
        virtual_padding.resize(0x1300, 0);
        assert!(ensure_candidate_slot_zero(&virtual_padding, 0x2000, 8).is_err());

        // A slot in the PE header is not backed by any section raw data.
        let header_slot = minimal_candidate(false, false, b"ExitProcess\0");
        assert!(ensure_candidate_slot_zero(&header_slot, 0x200, 8).is_err());

        let mut raw_boundary = minimal_candidate(false, false, b"ExitProcess\0");
        // Keep the file larger than the raw section so a file-length-only
        // check would incorrectly accept this crossing slot.
        put_u32(&mut raw_boundary, section_header + 16, 0x800);
        assert!(ensure_candidate_slot_zero(&raw_boundary, 0x17fc, 8).is_err());
    }

    #[test]
    fn report_presence_and_completeness_diagnostics_are_recomputed() {
        let dir = temp_dir("diagnostics");
        let (protected, candidate) =
            write_pair(&dir, &minimal_candidate(false, false, b"ExitProcess\0"));
        let mut report = report_for(1, false, "ExitProcess");
        report.iat_evidence_present = false;
        report.iat_evidence_complete = false;
        let sidecar =
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert!(sidecar.iat_evidence_present);
        assert!(sidecar.iat_evidence_complete);
        assert!(!sidecar.prerequisite_passes);
        assert!(sidecar.blocker.as_deref().unwrap().contains("disagrees"));
        report.iat_report.as_mut().unwrap().bytes_read = 8;
        report.iat_evidence_complete = true;
        let sidecar =
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert!(!sidecar.iat_evidence_complete);
        assert!(!sidecar.prerequisite_passes);
    }

    #[test]
    fn unresolved_live_slots_fail_closed_and_never_count_as_resolved() {
        // P8-D Lunlun negative-case semantics: a live IAT with an Unresolved
        // slot must not be accepted. The producer must mark it as a blocker
        // (fail-closed), and the Unresolved slot must never be turned into a
        // resolved import. This matches the gate contract and keeps protection-
        // induced unresolved imports visible instead of masked.
        let dir = temp_dir("unresolved-lunlun");
        let (protected, candidate) =
            write_pair(&dir, &minimal_candidate(false, false, b"ExitProcess\0"));
        let mut report = report_for(1, false, "ExitProcess");
        // Turn slot 0 into an Unresolved slot (observed but not rebuilt).
        report.iat_report.as_mut().unwrap().slots[0].status = IatSlotStatus::Unresolved;
        report.iat_report.as_mut().unwrap().slots[0].rebuilt_value = None;
        report.iat_report.as_mut().unwrap().slots[0].module_name = None;
        report.iat_report.as_mut().unwrap().slots[0].function_name = None;

        let sidecar =
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert!(!sidecar.prerequisite_passes);
        let blocker = sidecar.blocker.as_deref().unwrap();
        assert!(
            blocker.contains("Unresolved") || blocker.contains("unresolved"),
            "Unresolved live slot must appear as a blocker, got: {blocker}"
        );
        // The final-import table may still parse, but it must NOT gain a fake
        // import for the unresolved slot beyond what the candidate holds.
        assert!(
            sidecar.final_imports.is_empty() || sidecar.final_imports.len() == 1,
            "unresolved must not fabricate imports"
        );
    }

    #[test]
    fn resolved_live_slot_maps_one_to_one_to_final_import() {
        // P8-D: a Resolved live slot must map to exactly one final import with
        // matching module/function (producer-side, gate contract mirror).
        let dir = temp_dir("resolved-map");
        let (protected, candidate) =
            write_pair(&dir, &minimal_candidate(false, false, b"ExitProcess\0"));
        let report = report_for(1, false, "ExitProcess");
        let sidecar =
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert!(sidecar.prerequisite_passes, "{:?}", sidecar.blocker);
        let evidence = sidecar.iat_report.unwrap();
        let resolved = evidence
            .slots
            .iter()
            .filter(|s| s.status == "Resolved")
            .collect::<Vec<_>>();
        assert_eq!(resolved.len(), 1);
        assert_eq!(sidecar.final_imports.len(), 1);
        assert_eq!(
            sidecar.final_imports[0].function_name.as_deref(),
            Some("ExitProcess")
        );
    }

    #[test]
    fn short_read_and_alignment_or_coverage_fail_closed() {
        let dir = temp_dir("coverage");
        let (protected, candidate) =
            write_pair(&dir, &minimal_candidate(false, false, b"ExitProcess\0"));
        let mut report = report_for(1, false, "ExitProcess");
        let iat = report.iat_report.as_mut().unwrap();
        iat.requested_bytes = 15;
        iat.bytes_read = 14;
        iat.slots.pop();
        let sidecar =
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert!(!sidecar.prerequisite_passes);
        let blocker = sidecar.blocker.unwrap();
        assert!(
            blocker.contains("short-read")
                || blocker.contains("unaligned")
                || blocker.contains("coverage")
        );
    }

    #[test]
    fn missing_extra_and_duplicate_final_slots_fail_closed() {
        let dir = temp_dir("slots");
        let (protected, candidate_one) =
            write_pair(&dir, &minimal_candidate(false, false, b"ExitProcess\0"));
        let report_two = report_for(2, false, "ExitProcess");
        let sidecar =
            build_iat_evidence(&protected, &candidate_one, &report_two, "oreans_themida").unwrap();
        assert!(!sidecar.prerequisite_passes);
        let candidate_two = dir.join("candidate-two.exe");
        fs::write(
            &candidate_two,
            minimal_candidate(true, false, b"ExitProcess\0"),
        )
        .unwrap();
        let report_one = report_for(1, false, "ExitProcess");
        let sidecar =
            build_iat_evidence(&protected, &candidate_two, &report_one, "oreans_themida").unwrap();
        assert!(!sidecar.prerequisite_passes);
        let mut duplicate = minimal_candidate(false, false, b"ExitProcess\0");
        let desc2 = rva_off(0x1114);
        put_u32(&mut duplicate, desc2, 0x1140);
        put_u32(&mut duplicate, desc2 + 12, 0x1180);
        put_u32(&mut duplicate, desc2 + 16, 0x1150);
        let desc_end = rva_off(0x1128);
        duplicate[desc_end..desc_end + 20].fill(0);
        put_u32(&mut duplicate, 0x40 + 24 + 112 + 12, 0x3c);
        let duplicate_path = dir.join("duplicate.exe");
        fs::write(&duplicate_path, duplicate).unwrap();
        assert!(parse_final_import_identities(&fs::read(&duplicate_path).unwrap()).is_err());
    }

    #[test]
    fn ilt_iat_mismatch_and_nonzero_terminator_fail_closed() {
        let dir = temp_dir("residue");
        let (_protected, candidate) =
            write_pair(&dir, &minimal_candidate(false, false, b"ExitProcess\0"));
        let mut same_identity_different_encoding =
            minimal_candidate(false, false, b"ExitProcess\0");
        put_u32(&mut same_identity_different_encoding, rva_off(0x11a0), 0);
        same_identity_different_encoding[rva_off(0x11a2)..rva_off(0x11a2) + 12]
            .copy_from_slice(b"ExitProcess\0");
        put_u64(
            &mut same_identity_different_encoding,
            rva_off(0x1150),
            0x11a0,
        );
        let exact_encoding_error = parse_final_import_identities(&same_identity_different_encoding)
            .expect_err("same identity with different hint/name RVA must fail closed");
        assert!(exact_encoding_error
            .to_string()
            .contains("encoding mismatch"));
        let mut bytes = fs::read(&candidate).unwrap();
        put_u64(&mut bytes, rva_off(0x1150), 0x1190 + 0x20);
        fs::write(&candidate, &bytes).unwrap();
        assert!(parse_final_import_identities(&bytes).is_err());
        let mut bytes = minimal_candidate(false, false, b"ExitProcess\0");
        put_u64(&mut bytes, rva_off(0x1158), 0x1190);
        assert!(parse_final_import_identities(&bytes).is_err());
    }

    #[test]
    fn hashes_bind_disk_bytes_and_sidecar_replaces_stale_sibling() {
        let dir = temp_dir("atomic");
        let bytes = minimal_candidate(false, false, b"ExitProcess\0");
        let (protected, candidate) = write_pair(&dir, &bytes);
        let protected_before = fs::read(&protected).unwrap();
        let candidate_before = fs::read(&candidate).unwrap();
        let report = report_for(1, false, "ExitProcess");
        let sidecar_path =
            write_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        fs::write(&sidecar_path, b"stale sibling\n").unwrap();
        let replaced =
            write_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert_eq!(replaced, sidecar_path);
        let json: IatEvidenceSidecar =
            serde_json::from_slice(&fs::read(&sidecar_path).unwrap()).unwrap();
        assert_eq!(json.candidate.sha256.len(), 64);
        assert_eq!(fs::read(&protected).unwrap(), protected_before);
        assert_eq!(fs::read(&candidate).unwrap(), candidate_before);
    }

    #[test]
    fn same_path_and_hard_link_alias_are_refused() {
        let dir = temp_dir("alias");
        let bytes = minimal_candidate(false, false, b"ExitProcess\0");
        let (protected, candidate) = write_pair(&dir, &bytes);
        let report = report_for(1, false, "ExitProcess");
        let sidecar = candidate.with_file_name("candidate.exe.iat_evidence.json");
        fs::copy(&candidate, &sidecar).unwrap();
        assert!(write_iat_evidence(&sidecar, &candidate, &report, "oreans_themida").is_err());
        fs::remove_file(&sidecar).unwrap();
        fs::hard_link(&candidate, &sidecar).unwrap();
        assert!(write_iat_evidence(&protected, &candidate, &report, "oreans_themida").is_err());
    }

    #[test]
    fn sidecar_destination_failure_propagates_as_error() {
        let dir = temp_dir("write-failure");
        let bytes = minimal_candidate(false, false, b"ExitProcess\0");
        let (protected, candidate) = write_pair(&dir, &bytes);
        let report = report_for(1, false, "ExitProcess");
        let sidecar = candidate.with_file_name("candidate.exe.iat_evidence.json");
        fs::create_dir(&sidecar).unwrap();
        let result = write_iat_evidence(&protected, &candidate, &report, "oreans_themida");
        assert!(result.is_err(), "directory sidecar destination must fail");
    }

    #[test]
    fn missing_report_is_serialized_as_failed_evidence() {
        let dir = temp_dir("missing");
        let bytes = minimal_candidate(false, false, b"ExitProcess\0");
        let (protected, candidate) = write_pair(&dir, &bytes);
        let report = mida_pe::DumpProcessReport {
            fix_imports_requested: true,
            iat_evidence_present: true,
            iat_evidence_complete: false,
            iat_report: None,
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
            output_size: bytes.len(),
        };
        let sidecar =
            build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert!(!sidecar.prerequisite_passes);
        assert!(sidecar.iat_report.is_none());
    }

    /// G2-R2: the shared IAT sidecar producer emits the family-appropriate
    /// schema — `mida.oreans-iat-evidence/v1` for Oreans, `mida.unpack-iat-evidence/v1`
    /// for a generic family (ahk_gto). An unknown family fails closed.
    #[test]
    fn iat_sidecar_schema_dispatches_by_family() {
        let dir = temp_dir("iat_family");
        let bytes = minimal_candidate(false, false, b"ExitProcess\0");
        let (protected, candidate) = write_pair(&dir, &bytes);
        let report = report_for(1, false, "ExitProcess");
        let oreans = build_iat_evidence(&protected, &candidate, &report, "oreans_themida").unwrap();
        assert_eq!(oreans.schema_version, "mida.oreans-iat-evidence/v1");
        let gto = build_iat_evidence(&protected, &candidate, &report, "ahk_gto").unwrap();
        assert_eq!(gto.schema_version, "mida.unpack-iat-evidence/v1");
        // Same payload otherwise; only the schema id differs.
        assert_eq!(oreans.candidate, gto.candidate);
        assert!(build_iat_evidence(&protected, &candidate, &report, "bogus").is_err());
    }
}
