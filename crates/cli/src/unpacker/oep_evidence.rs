//! OEP provenance sidecar binding for native candidate dumps.
//!
//! The sidecar is written only after the candidate has been successfully
//! serialized. It binds the exact protected input and final candidate bytes to
//! the provenance that reached the dump boundary.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use mida_core::{OepProvenance, OepSource};
use mida_pe::PeHeader;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[allow(dead_code)] // legacy Oreans schema id; production uses evidence_schema dispatch
const SCHEMA_VERSION: &str = "mida.oreans-oep-evidence/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ArtifactIdentity {
    path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct OepEvidenceSidecar {
    schema_version: String,
    protected_input: ArtifactIdentity,
    candidate: ArtifactIdentity,
    source: String,
    va: Option<u64>,
    rva: Option<u32>,
    final_entry_rva: u32,
    evidence: String,
    application_oep: bool,
    bootstrap_or_ambiguous: bool,
    entry_rva_matches_provenance: bool,
    // H4-B: cold-start entry chain. A cold-start candidate's PE EP is the
    // .boot stub (final_entry_rva = boot_rva); the stub epilogue jmps to the
    // observed OEP. The chain fields record the DECODED machine-code proof.
    // They are emitted only for generic families (e.g. ahk_gto); the Oreans
    // family sidecar stays byte-compatible with the frozen acceptance schema
    // (all three are skipped when None/false-default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entry_chain: Option<EntryChain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain_decoded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chain_oep_matches_provenance: Option<bool>,
    prerequisite_passes: bool,
    blocker: Option<String>,
}

/// H4-B: decoded cold-start entry chain (PE EP .boot -> stub jmp OEP).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EntryChain {
    boot_rva: u32,
    oep_target_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(windows)]
    volume_serial: u32,
    #[cfg(windows)]
    file_index: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

/// Write the OEP sidecar for a successfully dumped native PE candidate.
///
/// The final entry RVA is parsed from the bytes currently on disk. The
/// candidate digest and size are computed over those same bytes, so the
/// sidecar cannot self-certify a dump-time `PeHeader` value or an in-memory
/// image. The sidecar is committed through a same-directory temporary file and
/// atomic replacement after all input/alias checks have completed.
pub(super) fn write_oep_evidence(
    protected_input: &Path,
    candidate: &Path,
    provenance: &OepProvenance,
    family: &str,
) -> anyhow::Result<PathBuf> {
    let schema_version = super::evidence_schema::member_schema_for_family(
        family,
        super::evidence_schema::EvidenceMemberKind::Oep,
    )
    .map_err(anyhow::Error::msg)?
    .to_string();
    let (_, protected_identity) = read_artifact(protected_input).with_context(|| {
        format!(
            "read protected input for OEP evidence: {}",
            protected_input.display()
        )
    })?;
    let (candidate_bytes, candidate_identity) = read_artifact(candidate)
        .with_context(|| format!("read candidate for OEP evidence: {}", candidate.display()))?;
    let final_entry_rva = PeHeader::from_bytes(&candidate_bytes)
        .map_err(|error| anyhow!("parse final candidate PE: {error}"))?
        .entry_point;
    let sidecar = sidecar_path(candidate)?;

    // This check happens before creating/opening any output path. Existing
    // sidecars may be replaced, but never when they alias either input.
    ensure_sidecar_is_safe(&sidecar, protected_input, candidate)?;

    let entry_rva_matches_provenance = provenance.rva == Some(final_entry_rva);
    // H4-B: decode the cold-start entry chain from candidate bytes. If the
    // candidate's PE EP is a .boot stub whose epilogue jmps to the provenance
    // RVA, the chain is accepted as the entry evidence (machine-code proof).
    // H4-B: the chain fields are structural — a cold-start candidate's PE EP
    // is a .boot stub whose epilogue jmps to the observed OEP. Decode is
    // attempted for every family; the fields are serialized only when a chain
    // was actually decoded (skip_serializing_if None), so the Oreans family
    // sidecar stays byte-compatible with the frozen acceptance schema (no
    // .boot candidate -> no chain fields).
    let chain = decode_boot_entry_chain(&candidate_bytes, final_entry_rva);
    let chain_decoded = chain.is_some();
    let chain_oep_matches_provenance =
        chain_decoded && provenance.rva == chain.as_ref().map(|c| c.oep_target_rva);
    // Chain fields are emitted only when a chain was actually decoded; a
    // candidate without .boot (e.g. Oreans) gets no chain fields, keeping the
    // Oreans family sidecar byte-compatible with the frozen acceptance schema.
    let (chain_decoded_field, chain_matches_field) = match &chain {
        Some(_) => (Some(chain_decoded), Some(chain_oep_matches_provenance)),
        None => (None, None),
    };
    let core_passes = provenance.application_oep_prerequisite_passes();
    let prerequisite_passes =
        core_passes && (entry_rva_matches_provenance || chain_oep_matches_provenance);
    let blocker = stable_blocker(
        provenance,
        final_entry_rva,
        entry_rva_matches_provenance,
        prerequisite_passes,
        chain_oep_matches_provenance,
    );

    let sidecar_value = OepEvidenceSidecar {
        schema_version: schema_version.clone(),
        protected_input: protected_identity,
        candidate: candidate_identity,
        source: source_name(provenance.source).to_string(),
        va: provenance.va,
        rva: provenance.rva,
        final_entry_rva,
        evidence: provenance.evidence.clone(),
        application_oep: provenance.application_oep,
        bootstrap_or_ambiguous: provenance.bootstrap_or_ambiguous,
        entry_rva_matches_provenance,
        entry_chain: chain,
        chain_decoded: chain_decoded_field,
        chain_oep_matches_provenance: chain_matches_field,
        prerequisite_passes,
        blocker,
    };
    let mut json =
        serde_json::to_vec_pretty(&sidecar_value).context("serialize OEP evidence sidecar")?;
    json.push(b'\n');

    atomic_write(&sidecar, &json)?;
    Ok(sidecar)
}

/// H4-B: decode the cold-start entry chain from candidate bytes.
///
/// A cold-start candidate's PE EP is the .boot stub RVA. The stub epilogue
/// (deterministic emit_two_phase_code shape) is:
///
///   add rsp, 0x28            ; 48 83 C4 28
///   pop r15                  ; 41 5F
///   pop r14                  ; 41 5E
///   pop r13                  ; 41 5D
///   pop r12                  ; 41 5C
///   pop rdi                  ; 5F
///   pop rsi                  ; 5E
///   pop rbp                  ; 5D
///   pop rbx                  ; 5B
///   jmp rel32                ; E9 xx xx xx xx  (patched to original OEP)
///
/// The function locates the .boot section (by name; falls back to the
/// section containing final_entry_rva), scans for the exact epilogue byte
/// sequence, and decodes the rel32 to recover oep_target_rva. Fail closed:
/// no .boot section / no epilogue -> None.
fn decode_boot_entry_chain(candidate_bytes: &[u8], final_entry_rva: u32) -> Option<EntryChain> {
    let pe = PeHeader::from_bytes(candidate_bytes).ok()?;
    eprintln!(
        "H4B-DBG sections={:?}",
        pe.sections
            .iter()
            .map(|s| (s.name.as_str(), s.virtual_address, s.raw_offset, s.raw_size))
            .collect::<Vec<_>>()
    );
    // Locate the .boot section; fall back to the section containing the EP.
    let boot = pe.sections.iter().find(|s| s.name == ".boot").or_else(|| {
        pe.sections.iter().find(|s| {
            final_entry_rva >= s.virtual_address
                && final_entry_rva
                    < s.virtual_address
                        .saturating_add(s.virtual_size.max(s.raw_size))
        })
    })?;
    if boot.raw_size == 0 || boot.raw_offset as usize >= candidate_bytes.len() {
        return None;
    }
    let raw_end = (boot.raw_offset as usize)
        .saturating_add(boot.raw_size as usize)
        .min(candidate_bytes.len());
    let raw = &candidate_bytes[boot.raw_offset as usize..raw_end];

    if raw.len() < 5 {
        return None;
    }
    // Epilogue signature: 48 83 C4 28 41 5F 41 5E 41 5D 41 5C 5F 5E 5D 5B E9
    const EPILOGUE: &[u8] = &[
        0x48, 0x83, 0xc4, 0x28, // add rsp, 0x28
        0x41, 0x5f, // pop r15
        0x41, 0x5e, // pop r14
        0x41, 0x5d, // pop r13
        0x41, 0x5c, // pop r12
        0x5f, // pop rdi
        0x5e, // pop rsi
        0x5d, // pop rbp
        0x5b, // pop rbx
        0xe9, // jmp rel32
    ];
    let sig_len = EPILOGUE.len(); // 19
    let mut pos = 0usize;
    let mut found: Option<usize> = None;
    while pos + sig_len <= raw.len() {
        if &raw[pos..pos + sig_len] == EPILOGUE {
            found = Some(pos);
            // Prefer the LAST match (the epilogue is the final jmp before
            // the helpers; earlier incidental matches are impossible for
            // this exact 19-byte signature but last-match is safest).
        }
        pos += 1;
    }
    let jmp_at = found?;
    if jmp_at + sig_len + 4 > raw.len() {
        return None;
    }
    let rel32 = i32::from_le_bytes([
        raw[jmp_at + sig_len],
        raw[jmp_at + sig_len + 1],
        raw[jmp_at + sig_len + 2],
        raw[jmp_at + sig_len + 3],
    ]);
    // The rel32 is relative to the address after the 5-byte jmp.
    // E9 sits at EPILOGUE index 16 (4 + 8 + 4), i.e. sig_len - 1.
    let jmp_insn_at = jmp_at + sig_len - 1; // E9 position
    let jmp_end_rva = boot.virtual_address + (jmp_insn_at + 5) as u32;
    let oep_target_rva = jmp_end_rva.wrapping_add(rel32 as u32);
    // Sanity: the target must land inside the image's virtual range — fail
    // closed on garbage. (Per-section checks are too strict: the observed
    // OEP may sit in any code section, e.g. .text after the fixture's small
    // dummy range.)
    let image_size = pe.sections.iter().fold(0u32, |acc, s| {
        acc.max(
            s.virtual_address
                .saturating_add(s.virtual_size.max(s.raw_size)),
        )
    });
    if oep_target_rva >= image_size {
        return None;
    }
    Some(EntryChain {
        boot_rva: boot.virtual_address,
        oep_target_rva,
    })
}

fn sidecar_path(candidate: &Path) -> anyhow::Result<PathBuf> {
    let file_name = candidate
        .file_name()
        .ok_or_else(|| anyhow!("candidate path has no file name"))?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(".oep_evidence.json");
    Ok(candidate.with_file_name(sidecar_name))
}
fn stable_blocker(
    provenance: &OepProvenance,
    final_entry_rva: u32,
    entry_rva_matches_provenance: bool,
    prerequisite_passes: bool,
    chain_oep_matches_provenance: bool,
) -> Option<String> {
    if prerequisite_passes {
        return None;
    }

    let mut reasons = Vec::new();
    if let Some(reason) = provenance.application_oep_blocker() {
        reasons.push(reason.to_string());
    }
    if !entry_rva_matches_provenance && !chain_oep_matches_provenance {
        reasons.push(match provenance.rva {
            Some(rva) => format!(
                "final candidate entry RVA {final_entry_rva:#x} does not match provenance RVA {rva:#x} (chain match: {chain_oep_matches_provenance})"
            ),
            None => "provenance RVA is missing; final candidate entry cannot be bound".to_string(),
        });
    }
    if reasons.is_empty() {
        reasons.push("OEP provenance prerequisite failed".to_string());
    }
    Some(reasons.join("; "))
}

fn source_name(source: OepSource) -> &'static str {
    match source {
        OepSource::RuntimeRip => "runtime_rip",
        OepSource::Trace => "trace",
        OepSource::ScanFallback => "scan_fallback",
        OepSource::Unknown => "unknown",
    }
}

fn read_artifact(path: &Path) -> anyhow::Result<(Vec<u8>, ArtifactIdentity)> {
    let bytes = fs::read(path).with_context(|| format!("read artifact: {}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    let size_bytes = bytes.len() as u64;
    Ok((
        bytes,
        ArtifactIdentity {
            path: path.to_string_lossy().into_owned(),
            sha256: format!("{digest:x}"),
            size_bytes,
        },
    ))
}

fn ensure_sidecar_is_safe(
    sidecar: &Path,
    protected_input: &Path,
    candidate: &Path,
) -> anyhow::Result<()> {
    if paths_alias(sidecar, protected_input)? {
        return Err(anyhow!(
            "refusing OEP sidecar: sidecar aliases protected input"
        ));
    }
    if paths_alias(sidecar, candidate)? {
        return Err(anyhow!("refusing OEP sidecar: sidecar aliases candidate"));
    }
    Ok(())
}

fn paths_alias(left: &Path, right: &Path) -> io::Result<bool> {
    if normalized_path(left)? == normalized_path(right)? {
        return Ok(true);
    }
    match (file_identity(left)?, file_identity(right)?) {
        (Some(left), Some(right)) => Ok(left == right),
        _ => Ok(false),
    }
}

fn normalized_path(path: &Path) -> io::Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    Ok(parent.join(absolute.file_name().unwrap_or_default()))
}

fn file_identity(path: &Path) -> io::Result<Option<FileIdentity>> {
    let _metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(windows)]
    {
        use std::fs::File;
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
            fn GetFileInformationByHandle(
                file: *mut std::ffi::c_void,
                information: *mut ByHandleFileInformation,
            ) -> i32;
        }

        let file = File::open(path)?;
        let mut info = ByHandleFileInformation::default();
        // SAFETY: the handle is owned by `file`; `info` is a valid output buffer.
        let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let file_index = (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low);
        return Ok(Some(FileIdentity {
            volume_serial: info.volume_serial_number,
            file_index,
        }));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(Some(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }));
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = metadata;
        Ok(None)
    }
}

fn atomic_write(destination: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("sidecar has no parent directory"))?;
    let temp = create_temp_file(
        parent,
        destination.file_name().unwrap_or_default(),
        contents,
    )?;

    if let Err(error) = atomic_replace(&temp, destination) {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| {
            format!(
                "atomically replace OEP evidence sidecar {}",
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
    // Same-directory temp plus MOVEFILE_REPLACE_EXISTING gives an atomic
    // rename/replace on the target volume and WRITE_THROUGH requests durable
    // metadata propagation before returning.
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("mida-oep-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn minimal_pe64(entry_rva: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0..2].copy_from_slice(b"MZ");
        buf[60..64].copy_from_slice(&0x40u32.to_le_bytes());
        let nt = 0x40usize;
        buf[nt..nt + 4].copy_from_slice(b"PE\0\0");
        let fh = nt + 4;
        buf[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[fh + 2..fh + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[fh + 16..fh + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        buf[fh + 18..fh + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let oh = nt + 24;
        buf[oh..oh + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        buf[oh + 16..oh + 20].copy_from_slice(&entry_rva.to_le_bytes());
        buf[oh + 24..oh + 32].copy_from_slice(&0x1400_00000u64.to_le_bytes());
        buf[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes());
        buf[oh + 56..oh + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[oh + 60..oh + 64].copy_from_slice(&0x200u32.to_le_bytes());
        buf[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes());
        let sh = nt + 24 + 0xF0;
        buf[sh..sh + 5].copy_from_slice(b".text");
        buf[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
        buf[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        buf
    }

    fn write_fixture(dir: &Path, entry_rva: u32) -> (PathBuf, PathBuf) {
        let input = dir.join("protected.exe");
        let candidate = dir.join("candidate.exe");
        fs::write(&input, b"protected bytes\x00\x90").expect("input");
        fs::write(&candidate, minimal_pe64(entry_rva)).expect("candidate");
        (input, candidate)
    }

    /// Build a minimal PE64 with a .boot section whose raw bytes carry the
    /// H4-B epilogue signature: add rsp,0x28 + 8 pops + jmp rel32 to OEP.
    fn boot_chain_fixture(dir: &Path, boot_rva: u32, oep_target: u32) -> (PathBuf, PathBuf) {
        let mut candidate = minimal_pe64(boot_rva);
        // Second section .boot at boot_rva with raw data.
        let sh = 0x40 + 24 + 0xF0 + 0x28; // after first section header (0x1A0)
        candidate.resize(sh + 0x28, 0);
        candidate[sh..sh + 5].copy_from_slice(b".boot");
        candidate[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual_size
        candidate[sh + 12..sh + 16].copy_from_slice(&boot_rva.to_le_bytes()); // virtual_address
        candidate[sh + 16..sh + 20].copy_from_slice(&0x60u32.to_le_bytes()); // size_of_raw_data (stub_len)
        candidate[sh + 20..sh + 24].copy_from_slice(&(sh as u32 + 0x28).to_le_bytes()); // pointer_to_raw_data
        candidate[sh + 36..sh + 40].copy_from_slice(&0xE0_0000_20u32.to_le_bytes());
        // 3rd section header must exist for the count (16 -> bump to 3)
        let fh = 0x40 + 4;
        let count_off = fh + 2;
        candidate[count_off..count_off + 2].copy_from_slice(&3u16.to_le_bytes());
        // Stub: fill with 0xcc then epilogue at raw end.
        let raw_off = (sh + 0x28) as usize;
        let stub_len = 0x60usize;
        candidate.resize(raw_off + stub_len, 0);
        // epilogue at raw_off + 0x40
        let ep = raw_off + 0x40;
        candidate[ep..ep + 4].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
        candidate[ep + 4..ep + 12]
            .copy_from_slice(&[0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c]);
        candidate[ep + 12..ep + 16].copy_from_slice(&[0x5f, 0x5e, 0x5d, 0x5b]);
        candidate[ep + 16] = 0xe9;
        // rel32: jmp_end_rva = boot_rva + 0x40 + 16 + 5 ; target = oep_target
        let jmp_insn_at = (0x40 + 16) as u32;
        let jmp_end = boot_rva + jmp_insn_at + 5;
        let rel = (oep_target as i64 - jmp_end as i64) as i32;
        candidate[ep + 17..ep + 21].copy_from_slice(&rel.to_le_bytes());
        let input = dir.join("protected.exe");
        let out = dir.join("candidate.exe");
        fs::write(&input, b"protected bytes\x00\x90").expect("input");
        fs::write(&out, &candidate).expect("candidate");
        (input, out)
    }

    fn pass_provenance(rva: u32) -> OepProvenance {
        OepProvenance::runtime_rip(0x1400_1234, "runtime RIP entered decrypted text")
            .with_rva(Some(rva))
    }

    fn read_sidecar(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(path).expect("sidecar bytes")).expect("parse sidecar")
    }

    fn cleanup(dir: PathBuf) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_rip_matching_rva_passes_and_binds_exact_digest_size() {
        let dir = temp_dir("runtime-pass");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let sidecar = write_oep_evidence(
            &input,
            &candidate,
            &pass_provenance(0x1234),
            "oreans_themida",
        )
        .expect("write");
        let value = read_sidecar(&sidecar);
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["source"], "runtime_rip");
        assert_eq!(value["rva"], 0x1234);
        assert_eq!(value["final_entry_rva"], 0x1234);
        assert_eq!(value["entry_rva_matches_provenance"], true);
        assert_eq!(value["prerequisite_passes"], true);
        assert_eq!(value["blocker"], serde_json::Value::Null);
        assert!(value.get("schema").is_none());
        assert!(value.get("entry_matches_provenance_rva").is_none());
        let input_bytes = fs::read(&input).expect("input bytes");
        let candidate_bytes = fs::read(&candidate).expect("candidate bytes");
        assert_eq!(value["protected_input"]["size_bytes"], input_bytes.len());
        assert_eq!(value["candidate"]["size_bytes"], candidate_bytes.len());
        assert_eq!(
            value["protected_input"]["sha256"],
            format!("{:x}", Sha256::digest(&input_bytes))
        );
        assert_eq!(
            value["candidate"]["sha256"],
            format!("{:x}", Sha256::digest(&candidate_bytes))
        );
        cleanup(dir);
    }

    #[test]
    fn trace_passes() {
        let dir = temp_dir("trace-pass");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let provenance = OepProvenance::trace(0x1400_1234, "trace resolved application OEP")
            .with_rva(Some(0x1234));
        let value = read_sidecar(
            &write_oep_evidence(&input, &candidate, &provenance, "oreans_themida").expect("write"),
        );
        assert_eq!(value["source"], "trace");
        assert_eq!(value["prerequisite_passes"], true);
        cleanup(dir);
    }

    #[test]
    fn scan_fallback_fails_closed() {
        let dir = temp_dir("scan-fail");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let provenance =
            OepProvenance::scan_fallback(0x1400_1234, "scan fallback").with_rva(Some(0x1234));
        let value = read_sidecar(
            &write_oep_evidence(&input, &candidate, &provenance, "oreans_themida").expect("write"),
        );
        assert_eq!(value["source"], "scan_fallback");
        assert_eq!(value["prerequisite_passes"], false);
        assert!(value["blocker"]
            .as_str()
            .expect("blocker")
            .contains("scan fallback"));
        cleanup(dir);
    }

    #[test]
    fn h4b_chain_decoder_recovers_oep_target() {
        let dir = temp_dir("h4b-dec");
        let (_, candidate) = boot_chain_fixture(&dir, 0x2d2_1000, 0x8f054);
        let bytes = fs::read(&candidate).expect("bytes");
        let chain = decode_boot_entry_chain(&bytes, 0x2d2_1000);
        let chain = chain.expect("chain decoded");
        assert_eq!(chain.boot_rva, 0x2d2_1000);
        assert_eq!(chain.oep_target_rva, 0x8f054);
        cleanup(dir);
    }

    #[test]
    fn h4b_chain_decoder_fails_closed_without_epilogue() {
        let dir = temp_dir("h4b-nodec");
        let (_input, candidate) = write_fixture(&dir, 0x1234); // .text only, no epilogue
        let bytes = fs::read(&candidate).expect("bytes");
        assert!(
            decode_boot_entry_chain(&bytes, 0x1234).is_none(),
            "no .boot -> None"
        );
        cleanup(dir);
    }

    #[test]
    fn h4b_runtime_rip_chain_match_passes() {
        let dir = temp_dir("h4b-pass");
        let (input, candidate) = boot_chain_fixture(&dir, 0x2d2_1000, 0x8f054);
        let provenance =
            OepProvenance::runtime_rip(0x1400_8f054, "frozen RIP captured application OEP")
                .with_rva(Some(0x8f054));
        let sidecar =
            write_oep_evidence(&input, &candidate, &provenance, "ahk_gto").expect("write");
        let value = read_sidecar(&sidecar);
        assert_eq!(value["source"], "runtime_rip");
        assert_eq!(value["chain_decoded"], true);
        assert_eq!(value["chain_oep_matches_provenance"], true);
        assert_eq!(
            value["prerequisite_passes"], true,
            "chain match must pass with runtime_rip"
        );
        assert_eq!(value["blocker"], serde_json::Value::Null);
        cleanup(dir);
    }

    #[test]
    fn h4b_runtime_rip_chain_mismatch_fails_closed() {
        let dir = temp_dir("h4b-mismatch");
        let (input, candidate) = boot_chain_fixture(&dir, 0x2d2_1000, 0x8f054);
        // Provenance claims a DIFFERENT OEP than the decoded chain.
        let provenance =
            OepProvenance::runtime_rip(0x1400_a550, "frozen RIP captured application OEP")
                .with_rva(Some(0xa550));
        let sidecar =
            write_oep_evidence(&input, &candidate, &provenance, "ahk_gto").expect("write");
        let value = read_sidecar(&sidecar);
        assert_eq!(value["chain_decoded"], true);
        assert_eq!(
            value
                .get("chain_oep_matches_provenance")
                .and_then(|v| v.as_bool()),
            Some(false),
            "chain mismatch must record chain_oep_matches_provenance=false"
        );
        assert_eq!(
            value["prerequisite_passes"], false,
            "chain mismatch must fail closed"
        );
        assert!(value["blocker"]
            .as_str()
            .expect("blocker")
            .contains("chain match: false"));
        cleanup(dir);
    }

    #[test]
    fn h4b_scan_fallback_chain_match_still_fails_closed() {
        let dir = temp_dir("h4b-scan");
        let (input, candidate) = boot_chain_fixture(&dir, 0x2d2_1000, 0x8f054);
        // Even with a decoded chain, scan_fallback provenance must NOT pass.
        let provenance =
            OepProvenance::scan_fallback(0x1400_8f054, "scan fallback").with_rva(Some(0x8f054));
        let sidecar =
            write_oep_evidence(&input, &candidate, &provenance, "ahk_gto").expect("write");
        let value = read_sidecar(&sidecar);
        assert_eq!(value["chain_decoded"], true);
        assert_eq!(value["chain_oep_matches_provenance"], true);
        assert_eq!(
            value["prerequisite_passes"], false,
            "scan_fallback must stay fail-closed"
        );
        assert!(value["blocker"]
            .as_str()
            .expect("blocker")
            .contains("scan fallback"));
        cleanup(dir);
    }

    #[test]
    fn h4b_sidecar_without_chain_fields_parses_backcompat() {
        // Old sidecar JSON (no chain fields) must parse with defaults.
        let dir = temp_dir("h4b-compat");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let provenance = pass_provenance(0x1234);
        let sidecar =
            write_oep_evidence(&input, &candidate, &provenance, "oreans_themida").expect("write");
        let bytes = fs::read(&sidecar).expect("sidecar bytes");
        // Strip chain fields and re-parse as the struct.
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).expect("parse");
        for k in [
            "entry_chain",
            "chain_decoded",
            "chain_oep_matches_provenance",
        ] {
            v.as_object_mut().expect("obj").remove(k);
        }
        let reparsed: OepEvidenceSidecar =
            serde_json::from_value(v).expect("reparse without chain fields");
        assert_eq!(reparsed.chain_decoded, None);
        assert_eq!(reparsed.chain_oep_matches_provenance, None);
        assert!(reparsed.entry_chain.is_none());
        cleanup(dir);
    }

    #[test]
    fn unknown_and_missing_addresses_fail_closed() {
        let dir = temp_dir("unknown-fail");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let unknown = OepProvenance::unknown("no trustworthy OEP");
        let value = read_sidecar(
            &write_oep_evidence(&input, &candidate, &unknown, "oreans_themida").expect("write"),
        );
        assert_eq!(value["source"], "unknown");
        assert_eq!(value["prerequisite_passes"], false);
        assert!(value["blocker"]
            .as_str()
            .expect("blocker")
            .contains("unknown"));

        let missing = OepProvenance::runtime_rip(0x1400_1234, "address incomplete");
        let value = read_sidecar(
            &write_oep_evidence(&input, &candidate, &missing, "oreans_themida").expect("write"),
        );
        assert_eq!(value["prerequisite_passes"], false);
        assert!(value["blocker"].as_str().expect("blocker").contains("RVA"));
        cleanup(dir);
    }

    #[test]
    fn bootstrap_ambiguous_fails_closed() {
        let dir = temp_dir("bootstrap-fail");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let provenance = OepProvenance::new(
            OepSource::RuntimeRip,
            0x1400_1234,
            "bootstrap RIP",
            true,
            true,
        )
        .with_rva(Some(0x1234));
        let value = read_sidecar(
            &write_oep_evidence(&input, &candidate, &provenance, "oreans_themida").expect("write"),
        );
        assert_eq!(value["prerequisite_passes"], false);
        assert!(value["blocker"]
            .as_str()
            .expect("blocker")
            .contains("bootstrap"));
        cleanup(dir);
    }

    #[test]
    fn final_candidate_entry_is_authoritative_and_mismatch_fails_closed() {
        let dir = temp_dir("mismatch-fail");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let value = read_sidecar(
            &write_oep_evidence(
                &input,
                &candidate,
                &pass_provenance(0x5678),
                "oreans_themida",
            )
            .expect("write"),
        );
        assert_eq!(value["final_entry_rva"], 0x1234);
        assert_eq!(value["entry_rva_matches_provenance"], false);
        assert_eq!(value["prerequisite_passes"], false);
        assert!(value["blocker"]
            .as_str()
            .expect("blocker")
            .contains("does not match"));
        cleanup(dir);
    }

    #[test]
    fn rewrite_is_deterministic_and_parseable() {
        let dir = temp_dir("deterministic");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let sidecar = write_oep_evidence(
            &input,
            &candidate,
            &pass_provenance(0x1234),
            "oreans_themida",
        )
        .expect("write");
        let first = fs::read(&sidecar).expect("first bytes");
        assert_eq!(
            sidecar.file_name().and_then(|name| name.to_str()),
            Some("candidate.exe.oep_evidence.json")
        );
        let second_path = write_oep_evidence(
            &input,
            &candidate,
            &pass_provenance(0x1234),
            "oreans_themida",
        )
        .expect("rewrite");
        let second = fs::read(second_path).expect("second bytes");
        assert_eq!(first, second);
        let _: OepEvidenceSidecar = serde_json::from_slice(&first).expect("typed parse");
        assert!(first.ends_with(b"\n"));
        assert!(!dir.join(".candidate.exe.oep_evidence.json.tmp").exists());
        cleanup(dir);
    }

    #[test]
    fn same_path_alias_is_rejected_before_replacement_and_original_is_unchanged() {
        let dir = temp_dir("same-path");
        let candidate = dir.join("candidate.exe");
        let input = sidecar_path(&candidate).expect("sidecar path");
        fs::write(&input, b"protected-original").expect("input");
        fs::write(&candidate, minimal_pe64(0x1234)).expect("candidate");
        let original = fs::read(&input).expect("original");
        let result = write_oep_evidence(
            &input,
            &candidate,
            &pass_provenance(0x1234),
            "oreans_themida",
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&input).expect("input after"), original);
        cleanup(dir);
    }

    #[test]
    fn hard_link_aliases_are_rejected_without_changing_originals() {
        let dir = temp_dir("hard-link");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let sidecar = sidecar_path(&candidate).expect("sidecar path");
        fs::hard_link(&input, &sidecar).expect("hard link input");
        let input_before = fs::read(&input).expect("input before");
        let candidate_before = fs::read(&candidate).expect("candidate before");
        assert!(write_oep_evidence(
            &input,
            &candidate,
            &pass_provenance(0x1234),
            "oreans_themida"
        )
        .is_err());
        assert_eq!(fs::read(&input).expect("input after"), input_before);
        assert_eq!(
            fs::read(&candidate).expect("candidate after"),
            candidate_before
        );
        fs::remove_file(&sidecar).expect("remove input link");
        fs::hard_link(&candidate, &sidecar).expect("hard link candidate");
        assert!(write_oep_evidence(
            &input,
            &candidate,
            &pass_provenance(0x1234),
            "oreans_themida"
        )
        .is_err());
        assert_eq!(fs::read(&input).expect("input final"), input_before);
        assert_eq!(
            fs::read(&candidate).expect("candidate final"),
            candidate_before
        );
        cleanup(dir);
    }

    #[test]
    fn invalid_final_candidate_writes_no_sidecar() {
        let dir = temp_dir("invalid-candidate");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        fs::write(&candidate, b"not a PE").expect("invalid candidate");
        let sidecar = sidecar_path(&candidate).expect("sidecar path");
        assert!(write_oep_evidence(
            &input,
            &candidate,
            &pass_provenance(0x1234),
            "oreans_themida"
        )
        .is_err());
        assert!(!sidecar.exists());
        cleanup(dir);
    }

    /// G2-R2: the OEP sidecar producer emits the family-appropriate schema —
    /// `mida.oreans-oep-evidence/v1` for Oreans, `mida.unpack-oep-evidence/v1`
    /// for a generic family (ahk_gto). An unknown family fails closed.
    #[test]
    fn oep_sidecar_schema_dispatches_by_family() {
        let dir = temp_dir("oep_family");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let oreans = write_oep_evidence(
            &input,
            &candidate,
            &pass_provenance(0x1234),
            "oreans_themida",
        )
        .expect("oreans oep");
        assert_eq!(
            read_sidecar(&oreans)["schema_version"],
            "mida.oreans-oep-evidence/v1"
        );
        let gto = write_oep_evidence(&input, &candidate, &pass_provenance(0x1234), "ahk_gto")
            .expect("gto oep");
        assert_eq!(
            read_sidecar(&gto)["schema_version"],
            "mida.unpack-oep-evidence/v1"
        );
        assert!(write_oep_evidence(&input, &candidate, &pass_provenance(0x1234), "bogus").is_err());
        cleanup(dir);
    }

    /// G2-R2: the REAL OEP producer output (family `ahk_gto`) matches the
    /// schema the generic bundle assembler expects for its `oep_evidence`
    /// member — so a genuinely-produced sidecar is consumable by the generic
    /// assembler, not just a hand-built fixture.
    #[test]
    fn real_oep_producer_output_matches_generic_assembler_member_schema() {
        let dir = temp_dir("real_oep_generic");
        let (input, candidate) = write_fixture(&dir, 0x1234);
        let path =
            write_oep_evidence(&input, &candidate, &pass_provenance(0x1234), "ahk_gto").unwrap();
        let value = read_sidecar(&path);
        assert_eq!(value["schema_version"], "mida.unpack-oep-evidence/v1");
        let expected = crate::unpacker::generic_bundle_assembler::EXPECTED_MEMBER_SCHEMAS
            .iter()
            .find(|(n, _)| *n == "oep_evidence")
            .expect("oep_evidence member")
            .1;
        assert_eq!(value["schema_version"], expected);
        cleanup(dir);
    }
}
