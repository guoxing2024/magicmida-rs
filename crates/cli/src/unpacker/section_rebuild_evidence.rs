//! Candidate-bound structured section/header evidence for the Oreans path.
//! The final candidate and protected input are re-read from disk here; no
//! caller-provided identity or pass flag is authoritative.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use mida_pe::PeHeader;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(test)] // used by schema-shape assertions below; production uses evidence_schema dispatch
pub(crate) const SCHEMA_VERSION: &str = "mida.oreans-section-rebuild-evidence/v1";

use super::evidence_schema::ArtifactIdentity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Section {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
    virtual_end: u64,
    raw_end: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Directory {
    index: u8,
    name: String,
    rva: u32,
    size: u32,
    present: bool,
    in_image: bool,
    raw_backed: bool,
    security_file_offset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SectionRebuildEvidenceSidecar {
    schema_version: String,
    protected_input: ArtifactIdentity,
    candidate: ArtifactIdentity,
    machine: u16,
    pe32_plus: bool,
    file_alignment: u32,
    section_alignment: u32,
    size_of_headers: u32,
    size_of_image: u32,
    section_table_offset: u64,
    section_table_size: u64,
    entry_rva: u32,
    entry_section: Option<String>,
    executable_sections: Vec<String>,
    sections: Vec<Section>,
    directories: Vec<Directory>,
    overlay_offset: u64,
    overlay_size: u64,
    section_rebuild_evidence_pass: bool,
    blockers: Vec<String>,
}

pub(crate) fn write_section_rebuild_evidence(
    protected_input: &Path,
    candidate: &Path,
    family: &str,
) -> anyhow::Result<PathBuf> {
    if same_file(protected_input, candidate)? {
        return Err(anyhow!("protected input and candidate are the same file"));
    }
    let (protected_bytes, protected) = read_artifact(protected_input)?;
    let (candidate_bytes, candidate_identity) = read_artifact(candidate)?;
    let value = build_section_rebuild_evidence(
        protected_input,
        &protected_bytes,
        candidate,
        &candidate_bytes,
        protected,
        candidate_identity,
        family,
    )?;
    let sidecar = sidecar_path(candidate)?;
    ensure_sidecar_is_safe(&sidecar, protected_input, candidate)?;
    let mut json =
        serde_json::to_vec_pretty(&value).context("serialize section rebuild evidence")?;
    json.push(b'\n');
    atomic_write(&sidecar, &json)?;
    Ok(sidecar)
}

fn align_up_u64(value: u64, alignment: u64) -> u64 {
    if alignment <= 1 {
        return value;
    }
    value
        .checked_add(alignment - 1)
        .map(|sum| sum / alignment * alignment)
        .unwrap_or(u64::MAX)
}

fn build_section_rebuild_evidence(
    protected_path: &Path,
    protected_bytes: &[u8],
    candidate_path: &Path,
    candidate_bytes: &[u8],
    protected: ArtifactIdentity,
    candidate: ArtifactIdentity,
    family: &str,
) -> anyhow::Result<SectionRebuildEvidenceSidecar> {
    let schema_version = super::evidence_schema::member_schema_for_family(
        family,
        super::evidence_schema::EvidenceMemberKind::SectionRebuild,
    )
    .map_err(anyhow::Error::msg)?
    .to_string();
    let _protected_parse = PeHeader::from_bytes(protected_bytes)
        .with_context(|| format!("parse protected PE {}", protected_path.display()))?;
    let pe = PeHeader::from_bytes(candidate_bytes)
        .with_context(|| format!("parse candidate PE {}", candidate_path.display()))?;
    let optional = &pe.nt_headers.optional_header;
    let section_table_offset = u64::from(pe.dos_header.e_lfanew)
        + 4
        + 20
        + u64::from(pe.nt_headers.file_header.size_of_optional_header);
    let section_table_size = u64::from(pe.nt_headers.file_header.number_of_sections) * 40;
    let mut blockers = Vec::new();
    let mut sections = Vec::new();
    let mut executable_sections = Vec::new();
    let mut virtual_ranges = Vec::new();
    let mut raw_ranges = Vec::new();
    for section in &pe.sections {
        let virtual_end = u64::from(section.virtual_address)
            .saturating_add(u64::from(section.virtual_size.max(section.raw_size)));
        let raw_end = u64::from(section.raw_offset).saturating_add(u64::from(section.raw_size));
        if (section.characteristics & 0x2000_0000) != 0 {
            executable_sections.push(section.name.clone());
        }
        if section.raw_size != 0 {
            raw_ranges.push((u64::from(section.raw_offset), raw_end));
        }
        virtual_ranges.push((u64::from(section.virtual_address), virtual_end));
        sections.push(Section {
            name: section.name.clone(),
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            raw_offset: section.raw_offset,
            raw_size: section.raw_size,
            characteristics: section.characteristics,
            virtual_end,
            raw_end,
        });
    }
    let entry_section = sections
        .iter()
        .find(|section| {
            u64::from(pe.entry_point) >= u64::from(section.virtual_address)
                && u64::from(pe.entry_point) < section.virtual_end
        })
        .map(|section| section.name.clone());
    let directories = optional
        .data_directory
        .iter()
        .enumerate()
        .map(|(index, directory)| {
            let present = directory.virtual_address != 0 || directory.size != 0;
            let security_file_offset = index == 4 && present;
            let end = directory.virtual_address.checked_add(directory.size);
            // P8-F: an absent directory (RVA 0) must not report in_image=true;
            // gate recomputation requires the same so both agree field-for-field.
            let in_image = if security_file_offset {
                false
            } else {
                directory.virtual_address != 0
                    && end.is_some_and(|end| end <= optional.size_of_image)
            };
            let raw_backed = if security_file_offset {
                usize::try_from(directory.virtual_address)
                    .ok()
                    .and_then(|offset| offset.checked_add(directory.size as usize))
                    .is_some_and(|end| end <= candidate_bytes.len())
            } else {
                directory.virtual_address != 0
                    && end.is_some_and(|end| {
                        pe.sections.iter().any(|section| {
                            section.raw_size != 0
                                && directory.virtual_address >= section.virtual_address
                                && end <= section.virtual_address.saturating_add(section.raw_size)
                        })
                    })
            };
            Directory {
                index: index as u8,
                name: directory_name(index).to_string(),
                rva: directory.virtual_address,
                size: directory.size,
                present,
                in_image,
                raw_backed,
                security_file_offset,
            }
        })
        .collect::<Vec<_>>();
    let overlay_offset = raw_ranges
        .iter()
        .map(|range| range.1)
        .max()
        .unwrap_or(u64::from(optional.size_of_headers));
    let mut sorted_raw = raw_ranges.clone();
    sorted_raw.sort_unstable();
    let mut sorted_virtual = virtual_ranges.clone();
    sorted_virtual.sort_unstable();
    if section_table_offset
        .checked_add(section_table_size)
        .is_none_or(|end| end > u64::from(optional.size_of_headers))
    {
        blockers.push("section table exceeds SizeOfHeaders".to_string());
    }
    if optional.file_alignment == 0
        || !optional.file_alignment.is_power_of_two()
        || optional.section_alignment == 0
        || !optional.section_alignment.is_power_of_two()
        || optional.file_alignment > optional.section_alignment
    {
        blockers.push("invalid PE alignment".to_string());
    }
    if sorted_raw.windows(2).any(|pair| pair[1].0 < pair[0].1) {
        blockers.push("raw section ranges overlap".to_string());
    }
    if raw_ranges.windows(2).any(|pair| pair[1].0 < pair[0].0) {
        blockers.push("raw section ranges are not in table order".to_string());
    }
    if sorted_virtual.windows(2).any(|pair| pair[1].0 < pair[0].1) {
        blockers.push("virtual section ranges overlap".to_string());
    }
    if optional.file_alignment != 0 && optional.size_of_headers % optional.file_alignment != 0 {
        blockers.push("SizeOfHeaders is not file-aligned".to_string());
    }
    if optional.section_alignment != 0 && optional.size_of_image % optional.section_alignment != 0 {
        blockers.push("SizeOfImage is not section-aligned".to_string());
    }
    if sections.iter().any(|section| {
        section.raw_end > candidate.size_bytes
            || (section.raw_size != 0
                && (section.raw_offset % optional.file_alignment.max(1) != 0
                    || section.raw_size % optional.file_alignment.max(1) != 0))
            || section.virtual_address % optional.section_alignment.max(1) != 0
    }) {
        blockers.push("section raw pointer/size or VA alignment is invalid".to_string());
    }
    if entry_section.is_none()
        || !sections.iter().any(|section| {
            Some(&section.name) == entry_section.as_ref()
                && (section.characteristics & 0x2000_0000) != 0
                && section.raw_size != 0
                && u64::from(pe.entry_point)
                    < u64::from(section.virtual_address)
                        + u64::from(section.raw_size.min(section.virtual_size.max(1)))
        })
    {
        blockers.push("entry is not executable and raw-backed".to_string());
    }
    for directory in &directories {
        // P8-F: align directory coverage checks with the gate so the sidecar's
        // `section_rebuild_evidence_pass` recomputes field-for-field with the
        // independent validator.
        if directory.present {
            if directory.size == 0 {
                blockers.push(format!("directory {} has zero size", directory.index));
            }
            if directory.security_file_offset {
                if directory.index != 4 {
                    blockers.push(format!(
                        "security directory {} is not file-backed",
                        directory.index
                    ));
                }
            } else if !directory.in_image || !directory.raw_backed {
                blockers.push(format!(
                    "directory {} is not in a raw-backed section",
                    directory.index
                ));
            }
        } else if directory.in_image || directory.raw_backed || directory.security_file_offset {
            blockers.push(format!(
                "absent directory {} has non-canonical coverage",
                directory.index
            ));
        }
    }
    // P8-F: duplicate section names are a production-contract violation the
    // gate rejects; the producer must report them so the pass flag agrees.
    let mut section_names = std::collections::HashSet::new();
    for section in &sections {
        if !section_names.insert(section.name.clone()) {
            blockers.push(format!("duplicate section name '{}'", section.name));
        }
    }
    // P8-F: SizeOfImage must equal the section-aligned extent of the highest
    // virtual end, matching the gate's recomputation (not merely divisible).
    let max_virtual_end = virtual_ranges
        .iter()
        .map(|range| range.1)
        .max()
        .unwrap_or(u64::from(optional.size_of_headers));
    let section_aligned_image =
        align_up_u64(max_virtual_end, u64::from(optional.section_alignment));
    if section_aligned_image != u64::from(optional.size_of_image) {
        blockers.push("SizeOfImage does not equal aligned section extent".to_string());
    }
    blockers.sort();
    blockers.dedup();
    Ok(SectionRebuildEvidenceSidecar {
        schema_version: schema_version.clone(),
        protected_input: protected,
        candidate,
        machine: pe.nt_headers.file_header.machine,
        pe32_plus: pe.is_64bit,
        file_alignment: optional.file_alignment,
        section_alignment: optional.section_alignment,
        size_of_headers: optional.size_of_headers,
        size_of_image: optional.size_of_image,
        section_table_offset,
        section_table_size,
        entry_rva: pe.entry_point,
        entry_section,
        executable_sections,
        sections,
        directories,
        overlay_offset,
        overlay_size: candidate_bytes
            .len()
            .saturating_sub(overlay_offset as usize) as u64,
        section_rebuild_evidence_pass: blockers.is_empty(),
        blockers,
    })
}

fn directory_name(index: usize) -> &'static str {
    [
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
    ]
    .get(index)
    .copied()
    .unwrap_or("unknown")
}

fn read_artifact(path: &Path) -> anyhow::Result<(Vec<u8>, ArtifactIdentity)> {
    let bytes = fs::read(path).with_context(|| format!("read artifact {}", path.display()))?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let size_bytes = bytes.len() as u64;
    Ok((
        bytes,
        ArtifactIdentity {
            path: path.display().to_string(),
            sha256: digest,
            size_bytes,
        },
    ))
}

fn sidecar_path(candidate: &Path) -> anyhow::Result<PathBuf> {
    let name = candidate
        .file_name()
        .ok_or_else(|| anyhow!("candidate path has no file name"))?;
    let mut sidecar = name.to_os_string();
    sidecar.push(".section_rebuild_evidence.json");
    Ok(candidate.with_file_name(sidecar))
}

fn ensure_sidecar_is_safe(
    sidecar: &Path,
    protected: &Path,
    candidate: &Path,
) -> anyhow::Result<()> {
    for source in [protected, candidate] {
        if sidecar.exists() && same_file(sidecar, source)? {
            return Err(anyhow!("refusing to replace aliased sidecar"));
        }
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
        struct T {
            low: u32,
            high: u32,
        }
        #[repr(C)]
        struct I {
            a: u32,
            b: T,
            c: T,
            d: T,
            v: u32,
            e: u32,
            f: u32,
            g: u32,
            h: u32,
            i: u32,
        }
        extern "system" {
            fn GetFileInformationByHandle(h: *mut std::ffi::c_void, i: *mut I) -> i32;
        }
        let id = |path: &Path| -> anyhow::Result<(u32, u64)> {
            let f = OpenOptions::new().read(true).share_mode(7).open(path)?;
            let mut i = I {
                a: 0,
                b: T { low: 0, high: 0 },
                c: T { low: 0, high: 0 },
                d: T { low: 0, high: 0 },
                v: 0,
                e: 0,
                f: 0,
                g: 0,
                h: 0,
                i: 0,
            };
            if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut i) } == 0 {
                return Err(anyhow!("GetFileInformationByHandle failed"));
            }
            Ok((i.v, (u64::from(i.h) << 32) | u64::from(i.i)))
        };
        Ok(id(left)? == id(right)?)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = fs::metadata(left)?;
        let b = fs::metadata(right)?;
        return Ok((a.dev(), a.ino()) == (b.dev(), b.ino()));
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(
        ".{}.tmp-{}-{}",
        destination
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        std::process::id(),
        now
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    file.write_all(contents)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let a: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
        let b: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        extern "system" {
            fn MoveFileExW(a: *const u16, b: *const u16, f: u32) -> i32;
        }
        if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), 9) } == 0 {
            let _ = fs::remove_file(&temp);
            return Err(anyhow!(
                "atomic replace failed: {}",
                io::Error::last_os_error()
            ));
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(&temp, destination)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..2].copy_from_slice(&0x5a4du16.to_le_bytes());
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let optional = 0x98;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32]
            .copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let section = optional + 0xf0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes
    }

    fn temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mida-section-evidence-{label}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn sidecar_round_trip_binds_final_disk_identity_and_replaces_atomically() {
        let root = temp_dir("happy");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let protected = root.join("protected.exe");
        let candidate = root.join("candidate.exe");
        fs::write(&protected, minimal_pe()).unwrap();
        fs::write(&candidate, minimal_pe()).unwrap();
        let sidecar =
            write_section_rebuild_evidence(&protected, &candidate, "oreans_themida").unwrap();
        let first = fs::read(&sidecar).unwrap();
        let value: SectionRebuildEvidenceSidecar = serde_json::from_slice(&first).unwrap();
        assert_eq!(value.schema_version, SCHEMA_VERSION);
        assert_eq!(
            value.candidate.size_bytes,
            fs::metadata(&candidate).unwrap().len()
        );
        assert!(value.section_rebuild_evidence_pass);
        let second_path =
            write_section_rebuild_evidence(&protected, &candidate, "oreans_themida").unwrap();
        assert_eq!(sidecar, second_path);
        assert!(!root
            .join(format!(
                ".{}.tmp",
                sidecar.file_name().unwrap().to_string_lossy()
            ))
            .exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn sidecar_unknown_fields_are_rejected() {
        let mut value = serde_json::to_value(SectionRebuildEvidenceSidecar {
            schema_version: SCHEMA_VERSION.to_string(),
            protected_input: ArtifactIdentity {
                path: "p".into(),
                sha256: "a".into(),
                size_bytes: 1,
            },
            candidate: ArtifactIdentity {
                path: "c".into(),
                sha256: "b".into(),
                size_bytes: 1,
            },
            machine: 0x8664,
            pe32_plus: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
            size_of_headers: 0x200,
            size_of_image: 0x2000,
            section_table_offset: 0x198,
            section_table_size: 40,
            entry_rva: 0x1000,
            entry_section: Some(".text".into()),
            executable_sections: vec![".text".into()],
            sections: Vec::new(),
            directories: Vec::new(),
            overlay_offset: 0x400,
            overlay_size: 0,
            section_rebuild_evidence_pass: false,
            blockers: vec!["test".into()],
        })
        .unwrap();
        value["unknown"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<SectionRebuildEvidenceSidecar>(value).is_err());
    }

    #[test]
    fn same_path_and_hard_link_aliases_are_rejected() {
        let root = temp_dir("alias");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let protected = root.join("protected.exe");
        let candidate = root.join("candidate.exe");
        let alias = root.join("candidate-alias.exe");
        fs::write(&protected, minimal_pe()).unwrap();
        fs::write(&candidate, minimal_pe()).unwrap();
        assert!(write_section_rebuild_evidence(&candidate, &candidate, "oreans_themida").is_err());
        fs::hard_link(&candidate, &alias).unwrap();
        assert!(write_section_rebuild_evidence(&candidate, &alias, "oreans_themida").is_err());
        let _ = fs::remove_dir_all(root);
    }

    fn minimal_pe_with_sections(names: &[&str]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x600];
        bytes[0..2].copy_from_slice(&0x5a4du16.to_le_bytes());
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&(names.len() as u16).to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let optional = 0x98;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32]
            .copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60]
            .copy_from_slice(&(0x1000 + (names.len() as u32) * 0x1000).to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let mut section = optional + 0xf0;
        for (i, name) in names.iter().enumerate() {
            bytes[section..section + name.len().min(8)].copy_from_slice(name.as_bytes());
            let va = 0x1000 + (i as u32) * 0x1000;
            bytes[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VS
            bytes[section + 12..section + 16].copy_from_slice(&va.to_le_bytes()); // VA
            bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes()); // rawsize
            bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes()); // rawoff
            bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
            section += 0x28;
        }
        bytes
    }

    #[test]
    fn duplicate_section_names_fail_closed() {
        // P8-F: the producer must report duplicate section names so its
        // section_rebuild_evidence_pass agrees with the gate's recomputation
        // (which rejects duplicate names).
        let root = temp_dir("dup");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let protected = root.join("protected.exe");
        let candidate = root.join("candidate.exe");
        // Two .rdata sections => duplicate name.
        fs::write(&protected, minimal_pe_with_sections(&[".rdata", ".rdata"])).unwrap();
        fs::write(&candidate, minimal_pe_with_sections(&[".rdata", ".rdata"])).unwrap();
        let sidecar =
            write_section_rebuild_evidence(&protected, &candidate, "oreans_themida").unwrap();
        let value: SectionRebuildEvidenceSidecar =
            serde_json::from_slice(&fs::read(&sidecar).unwrap()).unwrap();
        assert!(!value.section_rebuild_evidence_pass);
        assert!(
            value
                .blockers
                .iter()
                .any(|b| b.contains("duplicate section name '.rdata'")),
            "blockers must include the duplicate section name, got {:?}",
            value.blockers
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn absent_directories_are_canonical_when_zero() {
        // P8-F: an absent directory (RVA 0 / size 0) must report in_image=false
        // and raw_backed=false so it is NOT flagged as non-canonical coverage.
        // A normal PE has many absent directories and must stay passable.
        let root = temp_dir("absent");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let protected = root.join("protected.exe");
        let candidate = root.join("candidate.exe");
        fs::write(&protected, minimal_pe()).unwrap();
        fs::write(&candidate, minimal_pe()).unwrap();
        let sidecar =
            write_section_rebuild_evidence(&protected, &candidate, "oreans_themida").unwrap();
        let value: SectionRebuildEvidenceSidecar =
            serde_json::from_slice(&fs::read(&sidecar).unwrap()).unwrap();
        assert!(value.section_rebuild_evidence_pass, "{:?}", value.blockers);
        // All 16 directories absent (minimal_pe has none set) must be canonical.
        assert!(
            value
                .blockers
                .iter()
                .all(|b| !b.contains("absent directory")),
            "absent zero directories must be canonical, got {:?}",
            value.blockers
        );
        let _ = fs::remove_dir_all(root);
    }

    /// G2-R2: the section-rebuild sidecar producer emits the family-appropriate
    /// schema — `mida.oreans-section-rebuild-evidence/v1` for Oreans,
    /// `mida.unpack-section-rebuild-evidence/v1` for a generic family (ahk_gto).
    /// An unknown family fails closed.
    #[test]
    fn section_rebuild_schema_dispatches_by_family() {
        let root = temp_dir("section_family");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let protected = root.join("protected.exe");
        let candidate = root.join("candidate.exe");
        fs::write(&protected, minimal_pe()).unwrap();
        fs::write(&candidate, minimal_pe()).unwrap();
        let oreans =
            write_section_rebuild_evidence(&protected, &candidate, "oreans_themida").unwrap();
        let o: SectionRebuildEvidenceSidecar =
            serde_json::from_slice(&fs::read(&oreans).unwrap()).unwrap();
        assert_eq!(o.schema_version, "mida.oreans-section-rebuild-evidence/v1");
        let gto = write_section_rebuild_evidence(&protected, &candidate, "ahk_gto").unwrap();
        let g: SectionRebuildEvidenceSidecar =
            serde_json::from_slice(&fs::read(&gto).unwrap()).unwrap();
        assert_eq!(g.schema_version, "mida.unpack-section-rebuild-evidence/v1");
        assert!(write_section_rebuild_evidence(&protected, &candidate, "bogus").is_err());
        let _ = fs::remove_dir_all(root);
    }
}
