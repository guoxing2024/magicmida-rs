//! GTO-TR T2 Phase B: observed-surface assembly.
//!
//! Assembles a candidate PE from the TR-line carved components (per-section
//! bytes extracted from a trace-era memory image) plus the page-level
//! provenance map produced by `tools/tr_pilot/carve_observed_surface.py`.
//!
//! Scope notes (T2 work order §0/§2):
//! - The original PE headers were erased in-memory by the protector, so all
//!   header values here are RECONSTRUCTED from live-loader ground truth.
//! - Entry point is deliberately `0` and flagged `ep_tbd`: real OEP recovery
//!   is a later phase; this pilot asserts structural validity only.
//! - Import / TLS / reloc directories are deferred; `.pdata` / `.rsrc` are
//!   carried as content sections with fallback directory hints.
//! - Region disposition (live / cond-rare / unknown / suspected-decoy) is kept
//!   in provenance.json — this module copies bytes as-is by design so that
//!   loader failures can be attributed page-precisely.

use std::fs;
use std::path::Path;

use serde_json::Value;

use super::{ImageDataDirectory, PlannedSection, RebuildPlan};

/// Per-section characteristics sourced from H5-era runtime observation
/// (F1 fingerprint pass). Values are `IMAGE_SCN_*` combinations.
fn characteristics_for(name: &str) -> u32 {
    match name {
        // CODE | EXECUTE | READ
        "text" | "rdata0" => 0x6000_0020,
        // EXECUTE | READ | WRITE (mutated-code carrier)
        "rdata2" => 0xE000_0060,
        // READ | WRITE
        "data" | "rdata1" => 0xC000_0040,
        // READ | WRITE (shell IAT mirror lives in .rdata and must be writable)
        "rdata" => 0xC000_0040,
        // READ | WRITE (function-pointer table patched by the IAT-repair stub)
        "fptable" => 0xC000_0040,
        // INITIALIZED_DATA | READ (default for everything else)
        _ => 0x4000_0040,
    }
}

/// Metadata about one assembled section.
#[derive(Debug, Clone)]
pub struct TrSectionInfo {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub sha256: String,
}

/// Assembly metadata returned alongside the plan.
#[derive(Debug, Clone)]
pub struct TrSurfaceMeta {
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_point_tbd: bool,
    pub entry_point_rva: u32,
    pub deferred_directories: Vec<&'static str>,
    pub sections: Vec<TrSectionInfo>,
}

fn parse_hex_u32(v: &Value, field: &str) -> Result<u32, String> {
    let s = v
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("provenance: missing hex field `{field}`"))?;
    let t = s.trim_start_matches("0x");
    u32::from_str_radix(t, 16).map_err(|e| format!("provenance: bad hex `{s}`: {e}"))
}

fn parse_hex_u64(v: &Value, field: &str) -> Result<u64, String> {
    let s = v
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("provenance: missing hex field `{field}`"))?;
    let t = s.trim_start_matches("0x");
    u64::from_str_radix(t, 16).map_err(|e| format!("provenance: bad hex `{s}`: {e}"))
}

/// Import-directory ground truth extracted from the trace-era dump's own PE
/// header. The protector erases the original headers in the *protected* file,
/// but the trace-era memory image (`dump_source` in provenance.json) retains
/// the runtime import directory (descriptors + OFT + hint/name strings live in
/// `.rdata2`, IAT slots in `.rdata1`). Re-declaring those directory entries
/// makes the loader resolve all imported DLLs and re-write the IAT slots with
/// fresh addresses for the new process — without this, the copied IAT holds
/// stale absolute addresses and indirect calls AV on unmapped memory.
#[derive(Debug, Clone, Copy)]
struct ImportDirs {
    import_rva: u32,
    import_size: u32,
    iat_rva: u32,
    iat_size: u32,
}

fn extract_import_dirs(dump_path: &Path) -> Result<ImportDirs, String> {
    let data = fs::read(dump_path)
        .map_err(|e| format!("cannot read dump_source {}: {e}", dump_path.display()))?;
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err(format!(
            "dump_source {}: not a PE image (MZ missing)",
            dump_path.display()
        ));
    }
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 0x18 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(format!(
            "dump_source {}: PE signature missing",
            dump_path.display()
        ));
    }
    let opt_off = e_lfanew + 24;
    let magic = u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().unwrap());
    if magic != 0x20b {
        return Err(format!(
            "dump_source {}: not PE32+ (magic={magic:#x})",
            dump_path.display()
        ));
    }
    // PE32+ data directories start at opt header + 112; import is index 1, IAT is 12.
    let dd_off = opt_off + 112;
    let read_dd = |idx: usize| -> (u32, u32) {
        let o = dd_off + idx * 8;
        let rva = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let size = u32::from_le_bytes(data[o + 4..o + 8].try_into().unwrap());
        (rva, size)
    };
    let (import_rva, import_size) = read_dd(super::DIR_IMPORT);
    let (iat_rva, iat_size) = read_dd(super::DIR_IAT);
    if import_rva == 0 || import_size == 0 {
        return Err(format!(
            "dump_source {}: import directory is empty (rva={import_rva:#x}, size={import_size:#x})",
            dump_path.display()
        ));
    }
    Ok(ImportDirs {
        import_rva,
        import_size,
        iat_rva,
        iat_size,
    })
}

/// Build a [`RebuildPlan`] from TR carved components + provenance.
///
/// Returns the plan plus assembly metadata. Call [`super::rebuild_pe_image`]
/// on the plan to emit candidate bytes.
pub fn build_tr_surface_plan(
    components_dir: &Path,
    provenance_path: &Path,
    entry_point_rva_override: Option<u32>,
) -> Result<(RebuildPlan, TrSurfaceMeta), String> {
    let prov_raw = fs::read_to_string(provenance_path)
        .map_err(|e| format!("cannot read provenance {}: {e}", provenance_path.display()))?;
    let prov: Value =
        serde_json::from_str(&prov_raw).map_err(|e| format!("provenance JSON invalid: {e}"))?;

    let prov_img = prov
        .get("image")
        .ok_or_else(|| "provenance: missing `image` object".to_string())?;
    let image_base = parse_hex_u64(&prov_img, "base")?;
    let size_of_image = parse_hex_u32(&prov_img, "size_of_image")?;

    let sections_json = prov
        .get("sections")
        .and_then(Value::as_array)
        .ok_or_else(|| "provenance: missing `sections` array".to_string())?;
    if sections_json.is_empty() {
        return Err("provenance: zero sections".to_string());
    }

    let mut plan = RebuildPlan::pe32_plus();
    plan.image_base = image_base;
    // EP 语义: 有 override 用 override(H4B 记录 original_oep_rva=0x90176);
    // 无 override 置 0 并标注 ep_tbd —— 不假装知道 OEP。
    plan.entry_point_rva = entry_point_rva_override.unwrap_or(0);
    plan.section_alignment = 0x1000;
    plan.file_alignment = 0x200;
    plan.subsystem = 2; // IMAGE_SUBSYSTEM_WINDOWS_GUI
    plan.file_characteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    let mut meta_sections = Vec::new();
    let mut fallback = [ImageDataDirectory {
        virtual_address: 0,
        size: 0,
    }; 16];

    for sec in sections_json {
        let name = sec
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "provenance: section without name".to_string())?
            .to_string();
        let rva = parse_hex_u32(sec, "rva")?;
        let vsize = parse_hex_u32(sec, "vsize")?;
        let sha = sec
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("section {name}: missing sha256"))?
            .to_string();
        let component = sec
            .get("component")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("section {name}: missing component"))?
            .to_string();

        let path = components_dir.join(&component);
        let data = fs::read(&path)
            .map_err(|e| format!("cannot read component {}: {e}", path.display()))?;
        let actual = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&data);
            hex_lower(&h.finalize())
        };
        if actual != sha.to_ascii_lowercase() {
            return Err(format!(
                "component {} sha256 mismatch: expected {sha}, got {actual}",
                path.display()
            ));
        }

        if name == "pdata" {
            fallback[super::DIR_EXCEPTION] = ImageDataDirectory {
                virtual_address: rva,
                size: vsize,
            };
        }
        if name == "rsrc" {
            fallback[super::DIR_RESOURCE] = ImageDataDirectory {
                virtual_address: rva,
                size: vsize,
            };
        }

        let chars = characteristics_for(&name);
        meta_sections.push(TrSectionInfo {
            name: name.clone(),
            rva,
            virtual_size: vsize,
            sha256: sha,
        });
        plan.sections
            .push(PlannedSection::with_rva(name, chars, rva, vsize, data));
    }

    // GTO-TR D_a7: re-declare the trace-era dump's import directory so the
    // loader resolves the full 16-DLL import set and re-writes the copied IAT
    // slots with process-local addresses. Without this the copied IAT holds
    // stale absolute addresses (crash: call [IAT] -> jmp rax -> unmapped AV).
    if let Some(dump_source) = prov_img
        .get("dump_source")
        .and_then(Value::as_str)
        .map(Path::new)
    {
        match extract_import_dirs(dump_source) {
            Ok(dirs) => {
                fallback[super::DIR_IMPORT] = ImageDataDirectory {
                    virtual_address: dirs.import_rva,
                    size: dirs.import_size,
                };
                if dirs.iat_rva != 0 && dirs.iat_size != 0 {
                    fallback[super::DIR_IAT] = ImageDataDirectory {
                        virtual_address: dirs.iat_rva,
                        size: dirs.iat_size,
                    };
                }
            }
            Err(e) => {
                // 非致命: 无导入目录时保持原状(纯内容重建), 仅记录。
                eprintln!("tr_surface: import dirs not extracted: {e}");
            }
        }
    }

    // GTO-TR D_a9/D_a10: optional IAT-repair startup stub.
    // `stub.bin` (if present) holds a tiny loop that copies loader-resolved
    // addresses from the standard IAT slots back into the shell's private IAT
    // mirror, then jumps to the real OEP. The stub's trailing `jmp rel32` is
    // patched here to land on `entry_point_rva_override` (the true OEP), and
    // the PE entry point is set to the stub instead.
    let stub_path = components_dir.join("stub.bin");
    if stub_path.exists() && entry_point_rva_override.is_some() {
        let mut stub = fs::read(&stub_path)
            .map_err(|e| format!("cannot read stub {}: {e}", stub_path.display()))?;
        // Stub section goes after the last content section, aligned to 0x1000.
        let sa = plan.section_alignment;
        let last_end = plan
            .sections
            .iter()
            .map(|s| s.virtual_address.unwrap_or(0) + s.virtual_size)
            .max()
            .unwrap_or(sa);
        let stub_rva = (last_end + sa - 1) & !(sa - 1);
        // Patch the stub's trailing `jmp rel32`. The stub layout:
        // lea(0x00,7) mov(0x07,6) loop(0x0d,21) jnz(0x22,2), then the
        // pair table, then optional post-table code, and finally the
        // `E9 rel32` OEP jump as the very last 5 bytes of the file.
        let jmp_off = stub.len() - 5; // `E9` opcode position; disp32 follows
        let jmp_site = stub_rva + jmp_off as u32 + 5;
        let oep = entry_point_rva_override.unwrap_or(0);
        let disp = (oep as i64 - jmp_site as i64) as i32;
        stub[jmp_off + 1..jmp_off + 5].copy_from_slice(&disp.to_le_bytes());
        let stub_size = stub.len() as u32;
        plan.sections.push(PlannedSection::with_rva(
            "stub",
            0xE000_0020, // CODE | EXECUTE | READ | WRITE
            stub_rva,
            stub_size,
            stub,
        ));
        meta_sections.push(TrSectionInfo {
            name: "stub".to_string(),
            rva: stub_rva,
            virtual_size: stub_size,
            sha256: String::new(),
        });
        plan.entry_point_rva = stub_rva;
        // 镜像末尾被 stub 节延伸, 报告用 size_of_image 相应增大。
        let _ = size_of_image; // provenance 原始值保留在 meta 字段下
    }

    plan.fallback_data_directories = Some(fallback);

    let mut meta_size_of_image = size_of_image;
    if let Some(last) = plan.sections.last() {
        if let Some(va) = last.virtual_address {
            let end = va + last.virtual_size;
            let aligned = (end + plan.section_alignment - 1) & !(plan.section_alignment - 1);
            if aligned > meta_size_of_image {
                meta_size_of_image = aligned;
            }
        }
    }

    let meta = TrSurfaceMeta {
        image_base,
        size_of_image: meta_size_of_image,
        entry_point_tbd: entry_point_rva_override.is_none(),
        entry_point_rva: plan.entry_point_rva,
        // import/iat 现由 dump_source 目录声明接管; tls/basereloc 仍推迟。
        deferred_directories: vec!["tls", "basereloc"],
        sections: meta_sections,
    };
    Ok((plan, meta))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tr_surface_test_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_components(dir: &Path) -> (Vec<u8>, Vec<u8>) {
        let text = vec![0xCCu8; 0x800];
        let rdata = vec![0u8; 0x400];
        fs::write(dir.join("text.bin"), &text).unwrap();
        fs::write(dir.join("rdata.bin"), &rdata).unwrap();
        (text, rdata)
    }

    fn write_provenance(dir: &Path, text_sha: &str, rdata_sha: &str) -> PathBuf {
        let p = dir.join("provenance.json");
        let json = format!(
            r#"{{"image":{{"base":"0x140000000","size_of_image":"0x4000"}},
"sections":[
 {{"name":"text","rva":"0x1000","vsize":"0x800","component":"text.bin","sha256":"{text_sha}"}},
 {{"name":"rdata","rva":"0x2000","vsize":"0x400","component":"rdata.bin","sha256":"{rdata_sha}"}}
]}}"#
        );
        fs::write(&p, json).unwrap();
        p
    }

    fn sha_of(b: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b);
        hex_lower(&h.finalize())
    }

    #[test]
    fn assembles_parseable_image_from_synthetic_components() {
        let dir = tempdir("ok");
        let (text, _rdata) = write_components(&dir);
        let prov = write_provenance(&dir, &sha_of(&text), &sha_of(vec![0u8; 0x400].as_slice()));

        let (plan, meta) = build_tr_surface_plan(&dir, &prov, None).expect("assemble plan");
        assert!(meta.entry_point_tbd);
        assert_eq!(meta.image_base, 0x1_4000_0000);
        assert_eq!(meta.size_of_image, 0x4000);
        assert_eq!(meta.sections.len(), 2);

        let image = super::super::rebuild_pe_image(&plan).expect("rebuild");
        assert_eq!(&image[0..2], b"MZ");
        let pe = crate::header::PeHeader::from_bytes(&image).expect("parse own output");
        assert_eq!(pe.sections.len(), 2);
        assert!(
            pe.sections[0].name.starts_with("text"),
            "got {}",
            pe.sections[0].name
        );
        assert_eq!(pe.nt_headers.optional_header.image_base, 0x1_4000_0000);
        // EntryPoint 置零且 ep_tbd 标注 —— 不假装知道 OEP。
        assert_eq!(pe.nt_headers.optional_header.address_of_entry_point, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_component_sha_mismatch() {
        let dir = tempdir("bad");
        let (text, _r) = write_components(&dir);
        let bad_rdata_sha = sha_of(&[0xAB; 0x400]); // 与实际内容不符
        let prov = write_provenance(&dir, &sha_of(&text), &bad_rdata_sha);
        let err = build_tr_surface_plan(&dir, &prov, None).expect_err("must fail on mismatch");
        assert!(err.contains("sha256 mismatch"), "unexpected error: {err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
