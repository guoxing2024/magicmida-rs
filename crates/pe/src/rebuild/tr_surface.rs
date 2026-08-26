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

/// Build a [`RebuildPlan`] from TR carved components + provenance.
///
/// Returns the plan plus assembly metadata. Call [`super::rebuild_pe_image`]
/// on the plan to emit candidate bytes.
pub fn build_tr_surface_plan(
    components_dir: &Path,
    provenance_path: &Path,
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
    plan.entry_point_rva = 0; // ep_tbd: OEP recovery is a later phase
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

    plan.fallback_data_directories = Some(fallback);

    let meta = TrSurfaceMeta {
        image_base,
        size_of_image,
        entry_point_tbd: true,
        deferred_directories: vec!["import", "iat", "tls", "basereloc"],
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

        let (plan, meta) = build_tr_surface_plan(&dir, &prov).expect("assemble plan");
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
        let err = build_tr_surface_plan(&dir, &prov).expect_err("must fail on mismatch");
        assert!(err.contains("sha256 mismatch"), "unexpected error: {err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
