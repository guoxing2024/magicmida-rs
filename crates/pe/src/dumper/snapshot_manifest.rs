//! Dump snapshot manifest — observable capture contract for heap/container restore.
//!
//! Written beside the dumped PE as `{stem}.dump_snapshot.json` so runs can be
//! compared without parsing `.boot` payload bytes. Research / quality tool only;
//! not part of R0B acceptance and never decides dump success.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

use super::capture_policy::DumpCapturePolicy;
use super::container_snapshot::ContainerSnapshot;
use super::heap_global_snapshot::HeapGlobalSnapshot;
use super::types::DumpProfile;

pub(crate) const SCHEMA_VERSION: &str = "mida.dump-snapshot-manifest/v0";

/// Sidecar path next to the dumped PE: `foo.exe` → `foo.dump_snapshot.json`.
pub fn manifest_path_for_output(output_path: &Path) -> PathBuf {
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = output_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("dump");
    parent.join(format!("{stem}.dump_snapshot.json"))
}

/// Build and write a dump snapshot manifest. Best-effort: logs on failure.
pub(crate) fn write_dump_snapshot_manifest(
    output_path: &Path,
    profile: DumpProfile,
    image_base: u64,
    entry_point_rva: u32,
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    capture_policy: &DumpCapturePolicy,
) {
    let path = manifest_path_for_output(output_path);
    match render_manifest_json(
        output_path,
        profile,
        image_base,
        entry_point_rva,
        containers,
        heap_globals,
        capture_policy,
    ) {
        Ok(json) => match fs::File::create(&path).and_then(|mut f| f.write_all(json.as_bytes())) {
            Ok(()) => {
                info!(
                    path = %path.display(),
                    containers = containers.len(),
                    heap_globals = heap_globals.len(),
                    "Wrote dump snapshot manifest"
                );
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to write dump snapshot manifest (dump PE still valid)"
                );
            }
        },
        Err(e) => {
            warn!(
                error = %e,
                "Failed to render dump snapshot manifest (dump PE still valid)"
            );
        }
    }
}

fn profile_label(profile: DumpProfile) -> &'static str {
    match profile {
        DumpProfile::OreansClassic => "OreansClassic",
        DumpProfile::AhkGtoExperimental => "AhkGtoExperimental",
    }
}

fn hex_u32(v: u32) -> String {
    format!("{v:#x}")
}

fn hex_u64(v: u64) -> String {
    format!("{v:#x}")
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Render manifest JSON (stable key order, hand-rolled — no serde dep on mida-pe).
pub(crate) fn render_manifest_json(
    output_path: &Path,
    profile: DumpProfile,
    image_base: u64,
    entry_point_rva: u32,
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    capture_policy: &DumpCapturePolicy,
) -> Result<String, String> {
    let container_payload: u64 = containers.iter().map(|c| c.heap_content.len() as u64).sum();
    let heap_payload: u64 = heap_globals
        .iter()
        .filter(|g| !g.is_heap_handle)
        .map(|g| g.content.len() as u64)
        .sum();
    let graph_children = heap_globals.iter().filter(|g| g.rva == 0).count();
    let image_roots = heap_globals
        .iter()
        .filter(|g| g.rva != 0 && !g.is_heap_handle)
        .count();
    let heap_handles = heap_globals.iter().filter(|g| g.is_heap_handle).count();

    let mut buf = String::with_capacity(4096 + heap_globals.len() * 96);
    buf.push_str("{\n");
    buf.push_str(&format!("  \"schema_version\": \"{}\",\n", SCHEMA_VERSION));
    buf.push_str(&format!(
        "  \"output_path\": \"{}\",\n",
        json_escape(&output_path.display().to_string())
    ));
    buf.push_str(&format!("  \"profile\": \"{}\",\n", profile_label(profile)));
    buf.push_str(&format!("  \"image_base\": \"{}\",\n", hex_u64(image_base)));
    buf.push_str(&format!(
        "  \"entry_point_rva\": \"{}\",\n",
        hex_u32(entry_point_rva)
    ));

    // Resolved capture policy (post plugin-hint + profile). Observable only.
    buf.push_str("  \"capture_policy\": {\n");
    buf.push_str(&format!(
        "    \"source\": \"{}\",\n",
        capture_policy.source_label()
    ));
    buf.push_str(&format!(
        "    \"hot_root_count\": {},\n",
        capture_policy.hot_root_rvas.len()
    ));
    buf.push_str("    \"hot_root_rvas\": [");
    for (i, rva) in capture_policy.hot_root_rvas.iter().enumerate() {
        if i > 0 {
            buf.push_str(", ");
        }
        buf.push_str(&format!("\"{}\"", hex_u32(*rva)));
    }
    buf.push_str("],\n");
    buf.push_str(&format!(
        "    \"gscript_root_rva\": {},\n",
        match capture_policy.gscript_root() {
            Some(r) => format!("\"{}\"", hex_u32(r)),
            None => "null".to_string(),
        }
    ));
    buf.push_str(&format!(
        "    \"gscript_content_cap\": {},\n",
        capture_policy.gscript_content_cap()
    ));
    buf.push_str(&format!(
        "    \"first_hop_span\": {},\n",
        capture_policy.first_hop_span()
    ));
    buf.push_str(&format!(
        "    \"expand_seed_count\": {}\n",
        capture_policy.hot_expand_seed_rvas.len()
    ));
    buf.push_str("  },\n");

    buf.push_str("  \"containers\": [\n");
    for (i, c) in containers.iter().enumerate() {
        let content_size = c.decoded_end.saturating_sub(c.decoded_begin);
        let capacity_size = c.decoded_capacity.saturating_sub(c.decoded_begin);
        buf.push_str("    {\n");
        buf.push_str(&format!("      \"rva\": \"{}\",\n", hex_u32(c.rva)));
        buf.push_str(&format!("      \"content_size\": {content_size},\n"));
        buf.push_str(&format!("      \"capacity_size\": {capacity_size},\n"));
        buf.push_str(&format!(
            "      \"payload_bytes\": {},\n",
            c.heap_content.len()
        ));
        buf.push_str(&format!(
            "      \"live_begin\": \"{}\",\n",
            hex_u64(c.decoded_begin)
        ));
        buf.push_str(&format!("      \"cookie\": \"{}\"\n", hex_u64(c.cookie)));
        buf.push_str("    }");
        if i + 1 < containers.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ],\n");

    buf.push_str("  \"heap_globals\": [\n");
    for (i, g) in heap_globals.iter().enumerate() {
        let payload = if g.is_heap_handle {
            0usize
        } else {
            g.content.len()
        };
        buf.push_str("    {\n");
        buf.push_str(&format!("      \"rva\": \"{}\",\n", hex_u32(g.rva)));
        buf.push_str(&format!("      \"content_size\": {payload},\n"));
        buf.push_str(&format!(
            "      \"live_ptr\": \"{}\",\n",
            hex_u64(g.live_ptr)
        ));
        buf.push_str(&format!(
            "      \"is_heap_handle\": {},\n",
            if g.is_heap_handle { "true" } else { "false" }
        ));
        buf.push_str(&format!(
            "      \"is_image_inline\": {},\n",
            if g.is_image_inline { "true" } else { "false" }
        ));
        buf.push_str(&format!(
            "      \"is_graph_child\": {}\n",
            if g.rva == 0 { "true" } else { "false" }
        ));
        buf.push_str("    }");
        if i + 1 < heap_globals.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ],\n");

    buf.push_str("  \"summary\": {\n");
    buf.push_str(&format!("    \"container_count\": {},\n", containers.len()));
    buf.push_str(&format!(
        "    \"heap_global_count\": {},\n",
        heap_globals.len()
    ));
    buf.push_str(&format!("    \"image_roots\": {image_roots},\n"));
    buf.push_str(&format!("    \"graph_children\": {graph_children},\n"));
    buf.push_str(&format!("    \"heap_handles\": {heap_handles},\n"));
    buf.push_str(&format!(
        "    \"container_payload_bytes\": {container_payload},\n"
    ));
    buf.push_str(&format!(
        "    \"heap_global_payload_bytes\": {heap_payload},\n"
    ));
    buf.push_str(&format!(
        "    \"total_capture_payload_bytes\": {}\n",
        container_payload.saturating_add(heap_payload)
    ));
    buf.push_str("  }\n");
    buf.push_str("}\n");
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_path_uses_stem() {
        let p = PathBuf::from(r"D:\out\gto_unpacked.exe");
        let m = manifest_path_for_output(&p);
        assert_eq!(
            m.file_name().and_then(|s| s.to_str()),
            Some("gto_unpacked.dump_snapshot.json")
        );
    }

    #[test]
    fn empty_capture_renders() {
        let json = render_manifest_json(
            Path::new("out.exe"),
            DumpProfile::OreansClassic,
            0x140000000,
            0x1000,
            &[],
            &[],
            &DumpCapturePolicy::default(),
        )
        .unwrap();
        assert!(json.contains(SCHEMA_VERSION));
        assert!(json.contains("\"container_count\": 0"));
        assert!(json.contains("\"heap_global_count\": 0"));
        assert!(json.contains("OreansClassic"));
        assert!(json.contains("\"source\": \"empty\""));
        assert!(json.contains("\"hot_root_count\": 0"));
    }

    #[test]
    fn one_container_and_root_render() {
        let containers = [ContainerSnapshot {
            rva: 0x145710,
            decoded_begin: 0x89e5b0,
            decoded_end: 0x89e5f8,
            decoded_capacity: 0x89e6b0,
            cookie: 0x8610479a1eb2,
            heap_content: vec![0u8; 72],
        }];
        let heap_globals = [
            HeapGlobalSnapshot {
                rva: 0x141bf0,
                live_ptr: 0x3971ff0,
                content: vec![0u8; 0x4000],
                is_heap_handle: false,
                is_image_inline: false,
            },
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x10000,
                content: vec![0u8; 64],
                is_heap_handle: false,
                is_image_inline: false,
            },
        ];
        let policy = DumpCapturePolicy::ahk_gto_default();
        let json = render_manifest_json(
            Path::new("cand.exe"),
            DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &containers,
            &heap_globals,
            &policy,
        )
        .unwrap();
        assert!(json.contains("0x145710"));
        assert!(json.contains("0x141bf0"));
        assert!(json.contains("\"content_size\": 16384"));
        assert!(json.contains("\"graph_children\": 1"));
        assert!(json.contains("\"image_roots\": 1"));
        assert!(json.contains("\"heap_global_payload_bytes\": 16448"));
        assert!(json.contains("\"container_payload_bytes\": 72"));
        assert!(json.contains("\"source\": \"ahk_gto_defaults\""));
        assert!(json.contains("\"0x149d50\""));
    }
}
