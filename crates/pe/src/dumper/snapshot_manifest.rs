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
use super::heap_global_snapshot::{
    HeapGlobalSnapshot, SyntheticAssignment, SyntheticRegionRequest,
};
use super::runtime_rebase::RuntimeRebaseSummary;
use super::types::DumpProfile;

pub(crate) const SCHEMA_VERSION: &str = "mida.dump-snapshot-manifest/v0";

/// Route T R0 AF2 (TAF2-E): a single authoritative-slab ledger entry. Records the
/// slab's identity (base/size), its raw (captured) digest, its patched (after
/// overlay) digest, its role (main / dedicated / alias), its normalization, and
/// the source. This proves the runtime slab set == overlay slab set == manifest
/// declared set (TAF1-F).
#[derive(Debug, Clone)]
pub struct AuthoritativeSlabLedgerEntry {
    /// Sequence (index into the normalized slab set).
    pub sequence: usize,
    /// Role: "main" | "dedicated" | "alias".
    pub role: &'static str,
    /// Old base of the slab.
    pub old_base: u64,
    /// Slab size in bytes.
    pub size: usize,
    /// sha256 of the RAW slab bytes (before overlay).
    pub raw_digest: String,
    /// sha256 of the PATCHED slab bytes (after overlay). Empty when the slab was
    /// not overlaid (no child wrote to it).
    pub patched_digest: String,
    /// Normalization: kept | deduplicated | contained_exact_alias.
    pub normalization: &'static str,
    /// Source: "main" | "dedicated".
    pub source: &'static str,
}

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
    rebase_summary: Option<&RuntimeRebaseSummary>,
    overlay_ledger: &[super::raw_slab_coherence::TransformedRegionOverlay],
    capture_drift_ledger: &[super::raw_slab_coherence::CaptureDriftRun],
    transform_preimage_ledger: &[super::raw_slab_coherence::TransformPreimageBinding],
    transform_run_ledger: &super::raw_slab_coherence::TransformRunLedger,
    synthetic_requests: &[SyntheticRegionRequest],
    synthetic_assignment_ledger: &[SyntheticAssignment],
    authoritative_slab_ledger: &[AuthoritativeSlabLedgerEntry],
    normalization_events: &[super::raw_slab_coherence::NormalizationEvent],
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
        rebase_summary,
        overlay_ledger,
        capture_drift_ledger,
        transform_preimage_ledger,
        transform_run_ledger,
        synthetic_requests,
        synthetic_assignment_ledger,
        authoritative_slab_ledger,
        normalization_events,
    ) {
        Ok(json) => match fs::File::create(&path).and_then(|mut f| f.write_all(json.as_bytes())) {
            Ok(()) => {
                info!(
                    path = %path.display(),
                    containers = containers.len(),
                    heap_globals = heap_globals.len(),
                    rebase = rebase_summary.is_some(),
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

/// Lowercase hex encoding of a byte slice (for manifest byte evidence).
fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
    rebase_summary: Option<&RuntimeRebaseSummary>,
    overlay_ledger: &[super::raw_slab_coherence::TransformedRegionOverlay],
    capture_drift_ledger: &[super::raw_slab_coherence::CaptureDriftRun],
    transform_preimage_ledger: &[super::raw_slab_coherence::TransformPreimageBinding],
    transform_run_ledger: &super::raw_slab_coherence::TransformRunLedger,
    synthetic_requests: &[SyntheticRegionRequest],
    synthetic_assignment_ledger: &[SyntheticAssignment],
    authoritative_slab_ledger: &[AuthoritativeSlabLedgerEntry],
    normalization_events: &[super::raw_slab_coherence::NormalizationEvent],
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

    // GTO R0 runtime rebase summary (offline diagnostic; never acceptance).
    // Present only on the AhkGtoExperimental recovery path. State is one of
    // Complete / Incomplete / Rejected — never acceptance terms.
    if let Some(s) = rebase_summary {
        buf.push_str(",\n");
        buf.push_str("  \"runtime_rebase\": {\n");
        buf.push_str(&format!("    \"regions_total\": {},\n", s.regions_total));
        buf.push_str(&format!(
            "    \"regions_required\": {},\n",
            s.regions_required
        ));
        buf.push_str(&format!("    \"bytes_captured\": {},\n", s.bytes_captured));
        buf.push_str(&format!(
            "    \"pointer_slots_total\": {},\n",
            s.pointer_slots_total
        ));
        buf.push_str(&format!(
            "    \"intra_region_pointers\": {},\n",
            s.intra_region_pointers
        ));
        buf.push_str(&format!("    \"image_pointers\": {},\n", s.image_pointers));
        buf.push_str(&format!(
            "    \"external_pointers\": {},\n",
            s.external_pointers
        ));
        buf.push_str(&format!("    \"null_or_tagged\": {},\n", s.null_or_tagged));
        buf.push_str(&format!("    \"fixup_count\": {},\n", s.fixup_count));
        buf.push_str(&format!("    \"resolver_count\": {},\n", s.resolver_count));
        buf.push_str(&format!(
            "    \"candidate_count\": {},\n",
            s.candidate_count
        ));
        buf.push_str(&format!(
            "    \"bootstrap_contract_valid\": {},\n",
            s.bootstrap_contract_valid
        ));
        buf.push_str(&format!(
            "    \"unresolved_required\": {},\n",
            s.unresolved_required
        ));
        buf.push_str(&format!(
            "    \"unresolved_optional\": {},\n",
            s.unresolved_optional
        ));
        buf.push_str(&format!(
            "    \"image_roots_patched\": {},\n",
            s.image_roots_patched
        ));
        buf.push_str(&format!(
            "    \"bootstrap_kind\": \"{}\",\n",
            json_escape(&s.bootstrap_kind)
        ));
        buf.push_str(&format!(
            "    \"bootstrap_rva\": {},\n",
            s.bootstrap_rva
                .map(|r| format!("\"{}\"", hex_u32(r)))
                .unwrap_or_else(|| "null".to_string())
        ));
        buf.push_str(&format!(
            "    \"original_oep_rva\": \"{}\",\n",
            hex_u32(s.original_oep_rva)
        ));
        buf.push_str(&format!(
            "    \"completion_cookie_rva\": {},\n",
            s.completion_cookie_rva
                .map(|r| format!("\"{}\"", hex_u32(r)))
                .unwrap_or_else(|| "null".to_string())
        ));
        buf.push_str(&format!(
            "    \"deterministic_plan_digest\": \"{}\",\n",
            s.deterministic_plan_digest
        ));
        buf.push_str(&format!(
            "    \"recovery_status\": \"{}\"\n",
            s.recovery_status.label()
        ));
        buf.push_str("  }\n");
    }

    // GTO R0-F capture extent ledger: records each heap-global's extent
    // classification (ProbeWindow vs ObservedAllocation vs InteriorSubview vs
    // BackingObject vs SyntheticDerived). Diagnostic only — never acceptance.
    buf.push_str(",\n");
    buf.push_str("  \"capture_extent_ledger\": [\n");
    let data_globals: Vec<&HeapGlobalSnapshot> = heap_globals
        .iter()
        .filter(|g| !g.is_heap_handle && !g.content.is_empty())
        .collect();
    for (i, g) in data_globals.iter().enumerate() {
        let extent_label = match g.extent_kind {
            super::heap_global_snapshot::CaptureExtentKind::ProbeWindow => "probe_window",
            super::heap_global_snapshot::CaptureExtentKind::ObservedAllocation => {
                "observed_allocation"
            }
            super::heap_global_snapshot::CaptureExtentKind::BackingObject => "backing_object",
            super::heap_global_snapshot::CaptureExtentKind::InteriorSubview => "interior_subview",
            super::heap_global_snapshot::CaptureExtentKind::SyntheticDerived => "synthetic_derived",
        };
        let path_label = match g.extent_evidence.capture_path {
            super::heap_global_snapshot::CapturePath::MainSlot => "main_slot",
            super::heap_global_snapshot::CapturePath::GscriptFirstHop => "gscript_first_hop",
            super::heap_global_snapshot::CapturePath::GscriptChildLink => "gscript_child_link",
            super::heap_global_snapshot::CapturePath::GscriptLabelTableEntry => {
                "gscript_label_table_entry"
            }
            super::heap_global_snapshot::CapturePath::StringBufferChild => "string_buffer_child",
            super::heap_global_snapshot::CapturePath::DanglingEdge => "dangling_edge",
            super::heap_global_snapshot::CapturePath::ImageInline => "image_inline",
            super::heap_global_snapshot::CapturePath::Synthetic => "synthetic",
        };
        let parent = g.extent_evidence.containing_parent_old_base;
        let parent_size = g.extent_evidence.containing_parent_size;
        buf.push_str(&format!(
            "    {{\"capture_id\": \"{}\", \"capture_path\": \"{}\", \
             \"source_root_rva\": {}, \"source_slot_offset\": {}, \
             \"old_base\": \"{}\", \"size\": {}, \"extent_kind\": \"{}\", \
             \"was_interior\": {}, \"parent_old_base\": {}, \"parent_size\": {}, \
             \"transform_ids\": [{}]}}",
            json_escape(&g.extent_evidence.capture_id),
            path_label,
            g.extent_evidence
                .source_root_rva
                .map(|r| format!("\"{}\"", hex_u32(r)))
                .unwrap_or_else(|| "null".to_string()),
            g.extent_evidence
                .source_slot_offset
                .map(|o| o.to_string())
                .unwrap_or_else(|| "null".to_string()),
            hex_u64(g.live_ptr),
            g.content.len(),
            extent_label,
            g.extent_evidence.was_interior,
            parent
                .map(|p| format!("\"{}\"", hex_u64(p)))
                .unwrap_or_else(|| "null".to_string()),
            parent_size
                .map(|s| s.to_string())
                .unwrap_or_else(|| "null".to_string()),
            g.transform_ids
                .iter()
                .map(|t| format!("\"{}\"", json_escape(t)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        if i + 1 < data_globals.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ]\n");

    // GTO R0-F.1 overlap-relationship ledger: for every overlay child that is
    // a contained subview of another (or overlaps), record the relationship,
    // overlap range, common parent, and resolution. Diagnostic only.
    let subview_rels: Vec<_> = overlay_ledger
        .iter()
        .filter(|o| o.contained_in_old_base.is_some())
        .collect();
    buf.push_str(",\n");
    buf.push_str("  \"overlap_relationship_ledger\": [\n");
    for (i, o) in subview_rels.iter().enumerate() {
        let parent = o.contained_in_old_base.unwrap();
        buf.push_str(&format!(
            "    {{\"child_old_base\": \"{}\", \"child_size\": {}, \
             \"parent_old_base\": \"{}\", \"relationship\": \"ContainedSubview\", \
             \"overlap_start\": \"{}\", \"overlap_size\": {}, \
             \"common_parent\": \"{}\", \"resolution\": \"AbsorbedAsSlabOwnedAlias\"}}",
            hex_u64(o.child_old_base),
            o.child_size,
            hex_u64(parent),
            hex_u64(o.child_old_base),
            o.child_size,
            hex_u64(parent)
        ));
        if i + 1 < subview_rels.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ]\n");

    // GTO R0-F.1 transformed-write ledger: summarize per-child write runs.
    buf.push_str(",\n");
    buf.push_str("  \"transformed_write_ledger\": [\n");
    for (i, o) in overlay_ledger.iter().enumerate() {
        let transform_ids = o
            .transform_ids
            .iter()
            .map(|t| format!("\"{}\"", json_escape(t)))
            .collect::<Vec<_>>()
            .join(", ");
        buf.push_str(&format!(
            "    {{\"child_capture_id\": \"\", \"child_old_base\": \"{}\", \
             \"child_size\": {}, \"slab_offset\": {}, \
             \"transformed_digest\": \"{}\", \"transform_ids\": [{}], \
             \"resolution\": \"{}\"}}",
            hex_u64(o.child_old_base),
            o.child_size,
            o.slab_offset,
            o.transformed_child_digest,
            transform_ids,
            if o.overlay_applied {
                "AppliedUniqueWrite"
            } else {
                "NoTransform"
            }
        ));
        if i + 1 < overlay_ledger.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ]\n");

    // GTO R0-C.1 raw-slab overlay ledger (build-time diagnostic; never
    // acceptance). Proves raw coherence + transformed-child overlay applied to
    // the patched backing slab.
    if !overlay_ledger.is_empty() {
        buf.push_str(",\n");
        buf.push_str("  \"overlay_ledger\": [\n");
        for (i, o) in overlay_ledger.iter().enumerate() {
            buf.push_str(&format!(
                "    {{\"child_kind\": \"{}\", \"child_old_base\": \"{}\", \
                 \"child_size\": {}, \"slab_offset\": {}, \
                 \"raw_child_sha256\": \"{}\", \"raw_slab_slice_sha256\": \"{}\", \
                 \"transformed_child_sha256\": \"{}\", \"overlay_applied\": {}, \
                 \"contained_in_old_base\": {}}}",
                o.child_kind.label(),
                hex_u64(o.child_old_base),
                o.child_size,
                o.slab_offset,
                o.raw_child_digest,
                o.raw_slab_slice_digest,
                o.transformed_child_digest,
                o.overlay_applied,
                match o.contained_in_old_base {
                    Some(base) => format!("\"{}\"", hex_u64(base)),
                    None => "null".to_string(),
                }
            ));
            if i + 1 < overlay_ledger.len() {
                buf.push(',');
            }
            buf.push('\n');
        }
        buf.push_str("  ]\n");
    }

    // GTO R0-G capture-drift ledger: records each probe/interior non-write drift
    // run resolved to the authoritative slab (B[i]=S[i]) or a strict-extent
    // rejection / transform-preimage drift that failed closed. Diagnostic only.
    buf.push_str(",\n");
    buf.push_str("  \"capture_drift_ledger\": [\n");
    for (i, d) in capture_drift_ledger.iter().enumerate() {
        let resolution_label = match d.resolution {
            super::raw_slab_coherence::CaptureDriftResolution::NonWriteSlabAuthoritative => {
                "NonWriteSlabAuthoritative"
            }
            super::raw_slab_coherence::CaptureDriftResolution::TransformPreimageDrift => {
                "TransformPreimageDrift"
            }
            super::raw_slab_coherence::CaptureDriftResolution::StrictExtentRejected => {
                "StrictExtentRejected"
            }
            super::raw_slab_coherence::CaptureDriftResolution::TransformReplayedOnAuthoritativePreimage => {
                "TransformReplayedOnAuthoritativePreimage"
            }
        };
        buf.push_str(&format!(
            "    {{\"child_capture_id\": \"{}\", \"child_old_base\": \"{}\", \
             \"child_offset\": {}, \"slab_offset\": {}, \"length\": {}, \
             \"child_digest\": \"{}\", \"slab_digest\": \"{}\", \
             \"intersects_transform_write\": {}, \"resolution\": \"{}\"}}",
            json_escape(&d.child_capture_id),
            hex_u64(d.child_old_base),
            d.child_offset,
            d.slab_offset,
            d.length,
            d.child_digest,
            d.slab_digest,
            d.intersects_transform_write,
            resolution_label
        ));
        if i + 1 < capture_drift_ledger.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ]\n");

    // Route Q R0 Q0-A: transform-preimage ledger. Proves the preimage basis of
    // every transformed child: for probe/interior views the transform input was
    // seeded from the authoritative slab slice S (AuthoritativeSlabSlice,
    // transform_input_digest == sha256(S)); for strict extents the child capture
    // C is used only after proving C == S (ChildCapture). This is the audit
    // evidence that transforms ran on the authoritative preimage, never on a
    // stale child capture. Diagnostic only — never acceptance.
    //
    // Route T R0 AF2 (TAF2-E): the authoritative slab ledger proves the RUNTIME
    // slab set == OVERLAY slab set == MANIFEST declared set. Each entry carries
    // base, size, raw_digest, patched_digest, role, normalization, source.
    buf.push_str(",\n");
    buf.push_str("  \"authoritative_slab_ledger\": [\n");
    for (i, e) in authoritative_slab_ledger.iter().enumerate() {
        buf.push_str(&format!(
            "    {{\"sequence\": {}, \"role\": \"{}\", \"old_base\": \"{}\", \
             \"size\": {}, \"raw_digest\": \"{}\", \"patched_digest\": \"{}\", \
             \"normalization\": \"{}\", \"source\": \"{}\"}}",
            e.sequence,
            e.role,
            hex_u64(e.old_base),
            e.size,
            e.raw_digest,
            e.patched_digest,
            e.normalization,
            e.source
        ));
        if i + 1 < authoritative_slab_ledger.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ],\n");
    // Route T R0 AF3 (TAF3-B): the normalization event ledger answers which input
    // slab was dropped (dedup / contained alias), why, which survivor it belongs
    // to, its original digest, and the interval relationship. This proves the raw
    // authority set -> survivor mapping is complete and honest.
    buf.push_str("  \"normalization_events\": [\n");
    for (i, e) in normalization_events.iter().enumerate() {
        buf.push_str(&format!(
            "    {{\"input_sequence\": {}, \"input_role\": \"{}\", \"input_old_base\": \"{}\", \
             \"input_size\": {}, \"input_raw_digest\": \"{}\", \"action\": \"{}\", \
             \"survivor_sequence\": {}, \"relationship\": \"{}\"}}",
            e.input_sequence,
            e.input_role,
            hex_u64(e.input_old_base),
            e.input_size,
            e.input_raw_digest,
            e.action,
            e.survivor_sequence
                .map(|s| s.to_string())
                .unwrap_or_else(|| "null".into()),
            e.relationship
        ));
        if i + 1 < normalization_events.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ],\n");
    buf.push_str("  \"transform_preimage_ledger\": [\n");
    for (i, b) in transform_preimage_ledger.iter().enumerate() {
        let basis_label = match b.basis {
            super::raw_slab_coherence::TransformPreimageBasis::ChildCapture => "ChildCapture",
            super::raw_slab_coherence::TransformPreimageBasis::AuthoritativeSlabSlice => {
                "AuthoritativeSlabSlice"
            }
        };
        buf.push_str(&format!(
            "    {{\"child_kind\": \"{}\", \"capture_id\": \"{}\", \
             \"child_old_base\": \"{}\", \"child_size\": {}, \
             \"extent_kind\": \"{:?}\", \"slab_old_base\": \"{}\", \
             \"slab_size\": {}, \"slab_digest\": \"{}\", \"slab_offset\": {}, \"basis\": \"{}\", \
             \"raw_child_digest\": \"{}\", \"raw_slab_slice_digest\": \"{}\", \
             \"transform_input_digest\": \"{}\", \"seeded_from_slab\": {}}}",
            b.child_kind.label(),
            json_escape(&b.capture_id),
            hex_u64(b.child_old_base),
            b.child_size,
            b.extent_kind,
            hex_u64(b.slab_old_base),
            b.slab_size,
            b.slab_digest,
            b.slab_offset,
            basis_label,
            b.raw_child_digest,
            b.raw_slab_slice_digest,
            b.transform_input_digest,
            b.seeded_from_slab
        ));
        if i + 1 < transform_preimage_ledger.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ]\n");

    // Route Q R0 Q0-A AF1 Rev 2: byte/run transform write-run ledger. Produced by
    // the production pipeline (every transform diffs before/after and records
    // contiguous changed-byte runs, in execution order). Each run carries its
    // execution `sequence`, full child identity, offset/length, complete
    // before/after bytes (hex) and self-consistent digests, so a live consumer
    // can independently re-sha the digests, replay overlapping writer chains in
    // order, and determine the final writer (e.g. `repair_label_names_after_scrub`
    // for child +0x28, not `mark_labels_non_nested` which only writes +0x23).
    // Diagnostic only; array order is execution order (never sorted/deduped).
    buf.push_str(",\n");
    buf.push_str("  \"transform_write_run_ledger\": [\n");
    for (i, r) in transform_run_ledger.runs.iter().enumerate() {
        buf.push_str(&format!(
            "    {{\"sequence\": {}, \"child_capture_id\": \"{}\", \
             \"child_old_base\": \"{}\", \"child_size\": {}, \
             \"child_offset\": {}, \"length\": {}, \"transform_id\": \"{}\", \
             \"before_digest\": \"{}\", \"after_digest\": \"{}\", \
             \"first_before_byte\": {}, \"first_after_byte\": {}, \
             \"before_bytes_hex\": \"{}\", \"after_bytes_hex\": \"{}\"}}",
            i,
            json_escape(&r.child_capture_id),
            hex_u64(r.child_old_base),
            r.child_size,
            r.child_offset,
            r.length,
            json_escape(&r.transform_id),
            r.before_digest,
            r.after_digest,
            r.first_before_byte,
            r.first_after_byte,
            hex_bytes(&r.before_bytes),
            hex_bytes(&r.after_bytes)
        ));
        if i + 1 < transform_run_ledger.runs.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ]\n");

    // GTO R0-F.2 synthetic-assignment ledger: records the deterministic
    // collision-free logical-base assignment for every synthetic region request
    // (window class / title), with its source anchor, payload size, construction
    // digest, assigned base, alignment, ownership/extent, and whether the
    // pointer slot was rewritten. Also records the assignment algorithm version.
    // Diagnostic only — never acceptance.
    buf.push_str(",\n");
    buf.push_str("  \"synthetic_assignment_ledger\": [\n");
    for (i, a) in synthetic_assignment_ledger.iter().enumerate() {
        let req = synthetic_requests
            .iter()
            .find(|r| r.synthetic_id == a.synthetic_id);
        let source_anchor = req
            .map(|r| json_escape(&r.source_anchor))
            .unwrap_or_default();
        let payload_size = req.map(|r| r.payload.len()).unwrap_or(0);
        let construction_digest = req
            .map(|r| json_escape(&r.construction_digest))
            .unwrap_or_default();
        let expected_anchor_count = req.map(|r| r.pointer_slots.len()).unwrap_or(0);
        // GTO R0-F.2.1: rewrite status comes from the PRODUCTION result
        // (rewritten_anchor_count + materialized), never inferred from a
        // non-empty slot list.
        let rewritten_anchor_count = a.rewritten_anchor_count;
        let anchor_rewrite_verified =
            a.rewritten_anchor_count > 0 && a.rewritten_anchor_count == expected_anchor_count;
        buf.push_str(&format!(
            "    {{\"synthetic_id\": \"{}\", \"request_digest\": \"{}\", \
             \"transform_id\": \"{}\", \
             \"source_anchor\": \"{}\", \"payload_size\": {}, \
             \"construction_digest\": \"{}\", \
             \"assigned_logical_old_base\": \"{}\", \"alignment\": {}, \
             \"expected_anchor_count\": {}, \"rewritten_anchor_count\": {}, \
             \"anchor_rewrite_verified\": {}, \"materialized\": {}, \
             \"ownership\": \"synthetic_allocation\", \"extent_kind\": \"synthetic_derived\", \
             \"collision_checked\": true}}",
            json_escape(&a.synthetic_id),
            json_escape(&a.request_digest),
            json_escape(req.map(|r| r.transform_id.as_str()).unwrap_or("")),
            source_anchor,
            payload_size,
            construction_digest,
            hex_u64(a.assigned_logical_old_base),
            a.assignment_alignment,
            expected_anchor_count,
            rewritten_anchor_count,
            anchor_rewrite_verified,
            a.materialized
        ));
        if i + 1 < synthetic_assignment_ledger.len() {
            buf.push(',');
        }
        buf.push('\n');
    }
    buf.push_str("  ],\n");
    buf.push_str(&format!(
        "  \"synthetic_assignment_algorithm_version\": {}\n",
        synthetic_assignment_algorithm_version()
    ));
    buf.push_str("}\n");
    Ok(buf)
}

/// Version of the deterministic synthetic assignment algorithm (GTO R0-F.2 /
/// R0-F.2.1). Version 2: assignments are identity-bound (request_digest) with
/// real rewrite/materialization evidence; checked alignment on all jumps.
pub(crate) fn synthetic_assignment_algorithm_version() -> u32 {
    2
}

#[cfg(test)]
mod tests {
    use super::super::heap_global_snapshot::{
        CaptureExtentEvidence, CaptureExtentKind, RegionProvenance,
    };
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
            None,
            &[],
            &[],
            &[],
            &super::super::raw_slab_coherence::TransformRunLedger::default(),
            &[],
            &[],
            &[],
            &[],
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
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
            },
            HeapGlobalSnapshot {
                rva: 0,
                live_ptr: 0x10000,
                content: vec![0u8; 64],
                is_heap_handle: false,
                is_image_inline: false,
                extent_kind: CaptureExtentKind::default(),
                extent_evidence: CaptureExtentEvidence::default(),
                transform_ids: Vec::new(),
                provenance: RegionProvenance::default(),
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
            None,
            &[],
            &[],
            &[],
            &super::super::raw_slab_coherence::TransformRunLedger::default(),
            &[],
            &[],
            &[],
            &[],
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

    #[test]
    fn rebase_summary_renders_status_complete() {
        let summary = RuntimeRebaseSummary {
            regions_total: 3,
            regions_required: 3,
            bytes_captured: 4096,
            pointer_slots_total: 7,
            intra_region_pointers: 2,
            image_pointers: 1,
            external_pointers: 1,
            null_or_tagged: 2,
            unresolved_required: 0,
            unresolved_optional: 1,
            image_roots_patched: 1,
            bootstrap_kind: "post_crt_two_phase".to_string(),
            bootstrap_rva: Some(0x2f000),
            original_oep_rva: 0x5a10,
            completion_cookie_rva: Some(0x2ff00),
            deterministic_plan_digest: "abc123".to_string(),
            fixup_count: 7,
            resolver_count: 1,
            candidate_count: 3,
            bootstrap_contract_valid: true,
            recovery_status: crate::dumper::runtime_rebase::RebaseStatus::Complete,
        };
        let json = render_manifest_json(
            Path::new("cand.exe"),
            DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x5a10,
            &[],
            &[],
            &DumpCapturePolicy::ahk_gto_default(),
            Some(&summary),
            &[],
            &[],
            &[],
            &super::super::raw_slab_coherence::TransformRunLedger::default(),
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        assert!(json.contains("\"runtime_rebase\": {"));
        assert!(json.contains("\"regions_total\": 3"));
        assert!(json.contains("\"unresolved_required\": 0"));
        assert!(json.contains("\"bootstrap_kind\": \"post_crt_two_phase\""));
        assert!(json.contains("\"fixup_count\": 7"));
        assert!(json.contains("\"resolver_count\": 1"));
        assert!(json.contains("\"bootstrap_contract_valid\": true"));
        assert!(json.contains("\"completion_cookie_rva\": \"0x2ff00\""));
        assert!(json.contains("\"recovery_status\": \"Complete\""));
        assert!(json.contains("\"deterministic_plan_digest\": \"abc123\""));
    }

    // GTO R0-F.1: the manifest must serialize the capture-extent,
    // overlap-relationship, and transformed-write ledgers as valid JSON.
    #[test]
    fn r0f1_ledgers_serialize_as_valid_json() {
        use crate::dumper::container_snapshot::ContainerSnapshot;
        use crate::dumper::runtime_rebase::RuntimeRebaseSummary;
        let container = ContainerSnapshot {
            rva: 0x145710,
            decoded_begin: 0x96ad40,
            decoded_end: 0x96ad88,
            decoded_capacity: 0x96ae40,
            cookie: 0x8610479a1eb2,
            heap_content: vec![0u8; 72],
        };
        let mut heap_global = HeapGlobalSnapshot {
            rva: 0x146890,
            live_ptr: 0x96bb80,
            content: vec![0xAAu8; 0x400],
            is_heap_handle: false,
            is_image_inline: false,
            provenance: RegionProvenance::default(),
            extent_kind: CaptureExtentKind::ProbeWindow,
            extent_evidence: CaptureExtentEvidence {
                capture_id: "gscript_first_hop:0x48".to_string(),
                capture_path: super::super::heap_global_snapshot::CapturePath::GscriptFirstHop,
                source_root_rva: Some(0x149d50),
                source_slot_offset: Some(0x48),
                probe_requested_size: 0x400,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: vec!["repair_gscript_window_strings".to_string()],
        };
        // A second view that is a contained subview of the first.
        let mut subview = HeapGlobalSnapshot {
            rva: 0,
            live_ptr: 0x96bbd0,
            content: vec![0xAAu8; 0x400],
            is_heap_handle: false,
            is_image_inline: false,
            provenance: RegionProvenance::default(),
            extent_kind: CaptureExtentKind::InteriorSubview,
            extent_evidence: CaptureExtentEvidence {
                capture_id: "gscript_first_hop:0x50".to_string(),
                capture_path: super::super::heap_global_snapshot::CapturePath::GscriptFirstHop,
                source_root_rva: Some(0x149d50),
                source_slot_offset: Some(0x50),
                probe_requested_size: 0x400,
                was_interior: true,
                containing_parent_old_base: Some(0x96bb80),
                containing_parent_size: Some(0x400),
            },
            transform_ids: Vec::new(),
        };
        let _ = &mut heap_global;
        let _ = &mut subview;
        let summary = RuntimeRebaseSummary {
            regions_total: 1,
            regions_required: 1,
            bytes_captured: 0x400,
            pointer_slots_total: 0,
            intra_region_pointers: 0,
            image_pointers: 0,
            external_pointers: 0,
            null_or_tagged: 0,
            unresolved_required: 0,
            unresolved_optional: 0,
            image_roots_patched: 0,
            bootstrap_kind: "post_crt_two_phase".to_string(),
            bootstrap_rva: Some(0x2f000),
            original_oep_rva: 0x5a10,
            completion_cookie_rva: Some(0x2ff00),
            deterministic_plan_digest: "abc".to_string(),
            fixup_count: 0,
            resolver_count: 0,
            candidate_count: 1,
            bootstrap_contract_valid: true,
            recovery_status: crate::dumper::runtime_rebase::RebaseStatus::Complete,
        };
        // Overlay with a contained subview relationship.
        let overlay = vec![super::super::raw_slab_coherence::TransformedRegionOverlay {
            child_kind: super::super::raw_slab_coherence::RawChildKind::HeapGlobal,
            child_old_base: 0x96bbd0,
            child_size: 0x400,
            slab_offset: 0x81cbd0,
            raw_child_digest: "a".to_string(),
            raw_slab_slice_digest: "b".to_string(),
            transformed_child_digest: "c".to_string(),
            transform_ids: vec!["repair_gscript_window_strings".to_string()],
            overlay_applied: true,
            contained_in_old_base: Some(0x96bb80),
        }];
        let json = render_manifest_json(
            Path::new("cand.exe"),
            DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &[container],
            &[heap_global.clone(), subview.clone()],
            &DumpCapturePolicy::ahk_gto_default(),
            Some(&summary),
            &overlay,
            &[],
            &[],
            &super::super::raw_slab_coherence::TransformRunLedger::default(),
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        // The JSON must parse (valid) and contain all three ledgers.
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
        assert!(v.get("capture_extent_ledger").is_some());
        assert!(v.get("overlap_relationship_ledger").is_some());
        assert!(v.get("transformed_write_ledger").is_some());
        // The overlap ledger records the contained-subview relationship.
        let rels = v["overlap_relationship_ledger"].as_array().unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0]["relationship"], "ContainedSubview");
        // The capture-extent ledger records the first-hop source slot.
        let extents = v["capture_extent_ledger"].as_array().unwrap();
        assert!(extents
            .iter()
            .any(|e| e["capture_path"] == "gscript_first_hop"));
    }

    // GTO R0-F.2: the synthetic-assignment ledger must serialize as valid JSON
    // with the assigned logical base, source anchor, construction digest,
    // ownership/extent, pointer-slot-rewrite flag, and algorithm version.
    #[test]
    fn r0f2_synthetic_assignment_ledger_serializes_as_valid_json() {
        use super::super::heap_global_snapshot::{
            sha256_hex_pub, synthetic_request_digest, SyntheticAssignment, SyntheticPointerAnchor,
            SyntheticRegionRequest,
        };
        let payload = b"NewClassName\0".to_vec();
        let req = SyntheticRegionRequest {
            synthetic_id: "gto.window_class".to_string(),
            transform_id: "repair_gscript_window_strings".to_string(),
            source_anchor: "gscript+0xbd8 (RegisterClass lpszClassName)".to_string(),
            payload: payload.clone(),
            construction_digest: sha256_hex_pub(&payload),
            alignment: 0x10,
            pointer_slots: vec![SyntheticPointerAnchor {
                region_old_base: 0x140149d50,
                slot_offset: 0xbd8,
            }],
        };
        let assigned = vec![SyntheticAssignment {
            synthetic_id: "gto.window_class".to_string(),
            request_digest: synthetic_request_digest(&req),
            assigned_logical_old_base: 0x36f3d30,
            assignment_alignment: 0x10,
            rewritten_anchor_count: 1,
            materialized: true,
        }];
        let json = render_manifest_json(
            Path::new("cand.exe"),
            DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &[],
            &[],
            &DumpCapturePolicy::ahk_gto_default(),
            None,
            &[],
            &[],
            &[],
            &super::super::raw_slab_coherence::TransformRunLedger::default(),
            &[req.clone()],
            &assigned,
            &[],
            &[],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
        let ledger = v["synthetic_assignment_ledger"].as_array().unwrap();
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0]["synthetic_id"], "gto.window_class");
        assert_eq!(ledger[0]["assigned_logical_old_base"], "0x36f3d30");
        assert_eq!(ledger[0]["ownership"], "synthetic_allocation");
        assert_eq!(ledger[0]["extent_kind"], "synthetic_derived");
        assert_eq!(ledger[0]["collision_checked"], true);
        // GTO R0-F.2.1: rewrite status is production evidence, not inferred.
        assert_eq!(ledger[0]["expected_anchor_count"], 1);
        assert_eq!(ledger[0]["rewritten_anchor_count"], 1);
        assert_eq!(ledger[0]["anchor_rewrite_verified"], true);
        assert_eq!(ledger[0]["materialized"], true);
        assert_eq!(ledger[0]["request_digest"], synthetic_request_digest(&req));
        assert_eq!(ledger[0]["alignment"], 16);
        assert_eq!(v["synthetic_assignment_algorithm_version"], 2);
        // The ledger records the source anchor and construction digest.
        assert_eq!(
            ledger[0]["source_anchor"],
            "gscript+0xbd8 (RegisterClass lpszClassName)"
        );
        assert_eq!(ledger[0]["construction_digest"], sha256_hex_pub(&payload));
    }

    // Route Q R0 Q0-E: the manifest must independently prove the transform
    // preimage basis (probe/interior seeded from S, strict from C after C==S).
    #[test]
    fn route_q_r0e_manifest_proves_transform_preimage_basis() {
        use crate::dumper::heap_global_snapshot::{CaptureExtentKind, CapturePath};
        use crate::dumper::raw_slab_coherence::{
            FullCaptureIdentity, RawChildKind, TransformPreimageBasis, TransformPreimageBinding,
        };
        // A probe/interior binding (seeded from authoritative slab S).
        let interior = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "route-p-geometry".into(),
            child_old_base: 0x8aa5f8,
            child_size: 0x70,
            extent_kind: CaptureExtentKind::InteriorSubview,
            identity: FullCaptureIdentity::from_plain_parts(
                RawChildKind::HeapGlobal,
                "route-p-geometry".into(),
                0x8aa5f8,
                0x70,
                CaptureExtentKind::InteriorSubview,
                CapturePath::MainSlot,
                0,
            ),
            slab_old_base: 0x874000,
            slab_size: 0x48000,
            slab_digest: "slab_full_digest".into(),
            slab_offset: 0x36620,
            basis: TransformPreimageBasis::AuthoritativeSlabSlice,
            raw_child_digest: "raw_child_digest_abc".into(),
            raw_slab_slice_digest: "slab_digest_abc".into(),
            transform_input_digest: "slab_digest_abc".into(), // == sha256(S)
            seeded_from_slab: true,
        };
        // A strict binding (child capture, C==S proven).
        let strict = TransformPreimageBinding {
            child_kind: RawChildKind::HeapGlobal,
            capture_id: "strict1".into(),
            child_old_base: 0x8bb000,
            child_size: 0x40,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            identity: FullCaptureIdentity::from_plain_parts(
                RawChildKind::HeapGlobal,
                "strict1".into(),
                0x8bb000,
                0x40,
                CaptureExtentKind::ObservedAllocation,
                CapturePath::MainSlot,
                0,
            ),
            slab_old_base: 0x874000,
            slab_size: 0x48000,
            slab_digest: "slab_full_digest".into(),
            slab_offset: 0x47000,
            basis: TransformPreimageBasis::ChildCapture,
            raw_child_digest: "c_digest".into(),
            raw_slab_slice_digest: "s_digest".into(),
            transform_input_digest: "c_digest".into(), // == raw child digest
            seeded_from_slab: false,
        };
        let json = render_manifest_json(
            Path::new("cand.exe"),
            DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &[],
            &[],
            &DumpCapturePolicy::ahk_gto_default(),
            None,
            &[],
            &[],
            &[interior, strict],
            &super::super::raw_slab_coherence::TransformRunLedger::default(),
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
        let ledger = v["transform_preimage_ledger"].as_array().unwrap();
        assert_eq!(ledger.len(), 2);
        // The interior binding is AuthoritativeSlabSlice and seeded_from_slab,
        // proving the transform input came from S (transform_input_digest == S).
        let int = &ledger[0];
        assert_eq!(int["basis"], "AuthoritativeSlabSlice");
        assert_eq!(int["seeded_from_slab"], true);
        assert_eq!(int["transform_input_digest"], "slab_digest_abc");
        assert_eq!(int["extent_kind"], "InteriorSubview");
        // The strict binding is ChildCapture, not seeded.
        let st = &ledger[1];
        assert_eq!(st["basis"], "ChildCapture");
        assert_eq!(st["seeded_from_slab"], false);
        assert_eq!(st["transform_input_digest"], "c_digest");
    }

    // Route Q R0 AF1 Rev 2 (P1-2): the transform_write_run_ledger must serialize
    // full before/after bytes + execution sequence + digests so a consumer can
    // independently re-sha and replay overlapping writer chains.
    #[test]
    fn route_q_r0e_manifest_write_run_ledger_roundtrip() {
        use super::super::raw_slab_coherence::{TransformRunLedger, TransformWriteRun};
        let sha = |b: &[u8]| -> String {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(b))
        };
        // Two overlapping runs on the same child byte 0x28 (repair then sanitize),
        // plus a disjoint run on +0x23 (mark_non_nested) to test ordering.
        let mut ledger = TransformRunLedger::default();
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "c1".into(),
            child_old_base: 0x8aa5f8,
            child_size: 0x70,
            child_offset: 0x28,
            length: 1,
            transform_id: "repair_label_names_after_scrub".into(),
            before_digest: sha(&[0xf0]),
            after_digest: sha(&[0x28]),
            first_before_byte: 0xf0,
            first_after_byte: 0x28,
            before_bytes: vec![0xf0],
            after_bytes: vec![0x28],
        });
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "c1".into(),
            child_old_base: 0x8aa5f8,
            child_size: 0x70,
            child_offset: 0x28,
            length: 1,
            transform_id: "sanitize_ahk_runtime_global".into(),
            before_digest: sha(&[0x28]),
            after_digest: sha(&[0x00]),
            first_before_byte: 0x28,
            first_after_byte: 0x00,
            before_bytes: vec![0x28],
            after_bytes: vec![0x00],
        });
        ledger.runs.push(TransformWriteRun {
            child_capture_id: "c1".into(),
            child_old_base: 0x8aa5f8,
            child_size: 0x70,
            child_offset: 0x23,
            length: 1,
            transform_id: "mark_labels_non_nested".into(),
            before_digest: sha(&[0x00]),
            after_digest: sha(&[0x01]),
            first_before_byte: 0x00,
            first_after_byte: 0x01,
            before_bytes: vec![0x00],
            after_bytes: vec![0x01],
        });
        let json = render_manifest_json(
            Path::new("af1c.exe"),
            DumpProfile::AhkGtoExperimental,
            0x140000000,
            0x70b0,
            &[],
            &[],
            &DumpCapturePolicy::ahk_gto_default(),
            None,
            &[],
            &[],
            &[],
            &ledger,
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
        let wrl = v["transform_write_run_ledger"].as_array().unwrap();
        assert_eq!(wrl.len(), 3);
        // Execution order preserved (sequence 0..2), not sorted.
        assert_eq!(wrl[0]["sequence"], 0);
        assert_eq!(wrl[0]["transform_id"], "repair_label_names_after_scrub");
        assert_eq!(wrl[1]["sequence"], 1);
        assert_eq!(wrl[1]["transform_id"], "sanitize_ahk_runtime_global");
        assert_eq!(wrl[2]["sequence"], 2);
        assert_eq!(wrl[2]["transform_id"], "mark_labels_non_nested");
        // Full before/after hex bytes present and digest recomputable.
        for run in wrl.iter() {
            let before_hex = run["before_bytes_hex"].as_str().unwrap();
            let after_hex = run["after_bytes_hex"].as_str().unwrap();
            let before = hex_decode(before_hex);
            let after = hex_decode(after_hex);
            assert_eq!(sha(&before), run["before_digest"].as_str().unwrap());
            assert_eq!(sha(&after), run["after_digest"].as_str().unwrap());
            assert_eq!(run["first_before_byte"].as_u64().unwrap() as u8, before[0]);
            assert_eq!(run["first_after_byte"].as_u64().unwrap() as u8, after[0]);
        }
    }

    /// Decode a lowercase hex string into bytes (test helper).
    fn hex_decode(s: &str) -> Vec<u8> {
        let s = s.trim();
        let mut out = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let b = u8::from_str_radix(&s[i..i + 2], 16).expect("hex byte");
            out.push(b);
        }
        out
    }
}
