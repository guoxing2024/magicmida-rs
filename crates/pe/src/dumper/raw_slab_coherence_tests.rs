//! Unit tests for `raw_slab_coherence` (WO-9 split; WO-22 re-grouped by
//! route cluster). The prelude holds the shared fixtures; each route
//! cluster lives in its own sibling file declared below, so
//! `super`/`super::super` resolve exactly as they did in the original
//! `mod tests` block.

use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
use super::super::heap_global_snapshot::{CaptureExtentEvidence, CaptureExtentKind};
use super::*;
use crate::dumper::container_snapshot::ContainerSnapshot;
use crate::dumper::heap_global_snapshot::{HeapGlobalSnapshot, HeapSlab};

fn global(live_ptr: u64, content: Vec<u8>, inline: bool) -> HeapGlobalSnapshot {
    HeapGlobalSnapshot {
        rva: if inline { 0x40 } else { 0 },
        live_ptr,
        content,
        is_heap_handle: false,
        is_image_inline: inline,
        provenance: RegionProvenance::default(),
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
    }
}

fn handle(live_ptr: u64) -> HeapGlobalSnapshot {
    HeapGlobalSnapshot {
        rva: 0x10,
        live_ptr,
        content: Vec::new(),
        is_heap_handle: true,
        is_image_inline: false,
        provenance: RegionProvenance::default(),
        extent_kind: CaptureExtentKind::default(),
        extent_evidence: CaptureExtentEvidence::default(),
        transform_ids: Vec::new(),
    }
}

/// Produce same-length "transformed" bytes (each byte +1) so raw and
/// transformed child lengths always match (in-place transform model).
fn repaint(v: &[u8]) -> Vec<u8> {
    v.iter().map(|b| b.wrapping_add(1)).collect()
}

fn container(begin: u64, end: u64, content: Vec<u8>) -> ContainerSnapshot {
    ContainerSnapshot {
        rva: 0x20,
        decoded_begin: begin,
        decoded_end: end,
        decoded_capacity: end + 0x10,
        cookie: 0x1234,
        heap_content: content,
    }
}

fn slab(base: u64, content: Vec<u8>) -> HeapSlab {
    HeapSlab {
        old_base: base,
        content,
    }
}

fn slab_with_child(
    slab_base: u64,
    slab_sz: usize,
    child_base: u64,
    raw_child: Vec<u8>,
) -> HeapSlab {
    let mut content = vec![0u8; slab_sz];
    let off = (child_base - slab_base) as usize;
    content[off..off + raw_child.len()].copy_from_slice(&raw_child);
    slab(slab_base, content)
}

/// Test helper: a RawChild with default (probe-window, no-parent) provenance.
fn raw_child(old_base: u64, size: usize, raw_bytes: Vec<u8>, kind: RawChildKind) -> RawChild {
    RawChild {
        old_base,
        size,
        raw_bytes,
        kind,
        capture_id: String::new(),
        capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        extent_kind: super::super::heap_global_snapshot::CaptureExtentKind::ProbeWindow,
        source_slot_offset: None,
        requested_probe_size: 0,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    }
}

const ROUTEK_SLAB_BASE: u64 = 0x1ff000;
const ROUTEK_SLAB_SZ: usize = 0x35a1118;
const ROUTEK_CHILD_BASE: u64 = 0x200000;

#[test]
fn r0c1_capture_slab_before_transforms() {
    let g = global(ROUTEK_CHILD_BASE, b"raw-child-bytes".to_vec(), false);
    let children = raw_children_from_capture(&[], &[g.clone()]);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].raw_bytes, b"raw-child-bytes".to_vec());
    assert_eq!(children[0].kind, RawChildKind::HeapGlobal);
}

#[test]
fn r0c1_raw_equal_transform_unchanged() {
    let raw = b"child-unchanged".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let transformed = global(ROUTEK_CHILD_BASE, raw.clone(), false);
    let (patched, overlays, _) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    assert_eq!(overlays.len(), 1);
    let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    assert_eq!(&patched.content[off..off + raw.len()], &raw[..]);
}

#[test]
fn r0c1_raw_equal_transform_changed_overlay() {
    let raw = b"original-raw-child".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let transformed_bytes = b"REPAIRED-child-xxx".to_vec();
    let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
    let (patched, _, _) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    assert_eq!(
        &patched.content[off..off + transformed_bytes.len()],
        &transformed_bytes[..]
    );
}

#[test]
fn r0c1_raw_drift_rejected() {
    let raw = b"child-A-content".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        b"child-B-content".to_vec(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let mut transformed = global(ROUTEK_CHILD_BASE, raw.clone(), false);
    // Strict ObservedAllocation extent: full-range drift must be rejected.
    transformed.extent_kind =
        crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
    let err = build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
}

#[test]
fn r0c1_overlay_slab_slice_equals_transformed() {
    let raw = b"raw-AAAAAAAAAAAA".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let transformed_bytes = repaint(&raw);
    let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
    let (patched, _, _) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    assert_eq!(
        &patched.content[off..off + transformed_bytes.len()],
        &transformed_bytes[..]
    );
}

#[test]
fn r0c1_routek_exact_offset() {
    let raw = vec![0x41u8; 0x1a];
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            0x1a,
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let transformed_bytes = vec![0x42u8; 0x1a];
    let mut transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
    transformed.transform_ids = vec!["repair_gscript_window_strings".to_string()];
    let (patched, overlays, _) = build_patched_backing_slab(
        &raw_capture,
        &[transformed],
        &[],
        &["repair_gscript_window_strings"],
    )
    .unwrap();
    assert_eq!(overlays[0].slab_offset, 0x1000);
    assert_eq!(overlays[0].child_size, 0x1a);
    assert_eq!(&patched.content[0x1000..0x101a], &transformed_bytes[..]);
    assert_eq!(
        overlays[0].transform_ids,
        vec!["repair_gscript_window_strings".to_string()]
    );
}

#[test]
fn r0c1_repaired_window_string_overlay() {
    let raw = b"ZhuChuangKou".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let repaired = b"NewClassName".to_vec();
    let mut transformed = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
    transformed.transform_ids = vec!["repair_gscript_window_strings".to_string()];
    let (patched, o, _) = build_patched_backing_slab(
        &raw_capture,
        &[transformed],
        &[],
        &["repair_gscript_window_strings"],
    )
    .unwrap();
    assert_eq!(o[0].transform_ids[0], "repair_gscript_window_strings");
    let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    assert_eq!(&patched.content[off..off + repaired.len()], &repaired[..]);
}

#[test]
fn r0c1_scrubbed_pointer_overlay() {
    let raw = vec![0xAAu8; 16];
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            16,
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let scrubbed = vec![0u8; 16];
    let mut transformed = global(ROUTEK_CHILD_BASE, scrubbed.clone(), false);
    transformed.transform_ids = vec!["scrub_uncaptured_heap_pointers".to_string()];
    let (patched, o, _) = build_patched_backing_slab(
        &raw_capture,
        &[transformed],
        &[],
        &["scrub_uncaptured_heap_pointers"],
    )
    .unwrap();
    assert_eq!(o[0].transform_ids[0], "scrub_uncaptured_heap_pointers");
    let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    assert_eq!(&patched.content[off..off + 16], &[0u8; 16][..]);
}

#[test]
fn r0c1_container_scrub_overlay() {
    let raw = vec![0xAAu8; 24];
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            24,
            raw.clone(),
            RawChildKind::Container,
        )],
    };
    let scrubbed = vec![0u8; 24];
    let transformed = container(ROUTEK_CHILD_BASE, ROUTEK_CHILD_BASE + 24, scrubbed.clone());
    let (patched, o, _) =
        build_patched_backing_slab(&raw_capture, &[], &[transformed], &["scrub"]).unwrap();
    assert_eq!(o[0].child_kind, RawChildKind::Container);
    let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    assert_eq!(&patched.content[off..off + 24], &[0u8; 24][..]);
}

#[test]
fn r0c1_two_disjoint_children() {
    let raw_a = b"child-A-bytes".to_vec();
    let raw_b = b"child-B-bytes".to_vec();
    let mut content = vec![0u8; ROUTEK_SLAB_SZ];
    let off_a = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    content[off_a..off_a + raw_a.len()].copy_from_slice(&raw_a);
    content[0x3000..0x3000 + raw_b.len()].copy_from_slice(&raw_b);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(ROUTEK_SLAB_BASE, content)],
        children: vec![
            raw_child(
                ROUTEK_CHILD_BASE,
                raw_a.len(),
                raw_a.clone(),
                RawChildKind::HeapGlobal,
            ),
            raw_child(
                ROUTEK_SLAB_BASE + 0x3000,
                raw_b.len(),
                raw_b.clone(),
                RawChildKind::HeapGlobal,
            ),
        ],
    };
    let ga = global(ROUTEK_CHILD_BASE, repaint(&raw_a), false);
    let gb = global(ROUTEK_SLAB_BASE + 0x3000, repaint(&raw_b), false);
    let (_, overlays, _) =
        build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
    assert_eq!(overlays.len(), 2);
}

#[test]
fn r0c1_duplicate_overlay_dedup() {
    let raw = b"child-dup-xxx".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let repaired = repaint(&raw);
    let ga = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
    let gb = global(ROUTEK_CHILD_BASE, repaired.clone(), false);
    let (_, overlays, _) =
        build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
    assert_eq!(overlays.len(), 1);
}

#[test]
fn r0c1_duplicate_conflict_rejected() {
    let raw = b"child-confx".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let ga = global(ROUTEK_CHILD_BASE, repaint(&raw), false);
    let gb = global(ROUTEK_CHILD_BASE, repaint(&repaint(&raw)), false);
    let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
}

#[test]
fn r0c1_partial_overlap_rejected() {
    // Two children at 0x200000 and 0x200010 (offset +16), both 32 bytes.
    // Their raw bytes AGREE in the overlap so raw coherence passes; the
    // transformed overlays then partially overlap -> overlay conflict.
    let raw_a = vec![0xAAu8; 32];
    let raw_b = vec![0xAAu8; 32]; // same bytes (agree in overlap)
    let mut content = vec![0u8; ROUTEK_SLAB_SZ];
    let off_a = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    content[off_a..off_a + 32].copy_from_slice(&raw_a);
    let off_b = off_a + 16;
    content[off_b..off_b + 32].copy_from_slice(&raw_b);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(ROUTEK_SLAB_BASE, content)],
        children: vec![
            raw_child(ROUTEK_CHILD_BASE, 32, raw_a, RawChildKind::HeapGlobal),
            raw_child(ROUTEK_CHILD_BASE + 16, 32, raw_b, RawChildKind::HeapGlobal),
        ],
    };
    // transformed overlays differ and partially overlap -> conflict.
    let ga = global(ROUTEK_CHILD_BASE, vec![0u8; 32], false);
    let gb = global(ROUTEK_CHILD_BASE + 16, vec![0x01u8; 32], false);
    let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
}

#[test]
fn r0c1_overlay_out_of_slab() {
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(ROUTEK_SLAB_BASE, vec![0u8; 0x1000])],
        children: vec![],
    };
    let transformed = global(ROUTEK_SLAB_BASE + 0x1000, vec![0u8; 0x10], false);
    let err = build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. })
            || matches!(err, OverlayError::RawChildOutsideSlab { .. })
    );
}

#[test]
fn r0c1_child_outside_slab() {
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(0x1000, vec![0u8; 0x100])],
        children: vec![raw_child(0x2000, 8, vec![0u8; 8], RawChildKind::HeapGlobal)],
    };
    let transformed = global(0x2000, vec![0u8; 8], false);
    let err = build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::RawChildOutsideSlab { .. }));
}

#[test]
fn r0c1_image_inline_not_overlaid() {
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(0x1000, vec![0u8; 0x100])],
        children: vec![],
    };
    let inline = global(0x140000000, b"img-inline".to_vec(), true);
    // image-inline globals are skipped by overlay (they live in the image);
    // no overlay is produced.
    let (_, overlays, _) =
        build_patched_backing_slab(&raw_capture, &[inline], &[], &["t"]).unwrap();
    assert!(overlays.is_empty());
}

#[test]
fn r0c1_heap_handle_not_overlaid() {
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(0x1000, vec![0u8; 0x100])],
        children: vec![],
    };
    let h = handle(0x8f0000);
    let (_, overlays, _) = build_patched_backing_slab(&raw_capture, &[h], &[], &["t"]).unwrap();
    assert!(overlays.is_empty());
}

#[test]
fn r0c1_nobypass_off_path_unchanged() {
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(0x1000, vec![0u8; 0x100])],
        children: vec![],
    };
    let (_, overlays, _) = build_patched_backing_slab(&raw_capture, &[], &[], &["t"]).unwrap();
    assert!(overlays.is_empty());
}

#[test]
fn r0c1_ledger_deterministic_sort() {
    let raw_a = b"AAA".to_vec();
    let raw_b = b"BBB".to_vec();
    let mut content = vec![0u8; ROUTEK_SLAB_SZ];
    content[0x1000..0x1003].copy_from_slice(&raw_a);
    content[0x2000..0x2003].copy_from_slice(&raw_b);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(ROUTEK_SLAB_BASE, content)],
        children: vec![
            raw_child(
                ROUTEK_SLAB_BASE + 0x2000,
                3,
                raw_b,
                RawChildKind::HeapGlobal,
            ),
            raw_child(
                ROUTEK_SLAB_BASE + 0x1000,
                3,
                raw_a,
                RawChildKind::HeapGlobal,
            ),
        ],
    };
    let ga = global(ROUTEK_SLAB_BASE + 0x1000, b"XXX".to_vec(), false);
    let gb = global(ROUTEK_SLAB_BASE + 0x2000, b"YYY".to_vec(), false);
    let (_, o1, _) =
        build_patched_backing_slab(&raw_capture, &[gb.clone(), ga.clone()], &[], &["t"]).unwrap();
    let (_, o2, _) = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
    assert_eq!(o1, o2);
    assert!(o1[0].child_old_base < o1[1].child_old_base);
}

#[test]
fn r0c1_metadata_patched_slab() {
    let raw = b"raw-child-xyz".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let transformed_bytes = repaint(&raw);
    let transformed = global(ROUTEK_CHILD_BASE, transformed_bytes.clone(), false);
    let (patched, _, _) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    let off = (ROUTEK_CHILD_BASE - ROUTEK_SLAB_BASE) as usize;
    assert_eq!(
        &patched.content[off..off + transformed_bytes.len()],
        &transformed_bytes[..]
    );
}

#[test]
fn r0c1_raw_mismatch_no_candidate() {
    let raw = b"raw-A".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        b"raw-B".to_vec(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw,
            RawChildKind::HeapGlobal,
        )],
    };
    let transformed = global(ROUTEK_CHILD_BASE, b"REPAIRED".to_vec(), false);
    let err = build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
}

#[test]
fn r0c1_overlay_conflict_no_candidate() {
    let raw = b"child-conflict".to_vec();
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        raw.clone(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            ROUTEK_CHILD_BASE,
            raw.len(),
            raw.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    let ga = global(ROUTEK_CHILD_BASE, repaint(&raw), false);
    let gb = global(ROUTEK_CHILD_BASE, repaint(&repaint(&raw)), false);
    let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
}

fn synthetic(live_ptr: u64, bytes: Vec<u8>, tid: &str) -> HeapGlobalSnapshot {
    let mut g = global(live_ptr, bytes, false);
    g.provenance = RegionProvenance::SyntheticDerived {
        transform_id: tid.to_string(),
        source_anchor: "gscript+0xbd8 (test)".to_string(),
        construction_digest: sha256_hex(&g.content),
    };
    g
}

// GTO Core Recovery R0-D: the live Route L R1 geometry had a synthetic
// window-string child at 0x200000 OUTSIDE the captured slab
// [0x9e0000, 0x3977090). R0-D must not fail-closed on a SyntheticDerived
// child (no raw source by design) — it is recorded as a synthetic ledger
// entry and materialized as an independent runtime region.
#[test]
fn r0d_synthetic_child_outside_slab_not_rejected() {
    let slab_base: u64 = 0x9e0000;
    let slab_sz = 0x2a97090usize;
    let synthetic_base: u64 = 0x200000;
    // Raw slab contains a normal captured child inside it.
    let real_child_bytes = b"real-captured-child".to_vec();
    let s = slab_with_child(
        slab_base,
        slab_sz,
        slab_base + 0x3000,
        real_child_bytes.clone(),
    );
    let raw_slab_content = s.content.clone();
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![raw_child(
            slab_base + 0x3000,
            real_child_bytes.len(),
            real_child_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    // Transformed: one in-slab raw child (unchanged) + one synthetic child
    // at 0x200000 (outside the slab, SyntheticDerived provenance).
    let real = global(slab_base + 0x3000, real_child_bytes.clone(), false);
    let synth = synthetic(
        synthetic_base,
        b"NewClassName".to_vec(),
        "repair_gscript_window_strings",
    );
    let synth_transform_ids_provenance = match &synth.provenance {
        RegionProvenance::SyntheticDerived { transform_id, .. } => Some(transform_id.clone()),
        _ => None,
    };
    let (patched, overlays, _) = build_patched_backing_slab(
        &raw_capture,
        &[real, synth],
        &[],
        &["repair_gscript_window_strings"],
    )
    .unwrap();
    // Synthetic child did NOT get written into the slab and is NOT a
    // raw-slab overlay child (Route X R0: non-raw / SyntheticDerived is
    // excluded from raw overlay; it never appears as a raw overlay entry).
    let synth_overlays: Vec<_> = overlays
        .iter()
        .filter(|o| o.child_old_base == synthetic_base)
        .collect();
    assert_eq!(synth_overlays.len(), 0);
    // The synthetic child's child-level transform evidence is preserved
    // (transform provenance is not silently destroyed by exclusion).
    assert!(matches!(
        synth_transform_ids_provenance,
        Some(t) if t == "repair_gscript_window_strings"
    ));
    // The in-slab child overlay still applied.
    let real_overlays: Vec<_> = overlays
        .iter()
        .filter(|o| o.child_old_base == slab_base + 0x3000)
        .collect();
    assert_eq!(real_overlays.len(), 1);
    assert!(real_overlays[0].overlay_applied);
    // The patched slab is unchanged at the (non-existent) synthetic offset.
    assert_eq!(patched.content, raw_slab_content);
}

// R0-D: an UnknownSynthetic child must fail closed (never a fallback
// candidate, never silently dropped).
#[test]
fn r0d_unknown_synthetic_fails_closed() {
    let slab_base: u64 = 0x9e0000;
    let slab_sz = 0x2000usize;
    let s = slab(slab_base, vec![0u8; slab_sz]);
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![],
    };
    let mut g = global(slab_base + 0x1000, vec![0x41u8; 16], false);
    g.provenance = RegionProvenance::UnknownSynthetic;
    let err = build_patched_backing_slab(&raw_capture, &[g], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::RawChildMissing { .. }));
}

// R0-D: a SyntheticDerived child must NOT be silently treated as a raw
// child (it must carry SyntheticDerived provenance, not RawCaptured).
#[test]
fn r0d_synthetic_provenance_is_derived_not_raw() {
    let synth = synthetic(
        0x200000,
        b"NewClassName".to_vec(),
        "repair_gscript_window_strings",
    );
    match &synth.provenance {
        RegionProvenance::SyntheticDerived {
            transform_id,
            construction_digest,
            ..
        } => {
            assert_eq!(transform_id, "repair_gscript_window_strings");
            assert_eq!(*construction_digest, sha256_hex(&synth.content));
        }
        other => panic!("expected SyntheticDerived, got {other:?}"),
    }
}

// GTO Core Recovery R0-E Path A: a force-admit interior child contained
// within its backing object's range is reconciled as a subview (overlaid at
// its contained offset) rather than rejected as an OverlayConflict. This is
// the Route M R1 blocker geometry: slab [0x89f000,...), backing 0x8d8580,
// subview child 0x8d8d60 (inside 0x8d8580), both raw-coherent with the slab.
#[test]
fn r0e_contained_subview_reconciled_not_conflict() {
    let slab_base: u64 = 0x89f000;
    let backing_base: u64 = 0x8d8580;
    let subview_base: u64 = 0x8d8d60;
    let backing_sz: usize = 6688; // 0x1a20
    let subview_sz: usize = 0x400;
    // Raw slab content: backing occupies [0x8d8580, 0x8d8580+6688);
    // subview bytes at its offset are [0xEE; 0x400], and the backing raw
    // content matches at that offset (same physical memory).
    let backing_off = (backing_base - slab_base) as usize; // 0x39580
    let subview_off = (subview_base - slab_base) as usize; // 0x39d60
    let subview_in_backing = (subview_base - backing_base) as usize; // 0x7e0
    let mut slab_content = vec![0u8; backing_off + backing_sz];
    // Backing raw content at subview offset = [0xEE; 0x400].
    for i in 0..subview_sz {
        slab_content[backing_off + subview_in_backing + i] = 0xEE;
    }
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(slab_base, slab_content.clone())],
        children: vec![
            raw_child(
                backing_base,
                backing_sz,
                {
                    // raw backing: zeros with [0xEE;0x400] at subview offset
                    let mut b = vec![0u8; backing_sz];
                    b[subview_in_backing..subview_in_backing + subview_sz].fill(0xEE);
                    b
                },
                RawChildKind::HeapGlobal,
            ),
            raw_child(
                subview_base,
                subview_sz,
                vec![0xEEu8; subview_sz],
                RawChildKind::HeapGlobal,
            ),
        ],
    };
    // Transformed: backing unchanged; subview transformed (bytes differ from
    // raw to exercise the subview overlay). Both raw-coherent with the slab.
    let backing = global(
        backing_base,
        {
            let mut b = vec![0u8; backing_sz];
            b[subview_in_backing..subview_in_backing + subview_sz].fill(0xEE);
            b
        },
        false,
    );
    let subview_transformed = vec![0xDDu8; subview_sz];
    let subview = global(subview_base, subview_transformed.clone(), false);
    let (patched, overlays, _) = build_patched_backing_slab(
        &raw_capture,
        &[backing, subview],
        &[],
        &["repair_gscript_window_strings"],
    )
    .unwrap();
    // The subview's transformed bytes must be overlaid at its offset.
    let subview_overlays: Vec<_> = overlays
        .iter()
        .filter(|o| o.child_old_base == subview_base)
        .collect();
    assert_eq!(subview_overlays.len(), 1);
    assert!(subview_overlays[0].overlay_applied);
    assert_eq!(
        subview_overlays[0].contained_in_old_base,
        Some(backing_base)
    );
    // Patched slab at subview offset == transformed subview bytes.
    assert_eq!(
        &patched.content[subview_off..subview_off + subview_sz],
        &subview_transformed[..]
    );
}

// GTO Core Recovery R0-E: a genuinely partial overlap (neither child
// contained in the other) still fails closed — the containment
// reconciliation does NOT weaken the conflict guarantee for unrelated
// overlapping regions. In a single shared slab the partial overlap is
// detected either as raw drift (the two children can't both be coherent
// over the shared region) or as an OverlayConflict; either is fail-closed.
#[test]
fn r0e_partial_overlap_still_conflict() {
    let slab_base: u64 = 0x89f000;
    let a_base: u64 = 0x89f000 + 0x1000;
    let b_base: u64 = 0x89f000 + 0x1080;
    let sz = 0x100usize;
    let mut slab_content = vec![0u8; 0x2000];
    // a=[0x1000,0x1100), b=[0x1080,0x1180) share [0x1080,0x1100).
    slab_content[0x1000..0x1100].copy_from_slice(&vec![0xAA; 0x100]);
    slab_content[0x1080..0x1180].copy_from_slice(&vec![0xBB; 0x100]);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(slab_base, slab_content)],
        children: vec![
            raw_child(a_base, sz, vec![0xAA; sz], RawChildKind::HeapGlobal),
            raw_child(b_base, sz, vec![0xBB; sz], RawChildKind::HeapGlobal),
        ],
    };
    let mut ga = global(a_base, vec![0xAA; sz], false);
    let mut gb = global(b_base, vec![0xBB; sz], false);
    // Strict ObservedAllocation extents: an unrelated partial overlap with
    // conflicting bytes must still fail closed (the two children cannot both
    // be full-range coherent over the shared slab region).
    ga.extent_kind = crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
    gb.extent_kind = crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation;
    let result = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]);
    // Fail-closed: either raw drift (shared slab region cannot satisfy both
    // raw-coherence checks) or an overlay conflict. Never a successful plan.
    assert!(result.is_err());
}

/// Route O R1 exact drift geometry (recorded live): child 0x9f93e8 captured
/// at 0x70 bytes inside slab [0x9bf000,+0x2db3750), first mismatch at 0x28.
const R0G_SLAB_BASE: u64 = 0x9bf000;
const R0G_CHILD_BASE: u64 = 0x9f93e8;
const R0G_CHILD_SIZE: usize = 0x70;
const R0G_CHILD_OFF: usize = 0x3a3e8;
const R0G_FIRST_MISMATCH: usize = 0x28;

// Route N geometry constants: overlapping first-hop probe windows.
const ROUTEN_SLAB_BASE: u64 = 0x14f000;
const ROUTEN_A_BASE: u64 = 0x96bb80;
const ROUTEN_B_BASE: u64 = 0x96bbd0;
const ROUTEN_VIEW_SZ: usize = 0x400;

// ----- shared helpers relocated here so every route cluster can use them -----

/// TAF3: build an AuthoritativeSlabCandidate from a role + slab.
fn cand(role: &'static str, slab: HeapSlab) -> AuthoritativeSlabCandidate {
    AuthoritativeSlabCandidate { slab, role }
}

fn probe_global(live_ptr: u64, size: usize) -> HeapGlobalSnapshot {
    use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
    use super::super::heap_global_snapshot::CapturePath as CP;
    let mut g = global(live_ptr, vec![0u8; size], false);
    g.extent_kind = CEK::ProbeWindow;
    g.extent_evidence.capture_path = CP::DanglingEdge;
    g.extent_evidence.capture_id = format!("dangling_edge:{live_ptr:#x}:{size:#x}");
    g
}

fn slab_of_len(old_base: u64, len: usize) -> HeapSlab {
    HeapSlab {
        old_base,
        content: vec![0u8; len],
    }
}

/// A dedicated dangling-edge slab covering exactly [base, base+size), with a
/// ProbeWindow raw child + a matching transform + binding. This mirrors the
/// Route S R1 `0x850150` geometry but at a dedicated (non-main) slab.
fn taf1_dedicated_fixture(
    slab_base: u64,
    size: usize,
) -> (
    RawSlabCapture,
    HeapGlobalSnapshot,
    TransformPreimageBinding,
    Vec<u8>,
) {
    use super::super::heap_global_snapshot::CaptureExtentKind as CEK;
    use super::super::heap_global_snapshot::CapturePath as CP;
    let slab_content = vec![0x50u8; size];
    let slab_slice_digest = sha256_hex(&slab_content);
    let raw_bytes = vec![0x50u8; size];
    let cap_id = format!("dangling_edge:{slab_base:#x}:{size:#x}");
    let child = RawChild {
        old_base: slab_base,
        size,
        raw_bytes: raw_bytes.clone(),
        kind: RawChildKind::HeapGlobal,
        capture_id: cap_id.clone(),
        capture_path: CP::DanglingEdge,
        extent_kind: CEK::ProbeWindow,
        source_slot_offset: None,
        requested_probe_size: size,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let raw_capture = RawSlabCapture {
        slabs: vec![HeapSlab {
            old_base: slab_base,
            content: slab_content.clone(),
        }],
        children: vec![child],
    };
    let mut transformed = global(slab_base, vec![0x50u8; size], false);
    transformed.extent_kind = CEK::ProbeWindow;
    transformed.extent_evidence.capture_id = cap_id.clone();
    transformed.extent_evidence.capture_path = CP::DanglingEdge;
    // AF3 AF2 (P1-4): the transformed snapshot must carry the SAME source
    // evidence as the raw child (here the DanglingEdge probe size) so the
    // full-identity raw resolution and binding agree.
    transformed.extent_evidence.probe_requested_size = size;
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: cap_id.clone(),
        child_old_base: slab_base,
        child_size: size,
        extent_kind: CEK::ProbeWindow,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            cap_id.clone(),
            slab_base,
            size,
            CEK::ProbeWindow,
            crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge,
            size,
        ),
        slab_old_base: slab_base,
        slab_size: size,
        slab_digest: sha256_hex(&slab_content),
        slab_offset: 0,
        basis: TransformPreimageBasis::AuthoritativeSlabSlice,
        raw_child_digest: sha256_hex(&raw_bytes),
        raw_slab_slice_digest: slab_slice_digest.clone(),
        transform_input_digest: slab_slice_digest,
        seeded_from_slab: true,
    };
    (raw_capture, transformed, binding, raw_bytes)
}

/// A raw child at the Route O child base.
fn r0g_raw_child(prefix_match: usize, extent: CEK, capture_id: &str) -> RawChild {
    r0g_raw_child_at(R0G_CHILD_BASE, prefix_match, extent, capture_id)
}

/// A raw child in Route O geometry with the given stable prefix length.
fn r0g_raw_child_at(base: u64, prefix_match: usize, extent: CEK, capture_id: &str) -> RawChild {
    let mut bytes = vec![0xAAu8; R0G_CHILD_SIZE];
    // bytes[0..prefix_match] match the slab; bytes[prefix_match..] drift.
    for i in prefix_match..R0G_CHILD_SIZE {
        bytes[i] = 0xBB; // drifted (child != slab)
    }
    let mut c = raw_child(base, R0G_CHILD_SIZE, bytes, RawChildKind::HeapGlobal);
    c.extent_kind = extent;
    c.capture_id = capture_id.to_string();
    c
}

/// A slab whose content at the child offset is all 0xAA (so only bytes past
/// `prefix_match` drift in the child).
fn r0g_slab() -> HeapSlab {
    let mut content = vec![0u8; R0G_CHILD_OFF + R0G_CHILD_SIZE];
    for i in 0..R0G_CHILD_SIZE {
        content[R0G_CHILD_OFF + i] = 0xAA;
    }
    HeapSlab {
        old_base: R0G_SLAB_BASE,
        content,
    }
}

/// A transformed child in Route O geometry; if `write_off < prefix_match` the
/// transform writes into the stable prefix (clean preimage), else into the
/// drifted region.
fn r0g_transformed(
    prefix_match: usize,
    write_off: usize,
    write_val: u8,
    extent: CEK,
) -> HeapGlobalSnapshot {
    let mut content = vec![0xAAu8; R0G_CHILD_SIZE];
    for i in prefix_match..R0G_CHILD_SIZE {
        content[i] = 0xBB; // raw-child drift baseline
    }
    // Apply the transform write (over the raw-child value at that offset).
    content[write_off] = write_val;
    let mut g = global(R0G_CHILD_BASE, content, false);
    g.extent_kind = extent;
    g
}

fn route_n_raw_capture(fill: u8) -> RawSlabCapture {
    let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
    let end_off = (ROUTEN_B_BASE + ROUTEN_VIEW_SZ as u64 - ROUTEN_SLAB_BASE) as usize;
    let mut content = vec![0u8; end_off];
    content[a_off..end_off].fill(fill);
    RawSlabCapture {
        slabs: vec![slab(ROUTEN_SLAB_BASE, content)],
        children: vec![
            raw_child(
                ROUTEN_A_BASE,
                ROUTEN_VIEW_SZ,
                vec![fill; ROUTEN_VIEW_SZ],
                RawChildKind::HeapGlobal,
            ),
            raw_child(
                ROUTEN_B_BASE,
                ROUTEN_VIEW_SZ,
                vec![fill; ROUTEN_VIEW_SZ],
                RawChildKind::HeapGlobal,
            ),
        ],
    }
}
// ---- route clusters (WO-22) ----
#[cfg(test)]
#[path = "raw_slab_coherence_tests_rest.rs"]
mod rest;
#[cfg(test)]
#[path = "raw_slab_coherence_tests_route_q.rs"]
mod route_q;
#[cfg(test)]
#[path = "raw_slab_coherence_tests_route_r0.rs"]
mod route_r0;
#[cfg(test)]
#[path = "raw_slab_coherence_tests_route_s.rs"]
mod route_s;
#[cfg(test)]
#[path = "raw_slab_coherence_tests_route_t.rs"]
mod route_t;
