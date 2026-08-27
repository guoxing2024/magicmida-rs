//! route_r0 cluster tests (WO-22 split from raw_slab_coherence_tests.rs).

use super::*;
use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;

// ---------- GTO Core Recovery R0-F tests ----------

// Build a raw capture where the two Route N views both read from a slab
// whose bytes at [A_BASE .. B_BASE+0x400) are all `fill`.

// Two overlapping probe windows with DISJOINT transformed writes must NOT
// conflict (the core R0-F fix for Route N R1).
#[test]
fn r0f_overlapping_views_with_disjoint_writes_merge() {
    let raw_capture = route_n_raw_capture(0xAA);
    // A writes its first 0x50 bytes to 0xBB; B writes its last 0x20 bytes
    // to 0xCC. The write-sets are disjoint -> merge, no conflict.
    let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
    a[..0x50].fill(0xBB);
    let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
    b[0x3e0..].fill(0xCC);
    let (patched, overlays, _) = build_patched_backing_slab(
        &raw_capture,
        &[
            global(ROUTEN_A_BASE, a, false),
            global(ROUTEN_B_BASE, b, false),
        ],
        &[],
        &["t1", "t2"],
    )
    .unwrap();
    let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
    let b_off = (ROUTEN_B_BASE - ROUTEN_SLAB_BASE) as usize;
    // A's first 0x50 bytes written to 0xBB.
    assert_eq!(
        &patched.content[a_off..a_off + 0x50],
        &vec![0xBBu8; 0x50][..]
    );
    // B's last 0x20 bytes written to 0xCC.
    assert_eq!(
        &patched.content[b_off + 0x3e0..b_off + 0x400],
        &vec![0xCCu8; 0x20][..]
    );
    // Both overlays present.
    assert_eq!(overlays.len(), 2);
}

// Two overlapping views with NO transformed writes (unchanged) -> no
// conflict, patched slab == raw slab.
#[test]
fn r0f_overlapping_views_with_no_transforms_need_no_overlay() {
    let raw_capture = route_n_raw_capture(0xAA);
    let raw_slab = raw_capture.slabs[0].content.clone();
    let a = global(ROUTEN_A_BASE, vec![0xAAu8; ROUTEN_VIEW_SZ], false);
    let b = global(ROUTEN_B_BASE, vec![0xAAu8; ROUTEN_VIEW_SZ], false);
    let (patched, _, _) = build_patched_backing_slab(&raw_capture, &[a, b], &[], &["t"]).unwrap();
    assert_eq!(patched.content, raw_slab);
}

// Same byte written by two transforms to the SAME final value merges
// deterministically (SharedWriteSameValue).
#[test]
fn r0f_same_delta_value_merges_deterministically() {
    let raw_capture = route_n_raw_capture(0xAA);
    // Both A and B write byte 0x50 (the overlap) to 0xBB (same value).
    let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
    a[0x50] = 0xBB;
    let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
    b[0x00] = 0xBB; // B's offset 0 = slab A_off+0x50
    let (patched, overlays, _) = build_patched_backing_slab(
        &raw_capture,
        &[
            global(ROUTEN_A_BASE, a, false),
            global(ROUTEN_B_BASE, b, false),
        ],
        &[],
        &["t1", "t2"],
    )
    .unwrap();
    let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
    assert_eq!(patched.content[a_off + 0x50], 0xBB);
    assert_eq!(overlays.len(), 2);
}

// Same byte written to DIFFERENT final values -> TransformWriteConflict,
// with both real peer bases reported.
#[test]
fn r0f_different_delta_value_fails_closed() {
    let raw_capture = route_n_raw_capture(0xAA);
    // Both write the overlap byte at slab a_off+0x50 (A's offset 0x50,
    // B's offset 0x00) to different values.
    let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
    a[0x50] = 0xBB;
    let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
    b[0x00] = 0xCC;
    let err = build_patched_backing_slab(
        &raw_capture,
        &[
            global(ROUTEN_A_BASE, a, false),
            global(ROUTEN_B_BASE, b, false),
        ],
        &[],
        &["t1", "t2"],
    )
    .unwrap_err();
    match err {
        OverlayError::TransformWriteConflict {
            a_child_old_base,
            b_child_old_base,
            a_after_byte,
            b_after_byte,
            ..
        } => {
            // The two REAL children are reported (not the current child twice).
            assert_eq!(a_child_old_base, ROUTEN_A_BASE);
            assert_eq!(b_child_old_base, ROUTEN_B_BASE);
            assert_eq!(a_after_byte, 0xBB);
            assert_eq!(b_after_byte, 0xCC);
        }
        other => panic!("expected TransformWriteConflict, got {other:?}"),
    }
}

// Input order independence: reversing child order gives the same result.
#[test]
fn r0f_input_order_does_not_change_overlay_result() {
    let raw_capture = route_n_raw_capture(0xAA);
    let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
    a[..0x50].fill(0xBB);
    let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
    b[0x3e0..].fill(0xCC);
    let g_a = global(ROUTEN_A_BASE, a.clone(), false);
    let g_b = global(ROUTEN_B_BASE, b.clone(), false);
    let (p1, _, _) =
        build_patched_backing_slab(&raw_capture, &[g_a.clone(), g_b.clone()], &[], &["t"]).unwrap();
    let (p2, _, _) = build_patched_backing_slab(&raw_capture, &[g_b, g_a], &[], &["t"]).unwrap();
    assert_eq!(p1.content, p2.content);
}

// The Route N geometry (two 0x400 views, base delta 0x50, overlap 0x3b0)
// with NO transforms produces NO conflict.
#[test]
fn r0f_route_n_overlapping_probe_windows_no_conflict() {
    assert_eq!(ROUTEN_B_BASE - ROUTEN_A_BASE, 0x50);
    assert_eq!(0x400 - (ROUTEN_B_BASE - ROUTEN_A_BASE) as usize, 0x3b0);
    let raw_capture = route_n_raw_capture(0xAA);
    let a = global(ROUTEN_A_BASE, vec![0xAAu8; 0x400], false);
    let b = global(ROUTEN_B_BASE, vec![0xAAu8; 0x400], false);
    // Raw coherence passes (both match slab), and no writes -> no conflict.
    assert!(build_patched_backing_slab(&raw_capture, &[a, b], &[], &["t"]).is_ok());
}

// GTO R0-F: a TransformWriteConflict reports the exact slab offset of the
// first mismatching byte (not just the range start).
#[test]
fn r0f_conflict_reports_first_mismatching_slab_byte() {
    let raw_capture = route_n_raw_capture(0xAA);
    let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
    // A writes at A_off+0x50; B writes at the same slab byte differently.
    let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
    a[0x50] = 0xBB;
    let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
    b[0x00] = 0xCC;
    let err = build_patched_backing_slab(
        &raw_capture,
        &[
            global(ROUTEN_A_BASE, a, false),
            global(ROUTEN_B_BASE, b, false),
        ],
        &[],
        &["t1", "t2"],
    )
    .unwrap_err();
    match err {
        OverlayError::TransformWriteConflict {
            first_mismatch_slab_offset,
            before_byte,
            ..
        } => {
            assert_eq!(first_mismatch_slab_offset, a_off + 0x50);
            assert_eq!(before_byte, 0xAA);
        }
        other => panic!("expected TransformWriteConflict, got {other:?}"),
    }
}

// GTO R0-F: a probe-window capture (first-hop estimate without a proven
// boundary) must be classified as ProbeWindow, not ObservedAllocation.
#[test]
fn r0f_probe_window_is_not_claimed_as_allocation_extent() {
    let mut g = global(ROUTEN_A_BASE, vec![0xAAu8; ROUTEN_VIEW_SZ], false);
    // The default for a generic helper is ProbeWindow (the conservative
    // reading). A first-hop probe that only proves readability, not a
    // boundary, must stay ProbeWindow.
    assert_eq!(g.extent_kind, CaptureExtentKind::ProbeWindow);
    // Explicitly mark an observed allocation when a boundary is proven.
    g.extent_kind = CaptureExtentKind::ObservedAllocation;
    assert_eq!(g.extent_kind, CaptureExtentKind::ObservedAllocation);
}

// GTO R0-F.1: TransformWriteConflict reports the ACTUAL existing peer size
// (not the current child's size) and the authoritative absolute slab byte.
#[test]
fn r0f1_conflict_reports_existing_peer_size_and_absolute_slab_byte() {
    let raw_capture = route_n_raw_capture(0xAA);
    let a_off = (ROUTEN_A_BASE - ROUTEN_SLAB_BASE) as usize;
    let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
    a[0x50] = 0xBB;
    let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
    b[0x00] = 0xCC;
    let err = build_patched_backing_slab(
        &raw_capture,
        &[
            global(ROUTEN_A_BASE, a, false),
            global(ROUTEN_B_BASE, b, false),
        ],
        &[],
        &["t1", "t2"],
    )
    .unwrap_err();
    match err {
        OverlayError::TransformWriteConflict {
            a_size,
            b_size,
            before_byte,
            a_child_byte_offset,
            b_child_byte_offset,
            ..
        } => {
            // a is the earlier-applied peer (0x96bb80), size 0x400.
            assert_eq!(a_size, ROUTEN_VIEW_SZ);
            assert_eq!(b_size, ROUTEN_VIEW_SZ);
            // before_byte is the absolute slab byte (0xAA), not a run index.
            assert_eq!(before_byte, 0xAA);
            // a's child-relative offset of the conflict = 0x50.
            assert_eq!(a_child_byte_offset, 0x50);
            // b's child-relative offset = 0x00.
            assert_eq!(b_child_byte_offset, 0x00);
            let _ = a_off;
        }
        other => panic!("expected TransformWriteConflict, got {other:?}"),
    }
}

// GTO R0-F.1: per-child transform provenance — a child modified by a
// transform carries that transform id, and an unchanged child carries none.
#[test]
fn r0f1_per_child_transform_ids_not_global_and_unchanged_has_none() {
    // A modified child: its transform_ids = ["t1"] (not the global list).
    let raw_capture = route_n_raw_capture(0xAA);
    let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
    a[0x10] = 0xBB;
    let mut ga = global(ROUTEN_A_BASE, a, false);
    ga.transform_ids = vec!["t1".to_string()];
    // An unchanged child: content == raw, no transform_ids.
    let gb = global(ROUTEN_B_BASE, vec![0xAAu8; ROUTEN_VIEW_SZ], false);
    let (_, overlays, _) =
        build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t1", "t2", "t3"]).unwrap();
    let overlay_a = overlays
        .iter()
        .find(|o| o.child_old_base == ROUTEN_A_BASE)
        .unwrap();
    // The modified child's overlay carries only "t1", not the global 3.
    assert_eq!(overlay_a.transform_ids, vec!["t1".to_string()]);
    let overlay_b = overlays
        .iter()
        .find(|o| o.child_old_base == ROUTEN_B_BASE)
        .unwrap();
    // The unchanged child carries no transform writer (empty list).
    assert!(overlay_b.transform_ids.is_empty());
}

// ---------- GTO Core Recovery R0-G tests ----------

use crate::dumper::heap_global_snapshot::CapturePath;

#[test]
fn route_q_r0_probe_transform_input_is_seeded_from_authoritative_slab() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::InteriorSubview,
            "route-q-probe",
        )],
    };
    let mut global = r0g_transformed(
        R0G_FIRST_MISMATCH,
        R0G_FIRST_MISMATCH,
        0xBB,
        CEK::InteriorSubview,
    );
    global.extent_evidence.capture_id = "route-q-probe".into();
    let mut globals = vec![global];
    let mut containers = Vec::new();

    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();

    assert_eq!(
        globals[0].content,
        vec![0xAA; R0G_CHILD_SIZE],
        "probe/interior transform input must be the authoritative slab slice"
    );
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0].basis,
        TransformPreimageBasis::AuthoritativeSlabSlice
    );
    assert!(bindings[0].seeded_from_slab);
    assert_ne!(
        bindings[0].raw_child_digest,
        bindings[0].raw_slab_slice_digest
    );
    assert_eq!(
        bindings[0].transform_input_digest,
        bindings[0].raw_slab_slice_digest
    );
}

#[test]
fn route_q_r0_strict_extent_drift_is_rejected_before_transforms() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ObservedAllocation,
            "route-q-strict-drift",
        )],
    };
    let mut global = r0g_transformed(
        R0G_FIRST_MISMATCH,
        R0G_FIRST_MISMATCH,
        0xBB,
        CEK::ObservedAllocation,
    );
    global.extent_evidence.capture_id = "route-q-strict-drift".into();
    let mut globals = vec![global];
    let mut containers = Vec::new();

    let err =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap_err();
    assert!(matches!(
        err,
        OverlayError::RawCaptureDrift {
            first_mismatch_offset: R0G_FIRST_MISMATCH,
            ..
        }
    ));
}

#[test]
fn route_q_r0_clean_strict_extent_keeps_child_capture_basis() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_CHILD_SIZE,
            CEK::BackingObject,
            "route-q-strict-clean",
        )],
    };
    let mut global = global(R0G_CHILD_BASE, vec![0xAA; R0G_CHILD_SIZE], false);
    global.extent_kind = CEK::BackingObject;
    global.extent_evidence.capture_id = "route-q-strict-clean".into();
    let mut globals = vec![global];
    let mut containers = Vec::new();

    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();

    assert_eq!(globals[0].content, vec![0xAA; R0G_CHILD_SIZE]);
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].basis, TransformPreimageBasis::ChildCapture);
    assert!(!bindings[0].seeded_from_slab);
    assert_eq!(
        bindings[0].transform_input_digest,
        bindings[0].raw_child_digest
    );
}
