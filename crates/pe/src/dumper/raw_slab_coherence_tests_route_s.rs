//! route_s cluster tests (WO-22 split from raw_slab_coherence_tests.rs).

use super::*;

// ================= Route S R0-E: Route R1 exact geometry regression =========
// The Route R R1 live blocker: dangling heap edge 0x9a4d40 (size 0x710,
// slab 0x9a3000, offset 0x1d40, ProbeWindow, DanglingEdge) previously had an
// EMPTY capture_id (CaptureExtentEvidence::default()), which the Q0-C exact
// binding rejected as TransformPreimageDrift. S0-A fixes the identity at the
// source; S0-B validates it early. These tests pin the geometry + the fix.

const S0E_SLAB: u64 = 0x9a3000;
const S0E_CHILD: u64 = 0x9a4d40;
const S0E_SIZE: usize = 0x710;
const S0E_OFF: usize = 0x1d40;

/// A dangling-edge child with the Route R1 geometry + a deterministic
/// non-empty capture id (as S0-A now produces).
fn s0e_dangling_fixture() -> (RawSlabCapture, HeapGlobalSnapshot, TransformPreimageBinding) {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let mut slab_content = vec![0u8; S0E_OFF + S0E_SIZE];
    for i in 0..S0E_SIZE {
        slab_content[S0E_OFF + i] = 0x50;
    }
    let slab_slice_digest = sha256_hex(&slab_content[S0E_OFF..S0E_OFF + S0E_SIZE]);
    let slab = HeapSlab {
        old_base: S0E_SLAB,
        content: slab_content,
    };
    let raw_bytes = vec![0x50u8; S0E_SIZE];
    let cap_id = format!("dangling_edge:{S0E_CHILD:#x}:{S0E_SIZE:#x}");
    let child = RawChild {
        old_base: S0E_CHILD,
        size: S0E_SIZE,
        raw_bytes: raw_bytes.clone(),
        kind: RawChildKind::HeapGlobal,
        capture_id: cap_id.clone(),
        capture_path: crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge,
        extent_kind: CEK::ProbeWindow,
        source_slot_offset: None,
        requested_probe_size: 0x1000,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let slab_digest = sha256_hex(&slab.content);
    let slab_len = slab.content.len();
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![child],
    };
    let mut transformed = global(S0E_CHILD, vec![0x50u8; S0E_SIZE], false);
    transformed.extent_kind = CEK::ProbeWindow;
    transformed.extent_evidence.capture_id = cap_id.clone();
    transformed.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    transformed.extent_evidence.probe_requested_size = 0x1000;
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: cap_id.clone(),
        child_old_base: S0E_CHILD,
        child_size: S0E_SIZE,
        extent_kind: CEK::ProbeWindow,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            cap_id.clone(),
            S0E_CHILD,
            S0E_SIZE,
            CEK::ProbeWindow,
            crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge,
            0x1000,
        ),
        slab_old_base: S0E_SLAB,
        slab_size: slab_len,
        slab_digest,
        slab_offset: S0E_OFF,
        basis: TransformPreimageBasis::AuthoritativeSlabSlice,
        raw_child_digest: sha256_hex(&raw_bytes),
        raw_slab_slice_digest: slab_slice_digest.clone(),
        transform_input_digest: slab_slice_digest,
        seeded_from_slab: true,
    };
    (raw_capture, transformed, binding)
}

// With a correct non-empty capture_id, byte 0 C=S=T=0x50 does NOT error, and
// the overlay completes naturally (this is the exact Route R1 geometry that
// previously died on the empty-id exact-binding rejection).
#[test]
fn route_s_r0e_route_r1_geometry_overlay_completes() {
    let (raw_capture, transformed, binding) = s0e_dangling_fixture();
    // transform input = S (unchanged): T == P == S at every byte, incl byte 0.
    let ledger = TransformRunLedger::default();
    // No writes -> empty ledger is valid; overlay must complete.
    let (patched, overlays, _drift) =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap();
    // Byte 0 preserved (C=S=T=0x50 is not an error).
    assert_eq!(patched[0].content[S0E_OFF], 0x50);
    assert!(overlays
        .iter()
        .any(|o| o.child_old_base == S0E_CHILD && o.overlay_applied));
}

// The capture identity must be non-empty and identical across all three stages
// (raw child -> seed binding -> transform input).
#[test]
fn route_s_r0e_capture_id_consistent_three_stages() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    // Build a container-free dangling-edge capture, run the gate + raw_children.
    let mut slab_content = vec![0u8; S0E_OFF + S0E_SIZE];
    for i in 0..S0E_SIZE {
        slab_content[S0E_OFF + i] = 0x50;
    }
    let slab = HeapSlab {
        old_base: S0E_SLAB,
        content: slab_content,
    };
    let raw_bytes = vec![0x50u8; S0E_SIZE];
    let cap_id = format!("dangling_edge:{S0E_CHILD:#x}:{S0E_SIZE:#x}");
    // heap_global as the capture produces it (S0-A form).
    let mut g = global(S0E_CHILD, raw_bytes.clone(), false);
    g.extent_kind = CEK::ProbeWindow;
    g.extent_evidence.capture_id = cap_id.clone();
    g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    // The dangling-edge probe requested this size at raw capture; the
    // transformed snapshot must carry the SAME source evidence (P1-2 full
    // identity) or seeding fails closed.
    g.extent_evidence.probe_requested_size = 0x1000;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab.clone()],
        children: vec![RawChild {
            old_base: S0E_CHILD,
            size: S0E_SIZE,
            raw_bytes,
            kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge,
            extent_kind: CEK::ProbeWindow,
            source_slot_offset: None,
            requested_probe_size: 0x1000,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    // Gate passes (non-empty identity).
    let mut globals = vec![g];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    // raw_children_from_capture preserves the id.
    let raw_children = raw_children_from_capture(&containers, &globals);
    let rc = raw_children
        .iter()
        .find(|r| r.old_base == S0E_CHILD)
        .unwrap();
    assert_eq!(rc.capture_id, cap_id);
    // Seeding binding uses the same id.
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let b = bindings
        .iter()
        .find(|b| b.child_old_base == S0E_CHILD)
        .unwrap();
    assert_eq!(b.capture_id, cap_id);
}

// Negative: an empty dangling capture_id fails at the capture_identity_bind
// gate (validate_raw_coherence_capture_identities), NOT at overlay time.
#[test]
fn route_s_r0e_empty_dangling_capture_id_fails_at_bind_gate() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let mut g = global(S0E_CHILD, vec![0x50u8; S0E_SIZE], false);
    g.extent_kind = CEK::ProbeWindow;
    // Leave capture_id empty (the S0-A bug).
    let globals = vec![g];
    let containers: Vec<ContainerSnapshot> = Vec::new();
    let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
    assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
}

// Negative: the REAL scrub_uncaptured_heap_pointers must attribute only the
// qwords it actually zeroes (an external dangling pointer), and the run's
// capture_id must match the child/binding. This exercises the production
// scrub path (Route R R1 live exposed the dangling-edge identity gap), not a
// hand-constructed zeroing.
#[test]
fn route_s_r0e_scrub_writer_only_attributes_changed_qword() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    // Build the dangling-edge child with a REAL external pointer qword at +0x40
    // (points outside the child's own captured range, in the plausible user VA
    // window), so the production scrub zeroes it.
    let child_end = S0E_CHILD + S0E_SIZE as u64;
    let external_ptr = 0x4000_0000u64; // plausible user heap VA, outside child range
    let mut content = vec![0x50u8; S0E_SIZE];
    content[0x40..0x48].copy_from_slice(&external_ptr.to_le_bytes());
    let cap_id = format!("dangling_edge:{S0E_CHILD:#x}:{S0E_SIZE:#x}");
    let mut g = global(S0E_CHILD, content, false);
    g.extent_kind = CEK::ProbeWindow;
    g.extent_evidence.capture_id = cap_id.clone();
    g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    g.extent_evidence.was_interior = false;
    g.extent_evidence.probe_requested_size = 0x1000;
    // Raw capture matching the child.
    let mut raw_bytes = vec![0x50u8; S0E_SIZE];
    raw_bytes[0x40..0x48].copy_from_slice(&external_ptr.to_le_bytes());
    // Build the slab as a named variable so we can capture its digest before move.
    let s0e_slab = HeapSlab {
        old_base: S0E_SLAB,
        content: {
            let mut s = vec![0u8; S0E_OFF + S0E_SIZE];
            for i in 0..S0E_SIZE {
                s[S0E_OFF + i] = 0x50;
            }
            s[S0E_OFF + 0x40..S0E_OFF + 0x48].copy_from_slice(&external_ptr.to_le_bytes());
            s
        },
    };
    let slab_digest = sha256_hex(&s0e_slab.content);
    let slab_len = s0e_slab.content.len();
    let raw_capture = RawSlabCapture {
        slabs: vec![s0e_slab],
        children: vec![RawChild {
            old_base: S0E_CHILD,
            size: S0E_SIZE,
            raw_bytes: raw_bytes.clone(),
            kind: RawChildKind::HeapGlobal,
            capture_id: cap_id.clone(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge,
            extent_kind: CEK::ProbeWindow,
            source_slot_offset: None,
            requested_probe_size: 0x1000,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    let slab_slice_digest = sha256_hex(&raw_capture.slabs[0].content[S0E_OFF..S0E_OFF + S0E_SIZE]);
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: cap_id.clone(),
        child_old_base: S0E_CHILD,
        child_size: S0E_SIZE,
        extent_kind: CEK::ProbeWindow,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            cap_id.clone(),
            S0E_CHILD,
            S0E_SIZE,
            CEK::ProbeWindow,
            crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge,
            0x1000,
        ),
        slab_old_base: S0E_SLAB,
        slab_size: slab_len,
        slab_digest,
        slab_offset: S0E_OFF,
        basis: TransformPreimageBasis::AuthoritativeSlabSlice,
        raw_child_digest: sha256_hex(&raw_bytes),
        raw_slab_slice_digest: slab_slice_digest.clone(),
        transform_input_digest: slab_slice_digest,
        seeded_from_slab: true,
    };
    // Run the REAL production scrub via the execution-owning recorder.
    let mut globals = vec![g];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let mut ledger = TransformRunLedger::default();
    let image_base = 0x140000000u64;
    let image_end = image_base + 0x1000_0000;
    apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |g| {
            crate::dumper::heap_global_snapshot::scrub_uncaptured_heap_pointers(
                &mut containers,
                g,
                image_base,
                image_end,
            );
        },
    )
    .unwrap();
    // The REAL scrub zeroed the external pointer qword at +0x40..0x48. Because
    // 0x4000_0000 is little-endian [0,0,0,0x40,0,0,0,0], only byte +0x43 actually
    // changed (0x40 -> 0); the diff/run records exactly that changed byte (offset
    // 0x43, length 1) — proving the run attributes only the byte the production
    // scrub changed, not the whole qword.
    assert!(ledger.runs.iter().any(|r| {
        r.child_old_base == S0E_CHILD
            && r.child_offset == 0x43
            && r.length == 1
            && r.transform_id == "scrub_uncaptured_heap_pointers"
            && r.child_capture_id == cap_id
    }));
    let _ = (child_end, image_base, image_end);
    // Overlay with the recorded run + binding completes (C=S=T at byte 0 is fine).
    let (patched, _, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &containers, &[binding], &ledger)
            .unwrap();
    assert_eq!(patched[0].content[S0E_OFF + 0x40], 0x00);
}

// Negative: missing binding reports TransformPreimageBindingMissing.
#[test]
fn route_s_r0e_missing_binding_reports_binding_missing() {
    let (raw_capture, transformed, _binding) = s0e_dangling_fixture();
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OverlayError::TransformPreimageBindingMissing { .. }
    ));
}

// Negative: duplicate binding reports TransformPreimageBindingAmbiguous.
#[test]
fn route_s_r0e_duplicate_binding_reports_ambiguous() {
    let (raw_capture, transformed, binding) = s0e_dangling_fixture();
    let dup = binding.clone();
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding, dup],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OverlayError::TransformPreimageBindingAmbiguous { .. }
    ));
}

// Negative: a malformed unrelated run identifies the exact run index, and the
// FIRST unchanged child is NOT blamed for it.
#[test]
fn route_s_r0e_malformed_unrelated_run_identifies_exact_index() {
    let (raw_capture, transformed, binding) = s0e_dangling_fixture();
    let mut ledger = TransformRunLedger::default();
    // A malformed unrelated run (different child, zero-length).
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "unrelated".into(),
        child_old_base: 0xdead_0000,
        child_size: 8,
        child_offset: 0,
        length: 0, // malformed
        transform_id: "scrub_uncaptured_heap_pointers".into(),
        before_digest: sha256_hex(&[]),
        after_digest: sha256_hex(&[]),
        first_before_byte: 0,
        first_after_byte: 0,
        before_bytes: vec![],
        after_bytes: vec![],
    });
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    match &err {
        OverlayError::TransformRunLedgerInvalid { run_index, .. } => {
            assert_eq!(*run_index, 0, "must identify the malformed run index");
        }
        other => panic!("expected TransformRunLedgerInvalid, got {other:?}"),
    }
}

// Negative: a duplicate capture id across two raw-coherence participants fails
// at the capture_identity_bind gate (ambiguous identity).
#[test]
fn route_s_r0e_duplicate_capture_identity_fails_at_bind_gate() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let mut g1 = global(0x9a4d40, vec![0x50u8; 0x20], false);
    g1.extent_kind = CEK::ProbeWindow;
    g1.extent_evidence.capture_id = "dup_id".into();
    let mut g2 = global(0x9a6000, vec![0x50u8; 0x20], false);
    g2.extent_kind = CEK::ProbeWindow;
    g2.extent_evidence.capture_id = "dup_id".into(); // SAME id, different base
    let globals = vec![g1, g2];
    let containers: Vec<ContainerSnapshot> = Vec::new();
    let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
    assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
}

// Positive: every production raw-coherence participant with a non-empty
// identity passes the gate (the S0-B invariant holds for well-formed input).
#[test]
fn route_s_r0e_all_production_raw_snapshots_have_non_empty_identity() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    // A representative set of raw-coherence participants, each with a distinct
    // non-empty capture id and explicit path/extent.
    let mut g1 = global(0x9a4d40, vec![0x50u8; 0x710], false);
    g1.extent_kind = CEK::ProbeWindow;
    g1.extent_evidence.capture_id = format!("dangling_edge:{:#x}:{:#x}", 0x9a4d40u64, 0x710usize);
    g1.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    let mut g2 = global(0x9a6000, vec![0x50u8; 0x40], false);
    g2.extent_kind = CEK::ObservedAllocation;
    g2.extent_evidence.capture_id = format!("mainslot:{:#x}:{:#x}", 0x140000000u64, 0x9a6000u64);
    g2.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut g3 = global(0x9b0000, vec![0x50u8; 0x100], false);
    g3.extent_kind = CEK::InteriorSubview;
    g3.extent_evidence.capture_id = format!("gscript_child:{:#x}", 0x9b0000u64);
    g3.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::GscriptChildLink;
    let globals = vec![g1, g2, g3];
    let containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
}

// ---- Route S R0 Audit Fix 1 (P1-2/P1-3): identity matrix negatives. ----
// A raw-coherence participant must satisfy the capture_path <-> extent matrix,
// and duplicate capture ids are only valid if the FULL tuple matches.

fn s0e_identity_neg(mutate: impl FnOnce(&mut HeapGlobalSnapshot)) -> OverlayError {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let mut g = global(0x9a4d40, vec![0x50u8; 0x20], false);
    g.extent_kind = CEK::ProbeWindow;
    g.extent_evidence.capture_id = "dangling_edge:0x9a4d40:0x20".into();
    g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    mutate(&mut g);
    let globals = vec![g];
    let containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err()
}

// DanglingEdge + MainSlot path (masquerade) -> fail.
#[test]
fn route_s_r0e_identity_dangling_edge_mainslot_fails() {
    let err = s0e_identity_neg(|g| {
        g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    });
    assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
}

// DanglingEdge + non-ProbeWindow extent -> fail.
#[test]
fn route_s_r0e_identity_dangling_edge_non_probe_fails() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let err = s0e_identity_neg(|g| g.extent_kind = CEK::ObservedAllocation);
    assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
}

// Synthetic path on a raw-coherence participant -> fail.
#[test]
fn route_s_r0e_identity_synthetic_path_fails() {
    let err = s0e_identity_neg(|g| {
        g.extent_evidence.capture_path =
            crate::dumper::heap_global_snapshot::CapturePath::Synthetic;
    });
    assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
}

// Same id + same base + different size -> fail (ambiguous).
#[test]
fn route_s_r0e_identity_same_id_same_base_diff_size_fails() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let mut g1 = global(0x9a4d40, vec![0x50u8; 0x20], false);
    g1.extent_kind = CEK::ProbeWindow;
    g1.extent_evidence.capture_id = "dup".into();
    g1.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    let mut g2 = global(0x9a4d40, vec![0x50u8; 0x30], false); // SAME base, different size
    g2.extent_kind = CEK::ProbeWindow;
    g2.extent_evidence.capture_id = "dup".into();
    g2.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    let globals = vec![g1, g2];
    let containers: Vec<ContainerSnapshot> = Vec::new();
    let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
    assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
}

// Same id + same base + different path -> fail.
#[test]
fn route_s_r0e_identity_same_id_same_base_diff_path_fails() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let mut g1 = global(0x9a4d40, vec![0x50u8; 0x20], false);
    g1.extent_kind = CEK::ProbeWindow;
    g1.extent_evidence.capture_id = "dup".into();
    g1.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    let mut g2 = global(0x9a4d40, vec![0x50u8; 0x20], false); // SAME base + size
    g2.extent_kind = CEK::ProbeWindow;
    g2.extent_evidence.capture_id = "dup".into();
    g2.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot; // diff path
    let globals = vec![g1, g2];
    let containers: Vec<ContainerSnapshot> = Vec::new();
    let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
    assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
}

// Same id + same base + different extent -> fail.
#[test]
fn route_s_r0e_identity_same_id_same_base_diff_extent_fails() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let mut g1 = global(0x9a4d40, vec![0x50u8; 0x20], false);
    g1.extent_kind = CEK::ProbeWindow;
    g1.extent_evidence.capture_id = "dup".into();
    g1.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    let mut g2 = global(0x9a4d40, vec![0x50u8; 0x20], false); // SAME base + size + path
    g2.extent_kind = CEK::ObservedAllocation; // diff extent
    g2.extent_evidence.capture_id = "dup".into();
    g2.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge;
    let globals = vec![g1, g2];
    let containers: Vec<ContainerSnapshot> = Vec::new();
    let err = validate_raw_coherence_capture_identities(&containers, &globals).unwrap_err();
    assert!(matches!(err, OverlayError::CaptureIdentityInvalid { .. }));
}
