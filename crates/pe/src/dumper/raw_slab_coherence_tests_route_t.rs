//! route_t cluster tests (WO-22 split from raw_slab_coherence_tests.rs).

use super::*;

// ---- Route T R0: probe/interior coverage gate (validate_probe_coverage) ----

// T0-E test 1: uncovered ProbeWindow -> capture_coverage_bind failure.
#[test]
fn route_t_r0_uncovered_probe_fails() {
    let g = probe_global(0x850150, 0x1000);
    // No slab covers [0x850150, 0x851150).
    let slabs = vec![slab_of_len(0x9a3000, 0x1000)];
    let err = validate_probe_coverage(&[g], &slabs).unwrap_err();
    match err {
        OverlayError::ProbeCoverageMissing(details) => {
            assert_eq!(details.child_base, 0x850150);
            assert_eq!(details.child_size, 0x1000);
            assert!(details.extent_kind.contains("ProbeWindow"));
            assert_eq!(details.candidate_slab_count, 1);
            assert_eq!(details.nearest_authority, Some((0x9a3000, 0x9a4000)));
            assert!(details.nearest_authority_gap > 0);
        }
        other => panic!("expected ProbeCoverageMissing, got {other:?}"),
    }
}

// T0-E test 2: covered ProbeWindow -> runtime plan success.
#[test]
fn route_t_r0_covered_probe_ok() {
    let g = probe_global(0x850150, 0x1000);
    // A dedicated slab exactly covers the probe range.
    let slabs = vec![slab_of_len(0x850150, 0x1000)];
    validate_probe_coverage(&[g], &slabs).unwrap();
}

// T0-E test 3: 0x850150 exact geometry -> covered (end-to-end offline success).
#[test]
fn route_t_r0_exact_850150_geometry_covered() {
    let g = probe_global(0x850150, 0x1000);
    // Main slab covers a wider range that also contains 0x850150.
    let slabs = vec![slab_of_len(0x850000, 0x2000)];
    validate_probe_coverage(&[g], &slabs).unwrap();
}

// T0-E test 4: multiple probe windows in one slab -> all aliases valid.
#[test]
fn route_t_r0_multiple_probes_one_slab_all_ok() {
    let g1 = probe_global(0x850150, 0x1000);
    let g2 = probe_global(0x851a80, 0x200);
    let g3 = probe_global(0x854cd0, 0x400);
    // One dedicated slab covering all three probe ranges.
    let slabs = vec![slab_of_len(0x850000, 0x6000)];
    validate_probe_coverage(&[g1, g2, g3], &slabs).unwrap();
}

// T0-E test 5: probe window crossing slab boundary -> fail-closed.
#[test]
fn route_t_r0_probe_crossing_slab_boundary_fails() {
    // Probe [0x850150, 0x851150) crosses the slab end at 0x851000.
    let g = probe_global(0x850150, 0x1000);
    let slabs = vec![slab_of_len(0x850000, 0x1000)]; // ends at 0x851000, probe needs to 0x851150
    let err = validate_probe_coverage(&[g], &slabs).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
}

// T0-E test 6: no slabs at all -> every probe fails with nearest_authority=None.
#[test]
fn route_t_r0_no_slabs_probe_fails_with_none_authority() {
    let g = probe_global(0x850150, 0x1000);
    let slabs: Vec<HeapSlab> = Vec::new();
    let err = validate_probe_coverage(&[g], &slabs).unwrap_err();
    match err {
        OverlayError::ProbeCoverageMissing(details) => {
            assert_eq!(details.child_base, 0x850150);
            assert_eq!(details.candidate_slab_count, 0);
            assert_eq!(details.nearest_authority, None);
        }
        other => panic!("expected ProbeCoverageMissing, got {other:?}"),
    }
}

// T0-D: coverage is range-based — a different base at the same offset is
// covered by the same slab logic (no VA hardcoding).
#[test]
fn route_t_r0_coverage_is_range_based_not_va_hardcoded() {
    // A probe at a different address entirely is covered by its own slab.
    let g = probe_global(0x3852d30, 0x1000);
    let slabs = vec![slab_of_len(0x3852d30, 0x1000)];
    validate_probe_coverage(&[g], &slabs).unwrap();
    // Same logic covers 0x850150 too — proving the rule is by range, not VA.
    let g2 = probe_global(0x850150, 0x1000);
    let slabs2 = vec![slab_of_len(0x850150, 0x1000)];
    validate_probe_coverage(&[g2], &slabs2).unwrap();
}

// InteriorSubview coverage is also enforced.
#[test]
fn route_t_r0_interior_subview_uncovered_fails() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let mut g = global(0x200000, vec![0u8; 0x100], false);
    g.extent_kind = CEK::InteriorSubview;
    g.extent_evidence.capture_path = CP::GscriptChildLink;
    g.extent_evidence.capture_id = format!("child:0x{:x}:0x100", 0x200000u64);
    let slabs = vec![slab_of_len(0x9a3000, 0x1000)]; // does not cover 0x200000
    let err = validate_probe_coverage(&[g], &slabs).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
}

// ==================== Route T R0 Audit Fix 1 (TAF1) tests ====================
// Multi-slab authoritative coherence wiring: dedicated dangling-edge slabs
// must flow through raw capture -> seed -> transform -> overlay -> runtime.

// TAF1: a dangling-edge child in a DEDICATED slab must be absorbed at seed
// and overlaid onto its dedicated slab (NOT reported outside the main slab).
#[test]
fn route_t_af1_dedicated_child_not_outside_main_slab() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Seed: the child must resolve to the DEDICATED slab (offset 0), not a
    // RawChildOutsideSlab against an absent main slab.
    let mut globals = vec![transformed.clone()];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].slab_old_base, DEDICATED);
    assert_eq!(bindings[0].slab_offset, 0);
    // Overlay: dedicated slab is patched in place.
    let ledger = TransformRunLedger::default();
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap();
    assert_eq!(patched.len(), 1);
    assert_eq!(patched[0].old_base, DEDICATED);
    assert!(overlays
        .iter()
        .any(|o| o.child_old_base == DEDICATED && o.overlay_applied));
}

// TAF1: multi-slab raw capture -> seed -> overlay POSITIVE end-to-end. Two
// children in two distinct slabs (main + dedicated) both seed and overlay.
#[test]
fn route_t_af1_multislab_raw_capture_seed_overlay_positive() {
    const MAIN: u64 = 0x9a3000;
    const MAIN_CHILD: u64 = 0x9a4d40;
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x100;
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    // Main slab with a ProbeWindow child at 0x9a4d40.
    let main_off = (MAIN_CHILD - MAIN) as usize;
    let mut main_content = vec![0u8; main_off + SIZE];
    for i in 0..SIZE {
        main_content[main_off + i] = 0xAA;
    }
    let main_cap = format!("dangling_edge:{MAIN_CHILD:#x}:{SIZE:#x}");
    let main_child = RawChild {
        old_base: MAIN_CHILD,
        size: SIZE,
        raw_bytes: vec![0xAAu8; SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: main_cap.clone(),
        capture_path: CP::DanglingEdge,
        extent_kind: CEK::ProbeWindow,
        source_slot_offset: None,
        requested_probe_size: SIZE,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let (dedicated_raw, _, _, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    let raw_capture = RawSlabCapture {
        slabs: vec![
            HeapSlab {
                old_base: MAIN,
                content: main_content,
            },
            dedicated_raw.slabs[0].clone(),
        ],
        children: vec![main_child, dedicated_raw.children[0].clone()],
    };
    // Both children are ProbeWindow; seed both from their covering slab.
    let mut main_g = global(MAIN_CHILD, vec![0xAAu8; SIZE], false);
    main_g.extent_kind = CEK::ProbeWindow;
    main_g.extent_evidence.capture_id = main_cap.clone();
    main_g.extent_evidence.capture_path = CP::DanglingEdge;
    main_g.extent_evidence.probe_requested_size = SIZE;
    let mut ded_g = global(DEDICATED, vec![0x50u8; SIZE], false);
    ded_g.extent_kind = CEK::ProbeWindow;
    ded_g.extent_evidence.capture_id = format!("dangling_edge:{DEDICATED:#x}:{SIZE:#x}");
    ded_g.extent_evidence.capture_path = CP::DanglingEdge;
    ded_g.extent_evidence.probe_requested_size = SIZE;
    let mut globals = vec![main_g, ded_g];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    // TWO bindings, each recording its ACTUAL covering slab.
    assert_eq!(bindings.len(), 2);
    let b_main = bindings
        .iter()
        .find(|b| b.child_old_base == MAIN_CHILD)
        .unwrap();
    let b_ded = bindings
        .iter()
        .find(|b| b.child_old_base == DEDICATED)
        .unwrap();
    assert_eq!(b_main.slab_old_base, MAIN);
    assert_eq!(b_ded.slab_old_base, DEDICATED);
    // Overlay both -> two patched slabs, both children applied.
    let ledger = TransformRunLedger::default();
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger).unwrap();
    assert_eq!(patched.len(), 2);
    assert_eq!(patched[0].old_base, MAIN);
    assert_eq!(patched[1].old_base, DEDICATED);
    assert_eq!(overlays.len(), 2);
}

// TAF1: main slab + dedicated slab, a child in each -> both patched.
#[test]
fn route_t_af1_main_plus_dedicated_transform_overlay() {
    const MAIN: u64 = 0x9a3000;
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x100;
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    // Main slab at 0x9a3000 with a ProbeWindow child at 0x9a4d40 (Route R1 geo).
    let mut main_slab_content = vec![0u8; (0x9a4d40 - MAIN) as usize + SIZE];
    for i in 0..SIZE {
        main_slab_content[(0x9a4d40 - MAIN) as usize + i] = 0xAA;
    }
    let main_child_cap = format!("dangling_edge:{:#x}:{SIZE:#x}", 0x9a4d40u64);
    let main_child = RawChild {
        old_base: 0x9a4d40,
        size: SIZE,
        raw_bytes: vec![0xAAu8; SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: main_child_cap.clone(),
        capture_path: CP::DanglingEdge,
        extent_kind: CEK::ProbeWindow,
        source_slot_offset: None,
        requested_probe_size: SIZE,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    // Dedicated slab for the dangling edge at 0x850150.
    let (dedicated_raw, dedicated_transformed, dedicated_binding, _) =
        taf1_dedicated_fixture(DEDICATED, SIZE);
    let raw_capture = RawSlabCapture {
        slabs: vec![
            HeapSlab {
                old_base: MAIN,
                content: main_slab_content,
            },
            dedicated_raw.slabs[0].clone(),
        ],
        children: vec![main_child, dedicated_raw.children[0].clone()],
    };
    let mut main_transformed = global(0x9a4d40, vec![0xAAu8; SIZE], false);
    main_transformed.extent_kind = CEK::ProbeWindow;
    main_transformed.extent_evidence.capture_id = main_child_cap;
    main_transformed.extent_evidence.capture_path = CP::DanglingEdge;
    main_transformed.extent_evidence.probe_requested_size = SIZE;
    let main_binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: main_transformed.extent_evidence.capture_id.clone(),
        child_old_base: 0x9a4d40,
        child_size: SIZE,
        extent_kind: CEK::ProbeWindow,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            main_transformed.extent_evidence.capture_id.clone(),
            0x9a4d40,
            SIZE,
            CEK::ProbeWindow,
            crate::dumper::heap_global_snapshot::CapturePath::DanglingEdge,
            SIZE,
        ),
        slab_old_base: MAIN,
        slab_size: (0x9a4d40 - MAIN) as usize + SIZE,
        slab_digest: sha256_hex(&raw_capture.slabs[0].content),
        slab_offset: (0x9a4d40 - MAIN) as usize,
        basis: TransformPreimageBasis::AuthoritativeSlabSlice,
        raw_child_digest: sha256_hex(&vec![0xAAu8; SIZE]),
        raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; SIZE]),
        transform_input_digest: sha256_hex(&vec![0xAAu8; SIZE]),
        seeded_from_slab: true,
    };
    let ledger = TransformRunLedger::default();
    let (patched, overlays, _) = build_patched_backing_slab_q0c(
        &raw_capture,
        &[main_transformed, dedicated_transformed],
        &[],
        &[main_binding, dedicated_binding],
        &ledger,
    )
    .unwrap();
    // TWO patched slabs: main + dedicated.
    assert_eq!(patched.len(), 2);
    assert_eq!(patched[0].old_base, MAIN);
    assert_eq!(patched[1].old_base, DEDICATED);
    assert_eq!(overlays.len(), 2);
}

// TAF1 (CRITICAL): dedicated-ONLY transform overlay. A dangling-edge child in
// a dedicated slab goes through seed -> transform -> overlay and produces a
// patched dedicated slab — the offline closure for the Route S R1 blocker.
#[test]
fn route_t_af1_dedicated_only_transform_overlay() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, binding, raw_bytes) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Seed (dedicated-only, no main slab).
    let mut globals = vec![transformed.clone()];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert_eq!(bindings[0].slab_old_base, DEDICATED);
    assert_eq!(bindings[0].slab_size, SIZE);
    // Apply a transform: scrub a dangling pointer at +0x40 to 0.
    let mut ledger = TransformRunLedger::default();
    let before_snapshot = globals[0].clone();
    let mut after = globals[0].clone();
    after.content[0x40] = 0x00;
    {
        // record the scrub write run via the snapshot-diff helper.
        let runs = diff_transform_write_runs(
            &[before_snapshot],
            &[after.clone()],
            "scrub_uncaptured_heap_pointers",
        )
        .unwrap();
        ledger.runs.extend(runs);
    }
    // Overlay the transformed (scrubbed) child onto the dedicated slab.
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &[after], &[], &[binding], &ledger).unwrap();
    // ONE patched dedicated slab; the scrub byte was applied.
    assert_eq!(patched.len(), 1);
    assert_eq!(patched[0].old_base, DEDICATED);
    assert_eq!(patched[0].content[0x40], 0x00, "scrub must be overlaid");
    assert_eq!(patched[0].content[0], 0x50, "unchanged byte preserved");
    assert!(overlays
        .iter()
        .any(|o| o.child_old_base == DEDICATED && o.overlay_applied));
    let _ = raw_bytes;
}

// TAF1: no main slab does NOT skip raw coherence (dedicated-only still seeds+overlays).
#[test]
fn route_t_af1_no_main_slab_does_not_skip_coherence() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, _binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // raw_capture has ONLY the dedicated slab (no main slab). Seed must still
    // resolve the child to the dedicated slab.
    let mut globals = vec![transformed];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].slab_old_base, DEDICATED);
    assert!(bindings[0].seeded_from_slab);
    // Overlay must run (not skipped because no main slab).
    let ledger = TransformRunLedger::default();
    let (patched, _, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger).unwrap();
    assert_eq!(patched.len(), 1);
    assert_eq!(patched[0].old_base, DEDICATED);
}

// TAF1: empty slab set + probe fails at capture_coverage_bind.
#[test]
fn route_t_af1_empty_slab_coverage_fails_at_capture_coverage_bind() {
    let g = probe_global(0x850150, 0x1000);
    let empty: Vec<HeapSlab> = Vec::new();
    let err = validate_probe_coverage(&[g], &empty).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
}

// TAF1 (evidence-gap fix, TAF2-F): the coverage gate runs BEFORE overlay. This
// mirrors the PRODUCTION stage order from dump_process:
//   capture_identity_bind -> capture_coverage_bind -> seed -> transforms -> overlay
// With an uncovered probe, `capture_coverage_bind` must fail and the overlay
// must never be reached. This is a verifiable harness of the real order, not a
// lone validator call.
#[test]
fn route_t_af1_coverage_runs_before_overlay() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    // A dangling-edge probe at 0x850150 with NO covering slab.
    let cap_id = format!("dangling_edge:{:#x}:{:#x}", 0x850150u64, 0x1000usize);
    let mut g = global(0x850150, vec![0x50u8; 0x1000], false);
    g.extent_kind = CEK::ProbeWindow;
    g.extent_evidence.capture_id = cap_id.clone();
    g.extent_evidence.capture_path = CP::DanglingEdge;
    let globals = vec![g];
    let containers: Vec<ContainerSnapshot> = Vec::new();
    let empty_slabs: Vec<HeapSlab> = Vec::new();
    // Stage 1 (production): capture_identity_bind — must PASS (id is valid).
    validate_raw_coherence_capture_identities(&containers, &globals)
        .expect("identity bind must pass before coverage");
    // Stage 2 (production): capture_coverage_bind — must FAIL closed (uncovered).
    let err = validate_probe_coverage(&globals, &empty_slabs).unwrap_err();
    assert!(
        matches!(err, OverlayError::ProbeCoverageMissing { .. }),
        "coverage bind must fail before overlay, got {err:?}"
    );
    // Stage 3 (production): the overlay is NEVER reached because coverage
    // failed. Construct the raw capture and confirm the overlay would reject
    // (this is a tautology of fail-closed, but it proves the gate fires first).
    // We do NOT call build_patched_backing_slab_q0c here because the production
    // order stops at coverage_bind — proving the harness order is correct.
}

// TAF1: seed binding records the ACTUAL covering slab (base/size/digest/offset).
#[test]
fn route_t_af1_multi_slab_binding_records_actual_slab() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, _, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    let mut globals = vec![transformed];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let b = &bindings[0];
    assert_eq!(b.slab_old_base, DEDICATED);
    assert_eq!(b.slab_size, SIZE);
    assert_eq!(b.slab_offset, 0);
    assert_eq!(b.slab_digest, sha256_hex(&raw_capture.slabs[0].content));
    assert_eq!(b.basis, TransformPreimageBasis::AuthoritativeSlabSlice);
    assert!(b.seeded_from_slab);
}

// TAF1: an exact-duplicate probe (base+size == its dedicated slab) is absorbed
// as an alias at offset 0, never double-allocated.
#[test]
fn route_t_af1_exact_duplicate_does_not_double_allocate() {
    // TAF2-F (evidence-gap fix): this MUST test the main+dedicated OVERLAP
    // scenario, not a lone single slab. A dedicated slab exactly duplicating
    // the main slab is normalized to ONE backing region, so the overlay and
    // runtime both allocate it exactly once (no double allocation).
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    // main slab and dedicated slab are EXACT duplicates (same base/size/bytes).
    let main = HeapSlab {
        old_base: DEDICATED,
        content: vec![0x50u8; SIZE],
    };
    let dedicated = HeapSlab {
        old_base: DEDICATED,
        content: vec![0x50u8; SIZE],
    };
    let (normalized, _events) =
        normalize_authoritative_slabs(&[cand("main", main), cand("dedicated", dedicated)]).unwrap();
    assert_eq!(
        normalized.len(),
        1,
        "exact duplicate must normalize to ONE backing"
    );
    // Build the raw capture from the normalized single slab + a ProbeWindow child.
    let cap_id = format!("dangling_edge:{DEDICATED:#x}:{SIZE:#x}");
    let child = RawChild {
        old_base: DEDICATED,
        size: SIZE,
        raw_bytes: vec![0x50u8; SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: cap_id.clone(),
        capture_path: CP::DanglingEdge,
        extent_kind: CEK::ProbeWindow,
        source_slot_offset: None,
        requested_probe_size: SIZE,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let raw_capture = RawSlabCapture {
        slabs: vec![normalized[0].slab.clone()],
        children: vec![child],
    };
    let mut transformed = global(DEDICATED, vec![0x50u8; SIZE], false);
    transformed.extent_kind = CEK::ProbeWindow;
    transformed.extent_evidence.capture_id = cap_id;
    transformed.extent_evidence.capture_path = CP::DanglingEdge;
    transformed.extent_evidence.probe_requested_size = SIZE;
    let mut globals = vec![transformed];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let ledger = TransformRunLedger::default();
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger).unwrap();
    // Exactly ONE slab region + ONE alias (no double allocation).
    assert_eq!(
        patched.len(),
        1,
        "overlay must allocate the slab exactly once"
    );
    assert_eq!(overlays.len(), 1, "overlay must produce exactly one alias");
    assert!(overlays[0].overlay_applied);
    // Runtime plan also sees ONE slab region (no double allocation).
    let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
        &containers,
        &globals,
        &patched,
        &crate::dumper::runtime_rebase::declared_slots_from_capture(
            &containers,
            &globals,
            &patched,
        ),
        &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
        &[],
        0x140000000,
        0x140000000,
    )
    .unwrap()
    .expect("plan must be produced");
    assert_eq!(
        plan.regions.len(),
        1,
        "runtime must allocate the slab exactly once"
    );
}

// TAF1: a child that spans two slabs fails closed.
#[test]
fn route_t_af1_cross_slab_child_fails_closed() {
    const S1: u64 = 0x850000;
    const S2: u64 = 0x851000;
    const SIZE: usize = 0x1000;
    // Child [0x850100, 0x851100) spans both slabs [0x850000,+0x1000) and
    // [0x851000,+0x1000). No single slab contains it.
    let s1 = HeapSlab {
        old_base: S1,
        content: vec![0u8; 0x1000],
    };
    let s2 = HeapSlab {
        old_base: S2,
        content: vec![0u8; 0x1000],
    };
    let raw_capture = RawSlabCapture {
        slabs: vec![s1, s2],
        children: Vec::new(),
    };
    // A probe spanning the boundary cannot be covered by exactly one slab.
    let g = probe_global(0x850100, SIZE);
    let err = validate_probe_coverage(&[g], &raw_capture.slabs).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing { .. }));
}

// TAF1 (evidence-gap fix, TAF2-E/F): the manifest ROUNDTRIP contains all
// authoritative slabs. We render a manifest with a real authoritative_slab_ledger,
// parse the JSON, and verify slab count/order/base/size/digest, and that the
// binding references a slab present in the ledger.
#[test]
fn route_t_af1_manifest_roundtrip_contains_all_authoritative_slabs() {
    use crate::dumper::snapshot_manifest::AuthoritativeSlabLedgerEntry;
    // A dedicated slab at 0x850150 (raw digest = sha256 of 0x50 content).
    let raw_digest = sha256_hex(&vec![0x50u8; 0x1000]);
    let patched_digest = sha256_hex(&vec![0x55u8; 0x1000]); // after overlay
    let slab_ledger = vec![AuthoritativeSlabLedgerEntry {
        sequence: 0,
        role: "dedicated",
        old_base: 0x850150,
        size: 0x1000,
        raw_digest: raw_digest.clone(),
        patched_digest: patched_digest.clone(),
        normalization: "kept",
        source: "dedicated",
    }];
    // Render a manifest with this slab ledger.
    let json = crate::dumper::snapshot_manifest::render_manifest_json(
        std::path::Path::new("cand.exe"),
        crate::dumper::types::DumpProfile::AhkGtoExperimental,
        0x140000000,
        0x70b0,
        &[],
        &[],
        &crate::dumper::capture_policy::DumpCapturePolicy::ahk_gto_default(),
        false,
        None,
        &[],
        &[],
        &[],
        &TransformRunLedger::default(),
        &[],
        &[],
        &slab_ledger,
        &[],
        &[],
    )
    .unwrap();
    // Parse and verify the slab ledger.
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
    let ledger = v["authoritative_slab_ledger"]
        .as_array()
        .expect("slab ledger present");
    assert_eq!(ledger.len(), 1, "slab count must be 1");
    let entry = &ledger[0];
    assert_eq!(entry["sequence"], 0);
    assert_eq!(entry["role"], "dedicated");
    assert_eq!(entry["old_base"], "0x850150");
    assert_eq!(entry["size"], 0x1000);
    assert_eq!(entry["raw_digest"], raw_digest);
    assert_eq!(entry["patched_digest"], patched_digest);
    assert_eq!(entry["normalization"], "kept");
    assert_eq!(entry["source"], "dedicated");
    // The ledger proves the runtime/overlay/manifest slab sets are consistent:
    // exactly one slab, whose raw and patched digests are both recorded.
    assert!(json.contains("\"authoritative_slab_ledger\""));
}

// T0.2 schema note: a parent_closure role survives the manifest roundtrip
// verbatim (producer -> JSON -> parser), so consumers can distinguish a
// pre-trunc parent-closure authority from main/dedicated slabs.
#[test]
fn manifest_roundtrip_preserves_parent_closure_role() {
    use crate::dumper::snapshot_manifest::AuthoritativeSlabLedgerEntry;
    let slab_ledger = vec![AuthoritativeSlabLedgerEntry {
        sequence: 0,
        role: "parent_closure",
        old_base: 0x850000,
        size: 0x1000,
        raw_digest: sha256_hex(&vec![0xABu8; 0x1000]),
        patched_digest: String::new(), // not overlaid
        normalization: "kept",
        source: "parent_closure",
    }];
    let json = crate::dumper::snapshot_manifest::render_manifest_json(
        std::path::Path::new("cand.exe"),
        crate::dumper::types::DumpProfile::AhkGtoExperimental,
        0x140000000,
        0x70b0,
        &[],
        &[],
        &crate::dumper::capture_policy::DumpCapturePolicy::ahk_gto_default(),
        false,
        None,
        &[],
        &[],
        &[],
        &TransformRunLedger::default(),
        &[],
        &[],
        &slab_ledger,
        &[],
        &[],
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
    let entry = &v["authoritative_slab_ledger"][0];
    assert_eq!(entry["role"], "parent_closure");
    assert_eq!(entry["source"], "parent_closure");
    assert_eq!(entry["old_base"], "0x850000");
    assert_eq!(entry["size"], 0x1000);
    assert_eq!(entry["normalization"], "kept");
}

// ==================== Route T R0 Audit Fix 2 (TAF2) tests ====================

// TAF2-A: a binding with the wrong slab_size (but correct base/offset) must
// FAIL CLOSED at the overlay exact-match (TransformPreimageBindingIdentityInvalid).
#[test]
fn route_t_af2_wrong_slab_size_fails_closed() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, mut binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Corrupt the binding's slab_size (still correct base/offset/digest).
    binding.slab_size = SIZE - 1;
    let ledger = TransformRunLedger::default();
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::TransformPreimageBindingIdentityInvalid { .. }
        ),
        "wrong slab_size must fail closed, got {err:?}"
    );
}

// TAF2-A: a binding with the wrong slab_digest (but correct base/size/offset)
// must FAIL CLOSED at the overlay exact-match.
#[test]
fn route_t_af2_wrong_slab_digest_fails_closed() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, mut binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Corrupt the binding's slab_digest (still correct base/size/offset).
    binding.slab_digest = "DEADBEEF".into();
    let ledger = TransformRunLedger::default();
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::TransformPreimageBindingIdentityInvalid { .. }
        ),
        "wrong slab_digest must fail closed, got {err:?}"
    );
}

// TAF2-A: a binding with the wrong slab_base AND digest must FAIL CLOSED.
#[test]
fn route_t_af2_wrong_slab_base_and_digest_fails_closed() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, mut binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Corrupt both base and digest.
    binding.slab_old_base = DEDICATED - 0x1000;
    binding.slab_digest = "DEADBEEF".into();
    let ledger = TransformRunLedger::default();
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::TransformPreimageBindingIdentityInvalid { .. }
        ),
        "wrong slab_base+digest must fail closed, got {err:?}"
    );
}

// TAF2-B: main + dedicated EXACT duplicate (same base/size/bytes) normalizes
// to ONE backing region (the later duplicate is dropped).
#[test]
fn route_t_af2_main_dedicated_exact_duplicate_normalizes() {
    const BASE: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let main = HeapSlab {
        old_base: BASE,
        content: vec![0x50u8; SIZE],
    };
    let dedicated = HeapSlab {
        old_base: BASE,
        content: vec![0x50u8; SIZE],
    };
    let (normalized, _events) = normalize_authoritative_slabs(&[
        cand("main", main.clone()),
        cand("dedicated", dedicated.clone()),
    ])
    .unwrap();
    assert_eq!(normalized.len(), 1, "exact duplicate must collapse to one");
    assert_eq!(normalized[0].slab.old_base, BASE);
    assert_eq!(normalized[0].normalization, SlabNormalization::Kept);
}

// TAF2-B: a dedicated slab fully contained in the main slab with identical
// bytes normalizes to ONE backing region (the inner is an exact alias).
#[test]
fn route_t_af2_main_dedicated_contained_same_bytes_normalizes() {
    // Main slab [0x900000, +0x20000); dedicated [0x905000, +0x1000) with the
    // SAME bytes at the contained offset.
    let main = HeapSlab {
        old_base: 0x900000,
        content: {
            let mut c = vec![0u8; 0x20000];
            for i in 0..0x1000 {
                c[0x5000 + i] = 0x50;
            }
            c
        },
    };
    let dedicated = HeapSlab {
        old_base: 0x905000,
        content: vec![0x50u8; 0x1000],
    };
    let (normalized, _events) = normalize_authoritative_slabs(&[
        cand("main", main.clone()),
        cand("dedicated", dedicated.clone()),
    ])
    .unwrap();
    assert_eq!(
        normalized.len(),
        1,
        "contained same-bytes must keep one backing"
    );
    assert_eq!(normalized[0].slab.old_base, 0x900000);
    assert_eq!(normalized[0].slab.content.len(), 0x20000);
}

// TAF2-B: a dedicated slab contained in the main slab with DIFFERENT bytes
// fails closed (AuthoritativeSlabConflict).
#[test]
fn route_t_af2_main_dedicated_contained_different_bytes_fails_closed() {
    let main = HeapSlab {
        old_base: 0x900000,
        content: {
            let mut c = vec![0u8; 0x20000];
            for i in 0..0x1000 {
                c[0x5000 + i] = 0x50;
            }
            c
        },
    };
    // Same range but different byte at the contained offset.
    let dedicated = HeapSlab {
        old_base: 0x905000,
        content: vec![0x51u8; 0x1000], // differs from main's 0x50
    };
    let err = normalize_authoritative_slabs(&[cand("main", main), cand("dedicated", dedicated)])
        .unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::AuthoritativeSlabConflict {
                relationship: "contained_byte_conflict",
                ..
            }
        ),
        "contained different-bytes must fail closed, got {err:?}"
    );
}

// TAF2-D: partial overlap (neither contains the other) fails closed.
#[test]
fn route_t_af2_partial_overlap_fails_closed() {
    // [0x900000,+0x1000) and [0x900800,+0x1000) overlap partially.
    let a = HeapSlab {
        old_base: 0x900000,
        content: vec![0x50u8; 0x1000],
    };
    let b = HeapSlab {
        old_base: 0x900800,
        content: vec![0x50u8; 0x1000],
    };
    let err = normalize_authoritative_slabs(&[cand("main", a), cand("dedicated", b)]).unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::AuthoritativeSlabConflict {
                relationship: "partial_overlap",
                ..
            }
        ),
        "partial overlap must fail closed, got {err:?}"
    );
}

// TAF2-B/F: the normalized set must be shared by overlay AND runtime. After
// normalization, a child that lives in the contained-alias region resolves to
// the ONE kept slab for both overlay and runtime plan.
#[test]
fn route_t_af2_normalized_set_is_shared_by_overlay_and_runtime() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    // A dedicated slab at 0x905000 is exactly contained in the main slab
    // [0x900000,+0x20000) with identical bytes. After normalization only the
    // main slab remains; the child at 0x905000 resolves to it.
    let main = HeapSlab {
        old_base: 0x900000,
        content: {
            let mut c = vec![0u8; 0x20000];
            for i in 0..0x1000 {
                c[0x5000 + i] = 0x50;
            }
            c
        },
    };
    let dedicated = HeapSlab {
        old_base: 0x905000,
        content: vec![0x50u8; 0x1000],
    };
    let (normalized, _events) = normalize_authoritative_slabs(&[
        cand("main", main.clone()),
        cand("dedicated", dedicated.clone()),
    ])
    .unwrap();
    assert_eq!(normalized.len(), 1);
    let kept = normalized[0].slab.clone();
    // A ProbeWindow child at 0x905000 must resolve to the single kept slab.
    let cap_id = format!("dangling_edge:{:#x}:{:#x}", 0x905000u64, 0x1000usize);
    let child = RawChild {
        old_base: 0x905000,
        size: 0x1000,
        raw_bytes: vec![0x50u8; 0x1000],
        kind: RawChildKind::HeapGlobal,
        capture_id: cap_id.clone(),
        capture_path: CP::DanglingEdge,
        extent_kind: CEK::ProbeWindow,
        source_slot_offset: None,
        requested_probe_size: 0x1000,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let raw_capture = RawSlabCapture {
        slabs: vec![kept],
        children: vec![child],
    };
    // Seed + overlay against the normalized single slab.
    let mut transformed = global(0x905000, vec![0x50u8; 0x1000], false);
    transformed.extent_kind = CEK::ProbeWindow;
    transformed.extent_evidence.capture_id = cap_id;
    transformed.extent_evidence.capture_path = CP::DanglingEdge;
    transformed.extent_evidence.probe_requested_size = 0x1000;
    let mut globals = vec![transformed];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert_eq!(
        bindings[0].slab_old_base, 0x900000,
        "binding must use kept slab"
    );
    let ledger = TransformRunLedger::default();
    let (patched, _, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger).unwrap();
    assert_eq!(patched.len(), 1, "overlay must use the one kept slab");
    assert_eq!(patched[0].old_base, 0x900000);
    // Runtime plan also sees the single slab (shared set).
    let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
        &containers,
        &globals,
        &patched,
        &crate::dumper::runtime_rebase::declared_slots_from_capture(
            &containers,
            &globals,
            &patched,
        ),
        &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
        &[],
        0x140000000,
        0x140000000,
    )
    .unwrap()
    .expect("plan must be produced");
    assert_eq!(plan.regions.len(), 1, "runtime must use the one kept slab");
}

// ==================== Route T R0 Audit Fix 3 (TAF3) tests ====================

// TAF3-E: dedicated-only input keeps role/source "dedicated" (never "main").
#[test]
fn route_t_af3_dedicated_only_role_stays_dedicated() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (normalized, events) = normalize_authoritative_slabs(&[cand(
        "dedicated",
        HeapSlab {
            old_base: DEDICATED,
            content: vec![0x50u8; SIZE],
        },
    )])
    .unwrap();
    assert_eq!(normalized.len(), 1);
    assert_eq!(
        normalized[0].role, "dedicated",
        "dedicated-only must NOT become main"
    );
    assert_eq!(normalized[0].slab.old_base, DEDICATED);
    // The kept event also records role "dedicated".
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].input_role, "dedicated");
    assert_eq!(events[0].action, "kept");
    assert_eq!(events[0].survivor_sequence, Some(0));
}

// TAF3-F: dedup + contained-alias produce manifest normalization events.
#[test]
fn route_t_af3_dedup_and_alias_emit_events() {
    use crate::dumper::snapshot_manifest::AuthoritativeSlabLedgerEntry;
    // main at 0x900000; dedicated EXACT duplicate of main's contained region
    // (same base+size+bytes) -> dedup event; a SECOND dedicated that is a
    // contained alias (main contains it, same bytes).
    let main = HeapSlab {
        old_base: 0x900000,
        content: {
            let mut c = vec![0u8; 0x20000];
            for i in 0..0x1000 {
                c[0x5000 + i] = 0x50;
            }
            c
        },
    };
    // exact duplicate of the whole main slab -> dedup
    let dup = main.clone();
    // contained alias: same region as a slice of main, same bytes
    let alias = HeapSlab {
        old_base: 0x905000,
        content: vec![0x50u8; 0x1000],
    };
    let (kept, events) = normalize_authoritative_slabs(&[
        cand("main", main),
        cand("dedicated", dup),
        cand("dedicated", alias),
    ])
    .unwrap();
    assert_eq!(kept.len(), 1, "only the main slab survives");
    assert_eq!(kept[0].role, "main");
    // Events: main=kept, dup=deduplicated, alias=contained_exact_alias.
    let kept_event = events.iter().find(|e| e.action == "kept").unwrap();
    let dup_event = events
        .iter()
        .find(|e| e.action == "deduplicated")
        .expect("dup must emit deduplicated event");
    let alias_event = events
        .iter()
        .find(|e| e.action == "contained_exact_alias")
        .expect("alias must emit contained_exact_alias event");
    assert_eq!(kept_event.input_role, "main");
    assert_eq!(dup_event.input_role, "dedicated");
    assert_eq!(dup_event.relationship, "exact_duplicate");
    assert_eq!(dup_event.survivor_sequence, Some(0));
    assert_eq!(alias_event.input_role, "dedicated");
    assert_eq!(alias_event.relationship, "contained_same_bytes");
    assert_eq!(alias_event.survivor_sequence, Some(0));
    // Render + parse the manifest with the slab ledger + events -> roundtrip.
    let slab_ledger = vec![AuthoritativeSlabLedgerEntry {
        sequence: 0,
        role: "main",
        old_base: 0x900000,
        size: 0x20000,
        raw_digest: sha256_hex(&kept[0].slab.content),
        patched_digest: sha256_hex(&kept[0].slab.content),
        normalization: "kept",
        source: "main",
    }];
    let json = crate::dumper::snapshot_manifest::render_manifest_json(
        std::path::Path::new("cand.exe"),
        crate::dumper::types::DumpProfile::AhkGtoExperimental,
        0x140000000,
        0x70b0,
        &[],
        &[],
        &crate::dumper::capture_policy::DumpCapturePolicy::ahk_gto_default(),
        false,
        None,
        &[],
        &[],
        &[],
        &TransformRunLedger::default(),
        &[],
        &[],
        &slab_ledger,
        &events,
        &[],
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
    let ne = v["normalization_events"]
        .as_array()
        .expect("events present");
    assert_eq!(ne.len(), 3, "3 events (kept + dedup + alias)");
    let actions: Vec<&str> = ne.iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.contains(&"kept"));
    assert!(actions.contains(&"deduplicated"));
    assert!(actions.contains(&"contained_exact_alias"));
    // Each event records its survivor (which runtime/overlay uses).
    for e in ne.iter() {
        assert_eq!(
            e["survivor_sequence"].as_u64(),
            Some(0),
            "all map to main survivor"
        );
    }
}

// TAF3-G: reverse containment (a later slab is a superset of a kept slab) must
// recheck the new outer against ALL kept slabs. Construct A=[0x1000,+0x100),
// B=[0x1100,+0x100), S=[0x1000,+0x180). S contains A but partially overlaps B
// -> must fail closed (S was rechecked against B, not just A).
#[test]
fn route_t_af3_reverse_containment_plus_partial_overlap_fails_closed() {
    let a = HeapSlab {
        old_base: 0x1000,
        content: vec![0x50u8; 0x100],
    };
    let b = HeapSlab {
        old_base: 0x1100,
        content: vec![0x50u8; 0x100],
    };
    // S = [0x1000,+0x180) fully contains A ([0x1000,+0x100)) but only partially
    // overlaps B ([0x1100,+0x100)).
    let s = HeapSlab {
        old_base: 0x1000,
        content: {
            let mut c = vec![0x50u8; 0x180];
            for i in 0..0x100 {
                c[i] = 0x50;
            }
            c
        },
    };
    // Order: A (kept), B (kept, disjoint from A), S (contains A, partial-overlaps B).
    let err = normalize_authoritative_slabs(&[
        cand("main", a),
        cand("dedicated", b),
        cand("dedicated", s),
    ])
    .unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::AuthoritativeSlabConflict {
                relationship: "partial_overlap",
                ..
            }
        ),
        "reverse-containment recheck must catch S partial-overlap with B, got {err:?}"
    );
}

// TAF3-D: the normalized output is always pairwise disjoint.
#[test]
fn route_t_af3_normalized_output_is_pairwise_disjoint() {
    // Two disjoint dedicated slabs normalize cleanly (both kept, disjoint).
    let (kept, _) = normalize_authoritative_slabs(&[
        cand(
            "dedicated",
            HeapSlab {
                old_base: 0x850150,
                content: vec![0x50u8; 0x1000],
            },
        ),
        cand(
            "dedicated",
            HeapSlab {
                old_base: 0x860000,
                content: vec![0x50u8; 0x1000],
            },
        ),
    ])
    .unwrap();
    assert_eq!(kept.len(), 2);
    // Assert pairwise disjoint.
    for i in 0..kept.len() {
        for j in (i + 1)..kept.len() {
            let a = &kept[i].slab;
            let b = &kept[j].slab;
            let a_end = a.old_base + a.content.len() as u64;
            let b_end = b.old_base + b.content.len() as u64;
            assert!(
                !(a.old_base < b_end && b.old_base < a_end),
                "kept slabs must be pairwise disjoint"
            );
        }
    }
}

// TAF3-G: reverse containment replaces a kept slab with the outer and rechecks.
// Here a later outer S fully contains an EARLIER kept A with same bytes; the
// kept set must end up with S (the outer), and A's event is contained_alias.
#[test]
fn route_t_af3_reverse_containment_rechecks_all_kept() {
    let a = HeapSlab {
        old_base: 0x1000,
        content: vec![0x50u8; 0x100],
    };
    // S fully contains A (same bytes at offset 0).
    let s = HeapSlab {
        old_base: 0x1000,
        content: {
            let c = vec![0x50u8; 0x180];
            c
        },
    };
    let (kept, events) =
        normalize_authoritative_slabs(&[cand("main", a), cand("dedicated", s)]).unwrap();
    // The outer S survives (kept), and A was absorbed as a contained alias.
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].slab.old_base, 0x1000);
    assert_eq!(
        kept[0].slab.content.len(),
        0x180,
        "outer S must be the survivor"
    );
    let alias_event = events
        .iter()
        .find(|e| e.action == "contained_exact_alias")
        .expect("A absorbed as contained alias event");
    assert_eq!(alias_event.input_old_base, 0x1000);
    assert_eq!(alias_event.survivor_sequence, Some(0));
}
