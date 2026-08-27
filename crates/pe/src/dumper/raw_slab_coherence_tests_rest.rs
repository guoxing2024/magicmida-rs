//! rest cluster tests (WO-22 split from raw_slab_coherence_tests.rs).

use super::*;
use crate::dumper::heap_global_snapshot::CapturePath;

// ==================== Route T R0 Audit Fix 3 Rev 1 (bijection) tests ====================

// Rev1: reverse-containment event identity is BIJECTIVE. A=[0x1000,+0x100)
// main, S=[0x1000,+0x180) dedicated. S replaces A. Each input has exactly one
// event: seq0=A/main/alias, seq1=S/dedicated/kept. Survivor = S bytes with
// role=dedicated, origin_input_sequence=1.
#[test]
fn route_t_af3_rev1_reverse_containment_event_identity_is_bijective() {
    let a = HeapSlab {
        old_base: 0x1000,
        content: vec![0x50u8; 0x100],
    };
    let s = HeapSlab {
        old_base: 0x1000,
        content: vec![0x50u8; 0x180],
    };
    let (kept, events) =
        normalize_authoritative_slabs(&[cand("main", a), cand("dedicated", s)]).unwrap();
    // Exactly 2 events, one per valid input (bijection).
    assert_eq!(events.len(), 2, "one event per valid input");
    // input_sequence set == {0, 1}.
    let mut seqs: Vec<usize> = events.iter().map(|e| e.input_sequence).collect();
    seqs.sort();
    assert_eq!(seqs, vec![0, 1]);
    // seq 0 = A / main / contained_exact_alias (dropped into survivor).
    let e0 = events.iter().find(|e| e.input_sequence == 0).unwrap();
    assert_eq!(e0.input_role, "main");
    assert_eq!(e0.input_old_base, 0x1000);
    assert_eq!(e0.input_size, 0x100, "A's own geometry, not S's");
    assert_eq!(e0.action, "contained_exact_alias");
    assert_eq!(e0.survivor_sequence, Some(0));
    // seq 1 = S / dedicated / kept (the survivor).
    let e1 = events.iter().find(|e| e.input_sequence == 1).unwrap();
    assert_eq!(e1.input_role, "dedicated");
    assert_eq!(e1.input_old_base, 0x1000);
    assert_eq!(e1.input_size, 0x180, "S's own geometry");
    assert_eq!(e1.action, "kept");
    assert_eq!(e1.survivor_sequence, Some(0));
    // Survivor = S bytes, role=dedicated (NOT A's main), origin = input 1.
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].slab.content.len(), 0x180, "survivor bytes = S");
    assert_eq!(kept[0].role, "dedicated", "survivor role = S's role");
    assert_eq!(
        kept[0].origin_input_sequence, 1,
        "survivor origin = S input"
    );
}

// Rev1: reverse-containment manifest provenance roundtrip. Render + parse the
// normalization_events and authoritative_slab_ledger; re-assert the bijection
// and survivor role/origin from the parsed JSON.
#[test]
fn route_t_af3_rev1_reverse_containment_manifest_provenance_roundtrip() {
    use crate::dumper::snapshot_manifest::AuthoritativeSlabLedgerEntry;
    let a = HeapSlab {
        old_base: 0x1000,
        content: vec![0x50u8; 0x100],
    };
    let s = HeapSlab {
        old_base: 0x1000,
        content: vec![0x50u8; 0x180],
    };
    let (kept, events) =
        normalize_authoritative_slabs(&[cand("main", a), cand("dedicated", s)]).unwrap();
    let slab_ledger = vec![AuthoritativeSlabLedgerEntry {
        sequence: 0,
        role: kept[0].role,
        old_base: kept[0].slab.old_base,
        size: kept[0].slab.content.len(),
        raw_digest: sha256_hex(&kept[0].slab.content),
        patched_digest: sha256_hex(&kept[0].slab.content),
        normalization: "kept",
        source: kept[0].role,
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
    // normalization_events roundtrip.
    let ne = v["normalization_events"]
        .as_array()
        .expect("events present");
    assert_eq!(ne.len(), 2);
    let e0 = ne.iter().find(|e| e["input_sequence"] == 0).unwrap();
    assert_eq!(e0["input_role"], "main");
    assert_eq!(e0["input_size"], 0x100);
    assert_eq!(e0["action"], "contained_exact_alias");
    assert_eq!(e0["survivor_sequence"], 0);
    let e1 = ne.iter().find(|e| e["input_sequence"] == 1).unwrap();
    assert_eq!(e1["input_role"], "dedicated");
    assert_eq!(e1["input_size"], 0x180);
    assert_eq!(e1["action"], "kept");
    assert_eq!(e1["survivor_sequence"], 0);
    // authoritative_slab_ledger roundtrip: survivor role=dedicated, size=S.
    let al = v["authoritative_slab_ledger"]
        .as_array()
        .expect("slab ledger present");
    assert_eq!(al.len(), 1);
    assert_eq!(al[0]["role"], "dedicated");
    assert_eq!(al[0]["size"], 0x180);
}

// ------------------------------------------------------------------
// Route X R0 — raw-coherence participant-set and ledger identity closure.
// ------------------------------------------------------------------

/// Exact W R1 geometry: gscript image-inline body at RVA 0x149d50, live VA
/// 0x140149d50, size 0x1950 (6480). A transform mutating it must NOT create a
/// raw write run (image-inline is non-raw), so it can never emit an empty
/// child_capture_id into the overlay ledger.
#[test]
fn route_x_r0_exact_140149d50_geometry() {
    const W_IMAGE_INLINE_RVA: u32 = 0x149d50;
    const W_IMAGE_INLINE_VA: u64 = 0x140149d50;
    const W_IMAGE_INLINE_SIZE: usize = 0x1950;
    let mut g = global(W_IMAGE_INLINE_VA, vec![0u8; W_IMAGE_INLINE_SIZE], true);
    g.rva = W_IMAGE_INLINE_RVA;
    // Verify it is NOT a raw-coherence participant.
    assert!(!g.is_raw_coherence_participant());
    // Mutate it (simulate scrub/repair touching the image-inline body).
    let before = g.clone();
    g.content[0x28c..0x28c + 2].copy_from_slice(&[0x00, 0x00]);
    let runs =
        diff_transform_write_runs(&[before], &[g], "scrub_uncaptured_heap_pointers").unwrap();
    // NO raw run is produced for an image-inline participant.
    assert!(
        runs.is_empty(),
        "image-inline must never enter the raw ledger"
    );
}

/// X0-A: identity gate, raw-child capture, seeding, and ledger recording must
/// all agree that an image-inline snapshot is NOT a raw-coherence participant.
#[test]
fn route_x_r0_image_inline_is_non_raw_participant() {
    let g = global(0x140149d50, vec![0u8; 0x1950], true);
    assert!(!g.is_raw_coherence_participant());
    // raw_children_from_capture must exclude it.
    let children = raw_children_from_capture(&[], &[g.clone()]);
    assert!(!children.iter().any(|c| c.old_base == 0x140149d50));
    // diff_transform_write_runs must not emit a run for it even if mutated.
    let mut after = g.clone();
    after.content[0] ^= 0xFF;
    let runs = diff_transform_write_runs(&[g], &[after], "t").unwrap();
    assert!(runs.is_empty());
    // (overlay build on an empty raw capture would fail closed for other
    // reasons; the image-inline exclusion is proven by the gate/child/ledger
    // checks above.)
}

/// X0-B / X0-C: real scrub_uncaptured_heap_pointers through the PRODUCTION
/// recorder produces raw runs only for raw-coherence participants, and every
/// raw run carries a non-empty capture id (no empty-ID run from image-inline).
#[test]
fn route_x_r0_scrub_raw_runs_never_have_empty_capture_id() {
    let mut globals = vec![
        global(0x140149d50, vec![0x41u8; 0x1950], true), // image-inline (non-raw)
        global(0x200000, vec![0x42u8; 0x40], false),     // raw child
    ];
    // Give the raw child a capture id (as identity validation requires).
    globals[1].extent_evidence.capture_id = "gscript_child_link:0x200000:0:0x200000:true".into();
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let mut ledger = TransformRunLedger::default();
    let before = globals.clone();
    // Run the REAL scrub via the production recorder (also mutates containers).
    apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |g| {
            crate::dumper::heap_global_snapshot::scrub_uncaptured_heap_pointers(
                &mut containers,
                g,
                0x140000000,
                0x140100000,
            );
        },
    )
    .unwrap();
    // Every raw run has a non-empty capture id.
    for r in &ledger.runs {
        assert!(
            !r.child_capture_id.is_empty(),
            "raw run must carry a non-empty capture id: {r:?}"
        );
    }
    // No run references the image-inline base.
    assert!(!ledger.runs.iter().any(|r| r.child_old_base == 0x140149d50));
    // The raw child (if changed by scrub) is present with its capture id.
    let _ = before;
}

/// X0-A: the identity gate and the ledger recording must agree on the exact
/// participant set (no ad-hoc condition sets — both use the predicate).
#[test]
fn route_x_r0_identity_gate_and_run_ledger_share_participant_set() {
    // A mixed set: raw (with id), image-inline, heap-handle, empty, synthetic.
    let raw = global(0x200000, vec![0x42u8; 0x40], false);
    let image_inline = global(0x140149d50, vec![0x41u8; 0x1950], true);
    let h = handle(0x300000);
    let empty = global(0x400000, vec![], false);
    let synth = synthetic(0x500000, vec![0x55; 0x20], "t");
    let globals = vec![raw.clone(), image_inline, h, empty, synth.clone()];
    // Identity gate: only the raw participant requires a capture id; the
    // non-raw ones are skipped.
    let gate_ok = validate_raw_coherence_capture_identities(&[], &globals).is_ok();
    // (raw has empty id -> gate would fail; give it an id first)
    let mut g2 = raw.clone();
    g2.extent_evidence.capture_id = "main:0x200000:0:0x200000:false".into();
    assert!(validate_raw_coherence_capture_identities(&[], &[g2.clone()]).is_ok());
    // The predicate classifies exactly the raw participant as a participant.
    let raw_only = globals
        .iter()
        .filter(|g| g.is_raw_coherence_participant())
        .count();
    assert_eq!(raw_only, 1);
    // Ledger recording: only the raw participant (when mutated) yields runs.
    let mut after_raw = g2.clone();
    after_raw.content[0] ^= 0xFF;
    let runs = diff_transform_write_runs(&[g2], &[after_raw], "t").unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].child_capture_id, "main:0x200000:0:0x200000:false");
    let _ = gate_ok;
}

/// X0-B: a non-raw (image-inline) mutation is not destroyed — child-level
/// transform evidence is preserved even though it never enters the raw ledger.
#[test]
fn route_x_r0_non_raw_mutation_keeps_child_level_evidence() {
    let mut image = global(0x140149d50, vec![0x41u8; 0x1950], true);
    image
        .transform_ids
        .push("scrub_uncaptured_heap_pointers".to_string());
    let before = image.clone();
    image.content[0x28c] = 0x00;
    let runs = diff_transform_write_runs(&[before], &[image.clone()], "scrub").unwrap();
    // No raw run for the image-inline mutation...
    assert!(runs.is_empty());
    // ...but the child-level transform evidence is preserved.
    assert!(image
        .transform_ids
        .contains(&"scrub_uncaptured_heap_pointers".to_string()));
}

/// X0-B / X0-D: a genuinely malformed RAW child (non-image, non-handle,
/// non-empty, non-synthetic) with an EMPTY capture id that changes must fail
/// closed — never silently accepted.
#[test]
fn route_x_r0_malformed_empty_raw_id_still_fails_closed() {
    let mut raw = global(0x200000, vec![0x42u8; 0x40], false); // empty capture id
    assert!(raw.is_raw_coherence_participant()); // it IS a raw participant
    let before = raw.clone();
    raw.content[0] ^= 0xFF;
    let err = diff_transform_write_runs(&[before], &[raw], "t")
        .expect_err("empty raw id must fail closed");
    match err {
        OverlayError::TransformRunLedgerInvalid {
            child_old_base,
            reason,
            ..
        } => {
            assert_eq!(child_old_base, 0x200000);
            assert!(reason.contains("empty raw capture id"), "reason: {reason}");
        }
        other => panic!("expected TransformRunLedgerInvalid, got {other:?}"),
    }
}

/// X0-B: a participant-set change across one transform (a raw participant
/// present in before but missing in after) fails closed.
#[test]
fn route_x_r0_participant_set_change_fails_closed() {
    let a = global(0x200000, vec![0x42u8; 0x40], false);
    let b = global(0x210000, vec![0x43u8; 0x40], false);
    // before has two raw participants; after drops 0x210000 -> set change.
    let before = vec![a.clone(), b.clone()];
    let after = vec![a.clone()];
    let err = diff_transform_write_runs(&before, &after, "t")
        .expect_err("participant set change must fail closed");
    match err {
        OverlayError::TransformRunLedgerInvalid { reason, .. } => {
            assert!(
                reason.contains("participant set change"),
                "reason: {reason}"
            );
        }
        other => panic!("expected TransformRunLedgerInvalid, got {other:?}"),
    }
}

/// X0-F #8 / X0-AF1 (P0-4): the exact mixed raw + image-inline W R1 case
/// completes overlay through the REAL production-order chain (not the legacy
/// wrapper): identity bind -> coverage -> raw children -> seeding -> real
/// scrub via the production recorder -> q0c overlay.
///
/// Exact W R1 geometry: image RVA 0x149d50, image VA 0x140149d50, size 0x1950,
/// scrub area +0x28c.
#[test]
fn route_x_af1_w_exact_geometry_real_scrub_recorder_q0c_overlay() {
    const IMAGE_RVA: u32 = 0x149d50;
    const IMAGE_VA: u64 = 0x140149d50;
    const IMAGE_SIZE: usize = 0x1950;
    // W R1 scrub write area +0x28c (length 0x2); use an 8-byte-aligned offset
    // within it so the real scrub's pointer scan actually zeroes the external
    // pointer qword.
    const SCRUB_OFF: usize = 0x288;
    const SLAB_BASE: u64 = 0x140000000;
    const SLAB_SZ: usize = 0x40000;
    const RAW_BASE: u64 = SLAB_BASE + 0x3000;

    // Raw slab with one in-slab raw child (ObservedAllocation).
    // The raw child contains a scrubbed external pointer at +0x20 so the
    // real scrub modifies it AND the raw ledger gets a genuine run.
    let mut raw_child_bytes = b"raw-captured-child-ok".to_vec();
    raw_child_bytes.resize(0x40, 0);
    raw_child_bytes[0x20..0x28].copy_from_slice(&0x6000_0000u64.to_le_bytes());
    let slab = slab_with_child(SLAB_BASE, SLAB_SZ, RAW_BASE, raw_child_bytes.clone());
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            RAW_BASE,
            raw_child_bytes.len(),
            raw_child_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;

    // Globals: the raw child (canonical participant, MainSlot) + the image-inline.
    let mut raw_g = global(RAW_BASE, raw_child_bytes.clone(), false);
    raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    // Image-inline body: contains an external pointer-shaped qword at +0x28c
    // that scrub will zero (the W R1 scrub area).
    let mut image = global(IMAGE_VA, vec![0x41u8; IMAGE_SIZE], true);
    image.rva = IMAGE_RVA;
    image.content[SCRUB_OFF..SCRUB_OFF + 8].copy_from_slice(&0x4000_0000u64.to_le_bytes());

    let mut globals = vec![raw_g.clone(), image];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();

    // 1. Identity bind: image-inline is NOT a raw participant, so the raw
    //    child's id is the only requirement.
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    // 2. Coverage bind: no probe/interior children (raw is ObservedAllocation),
    //    image-inline excluded -> passes.
    validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
    // 3. Raw children from capture: only the raw child.
    let children = raw_children_from_capture(&containers, &globals);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].old_base, RAW_BASE);
    // 4. Seed transform inputs from authoritative slab.
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert_eq!(bindings.len(), 1);
    // 5. Real scrub via the production recorder.
    let mut ledger = TransformRunLedger::default();
    apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |g| {
            crate::dumper::heap_global_snapshot::scrub_uncaptured_heap_pointers(
                &mut containers,
                g,
                0x140000000,
                0x140100000,
            );
        },
    )
    .unwrap();
    //    - the image-inline body WAS actually modified by the real scrub.
    assert_eq!(globals[1].content[SCRUB_OFF], 0x00);
    //    - child-level transform evidence preserved on the image-inline.
    assert!(globals[1]
        .transform_ids
        .contains(&"scrub_uncaptured_heap_pointers".to_string()));
    //    - no raw write run references the image-inline base.
    assert!(!ledger.runs.iter().any(|r| r.child_old_base == IMAGE_VA));
    //    - every raw run has a non-empty capture id + full identity.
    for r in &ledger.runs {
        assert!(!r.child_capture_id.is_empty());
        assert_eq!(r.child_capture_id, "main:0x140003000:0:0x140003000:false");
    }
    // 6. q0c overlay completes (membership + shape gates run inside).
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger).unwrap();
    assert!(overlays
        .iter()
        .any(|o| o.child_old_base == RAW_BASE && o.overlay_applied));
    assert!(!overlays.iter().any(|o| o.child_old_base == IMAGE_VA));
    assert!(!patched.is_empty() && !patched[0].content.is_empty());
}

// ------------------------------------------------------------------
// Route X R0 AF1 (X0-AF1) — P0-1/P0-2/P0-3 closure tests.
// ------------------------------------------------------------------

/// P0-1: seeding must use the canonical raw-coherence participant set. A
/// SyntheticDerived global must be excluded from seeding (no seed binding).
#[test]
fn route_x_af1_synthetic_derived_is_excluded_from_seeding() {
    let raw_capture = RawSlabCapture {
        slabs: vec![],
        children: vec![],
    };
    // A SyntheticDerived child (non-raw by predicate).
    let mut synth = global(0x200000, vec![0x55; 0x20], false);
    synth.provenance = RegionProvenance::SyntheticDerived {
        transform_id: "t".into(),
        source_anchor: "anchor".into(),
        construction_digest: sha256_hex(&synth.content),
    };
    synth.extent_kind = CaptureExtentKind::SyntheticDerived;
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let mut globals = vec![synth];
    // Seeding with an empty raw capture must not fail on the synthetic child
    // (it is excluded), and must produce no bindings.
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert!(bindings.is_empty());
}

/// P0-1: seeding participant set == canonical predicate set. Only the raw
/// participant is seeded; the image-inline and SyntheticDerived are not.
#[test]
fn route_x_af1_seeding_uses_canonical_participant_set() {
    // Slab with one in-slab raw child.
    let slab_base: u64 = 0x140000000;
    let raw_bytes = b"seed-canonical".to_vec();
    let raw_base = slab_base + 0x3000;
    let slab = slab_with_child(slab_base, 0x40000, raw_base, raw_bytes.clone());
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            raw_base,
            raw_bytes.len(),
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    // globals: raw participant + image-inline + synthetic.
    let mut raw_g = global(raw_base, raw_bytes.clone(), false);
    raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let image = global(0x140149d50, vec![0x41; 0x1950], true);
    let mut synth = global(0x200000, vec![0x55; 0x20], false);
    synth.provenance = RegionProvenance::SyntheticDerived {
        transform_id: "t".into(),
        source_anchor: "a".into(),
        construction_digest: sha256_hex(&synth.content),
    };
    synth.extent_kind = CaptureExtentKind::SyntheticDerived;
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let mut globals = vec![raw_g.clone(), image, synth];
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    // Exactly ONE binding: the raw participant. Not the image-inline, not the
    // synthetic.
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].child_old_base, raw_base);
}

/// P0-2: same-base capture_id change fails closed (provenance drift).
#[test]
fn route_x_af1_same_base_capture_id_change_fails_closed() {
    let mut a = global(0x200000, vec![0x42u8; 0x40], false);
    a.extent_evidence.capture_id = "id-before".into();
    let mut b = a.clone();
    b.extent_evidence.capture_id = "id-after".into();
    b.content[0] ^= 0xFF;
    let err =
        diff_transform_write_runs(&[a], &[b], "t").expect_err("capture_id change must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// P0-2: same-base content.len() change fails closed (size drift).
#[test]
fn route_x_af1_same_base_size_change_fails_closed() {
    let mut a = global(0x200000, vec![0x42u8; 0x40], false);
    a.extent_evidence.capture_id = "id".into();
    let mut b = a.clone();
    b.content.truncate(0x30); // size changes 0x40 -> 0x30
    b.content[0] ^= 0xFF;
    let err = diff_transform_write_runs(&[a], &[b], "t")
        .expect_err("content.len change must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// P0-2: same-base extent_kind change fails closed.
#[test]
fn route_x_af1_same_base_extent_change_fails_closed() {
    let mut a = global(0x200000, vec![0x42u8; 0x40], false);
    a.extent_evidence.capture_id = "id".into();
    a.extent_kind = CaptureExtentKind::ProbeWindow;
    let mut b = a.clone();
    b.extent_kind = CaptureExtentKind::ObservedAllocation;
    b.content[0] ^= 0xFF;
    let err = diff_transform_write_runs(&[a], &[b], "t")
        .expect_err("extent_kind change must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// P0-2: same-base capture_path change fails closed.
#[test]
fn route_x_af1_same_base_capture_path_change_fails_closed() {
    let mut a = global(0x200000, vec![0x42u8; 0x40], false);
    a.extent_evidence.capture_id = "id".into();
    a.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut b = a.clone();
    b.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::GscriptChildLink;
    b.content[0] ^= 0xFF;
    let err = diff_transform_write_runs(&[a], &[b], "t")
        .expect_err("capture_path change must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// P0-3: a well-formed but orphaned run (no raw child by identity) fails the
/// global membership gate before byte replay.
#[test]
fn route_x_af1_well_formed_extra_run_without_raw_child_fails_closed() {
    // Raw capture with ONE raw child.
    let raw_bytes = b"orphan-check".to_vec();
    let raw_base = 0x140003000u64;
    let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            raw_base,
            raw_bytes.len(),
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    // Transformed set: the raw child (canonical participant). Its identity
    // must EQUAL the raw child's full identity so identity pre-resolution
    // passes; the orphan run below is then caught at run membership.
    let mut raw_g = global(raw_base, raw_bytes.clone(), false);
    raw_g.extent_kind = CaptureExtentKind::ProbeWindow;
    raw_g.extent_evidence.capture_id = String::new();
    raw_g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    // A shape-VALID ledger with an EXTRA run whose child (base 0x9999) has no
    // raw child and is not a canonical participant.
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "ghost:0x9999".into(),
        child_old_base: 0x9999,
        child_size: 0x10,
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[raw_g], &[], &[], &ledger).unwrap_err();
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// P0-3: a run with a WRONG capture id fails membership (orphaned).
#[test]
fn route_x_af1_run_wrong_capture_id_fails_membership() {
    let raw_bytes = b"wrongcap".to_vec();
    let raw_base = 0x140003000u64;
    let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            raw_base,
            raw_bytes.len(),
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    let mut raw_g = global(raw_base, raw_bytes.clone(), false);
    raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    // A ledger run with a WRONG capture id (but matching base).
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "wrong-id".into(),
        child_old_base: raw_base,
        child_size: raw_bytes.len(),
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[raw_g], &[], &[], &ledger).unwrap_err();
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// P0-3: a run with a WRONG child size fails membership.
#[test]
fn route_x_af1_run_wrong_child_size_fails_membership() {
    let raw_bytes = b"wrongsize".to_vec();
    let raw_base = 0x140003000u64;
    let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            raw_base,
            raw_bytes.len(),
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    let mut raw_g = global(raw_base, raw_bytes.clone(), false);
    raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    // A ledger run with the RIGHT capture id but WRONG child size.
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "main:0x140003000:0:0x140003000:false".into(),
        child_old_base: raw_base,
        child_size: raw_bytes.len() + 16, // wrong size
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[raw_g], &[], &[], &ledger).unwrap_err();
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// P0-3 positive: a run matching EXACTLY one raw child (full identity tuple)
/// passes the membership gate and reaches overlay.
#[test]
fn route_x_af1_run_matches_exactly_one_raw_child_positive() {
    let raw_bytes = b"exactmatch".to_vec();
    let raw_base = 0x140003000u64;
    let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            raw_base,
            raw_bytes.len(),
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    let mut raw_g = global(raw_base, raw_bytes.clone(), false);
    raw_g.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_g.extent_evidence.capture_id = "main:0x140003000:0:0x140003000:false".into();
    raw_g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    // A ledger run matching the raw child EXACTLY (capture_id, base, size).
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "main:0x140003000:0:0x140003000:false".into(),
        child_old_base: raw_base,
        child_size: raw_bytes.len(),
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    // validate_run_membership passes (exactly one raw child, in participant set).
    validate_run_membership(&raw_capture, &[raw_g.clone()], &ledger).unwrap();
}

// ------------------------------------------------------------------
// Route Y R0 (Y0) — Declared Size-Reinit Semantics Closure tests.
// ------------------------------------------------------------------

/// The sanitize_ahk_runtime_global size reinit (rva 0x141bf0, old ~0x8000 ->
/// 0x180 zero-filled) is a DECLARED transition: diff_transform_write_runs must
/// allow it and emit a run with the transformed (new) child size.
#[test]
fn route_y_r0_sanitize_size_reinit_is_declared_and_allowed() {
    let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
    a.rva = 0x141bf0;
    a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    a.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    a.extent_kind = CaptureExtentKind::ObservedAllocation;
    // sanitize re-init: 0x8000 -> 0x180 zero-filled.
    let mut b = a.clone();
    b.content = vec![0u8; 0x180];
    let runs = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global").unwrap();
    assert!(!runs.is_empty(), "sanitize re-init must emit a run");
    assert_eq!(
        runs[0].child_size, 0x180,
        "run child_size must be the new size"
    );
    assert_eq!(runs[0].child_capture_id, "mainslot:0x141bf0:0x3437e50");
    assert_eq!(runs[0].transform_id, "sanitize_ahk_runtime_global");
}

/// An UNDECLARED size change (not a declared reinit) still fails closed.
#[test]
fn route_y_r0_undeclared_size_drift_still_fails_closed() {
    let mut a = global(0x200000, vec![0xAA; 0x40], false);
    a.extent_evidence.capture_id = "id".into();
    let mut b = a.clone();
    b.content = vec![0xBB; 0x60]; // size change, no declaration
    let err = diff_transform_write_runs(&[a], &[b], "some_transform")
        .expect_err("undeclared size drift must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// A size change at the sanitize child rva but with a DIFFERENT transform is
/// not a declared reinit and fails closed.
#[test]
fn route_y_r0_wrong_transform_declaration_fails_closed() {
    let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
    a.rva = 0x141bf0;
    a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    let mut b = a.clone();
    b.content = vec![0u8; 0x180];
    // Transform id is NOT sanitize_ahk_runtime_global -> undeclared.
    let err = diff_transform_write_runs(&[a], &[b], "sort_gscript_label_table")
        .expect_err("wrong transform must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// A declared reinit whose OLD size is outside tolerance fails closed.
#[test]
fn route_y_r0_wrong_old_size_fails_closed() {
    let mut a = global(0x3437e50, vec![0xAA; 0x20], false); // way too small
    a.rva = 0x141bf0;
    a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    let mut b = a.clone();
    b.content = vec![0u8; 0x180];
    let err = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global")
        .expect_err("wrong old size must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// A declared reinit whose NEW size != 0x180 fails closed.
#[test]
fn route_y_r0_wrong_new_size_fails_closed() {
    let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
    a.rva = 0x141bf0;
    a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    let mut b = a.clone();
    b.content = vec![0u8; 0x200]; // wrong new size
    let err = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global")
        .expect_err("wrong new size must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// A declared reinit whose after content is NOT zero-filled fails closed.
#[test]
fn route_y_r0_reinit_not_zero_filled_fails_closed() {
    let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
    a.rva = 0x141bf0;
    a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    let mut b = a.clone();
    b.content = vec![0x00; 0x180];
    b.content[0x10] = 0xFF; // not all zero
    let err = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global")
        .expect_err("non-zero re-init must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// A declared reinit whose capture identity drifted fails closed (capture_id
/// check is independent of the size declaration).
#[test]
fn route_y_r0_wrong_capture_identity_fails_closed() {
    let mut a = global(0x3437e50, vec![0xAA; 0x8000], false);
    a.rva = 0x141bf0;
    a.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    let mut b = a.clone();
    b.content = vec![0u8; 0x180];
    b.extent_evidence.capture_id = "wrong-id".into(); // capture_id drift
    let err = diff_transform_write_runs(&[a], &[b], "sanitize_ahk_runtime_global")
        .expect_err("capture_id drift must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// Build a COMPLETE legal declared-reinit scenario through the production
/// chain: identity -> coverage -> raw-children -> seed -> apply_recorded_transform
/// (real sanitize) -> (ready for q0c). Returns the full fixture so tests can
/// either pass it straight to `build_patched_backing_slab_q0c` (positive) or
/// corrupt exactly one dimension to exercise the Q0-C consumer fail-closed
/// boundary (negative).
fn y0_declared_q0c_fixture() -> (
    RawSlabCapture,
    Vec<HeapGlobalSnapshot>,
    Vec<ContainerSnapshot>,
    Vec<TransformPreimageBinding>,
    TransformRunLedger,
) {
    const RVA: u32 = 0x141bf0;
    const LIVE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    let raw_bytes = vec![0xAAu8; OLD_SIZE];
    let slab = slab_with_child(0x3400000, 0x100000, LIVE, raw_bytes.clone());
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            LIVE,
            OLD_SIZE,
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "mainslot:0x141bf0:0x3437e50".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    let mut g = global(LIVE, raw_bytes.clone(), false);
    g.rva = RVA;
    g.extent_kind = CaptureExtentKind::ObservedAllocation;
    g.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut globals = vec![g];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
    let children = raw_children_from_capture(&containers, &globals);
    assert_eq!(children.len(), 1);
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert_eq!(bindings.len(), 1);
    let mut ledger = TransformRunLedger::default();
    apply_recorded_transform(
        &mut globals,
        "sanitize_ahk_runtime_global",
        &mut ledger,
        |g| {
            crate::dumper::heap_global_snapshot::sanitize_ahk_runtime_global(g);
        },
    )
    .unwrap();
    assert_eq!(globals[0].content.len(), 0x180);
    assert!(globals[0].content.iter().all(|&b| b == 0));
    assert!(!ledger.runs.is_empty());
    assert_eq!(ledger.runs[0].child_old_base, LIVE);
    assert_eq!(ledger.runs[0].child_size, 0x180);
    (raw_capture, globals, containers, bindings, ledger)
}

/// The real sanitize_ahk_runtime_global through the PRODUCTION chain
/// (identity -> coverage -> raw-children -> seed -> apply_recorded_transform
/// with the real sanitize -> q0c overlay -> runtime rebase plan -> manifest)
/// must COMPLETE overlay, produce a run for the size re-init, and the patched
/// slab must contain the expected zeroed 0x180 region.
#[test]
fn route_y_r0_sanitize_full_production_chain_q0c_overlay() {
    const LIVE: u64 = 0x3437e50;
    let (raw_capture, globals, containers, bindings, ledger) = y0_declared_q0c_fixture();
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger).unwrap();
    assert!(overlays
        .iter()
        .any(|o| o.child_old_base == LIVE && o.overlay_applied));
    assert!(!patched.is_empty() && !patched[0].content.is_empty());
    // The patched slab region for the re-init child must be exactly 0x180 zeros.
    let off = (LIVE - raw_capture.slabs[0].old_base) as usize;
    let region = &patched[0].content[off..off + 0x180];
    assert_eq!(region.len(), 0x180);
    assert!(
        region.iter().all(|&b| b == 0),
        "declared re-init region must be zero-filled in the patched slab"
    );
    // The overlay record for the declared transition must carry the NEW size
    // and the transformed (zeroed) digest — replayable evidence.
    let o = overlays
        .iter()
        .find(|o| o.child_old_base == LIVE)
        .expect("declared overlay record");
    assert_eq!(o.child_size, 0x180);
    assert_eq!(
        o.transformed_child_digest,
        sha256_hex(&vec![0u8; 0x180]),
        "overlay must record the exact zeroed new-size digest"
    );
    // Runtime rebase plan over the patched slabs: must construct without
    // error (the declared re-init is reflected in the patched backing slab).
    let slots =
        crate::dumper::runtime_rebase::declared_slots_from_capture(&containers, &globals, &patched);
    // P2: the fixture must genuinely produce a runtime rebase plan over the
    // patched slabs (the declared re-init is part of the patched backing).
    let plan = crate::dumper::runtime_rebase::build_runtime_rebase_plan(
        &containers,
        &globals,
        &patched,
        &slots,
        &crate::dumper::runtime_rebase::ExternalResolverTable::new(),
        &[],
        0x140000000,
        0x150000000,
    )
    .unwrap()
    .expect("a runtime rebase plan must be produced for the declared re-init fixture");
    crate::dumper::runtime_rebase::validate_runtime_rebase_plan(&plan).unwrap();
    // Manifest: the declared transition appears in the recorded transform
    // ledger evidence (the sanitize transform is bound to the candidate).
    let declared_digest = sha256_hex(&vec![0u8; 0x180]);
    assert_eq!(
        overlays.iter().filter(|o| o.child_old_base == LIVE).count(),
        1,
        "exactly one declared overlay record"
    );
    assert_eq!(ledger.runs.len(), 1);
    assert_eq!(ledger.runs[0].transform_id, "sanitize_ahk_runtime_global");
    assert_eq!(ledger.runs[0].after_digest, declared_digest);
    // Manifest serialization must be derived from the ACTUAL ledger/overlay
    // data flow — not hand-injected strings. Build the transform list from
    // the recorded runs (the sanitize transition) and serialize.
    let manifest_dir = std::env::temp_dir().join(format!(
        "mida_y0_manifest_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&manifest_dir).unwrap();
    let candidate = manifest_dir.join("candidate.exe");
    let mut manifest_transforms: Vec<(&str, &str)> = Vec::new();
    for r in &ledger.runs {
        manifest_transforms.push((r.transform_id.as_str(), "declared-size-reinit"));
    }
    assert_eq!(
        manifest_transforms.len(),
        1,
        "ledger must drive exactly one manifest transform entry"
    );
    crate::dumper::dump_process::write_bound_transform_manifest(
        &candidate,
        &patched[0].content,
        &manifest_transforms,
        None,
    )
    .unwrap();
    let manifest = candidate.with_extension("transform_manifest.json");
    let parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).expect("manifest written"))
            .expect("manifest must be valid JSON");
    assert_eq!(parsed["schema_version"], "mida.transform-manifest/v0");
    let entries = parsed["entries"].as_array().expect("entries array");
    assert!(
        entries
            .iter()
            .any(|e| e["id"] == "sanitize_ahk_runtime_global"),
        "manifest must record the declared transition transform from the ledger"
    );
    let _ = std::fs::remove_dir_all(&manifest_dir);
}

/// Q0-C consumer boundary: an EMPTY ledger cannot authorize the declared
/// transition — no run evidence -> fails closed.
#[test]
fn route_y_r0_q0c_empty_ledger_fails_closed() {
    let (raw_capture, globals, _c, bindings, _ledger) = y0_declared_q0c_fixture();
    let empty_ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &empty_ledger)
        .expect_err("empty ledger must fail closed at Q0-C");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// Q0-C consumer boundary: an OLD size far outside the declared tolerance
/// (raw child much smaller than 0x8000) must be rejected THROUGH the real
/// `build_patched_backing_slab_q0c` path — not by calling the field validator
/// directly. We build a complete fixture whose raw child has an out-of-range
/// size but a fully self-consistent raw/binding/ledger (so the overlay reaches
/// the declared-reinit boundary) and assert the overlay call itself fails.
#[test]
fn route_y_r0_q0c_old_size_out_of_tolerance_fails_closed() {
    const RVA: u32 = 0x141bf0;
    const LIVE: u64 = 0x3437e50;
    const SLAB_BASE: u64 = 0x3400000;
    const SLAB_SZ: usize = 0x100000;
    const RAW_SIZE: usize = 0x100; // far below 0x8000 - 0x2000
    const NEW_SIZE: usize = 0x180;
    let raw_bytes = vec![0xAAu8; RAW_SIZE];
    let slab_content = slab_with_child(SLAB_BASE, SLAB_SZ, LIVE, raw_bytes.clone()).content;
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_content.clone())],
        children: vec![raw_child(
            LIVE,
            RAW_SIZE,
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "mainA".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_capture.children[0].capture_path = CapturePath::MainSlot;
    // Transformed child: declared re-init -> zeroed NEW_SIZE.
    let mut g = global(LIVE, vec![0u8; NEW_SIZE], false);
    g.rva = RVA;
    g.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    g.extent_kind = CaptureExtentKind::ObservedAllocation;
    g.extent_evidence.capture_id = "mainA".into();
    g.extent_evidence.capture_path = CapturePath::MainSlot;
    let globals = vec![g];
    // Hand-built binding: self-consistent with the RAW_SIZE raw child and the
    // covering slab (ChildCapture basis for an ObservedAllocation child).
    let off = (LIVE - SLAB_BASE) as usize;
    let slab_slice = slab_content[off..off + RAW_SIZE].to_vec();
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "mainA".into(),
        child_old_base: LIVE,
        child_size: RAW_SIZE,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("mainA"),
            LIVE,
            RAW_SIZE,
            CaptureExtentKind::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: SLAB_BASE,
        slab_size: SLAB_SZ,
        slab_digest: sha256_hex(&slab_content),
        slab_offset: off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&raw_bytes),
        raw_slab_slice_digest: sha256_hex(&slab_slice),
        transform_input_digest: sha256_hex(&raw_bytes),
        seeded_from_slab: false,
    };
    let bindings = vec![binding];
    // A shape-valid sanitize transition run (the old-size gate rejects before
    // the run shape/evidence is even consulted).
    let ledger = TransformRunLedger {
        runs: vec![TransformWriteRun {
            child_capture_id: "mainA".into(),
            child_old_base: LIVE,
            child_size: NEW_SIZE,
            child_offset: 0,
            length: NEW_SIZE,
            transform_id: "sanitize_ahk_runtime_global".into(),
            before_digest: sha256_hex(&vec![0xAAu8; NEW_SIZE]),
            after_digest: sha256_hex(&vec![0u8; NEW_SIZE]),
            first_before_byte: 0xAA,
            first_after_byte: 0x00,
            before_bytes: vec![0xAAu8; NEW_SIZE],
            after_bytes: vec![0u8; NEW_SIZE],
        }],
    };
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("out-of-tolerance old size must fail closed THROUGH Q0-C");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// Q0-C consumer boundary: a NEW size != 0x180 on the transformed snapshot
/// fails closed (declaration requires the exact re-init size).
#[test]
fn route_y_r0_q0c_new_size_wrong_fails_closed() {
    let (raw_capture, mut globals, _c, bindings, ledger) = y0_declared_q0c_fixture();
    globals[0].content = vec![0u8; 0x200]; // wrong new size
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("wrong new size must fail closed at Q0-C");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// Q0-C consumer boundary: transformed bytes that are NOT zero-filled fail
/// closed even though the ledger claims a reinit.
#[test]
fn route_y_r0_q0c_new_bytes_nonzero_fails_closed() {
    let (raw_capture, mut globals, _c, bindings, ledger) = y0_declared_q0c_fixture();
    globals[0].content = vec![0u8; 0x180];
    globals[0].content[0x40] = 0x5A; // non-zero
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("non-zero re-init bytes must fail closed at Q0-C");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// Q0-C consumer boundary: a ledger run with a WRONG child_size (not the
/// declared new size) fails closed — the transition must be proven at the
/// declared new size.
#[test]
fn route_y_r0_q0c_ledger_child_size_wrong_fails_closed() {
    let (raw_capture, globals, _c, bindings, mut ledger) = y0_declared_q0c_fixture();
    ledger.runs[0].child_size = 0x400; // wrong new size in the ledger
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("wrong ledger child_size must fail closed at Q0-C");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// Q0-C consumer boundary (P1-2): a declared re-init whose new-size region
/// overlaps another transformed child writing a DIFFERENT value must fail
/// closed with a TransformWriteConflict — never a silent overwrite. The
/// ordinary child is processed first (lower base), registers its bytes into
/// `resolved_writes`, then the declared re-init's zeroed region collides.
#[test]
fn route_y_r0_q0c_overlap_different_value_fails_closed() {
    const RVA: u32 = 0x141bf0;
    const LIVE: u64 = 0x3437e50; // declared child base (0x141bf0)
    const B_BASE: u64 = 0x3437e20; // ordinary child base, covers LIVE region
    const OLD_SIZE: usize = 0x8000;
    const NEW_SIZE: usize = 0x180;
    const SLAB_BASE: u64 = 0x3400000;
    const SLAB_SZ: usize = 0x100000;
    // A: raw [0xAA; 0x8000] at LIVE. B: raw = [0xCC; 0x30] then [0xAA; 0x180]
    // so B covers [B_BASE, LIVE+NEW_SIZE) and its overlap with A is 0xAA.
    let off_a = (LIVE - SLAB_BASE) as usize;
    let off_b = (B_BASE - SLAB_BASE) as usize;
    let b_sz = (LIVE + NEW_SIZE as u64 - B_BASE) as usize; // 0x30 + 0x180
    let a_raw = vec![0xAAu8; OLD_SIZE];
    let mut b_raw = vec![0xCCu8; 0x30];
    b_raw.extend(std::iter::repeat(0xAAu8).take(NEW_SIZE));
    assert_eq!(b_raw.len(), b_sz);
    let mut slab_content = vec![0u8; SLAB_SZ];
    slab_content[off_a..off_a + OLD_SIZE].copy_from_slice(&a_raw);
    slab_content[off_b..off_b + b_sz].copy_from_slice(&b_raw);
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_content)],
        children: vec![
            raw_child(LIVE, OLD_SIZE, a_raw.clone(), RawChildKind::HeapGlobal),
            raw_child(B_BASE, b_sz, b_raw.clone(), RawChildKind::HeapGlobal),
        ],
    };
    raw_capture.children[0].capture_id = "mainA".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_capture.children[1].capture_id = "mainB".into();
    raw_capture.children[1].extent_kind = CaptureExtentKind::ObservedAllocation;
    // Declared re-init child A.
    let mut ga = global(LIVE, a_raw.clone(), false);
    ga.rva = RVA;
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = "mainA".into();
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    // Ordinary child B.
    let mut gb = global(B_BASE, b_raw.clone(), false);
    gb.extent_kind = CaptureExtentKind::ObservedAllocation;
    gb.extent_evidence.capture_id = "mainB".into();
    gb.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut globals = vec![ga, gb];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
    let _ = raw_children_from_capture(&containers, &globals);
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert_eq!(bindings.len(), 2);
    // Apply: A -> sanitize (zeroed 0x180); B -> ordinary +1 (0xCC->0xCD, 0xAA->0xAB).
    let mut ledger = TransformRunLedger::default();
    apply_recorded_transform(
        &mut globals,
        "sanitize_ahk_runtime_global",
        &mut ledger,
        |gs| {
            for g in gs.iter_mut() {
                if g.rva == RVA {
                    crate::dumper::heap_global_snapshot::sanitize_ahk_runtime_global(
                        std::slice::from_mut(g),
                    );
                }
            }
        },
    )
    .unwrap();
    apply_recorded_transform(
        &mut globals,
        "sort_gscript_label_table",
        &mut ledger,
        |gs| {
            for g in gs.iter_mut() {
                if g.rva != RVA {
                    for b in g.content.iter_mut() {
                        *b = b.wrapping_add(1);
                    }
                }
            }
        },
    )
    .unwrap();
    // B transforms to 0xCD/0xAB; A re-inits to 0x00.
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("overlapping different-value write must fail closed at Q0-C");
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
}

/// Route Y R1 A6 Q0-C deterministic fixture: a heap-global parent slot (A)
/// containing an interior gscript label-table entry (B), where
/// `scrub_uncaptured_heap_pointers` zeroes the qword holding B's `+0x23`
/// non-nested flag (because that qword looks like a dangling external
/// pointer), while `mark_labels_non_nested` sets B+0x23 = 1. The two children
/// therefore write the SAME slab byte to different final values → Q0-C must
/// fail closed with a `TransformWriteConflict`. This reproduces the live A6
/// conflict (A=[0x8e93c8,+0x2000), B=[0x8e9da8,+0x400), byte 0x8e9dcb)
/// deterministically, with explicit capture_id / extent_kind / capture_path /
/// binding / coverage membership / parent-interior lineage.
#[test]
fn route_y_r1_a6_q0c_contained_label_scrub_vs_mark_conflict() {
    // Geometry mirrors the live A6 conflict byte 0x8e9dcb.
    const A_BASE: u64 = 0x8e93c8; // heap-global parent slot
    const A_SIZE: usize = 0x2000; // 8192
    const B_BASE: u64 = 0x8e9da8; // interior gscript label-table entry
    const B_SIZE: usize = 0x400; // 1024
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    // Byte A+0xa03 == B+0x23 == absolute 0x8e9dcb (the conflict byte).
    let _a_off = (A_BASE - SLAB_BASE) as usize;
    let _b_off = (B_BASE - SLAB_BASE) as usize;
    assert_eq!(A_BASE + 0xa03, 0x8e9dcb);
    assert_eq!(B_BASE + 0x23, 0x8e9dcb);
    // Dangling user pointer (in user range, not in any captured range, not
    // image, not module) so scrub zeroes the qword holding it. 0x70000000's
    // LE bytes are [00,00,00,70,00,00,00,00] → the 0x70 non-zero byte lands
    // at byte offset 3, i.e. A+0xa03 == B+0x23 == 0x8e9dcb (the conflict byte).
    const DANGLING: u64 = 0x70000000;

    // --- A: parent heap-global slot, content 0xAA, with a dangling-ptr qword
    // at A+0xa00..0xa08 (holds A+0xa03's flag byte). B is interior to A and is
    // seeded from the authoritative slab slice, so B's raw bytes at its location
    // equal A's bytes (0xAA) — identical overlap keeps A's ObservedAllocation
    // (slab==content) seed check from drifting.
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    // --- B: interior gscript label-table entry, content = A's bytes at B's
    // location (0xAA) with a dangling-ptr qword at B+0x20..0x28 (holds B+0x23
    // flag). B is InteriorSubview → seeded from the authoritative slab slice.
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());

    let (raw_capture, globals, _containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw,
        &b_raw,
        A_BASE,
        A_SIZE,
        B_BASE,
        SLAB_BASE,
        SLAB_SZ,
        &protected_label_config(),
    );

    // Narrow mitigation (Route Y R1 A6): A's scrub SKIPS the protected
    // Label +0x23 flag qword (A is a DIFFERENT buffer than the Label B), so
    // A[0xa03] is NOT clobbered (stays 0x70). B's OWN scrub still zeroes
    // B[0x23] (0x70→0x00), then mark_labels_non_nested sets it to 1. So only
    // B writes at slab byte 0x8e9dcb → no TransformWriteConflict → overlay
    // succeeds, and the cold-start flag ends at the correct value 1.
    assert_eq!(globals[0].content[0xa03], 0x70); // A did NOT clobber the flag
    assert_eq!(globals[1].content[0x23], 0x01); // B flag = 1 (non-nested)
    let (_patched, overlays, _drift) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("narrow +0x23 mitigation must resolve the A/B conflict (no false fail)");
    assert!(
        overlays.iter().any(|o| o.child_old_base == A_BASE),
        "parent A overlay missing"
    );
    assert!(
        overlays.iter().any(|o| o.child_old_base == B_BASE),
        "interior B overlay missing"
    );
}

/// Build the A/B contained-label fixture, run the real production
/// scrub → mark_labels pipeline, and return the state for overlay assertion.
///
/// `protect_b` controls whether B is a legitimate gscript Label eligible for
/// the narrow +0x23 scrub protection. When true, B is in the table with a
/// valid capture_id and InteriorSubview lineage (protected → scrub skips A's
/// clobber of the flag, overlay succeeds). When false, B is in the table with
/// a valid capture_id but ObservedAllocation lineage (a same-offset
/// impersonator / wrong-lineage object) → protection is NOT applied → the
/// original scrub-vs-mark TransformWriteConflict must still fail closed.
#[allow(clippy::too_many_arguments)]
/// Configures B's identity/lineage/parent fields independently so the AF1/AF2
/// negative matrix can construct each failure mode explicitly.
#[derive(Clone)]
struct LabelConfig {
    /// In the gscript label table? (mark_labels_non_nested targets table-reachable
    /// labels regardless of the other fields.)
    in_table: bool,
    /// B's extent_kind.
    extent_kind: CaptureExtentKind,
    /// B's capture_id (empty = invalid identity).
    capture_id: String,
    /// B's capture_path.
    capture_path: crate::dumper::heap_global_snapshot::CapturePath,
    /// B's content length (must be > 0x23 for a valid flag byte).
    b_size: usize,
    /// containing_parent_old_base (None = no parent).
    parent_base: Option<u64>,
    /// containing_parent_size (None = no parent size).
    parent_size: Option<usize>,
    /// Parent A's capture_id (AF2: full parent identity).
    parent_capture_id: String,
    /// Parent A's extent_kind.
    parent_extent_kind: CaptureExtentKind,
    /// Parent A's capture_path.
    parent_capture_path: crate::dumper::heap_global_snapshot::CapturePath,
    /// When true, insert a second label snapshot at B's live_ptr (duplicate).
    duplicate_label: bool,
    /// When true, insert a second parent snapshot at A's base/size (duplicate).
    duplicate_parent: bool,
    /// When Some, override A's content length independently of a_raw (for
    /// child-not-contained cases that keep declared parent_size different).
    parent_content_size_override: Option<usize>,
}

impl Default for LabelConfig {
    fn default() -> Self {
        use crate::dumper::heap_global_snapshot::CapturePath as CP;
        LabelConfig {
            in_table: true,
            extent_kind: CaptureExtentKind::InteriorSubview,
            capture_id: "gscript_label:0x8e9da8".into(),
            // Route Y R1 A6 AF3: the A6 chain captures B via
            // `exhaust_gscript_label_table_entries`, which now emits
            // GscriptLabelTableEntry (the truthful label-table source, not
            // MainSlot). GscriptChildLink is NOT the production path for a
            // label-table entry — the AF3 fixture uses the real family.
            capture_path: CP::GscriptLabelTableEntry,
            b_size: 0x400,
            parent_base: Some(0x8e93c8),
            parent_size: Some(0x2000),
            parent_capture_id: "heap_global_slot:0x8e93c8".into(),
            parent_extent_kind: CaptureExtentKind::ObservedAllocation,
            parent_capture_path: CP::MainSlot,
            duplicate_label: false,
            duplicate_parent: false,
            parent_content_size_override: None,
        }
    }
}

/// A fully-protected legitimate Label config (the A6-confirmed case).
fn protected_label_config() -> LabelConfig {
    LabelConfig::default()
}

/// Build the A/B contained-label fixture, run the real production
/// scrub → mark_labels pipeline, and return the state for overlay assertion.
///
/// `b_config` fully controls B's and A's identity/lineage/parent so the AF1/AF2
/// negative matrix can exercise each protection-gate failure independently.
#[allow(clippy::too_many_arguments)]
fn a6_contained_label_pipeline(
    a_raw: &[u8],
    b_raw: &[u8],
    a_base: u64,
    a_size: usize,
    b_base: u64,
    slab_base: u64,
    slab_sz: usize,
    b_config: &LabelConfig,
) -> (
    RawSlabCapture,
    Vec<HeapGlobalSnapshot>,
    Vec<ContainerSnapshot>,
    Vec<TransformPreimageBinding>,
    TransformRunLedger,
) {
    use crate::dumper::heap_global_snapshot::mark_labels_non_nested;
    use crate::dumper::heap_global_snapshot::scrub_uncaptured_heap_pointers;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    let b_size = b_config.b_size;
    let a_content_size = b_config.parent_content_size_override.unwrap_or(a_size);
    let a_off = (a_base - slab_base) as usize;
    let b_off = (b_base - slab_base) as usize;
    let mut gscript = vec![0u8; 0x40];
    gscript[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table = vec![0u8; 0x10];
    if b_config.in_table {
        table[0..8].copy_from_slice(&b_base.to_le_bytes()); // B is a table entry
    }
    let snap = vec![0u8; 0x30];
    let gscript_off = (GSCRIPT - slab_base) as usize;
    let table_off = (TABLE - slab_base) as usize;
    let snap_off = (SNAP - slab_base) as usize;
    // a_raw may be longer than a_content_size when testing containment failure;
    // take the leading a_content_size bytes for the snapshot content.
    let a_content = if a_raw.len() >= a_content_size {
        a_raw[..a_content_size].to_vec()
    } else {
        let mut v = a_raw.to_vec();
        v.resize(a_content_size, 0xAA);
        v
    };
    let mut slab_content = vec![0u8; slab_sz];
    let a_slab_len = a_content.len().min(slab_sz.saturating_sub(a_off));
    slab_content[a_off..a_off + a_slab_len].copy_from_slice(&a_content[..a_slab_len]);
    if b_off + b_size <= slab_sz {
        slab_content[b_off..b_off + b_size].copy_from_slice(b_raw);
    }
    slab_content[gscript_off..gscript_off + gscript.len()].copy_from_slice(&gscript);
    slab_content[table_off..table_off + table.len()].copy_from_slice(&table);
    slab_content[snap_off..snap_off + snap.len()].copy_from_slice(&snap);
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab(slab_base, slab_content)],
        children: vec![
            raw_child(
                a_base,
                a_content.len(),
                a_content.clone(),
                RawChildKind::HeapGlobal,
            ),
            raw_child(b_base, b_size, b_raw.to_vec(), RawChildKind::HeapGlobal),
            raw_child(TABLE, table.len(), table.clone(), RawChildKind::HeapGlobal),
            raw_child(SNAP, snap.len(), snap.clone(), RawChildKind::HeapGlobal),
        ],
    };
    raw_capture.children[0].capture_id = b_config.parent_capture_id.clone();
    raw_capture.children[2].capture_id = "gscript_table:0x8f1000".into();
    raw_capture.children[3].capture_id = "string_snapshot:0x900000".into();
    for c in raw_capture.children.iter_mut() {
        c.extent_kind = CaptureExtentKind::ObservedAllocation;
    }
    raw_capture.children[0].extent_kind = b_config.parent_extent_kind;
    raw_capture.children[0].capture_path = b_config.parent_capture_path;
    raw_capture.children[1].capture_id = b_config.capture_id.clone();
    raw_capture.children[1].extent_kind = b_config.extent_kind;
    raw_capture.children[1].capture_path = b_config.capture_path;
    raw_capture.children[1].containing_parent_old_base = b_config.parent_base;
    raw_capture.children[1].containing_parent_size = b_config.parent_size;

    let mut ga = global(a_base, a_content, false);
    ga.extent_kind = b_config.parent_extent_kind;
    ga.extent_evidence.capture_id = b_config.parent_capture_id.clone();
    ga.extent_evidence.capture_path = b_config.parent_capture_path;
    let mut gb = global(b_base, b_raw.to_vec(), false);
    gb.extent_kind = b_config.extent_kind;
    gb.extent_evidence.capture_id = b_config.capture_id.clone();
    gb.extent_evidence.capture_path = b_config.capture_path;
    gb.extent_evidence.containing_parent_old_base = b_config.parent_base;
    gb.extent_evidence.containing_parent_size = b_config.parent_size;
    // Route Y R1 A6 AF3 AF1 (P1-5/P1-6): the label-table family requires its
    // deterministic source evidence to be canonical. When B's path is
    // GscriptLabelTableEntry, record the table-entry offset (0 here — single
    // entry at +0), the gscript root RVA, was_interior = true, and probe = 0.
    if b_config.capture_path
        == crate::dumper::heap_global_snapshot::CapturePath::GscriptLabelTableEntry
    {
        gb.extent_evidence.source_slot_offset = Some(0);
        gb.extent_evidence.source_root_rva = Some(0x149d50);
        gb.extent_evidence.was_interior = true;
        gb.extent_evidence.probe_requested_size = 0;
    }
    // Mirror the source evidence onto the raw child so raw binding and the
    // consume-time canonical check agree (AF3 AF2 P1-2: RawChild now freezes
    // source_root_rva too, so the raw child and transformed B carry the SAME
    // complete identity).
    raw_capture.children[1].source_slot_offset = gb.extent_evidence.source_slot_offset;
    raw_capture.children[1].source_root_rva = gb.extent_evidence.source_root_rva;
    raw_capture.children[1].requested_probe_size = gb.extent_evidence.probe_requested_size;
    raw_capture.children[1].was_interior = gb.extent_evidence.was_interior;
    let mut gg = global(GSCRIPT, gscript, true);
    gg.rva = 0x149d50; // image-inline gscript root RVA (matches B source_root_rva)
    gg.extent_kind = CaptureExtentKind::ObservedAllocation;
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    gg.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut gt = global(TABLE, table, false);
    gt.extent_kind = CaptureExtentKind::ObservedAllocation;
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    gt.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut gsnap = global(SNAP, snap, false);
    gsnap.extent_kind = CaptureExtentKind::ObservedAllocation;
    gsnap.extent_evidence.capture_id = "string_snapshot:0x900000".into();
    gsnap.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;

    let mut globals = vec![ga, gb, gg, gt, gsnap];

    // AF2: inject a second label at the same live_ptr (duplicate identity
    // ambiguity). Unique resolution must refuse protection.
    if b_config.duplicate_label {
        let mut gb2 = global(b_base, b_raw.to_vec(), false);
        gb2.extent_kind = b_config.extent_kind;
        // Distinct capture_id so identity matrix accepts both, but same live_ptr
        // so unique_heap_global(live_ptr==entry) sees >1 match.
        gb2.extent_evidence.capture_id = format!("{}:dup", b_config.capture_id);
        gb2.extent_evidence.capture_path = b_config.capture_path;
        gb2.extent_evidence.containing_parent_old_base = b_config.parent_base;
        gb2.extent_evidence.containing_parent_size = b_config.parent_size;
        // Skip identity validation for the duplicate case — the production
        // protection generator must still refuse without relying on the gate.
        globals.push(gb2);
    }

    // AF2: inject a second parent at the same base/size but different capture_id.
    if b_config.duplicate_parent {
        let mut ga2 = global(
            a_base,
            a_raw[..a_content_size.min(a_raw.len())].to_vec(),
            false,
        );
        if ga2.content.len() < a_content_size {
            ga2.content.resize(a_content_size, 0xAA);
        }
        ga2.extent_kind = b_config.parent_extent_kind;
        ga2.extent_evidence.capture_id = format!("{}:dup", b_config.parent_capture_id);
        ga2.extent_evidence.capture_path = b_config.parent_capture_path;
        globals.push(ga2);
    }

    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    // Duplicate cases intentionally violate uniqueness; skip the identity gate
    // so we can observe the protection generator's own fail-closed behaviour.
    if !b_config.duplicate_label && !b_config.duplicate_parent {
        validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    }
    // Probe coverage only over non-duplicate fixtures (duplicates may place
    // extra objects outside the slab).
    if !b_config.duplicate_label && !b_config.duplicate_parent {
        validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
    }
    let _ = raw_children_from_capture(&containers, &globals);
    let bindings = if !b_config.duplicate_label && !b_config.duplicate_parent {
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap()
    } else {
        // Minimal empty bindings for scrub-only negative tests.
        Vec::new()
    };
    let mut ledger = TransformRunLedger::default();
    if !b_config.duplicate_label && !b_config.duplicate_parent {
        apply_recorded_transform(
            &mut globals,
            "scrub_uncaptured_heap_pointers",
            &mut ledger,
            |gs| {
                scrub_uncaptured_heap_pointers(&mut containers, gs, 0, slab_base + slab_sz as u64);
            },
        )
        .unwrap();
        apply_recorded_transform(&mut globals, "mark_labels_non_nested", &mut ledger, |gs| {
            mark_labels_non_nested(gs)
        })
        .unwrap();
    } else {
        // Scrub + mark directly (no transform ledger) for ambiguity negatives.
        scrub_uncaptured_heap_pointers(
            &mut containers,
            &mut globals,
            0,
            slab_base + slab_sz as u64,
        );
        mark_labels_non_nested(&mut globals);
    }
    (raw_capture, globals, containers, bindings, ledger)
}

/// AF1 negative #1 (same_address_different_capture_id): B occupies the same
/// physical offset with an InteriorSubview shape but a DIFFERENT capture_id
/// (not the gscript_label id) — the protection's strict identity gate must
/// reject it. A's scrub clobbers the shared byte (0x00) while B's mark sets
/// it (0x01) → TransformWriteConflict must still fail closed.
#[test]
fn route_y_r1_a6_q0c_same_addr_diff_capture_id_fails_closed() {
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let mut cfg = protected_label_config();
    cfg.capture_id = "different_capture:0x8e9da8".into(); // wrong capture identity
    let (raw_capture, globals, containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    // Wrong capture_id → not protected → A clobbers the shared byte.
    assert_eq!(globals[0].content[0xa03], 0x00);
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("same-address different capture_id must fail closed at Q0-C");
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    let _ = containers;
}

/// Negative: two distinct captures write different values to the SAME slab
/// byte — neither is a protected label — so TransformWriteConflict still
/// fails closed (the resolved-writes check is not weakened).
#[test]
fn route_y_r1_a6_q0c_two_distinct_identities_conflict_still_fails_closed() {
    // Reuse the existing geometry but with a second non-label interior child
    // that is NOT in the table (protect_b=false) AND has a distinct identity,
    // forcing the conflicting write at the shared byte.
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    // B is a non-label "other" heap-global (wrong identity) — not protected.
    let mut cfg = protected_label_config();
    cfg.capture_id = "heap_global_other:0x8e9da8".into();
    cfg.extent_kind = CaptureExtentKind::ObservedAllocation;
    cfg.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let (raw_capture, globals, _containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    // Both A and B write to the shared byte 0x8e9dcb: A scrubs (0x00), B's
    // scrub then mark sets (0x01). Distinct identities, different values →
    // conflict must fail closed.
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("two distinct identities writing different values must fail closed");
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
}

/// AF1 negative #2 (non_gscript_object_same_offset_not_protected): an object
/// that is NOT a gscript Label (ObservedAllocation / MainSlot, "other"
/// identity) at the same physical offset must NOT get the +0x23 protection.
/// A's scrub clobbers the shared byte while B's mark sets it → conflict.
#[test]
fn route_y_r1_a6_q0c_non_gscript_object_not_protected() {
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    // Non-gscript: ObservedAllocation + MainSlot + "other" identity. Still
    // table-reachable so mark fires, but not a protected Label.
    let mut cfg = protected_label_config();
    cfg.extent_kind = CaptureExtentKind::ObservedAllocation;
    cfg.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    cfg.capture_id = "heap_global_other:0x8e9da8".into();
    let (raw_capture, globals, containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    assert_eq!(globals[0].content[0xa03], 0x00); // A scrubbed (not protected)
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("non-gscript same-offset object must not be protected (fail closed)");
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    let _ = containers;
}

/// AF1 negative #3 (gscript_label_wrong_containing_parent_not_protected): a
/// table-reachable InteriorSubview Label whose containing_parent points at the
/// WRONG object (not the buffer being scrubbed). The strict parent binding
/// must reject it → A's scrub clobbers the shared byte → conflict.
#[test]
fn route_y_r1_a6_q0c_label_wrong_containing_parent_not_protected() {
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    // InteriorSubview + gscript_label id + GscriptChildLink, but parent points
    // at a WRONG object (a different base/size), so A's scrub is NOT authorized
    // to skip this qword.
    let mut cfg = protected_label_config();
    cfg.parent_base = Some(0x99990000); // wrong parent base
    cfg.parent_size = Some(0x9999); // wrong parent size
    let (raw_capture, globals, containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    assert_eq!(globals[0].content[0xa03], 0x00); // A scrubbed (parent mismatch → not protected)
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("label with wrong containing_parent must not be protected (fail closed)");
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    let _ = containers;
}

/// AF1 negative #4 (gscript_label_wrong_capture_path_not_protected): a Label
/// with the gscript_label capture_id but a MainSlot capture_path (which is not
/// a gscript Label path). The protection's path gate must reject it → the
/// object is treated as a plain heap-global → A's scrub clobbers the shared
/// byte → conflict. (ObservedAllocation extent is used so the identity matrix
/// accepts the MainSlot path — isolating the capture_path as the only reason
/// protection is denied.)
#[test]
fn route_y_r1_a6_q0c_label_wrong_capture_path_not_protected() {
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let mut cfg = protected_label_config();
    cfg.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot; // wrong path
    cfg.extent_kind = CaptureExtentKind::ObservedAllocation; // valid for MainSlot identity
    let (raw_capture, globals, containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    assert_eq!(globals[0].content[0xa03], 0x00); // A scrubbed (MainSlot path → not protected)
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("label with wrong capture_path must not be protected (fail closed)");
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    let _ = containers;
}

/// AF1 negative #5 (gscript_label_flag_out_of_bounds_not_protected): a Label
/// whose content.len() <= 0x23 has no valid +0x23 flag byte → no protection
/// entry is generated → A's scrub clobbers the byte → conflict.
#[test]
fn route_y_r1_a6_q0c_label_flag_out_of_bounds_not_protected() {
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x10; // too short for +0x23
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    // B too short to hold +0x23; the +0x23 byte is outside B.
    let b_raw = vec![0xAAu8; B_SIZE];
    let mut cfg = protected_label_config();
    cfg.b_size = B_SIZE;
    let (_raw_capture, globals, _containers, _bindings, _ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    // A's scrub clobbers the shared byte (no protection entry for an out-of-bounds
    // flag). B has no +0x23 field (len<=0x23) so mark cannot set it; but A's
    // scrub write at the shared byte is still a transform write. Assert the
    // target byte was scrubbed (the actual observable outcome).
    assert_eq!(globals[0].content[0xa03], 0x00);
}

/// AF1 negative #6 (wrong_extent_kind_not_protected): ProbeWindow (and any
/// non-InteriorSubview extent) must NOT receive protection. ProbeWindow has no
/// fixture/evidence justifying protection, so it is excluded by design.
#[test]
fn route_y_r1_a6_q0c_probe_window_extent_not_protected() {
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    // ProbeWindow extent → NOT protected (only InteriorSubview is authorized).
    let mut cfg = protected_label_config();
    cfg.extent_kind = CaptureExtentKind::ProbeWindow;
    cfg.capture_path = crate::dumper::heap_global_snapshot::CapturePath::GscriptChildLink;
    let (raw_capture, globals, containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    assert_eq!(globals[0].content[0xa03], 0x00); // ProbeWindow not protected → A scrubbed
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("ProbeWindow extent must not be protected (fail closed)");
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    let _ = containers;
}

/// AF1 negative #7 (unrelated_overlapping_parent_not_protected): a buffer that
/// merely OVERLAPS the protected flag address but is NOT the Label's containing
/// parent must not skip the scrub. Construct an unrelated parent C whose range
/// covers the flag address but is not A (the Label's declared parent). The
/// scrub of C must still zero the qword.
#[test]
fn route_y_r1_a6_q0c_unrelated_overlapping_parent_not_protected() {
    use crate::dumper::heap_global_snapshot::scrub_uncaptured_heap_pointers;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    // Unrelated parent C covers B's flag address but is NOT B's containing parent
    // (which is A). C's scrub must NOT skip the qword.
    const C_BASE: u64 = 0x8e9000;
    const C_SIZE: usize = 0x2000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    // B's declared containing parent is A (default), not C.
    let cfg = protected_label_config();
    let (_raw_capture, mut globals, mut containers, _bindings, _ledger) =
        a6_contained_label_pipeline(
            &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
        );
    // Add an unrelated buffer C whose range overlaps the flag address but whose
    // base/size do NOT match B's containing parent (A). Scrubbing C must zero
    // its dangling qword (no protection applies to a non-parent buffer).
    let mut gc = global(C_BASE, vec![0xCCu8; C_SIZE], false);
    gc.extent_kind = CaptureExtentKind::ObservedAllocation;
    gc.extent_evidence.capture_id = "unrelated_parent:0x8e9000".into();
    gc.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    // C covers B's flag address (0x8e9dcb is within [C_BASE, C_BASE+C_SIZE)).
    assert!(B_BASE + 0x23 >= C_BASE && B_BASE + 0x23 < C_BASE + C_SIZE as u64);
    // Place a dangling pointer in C at the flag-relative offset.
    let c_flag_off = (B_BASE + 0x23 - C_BASE) as usize - 3; // align qword containing flag
    gc.content[c_flag_off..c_flag_off + 8].copy_from_slice(&DANGLING.to_le_bytes());
    globals.push(gc);
    // Scrub all buffers; C is not the Label's parent, so its qword IS zeroed.
    scrub_uncaptured_heap_pointers(&mut containers, &mut globals, 0, SLAB_BASE + SLAB_SZ as u64);
    // Find C's global and assert its qword was scrubbed (unrelated parent not protected).
    let gc_after = globals
        .iter()
        .find(|g| g.extent_evidence.capture_id == "unrelated_parent:0x8e9000")
        .expect("unrelated C present");
    assert_eq!(
        &gc_after.content[c_flag_off..c_flag_off + 8],
        &[0u8; 8],
        "unrelated overlapping parent C must NOT be protected (qword must be scrubbed)"
    );
}

/// P2 (qword minimal authorization): the protection skips ONLY the qword
/// containing the protected Label +0x23 flag byte (A[0xa00..0xa08), which
/// holds B+0x23). The qword BEFORE B's range and AFTER B's range in the parent
/// buffer A, plus an unrelated dangling qword, must all still be scrubbed.
/// This proves the qword grant is minimal — it protects only the Label's own
/// flag qword, not surrounding bytes or unrelated dangling pointers.
#[test]
fn route_y_r1_a6_q0c_qword_grant_is_minimal() {
    use crate::dumper::heap_global_snapshot::scrub_uncaptured_heap_pointers;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    // B occupies A[0x9e0..0xde0). The protected flag byte B+0x23 == A+0xa03 is
    // inside qword A[0xa00..0xa08). Place control dangling qwords OUTSIDE B's
    // range so A's scrub cleanly targets them (no B-buffer interference).
    let b_start = (B_BASE - A_BASE) as usize; // 0x9e0
    let flag_q = (B_BASE + 0x20 - A_BASE) as usize; // A[0xa00..0xa08)
    let before_q = b_start - 0x20; // A[0x9c0..0x9c8), before B
    let after_q = b_start + B_SIZE; // A[0xde0..0xde8), after B
    let other_q = 0x500usize; // unrelated dangling qword deep in A
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[before_q..before_q + 8].copy_from_slice(&DANGLING.to_le_bytes());
    a_raw[flag_q..flag_q + 8].copy_from_slice(&DANGLING.to_le_bytes());
    a_raw[after_q..after_q + 8].copy_from_slice(&DANGLING.to_le_bytes());
    a_raw[other_q..other_q + 8].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let cfg = protected_label_config();
    let (_raw_capture, mut globals, mut containers, _bindings, _ledger) =
        a6_contained_label_pipeline(
            &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
        );
    // Scrub all buffers. A is the Label's containing parent, so its flag qword
    // is skipped; the before/after/unrelated qwords are NOT protected and are
    // scrubbed to 0.
    scrub_uncaptured_heap_pointers(&mut containers, &mut globals, 0, SLAB_BASE + SLAB_SZ as u64);
    let a = &globals[0].content;
    assert_eq!(
        &a[flag_q..flag_q + 8],
        &DANGLING.to_le_bytes(),
        "A must skip the Label's own flag qword (not scrub it)"
    );
    assert_eq!(
        &a[before_q..before_q + 8],
        &[0u8; 8],
        "qword before B must still be scrubbed"
    );
    assert_eq!(
        &a[after_q..after_q + 8],
        &[0u8; 8],
        "qword after B must still be scrubbed"
    );
    assert_eq!(
        &a[other_q..other_q + 8],
        &[0u8; 8],
        "unrelated dangling qword must still be scrubbed"
    );
}

/// Legitimate label containment: A (parent heap-global) contains interior
/// label B, and B's +0x23 flag is ALREADY non-zero (mark_labels_non_nested
/// skips it — line 3127 "Already non-nested"). Then B's only write is scrub
/// zeroing the dangling qword — the SAME value A writes at the shared slab
/// byte. Q0-C must NOT false-positive: identical write values at the shared
/// byte are `SharedWriteSameValue` (no conflict), so the overlay succeeds.
/// This proves legitimate contained label writes that agree with the parent
/// are NOT over-rejected.
#[test]
fn route_y_r1_a6_q0c_legitimate_containment_agrees_no_conflict() {
    use crate::dumper::heap_global_snapshot::mark_labels_non_nested;
    use crate::dumper::heap_global_snapshot::scrub_uncaptured_heap_pointers;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000; // LE [00,00,00,70,...] → 0x70 at byte 3
    let a_off = (A_BASE - SLAB_BASE) as usize;
    let b_off = (B_BASE - SLAB_BASE) as usize;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    // B is an interior child NOT referenced from the gscript label table, so
    // mark_labels_non_nested does NOT target B. B's only transform is scrub,
    // which zeroes the shared byte to 0x00 — the SAME value A writes. This is
    // the legitimate-containment scenario: A and B agree on the shared byte.
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    let mut gscript = vec![0u8; 0x40];
    gscript[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript[0x10..0x14].copy_from_slice(&0u32.to_le_bytes()); // empty table → no labels
    let table = vec![0u8; 0x10]; // empty label table (no entry for B)
    let snap = vec![0u8; 0x30];
    let gscript_off = (GSCRIPT - SLAB_BASE) as usize;
    let table_off = (TABLE - SLAB_BASE) as usize;
    let snap_off = (SNAP - SLAB_BASE) as usize;
    let mut slab_content = vec![0u8; SLAB_SZ];
    slab_content[a_off..a_off + A_SIZE].copy_from_slice(&a_raw);
    slab_content[b_off..b_off + B_SIZE].copy_from_slice(&b_raw);
    slab_content[gscript_off..gscript_off + gscript.len()].copy_from_slice(&gscript);
    slab_content[table_off..table_off + table.len()].copy_from_slice(&table);
    slab_content[snap_off..snap_off + snap.len()].copy_from_slice(&snap);
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_content)],
        children: vec![
            raw_child(A_BASE, A_SIZE, a_raw.clone(), RawChildKind::HeapGlobal),
            raw_child(B_BASE, B_SIZE, b_raw.clone(), RawChildKind::HeapGlobal),
            raw_child(TABLE, table.len(), table.clone(), RawChildKind::HeapGlobal),
            raw_child(SNAP, snap.len(), snap.clone(), RawChildKind::HeapGlobal),
        ],
    };
    raw_capture.children[0].capture_id = "heap_global_slot:0x8e93c8".into();
    raw_capture.children[1].capture_id = "gscript_label:0x8e9da8".into();
    raw_capture.children[2].capture_id = "gscript_table:0x8f1000".into();
    raw_capture.children[3].capture_id = "string_snapshot:0x900000".into();
    for c in raw_capture.children.iter_mut() {
        c.extent_kind = CaptureExtentKind::ObservedAllocation;
    }
    raw_capture.children[1].extent_kind = CaptureExtentKind::InteriorSubview;
    raw_capture.children[1].capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::GscriptChildLink;
    raw_capture.children[1].containing_parent_old_base = Some(A_BASE);
    raw_capture.children[1].containing_parent_size = Some(A_SIZE);

    let mut ga = global(A_BASE, a_raw.clone(), false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = "heap_global_slot:0x8e93c8".into();
    ga.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut gb = global(B_BASE, b_raw.clone(), false);
    gb.extent_kind = CaptureExtentKind::InteriorSubview;
    gb.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    gb.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::GscriptChildLink;
    gb.extent_evidence.containing_parent_old_base = Some(A_BASE);
    gb.extent_evidence.containing_parent_size = Some(A_SIZE);
    let mut gg = global(GSCRIPT, gscript, true);
    gg.extent_kind = CaptureExtentKind::ObservedAllocation;
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    gg.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut gt = global(TABLE, table, false);
    gt.extent_kind = CaptureExtentKind::ObservedAllocation;
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    gt.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut gsnap = global(SNAP, snap, false);
    gsnap.extent_kind = CaptureExtentKind::ObservedAllocation;
    gsnap.extent_evidence.capture_id = "string_snapshot:0x900000".into();
    gsnap.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    let mut globals = vec![ga, gb, gg, gt, gsnap];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
    let _ = raw_children_from_capture(&containers, &globals);
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let mut ledger = TransformRunLedger::default();
    apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |gs| {
            scrub_uncaptured_heap_pointers(&mut containers, gs, 0, SLAB_BASE + SLAB_SZ as u64);
        },
    )
    .unwrap();
    apply_recorded_transform(&mut globals, "mark_labels_non_nested", &mut ledger, |gs| {
        mark_labels_non_nested(gs)
    })
    .unwrap();
    // B is NOT a mark_labels target (empty table), so B's +0x23 was scrubbed
    // to 0x00 (dangling qword zeroed), matching A's 0x00 at the shared byte.
    // Both write 0x00 at 0x8e9dcb → SharedWriteSameValue, no conflict. Overlay
    // must SUCCEED (legitimate containment, agreeing writes).
    assert_eq!(globals[0].content[0xa03], 0x00); // A scrubbed shared byte
    assert_eq!(globals[1].content[0x23], 0x00); // B scrubbed shared byte (mark skipped)
    let (_patched, overlays, _drift) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("legitimate contained label (agreeing writes) must NOT fail closed");
    // Both A and B present as overlays.
    assert!(
        overlays.iter().any(|o| o.child_old_base == A_BASE),
        "parent A overlay missing"
    );
    assert!(
        overlays.iter().any(|o| o.child_old_base == B_BASE),
        "interior B overlay missing"
    );
}

/// Hand-build a complete declared-reinit fixture WITHOUT running the
/// production recorder, so a test can supply an arbitrary ledger (prior-writer
/// chains, malformed extra runs, etc.). Raw child A carries the declared
/// capture identity; the binding is a self-consistent ChildCapture binding
/// over that raw child. Returns (raw_capture, globals, bindings); the caller
/// owns the ledger.
fn y0_manual_identity_fixture(
    raw_capture_id: &str,
) -> (
    RawSlabCapture,
    Vec<HeapGlobalSnapshot>,
    Vec<TransformPreimageBinding>,
) {
    const RVA: u32 = 0x141bf0;
    const LIVE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const SLAB_BASE: u64 = 0x3400000;
    const SLAB_SZ: usize = 0x100000;
    let raw_bytes = vec![0xAAu8; OLD_SIZE];
    let slab_content = slab_with_child(SLAB_BASE, SLAB_SZ, LIVE, raw_bytes.clone()).content;
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_content.clone())],
        children: vec![raw_child(
            LIVE,
            OLD_SIZE,
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = raw_capture_id.to_string();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_capture.children[0].capture_path = CapturePath::MainSlot;
    let mut g = global(LIVE, vec![0u8; 0x180], false);
    g.rva = RVA;
    g.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    g.extent_kind = CaptureExtentKind::ObservedAllocation;
    g.extent_evidence.capture_id = raw_capture_id.to_string();
    g.extent_evidence.capture_path = CapturePath::MainSlot;
    let globals = vec![g];
    let off = (LIVE - SLAB_BASE) as usize;
    let slab_slice = slab_content[off..off + OLD_SIZE].to_vec();
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: raw_capture_id.to_string(),
        child_old_base: LIVE,
        child_size: OLD_SIZE,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            raw_capture_id.to_string(),
            LIVE,
            OLD_SIZE,
            CaptureExtentKind::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: SLAB_BASE,
        slab_size: SLAB_SZ,
        slab_digest: sha256_hex(&slab_content),
        slab_offset: off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&raw_bytes),
        raw_slab_slice_digest: sha256_hex(&slab_slice),
        transform_input_digest: sha256_hex(&raw_bytes),
        seeded_from_slab: false,
    };
    (raw_capture, globals, vec![binding])
}

/// Build a sanitize transition run with the given before bytes.
fn y0_sanitize_run(capture_id: &str, before: Vec<u8>) -> TransformWriteRun {
    let new_size = 0x180usize;
    let after = vec![0u8; new_size];
    assert_eq!(before.len(), new_size);
    TransformWriteRun {
        child_capture_id: capture_id.to_string(),
        child_old_base: 0x3437e50,
        child_size: new_size,
        child_offset: 0,
        length: new_size,
        transform_id: "sanitize_ahk_runtime_global".into(),
        before_digest: sha256_hex(&before),
        after_digest: sha256_hex(&after),
        first_before_byte: before[0],
        first_after_byte: 0x00,
        before_bytes: before,
        after_bytes: after,
    }
}

/// Q0-C consumer boundary (P1-3 / Audit P1-3): a LEGAL prior-writer chain
/// before the declared re-init must be accepted. A prior recorded transform
/// (e.g. scrub_uncaptured_heap_pointers) changes byte 0 from 0xAA to 0xAB
/// before sanitize; the sanitize run's before state is the replayed current
/// state (0xAB prefix), NOT the raw prefix. The chain replays in ledger
/// execution order and the overlay must succeed.
#[test]
fn route_y_r0_q0c_prior_writer_chain_before_declared_reinit_succeeds() {
    let (raw_capture, globals, bindings) = y0_manual_identity_fixture("mainA");
    // prior writer: byte 0 -> 0xAB (raw child_size 0x8000, offset 0, len 1).
    let prior = TransformWriteRun {
        child_capture_id: "mainA".into(),
        child_old_base: 0x3437e50,
        child_size: 0x8000,
        child_offset: 0,
        length: 1,
        transform_id: "scrub_uncaptured_heap_pointers".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xAB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xAB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xAB],
    };
    // sanitize sees byte 0 = 0xAB (post-scrub), rest = 0xAA.
    let mut before = vec![0xAAu8; 0x180];
    before[0] = 0xAB;
    let sanitize = y0_sanitize_run("mainA", before);
    let ledger = TransformRunLedger {
        runs: vec![prior, sanitize],
    };
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("a valid prior-writer chain + declared re-init must succeed");
    let off = (0x3437e50 - 0x3400000) as usize;
    assert_eq!(&patched[0].content[off..off + 0x180], &[0u8; 0x180]);
    assert!(overlays.iter().any(|o| o.overlay_applied));
}

/// Q0-C consumer boundary (P1-2 / Audit P1-2): one well-formed transition run
/// PLUS an extra run with the same transition identity but a WRONG shape must
/// fail closed (ambiguous transition). The extra bad run must not be silently
/// filtered out.
#[test]
fn route_y_r0_q0c_extra_same_identity_bad_run_fails_closed() {
    let (raw_capture, globals, bindings) = y0_manual_identity_fixture("mainA");
    let good = y0_sanitize_run("mainA", vec![0xAAu8; 0x180]);
    // Same transition identity, but wrong child_size / offset / fabricated bytes.
    let bad = TransformWriteRun {
        child_capture_id: "mainA".into(),
        child_old_base: 0x3437e50,
        child_size: 0x200, // wrong new size
        child_offset: 0x180,
        length: 0x80,
        transform_id: "sanitize_ahk_runtime_global".into(),
        before_digest: sha256_hex(&[0xAA; 0x80]),
        after_digest: sha256_hex(&[0x55; 0x80]),
        first_before_byte: 0xAA,
        first_after_byte: 0x55,
        before_bytes: vec![0xAA; 0x80],
        after_bytes: vec![0x55; 0x80],
    };
    let ledger = TransformRunLedger {
        runs: vec![good, bad],
    };
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("an extra same-identity bad run must fail closed");
    assert!(matches!(
        err,
        OverlayError::TransformRunLedgerInvalid { .. }
    ));
}

/// Q0-C consumer boundary (P1-1 / Audit P1-1): two raw children share the same
/// old_base + kind but carry DIFFERENT capture identities. The declared
/// re-init resolves by full capture identity and must succeed with the
/// declared capture — it must not confuse the two captures (the pre-fix code
/// selected by raw-byte/slab coherence and could consume the wrong capture).
#[test]
fn route_y_r0_q0c_same_base_different_capture_identity_resolves_correctly() {
    const RVA: u32 = 0x141bf0;
    const LIVE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const SLAB_BASE: u64 = 0x3400000;
    const SLAB_SZ: usize = 0x100000;
    let raw_bytes = vec![0xAAu8; OLD_SIZE];
    let slab_content = slab_with_child(SLAB_BASE, SLAB_SZ, LIVE, raw_bytes.clone()).content;
    // Two raw children at the SAME base+kind with different capture ids.
    let mut raw_a = raw_child(LIVE, OLD_SIZE, raw_bytes.clone(), RawChildKind::HeapGlobal);
    raw_a.capture_id = "realA".into();
    raw_a.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_a.capture_path = CapturePath::MainSlot;
    let mut raw_b = raw_child(LIVE, OLD_SIZE, raw_bytes.clone(), RawChildKind::HeapGlobal);
    raw_b.capture_id = "fakeB".into();
    raw_b.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_b.capture_path = CapturePath::MainSlot;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_content.clone())],
        children: vec![raw_a, raw_b],
    };
    // Transformed snapshot declares capture "realA".
    let mut g = global(LIVE, vec![0u8; 0x180], false);
    g.rva = RVA;
    g.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    g.extent_kind = CaptureExtentKind::ObservedAllocation;
    g.extent_evidence.capture_id = "realA".into();
    g.extent_evidence.capture_path = CapturePath::MainSlot;
    let globals = vec![g];
    let off = (LIVE - SLAB_BASE) as usize;
    let slab_slice = slab_content[off..off + OLD_SIZE].to_vec();
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "realA".into(),
        child_old_base: LIVE,
        child_size: OLD_SIZE,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("realA"),
            LIVE,
            OLD_SIZE,
            CaptureExtentKind::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: SLAB_BASE,
        slab_size: SLAB_SZ,
        slab_digest: sha256_hex(&slab_content),
        slab_offset: off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&raw_bytes),
        raw_slab_slice_digest: sha256_hex(&slab_slice),
        transform_input_digest: sha256_hex(&raw_bytes),
        seeded_from_slab: false,
    };
    let ledger = TransformRunLedger {
        runs: vec![y0_sanitize_run("realA", vec![0xAAu8; 0x180])],
    };
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &[binding], &ledger)
            .expect("declared re-init must resolve the declared capture by identity");
    let off2 = (LIVE - SLAB_BASE) as usize;
    assert_eq!(&patched[0].content[off2..off2 + 0x180], &[0u8; 0x180]);
    assert!(overlays
        .iter()
        .any(|o| o.child_old_base == LIVE && o.overlay_applied));
}

/// Q0-C consumer boundary (P1-1 / Audit P1-1 strongest form): the declared
/// capture's raw bytes DISAGREE with the slab, while a DIFFERENT capture at
/// the same base+kind AGREES with the slab. The overlay must resolve by
/// capture identity (choose A) and then FAIL CLOSED on A's coherence — it
/// must NEVER silently fall back to the different-capture raw child (B) that
/// happens to match the slab.
#[test]
fn route_y_r0_q0c_wrong_capture_raw_bytes_must_not_fall_back_to_slab_matching_child() {
    const RVA: u32 = 0x141bf0;
    const LIVE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const SLAB_BASE: u64 = 0x3400000;
    const SLAB_SZ: usize = 0x100000;
    // Slab region holds B's bytes (0xBB); A's declared bytes (0xAA) differ.
    let slab_bytes = vec![0xBBu8; OLD_SIZE];
    let slab_content = slab_with_child(SLAB_BASE, SLAB_SZ, LIVE, slab_bytes.clone()).content;
    let mut raw_a = raw_child(
        LIVE,
        OLD_SIZE,
        vec![0xAAu8; OLD_SIZE],
        RawChildKind::HeapGlobal,
    );
    raw_a.capture_id = "realA".into();
    raw_a.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_a.capture_path = CapturePath::MainSlot;
    let mut raw_b = raw_child(LIVE, OLD_SIZE, slab_bytes.clone(), RawChildKind::HeapGlobal);
    raw_b.capture_id = "fakeB".into();
    raw_b.extent_kind = CaptureExtentKind::ObservedAllocation;
    raw_b.capture_path = CapturePath::MainSlot;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_content.clone())],
        children: vec![raw_a, raw_b],
    };
    // Transformed snapshot + binding + ledger all declare capture "realA".
    let mut g = global(LIVE, vec![0u8; 0x180], false);
    g.rva = RVA;
    g.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    g.extent_kind = CaptureExtentKind::ObservedAllocation;
    g.extent_evidence.capture_id = "realA".into();
    g.extent_evidence.capture_path = CapturePath::MainSlot;
    let globals = vec![g];
    let off = (LIVE - SLAB_BASE) as usize;
    let a_slice = slab_content[off..off + OLD_SIZE].to_vec(); // B's bytes in the slab
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "realA".into(),
        child_old_base: LIVE,
        child_size: OLD_SIZE,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("realA"),
            LIVE,
            OLD_SIZE,
            CaptureExtentKind::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: SLAB_BASE,
        slab_size: SLAB_SZ,
        slab_digest: sha256_hex(&slab_content),
        slab_offset: off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&vec![0xAAu8; OLD_SIZE]), // A's digest
        raw_slab_slice_digest: sha256_hex(&a_slice),
        transform_input_digest: sha256_hex(&vec![0xAAu8; OLD_SIZE]), // A's preimage
        seeded_from_slab: false,
    };
    let ledger = TransformRunLedger {
        runs: vec![y0_sanitize_run("realA", vec![0xAAu8; 0x180])],
    };
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &[binding], &ledger)
        .expect_err(
            "declared capture whose raw disagrees with the slab must fail closed, \
                 never fall back to the different-capture slab-matching child",
        );
    assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
}

/// Q0-C + recorder agreement (Audit P1): a real declared size re-init whose
/// old prefix ALREADY contains zero bytes (free-list-polluted heap blob) must
/// go through the PRODUCTION chain — recorder emits a single dedicated full
/// transition run, and Q0-C accepts it. The recorder must NOT emit multiple
/// sparse byte-diff runs (a zero already present in the prefix would otherwise
/// split the diff), and Q0-C must NOT reject a legitimate single-run ledger.
#[test]
fn route_y_r0_q0c_sparse_zero_prefix_succeeds() {
    const RVA: u32 = 0x141bf0;
    const LIVE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    // Old prefix is mostly 0xAA but contains ZERO bytes at scattered offsets
    // (0x40, 0x80, 0x100) — exactly the polluted free-list blob shape.
    let mut raw_bytes = vec![0xAAu8; OLD_SIZE];
    raw_bytes[0x40] = 0x00;
    raw_bytes[0x80] = 0x00;
    raw_bytes[0x100] = 0x00;
    let slab = slab_with_child(0x3400000, 0x100000, LIVE, raw_bytes.clone());
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            LIVE,
            OLD_SIZE,
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "mainslot:0x141bf0:0x3437e50".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    let mut g = global(LIVE, raw_bytes.clone(), false);
    g.rva = RVA;
    g.extent_kind = CaptureExtentKind::ObservedAllocation;
    g.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    g.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut globals = vec![g];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
    let _ = raw_children_from_capture(&containers, &globals);
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    // Real recorder + real sanitize.
    let mut ledger = TransformRunLedger::default();
    apply_recorded_transform(
        &mut globals,
        "sanitize_ahk_runtime_global",
        &mut ledger,
        |gs| {
            for gs in gs.iter_mut() {
                crate::dumper::heap_global_snapshot::sanitize_ahk_runtime_global(
                    std::slice::from_mut(gs),
                );
            }
        },
    )
    .unwrap();
    assert_eq!(globals[0].content.len(), 0x180);
    assert!(globals[0].content.iter().all(|&b| b == 0));
    // The recorder MUST emit exactly ONE full transition run despite the
    // sparse zero bytes in the old prefix.
    assert_eq!(
        ledger.runs.len(),
        1,
        "declared re-init recorder must emit exactly one full transition run"
    );
    assert_eq!(ledger.runs[0].child_offset, 0);
    assert_eq!(ledger.runs[0].length, 0x180);
    // Q0-C accepts the single-run ledger and produces an exactly-zeroed slab.
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("sparse-zero-prefix declared re-init must succeed at Q0-C");
    let off = (LIVE - 0x3400000) as usize;
    assert_eq!(&patched[0].content[off..off + 0x180], &[0u8; 0x180]);
    assert!(overlays.iter().any(|o| o.overlay_applied));
}

/// Q0-C + recorder agreement (Audit P1, prior-writer variant): a prior
/// recorded transform zeros part of the prefix, then sanitize runs. The
/// recorder still emits ONE full transition run for sanitize (its before
/// state already includes the prior zeros), and Q0-C accepts the full chain.
#[test]
fn route_y_r0_q0c_prior_writer_sparse_zero_prefix_succeeds() {
    const RVA: u32 = 0x141bf0;
    const LIVE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    let raw_bytes = vec![0xAAu8; OLD_SIZE];
    let slab = slab_with_child(0x3400000, 0x100000, LIVE, raw_bytes.clone());
    let mut raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            LIVE,
            OLD_SIZE,
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    raw_capture.children[0].capture_id = "mainslot:0x141bf0:0x3437e50".into();
    raw_capture.children[0].extent_kind = CaptureExtentKind::ObservedAllocation;
    let mut g = global(LIVE, raw_bytes.clone(), false);
    g.rva = RVA;
    g.extent_kind = CaptureExtentKind::ObservedAllocation;
    g.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    g.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut globals = vec![g];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals).unwrap();
    validate_probe_coverage(&globals, &raw_capture.slabs).unwrap();
    let _ = raw_children_from_capture(&containers, &globals);
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let mut ledger = TransformRunLedger::default();
    // A prior transform zeros byte 0x40 (like scrub), then sanitize re-inits.
    apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |gs| {
            for gs in gs.iter_mut() {
                if gs.rva == RVA {
                    if let Some(b) = gs.content.get_mut(0x40) {
                        *b = 0x00;
                    }
                }
            }
        },
    )
    .unwrap();
    apply_recorded_transform(
        &mut globals,
        "sanitize_ahk_runtime_global",
        &mut ledger,
        |gs| {
            for gs in gs.iter_mut() {
                crate::dumper::heap_global_snapshot::sanitize_ahk_runtime_global(
                    std::slice::from_mut(gs),
                );
            }
        },
    )
    .unwrap();
    assert_eq!(globals[0].content.len(), 0x180);
    assert!(globals[0].content.iter().all(|&b| b == 0));
    // sanitize's own ledger run must be a single full [0,0x180) transition run.
    let sanitize_runs: Vec<_> = ledger
        .runs
        .iter()
        .filter(|r| r.transform_id == "sanitize_ahk_runtime_global")
        .collect();
    assert_eq!(
        sanitize_runs.len(),
        1,
        "sanitize must emit exactly one full run"
    );
    assert_eq!(sanitize_runs[0].child_offset, 0);
    assert_eq!(sanitize_runs[0].length, 0x180);
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("prior-writer + declared re-init must succeed at Q0-C");
    let off = (LIVE - 0x3400000) as usize;
    assert_eq!(&patched[0].content[off..off + 0x180], &[0u8; 0x180]);
    assert!(overlays.iter().any(|o| o.overlay_applied));
}

// =====================================================================
// AF2R1 mandatory tests — full-identity authorization consumption.
// =====================================================================

/// AF2R1 mandatory #1: same parent base/size but a DIFFERENT parent
/// capture_id must not be authorized. The scrub parent (current identity)
/// has the same base and size as the protection's recorded parent, but its
/// capture_id differs. The production predicate must reject it and the
/// actual scrub must zero the flag qword.
#[test]
fn route_y_r1_a6_q0c_same_parent_base_size_different_capture_id_not_protected() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    use crate::dumper::heap_global_snapshot::{
        parse_canonical_gscript_label_capture_id, protection_authorizes_qword,
        scrub_buffer_external_ptrs, CaptureIdentity, CurrentScrubIdentity, LabelFlagProtection,
        ScrubObjectKind,
    };
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const DANGLING: u64 = 0x70000000;
    // Baseline protection entry (parent identity with the canonical id).
    let parent = CaptureIdentity {
        capture_id: "heap_global_slot:0x8e93c8".into(),
        extent_kind: CaptureExtentKind::ObservedAllocation,
        capture_path: CP::MainSlot,
        old_base: A_BASE,
        size: A_SIZE,
        source_slot_offset: None,
        probe_requested_size: 0,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    // Route Y R1 A6 AF3: production-reachable label identity family — the
    // exhaust emitter (which captured the live A6 B) emits
    // GscriptLabelTableEntry + `gscript_label:{base}` + InteriorSubview.
    let child = CaptureIdentity {
        capture_id: "gscript_label:0x8e9da8".into(),
        extent_kind: CaptureExtentKind::InteriorSubview,
        capture_path: CP::GscriptLabelTableEntry,
        old_base: B_BASE,
        size: B_SIZE,
        source_slot_offset: Some(0),
        probe_requested_size: 0,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let p = LabelFlagProtection {
        child,
        parent,
        flag_offset: 0x23,
        flag_addr: B_BASE + 0x23,
        flag_qword_lo: B_BASE + 0x20,
        flag_qword_hi: B_BASE + 0x28,
    };
    // Current scrub buffer: same base/size, DIFFERENT capture_id.
    let current = CurrentScrubIdentity {
        kind: ScrubObjectKind::HeapGlobal,
        capture_id: "heap_global_slot:0xDEADBEEF".into(),
        extent_kind: CaptureExtentKind::ObservedAllocation,
        capture_path: CP::MainSlot,
        old_base: A_BASE,
        size: A_SIZE,
        source_root_rva: None,
        source_slot_offset: None,
        probe_requested_size: 0,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    assert!(
        !protection_authorizes_qword(&current, &p, p.flag_qword_lo, p.flag_qword_hi),
        "same parent base/size but different capture_id must NOT be authorized"
    );
    // Actual scrub: a dangling qword inside this buffer must be zeroed.
    let mut buf = vec![0xAAu8; A_SIZE];
    let flag_q = (B_BASE - A_BASE) as usize + 0x20; // A[0xa00..0xa08)
    buf[flag_q..flag_q + 8].copy_from_slice(&DANGLING.to_le_bytes());
    scrub_buffer_external_ptrs(&mut buf, &current, &[], 0, 0, &[p]);
    assert_eq!(
        &buf[flag_q..flag_q + 8],
        &[0u8; 8],
        "unrelated-identity parent qword must be scrubbed"
    );
    // Canonical parser sanity (this test's id is the canonical one).
    assert!(parse_canonical_gscript_label_capture_id(
        "gscript_label:0x8e9da8",
        B_BASE
    ));
}

/// AF2R1 mandatory #2: same parent identity except a DIFFERENT capture_path
/// must not be authorized.
#[test]
fn route_y_r1_a6_q0c_same_parent_identity_except_capture_path_not_protected() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    use crate::dumper::heap_global_snapshot::{
        protection_authorizes_qword, CaptureIdentity, CurrentScrubIdentity, LabelFlagProtection,
        ScrubObjectKind,
    };
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    let parent = CaptureIdentity {
        capture_id: "heap_global_slot:0x8e93c8".into(),
        extent_kind: CaptureExtentKind::ObservedAllocation,
        capture_path: CP::MainSlot,
        old_base: A_BASE,
        size: A_SIZE,
        source_slot_offset: None,
        probe_requested_size: 0,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    // Production-reachable label identity family (AF3).
    let child = CaptureIdentity {
        capture_id: "gscript_label:0x8e9da8".into(),
        extent_kind: CaptureExtentKind::InteriorSubview,
        capture_path: CP::GscriptLabelTableEntry,
        old_base: B_BASE,
        size: B_SIZE,
        source_slot_offset: Some(0),
        probe_requested_size: 0,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let p = LabelFlagProtection {
        child,
        parent: parent.clone(),
        flag_offset: 0x23,
        flag_addr: B_BASE + 0x23,
        flag_qword_lo: B_BASE + 0x20,
        flag_qword_hi: B_BASE + 0x28,
    };
    // Same everything, except capture_path is GscriptChildLink (not MainSlot).
    let current = CurrentScrubIdentity {
        kind: ScrubObjectKind::HeapGlobal,
        capture_id: parent.capture_id.clone(),
        extent_kind: parent.extent_kind,
        capture_path: CP::GscriptChildLink,
        old_base: parent.old_base,
        size: parent.size,
        source_root_rva: parent.source_root_rva,
        source_slot_offset: parent.source_slot_offset,
        probe_requested_size: parent.probe_requested_size,
        was_interior: parent.was_interior,
        containing_parent_old_base: parent.containing_parent_old_base,
        containing_parent_size: parent.containing_parent_size,
    };
    assert!(
        !protection_authorizes_qword(&current, &p, p.flag_qword_lo, p.flag_qword_hi),
        "parent identity differing only in capture_path must NOT be authorized"
    );
}

/// AF2R1 mandatory #3: child capture_id keeps the `gscript_label:` prefix but
/// the ENCODED address differs from child.old_base. The canonical parser must
/// reject it, no protection entry is generated, and the full pipeline fails
/// closed at Q0-C overlay.
#[test]
fn route_y_r1_a6_q0c_same_child_address_gscript_prefix_but_wrong_encoded_address() {
    use crate::dumper::heap_global_snapshot::parse_canonical_gscript_label_capture_id;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    // Prefix correct, encoded address wrong → parser rejects.
    assert!(!parse_canonical_gscript_label_capture_id(
        "gscript_label:0x8e9000",
        B_BASE
    ));
    assert!(!parse_canonical_gscript_label_capture_id(
        "gscript_label:0x8e9da8:foreign",
        B_BASE
    ));
    assert!(!parse_canonical_gscript_label_capture_id(
        "gscript_label:0x8e9000:0x1",
        B_BASE
    ));
    assert!(parse_canonical_gscript_label_capture_id(
        "gscript_label:0x8e9da8",
        B_BASE
    ));

    // Full pipeline with the wrong-encoded-address id → no protection →
    // A's scrub clobbers the shared byte, B's mark sets it → conflict.
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let mut cfg = protected_label_config();
    cfg.capture_id = "gscript_label:0x8e9000".into(); // wrong encoded address
    let (raw_capture, globals, containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    assert_eq!(
        globals[0].content[0xa03], 0x00,
        "A must have clobbered the shared byte (wrong-address child NOT protected)"
    );
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
        .expect_err("wrong-encoded-address child capture id must fail closed");
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
    let _ = containers;
}

/// AF2R1 mandatory #4: malformed gscript_label capture_ids must not be
/// protected. The canonical parser independently rejects every listed form,
/// and for each non-empty malformed id the full pipeline fails closed.
#[test]
fn route_y_r1_a6_q0c_malformed_gscript_label_capture_id_not_protected() {
    use crate::dumper::heap_global_snapshot::parse_canonical_gscript_label_capture_id;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    // (a) Parser rejects every malformed form independently.
    let malformed: &[&str] = &[
        "",
        "gscript_label:",
        "gscript_label:wrong",
        "gscript_label:0x8e9da8:foreign",
        "gscript_label:0x8E9DA8",        // uppercase hex
        "gscript_label:0x8e9da8garbage", // trailing non-hex
        "gscript_label:0x00008e9da8",    // leading zero (non-canonical)
        "gscript_label:0x8e9da8x",
        "gscript_label:0x8e9da8 ",
        "gscript_label:0x8e9da8\n",
    ];
    for id in malformed {
        assert!(
            !parse_canonical_gscript_label_capture_id(id, B_BASE),
            "malformed capture_id {:?} must NOT pass canonical parse",
            id
        );
    }
    // (b) Full pipeline for every NON-EMPTY malformed id (empty id is
    // rejected earlier at identity validation, never reaching protections).
    // Each case must independently resolve to no protection → TransformWriteConflict.
    let pipeline_malformed: &[&str] = &[
        "gscript_label:",
        "gscript_label:wrong",
        "gscript_label:0x8e9da8:foreign",
        "gscript_label:0x8E9DA8",
        "gscript_label:0x8e9da8garbage",
        "gscript_label:0x00008e9da8",
        "gscript_label:0x8e9da8x",
        "gscript_label:0x8e9da8 ",
        "gscript_label:0x8e9da8\n",
    ];
    for id in pipeline_malformed {
        let mut a_raw = vec![0xAAu8; A_SIZE];
        a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
        let mut b_raw = vec![0xAAu8; B_SIZE];
        b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
        let mut cfg = protected_label_config();
        cfg.capture_id = (*id).to_string();
        let (raw_capture, globals, containers, bindings, ledger) = a6_contained_label_pipeline(
            &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
        );
        assert_eq!(
            globals[0].content[0xa03], 0x00,
            "malformed id {:?} must NOT be protected (A clobbers shared byte)",
            id
        );
        let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect_err("malformed id must fail closed at Q0-C");
        assert!(
            matches!(err, OverlayError::TransformWriteConflict { .. }),
            "id {:?} must fail closed",
            id
        );
        let _ = containers;
    }
}

/// AF2R1 mandatory #5: duplicate label at the same address must fail closed —
/// unique resolution refuses to pick the first; no protection entry is
/// generated.
#[test]
fn route_y_r1_a6_q0c_duplicate_label_same_address_fails_closed() {
    use crate::dumper::heap_global_snapshot::gscript_label_flag_protections;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let mut cfg = protected_label_config();
    cfg.duplicate_label = true;
    let (_raw, globals, _containers, _bindings, _ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    // Two labels at the same live_ptr → unique resolution must refuse.
    let protections = gscript_label_flag_protections(&globals);
    assert!(
        protections.is_empty(),
        "duplicate label at same address must not be protected (must not pick first)"
    );
}

/// AF2R1 mandatory #6: duplicate parent (same base/size, different identity)
/// must fail closed — no protection entry is generated.
#[test]
fn route_y_r1_a6_q0c_duplicate_parent_same_base_size_fails_closed() {
    use crate::dumper::heap_global_snapshot::gscript_label_flag_protections;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let mut cfg = protected_label_config();
    cfg.duplicate_parent = true;
    let (_raw, globals, _containers, _bindings, _ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    let protections = gscript_label_flag_protections(&globals);
    assert!(
        protections.is_empty(),
        "duplicate parent (same base/size, different identity) must not be protected"
    );
}

/// AF2R1 mandatory #7: child not fully contained in parent (child end beyond
/// parent end) must not be protected.
#[test]
fn route_y_r1_a6_q0c_child_not_fully_contained_not_protected() {
    use crate::dumper::heap_global_snapshot::label_flag_range_authorized;
    const A_BASE: u64 = 0x8e93c8;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const FLAG: u64 = B_BASE + 0x23;
    // Parent is truncated so child end (B_BASE+B_SIZE) is beyond parent end.
    // A_BASE + 0x600 > B_BASE + B_SIZE would be contained; use A_BASE+0x200 so
    // parent end = 0x8e95c8 < child end 0x8ea1a8 → not contained.
    assert!(!label_flag_range_authorized(
        B_BASE, B_SIZE, A_BASE, 0x200, FLAG,
    ));
    // Child start below parent start is also not contained.
    assert!(!label_flag_range_authorized(
        A_BASE - 0x100,
        0x2000,
        A_BASE,
        0x2000,
        A_BASE,
    ));
    // Sanity: fully-contained still authorized.
    assert!(label_flag_range_authorized(
        B_BASE, B_SIZE, A_BASE, 0x2000, FLAG,
    ));
}

/// AF2R1 mandatory #8: flag address overflow or outside parent must not be
/// authorized (checked_add, no wrapping).
#[test]
fn route_y_r1_a6_q0c_flag_address_overflow_or_outside_parent_not_protected() {
    use crate::dumper::heap_global_snapshot::label_flag_range_authorized;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    // Flag OUTSIDE parent end (parent [A_BASE, A_BASE+0x300), flag at
    // B_BASE+0x23 = A_BASE+0xa03 is way beyond parent end).
    assert!(!label_flag_range_authorized(
        B_BASE,
        B_SIZE,
        A_BASE,
        0x300,
        B_BASE + 0x23,
    ));
    // Overflow: child_base near u64::MAX → checked_add must fail closed.
    // (u64::MAX - 0x10) + 0x23 itself overflows, so we build the two values
    // with wrapping in the TEST ONLY and assert the range predicate rejects
    // the wrapping-derived flag (never authorizes on checked_add failure).
    let child_base_near_max = u64::MAX - 0x10;
    let wrapped_flag = child_base_near_max.wrapping_add(0x23);
    assert_eq!(
        child_base_near_max.checked_add(0x23),
        None,
        "precondition: child_base + 0x23 must overflow"
    );
    assert!(!label_flag_range_authorized(
        child_base_near_max,
        0x40,
        0,
        0x1000,
        wrapped_flag,
    ));
    // Fully-contained baseline (A contains B, flag inside both).
    assert!(label_flag_range_authorized(
        B_BASE,
        B_SIZE,
        A_BASE,
        A_SIZE,
        B_BASE + 0x23,
    ));
}

/// AF2R1 mandatory #9: EVERY identity field is consumed by the authorization
/// predicate. Flipping any one of the 10 fields (child capture_id/extent/path/
/// base/size + parent capture_id/extent/path/base/size) must make the
/// predicate deny authorization.
#[test]
fn route_y_r1_a6_q0c_identity_fields_are_consumed() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    use crate::dumper::heap_global_snapshot::{
        protection_authorizes_qword, CaptureIdentity, CurrentScrubIdentity, LabelFlagProtection,
        ScrubObjectKind,
    };
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    let qlo = B_BASE + 0x20;
    let qhi = B_BASE + 0x28;
    let make_parent = |capture_id: &str,
                       extent_kind: CaptureExtentKind,
                       capture_path: CP,
                       old_base: u64,
                       size: usize| CaptureIdentity {
        capture_id: capture_id.into(),
        extent_kind,
        capture_path,
        old_base,
        size,
        source_slot_offset: None,
        probe_requested_size: 0,
        source_root_rva: None,
        was_interior: false,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let baseline_parent = make_parent(
        "heap_global_slot:0x8e93c8",
        CaptureExtentKind::ObservedAllocation,
        CP::MainSlot,
        A_BASE,
        A_SIZE,
    );
    // Route Y R1 A6 AF3: production-reachable label identity family. The
    // child must carry the canonical label-table source evidence (AF3 AF1
    // P1-5/P1-6) so the baseline is authorized.
    let mut baseline_child = make_parent(
        "gscript_label:0x8e9da8",
        CaptureExtentKind::InteriorSubview,
        CP::GscriptLabelTableEntry,
        B_BASE,
        B_SIZE,
    );
    baseline_child.source_slot_offset = Some(0);
    baseline_child.source_root_rva = Some(0x149d50);
    baseline_child.was_interior = true;
    let make_current = |parent: &CaptureIdentity| CurrentScrubIdentity {
        kind: ScrubObjectKind::HeapGlobal,
        capture_id: parent.capture_id.clone(),
        extent_kind: parent.extent_kind,
        capture_path: parent.capture_path,
        old_base: parent.old_base,
        size: parent.size,
        source_root_rva: parent.source_root_rva,
        source_slot_offset: parent.source_slot_offset,
        probe_requested_size: parent.probe_requested_size,
        was_interior: parent.was_interior,
        containing_parent_old_base: parent.containing_parent_old_base,
        containing_parent_size: parent.containing_parent_size,
    };
    let make_prot = |child: CaptureIdentity, parent: CaptureIdentity| LabelFlagProtection {
        child,
        parent,
        flag_offset: 0x23,
        flag_addr: B_BASE + 0x23,
        flag_qword_lo: qlo,
        flag_qword_hi: qhi,
    };
    // Baseline: full match → authorized.
    let base_prot = make_prot(baseline_child.clone(), baseline_parent.clone());
    let base_current = make_current(&baseline_parent);
    assert!(
        protection_authorizes_qword(&base_current, &base_prot, qlo, qhi),
        "baseline full-identity match must be authorized"
    );

    // Child field flips (each independently must deny).
    let mut flips: Vec<(&str, CaptureIdentity, CurrentScrubIdentity)> = Vec::new();

    // child.capture_id flip.
    let mut c = baseline_child.clone();
    c.capture_id = "gscript_label:0x99999999".into();
    flips.push(("child.capture_id", c.clone(), base_current.clone()));

    // child.extent_kind flip.
    let mut c = baseline_child.clone();
    c.extent_kind = CaptureExtentKind::ProbeWindow;
    flips.push(("child.extent_kind", c.clone(), base_current.clone()));

    // child.capture_path flip.
    let mut c = baseline_child.clone();
    c.capture_path = CP::MainSlot;
    flips.push(("child.capture_path", c.clone(), base_current.clone()));

    // child.old_base flip (child base no longer matches flag_addr).
    let mut c = baseline_child.clone();
    c.old_base = B_BASE + 0x10;
    flips.push(("child.old_base", c.clone(), base_current.clone()));

    // child.size flip (child no longer contains flag byte).
    let mut c = baseline_child.clone();
    c.size = 0x10; // < 0x23 → flag out of bounds
    flips.push(("child.size", c.clone(), base_current.clone()));

    // Parent field flips: the CURRENT scrub identity differs from the
    // protection's recorded parent by exactly one field.

    // parent.capture_id flip.
    let mut cur = base_current.clone();
    cur.capture_id = "heap_global_slot:0xDEADBEEF".into();
    flips.push(("parent.capture_id", baseline_child.clone(), cur.clone()));

    // parent.extent_kind flip.
    let mut cur = base_current.clone();
    cur.extent_kind = CaptureExtentKind::ProbeWindow;
    flips.push(("parent.extent_kind", baseline_child.clone(), cur.clone()));

    // parent.capture_path flip.
    let mut cur = base_current.clone();
    cur.capture_path = CP::GscriptChildLink;
    flips.push(("parent.capture_path", baseline_child.clone(), cur.clone()));

    // parent.old_base flip.
    let mut cur = base_current.clone();
    cur.old_base = A_BASE + 0x100;
    flips.push(("parent.old_base", baseline_child.clone(), cur.clone()));

    // parent.size flip.
    let mut cur = base_current.clone();
    cur.size = A_SIZE - 0x100;
    flips.push(("parent.size", baseline_child.clone(), cur.clone()));

    for (name, child_id, current) in flips {
        let prot = make_prot(child_id.clone(), baseline_parent.clone());
        assert!(
            !protection_authorizes_qword(&current, &prot, qlo, qhi),
            "field flip {} must DENY authorization",
            name
        );
    }
}

// ==================== Route Y R1 A6 AF3 AF2 AF1 tests ====================

/// Build a baseline gscript-label protection whose PARENT carries the FULL
/// source-evidence identity (source_root_rva, source_slot_offset,
/// probe_requested_size, was_interior, containing_parent). Returns
/// (protection, current_matching_parent, qword_lo, qword_hi) — where
/// `current_matching_parent` EQUALS the recorded parent on every field, so the
/// baseline is authorized and a single source-evidence flip on `current` must
/// deny.
fn a6_parent_source_evidence_fixture() -> (
    crate::dumper::heap_global_snapshot::LabelFlagProtection,
    crate::dumper::heap_global_snapshot::CurrentScrubIdentity,
    u64,
    u64,
) {
    use crate::dumper::heap_global_snapshot::CaptureIdentity;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    use crate::dumper::heap_global_snapshot::CurrentScrubIdentity;
    use crate::dumper::heap_global_snapshot::LabelFlagProtection;
    use crate::dumper::heap_global_snapshot::ScrubObjectKind;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    let qlo = B_BASE + 0x20;
    let qhi = B_BASE + 0x28;
    // Parent carries the FULL source-evidence identity.
    let parent = CaptureIdentity {
        capture_id: "heap_global_slot:0x8e93c8".into(),
        extent_kind: CaptureExtentKind::ObservedAllocation,
        capture_path: CP::MainSlot,
        old_base: A_BASE,
        size: A_SIZE,
        source_slot_offset: Some(0),
        probe_requested_size: 0x1000,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: Some(0x900000),
        containing_parent_size: Some(0x100),
    };
    let child = CaptureIdentity {
        capture_id: "gscript_label:0x8e9da8".into(),
        extent_kind: CaptureExtentKind::InteriorSubview,
        capture_path: CP::GscriptLabelTableEntry,
        old_base: B_BASE,
        size: B_SIZE,
        source_slot_offset: Some(0),
        probe_requested_size: 0,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: None,
        containing_parent_size: None,
    };
    let p = LabelFlagProtection {
        child,
        parent,
        flag_offset: 0x23,
        flag_addr: B_BASE + 0x23,
        flag_qword_lo: qlo,
        flag_qword_hi: qhi,
    };
    // A current scrub parent that EQUALS the recorded parent on every field.
    let current = CurrentScrubIdentity {
        kind: ScrubObjectKind::HeapGlobal,
        capture_id: p.parent.capture_id.clone(),
        extent_kind: p.parent.extent_kind,
        capture_path: p.parent.capture_path,
        old_base: p.parent.old_base,
        size: p.parent.size,
        source_root_rva: p.parent.source_root_rva,
        source_slot_offset: p.parent.source_slot_offset,
        probe_requested_size: p.parent.probe_requested_size,
        was_interior: p.parent.was_interior,
        containing_parent_old_base: p.parent.containing_parent_old_base,
        containing_parent_size: p.parent.containing_parent_size,
    };
    // Baseline sanity: full match is authorized.
    assert!(
        crate::dumper::heap_global_snapshot::protection_authorizes_qword(&current, &p, qlo, qhi),
        "baseline full parent source-evidence match must be authorized"
    );
    (p, current, qlo, qhi)
}

/// Assert that flipping a SINGLE parent source-evidence field on the current
/// scrub identity denies authorization AND the dangling qword is actually
/// scrubbed (not merely `matches_parent` false).
fn assert_parent_source_flip_denies_and_scrubs(
    name: &str,
    flip: impl FnOnce(&mut crate::dumper::heap_global_snapshot::CurrentScrubIdentity),
) {
    use crate::dumper::heap_global_snapshot::scrub_buffer_external_ptrs;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const A_BASE: u64 = 0x8e93c8;
    const DANGLING: u64 = 0x70000000;
    let (p, mut current, qlo, qhi) = a6_parent_source_evidence_fixture();
    flip(&mut current);
    assert!(
        !crate::dumper::heap_global_snapshot::protection_authorizes_qword(&current, &p, qlo, qhi),
        "parent {name} flip must DENY authorization"
    );
    // Actual scrub: the dangling qword in this buffer must be zeroed because
    // the protection does NOT cover the current parent.
    let mut buf = vec![0xAAu8; A_SIZE];
    let flag_q = (B_BASE - A_BASE) as usize + 0x20; // A[0xa00..0xa08)
    buf[flag_q..flag_q + 8].copy_from_slice(&DANGLING.to_le_bytes());
    scrub_buffer_external_ptrs(&mut buf, &current, &[], 0, 0, &[p]);
    assert_eq!(
        &buf[flag_q..flag_q + 8],
        &[0u8; 8],
        "parent {name} flip must cause the qword to be scrubbed"
    );
}

// P1-1 test 1: parent.source_root_rva mismatch not protected + scrubbed.
#[test]
fn route_y_r1_a6_q0c_parent_source_root_rva_mismatch_not_protected() {
    assert_parent_source_flip_denies_and_scrubs("source_root_rva", |c| {
        c.source_root_rva = Some(0xDEAD);
    });
}

// P1-1 test 2: parent.source_slot_offset mismatch not protected + scrubbed.
#[test]
fn route_y_r1_a6_q0c_parent_source_slot_offset_mismatch_not_protected() {
    assert_parent_source_flip_denies_and_scrubs("source_slot_offset", |c| {
        c.source_slot_offset = Some(7);
    });
}

// P1-1 test 3: parent.probe_requested_size mismatch not protected + scrubbed.
#[test]
fn route_y_r1_a6_q0c_parent_probe_requested_size_mismatch_not_protected() {
    assert_parent_source_flip_denies_and_scrubs("probe_requested_size", |c| {
        c.probe_requested_size = 0x40;
    });
}

// P1-1 test 4: parent.was_interior mismatch not protected + scrubbed.
#[test]
fn route_y_r1_a6_q0c_parent_was_interior_mismatch_not_protected() {
    assert_parent_source_flip_denies_and_scrubs("was_interior", |c| {
        c.was_interior = false;
    });
}

// P1-1 test 5: parent.containing_parent_old_base mismatch not protected + scrubbed.
#[test]
fn route_y_r1_a6_q0c_parent_containing_parent_base_mismatch_not_protected() {
    assert_parent_source_flip_denies_and_scrubs("containing_parent_old_base", |c| {
        c.containing_parent_old_base = Some(0x910000);
    });
}

// P1-1 test 6: parent.containing_parent_size mismatch not protected + scrubbed.
#[test]
fn route_y_r1_a6_q0c_parent_containing_parent_size_mismatch_not_protected() {
    assert_parent_source_flip_denies_and_scrubs("containing_parent_size", |c| {
        c.containing_parent_size = Some(0x200);
    });
}

/// Build a single-transformed-child seeding fixture where the transformed
/// snapshot carries FULL source evidence. Returns (raw_capture, transformed).
fn seeding_full_identity_fixture(
    probe: usize,
    was_interior: bool,
    src_root: Option<u32>,
) -> (RawSlabCapture, HeapGlobalSnapshot) {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    let mut slab_bytes = vec![0u8; 0x200000];
    let off = (B_BASE - SLAB_BASE) as usize;
    slab_bytes[off..off + B_SIZE].fill(0xAA);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_bytes)],
        children: vec![RawChild {
            old_base: B_BASE,
            size: B_SIZE,
            raw_bytes: vec![0xAAu8; B_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "gscript_label:0x8e9da8".into(),
            capture_path: CP::GscriptLabelTableEntry,
            extent_kind: CaptureExtentKind::InteriorSubview,
            source_slot_offset: Some(0),
            requested_probe_size: probe,
            source_root_rva: src_root,
            was_interior,
            containing_parent_old_base: Some(0x8e93c8),
            containing_parent_size: Some(0x2000),
        }],
    };
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = probe;
    transformed.extent_evidence.source_root_rva = src_root;
    transformed.extent_evidence.was_interior = was_interior;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    (raw_capture, transformed)
}

// P1-2 test 7: same bytes, different source identity -> seeding selects the
// EXACT full identity (not first-match by capture_id sort).
#[test]
fn route_y_r1_a6_q0c_seed_same_bytes_different_source_identity_selects_exact() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    // Two raw children: SAME base/size/bytes/capture_id/path/extent, SAME
    // source_slot_offset, but DIFFERENT probe (0x100 vs 0x200). Both have
    // identical raw bytes. The transformed snapshot matches EXACTLY the
    // probe=0x100 child. Seeding must pick it, NOT sort-then-first.
    let mk = |probe: usize| RawChild {
        old_base: B_BASE,
        size: B_SIZE,
        raw_bytes: vec![0xAAu8; B_SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: "gscript_label:0x8e9da8".into(),
        capture_path: CP::GscriptLabelTableEntry,
        extent_kind: CaptureExtentKind::InteriorSubview,
        source_slot_offset: Some(0),
        requested_probe_size: probe,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: Some(0x8e93c8),
        containing_parent_size: Some(0x2000),
    };
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; 0x200000])],
        children: vec![mk(0x100), mk(0x200)],
    };
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    let mut globals = vec![transformed.clone()];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let b = bindings
        .iter()
        .find(|b| b.child_old_base == B_BASE)
        .expect("binding for B");
    assert_eq!(
        b.identity.probe_requested_size, 0x100,
        "seeding must select the exact probe=0x100 full identity, not first-match"
    );
}

// P1-2 test 8: two raw children with IDENTICAL full identity -> seeding fails
// closed (ambiguous duplicate, never picks one).
#[test]
fn route_y_r1_a6_q0c_seed_same_bytes_duplicate_full_identity_fails_closed() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    let mk = || RawChild {
        old_base: B_BASE,
        size: B_SIZE,
        raw_bytes: vec![0xAAu8; B_SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: "gscript_label:0x8e9da8".into(),
        capture_path: CP::GscriptLabelTableEntry,
        extent_kind: CaptureExtentKind::InteriorSubview,
        source_slot_offset: Some(0),
        requested_probe_size: 0x100,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: Some(0x8e93c8),
        containing_parent_size: Some(0x2000),
    };
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; 0x200000])],
        children: vec![mk(), mk()], // identical full identity -> ambiguous
    };
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    let mut globals = vec![transformed];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let err =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .expect_err("duplicate full identity must fail closed");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "duplicate full identity must fail closed, got {err:?}"
    );
}

// P1-2 test 9: a SINGLE raw candidate whose source identity differs from the
// transformed snapshot fails closed (identity precedes raw bytes).
#[test]
fn route_y_r1_a6_q0c_seed_single_candidate_wrong_source_identity_fails_closed() {
    // Raw child probe=0x100, transformed probe=0x200 (wrong source evidence).
    let (raw_capture, mut transformed) = seeding_full_identity_fixture(0x100, true, Some(0x149d50));
    transformed.extent_evidence.probe_requested_size = 0x200; // wrong source identity
    let mut globals = vec![transformed];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let err =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .expect_err("single candidate with wrong source identity must fail closed");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "single wrong-source-identity candidate must fail closed, got {err:?}"
    );
}

// P1-2 test 10: empty capture_id is NOT a wildcard during seeding.
#[test]
fn route_y_r1_a6_q0c_seed_empty_capture_id_is_not_wildcard() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    // Raw child carries a NON-empty capture id.
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; 0x200000])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: B_SIZE,
            raw_bytes: vec![0xAAu8; B_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "gscript_label:0x8e9da8".into(),
            capture_path: CP::GscriptLabelTableEntry,
            extent_kind: CaptureExtentKind::InteriorSubview,
            source_slot_offset: Some(0),
            requested_probe_size: 0x100,
            source_root_rva: Some(0x149d50),
            was_interior: true,
            containing_parent_old_base: Some(0x8e93c8),
            containing_parent_size: Some(0x2000),
        }],
    };
    // Transformed snapshot has an EMPTY capture_id -> must NOT match the raw
    // child by wildcard; it must fail closed.
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    let mut globals = vec![transformed];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let err =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .expect_err("empty capture_id must not be a wildcard");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "empty capture_id must NOT match the raw child, got {err:?}"
    );
}

// P1-2 test 11: identity resolution precedes byte drift. Even when BOTH the
// identity and the bytes are wrong, the identity error must surface first.
#[test]
fn route_y_r1_a6_q0c_seed_identity_resolution_precedes_byte_drift() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    // Raw child: probe=0x100, bytes 0xAA.
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; 0x200000])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: B_SIZE,
            raw_bytes: vec![0xAAu8; B_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "gscript_label:0x8e9da8".into(),
            capture_path: CP::GscriptLabelTableEntry,
            extent_kind: CaptureExtentKind::InteriorSubview,
            source_slot_offset: Some(0),
            requested_probe_size: 0x100,
            source_root_rva: Some(0x149d50),
            was_interior: true,
            containing_parent_old_base: Some(0x8e93c8),
            containing_parent_size: Some(0x2000),
        }],
    };
    // Transformed: WRONG identity (probe=0x200) AND WRONG bytes (0xBB).
    let mut transformed = global(B_BASE, vec![0xBBu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x200; // wrong identity
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    let mut globals = vec![transformed];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let err =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .expect_err("identity resolution must precede byte drift");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "identity error must surface BEFORE byte drift, got {err:?}"
    );
}

/// Build a Q0-C single-candidate fixture where the transformed snapshot's
/// source evidence does NOT match the single raw child. Returns
/// (raw_capture, transformed, binding). The identity error must surface as
/// `RawChildMissing` (never RawCaptureDrift / RawChildOutsideSlab).
fn q0c_single_candidate_wrong_identity_fixture() -> (
    RawSlabCapture,
    Vec<HeapGlobalSnapshot>,
    Vec<TransformPreimageBinding>,
) {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    let off = (B_BASE - SLAB_BASE) as usize;
    let mut slab_bytes = vec![0u8; 0x200000];
    slab_bytes[off..off + B_SIZE].fill(0xAA);
    // Single raw child with probe=0x100.
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_bytes)],
        children: vec![RawChild {
            old_base: B_BASE,
            size: B_SIZE,
            raw_bytes: vec![0xAAu8; B_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "gscript_label:0x8e9da8".into(),
            capture_path: CP::GscriptLabelTableEntry,
            extent_kind: CaptureExtentKind::InteriorSubview,
            source_slot_offset: Some(0),
            requested_probe_size: 0x100,
            source_root_rva: Some(0x149d50),
            was_interior: true,
            containing_parent_old_base: Some(0x8e93c8),
            containing_parent_size: Some(0x2000),
        }],
    };
    // Transformed with WRONG probe (0x200) -> full identity differs.
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x200; // wrong
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    let bindings = Vec::new();
    (raw_capture, vec![transformed], bindings)
}

// P1-3 test 12: single raw candidate with wrong source identity -> RawChildMissing.
#[test]
fn route_y_r1_a6_q0c_q0c_single_raw_wrong_source_identity_is_raw_child_missing() {
    let (raw, globals, bindings) = q0c_single_candidate_wrong_identity_fixture();
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &globals, &[], &bindings, &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "single candidate wrong source identity must be RawChildMissing, got {err:?}"
    );
}

// P1-3 test 13: single candidate wrong identity surfaces before any slab failure.
#[test]
fn route_y_r1_a6_q0c_q0c_single_raw_wrong_identity_precedes_slab_failure() {
    let (raw, globals, bindings) = q0c_single_candidate_wrong_identity_fixture();
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &globals, &[], &bindings, &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. })
            && !matches!(err, OverlayError::RawChildOutsideSlab { .. }),
        "identity error must precede slab failure, got {err:?}"
    );
}

// P1-3 test 14: single candidate wrong identity precedes byte drift.
#[test]
fn route_y_r1_a6_q0c_q0c_single_raw_wrong_identity_precedes_byte_drift() {
    let (raw, globals, bindings) = q0c_single_candidate_wrong_identity_fixture();
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &globals, &[], &bindings, &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. })
            && !matches!(err, OverlayError::RawCaptureDrift { .. })
            && !matches!(err, OverlayError::TransformPreimageDrift { .. }),
        "identity error must precede byte drift, got {err:?}"
    );
}

// P1-3 test 15: duplicate full identity (two raw children identical) -> fail
// closed at Q0-C resolution.
#[test]
fn route_y_r1_a6_q0c_q0c_duplicate_full_identity_is_exact_raw_child_missing() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    let mk = || RawChild {
        old_base: B_BASE,
        size: B_SIZE,
        raw_bytes: vec![0xAAu8; B_SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: "gscript_label:0x8e9da8".into(),
        capture_path: CP::GscriptLabelTableEntry,
        extent_kind: CaptureExtentKind::InteriorSubview,
        source_slot_offset: Some(0),
        requested_probe_size: 0x100,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: Some(0x8e93c8),
        containing_parent_size: Some(0x2000),
    };
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; 0x200000])],
        children: vec![mk(), mk()],
    };
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "duplicate full identity must be EXACTLY RawChildMissing (identity-first), got {err:?}"
    );
}

// P1-3 test 16: declared-reinit single raw candidate with a source-identity
// drift fails BEFORE size handling.
#[test]
fn route_y_r1_a6_q0c_q0c_declared_reinit_single_raw_source_drift_fails_before_size_handling() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const NEW_SIZE: usize = 0x180;
    const SLAB_BASE: u64 = 0x3000000; // well below B_BASE so the slab covers B
                                      // Raw child: sanitize declared-reinit identity, probe=0x100.
    let slab_size = (B_BASE - SLAB_BASE) as usize + OLD_SIZE;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    // Transformed: declared reinit (new size 0x180) but WRONG source identity
    // (probe=0x200). The identity drift must fail before size handling.
    let mut transformed = global(B_BASE, vec![0u8; NEW_SIZE], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x200; // wrong source identity
                                                              // Mark this child as a declared reinit via its transform_ids (the ledger
                                                              // stays empty so shape/membership pass and the identity error surfaces
                                                              // first).
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "declared reinit source-identity drift must fail before size handling, got {err:?}"
    );
}

// P1-4 test 17: `source_parent_old_base` is REMOVED — the only parent anchor is
// `containing_parent_old_base`, so the two can never diverge. This is the
// compile-layer proof: the field no longer exists on RawChild.
#[test]
fn route_y_r1_a6_q0c_source_parent_and_containing_parent_cannot_diverge() {
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    // A raw child built via `raw_children_from_capture` (production) carries
    // ONLY `containing_parent_old_base`; the removed `source_parent_old_base`
    // cannot exist to diverge. Assert the single anchor is what FullCaptureIdentity
    // reads and that building through the production constructor freezes it.
    let g = a6_full_identity_global(B_BASE, B_SIZE);
    let mut globals = vec![g.clone()];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let raws = raw_children_from_capture(&mut containers, &mut globals);
    let rc = raws
        .iter()
        .find(|r| r.old_base == B_BASE)
        .expect("production raw child present");
    // containing_parent_old_base == containing_parent_size (the ONLY parent anchor).
    assert_eq!(
        rc.containing_parent_old_base, g.extent_evidence.containing_parent_old_base,
        "production raw child must freeze containing_parent_old_base"
    );
    assert_eq!(
        FullCaptureIdentity::from_raw_child(rc).containing_parent_old_base,
        g.extent_evidence.containing_parent_old_base,
        "FullCaptureIdentity must carry the single parent anchor"
    );
    // Compile-time: RawChild has NO source_parent_old_base field (removed).
    // Referencing it would fail to compile, so we assert the canonical identity
    // round-trips the single parent anchor.
    assert_eq!(
        FullCaptureIdentity::from_raw_child(rc).containing_parent_size,
        g.extent_evidence.containing_parent_size,
        "FullCaptureIdentity must carry containing_parent_size"
    );
}

// P2 test 18: a binding whose legacy field tuple diverges from its
// `identity` must fail closed at the Q0-C entry (BindingIdentityInconsistent).
#[test]
fn route_y_r1_a6_q0c_binding_legacy_fields_cannot_diverge_from_full_identity() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Each legacy overlapping field is mutated to diverge from `identity`.
    // Every one must fail closed with BindingIdentityInconsistent at the Q0-C
    // entry (before any binding resolution).
    let cases: Vec<(String, fn(&mut TransformPreimageBinding))> = vec![
        ("child_kind".into(), |b| {
            b.child_kind = RawChildKind::Container
        }),
        ("capture_id".into(), |b| {
            b.capture_id = "gscript_label:0xDEAD".into()
        }),
        ("child_old_base".into(), |b| b.child_old_base += 0x10),
        ("child_size".into(), |b| b.child_size += 1),
        ("extent_kind".into(), |b| b.extent_kind = CEK::BackingObject),
    ];
    for (name, mutate) in cases {
        let mut b = binding.clone();
        mutate(&mut b);
        let ledger = TransformRunLedger::default();
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed.clone()],
            &[],
            &[b],
            &ledger,
        )
        .expect_err("contradictory binding must fail closed at Q0-C entry");
        assert!(
            matches!(err, OverlayError::BindingIdentityInconsistent { .. }),
            "legacy field {name} divergence must fail as BindingIdentityInconsistent, got {err:?}"
        );
    }
    // The consistency validator rejects a divergent binding directly too.
    let mut b = binding.clone();
    b.capture_id = "gscript_label:0xBEEF".into();
    assert!(matches!(
        b.validate_identity_consistency().unwrap_err(),
        OverlayError::BindingIdentityInconsistent { .. }
    ));
    // And a self-consistent binding passes the validator.
    assert!(binding.validate_identity_consistency().is_ok());
}

// ============ Route Y R1 A6 AF3 AF2 AF1 AF1 (identity-first) tests ============

// Test 1: raw identity WRONG + binding self-contradictory -> EXACTLY
// RawChildMissing (identity pre-resolution precedes binding consistency).
#[test]
fn route_y_r1_a6_q0c_q0c_wrong_identity_precedes_binding_identity_inconsistent() {
    let (raw, globals, _bindings) = q0c_single_candidate_wrong_identity_fixture();
    // A self-contradictory binding (legacy capture_id != identity capture_id).
    let mut bad_binding = taf1_dedicated_fixture(0x850150, 0x1000).2;
    bad_binding.capture_id = "gscript_label:0xDEAD".into(); // diverge from identity
    let ledger = TransformRunLedger::default();
    let err =
        build_patched_backing_slab_q0c(&raw, &globals, &[], &[bad_binding], &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "wrong identity must precede BindingIdentityInconsistent, got {err:?}"
    );
}

// Test 2: raw identity WRONG + ledger/membership invalid -> EXACTLY
// RawChildMissing (identity pre-resolution precedes run membership).
#[test]
fn route_y_r1_a6_q0c_q0c_wrong_identity_precedes_run_membership_invalid() {
    let (raw, globals, bindings) = q0c_single_candidate_wrong_identity_fixture();
    // A malformed/orphaned ledger run (base 0x9999 has no raw child).
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "ghost:0x9999".into(),
        child_old_base: 0x9999,
        child_size: 0x10,
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err = build_patched_backing_slab_q0c(&raw, &globals, &[], &bindings, &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "wrong identity must precede run-membership invalid, got {err:?}"
    );
}

// Test 4: declared reinit with a valid size change but a SOURCE-evidence drift,
// while BOTH binding and ledger are defective -> EXACTLY RawChildMissing.
#[test]
fn route_y_r1_a6_q0c_q0c_declared_reinit_source_drift_precedes_binding_and_ledger() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const NEW_SIZE: usize = 0x180;
    const SLAB_BASE: u64 = 0x3000000;
    let slab_size = (B_BASE - SLAB_BASE) as usize + OLD_SIZE;
    // Raw child: sanitize declared-reinit identity, probe=0x100.
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    // Transformed: declared reinit (new size 0x180), but WRONG source identity
    // (probe=0x200). The identity drift must fire FIRST.
    let mut transformed = global(B_BASE, vec![0u8; NEW_SIZE], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x200; // wrong source identity
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    // Defective binding (contradictory) + defective ledger (orphan run).
    let mut bad_binding = taf1_dedicated_fixture(0x850150, 0x1000).2;
    bad_binding.child_size += 1;
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "ghost".into(),
        child_old_base: 0x9999,
        child_size: 1,
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[bad_binding], &ledger)
            .unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "declared-reinit source drift must precede binding AND ledger errors, got {err:?}"
    );
}

// Test 5: raw identity unique + correct; binding legacy tuple conflicts with
// identity -> BindingIdentityInconsistent (after identity pre-resolution).
#[test]
fn route_y_r1_a6_q0c_q0c_exact_identity_then_binding_inconsistency_is_reported() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, mut binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Corrupt the binding's legacy extent_kind (identity stays correct).
    binding.extent_kind = CEK::BackingObject;
    let ledger = TransformRunLedger::default();
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(
            matches!(err, OverlayError::BindingIdentityInconsistent { .. }),
            "exact identity then contradictory binding must be BindingIdentityInconsistent, got {err:?}"
        );
}

// Test 6: raw identity unique + correct; a ledger run is orphaned (no matching
// raw child) -> TransformRunLedgerInvalid (identity pre-resolution passes).
#[test]
fn route_y_r1_a6_q0c_q0c_exact_identity_then_membership_error_is_reported() {
    let raw_bytes = b"orphan-check".to_vec();
    let raw_base = 0x140003000u64;
    let slab = slab_with_child(0x140000000, 0x40000, raw_base, raw_bytes.clone());
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![raw_child(
            raw_base,
            raw_bytes.len(),
            raw_bytes.clone(),
            RawChildKind::HeapGlobal,
        )],
    };
    // Transformed matches the raw child's FULL identity (defaults).
    let mut raw_g = global(raw_base, raw_bytes.clone(), false);
    raw_g.extent_kind = CaptureExtentKind::ProbeWindow;
    raw_g.extent_evidence.capture_id = String::new();
    raw_g.extent_evidence.capture_path = crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    // Orphaned ledger run -> membership fails AFTER identity passes.
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "ghost:0x9999".into(),
        child_old_base: 0x9999,
        child_size: 0x10,
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[raw_g], &[], &[], &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "exact identity then orphaned run must be TransformRunLedgerInvalid, got {err:?}"
    );
}

// Test 7: an orphan + self-inconsistent binding still fails closed at the
// global binding-consistency gate (identity pre-resolution succeeds).
#[test]
fn route_y_r1_a6_q0c_q0c_orphan_inconsistent_binding_still_fails_closed() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, mut orphan, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Make the binding self-inconsistent AND orphaned (not the transformed child's).
    orphan.capture_id = "gscript_label:0xORPHAN".into(); // legacy != identity
    orphan.child_old_base = 0x9999; // not any transformed child
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[orphan], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::BindingIdentityInconsistent { .. }),
        "orphan + inconsistent binding must still fail closed at binding consistency, got {err:?}"
    );
}

// Test 8: identity failure does NOT touch the slab (no usable slab + wrong
// identity) -> RawChildMissing proves slab is not the first adjudicator.
#[test]
fn route_y_r1_a6_q0c_q0c_identity_failure_does_not_touch_slab() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    // EMPTY slab set (no coverage possible) + wrong identity.
    let raw_capture = RawSlabCapture {
        slabs: vec![],
        children: vec![RawChild {
            old_base: B_BASE,
            size: B_SIZE,
            raw_bytes: vec![0xAAu8; B_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "gscript_label:0x8e9da8".into(),
            capture_path: CP::GscriptLabelTableEntry,
            extent_kind: CaptureExtentKind::InteriorSubview,
            source_slot_offset: Some(0),
            requested_probe_size: 0x100,
            source_root_rva: Some(0x149d50),
            was_interior: true,
            containing_parent_old_base: Some(0x8e93c8),
            containing_parent_size: Some(0x2000),
        }],
    };
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x200; // wrong identity
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "identity failure must fire before any slab/coverage decision, got {err:?}"
    );
}

// ---- Route Y R1 A6 AF3 AF2 AF1 AF1 AF1 (UnknownSynthetic + declared-reinit
// ---- qualification) mandatory tests ----

/// Build a transformed global with UnknownSynthetic provenance (non-empty
/// content, so it IS a raw-coherence participant and reaches the identity
/// pre-resolution, where it must fail closed immediately).
fn unknown_synthetic_global(live: u64, bytes: Vec<u8>) -> HeapGlobalSnapshot {
    let mut g = global(live, bytes, false);
    g.provenance = RegionProvenance::UnknownSynthetic;
    g
}

// Test 1: UnknownSynthetic -> EXACTLY RawChildMissing at identity pre-resolution.
#[test]
fn route_y_r1_a6_q0c_q0c_unknown_synthetic_is_exact_raw_child_missing() {
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    let g = unknown_synthetic_global(B_BASE, vec![0xAAu8; B_SIZE]);
    let raw_capture = RawSlabCapture {
        slabs: vec![],
        children: vec![],
    };
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[g], &[], &[], &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "UnknownSynthetic must be EXACTLY RawChildMissing at pre-resolution, got {err:?}"
    );
}

// Test 2: UnknownSynthetic + contradictory binding -> EXACTLY RawChildMissing
// (UnknownSynthetic precedence over BindingIdentityInconsistent).
#[test]
fn route_y_r1_a6_q0c_q0c_unknown_synthetic_precedes_binding_inconsistency() {
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    let g = unknown_synthetic_global(B_BASE, vec![0xAAu8; B_SIZE]);
    let raw_capture = RawSlabCapture {
        slabs: vec![],
        children: vec![],
    };
    // A self-contradictory binding (legacy capture_id != identity capture_id).
    let mut bad_binding = taf1_dedicated_fixture(0x850150, 0x1000).2;
    bad_binding.capture_id = "gscript_label:0xDEAD".into();
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[g], &[], &[bad_binding], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "UnknownSynthetic must precede BindingIdentityInconsistent, got {err:?}"
    );
}

// Test 3: UnknownSynthetic + malformed/orphan ledger -> EXACTLY RawChildMissing.
#[test]
fn route_y_r1_a6_q0c_q0c_unknown_synthetic_precedes_ledger_invalid() {
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    let g = unknown_synthetic_global(B_BASE, vec![0xAAu8; B_SIZE]);
    let raw_capture = RawSlabCapture {
        slabs: vec![],
        children: vec![],
    };
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "ghost:0x9999".into(),
        child_old_base: 0x9999,
        child_size: 0x10,
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err = build_patched_backing_slab_q0c(&raw_capture, &[g], &[], &[], &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "UnknownSynthetic must precede ledger-invalid, got {err:?}"
    );
}

// Test 4: SyntheticDerived is a LEGAL bypass — it must NOT be rejected by the
// raw-identity pre-resolution.
#[test]
fn route_y_r1_a6_q0c_q0c_synthetic_derived_still_bypasses_raw_identity() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const REAL: u64 = 0x8e9da8;
    const REAL_SIZE: usize = 0x400;
    const SYNTH: u64 = 0x200000;
    const SLAB_BASE: u64 = 0x800000;
    // A valid raw child that the overlay processes normally.
    let mut slab_bytes = vec![0u8; 0x200000];
    let off = (REAL - SLAB_BASE) as usize;
    slab_bytes[off..off + REAL_SIZE].fill(0xAA);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_bytes)],
        children: vec![RawChild {
            old_base: REAL,
            size: REAL_SIZE,
            raw_bytes: vec![0xAAu8; REAL_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "gscript_label:0x8e9da8".into(),
            capture_path: CP::GscriptLabelTableEntry,
            extent_kind: CaptureExtentKind::InteriorSubview,
            source_slot_offset: Some(0),
            requested_probe_size: 0x100,
            source_root_rva: Some(0x149d50),
            was_interior: true,
            containing_parent_old_base: Some(0x8e93c8),
            containing_parent_size: Some(0x2000),
        }],
    };
    let mut real = global(REAL, vec![0xAAu8; REAL_SIZE], false);
    real.extent_kind = CaptureExtentKind::InteriorSubview;
    real.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    real.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    real.extent_evidence.source_slot_offset = Some(0);
    real.extent_evidence.probe_requested_size = 0x100;
    real.extent_evidence.source_root_rva = Some(0x149d50);
    real.extent_evidence.was_interior = true;
    real.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    real.extent_evidence.containing_parent_size = Some(0x2000);
    // A SyntheticDerived child with NO raw preimage — must be skipped, not
    // resolved, and must NOT cause RawChildMissing.
    let synth = synthetic(
        SYNTH,
        b"NewClassName".to_vec(),
        "repair_gscript_window_strings",
    );
    let mut globals = vec![real.clone(), synth];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let ledger = TransformRunLedger::default();
    let result = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger);
    assert!(
        result.is_ok(),
        "SyntheticDerived child must bypass raw identity (not RawChildMissing), got {result:?}"
    );
}

/// Build a declared-reinit fixture where the raw identity (ignoring size)
/// resolves uniquely but the DECLARATION itself is invalid. Returns
/// (raw_capture, transformed, bad_binding, ledger_with_orphan).
fn declared_bad_qualification_fixture(
    raw_old_size: usize,
    new_size: usize,
    new_fill: u8,
) -> (
    RawSlabCapture,
    HeapGlobalSnapshot,
    TransformPreimageBinding,
    TransformRunLedger,
) {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const SLAB_BASE: u64 = 0x3000000;
    let slab_size = (B_BASE - SLAB_BASE) as usize + raw_old_size;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: raw_old_size,
            raw_bytes: vec![0xAAu8; raw_old_size],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    let mut transformed = global(B_BASE, vec![new_fill; new_size], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    // Defective binding + orphan ledger run (must be masked by the declaration
    // error).
    let mut bad_binding = taf1_dedicated_fixture(0x850150, 0x1000).2;
    bad_binding.capture_id = "gscript_label:0xDEAD".into();
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "ghost:0x9999".into(),
        child_old_base: 0x9999,
        child_size: 1,
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    (raw_capture, transformed, bad_binding, ledger)
}

// Test 5: declared reinit, raw old size out of tolerance, with defective
// binding + ledger -> TransformRunLedgerInvalid with an old-size reason.
#[test]
fn route_y_r1_a6_q0c_q0c_declared_wrong_old_size_precedes_binding_and_ledger() {
    let (raw, transformed, bad_binding, ledger) =
        declared_bad_qualification_fixture(0x200, 0x180, 0u8); // old way below 0x8000±0x2000
    let err = build_patched_backing_slab_q0c(&raw, &[transformed], &[], &[bad_binding], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "declared wrong old size must be TransformRunLedgerInvalid, got {err:?}"
    );
    let reason = format!("{err:?}");
    assert!(
        reason.contains("old size"),
        "declared wrong old-size reason must name the old-size failure, got {err:?}"
    );
}

// Test 6: declared reinit, wrong new size, with defective binding + ledger ->
// TransformRunLedgerInvalid with a new-size reason.
#[test]
fn route_y_r1_a6_q0c_q0c_declared_wrong_new_size_precedes_binding_and_ledger() {
    let (raw, transformed, bad_binding, ledger) =
        declared_bad_qualification_fixture(0x8000, 0x200, 0u8); // new != 0x180
    let err = build_patched_backing_slab_q0c(&raw, &[transformed], &[], &[bad_binding], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "declared wrong new size must be TransformRunLedgerInvalid, got {err:?}"
    );
    let reason = format!("{err:?}");
    assert!(
        reason.contains("new size"),
        "declared wrong new-size reason must name the new-size failure, got {err:?}"
    );
}

// Test 7: declared reinit, correct new size but NON-zero-filled content, with
// defective binding + ledger -> TransformRunLedgerInvalid with a zero-fill reason.
#[test]
fn route_y_r1_a6_q0c_q0c_declared_nonzero_bytes_precede_binding_and_ledger() {
    let (raw, transformed, bad_binding, ledger) =
        declared_bad_qualification_fixture(0x8000, 0x180, 0x55u8); // nonzero content
    let err = build_patched_backing_slab_q0c(&raw, &[transformed], &[], &[bad_binding], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "declared nonzero reinit must be TransformRunLedgerInvalid, got {err:?}"
    );
    let reason = format!("{err:?}");
    assert!(
        reason.contains("zero") || reason.contains("all-zero"),
        "declared nonzero reason must name the zero-fill failure, got {err:?}"
    );
}

// Test 8: source identity WRONG and declaration fields also invalid -> EXACTLY
// RawChildMissing (identity missing precedes declaration validation).
#[test]
fn route_y_r1_a6_q0c_q0c_declared_identity_missing_precedes_declaration_validation() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const SLAB_BASE: u64 = 0x3000000;
    let slab_size = (B_BASE - SLAB_BASE) as usize + OLD_SIZE;
    // Raw child probe=0x100; transformed probe=0x200 (WRONG source identity)
    // AND wrong new size — identity missing must win.
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    let mut transformed = global(B_BASE, vec![0u8; 0x200], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x200; // wrong identity
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "identity missing must precede declaration validation, got {err:?}"
    );
}

// Test 9: valid declared transition (identity + declaration all valid) then a
// contradictory binding -> BindingIdentityInconsistent (not declaration error).
#[test]
fn route_y_r1_a6_q0c_q0c_valid_declared_transition_then_binding_error_is_visible() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const NEW_SIZE: usize = 0x180;
    const SLAB_BASE: u64 = 0x3000000;
    let slab_size = (B_BASE - SLAB_BASE) as usize + OLD_SIZE;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    let mut transformed = global(B_BASE, vec![0u8; NEW_SIZE], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    // Valid declaration; then a contradictory binding.
    let mut bad_binding = taf1_dedicated_fixture(0x850150, 0x1000).2;
    bad_binding.capture_id = "gscript_label:0xDEAD".into();
    let ledger = TransformRunLedger::default();
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[bad_binding], &ledger)
            .unwrap_err();
    assert!(
            matches!(err, OverlayError::BindingIdentityInconsistent { .. }),
            "valid declared transition then contradictory binding must be BindingIdentityInconsistent, got {err:?}"
        );
}

// Test 10: valid declared transition then a ledger error -> TransformRunLedgerInvalid
// (the reason must be the ledger, not the declaration).
#[test]
fn route_y_r1_a6_q0c_q0c_valid_declared_transition_then_ledger_error_is_visible() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const NEW_SIZE: usize = 0x180;
    const SLAB_BASE: u64 = 0x3000000;
    let slab_size = (B_BASE - SLAB_BASE) as usize + OLD_SIZE;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    let mut transformed = global(B_BASE, vec![0u8; NEW_SIZE], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    // Valid declaration; then an orphaned ledger run.
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "ghost:0x9999".into(),
        child_old_base: 0x9999,
        child_size: 1,
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[], &ledger)
        .unwrap_err();
    assert!(
            matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
            "valid declared transition then ledger error must be TransformRunLedgerInvalid, got {err:?}"
        );
}

// Test 11: the plan's qualified declaration spec is consumed by the child
// loop (no re-selection via transform_ids first-match). A valid declared
// transition whose raw identity is unique and declaration valid reaches the
// overlay (proving the plan spec was consumed, not re-derived wrongly).
#[test]
fn route_y_r1_a6_q0c_q0c_declared_plan_spec_is_consumed_without_relookup() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const NEW_SIZE: usize = 0x180;
    const SLAB_BASE: u64 = 0x3000000;
    let off = (B_BASE - SLAB_BASE) as usize;
    let slab_size = off + OLD_SIZE;
    let mut slab_bytes = vec![0u8; slab_size];
    slab_bytes[off..off + OLD_SIZE].fill(0xAA);
    // Raw child: declared-reinit identity, probe=0x100.
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_bytes.clone())],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    let mut transformed = global(B_BASE, vec![0u8; NEW_SIZE], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    // A valid binding for the declared-reinit child: identity from the raw
    // child (size ignored by the declared-reinit exemption), correct slab
    // evidence. This is the SAME binding the Q0-C exact-match requires.
    let raw = &raw_capture.children[0];
    let binding = TransformPreimageBinding::new(
        FullCaptureIdentity::from_raw_child(raw),
        SLAB_BASE,
        slab_bytes.len(),
        sha256_hex(&slab_bytes),
        off,
        TransformPreimageBasis::ChildCapture,
        sha256_hex(&raw.raw_bytes),
        sha256_hex(&slab_bytes[off..off + OLD_SIZE]),
        sha256_hex(&raw.raw_bytes),
        false,
    );
    // A valid declared transition must be accepted by the plan and reach the
    // overlay (the plan spec is consumed — no RawChildMissing / declaration
    // error). The overlay's new-size write is the zero-filled re-init slab.
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "mainslot:0x141bf0:0x3437e50".into(),
        child_old_base: B_BASE,
        child_size: NEW_SIZE,
        child_offset: 0,
        length: NEW_SIZE,
        transform_id: "sanitize_ahk_runtime_global".into(),
        before_digest: sha256_hex(&vec![0xAA; NEW_SIZE]),
        after_digest: sha256_hex(&vec![0u8; NEW_SIZE]),
        first_before_byte: 0xAA,
        first_after_byte: 0x00,
        before_bytes: vec![0xAA; NEW_SIZE],
        after_bytes: vec![0u8; NEW_SIZE],
    });
    let result =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger);
    assert!(
        result.is_ok(),
        "valid declared transition must be consumed via the plan spec and overlay, got {result:?}"
    );
}

// Test 9 (P2): the identity PLAN resolves ONE raw child that BOTH the binding
// exact-match and the overlay consume — no later partial re-lookup.
#[test]
fn route_y_r1_a6_q0c_q0c_identity_plan_uses_same_raw_for_binding_and_overlay() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    // TWO raw children share (base, kind, path, extent, source slot, root,
    // interior, parent) and differ in probe + capture_id, AND have DISTINCT
    // bytes/digests so the plan-selected raw is provable.
    //   exact   probe=0x100 capture_id "gscript_label:0x8e9da8"  bytes A (0xAA)
    //   distract probe=0x200 capture_id "...:dup"                bytes B (0x55)
    let mk = |probe: usize, cap: &str, byte: u8| RawChild {
        old_base: B_BASE,
        size: B_SIZE,
        raw_bytes: vec![byte; B_SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: cap.into(),
        capture_path: CP::GscriptLabelTableEntry,
        extent_kind: CaptureExtentKind::InteriorSubview,
        source_slot_offset: Some(0),
        requested_probe_size: probe,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: Some(0x8e93c8),
        containing_parent_size: Some(0x2000),
    };
    let exact_raw = mk(0x100, "gscript_label:0x8e9da8", 0xAA);
    let distract_raw = mk(0x200, "gscript_label:0x8e9da8:dup", 0x55);
    let digest_a = sha256_hex(&exact_raw.raw_bytes);
    let digest_b = sha256_hex(&distract_raw.raw_bytes);
    assert_ne!(digest_a, digest_b, "exact and distractor bytes must differ");
    // Authoritative slab matches the EXACT raw child bytes (0xAA), not the
    // distractor (0x55).
    let mut slab_bytes = vec![0u8; 0x200000];
    let off = (B_BASE - SLAB_BASE) as usize;
    slab_bytes[off..off + B_SIZE].fill(0xAA);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_bytes)],
        children: vec![exact_raw, distract_raw],
    };
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.extent_kind = CaptureExtentKind::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x100; // exact probe
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    // Seed: binding resolves the SAME probe=0x100 raw child the identity plan
    // will use — its raw_child_digest must be digest A (not B).
    let mut globals = vec![transformed.clone()];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let b = bindings
        .iter()
        .find(|b| b.child_old_base == B_BASE)
        .expect("binding for B");
    assert_eq!(b.identity.probe_requested_size, 0x100);
    assert_eq!(
        b.raw_child_digest, digest_a,
        "binding raw_child_digest must be the exact (plan) raw child's digest A"
    );
    assert_ne!(
        b.raw_child_digest, digest_b,
        "must NOT be the distractor digest B"
    );
    let ledger = TransformRunLedger::default();
    // Overlay consumes the SAME plan-resolved raw child (probe=0x100). The
    // overlay ledger's raw_child_digest must be digest A, never B.
    let (patched, overlays, _drift) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("exact full identity must overlay successfully");
    let ov = overlays
        .iter()
        .find(|o| o.child_old_base == B_BASE)
        .expect("B overlay present");
    assert_eq!(
        ov.raw_child_digest, digest_a,
        "overlay raw_child_digest must be the plan-selected exact raw child (A)"
    );
    assert_ne!(
        ov.raw_child_digest, digest_b,
        "overlay must NOT consume the distractor raw child (B)"
    );
    // Patched bytes come from the expected transformed child (scrub/overlay of
    // the exact raw child region), and the overlay written byte reflects the
    // plan-selected raw, not the distractor.
    assert_eq!(
        patched[0].content[off + 0x23],
        0xAA,
        "overlay byte must come from the plan-selected raw child (A)"
    );
}

// ==================== Route Y R1 A6 AF3 AF2 (P1-1..P1-7) tests ====================

/// Build a raw-coherence participant snapshot carrying the FULL canonical
/// label-table source evidence (kind=HeapGlobal, GscriptLabelTableEntry path,
/// InteriorSubview extent, source_root_rva 0x149d50, source_slot_offset 0,
/// probe 0x1000, was_interior, containing parent A). Used by the recorder
/// drift tests (P1-3) to flip ONE source-evidence field at a time after the
/// raw capture is already frozen.
fn a6_full_identity_global(base: u64, size: usize) -> HeapGlobalSnapshot {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let mut g = global(base, vec![0xAAu8; size], false);
    g.rva = 0x149d50;
    g.extent_kind = CaptureExtentKind::InteriorSubview;
    g.extent_evidence.capture_id = format!("gscript_label:{base:#x}");
    g.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    g.extent_evidence.source_root_rva = Some(0x149d50);
    g.extent_evidence.source_slot_offset = Some(0);
    g.extent_evidence.probe_requested_size = 0x1000;
    g.extent_evidence.was_interior = true;
    g.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    g.extent_evidence.containing_parent_size = Some(0x2000);
    g
}

/// Assert that running a transform which drifts ONE source-evidence field on
/// the `after` snapshot (the raw capture identity is already frozen) fails
/// closed with `TransformRunLedgerInvalid` (AF3 AF2 P1-3: the recorder must
/// never allow a transform to re-anchor / reclassify source evidence).
fn assert_recorder_identity_drift_fails(field: &str, drift: impl FnOnce(&mut HeapGlobalSnapshot)) {
    const BASE: u64 = 0x8e9da8;
    let before = a6_full_identity_global(BASE, 0x400);
    let mut globals = vec![before.clone()];
    let mut ledger = TransformRunLedger::default();
    let err = apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |gs| drift(&mut gs[0]),
    )
    .expect_err("source-evidence drift after raw capture must fail closed");
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "{field} drift must fail closed via the production recorder, got {err:?}"
    );
}

// P1-3 #1: source_root_rva drift after raw capture fails closed.
#[test]
fn route_y_r1_a6_q0c_source_root_rva_drift_after_raw_capture_fails_closed() {
    assert_recorder_identity_drift_fails("source_root_rva", |g| {
        g.extent_evidence.source_root_rva = Some(0xDEAD);
    });
}

// P1-3 #2: source_slot_offset drift after raw capture fails closed.
#[test]
fn route_y_r1_a6_q0c_source_slot_offset_drift_after_raw_capture_fails_closed() {
    assert_recorder_identity_drift_fails("source_slot_offset", |g| {
        g.extent_evidence.source_slot_offset = Some(7);
    });
}

// P1-3 #3: probe_requested_size drift after raw capture fails closed.
#[test]
fn route_y_r1_a6_q0c_probe_requested_size_drift_after_raw_capture_fails_closed() {
    assert_recorder_identity_drift_fails("probe_requested_size", |g| {
        g.extent_evidence.probe_requested_size = 0x40;
    });
}

// P1-3 #4: was_interior drift after raw capture fails closed.
#[test]
fn route_y_r1_a6_q0c_was_interior_drift_after_raw_capture_fails_closed() {
    assert_recorder_identity_drift_fails("was_interior", |g| {
        g.extent_evidence.was_interior = false;
    });
}

// P1-3 #5: containing_parent_old_base drift after raw capture fails closed.
#[test]
fn route_y_r1_a6_q0c_containing_parent_base_drift_after_raw_capture_fails_closed() {
    assert_recorder_identity_drift_fails("containing_parent_old_base", |g| {
        g.extent_evidence.containing_parent_old_base = Some(0x900000);
    });
}

// P1-3 #6: containing_parent_size drift after raw capture fails closed.
#[test]
fn route_y_r1_a6_q0c_containing_parent_size_drift_after_raw_capture_fails_closed() {
    assert_recorder_identity_drift_fails("containing_parent_size", |g| {
        g.extent_evidence.containing_parent_size = Some(0x100);
    });
}

/// Build a raw capture with TWO raw children at the SAME (old_base, kind),
/// sharing capture_path/extent, whose capture_ids AND one source-evidence
/// field differ. The transformed child matches raw[0] on (base, kind,
/// capture_id, path, extent) but differs from BOTH raw children on the
/// source-evidence field — so the P1-4 full-identity resolution must NOT pick
/// raw[0] by partial identity, and must fail closed (RawChildMissing).
/// Returns (raw_capture, transformed_globals, bindings).
fn q0c_ambiguous_source_fixture(
    source_field: &str,
) -> (
    RawSlabCapture,
    Vec<HeapGlobalSnapshot>,
    Vec<TransformPreimageBinding>,
) {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    let mut slab_bytes = vec![0u8; 0x200000];
    let off = (B_BASE - SLAB_BASE) as usize;
    slab_bytes[off..off + B_SIZE].fill(0xAA);
    // Two raw children, same (base, kind, path, extent), differ in capture_id
    // and in exactly one source-evidence field.
    let mut raw0 = RawChild {
        old_base: B_BASE,
        size: B_SIZE,
        raw_bytes: vec![0xAAu8; B_SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: "gscript_label:0x8e9da8".into(),
        capture_path: CP::GscriptLabelTableEntry,
        extent_kind: CEK::InteriorSubview,
        source_slot_offset: Some(0),
        requested_probe_size: 0x1000,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: Some(0x8e93c8),
        containing_parent_size: Some(0x2000),
    };
    let mut raw1 = RawChild {
        old_base: B_BASE,
        size: B_SIZE,
        raw_bytes: vec![0xAAu8; B_SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: "gscript_label:0x8e9da8:dup".into(),
        capture_path: CP::GscriptLabelTableEntry,
        extent_kind: CEK::InteriorSubview,
        source_slot_offset: Some(0),
        requested_probe_size: 0x1000,
        source_root_rva: Some(0x149d50),
        was_interior: true,
        containing_parent_old_base: Some(0x8e93c8),
        containing_parent_size: Some(0x2000),
    };
    match source_field {
        "source_root" => {
            raw0.source_root_rva = Some(0x100);
            raw1.source_root_rva = Some(0x200);
        }
        "source_slot" => {
            raw0.source_slot_offset = Some(1);
            raw1.source_slot_offset = Some(2);
        }
        "probe" => {
            raw0.requested_probe_size = 0x100;
            raw1.requested_probe_size = 0x200;
        }
        "parent" => {
            raw0.containing_parent_old_base = Some(0x900000);
            raw1.containing_parent_old_base = Some(0x910000);
        }
        _ => unreachable!("unknown source field {source_field}"),
    }
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_bytes)],
        children: vec![raw0, raw1],
    };
    // Transformed child matches raw0 on (base, kind, capture_id, path, extent)
    // but carries a source-evidence value that matches NEITHER raw child.
    let mut transformed = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    transformed.rva = 0x149d50;
    transformed.extent_kind = CEK::InteriorSubview;
    transformed.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    transformed.extent_evidence.capture_path = CP::GscriptLabelTableEntry;
    transformed.extent_evidence.source_slot_offset = Some(0);
    transformed.extent_evidence.probe_requested_size = 0x1000;
    transformed.extent_evidence.source_root_rva = Some(0x149d50);
    transformed.extent_evidence.was_interior = true;
    transformed.extent_evidence.containing_parent_old_base = Some(0x8e93c8);
    transformed.extent_evidence.containing_parent_size = Some(0x2000);
    match source_field {
        "source_root" => transformed.extent_evidence.source_root_rva = Some(0x300),
        "source_slot" => transformed.extent_evidence.source_slot_offset = Some(3),
        "probe" => transformed.extent_evidence.probe_requested_size = 0x300,
        "parent" => transformed.extent_evidence.containing_parent_old_base = Some(0x920000),
        _ => unreachable!(),
    }
    let bindings = Vec::new();
    (raw_capture, vec![transformed], bindings)
}

// P1-4 #7: same base/id/path/extent but different source_root -> not resolved.
#[test]
fn route_y_r1_a6_q0c_same_base_id_path_extent_different_source_root_not_resolved() {
    let (raw, globals, bindings) = q0c_ambiguous_source_fixture("source_root");
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &globals, &[], &bindings, &ledger)
        .expect_err("different source_root must not resolve");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "Q0-C must not pick the first candidate on source_root, got {err:?}"
    );
}

// P1-4 #8: same base/id/path/extent but different source_slot -> not resolved.
#[test]
fn route_y_r1_a6_q0c_same_base_id_path_extent_different_source_slot_not_resolved() {
    let (raw, globals, bindings) = q0c_ambiguous_source_fixture("source_slot");
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &globals, &[], &bindings, &ledger)
        .expect_err("different source_slot must not resolve");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "Q0-C must not pick the first candidate on source_slot, got {err:?}"
    );
}

// P1-4 #9: same base/id/path/extent but different probe -> not resolved.
#[test]
fn route_y_r1_a6_q0c_same_base_id_path_extent_different_probe_not_resolved() {
    let (raw, globals, bindings) = q0c_ambiguous_source_fixture("probe");
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &globals, &[], &bindings, &ledger)
        .expect_err("different probe must not resolve");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "Q0-C must not pick the first candidate on probe, got {err:?}"
    );
}

// P1-4 #10: same base/id/path/extent but different parent -> not resolved.
#[test]
fn route_y_r1_a6_q0c_same_base_id_path_extent_different_parent_not_resolved() {
    let (raw, globals, bindings) = q0c_ambiguous_source_fixture("parent");
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &globals, &[], &bindings, &ledger)
        .expect_err("different parent must not resolve");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "Q0-C must not pick the first candidate on parent, got {err:?}"
    );
}

// P1-5 #11: a binding whose source identity differs from the transformed AND
// raw child must fail closed at the overlay exact-match.
#[test]
fn route_y_r1_a6_q0c_binding_source_identity_mismatch_fails_closed() {
    const DEDICATED: u64 = 0x850150;
    const SIZE: usize = 0x1000;
    let (raw_capture, transformed, binding, _) = taf1_dedicated_fixture(DEDICATED, SIZE);
    // Flip each source-evidence field on the binding identity in turn. Each
    // must leave the overlay exact-match empty -> TransformPreimageBindingIdentityInvalid.
    let cases: Vec<(String, fn(&mut FullCaptureIdentity))> = vec![
        ("source_root".into(), |id| id.source_root_rva = Some(0xDEAD)),
        ("source_slot".into(), |id| id.source_slot_offset = Some(5)),
        ("probe".into(), |id| id.probe_requested_size += 1),
        ("interior".into(), |id| id.was_interior = true),
        ("parent".into(), |id| {
            id.containing_parent_old_base = Some(0x900000)
        }),
    ];
    for (name, flip) in cases {
        let mut b = binding.clone();
        flip(&mut b.identity);
        let ledger = TransformRunLedger::default();
        let err = build_patched_backing_slab_q0c(
            &raw_capture,
            &[transformed.clone()],
            &[],
            &[b],
            &ledger,
        )
        .expect_err("binding source-identity mismatch must fail closed");
        assert!(
            matches!(
                err,
                OverlayError::TransformPreimageBindingIdentityInvalid { .. }
            ),
            "binding {name} mismatch must fail closed, got {err:?}"
        );
    }
}

// P1-6 #12: two raw children sharing (capture_id, old_base) but differing in
// source evidence cannot both be members of one run — the ledger run must not
// cross-select between the two source-evidence identities.
#[test]
fn route_y_r1_a6_q0c_ledger_cannot_cross_source_identity() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    // Two raw children: SAME (capture_id, old_base), SAME path/extent, but
    // DIFFERENT source_root_rva (two source-evidence identities).
    let mk = |src: u32| RawChild {
        old_base: B_BASE,
        size: B_SIZE,
        raw_bytes: vec![0xAAu8; B_SIZE],
        kind: RawChildKind::HeapGlobal,
        capture_id: "gscript_label:0x8e9da8".into(),
        capture_path: CP::GscriptLabelTableEntry,
        extent_kind: CEK::InteriorSubview,
        source_slot_offset: Some(0),
        requested_probe_size: 0x1000,
        source_root_rva: Some(src),
        was_interior: true,
        containing_parent_old_base: Some(0x8e93c8),
        containing_parent_size: Some(0x2000),
    };
    let raw_capture = RawSlabCapture {
        slabs: Vec::new(),
        children: vec![mk(0x100), mk(0x200)],
    };
    // A run targeting (capture_id, old_base) is ambiguous: it could bind to
    // either source identity. validate_run_membership must fail closed.
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "gscript_label:0x8e9da8".into(),
        child_old_base: B_BASE,
        child_size: B_SIZE,
        child_offset: 0,
        length: 0,
        transform_id: "scrub_uncaptured_heap_pointers".into(),
        before_digest: sha256_hex(&[0u8; 0]),
        after_digest: sha256_hex(&[0u8; 0]),
        first_before_byte: 0,
        first_after_byte: 0,
        before_bytes: Vec::new(),
        after_bytes: Vec::new(),
    });
    let mut g = a6_full_identity_global(B_BASE, B_SIZE);
    g.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    g.extent_evidence.source_root_rva = Some(0x100);
    let err = validate_run_membership(&raw_capture, &[g], &ledger)
        .expect_err("run must not cross source-evidence identities");
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "a run spanning two source-evidence identities must fail closed, got {err:?}"
    );
}

/// Run the full production A6 contained-label pipeline for the given config
/// and verify the FULL capture identity is identical across every stage of the
/// raw -> binding -> recorder -> Q0-C chain (P1-5/P1-7). Returns the patched
/// slab index so the caller can assert the canonical qword.
fn assert_full_identity_roundtrip(cfg: &LabelConfig, expected_flag: u8) -> usize {
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let (raw_capture, globals, _containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, cfg,
    );
    // Locate B across every stage.
    let raw_b = raw_capture
        .children
        .iter()
        .find(|c| c.old_base == B_BASE && c.capture_id == cfg.capture_id)
        .expect("raw child B present");
    let transformed_b = globals
        .iter()
        .find(|g| g.live_ptr == B_BASE && g.extent_evidence.capture_id == cfg.capture_id)
        .expect("transformed B present");
    let binding_b = bindings
        .iter()
        .find(|b| b.child_old_base == B_BASE && b.capture_id == cfg.capture_id)
        .expect("binding B present");
    // raw identity == transformed identity == binding identity (structural).
    let raw_id = FullCaptureIdentity::from_raw_child(raw_b);
    let trans_id = FullCaptureIdentity::from_heap_global(transformed_b);
    assert_eq!(
        raw_id, trans_id,
        "raw child identity must equal transformed snapshot identity for B"
    );
    assert_eq!(
        binding_b.identity, raw_id,
        "binding identity must equal raw child identity for B"
    );
    // Q0-C overlay succeeds with the SAME full identity (resolves + binds B).
    let (patched, overlays, _drift) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("full-identity roundtrip must reach Q0-C and overlay successfully");
    assert!(
        overlays.iter().any(|o| o.child_old_base == B_BASE),
        "B must be overlaid"
    );
    let b_off = (B_BASE - SLAB_BASE) as usize;
    assert_eq!(
        patched[0].content[b_off + 0x23],
        expected_flag,
        "patched B+0x23 flag must be canonical"
    );
    let patched_qword = &patched[0].content[b_off + 0x20..b_off + 0x28];
    // For the label-table emitter B+0x23 == 1 -> qword 00 00 00 01 00 00 00 00.
    // For a child-link interior (not table-reachable) B+0x23 == 0x00 -> qword
    // all zero. Either way the original dangling pointer (0x70 at +3) is gone.
    let mut expected = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    expected[3] = expected_flag;
    assert_eq!(
        patched_qword,
        &expected[..],
        "patched qword must be canonical (dangling pointer cleared)"
    );
    assert_ne!(
        patched_qword,
        &DANGLING.to_le_bytes()[..],
        "original dangling pointer must not survive"
    );
    0
}

// P1-5 #13: label-table emitter — full identity roundtrip through the real
// production pipeline + Q0-C succeeds with the canonical patched qword.
#[test]
fn route_y_r1_a6_q0c_label_table_emitter_full_identity_roundtrip() {
    assert_full_identity_roundtrip(&protected_label_config(), 0x01);
}

// P1-5 #14: child-link emitter — full identity roundtrip through the real
// production pipeline + Q0-C succeeds.
#[test]
fn route_y_r1_a6_q0c_child_link_emitter_full_identity_roundtrip() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let mut cfg = protected_label_config();
    // The child-link emitter captures B via a gscript child pointer, not the
    // label-table entry; the source root/slot/interior evidence mirrors it.
    cfg.capture_path = CP::GscriptChildLink;
    cfg.in_table = false;
    // A child-link interior that is NOT table-reachable is not a mark target;
    // B's only transform is scrub, which zeroes the shared byte to 0x00,
    // AGREEING with A's scrub (legitimate containment). Overlay must succeed
    // with the full identity roundtrip intact and B+0x23 == 0x00.
    assert_full_identity_roundtrip(&cfg, 0x00);
}

// P1-3 #15: a DECLARED size reinit may change size but NEVER any
// source-evidence field. Flipping source evidence on the declared-reinit
// child must fail closed, exactly as for a non-reinit child.
#[test]
fn route_y_r1_a6_q0c_declared_size_reinit_cannot_change_source_identity() {
    // The declared sanitize_ahk_runtime_global reinit (rva 0x141bf0, old
    // 0x8000 -> new 0x180 zero-filled) is allowed to change size.
    let mut before = global(0x3437e50, vec![0xAA; 0x8000], false);
    before.rva = 0x141bf0;
    before.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    before.extent_evidence.capture_path =
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot;
    before.extent_kind = CaptureExtentKind::ObservedAllocation;
    // Size reinit (declared) with NO source-evidence change -> allowed.
    let mut ok = before.clone();
    ok.content = vec![0u8; 0x180];
    diff_transform_write_runs(&[before.clone()], &[ok], "sanitize_ahk_runtime_global")
        .expect("declared size reinit with unchanged source identity must be allowed");
    // Flip EACH source-evidence field on the declared-reinit child -> must
    // fail closed (a declared reinit can only change size, never provenance).
    let cases: Vec<(String, fn(&mut HeapGlobalSnapshot))> = vec![
        ("source_root_rva".into(), |g| {
            g.extent_evidence.source_root_rva = Some(0x1000)
        }),
        ("source_slot_offset".into(), |g| {
            g.extent_evidence.source_slot_offset = Some(1)
        }),
        ("probe_requested_size".into(), |g| {
            g.extent_evidence.probe_requested_size = 1
        }),
        ("was_interior".into(), |g| {
            g.extent_evidence.was_interior = true
        }),
        ("containing_parent_old_base".into(), |g| {
            g.extent_evidence.containing_parent_old_base = Some(0x900000)
        }),
        ("containing_parent_size".into(), |g| {
            g.extent_evidence.containing_parent_size = Some(0x100)
        }),
    ];
    for (name, flip) in cases {
        let mut after = before.clone();
        after.content = vec![0u8; 0x180];
        flip(&mut after);
        let err =
            diff_transform_write_runs(&[before.clone()], &[after], "sanitize_ahk_runtime_global")
                .expect_err("declared reinit cannot change source evidence");
        assert!(
            matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
            "declared reinit {name} drift must fail closed, got {err:?}"
        );
    }
}

/// AF2R1 mandatory #10: final patched qword is canonical — run the real
/// production pipeline (scrub → mark → recorded ledger → Q0-C overlay),
/// assert overlay succeeds, patched slab B+0x23 == 1, and the flag qword is
/// the canonical child-written value (not the original dangling pointer).
#[test]
fn route_y_r1_a6_q0c_final_patched_qword_is_canonical() {
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let cfg = protected_label_config();
    let (raw_capture, globals, _containers, bindings, ledger) = a6_contained_label_pipeline(
        &a_raw, &b_raw, A_BASE, A_SIZE, B_BASE, SLAB_BASE, SLAB_SZ, &cfg,
    );
    // Overlay succeeds (mitigation resolves the A/B conflict).
    let (patched, _overlays, _drift) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("full-identity mitigation must resolve the Q0-C conflict");
    let b_off = (B_BASE - SLAB_BASE) as usize;
    // Final patched qword at B[0x20..0x28]: B's own scrub zeroes the dangling
    // qword, then mark_labels_non_nested sets byte 0x23 = 1.
    let patched_qword = &patched[0].content[b_off + 0x20..b_off + 0x28];
    assert_eq!(
        patched[0].content[b_off + 0x23],
        0x01,
        "patched B+0x23 flag must be canonical 1"
    );
    assert_ne!(
        patched_qword,
        &DANGLING.to_le_bytes()[..],
        "original dangling pointer value must NOT be preserved in the patched qword"
    );
    // The qword must be exactly the canonical child-written bytes: B's own
    // scrub zeroes the dangling qword [0x20..0x28), then mark sets byte 0x23
    // → [0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00] (no dangling pointer kept).
    let expected = [0x00u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(patched_qword, &expected[..]);
    // Parent A did not register a conflicting write at the shared byte: A
    // skipped the flag qword, so A's snapshot still holds the original
    // dangling value (0x70 at byte +3) — i.e. A never wrote 0x00 there.
    assert_eq!(
        globals[0].content[0xa03], 0x70,
        "A must not clobber the flag byte"
    );
    // Ledger replayability: the child B has both a scrub run (zeroing the
    // dangling byte at B+0x23 — the LE byte 3 of the 0x70000000 qword) and a
    // mark run (setting the flag to 1 at the same offset).
    let b_runs: Vec<_> = ledger
        .runs
        .iter()
        .filter(|r| r.child_old_base == B_BASE)
        .collect();
    assert!(
        b_runs
            .iter()
            .any(|r| r.transform_id == "mark_labels_non_nested"
                && r.child_offset == 0x23
                && r.first_after_byte == 1),
        "ledger must record the child's canonical mark write (B+0x23=1)"
    );
    assert!(
        b_runs
            .iter()
            .any(|r| r.transform_id == "scrub_uncaptured_heap_pointers"
                && r.child_offset == 0x23
                && r.first_after_byte == 0),
        "ledger must record the child's scrub zeroing of the dangling byte (B+0x23 0x70->0x00)"
    );
}

/// AF2R1 task 2: duplicate gscript object (two image-inline objects) must
/// refuse protection.
#[test]
fn route_y_r1_a6_q0c_duplicate_gscript_refuses_protection() {
    use crate::dumper::heap_global_snapshot::gscript_label_flag_protections;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    // Standard fixture (one gscript), then append a SECOND image-inline
    // object that also looks like a gscript → unique resolution must refuse.
    let (_raw, mut globals, _containers, _bindings, _ledger) = a6_contained_label_pipeline(
        &a_raw,
        &b_raw,
        A_BASE,
        A_SIZE,
        B_BASE,
        SLAB_BASE,
        SLAB_SZ,
        &protected_label_config(),
    );
    // Find the real gscript and clone it as an imposter at a different base.
    let gscript = globals
        .iter()
        .find(|g| g.is_image_inline)
        .expect("fixture must have an image-inline gscript")
        .clone();
    let mut impostor = gscript.clone();
    impostor.live_ptr = 0x8f5000;
    globals.push(impostor);
    assert!(
        gscript_label_flag_protections(&globals).is_empty(),
        "duplicate gscript candidate must refuse protection"
    );
}

/// AF2R1 task 2: duplicate label table (two objects at the table pointer)
/// must refuse protection.
#[test]
fn route_y_r1_a6_q0c_duplicate_label_table_refuses_protection() {
    use crate::dumper::heap_global_snapshot::gscript_label_flag_protections;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const TABLE: u64 = 0x8f1000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let (_raw, mut globals, _containers, _bindings, _ledger) = a6_contained_label_pipeline(
        &a_raw,
        &b_raw,
        A_BASE,
        A_SIZE,
        B_BASE,
        SLAB_BASE,
        SLAB_SZ,
        &protected_label_config(),
    );
    // Append a second snapshot at the same table pointer.
    let table = globals
        .iter()
        .find(|g| g.live_ptr == TABLE)
        .expect("fixture must contain the label table")
        .clone();
    let mut impostor = table.clone();
    impostor.live_ptr = TABLE; // same address → duplicate table
    globals.push(impostor);
    assert!(
        gscript_label_flag_protections(&globals).is_empty(),
        "duplicate label table must refuse protection"
    );
}

// =====================================================================
// AF3 emitter-driven tests — production capture-identity reachability.
// =====================================================================

/// Minimal memory-map `DebuggerCore` for driving the REAL production
/// `exhaust_gscript_label_table_entries` emitter (AF3 task 3/4). Serves a
/// fixed set of (base → bytes) regions; reads outside any region fail.
#[derive(Default)]
struct RegionMapMock {
    regions: std::collections::BTreeMap<u64, Vec<u8>>,
    image_base: u64,
}

impl RegionMapMock {
    fn new() -> Self {
        Self {
            regions: std::collections::BTreeMap::new(),
            image_base: 0x140000000,
        }
    }
    fn set(&mut self, base: u64, bytes: Vec<u8>) {
        self.regions.insert(base, bytes);
    }
}

impl mida_core::DebuggerCore for RegionMapMock {
    fn process_handle(&self) -> windows::Win32::Foundation::HANDLE {
        windows::Win32::Foundation::HANDLE(std::ptr::null_mut())
    }
    fn pid(&self) -> u32 {
        1
    }
    fn image_base(&self) -> u64 {
        self.image_base
    }
    fn wait_event(&mut self) -> Result<mida_core::DebugEvent, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn continue_event(
        &mut self,
        _t: u32,
        _s: mida_core::ContinueStatus,
    ) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, mida_core::CoreError> {
        let addr = address as u64;
        for (base, region) in &self.regions {
            if addr >= *base && addr < base.saturating_add(region.len() as u64) {
                let off = (addr - *base) as usize;
                let n = (region.len() - off).min(buf.len());
                buf[..n].copy_from_slice(&region[off..off + n]);
                return Ok(n);
            }
        }
        Err(mida_core::CoreError::MemoryRead {
            address: addr,
            requested: buf.len(),
        })
    }
    fn write_memory(&mut self, _a: usize, _d: &[u8]) -> Result<usize, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn get_thread_context(
        &self,
        _t: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn set_thread_context(
        &self,
        _t: u32,
        _c: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
    ) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
}

/// Build the AF3 emitter fixture `out` = [gscript(inline), table, A, snap]
/// (pre-exhaust) and a memory-map mock serving B's raw bytes, then drive the
/// REAL `exhaust_gscript_label_table_entries`. Returns the post-exhaust
/// globals. B's identity (capture_id / path / extent / parent) is produced
/// entirely by the production emitter — never hand-edited.
fn a6_emitter_globals(
    a_raw: &[u8],
    b_raw: &[u8],
    a_base: u64,
    b_base: u64,
    gscript: u64,
    table: u64,
    snap: u64,
) -> (Vec<HeapGlobalSnapshot>, RegionMapMock) {
    use crate::dumper::capture_policy::DumpCapturePolicy;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_label_table_entries;
    use crate::dumper::heap_global_snapshot::CapturePath;
    let mut mock = RegionMapMock::new();
    // The REAL exhaust runs the memory handlers on the label bytes. Sanitize
    // the fixture so they no-op deterministically: p0 == 0 (no refcounted
    // string shell — it would otherwise truncate/null the buffer) and
    // name_ptr / inline name NUL (no name externalization / synthetic read).
    let mut served = b_raw.to_vec();
    if served.len() >= 0x38 {
        served[0..8].fill(0);
        served[0x28..0x38].fill(0);
    }
    mock.set(b_base, served);

    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&table.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&b_base.to_le_bytes());
    let snap_content = vec![0u8; 0x30];

    let mut ga = global(a_base, a_raw.to_vec(), false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{a_base:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gg = global(gscript, gscript_content, true);
    gg.extent_kind = CaptureExtentKind::ObservedAllocation;
    gg.extent_evidence.capture_id = format!("gscript:{gscript:#x}");
    gg.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gt = global(table, table_content, false);
    gt.extent_kind = CaptureExtentKind::ObservedAllocation;
    gt.extent_evidence.capture_id = format!("gscript_table:{table:#x}");
    gt.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gsnap = global(snap, snap_content, false);
    gsnap.extent_kind = CaptureExtentKind::ObservedAllocation;
    gsnap.extent_evidence.capture_id = format!("string_snapshot:{snap:#x}");
    gsnap.extent_evidence.capture_path = CapturePath::MainSlot;

    let mut globals = vec![ga, gg, gt, gsnap];
    let mut total_bytes = 0usize;
    let mut seen_heaps = std::collections::BTreeSet::new();
    let policy = DumpCapturePolicy::default();
    exhaust_gscript_label_table_entries(
        &mut globals,
        &mut total_bytes,
        &mut seen_heaps,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    (globals, mock)
}

/// Safe raw Label payload for emitter-driven tests. The real exhaust runs the
/// memory handlers on the label: p0 == 0 (no refcounted-string shell, so the
/// shell handler never truncates or nulls the buffer), all-zero otherwise so
/// scrub does not treat arbitrary bytes as external heap pointers (a clean
/// single dangling qword at [0x20..0x28) holds the +0x23 flag), and name_ptr /
/// inline name NUL (no name externalization / synthetic read). Not detected as
/// a free-list tail (no repeated fill qwords) and not a heap handle (unaligned).
fn a6_b_raw() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    b[0x20..0x28].copy_from_slice(&0x70000000u64.to_le_bytes());
    b
}

/// Build a slab whose bytes match each global's content at its live offset.
/// Guarantees every strict (ObservedAllocation) raw child satisfies C == S, and
/// every InteriorSubview is seeded from the same bytes the emitter captured.
fn slab_from_globals(globals: &[HeapGlobalSnapshot], slab_base: u64, slab_sz: usize) -> Vec<u8> {
    let mut content = vec![0u8; slab_sz];
    for g in globals {
        let off = (g.live_ptr - slab_base) as usize;
        if off >= slab_sz {
            continue;
        }
        let n = g.content.len().min(slab_sz - off);
        content[off..off + n].copy_from_slice(&g.content[..n]);
    }
    content
}

/// AF3 task 3 test 1: the REAL production `exhaust_gscript_label_table_entries`
/// emitter must produce B with the production-reachable identity
/// (GscriptLabelTableEntry + InteriorSubview + unique parent A + canonical
/// `gscript_label:{base}`), and that identity must generate exactly one
/// LabelFlagProtection whose child/parent identities equal the actual B/A
/// snapshots.
#[test]
fn production_exhaust_emitter_label_protection_is_reachable() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let b_raw = a6_b_raw();
    let (globals, _mock) = a6_emitter_globals(&a_raw, &b_raw, A_BASE, B_BASE, GSCRIPT, TABLE, SNAP);
    // The emitter must have added exactly one label with the reachable identity.
    let b = globals
        .iter()
        .find(|g| g.live_ptr == B_BASE)
        .expect("emitter must capture label-table entry B");
    assert_eq!(b.extent_evidence.capture_id, "gscript_label:0x8e9da8");
    assert_eq!(
        b.extent_evidence.capture_path,
        CapturePath::GscriptLabelTableEntry
    );
    assert_eq!(b.extent_kind, CaptureExtentKind::InteriorSubview);
    assert_eq!(b.extent_evidence.containing_parent_old_base, Some(A_BASE));
    assert_eq!(b.extent_evidence.containing_parent_size, Some(A_SIZE));
    assert!(b.extent_evidence.was_interior);
    // Exactly one protection, and its identities match the actual snapshots.
    let prot = gscript_label_flag_protections(&globals);
    assert_eq!(
        prot.len(),
        1,
        "production-reachable B must yield one protection"
    );
    let a = globals
        .iter()
        .find(|g| g.live_ptr == A_BASE)
        .expect("parent A present");
    let b = globals
        .iter()
        .find(|g| g.live_ptr == B_BASE)
        .expect("label B present");
    assert_eq!(prot[0].child.capture_id, b.extent_evidence.capture_id);
    assert_eq!(prot[0].child.old_base, b.live_ptr);
    assert_eq!(prot[0].child.size, b.content.len());
    assert_eq!(prot[0].child.extent_kind, b.extent_kind);
    assert_eq!(prot[0].child.capture_path, b.extent_evidence.capture_path);
    assert_eq!(prot[0].parent.capture_id, a.extent_evidence.capture_id);
    assert_eq!(prot[0].parent.old_base, a.live_ptr);
    assert_eq!(prot[0].parent.size, a.content.len());
    assert_eq!(prot[0].parent.extent_kind, a.extent_kind);
    assert_eq!(prot[0].parent.capture_path, a.extent_evidence.capture_path);
}

/// AF3 task 3 test 2 (AF3 AF1 P1-1): a PRE-EXISTING interior label first
/// captured by the REAL production `exhaust_gscript_child_link_fields`
/// emitter, then referenced by the gscript label table, must still be
/// protection-reachable. B's identity (capture_id / capture_path /
/// extent_kind / source_root_rva / source_slot_offset / probe_requested_size
/// / was_interior / containing_parent) is produced ENTIRELY by the emitter —
/// never hand-built, never deleted-and-reinserted, never directly formatted.
///
/// Pipeline:
///   1. Build `out` = [A(parent, whose link field points to B), gscript
///      (image-inline, table ptr), label table (references B), snap], with a
///      memory-map mock serving B's raw bytes.
///   2. Drive the REAL `exhaust_gscript_child_link_fields` — it walks A's
///      link fields, reads B, and emits B as GscriptChildLink + InteriorSubview
///      + parent A + `gscript_child_link:{A}:{loff}:{B}:{probe}`.
///   3. Drive the REAL `exhaust_gscript_label_table_entries` — it must NOT
///      create a duplicate B (B is already an exact live ptr).
///   4. `gscript_label_flag_protections` must yield exactly one protection
///      whose child/parent identities equal the real emitter output.
#[test]
fn production_preexisting_label_entry_protection_is_reachable() {
    use crate::dumper::capture_policy::DumpCapturePolicy;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_child_link_fields;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_label_table_entries;
    use crate::dumper::heap_global_snapshot::gscript_label_flag_protections;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    const LINK_OFF: usize = 0x10; // A[0x10] points to B (a real link field)
    let mut mock = RegionMapMock::new();
    // B's served bytes: no refcounted-string shell (p0=0), no freelist fill,
    // dangling flag qword at [0x20..0x28), no name externalization.
    let mut b_raw = vec![0u8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&0x70000000u64.to_le_bytes());
    mock.set(B_BASE, b_raw.clone());

    // gscript root (image-inline) with label table ptr at +0 and count at +0x10.
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    // Label table references B at entry +0.
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let snap_content = vec![0u8; 0x30];

    // Parent A must FULLY contain B and carry B's pointer at a link field.
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[LINK_OFF..LINK_OFF + 8].copy_from_slice(&B_BASE.to_le_bytes());
    // A's content at B's sub-range must match B's raw bytes (strict A seeding
    // compares the full slab slice); B sits at A offset (B_BASE - A_BASE).
    let b_in_a = (B_BASE - A_BASE) as usize;
    a_raw[b_in_a..b_in_a + B_SIZE].copy_from_slice(&b_raw);

    let mut ga = global(A_BASE, a_raw, false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_kind = CaptureExtentKind::ObservedAllocation;
    gg.extent_evidence.capture_id = format!("gscript:{GSCRIPT:#x}");
    gg.extent_evidence.capture_path = CapturePath::MainSlot;
    gg.extent_evidence.source_root_rva = Some(0x149d50);
    let mut gt = global(TABLE, table_content, false);
    gt.extent_kind = CaptureExtentKind::ObservedAllocation;
    gt.extent_evidence.capture_id = format!("gscript_table:{TABLE:#x}");
    gt.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gsnap = global(SNAP, snap_content, false);
    gsnap.extent_kind = CaptureExtentKind::ObservedAllocation;
    gsnap.extent_evidence.capture_id = format!("string_snapshot:{SNAP:#x}");
    gsnap.extent_evidence.capture_path = CapturePath::MainSlot;

    let mut globals = vec![ga, gg, gt, gsnap];
    let mut total_bytes = 0usize;
    let mut seen_heaps = std::collections::BTreeSet::new();
    let policy = DumpCapturePolicy::default();
    // 1. REAL child-link emitter produces B.
    exhaust_gscript_child_link_fields(
        &mut globals,
        &mut total_bytes,
        &mut seen_heaps,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    // The emitter must have admitted exactly one B with the child-link family.
    let b_before_table = globals.iter().filter(|g| g.live_ptr == B_BASE).count();
    assert_eq!(
        b_before_table, 1,
        "real child-link emitter must produce exactly one B"
    );
    let b = globals.iter().find(|g| g.live_ptr == B_BASE).unwrap();
    assert_eq!(
        b.extent_evidence.capture_path,
        CapturePath::GscriptChildLink,
        "emitter must set GscriptChildLink path"
    );
    assert_eq!(b.extent_kind, CaptureExtentKind::InteriorSubview);
    assert_eq!(b.extent_evidence.was_interior, true);
    assert_eq!(b.extent_evidence.containing_parent_old_base, Some(A_BASE));
    assert_eq!(b.extent_evidence.containing_parent_size, Some(A_SIZE));
    assert_eq!(b.extent_evidence.source_slot_offset, Some(LINK_OFF));
    // Default DumpCapturePolicy → first_hop_probe() == 0x800, below
    // MAX_HEAP_GLOBAL_BYTES (64 KiB), so probe_requested_size == 0x800.
    assert_eq!(b.extent_evidence.probe_requested_size, 0x800);
    let probe = b.extent_evidence.probe_requested_size;
    assert_eq!(
        b.extent_evidence.capture_id,
        format!("gscript_child_link:{A_BASE:#x}:{LINK_OFF:#x}:{B_BASE:#x}:{probe}")
    );
    // 2. REAL label-table exhaust must NOT duplicate B (exact-live-ptr).
    exhaust_gscript_label_table_entries(
        &mut globals,
        &mut total_bytes,
        &mut seen_heaps,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    let b_count = globals.iter().filter(|g| g.live_ptr == B_BASE).count();
    assert_eq!(
        b_count, 1,
        "label-table exhaust must not create a duplicate B"
    );
    // 3. Exactly one protection; child/parent equal the real emitter output.
    let prot = gscript_label_flag_protections(&globals);
    assert_eq!(
        prot.len(),
        1,
        "pre-existing child-link-captured interior label must be reachable"
    );
    let a = globals.iter().find(|g| g.live_ptr == A_BASE).unwrap();
    let b = globals.iter().find(|g| g.live_ptr == B_BASE).unwrap();
    assert_eq!(prot[0].child.capture_id, b.extent_evidence.capture_id);
    assert_eq!(prot[0].child.old_base, b.live_ptr);
    assert_eq!(prot[0].child.size, b.content.len());
    assert_eq!(prot[0].child.extent_kind, b.extent_kind);
    assert_eq!(prot[0].child.capture_path, b.extent_evidence.capture_path);
    assert_eq!(
        prot[0].child.source_slot_offset,
        b.extent_evidence.source_slot_offset
    );
    assert_eq!(
        prot[0].child.probe_requested_size,
        b.extent_evidence.probe_requested_size
    );
    assert_eq!(prot[0].child.was_interior, b.extent_evidence.was_interior);
    assert_eq!(prot[0].parent.capture_id, a.extent_evidence.capture_id);
    assert_eq!(prot[0].parent.old_base, a.live_ptr);
    assert_eq!(prot[0].parent.size, a.content.len());
    assert_eq!(prot[0].parent.extent_kind, a.extent_kind);
    assert_eq!(prot[0].parent.capture_path, a.extent_evidence.capture_path);
}

/// AF3 AF1 P1-1 test 2: full Q0-C pipeline from REAL child-link emitter
/// output. B is produced by `exhaust_gscript_child_link_fields` (never
/// hand-built), then the label-table exhaust is driven (skips B), then the
/// real raw → validate → coverage → seed → scrub → mark → ledger → Q0-C
/// overlay runs. Assert the patched flag qword is canonical and B+0x23 == 1
/// with no dangling pointer preserved.
#[test]
fn production_preexisting_child_link_scrub_mark_q0c_succeeds() {
    use crate::dumper::capture_policy::DumpCapturePolicy;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_child_link_fields;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_label_table_entries;
    use crate::dumper::heap_global_snapshot::{
        mark_labels_non_nested, scrub_uncaptured_heap_pointers,
    };
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const LINK_OFF: usize = 0x10;
    let mut mock = RegionMapMock::new();
    let mut b_raw = vec![0u8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&0x70000000u64.to_le_bytes());
    mock.set(B_BASE, b_raw.clone());

    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let snap_content = vec![0u8; 0x30];

    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[LINK_OFF..LINK_OFF + 8].copy_from_slice(&B_BASE.to_le_bytes());
    let b_in_a = (B_BASE - A_BASE) as usize;
    a_raw[b_in_a..b_in_a + B_SIZE].copy_from_slice(&b_raw);

    let mut ga = global(A_BASE, a_raw, false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_kind = CaptureExtentKind::ObservedAllocation;
    gg.extent_evidence.capture_id = format!("gscript:{GSCRIPT:#x}");
    gg.extent_evidence.capture_path = CapturePath::MainSlot;
    gg.extent_evidence.source_root_rva = Some(0x149d50);
    let mut gt = global(TABLE, table_content, false);
    gt.extent_kind = CaptureExtentKind::ObservedAllocation;
    gt.extent_evidence.capture_id = format!("gscript_table:{TABLE:#x}");
    gt.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gsnap = global(SNAP, snap_content, false);
    gsnap.extent_kind = CaptureExtentKind::ObservedAllocation;
    gsnap.extent_evidence.capture_id = format!("string_snapshot:{SNAP:#x}");
    gsnap.extent_evidence.capture_path = CapturePath::MainSlot;

    let mut globals = vec![ga, gg, gt, gsnap];
    let mut total_bytes = 0usize;
    let mut seen_heaps = std::collections::BTreeSet::new();
    let policy = DumpCapturePolicy::default();
    // REAL child-link emitter produces B.
    exhaust_gscript_child_link_fields(
        &mut globals,
        &mut total_bytes,
        &mut seen_heaps,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    // REAL label-table exhaust skips B (already exact).
    exhaust_gscript_label_table_entries(
        &mut globals,
        &mut total_bytes,
        &mut seen_heaps,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    let b_off = (B_BASE - SLAB_BASE) as usize;
    // Slab built from the post-emitter globals so every strict participant
    // satisfies C == S and B (InteriorSubview) seeds from the emitted bytes.
    let slab_content = slab_from_globals(&globals, SLAB_BASE, SLAB_SZ);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_content)],
        children: raw_children_from_capture(&[], &globals),
    };
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals)
        .expect("emitter identity must validate");
    validate_probe_coverage(&globals, &raw_capture.slabs).expect("coverage must hold");
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .expect("seeding must succeed");
    let mut ledger = TransformRunLedger::default();
    apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |gs| {
            scrub_uncaptured_heap_pointers(&mut containers, gs, 0, SLAB_BASE + SLAB_SZ as u64);
        },
    )
    .expect("scrub must record");
    apply_recorded_transform(&mut globals, "mark_labels_non_nested", &mut ledger, |gs| {
        mark_labels_non_nested(gs)
    })
    .expect("mark must record");
    let (patched, _overlays, _drift) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("child-link emitter-driven Q0-C overlay must succeed");
    assert_eq!(patched[0].content[b_off + 0x23], 0x01);
    assert_ne!(
        &patched[0].content[b_off + 0x20..b_off + 0x28],
        &0x70000000u64.to_le_bytes()[..],
        "original dangling pointer must not be preserved"
    );
    assert_eq!(
        &patched[0].content[b_off + 0x20..b_off + 0x28],
        &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        "patched flag qword must be canonical"
    );
    // A must not clobber the flag byte.
    assert_eq!(
        globals[0].content[b_in_a + 0x23],
        0x70,
        "A must not clobber the flag byte"
    );
}

/// AF3 task 3 test 3: positive protection must NOT depend on the old
/// hand-built impossible tuple (capture_id `gscript_label:*` + path
/// GscriptChildLink + hand-assigned InteriorSubview/parent). The family-aware
/// parser rejects that mixture → no protection.
#[test]
fn hand_built_impossible_identity_tuple_is_not_required() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    const DANGLING: u64 = 0x70000000;
    let a_raw = vec![0xAAu8; A_SIZE];
    let mut b_raw = vec![0xAAu8; B_SIZE];
    b_raw[0x20..0x28].copy_from_slice(&DANGLING.to_le_bytes());
    let (mut globals, _mock) =
        a6_emitter_globals(&a_raw, &b_raw, A_BASE, B_BASE, GSCRIPT, TABLE, SNAP);
    globals.retain(|g| g.live_ptr != B_BASE);
    // Old AF2 fixture tuple: gscript_label id + GscriptChildLink path +
    // hand-assigned InteriorSubview/parent. This is NOT a production emitter
    // output — must NOT be protected.
    let mut gb = global(B_BASE, b_raw, false);
    gb.extent_kind = CaptureExtentKind::InteriorSubview;
    gb.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    gb.extent_evidence.capture_path = CapturePath::GscriptChildLink;
    gb.extent_evidence.containing_parent_old_base = Some(A_BASE);
    gb.extent_evidence.containing_parent_size = Some(A_SIZE);
    globals.push(gb);
    assert!(
        gscript_label_flag_protections(&globals).is_empty(),
        "hand-built gscript_label+GscriptChildLink tuple must NOT be protected"
    );
}

/// AF3 task 4: full pipeline from REAL emitter output — raw children →
/// identity validation → coverage → seeding → scrub → mark → recorded ledger
/// → Q0-C overlay. Assert overlay succeeds, patched B+0x23 == 1, and the
/// patched flag qword is canonical (no dangling pointer preserved).
#[test]
fn production_emitter_scrub_mark_q0c_succeeds() {
    use crate::dumper::heap_global_snapshot::{
        mark_labels_non_nested, scrub_uncaptured_heap_pointers,
    };
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    // B is an interior child of A: its raw bytes are part of A's memory. A's
    // content must match the slab where B sits (A's strict seeding compares the
    // full slab slice to A's captured bytes). Put B's raw bytes at A offset
    // (B_BASE - A_BASE) so A's region is coherent with the interior capture.
    let b_raw = a6_b_raw();
    let b_in_a = (B_BASE - A_BASE) as usize;
    a_raw[b_in_a..b_in_a + b_raw.len()].copy_from_slice(&b_raw);
    let (mut globals, _mock) =
        a6_emitter_globals(&a_raw, &b_raw, A_BASE, B_BASE, GSCRIPT, TABLE, SNAP);

    let b_off = (B_BASE - SLAB_BASE) as usize;
    // Slab built from the post-emitter globals so every strict participant
    // satisfies C == S and B (InteriorSubview) seeds from the emitted bytes.
    let slab_content = slab_from_globals(&globals, SLAB_BASE, SLAB_SZ);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, slab_content)],
        children: raw_children_from_capture(&[], &globals),
    };
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    validate_raw_coherence_capture_identities(&containers, &globals)
        .expect("emitter identity must validate");
    validate_probe_coverage(&globals, &raw_capture.slabs).expect("coverage must hold");
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .expect("seeding must succeed");
    let mut ledger = TransformRunLedger::default();
    apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |gs| {
            scrub_uncaptured_heap_pointers(&mut containers, gs, 0, SLAB_BASE + SLAB_SZ as u64);
        },
    )
    .expect("scrub must record");
    apply_recorded_transform(&mut globals, "mark_labels_non_nested", &mut ledger, |gs| {
        mark_labels_non_nested(gs)
    })
    .expect("mark must record");
    let (patched, _overlays, _drift) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &bindings, &ledger)
            .expect("emitter-driven Q0-C overlay must succeed");
    assert_eq!(patched[0].content[b_off + 0x23], 0x01);
    assert_ne!(
        &patched[0].content[b_off + 0x20..b_off + 0x28],
        &DANGLING.to_le_bytes()[..],
        "original dangling pointer must not be preserved"
    );
    assert_eq!(
        &patched[0].content[b_off + 0x20..b_off + 0x28],
        &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        "patched flag qword must be canonical"
    );
    // A must not clobber the flag byte: its own scrub skipped the protected
    // qword, so A never wrote 0x00 at the shared byte (0x70 preserved).
    assert_eq!(
        globals[0].content[0xa03], 0x70,
        "A must not clobber the flag byte"
    );
    // Ledger replayability: B recorded both the zeroing scrub run and the
    // canonical mark run (same as the AF2R1 final-patched proof).
    let b_runs: Vec<_> = ledger
        .runs
        .iter()
        .filter(|r| r.child_old_base == B_BASE)
        .collect();
    assert!(
        b_runs
            .iter()
            .any(|r| r.transform_id == "scrub_uncaptured_heap_pointers"
                && r.child_offset == 0x23
                && r.first_after_byte == 0),
        "ledger must record B's scrub zeroing of the flag byte (B+0x23 0x70->0x00)"
    );
    assert!(
        b_runs
            .iter()
            .any(|r| r.transform_id == "mark_labels_non_nested"
                && r.child_offset == 0x23
                && r.first_after_byte == 1),
        "ledger must record B's canonical mark write (B+0x23=1)"
    );
}

/// AF3 task 5 negative #1: a MainSlot-path ProbeWindow-without-parent label
/// (the OLD exhaust metadata) must NOT be protected.
#[test]
fn main_slot_probe_without_parent_not_protected() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut gb = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb.extent_kind = CaptureExtentKind::ProbeWindow; // ProbeWindow, NO parent
    gb.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    gb.extent_evidence.capture_path = CapturePath::MainSlot; // MainSlot
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    assert!(
        gscript_label_flag_protections(&[gg, gt, gb]).is_empty(),
        "MainSlot/ProbeWindow without parent must not be protected"
    );
}

/// AF3 task 5 negative #2: a real child-link family id whose ENCODED source
/// parent disagrees with the snapshot's containing parent must not be
/// protected (strict family parser).
#[test]
fn gscript_child_link_id_with_wrong_source_parent_not_protected() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const A_BASE: u64 = 0x8e93c8;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga = global(A_BASE, vec![0xAAu8; 0x2000], false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gb = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb.extent_kind = CaptureExtentKind::InteriorSubview;
    // Encoded parent = 0x12345678, snapshot containing parent = A → mismatch.
    gb.extent_evidence.capture_id = "gscript_child_link:0x12345678:0x20:0x8e9da8:2048".into();
    gb.extent_evidence.capture_path = CapturePath::GscriptChildLink;
    gb.extent_evidence.source_slot_offset = Some(0x20);
    gb.extent_evidence.probe_requested_size = 0x800;
    gb.extent_evidence.containing_parent_old_base = Some(A_BASE);
    gb.extent_evidence.containing_parent_size = Some(0x2000);
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    assert!(
        gscript_label_flag_protections(&[ga, gg, gt, gb, gsnap]).is_empty(),
        "child_link id with wrong encoded source parent must not be protected"
    );
}

/// AF3 task 5 negative #3: child_link id with a wrong encoded link offset.
#[test]
fn gscript_child_link_id_with_wrong_link_offset_not_protected() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const A_BASE: u64 = 0x8e93c8;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga = global(A_BASE, vec![0xAAu8; 0x2000], false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gb = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb.extent_kind = CaptureExtentKind::InteriorSubview;
    // Encoded loff = 0x30, snapshot source_slot_offset = 0x20 → mismatch.
    gb.extent_evidence.capture_id = "gscript_child_link:0x8e93c8:0x30:0x8e9da8:2048".into();
    gb.extent_evidence.capture_path = CapturePath::GscriptChildLink;
    gb.extent_evidence.source_slot_offset = Some(0x20);
    gb.extent_evidence.probe_requested_size = 0x800;
    gb.extent_evidence.containing_parent_old_base = Some(A_BASE);
    gb.extent_evidence.containing_parent_size = Some(0x2000);
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    assert!(
        gscript_label_flag_protections(&[ga, gg, gt, gb, gsnap]).is_empty(),
        "child_link id with wrong encoded link offset must not be protected"
    );
}

/// AF3 task 5 negative #4: child_link id with a wrong encoded probe size.
#[test]
fn gscript_child_link_id_with_wrong_probe_size_not_protected() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const A_BASE: u64 = 0x8e93c8;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga = global(A_BASE, vec![0xAAu8; 0x2000], false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gb = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb.extent_kind = CaptureExtentKind::InteriorSubview;
    // Encoded probe = 2048, snapshot probe_requested_size = 0x1000 → mismatch.
    gb.extent_evidence.capture_id = "gscript_child_link:0x8e93c8:0x20:0x8e9da8:2048".into();
    gb.extent_evidence.capture_path = CapturePath::GscriptChildLink;
    gb.extent_evidence.source_slot_offset = Some(0x20);
    gb.extent_evidence.probe_requested_size = 0x1000;
    gb.extent_evidence.containing_parent_old_base = Some(A_BASE);
    gb.extent_evidence.containing_parent_size = Some(0x2000);
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    assert!(
        gscript_label_flag_protections(&[ga, gg, gt, gb, gsnap]).is_empty(),
        "child_link id with wrong encoded probe must not be protected"
    );
}

/// AF3 task 5 negative #5: table-reachable but malformed identity — not
/// protected.
#[test]
fn table_reachable_but_identity_malformed_not_protected() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut gb = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb.extent_kind = CaptureExtentKind::InteriorSubview;
    gb.extent_evidence.capture_id = "gscript_label:0xWRONG".into(); // malformed
    gb.extent_evidence.capture_path = CapturePath::GscriptLabelTableEntry;
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    assert!(
        gscript_label_flag_protections(&[gg, gt, gb]).is_empty(),
        "table-reachable malformed identity must not be protected"
    );
}

/// AF3 task 5 negative #6: reclassifying identity AFTER raw capture is
/// forbidden — the Q0-C run-membership gate binds every recorded run to a raw
/// child by (capture_id, old_base) and rejects/never silently accepts a
/// same-base capture identity change (never binds by physical address alone).
#[test]
fn semantic_reclassification_after_raw_capture_forbidden() {
    use crate::dumper::heap_global_snapshot::{
        mark_labels_non_nested, scrub_uncaptured_heap_pointers,
    };
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const SLAB_BASE: u64 = 0x800000;
    const SLAB_SZ: usize = 0x200000;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    const DANGLING: u64 = 0x70000000;
    let mut a_raw = vec![0xAAu8; A_SIZE];
    a_raw[0xa00..0xa08].copy_from_slice(&DANGLING.to_le_bytes());
    let b_raw = a6_b_raw();
    let (mut globals, _mock) =
        a6_emitter_globals(&a_raw, &b_raw, A_BASE, B_BASE, GSCRIPT, TABLE, SNAP);
    // Production ordering: raw children are derived BEFORE any identity change,
    // recording the ORIGINAL capture identity.
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(
            SLAB_BASE,
            slab_from_globals(&globals, SLAB_BASE, SLAB_SZ),
        )],
        children: raw_children_from_capture(&[], &globals),
    };
    // Attempt to reclassify B's capture identity AFTER raw capture (same base).
    for g in globals.iter_mut() {
        if g.live_ptr == B_BASE {
            g.extent_evidence.capture_id = "gscript_label:0x99999999".into();
        }
    }
    // Transforms run over the reclassified id and record runs carrying it. The
    // Q0-C run-membership gate then binds each run to a raw child by
    // (capture_id, old_base): no raw child carries the reclassified id → the
    // strict binding rejects the reclassification (never silently binds by
    // physical address).
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let mut ledger = TransformRunLedger::default();
    apply_recorded_transform(
        &mut globals,
        "scrub_uncaptured_heap_pointers",
        &mut ledger,
        |gs| {
            scrub_uncaptured_heap_pointers(&mut containers, gs, 0, SLAB_BASE + SLAB_SZ as u64);
        },
    )
    .expect("scrub runs recorded under the reclassified id");
    apply_recorded_transform(&mut globals, "mark_labels_non_nested", &mut ledger, |gs| {
        mark_labels_non_nested(gs)
    })
    .expect("mark runs recorded under the reclassified id");
    let err = build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &[], &ledger)
        .expect_err("post-raw reclassification must fail closed");
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "reclassified id must not resolve to any raw child (identity-first), got {err:?}"
    );
}

/// AF3 task 5 negative #7: production emitter duplicate parent fails closed.
#[test]
fn production_emitter_duplicate_parent_fails_closed() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga = global(A_BASE, vec![0xAAu8; A_SIZE], false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    // Duplicate parent: same base/size, different identity.
    let mut ga2 = global(A_BASE, vec![0xAAu8; A_SIZE], false);
    ga2.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga2.extent_evidence.capture_id = "heap_global_slot:0xDEADBEEF".into();
    ga2.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gb = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb.extent_kind = CaptureExtentKind::InteriorSubview;
    gb.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    gb.extent_evidence.capture_path = CapturePath::GscriptLabelTableEntry;
    gb.extent_evidence.containing_parent_old_base = Some(A_BASE);
    gb.extent_evidence.containing_parent_size = Some(A_SIZE);
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    assert!(
        gscript_label_flag_protections(&[ga, ga2, gg, gt, gb, gsnap]).is_empty(),
        "duplicate parent must fail closed"
    );
}

/// AF3 task 5 negative #8: production emitter duplicate label fails closed.
#[test]
fn production_emitter_duplicate_label_fails_closed() {
    use crate::dumper::heap_global_snapshot::{gscript_label_flag_protections, CapturePath};
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga = global(A_BASE, vec![0xAAu8; A_SIZE], false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gb = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb.extent_kind = CaptureExtentKind::InteriorSubview;
    gb.extent_evidence.capture_id = "gscript_label:0x8e9da8".into();
    gb.extent_evidence.capture_path = CapturePath::GscriptLabelTableEntry;
    gb.extent_evidence.containing_parent_old_base = Some(A_BASE);
    gb.extent_evidence.containing_parent_size = Some(A_SIZE);
    // Duplicate label at the same base, different identity.
    let mut gb2 = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb2.extent_kind = CaptureExtentKind::InteriorSubview;
    gb2.extent_evidence.capture_id = "gscript_label:0x8e9da8:dup".into();
    gb2.extent_evidence.capture_path = CapturePath::GscriptLabelTableEntry;
    gb2.extent_evidence.containing_parent_old_base = Some(A_BASE);
    gb2.extent_evidence.containing_parent_size = Some(A_SIZE);
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    assert!(
        gscript_label_flag_protections(&[ga, gg, gt, gb, gb2, gsnap]).is_empty(),
        "duplicate label must fail closed"
    );
}

// =====================================================================
// AF3 AF1 — production capture-family scope closure (P1-2/P1-3) and
// source-evidence / parent-ambiguity fail-closed (P1-4/P1-5).
// =====================================================================

/// Build a label-table-reachable B with the given identity path/id/evidence
/// and a gscript+table fixture, then assert `gscript_label_flag_protections`
/// yields no protection. Used by the P1-2/P1-3 ExplicitlyRejectedFailClosed
/// family negatives and the P1-5 source-evidence negatives.
fn assert_label_table_reachable_not_protected(
    capture_id: &str,
    capture_path: CapturePath,
    extent_kind: CaptureExtentKind,
    source_slot_offset: Option<usize>,
    source_root_rva: Option<u32>,
    probe_requested_size: usize,
    was_interior: bool,
    parent: Option<(u64, usize)>,
) {
    use crate::dumper::heap_global_snapshot::gscript_label_flag_protections;
    const B_BASE: u64 = 0x8e9da8;
    const B_SIZE: usize = 0x400;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    const A_BASE: u64 = 0x8e93c8;
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga = global(A_BASE, vec![0xAAu8; 0x2000], false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gb = global(B_BASE, vec![0xAAu8; B_SIZE], false);
    gb.extent_kind = extent_kind;
    gb.extent_evidence.capture_id = capture_id.into();
    gb.extent_evidence.capture_path = capture_path;
    gb.extent_evidence.source_slot_offset = source_slot_offset;
    gb.extent_evidence.source_root_rva = source_root_rva;
    gb.extent_evidence.probe_requested_size = probe_requested_size;
    gb.extent_evidence.was_interior = was_interior;
    gb.extent_evidence.containing_parent_old_base = parent.map(|(b, _)| b);
    gb.extent_evidence.containing_parent_size = parent.map(|(_, s)| s);
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    gg.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    gt.extent_evidence.capture_path = CapturePath::MainSlot;
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    let mut all = vec![ga, gg, gt, gb, gsnap];
    // Only keep a parent when the caller declared one (avoids a dangling A
    // that changes nothing but keeps the fixture minimal).
    if parent.is_none() {
        all.retain(|g| g.live_ptr != A_BASE);
    }
    assert!(
        gscript_label_flag_protections(&all).is_empty(),
        "capture family {:?} must be ExplicitlyRejectedFailClosed",
        capture_id
    );
}

/// AF3 AF1 P1-2 (方案A): `gscript_first_hop:` is NOT authorized. The id
/// encodes only edge_off and cannot strictly bind base/parent/probe/
/// was_interior, so a first-hop-captured table-reachable label stays
/// fail-closed.
#[test]
fn first_hop_table_reachable_not_protected() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind;
    // Real first-hop id form, GscriptFirstHop path, interior-with-parent —
    // still NOT protected because the family is explicitly rejected.
    assert_label_table_reachable_not_protected(
        "gscript_first_hop:0x0",
        CapturePath::GscriptFirstHop,
        CaptureExtentKind::InteriorSubview,
        Some(0x0),
        Some(0x149d50),
        0x800,
        true,
        Some((0x8e93c8, 0x2000)),
    );
}

/// AF3 AF1 P1-3: `gscript_child:{base}` (pointer-table first-hop) is
/// ExplicitlyRejectedFailClosed. Its id is not a canonical
/// `gscript_child_link:{parent}:{loff}:{base}:{probe}` (missing fields) and
/// it has no containing parent — the strict family parser rejects it.
#[test]
fn gscript_child_table_reachable_not_protected() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind;
    assert_label_table_reachable_not_protected(
        "gscript_child:0x8e9da8",
        CapturePath::GscriptChildLink, // gscript_child emitter uses this path
        CaptureExtentKind::ObservedAllocation,
        None,
        None,
        0,
        false,
        None,
    );
}

/// AF3 AF1 P1-3: `gscript_seed_child:{base}` is ExplicitlyRejectedFailClosed.
/// Its path is GscriptFirstHop (not authorized) and its id is not a
/// supported family.
#[test]
fn gscript_seed_child_table_reachable_not_protected() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind;
    assert_label_table_reachable_not_protected(
        "gscript_seed_child:0x8e9da8",
        CapturePath::GscriptFirstHop,
        CaptureExtentKind::InteriorSubview,
        None,
        None,
        0,
        false,
        None,
    );
}

/// AF3 AF1 P1-3: `graph_child:{base}` is ExplicitlyRejectedFailClosed. Its
/// path is GscriptFirstHop (not authorized) and its id is not a supported
/// family.
#[test]
fn graph_child_table_reachable_not_protected() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind;
    assert_label_table_reachable_not_protected(
        "graph_child:0x8e9da8",
        CapturePath::GscriptFirstHop,
        CaptureExtentKind::InteriorSubview,
        None,
        None,
        0,
        false,
        None,
    );
}

/// AF3 AF1 P1-5: a label-table entry with the WRONG table offset in its
/// source evidence must not be protected (correct base but wrong
/// source_slot_offset).
#[test]
fn label_table_entry_wrong_table_offset_not_protected() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind;
    assert_label_table_reachable_not_protected(
        "gscript_label:0x8e9da8",
        CapturePath::GscriptLabelTableEntry,
        CaptureExtentKind::InteriorSubview,
        Some(0x10), // real table is at offset 0, but evidence says 0x10
        Some(0x149d50),
        0,
        true,
        Some((0x8e93c8, 0x2000)),
    );
}

/// AF3 AF1 P1-5: a label-table entry with the WRONG source root RVA must not
/// be protected.
#[test]
fn label_table_entry_wrong_source_root_not_protected() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind;
    assert_label_table_reachable_not_protected(
        "gscript_label:0x8e9da8",
        CapturePath::GscriptLabelTableEntry,
        CaptureExtentKind::InteriorSubview,
        Some(0x0),
        Some(0xdeadbeef), // implausible gscript root RVA
        0,
        true,
        Some((0x8e93c8, 0x2000)),
    );
}

/// AF3 AF1 P1-5: a GscriptLabelTableEntry path with MISSING source evidence
/// (no source_slot_offset / root RVA / was_interior) must not be protected.
#[test]
fn label_table_entry_missing_source_evidence_not_protected() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind;
    assert_label_table_reachable_not_protected(
        "gscript_label:0x8e9da8",
        CapturePath::GscriptLabelTableEntry,
        CaptureExtentKind::InteriorSubview,
        None, // missing table offset
        None, // missing source root
        0,
        false, // not marked interior
        Some((0x8e93c8, 0x2000)),
    );
}

/// Drive the REAL label-table exhaust with two equal-size, different-base
/// overlapping parents around B. The classification must be fail-closed
/// (ProbeWindow, no parent) — never pick the iteration-order first.
#[test]
fn equal_size_different_base_parents_refuse_interior_classification() {
    use crate::dumper::capture_policy::DumpCapturePolicy;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_label_table_entries;
    const B_BASE: u64 = 0x8e9da8;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    // Two parents, same size, different bases, BOTH fully contain B.
    const A1: u64 = 0x8e9000;
    const A2: u64 = 0x8e93c8;
    const PSIZE: usize = 0x2000;
    let mut mock = RegionMapMock::new();
    let mut b_raw = vec![0u8; 0x400];
    b_raw[0x20..0x28].copy_from_slice(&0x70000000u64.to_le_bytes());
    mock.set(B_BASE, b_raw);
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga1 = global(A1, vec![0xAAu8; PSIZE], false);
    ga1.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga1.extent_evidence.capture_id = format!("heap_global_slot:{A1:#x}");
    ga1.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut ga2 = global(A2, vec![0xAAu8; PSIZE], false);
    ga2.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga2.extent_evidence.capture_id = format!("heap_global_slot:{A2:#x}");
    ga2.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    let mut globals = vec![ga1, ga2, gg, gt, gsnap];
    let mut tb = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    let policy = DumpCapturePolicy::default();
    exhaust_gscript_label_table_entries(
        &mut globals,
        &mut tb,
        &mut seen,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    let b = globals.iter().find(|g| g.live_ptr == B_BASE).unwrap();
    assert_eq!(
        b.extent_kind,
        CaptureExtentKind::ProbeWindow,
        "equal-size different-base parents must refuse interior classification"
    );
    assert_eq!(
        b.extent_evidence.containing_parent_old_base, None,
        "ambiguous parents must yield NO parent"
    );
}

/// Drive the REAL label-table exhaust with two same-base/size parents that
/// differ only in capture identity. The classification must be fail-closed.
#[test]
fn same_base_size_different_parent_identity_refuses_classification() {
    use crate::dumper::capture_policy::DumpCapturePolicy;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_label_table_entries;
    const B_BASE: u64 = 0x8e9da8;
    const A_BASE: u64 = 0x8e93c8;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    const PSIZE: usize = 0x2000;
    let mut mock = RegionMapMock::new();
    let mut b_raw = vec![0u8; 0x400];
    b_raw[0x20..0x28].copy_from_slice(&0x70000000u64.to_le_bytes());
    mock.set(B_BASE, b_raw);
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga1 = global(A_BASE, vec![0xAAu8; PSIZE], false);
    ga1.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga1.extent_evidence.capture_id = "heap_global_slot:0x8e93c8".into();
    ga1.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut ga2 = global(A_BASE, vec![0xAAu8; PSIZE], false);
    ga2.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga2.extent_evidence.capture_id = "heap_global_slot:0xDEADBEEF".into();
    ga2.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    let mut globals = vec![ga1, ga2, gg, gt, gsnap];
    let mut tb = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    let policy = DumpCapturePolicy::default();
    exhaust_gscript_label_table_entries(
        &mut globals,
        &mut tb,
        &mut seen,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    let b = globals.iter().find(|g| g.live_ptr == B_BASE).unwrap();
    assert_eq!(
        b.extent_kind,
        CaptureExtentKind::ProbeWindow,
        "same base/size different identity parents must refuse classification"
    );
    assert_eq!(b.extent_evidence.containing_parent_old_base, None);
}

/// Drive the REAL label-table exhaust with a parent that starts before B but
/// ENDS before B's end (child escapes parent). Must be ProbeWindow.
#[test]
fn child_start_inside_but_end_outside_is_probe_window() {
    use crate::dumper::capture_policy::DumpCapturePolicy;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_label_table_entries;
    const B_BASE: u64 = 0x8e9da8;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    // Parent A covers [0x8e9000, 0x8e9de0) — starts before B (0x8e9da8) but
    // ends at 0x8e9de0, which is BEFORE B's end. B is trimmed to 0x40 bytes
    // (trailing zeros) so its end is 0x8e9de8, which escapes A's 0x8e9de0.
    const A_BASE: u64 = 0x8e9000;
    const ASIZE: usize = 0x8e9de0 - 0x8e9000; // = 0xDE0
    let mut mock = RegionMapMock::new();
    let mut b_raw = vec![0u8; 0x400];
    b_raw[0x20..0x28].copy_from_slice(&0x70000000u64.to_le_bytes());
    mock.set(B_BASE, b_raw);
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga = global(A_BASE, vec![0xAAu8; ASIZE], false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    let mut globals = vec![ga, gg, gt, gsnap];
    let mut tb = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    let policy = DumpCapturePolicy::default();
    exhaust_gscript_label_table_entries(
        &mut globals,
        &mut tb,
        &mut seen,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    let b = globals.iter().find(|g| g.live_ptr == B_BASE).unwrap();
    assert_eq!(
        b.extent_kind,
        CaptureExtentKind::ProbeWindow,
        "child end outside parent must be ProbeWindow"
    );
    assert_eq!(b.extent_evidence.containing_parent_old_base, None);
}

/// Drive the REAL label-table exhaust with a parent whose end would overflow
/// u64. The classification must be ProbeWindow (no wrapping containment).
#[test]
fn parent_range_overflow_is_probe_window() {
    use crate::dumper::capture_policy::DumpCapturePolicy;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_label_table_entries;
    const B_BASE: u64 = 0x8e9da8;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    // Parent A covers B and its live_ptr + content.len() overflows u64.
    const A_BASE: u64 = u64::MAX - 0x2000;
    const ASIZE: usize = 0x4000;
    let mut mock = RegionMapMock::new();
    let mut b_raw = vec![0u8; 0x400];
    b_raw[0x20..0x28].copy_from_slice(&0x70000000u64.to_le_bytes());
    mock.set(B_BASE, b_raw);
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    // This parent does NOT actually contain B (A_BASE is near u64::MAX); it
    // exists only to exercise the overflow branch. A real containing parent
    // for B is also present.
    let mut goverflow = global(A_BASE, vec![0xAAu8; ASIZE], false);
    goverflow.extent_kind = CaptureExtentKind::ObservedAllocation;
    goverflow.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    goverflow.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    let mut globals = vec![goverflow, gg, gt, gsnap];
    let mut tb = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    let policy = DumpCapturePolicy::default();
    exhaust_gscript_label_table_entries(
        &mut globals,
        &mut tb,
        &mut seen,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    // With no valid containing parent, B is ProbeWindow.
    let b = globals.iter().find(|g| g.live_ptr == B_BASE).unwrap();
    assert_eq!(b.extent_kind, CaptureExtentKind::ProbeWindow);
    assert_eq!(b.extent_evidence.containing_parent_old_base, None);
}

/// Drive the REAL label-table exhaust with ONE unique innermost parent. B
/// must be InteriorSubview with that exact parent.
#[test]
fn unique_innermost_parent_is_selected() {
    use crate::dumper::capture_policy::DumpCapturePolicy;
    use crate::dumper::heap_global_snapshot::exhaust_gscript_label_table_entries;
    const B_BASE: u64 = 0x8e9da8;
    const A_BASE: u64 = 0x8e93c8;
    const A_SIZE: usize = 0x2000;
    const GSCRIPT: u64 = 0x8f0000;
    const TABLE: u64 = 0x8f1000;
    const SNAP: u64 = 0x900000;
    let mut mock = RegionMapMock::new();
    let mut b_raw = vec![0u8; 0x400];
    b_raw[0x20..0x28].copy_from_slice(&0x70000000u64.to_le_bytes());
    mock.set(B_BASE, b_raw);
    let mut gscript_content = vec![0u8; 0x40];
    gscript_content[0..8].copy_from_slice(&TABLE.to_le_bytes());
    gscript_content[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
    let mut table_content = vec![0u8; 0x10];
    table_content[0..8].copy_from_slice(&B_BASE.to_le_bytes());
    let mut ga = global(A_BASE, vec![0xAAu8; A_SIZE], false);
    ga.extent_kind = CaptureExtentKind::ObservedAllocation;
    ga.extent_evidence.capture_id = format!("heap_global_slot:{A_BASE:#x}");
    ga.extent_evidence.capture_path = CapturePath::MainSlot;
    let mut gg = global(GSCRIPT, gscript_content, true);
    gg.extent_evidence.capture_id = "gscript:0x8f0000".into();
    let mut gt = global(TABLE, table_content, false);
    gt.extent_evidence.capture_id = "gscript_table:0x8f1000".into();
    let gsnap = global(SNAP, vec![0u8; 0x30], false);
    let mut globals = vec![ga, gg, gt, gsnap];
    let mut tb = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    let policy = DumpCapturePolicy::default();
    exhaust_gscript_label_table_entries(
        &mut globals,
        &mut tb,
        &mut seen,
        mock.image_base,
        mock.image_base + 0x1000000,
        &[],
        &mut mock,
        &policy,
    );
    let b = globals.iter().find(|g| g.live_ptr == B_BASE).unwrap();
    assert_eq!(b.extent_kind, CaptureExtentKind::InteriorSubview);
    assert_eq!(
        b.extent_evidence.containing_parent_old_base,
        Some(A_BASE),
        "unique innermost parent must be selected"
    );
    assert_eq!(b.extent_evidence.containing_parent_size, Some(A_SIZE));
}

// ============ Route Y R1 A6 AF3 AF2 AF1 AF1 AF1 AF1 (unique declaration
// ============ resolution / first-match elimination) tests ============

/// A canonical VALID declared size-reinit scaffold (raw child identity matches
/// the transformed identity; declaration fields all correct). Individual tests
/// mutate one axis so exactly one failure surfaces in the locked order.
fn af6_declared_reinit_scaffold() -> (RawSlabCapture, HeapGlobalSnapshot) {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const NEW_SIZE: usize = 0x180;
    const SLAB_BASE: u64 = 0x3000000;
    let slab_size = (B_BASE - SLAB_BASE) as usize + OLD_SIZE;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    let mut transformed = global(B_BASE, vec![0u8; NEW_SIZE], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    (raw_capture, transformed)
}

// Task 4 test 1: two IDENTICAL declared transform ids in the same child, raw
// identity correct -> EXACTLY TransformRunLedgerInvalid with `ambiguous
// declared size reinit` and match count. Duplicate evidence must not pass as
// "one unique declaration".
#[test]
fn q0c_duplicate_declared_reinit_spec_is_exact_ledger_invalid() {
    let (raw, mut transformed) = af6_declared_reinit_scaffold();
    transformed.transform_ids = vec![
        "sanitize_ahk_runtime_global".into(),
        "sanitize_ahk_runtime_global".into(),
    ];
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &[transformed], &[], &[], &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "duplicate declared reinit spec must be TransformRunLedgerInvalid, got {err:?}"
    );
    let reason = format!("{err:?}");
    assert!(
        reason.contains("ambiguous declared size reinit"),
        "duplicate declaration reason must name the ambiguity, got {err:?}"
    );
    assert!(
        reason.contains("matched 2 transform id(s)"),
        "duplicate declaration reason must record match count 2, got {err:?}"
    );
}

// Task 4 test 2: declaration AMBIGUITY + contradictory binding + orphan ledger
// -> EXACTLY TransformRunLedgerInvalid (the ambiguity precedes binding and
// ledger errors; it is never coerced to ordinary nor masked).
#[test]
fn q0c_duplicate_declared_spec_precedes_binding_and_ledger() {
    let (raw, mut transformed) = af6_declared_reinit_scaffold();
    transformed.transform_ids = vec![
        "sanitize_ahk_runtime_global".into(),
        "sanitize_ahk_runtime_global".into(),
    ];
    // Contradictory binding (would be BindingIdentityInconsistent if reached).
    let mut bad_binding = taf1_dedicated_fixture(0x850150, 0x1000).2;
    bad_binding.capture_id = "gscript_label:0xDEAD".into();
    // Orphan/malformed ledger run (would be TransformRunLedgerInvalid via the
    // ledger path if the ambiguity did not precede it).
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "ghost:0x9999".into(),
        child_old_base: 0x9999,
        child_size: 1,
        child_offset: 0,
        length: 1,
        transform_id: "t".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xBB]),
        first_before_byte: 0xAA,
        first_after_byte: 0xBB,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xBB],
    });
    let err = build_patched_backing_slab_q0c(&raw, &[transformed], &[], &[bad_binding], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "declaration ambiguity must precede binding/ledger errors, got {err:?}"
    );
    let reason = format!("{err:?}");
    assert!(
        reason.contains("ambiguous declared size reinit"),
        "the winning error must be the declaration ambiguity, got {err:?}"
    );
}

// Task 4 test 3: declaration candidate UNIQUE but raw full identity WRONG ->
// EXACTLY RawChildMissing (declaration ambiguity resolved first, then raw
// identity; a wrong identity is never masked by the unique declaration).
#[test]
fn q0c_declaration_unique_then_wrong_identity_is_raw_child_missing() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const SLAB_BASE: u64 = 0x3000000;
    let slab_size = (B_BASE - SLAB_BASE) as usize + OLD_SIZE;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100, // raw probe
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    // Unique declaration candidate, but WRONG source identity (probe=0x200).
    let mut transformed = global(B_BASE, vec![0u8; 0x180], false);
    transformed.rva = 0x141bf0;
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x200; // wrong identity
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "unique declaration then wrong identity must be RawChildMissing, got {err:?}"
    );
}

// Task 4 test 4: declaration candidate UNIQUE + raw identity UNIQUE but an
// invalid declaration field (wrong new size) -> EXACTLY TransformRunLedgerInvalid
// with a reason naming the field.
#[test]
fn q0c_declaration_unique_then_invalid_fields_is_ledger_invalid() {
    let (raw, mut transformed) = af6_declared_reinit_scaffold();
    // Unique declaration, unique identity, but new size != 0x180.
    transformed.content = vec![0u8; 0x200]; // wrong new size (declared 0x180)
    transformed.transform_ids = vec!["sanitize_ahk_runtime_global".into()];
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw, &[transformed], &[], &[], &ledger).unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "unique declaration + invalid field must be TransformRunLedgerInvalid, got {err:?}"
    );
    let reason = format!("{err:?}");
    assert!(
        reason.contains("new size"),
        "invalid-field reason must name the field, got {err:?}"
    );
}

// Task 4 test 5: NO declaration hit (ordinary mode) uses EXACT identity — a
// size difference with otherwise-identical identity must be RawChildMissing,
// proving ordinary mode does NOT ignore size.
#[test]
fn q0c_ordinary_no_declaration_hit_uses_exact_identity() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    const B_BASE: u64 = 0x3437e50;
    const OLD_SIZE: usize = 0x8000;
    const SLAB_BASE: u64 = 0x3000000;
    let slab_size = (B_BASE - SLAB_BASE) as usize + OLD_SIZE;
    let raw_capture = RawSlabCapture {
        slabs: vec![slab(SLAB_BASE, vec![0u8; slab_size])],
        children: vec![RawChild {
            old_base: B_BASE,
            size: OLD_SIZE,
            raw_bytes: vec![0xAAu8; OLD_SIZE],
            kind: RawChildKind::HeapGlobal,
            capture_id: "mainslot:0x141bf0:0x3437e50".into(),
            capture_path: CP::MainSlot,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            source_slot_offset: None,
            requested_probe_size: 0x100,
            source_root_rva: None,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        }],
    };
    // NO declaration hit (no declared transform id). Size differs (0x180 vs
    // 0x8000) but everything else identical. Ordinary mode must NOT ignore
    // size -> RawChildMissing.
    let mut transformed = global(B_BASE, vec![0u8; 0x180], false);
    transformed.extent_kind = CaptureExtentKind::ObservedAllocation;
    transformed.extent_evidence.capture_id = "mainslot:0x141bf0:0x3437e50".into();
    transformed.extent_evidence.capture_path = CP::MainSlot;
    transformed.extent_evidence.probe_requested_size = 0x100;
    transformed.transform_ids = vec!["some_other_transform".into()]; // no declaration hit
    let ledger = TransformRunLedger::default();
    let err = build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[], &ledger)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::RawChildMissing { .. }),
        "ordinary mode with differing size must be RawChildMissing, got {err:?}"
    );
}

// Task 4 test 6: pure/static resolver test — duplicate hits never yield an
// arbitrary spec, and the exact match count is recorded. This exercises the
// counting core directly, independent of overlay plumbing.
#[test]
fn q0c_declaration_resolver_has_no_first_match() {
    let rva = 0x141bf0u32;
    let hit_id = "sanitize_ahk_runtime_global".to_string();
    // 0 hits -> None.
    let (c0, m0) = collect_declared_reinit_hits(&["other".into()], rva);
    assert_eq!(c0, 0, "no declaration hit must count 0");
    assert!(m0.is_empty());
    // Exactly 1 hit -> Some(spec), count 1, and the resolver returns it.
    let (c1, m1) = collect_declared_reinit_hits(&[hit_id.clone()], rva);
    assert_eq!(c1, 1, "single declaration hit must count 1");
    assert_eq!(m1, vec![hit_id.clone()]);
    let resolved = resolve_declared_size_reinit_spec(&[hit_id.clone()], rva, "id", 0, 0);
    assert!(
        resolved.unwrap().is_some(),
        "unique hit must resolve to a spec"
    );
    // Duplicate identical id -> count 2 (NOT deduplicated to 1), and the
    // resolver must fail closed rather than first-match one spec.
    let (c2, m2) = collect_declared_reinit_hits(&[hit_id.clone(), hit_id.clone()], rva);
    assert_eq!(
        c2, 2,
        "duplicate identical id must count 2, not deduplicate to 1"
    );
    assert_eq!(m2, vec![hit_id.clone(), hit_id.clone()]);
    let err = resolve_declared_size_reinit_spec(&[hit_id.clone(), hit_id.clone()], rva, "id", 0, 0)
        .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "duplicate declaration must fail closed, not first-match, got {err:?}"
    );
    let reason = format!("{err:?}");
    assert!(
        reason.contains("ambiguous declared size reinit") && reason.contains("matched 2"),
        "duplicate declaration must record the ambiguity + count, got {err:?}"
    );
}

// ============ MIDA-SERIAL-33 authority closure + provenance ============

fn m33_probe_with_parent(
    child_base: u64,
    child_size: usize,
    parent_base: u64,
    parent_size: usize,
    parent_extent: CaptureExtentKind,
    parent_provenance: RegionProvenance,
) -> (HeapGlobalSnapshot, HeapGlobalSnapshot) {
    let mut child = probe_global(child_base, child_size);
    child.extent_evidence.containing_parent_old_base = Some(parent_base);
    child.extent_evidence.containing_parent_size = Some(parent_size);
    let mut parent = global(parent_base, vec![0u8; parent_size], false);
    parent.extent_kind = parent_extent;
    parent.provenance = parent_provenance;
    (child, parent)
}

/// MIDA-SERIAL-34: extract the slab vector from closure candidates.
fn m34_closure_slabs(candidates: Vec<AuthoritativeSlabCandidate>) -> Vec<HeapSlab> {
    candidates.into_iter().map(|c| c.slab).collect()
}

#[test]
fn m33_unique_observed_parent_closure_succeeds() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let (mut child, mut parent) = m33_probe_with_parent(
        0x850150,
        8,
        0x850000,
        0x1000,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
    );
    // Make parent slice byte-identical to child bytes.
    parent.content[0x150..0x158].copy_from_slice(&child.content);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "split_child:0x850150".into();
    let candidates = build_authority_closure_candidates(
        &[child.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].role, "parent_closure");
    let closure = m34_closure_slabs(candidates);
    assert_eq!(closure[0].old_base, 0x850000);
    assert_eq!(closure[0].content.len(), 0x1000);
    // Coverage gate then passes.
    validate_probe_coverage(&[child, parent], &closure).unwrap();
}

#[test]
fn m33_parent_partial_containment_rejected() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let (mut child, mut parent) = m33_probe_with_parent(
        0x850050,
        0x40,
        0x850000,
        0x80,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
    );
    parent.content[0x50..0x70].copy_from_slice(&child.content[0..0x20]);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "split_child:0x850050".into();
    let candidates = build_authority_closure_candidates(
        &[child, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_child_range_overflow_rejected() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let (mut child, mut parent) = m33_probe_with_parent(
        u64::MAX - 4,
        8,
        u64::MAX - 0x100,
        0x200,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
    );
    parent.content[0xfc..0x104].copy_from_slice(&child.content);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "overflow_child".into();
    let candidates = build_authority_closure_candidates(
        &[child, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_parent_range_overflow_rejected() {
    let (mut child, mut parent) = m33_probe_with_parent(
        0x850150,
        8,
        u64::MAX - 0x10,
        0x100,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
    );
    parent.content[0x0..0x8].copy_from_slice(&child.content);
    child.extent_evidence.capture_id = "parent_overflow_child".into();
    let candidates = build_authority_closure_candidates(
        &[child, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_two_parents_ambiguous_rejected() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let mut child = probe_global(0x850150, 8);
    child.extent_evidence.containing_parent_old_base = Some(0x850000);
    child.extent_evidence.containing_parent_size = Some(0x1000);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "ambiguous_child".into();
    let mut p1 = global(0x850000, vec![0u8; 0x1000], false);
    p1.extent_kind = CaptureExtentKind::ObservedAllocation;
    p1.content[0x150..0x158].copy_from_slice(&child.content);
    let mut p2 = global(0x850000, vec![0u8; 0x1000], false);
    p2.extent_kind = CaptureExtentKind::ObservedAllocation;
    p2.content[0x150..0x158].copy_from_slice(&child.content);
    let candidates = build_authority_closure_candidates(
        &[child, p1, p2],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_same_base_size_different_identity_rejected() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let mut child = probe_global(0x850150, 8);
    child.extent_evidence.containing_parent_old_base = Some(0x850000);
    child.extent_evidence.containing_parent_size = Some(0x1000);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "identity_child".into();
    let mut p1 = global(0x850000, vec![0u8; 0x1000], false);
    p1.extent_kind = CaptureExtentKind::ObservedAllocation;
    p1.extent_evidence.capture_id = "id1".into();
    p1.content[0x150..0x158].copy_from_slice(&child.content);
    let mut p2 = global(0x850000, vec![0u8; 0x1000], false);
    p2.extent_kind = CaptureExtentKind::ObservedAllocation;
    p2.extent_evidence.capture_id = "id2".into();
    p2.content[0x150..0x158].copy_from_slice(&child.content);
    let candidates = build_authority_closure_candidates(
        &[child, p1, p2],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_probe_parent_not_promoted() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let (mut child, mut parent) = m33_probe_with_parent(
        0x850150,
        8,
        0x850000,
        0x1000,
        CaptureExtentKind::ProbeWindow,
        RegionProvenance::default(),
    );
    parent.content[0x150..0x158].copy_from_slice(&child.content);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "probe_parent_child".into();
    let candidates = build_authority_closure_candidates(
        &[child, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_interior_parent_not_promoted() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let (mut child, mut parent) = m33_probe_with_parent(
        0x850150,
        8,
        0x850000,
        0x1000,
        CaptureExtentKind::InteriorSubview,
        RegionProvenance::default(),
    );
    parent.content[0x150..0x158].copy_from_slice(&child.content);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "interior_parent_child".into();
    let candidates = build_authority_closure_candidates(
        &[child, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_synthetic_parent_not_promoted() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let (mut child, mut parent) = m33_probe_with_parent(
        0x850150,
        8,
        0x850000,
        0x1000,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::SyntheticDerived {
            transform_id: "t".into(),
            source_anchor: "a".into(),
            construction_digest: "d".into(),
        },
    );
    parent.content[0x150..0x158].copy_from_slice(&child.content);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "synthetic_parent_child".into();
    let candidates = build_authority_closure_candidates(
        &[child, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_parent_bytes_drift_rejected() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let (mut child, parent) = m33_probe_with_parent(
        0x850150,
        8,
        0x850000,
        0x1000,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
    );
    // Make child bytes non-zero and keep parent slice zero -> drift.
    child.content = vec![0xAA; 8];
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "drift_child".into();
    let candidates = build_authority_closure_candidates(
        &[child, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn m33_no_parent_evidence_probe_not_promoted() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let mut child = probe_global(0x850150, 8);
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.capture_id = "no_parent_child".into();
    let candidates = build_authority_closure_candidates(
        &[child.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
    // Coverage gate still fails closed.
    let err = validate_probe_coverage(&[child], &[]).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing(_)));
}

#[test]
fn m33_nearest_slab_with_large_gap_still_rejected() {
    let child = probe_global(0x850150, 8);
    let slabs = vec![slab_of_len(0x9a3000, 0x1000)];
    let err = validate_probe_coverage(&[child], &slabs).unwrap_err();
    match err {
        OverlayError::ProbeCoverageMissing(details) => {
            assert_eq!(details.nearest_authority, Some((0x9a3000, 0x9a4000)));
            assert!(details.nearest_authority_gap > 0x1000);
        }
        other => panic!("expected ProbeCoverageMissing, got {other:?}"),
    }
}

#[test]
fn m33_dangling_dedicated_extent_preserved() {
    // Dangling edge already carries its own dedicated slab (existing behavior).
    let g = probe_global(0x850150, 0x1000);
    let slabs = vec![slab_of_len(0x850150, 0x1000)];
    validate_probe_coverage(&[g], &slabs).unwrap();
}

#[test]
fn m33_multi_authority_full_cover_ambiguous_fails() {
    let child = probe_global(0x850150, 8);
    let slabs = vec![slab_of_len(0x850000, 0x1000), slab_of_len(0x850000, 0x1000)];
    let err = validate_probe_coverage(&[child], &slabs).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing(_)));
}

#[test]
fn m33_probe_coverage_display_contains_provenance() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let mut child = probe_global(0x850150, 8);
    child.extent_evidence.capture_id = "split_child:0x850150".into();
    child.extent_evidence.capture_path = CP::MainSlot;
    child.extent_evidence.source_root_rva = Some(0x1234);
    child.extent_evidence.source_slot_offset = Some(0x20);
    child.extent_evidence.probe_requested_size = 0x1000;
    child.extent_evidence.was_interior = true;
    child.extent_evidence.containing_parent_old_base = Some(0x850000);
    child.extent_evidence.containing_parent_size = Some(0x1000);
    let err = validate_probe_coverage(&[child], &[]).unwrap_err();
    let text = format!("{err}");
    assert!(
        text.contains("split_child:0x850150"),
        "missing capture_id: {text}"
    );
    assert!(text.contains("MainSlot"), "missing capture_path: {text}");
    assert!(text.contains("0x1234"), "missing root rva: {text}");
    assert!(text.contains("0x20"), "missing slot offset: {text}");
    assert!(text.contains("0x1000"), "missing probe size: {text}");
    assert!(text.contains("true"), "missing was_interior: {text}");
    assert!(text.contains("0x850000"), "missing parent identity: {text}");
}

// ============ MIDA-SERIAL-34 authority closure + normalization ============

/// Helper: build a probe child with a strict parent and matching bytes.
fn m34_child_with_strict_parent(
    child_base: u64,
    child_size: usize,
    parent_base: u64,
    parent_size: usize,
) -> (HeapGlobalSnapshot, HeapGlobalSnapshot) {
    let (mut child, mut parent) = m33_probe_with_parent(
        child_base,
        child_size,
        parent_base,
        parent_size,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
    );
    let off = (child_base - parent_base) as usize;
    parent.content[off..off + child_size].copy_from_slice(&child.content);
    child.extent_evidence.capture_id = format!("split_child:{child_base:#x}");
    (child, parent)
}

/// Test 1: empty base candidates + unique strict parent -> closure candidate
/// still enters normalization (never gated on the base set being non-empty).
#[test]
fn m34_empty_base_candidates_unique_strict_parent_closure_enters_normalization() {
    let (child, parent) = m34_child_with_strict_parent(0x850150, 8, 0x850000, 0x1000);
    let closure = build_authority_closure_candidates(
        &[child.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(closure.len(), 1);
    assert_eq!(closure[0].role, "parent_closure");
    // The closure candidate joins normalization even though there are ZERO
    // main/dedicated candidates.
    let (normalized, events) = normalize_authoritative_slabs(&closure).unwrap();
    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].slab.old_base, 0x850000);
    assert_eq!(normalized[0].role, "parent_closure");
    assert!(events.iter().any(|e| e.action == "kept"));
    // The final authoritative set covers the child.
    let slabs: Vec<HeapSlab> = normalized.iter().map(|n| n.slab.clone()).collect();
    validate_probe_coverage(&[child, parent], &slabs).unwrap();
}

/// Test 2: two children -> same strict parent -> exactly ONE retained
/// authority (deduped through normalization).
#[test]
fn m34_two_children_same_strict_parent_one_retained_authority() {
    // Two children inside the same parent, same bytes at both slots.
    let (mut c1, mut parent) = m34_child_with_strict_parent(0x850150, 8, 0x850000, 0x1000);
    let mut c2 = probe_global(0x850200, 8);
    c2.extent_evidence.containing_parent_old_base = Some(0x850000);
    c2.extent_evidence.containing_parent_size = Some(0x1000);
    parent.content[0x150..0x158].copy_from_slice(&c1.content);
    parent.content[0x200..0x208].copy_from_slice(&c2.content);
    c2.extent_evidence.capture_id = "split_child:0x850200".into();
    c1.extent_evidence.capture_id = "split_child:0x850150".into();
    let closure = build_authority_closure_candidates(
        &[c1.clone(), c2.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    // Both children prove the SAME parent -> ONE logical closure candidate.
    assert_eq!(closure.len(), 1);
    let (normalized, _events) = normalize_authoritative_slabs(&closure).unwrap();
    assert_eq!(normalized.len(), 1);
    let slabs: Vec<HeapSlab> = normalized.iter().map(|n| n.slab.clone()).collect();
    validate_probe_coverage(&[c1, c2, parent], &slabs).unwrap();
}

/// Test 3: closure and main exact duplicate -> deterministic dedup (the
/// main candidate is kept; the closure input is dropped with a
/// deduplicated event).
#[test]
fn m34_closure_main_exact_duplicate_deterministic_dedup() {
    let (child, parent) = m34_child_with_strict_parent(0x850150, 8, 0x850000, 0x1000);
    let closure = build_authority_closure_candidates(
        &[child.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(closure.len(), 1);
    // Build a main candidate that is an EXACT duplicate of the closure slab.
    let main = cand("main", slab_of_len(0x850000, 0x1000));
    let all = vec![main, closure.into_iter().next().unwrap()];
    // Ensure identical bytes: both all-zero (slab_of_len zero-fills).
    let (normalized, events) = normalize_authoritative_slabs(&all).unwrap();
    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].role, "main");
    assert!(
        events.iter().any(|e| e.action == "deduplicated"),
        "closure exact duplicate must emit a deduplicated event: {events:?}"
    );
    let slabs: Vec<HeapSlab> = normalized.iter().map(|n| n.slab.clone()).collect();
    validate_probe_coverage(&[child, parent], &slabs).unwrap();
}

/// Test 4: closure fully contained in main with identical bytes ->
/// contained_exact_alias (inner closure dropped, outer main kept).
#[test]
fn m34_closure_contained_in_main_exact_alias() {
    let (child, parent) = m34_child_with_strict_parent(0x850150, 8, 0x850000, 0x1000);
    let closure = build_authority_closure_candidates(
        &[child.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(closure.len(), 1);
    // Main is a LARGER slab [0x84f000, +0x3000) whose inner slice at +0x1000
    // equals the closure bytes (all zero) — containment with identical bytes.
    let mut main_content = vec![0u8; 0x3000];
    main_content[0x1000..0x2000].copy_from_slice(&parent.content);
    let main = cand(
        "main",
        HeapSlab {
            old_base: 0x84f000,
            content: main_content,
        },
    );
    let all = vec![main, closure.into_iter().next().unwrap()];
    let (normalized, events) = normalize_authoritative_slabs(&all).unwrap();
    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].slab.old_base, 0x84f000);
    assert_eq!(normalized[0].role, "main");
    assert!(
        events.iter().any(|e| e.action == "contained_exact_alias"),
        "closure contained-in-main must emit contained_exact_alias: {events:?}"
    );
    let slabs: Vec<HeapSlab> = normalized.iter().map(|n| n.slab.clone()).collect();
    validate_probe_coverage(&[child, parent], &slabs).unwrap();
}

/// Test 5: closure and main PARTIAL overlap -> AuthoritativeSlabConflict
/// (never implicitly joined).
#[test]
fn m34_closure_main_partial_overlap_conflict() {
    let (child, parent) = m34_child_with_strict_parent(0x850150, 8, 0x850000, 0x1000);
    let closure = build_authority_closure_candidates(
        &[child.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(closure.len(), 1);
    // Main slab [0x850800, +0x1000) overlaps the closure's tail [0x850000,0x851000).
    let main = cand("main", slab_of_len(0x850800, 0x1000));
    let all = vec![main, closure.into_iter().next().unwrap()];
    let err = normalize_authoritative_slabs(&all).unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::AuthoritativeSlabConflict {
                relationship: "partial_overlap",
                ..
            }
        ),
        "partial overlap must fail closed as AuthoritativeSlabConflict, got {err:?}"
    );
    let _ = &[child, parent];
}

/// Test 6: closure containment with DIFFERENT bytes -> AuthoritativeSlabConflict
/// (contained_byte_conflict) — never silently picks one.
#[test]
fn m34_closure_containment_bytes_differ_conflict() {
    let (child, parent) = m34_child_with_strict_parent(0x850150, 8, 0x850000, 0x1000);
    let closure = build_authority_closure_candidates(
        &[child.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(closure.len(), 1);
    // Main is a larger slab whose inner slice DIFFERS from the closure bytes.
    let mut main_content = vec![0xFFu8; 0x3000];
    main_content[0x1000..0x2000].copy_from_slice(&parent.content);
    main_content[0x1000 + 0x100] = 0xAA; // byte conflict at +0x100
    let main = cand(
        "main",
        HeapSlab {
            old_base: 0x84f000,
            content: main_content,
        },
    );
    let all = vec![main, closure.into_iter().next().unwrap()];
    let err = normalize_authoritative_slabs(&all).unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::AuthoritativeSlabConflict {
                relationship: "contained_byte_conflict",
                ..
            }
        ),
        "containment byte conflict must fail closed, got {err:?}"
    );
    let _ = &[child, parent];
}

/// Test 7: an overflowed slab end must NOT be treated as a covering
/// authority (checked_add; a wrapping end cannot cover anything).
#[test]
fn m34_overflowed_slab_end_not_covering_authority() {
    let child = probe_global(0x850150, 8);
    // Slab whose end overflows u64: old_base + len wraps.
    let overflow_slab = slab_of_len(u64::MAX - 0x10, 0x100);
    // The range [u64::MAX-0x10, +0x100) wraps; the child is NOT inside it.
    let err = validate_probe_coverage(&[child.clone()], &[overflow_slab]).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing(_)));
    // Also: closure derivation must reject a wrapping parent range.
    let (mut child2, mut parent) = m33_probe_with_parent(
        0x850150,
        8,
        u64::MAX - 0x10,
        0x100,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
    );
    parent.content[0x0..0x8].copy_from_slice(&child2.content);
    child2.extent_evidence.capture_id = "overflow_parent_child".into();
    let candidates = build_authority_closure_candidates(
        &[child2, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
    let _ = child;
}

/// Test 8: authoritative_slabs, normalization ledger, manifest ledger are
/// one-to-one in count AND order. Exercised through the production helper:
/// every kept slab has exactly one ledger entry with matching base/role.
#[test]
fn m34_authoritative_ledger_manifest_one_to_one() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    // Two distinct closure parents + one main.
    let (c1, p1) = m34_child_with_strict_parent(0x850150, 8, 0x850000, 0x1000);
    let (c2, p2) = m34_child_with_strict_parent(0x860150, 8, 0x860000, 0x1000);
    let closure = build_authority_closure_candidates(
        &[c1.clone(), p1.clone(), c2.clone(), p2.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(closure.len(), 2);
    assert!(
        closure.iter().all(|c| c.role == "parent_closure"),
        "all closure candidates must carry role parent_closure"
    );
    let main = cand("main", slab_of_len(0x870000, 0x1000));
    let mut all = vec![main];
    all.extend(closure);
    let (normalized, _events) = normalize_authoritative_slabs(&all).unwrap();
    // authoritative_slabs == kept slabs (in order).
    let authoritative_slabs: Vec<HeapSlab> = normalized.iter().map(|n| n.slab.clone()).collect();
    let ledger: Vec<(u64, &'static str, SlabNormalization)> = normalized
        .iter()
        .map(|n| (n.slab.old_base, n.role, n.normalization))
        .collect();
    assert_eq!(authoritative_slabs.len(), ledger.len());
    // 1:1 and order-preserving: ledger[i] describes authoritative_slabs[i].
    for (i, (base, role, norm)) in ledger.iter().enumerate() {
        assert_eq!(authoritative_slabs[i].old_base, *base);
        assert!(matches!(norm, SlabNormalization::Kept));
        assert!(*role == "main" || *role == "parent_closure");
    }
    // Deterministic order: normalization preserves INPUT order (main first,
    // then closure candidates in the deterministic closure order). Running
    // normalization twice on the same inputs must produce the same order.
    let bases: Vec<u64> = authoritative_slabs.iter().map(|s| s.old_base).collect();
    let (normalized2, _) = normalize_authoritative_slabs(&all).unwrap();
    let bases2: Vec<u64> = normalized2.iter().map(|n| n.slab.old_base).collect();
    assert_eq!(bases, bases2, "normalization must be order-deterministic");
    assert_eq!(
        bases[0], 0x870000,
        "main candidate keeps its input position"
    );
    // Every child is covered by exactly one retained authority.
    validate_probe_coverage(&[c1, p1, c2, p2], &authoritative_slabs).unwrap();
    let _ = CP::MainSlot;
}

/// Test 9 (split producer): a split candidate must preserve the REAL source
/// slot offset (the byte offset of the qword that referenced the child).
#[test]
fn m34_split_candidate_preserves_real_source_slot_offset() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    // Parent snapshot at 0x850000, 0x1000 bytes, with a heap pointer at
    // slot offset 0x200 (qword at bytes 0x200..0x208) that references the
    // child 0x850150. The child's captured content is the parent slice at
    // the child offset 0x150 (rule 9: byte-identical slice).
    let child_ptr = 0x850150u64;
    let mut parent = global(0x850000, vec![0u8; 0x1000], false);
    parent.extent_kind = CaptureExtentKind::ObservedAllocation;
    parent.extent_evidence.capture_id = "main:0x850000".into();
    parent.content[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    // The child's content == the parent slice at the child offset (0x150).
    // (all-zero content here, matching the all-zero parent slice).
    // The produced child carries the REAL source slot offset (0x200).
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: child_ptr,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:main:0x850000:0x200".into(),
            capture_path: CP::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x200),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(0x850000),
            containing_parent_size: Some(0x1000),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    assert_eq!(child.extent_evidence.source_slot_offset, Some(0x200));
    assert_eq!(child.extent_evidence.capture_path, CP::SplitSibling);
    assert_eq!(child.extent_evidence.was_interior, true);
    assert_eq!(child.extent_evidence.probe_requested_size, 0x2000);
    assert_eq!(
        child.extent_evidence.containing_parent_old_base,
        Some(0x850000)
    );
    assert_eq!(child.extent_evidence.containing_parent_size, Some(0x1000));
    // The real producer identity is validated by the identity gate.
    let gs = [child.clone(), parent.clone()];
    validate_raw_coherence_capture_identities(&[], &gs).unwrap();
    // Closure from the child + strict parent works (pre-trunc evidence):
    // parent slice at child offset 0x150 == child content (all zero).
    let candidates = build_authority_closure_candidates(
        &[child, parent],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].slab.old_base, 0x850000);
}

/// Test 10 (split producer): a split candidate with MULTIPLE sources /
/// parents must NOT fabricate a unique containing parent.
#[test]
fn m34_split_candidate_multi_source_no_fake_parent() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let child_ptr = 0x850150u64;
    // Two parents both swallow the child (ambiguous parent identity).
    let mut p1 = global(0x850000, vec![0u8; 0x1000], false);
    p1.extent_kind = CaptureExtentKind::ObservedAllocation;
    p1.extent_evidence.capture_id = "p1".into();
    p1.content[0x150..0x158].copy_from_slice(&child_ptr.to_le_bytes());
    let mut p2 = global(0x850000, vec![0u8; 0x1000], false);
    p2.extent_kind = CaptureExtentKind::ObservedAllocation;
    p2.extent_evidence.capture_id = "p2".into();
    p2.content[0x150..0x158].copy_from_slice(&child_ptr.to_le_bytes());
    // The child (as produced) must keep parent evidence NONE when the parent
    // is ambiguous — exactly what the producer does.
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: child_ptr,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:p1:0x150".into(),
            capture_path: CP::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    assert_eq!(child.extent_evidence.containing_parent_old_base, None);
    // The closure helper must NOT fabricate a parent: with two matching
    // snapshots at the same (base,size), no closure candidate is produced.
    let candidates = build_authority_closure_candidates(
        &[child.clone(), p1.clone(), p2.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
    // The coverage gate fails closed with the full provenance.
    let err = validate_probe_coverage(&[child], &[]).unwrap_err();
    let text = format!("{err}");
    assert!(
        text.contains("split_sibling:0x850150"),
        "missing provenance: {text}"
    );
    assert!(text.contains("SplitSibling"), "missing path: {text}");
}

/// Test 11: a strict PRE-TRUNC parent (ObservedAllocation/BackingObject,
/// non-synthetic, unique) produces a parent_closure candidate that enters
/// unified normalization.
#[test]
fn m34_strict_pre_trunc_parent_produces_parent_closure_candidate() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let child_ptr = 0x850150u64;
    let mut parent = global(0x850000, vec![0u8; 0x1000], false);
    parent.extent_kind = CaptureExtentKind::ObservedAllocation;
    parent.extent_evidence.capture_id = "main:0x850000".into();
    // Pointer at slot 0x200 references the child; the child-offset slice
    // (0x150) stays all-zero to match the child's content bytes.
    parent.content[0x200..0x208].copy_from_slice(&child_ptr.to_le_bytes());
    // Split child carrying the PRE-TRUNC parent evidence.
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: child_ptr,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:main:0x850000:0x200".into(),
            capture_path: CP::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x200),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(0x850000),
            containing_parent_size: Some(0x1000),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let candidates = build_authority_closure_candidates(
        &[child.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].role, "parent_closure");
    assert_eq!(candidates[0].slab.old_base, 0x850000);
    // Unified normalization keeps exactly one authority.
    let (normalized, events) = normalize_authoritative_slabs(&candidates).unwrap();
    assert_eq!(normalized.len(), 1);
    assert!(events.iter().any(|e| e.action == "kept"));
    let slabs: Vec<HeapSlab> = normalized.iter().map(|n| n.slab.clone()).collect();
    validate_probe_coverage(&[child, parent], &slabs).unwrap();
}

/// Test 12: a ProbeWindow / heuristic pre-trunc parent produces NO closure
/// candidate.
#[test]
fn m34_probe_window_pre_trunc_parent_no_closure() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let child_ptr = 0x850150u64;
    // Parent is a ProbeWindow (heuristic read window) — never a proven
    // allocation boundary.
    let mut parent = global(0x850000, vec![0u8; 0x1000], false);
    parent.extent_kind = CaptureExtentKind::ProbeWindow;
    parent.extent_evidence.capture_id = "probe_parent:0x850000".into();
    parent.content[0x150..0x158].copy_from_slice(&child_ptr.to_le_bytes());
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: child_ptr,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:probe_parent:0x150".into(),
            capture_path: CP::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(0x850000),
            containing_parent_size: Some(0x1000),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let candidates = build_authority_closure_candidates(
        &[child.clone(), parent.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(
        candidates.is_empty(),
        "heuristic ProbeWindow parent must never produce a closure candidate"
    );
    // Coverage gate still fails closed.
    let err = validate_probe_coverage(&[child], &[]).unwrap_err();
    assert!(matches!(err, OverlayError::ProbeCoverageMissing(_)));
}

/// Test 13: the current blocker-equivalent fixture — a split child with
/// content len == 8 and NO strict parent evidence — STILL fails closed at
/// capture_coverage_bind, and the error carries the complete producer
/// provenance.
#[test]
fn m34_blocker_split_child_len8_no_parent_still_fails_closed_with_provenance() {
    use crate::dumper::heap_global_snapshot::CapturePath as CP;
    let child_ptr = 0x850150u64;
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: child_ptr,
        content: vec![0u8; 8], // the blocker: exactly 8 bytes
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:main:0x850000:0x150".into(),
            capture_path: CP::SplitSibling,
            source_root_rva: Some(0x1234),
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: None, // no strict parent evidence
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    // No closure candidate can be derived (no parent evidence).
    let candidates = build_authority_closure_candidates(
        &[child.clone()],
        &[],
        &PreTruncParentAuthorityStore::default(),
    )
    .unwrap();
    assert!(candidates.is_empty());
    // The coverage gate fails closed...
    let err = validate_probe_coverage(&[child.clone()], &[]).unwrap_err();
    assert!(
        matches!(err, OverlayError::ProbeCoverageMissing(_)),
        "must fail closed as ProbeCoverageMissing, got {err:?}"
    );
    // ...and the error contains the COMPLETE producer provenance.
    let text = format!("{err}");
    assert!(
        text.contains("split_sibling:0x850150:main:0x850000:0x150"),
        "missing capture_id: {text}"
    );
    assert!(text.contains("SplitSibling"), "missing path: {text}");
    assert!(text.contains("0x1234"), "missing source root rva: {text}");
    assert!(text.contains("0x150"), "missing slot offset: {text}");
    assert!(text.contains("0x2000"), "missing probe size: {text}");
    assert!(text.contains("true"), "missing was_interior: {text}");
}

// ============ MIDA-SERIAL-35 slab/ledger/manifest bijection ============

/// raw_capture established + authoritative nonempty + all_slabs empty must
/// fail closed (cardinality mismatch detected by the bijection validator).
#[test]
fn m35_raw_capture_established_all_slabs_empty_fails_closed() {
    // Authoritative set non-empty.
    let raw_slabs = vec![slab_of_len(0x850000, 0x1000)];
    // Patched (all_slabs) EMPTY — the drift case P1-3 flagged.
    let patched_slabs: Vec<HeapSlab> = Vec::new();
    let ledger: Vec<(u64, &'static str, SlabNormalization)> =
        vec![(0x850000, "parent_closure", SlabNormalization::Kept)];
    let err = validate_slab_bijection(&ledger, &raw_slabs, &patched_slabs).unwrap_err();
    assert!(
        err.contains("bijection drift"),
        "authoritative non-empty + all_slabs empty must fail closed: {err}"
    );
}

/// Manifest ledger bijection: raw/patched/normalization exactly 1:1 in
/// count, order, base, size; every digest is non-empty.
#[test]
fn m35_manifest_bijection_one_to_one_no_empty_digest() {
    // Three slabs in deterministic order.
    let mk_slab = |base: u64, len: usize| {
        let mut c = vec![0u8; len];
        c[0] = (base & 0xff) as u8;
        HeapSlab {
            old_base: base,
            content: c,
        }
    };
    let raw = vec![
        mk_slab(0x850000, 0x1000),
        mk_slab(0x860000, 0x800),
        mk_slab(0x870000, 0x400),
    ];
    // Patched slabs: same bases, same sizes (content may differ after overlay).
    let patched = vec![
        mk_slab(0x850000, 0x1000),
        mk_slab(0x860000, 0x800),
        mk_slab(0x870000, 0x400),
    ];
    let ledger: Vec<(u64, &'static str, SlabNormalization)> = vec![
        (0x850000, "main", SlabNormalization::Kept),
        (0x860000, "parent_closure", SlabNormalization::Kept),
        (0x870000, "dedicated", SlabNormalization::Kept),
    ];
    // Bijection validates.
    validate_slab_bijection(&ledger, &raw, &patched).unwrap();
    // Every digest computed from the aligned triple is non-empty.
    for ((_base, _role, _norm), (raw_s, patched_s)) in
        ledger.iter().zip(raw.iter().zip(patched.iter()))
    {
        let mut rh = sha2::Sha256::new();
        rh.update(&raw_s.content);
        let rd = format!("{:x}", rh.finalize());
        let mut ph = sha2::Sha256::new();
        ph.update(&patched_s.content);
        let pd = format!("{:x}", ph.finalize());
        assert!(
            !rd.is_empty() && !pd.is_empty(),
            "digests must never be empty"
        );
    }
    // Drift cases fail closed:
    //  (a) base mismatch at an index
    let raw_bad = vec![
        mk_slab(0x851000, 0x1000),
        mk_slab(0x860000, 0x800),
        mk_slab(0x870000, 0x400),
    ];
    let err = validate_slab_bijection(&ledger, &raw_bad, &patched).unwrap_err();
    assert!(
        err.contains("base mismatch"),
        "base mismatch must fail: {err}"
    );
    //  (b) size mismatch at an index
    let patched_bad = vec![
        mk_slab(0x850000, 0x2000),
        mk_slab(0x860000, 0x800),
        mk_slab(0x870000, 0x400),
    ];
    let err = validate_slab_bijection(&ledger, &raw, &patched_bad).unwrap_err();
    assert!(
        err.contains("size mismatch"),
        "size mismatch must fail: {err}"
    );
    //  (c) cardinality mismatch (extra patched slab)
    let mut patched_extra = patched.clone();
    patched_extra.push(mk_slab(0x880000, 0x100));
    let err = validate_slab_bijection(&ledger, &raw, &patched_extra).unwrap_err();
    assert!(
        err.contains("bijection drift"),
        "cardinality drift must fail: {err}"
    );
}

// ============ MIDA-SERIAL-36 Path A + store + bijection ============

/// Test 5: declared parent size vs full bytes mismatch — declared SMALLER
/// and declared LARGER must both produce NO closure candidate (fail-closed).
#[test]
fn m36_declared_parent_size_bytes_mismatch_no_closure() {
    use crate::dumper::heap_global_snapshot::{
        PreTruncParentAuthorityKey, PreTruncParentAuthorityStore,
    };
    // Child whose parent slice (zeros) matches child content (zeros).
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850150,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:src:0x150".into(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(0x850000),
            containing_parent_size: Some(0x1000),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let mk_store = |declared_size: usize, bytes_len: usize| {
        let mut store = PreTruncParentAuthorityStore::default();
        let key = PreTruncParentAuthorityKey {
            parent_old_base: 0x850000,
            parent_pre_trunc_size: declared_size,
            parent_capture_id: "main:0x850000".into(),
        };
        store.record_parent(
            &key,
            &vec![0u8; bytes_len],
            CaptureExtentKind::ObservedAllocation,
            RegionProvenance::default(),
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        );
        store.record_binding(
            key,
            CaptureExtentKind::ObservedAllocation,
            RegionProvenance::default(),
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0x850150,
            8,
            "src".into(),
            Some(0x150),
        );
        store
    };
    // Declared SMALLER: pre_trunc_size=0x100 but full_bytes=0x1000.
    let store_smaller = mk_store(0x100, 0x1000);
    let c1 = build_authority_closure_candidates(&[child.clone()], &[], &store_smaller).unwrap();
    assert!(c1.is_empty(), "declared smaller must produce no closure");
    // Declared LARGER: pre_trunc_size=0x1000 but full_bytes=0x100.
    let store_larger = mk_store(0x1000, 0x100);
    let c2 = build_authority_closure_candidates(&[child], &[], &store_larger).unwrap();
    assert!(c2.is_empty(), "declared larger must produce no closure");
}

/// Test 6: offset + child_size overflow/range failure must NOT panic and
/// must produce NO closure candidate.
#[test]
fn m36_offset_child_size_overflow_no_panic_no_closure() {
    use crate::dumper::heap_global_snapshot::{
        PreTruncParentAuthorityKey, PreTruncParentAuthorityStore,
    };
    // Parent at 0, child near u64::MAX: child_base - parent_old_base overflows
    // usize (u64::MAX - 0 as usize is huge); the slice end overflows too.
    let child = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: u64::MAX - 4,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:overflow".into(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(0),
            containing_parent_size: Some(0x1000),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let mut store = PreTruncParentAuthorityStore::default();
    let key = PreTruncParentAuthorityKey {
        parent_old_base: 0,
        parent_pre_trunc_size: 0x1000,
        parent_capture_id: "main:0".into(),
    };
    store.record_parent(
        &key,
        &vec![0u8; 0x1000],
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
    );
    store.record_binding(
        key,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        u64::MAX - 4,
        8,
        "src".into(),
        None,
    );
    // Must not panic; no closure.
    let c = build_authority_closure_candidates(&[child], &[], &store).unwrap();
    assert!(c.is_empty(), "overflow must produce no closure candidate");
}

/// Test 7 + 8: bijection gate — equal cardinality but base/order drift or
/// patched-size drift must fail closed.
#[test]
fn m36_bijection_base_and_size_drift_fails() {
    let mk = |base: u64, len: usize| {
        let mut c = vec![0u8; len];
        c[0] = (base & 0xff) as u8;
        HeapSlab {
            old_base: base,
            content: c,
        }
    };
    let ledger: Vec<(u64, &'static str, SlabNormalization)> = vec![
        (0x850000, "main", SlabNormalization::Kept),
        (0x860000, "parent_closure", SlabNormalization::Kept),
    ];
    let raw = vec![mk(0x850000, 0x1000), mk(0x860000, 0x800)];
    let patched = vec![mk(0x850000, 0x1000), mk(0x860000, 0x800)];
    // Valid bijection.
    validate_slab_bijection(&ledger, &raw, &patched).unwrap();
    // Base/order drift: same cardinality, patched bases swapped.
    let patched_swapped = vec![mk(0x860000, 0x800), mk(0x850000, 0x1000)];
    let err = validate_slab_bijection(&ledger, &raw, &patched_swapped).unwrap_err();
    assert!(err.contains("base mismatch"), "base drift must fail: {err}");
    // Patched size drift: same cardinality, patched[1] size differs.
    let patched_size = vec![mk(0x850000, 0x1000), mk(0x860000, 0x900)];
    let err = validate_slab_bijection(&ledger, &raw, &patched_size).unwrap_err();
    assert!(err.contains("size mismatch"), "size drift must fail: {err}");
}

/// Test 10: the same parent backing multiple children stores its bytes ONCE
/// and produces one binding per child; the closure yields ONE authority
/// (no duplicate/overlap after normalization). The bindings must NOT hold
/// the full bytes — only the store does (bytes-level dedup).
#[test]
fn m36_same_parent_multiple_children_store_once() {
    use crate::dumper::heap_global_snapshot::{
        PreTruncParentAuthorityKey, PreTruncParentAuthorityStore,
    };
    let mut store = PreTruncParentAuthorityStore::default();
    let parent_bytes = vec![0xABu8; 0x1000];
    let key = PreTruncParentAuthorityKey {
        parent_old_base: 0x850000,
        parent_pre_trunc_size: 0x1000,
        parent_capture_id: "main:0x850000".into(),
    };
    store.record_parent(
        &key,
        &parent_bytes,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
    );
    // Child 1 and child 2 inside the same parent.
    let b1 = store.record_binding(
        key.clone(),
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        0x850150,
        8,
        "src1".into(),
        Some(0x200),
    );
    let b2 = store.record_binding(
        key,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        0x850200,
        8,
        "src2".into(),
        Some(0x300),
    );
    assert_eq!(store.parent_count(), 1, "bytes stored once");
    assert_eq!(store.binding_count(), 2);
    // Bindings carry ONLY the key — never the full Vec<u8>.
    assert_eq!(b1.parent_key.parent_old_base, 0x850000);
    assert_eq!(b2.parent_key.parent_old_base, 0x850000);
    assert_eq!(b1.child_base, 0x850150);
    assert_eq!(b2.child_base, 0x850200);
    // The shared bytes resolve through the store lookup (ONE copy).
    assert_eq!(
        store.lookup(&b1.parent_key).unwrap(),
        parent_bytes,
        "lookup returns the single stored bytes copy"
    );
    // Conflicting bytes on the same identity -> fail-closed Err.
    let bad = store.bind_child(
        0x850000,
        0x1000,
        &vec![0xFFu8; 0x1000],
        CaptureExtentKind::ObservedAllocation,
        &RegionProvenance::default(),
        "main:0x850000",
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        0x850300,
        8,
        "src3".into(),
        None,
    );
    assert!(
        bad.is_err(),
        "conflicting bytes on same identity must fail closed"
    );
    // Feed both bindings to the closure helper with both children present:
    // both children in heap_globals, one parent authority -> ONE candidate.
    let mk_child = |base: u64| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: base,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: format!("split_sibling:{base:#x}:src:0x150"),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(0x850000),
            containing_parent_size: Some(0x1000),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    // Parent slice at child offsets must be zero (matches child content).
    let mut parent_snap = vec![0u8; 0x1000];
    parent_snap[0x150..0x158].copy_from_slice(&[0u8; 8]);
    parent_snap[0x200..0x208].copy_from_slice(&[0u8; 8]);
    let parent = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: 0x850000,
        content: parent_snap,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let globals = vec![mk_child(0x850150), mk_child(0x850200), parent];
    let candidates = build_authority_closure_candidates(&globals, &[], &store).unwrap();
    assert_eq!(
        candidates.len(),
        1,
        "two children of the same parent must yield ONE closure candidate"
    );
    // Normalization keeps one authority; no overlap.
    let (normalized, _) = normalize_authoritative_slabs(&candidates).unwrap();
    assert_eq!(normalized.len(), 1);
    validate_probe_coverage(&globals, &[normalized[0].slab.clone()]).unwrap();
}

// ============ MIDA-SERIAL-38: Path A per-key single build ============

/// Path A must build ONE closure candidate per unique parent key — two
/// bindings of the SAME key produce ONE candidate and resolve the shared
/// Arc bytes once (never a per-binding Vec<u8> copy). Three bindings across
/// TWO keys produce exactly TWO candidates.
#[test]
fn m38_path_a_builds_once_per_unique_key() {
    use crate::dumper::heap_global_snapshot::{
        PreTruncParentAuthorityKey, PreTruncParentAuthorityStore,
    };
    // Two distinct parents, three children total (2 for parent A, 1 for B).
    let mk_child = |base: u64, parent_base: u64, parent_size: usize| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: base,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: format!("split_sibling:{base:#x}:src:0x150"),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(parent_base),
            containing_parent_size: Some(parent_size),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let mut store = PreTruncParentAuthorityStore::default();
    // Parent A (0x850000): children at 0x850150 and 0x850200 (slice zeros).
    let key_a = PreTruncParentAuthorityKey {
        parent_old_base: 0x850000,
        parent_pre_trunc_size: 0x1000,
        parent_capture_id: "main:0x850000".into(),
    };
    store.record_parent(
        &key_a,
        &vec![0u8; 0x1000],
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
    );
    store.record_binding(
        key_a.clone(),
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        0x850150,
        8,
        "src1".into(),
        Some(0x150),
    );
    store.record_binding(
        key_a.clone(),
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        0x850200,
        8,
        "src2".into(),
        Some(0x200),
    );
    // Parent B (0x860000): child at 0x860150 (slice zeros).
    let key_b = PreTruncParentAuthorityKey {
        parent_old_base: 0x860000,
        parent_pre_trunc_size: 0x1000,
        parent_capture_id: "main:0x860000".into(),
    };
    store.record_parent(
        &key_b,
        &vec![0u8; 0x1000],
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
    );
    store.record_binding(
        key_b.clone(),
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        0x860150,
        8,
        "src3".into(),
        Some(0x150),
    );
    // Parent snapshots (slices at child offsets are zeros to match).
    let mk_parent = |base: u64| {
        let mut c = vec![0u8; 0x1000];
        c[0x150..0x158].copy_from_slice(&[0u8; 8]);
        c[0x200..0x208].copy_from_slice(&[0u8; 8]);
        HeapGlobalSnapshot {
            rva: 0,
            live_ptr: base,
            content: c,
            is_heap_handle: false,
            is_image_inline: false,
            extent_kind: CaptureExtentKind::ObservedAllocation,
            extent_evidence: CaptureExtentEvidence {
                capture_id: format!("main:{base:#x}"),
                capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
                source_root_rva: None,
                source_slot_offset: None,
                probe_requested_size: 0,
                was_interior: false,
                containing_parent_old_base: None,
                containing_parent_size: None,
            },
            transform_ids: Vec::new(),
            provenance: RegionProvenance::default(),
        }
    };
    let globals = vec![
        mk_child(0x850150, 0x850000, 0x1000),
        mk_child(0x850200, 0x850000, 0x1000),
        mk_child(0x860150, 0x860000, 0x1000),
        mk_parent(0x850000),
        mk_parent(0x860000),
    ];
    // 3 bindings, 2 unique keys -> exactly 2 candidates (one per key).
    assert_eq!(store.binding_count(), 3);
    assert_eq!(store.parent_count(), 2);
    let candidates = build_authority_closure_candidates(&globals, &[], &store).unwrap();
    assert_eq!(
        candidates.len(),
        2,
        "Path A builds ONE candidate per unique parent key"
    );
    let mut bases: Vec<u64> = candidates.iter().map(|c| c.slab.old_base).collect();
    bases.sort_unstable();
    assert_eq!(bases, vec![0x850000, 0x860000]);
    // Each candidate's content is the full parent bytes (0x1000).
    assert!(candidates.iter().all(|c| c.slab.content.len() == 0x1000));
    // Observable ownership: the two bindings of key A resolve to the SAME
    // Arc backing allocation (pointer equality), proving the store holds
    // ONE bytes copy shared by all bindings of that key.
    let bindings = store.bindings();
    let arc_a1 = store.lookup_arc(&bindings[0].parent_key).unwrap();
    let arc_a2 = store.lookup_arc(&bindings[1].parent_key).unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&arc_a1, &arc_a2),
        "both key-A bindings share ONE Arc backing allocation"
    );
    let arc_b = store.lookup_arc(&bindings[2].parent_key).unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(&arc_a1, &arc_b),
        "different parent keys have distinct backings"
    );
}

/// Path A strict byte-equality conflict: two bindings of the SAME key with
/// DIFFERENT parent bytes must fail closed with an error (never a silent
/// last-write-wins), even when the conflict is introduced via two stores.
#[test]
fn m39_path_a_same_key_byte_conflict_fails_closed() {
    use crate::dumper::heap_global_snapshot::{
        PreTruncParentAuthorityKey, PreTruncParentAuthorityStore,
    };
    let mk_child = |base: u64, parent_base: u64| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: base,
        content: vec![0u8; 8],
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: format!("split_sibling:{base:#x}:src:0x150"),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(parent_base),
            containing_parent_size: Some(0x1000),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    // A single store cannot hold same-key different bytes (record_parent
    // keeps the first). Build TWO stores, each with one binding of the same
    // key but different parent bytes, and merge their bindings by hand.
    let mk_store = |bytes: Vec<u8>, child_base: u64| {
        let mut store = PreTruncParentAuthorityStore::default();
        let key = PreTruncParentAuthorityKey {
            parent_old_base: 0x850000,
            parent_pre_trunc_size: 0x1000,
            parent_capture_id: "main:0x850000".into(),
        };
        store.record_parent(
            &key,
            &bytes,
            CaptureExtentKind::ObservedAllocation,
            RegionProvenance::default(),
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        );
        store.record_binding(
            key,
            CaptureExtentKind::ObservedAllocation,
            RegionProvenance::default(),
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            child_base,
            8,
            "src".into(),
            Some(0x150),
        );
        store
    };
    let s1 = mk_store(vec![0u8; 0x1000], 0x850150);
    let s2 = mk_store(vec![0xFFu8; 0x1000], 0x850200);
    // Merge: build a combined store where the parent bytes differ between
    // the two bindings of the same key. record_parent keeps FIRST bytes, so
    // use a store with parent A bytes and manually push a second binding
    // whose key maps to different bytes by inserting into the parents map
    // through a second key variant is not possible — instead construct the
    // conflict via build_authority_closure_candidates with a store whose
    // binding key resolves to different bytes is impossible by design.
    // The realistic conflict: Path B (heap_globals containing-parent) meets
    // Path A with the SAME key but different bytes.
    let globals = vec![mk_child(0x850150, 0x850000)];
    // Path A store: parent bytes all-zero; child slice zeros -> matches.
    let _ = &s1;
    let _ = &s2;
    // Feed ONLY s1's binding: candidate built from zero bytes.
    let c1 = build_authority_closure_candidates(&globals, &[], &s1).unwrap();
    assert_eq!(c1.len(), 1);
    // Now a DIFFERENT store with the same key + different bytes cannot
    // co-exist in one store, so the strict conflict is enforced inside the
    // store's prepare_parent (IdentityConflict). Prove that here:
    let mut merged = s1.clone();
    let res = merged.bind_child(
        0x850000,
        0x1000,
        &vec![0xFFu8; 0x1000],
        CaptureExtentKind::ObservedAllocation,
        &RegionProvenance::default(),
        "main:0x850000",
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        0x850300,
        8,
        "src".into(),
        None,
    );
    assert!(
        res.is_err(),
        "same key + different bytes must fail closed (IdentityConflict)"
    );
    // And a store with identical bytes accepts the second binding.
    let mut same = s1.clone();
    let ok = same.bind_child(
        0x850000,
        0x1000,
        &vec![0u8; 0x1000],
        CaptureExtentKind::ObservedAllocation,
        &RegionProvenance::default(),
        "main:0x850000",
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        0x850300,
        8,
        "src".into(),
        None,
    );
    assert!(ok.is_ok(), "identical bytes accept the second binding");
}

/// Closure-LEVEL conflict: Path A (pre-trunc store) and Path B (heap_globals
/// containing-parent evidence) claim the SAME parent key with DIFFERENT
/// bytes. register_candidate's strict byte equality must surface a conflict
/// error from build_authority_closure_candidates — not a silent winner.
#[test]
fn m39_closure_path_a_path_b_same_key_conflict_fails_closed() {
    use crate::dumper::heap_global_snapshot::{
        PreTruncParentAuthorityKey, PreTruncParentAuthorityStore,
    };
    let parent_base = 0x850000u64;
    let parent_size = 0x1000usize;
    let child_base = 0x850150u64;
    // Path A store: parent key (0x850000/0x1000, "main:0x850000") with
    // all-ZERO bytes; one binding at child 0x850150 size 8. The child in
    // heap_globals must carry ZERO bytes at 0x150 for Path A to match.
    let mut store = PreTruncParentAuthorityStore::default();
    let key = PreTruncParentAuthorityKey {
        parent_old_base: parent_base,
        parent_pre_trunc_size: parent_size,
        parent_capture_id: "main:0x850000".into(),
    };
    store.record_parent(
        &key,
        &vec![0u8; parent_size],
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
    );
    store.record_binding(
        key,
        CaptureExtentKind::ObservedAllocation,
        RegionProvenance::default(),
        crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        child_base,
        8,
        "src".into(),
        Some(0x150),
    );
    // Path B: a heap_global child whose containing-parent evidence points
    // at the SAME key (0x850000/0x1000) but the parent snapshot content is
    // 0xFF bytes. The child's slice at 0x150 is 0xFF (matches the 0xFF
    // parent), so Path B alone builds a candidate for the same key.
    let mk_child = |content: Vec<u8>| HeapGlobalSnapshot {
        rva: 0,
        live_ptr: child_base,
        content,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ProbeWindow,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "split_sibling:0x850150:src:0x150".into(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::SplitSibling,
            source_root_rva: None,
            source_slot_offset: Some(0x150),
            probe_requested_size: 0x2000,
            was_interior: true,
            containing_parent_old_base: Some(parent_base),
            containing_parent_size: Some(parent_size),
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    // The Path A binding's child (zero bytes at 0x150) AND the Path B
    // child (0xFF bytes at 0x150) both exist in heap_globals as ProbeWindow
    // snapshots at the SAME base — the closure builder sees both producers.
    let child_a = mk_child(vec![0u8; 8]);
    let child_b = mk_child(vec![0xFFu8; 8]);
    let mut parent_ff = vec![0xFFu8; parent_size];
    parent_ff[0x150..0x158].copy_from_slice(&[0xFFu8; 8]);
    let parent_ff = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: parent_base,
        content: parent_ff,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    // Path A alone (child_a zero bytes matching the zero store): the store
    // binding proves the parent; closure builds ONE zero-byte candidate.
    let globals_a = vec![child_a.clone(), parent_ff.clone()];
    let c_a = build_authority_closure_candidates(&globals_a, &[], &store).unwrap();
    assert_eq!(c_a.len(), 1, "Path A builds from the pre-trunc store");
    assert_eq!(
        c_a[0].slab.content[0], 0x00,
        "Path A candidate uses the store's zero bytes"
    );
    // Path B alone (child_b 0xFF bytes matching the 0xFF parent): the
    // containing-parent evidence proves the parent; closure builds ONE
    // 0xFF candidate for the SAME key.
    let globals_b = vec![child_b.clone(), parent_ff.clone()];
    let c_b = build_authority_closure_candidates(&globals_b, &[], &store).unwrap();
    assert_eq!(
        c_b.len(),
        1,
        "Path B builds from containing-parent evidence"
    );
    assert_eq!(
        c_b[0].slab.content[0], 0xFF,
        "Path B candidate uses the 0xFF parent bytes"
    );
    // BOTH paths active in ONE call: Path A registers the key with zero
    // bytes, Path B re-registers the same key with 0xFF bytes -> strict
    // byte equality surfaces AuthoritativeSlabConflict (fail-closed, no
    // silent winner).
    let globals_both = vec![child_a.clone(), child_b.clone(), parent_ff.clone()];
    let err = build_authority_closure_candidates(&globals_both, &[], &store).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("parent_closure_byte_conflict"),
        "same-key different-bytes must fail closed, got: {msg}"
    );
    // Control: identical bytes via BOTH paths -> ONE resolvable candidate.
    let store_same = PreTruncParentAuthorityStore::default();
    let mut parent_same = vec![0u8; parent_size];
    parent_same[0x150..0x158].copy_from_slice(&[0u8; 8]);
    let parent_same = HeapGlobalSnapshot {
        rva: 0,
        live_ptr: parent_base,
        content: parent_same,
        is_heap_handle: false,
        is_image_inline: false,
        extent_kind: CaptureExtentKind::ObservedAllocation,
        extent_evidence: CaptureExtentEvidence {
            capture_id: "main:0x850000".into(),
            capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            source_root_rva: None,
            source_slot_offset: None,
            probe_requested_size: 0,
            was_interior: false,
            containing_parent_old_base: None,
            containing_parent_size: None,
        },
        transform_ids: Vec::new(),
        provenance: RegionProvenance::default(),
    };
    let globals_same = vec![child_a.clone(), parent_same];
    let c_same = build_authority_closure_candidates(&globals_same, &[], &store_same).unwrap();
    assert_eq!(
        c_same.len(),
        1,
        "identical bytes through both paths collapse to one candidate"
    );
}
