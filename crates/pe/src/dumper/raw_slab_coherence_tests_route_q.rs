//! route_q cluster tests (WO-22 split from raw_slab_coherence_tests.rs).

use super::*;

// ---- Route Q R0 Q0-B: byte/run-level transform provenance ----

// The Route P geometry writer: a transform that writes the mName qword at
// +0x28 (repair_label_names_after_scrub) must be attributed to exactly that
// contiguous 8-byte run, with the authoritative preimage in `before_bytes`.
#[test]
fn route_q_r0b_repair_label_name_writer_isolated_to_0x28_run() {
    let mut before = global(0x8aa5f8, vec![0u8; 0x70], false);
    before.extent_evidence.capture_id = "gscript_child_link:0x8bc550:0x0:0x8aa5f8:true".into();
    // The authoritative slab preimage S at +0x28 already holds a different
    // non-null pointer (e.g. first byte 0xf0). Repair overwrites it with the
    // inline pointer label_live+0x30 = 0x8aa5f8+0x30 = 0x8aa628.
    let s_preimage = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
    before.content[0x28..0x30].copy_from_slice(&s_preimage);
    let mut after = before.clone();
    let ptr = 0x8aa628u64.to_le_bytes();
    after.content[0x28..0x30].copy_from_slice(&ptr);

    let runs = diff_transform_write_runs(
        &[before.clone()],
        &[after],
        "repair_label_names_after_scrub",
    )
    .unwrap();

    assert_eq!(runs.len(), 1, "one contiguous 8-byte run expected");
    let run = &runs[0];
    assert_eq!(run.transform_id, "repair_label_names_after_scrub");
    assert_eq!(run.child_old_base, 0x8aa5f8);
    assert_eq!(run.child_offset, 0x28);
    assert_eq!(run.length, 8);
    assert_eq!(run.first_before_byte, s_preimage[0]);
    assert_eq!(run.first_after_byte, ptr[0]);
    assert_eq!(run.before_bytes, s_preimage.to_vec());
    assert_eq!(run.after_bytes, ptr.to_vec());
    assert_eq!(run.before_digest, sha256_hex(&s_preimage));
    assert_eq!(run.after_digest, sha256_hex(&ptr));
    assert!(run.child_capture_id.contains("gscript_child_link"));
}

// mark_labels_non_nested writes Label+0x23, NOT +0x28. The byte/run diff
// must never attribute a +0x28 write to it.
#[test]
fn route_q_r0b_mark_non_nested_writer_only_attributed_to_0x23() {
    let mut before = global(0x8aa5f8, vec![0u8; 0x70], false);
    before.extent_evidence.capture_id = "gscript_child_link:0x8bc550:0x0:0x8aa5f8:true".into();
    let mut after = before.clone();
    // mark_labels_non_nested flips byte +0x23 (nested flag).
    after.content[0x23] = 0x01;

    let runs = diff_transform_write_runs(&[before], &[after], "mark_labels_non_nested").unwrap();

    assert_eq!(runs.len(), 1, "only the +0x23 write is present");
    assert_eq!(runs[0].transform_id, "mark_labels_non_nested");
    assert_eq!(runs[0].child_offset, 0x23);
    assert_eq!(runs[0].length, 1);
    // Critical: never a +0x28 run for this transform.
    assert_ne!(runs[0].child_offset, 0x28);
    assert_eq!(runs[0].first_before_byte, 0x00);
    assert_eq!(runs[0].first_after_byte, 0x01);
}

// scrub_uncaptured_heap_pointers zeroes dangling pointers (S -> 0). The run
// records the authoritative preimage byte (before) and the zeroed output.
#[test]
fn route_q_r0b_scrub_zeroing_records_clean_preimage() {
    let mut before = global(0x8aa5f8, vec![0u8; 0x70], false);
    before.extent_evidence.capture_id = "gscript_child_link:0x8bc550:0x0:0x8aa5f8:true".into();
    // The authoritative slab preimage S at +0x28 is a full non-null pointer
    // (drift byte 0xf0, remaining qword bytes non-zero). Scrub zeroes the
    // dangling pointer (it pointed at an uncaptured range).
    let s_preimage = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
    before.content[0x28..0x30].copy_from_slice(&s_preimage);
    let mut after = before.clone();
    after.content[0x28..0x30].fill(0);

    let runs =
        diff_transform_write_runs(&[before], &[after], "scrub_uncaptured_heap_pointers").unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].transform_id, "scrub_uncaptured_heap_pointers");
    assert_eq!(runs[0].child_offset, 0x28);
    assert_eq!(runs[0].length, 8);
    // before digest = the authoritative S preimage bytes; after = zeroed.
    assert_eq!(runs[0].before_bytes, s_preimage.to_vec());
    assert_eq!(runs[0].after_bytes, vec![0u8; 8]);
    assert_eq!(runs[0].first_before_byte, s_preimage[0]);
    assert_eq!(runs[0].first_after_byte, 0x00);
}

// Two disjoint write runs in one child become two separate runs, each with
// its own offset/length/digest, and the ledger sorts deterministically.
#[test]
fn route_q_r0b_disjoint_runs_are_separate_and_sorted() {
    let mut before = global(0x8aa5f8, vec![0u8; 0x70], false);
    before.extent_evidence.capture_id = "route-q-disjoint".into();
    let mut after = before.clone();
    after.content[0x23] = 0x01;
    // A full non-zero qword write (all 8 bytes differ from the zero preimage).
    let ptr = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
    after.content[0x28..0x30].copy_from_slice(&ptr);

    let mut runs = diff_transform_write_runs(
        &[before],
        &[after],
        "mark_labels_non_nested", // combined for determinism demo
    )
    .unwrap();
    runs.sort_by(|a, b| a.child_offset.cmp(&b.child_offset));
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].child_offset, 0x23);
    assert_eq!(runs[0].length, 1);
    assert_eq!(runs[1].child_offset, 0x28);
    assert_eq!(runs[1].length, 8);
}

// A child whose content is unchanged by the transform produces no runs.
#[test]
fn route_q_r0b_unchanged_child_produces_no_runs() {
    let before = global(0x8aa5f8, vec![0xAA; 0x70], false);
    let after = before.clone();
    let runs =
        diff_transform_write_runs(&[before], &[after], "repair_label_names_after_scrub").unwrap();
    assert!(runs.is_empty());
}

// The run ledger sorts deterministically by (base, offset, length, id).
#[test]
fn route_q_r0b_run_ledger_deterministic_sort() {
    let mut l1 = TransformRunLedger::default();
    let mut l2 = TransformRunLedger::default();
    let base = TransformWriteRun {
        child_capture_id: "x".into(),
        child_old_base: 0x8aa5f8,
        child_size: 0x70,
        child_offset: 0x28,
        length: 8,
        transform_id: "repair_label_names_after_scrub".into(),
        before_digest: "b".into(),
        after_digest: "a".into(),
        first_before_byte: 0,
        first_after_byte: 0x28,
        before_bytes: vec![0; 8],
        after_bytes: vec![0x28; 8],
    };
    // Insert out of order in l1 and in order in l2; both sort identically.
    let mut low = base.clone();
    low.child_offset = 0x23;
    low.length = 1;
    l1.runs.push(base.clone());
    l1.runs.push(low.clone());
    l2.runs.push(low);
    l2.runs.push(base);
    l1.sort_runs();
    l2.sort_runs();
    assert_eq!(l1, l2);
    assert_eq!(l1.runs[0].child_offset, 0x23);
    assert_eq!(l1.runs[1].child_offset, 0x28);
}

// ---- Route Q R0 Q0-C: three-way overlay over authoritative preimage ----

// Route P exact geometry: an InteriorSubview child (size 0x70, drift at
// +0x28) whose transform runs on the authoritative slab slice (P=S) and
// writes byte +0x28. Under Q0-C this must be APPLIED as
// TransformReplayedOnAuthoritativePreimage (NOT fail-closed), because the
// binding proves transform_input_digest == sha256(S).
#[test]
fn route_q_r0c_interior_transform_replayed_on_authoritative_preimage() {
    // Slab where the child range is all 0xAA except +0x28 = 0xf0 (authoritative S).
    let child_base: u64 = 0x8aa5f8;
    let child_size = 0x70usize;
    let slab_base: u64 = 0x874000;
    let child_off = (child_base - slab_base) as usize;
    let mut slab_content = vec![0u8; child_off + child_size];
    for i in 0..child_size {
        slab_content[child_off + i] = 0xAA;
    }
    slab_content[child_off + 0x28] = 0xf0; // S byte at +0x28
    let slab = HeapSlab {
        old_base: slab_base,
        content: slab_content,
    };
    // Raw child capture C: drifts from S (C[0x28]=0x00 != S[0x28]=0xf0).
    let mut raw_bytes = vec![0xAAu8; child_size];
    raw_bytes[0x28] = 0x00;
    let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
    child.extent_kind = CEK::InteriorSubview;
    child.capture_id = "route-p-geometry".into();
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![child],
    };

    // Q0-A seeding: replace the probe/interior transform input with S.
    // The child's pre-seed content must equal the raw child capture C.
    let mut seeded = global(child_base, vec![0xAAu8; child_size], false);
    seeded.content[0x28] = 0x00; // C value at +0x28
    seeded.extent_kind = CEK::InteriorSubview;
    seeded.extent_evidence.capture_id = "route-p-geometry".into();
    let mut globals = vec![seeded];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(
        bindings[0].basis,
        TransformPreimageBasis::AuthoritativeSlabSlice
    );
    // Seeded input now == S (0xAA everywhere, +0x28 = 0xf0).
    assert_eq!(globals[0].content[0x28], 0xf0);

    // Transform writes +0x28 to a repaired pointer (0x8aa628 first byte 0x28).
    globals[0].content[0x28] = 0x28;
    globals[0].transform_ids = vec!["repair_label_names_after_scrub".to_string()];
    // A production byte/run ledger proving the +0x28 write came from
    // repair_label_names_after_scrub on the authoritative preimage S[0x28]=0xf0.
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "route-p-geometry".into(),
        child_old_base: child_base,
        child_size,
        child_offset: 0x28,
        length: 1,
        transform_id: "repair_label_names_after_scrub".into(),
        before_digest: sha256_hex(&[0xf0]),
        after_digest: sha256_hex(&[0x28]),
        first_before_byte: 0xf0,
        first_after_byte: 0x28,
        before_bytes: vec![0xf0],
        after_bytes: vec![0x28],
    });

    let (patched, overlays, drift) = build_patched_backing_slab_q0c(
        &raw_capture,
        &[globals[0].clone()],
        &[],
        &bindings,
        &ledger,
    )
    .unwrap();
    // The +0x28 write was applied (T != S).
    assert_eq!(patched[0].content[child_off + 0x28], 0x28);
    // A TransformReplayedOnAuthoritativePreimage run was recorded.
    assert!(drift.iter().any(|d| {
        d.resolution == CaptureDriftResolution::TransformReplayedOnAuthoritativePreimage
            && d.child_offset == 0x28
    }));
    assert_eq!(overlays.len(), 1);
    assert_eq!(overlays[0].overlay_applied, true);
}

// Probe/interior non-write drift under Q0-C still resolves to slab authority.
#[test]
fn route_q_r0c_interior_nonwrite_drift_uses_slab_authority() {
    let child_base: u64 = 0x8aa5f8;
    let child_size = 0x70usize;
    let slab_base: u64 = 0x874000;
    let child_off = (child_base - slab_base) as usize;
    let mut slab_content = vec![0u8; child_off + child_size];
    for i in 0..child_size {
        slab_content[child_off + i] = 0xAA;
    }
    slab_content[child_off + 0x28] = 0xf0;
    let slab = HeapSlab {
        old_base: slab_base,
        content: slab_content,
    };
    // C drifts at +0x28 (0x00 vs S 0xf0) but the transform writes nothing.
    let mut raw_bytes = vec![0xAAu8; child_size];
    raw_bytes[0x28] = 0x00;
    let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
    child.extent_kind = CEK::InteriorSubview;
    child.capture_id = "route-p-nonwrite".into();
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![child],
    };
    // Seed: transform input becomes S. Pre-seed content must equal C.
    let mut seeded = global(child_base, vec![0xAAu8; child_size], false);
    seeded.content[0x28] = 0x00; // C value at +0x28
    seeded.extent_kind = CEK::InteriorSubview;
    seeded.extent_evidence.capture_id = "route-p-nonwrite".into();
    let mut globals = vec![seeded];
    let mut containers: Vec<ContainerSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    // No transform write: T == S. Backing starts from S.
    let (patched, _, drift) = build_patched_backing_slab_q0c(
        &raw_capture,
        &[globals[0].clone()],
        &[],
        &bindings,
        &TransformRunLedger::default(),
    )
    .unwrap();
    // Slab authority wins at +0x28.
    assert_eq!(patched[0].content[child_off + 0x28], 0xf0);
    // NonWriteSlabAuthoritative drift run recorded.
    assert!(drift.iter().any(|d| {
        d.resolution == CaptureDriftResolution::NonWriteSlabAuthoritative && d.child_offset == 0x28
    }));
}

// Q0-C: a binding claiming slab basis but whose transform_input_digest does
// NOT equal the authoritative slab slice digest fails closed.
#[test]
fn route_q_r0c_mismatched_transform_input_digest_fails_closed() {
    let child_base: u64 = 0x8aa5f8;
    let child_size = 0x70usize;
    let slab_base: u64 = 0x874000;
    let child_off = (child_base - slab_base) as usize;
    let mut slab_content = vec![0u8; child_off + child_size];
    for i in 0..child_size {
        slab_content[child_off + i] = 0xAA;
    }
    slab_content[child_off + 0x28] = 0xf0;
    let slab = HeapSlab {
        old_base: slab_base,
        content: slab_content,
    };
    // TAF2-A: capture the full-slab digest/size before moving into raw_capture.
    let slab_digest = sha256_hex(&slab.content);
    let slab_len = slab.content.len();
    let mut raw_bytes = vec![0xAAu8; child_size];
    raw_bytes[0x28] = 0x00;
    let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
    child.extent_kind = CEK::InteriorSubview;
    child.capture_id = "route-p-baddigest".into();
    // Capture digest inputs before moving child/slab into raw_capture.
    let child_digest = sha256_hex(&child.raw_bytes);
    let slab_slice_digest = sha256_hex(&slab.content[child_off..child_off + child_size]);
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![child],
    };
    // A forged binding: claims AuthoritativeSlabSlice with correct C/S digests
    // but a WRONG transform_input_digest (!= sha256(S)).
    let bad_binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "route-p-baddigest".into(),
        child_old_base: child_base,
        child_size,
        extent_kind: CEK::InteriorSubview,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("route-p-baddigest"),
            child_base,
            child_size,
            CEK::InteriorSubview,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: slab_base,
        slab_size: slab_len,
        slab_digest,
        slab_offset: child_off,
        basis: TransformPreimageBasis::AuthoritativeSlabSlice,
        raw_child_digest: child_digest,
        raw_slab_slice_digest: slab_slice_digest,
        transform_input_digest: "WRONG".into(), // != sha256(S)
        seeded_from_slab: true,
    };
    let mut transformed = global(child_base, vec![0xAAu8; child_size], false);
    transformed.extent_kind = CEK::InteriorSubview;
    transformed.extent_evidence.capture_id = "route-p-baddigest".into();
    transformed.content[0x28] = 0x28;
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[bad_binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
}

// Q0-C: strict extent with a ChildCapture binding and full C==S coherence
// produces a write-set overlay; any C!=S drift is rejected.
#[test]
fn route_q_r0c_strict_extent_write_applies_and_drift_rejected() {
    let child_base: u64 = 0x8aa5f8;
    let child_size = 0x70usize;
    let slab_base: u64 = 0x874000;
    let child_off = (child_base - slab_base) as usize;
    let mut slab_content = vec![0u8; child_off + child_size];
    for i in 0..child_size {
        slab_content[child_off + i] = 0xAA;
    }
    let slab = HeapSlab {
        old_base: slab_base,
        content: slab_content,
    };
    // TAF2-A: full-slab identity for the binding.
    let slab_digest = sha256_hex(&slab.content);
    let slab_len = slab.content.len();
    // C == S (all 0xAA), strict ObservedAllocation.
    let raw_bytes = vec![0xAAu8; child_size];
    let mut child = raw_child(child_base, child_size, raw_bytes, RawChildKind::HeapGlobal);
    child.extent_kind = CEK::ObservedAllocation;
    child.capture_id = "route-q-strict-ok".into();
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![child],
    };
    // ChildCapture binding (strict), C==S.
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "route-q-strict-ok".into(),
        child_old_base: child_base,
        child_size,
        extent_kind: CEK::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("route-q-strict-ok"),
            child_base,
            child_size,
            CEK::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: slab_base,
        slab_size: slab_len,
        slab_digest,
        slab_offset: child_off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&vec![0xAAu8; child_size]),
        raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; child_size]),
        transform_input_digest: sha256_hex(&vec![0xAAu8; child_size]),
        seeded_from_slab: false,
    };
    // Transform writes byte 0x10 to 0xEE.
    let mut transformed = global(child_base, vec![0xAAu8; child_size], false);
    transformed.extent_kind = CEK::ObservedAllocation;
    transformed.extent_evidence.capture_id = "route-q-strict-ok".into();
    transformed.content[0x10] = 0xEE;
    transformed.transform_ids = vec!["t1".to_string()];
    // Production byte/run ledger: the +0x10 write from t1 (preimage 0xAA -> 0xEE).
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "route-q-strict-ok".into(),
        child_old_base: child_base,
        child_size,
        child_offset: 0x10,
        length: 1,
        transform_id: "t1".into(),
        before_digest: sha256_hex(&[0xAA]),
        after_digest: sha256_hex(&[0xEE]),
        first_before_byte: 0xAA,
        first_after_byte: 0xEE,
        before_bytes: vec![0xAA],
        after_bytes: vec![0xEE],
    });
    let (patched, overlays, _) =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap();
    assert_eq!(patched[0].content[child_off + 0x10], 0xEE);
    assert_eq!(overlays.len(), 1);
    // Non-written bytes stay 0xAA (unchanged).
    assert_eq!(patched[0].content[child_off + 0x20], 0xAA);

    // Now a strict child with C!=S must fail closed.
    let mut drifting_raw = vec![0xAAu8; child_size];
    drifting_raw[0x28] = 0x00; // C[0x28] != S[0x28] (0xAA)
    let mut child2 = raw_child(
        child_base,
        child_size,
        drifting_raw.clone(),
        RawChildKind::HeapGlobal,
    );
    child2.extent_kind = CEK::ObservedAllocation;
    child2.capture_id = "route-q-strict-drift".into();
    // TAF2-A: this test's second slab is a separate inline authority; capture
    // its own digest/size.
    let slab2 = HeapSlab {
        old_base: slab_base,
        content: vec![0xAAu8; child_off + child_size],
    };
    let slab2_digest = sha256_hex(&slab2.content);
    let slab2_len = slab2.content.len();
    let raw_capture2 = RawSlabCapture {
        slabs: vec![slab2],
        children: vec![child2],
    };
    let binding2 = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "route-q-strict-drift".into(),
        child_old_base: child_base,
        child_size,
        extent_kind: CEK::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("route-q-strict-drift"),
            child_base,
            child_size,
            CEK::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: slab_base,
        slab_size: slab2_len,
        slab_digest: slab2_digest,
        slab_offset: child_off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&drifting_raw),
        raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; child_size]),
        transform_input_digest: sha256_hex(&drifting_raw),
        seeded_from_slab: false,
    };
    let mut transformed2 = global(child_base, vec![0xAAu8; child_size], false);
    transformed2.extent_kind = CEK::ObservedAllocation;
    transformed2.extent_evidence.capture_id = "route-q-strict-drift".into();
    transformed2.content[0x28] = 0x00;
    let err = build_patched_backing_slab_q0c(
        &raw_capture2,
        &[transformed2],
        &[],
        &[binding2],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
}

// ---- Route Q R0 Q0-A AF1-B: binding resolution negative matrix ----
// The audit (AF1-B) requires exact, unique, full-field binding resolution.
// Every under-constraint below must fail closed. This builds a probe/interior
// child + a CORRECT binding, then mutates one identity/digest field at a time
// and asserts the overlay rejects it (TransformPreimageDrift / RawCaptureDrift).

const AF1B_BASE: u64 = 0x8aa5f8;
const AF1B_SIZE: usize = 0x70;
const AF1B_SLAB: u64 = 0x874000;

/// A valid probe/interior fixture + correct AuthoritativeSlabSlice binding.
fn af1b_fixture() -> (RawSlabCapture, HeapGlobalSnapshot, TransformPreimageBinding) {
    let child_off = (AF1B_BASE - AF1B_SLAB) as usize;
    let mut slab_content = vec![0u8; child_off + AF1B_SIZE];
    for i in 0..AF1B_SIZE {
        slab_content[child_off + i] = 0xAA;
    }
    // S mName = full non-null pointer (drift byte 0xf0).
    let s_ptr = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
    slab_content[child_off + 0x28..child_off + 0x30].copy_from_slice(&s_ptr);
    let slab = HeapSlab {
        old_base: AF1B_SLAB,
        content: slab_content,
    };
    let mut raw_bytes = vec![0xAAu8; AF1B_SIZE];
    raw_bytes[0x28..0x30].fill(0); // C mName null (drift)
                                   // Capture digests before moving.
    let child_digest = sha256_hex(&raw_bytes);
    let slab_slice_digest = sha256_hex(&slab.content[child_off..child_off + AF1B_SIZE]);
    let mut child = raw_child(AF1B_BASE, AF1B_SIZE, raw_bytes, RawChildKind::HeapGlobal);
    child.extent_kind = CEK::InteriorSubview;
    child.capture_id = "af1b-probe".into();
    let slab_digest = sha256_hex(&slab.content);
    let slab_len = slab.content.len();
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![child],
    };
    // Pre-seed content == C so seeding can find it.
    let mut seeded = global(AF1B_BASE, vec![0xAAu8; AF1B_SIZE], false);
    seeded.extent_kind = CEK::InteriorSubview;
    seeded.extent_evidence.capture_id = "af1b-probe".into();
    seeded.content[0x28..0x30].fill(0);
    // A correct binding (matching the seeded transform input).
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "af1b-probe".into(),
        child_old_base: AF1B_BASE,
        child_size: AF1B_SIZE,
        extent_kind: CEK::InteriorSubview,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("af1b-probe"),
            AF1B_BASE,
            AF1B_SIZE,
            CEK::InteriorSubview,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: AF1B_SLAB,
        slab_size: slab_len,
        slab_digest,
        slab_offset: child_off,
        basis: TransformPreimageBasis::AuthoritativeSlabSlice,
        raw_child_digest: child_digest,
        raw_slab_slice_digest: slab_slice_digest.clone(),
        transform_input_digest: slab_slice_digest,
        seeded_from_slab: true,
    };
    (raw_capture, seeded, binding)
}

// Missing binding -> fail closed (no legacy fallback for probe/interior).
#[test]
fn route_q_af1b_missing_binding_fails_closed() {
    let (raw_capture, transformed, _binding) = af1b_fixture();
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

// Duplicate full-identity bindings -> ambiguous -> fail closed.
#[test]
fn route_q_af1b_duplicate_binding_fails_closed() {
    let (raw_capture, transformed, binding) = af1b_fixture();
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

// A strict child accepting a slab-seeded (AuthoritativeSlabSlice) binding
// must fail closed — it would bypass the C==S check.
#[test]
fn route_q_af1b_strict_accepting_slab_basis_fails_closed() {
    let (raw_capture, mut transformed, mut binding) = af1b_fixture();
    // Reclassify as strict; the binding stays slab-seeded (wrong basis).
    transformed.extent_kind = CEK::ObservedAllocation;
    binding.extent_kind = CEK::ObservedAllocation;
    binding.identity.extent_kind = CEK::ObservedAllocation; // keep identity consistent
    binding.basis = TransformPreimageBasis::AuthoritativeSlabSlice; // forbidden for strict
    binding.seeded_from_slab = true;
    // Keep the raw child consistent with the reclassified strict identity so
    // the test exercises the forbidden basis (slab-seeded on a strict child),
    // not an identity mismatch.
    let mut rc = raw_capture.clone();
    rc.children[0].extent_kind = CEK::ObservedAllocation;
    let err = build_patched_backing_slab_q0c(
        &rc,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformPreimageDrift { .. })
            || matches!(err, OverlayError::RawCaptureDrift { .. })
    );
}

// Wrong extent_kind in the binding (does not match child) -> fail closed.
#[test]
fn route_q_af1b_wrong_extent_fails_closed() {
    let (raw_capture, transformed, mut binding) = af1b_fixture();
    binding.extent_kind = CEK::BackingObject; // mismatched extent
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(
            matches!(
                err,
                OverlayError::TransformPreimageBindingIdentityInvalid { .. }
            ) || matches!(err, OverlayError::BindingIdentityInconsistent { .. }),
            "wrong binding extent_kind must fail closed (identity-consistent or self-inconsistent), got {err:?}"
        );
}

// Wrong child_size in the binding -> fail closed.
#[test]
fn route_q_af1b_wrong_size_fails_closed() {
    let (raw_capture, transformed, mut binding) = af1b_fixture();
    binding.child_size = AF1B_SIZE + 8; // mismatched size
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(
            matches!(
                err,
                OverlayError::TransformPreimageBindingIdentityInvalid { .. }
            ) || matches!(err, OverlayError::BindingIdentityInconsistent { .. }),
            "wrong binding child_size must fail closed (identity-consistent or self-inconsistent), got {err:?}"
        );
}

// Wrong slab_old_base in the binding -> fail closed.
#[test]
fn route_q_af1b_wrong_slab_base_fails_closed() {
    let (raw_capture, transformed, mut binding) = af1b_fixture();
    binding.slab_old_base = AF1B_SLAB - 0x1000; // mismatched slab identity
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OverlayError::TransformPreimageBindingIdentityInvalid { .. }
    ));
}

// Wrong slab_offset in the binding -> fail closed.
#[test]
fn route_q_af1b_wrong_slab_offset_fails_closed() {
    let (raw_capture, transformed, mut binding) = af1b_fixture();
    binding.slab_offset += 8; // mismatched offset
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        OverlayError::TransformPreimageBindingIdentityInvalid { .. }
    ));
}

// Wrong raw_child_digest (stale C) -> fail closed.
#[test]
fn route_q_af1b_wrong_child_digest_fails_closed() {
    let (raw_capture, transformed, mut binding) = af1b_fixture();
    binding.raw_child_digest = "stale".into(); // mismatched C digest
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
}

// Wrong raw_slab_slice_digest (stale S) -> fail closed.
#[test]
fn route_q_af1b_wrong_slab_digest_fails_closed() {
    let (raw_capture, transformed, mut binding) = af1b_fixture();
    binding.raw_slab_slice_digest = "stale".into(); // mismatched S digest
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
}

// Inconsistent seeded_from_slab (false on a slab-seeded binding) -> fail closed.
#[test]
fn route_q_af1b_inconsistent_seeded_fails_closed() {
    let (raw_capture, transformed, mut binding) = af1b_fixture();
    binding.seeded_from_slab = false; // inconsistent with AuthoritativeSlabSlice
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
}

// Empty capture_id in the binding -> ambiguous -> fail closed.
#[test]
fn route_q_af1b_empty_capture_id_fails_closed() {
    let (raw_capture, transformed, mut binding) = af1b_fixture();
    binding.capture_id = String::new(); // empty capture id = identity invalid
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(
            matches!(
                err,
                OverlayError::TransformPreimageBindingIdentityInvalid { .. }
            ) || matches!(err, OverlayError::BindingIdentityInconsistent { .. }),
            "empty binding capture_id must fail closed (identity-consistent or self-inconsistent), got {err:?}"
        );
}

// ---- Route Q R0 AF1 Rev 2 (P0-1): strict write-run attribution negatives ----
// For every T != P byte the ledger MUST prove a deterministic last writer via a
// contiguous, digest-consistent, in-order replay landing on T. Each negative
// below must fail closed. The fixture writes child +0x28 from P=S[0x28]=0xf0 to
// T[0x28]=0x28 (repair_label_names_after_scrub) with a CORRECT binding; only the
// ledger is perturbed.

/// A probe/interior child with correct binding, transformed +0x28 -> 0x28.
fn af1a_write_fixture() -> (RawSlabCapture, HeapGlobalSnapshot, TransformPreimageBinding) {
    let (raw_capture, mut transformed, binding) = af1b_fixture();
    // The transform input P == S. The transformed child must equal S except for
    // the +0x28 write, so only one byte differs (clean single write). S's
    // +0x28..+0x30 carries the full pointer 0xf0f1f2f3f4f5f6f7.
    let s_ptr = 0xf0f1f2f3f4f5f6f7u64.to_le_bytes();
    transformed.content[0x28..0x30].copy_from_slice(&s_ptr); // == S
    transformed.content[0x28] = 0x28; // repair writes the pointer low byte
    (raw_capture, transformed, binding)
}

/// A correct single-run ledger: repair wrote +0x28 0xf7 -> 0x28.
fn af1a_correct_ledger() -> TransformRunLedger {
    let mut ledger = TransformRunLedger::default();
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "af1b-probe".into(),
        child_old_base: AF1B_BASE,
        child_size: AF1B_SIZE,
        child_offset: 0x28,
        length: 1,
        transform_id: "repair_label_names_after_scrub".into(),
        before_digest: sha256_hex(&[0xf7]),
        after_digest: sha256_hex(&[0x28]),
        first_before_byte: 0xf7,
        first_after_byte: 0x28,
        before_bytes: vec![0xf7],
        after_bytes: vec![0x28],
    });
    ledger
}

// 1. T != P with ZERO covering runs -> fail closed (no has_runs_for_child bypass).
#[test]
fn route_q_af1a_zero_runs_fails_closed() {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[transformed],
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
}

// 2. Wrong capture id in the run -> no identity match -> fail closed.
// Route X R0 AF1 (P0-3): the global run-membership gate catches this EARLIER
// as TransformRunLedgerInvalid (precise reason), before per-child replay.
#[test]
fn route_q_af1a_wrong_capture_id_fails_closed() {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let mut ledger = af1a_correct_ledger();
    ledger.runs[0].child_capture_id = "different-child".into();
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
                | OverlayError::TransformPreimageDrift { .. }
        ),
        "wrong capture id must fail closed, got {err:?}"
    );
}

// 3. Wrong child size in the run -> identity mismatch -> fail closed.
#[test]
fn route_q_af1a_wrong_child_size_fails_closed() {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let mut ledger = af1a_correct_ledger();
    ledger.runs[0].child_size = AF1B_SIZE + 16;
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(
        matches!(
            err,
            OverlayError::TransformRunLedgerInvalid { .. }
                | OverlayError::TransformPreimageDrift { .. }
        ),
        "wrong child size must fail closed, got {err:?}"
    );
}

// 4. Out-of-range run (offset+length > child_size) -> fail closed.
#[test]
fn route_q_af1a_out_of_range_run_fails_closed() {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let mut ledger = af1a_correct_ledger();
    ledger.runs[0].child_offset = AF1B_SIZE - 1; // length 1 -> runs past end
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
}

// 5. Earlier writer matches T but a LATER writer differs -> the later writer
//    must win; if the final state != T, fail closed (no earlier-writer spoof).
#[test]
fn route_q_af1a_later_writer_differs_fails_closed() {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let mut ledger = af1a_correct_ledger(); // repair: 0xf0 -> 0x28 (matches T)
                                            // A later writer (sanitize) overwrites +0x28 to 0x00, so final != T.
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "af1b-probe".into(),
        child_old_base: AF1B_BASE,
        child_size: AF1B_SIZE,
        child_offset: 0x28,
        length: 1,
        transform_id: "sanitize_ahk_runtime_global".into(),
        before_digest: sha256_hex(&[0x28]),
        after_digest: sha256_hex(&[0x00]),
        first_before_byte: 0x28,
        first_after_byte: 0x00,
        before_bytes: vec![0x28],
        after_bytes: vec![0x00],
    });
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformPreimageDrift { .. }),
        "later writer differs from T must fail closed"
    );
}

// 6. Broken before/after chain: a later run's before byte != prior state.
#[test]
fn route_q_af1a_broken_chain_fails_closed() {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let mut ledger = af1a_correct_ledger();
    // A later run whose before byte does NOT equal the prior state (0x28).
    ledger.runs.push(TransformWriteRun {
        child_capture_id: "af1b-probe".into(),
        child_old_base: AF1B_BASE,
        child_size: AF1B_SIZE,
        child_offset: 0x28,
        length: 1,
        transform_id: "sanitize_ahk_runtime_global".into(),
        before_digest: sha256_hex(&[0xAB]), // != prior state 0x28
        after_digest: sha256_hex(&[0x00]),
        first_before_byte: 0xAB,
        first_after_byte: 0x00,
        before_bytes: vec![0xAB],
        after_bytes: vec![0x00],
    });
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformPreimageDrift { .. }),
        "broken before/after chain must fail closed"
    );
}

// 7. Digest mismatch: before_digest != sha256(before_bytes) -> fail closed.
#[test]
fn route_q_af1a_digest_mismatch_fails_closed() {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let mut ledger = af1a_correct_ledger();
    ledger.runs[0].before_digest = "wrong-digest".into(); // != sha256(before_bytes)
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    // Route S R0-D: digest mismatch is caught by the global run-ledger validator.
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "digest mismatch must fail closed, got {err:?}"
    );
}

// 8. A CORRECT ledger (positive control): the write is attributed and applied.
#[test]
fn route_q_af1a_correct_ledger_attributes_and_applies() {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let ledger = af1a_correct_ledger();
    let (patched, _, _) =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap();
    assert_eq!(
        patched[0].content[(AF1B_BASE - AF1B_SLAB) as usize + 0x28],
        0x28
    );
}

// ---- Route R R0-C: malformed run shape must FAIL CLOSED (TransformPreimageDrift),
// never panic on a short byte vector or inconsistent first bytes.
fn route_q_af1a_malformed_run(mutate: impl FnOnce(&mut TransformWriteRun)) {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let mut ledger = af1a_correct_ledger();
    mutate(&mut ledger.runs[0]);
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    // Route S R0-D: malformed covering run is caught by the global validator.
    assert!(
        matches!(err, OverlayError::TransformRunLedgerInvalid { .. }),
        "malformed run must fail closed, got {err:?}"
    );
}

#[test]
fn route_q_af1a_short_before_bytes_fails_closed() {
    // before_bytes too short (would index-panic without shape validation).
    route_q_af1a_malformed_run(|r| r.before_bytes.clear());
}

#[test]
fn route_q_af1a_empty_capture_id_run_fails_closed() {
    route_q_af1a_malformed_run(|r| r.child_capture_id.clear());
}

#[test]
fn route_q_af1a_empty_transform_id_run_fails_closed() {
    route_q_af1a_malformed_run(|r| r.transform_id.clear());
}

#[test]
fn route_q_af1a_first_before_byte_inconsistent_fails_closed() {
    // first_before_byte disagrees with before_bytes[0].
    route_q_af1a_malformed_run(|r| r.first_before_byte = r.first_before_byte.wrapping_add(1));
}

#[test]
fn route_q_af1a_length_zero_fails_closed() {
    route_q_af1a_malformed_run(|r| r.length = 0);
}

// ---- Route R R0-C / Audit Fix 1: GLOBAL ledger validation. ----
// A malformed run for a DIFFERENT (unrelated) child must still fail the whole
// ledger, even when the current child has a correct covering writer. This is
// exercised with a valid covering run + a malformed extra run; the overlay
// must fail closed (the global validator runs before per-byte attribution).

fn route_r_r0c_malformed_extra(mutate: impl FnOnce(&mut TransformWriteRun)) {
    let (raw_capture, transformed, binding) = af1a_write_fixture();
    let mut ledger = af1a_correct_ledger(); // valid covering run for +0x28
                                            // A malformed run for an UNRELATED child (different base) — must fail the
                                            // whole ledger via the global validator, not be ignored.
    let mut extra = TransformWriteRun {
        child_capture_id: "other-child".into(),
        child_old_base: AF1B_BASE + 0x10000, // unrelated base
        child_size: 8,
        child_offset: 0,
        length: 1,
        transform_id: "scrub_uncaptured_heap_pointers".into(),
        before_digest: sha256_hex(&[0x01]),
        after_digest: sha256_hex(&[0x02]),
        first_before_byte: 0x01,
        first_after_byte: 0x02,
        before_bytes: vec![0x01],
        after_bytes: vec![0x02],
    };
    mutate(&mut extra);
    ledger.runs.push(extra);
    let err =
        build_patched_backing_slab_q0c(&raw_capture, &[transformed], &[], &[binding], &ledger)
            .unwrap_err();
    // Route S R0-D: the global validator reports the EXACT malformed run index
    // (the extra run at index 1) via TransformRunLedgerInvalid, not a per-child
    // TransformPreimageDrift.
    match &err {
        OverlayError::TransformRunLedgerInvalid { run_index, .. } => {
            assert_eq!(*run_index, 1, "must identify the malformed extra run index");
        }
        other => panic!("expected TransformRunLedgerInvalid, got {other:?}"),
    }
}

#[test]
fn route_r_r0c_valid_plus_zero_length_extra_fails() {
    route_r_r0c_malformed_extra(|r| r.length = 0);
}

#[test]
fn route_r_r0c_valid_plus_empty_id_extra_fails() {
    route_r_r0c_malformed_extra(|r| r.child_capture_id.clear());
}

#[test]
fn route_r_r0c_valid_plus_short_vector_extra_fails() {
    route_r_r0c_malformed_extra(|r| r.before_bytes.clear());
}

#[test]
fn route_r_r0c_offset_length_overflow_fails() {
    route_r_r0c_malformed_extra(|r| r.child_offset = usize::MAX - 1);
}

// ---- Route R R0-B / Audit Fix 1: execution-owning recorder tests. ----
// The recorder executes the transform AND records both child-level
// `transform_ids` and the byte/run ledger in one call, so the two can never
// diverge.

#[test]
fn route_r_r0b_apply_recorded_transform_records_both_ledgers() {
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    // A strict child (C==S) that a transform will modify.
    let child_base = 0x8aa5f8u64;
    let child_size = 0x70usize;
    let slab_base = 0x874000u64;
    let child_off = (child_base - slab_base) as usize;
    let slab = HeapSlab {
        old_base: slab_base,
        content: vec![0xAAu8; child_off + child_size],
    };
    let mut child = raw_child(
        child_base,
        child_size,
        vec![0xAAu8; child_size],
        RawChildKind::HeapGlobal,
    );
    child.extent_kind = CEK::ObservedAllocation;
    child.capture_id = "r0b-child".into();
    let slab_digest = sha256_hex(&slab.content);
    let slab_len = slab.content.len();
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![child],
    };
    // A transformed child whose +0x10 will be changed by the transform.
    let mut globals = vec![global(child_base, vec![0xAAu8; child_size], false)];
    globals[0].extent_kind = CEK::ObservedAllocation;
    globals[0].extent_evidence.capture_id = "r0b-child".into();
    let mut binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "r0b-child".into(),
        child_old_base: child_base,
        child_size,
        extent_kind: CEK::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("r0b-child"),
            child_base,
            child_size,
            CEK::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: slab_base,
        slab_size: slab_len,
        slab_digest,
        slab_offset: child_off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&vec![0xAAu8; child_size]),
        raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; child_size]),
        transform_input_digest: sha256_hex(&vec![0xAAu8; child_size]),
        seeded_from_slab: false,
    };
    let _ = &mut binding;
    let mut ledger = TransformRunLedger::default();
    // Use the execution-owning helper: it must run the transform AND record.
    let b = binding;
    apply_recorded_transform(&mut globals, "t_probe_write", &mut ledger, |g| {
        g[0].content[0x10] = 0xEE; // the transform writes +0x10
    })
    .unwrap();
    // The child's transform_ids now carries t_probe_write (child-level evidence).
    assert!(globals[0]
        .transform_ids
        .contains(&"t_probe_write".to_string()));
    // The byte/run ledger has a run at +0x10 for this child.
    assert!(ledger.runs.iter().any(|r| {
        r.transform_id == "t_probe_write"
            && r.child_old_base == child_base
            && r.child_offset == 0x10
            && r.after_bytes == vec![0xEE]
    }));
    // The run ledger and child transform_ids are consistent.
    for r in &ledger.runs {
        assert!(globals[0].transform_ids.contains(&r.transform_id));
    }
    // The overlay must attribute +0x10 to t_probe_write (proves consistency).
    let (patched, _, _) =
        build_patched_backing_slab_q0c(&raw_capture, &globals, &[], &[b], &ledger).unwrap();
    assert_eq!(patched[0].content[child_off + 0x10], 0xEE);
}

// The execution-owning API makes "forgot to record" / "wrong transform id"
// structurally impossible: there is no way to execute a transform and NOT
// record it, because the recorder owns execution.
#[test]
fn route_r_r0b_wrong_or_missing_recording_not_constructible() {
    // Build a child + correct binding, then verify that ANY write to the child
    // MUST go through apply_recorded_transform (which always records). We prove
    // this by showing that applying the transform via the helper records the
    // run; there is no separate "execute without recording" entry point for a
    // transform in the production API. If the ledger were empty after a write,
    // the overlay would fail closed (unattributed byte).
    use crate::dumper::heap_global_snapshot::CaptureExtentKind as CEK;
    let child_base = 0x8aa5f8u64;
    let child_size = 0x70usize;
    let slab_base = 0x874000u64;
    let child_off = (child_base - slab_base) as usize;
    let slab = HeapSlab {
        old_base: slab_base,
        content: vec![0xAAu8; child_off + child_size],
    };
    let mut child = raw_child(
        child_base,
        child_size,
        vec![0xAAu8; child_size],
        RawChildKind::HeapGlobal,
    );
    child.extent_kind = CEK::ObservedAllocation;
    child.capture_id = "r0b-constructible".into();
    let slab_digest = sha256_hex(&slab.content);
    let slab_len = slab.content.len();
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![child],
    };
    let mut globals = vec![global(child_base, vec![0xAAu8; child_size], false)];
    globals[0].extent_kind = CEK::ObservedAllocation;
    globals[0].extent_evidence.capture_id = "r0b-constructible".into();
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::HeapGlobal,
        capture_id: "r0b-constructible".into(),
        child_old_base: child_base,
        child_size,
        extent_kind: CEK::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::HeapGlobal,
            String::from("r0b-constructible"),
            child_base,
            child_size,
            CEK::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: slab_base,
        slab_size: slab_len,
        slab_digest,
        slab_offset: child_off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&vec![0xAAu8; child_size]),
        raw_slab_slice_digest: sha256_hex(&vec![0xAAu8; child_size]),
        transform_input_digest: sha256_hex(&vec![0xAAu8; child_size]),
        seeded_from_slab: false,
    };
    // If we somehow wrote the child WITHOUT recording (which the API prevents),
    // the overlay would fail closed. Prove the fail-closed backstop exists:
    // an empty ledger + a written byte => TransformPreimageDrift.
    let mut globals_dirty = globals.clone();
    globals_dirty[0].content[0x10] = 0xEE; // a write with NO recorded run
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &globals_dirty,
        &[],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformPreimageDrift { .. }),
        "a write with no recorded run must fail closed"
    );
}

// ---- Route Q R0 AF1 Rev 2 (P0-2/P0-3): Container identity + basis matrix ----
// A Container is a strict child: ChildCapture basis, and its capture id must be
// the deterministic `container_capture_id(decoded_begin)` so the raw/seeding
// stage and the transformed representation agree. Wrong-basis (slab-seeded)
// Container bindings must fail closed (no exemption).

const AF1C_BASE: u64 = 0x8cc000;
const AF1C_SIZE: usize = 0x40;

/// A Container child inside a slab, with a correct ChildCapture binding.
fn af1c_container_fixture() -> (RawSlabCapture, ContainerSnapshot, TransformPreimageBinding) {
    let child_off = (AF1C_BASE - AF1B_SLAB) as usize; // reuse slab base 0x874000
    let mut slab_content = vec![0u8; child_off + AF1C_SIZE];
    for i in 0..AF1C_SIZE {
        slab_content[child_off + i] = 0x55;
    }
    let slab_slice_digest = sha256_hex(&slab_content[child_off..child_off + AF1C_SIZE]);
    let slab = HeapSlab {
        old_base: AF1B_SLAB,
        content: slab_content,
    };
    let content = vec![0x55u8; AF1C_SIZE];
    let cap_id = container_capture_id(AF1C_BASE);
    let child = RawChild {
        old_base: AF1C_BASE,
        size: AF1C_SIZE,
        raw_bytes: content.clone(),
        kind: RawChildKind::Container,
        capture_id: cap_id.clone(),
        capture_path: crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
        extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
        source_slot_offset: None,
        requested_probe_size: 0,
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
    let binding = TransformPreimageBinding {
        child_kind: RawChildKind::Container,
        capture_id: cap_id.clone(),
        child_old_base: AF1C_BASE,
        child_size: AF1C_SIZE,
        extent_kind: crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
        identity: FullCaptureIdentity::from_plain_parts(
            RawChildKind::Container,
            cap_id.to_string(),
            AF1C_BASE,
            AF1C_SIZE,
            crate::dumper::heap_global_snapshot::CaptureExtentKind::ObservedAllocation,
            crate::dumper::heap_global_snapshot::CapturePath::MainSlot,
            0,
        ),
        slab_old_base: AF1B_SLAB,
        slab_size: slab_len,
        slab_digest,
        slab_offset: child_off,
        basis: TransformPreimageBasis::ChildCapture,
        raw_child_digest: sha256_hex(&content),
        raw_slab_slice_digest: slab_slice_digest,
        transform_input_digest: sha256_hex(&content),
        seeded_from_slab: false,
    };
    let cont = container(AF1C_BASE, AF1C_BASE + AF1C_SIZE as u64, content);
    (raw_capture, cont, binding)
}

// Positive: a Container with exact ChildCapture binding and matching identity
// is overlaid successfully (identity matches across stages).
#[test]
fn route_q_af1c_container_exact_child_capture_positive() {
    let (raw_capture, cont, binding) = af1c_container_fixture();
    let (patched, overlays, _) = build_patched_backing_slab_q0c(
        &raw_capture,
        &[],
        &[cont],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap();
    // No transform wrote the container, so the slab bytes are preserved.
    let child_off = (AF1C_BASE - AF1B_SLAB) as usize;
    assert_eq!(patched[0].content[child_off], 0x55);
    assert!(overlays
        .iter()
        .any(|o| o.child_kind == RawChildKind::Container));
}

// Route R R0-E: TRUE end-to-end Container identity chain. From a raw
// ContainerSnapshot, derive raw children, construct the RawSlabCapture, seed
// the authoritative preimage (returning the real binding), run the Q0-C
// overlay with THAT binding (no manual reconstruction), and render+parse the
// manifest — proving the production three-stage identity chain is coherent.
#[test]
fn route_q_af1c_container_end_to_end() {
    // 1. Raw ContainerSnapshot + a slab covering it.
    let child_off = (AF1C_BASE - AF1B_SLAB) as usize;
    let mut slab_content = vec![0u8; child_off + AF1C_SIZE];
    for i in 0..AF1C_SIZE {
        slab_content[child_off + i] = 0x55;
    }
    let slab = HeapSlab {
        old_base: AF1B_SLAB,
        content: slab_content,
    };
    let cont = container(
        AF1C_BASE,
        AF1C_BASE + AF1C_SIZE as u64,
        vec![0x55u8; AF1C_SIZE],
    );
    // 2. raw_children_from_capture derives the container's raw child + id.
    let raw_children = raw_children_from_capture(&[cont.clone()], &[]);
    let rc = raw_children
        .iter()
        .find(|r| r.kind == RawChildKind::Container)
        .expect("container raw child");
    assert_eq!(rc.capture_id, container_capture_id(AF1C_BASE));
    // 3. Construct RawSlabCapture from the real slab + derived raw children.
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: raw_children,
    };
    // 4. seed_transform_inputs_from_authoritative_slab returns the REAL binding.
    let mut globals: Vec<HeapGlobalSnapshot> = Vec::new();
    let mut containers = vec![cont.clone()];
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut containers, &mut globals)
            .unwrap();
    let binding = bindings
        .iter()
        .find(|b| b.child_kind == RawChildKind::Container)
        .expect("container binding");
    assert_eq!(binding.capture_id, container_capture_id(AF1C_BASE));
    assert_eq!(binding.basis, TransformPreimageBasis::ChildCapture);
    // 5. Q0-C overlay using the REAL seeded binding (no manual reconstruction).
    let (patched, overlays, _drift) = build_patched_backing_slab_q0c(
        &raw_capture,
        &globals,
        &containers,
        &bindings,
        &TransformRunLedger::default(),
    )
    .unwrap();
    assert_eq!(patched[0].content[child_off], 0x55);
    assert!(overlays
        .iter()
        .any(|o| o.child_kind == RawChildKind::Container));
    // 6. Render + parse the manifest (production contract).
    let json = crate::dumper::snapshot_manifest::render_manifest_json(
        std::path::Path::new("af1c.exe"),
        crate::dumper::types::DumpProfile::AhkGtoExperimental,
        0x140000000,
        0x70b0,
        &containers,
        &globals,
        &crate::dumper::capture_policy::DumpCapturePolicy::ahk_gto_default(),
        false,
        None,
        &overlays,
        &[],
        &bindings,
        &TransformRunLedger::default(),
        &[],
        &[],
        &[],
        &[],
        &[],
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid manifest JSON");
    // The preimage ledger proves the container's ChildCapture basis.
    let pl = v["transform_preimage_ledger"].as_array().unwrap();
    assert!(pl.iter().any(|b| b["child_kind"] == "container"
        && b["basis"] == "ChildCapture"
        && b["capture_id"] == container_capture_id(AF1C_BASE)));
}

// Negative: a Container with a slab-seeded (AuthoritativeSlabSlice) basis must
// fail closed — the Container must be ChildCapture (no basis exemption).
#[test]
fn route_q_af1c_container_wrong_slab_basis_fails_closed() {
    let (raw_capture, cont, mut binding) = af1c_container_fixture();
    binding.basis = TransformPreimageBasis::AuthoritativeSlabSlice;
    binding.seeded_from_slab = true;
    let err = build_patched_backing_slab_q0c(
        &raw_capture,
        &[],
        &[cont],
        &[binding],
        &TransformRunLedger::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, OverlayError::TransformPreimageDrift { .. }),
        "Container must not accept slab basis"
    );
}

// Identity stability: container_capture_id is deterministic and used by both
// raw_children_from_capture and the seed binding so they agree.
#[test]
fn route_q_af1c_container_identity_is_deterministic_and_stable() {
    let (raw_capture, cont, _binding) = af1c_container_fixture();
    // raw_children_from_capture derives the same id as container_capture_id.
    let raw_children = raw_children_from_capture(&[cont.clone()], &[]);
    let rc = raw_children
        .iter()
        .find(|r| r.kind == RawChildKind::Container)
        .unwrap();
    assert_eq!(rc.capture_id, container_capture_id(AF1C_BASE));
    assert!(!rc.capture_id.is_empty());
    // Seeding produces a binding whose capture_id matches the container raw id.
    let mut globals: Vec<HeapGlobalSnapshot> = Vec::new();
    let bindings =
        seed_transform_inputs_from_authoritative_slab(&raw_capture, &mut [cont], &mut globals)
            .unwrap();
    let b = bindings
        .iter()
        .find(|b| b.child_kind == RawChildKind::Container)
        .unwrap();
    assert_eq!(b.capture_id, container_capture_id(AF1C_BASE));
    assert_eq!(b.basis, TransformPreimageBasis::ChildCapture);
}

// 1. Probe-window non-write drift uses the authoritative slab (B[i]=S[i]).
#[test]
fn r0g_nonwrite_probe_drift_uses_slab_authority() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ProbeWindow,
            "probe1",
        )],
    };
    // No transform: T == C.
    let mut transformed = global(
        R0G_CHILD_BASE,
        {
            let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
            for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                b[i] = 0xBB;
            }
            b
        },
        false,
    );
    transformed.extent_kind = CEK::ProbeWindow;
    let (patched, _, drift) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    // The authoritative slab byte wins: patched at child offset is the slab
    // value (0xAA everywhere, since the slab is all 0xAA).
    assert_eq!(
        &patched.content[R0G_CHILD_OFF..R0G_CHILD_OFF + R0G_CHILD_SIZE],
        &vec![0xAAu8; R0G_CHILD_SIZE][..]
    );
    // A NonWriteSlabAuthoritative drift run was recorded covering the tail.
    assert!(!drift.is_empty());
    assert!(drift
        .iter()
        .any(|d| d.resolution == CaptureDriftResolution::NonWriteSlabAuthoritative));
    assert!(drift
        .iter()
        .all(|d| d.resolution == CaptureDriftResolution::NonWriteSlabAuthoritative));
}

// 2. Interior-subview non-write drift uses the authoritative slab.
#[test]
fn r0g_nonwrite_interior_drift_uses_slab_authority() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::InteriorSubview,
            "interior1",
        )],
    };
    let mut transformed = global(
        R0G_CHILD_BASE,
        {
            let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
            for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                b[i] = 0xBB;
            }
            b
        },
        false,
    );
    transformed.extent_kind = CEK::InteriorSubview;
    let (patched, _, drift) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    assert_eq!(
        &patched.content[R0G_CHILD_OFF..R0G_CHILD_OFF + R0G_CHILD_SIZE],
        &vec![0xAAu8; R0G_CHILD_SIZE][..]
    );
    assert!(drift
        .iter()
        .all(|d| d.resolution == CaptureDriftResolution::NonWriteSlabAuthoritative));
}

// 3. No-transform drift does not modify the slab (patched == raw slab).
#[test]
fn r0g_no_transform_drift_does_not_modify_slab() {
    let slab = r0g_slab();
    let raw_slab = slab.content.clone();
    let raw_capture = RawSlabCapture {
        slabs: vec![slab],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ProbeWindow,
            "probe2",
        )],
    };
    // T == C (no transform writes).
    let mut transformed = global(
        R0G_CHILD_BASE,
        {
            let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
            for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                b[i] = 0xBB;
            }
            b
        },
        false,
    );
    transformed.extent_kind = CEK::ProbeWindow;
    let (patched, _, _) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    assert_eq!(patched.content, raw_slab);
}

// 4. A transform writing a stable preimage (write < first mismatch) applies.
#[test]
fn r0g_stable_preimage_transform_write_applies() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ProbeWindow,
            "probe3",
        )],
    };
    // Transform writes byte 0x10 (within stable prefix) to 0xEE.
    let transformed = r0g_transformed(R0G_FIRST_MISMATCH, 0x10, 0xEE, CEK::ProbeWindow);
    let (patched, _, _) = build_patched_backing_slab(
        &raw_capture,
        &[transformed],
        &[],
        &["repair_gscript_window_strings"],
    )
    .unwrap();
    // The write was applied at slab offset.
    assert_eq!(patched.content[R0G_CHILD_OFF + 0x10], 0xEE);
    // The drifted tail stays at slab authority (0xAA).
    assert_eq!(patched.content[R0G_CHILD_OFF + R0G_FIRST_MISMATCH], 0xAA);
}

// 5. A transform writing a drifted preimage fails closed (TransformPreimageDrift).
#[test]
fn r0g_transform_preimage_drift_fails_closed() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ProbeWindow,
            "probe4",
        )],
    };
    // Transform writes byte 0x30 (>= first mismatch 0x28), which drifted.
    let transformed = r0g_transformed(R0G_FIRST_MISMATCH, 0x30, 0xEE, CEK::ProbeWindow);
    let err = build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::TransformPreimageDrift { .. }));
}

// 6. Strict ObservedAllocation full-range drift still fails closed.
#[test]
fn r0g_strict_observed_allocation_drift_fails_closed() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ObservedAllocation,
            "obs1",
        )],
    };
    // Even with no transform, a strict allocation with full-range drift fails.
    let mut transformed = global(
        R0G_CHILD_BASE,
        {
            let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
            for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                b[i] = 0xBB;
            }
            b
        },
        false,
    );
    transformed.extent_kind = CEK::ObservedAllocation;
    let err = build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
}

// 7. BackingObject full-range drift still fails closed.
#[test]
fn r0g_backing_object_drift_fails_closed() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::BackingObject,
            "back1",
        )],
    };
    let mut transformed = global(
        R0G_CHILD_BASE,
        {
            let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
            for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                b[i] = 0xBB;
            }
            b
        },
        false,
    );
    transformed.extent_kind = CEK::BackingObject;
    let err = build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::RawCaptureDrift { .. }));
}

// 8. Synthetic children still skip raw coherence entirely.
#[test]
fn r0g_synthetic_still_skips_raw_coherence() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![],
    };
    // A synthetic child (SyntheticDerived provenance) with no raw source.
    let mut synth = global(0x10000, b"NewClassName\0".to_vec(), false);
    synth.provenance = RegionProvenance::SyntheticDerived {
        transform_id: "repair_gscript_window_strings".to_string(),
        source_anchor: "gscript+0xbd8".to_string(),
        construction_digest: sha256_hex(&synth.content),
    };
    synth.extent_kind = CEK::SyntheticDerived;
    // Should not fail on raw coherence (no raw child); recorded as synthetic.
    // Route X R0: the SyntheticDerived child is NOT a raw-slab overlay child,
    // so it produces NO raw overlay entry (it may still carry child-level
    // transform evidence).
    let (_, overlays, _) = build_patched_backing_slab(&raw_capture, &[synth], &[], &["t"]).unwrap();
    assert!(overlays.is_empty());
}

// 9. Drift runs are deterministically sorted.
#[test]
fn r0g_drift_runs_are_deterministically_sorted() {
    // Two probe children with drift -> drift runs sorted by (base, slab_offset).
    let a = R0G_CHILD_BASE;
    let b = R0G_CHILD_BASE + 0x100;
    let mut content = vec![0u8; (b - R0G_SLAB_BASE) as usize + R0G_CHILD_SIZE];
    for off in 0..R0G_CHILD_SIZE {
        content[(a - R0G_SLAB_BASE) as usize + off] = 0xAA;
        content[(b - R0G_SLAB_BASE) as usize + off] = 0xAA;
    }
    let raw_capture = RawSlabCapture {
        slabs: vec![HeapSlab {
            old_base: R0G_SLAB_BASE,
            content,
        }],
        children: vec![
            r0g_raw_child_at(a, R0G_FIRST_MISMATCH, CEK::ProbeWindow, "pa"),
            r0g_raw_child_at(b, R0G_FIRST_MISMATCH, CEK::ProbeWindow, "pb"),
        ],
    };
    let mk = |live: u64, id: &str| {
        let mut g = global(
            live,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        g.extent_kind = CEK::ProbeWindow;
        g.extent_evidence.capture_id = id.to_string();
        g
    };
    let ga = mk(a, "pa");
    let gb = mk(b, "pb");
    let (_, _, d1) =
        build_patched_backing_slab(&raw_capture, &[gb.clone(), ga.clone()], &[], &["t"]).unwrap();
    let (_, _, d2) = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap();
    assert_eq!(d1, d2);
    for w in d1.windows(2) {
        assert!(w[0].child_old_base <= w[1].child_old_base);
    }
}

// 10. Drift ledger binds the child capture id.
#[test]
fn r0g_drift_ledger_binds_capture_id() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ProbeWindow,
            "gscript_child_link:0x1:0x0:0x9f93e8:0x400",
        )],
    };
    let mut transformed = global(
        R0G_CHILD_BASE,
        {
            let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
            for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                b[i] = 0xBB;
            }
            b
        },
        false,
    );
    transformed.extent_kind = CEK::ProbeWindow;
    transformed.extent_evidence.capture_id =
        "gscript_child_link:0x1:0x0:0x9f93e8:0x400".to_string();
    let (_, _, drift) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    assert!(!drift.is_empty());
    for d in &drift {
        assert_eq!(
            d.child_capture_id,
            "gscript_child_link:0x1:0x0:0x9f93e8:0x400"
        );
    }
}

// 11. first_mismatch is never used as the allocation size.
#[test]
fn r0g_first_mismatch_is_not_used_as_size() {
    // The drift at 0x28 must NOT truncate the child to 0x28. The child keeps
    // its full captured size (0x70) and the slab stays authoritative.
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ProbeWindow,
            "probe5",
        )],
    };
    let mut transformed = global(
        R0G_CHILD_BASE,
        {
            let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
            for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                b[i] = 0xBB;
            }
            b
        },
        false,
    );
    transformed.extent_kind = CEK::ProbeWindow;
    let (patched, _, _) =
        build_patched_backing_slab(&raw_capture, &[transformed], &[], &["t"]).unwrap();
    // The slab content at the full child range (0x70 bytes) is retained.
    assert_eq!(
        &patched.content[R0G_CHILD_OFF..R0G_CHILD_OFF + R0G_CHILD_SIZE],
        &vec![0xAAu8; R0G_CHILD_SIZE][..]
    );
}

// 12. Input order does not change drift resolution.
#[test]
fn r0g_input_order_does_not_change_drift_resolution() {
    let raw_capture = RawSlabCapture {
        slabs: vec![r0g_slab()],
        children: vec![r0g_raw_child(
            R0G_FIRST_MISMATCH,
            CEK::ProbeWindow,
            "probe6",
        )],
    };
    // T == C (child with the same drift tail as the raw child).
    let mk = || {
        let mut g = global(
            R0G_CHILD_BASE,
            {
                let mut b = vec![0xAAu8; R0G_CHILD_SIZE];
                for i in R0G_FIRST_MISMATCH..R0G_CHILD_SIZE {
                    b[i] = 0xBB;
                }
                b
            },
            false,
        );
        g.extent_kind = CEK::ProbeWindow;
        g
    };
    let t1 = mk();
    let t2 = mk();
    let (p1, _, d1) = build_patched_backing_slab(&raw_capture, &[t1], &[], &["t"]).unwrap();
    let (p2, _, d2) = build_patched_backing_slab(&raw_capture, &[t2], &[], &["t"]).unwrap();
    assert_eq!(p1.content, p2.content);
    assert_eq!(d1, d2);
}

// 13. Existing transform-write conflict (same byte, different value) still fails.
#[test]
fn r0g_existing_transform_write_conflict_still_fails() {
    let raw_capture = route_n_raw_capture(0xAA);
    let mut a = vec![0xAAu8; ROUTEN_VIEW_SZ];
    a[0x50] = 0xBB;
    let mut b = vec![0xAAu8; ROUTEN_VIEW_SZ];
    b[0x00] = 0xCC;
    // Both children are strict ObservedAllocation (R0-F semantics preserved).
    let mut ga = global(ROUTEN_A_BASE, a, false);
    ga.extent_kind = CEK::ObservedAllocation;
    let mut gb = global(ROUTEN_B_BASE, b, false);
    gb.extent_kind = CEK::ObservedAllocation;
    let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t1", "t2"]).unwrap_err();
    assert!(matches!(err, OverlayError::TransformWriteConflict { .. }));
}

// 14. Existing raw-duplicate ambiguity still fails closed.
#[test]
fn r0g_existing_raw_duplicate_ambiguity_still_fails() {
    // Two distinct raw children at the same base with different bytes, NEITHER
    // slab-coherent (slab holds a third distinct byte pattern) -> ambiguous,
    // fails closed (no silent overwrite).
    let s = slab_with_child(
        ROUTEK_SLAB_BASE,
        ROUTEK_SLAB_SZ,
        ROUTEK_CHILD_BASE,
        b"slab-bytes-xxx".to_vec(),
    );
    let raw_capture = RawSlabCapture {
        slabs: vec![s],
        children: vec![
            raw_child(
                ROUTEK_CHILD_BASE,
                14,
                b"child-A-bytes".to_vec(),
                RawChildKind::HeapGlobal,
            ),
            raw_child(
                ROUTEK_CHILD_BASE,
                14,
                b"child-B-bytes".to_vec(),
                RawChildKind::HeapGlobal,
            ),
        ],
    };
    let ga = global(ROUTEK_CHILD_BASE, b"child-A-bytes".to_vec(), false);
    let gb = global(ROUTEK_CHILD_BASE, b"child-B-bytes".to_vec(), false);
    // Neither raw child matches the slab ("slab-bytes-xxx"); the two raw
    // children differ from each other -> ambiguous duplicate -> fail closed.
    let err = build_patched_backing_slab(&raw_capture, &[ga, gb], &[], &["t"]).unwrap_err();
    assert!(matches!(err, OverlayError::RawChildMissing { .. }));
}

// 15. Route O exact geometry constant sanity.
#[test]
fn r0g_route_o_geometry_is_exact() {
    assert_eq!(R0G_CHILD_BASE - R0G_SLAB_BASE, R0G_CHILD_OFF as u64);
    assert_eq!(R0G_CHILD_OFF as u64, 0x3a3e8);
    assert_eq!(R0G_CHILD_SIZE, 0x70);
    assert_eq!(R0G_FIRST_MISMATCH, 0x28);
    // The child is inside the Route O slab.
    assert!(R0G_CHILD_BASE >= R0G_SLAB_BASE);
    assert!(R0G_CHILD_BASE + R0G_CHILD_SIZE as u64 <= R0G_SLAB_BASE + 0x2db3750);
}
